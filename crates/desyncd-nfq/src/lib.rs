//! NFQ mode handler.
//!
//! Intercepts packets via Linux NFQUEUE and applies desync techniques
//! at the kernel/packet level. This is a **secondary, optional** mode.
//!
//! Trade-offs vs SOCKS mode:
//! - Pro: Can inject fake packets with bad TTL/checksum (true desync)
//! - Pro: Transparent to applications (no proxy config needed)
//! - Con: Higher CPU overhead (kernel↔userspace context switch per packet)
//! - Con: Higher latency (every packet goes through the queue)
//! - Con: More detectable (iptables rules visible, nfqueue process visible)
//! - Con: Requires root/CAP_NET_ADMIN
//!
//! For most users, SOCKS mode is the better choice.

pub mod raw_packet;
pub mod connstate;

use std::sync::Arc;

use connstate::{AppliedAction, ConnKey, ConnTracker};
use desyncd_desync::PayloadContext;
use desyncd_platform::{InterceptedPacket, PacketInterceptor, Verdict};
use desyncd_strategy::Selector;
use desyncd_types::DesyncAction;
use tracing::{debug, info, warn};

/// Configuration for NFQ mode.
#[derive(Debug, Clone)]
pub struct NfqConfig {
    /// NFQUEUE number to bind to.
    pub queue_num: u16,
    /// Ports to intercept (default: [80, 443]).
    pub ports: Vec<u16>,
    /// Maximum tracked connections.
    pub max_connections: usize,
}

impl Default for NfqConfig {
    fn default() -> Self {
        Self {
            queue_num: 200,
            ports: vec![80, 443],
            max_connections: 10000,
        }
    }
}

/// Run the NFQ mode packet processing loop.
pub async fn run_nfq<I: PacketInterceptor>(
    mut interceptor: I,
    selector: Arc<Selector>,
    config: NfqConfig,
) -> anyhow::Result<()> {
    interceptor.start().await?;
    info!("NFQ mode started (secondary mode — consider SOCKS for lower overhead)");

    let mut tracker = ConnTracker::new(config.max_connections);
    let mut packets_processed: u64 = 0;

    loop {
        let packet = match interceptor.recv_packet().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "error receiving packet");
                continue;
            }
        };

        let verdict = process_packet(&packet, &selector, &mut tracker);

        match &verdict {
            Verdict::Accept => {
                interceptor.send_verdict(packet.id, verdict, None).await?;
            }
            Verdict::Drop => {
                interceptor.send_verdict(packet.id, verdict, None).await?;
            }
            Verdict::Modify(new_data) => {
                interceptor
                    .send_verdict(packet.id, Verdict::Accept, Some(new_data))
                    .await?;
            }
        }

        packets_processed += 1;

        // Periodic cleanup of expired connections.
        if packets_processed.is_multiple_of(1000) {
            tracker.cleanup_expired();
        }
    }
}

/// Process a single intercepted packet and determine the verdict.
fn process_packet(
    packet: &InterceptedPacket,
    selector: &Selector,
    tracker: &mut ConnTracker,
) -> Verdict {
    let parsed = match raw_packet::parse_ip_tcp(&packet.data) {
        Some(p) => p,
        None => return Verdict::Accept,
    };

    if parsed.payload.is_empty() {
        return Verdict::Accept; // SYN/ACK, no payload.
    }

    let conn_key = ConnKey {
        src: parsed.src_addr,
        dst: parsed.dst_addr,
    };

    // Extract TCP sequence number for retransmit detection.
    let seq = parsed.tcp_seq();

    // Check for retransmit of an already-processed packet.
    if tracker.is_retransmit(&conn_key, seq) {
        debug!("retransmit detected, accepting original");
        return Verdict::Accept;
    }

    let state = tracker.get_or_create(&conn_key);
    if state.desync_applied {
        return Verdict::Accept; // Already handled this connection.
    }

    let ctx = PayloadContext::new(parsed.payload.to_vec());
    let action = selector.apply(&ctx).unwrap_or(DesyncAction::PassThrough);

    match action {
        DesyncAction::PassThrough => {
            tracker.mark_applied(&conn_key, seq, AppliedAction::PassThrough);
            Verdict::Accept
        }
        DesyncAction::Replace(new_payload) => {
            debug!(
                original_len = parsed.payload.len(),
                new_len = new_payload.len(),
                "nfq: replacing payload"
            );
            tracker.mark_applied(&conn_key, seq, AppliedAction::Replaced);
            match raw_packet::rebuild_packet(&packet.data, &parsed, &new_payload) {
                Some(new_packet) => Verdict::Modify(new_packet),
                None => Verdict::Accept,
            }
        }
        DesyncAction::Split(_chunks) => {
            // TCP splitting in NFQ requires raw socket injection.
            // For now, accept. Users should prefer SOCKS mode for splitting.
            debug!("nfq: split not implemented in NFQ mode, accepting (use SOCKS mode)");
            tracker.mark_applied(&conn_key, seq, AppliedAction::PassThrough);
            Verdict::Accept
        }
        DesyncAction::InjectBefore(_fakes) => {
            debug!("nfq: fake injection not yet implemented, accepting (use SOCKS mode)");
            tracker.mark_applied(&conn_key, seq, AppliedAction::PassThrough);
            Verdict::Accept
        }
        DesyncAction::SlowSplit { .. } => {
            debug!("nfq: slow_split not implemented in NFQ mode, accepting (use SOCKS mode)");
            tracker.mark_applied(&conn_key, seq, AppliedAction::PassThrough);
            Verdict::Accept
        }
    }
}
