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
use desyncd_packet::quic::parse_quic_initial;
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
    /// Drop outbound QUIC Initial packets (UDP/443).
    ///
    /// Our desync techniques operate on TCP only. If a browser negotiates
    /// HTTP/3, the QUIC traffic bypasses our pipeline entirely and is
    /// vulnerable to DPI. Dropping QUIC Initial packets forces the browser
    /// to fall back to TCP+TLS, where the techniques apply.
    ///
    /// SOCKS mode already gets this for free — it rejects UDP_ASSOCIATE,
    /// so browsers using SOCKS5 never attempt QUIC through the proxy. NFQ
    /// mode needs this explicit switch because packets flow through the
    /// kernel, not the proxy.
    ///
    /// Default: `true` — safer bypass; users who specifically want to
    /// allow QUIC (e.g. for latency) can opt out.
    pub block_quic: bool,
}

impl Default for NfqConfig {
    fn default() -> Self {
        Self {
            queue_num: 200,
            ports: vec![80, 443],
            max_connections: 10000,
            block_quic: true,
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
    info!(
        block_quic = config.block_quic,
        "NFQ mode started (secondary mode — consider SOCKS for lower overhead)"
    );

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

        let verdict = process_packet(&packet, &selector, &mut tracker, &config);

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
    config: &NfqConfig,
) -> Verdict {
    // Drop outbound QUIC Initial packets first, before the TCP fast path.
    // Our desync techniques are TCP-only, so QUIC traffic would otherwise
    // pass through unprotected and hit DPI directly. Dropping the Initial
    // makes the browser abandon HTTP/3 for this destination and fall back
    // to TCP+TLS, where the techniques apply.
    if config.block_quic {
        if let Some(udp) = raw_packet::parse_ip_udp(&packet.data) {
            if udp.dst_addr.port() == 443 && parse_quic_initial(udp.payload).is_some() {
                debug!(
                    dst = %udp.dst_addr,
                    payload_len = udp.payload.len(),
                    "nfq: dropping QUIC Initial to force TCP fallback"
                );
                return Verdict::Drop;
            }
        }
    }

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desyncd_strategy::Selector;
    use desyncd_types::Direction;

    /// Build a fake InterceptedPacket with the given raw IP data.
    fn pkt(data: Vec<u8>) -> InterceptedPacket {
        InterceptedPacket {
            id: 1,
            data,
            direction: Direction::Outbound,
        }
    }

    /// Build an IPv4 + UDP packet containing a well-formed QUIC v1 Initial
    /// header. Used to exercise the QUIC-drop path in process_packet.
    fn build_quic_initial_udp(dst_port: u16) -> Vec<u8> {
        // Inner QUIC Initial header (first bytes: 0xC0 + version=1 + empty
        // DCID/SCID + token length 0 + dummy length/PN + dummy payload).
        let mut quic = Vec::new();
        quic.push(0xC0); // long header + fixed bit + Initial type
        quic.extend_from_slice(&1u32.to_be_bytes()); // QUIC v1
        quic.push(0); // DCID length
        quic.push(0); // SCID length
        quic.push(0); // token length (varint 0)
        quic.extend_from_slice(&[0; 4]); // dummy length + packet number
        quic.extend_from_slice(&[0xAA; 32]); // dummy encrypted payload

        let total_len = 20 + 8 + quic.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45; // IPv4 + IHL 5
        buf[2] = (total_len >> 8) as u8;
        buf[3] = total_len as u8;
        buf[8] = 64; // TTL
        buf[9] = 17; // UDP
        buf[12..16].copy_from_slice(&[192, 168, 0, 1]); // src
        buf[16..20].copy_from_slice(&[1, 1, 1, 1]); // dst
        buf[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes()); // dst port
        let udp_len = (8 + quic.len()) as u16;
        buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // checksum left as zero (optional on IPv4)
        buf[28..].copy_from_slice(&quic);
        buf
    }

    #[test]
    fn drops_quic_initial_when_block_quic_enabled() {
        let selector = Selector::new(vec![], vec![], None);
        let mut tracker = ConnTracker::new(100);
        let config = NfqConfig { block_quic: true, ..Default::default() };
        let data = build_quic_initial_udp(443);

        let verdict = process_packet(&pkt(data), &selector, &mut tracker, &config);
        assert!(matches!(verdict, Verdict::Drop), "expected Drop, got {:?}", verdict);
    }

    #[test]
    fn accepts_quic_initial_when_block_quic_disabled() {
        let selector = Selector::new(vec![], vec![], None);
        let mut tracker = ConnTracker::new(100);
        let config = NfqConfig { block_quic: false, ..Default::default() };
        let data = build_quic_initial_udp(443);

        let verdict = process_packet(&pkt(data), &selector, &mut tracker, &config);
        assert!(matches!(verdict, Verdict::Accept), "expected Accept, got {:?}", verdict);
    }

    #[test]
    fn leaves_non_quic_udp_alone() {
        let selector = Selector::new(vec![], vec![], None);
        let mut tracker = ConnTracker::new(100);
        let config = NfqConfig { block_quic: true, ..Default::default() };
        // DNS-like UDP payload on port 53 — definitely not QUIC.
        let payload = [0x12u8, 0x34, 0x01, 0x00]; // DNS query header start
        let mut buf = vec![0u8; 20 + 8 + payload.len()];
        buf[0] = 0x45;
        buf[2] = (buf.len() >> 8) as u8;
        buf[3] = buf.len() as u8;
        buf[9] = 17;
        buf[16..20].copy_from_slice(&[8, 8, 8, 8]);
        buf[22..24].copy_from_slice(&53u16.to_be_bytes());
        buf[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        buf[28..].copy_from_slice(&payload);

        let verdict = process_packet(&pkt(buf), &selector, &mut tracker, &config);
        assert!(matches!(verdict, Verdict::Accept), "expected Accept, got {:?}", verdict);
    }

    #[test]
    fn ignores_quic_on_non_443_port() {
        // QUIC Initial bytes but destination port isn't 443 — should not drop.
        // (Someone hosting a custom QUIC service shouldn't be affected.)
        let selector = Selector::new(vec![], vec![], None);
        let mut tracker = ConnTracker::new(100);
        let config = NfqConfig { block_quic: true, ..Default::default() };
        let data = build_quic_initial_udp(4433); // custom port

        let verdict = process_packet(&pkt(data), &selector, &mut tracker, &config);
        assert!(matches!(verdict, Verdict::Accept), "expected Accept, got {:?}", verdict);
    }
}
