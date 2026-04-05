//! Bidirectional relay with DPI desync hook.
//!
//! After the SOCKS5/HTTP CONNECT handshake completes, this module relays
//! data between the client and upstream server. On the first outbound data
//! (which typically contains the TLS ClientHello or HTTP request), it
//! intercepts, applies desync techniques, and sends the modified segments.
//!
//! Handles real-world edge cases:
//! - Partial reads: ClientHello may arrive across multiple `read()` calls
//! - Coalesced data: ClientHello may be followed by other data in the same read
//! - Non-TLS: HTTP requests, unknown protocols — pass through or apply HTTP techniques

use std::io;
use std::sync::Arc;
use std::time::Duration;

use desyncd_desync::PayloadContext;
use desyncd_packet::tls::ParseStatus;
use desyncd_strategy::Selector;
use desyncd_types::{DesyncAction, StealthConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, trace};

use crate::connstate::ConnState;

/// Maximum buffer size for first-packet reassembly (64KB).
/// A typical ClientHello is 200-600 bytes; Firefox/Chrome can be ~700 bytes
/// with many extensions. 64KB covers even pathological cases.
const MAX_FIRST_BUF: usize = 65536;

/// Timeout for reassembling the first outbound message.
/// If we can't get a complete ClientHello in 5 seconds, apply what we have.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Relay data between client and upstream, applying desync on the first
/// outbound (client → upstream) data.
pub async fn relay_with_desync(
    mut client: TcpStream,
    mut upstream: TcpStream,
    domain: Option<&str>,
    selector: &Selector,
    stealth: Option<&StealthConfig>,
) -> anyhow::Result<()> {
    // Enable TCP_NODELAY on upstream to control segment boundaries.
    upstream.set_nodelay(true)?;

    // Per-connection state, shared between the two relay directions.
    let state = Arc::new(ConnState::new());

    // --- First outbound data: reassemble and apply desync ---
    let first_buf = match reassemble_first_message(&mut client).await {
        Ok(buf) if buf.is_empty() => return Ok(()),
        Ok(buf) => buf,
        Err(e) => {
            debug!(error = %e, "error reading first outbound data");
            return Err(e);
        }
    };

    debug!(len = first_buf.len(), ?domain, "intercepted first outbound data");

    // NOTE: randomize_tls_padding MUST NOT be applied in proxy mode.
    // The ClientHello belongs to the actual TLS client (browser). Modifying it
    // changes the TLS transcript hash, causing the client and server to derive
    // different keys → SSL_ERROR_BAD_MAC_READ. Padding is only safe when we
    // generate our own ClientHello (probe mode).

    // Create payload context and apply strategy.
    let ctx = PayloadContext::new(first_buf);
    let action = selector.apply(&ctx).unwrap_or(DesyncAction::PassThrough);

    // Log the desync action at INFO level so users can diagnose.
    match &action {
        DesyncAction::PassThrough => {
            debug!(?domain, "desync: passthrough (no technique applied)");
        }
        DesyncAction::Replace(data) => {
            info!(
                ?domain,
                original_len = ctx.payload.len(),
                new_len = data.len(),
                "desync: payload replaced (e.g. tls_record_frag)"
            );
            state.mark_desync_applied();
        }
        DesyncAction::Split(chunks) => {
            let sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
            info!(
                ?domain,
                num_chunks = chunks.len(),
                ?sizes,
                "desync: payload split (e.g. tcp_split)"
            );
            state.mark_desync_applied();
        }
        DesyncAction::InjectBefore(fakes) => {
            info!(
                ?domain,
                num_fakes = fakes.len(),
                "desync: injecting fake packets before real data"
            );
            state.mark_desync_applied();
        }
    }

    crate::action::execute_action(&action, &ctx.payload, &mut upstream, stealth).await?;
    state.add_bytes_sent(ctx.payload.len() as u64);

    // --- Bidirectional relay for remaining data ---
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let state_up = Arc::clone(&state);
    let state_down = Arc::clone(&state);

    let client_to_upstream = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(e),
            };
            upstream_writer.write_all(&buf[..n]).await?;
            state_up.add_bytes_sent(n as u64);
        }
        upstream_writer.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    let upstream_to_client = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match upstream_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(e),
            };
            // First response from upstream — the desync didn't break the handshake.
            state_down.mark_upstream_responded();
            state_down.add_bytes_received(n as u64);
            client_writer.write_all(&buf[..n]).await?;
        }
        client_writer.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                trace!(error = %e, "client->upstream relay ended");
            }
        }
        result = upstream_to_client => {
            if let Err(e) = result {
                trace!(error = %e, "upstream->client relay ended");
            }
        }
    }

    // Telemetry: if desync was applied but upstream never responded, the
    // technique likely broke the connection. Useful for diagnosing bad strategies.
    if !state.is_success() {
        debug!(
            ?domain,
            elapsed_ms = state.elapsed().as_millis() as u64,
            "desync applied but upstream never responded — strategy may be broken"
        );
    }

    Ok(())
}

/// Initial buffer size for first-packet reassembly (4KB).
/// A typical ClientHello is 200-700 bytes; this covers the common case
/// without over-allocating. Grows to MAX_FIRST_BUF only if needed.
const INITIAL_FIRST_BUF: usize = 4096;

/// Reassemble the first outbound message (TLS ClientHello or HTTP request).
///
/// Reads from the client socket, using the TLS parser's `NeedMore` signal
/// to determine when we have a complete message. Falls back to a single
/// read for non-TLS protocols (HTTP, unknown).
///
/// Handles:
/// - Partial reads: keeps reading until parser says Complete or NotTls
/// - Timeout: gives up after REASSEMBLY_TIMEOUT and uses what we have
/// - Coalesced data: correctly handles extra data after the ClientHello
/// - Large messages: caps at MAX_FIRST_BUF to prevent memory issues
async fn reassemble_first_message(
    client: &mut TcpStream,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; INITIAL_FIRST_BUF];
    // First read — always do at least one.
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut filled: usize = n;

    // Quick check: is this even TLS?
    let status = desyncd_packet::tls::try_parse_client_hello(&buf[..filled]);

    match status {
        ParseStatus::Complete(_) => {
            // Got complete ClientHello in first read (common case).
            buf.truncate(filled);
            return Ok(buf);
        }
        ParseStatus::NotTls => {
            // Not TLS — could be HTTP or unknown. Single read is enough.
            buf.truncate(filled);
            return Ok(buf);
        }
        ParseStatus::NeedMore(needed) => {
            debug!(
                have = filled,
                need = needed,
                "partial TLS data, reading more"
            );
            // Grow buffer to MAX_FIRST_BUF for reassembly.
            buf.resize(MAX_FIRST_BUF, 0);
        }
    }

    // Reassembly loop with timeout.
    let deadline = tokio::time::Instant::now() + REASSEMBLY_TIMEOUT;

    loop {
        if filled >= MAX_FIRST_BUF {
            debug!("reassembly buffer full, proceeding with what we have");
            break;
        }

        let remaining_time = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining_time.is_zero() {
            debug!(filled, "reassembly timeout, proceeding with what we have");
            break;
        }

        match tokio::time::timeout(remaining_time, client.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => {
                debug!("client closed during reassembly");
                break;
            }
            Ok(Ok(n)) => {
                filled += n;
                trace!(filled, read = n, "reassembly: read more data");

                match desyncd_packet::tls::try_parse_client_hello(&buf[..filled]) {
                    ParseStatus::Complete(_) => {
                        debug!(filled, "reassembly: ClientHello complete");
                        break;
                    }
                    ParseStatus::NeedMore(needed) => {
                        if needed > MAX_FIRST_BUF {
                            debug!(needed, "ClientHello claims too large, proceeding");
                            break;
                        }
                        trace!(filled, needed, "reassembly: still need more");
                        continue;
                    }
                    ParseStatus::NotTls => {
                        debug!("reassembly: data no longer looks like TLS");
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(error = %e, "read error during reassembly");
                if filled > 0 {
                    break; // Use what we have.
                }
                return Err(e.into());
            }
            Err(_) => {
                debug!(filled, "reassembly timeout");
                break;
            }
        }
    }

    buf.truncate(filled);
    Ok(buf)
}
