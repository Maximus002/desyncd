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
use std::time::Duration;

use desyncd_desync::PayloadContext;
use desyncd_packet::tls::ParseStatus;
use desyncd_strategy::Selector;
use desyncd_types::{DesyncAction, StealthConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// Apply random timing jitter between segments if configured.
async fn maybe_timing_jitter(stealth: Option<&StealthConfig>) {
    if let Some(jitter_us) = stealth.and_then(|s| {
        if s.timing_jitter_us > 0 { Some(s.timing_jitter_us) } else { None }
    }) {
        let delay = fastrand::u32(0..=jitter_us);
        tokio::time::sleep(Duration::from_micros(delay as u64)).await;
    }
}

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

    // Apply TLS padding if stealth config requests it (anti-ML).
    let first_buf = if stealth.is_some_and(|s| s.randomize_tls_padding) {
        let pad_len = fastrand::usize(16..=256);
        desyncd_desync::padding::add_tls_padding(&first_buf, pad_len)
            .unwrap_or(first_buf)
    } else {
        first_buf
    };

    // Create payload context and apply strategy.
    let ctx = PayloadContext::new(first_buf.clone());
    let action = selector.apply(&ctx).unwrap_or(DesyncAction::PassThrough);

    match action {
        DesyncAction::PassThrough => {
            debug!("no desync applied, passing through");
            upstream.write_all(&first_buf).await?;
        }
        DesyncAction::Replace(new_data) => {
            debug!(
                original_len = first_buf.len(),
                new_len = new_data.len(),
                "desync: replacing payload"
            );
            upstream.write_all(&new_data).await?;
        }
        DesyncAction::Split(chunks) => {
            debug!(num_chunks = chunks.len(), "desync: splitting into segments");
            for (i, chunk) in chunks.iter().enumerate() {
                trace!(chunk_idx = i, len = chunk.len(), "sending chunk");
                upstream.write_all(chunk).await?;
                upstream.flush().await?;
                maybe_timing_jitter(stealth).await;
            }
        }
        DesyncAction::InjectBefore(fake_chunks) => {
            debug!(
                num_fakes = fake_chunks.len(),
                "desync: injecting fake data before real payload"
            );
            for (i, chunk) in fake_chunks.iter().enumerate() {
                trace!(chunk_idx = i, len = chunk.len(), "sending fake chunk");
                upstream.write_all(chunk).await?;
                upstream.flush().await?;
            }
            maybe_timing_jitter(stealth).await;
            upstream.write_all(&first_buf).await?;
        }
    }

    // --- Bidirectional relay for remaining data ---
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let client_to_upstream = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(e),
            };
            upstream_writer.write_all(&buf[..n]).await?;
        }
        upstream_writer.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    let upstream_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match upstream_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(e),
            };
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

    Ok(())
}

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
    let mut buf = vec![0u8; MAX_FIRST_BUF];
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
            // Fall through to reassembly loop.
            let _ = needed; // We'll re-check after each read.
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
