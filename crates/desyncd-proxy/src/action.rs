//! Shared execution logic for DesyncAction.
//!
//! Used by both the live relay (proxy mode) and the probe (adaptation mode)
//! to apply desync actions to TCP streams. This eliminates code duplication
//! and ensures consistent behavior between testing and production.

use std::time::Duration;

use desyncd_types::{DesyncAction, StealthConfig};
use tokio::io::{AsyncWriteExt, AsyncWrite};
use tracing::{debug, trace};

/// Execute a DesyncAction on a writable stream.
///
/// - `action`: the desync action to apply
/// - `original`: the original payload (used by InjectBefore to send after fakes)
/// - `stream`: any async writable stream (TcpStream, etc.)
/// - `stealth`: optional timing jitter between segments
pub async fn execute_action<W: AsyncWrite + Unpin>(
    action: &DesyncAction,
    original: &[u8],
    stream: &mut W,
    stealth: Option<&StealthConfig>,
) -> std::io::Result<()> {
    match action {
        DesyncAction::PassThrough => {
            debug!("no desync applied, passing through");
            stream.write_all(original).await?;
        }
        DesyncAction::Replace(new_data) => {
            debug!(
                original_len = original.len(),
                new_len = new_data.len(),
                "desync: replacing payload"
            );
            stream.write_all(new_data).await?;
        }
        DesyncAction::Split(chunks) => {
            debug!(num_chunks = chunks.len(), "desync: splitting into segments");
            for (i, chunk) in chunks.iter().enumerate() {
                trace!(chunk_idx = i, len = chunk.len(), "sending chunk");
                stream.write_all(chunk).await?;
                // TCP_NODELAY ensures each write_all maps to a separate segment.
                // Only apply timing jitter between chunks (no flush syscall needed).
                if i + 1 < chunks.len() {
                    maybe_timing_jitter(stealth).await;
                }
            }
        }
        DesyncAction::InjectBefore(fake_chunks) => {
            debug!(
                num_fakes = fake_chunks.len(),
                "desync: injecting fake data before real payload"
            );
            for (i, chunk) in fake_chunks.iter().enumerate() {
                trace!(chunk_idx = i, len = chunk.len(), "sending fake chunk");
                stream.write_all(chunk).await?;
                stream.flush().await?;
            }
            maybe_timing_jitter(stealth).await;
            stream.write_all(original).await?;
        }
        DesyncAction::SlowSplit { chunks, delay_us } => {
            debug!(
                num_chunks = chunks.len(),
                delay_ms = delay_us / 1000,
                "desync: slow split (DPI timeout exploitation)"
            );
            for (i, chunk) in chunks.iter().enumerate() {
                trace!(chunk_idx = i, len = chunk.len(), "sending slow split chunk");
                stream.write_all(chunk).await?;
                stream.flush().await?;
                // Apply the long inter-segment delay between chunks (not after last).
                if i + 1 < chunks.len() {
                    debug!(delay_ms = delay_us / 1000, "slow_split: waiting for DPI timeout");
                    tokio::time::sleep(Duration::from_micros(*delay_us as u64)).await;
                }
            }
        }
    }
    Ok(())
}

/// Apply random timing jitter between segments if configured.
async fn maybe_timing_jitter(stealth: Option<&StealthConfig>) {
    if let Some(jitter_us) = stealth.and_then(|s| {
        if s.timing_jitter_us > 0 { Some(s.timing_jitter_us) } else { None }
    }) {
        let delay = fastrand::u32(0..=jitter_us);
        tokio::time::sleep(Duration::from_micros(delay as u64)).await;
    }
}
