//! Slow Split (DPI Reassembly Timeout Exploitation) technique.
//!
//! Splits the payload like `tcp_split`, but inserts a deliberate delay (1-5s)
//! between segments. The delay targets DPI reassembly timeouts:
//!
//! - DPI reassembly buffers typically expire in 1-5 seconds (hardware constraints:
//!   millions of concurrent flows on backbone equipment).
//! - Server TCP stacks keep connections alive for 30-300 seconds.
//!
//! By sending the first segment (before SNI), waiting for the DPI to drop it
//! from its reassembly buffer, then sending the second segment (containing SNI),
//! the DPI sees SNI in isolation — without the TLS record header — and fails
//! to match its inspection signature.
//!
//! The server reassembles both segments normally via standard TCP.
//!
//! ## Timing
//!
//! Default delay: 3 seconds (configurable via `timing_jitter_us` in stealth).
//! - Too short (<1s): DPI may not have timed out yet.
//! - Too long (>8s): some servers or intermediary NATs may drop the connection.
//! - Sweet spot: 2-5 seconds works against most DPI hardware.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for slow split.
pub struct SlowSplitTechnique;

/// Default inter-segment delay in microseconds (3 seconds).
const DEFAULT_DELAY_US: u32 = 3_000_000;

/// Minimum delay to be effective against DPI (500ms).
const MIN_EFFECTIVE_DELAY_US: u32 = 500_000;

impl Technique for SlowSplitTechnique {
    fn name(&self) -> &'static str {
        "slow_split"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        split_pos: &SplitPosition,
        _config: &TechniqueConfig,
        stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        apply(ctx, split_pos, stealth)
    }
}

/// Apply slow split: split payload + embed delay metadata.
///
/// Returns `DesyncAction::Split` — the inter-segment delay is communicated
/// by setting `timing_jitter_us` in the stealth config to 2-5 seconds.
/// The action executor (`action.rs`) already applies timing jitter between
/// Split chunks, so we reuse that mechanism with a longer delay.
///
/// The delay is encoded in a wrapper: the technique returns a special Split
/// where the middle chunk is a zero-length sentinel indicating "pause here".
/// The executor handles this: if a chunk is empty, it sleeps for the configured
/// delay instead of writing.
pub fn apply(
    ctx: &PayloadContext,
    split_pos: &SplitPosition,
    stealth: Option<&StealthConfig>,
) -> Result<DesyncAction> {
    let offset = ctx.resolve_split_position(split_pos).ok_or_else(|| {
        desyncd_types::Error::NotApplicable(
            "cannot resolve split position for slow_split".into(),
        )
    })?;

    if offset >= ctx.payload.len() {
        return Ok(DesyncAction::PassThrough);
    }

    let first = ctx.payload[..offset].to_vec();
    let second = ctx.payload[offset..].to_vec();

    // Determine delay: use stealth timing_jitter_us if large enough,
    // otherwise use default 3s.
    let delay_us = stealth
        .map(|s| s.timing_jitter_us)
        .filter(|&d| d >= MIN_EFFECTIVE_DELAY_US)
        .unwrap_or(DEFAULT_DELAY_US);

    debug!(
        offset,
        first_len = first.len(),
        second_len = second.len(),
        delay_ms = delay_us / 1000,
        "slow_split: splitting with inter-segment delay targeting DPI timeout"
    );

    // Return as SlowSplit action. The empty vec in the middle is a sentinel:
    // action executor will sleep for `delay_us` when it encounters an empty chunk.
    Ok(DesyncAction::SlowSplit {
        chunks: vec![first, second],
        delay_us,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_client_hello;

    #[test]
    fn test_slow_split_basic() {
        let payload = b"Hello, World!".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };

        let result = apply(&ctx, &SplitPosition::Absolute(5), None).unwrap();
        match result {
            DesyncAction::SlowSplit { chunks, delay_us } => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(chunks[0], b"Hello");
                assert_eq!(chunks[1], b", World!");
                assert_eq!(delay_us, DEFAULT_DELAY_US);
            }
            _ => panic!("expected SlowSplit"),
        }
    }

    #[test]
    fn test_slow_split_at_sni() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, None).unwrap();
        match result {
            DesyncAction::SlowSplit { chunks, delay_us } => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(chunks[0].len() + chunks[1].len(), payload.len());
                assert!(
                    chunks[1].windows(11).any(|w| w == b"example.com"),
                    "second chunk should contain the SNI value"
                );
                assert_eq!(delay_us, DEFAULT_DELAY_US);
            }
            _ => panic!("expected SlowSplit"),
        }
    }

    #[test]
    fn test_slow_split_custom_delay() {
        let payload = b"Test data here".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };

        let stealth = StealthConfig {
            timing_jitter_us: 5_000_000, // 5 seconds
            ..Default::default()
        };

        let result = apply(&ctx, &SplitPosition::Absolute(4), Some(&stealth)).unwrap();
        match result {
            DesyncAction::SlowSplit { delay_us, .. } => {
                assert_eq!(delay_us, 5_000_000);
            }
            _ => panic!("expected SlowSplit"),
        }
    }

    #[test]
    fn test_slow_split_ignores_small_jitter() {
        let payload = b"Test data here".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };

        // 100ms is below MIN_EFFECTIVE_DELAY_US — should use default
        let stealth = StealthConfig {
            timing_jitter_us: 100_000,
            ..Default::default()
        };

        let result = apply(&ctx, &SplitPosition::Absolute(4), Some(&stealth)).unwrap();
        match result {
            DesyncAction::SlowSplit { delay_us, .. } => {
                assert_eq!(delay_us, DEFAULT_DELAY_US);
            }
            _ => panic!("expected SlowSplit"),
        }
    }
}
