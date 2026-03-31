//! TCP Split technique.
//!
//! Splits the application payload into two or more segments at a specified
//! byte offset. In SOCKS proxy mode, this is achieved by sending the segments
//! as separate `write()` calls with `TCP_NODELAY` enabled, which causes the
//! OS to emit separate TCP segments.
//!
//! The DPI system sees the first segment (which doesn't contain the full SNI
//! or Host header) and cannot match its signature. The real server reassembles
//! the TCP stream normally.

use crate::PayloadContext;
use desyncd_types::{DesyncAction, Result, SplitPosition};
use tracing::debug;

/// Apply TCP split to the given payload context.
///
/// Returns `DesyncAction::Split` with the payload divided into two chunks.
pub fn apply(ctx: &PayloadContext, split_pos: &SplitPosition) -> Result<DesyncAction> {
    let offset = ctx.resolve_split_position(split_pos).ok_or_else(|| {
        desyncd_types::Error::NotApplicable(
            "cannot resolve split position for this payload".into(),
        )
    })?;

    if offset == 0 || offset >= ctx.payload.len() {
        return Ok(DesyncAction::PassThrough);
    }

    let first = ctx.payload[..offset].to_vec();
    let second = ctx.payload[offset..].to_vec();

    debug!(
        offset,
        first_len = first.len(),
        second_len = second.len(),
        "tcp_split: splitting payload"
    );

    Ok(DesyncAction::Split(vec![first, second]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_client_hello;

    #[test]
    fn test_split_at_absolute_position() {
        let payload = b"Hello, World!".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };

        let result = apply(&ctx, &SplitPosition::Absolute(5)).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(chunks[0], b"Hello");
                assert_eq!(chunks[1], b", World!");
            }
            _ => panic!("expected Split"),
        }
    }

    #[test]
    fn test_split_at_sni_offset() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
                assert_eq!(chunks[0].len() + chunks[1].len(), payload.len());
                assert!(
                    chunks[1].windows(11).any(|w| w == b"example.com"),
                    "second chunk should contain the SNI value"
                );
            }
            _ => panic!("expected Split"),
        }
    }
}
