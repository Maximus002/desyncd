//! Disorder technique.
//!
//! Sends TCP segments in reverse order: the second segment is sent first,
//! then the first. DPI systems that process packets in arrival order will
//! see incomplete data and fail to match signatures.
//!
//! In SOCKS mode, this is achieved by splitting the payload and returning
//! the chunks in reversed order. With TCP_NODELAY enabled, the OS will
//! emit separate segments, and the receiver's TCP stack will buffer and
//! reorder them using sequence numbers.
//!
//! In NFQ mode, the original packet is replaced by the second segment,
//! and the first segment is injected with a brief delay.

use crate::PayloadContext;
use desyncd_types::{DesyncAction, Result, SplitPosition};
use tracing::debug;

/// Apply disorder technique: split and reverse segment order.
pub fn apply(ctx: &PayloadContext, split_pos: &SplitPosition) -> Result<DesyncAction> {
    let offset = ctx.resolve_split_position(split_pos).ok_or_else(|| {
        desyncd_types::Error::NotApplicable(
            "cannot resolve split position for disorder".into(),
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
        "disorder: splitting and reversing segment order"
    );

    // Return in reversed order: second chunk first, then first chunk.
    // The TCP stack on the receiving end will reorder by sequence number.
    Ok(DesyncAction::Split(vec![second, first]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disorder_reverses_order() {
        let payload = b"AAAAABBBBB".to_vec();
        let ctx = PayloadContext {
            protocol: desyncd_types::AppProtocol::Unknown,
            payload,
        };

        let result = apply(&ctx, &SplitPosition::Absolute(5)).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
                // Second chunk comes first.
                assert_eq!(chunks[0], b"BBBBB");
                assert_eq!(chunks[1], b"AAAAA");
            }
            _ => panic!("expected Split"),
        }
    }

    #[test]
    fn test_disorder_with_sni() {
        let payload = crate::testutil::build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);
                // Reversed: second chunk (containing SNI) comes first.
                assert!(
                    chunks[0].windows(11).any(|w| w == b"example.com"),
                    "first sent chunk should contain SNI (it's the second data chunk)"
                );
                assert_eq!(chunks[0].len() + chunks[1].len(), payload.len());
            }
            _ => panic!("expected Split"),
        }
    }
}
