//! Multi-Stream TLS Record Fragmentation.
//!
//! Extends `tls_record_frag` by splitting the ClientHello into N TLS records
//! (default 3) instead of just 2. Each record contains a portion of the
//! handshake data, with split points chosen so the SNI hostname is distributed
//! across multiple records.
//!
//! This defeats DPI systems that:
//! - Only read the first TLS record (TSPU) — already beaten by tls_record_frag
//! - Read the first N-1 records (beaten when N > their reassembly window)
//! - Use fixed-size buffers for TLS reassembly (overflowed by many tiny records)
//!
//! The technique is RFC 5246 compliant — handshake fragmentation across records
//! is explicitly allowed and all modern TLS implementations handle it.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Default number of TLS record fragments.
const DEFAULT_FRAGMENTS: usize = 3;

/// Maximum allowed fragments (to avoid pathological cases).
const MAX_FRAGMENTS: usize = 8;

pub struct MultiStreamFragTechnique;

impl Technique for MultiStreamFragTechnique {
    fn name(&self) -> &'static str {
        "multi_stream_frag"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        split_pos: &SplitPosition,
        config: &TechniqueConfig,
        _stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        // Parse fragment count from sni_mode field (reusing existing config field).
        // Format: "3", "4", "5" etc. Default: 3.
        let n_fragments = config
            .sni_mode
            .as_deref()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FRAGMENTS)
            .clamp(2, MAX_FRAGMENTS);

        apply(ctx, split_pos, n_fragments)
    }
}

/// TLS ContentType for Handshake messages.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS record header size.
const TLS_HEADER_LEN: usize = 5;

/// Apply multi-stream TLS record fragmentation.
///
/// Splits a TLS ClientHello into `n_fragments` TLS records. The split points
/// are distributed so that the SNI hostname is fragmented across records.
pub fn apply(
    ctx: &PayloadContext,
    split_pos: &SplitPosition,
    n_fragments: usize,
) -> Result<DesyncAction> {
    // Must be TLS ClientHello with SNI.
    match &ctx.protocol {
        AppProtocol::TlsClientHello { sni: Some(_), .. } => {}
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "multi_stream_frag requires a TLS ClientHello with SNI".into(),
            ));
        }
    }

    if ctx.payload.len() < TLS_HEADER_LEN || ctx.payload[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(desyncd_types::Error::NotApplicable(
            "payload is not a TLS Handshake record".into(),
        ));
    }

    let version_major = ctx.payload[1];
    let version_minor = ctx.payload[2];
    let record_data_len = u16::from_be_bytes([ctx.payload[3], ctx.payload[4]]) as usize;
    let record_data = &ctx.payload[5..];

    if record_data.len() < record_data_len {
        return Err(desyncd_types::Error::NotApplicable(
            "TLS record truncated".into(),
        ));
    }

    // Not enough data for the requested number of fragments.
    if record_data_len < n_fragments {
        return Err(desyncd_types::Error::NotApplicable(
            "TLS record too small for requested fragment count".into(),
        ));
    }

    // Resolve the primary split position (where SNI lives).
    let sni_offset = ctx.resolve_split_position(split_pos).unwrap_or(
        // Fallback: split in the middle.
        TLS_HEADER_LEN + record_data_len / 2,
    );

    // Convert to record-data offset.
    let sni_data_offset = if sni_offset > TLS_HEADER_LEN {
        sni_offset - TLS_HEADER_LEN
    } else {
        1
    }
    .clamp(1, record_data_len.saturating_sub(1));

    // Calculate split points to distribute data across N fragments,
    // ensuring SNI falls in the middle of the fragment sequence.
    let split_points = compute_split_points(record_data_len, sni_data_offset, n_fragments);

    debug!(
        n_fragments,
        record_data_len,
        sni_data_offset,
        ?split_points,
        "multi_stream_frag: splitting into {} TLS records",
        split_points.len() + 1
    );

    // Build all TLS records in a single allocation.
    // Total: (n_fragments * 5 header bytes) + record_data_len
    let total_len = n_fragments * TLS_HEADER_LEN + record_data_len;
    let mut combined = Vec::with_capacity(total_len);

    let mut prev = 0usize;
    for (i, &split) in split_points.iter().enumerate() {
        let chunk = &record_data[prev..split];
        write_tls_record(&mut combined, version_major, version_minor, chunk);
        debug!(
            fragment = i + 1,
            offset = prev,
            len = chunk.len(),
            "multi_stream_frag: fragment"
        );
        prev = split;
    }

    // Last fragment: remaining data.
    let last_chunk = &record_data[prev..record_data_len];
    write_tls_record(&mut combined, version_major, version_minor, last_chunk);
    debug!(
        fragment = split_points.len() + 1,
        offset = prev,
        len = last_chunk.len(),
        "multi_stream_frag: fragment (last)"
    );

    Ok(DesyncAction::Replace(combined))
}

/// Compute split points that distribute fragments around the SNI position.
///
/// Strategy: place one split just before the SNI offset, then distribute
/// remaining splits evenly across the data. This ensures the SNI hostname
/// is split across at least 2 records.
fn compute_split_points(
    data_len: usize,
    sni_offset: usize,
    n_fragments: usize,
) -> Vec<usize> {
    if n_fragments <= 1 {
        return vec![];
    }

    let n_splits = n_fragments - 1;

    if n_splits == 1 {
        // Simple case: just split at the SNI offset.
        return vec![sni_offset];
    }

    // Place splits to maximize SNI fragmentation:
    // - One split just before SNI (sni_offset - small_delta)
    // - One split at SNI offset itself (or just after)
    // - Remaining splits distributed evenly in the remaining space
    let mut points = Vec::with_capacity(n_splits);

    // First: split a few bytes before the SNI offset.
    let pre_sni = (sni_offset / 2).max(1);
    points.push(pre_sni);

    // Second: split at or just after the SNI offset.
    if n_splits >= 2 {
        let post_sni = sni_offset.clamp(pre_sni + 1, data_len.saturating_sub(1));
        points.push(post_sni);
    }

    // Distribute any remaining splits evenly in the space after post_sni.
    if n_splits > 2 {
        if let Some(&last_point) = points.last() {
            let remaining_space = data_len.saturating_sub(last_point + 1);
            let extra_splits = n_splits - 2;

            for i in 1..=extra_splits {
                let pos = last_point + (remaining_space * i) / (extra_splits + 1);
                let pos = pos.clamp(last_point + 1, data_len.saturating_sub(1));
                if points.last().is_none_or(|&last| pos > last) {
                    points.push(pos);
                }
            }
        }
    }

    // Ensure all points are unique, sorted, and within bounds.
    points.sort();
    points.dedup();
    points.retain(|&p| p > 0 && p < data_len);

    points
}

/// Write a single TLS record (header + data) into the output buffer.
#[inline]
fn write_tls_record(buf: &mut Vec<u8>, version_major: u8, version_minor: u8, data: &[u8]) {
    buf.push(CONTENT_TYPE_HANDSHAKE);
    buf.push(version_major);
    buf.push(version_minor);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
        let sni_ext_len = 4 + sni_ext_data_len;
        let extensions_len = sni_ext_len;
        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let hs_len = 4 + ch_body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&0x0301u16.to_be_bytes());
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(0x01);
        buf.push(0x00);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&0x0303u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&0x1301u16.to_be_bytes());
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let sni_list_len = 1 + 2 + sni_bytes.len();
        buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn test_3_fragments() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 3).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // Extra overhead: 2 additional TLS headers (10 bytes).
                assert_eq!(new_payload.len(), payload.len() + 10);
                // Count TLS record headers.
                let mut pos = 0;
                let mut records = 0;
                while pos < new_payload.len() {
                    assert_eq!(new_payload[pos], 0x16, "record {} is not TLS Handshake", records);
                    let len = u16::from_be_bytes([new_payload[pos + 3], new_payload[pos + 4]]) as usize;
                    assert!(len > 0, "record {} has zero length", records);
                    pos += 5 + len;
                    records += 1;
                }
                assert_eq!(records, 3);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_5_fragments() {
        let payload = build_test_client_hello("www.youtube.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 5).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // Extra overhead: 4 additional TLS headers (20 bytes).
                assert_eq!(new_payload.len(), payload.len() + 20);
                let mut pos = 0;
                let mut records = 0;
                while pos < new_payload.len() {
                    assert_eq!(new_payload[pos], 0x16);
                    let len = u16::from_be_bytes([new_payload[pos + 3], new_payload[pos + 4]]) as usize;
                    assert!(len > 0);
                    pos += 5 + len;
                    records += 1;
                }
                assert_eq!(records, 5);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_2_fragments_matches_original() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 2).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // 2 fragments = same as tls_record_frag: +5 bytes.
                assert_eq!(new_payload.len(), payload.len() + 5);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_non_tls_rejected() {
        let ctx = PayloadContext {
            payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            protocol: AppProtocol::HttpRequest {
                method: "GET".into(),
                host: None,
                host_offset: 0,
            },
        };
        assert!(apply(&ctx, &SplitPosition::Sni, 3).is_err());
    }
}
