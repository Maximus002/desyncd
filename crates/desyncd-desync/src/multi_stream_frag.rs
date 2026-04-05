//! Multi-Stream TLS Record Fragmentation.
//!
//! Extends `tls_record_frag` by splitting the ClientHello into N TLS records
//! (default 3) instead of just 2. Each record carries a slice of the
//! handshake bytes, and split points are chosen so that the SNI hostname
//! always ends up in the **last** fragment. That forces any DPI reassembler
//! to coalesce all N records before it can read the SNI — raising N by 1
//! is often enough to exceed a fixed reassembly window.
//!
//! This defeats DPI systems that:
//! - Only read the first TLS record (TSPU) — already beaten by tls_record_frag
//! - Read the first N-1 records (beaten when N > their reassembly window)
//! - Use fixed-size buffers for TLS reassembly (overflowed by many tiny records)
//!
//! The technique is RFC 5246 §6.2.1 compliant — handshake messages may be
//! fragmented across multiple records, and every modern TLS stack reassembles
//! them transparently.
//!
//! ## Historic note
//!
//! Up to v2.0 the fragment count was carried via the `sni_mode` config field
//! (stringly-typed). v2.1 introduced a dedicated `fragments: Option<usize>`
//! field; `sni_mode` numeric values are still accepted as a fallback for
//! existing on-disk configs but are considered deprecated and will be
//! removed in a future release.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::{debug, warn};

/// Default number of TLS record fragments.
const DEFAULT_FRAGMENTS: usize = 3;

/// Maximum allowed fragments (to avoid pathological cases).
const MAX_FRAGMENTS: usize = 8;

/// Minimum allowed fragments (2 = same as `tls_record_frag`).
const MIN_FRAGMENTS: usize = 2;

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
        // Resolve the fragment count. Prefer the new typed `fragments`
        // field; fall back to parsing `sni_mode` for backward compatibility
        // with pre-2.1 configs, with a warning so operators notice the
        // deprecated usage.
        let n_fragments = if let Some(n) = config.fragments {
            n
        } else if let Some(s) = config.sni_mode.as_deref() {
            match s.parse::<usize>() {
                Ok(n) => {
                    warn!(
                        "multi_stream_frag: reading fragment count from deprecated \
                         `sni_mode = \"{}\"` — migrate to `fragments = {}`",
                        s, n
                    );
                    n
                }
                Err(_) => {
                    // `sni_mode` holds a non-numeric value (intended for
                    // `sni_manip`, not this technique). Fall back to default.
                    DEFAULT_FRAGMENTS
                }
            }
        } else {
            DEFAULT_FRAGMENTS
        }
        .clamp(MIN_FRAGMENTS, MAX_FRAGMENTS);

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

/// Compute split points so the SNI hostname always lands in the **last**
/// TLS record fragment.
///
/// The goal of multi-record fragmentation is to force a DPI reassembler to
/// coalesce as many records as possible before it can read the SNI. If the
/// reassembler has a hard cap (e.g. "only look at the first 3 records"),
/// the only useful knob we have is: push the SNI into record `N` where
/// `N > cap`. Adding fragments **after** the SNI is a no-op — the DPI has
/// already seen everything it needs by record `k` (the one containing the
/// SNI), regardless of how many more records follow.
///
/// Therefore the algorithm distributes all `n_fragments - 1` cuts in the
/// `[0, sni_offset]` range:
///
///   * `n=2` → `[pre | SNI+tail]`
///   * `n=3` → `[pre1 | pre2 | SNI+tail]`
///   * `n=4` → `[pre1 | pre2 | pre3 | SNI+tail]`
///   * `n=5` → `[pre1 | pre2 | pre3 | pre4 | SNI+tail]`
///
/// where `preK` are slices of the data that precede the SNI hostname.
///
/// If there is not enough pre-SNI data to host the requested number of
/// cuts, duplicates are collapsed and the effective fragment count may be
/// smaller than requested — this is graceful degradation, not an error.
fn compute_split_points(
    data_len: usize,
    sni_offset: usize,
    n_fragments: usize,
) -> Vec<usize> {
    if n_fragments <= 1 || data_len == 0 {
        return vec![];
    }

    let n_splits = n_fragments - 1;

    // Clamp sni_offset into a usable range. If the caller gave us something
    // outside (0, data_len), fall back to splitting near the middle — still
    // better than panicking.
    let sni_offset = sni_offset.clamp(1, data_len.saturating_sub(1));

    // Degenerate case: not enough pre-SNI data for multiple cuts.
    // We can fit at most `sni_offset` distinct split positions in [1..sni_offset].
    // If n_splits exceeds that, the `dedup` below will collapse the extras.
    let mut points = Vec::with_capacity(n_splits);

    // Place `n_splits` evenly-spaced cuts in (0, sni_offset], inclusive of
    // sni_offset itself. The last cut = sni_offset guarantees the final
    // fragment starts exactly at the SNI hostname.
    //
    // positions: i * sni_offset / n_splits for i = 1..=n_splits
    for i in 1..=n_splits {
        let pos = (sni_offset * i) / n_splits;
        let pos = pos.clamp(1, data_len.saturating_sub(1));
        points.push(pos);
    }

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

    /// Walk the resulting payload record-by-record and return each record's
    /// data slice (without the 5-byte header). Asserts every record has
    /// ContentType=Handshake and valid length.
    fn extract_records(new_payload: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < new_payload.len() {
            assert!(pos + 5 <= new_payload.len(), "record header overflow");
            assert_eq!(new_payload[pos], 0x16, "record at {} is not Handshake", pos);
            let len = u16::from_be_bytes([new_payload[pos + 3], new_payload[pos + 4]]) as usize;
            assert!(len > 0, "record at {} has zero length", pos);
            assert!(pos + 5 + len <= new_payload.len(), "record data overflow");
            out.push(&new_payload[pos + 5..pos + 5 + len]);
            pos += 5 + len;
        }
        out
    }

    /// Assert that the SNI hostname bytes live entirely inside the LAST
    /// record. This is the whole point of the technique — DPI must read
    /// every single fragment before it can see the SNI.
    fn assert_sni_in_last_record(records: &[&[u8]], sni: &str) {
        let sni_bytes = sni.as_bytes();
        let last = records.last().expect("no records");
        assert!(
            last.windows(sni_bytes.len()).any(|w| w == sni_bytes),
            "SNI {:?} not found in last record {:02x?}",
            sni,
            last
        );
        // And crucially: not in any of the earlier records.
        for (i, r) in records.iter().enumerate().take(records.len() - 1) {
            assert!(
                !r.windows(sni_bytes.len()).any(|w| w == sni_bytes),
                "SNI {:?} leaked into non-last record {} (of {})",
                sni,
                i,
                records.len()
            );
        }
    }

    #[test]
    fn test_2_fragments() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 2).unwrap();
        let DesyncAction::Replace(new_payload) = result else { panic!("expected Replace") };

        // 2 fragments = same as tls_record_frag: +5 bytes.
        assert_eq!(new_payload.len(), payload.len() + 5);
        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 2);
        assert_sni_in_last_record(&records, "example.com");
    }

    #[test]
    fn test_3_fragments() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 3).unwrap();
        let DesyncAction::Replace(new_payload) = result else { panic!("expected Replace") };

        // Extra overhead: 2 additional TLS headers (10 bytes).
        assert_eq!(new_payload.len(), payload.len() + 10);
        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 3);
        assert_sni_in_last_record(&records, "example.com");
    }

    #[test]
    fn test_4_fragments_sni_in_last() {
        // Regression for the friend-reported bug: pre-v2.1, n=4 placed
        // the extra fragment AFTER the SNI, so SNI still lived in record 3
        // (same as n=3 — useless). Verify the fix: SNI must be in record 4.
        let payload = build_test_client_hello("www.youtube.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 4).unwrap();
        let DesyncAction::Replace(new_payload) = result else { panic!("expected Replace") };

        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 4, "expected exactly 4 records");
        assert_sni_in_last_record(&records, "www.youtube.com");
    }

    #[test]
    fn test_5_fragments_sni_in_last() {
        let payload = build_test_client_hello("www.facebook.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 5).unwrap();
        let DesyncAction::Replace(new_payload) = result else { panic!("expected Replace") };

        // Extra overhead: 4 additional TLS headers (20 bytes).
        assert_eq!(new_payload.len(), payload.len() + 20);
        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 5);
        assert_sni_in_last_record(&records, "www.facebook.com");
    }

    #[test]
    fn test_8_fragments_sni_in_last() {
        let payload = build_test_client_hello("discord.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni, 8).unwrap();
        let DesyncAction::Replace(new_payload) = result else { panic!("expected Replace") };

        let records = extract_records(&new_payload);
        assert!(records.len() <= 8, "got {} records, expected <= 8", records.len());
        assert!(records.len() >= 2, "got {} records, expected >= 2", records.len());
        assert_sni_in_last_record(&records, "discord.com");
    }

    #[test]
    fn test_fragments_field_preferred_over_sni_mode() {
        // When both `fragments` and numeric `sni_mode` are set, `fragments`
        // wins (sni_mode path is deprecated backcompat).
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload);

        let config = TechniqueConfig {
            name: "multi_stream_frag".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: Some("2".into()),    // would produce 2 fragments
            fragments: Some(4),            // but fragments wins → 4
            host_mode: None,
            stealth: None,
            l7_filter: None,
        };
        let tech = MultiStreamFragTechnique;
        let action = tech.apply(&ctx, &SplitPosition::Sni, &config, None).unwrap();
        let DesyncAction::Replace(new_payload) = action else { panic!("expected Replace") };
        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 4);
        assert_sni_in_last_record(&records, "example.com");
    }

    #[test]
    fn test_sni_mode_numeric_still_works_with_warning() {
        // Backward-compat: old configs using sni_mode="4" should still work.
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload);

        let config = TechniqueConfig {
            name: "multi_stream_frag".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: Some("4".into()),
            fragments: None,
            host_mode: None,
            stealth: None,
            l7_filter: None,
        };
        let tech = MultiStreamFragTechnique;
        let action = tech.apply(&ctx, &SplitPosition::Sni, &config, None).unwrap();
        let DesyncAction::Replace(new_payload) = action else { panic!("expected Replace") };
        let records = extract_records(&new_payload);
        assert_eq!(records.len(), 4);
        assert_sni_in_last_record(&records, "example.com");
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

    #[test]
    fn test_compute_split_points_n4_all_before_sni() {
        // Direct unit test of the algorithm: n=4 → n-1 = 3 splits, all
        // in (0, sni_offset], with the last == sni_offset. The expected
        // positions are evenly spaced: 300/3=100, 2·100=200, 3·100=300.
        let splits = compute_split_points(1000, 300, 4);
        assert_eq!(splits, vec![100, 200, 300]);
        assert_eq!(*splits.last().unwrap(), 300);
    }

    #[test]
    fn test_compute_split_points_n5_all_before_sni() {
        // n=5 → 4 splits, evenly spaced in (0, 300]: 75, 150, 225, 300.
        let splits = compute_split_points(1000, 300, 5);
        assert_eq!(splits, vec![75, 150, 225, 300]);
    }

    #[test]
    fn test_compute_split_points_n3_matches_friend_example() {
        // The friend's specification:
        //   n=3 → [pre | mid | SNI+tail]
        // Two splits, both ≤ sni_offset, last at sni_offset.
        let splits = compute_split_points(1000, 300, 3);
        assert_eq!(splits, vec![150, 300]);
    }

    #[test]
    fn test_compute_split_points_degenerate_tiny_sni_offset() {
        // sni_offset=3 with n=5 → only 2-3 unique split points fit.
        // Must not panic, must still place last split at/before sni_offset.
        let splits = compute_split_points(100, 3, 5);
        assert!(!splits.is_empty());
        assert!(splits.iter().all(|&p| p > 0 && p < 100));
        assert!(*splits.last().unwrap() <= 3);
    }
}
