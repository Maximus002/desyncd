//! Minimal QUIC Initial packet parser.
//!
//! Extracts DCID and SCID from QUIC long header packets (RFC 9000).
//! This is used for protocol detection — we don't decrypt QUIC payloads.
//!
//! QUIC Initial packets are relevant for DPI because they contain the
//! TLS ClientHello (encrypted), and blocking/manipulating them can force
//! fallback to TCP+TLS where our desync techniques work.

use desyncd_types::AppProtocol;

/// QUIC v1 version number.
const QUIC_V1: u32 = 0x00000001;
/// QUIC v2 version number (RFC 9369).
const QUIC_V2: u32 = 0x6b3343cf;

/// Try to parse a QUIC Initial packet from the given data.
///
/// Returns `Some(AppProtocol::QuicInitial { dcid, scid })` if the data
/// looks like a valid QUIC long header packet, `None` otherwise.
///
/// Only checks the unencrypted header fields — does not attempt to
/// decrypt the payload or extract the inner TLS ClientHello.
pub fn parse_quic_initial(data: &[u8]) -> Option<AppProtocol> {
    // Minimum: header form(1) + version(4) + dcid_len(1) + scid_len(1) = 7
    if data.len() < 7 {
        return None;
    }

    // Long header: form bit (0x80) must be set.
    if data[0] & 0x80 == 0 {
        return None;
    }

    // Fixed bit (0x40) should be set for QUIC v1/v2.
    if data[0] & 0x40 == 0 {
        return None;
    }

    // Version field (bytes 1-4).
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    // Only match known QUIC versions (avoid false positives on random data).
    if version != QUIC_V1 && version != QUIC_V2 {
        return None;
    }

    // For Initial packets, the packet type bits are 0b00 (QUIC v1) in bits 4-5.
    // Bits 4-5 of the first byte: (data[0] >> 4) & 0x03
    let packet_type = (data[0] >> 4) & 0x03;
    if packet_type != 0x00 {
        // Not an Initial packet (could be 0-RTT, Handshake, or Retry).
        // Still return as QuicInitial for protocol detection purposes.
    }

    // DCID length (1 byte at offset 5).
    let dcid_len = data[5] as usize;
    if dcid_len > 20 {
        return None; // RFC 9000: max connection ID length is 20.
    }
    if data.len() < 6 + dcid_len + 1 {
        return None;
    }
    let dcid = data[6..6 + dcid_len].to_vec();

    // SCID length (1 byte at offset 6 + dcid_len).
    let scid_len = data[6 + dcid_len] as usize;
    if scid_len > 20 {
        return None;
    }
    if data.len() < 7 + dcid_len + scid_len {
        return None;
    }
    let scid = data[7 + dcid_len..7 + dcid_len + scid_len].to_vec();

    Some(AppProtocol::QuicInitial { dcid, scid })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal QUIC v1 Initial packet header.
    fn build_quic_initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // First byte: long header (0x80) + fixed bit (0x40) + Initial type (0x00 in bits 4-5)
        buf.push(0xC0); // 1100_0000
        // Version: QUIC v1
        buf.extend_from_slice(&QUIC_V1.to_be_bytes());
        // DCID
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(dcid);
        // SCID
        buf.push(scid.len() as u8);
        buf.extend_from_slice(scid);
        // Token length (varint 0) + dummy payload
        buf.push(0x00); // token length = 0
        buf.extend_from_slice(&[0x00; 4]); // length + packet number (dummy)
        buf.extend_from_slice(&[0xAA; 32]); // encrypted payload (dummy)
        buf
    }

    #[test]
    fn test_parse_quic_v1_initial() {
        let dcid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = vec![0xA1, 0xA2, 0xA3, 0xA4];
        let data = build_quic_initial(&dcid, &scid);

        match parse_quic_initial(&data) {
            Some(AppProtocol::QuicInitial { dcid: d, scid: s }) => {
                assert_eq!(d, dcid);
                assert_eq!(s, scid);
            }
            other => panic!("expected QuicInitial, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_quic_v2() {
        let mut data = build_quic_initial(&[0x01, 0x02], &[0x03]);
        // Change version to QUIC v2.
        data[1..5].copy_from_slice(&QUIC_V2.to_be_bytes());

        assert!(parse_quic_initial(&data).is_some());
    }

    #[test]
    fn test_empty_cids() {
        let data = build_quic_initial(&[], &[]);
        match parse_quic_initial(&data) {
            Some(AppProtocol::QuicInitial { dcid, scid }) => {
                assert!(dcid.is_empty());
                assert!(scid.is_empty());
            }
            other => panic!("expected QuicInitial with empty CIDs, got {:?}", other),
        }
    }

    #[test]
    fn test_not_quic_short_header() {
        // Short header: form bit not set.
        let data = vec![0x40, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_not_quic_unknown_version() {
        let mut data = build_quic_initial(&[0x01], &[0x02]);
        // Set unknown version.
        data[1..5].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        assert!(parse_quic_initial(&[0xC0, 0x00, 0x00]).is_none());
        assert!(parse_quic_initial(&[]).is_none());
    }

    #[test]
    fn test_not_quic_tls_data() {
        // TLS ClientHello starts with 0x16 — should not match QUIC.
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_quic_initial(&data).is_none());
    }

    #[test]
    fn test_dcid_too_long() {
        let mut data = build_quic_initial(&[0x01], &[0x02]);
        data[5] = 21; // DCID length > 20 → invalid
        assert!(parse_quic_initial(&data).is_none());
    }
}
