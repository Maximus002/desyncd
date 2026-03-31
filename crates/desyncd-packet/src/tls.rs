//! TLS ClientHello parser.
//!
//! Parses just enough of a TLS record to extract the SNI (Server Name Indication)
//! extension and its byte offset within the payload. This is the most critical
//! parser for DPI bypass — the SNI offset determines where to split.
//!
//! Handles real-world edge cases:
//! - Partial reads (returns `NeedMore` with minimum bytes needed)
//! - Multiple TLS records wrapping a single ClientHello (fragmented records)
//! - Coalesced data after the ClientHello
//!
//! Reference: RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), RFC 6066 (SNI Extension).

use desyncd_types::AppProtocol;

/// TLS content types.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS handshake type for ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// SNI extension type.
const EXTENSION_SNI: u16 = 0x0000;
/// SNI host name type.
const SNI_TYPE_HOSTNAME: u8 = 0x00;
/// Maximum TLS record size (16KB + overhead).
const MAX_TLS_RECORD: usize = 16384 + 2048;

/// Result of attempting to parse a TLS ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStatus {
    /// Successfully parsed. Contains the protocol info.
    Complete(AppProtocol),
    /// Data looks like TLS but is incomplete. Contains minimum bytes needed.
    NeedMore(usize),
    /// Data is not a TLS ClientHello.
    NotTls,
}

/// Attempt to parse a TLS ClientHello from the given payload.
///
/// Returns `Complete` if fully parsed, `NeedMore(n)` if the data looks
/// like TLS but is truncated (need at least `n` total bytes),
/// or `NotTls` if it doesn't look like a TLS record.
pub fn try_parse_client_hello(data: &[u8]) -> ParseStatus {
    // Need at least 5 bytes for TLS record header.
    if data.len() < 5 {
        if !data.is_empty() && data[0] == CONTENT_TYPE_HANDSHAKE {
            return ParseStatus::NeedMore(5);
        }
        return ParseStatus::NotTls;
    }

    // -- TLS Record Header --
    if data[0] != CONTENT_TYPE_HANDSHAKE {
        return ParseStatus::NotTls;
    }

    let record_version = u16::from_be_bytes([data[1], data[2]]);
    if !(0x0301..=0x0303).contains(&record_version) {
        return ParseStatus::NotTls;
    }

    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if record_length == 0 || record_length > MAX_TLS_RECORD {
        return ParseStatus::NotTls;
    }

    let record_end = 5 + record_length;

    // Reassemble handshake data from potentially multiple TLS records.
    // A single ClientHello can be split across multiple TLS records.
    
    

    if data.len() < record_end {
        // First record is incomplete — need more data.
        return ParseStatus::NeedMore(record_end);
    }

    let first_record_payload_len = record_length;
    let first_record_payload = &data[5..record_end];

    // Check if there are continuation records (same content type, fragmented handshake).
    // A ClientHello > 16KB is rare but possible with large extension lists.
    let mut total_handshake = first_record_payload.to_vec();
    let mut scan_pos = record_end;

    while scan_pos + 5 <= data.len() {
        if data[scan_pos] != CONTENT_TYPE_HANDSHAKE {
            break;
        }
        let cont_version = u16::from_be_bytes([data[scan_pos + 1], data[scan_pos + 2]]);
        if !(0x0301..=0x0303).contains(&cont_version) {
            break;
        }
        let cont_len = u16::from_be_bytes([data[scan_pos + 3], data[scan_pos + 4]]) as usize;
        let cont_end = scan_pos + 5 + cont_len;
        if data.len() < cont_end {
            // Continuation record is incomplete.
            return ParseStatus::NeedMore(cont_end);
        }
        total_handshake.extend_from_slice(&data[scan_pos + 5..cont_end]);
        scan_pos = cont_end;
    }

    let handshake_data: Vec<u8> = total_handshake;

    // Now parse the reassembled handshake data.
    parse_handshake(&handshake_data, first_record_payload_len)
}

/// Parse reassembled handshake data.
///
/// `first_record_payload_len` is used to calculate offsets relative
/// to the original wire data (including the 5-byte record header).
fn parse_handshake(handshake: &[u8], _first_record_payload_len: usize) -> ParseStatus {
    if handshake.is_empty() {
        return ParseStatus::NotTls;
    }

    if handshake[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return ParseStatus::NotTls;
    }

    // Handshake header: type(1) + length(3).
    if handshake.len() < 4 {
        return ParseStatus::NeedMore(5 + 4); // record header + handshake header
    }

    let hs_length = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);

    // Check we have enough handshake data.
    let needed_handshake = 4 + hs_length;
    if handshake.len() < needed_handshake {
        // We know the full size needed. Account for TLS record header.
        return ParseStatus::NeedMore(5 + needed_handshake);
    }

    let mut pos: usize = 4;

    // -- ClientHello Body --

    // 2 bytes: client version.
    if pos + 2 > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + 2);
    }
    pos += 2;

    // 32 bytes: client random.
    if pos + 32 > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + 32);
    }
    pos += 32;

    // Session ID (1 byte length + variable).
    if pos + 1 > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + 1);
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1;
    if pos + session_id_len > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + session_id_len);
    }
    pos += session_id_len;

    // Cipher suites (2 byte length + variable).
    if pos + 2 > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + 2);
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + cipher_suites_len);
    }
    pos += cipher_suites_len;

    // Compression methods (1 byte length + variable).
    if pos + 1 > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + 1);
    }
    let comp_methods_len = handshake[pos] as usize;
    pos += 1;
    if pos + comp_methods_len > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + comp_methods_len);
    }
    pos += comp_methods_len;

    // -- Extensions --
    if pos + 2 > handshake.len() {
        // No extensions — valid ClientHello but no SNI.
        return ParseStatus::Complete(AppProtocol::TlsClientHello {
            sni: None,
            sni_offset: 0,
            sni_len: 0,
        });
    }

    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    if pos + extensions_len > handshake.len() {
        return ParseStatus::NeedMore(5 + pos + extensions_len);
    }

    let extensions_end = pos + extensions_len;

    // Walk through extensions looking for SNI.
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            break; // Malformed extension, stop walking.
        }

        if ext_type == EXTENSION_SNI {
            // Parse SNI. Offset needs to be relative to the full wire payload.
            // wire layout: [record_hdr(5)][handshake_data...]
            // pos is offset within handshake_data, so wire offset = 5 + pos
            return parse_sni_extension(&handshake[pos..pos + ext_len], 5 + pos);
        }

        pos += ext_len;
    }

    // ClientHello without SNI extension.
    ParseStatus::Complete(AppProtocol::TlsClientHello {
        sni: None,
        sni_offset: 0,
        sni_len: 0,
    })
}

/// Parse the SNI extension payload.
///
/// `wire_offset` is the byte offset of the extension data start within
/// the original wire payload (including the 5-byte TLS record header).
fn parse_sni_extension(ext_data: &[u8], wire_offset: usize) -> ParseStatus {
    if ext_data.len() < 2 {
        return ParseStatus::Complete(AppProtocol::TlsClientHello {
            sni: None,
            sni_offset: 0,
            sni_len: 0,
        });
    }

    let _sni_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    let mut pos = 2;

    while pos + 3 <= ext_data.len() {
        let name_type = ext_data[pos];
        let name_len = u16::from_be_bytes([ext_data[pos + 1], ext_data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > ext_data.len() {
            break; // Truncated SNI entry.
        }

        if name_type == SNI_TYPE_HOSTNAME {
            let name_bytes = &ext_data[pos..pos + name_len];
            // Validate: SNI should be printable ASCII (RFC 6066).
            let sni = match std::str::from_utf8(name_bytes) {
                Ok(s) if s.bytes().all(|b| (0x20..0x7f).contains(&b)) => s.to_string(),
                _ => String::from_utf8_lossy(name_bytes).to_string(),
            };
            let sni_offset = wire_offset + pos;
            return ParseStatus::Complete(AppProtocol::TlsClientHello {
                sni: Some(sni),
                sni_offset,
                sni_len: name_len,
            });
        }

        pos += name_len;
    }

    ParseStatus::Complete(AppProtocol::TlsClientHello {
        sni: None,
        sni_offset: 0,
        sni_len: 0,
    })
}

/// Legacy wrapper: parse and return AppProtocol or None.
///
/// This is the simple API used by `detect_protocol`. For code that needs
/// to handle partial data, use `try_parse_client_hello` directly.
pub fn parse_client_hello(data: &[u8]) -> Option<AppProtocol> {
    match try_parse_client_hello(data) {
        ParseStatus::Complete(proto) => Some(proto),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(sni: &str) -> Vec<u8> {
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
        buf.extend_from_slice(&EXTENSION_SNI.to_be_bytes());
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let sni_list_len = 1 + 2 + sni_bytes.len();
        buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        buf.push(SNI_TYPE_HOSTNAME);
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn test_parse_client_hello_with_sni() {
        let data = build_client_hello("www.example.com");
        let result = try_parse_client_hello(&data);

        match result {
            ParseStatus::Complete(AppProtocol::TlsClientHello {
                sni,
                sni_offset,
                sni_len,
            }) => {
                assert_eq!(sni.as_deref(), Some("www.example.com"));
                assert_eq!(sni_len, 15);
                assert!(sni_offset > 0);
                let extracted = &data[sni_offset..sni_offset + sni_len];
                assert_eq!(extracted, b"www.example.com");
            }
            other => panic!("expected Complete TlsClientHello with SNI, got {:?}", other),
        }
    }

    #[test]
    fn test_non_tls_data() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(try_parse_client_hello(data), ParseStatus::NotTls);
    }

    #[test]
    fn test_too_short_but_looks_tls() {
        // Just the content type byte — looks like it could be TLS.
        assert_eq!(
            try_parse_client_hello(&[0x16]),
            ParseStatus::NeedMore(5)
        );
    }

    #[test]
    fn test_too_short_not_tls() {
        assert_eq!(try_parse_client_hello(&[0x00]), ParseStatus::NotTls);
    }

    #[test]
    fn test_partial_record() {
        let data = build_client_hello("example.com");
        // Truncate to just the record header + partial handshake.
        let partial = &data[..20];
        match try_parse_client_hello(partial) {
            ParseStatus::NeedMore(n) => {
                assert!(n > 20, "should need more than 20 bytes, got {}", n);
                assert!(n <= data.len(), "shouldn't need more than full packet");
            }
            other => panic!("expected NeedMore, got {:?}", other),
        }
    }

    #[test]
    fn test_truncated_at_extensions() {
        let data = build_client_hello("example.com");
        // Truncate right before the SNI value.
        let truncated = &data[..data.len() - 5];
        match try_parse_client_hello(truncated) {
            ParseStatus::NeedMore(n) => {
                assert!(n >= data.len() - 5);
            }
            other => panic!("expected NeedMore, got {:?}", other),
        }
    }

    #[test]
    fn test_coalesced_data_after_clienthello() {
        let mut data = build_client_hello("example.com");
        // Append some garbage after the ClientHello — simulating
        // coalesced data or a second TLS record.
        data.extend_from_slice(&[0xFF; 100]);

        match try_parse_client_hello(&data) {
            ParseStatus::Complete(AppProtocol::TlsClientHello { sni, .. }) => {
                assert_eq!(sni.as_deref(), Some("example.com"));
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_fragmented_tls_records() {
        // Build a ClientHello, then split it across two TLS records.
        let full = build_client_hello("fragmented.example.com");
        let handshake_data = &full[5..]; // Strip record header.

        // Split handshake data into two halves.
        let mid = handshake_data.len() / 2;
        let part1 = &handshake_data[..mid];
        let part2 = &handshake_data[mid..];

        // Build two TLS records.
        let mut fragmented = Vec::new();
        // Record 1.
        fragmented.push(0x16);
        fragmented.extend_from_slice(&0x0301u16.to_be_bytes());
        fragmented.extend_from_slice(&(part1.len() as u16).to_be_bytes());
        fragmented.extend_from_slice(part1);
        // Record 2.
        fragmented.push(0x16);
        fragmented.extend_from_slice(&0x0301u16.to_be_bytes());
        fragmented.extend_from_slice(&(part2.len() as u16).to_be_bytes());
        fragmented.extend_from_slice(part2);

        match try_parse_client_hello(&fragmented) {
            ParseStatus::Complete(AppProtocol::TlsClientHello { sni, .. }) => {
                assert_eq!(sni.as_deref(), Some("fragmented.example.com"));
            }
            other => panic!(
                "expected Complete with SNI, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_fragmented_record_incomplete() {
        // Two TLS records but the second is incomplete.
        let full = build_client_hello("test.com");
        let handshake_data = &full[5..];
        let mid = handshake_data.len() / 2;
        let part1 = &handshake_data[..mid];
        let part2 = &handshake_data[mid..];

        let mut fragmented = Vec::new();
        fragmented.push(0x16);
        fragmented.extend_from_slice(&0x0301u16.to_be_bytes());
        fragmented.extend_from_slice(&(part1.len() as u16).to_be_bytes());
        fragmented.extend_from_slice(part1);
        // Second record header says it has part2.len() bytes but we only provide half.
        fragmented.push(0x16);
        fragmented.extend_from_slice(&0x0301u16.to_be_bytes());
        fragmented.extend_from_slice(&(part2.len() as u16).to_be_bytes());
        fragmented.extend_from_slice(&part2[..part2.len() / 2]);

        match try_parse_client_hello(&fragmented) {
            ParseStatus::NeedMore(_) => {} // Expected.
            other => panic!("expected NeedMore, got {:?}", other),
        }
    }

    #[test]
    fn test_legacy_wrapper() {
        let data = build_client_hello("example.com");
        let result = parse_client_hello(&data);
        assert!(result.is_some());

        let result = parse_client_hello(b"not tls");
        assert!(result.is_none());
    }

    #[test]
    fn test_large_session_id() {
        // Build a ClientHello with a 32-byte session ID (TLS 1.2 resumption).
        let sni = "resume.example.com";
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
        let sni_ext_len = 4 + sni_ext_data_len;
        let extensions_len = sni_ext_len;
        let session_id_len: usize = 32;
        let ch_body_len =
            2 + 32 + 1 + session_id_len + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let hs_len = 4 + ch_body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&0x0301u16.to_be_bytes());
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(0x01);
        buf.push(0x00);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&0x0303u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]); // random
        buf.push(session_id_len as u8);
        buf.extend_from_slice(&[0xBB; 32]); // session ID
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&0xc02fu16.to_be_bytes());
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

        match try_parse_client_hello(&buf) {
            ParseStatus::Complete(AppProtocol::TlsClientHello { sni: s, sni_offset, sni_len }) => {
                assert_eq!(s.as_deref(), Some("resume.example.com"));
                let extracted = &buf[sni_offset..sni_offset + sni_len];
                assert_eq!(extracted, sni.as_bytes());
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }
}
