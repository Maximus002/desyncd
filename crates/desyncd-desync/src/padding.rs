//! TLS ClientHello padding extension insertion.
//!
//! Adds a TLS padding extension (type 0x0015, RFC 7685) to a ClientHello
//! to randomize the total packet size. This defeats ML classifiers that
//! use packet length as a fingerprinting feature.
//!
//! Updates all three length fields in the TLS structure:
//! - TLS record length (bytes 3-4)
//! - Handshake message length (bytes 6-8)
//! - Extensions total length (variable position)

/// Add a padding extension to a TLS ClientHello payload.
///
/// Returns `None` if the payload is not a valid ClientHello or is too
/// malformed to safely modify. The padding extension contains `pad_len`
/// zero bytes.
pub fn add_tls_padding(payload: &[u8], pad_len: usize) -> Option<Vec<u8>> {
    // Minimum: record header(5) + handshake header(4) + version(2) + random(32) = 43
    if payload.len() < 43 {
        return None;
    }

    // Verify TLS Handshake record.
    if payload[0] != 0x16 {
        return None;
    }

    // Find the extensions length field position by walking the structure.
    let mut pos: usize = 5; // skip record header

    // Handshake header: type(1) + length(3)
    if payload[pos] != 0x01 {
        return None; // Not ClientHello
    }
    pos += 4;

    // Version (2 bytes)
    pos += 2;

    // Random (32 bytes)
    pos += 32;

    // Session ID
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > payload.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Compression methods
    if pos >= payload.len() {
        return None;
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;

    // Extensions length field position
    if pos + 2 > payload.len() {
        return None;
    }
    let ext_len_pos = pos;
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // Verify extensions don't overflow the payload
    if pos + ext_len > payload.len() {
        return None;
    }

    // Build the padding extension: type(2) + length(2) + zeros(pad_len)
    let pad_ext_total = 4 + pad_len;

    // Check that new lengths won't overflow u16
    let new_ext_len = ext_len + pad_ext_total;
    if new_ext_len > 0xFFFF {
        return None;
    }

    // Build the new payload
    let mut result = Vec::with_capacity(payload.len() + pad_ext_total);

    // Copy everything up to end of existing extensions
    let ext_end = pos + ext_len;
    result.extend_from_slice(&payload[..ext_end]);

    // Append padding extension
    result.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension type
    result.extend_from_slice(&(pad_len as u16).to_be_bytes()); // extension data length
    result.resize(result.len() + pad_len, 0x00); // zero padding

    // Append anything after the extensions (unlikely but safe)
    if ext_end < payload.len() {
        result.extend_from_slice(&payload[ext_end..]);
    }

    // Update TLS record length (bytes 3-4): original + pad_ext_total
    let orig_record_len = u16::from_be_bytes([result[3], result[4]]) as usize;
    let new_record_len = orig_record_len + pad_ext_total;
    if new_record_len > 0xFFFF {
        return None;
    }
    result[3..5].copy_from_slice(&(new_record_len as u16).to_be_bytes());

    // Update handshake length (bytes 6-8, 3-byte big-endian)
    let orig_hs_len = ((result[6] as usize) << 16)
        | ((result[7] as usize) << 8)
        | (result[8] as usize);
    let new_hs_len = orig_hs_len + pad_ext_total;
    result[6] = ((new_hs_len >> 16) & 0xFF) as u8;
    result[7] = ((new_hs_len >> 8) & 0xFF) as u8;
    result[8] = (new_hs_len & 0xFF) as u8;

    // Update extensions length
    result[ext_len_pos..ext_len_pos + 2]
        .copy_from_slice(&(new_ext_len as u16).to_be_bytes());

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_client_hello;
    use desyncd_packet::tls::{try_parse_client_hello, ParseStatus};
    use desyncd_types::AppProtocol;

    #[test]
    fn test_padding_preserves_sni() {
        let original = build_test_client_hello("www.example.com");
        let padded = add_tls_padding(&original, 64).expect("padding failed");

        // Padded should be larger.
        assert_eq!(padded.len(), original.len() + 4 + 64);

        // Should still parse as a valid ClientHello with the same SNI.
        match try_parse_client_hello(&padded) {
            ParseStatus::Complete(AppProtocol::TlsClientHello { sni, .. }) => {
                assert_eq!(sni.as_deref(), Some("www.example.com"));
            }
            other => panic!("expected Complete with SNI, got {:?}", other),
        }
    }

    #[test]
    fn test_padding_extension_present() {
        let original = build_test_client_hello("test.com");
        let padded = add_tls_padding(&original, 32).expect("padding failed");

        // The padding extension (0x0015) should be in the payload.
        let has_padding_ext = padded
            .windows(2)
            .any(|w| w == [0x00, 0x15]);
        assert!(has_padding_ext, "padding extension type not found");
    }

    #[test]
    fn test_varying_pad_sizes() {
        let original = build_test_client_hello("vary.example.com");
        let orig_len = original.len();

        for pad_len in [16, 64, 128, 256] {
            let padded = add_tls_padding(&original, pad_len).expect("padding failed");
            assert_eq!(padded.len(), orig_len + 4 + pad_len);

            // Verify still parseable.
            match try_parse_client_hello(&padded) {
                ParseStatus::Complete(AppProtocol::TlsClientHello { sni, .. }) => {
                    assert_eq!(sni.as_deref(), Some("vary.example.com"));
                }
                other => panic!("pad_len={}: expected Complete, got {:?}", pad_len, other),
            }
        }
    }

    #[test]
    fn test_non_tls_returns_none() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(add_tls_padding(data, 32).is_none());
    }

    #[test]
    fn test_too_short_returns_none() {
        assert!(add_tls_padding(&[0x16, 0x03, 0x01], 32).is_none());
    }
}
