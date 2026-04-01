//! TLS Record Layer Fragmentation technique.
//!
//! Unlike TCP split which operates at the transport layer, this technique
//! fragments the TLS handshake at the TLS record layer. The original
//! ClientHello is wrapped in multiple TLS records, each containing a
//! portion of the handshake message.
//!
//! This is fully specification-compliant: RFC 5246 Section 6.2.1 explicitly
//! allows handshake messages to be fragmented across multiple records.
//! The server reassembles them transparently.
//!
//! DPI systems that only inspect the first TLS record will miss the full SNI.
//!
//! Reference: https://upb-syssec.github.io/blog/2023/record-fragmentation/

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for TLS record fragmentation.
pub struct TlsRecordFragTechnique;

impl Technique for TlsRecordFragTechnique {
    fn name(&self) -> &'static str {
        "tls_record_frag"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        split_pos: &SplitPosition,
        _config: &TechniqueConfig,
        _stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        apply(ctx, split_pos)
    }
}

/// TLS ContentType for Handshake messages.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// Apply TLS record fragmentation to the given payload context.
///
/// Takes a single TLS record containing a ClientHello and splits it into
/// two TLS records at the specified position. Each record has its own
/// 5-byte header (content_type, version, length).
pub fn apply(ctx: &PayloadContext, split_pos: &SplitPosition) -> Result<DesyncAction> {
    // This technique only applies to TLS ClientHello.
    match &ctx.protocol {
        AppProtocol::TlsClientHello { sni: Some(_), .. } => {}
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "tls_record_frag requires a TLS ClientHello with SNI".into(),
            ));
        }
    }

    // Verify this is a TLS record.
    if ctx.payload.len() < 5 || ctx.payload[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(desyncd_types::Error::NotApplicable(
            "payload is not a TLS Handshake record".into(),
        ));
    }

    // Extract TLS record header.
    let version_major = ctx.payload[1];
    let version_minor = ctx.payload[2];
    let record_data_len = u16::from_be_bytes([ctx.payload[3], ctx.payload[4]]) as usize;
    let record_data = &ctx.payload[5..];

    if record_data.len() < record_data_len {
        return Err(desyncd_types::Error::NotApplicable(
            "TLS record truncated".into(),
        ));
    }

    // The split position is relative to the full payload (including the 5-byte header).
    // We need to translate it to a position within the record data.
    let abs_offset = ctx.resolve_split_position(split_pos).ok_or_else(|| {
        desyncd_types::Error::NotApplicable(
            "cannot resolve split position for TLS record fragmentation".into(),
        )
    })?;

    // Convert from payload offset to record-data offset.
    let data_offset = if abs_offset > 5 {
        abs_offset - 5
    } else {
        1 // Split at minimum 1 byte into the record.
    };

    let data_offset = data_offset.clamp(1, record_data_len.saturating_sub(1));

    let first_data = &record_data[..data_offset];
    let second_data = &record_data[data_offset..record_data_len];

    // Build two TLS records.
    let mut first_record = Vec::with_capacity(5 + first_data.len());
    first_record.push(CONTENT_TYPE_HANDSHAKE);
    first_record.push(version_major);
    first_record.push(version_minor);
    first_record.extend_from_slice(&(first_data.len() as u16).to_be_bytes());
    first_record.extend_from_slice(first_data);

    let mut second_record = Vec::with_capacity(5 + second_data.len());
    second_record.push(CONTENT_TYPE_HANDSHAKE);
    second_record.push(version_major);
    second_record.push(version_minor);
    second_record.extend_from_slice(&(second_data.len() as u16).to_be_bytes());
    second_record.extend_from_slice(second_data);

    debug!(
        data_offset,
        first_len = first_data.len(),
        second_len = second_data.len(),
        "tls_record_frag: splitting into two TLS records"
    );

    // Return as a replacement: the original single-record payload is replaced
    // by the concatenation of two records. In SOCKS mode, these can optionally
    // be sent as separate TCP segments via Split.
    let mut combined = Vec::with_capacity(first_record.len() + second_record.len());
    combined.extend_from_slice(&first_record);
    combined.extend_from_slice(&second_record);

    Ok(DesyncAction::Replace(combined))
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
    fn test_tls_record_fragmentation() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // New payload should be larger (extra 5-byte TLS header).
                assert_eq!(new_payload.len(), payload.len() + 5);
                // Both records should be valid TLS Handshake records.
                assert_eq!(new_payload[0], 0x16);
                let first_len =
                    u16::from_be_bytes([new_payload[3], new_payload[4]]) as usize;
                assert_eq!(new_payload[5 + first_len], 0x16);
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
        assert!(apply(&ctx, &SplitPosition::Sni).is_err());
    }
}
