//! CCS Injection (ChangeCipherSpec Record Confusion) technique.
//!
//! Exploits how DPI state machines track TLS handshake progress.
//! Inserts a fake TLS ChangeCipherSpec (CCS) record between fragments
//! of the ClientHello, causing the DPI to believe encryption has begun.
//!
//! ## How it works
//!
//! TLS has 4 content types:
//! - 0x14 = ChangeCipherSpec (CCS) — signals transition to encrypted comms
//! - 0x15 = Alert
//! - 0x16 = Handshake (ClientHello, ServerHello, etc.)
//! - 0x17 = Application Data (encrypted payload)
//!
//! Many DPI systems track TLS state:
//!   Handshake → CCS → Encrypted
//!
//! After seeing a CCS record, the DPI transitions to "encrypted" state and
//! stops inspecting payload (since it would be encrypted garbage).
//!
//! We exploit this by:
//! 1. Sending the first part of ClientHello (content type 0x16)
//! 2. Sending a fake CCS record (content type 0x14, 1 byte payload: 0x01)
//! 3. Sending the second part of ClientHello (content type 0x16)
//!
//! The DPI sees CCS after partial handshake and stops parsing.
//! The real TLS server either:
//! - Ignores the unexpected CCS (TLS 1.3 middlebox compat, RFC 8446 §D.4)
//! - Processes it harmlessly (CCS has no effect before cipher negotiation)
//!
//! ## Compatibility
//!
//! - TLS 1.3: CCS is explicitly part of the middlebox compatibility mode.
//!   Servers MUST accept (and ignore) CCS at any point during handshake.
//! - TLS 1.2: Most implementations tolerate unexpected CCS before Finished.
//!   Some strict implementations may reject it — the adaptation engine
//!   will detect this and avoid the technique for those targets.
//!
//! ## Output format
//!
//! Returns `DesyncAction::Replace` with the combined payload:
//! [CH_part1_record] [CCS_record] [CH_part2_record]
//!
//! Each part is a complete TLS record with its own 5-byte header.
//! This is then typically wrapped in `DesyncAction::Split` by combining
//! with `tcp_split` in a strategy, sending each record as a separate
//! TCP segment.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for CCS injection.
pub struct CcsInjectTechnique;

/// TLS content types.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_CCS: u8 = 0x14;

/// CCS record payload: a single byte 0x01 (the only valid CCS message).
const CCS_PAYLOAD: [u8; 1] = [0x01];

impl Technique for CcsInjectTechnique {
    fn name(&self) -> &'static str {
        "ccs_inject"
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

/// Apply CCS injection to a TLS ClientHello.
///
/// Takes the original single-record ClientHello, splits it into two TLS
/// Handshake records, and inserts a CCS record between them.
pub fn apply(ctx: &PayloadContext, split_pos: &SplitPosition) -> Result<DesyncAction> {
    // Only applies to TLS ClientHello.
    match &ctx.protocol {
        AppProtocol::TlsClientHello { sni: Some(_), .. } => {}
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "ccs_inject requires a TLS ClientHello with SNI".into(),
            ));
        }
    }

    // Verify TLS record header.
    if ctx.payload.len() < 5 || ctx.payload[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(desyncd_types::Error::NotApplicable(
            "payload is not a TLS Handshake record".into(),
        ));
    }

    // Parse TLS record header.
    let version_major = ctx.payload[1];
    let version_minor = ctx.payload[2];
    let record_data_len = u16::from_be_bytes([ctx.payload[3], ctx.payload[4]]) as usize;
    let record_data = &ctx.payload[5..];

    if record_data.len() < record_data_len {
        return Err(desyncd_types::Error::NotApplicable(
            "TLS record truncated".into(),
        ));
    }

    // Resolve split position within the record data.
    let abs_offset = ctx.resolve_split_position(split_pos).ok_or_else(|| {
        desyncd_types::Error::NotApplicable(
            "cannot resolve split position for ccs_inject".into(),
        )
    })?;

    let data_offset = if abs_offset > 5 {
        abs_offset - 5
    } else {
        1
    };
    let data_offset = data_offset.clamp(1, record_data_len.saturating_sub(1));

    let first_data = &record_data[..data_offset];
    let second_data = &record_data[data_offset..record_data_len];

    debug!(
        data_offset,
        first_len = first_data.len(),
        second_len = second_data.len(),
        "ccs_inject: splitting ClientHello with CCS record between fragments"
    );

    // Build: [Handshake record 1] + [CCS record] + [Handshake record 2]
    // Total: (5 + first_data) + 6 + (5 + second_data) = 16 + record_data_len
    let total_len = 16 + record_data_len;
    let mut combined = Vec::with_capacity(total_len);

    // First Handshake record (before SNI).
    combined.push(CONTENT_TYPE_HANDSHAKE);
    combined.push(version_major);
    combined.push(version_minor);
    combined.extend_from_slice(&(first_data.len() as u16).to_be_bytes());
    combined.extend_from_slice(first_data);

    // Fake CCS record.
    // Use the same TLS version as the ClientHello for consistency.
    combined.push(CONTENT_TYPE_CCS);
    combined.push(version_major);
    combined.push(version_minor);
    combined.extend_from_slice(&(CCS_PAYLOAD.len() as u16).to_be_bytes());
    combined.extend_from_slice(&CCS_PAYLOAD);

    // Second Handshake record (contains SNI).
    combined.push(CONTENT_TYPE_HANDSHAKE);
    combined.push(version_major);
    combined.push(version_minor);
    combined.extend_from_slice(&(second_data.len() as u16).to_be_bytes());
    combined.extend_from_slice(second_data);

    Ok(DesyncAction::Replace(combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_client_hello;

    /// Total size of a CCS record: 5-byte header + 1-byte payload.
    const CCS_RECORD_LEN: usize = 6;

    #[test]
    fn test_ccs_inject_structure() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // Should be original + 5 (extra TLS header) + 6 (CCS record) = +11 bytes
                assert_eq!(new_payload.len(), payload.len() + 11);

                // First record: Handshake (0x16)
                assert_eq!(new_payload[0], CONTENT_TYPE_HANDSHAKE);
                let first_len =
                    u16::from_be_bytes([new_payload[3], new_payload[4]]) as usize;

                // CCS record starts right after first Handshake record
                let ccs_offset = 5 + first_len;
                assert_eq!(new_payload[ccs_offset], CONTENT_TYPE_CCS);
                let ccs_len = u16::from_be_bytes([
                    new_payload[ccs_offset + 3],
                    new_payload[ccs_offset + 4],
                ]) as usize;
                assert_eq!(ccs_len, 1);
                assert_eq!(new_payload[ccs_offset + 5], 0x01);

                // Second record: Handshake (0x16)
                let second_offset = ccs_offset + CCS_RECORD_LEN;
                assert_eq!(new_payload[second_offset], CONTENT_TYPE_HANDSHAKE);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_ccs_inject_preserves_data() {
        let payload = build_test_client_hello("test.example.org");
        let original_data_len = payload.len() - 5; // minus TLS header
        let ctx = PayloadContext::new(payload);

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // Extract data from first and second Handshake records
                let first_data_len =
                    u16::from_be_bytes([new_payload[3], new_payload[4]]) as usize;
                let second_offset = 5 + first_data_len + CCS_RECORD_LEN;
                let second_data_len = u16::from_be_bytes([
                    new_payload[second_offset + 3],
                    new_payload[second_offset + 4],
                ]) as usize;

                // All original record data must be preserved
                assert_eq!(first_data_len + second_data_len, original_data_len);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_ccs_inject_version_consistency() {
        let payload = build_test_client_hello("example.com");
        let version_major = payload[1];
        let version_minor = payload[2];
        let ctx = PayloadContext::new(payload);

        let result = apply(&ctx, &SplitPosition::Sni).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                // All three records should use the same TLS version
                // First record
                assert_eq!(new_payload[1], version_major);
                assert_eq!(new_payload[2], version_minor);

                let first_len =
                    u16::from_be_bytes([new_payload[3], new_payload[4]]) as usize;
                let ccs_offset = 5 + first_len;

                // CCS record
                assert_eq!(new_payload[ccs_offset + 1], version_major);
                assert_eq!(new_payload[ccs_offset + 2], version_minor);

                // Second record
                let second_offset = ccs_offset + CCS_RECORD_LEN;
                assert_eq!(new_payload[second_offset + 1], version_major);
                assert_eq!(new_payload[second_offset + 2], version_minor);
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_ccs_inject_non_tls_rejected() {
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
