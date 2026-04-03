//! CCS Injection (ChangeCipherSpec Pre-Injection) technique.
//!
//! Exploits how DPI state machines track TLS handshake progress.
//! Sends a fake TLS ChangeCipherSpec (CCS) record BEFORE the real
//! ClientHello, causing the DPI to believe encryption has already begun
//! when it encounters the actual handshake data.
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
//! We exploit this by sending data in separate TCP segments:
//!   Segment 1: [CCS record]    → DPI: "ah, encryption started"
//!   Segment 2: [ClientHello]   → DPI: ignores (thinks it's encrypted)
//!                               → Server: processes CH normally
//!
//! ## Why the server tolerates it
//!
//! The CCS is sent as a separate TCP segment BEFORE the ClientHello.
//! Critically, both arrive on the same TCP connection, but:
//!
//! - In TLS 1.3 (RFC 8446 §D.4): servers MUST accept and ignore CCS
//!   at any point during the handshake (middlebox compatibility mode).
//! - In TLS 1.2: most implementations simply ignore unexpected CCS
//!   that arrives before the handshake is established, since there's
//!   no cipher state to change yet.
//!
//! ## Output format
//!
//! Returns `DesyncAction::Split` with two chunks:
//! - Chunk 0: CCS record (6 bytes: 5-byte TLS header + 1-byte payload)
//! - Chunk 1: Original ClientHello (unmodified)
//!
//! The action executor sends each chunk as a separate TCP segment
//! (TCP_NODELAY is enabled on upstream).

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for CCS injection.
pub struct CcsInjectTechnique;

/// TLS content types.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_CCS: u8 = 0x14;

/// Pre-built CCS record: content_type(1) + version(2) + length(2) + payload(1).
/// Version 0x0303 = TLS 1.2 (used in both TLS 1.2 and 1.3 records).
const CCS_RECORD: [u8; 6] = [
    CONTENT_TYPE_CCS,
    0x03, 0x03,         // TLS 1.2 record version
    0x00, 0x01,         // length = 1
    0x01,               // CCS message: change_cipher_spec
];

impl Technique for CcsInjectTechnique {
    fn name(&self) -> &'static str {
        "ccs_inject"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        _split_pos: &SplitPosition,
        _config: &TechniqueConfig,
        _stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        apply(ctx)
    }
}

/// Apply CCS injection: prepend a CCS record before the ClientHello.
///
/// The CCS and ClientHello are sent as separate TCP segments.
/// DPI sees CCS first → transitions to "encrypted" state → ignores the CH.
pub fn apply(ctx: &PayloadContext) -> Result<DesyncAction> {
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

    debug!(
        ch_len = ctx.payload.len(),
        "ccs_inject: prepending CCS record before ClientHello"
    );

    // Split: [CCS record] then [original ClientHello, unmodified]
    Ok(DesyncAction::Split(vec![
        CCS_RECORD.to_vec(),
        ctx.payload.clone(),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_client_hello;

    #[test]
    fn test_ccs_inject_produces_split() {
        let payload = build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                assert_eq!(chunks.len(), 2);

                // First chunk: CCS record
                assert_eq!(chunks[0].len(), 6);
                assert_eq!(chunks[0][0], CONTENT_TYPE_CCS);
                assert_eq!(chunks[0][3], 0x00);
                assert_eq!(chunks[0][4], 0x01); // length = 1
                assert_eq!(chunks[0][5], 0x01); // CCS message

                // Second chunk: original ClientHello, unmodified
                assert_eq!(chunks[1], payload);
            }
            _ => panic!("expected Split, got {:?}", result),
        }
    }

    #[test]
    fn test_ccs_inject_preserves_clienthello() {
        let payload = build_test_client_hello("test.example.org");
        let ctx = PayloadContext::new(payload.clone());

        let result = apply(&ctx).unwrap();
        match result {
            DesyncAction::Split(chunks) => {
                // ClientHello must be byte-for-byte identical
                assert_eq!(chunks[1], payload);
            }
            _ => panic!("expected Split"),
        }
    }

    #[test]
    fn test_ccs_record_is_valid_tls() {
        // Verify the CCS record structure
        assert_eq!(CCS_RECORD[0], 0x14); // content type: CCS
        assert_eq!(CCS_RECORD[1], 0x03); // version major
        assert_eq!(CCS_RECORD[2], 0x03); // version minor (TLS 1.2)
        let length = u16::from_be_bytes([CCS_RECORD[3], CCS_RECORD[4]]);
        assert_eq!(length, 1);
        assert_eq!(CCS_RECORD[5], 0x01); // the CCS message itself
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
        assert!(apply(&ctx).is_err());
    }
}
