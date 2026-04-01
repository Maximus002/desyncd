//! Fake Packet Injection technique.
//!
//! Injects a fake packet containing a bogus ClientHello (with random/wrong SNI)
//! BEFORE the real one. The fake must not reach the real server — this is achieved
//! by corrupting the packet in ways that intermediate routers or the server will
//! reject, but DPI typically won't check:
//!
//! - `BadChecksum`: Corrupt TCP checksum (fails if behind NAT that recalculates)
//! - `BadTtl`: Set TTL so packet expires before reaching the server
//! - `BadMd5Sig`: Add TCP MD5 signature option (Linux servers drop these)
//! - `BadSeq`: Use wrong TCP sequence number
//!
//! In SOCKS proxy mode, we can only generate fake application-layer data
//! (since we operate on a regular TCP socket, not raw packets). The full
//! fake packet injection with TTL/checksum manipulation requires NFQ mode.
//!
//! In SOCKS mode, we use a simulated approach: send garbage TLS record
//! before the real ClientHello. Some DPI systems will try to parse the
//! first TLS record and get confused by the fake data.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, FakeType, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for fake packet injection.
pub struct FakePacketTechnique;

impl Technique for FakePacketTechnique {
    fn name(&self) -> &'static str {
        "fake_packet"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        _split_pos: &SplitPosition,
        config: &TechniqueConfig,
        stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        let mut fake_config = FakeConfig::default();
        if let Some(ref ft) = config.fake_type {
            fake_config.fake_type = *ft;
        }
        apply_socks(ctx, &fake_config, stealth)
    }
}

/// Configuration for fake packet injection.
#[derive(Debug, Clone)]
pub struct FakeConfig {
    /// How to make the fake undeliverable (for NFQ mode).
    pub fake_type: FakeType,
    /// TTL value for BadTtl mode (typically 1-4).
    pub ttl: u8,
    /// Number of fake packets to inject.
    pub repeats: u32,
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self {
            fake_type: FakeType::BadTtl,
            ttl: 3,
            repeats: 1,
        }
    }
}

/// Apply fake packet injection (SOCKS mode variant).
///
/// In SOCKS mode, we can't manipulate IP/TCP headers, so we generate
/// a fake TLS record with garbage content that precedes the real ClientHello.
/// Some DPI systems process the first TLS record they see and miss the real one.
pub fn apply_socks(ctx: &PayloadContext, config: &FakeConfig, stealth: Option<&StealthConfig>) -> Result<DesyncAction> {
    match &ctx.protocol {
        AppProtocol::TlsClientHello { .. } => {}
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "fake_packet requires TLS ClientHello".into(),
            ));
        }
    }

    let mut fake_chunks = Vec::new();

    for _ in 0..config.repeats {
        let fake = build_fake_tls_record(stealth);
        fake_chunks.push(fake);
    }

    debug!(
        repeats = config.repeats,
        fake_type = ?config.fake_type,
        "fake_packet: generating fake TLS records for SOCKS mode"
    );

    Ok(DesyncAction::InjectBefore(fake_chunks))
}

/// Apply fake packet injection (NFQ mode variant).
///
/// Returns raw fake IP packets that should be injected before the real packet.
/// The caller (NFQ handler) is responsible for setting the appropriate
/// TTL, checksum corruption, or TCP options based on `fake_type`.
pub fn build_fake_payload(
    original_payload: &[u8],
    sni: Option<&str>,
) -> Vec<u8> {
    // Build a fake ClientHello with a random SNI.
    let fake_sni = sni
        .map(scramble_sni)
        .unwrap_or_else(|| "decoy.example.com".to_string());

    build_fake_client_hello(&fake_sni, original_payload.len())
}

/// Build a fake TLS record (for SOCKS mode).
///
/// Creates a TLS record that looks plausible but contains garbage data.
/// With stealth config, randomizes size and record type to defeat ML classifiers.
fn build_fake_tls_record(stealth: Option<&StealthConfig>) -> Vec<u8> {
    let fake_data_len: usize = match stealth.and_then(|s| s.fake_size_range) {
        Some((min, max)) if min < max => fastrand::usize(min..=max),
        _ => 64,
    };

    let mut record = Vec::with_capacity(5 + fake_data_len);

    // Vary TLS content type to make fingerprinting harder.
    let content_type: u8 = match fastrand::u8(0..10) {
        0..=6 => 0x16, // Handshake (70%)
        7..=8 => 0x17, // ApplicationData (20%)
        _ => 0x14,     // ChangeCipherSpec (10%)
    };

    record.push(content_type);
    record.push(0x03);
    record.push(fastrand::u8(1..=3)); // TLS 1.0-1.2
    record.extend_from_slice(&(fake_data_len as u16).to_be_bytes());

    if content_type == 0x16 && fake_data_len >= 4 {
        // Fake handshake header.
        record.push(0x01); // ClientHello type
        let body_len = fake_data_len - 4;
        record.push(0x00);
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        for _ in 0..body_len {
            record.push(fastrand::u8(..));
        }
    } else {
        // Pure random payload for non-handshake types.
        for _ in 0..fake_data_len {
            record.push(fastrand::u8(..));
        }
    }

    record
}

/// Build a fake TLS ClientHello with the given SNI (for NFQ mode).
fn build_fake_client_hello(sni: &str, target_len: usize) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
    let sni_ext_len = 4 + sni_ext_data_len;
    let extensions_len = sni_ext_len;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let hs_len = 4 + ch_body_len;

    let mut buf = Vec::with_capacity(5 + hs_len);

    // TLS record header.
    buf.push(0x16);
    buf.extend_from_slice(&0x0301u16.to_be_bytes());
    buf.extend_from_slice(&(hs_len as u16).to_be_bytes());

    // Handshake header.
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());

    // ClientHello body.
    buf.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2

    // Random (32 bytes).
    for _ in 0..32 {
        buf.push(fastrand::u8(..));
    }

    buf.push(0); // session_id_len = 0
    buf.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
    buf.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    buf.push(1); // compression_methods_len
    buf.push(0); // null compression

    // Extensions.
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    // SNI extension.
    buf.extend_from_slice(&0u16.to_be_bytes()); // SNI extension type
    buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    let sni_list_len = 1 + 2 + sni_bytes.len();
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00); // hostname type
    buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);

    // Pad to approximately match original packet size to look less suspicious.
    if buf.len() < target_len {
        // Add padding extension (type 0x0015).
        // We'd need to rebuild the extensions, but for now just pad with zeros.
        // The fake doesn't need to be perfectly valid — it just needs to fool DPI.
    }

    buf
}

/// Scramble an SNI to produce a decoy that looks different but plausible.
fn scramble_sni(sni: &str) -> String {
    // Simple approach: reverse domain labels and add a prefix.
    let parts: Vec<&str> = sni.split('.').collect();
    if parts.len() >= 2 {
        format!(
            "www.{}.{}",
            parts[parts.len() - 1],
            parts[parts.len() - 2]
        )
    } else {
        format!("decoy.{}", sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_tls_record_is_valid_structure() {
        let record = build_fake_tls_record(None);
        assert!(record.len() >= 5);
        // Content type should be a valid TLS record type.
        assert!(
            record[0] == 0x14 || record[0] == 0x16 || record[0] == 0x17,
            "unexpected content type: 0x{:02x}", record[0]
        );
        assert_eq!(record[1], 0x03); // TLS major version
        assert!(record[2] >= 1 && record[2] <= 3); // TLS minor 1.0-1.2
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), 5 + len);
    }

    #[test]
    fn test_fake_tls_record_stealth_size_range() {
        use desyncd_types::StealthConfig;
        let stealth = StealthConfig {
            fake_size_range: Some((100, 200)),
            ..Default::default()
        };
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..20 {
            let record = build_fake_tls_record(Some(&stealth));
            let len = u16::from_be_bytes([record[3], record[4]]) as usize;
            assert!(len >= 100 && len <= 200, "size {} out of range", len);
            assert_eq!(record.len(), 5 + len);
            sizes.insert(len);
        }
        // Should have at least a few different sizes.
        assert!(sizes.len() >= 3, "expected size variation, got {:?}", sizes);
    }

    #[test]
    fn test_fake_client_hello_contains_sni() {
        let fake = build_fake_client_hello("fake.example.com", 200);
        // Should start with TLS record header.
        assert_eq!(fake[0], 0x16);
        // Should contain the fake SNI.
        let sni = b"fake.example.com";
        assert!(fake.windows(sni.len()).any(|w| w == sni));
    }

    #[test]
    fn test_scramble_sni() {
        let result = scramble_sni("www.youtube.com");
        assert_ne!(result, "www.youtube.com");
        assert!(result.contains('.'));
    }

    #[test]
    fn test_apply_socks_mode() {
        let payload = crate::testutil::build_test_client_hello("example.com");
        let ctx = PayloadContext::new(payload);
        let config = FakeConfig::default();
        let result = apply_socks(&ctx, &config, None).unwrap();
        match result {
            DesyncAction::InjectBefore(chunks) => {
                assert_eq!(chunks.len(), 1);
                // Content type is randomized: 0x14 (CCS), 0x16 (Handshake), 0x17 (AppData)
                assert!(
                    chunks[0][0] == 0x14 || chunks[0][0] == 0x16 || chunks[0][0] == 0x17,
                    "unexpected TLS content type: {:#x}", chunks[0][0]
                );
            }
            _ => panic!("expected InjectBefore"),
        }
    }
}
