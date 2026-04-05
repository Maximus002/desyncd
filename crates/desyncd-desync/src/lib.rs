pub mod technique;
pub mod tcp_split;
pub mod tls_record_frag;
pub mod multi_stream_frag;
pub mod fake_packet;
pub mod disorder;
pub mod sni_manip;
pub mod http_host;
pub mod combo;
pub mod padding;

#[cfg(test)]
pub mod testutil;

use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};

use crate::technique::{TechniqueConfig, TechniqueRegistry};

/// Context for applying desync techniques.
///
/// This is created from the raw application payload (not IP/TCP headers)
/// when operating in SOCKS proxy mode. In NFQ mode, the full packet context
/// would be used instead.
pub struct PayloadContext {
    /// The raw application-layer payload (e.g., TLS ClientHello, HTTP request).
    pub payload: Vec<u8>,
    /// Detected application protocol and extracted metadata.
    pub protocol: AppProtocol,
}

impl PayloadContext {
    /// Create a new context by detecting the protocol from the payload.
    pub fn new(payload: Vec<u8>) -> Self {
        let protocol = desyncd_packet::detect_protocol(&payload);
        Self { payload, protocol }
    }

    /// Resolve a split position with optional jitter applied.
    pub fn resolve_split_position_with_jitter(
        &self,
        pos: &SplitPosition,
        jitter: u8,
    ) -> Option<usize> {
        let base = self.resolve_split_position(pos)?;
        if jitter == 0 {
            return Some(base);
        }
        let delta = fastrand::i32(-(jitter as i32)..=(jitter as i32));
        let result = (base as i64 + delta as i64).max(1).min(self.payload.len() as i64 - 1);
        Some(result as usize)
    }

    /// Resolve a `SplitPosition` to an absolute byte offset within the payload.
    pub fn resolve_split_position(&self, pos: &SplitPosition) -> Option<usize> {
        match pos {
            SplitPosition::Absolute(offset) => {
                if *offset < self.payload.len() {
                    Some(*offset)
                } else {
                    None
                }
            }
            SplitPosition::Sni => desyncd_packet::default_split_offset(&self.protocol),
            SplitPosition::SniOffset(delta) => {
                let base = desyncd_packet::default_split_offset(&self.protocol)?;
                let result = base as i64 + *delta as i64;
                if result >= 0 && (result as usize) < self.payload.len() {
                    Some(result as usize)
                } else {
                    None
                }
            }
            SplitPosition::Random { min, max } => {
                if *min >= *max || *max >= self.payload.len() {
                    return None;
                }
                Some(fastrand::usize(*min..*max))
            }
            SplitPosition::SniExtStart => {
                // 9 bytes before the SNI value covers: ext_type(2) +
                // ext_len(2) + server_name_list_len(2) + name_type(1) +
                // server_name_len(2). See RFC 6066 §3.
                // Gated on TLS-only to avoid matching HTTP payloads.
                let (_, sni_offset) = sni_with_offset(&self.protocol)?;
                sni_offset.checked_sub(9).filter(|o| *o < self.payload.len())
            }
            SplitPosition::EndSld => {
                let (sni, sni_offset) = sni_with_offset(&self.protocol)?;
                let sld_end = sld_range(sni)?.1;
                let abs = sni_offset + sld_end;
                if abs < self.payload.len() {
                    Some(abs)
                } else {
                    None
                }
            }
            SplitPosition::MidSld => {
                let (sni, sni_offset) = sni_with_offset(&self.protocol)?;
                let (start, end) = sld_range(sni)?;
                let mid = start + (end - start) / 2;
                let abs = sni_offset + mid;
                if abs < self.payload.len() {
                    Some(abs)
                } else {
                    None
                }
            }
            SplitPosition::OffsetFrom { marker, delta } => {
                let base = self.resolve_split_position(marker)?;
                let result = base as i64 + *delta as i64;
                if result >= 0 && (result as usize) < self.payload.len() {
                    Some(result as usize)
                } else {
                    None
                }
            }
        }
    }
}

/// Return (sni, sni_offset) if the protocol is a TLS ClientHello with SNI.
fn sni_with_offset(proto: &AppProtocol) -> Option<(&str, usize)> {
    match proto {
        AppProtocol::TlsClientHello {
            sni: Some(sni),
            sni_offset,
            ..
        } => Some((sni.as_str(), *sni_offset)),
        _ => None,
    }
}

/// Compute the (start, end) byte range of the second-level domain inside
/// an SNI hostname. Returns None if the hostname has fewer than two labels.
///
/// Examples:
/// - `www.twitter.com`  → `(4, 11)`  (covers "twitter")
/// - `twitter.com`      → `(0, 7)`   (covers "twitter")
/// - `a.b.c.example.org`→ `(6, 13)`  (covers "example")
/// - `localhost`        → `None`     (only one label)
///
/// This is a simple heuristic — no public-suffix-list awareness — but that
/// matches what byedpi/zapret's `endsld`/`midsld` markers do.
fn sld_range(hostname: &str) -> Option<(usize, usize)> {
    let bytes = hostname.as_bytes();
    // Find the last dot (separates TLD from SLD).
    let last_dot = bytes.iter().rposition(|&b| b == b'.')?;
    // SLD ends at last_dot. Search for the preceding dot to find SLD start.
    let sld_start = bytes[..last_dot]
        .iter()
        .rposition(|&b| b == b'.')
        .map(|p| p + 1)
        .unwrap_or(0);
    if sld_start >= last_dot {
        // Degenerate: two consecutive dots.
        return None;
    }
    Some((sld_start, last_dot))
}

/// Global default registry (created once per call — cheap since it's just vtable pointers).
fn default_registry() -> TechniqueRegistry {
    TechniqueRegistry::default()
}

/// Apply a technique described by `TechniqueConfig` to the payload context.
///
/// Reads `sni_mode`, `host_mode`, `fake_type`, and `stealth` from the config.
/// Falls back to defaults when the config fields are `None`.
pub fn apply_technique_cfg(
    config: &TechniqueConfig,
    ctx: &PayloadContext,
) -> Result<DesyncAction> {
    let split_pos = config
        .split_position
        .clone()
        .unwrap_or(SplitPosition::Sni);
    let stealth = config.stealth.as_ref();

    default_registry().apply(&config.name, ctx, &split_pos, config, stealth)
}

/// Apply a named technique to the payload context.
///
/// The optional `stealth` config controls jitter, fake record sizing, etc.
/// When called with a full `TechniqueConfig`, mode fields (sni_mode, host_mode,
/// fake_type) are respected; otherwise defaults are used.
pub fn apply_technique(
    name: &str,
    ctx: &PayloadContext,
    split_pos: &SplitPosition,
    stealth: Option<&StealthConfig>,
    config: &TechniqueConfig,
) -> Result<DesyncAction> {
    default_registry().apply(name, ctx, split_pos, config, stealth)
}

#[cfg(test)]
mod split_position_tests {
    use super::*;
    use crate::testutil::build_test_client_hello;

    #[test]
    fn sld_range_simple() {
        assert_eq!(sld_range("twitter.com"), Some((0, 7)));
        assert_eq!(sld_range("www.twitter.com"), Some((4, 11)));
        assert_eq!(sld_range("a.b.example.org"), Some((4, 11)));
        assert_eq!(sld_range("localhost"), None);
        assert_eq!(sld_range(""), None);
    }

    #[test]
    fn sni_ext_start_is_nine_bytes_before_sni() {
        let ctx = PayloadContext::new(build_test_client_hello("twitter.com"));
        let sni = ctx.resolve_split_position(&SplitPosition::Sni).unwrap();
        let ext = ctx.resolve_split_position(&SplitPosition::SniExtStart).unwrap();
        assert_eq!(ext, sni - 9);
        // And the bytes at ext..ext+2 should be the SNI extension type 0x0000.
        assert_eq!(&ctx.payload[ext..ext + 2], &[0x00, 0x00]);
    }

    #[test]
    fn end_sld_falls_between_sld_and_tld() {
        // "www.twitter.com": SLD is "twitter" at positions 4..11 within SNI.
        let ctx = PayloadContext::new(build_test_client_hello("www.twitter.com"));
        let sni_start = ctx.resolve_split_position(&SplitPosition::Sni).unwrap();
        let end_sld = ctx.resolve_split_position(&SplitPosition::EndSld).unwrap();
        assert_eq!(end_sld, sni_start + 11);
        // The byte at end_sld should be '.'.
        assert_eq!(ctx.payload[end_sld], b'.');
    }

    #[test]
    fn mid_sld_lands_inside_sld() {
        // "twitter.com": SLD "twitter" is 7 bytes, middle offset = 3.
        let ctx = PayloadContext::new(build_test_client_hello("twitter.com"));
        let sni_start = ctx.resolve_split_position(&SplitPosition::Sni).unwrap();
        let mid = ctx.resolve_split_position(&SplitPosition::MidSld).unwrap();
        assert_eq!(mid, sni_start + 3);
        assert_eq!(ctx.payload[mid], b't'); // "twi[t]ter"
    }

    #[test]
    fn offset_from_marker_adds_delta() {
        let ctx = PayloadContext::new(build_test_client_hello("twitter.com"));
        let sni_start = ctx.resolve_split_position(&SplitPosition::Sni).unwrap();

        // EndSld points to the dot after "twitter" (sni_start + 7). Subtracting
        // 2 lands inside the SLD at sni_start + 5 — the 'e' in "twitt[e]r".
        let tamper = ctx
            .resolve_split_position(&SplitPosition::OffsetFrom {
                marker: Box::new(SplitPosition::EndSld),
                delta: -2,
            })
            .unwrap();
        assert_eq!(tamper, sni_start + 5);
        assert_eq!(ctx.payload[tamper], b'e'); // "twitt[e]r"
    }

    #[test]
    fn markers_return_none_when_no_sni() {
        // Non-TLS payload: resolve should return None for all marker variants.
        let ctx = PayloadContext::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
        assert!(ctx.resolve_split_position(&SplitPosition::SniExtStart).is_none());
        assert!(ctx.resolve_split_position(&SplitPosition::EndSld).is_none());
        assert!(ctx.resolve_split_position(&SplitPosition::MidSld).is_none());
    }
}
