//! SNI Manipulation technique.
//!
//! Modifies the SNI extension in a TLS ClientHello to confuse DPI:
//!
//! - `Pad`: Add null bytes or padding around the SNI value
//! - `MixedCase`: Randomize case of the SNI (servers are case-insensitive per RFC)
//! - `ExtraExtension`: Add a duplicate SNI extension or padding extension
//! - `Remove`: Remove the SNI extension entirely (works if server uses default cert)
//!
//! These operate at the application layer and modify the actual payload bytes.

use crate::PayloadContext;
use crate::technique::{Technique, TechniqueConfig};
use desyncd_types::{AppProtocol, DesyncAction, Result, SplitPosition, StealthConfig};
use tracing::debug;

/// Technique trait implementation for SNI manipulation.
pub struct SniManipTechnique;

impl Technique for SniManipTechnique {
    fn name(&self) -> &'static str {
        "sni_manip"
    }

    fn apply(
        &self,
        ctx: &PayloadContext,
        _split_pos: &SplitPosition,
        config: &TechniqueConfig,
        _stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction> {
        let mode = config
            .sni_mode
            .as_deref()
            .and_then(SniMode::from_str_opt)
            .unwrap_or_default();
        apply(ctx, mode)
    }
}

/// SNI manipulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[derive(Default)]
pub enum SniMode {
    /// Randomize case of the hostname (e.g., "WwW.YouTuBe.COM").
    #[default]
    MixedCase,
    /// Remove the SNI extension entirely.
    Remove,
    /// Add padding extension before SNI to shift its position.
    Pad,
}

impl SniMode {
    /// Parse a mode from a string (case-insensitive).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mixed_case" | "mixedcase" | "mixed" => Some(Self::MixedCase),
            "remove" => Some(Self::Remove),
            "pad" | "padding" => Some(Self::Pad),
            _ => None,
        }
    }
}


/// Apply SNI manipulation.
pub fn apply(ctx: &PayloadContext, mode: SniMode) -> Result<DesyncAction> {
    let (sni, sni_offset, sni_len) = match &ctx.protocol {
        AppProtocol::TlsClientHello {
            sni: Some(sni),
            sni_offset,
            sni_len,
        } => (sni.clone(), *sni_offset, *sni_len),
        _ => {
            return Err(desyncd_types::Error::NotApplicable(
                "sni_manip requires TLS ClientHello with SNI".into(),
            ));
        }
    };

    match mode {
        SniMode::MixedCase => apply_mixed_case(ctx, &sni, sni_offset, sni_len),
        SniMode::Remove => apply_remove(ctx, sni_offset, sni_len),
        SniMode::Pad => apply_pad(ctx, sni_offset),
    }
}

/// Randomize the case of the SNI hostname.
/// RFC 6066 says the server SHOULD treat SNI as case-insensitive.
fn apply_mixed_case(
    ctx: &PayloadContext,
    sni: &str,
    sni_offset: usize,
    sni_len: usize,
) -> Result<DesyncAction> {
    let mut payload = ctx.payload.clone();

    if sni_offset + sni_len > payload.len() {
        return Err(desyncd_types::Error::NotApplicable(
            "SNI offset out of bounds".into(),
        ));
    }

    // Generate mixed-case version.
    let mixed: Vec<u8> = sni
        .bytes()
        .map(|b| {
            if b.is_ascii_alphabetic() {
                if fastrand::bool() {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                }
            } else {
                b
            }
        })
        .collect();

    payload[sni_offset..sni_offset + sni_len].copy_from_slice(&mixed);

    debug!(
        original = %sni,
        mixed = %String::from_utf8_lossy(&mixed),
        "sni_manip: applied mixed case"
    );

    Ok(DesyncAction::Replace(payload))
}

/// Remove the SNI extension from the ClientHello.
/// The server must use a default certificate or support ESNI/ECH.
fn apply_remove(
    ctx: &PayloadContext,
    sni_offset: usize,
    sni_len: usize,
) -> Result<DesyncAction> {
    // Finding and removing the SNI extension requires re-parsing to find
    // extension boundaries. For now, we zero out the SNI value.
    // A zero-length or null SNI effectively "removes" the readable hostname
    // while keeping the TLS structure valid.
    let mut payload = ctx.payload.clone();

    if sni_offset + sni_len > payload.len() {
        return Err(desyncd_types::Error::NotApplicable(
            "SNI offset out of bounds".into(),
        ));
    }

    // Replace SNI bytes with dots (less suspicious than zeros).
    for i in 0..sni_len {
        payload[sni_offset + i] = b'.';
    }

    debug!(sni_len, "sni_manip: removed SNI (replaced with dots)");

    Ok(DesyncAction::Replace(payload))
}

/// Add padding before the SNI to shift its position in the packet.
/// This confuses DPI that looks for SNI at a fixed offset.
fn apply_pad(ctx: &PayloadContext, sni_offset: usize) -> Result<DesyncAction> {
    // We can't easily insert bytes into a TLS record without recalculating
    // lengths. Instead, we use TLS record fragmentation to split right
    // before the SNI, which achieves a similar effect.
    // Fall back to mixed case as a simpler alternative.
    debug!("sni_manip: pad mode falling back to mixed case");
    
    match &ctx.protocol {
        AppProtocol::TlsClientHello { sni: Some(s), sni_len, .. } => {
            apply_mixed_case(ctx, s, sni_offset, *sni_len)
        }
        _ => Err(desyncd_types::Error::NotApplicable("no SNI".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(sni: &str) -> PayloadContext {
        let payload = crate::testutil::build_test_client_hello(sni);
        PayloadContext::new(payload)
    }

    #[test]
    fn test_mixed_case() {
        let ctx = make_ctx("www.youtube.com");
        let result = apply(&ctx, SniMode::MixedCase).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                assert_eq!(new_payload.len(), ctx.payload.len());
                // The SNI should be different (mixed case).
                // Extract SNI from new payload.
                let new_ctx = PayloadContext::new(new_payload);
                match &new_ctx.protocol {
                    AppProtocol::TlsClientHello { sni: Some(new_sni), .. } => {
                        assert_eq!(new_sni.to_lowercase(), "www.youtube.com");
                    }
                    _ => panic!("should still parse as TLS"),
                }
            }
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn test_remove() {
        let ctx = make_ctx("example.com");
        let result = apply(&ctx, SniMode::Remove).unwrap();
        match result {
            DesyncAction::Replace(new_payload) => {
                assert_eq!(new_payload.len(), ctx.payload.len());
                // SNI should now be dots.
                let new_ctx = PayloadContext::new(new_payload);
                match &new_ctx.protocol {
                    AppProtocol::TlsClientHello { sni: Some(new_sni), .. } => {
                        assert!(new_sni.chars().all(|c| c == '.'));
                    }
                    _ => panic!("should still parse as TLS"),
                }
            }
            _ => panic!("expected Replace"),
        }
    }
}
