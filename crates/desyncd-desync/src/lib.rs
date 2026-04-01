pub mod technique;
pub mod tcp_split;
pub mod tls_record_frag;
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
        }
    }
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
