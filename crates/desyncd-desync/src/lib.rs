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
                if *offset > 0 && *offset < self.payload.len() {
                    Some(*offset)
                } else {
                    None
                }
            }
            SplitPosition::Sni => desyncd_packet::default_split_offset(&self.protocol),
            SplitPosition::SniOffset(delta) => {
                let base = desyncd_packet::default_split_offset(&self.protocol)?;
                let result = base as i64 + *delta as i64;
                if result > 0 && (result as usize) < self.payload.len() {
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

/// Apply a named technique to the payload context.
///
/// The optional `stealth` config controls jitter, fake record sizing, etc.
pub fn apply_technique(
    name: &str,
    ctx: &PayloadContext,
    split_pos: &SplitPosition,
    stealth: Option<&StealthConfig>,
) -> Result<DesyncAction> {
    // Resolve split position with optional jitter.
    let jitter = stealth.map_or(0, |s| s.split_jitter);
    let effective_pos = if jitter > 0 {
        ctx.resolve_split_position_with_jitter(split_pos, jitter)
            .map(SplitPosition::Absolute)
            .unwrap_or_else(|| split_pos.clone())
    } else {
        split_pos.clone()
    };

    match name {
        "tcp_split" => tcp_split::apply(ctx, &effective_pos),
        "tls_record_frag" => tls_record_frag::apply(ctx, &effective_pos),
        "fake_packet" => fake_packet::apply_socks(ctx, &fake_packet::FakeConfig::default(), stealth),
        "disorder" => disorder::apply(ctx, &effective_pos),
        "sni_manip" => sni_manip::apply(ctx, sni_manip::SniMode::default()),
        "http_host" => http_host::apply(ctx, http_host::HostMode::default()),
        _ => Err(desyncd_types::Error::NotApplicable(format!(
            "unknown technique: {}",
            name
        ))),
    }
}
