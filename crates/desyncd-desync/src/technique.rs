//! Technique trait and registry.
//!
//! Defines the interface for all DPI bypass techniques and provides
//! a registry for looking them up by name.
//!
//! ## Adding a new technique
//!
//! 1. Create a new module (e.g., `my_technique.rs`) implementing [`Technique`].
//! 2. Add `pub mod my_technique;` to `lib.rs`.
//! 3. Register it in [`TechniqueRegistry::default()`].
//!
//! That's it — the strategy engine, probe, and CLI will pick it up automatically.

use serde::{Deserialize, Serialize};

use crate::PayloadContext;
use desyncd_types::{DesyncAction, L7Filter, Result, SplitPosition, StealthConfig};

/// Configuration for a single technique within a strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueConfig {
    /// Technique name (e.g., "tcp_split", "tls_record_frag").
    pub name: String,

    /// Where to split the payload (applies to split-based techniques).
    #[serde(default)]
    pub split_position: Option<SplitPosition>,

    /// Whether this technique is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Fake packet type (for "fake_packet" technique).
    #[serde(default)]
    pub fake_type: Option<desyncd_types::FakeType>,

    /// SNI manipulation mode (for "sni_manip" technique, e.g. "MixedCase").
    #[serde(default)]
    pub sni_mode: Option<String>,

    /// Number of TLS record fragments (for "multi_stream_frag" technique).
    /// When unset, the technique uses its built-in default (3). Values are
    /// clamped to a reasonable range at apply time. This field replaces the
    /// earlier hack of reusing `sni_mode` as a stringly-typed integer.
    #[serde(default)]
    pub fragments: Option<usize>,

    /// HTTP Host manipulation mode (for "http_host" technique).
    #[serde(default)]
    pub host_mode: Option<String>,

    /// Per-technique stealth overrides.
    #[serde(default)]
    pub stealth: Option<desyncd_types::StealthConfig>,

    /// L7 protocol filter — only apply this technique if the detected
    /// application-layer protocol matches. `None` means apply to any. Lets
    /// a single strategy chain different techniques per protocol
    /// (byedpi's `--filter-l7 tls`/`--filter-l7 http` equivalent).
    #[serde(default)]
    pub l7_filter: Option<L7Filter>,
}

fn default_true() -> bool {
    true
}

/// The core trait for all DPI bypass techniques.
///
/// Each technique receives the payload context + its config, and returns
/// a `DesyncAction` describing how to modify/send the data.
pub trait Technique: Send + Sync {
    /// Unique name of this technique (e.g., "tcp_split").
    fn name(&self) -> &'static str;

    /// Apply the technique to the given payload.
    ///
    /// `split_pos` is the effective (jitter-resolved) split position.
    /// `config` provides technique-specific options (sni_mode, fake_type, etc.).
    /// `stealth` provides global stealth options.
    fn apply(
        &self,
        ctx: &PayloadContext,
        split_pos: &SplitPosition,
        config: &TechniqueConfig,
        stealth: Option<&StealthConfig>,
    ) -> Result<DesyncAction>;
}

/// Registry of all available techniques.
///
/// Holds boxed trait objects, keyed by name. The `apply` method looks up
/// the technique by name and delegates to its `Technique::apply`.
pub struct TechniqueRegistry {
    techniques: Vec<Box<dyn Technique>>,
}

impl TechniqueRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            techniques: Vec::new(),
        }
    }

    /// Register a technique.
    pub fn register(&mut self, technique: Box<dyn Technique>) {
        self.techniques.push(technique);
    }

    /// Look up a technique by name.
    pub fn get(&self, name: &str) -> Option<&dyn Technique> {
        self.techniques
            .iter()
            .find(|t| t.name() == name)
            .map(|t| t.as_ref())
    }

    /// List all registered technique names.
    pub fn available_names(&self) -> Vec<&'static str> {
        self.techniques.iter().map(|t| t.name()).collect()
    }

    /// Apply a named technique to a payload context.
    ///
    /// Resolves split position (with optional jitter), looks up the technique
    /// by name, and delegates.
    pub fn apply(
        &self,
        name: &str,
        ctx: &PayloadContext,
        split_pos: &SplitPosition,
        config: &TechniqueConfig,
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

        match self.get(name) {
            Some(technique) => technique.apply(ctx, &effective_pos, config, stealth),
            None => Err(desyncd_types::Error::NotApplicable(format!(
                "unknown technique: {}",
                name
            ))),
        }
    }
}

impl Default for TechniqueRegistry {
    /// Create a registry with all built-in techniques.
    fn default() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(super::tcp_split::TcpSplitTechnique));
        reg.register(Box::new(super::tls_record_frag::TlsRecordFragTechnique));
        reg.register(Box::new(super::multi_stream_frag::MultiStreamFragTechnique));
        reg.register(Box::new(super::fake_packet::FakePacketTechnique));
        reg.register(Box::new(super::disorder::DisorderTechnique));
        reg.register(Box::new(super::sni_manip::SniManipTechnique));
        reg.register(Box::new(super::http_host::HttpHostTechnique));
        reg
    }
}

/// List of all available technique names (convenience for backward compat).
pub fn available_techniques() -> &'static [&'static str] {
    &[
        "tcp_split",
        "tls_record_frag",
        "multi_stream_frag",
        "fake_packet",
        "disorder",
        "sni_manip",
        "http_host",
    ]
}
