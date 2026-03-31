//! Technique trait and registry.
//!
//! Defines the interface for all DPI bypass techniques and provides
//! a registry for looking them up by name.

use serde::{Deserialize, Serialize};

use desyncd_types::SplitPosition;

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

    /// SNI manipulation mode (for "sni_manip" technique).
    #[serde(default)]
    pub sni_mode: Option<String>,

    /// HTTP Host manipulation mode (for "http_host" technique).
    #[serde(default)]
    pub host_mode: Option<String>,

    /// Per-technique stealth overrides.
    #[serde(default)]
    pub stealth: Option<desyncd_types::StealthConfig>,
}

fn default_true() -> bool {
    true
}

/// List of all available technique names.
pub fn available_techniques() -> &'static [&'static str] {
    &[
        "tcp_split",
        "tls_record_frag",
        "fake_packet",
        "disorder",
        "sni_manip",
        "http_host",
    ]
}
