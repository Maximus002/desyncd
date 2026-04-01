//! Auto-adaptation engine for desyncd.
//!
//! Automatically discovers the best DPI bypass strategy for each domain
//! by probing with different techniques and scoring the results.

pub mod dns;
pub mod probe;
pub mod search;
pub mod scheduler;

use desyncd_store::Store;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the adaptation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptConfig {
    /// Whether auto-adaptation is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Interval between automatic re-tests (seconds).
    #[serde(default = "default_interval")]
    pub test_interval_secs: u64,

    /// Domains to test periodically.
    #[serde(default)]
    pub test_domains: Vec<String>,

    /// Maximum number of probes per domain per search.
    #[serde(default = "default_max_probes")]
    pub max_probes: usize,

    /// Timeout per probe.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Path to the SQLite database.
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Use public DNS (Cloudflare 1.1.1.1, Google 8.8.8.8) instead of
    /// system DNS for probe resolution. Bypasses ISP DNS poisoning.
    #[serde(default = "default_true")]
    pub secure_dns: bool,
}

impl Default for AdaptConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            test_interval_secs: default_interval(),
            test_domains: Vec::new(),
            max_probes: default_max_probes(),
            timeout_secs: default_timeout(),
            db_path: default_db_path(),
            secure_dns: true,
        }
    }
}

impl AdaptConfig {
    pub fn test_interval(&self) -> Duration {
        Duration::from_secs(self.test_interval_secs)
    }

    pub fn probe_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

fn default_true() -> bool {
    true
}
fn default_interval() -> u64 {
    21600 // 6 hours
}
fn default_max_probes() -> usize {
    40
}
fn default_timeout() -> u64 {
    10
}
fn default_db_path() -> String {
    "~/.local/share/desyncd/state.db".into()
}

/// The adaptation engine.
pub struct AdaptEngine {
    pub store: Store,
    pub config: AdaptConfig,
}

impl AdaptEngine {
    /// Create a new engine with the given store and config.
    pub fn new(store: Store, config: AdaptConfig) -> Self {
        Self { store, config }
    }
}
