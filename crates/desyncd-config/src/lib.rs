//! Configuration system for desyncd.
//!
//! Supports three-layer merge: defaults < config file < CLI args.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use desyncd_strategy::{MatchRule, Strategy};
use desyncd_types::{Mode, StealthConfig};

/// desyncd — Adaptive DPI Desynchronizer.
///
/// Lightweight, cross-platform DPI bypass tool with auto-adaptation.
/// Combines the power of zapret/nfqws with the simplicity of byedpi.
#[derive(Parser, Debug)]
#[command(name = "desyncd", version, about)]
pub struct Cli {
    /// Operating mode.
    #[arg(short, long, value_enum)]
    pub mode: Option<Mode>,

    /// Proxy listen address (for socks/transparent modes).
    #[arg(short, long)]
    pub listen: Option<SocketAddr>,

    /// Path to configuration file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Override strategy for all connections.
    #[arg(short, long)]
    pub strategy: Option<String>,

    /// Increase log verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the proxy/interceptor (default if no command given).
    Run,
    /// Run block detection tests against specified domains.
    Test {
        /// Domains to test.
        #[arg(short, long)]
        domain: Vec<String>,
        /// Try all available techniques and show results.
        #[arg(long)]
        all_techniques: bool,
    },
    /// Run auto-adaptation to find the best strategy for domains.
    Adapt {
        /// Domains to find strategies for.
        #[arg(short, long)]
        domain: Vec<String>,
        /// Read domains from a file (one per line).
        #[arg(long)]
        domains_file: Option<String>,
        /// Use a built-in preset: russia, china, iran.
        #[arg(long)]
        preset: Option<String>,
        /// Save discovered strategies and generate config.
        #[arg(long)]
        save: bool,
        /// Use protocol morphing (classify DPI first, then targeted search).
        #[arg(long)]
        morphing: bool,
    },
    /// Print effective configuration.
    ShowConfig,
    /// Launch the GUI application.
    Gui,
}

/// Configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub adaptation: AdaptationConfig,

    #[serde(default)]
    pub stealth: StealthConfig,

    #[serde(default)]
    pub strategies: HashMap<String, StrategyDef>,

    #[serde(default)]
    pub rules: Vec<MatchRule>,
}

/// Configuration for the auto-adaptation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_test_interval")]
    pub test_interval_secs: u64,

    #[serde(default)]
    pub test_domains: Vec<String>,

    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Use public DNS (Cloudflare/Google) instead of system DNS
    /// for probe resolution. Bypasses ISP DNS poisoning.
    #[serde(default = "default_true")]
    pub secure_dns: bool,
}

impl Default for AdaptationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            test_interval_secs: default_test_interval(),
            test_domains: Vec::new(),
            db_path: default_db_path(),
            secure_dns: true,
        }
    }
}

fn default_test_interval() -> u64 {
    21600
}

fn default_db_path() -> String {
    // On Windows the default lives under %APPDATA% (=%USERPROFILE%\AppData\Roaming),
    // matching where `dirs_path("data", ...)` resolves to. On Unix we keep the
    // XDG-style ~/.local/share path. The `~` prefix is expanded at load time
    // by `expand_tilde`, which uses USERPROFILE on Windows and HOME elsewhere.
    #[cfg(windows)]
    {
        "~/AppData/Roaming/desyncd/state.db".into()
    }
    #[cfg(not(windows))]
    {
        "~/.local/share/desyncd/state.db".into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: Mode,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            log_level: default_log_level(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    #[serde(default = "default_true")]
    pub socks5: bool,

    /// Auto-retry fallback chain. When non-empty, desyncd detects early RST
    /// from upstream after applying the primary strategy and reconnects to
    /// retry each listed technique in order. Inspired by byedpi's --auto=torst.
    #[serde(default)]
    pub auto_retry_fallback: Vec<desyncd_desync::technique::TechniqueConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            socks5: true,
            auto_retry_fallback: Vec::new(),
        }
    }
}

/// Strategy definition in config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyDef {
    pub techniques: Vec<desyncd_desync::technique::TechniqueConfig>,
}

fn default_mode() -> Mode {
    Mode::Socks
}
fn default_log_level() -> String {
    "info".into()
}
fn default_listen() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}
fn default_true() -> bool {
    true
}

/// Resolved configuration after merging all sources.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub mode: Mode,
    pub listen: SocketAddr,
    pub log_level: String,
    pub strategies: Vec<Strategy>,
    pub rules: Vec<MatchRule>,
    pub default_strategy: Option<String>,
    pub db_path: String,
    pub adaptation: AdaptationConfig,
    pub stealth: StealthConfig,
    /// Auto-retry fallback chain (empty = disabled).
    pub auto_retry_fallback: Vec<desyncd_desync::technique::TechniqueConfig>,
}

impl AppConfig {
    /// Load configuration from CLI args and optional config file.
    pub fn load(cli: &Cli) -> anyhow::Result<Self> {
        let config_file = if let Some(ref path) = cli.config {
            let content = std::fs::read_to_string(path)?;
            toml::from_str::<ConfigFile>(&content)?
        } else {
            // Try default locations.
            Self::try_load_default_config().unwrap_or_else(|| ConfigFile {
                general: GeneralConfig::default(),
                proxy: ProxyConfig::default(),
                adaptation: AdaptationConfig::default(),
                stealth: StealthConfig::default(),
                strategies: HashMap::new(),
                rules: Vec::new(),
            })
        };

        // Convert strategy definitions to Strategy objects.
        let strategies: Vec<Strategy> = config_file
            .strategies
            .into_iter()
            .map(|(name, def)| Strategy {
                name,
                techniques: def.techniques,
            })
            .collect();

        // Find default strategy (the one in the catch-all rule, or first defined).
        let default_strategy = config_file
            .rules
            .iter()
            .find(|r| r.domains.contains(&"*".to_string()))
            .map(|r| r.strategy.clone())
            .or_else(|| strategies.first().map(|s| s.name.clone()));

        // CLI overrides.
        let mode = cli.mode.unwrap_or(config_file.general.mode);
        let listen = cli.listen.unwrap_or(config_file.proxy.listen);

        let log_level = match cli.verbose {
            0 => config_file.general.log_level.clone(),
            1 => "debug".into(),
            _ => "trace".into(),
        };

        // If CLI specifies --strategy, use it as default.
        let default_strategy = cli
            .strategy
            .clone()
            .or(default_strategy);

        // If no strategies defined at all, use a built-in default.
        let strategies = if strategies.is_empty() {
            vec![Strategy {
                name: "default_tls".into(),
                techniques: vec![desyncd_desync::technique::TechniqueConfig {
                    name: "tcp_split".into(),
                    split_position: Some(desyncd_types::SplitPosition::Sni),
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    host_mode: None,
                    stealth: None,
                    l7_filter: None,
                }],
            }]
        } else {
            strategies
        };

        let default_strategy =
            default_strategy.or_else(|| Some("default_tls".into()));

        Ok(Self {
            mode,
            listen,
            log_level,
            strategies,
            rules: config_file.rules,
            default_strategy,
            db_path: config_file.adaptation.db_path.clone(),
            adaptation: config_file.adaptation,
            stealth: config_file.stealth,
            auto_retry_fallback: config_file.proxy.auto_retry_fallback,
        })
    }

    fn try_load_default_config() -> Option<ConfigFile> {
        let candidates = [
            dirs_path("config", "desyncd/config.toml"),
            Some(PathBuf::from("desyncd.toml")),
        ];

        for path in candidates.into_iter().flatten() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(config) = toml::from_str::<ConfigFile>(&content) {
                    tracing::info!(?path, "loaded config file");
                    return Some(config);
                }
            }
        }

        None
    }
}

fn dirs_path(base: &str, relative: &str) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").ok()?;
        match base {
            "config" => Some(PathBuf::from(home).join(".config").join(relative)),
            "data" => Some(PathBuf::from(home).join(".local/share").join(relative)),
            _ => None,
        }
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").ok()?;
        match base {
            "config" => {
                let xdg = std::env::var("XDG_CONFIG_HOME")
                    .unwrap_or_else(|_| format!("{}/.config", home));
                Some(PathBuf::from(xdg).join(relative))
            }
            "data" => {
                let xdg = std::env::var("XDG_DATA_HOME")
                    .unwrap_or_else(|_| format!("{}/.local/share", home));
                Some(PathBuf::from(xdg).join(relative))
            }
            _ => None,
        }
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        match base {
            "config" | "data" => Some(PathBuf::from(appdata).join(relative)),
            _ => None,
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}
