#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tokio::sync::oneshot;

use desyncd_config::AppConfig;
use desyncd_strategy::Selector;

/// Application state shared across Tauri commands.
struct AppState {
    /// Current proxy status.
    status: Mutex<ProxyStatus>,
    /// Shutdown signal sender (if proxy is running).
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyStatus {
    running: bool,
    mode: String,
    listen: String,
    connections: u64,
}

impl Default for ProxyStatus {
    fn default() -> Self {
        Self {
            running: false,
            mode: "socks".into(),
            listen: "127.0.0.1:1080".into(),
            connections: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigResponse {
    mode: String,
    listen: String,
    log_level: String,
    strategies: Vec<StrategyInfo>,
    rules: Vec<RuleInfo>,
    stealth: StealthInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StrategyInfo {
    name: String,
    techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuleInfo {
    domains: Vec<String>,
    strategy: String,
    priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StealthInfo {
    split_jitter: u8,
    timing_jitter_us: u32,
    randomize_tls_padding: bool,
    fake_size_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeResultInfo {
    technique: String,
    success: bool,
    latency_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdaptResultInfo {
    domain: String,
    strategy: Option<String>,
    score: f64,
    stealth: bool,
    probes: Vec<ProbeResultInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdaptResponse {
    results: Vec<AdaptResultInfo>,
    config_path: Option<String>,
}

// --- Tauri Commands ---

#[tauri::command]
fn get_status(state: tauri::State<'_, AppState>) -> ProxyStatus {
    state.status.lock().expect("state lock poisoned").clone()
}

#[tauri::command]
async fn start_proxy(
    config_path: Option<String>,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let already_running = state.status.lock().expect("state lock poisoned").running;
    if already_running {
        return Err("Proxy is already running".into());
    }

    let cli = desyncd_config::Cli {
        mode: None,
        listen: None,
        config: config_path.map(PathBuf::from),
        strategy: None,
        verbose: 0,
        command: None,
    };

    let config = AppConfig::load(&cli).map_err(|e| e.to_string())?;
    let listen = config.listen;
    let mode = format!("{:?}", config.mode);

    let selector = Arc::new(Selector::new(
        config.strategies.clone(),
        config.rules.clone(),
        config.default_strategy.clone(),
    ));

    let stealth = if config.stealth == desyncd_types::StealthConfig::default() {
        None
    } else {
        Some(config.stealth.clone())
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    *state.shutdown_tx.lock().expect("state lock poisoned") = Some(shutdown_tx);

    {
        let mut status = state.status.lock().expect("state lock poisoned");
        status.running = true;
        status.mode = mode.clone();
        status.listen = listen.to_string();
    }

    // Emit status update to frontend.
    let _ = app.emit("proxy-status", &*state.status.lock().expect("state lock poisoned"));

    // Spawn proxy task.
    let app_handle = app.clone();
    tokio::spawn(async move {
        let proxy_fut = desyncd_proxy::run_socks_proxy(listen, selector, stealth);

        tokio::select! {
            result = proxy_fut => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "proxy error");
                }
            }
            _ = shutdown_rx => {
                tracing::info!("proxy shutdown requested");
            }
        }

        // Update status on stop.
        let state = app_handle.state::<AppState>();
        {
            let mut status = state.status.lock().expect("state lock poisoned");
            status.running = false;
        }
        let _ = app_handle.emit("proxy-status", &*state.status.lock().expect("state lock poisoned"));
    });

    Ok(())
}

#[tauri::command]
fn stop_proxy(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let running = state.status.lock().expect("state lock poisoned").running;
    if !running {
        return Err("Proxy is not running".into());
    }

    if let Some(tx) = state.shutdown_tx.lock().expect("state lock poisoned").take() {
        let _ = tx.send(());
    }

    let mut status = state.status.lock().expect("state lock poisoned");
    status.running = false;

    Ok(())
}

#[tauri::command]
fn get_config(config_path: Option<String>) -> Result<ConfigResponse, String> {
    let cli = desyncd_config::Cli {
        mode: None,
        listen: None,
        config: config_path.map(PathBuf::from),
        strategy: None,
        verbose: 0,
        command: None,
    };

    let config = AppConfig::load(&cli).map_err(|e| e.to_string())?;

    let strategies = config
        .strategies
        .iter()
        .map(|s| StrategyInfo {
            name: s.name.clone(),
            techniques: s.techniques.iter().map(|t| t.name.clone()).collect(),
        })
        .collect();

    let rules = config
        .rules
        .iter()
        .map(|r| RuleInfo {
            domains: r.domains.clone(),
            strategy: r.strategy.clone(),
            priority: r.priority,
        })
        .collect();

    Ok(ConfigResponse {
        mode: format!("{:?}", config.mode),
        listen: config.listen.to_string(),
        log_level: config.log_level,
        strategies,
        rules,
        stealth: StealthInfo {
            split_jitter: config.stealth.split_jitter,
            timing_jitter_us: config.stealth.timing_jitter_us,
            randomize_tls_padding: config.stealth.randomize_tls_padding,
            fake_size_range: config.stealth.fake_size_range,
        },
    })
}

#[tauri::command]
async fn test_domain(domain: String) -> Result<Vec<ProbeResultInfo>, String> {
    let techniques = desyncd_desync::technique::available_techniques();
    let mut results = Vec::new();

    // Baseline (no desync).
    let baseline = desyncd_adapt::probe::probe_domain(
        &domain,
        443,
        None,
        std::time::Duration::from_secs(10),
    )
    .await;

    results.push(ProbeResultInfo {
        technique: "baseline".into(),
        success: baseline.success,
        latency_ms: baseline.latency.as_millis(),
        error: baseline.error,
    });

    // Each technique.
    for tech_name in techniques {
        let strategy = desyncd_strategy::Strategy {
            name: tech_name.to_string(),
            techniques: vec![desyncd_desync::technique::TechniqueConfig {
                name: tech_name.to_string(),
                split_position: Some(desyncd_types::SplitPosition::Sni),
                enabled: true,
                fake_type: None,
                sni_mode: None,
                fragments: None,
                host_mode: None,
                stealth: None,
                l7_filter: None,
            }],
        };

        let result = desyncd_adapt::probe::probe_domain(
            &domain,
            443,
            Some(&strategy),
            std::time::Duration::from_secs(10),
        )
        .await;

        results.push(ProbeResultInfo {
            technique: tech_name.to_string(),
            success: result.success,
            latency_ms: result.latency.as_millis(),
            error: result.error,
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    Ok(results)
}

#[tauri::command]
fn get_presets() -> Vec<String> {
    vec![
        "russia".into(),
        "china".into(),
        "iran".into(),
        "test".into(),
    ]
}

#[tauri::command]
async fn adapt_domains(
    domains: Vec<String>,
    save: bool,
    app: tauri::AppHandle,
) -> Result<AdaptResponse, String> {
    if domains.is_empty() {
        return Err("No domains specified".into());
    }

    let cli = desyncd_config::Cli {
        mode: None,
        listen: None,
        config: None,
        strategy: None,
        verbose: 0,
        command: None,
    };
    let config = desyncd_config::AppConfig::load(&cli).map_err(|e| e.to_string())?;

    let db_path = expand_tilde(&config.db_path);
    let store = desyncd_store::Store::open(&db_path).map_err(|e| e.to_string())?;

    let adapt_config = desyncd_adapt::AdaptConfig {
        enabled: true,
        test_domains: domains.clone(),
        secure_dns: config.adaptation.secure_dns,
        ..Default::default()
    };

    let engine = desyncd_adapt::AdaptEngine::new(store, adapt_config);
    let mut results = Vec::new();
    let mut discovered: Vec<(String, desyncd_strategy::Strategy)> = Vec::new();

    for (i, domain) in domains.iter().enumerate() {
        // Emit progress event.
        let _ = app.emit("adapt-progress", serde_json::json!({
            "current": i + 1,
            "total": domains.len(),
            "domain": domain,
        }));

        let search_result = desyncd_adapt::search::find_best_strategy(&engine, domain)
            .await
            .map_err(|e| e.to_string())?;

        let probes: Vec<ProbeResultInfo> = search_result
            .probes
            .iter()
            .map(|(label, p)| ProbeResultInfo {
                technique: label.clone(),
                success: p.success,
                latency_ms: p.latency.as_millis(),
                error: p.error.clone(),
            })
            .collect();

        let strategy_name = search_result
            .best_strategy
            .as_ref()
            .map(|s| s.name.clone());

        if let Some(ref strategy) = search_result.best_strategy {
            if save {
                let _ = engine.store.save_strategy(&strategy.name, &strategy.techniques)
                    .and_then(|sid| engine.store.update_domain_strategy(domain, sid, search_result.best_score));
            }
            discovered.push((domain.clone(), strategy.clone()));
        }

        results.push(AdaptResultInfo {
            domain: domain.clone(),
            strategy: strategy_name,
            score: search_result.best_score,
            stealth: search_result.stealth_used,
            probes,
        });
    }

    let config_path = if save && !discovered.is_empty() {
        let path = resolve_config_path();
        generate_config_for_gui(&config, &discovered, &path).map_err(|e| e.to_string())?;
        Some(path.to_string_lossy().to_string())
    } else {
        None
    };

    Ok(AdaptResponse { results, config_path })
}

/// Generate config from GUI adapt results.
fn generate_config_for_gui(
    base_config: &desyncd_config::AppConfig,
    discovered: &[(String, desyncd_strategy::Strategy)],
    output_path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::collections::HashMap;
    use std::io::Write;

    let mut strategies = HashMap::new();
    let mut rules = Vec::new();
    let mut priority = 10i32;

    for (domain, strategy) in discovered {
        let strategy_name = domain.replace('.', "_").replace('*', "wildcard");
        strategies.insert(
            strategy_name.clone(),
            desyncd_config::StrategyDef { techniques: strategy.techniques.clone() },
        );
        rules.push(desyncd_strategy::MatchRule {
            domains: vec![domain.clone(), format!("*.{}", domain)],
            strategy: strategy_name,
            priority,
        });
        priority += 1;
    }

    // Default catch-all: passthrough for unmatched domains.
    strategies.insert(
        "passthrough".into(),
        desyncd_config::StrategyDef { techniques: vec![] },
    );

    rules.push(desyncd_strategy::MatchRule {
        domains: vec!["*".into()],
        strategy: "passthrough".into(),
        priority: 0,
    });

    let config_file = desyncd_config::ConfigFile {
        general: desyncd_config::GeneralConfig {
            mode: base_config.mode,
            log_level: base_config.log_level.clone(),
        },
        proxy: desyncd_config::ProxyConfig {
            listen: base_config.listen,
            socks5: true,
            auto_retry_fallback: base_config.auto_retry_fallback.clone(),
        },
        adaptation: desyncd_config::AdaptationConfig {
            enabled: true,
            test_interval_secs: base_config.adaptation.test_interval_secs,
            test_domains: discovered.iter().map(|(d, _)| d.clone()).collect(),
            db_path: base_config.db_path.clone(),
            secure_dns: base_config.adaptation.secure_dns,
        },
        stealth: desyncd_adapt::search::recommended_stealth(),
        strategies,
        rules,
    };

    let toml_str = toml::to_string_pretty(&config_file)?;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(output_path)?;
    writeln!(file, "# desyncd configuration")?;
    writeln!(file, "# Auto-generated by desyncd GUI")?;
    writeln!(file)?;
    file.write_all(toml_str.as_bytes())?;
    Ok(())
}

fn resolve_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    let config_dir = std::env::var("HOME").ok()
        .map(|h| PathBuf::from(h).join(".config/desyncd"));
    #[cfg(target_os = "linux")]
    let config_dir = std::env::var("XDG_CONFIG_HOME").ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))
        .map(|p| p.join("desyncd"));
    #[cfg(target_os = "windows")]
    let config_dir = std::env::var("APPDATA").ok()
        .map(|a| PathBuf::from(a).join("desyncd"));
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let config_dir: Option<PathBuf> = None;

    // Fallback chain: platform-specific home dir → current directory.
    // On Windows prefer USERPROFILE (HOME is typically unset).
    config_dir
        .or_else(|| home_dir().map(|h| h.join(".config/desyncd")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("config.toml")
}

/// Return the user's home directory. Uses `USERPROFILE` on Windows
/// (where `HOME` is typically unset) and `HOME` elsewhere.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

/// Expand a leading `~` or `~/...` to the user's home directory.
/// Returns the unchanged path if expansion fails (e.g. no home dir known).
fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new("info")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tauri::Builder::default()
        .manage(AppState {
            status: Mutex::new(ProxyStatus::default()),
            shutdown_tx: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_proxy,
            stop_proxy,
            get_config,
            test_domain,
            get_presets,
            adapt_domains,
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri application");
}
