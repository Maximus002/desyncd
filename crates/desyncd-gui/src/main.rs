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
                host_mode: None,
                stealth: None,
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
        ])
        .run(tauri::generate_context!())
        .expect("error running tauri application");
}
