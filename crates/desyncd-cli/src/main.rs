use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use desyncd_config::{AppConfig, Cli, Command};
use desyncd_strategy::Selector;
use desyncd_types::{Mode, StealthConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(&cli).context("failed to load configuration")?;

    // Initialize logging.
    let filter = EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        mode = ?config.mode,
        "desyncd starting"
    );

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(config).await,
        Command::Test {
            domain,
            all_techniques,
        } => test_domains(config, domain, all_techniques).await,
        Command::Adapt {
            domain,
            save,
        } => adapt_domains(config, domain, save).await,
        Command::ShowConfig => {
            show_config(&config);
            Ok(())
        }
    }
}

async fn run(config: AppConfig) -> anyhow::Result<()> {
    let selector = Arc::new(Selector::new(
        config.strategies.clone(),
        config.rules.clone(),
        config.default_strategy.clone(),
    ));

    match config.mode {
        Mode::Socks => {
            info!("starting in SOCKS5 proxy mode (with HTTP CONNECT auto-detect)");

            // Optionally start adaptation scheduler in background.
            if config.adaptation.enabled && !config.adaptation.test_domains.is_empty() {
                let db_path = expand_tilde(&config.db_path);
                if let Ok(store) = desyncd_store::Store::open(&db_path) {
                    let adapt_config = desyncd_adapt::AdaptConfig {
                        enabled: config.adaptation.enabled,
                        test_interval_secs: config.adaptation.test_interval_secs,
                        test_domains: config.adaptation.test_domains.clone(),
                        ..Default::default()
                    };
                    let engine = Arc::new(desyncd_adapt::AdaptEngine::new(store, adapt_config));
                    tokio::spawn(desyncd_adapt::scheduler::run_scheduler(engine));
                    info!("adaptation scheduler started in background");
                }
            }

            let stealth = if config.stealth == StealthConfig::default() {
                None
            } else {
                Some(config.stealth.clone())
            };
            desyncd_proxy::run_socks_proxy(config.listen, selector, stealth).await
        }
        Mode::Nfq => {
            anyhow::bail!(
                "NFQ mode requires a Linux system with NFQUEUE support. \
                 Use --mode socks on other platforms."
            );
        }
        Mode::Transparent => {
            info!("starting in transparent proxy mode");
            let stealth = if config.stealth == StealthConfig::default() {
                None
            } else {
                Some(config.stealth.clone())
            };
            desyncd_proxy::transparent::run_transparent_proxy(
                config.listen,
                selector,
                stealth,
            ).await
        }
        Mode::Hybrid => {
            anyhow::bail!("hybrid mode not yet implemented (planned for Phase 3)");
        }
    }
}

async fn test_domains(
    config: AppConfig,
    domains: Vec<String>,
    all_techniques: bool,
) -> anyhow::Result<()> {
    if domains.is_empty() {
        anyhow::bail!("no domains specified. Usage: desyncd test --domain example.com");
    }

    let selector = Selector::new(
        config.strategies.clone(),
        config.rules.clone(),
        config.default_strategy.clone(),
    );

    if all_techniques {
        info!("testing all techniques against each domain");
        let techniques = desyncd_desync::technique::available_techniques();

        for domain in &domains {
            println!("\n--- {} ---", domain);
            println!(
                "{:<20} {:<10} {:<10} Error",
                "Technique", "Result", "Latency"
            );
            println!("{}", "-".repeat(60));

            // Baseline.
            let baseline = desyncd_adapt::probe::probe_domain(
                domain,
                443,
                None,
                std::time::Duration::from_secs(10),
            )
            .await;
            println!(
                "{:<20} {:<10} {:<10} {}",
                "baseline",
                if baseline.success { "OK" } else { "FAIL" },
                format!("{}ms", baseline.latency.as_millis()),
                baseline.error.unwrap_or_default(),
            );

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
                    domain,
                    443,
                    Some(&strategy),
                    std::time::Duration::from_secs(10),
                )
                .await;

                println!(
                    "{:<20} {:<10} {:<10} {}",
                    tech_name,
                    if result.success { "OK" } else { "FAIL" },
                    format!("{}ms", result.latency.as_millis()),
                    result.error.unwrap_or_default(),
                );

                // Rate limit.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    } else {
        // Basic connectivity test.
        info!("block detection test — basic connectivity check");

        for domain in &domains {
            info!(%domain, "testing connectivity");

            let addr = format!("{}:443", domain);
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => {
                    let peer = stream.peer_addr()?;
                    info!(%domain, %peer, "TCP connection successful");

                    let strategy = selector.select(Some(domain));
                    if let Some(s) = strategy {
                        info!(%domain, strategy = %s.name, "would apply strategy");
                    } else {
                        info!(%domain, "no strategy configured");
                    }
                }
                Err(e) => {
                    info!(%domain, error = %e, "TCP connection failed (possibly blocked)");
                }
            }
        }
    }

    Ok(())
}

async fn adapt_domains(config: AppConfig, domains: Vec<String>, save: bool) -> anyhow::Result<()> {
    if domains.is_empty() {
        anyhow::bail!("no domains specified. Usage: desyncd adapt --domain youtube.com");
    }

    let db_path = expand_tilde(&config.db_path);
    let store = desyncd_store::Store::open(&db_path)
        .context("failed to open database")?;

    let adapt_config = desyncd_adapt::AdaptConfig {
        enabled: true,
        test_domains: domains.clone(),
        ..Default::default()
    };

    let engine = desyncd_adapt::AdaptEngine::new(store, adapt_config);

    for domain in &domains {
        println!("\n=== Adapting: {} ===\n", domain);

        let result = desyncd_adapt::search::find_best_strategy(&engine, domain).await?;

        println!(
            "\nProbes ({} total):",
            result.probes.len()
        );
        println!(
            "{:<30} {:<10} {:<10} Error",
            "Technique", "Result", "Latency"
        );
        println!("{}", "-".repeat(70));

        for (label, probe) in &result.probes {
            println!(
                "{:<30} {:<10} {:<10} {}",
                label,
                if probe.success { "OK" } else { "FAIL" },
                format!("{}ms", probe.latency.as_millis()),
                probe.error.as_deref().unwrap_or(""),
            );
        }

        if let Some(ref strategy) = result.best_strategy {
            println!(
                "\nBest strategy: {} (score: {:.1})",
                strategy.name, result.best_score
            );
            for tech in &strategy.techniques {
                println!(
                    "  - {} (split: {:?})",
                    tech.name, tech.split_position
                );
            }

            if save {
                let strategy_id = engine.store.save_strategy(
                    &strategy.name,
                    &strategy.techniques,
                )?;
                engine.store.update_domain_strategy(
                    domain,
                    strategy_id,
                    result.best_score,
                )?;
                println!("  Saved to database.");
            }
        } else {
            println!("\nNo working strategy found (domain may not be blocked).");
        }
    }

    Ok(())
}

fn show_config(config: &AppConfig) {
    println!("desyncd effective configuration:");
    println!("  mode: {:?}", config.mode);
    println!("  listen: {}", config.listen);
    println!("  log_level: {}", config.log_level);
    println!("  db_path: {}", config.db_path);
    println!("  default_strategy: {:?}", config.default_strategy);
    println!();
    println!("  adaptation:");
    println!("    enabled: {}", config.adaptation.enabled);
    println!(
        "    test_interval: {}s",
        config.adaptation.test_interval_secs
    );
    println!(
        "    test_domains: {:?}",
        config.adaptation.test_domains
    );
    println!();
    println!("  stealth:");
    println!("    split_jitter: {}", config.stealth.split_jitter);
    println!("    timing_jitter_us: {}", config.stealth.timing_jitter_us);
    println!("    fake_size_range: {:?}", config.stealth.fake_size_range);
    println!("    randomize_tls_padding: {}", config.stealth.randomize_tls_padding);
    println!();
    println!("  strategies:");
    for s in &config.strategies {
        println!("    {}:", s.name);
        for t in &s.techniques {
            println!(
                "      - {} (split: {:?}, enabled: {})",
                t.name, t.split_position, t.enabled
            );
        }
    }
    println!();
    println!("  rules:");
    for r in &config.rules {
        println!(
            "    domains={:?} -> strategy={} (priority={})",
            r.domains, r.strategy, r.priority
        );
    }
}

/// Expand `~` in a path to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    PathBuf::from(path)
}
