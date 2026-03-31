//! Strategy search: find the best bypass technique for a domain.
//!
//! Two-phase algorithm:
//! - Phase 1 (fast guess): try previously successful strategies first
//! - Phase 2 (full sweep): systematic search if guess fails

use std::time::Duration;

use desyncd_desync::technique::TechniqueConfig;
use desyncd_strategy::Strategy;
use desyncd_types::SplitPosition;
use tracing::{debug, info};

use crate::probe::{self, ProbeResult};
use crate::AdaptEngine;

/// Result of a strategy search for a single domain.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub domain: String,
    /// Best strategy found (None if domain is not blocked).
    pub best_strategy: Option<Strategy>,
    /// Score of the best strategy.
    pub best_score: f64,
    /// All probe results collected during the search.
    pub probes: Vec<(String, ProbeResult)>,
    /// Whether the result came from fast guess (Phase 1).
    pub was_fast_guess: bool,
}

/// Run a full strategy search for a domain.
///
/// Algorithm:
/// 0. Smart prediction — try known successful strategies from DB
/// 1. Baseline (no desync) — check if domain is actually blocked
/// 2. Single technique sweep — try each technique with default params
/// 3. Parameter variations — for winners, try different split positions
pub async fn find_best_strategy(
    engine: &AdaptEngine,
    domain: &str,
) -> anyhow::Result<SearchResult> {
    let timeout = engine.config.probe_timeout();
    let port = 443u16;
    let mut all_probes: Vec<(String, ProbeResult)> = Vec::new();

    info!(%domain, "starting strategy search");

    // Step 0: Smart prediction — try known strategies before full sweep.
    // First check if this exact domain has a known strategy.
    // Then check if ANY domain has a working strategy (same ISP/DPI assumption).
    let candidates = collect_candidate_strategies(engine, domain);

    if !candidates.is_empty() {
        info!(
            %domain,
            candidates = candidates.len(),
            "trying known strategies first (fast guess)"
        );

        for (label, strategy) in &candidates {
            let result = probe::probe_domain(domain, port, Some(strategy), timeout).await;
            let score = compute_score(&result);
            all_probes.push((format!("guess:{}", label), result.clone()));

            if result.success {
                info!(
                    %domain,
                    strategy = %label,
                    score,
                    "fast guess succeeded!"
                );

                // Save to DB.
                if let Ok(sid) = engine
                    .store
                    .save_strategy(&strategy.name, &strategy.techniques)
                {
                    let _ = engine.store.update_domain_strategy(domain, sid, score);
                }

                return Ok(SearchResult {
                    domain: domain.to_string(),
                    best_strategy: Some(strategy.clone()),
                    best_score: score,
                    probes: all_probes,
                    was_fast_guess: true,
                });
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        debug!(%domain, "fast guess failed, falling back to full sweep");
    }

    // Step 1: Baseline test.
    let baseline = probe::probe_domain(domain, port, None, timeout).await;
    all_probes.push(("baseline".into(), baseline.clone()));

    if baseline.success {
        info!(%domain, "baseline succeeded — domain is not blocked");
        let _ = engine.store.save_test_result(
            domain,
            None,
            Some("baseline"),
            true,
            Some(baseline.latency.as_millis() as i64),
            None,
        );
        return Ok(SearchResult {
            domain: domain.to_string(),
            best_strategy: None,
            best_score: 0.0,
            probes: all_probes,
            was_fast_guess: false,
        });
    }

    debug!(%domain, "baseline failed, searching for bypass strategy");

    // Step 2: Single technique sweep.
    // Note: fake_packet is excluded — in SOCKS mode, fake data is sent
    // on the same TCP stream and reaches the server, breaking TLS.
    // It only works in NFQ mode where packets can have TTL=1.
    let techniques = [
        ("tcp_split", SplitPosition::Sni),
        ("tls_record_frag", SplitPosition::Sni),
        ("disorder", SplitPosition::Sni),
        ("sni_manip", SplitPosition::Sni),
    ];

    let mut winners: Vec<(String, SplitPosition, f64)> = Vec::new();

    for (tech_name, split_pos) in &techniques {
        let strategy = Strategy {
            name: format!("probe_{}", tech_name),
            techniques: vec![TechniqueConfig {
                name: tech_name.to_string(),
                split_position: Some(split_pos.clone()),
                enabled: true,
                fake_type: None,
                sni_mode: None,
                host_mode: None,
                stealth: None,
            }],
        };

        let result = probe::probe_domain(domain, port, Some(&strategy), timeout).await;
        let score = compute_score(&result);

        let _ = engine.store.save_test_result(
            domain,
            None,
            Some(tech_name),
            result.success,
            Some(result.latency.as_millis() as i64),
            result.error.as_deref(),
        );

        all_probes.push((tech_name.to_string(), result.clone()));

        if result.success {
            winners.push((tech_name.to_string(), split_pos.clone(), score));
            debug!(technique = tech_name, score, "technique succeeded");
        }

        // Rate limiting: 1 probe per second.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Step 3: Parameter variations for winners.
    let split_variations = [
        SplitPosition::Sni,
        SplitPosition::SniOffset(-1),
        SplitPosition::SniOffset(-2),
        SplitPosition::SniOffset(1),
        SplitPosition::Absolute(1),
        SplitPosition::Absolute(3),
        SplitPosition::Absolute(5),
    ];

    let mut best_score: f64 = 0.0;
    let mut best_strategy: Option<Strategy> = None;

    for (tech_name, _, _) in &winners {
        for split_pos in &split_variations {
            // Skip if we already tested this combination.
            if matches!(split_pos, SplitPosition::Sni) {
                continue; // Already tested in step 2.
            }

            let strategy = Strategy {
                name: format!("probe_{}_{:?}", tech_name, split_pos),
                techniques: vec![TechniqueConfig {
                    name: tech_name.clone(),
                    split_position: Some(split_pos.clone()),
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    host_mode: None,
                    stealth: None,
                }],
            };

            let result = probe::probe_domain(domain, port, Some(&strategy), timeout).await;
            let score = compute_score(&result);
            let label = format!("{}+{:?}", tech_name, split_pos);
            all_probes.push((label, result.clone()));

            if result.success && score > best_score {
                best_score = score;
                best_strategy = Some(strategy);
            }

            tokio::time::sleep(Duration::from_millis(500)).await;

            // Respect max_probes limit.
            if all_probes.len() >= engine.config.max_probes {
                break;
            }
        }
    }

    // If no variation beat the original winners, use the first winner.
    if best_strategy.is_none() && !winners.is_empty() {
        let (tech_name, split_pos, score) = &winners[0];
        best_score = *score;
        best_strategy = Some(Strategy {
            name: format!("auto_{}_{}", domain, tech_name),
            techniques: vec![TechniqueConfig {
                name: tech_name.clone(),
                split_position: Some(split_pos.clone()),
                enabled: true,
                fake_type: None,
                sni_mode: None,
                host_mode: None,
                stealth: None,
            }],
        });
    }

    // Save the best strategy to the store.
    if let Some(ref strategy) = best_strategy {
        if let Ok(sid) = engine
            .store
            .save_strategy(&strategy.name, &strategy.techniques)
        {
            let _ = engine
                .store
                .update_domain_strategy(domain, sid, best_score);
        }
        info!(
            %domain,
            strategy = %strategy.name,
            score = best_score,
            "best strategy found"
        );
    } else {
        info!(%domain, "no working strategy found");
    }

    Ok(SearchResult {
        domain: domain.to_string(),
        best_strategy,
        best_score,
        probes: all_probes,
        was_fast_guess: false,
    })
}

/// Collect candidate strategies from the database for smart prediction.
///
/// Priority order:
/// 1. Exact domain match (e.g. facebook.com already tested)
/// 2. Best strategy from any other domain (same ISP assumption)
fn collect_candidate_strategies(engine: &AdaptEngine, domain: &str) -> Vec<(String, Strategy)> {
    let mut candidates = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Try exact domain match first.
    if let Ok(Some(record)) = engine.store.get_best_strategy(domain) {
        seen_names.insert(record.name.clone());
        candidates.push((
            format!("exact:{}", domain),
            Strategy {
                name: record.name,
                techniques: record.techniques,
            },
        ));
    }

    // Try best strategy from any domain (cross-domain prediction).
    if let Ok(Some(record)) = engine.store.get_any_best_strategy() {
        if !seen_names.contains(&record.name) {
            candidates.push((
                format!("cross-domain:{}", record.name),
                Strategy {
                    name: record.name,
                    techniques: record.techniques,
                },
            ));
        }
    }

    candidates
}

/// Compute a score for a probe result.
///
/// `score = success * 100 - latency_ms * 0.01`
fn compute_score(result: &ProbeResult) -> f64 {
    if !result.success {
        return 0.0;
    }
    let base = 100.0;
    let latency_penalty = result.latency.as_millis() as f64 * 0.01;
    (base - latency_penalty).max(1.0)
}
