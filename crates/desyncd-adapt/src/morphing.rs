//! Protocol Morphing: intelligent DPI classification and counter-strategy selection.
//!
//! Instead of blindly sweeping all techniques (15-20 probes), morphing runs
//! 5 targeted diagnostic probes to classify the DPI type, then selects the
//! optimal counter-strategy based on the classification.
//!
//! Known DPI profiles:
//! - TlsRecordInspector (TSPU): reads first TLS record only, reassembles TCP
//! - TcpNaive: doesn't reassemble TCP segments
//! - SniExactMatch: compares SNI literally (case-sensitive)
//! - OrderDependent: processes packets in arrival order
//! - IpBlocked: IP-level blocking, no SNI bypass possible
//! - Permissive: multiple techniques work (weak or no DPI)

use std::fmt;
use std::time::Duration;

use desyncd_desync::technique::TechniqueConfig;
use desyncd_strategy::Strategy;
use desyncd_types::SplitPosition;
use tracing::{debug, info};

use crate::probe::{self, ProbeResult};
use crate::search::compute_score;
use crate::AdaptEngine;

/// Known DPI behavior profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpiProfile {
    /// Russian TSPU: reads first TLS record only, reassembles TCP.
    /// Bypass: tls_record_frag (split SNI across TLS records).
    TlsRecordInspector,

    /// Naive TCP inspection: doesn't reassemble TCP segments.
    /// Bypass: tcp_split.
    TcpNaive,

    /// SNI exact-match: compares SNI literally (case-sensitive).
    /// Bypass: sni_manip (mixed case).
    SniExactMatch,

    /// Order-dependent: processes packets in arrival order.
    /// Bypass: disorder (reverse segment order).
    OrderDependent,

    /// IP-level blocking: no SNI-based bypass will work.
    IpBlocked,

    /// Multiple techniques work — DPI is weak or intermittent.
    Permissive,

    /// Could not classify.
    Unknown,
}

impl fmt::Display for DpiProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsRecordInspector => write!(f, "TLS-record-inspector (TSPU-like)"),
            Self::TcpNaive => write!(f, "TCP-naive"),
            Self::SniExactMatch => write!(f, "SNI-exact-match"),
            Self::OrderDependent => write!(f, "order-dependent"),
            Self::IpBlocked => write!(f, "IP-blocked"),
            Self::Permissive => write!(f, "permissive (weak DPI)"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of DPI classification.
#[derive(Debug, Clone)]
pub struct MorphResult {
    /// Detected DPI profile.
    pub profile: DpiProfile,
    /// Recommended techniques, ordered by preference.
    pub recommended: Vec<(String, SplitPosition)>,
    /// Diagnostic probe results.
    pub probes: Vec<(String, ProbeResult)>,
    /// Classification confidence (0.0 - 1.0).
    pub confidence: f64,
}

/// Diagnostic probe results used for classification.
struct DiagProbes {
    tls_record_frag: Option<ProbeResult>,
    tcp_split: Option<ProbeResult>,
    sni_manip: Option<ProbeResult>,
    disorder: Option<ProbeResult>,
}

/// Run DPI classification for a domain.
///
/// Uses 5 targeted probes (baseline + 4 techniques) to determine
/// the DPI type and recommend the optimal counter-strategy.
pub async fn classify_dpi(
    engine: &AdaptEngine,
    domain: &str,
) -> MorphResult {
    let timeout = engine.config.probe_timeout();
    let port = 443u16;
    let secure_dns = engine.config.secure_dns;
    let mut all_probes: Vec<(String, ProbeResult)> = Vec::new();

    info!(%domain, "morphing: starting DPI classification");

    // Probe 1: baseline (no desync) — is domain actually blocked?
    let baseline = probe::probe_domain_ex(domain, port, None, timeout, secure_dns).await;
    all_probes.push(("morph:baseline".into(), baseline.clone()));

    if baseline.success {
        info!(%domain, "morphing: domain not blocked");
        return MorphResult {
            profile: DpiProfile::Permissive,
            recommended: vec![],
            probes: all_probes,
            confidence: 1.0,
        };
    }

    let baseline_error = baseline.error.as_deref().unwrap_or("");
    let is_conn_refused = baseline_error.contains("onnection refused");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Probe 2: tls_record_frag — detects first-TLS-record inspectors (TSPU).
    let tls_frag = run_diag_probe(
        domain, port, timeout, secure_dns,
        "tls_record_frag", SplitPosition::Sni, None,
    ).await;
    all_probes.push(("morph:tls_record_frag".into(), tls_frag.clone()));

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Probe 3: tcp_split — detects TCP-level inspectors.
    let tcp_split = run_diag_probe(
        domain, port, timeout, secure_dns,
        "tcp_split", SplitPosition::Sni, None,
    ).await;
    all_probes.push(("morph:tcp_split".into(), tcp_split.clone()));

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Probe 4: sni_manip — detects exact-match SNI filters.
    let sni_manip = run_diag_probe(
        domain, port, timeout, secure_dns,
        "sni_manip", SplitPosition::Sni, Some("mixed_case"),
    ).await;
    all_probes.push(("morph:sni_manip".into(), sni_manip.clone()));

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Probe 5: disorder — detects order-dependent inspectors.
    let disorder = run_diag_probe(
        domain, port, timeout, secure_dns,
        "disorder", SplitPosition::Sni, None,
    ).await;
    all_probes.push(("morph:disorder".into(), disorder.clone()));

    let diag = DiagProbes {
        tls_record_frag: Some(tls_frag),
        tcp_split: Some(tcp_split),
        sni_manip: Some(sni_manip),
        disorder: Some(disorder),
    };

    let (profile, recommended, confidence) = classify_from_probes(&diag, is_conn_refused);

    info!(
        %domain,
        profile = %profile,
        confidence = format!("{:.0}%", confidence * 100.0),
        techniques = recommended.len(),
        "morphing: DPI classified"
    );

    // Save diagnostic results to store.
    for (label, result) in &all_probes {
        let tech = label.strip_prefix("morph:").unwrap_or(label);
        let _ = engine.store.save_test_result(
            domain,
            None,
            Some(tech),
            result.success,
            Some(result.latency.as_millis() as i64),
            result.error.as_deref(),
        );
    }

    MorphResult {
        profile,
        recommended,
        probes: all_probes,
        confidence,
    }
}

/// Classification-guided strategy search.
///
/// 1. Classify DPI with 5 diagnostic probes
/// 2. If confident, test only recommended techniques with parameter variations
/// 3. Confirm the best result
/// 4. Falls back to full sweep if classification confidence is low
pub async fn morphing_search(
    engine: &AdaptEngine,
    domain: &str,
) -> anyhow::Result<crate::search::SearchResult> {
    let morph = classify_dpi(engine, domain).await;

    // If IP-blocked or unknown with low confidence, report immediately.
    if morph.profile == DpiProfile::IpBlocked {
        info!(%domain, "morphing: IP-level block detected, no SNI bypass possible");
        return Ok(crate::search::SearchResult {
            domain: domain.to_string(),
            best_strategy: None,
            best_score: 0.0,
            probes: morph.probes,
            was_fast_guess: false,
            stealth_used: false,
        });
    }

    // Domain not blocked.
    if morph.profile == DpiProfile::Permissive && morph.recommended.is_empty() {
        return Ok(crate::search::SearchResult {
            domain: domain.to_string(),
            best_strategy: None,
            best_score: 0.0,
            probes: morph.probes,
            was_fast_guess: false,
            stealth_used: false,
        });
    }

    // Low confidence — fall back to full sweep.
    if morph.confidence < 0.5 || morph.recommended.is_empty() {
        info!(
            %domain,
            confidence = format!("{:.0}%", morph.confidence * 100.0),
            "morphing: low confidence, falling back to full sweep"
        );
        return crate::search::find_best_strategy(engine, domain).await;
    }

    // High confidence — test only recommended techniques with variations.
    let timeout = engine.config.probe_timeout();
    let port = 443u16;
    let secure_dns = engine.config.secure_dns;
    let mut all_probes = morph.probes;

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

    // Test recommended techniques (already ordered by preference).
    for (tech_name, default_split) in &morph.recommended {
        // First: test with the default split position from classification.
        // (This was already tested in classification, but we re-probe for score.)
        let strategy = make_strategy(tech_name, default_split.clone(), None);
        let result = probe::probe_domain_ex(domain, port, Some(&strategy), timeout, secure_dns).await;
        let score = compute_score(&result);
        all_probes.push((format!("morph_var:{}+{:?}", tech_name, default_split), result.clone()));

        if result.success && score > best_score {
            best_score = score;
            best_strategy = Some(strategy);
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

        // Then: try split position variations.
        for split_pos in &split_variations {
            if split_pos == default_split {
                continue;
            }

            let strategy = make_strategy(tech_name, split_pos.clone(), None);
            let result = probe::probe_domain_ex(domain, port, Some(&strategy), timeout, secure_dns).await;
            let score = compute_score(&result);
            all_probes.push((format!("morph_var:{}+{:?}", tech_name, split_pos), result.clone()));

            if result.success && score > best_score {
                best_score = score;
                best_strategy = Some(strategy);
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            if all_probes.len() >= engine.config.max_probes {
                break;
            }
        }

        // If we found a good strategy with the top-recommended technique, skip others.
        if best_strategy.is_some() && best_score > 80.0 {
            debug!(
                %domain,
                technique = tech_name,
                score = best_score,
                "morphing: excellent match found, skipping remaining techniques"
            );
            break;
        }

        if all_probes.len() >= engine.config.max_probes {
            break;
        }
    }

    // Confirmation probes — verify the best strategy works reliably.
    let mut stealth_used = false;
    if let Some(ref strategy) = best_strategy {
        let mut confirm_ok = 0usize;
        let confirm_count = 2;

        for i in 0..confirm_count {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let result = probe::probe_domain_ex(domain, port, Some(strategy), timeout, secure_dns).await;
            all_probes.push((format!("morph_confirm:{}", i + 1), result.clone()));
            if result.success {
                confirm_ok += 1;
            }
        }

        if confirm_ok < confirm_count {
            best_score *= confirm_ok as f64 / confirm_count as f64;
            if confirm_ok == 0 {
                info!(%domain, "morphing: strategy failed confirmation, discarding");
                best_strategy = None;
                best_score = 0.0;
            }
        } else {
            debug!(%domain, strategy = %strategy.name, "morphing: strategy confirmed reliable");
        }
    }

    // If no strategy found with recommended techniques, try stealth variants.
    if best_strategy.is_none() && !morph.recommended.is_empty() {
        info!(%domain, "morphing: trying stealth variants");
        let stealth_cfg = crate::search::recommended_stealth();

        for (tech_name, split_pos) in &morph.recommended {
            let strategy = make_strategy(tech_name, split_pos.clone(), Some(stealth_cfg.clone()));
            let result = probe::probe_domain_ex(domain, port, Some(&strategy), timeout, secure_dns).await;
            let score = compute_score(&result);
            all_probes.push((format!("morph_stealth:{}", tech_name), result.clone()));

            if result.success && score > best_score {
                best_score = score;
                best_strategy = Some(strategy);
                stealth_used = true;
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            if all_probes.len() >= engine.config.max_probes {
                break;
            }
        }
    }

    // Save the best strategy.
    if let Some(ref strategy) = best_strategy {
        if let Ok(sid) = engine.store.save_strategy(&strategy.name, &strategy.techniques) {
            let _ = engine.store.update_domain_strategy(domain, sid, best_score);
        }
        info!(
            %domain,
            strategy = %strategy.name,
            profile = %morph.profile,
            score = best_score,
            total_probes = all_probes.len(),
            "morphing: strategy found"
        );
    } else {
        info!(%domain, profile = %morph.profile, "morphing: no working strategy found");
    }

    Ok(crate::search::SearchResult {
        domain: domain.to_string(),
        best_strategy,
        best_score,
        probes: all_probes,
        was_fast_guess: false,
        stealth_used,
    })
}

// ── Classification logic ──────────────────────────────────────────────

/// Classify DPI type from diagnostic probe results.
fn classify_from_probes(
    diag: &DiagProbes,
    connection_refused: bool,
) -> (DpiProfile, Vec<(String, SplitPosition)>, f64) {
    let tls_ok = diag.tls_record_frag.as_ref().is_some_and(|r| r.success);
    let tcp_ok = diag.tcp_split.as_ref().is_some_and(|r| r.success);
    let sni_ok = diag.sni_manip.as_ref().is_some_and(|r| r.success);
    let dis_ok = diag.disorder.as_ref().is_some_and(|r| r.success);

    let successes = [tls_ok, tcp_ok, sni_ok, dis_ok]
        .iter()
        .filter(|&&s| s)
        .count();

    // Nothing works + connection refused → IP-level block.
    if successes == 0 && connection_refused {
        return (DpiProfile::IpBlocked, vec![], 0.9);
    }

    // Nothing works at all → unknown DPI or very advanced.
    if successes == 0 {
        return (DpiProfile::Unknown, vec![], 0.3);
    }

    // Everything works → weak/no DPI.
    if successes == 4 {
        let recs = rank_by_latency(diag);
        return (DpiProfile::Permissive, recs, 0.7);
    }

    // ── Pattern matching for known DPI types ──

    // TSPU pattern: tls_record_frag works, tcp_split doesn't.
    // DPI reassembles TCP but only inspects the first TLS record.
    //
    // Ordering note: multi_stream_frag is preferred over tls_record_frag for TSPU.
    // Benchmarking against live TSPU-blocked domains (2026-04, twitter/discord/bbc/
    // meduza/roblox) showed MSF has substantially better tail latency: P95 ~491ms
    // vs ~868ms for tls_record_frag. Since MSF is a generalization of the 2-record
    // split (N>=3 records), if tls_record_frag works, MSF will work too. We lead
    // with MSF and keep tls_record_frag as a fallback in case MSF triggers a
    // parser-strict middlebox that tls_record_frag tolerates.
    if tls_ok && !tcp_ok {
        let mut recs = vec![
            ("multi_stream_frag".into(), SplitPosition::Sni),
            ("tls_record_frag".into(), SplitPosition::Sni),
        ];
        if dis_ok {
            recs.push(("disorder".into(), SplitPosition::Sni));
        }
        if sni_ok {
            recs.push(("sni_manip".into(), SplitPosition::Sni));
        }
        return (DpiProfile::TlsRecordInspector, recs, 0.9);
    }

    // TCP-naive: tcp_split works, tls_record_frag doesn't.
    // DPI doesn't reassemble TCP but reads complete TLS records.
    if tcp_ok && !tls_ok {
        let mut recs = vec![("tcp_split".into(), SplitPosition::Sni)];
        if dis_ok {
            recs.push(("disorder".into(), SplitPosition::Sni));
        }
        return (DpiProfile::TcpNaive, recs, 0.85);
    }

    // SNI exact-match: only sni_manip works.
    if sni_ok && !tls_ok && !tcp_ok && !dis_ok {
        return (
            DpiProfile::SniExactMatch,
            vec![("sni_manip".into(), SplitPosition::Sni)],
            0.8,
        );
    }

    // Order-dependent: disorder works, tcp_split doesn't.
    if dis_ok && !tcp_ok {
        let mut recs = vec![("disorder".into(), SplitPosition::Sni)];
        if tls_ok {
            recs.push(("tls_record_frag".into(), SplitPosition::Sni));
        }
        return (DpiProfile::OrderDependent, recs, 0.75);
    }

    // Multiple techniques work but not all — use whatever works, ranked by latency.
    let recs = rank_by_latency(diag);
    let confidence = 0.6 + (successes as f64 * 0.05);
    (DpiProfile::Permissive, recs, confidence.min(0.85))
}

/// Rank successful techniques by probe latency (fastest first).
fn rank_by_latency(diag: &DiagProbes) -> Vec<(String, SplitPosition)> {
    let mut entries: Vec<(&str, Duration)> = Vec::new();

    if let Some(r) = &diag.tls_record_frag {
        if r.success { entries.push(("tls_record_frag", r.latency)); }
    }
    if let Some(r) = &diag.tcp_split {
        if r.success { entries.push(("tcp_split", r.latency)); }
    }
    if let Some(r) = &diag.sni_manip {
        if r.success { entries.push(("sni_manip", r.latency)); }
    }
    if let Some(r) = &diag.disorder {
        if r.success { entries.push(("disorder", r.latency)); }
    }

    entries.sort_by_key(|(_, lat)| *lat);
    entries
        .into_iter()
        .map(|(name, _)| (name.to_string(), SplitPosition::Sni))
        .collect()
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Run a single diagnostic probe with a given technique.
async fn run_diag_probe(
    domain: &str,
    port: u16,
    timeout: Duration,
    secure_dns: bool,
    technique: &str,
    split_pos: SplitPosition,
    sni_mode: Option<&str>,
) -> ProbeResult {
    let strategy = make_strategy(technique, split_pos, None);
    let strategy = if let Some(mode) = sni_mode {
        Strategy {
            techniques: vec![TechniqueConfig {
                sni_mode: Some(mode.to_string()),
                ..strategy.techniques.into_iter().next().unwrap()
            }],
            ..strategy
        }
    } else {
        strategy
    };

    probe::probe_domain_ex(domain, port, Some(&strategy), timeout, secure_dns).await
}

fn make_strategy(
    technique: &str,
    split_pos: SplitPosition,
    stealth: Option<desyncd_types::StealthConfig>,
) -> Strategy {
    Strategy {
        name: format!("morph_{}_{:?}", technique, split_pos),
        techniques: vec![TechniqueConfig {
            name: technique.to_string(),
            split_position: Some(split_pos),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            fragments: None,
            host_mode: None,
            stealth,
            l7_filter: None,
        }],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::ProbeResult;

    fn ok(latency_ms: u64) -> ProbeResult {
        ProbeResult {
            success: true,
            latency: Duration::from_millis(latency_ms),
            error: None,
        }
    }

    fn fail() -> ProbeResult {
        ProbeResult {
            success: false,
            latency: Duration::from_millis(10_000),
            error: Some("timeout".into()),
        }
    }

    /// TSPU pattern: tls_record_frag works, tcp_split fails.
    /// MSF must be recommended FIRST (better tail latency than plain 2-record split).
    #[test]
    fn tspu_pattern_recommends_msf_first() {
        let diag = DiagProbes {
            tls_record_frag: Some(ok(400)),
            tcp_split: Some(fail()),
            sni_manip: Some(fail()),
            disorder: Some(fail()),
        };
        let (profile, recs, confidence) = classify_from_probes(&diag, false);
        assert_eq!(profile, DpiProfile::TlsRecordInspector);
        assert!(confidence >= 0.85);
        assert!(!recs.is_empty(), "should recommend at least one technique");
        assert_eq!(
            recs[0].0, "multi_stream_frag",
            "MSF must lead TSPU recommendations (better P95 than tls_record_frag)"
        );
        assert!(
            recs.iter().any(|(n, _)| n == "tls_record_frag"),
            "tls_record_frag should remain as a fallback"
        );
    }

    #[test]
    fn tspu_pattern_includes_fallbacks_when_available() {
        let diag = DiagProbes {
            tls_record_frag: Some(ok(350)),
            tcp_split: Some(fail()),
            sni_manip: Some(ok(400)),
            disorder: Some(ok(420)),
        };
        let (profile, recs, _) = classify_from_probes(&diag, false);
        assert_eq!(profile, DpiProfile::TlsRecordInspector);
        // Primary pair + disorder + sni_manip fallbacks.
        let names: Vec<&str> = recs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names[0], "multi_stream_frag");
        assert_eq!(names[1], "tls_record_frag");
        assert!(names.contains(&"disorder"));
        assert!(names.contains(&"sni_manip"));
    }

    #[test]
    fn ip_block_returns_no_recommendations() {
        let diag = DiagProbes {
            tls_record_frag: Some(fail()),
            tcp_split: Some(fail()),
            sni_manip: Some(fail()),
            disorder: Some(fail()),
        };
        let (profile, recs, _) = classify_from_probes(&diag, true);
        assert_eq!(profile, DpiProfile::IpBlocked);
        assert!(recs.is_empty());
    }
}
