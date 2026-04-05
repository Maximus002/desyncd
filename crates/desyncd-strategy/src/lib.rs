//! Strategy selection engine.
//!
//! A "strategy" is an ordered list of desync techniques with parameters.
//! The selector matches connections to strategies based on domain, port,
//! and protocol rules.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use desyncd_desync::technique::TechniqueConfig;
use desyncd_desync::PayloadContext;
use desyncd_types::{AppProtocol, DesyncAction, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Runtime set of domains discovered to need desync (learned from early-RST
/// failures at connection time). Inspired by byedpi's hostlist-auto.
///
/// When a domain appears here, future connections apply the first auto-retry
/// fallback technique as the primary strategy instead of passthrough — this
/// cuts the steady-state latency on the second-and-subsequent visit.
#[derive(Debug, Clone, Default)]
pub struct LearnedBlocked {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl LearnedBlocked {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a domain as learned-blocked. Returns true if newly added.
    pub fn insert(&self, domain: &str) -> bool {
        match self.inner.write() {
            Ok(mut set) => set.insert(domain.to_ascii_lowercase()),
            Err(_) => false,
        }
    }

    /// Check whether a domain is known to need desync.
    pub fn contains(&self, domain: &str) -> bool {
        match self.inner.read() {
            Ok(set) => set.contains(&domain.to_ascii_lowercase()),
            Err(_) => false,
        }
    }

    /// Current number of learned domains.
    pub fn len(&self) -> usize {
        self.inner.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Is the set empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A named strategy consisting of ordered techniques.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strategy {
    pub name: String,
    pub techniques: Vec<TechniqueConfig>,
}

impl Strategy {
    /// Apply this strategy to a payload context.
    ///
    /// Executes techniques in order. The first applicable technique's result
    /// is returned. Techniques whose `l7_filter` does not match the detected
    /// protocol are skipped before being invoked, letting a single chain
    /// dispatch different techniques per L7 protocol.
    pub fn apply(&self, ctx: &PayloadContext) -> Result<DesyncAction> {
        for tech in &self.techniques {
            if !tech.enabled {
                continue;
            }

            if let Some(filter) = tech.l7_filter {
                if !filter.matches(&ctx.protocol) {
                    debug!(
                        technique = %tech.name,
                        ?filter,
                        "l7 filter skipped technique"
                    );
                    continue;
                }
            }

            match desyncd_desync::apply_technique_cfg(tech, ctx) {
                Ok(action) => {
                    debug!(technique = %tech.name, "strategy applied technique");
                    return Ok(action);
                }
                Err(desyncd_types::Error::NotApplicable(reason)) => {
                    debug!(technique = %tech.name, %reason, "technique not applicable, trying next");
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(DesyncAction::PassThrough)
    }
}

/// A rule that maps domain/port patterns to a strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    /// Domain glob patterns (e.g., "*.youtube.com").
    pub domains: Vec<String>,
    /// Strategy name to apply when matched.
    pub strategy: String,
    /// Priority (higher wins on conflict).
    #[serde(default)]
    pub priority: i32,
}

/// The strategy selector holds all strategies and rules.
pub struct Selector {
    strategies: HashMap<String, Strategy>,
    rules: Vec<MatchRule>,
    default_strategy: Option<String>,
    /// Auto-retry fallback chain — techniques to try if the primary strategy
    /// results in early RST from upstream. Inspired by byedpi's --auto=torst.
    /// Empty means no retry (current behavior).
    auto_retry_fallback: Vec<TechniqueConfig>,
    /// Runtime learned-blocked domain set, shared with the proxy relay so it
    /// can insert newly-discovered blocked domains.
    learned_blocked: LearnedBlocked,
}

impl Selector {
    pub fn new(
        strategies: Vec<Strategy>,
        mut rules: Vec<MatchRule>,
        default_strategy: Option<String>,
    ) -> Self {
        // Sort rules by priority descending.
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        let strategies = strategies
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();
        Self {
            strategies,
            rules,
            default_strategy,
            auto_retry_fallback: Vec::new(),
            learned_blocked: LearnedBlocked::new(),
        }
    }

    /// Enable auto-retry on early RST by configuring a fallback chain.
    /// Techniques are tried in order; each failure triggers one reconnection.
    pub fn with_auto_retry_fallback(mut self, fallback: Vec<TechniqueConfig>) -> Self {
        self.auto_retry_fallback = fallback;
        self
    }

    /// Return the auto-retry fallback chain. Empty if auto-retry is disabled.
    pub fn auto_retry_fallback(&self) -> &[TechniqueConfig] {
        &self.auto_retry_fallback
    }

    /// Handle to the runtime learned-blocked domain set, shared between the
    /// selector (read side) and the relay (write side).
    pub fn learned_blocked(&self) -> &LearnedBlocked {
        &self.learned_blocked
    }

    /// Find the appropriate strategy for a given domain.
    pub fn select(&self, domain: Option<&str>) -> Option<&Strategy> {
        if let Some(domain) = domain {
            for rule in &self.rules {
                if rule.domains.iter().any(|pat| domain_matches(pat, domain)) {
                    return self.strategies.get(&rule.strategy);
                }
            }
        }

        // Fall back to default strategy.
        self.default_strategy
            .as_ref()
            .and_then(|name| self.strategies.get(name))
    }

    /// Apply the selected strategy to a payload.
    ///
    /// Detects the domain from the payload's protocol info and selects
    /// the matching strategy. If the strategy would result in `PassThrough`
    /// but the domain is in the runtime learned-blocked set, upgrade to the
    /// first auto-retry fallback technique as a hot-start (we already know
    /// this domain needs desync from a previous connection).
    pub fn apply(&self, ctx: &PayloadContext) -> Result<DesyncAction> {
        let domain = extract_domain(&ctx.protocol);
        let strategy = self.select(domain);

        let action = match strategy {
            Some(s) => {
                info!(
                    strategy = %s.name,
                    domain = ?domain,
                    "applying desync strategy"
                );
                s.apply(ctx)?
            }
            None => {
                debug!(domain = ?domain, "no strategy matched, passing through");
                DesyncAction::PassThrough
            }
        };

        // Hot-start for learned-blocked domains: if we'd pass through but the
        // relay previously had to retry this domain, go straight to the first
        // fallback technique.
        if let (DesyncAction::PassThrough, Some(d)) = (&action, domain) {
            if !self.auto_retry_fallback.is_empty() && self.learned_blocked.contains(d) {
                let first = Strategy {
                    name: "learned_fallback".into(),
                    techniques: vec![self.auto_retry_fallback[0].clone()],
                };
                debug!(
                    domain = d,
                    technique = %self.auto_retry_fallback[0].name,
                    "learned-blocked hot-start: applying first fallback technique"
                );
                return first.apply(ctx);
            }
        }

        Ok(action)
    }
}

/// Extract domain from detected protocol info.
fn extract_domain(proto: &AppProtocol) -> Option<&str> {
    match proto {
        AppProtocol::TlsClientHello { sni: Some(sni), .. } => Some(sni.as_str()),
        AppProtocol::HttpRequest { host: Some(host), .. } => {
            // Strip port if present.
            Some(host.split(':').next().unwrap_or(host))
        }
        _ => None,
    }
}

/// Simple glob matcher for domain patterns.
///
/// Supports `*` as a catch-all and `*.example.com` for subdomains.
/// Per RFC 6125, `*.example.com` matches subdomains only, NOT `example.com` itself.
/// To match both, use two rules: `example.com` and `*.example.com`.
fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: match subdomains only (RFC 6125).
        // e.g. *.youtube.com matches www.youtube.com but NOT youtube.com.
        // Avoid format!() allocation in hot path.
        domain.len() > suffix.len()
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    } else {
        // Exact match (case-insensitive).
        pattern.eq_ignore_ascii_case(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desyncd_types::SplitPosition;

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("*", "anything.com"));
        assert!(domain_matches("*.youtube.com", "www.youtube.com"));
        assert!(!domain_matches("*.youtube.com", "youtube.com")); // RFC 6125: wildcard != bare domain
        assert!(domain_matches("*.youtube.com", "a.b.youtube.com"));
        assert!(!domain_matches("*.youtube.com", "notyoutube.com"));
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "www.example.com"));
    }

    #[test]
    fn test_selector() {
        let strategies = vec![
            Strategy {
                name: "aggressive".into(),
                techniques: vec![TechniqueConfig {
                    name: "tcp_split".into(),
                    split_position: Some(SplitPosition::Sni),
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    fragments: None,
                    host_mode: None,
                    stealth: None,
                    l7_filter: None,
                }],
            },
            Strategy {
                name: "default".into(),
                techniques: vec![TechniqueConfig {
                    name: "tcp_split".into(),
                    split_position: Some(SplitPosition::Absolute(10)),
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    fragments: None,
                    host_mode: None,
                    stealth: None,
                    l7_filter: None,
                }],
            },
        ];

        let rules = vec![
            MatchRule {
                domains: vec!["*.youtube.com".into()],
                strategy: "aggressive".into(),
                priority: 10,
            },
            MatchRule {
                domains: vec!["*".into()],
                strategy: "default".into(),
                priority: 0,
            },
        ];

        let selector = Selector::new(strategies, rules, Some("default".into()));

        let s = selector.select(Some("www.youtube.com")).unwrap();
        assert_eq!(s.name, "aggressive");

        let s = selector.select(Some("example.com")).unwrap();
        assert_eq!(s.name, "default");

        let s = selector.select(None).unwrap();
        assert_eq!(s.name, "default");
    }

    #[test]
    fn test_learned_blocked_insert_and_contains() {
        let lb = LearnedBlocked::new();
        assert!(lb.is_empty());
        assert!(lb.insert("twitter.com"));
        assert!(!lb.insert("twitter.com")); // duplicate returns false
        assert!(lb.contains("twitter.com"));
        assert!(lb.contains("TWITTER.COM")); // case-insensitive
        assert!(!lb.contains("facebook.com"));
        assert_eq!(lb.len(), 1);
    }

    /// Minimal TLS 1.2 ClientHello carrying a single SNI extension. Kept
    /// local to this test module to avoid depending on desyncd-desync's
    /// `cfg(test)` testutil module.
    fn minimal_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
        let sni_ext_len = 4 + sni_ext_data_len;
        let extensions_len = sni_ext_len;
        let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
        let hs_len = 4 + ch_body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&0x0301u16.to_be_bytes());
        buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
        buf.push(0x01);
        buf.push(0x00);
        buf.extend_from_slice(&(ch_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&0x0303u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&0x1301u16.to_be_bytes());
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let sni_list_len = 1 + 2 + sni_bytes.len();
        buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sni_bytes);
        buf
    }

    #[test]
    fn test_selector_hotstart_upgrades_passthrough_on_learned_blocked() {
        // Build a selector with NO rules (so select() returns None →
        // Action::PassThrough) but with an auto-retry fallback configured.
        let fallback = vec![TechniqueConfig {
            name: "tls_record_frag".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            fragments: None,
            host_mode: None,
            stealth: None,
            l7_filter: None,
        }];
        let selector = Selector::new(Vec::new(), Vec::new(), None)
            .with_auto_retry_fallback(fallback);

        // Synthesize a TLS ClientHello carrying sni=example.com.
        let ctx = PayloadContext::new(minimal_client_hello_with_sni("example.com"));

        // First call — nothing learned yet, should pass through.
        let action = selector.apply(&ctx).unwrap();
        assert!(matches!(action, DesyncAction::PassThrough));

        // Simulate the relay discovering that example.com needs desync.
        selector.learned_blocked().insert("example.com");

        // Second call — should now upgrade to the fallback technique
        // (tls_record_frag produces Replace).
        let action = selector.apply(&ctx).unwrap();
        assert!(
            !matches!(action, DesyncAction::PassThrough),
            "expected fallback upgrade, got {:?}", action
        );
    }

    #[test]
    fn test_l7_filter_skips_mismatched_protocol() {
        use desyncd_types::L7Filter;

        // Strategy with two techniques: the first is filtered to HTTP-only
        // (should be skipped for TLS payloads), the second is TLS-only.
        let strategy = Strategy {
            name: "chain".into(),
            techniques: vec![
                TechniqueConfig {
                    name: "http_host".into(),
                    split_position: None,
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    fragments: None,
                    host_mode: Some("mixed_case".into()),
                    stealth: None,
                    l7_filter: Some(L7Filter::Http),
                },
                TechniqueConfig {
                    name: "tls_record_frag".into(),
                    split_position: Some(SplitPosition::Sni),
                    enabled: true,
                    fake_type: None,
                    sni_mode: None,
                    fragments: None,
                    host_mode: None,
                    stealth: None,
                    l7_filter: Some(L7Filter::Tls),
                },
            ],
        };

        // TLS ClientHello → first technique must be skipped (wrong L7),
        // second must be applied.
        let ctx = PayloadContext::new(minimal_client_hello_with_sni("example.com"));
        let action = strategy.apply(&ctx).unwrap();
        assert!(
            matches!(action, DesyncAction::Replace(_)),
            "expected tls_record_frag Replace, got {:?}",
            action
        );

        // HTTP request → first technique (http_host) must be applied even
        // though the tls-filtered one sits later in the chain.
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let ctx_http = PayloadContext::new(http_payload);
        let action_http = strategy.apply(&ctx_http).unwrap();
        assert!(
            !matches!(action_http, DesyncAction::PassThrough),
            "expected http_host to run, got {:?}",
            action_http
        );
    }
}
