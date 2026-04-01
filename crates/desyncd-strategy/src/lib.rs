//! Strategy selection engine.
//!
//! A "strategy" is an ordered list of desync techniques with parameters.
//! The selector matches connections to strategies based on domain, port,
//! and protocol rules.

use desyncd_desync::technique::TechniqueConfig;
use desyncd_desync::PayloadContext;
use desyncd_types::{AppProtocol, DesyncAction, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

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
    /// is returned. If a technique produces `Split`, subsequent techniques
    /// are applied to each chunk.
    pub fn apply(&self, ctx: &PayloadContext) -> Result<DesyncAction> {
        for tech in &self.techniques {
            if !tech.enabled {
                continue;
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
    strategies: Vec<Strategy>,
    rules: Vec<MatchRule>,
    default_strategy: Option<String>,
}

impl Selector {
    pub fn new(
        strategies: Vec<Strategy>,
        mut rules: Vec<MatchRule>,
        default_strategy: Option<String>,
    ) -> Self {
        // Sort rules by priority descending.
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self {
            strategies,
            rules,
            default_strategy,
        }
    }

    /// Find the appropriate strategy for a given domain.
    pub fn select(&self, domain: Option<&str>) -> Option<&Strategy> {
        if let Some(domain) = domain {
            for rule in &self.rules {
                if rule.domains.iter().any(|pat| domain_matches(pat, domain)) {
                    return self.find_strategy(&rule.strategy);
                }
            }
        }

        // Fall back to default strategy.
        self.default_strategy
            .as_ref()
            .and_then(|name| self.find_strategy(name))
    }

    /// Apply the selected strategy to a payload.
    ///
    /// Detects the domain from the payload's protocol info and selects
    /// the matching strategy.
    pub fn apply(&self, ctx: &PayloadContext) -> Result<DesyncAction> {
        let domain = extract_domain(&ctx.protocol);
        let strategy = self.select(domain.as_deref());

        match strategy {
            Some(s) => {
                info!(
                    strategy = %s.name,
                    domain = ?domain,
                    techniques = %s.techniques.iter()
                        .filter(|t| t.enabled)
                        .map(|t| t.name.as_str())
                        .collect::<Vec<_>>()
                        .join("+"),
                    "applying desync strategy"
                );
                s.apply(ctx)
            }
            None => {
                debug!(domain = ?domain, "no strategy matched, passing through");
                Ok(DesyncAction::PassThrough)
            }
        }
    }

    fn find_strategy(&self, name: &str) -> Option<&Strategy> {
        self.strategies.iter().find(|s| s.name == name)
    }
}

/// Extract domain from detected protocol info.
fn extract_domain(proto: &AppProtocol) -> Option<String> {
    match proto {
        AppProtocol::TlsClientHello { sni: Some(sni), .. } => Some(sni.clone()),
        AppProtocol::HttpRequest { host: Some(host), .. } => {
            // Strip port if present.
            Some(host.split(':').next().unwrap_or(host).to_string())
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
                    host_mode: None,
                    stealth: None,
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
                    host_mode: None,
                    stealth: None,
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
}
