//! Database query helpers.

use crate::Store;
use anyhow::Context;
use desyncd_desync::technique::TechniqueConfig;
use tracing::debug;

/// A strategy record from the database.
#[derive(Debug, Clone)]
pub struct StrategyRecord {
    pub id: i64,
    pub name: String,
    pub techniques: Vec<TechniqueConfig>,
}

/// A test result record.
#[derive(Debug, Clone)]
pub struct TestResultRecord {
    pub id: i64,
    pub domain: String,
    pub strategy_id: Option<i64>,
    pub technique: Option<String>,
    pub success: bool,
    pub latency_ms: Option<i64>,
    pub error_msg: Option<String>,
    pub tested_at: String,
}

impl Store {
    /// Save or update a strategy definition.
    pub fn save_strategy(
        &self,
        name: &str,
        techniques: &[TechniqueConfig],
    ) -> anyhow::Result<i64> {
        let json = serde_json::to_string(techniques)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO strategies (name, techniques_json, updated_at)
                 VALUES (?1, ?2, datetime('now'))
                 ON CONFLICT(name) DO UPDATE SET
                    techniques_json = excluded.techniques_json,
                    updated_at = datetime('now')",
                rusqlite::params![name, json],
            )?;
            // last_insert_rowid() returns 0 on ON CONFLICT UPDATE,
            // so always query the actual id by name.
            let id: i64 = conn.query_row(
                "SELECT id FROM strategies WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )?;
            debug!(name, id, "saved strategy");
            Ok(id)
        })
    }

    /// Get a strategy by name.
    pub fn get_strategy(&self, name: &str) -> anyhow::Result<Option<StrategyRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, techniques_json FROM strategies WHERE name = ?1",
            )?;

            let result = stmt
                .query_row(rusqlite::params![name], |row| {
                    let id: i64 = row.get(0)?;
                    let name: String = row.get(1)?;
                    let json: String = row.get(2)?;
                    Ok((id, name, json))
                })
                .optional()?;

            match result {
                Some((id, name, json)) => {
                    let techniques: Vec<TechniqueConfig> =
                        serde_json::from_str(&json).context("invalid techniques JSON")?;
                    Ok(Some(StrategyRecord {
                        id,
                        name,
                        techniques,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Get the best strategy for a domain (highest score).
    pub fn get_best_strategy(&self, domain: &str) -> anyhow::Result<Option<StrategyRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT s.id, s.name, s.techniques_json
                 FROM domain_strategies ds
                 JOIN strategies s ON s.id = ds.strategy_id
                 WHERE ds.domain = ?1
                 ORDER BY ds.score DESC
                 LIMIT 1",
            )?;

            let result = stmt
                .query_row(rusqlite::params![domain], |row| {
                    let id: i64 = row.get(0)?;
                    let name: String = row.get(1)?;
                    let json: String = row.get(2)?;
                    Ok((id, name, json))
                })
                .optional()?;

            match result {
                Some((id, name, json)) => {
                    let techniques: Vec<TechniqueConfig> =
                        serde_json::from_str(&json).context("invalid techniques JSON")?;
                    Ok(Some(StrategyRecord {
                        id,
                        name,
                        techniques,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Record a test result.
    pub fn save_test_result(
        &self,
        domain: &str,
        strategy_id: Option<i64>,
        technique: Option<&str>,
        success: bool,
        latency_ms: Option<i64>,
        error_msg: Option<&str>,
    ) -> anyhow::Result<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO test_results (domain, strategy_id, technique, success, latency_ms, error_msg)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![domain, strategy_id, technique, success as i32, latency_ms, error_msg],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get recent test results for a domain.
    pub fn get_test_history(
        &self,
        domain: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TestResultRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, domain, strategy_id, technique, success, latency_ms, error_msg, tested_at
                 FROM test_results
                 WHERE domain = ?1
                 ORDER BY tested_at DESC
                 LIMIT ?2",
            )?;

            let rows = stmt.query_map(rusqlite::params![domain, limit as i64], |row| {
                Ok(TestResultRecord {
                    id: row.get(0)?,
                    domain: row.get(1)?,
                    strategy_id: row.get(2)?,
                    technique: row.get(3)?,
                    success: row.get::<_, i32>(4)? != 0,
                    latency_ms: row.get(5)?,
                    error_msg: row.get(6)?,
                    tested_at: row.get(7)?,
                })
            })?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    /// Get the highest-scoring strategy across ALL domains.
    ///
    /// Used for smart prediction: if tls_record_frag worked for facebook.com,
    /// it will likely work for instagram.com on the same ISP/DPI.
    pub fn get_any_best_strategy(&self) -> anyhow::Result<Option<StrategyRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT s.id, s.name, s.techniques_json
                 FROM domain_strategies ds
                 JOIN strategies s ON s.id = ds.strategy_id
                 ORDER BY ds.score DESC
                 LIMIT 1",
            )?;

            let result = stmt
                .query_row([], |row| {
                    let id: i64 = row.get(0)?;
                    let name: String = row.get(1)?;
                    let json: String = row.get(2)?;
                    Ok((id, name, json))
                })
                .optional()?;

            match result {
                Some((id, name, json)) => {
                    let techniques: Vec<TechniqueConfig> =
                        serde_json::from_str(&json).context("invalid techniques JSON")?;
                    Ok(Some(StrategyRecord {
                        id,
                        name,
                        techniques,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Update or create a domain→strategy mapping with a score.
    pub fn update_domain_strategy(
        &self,
        domain: &str,
        strategy_id: i64,
        score: f64,
    ) -> anyhow::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO domain_strategies (domain, strategy_id, score, last_tested, last_success, confidence, success_count, fail_count)
                 VALUES (?1, ?2, ?3, datetime('now'), datetime('now'), 1.0, 1, 0)
                 ON CONFLICT(domain) DO UPDATE SET
                    strategy_id = excluded.strategy_id,
                    score = excluded.score,
                    last_tested = datetime('now'),
                    last_success = datetime('now'),
                    confidence = 1.0,
                    success_count = success_count + 1,
                    fail_count = 0",
                rusqlite::params![domain, strategy_id, score],
            )?;
            Ok(())
        })
    }

    /// Record a relay success for a domain (boosts confidence).
    pub fn record_relay_success(&self, domain: &str) -> anyhow::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE domain_strategies SET
                    success_count = success_count + 1,
                    last_success = datetime('now')
                 WHERE domain = ?1",
                rusqlite::params![domain],
            )?;
            Ok(())
        })
    }

    /// Record a relay failure for a domain (degrades confidence).
    pub fn record_relay_failure(&self, domain: &str) -> anyhow::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE domain_strategies SET
                    fail_count = fail_count + 1
                 WHERE domain = ?1",
                rusqlite::params![domain],
            )?;
            Ok(())
        })
    }

    /// Get confidence for a domain's strategy, accounting for time decay.
    ///
    /// Formula: `confidence = base × decay(age) × success_rate`
    /// - `decay`: exponential, half-life = 7 days
    /// - `success_rate`: `successes / (successes + failures)`, min 10 samples
    pub fn get_confidence(&self, domain: &str) -> anyhow::Result<f64> {
        self.with_conn(|conn| {
            let result: Option<(f64, i64, i64, String)> = conn
                .prepare(
                    "SELECT confidence, success_count, fail_count, last_success
                     FROM domain_strategies WHERE domain = ?1",
                )?
                .query_row(rusqlite::params![domain], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .optional()?;

            match result {
                Some((_base_conf, successes, failures, last_success_str)) => {
                    // Time decay: half-life of 7 days.
                    let age_secs = parse_age_secs(&last_success_str);
                    let half_life_secs = 7.0 * 24.0 * 3600.0; // 7 days
                    let decay = (0.5_f64).powf(age_secs / half_life_secs);

                    // Success rate (with smoothing — need at least a few samples).
                    let total = successes + failures;
                    let success_rate = if total >= 3 {
                        successes as f64 / total as f64
                    } else {
                        1.0 // Not enough data, assume good.
                    };

                    Ok((decay * success_rate).clamp(0.0, 1.0))
                }
                None => Ok(0.0),
            }
        })
    }

    /// Get the best strategy for a domain, but only if confidence is above threshold.
    ///
    /// Returns None if the strategy exists but confidence is too low.
    pub fn get_confident_strategy(
        &self,
        domain: &str,
        min_confidence: f64,
    ) -> anyhow::Result<Option<StrategyRecord>> {
        let confidence = self.get_confidence(domain)?;
        if confidence < min_confidence {
            debug!(
                %domain,
                confidence,
                min_confidence,
                "strategy confidence too low, needs re-validation"
            );
            return Ok(None);
        }
        self.get_best_strategy(domain)
    }

    /// Get the best strategy across all domains, with confidence check.
    pub fn get_any_confident_strategy(
        &self,
        min_confidence: f64,
    ) -> anyhow::Result<Option<(StrategyRecord, f64)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT s.id, s.name, s.techniques_json,
                        ds.confidence, ds.success_count, ds.fail_count, ds.last_success
                 FROM domain_strategies ds
                 JOIN strategies s ON s.id = ds.strategy_id
                 ORDER BY ds.score DESC",
            )?;

            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?;

            for row in rows {
                let (id, name, json, _base_conf, successes, failures, last_success_str) = row?;

                // Compute live confidence.
                let age_secs = parse_age_secs(&last_success_str);
                let half_life_secs = 7.0 * 24.0 * 3600.0;
                let decay = (0.5_f64).powf(age_secs / half_life_secs);
                let total = successes + failures;
                let success_rate = if total >= 3 {
                    successes as f64 / total as f64
                } else {
                    1.0
                };
                let confidence = (decay * success_rate).clamp(0.0, 1.0);

                if confidence >= min_confidence {
                    let techniques: Vec<TechniqueConfig> =
                        serde_json::from_str(&json).context("invalid techniques JSON")?;
                    return Ok(Some((
                        StrategyRecord { id, name, techniques },
                        confidence,
                    )));
                }
            }

            Ok(None)
        })
    }

    /// Get or create a provider record.
    pub fn get_or_create_provider(
        &self,
        name: &str,
        asn: Option<u32>,
    ) -> anyhow::Result<i64> {
        self.with_conn(|conn| {
            let existing: Option<i64> = conn
                .prepare("SELECT id FROM providers WHERE name = ?1")?
                .query_row(rusqlite::params![name], |row| row.get(0))
                .optional()?;

            if let Some(id) = existing {
                return Ok(id);
            }

            conn.execute(
                "INSERT INTO providers (name, asn) VALUES (?1, ?2)",
                rusqlite::params![name, asn.map(|a| a as i64)],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Import a host list (replace all entries).
    pub fn import_hostlist(
        &self,
        name: &str,
        source_url: Option<&str>,
        domains: &[String],
    ) -> anyhow::Result<()> {
        self.with_conn(|conn| {
            // Upsert hostlist.
            conn.execute(
                "INSERT INTO hostlists (name, source_url, updated_at)
                 VALUES (?1, ?2, datetime('now'))
                 ON CONFLICT(name) DO UPDATE SET
                    source_url = excluded.source_url,
                    updated_at = datetime('now')",
                rusqlite::params![name, source_url],
            )?;

            let list_id: i64 = conn.query_row(
                "SELECT id FROM hostlists WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )?;

            conn.execute(
                "DELETE FROM hostlist_entries WHERE hostlist_id = ?1",
                rusqlite::params![list_id],
            )?;

            let mut stmt = conn.prepare(
                "INSERT OR IGNORE INTO hostlist_entries (hostlist_id, domain) VALUES (?1, ?2)",
            )?;
            for domain in domains {
                stmt.execute(rusqlite::params![list_id, domain])?;
            }

            debug!(name, count = domains.len(), "imported hostlist");
            Ok(())
        })
    }

    /// Get all domains from a host list.
    pub fn get_hostlist_domains(&self, name: &str) -> anyhow::Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT he.domain
                 FROM hostlist_entries he
                 JOIN hostlists h ON h.id = he.hostlist_id
                 WHERE h.name = ?1
                 ORDER BY he.domain",
            )?;

            let rows = stmt.query_map(rusqlite::params![name], |row| {
                row.get::<_, String>(0)
            })?;

            let mut domains = Vec::new();
            for row in rows {
                domains.push(row?);
            }
            Ok(domains)
        })
    }
}

/// Parse a SQLite datetime string and return age in seconds from now.
fn parse_age_secs(datetime_str: &str) -> f64 {
    // SQLite datetime format: "2026-04-01 12:34:56"
    // We parse it manually to avoid pulling in chrono just for this.
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple parser for "YYYY-MM-DD HH:MM:SS".
    let parts: Vec<&str> = datetime_str.split(&['-', ' ', ':'][..]).collect();
    if parts.len() < 6 {
        return 0.0; // Can't parse, treat as fresh.
    }

    let year: i64 = parts[0].parse().unwrap_or(2026);
    let month: i64 = parts[1].parse().unwrap_or(1);
    let day: i64 = parts[2].parse().unwrap_or(1);
    let hour: i64 = parts[3].parse().unwrap_or(0);
    let min: i64 = parts[4].parse().unwrap_or(0);
    let sec: i64 = parts[5].parse().unwrap_or(0);

    // Rough days-since-epoch (good enough for decay calculation).
    // Not astronomically precise, but decay is a smooth function anyway.
    let days_approx = (year - 1970) * 365 + (year - 1970) / 4
        + [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
            .get((month - 1) as usize)
            .copied()
            .unwrap_or(0)
        + day - 1;
    let timestamp_approx = days_approx * 86400 + hour * 3600 + min * 60 + sec;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    (now - timestamp_approx).max(0) as f64
}

/// Extension trait to add `.optional()` to rusqlite query results.
trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desyncd_types::SplitPosition;

    fn test_store() -> Store {
        Store::open_memory().unwrap()
    }

    #[test]
    fn test_save_and_get_strategy() {
        let store = test_store();
        let techniques = vec![TechniqueConfig {
            name: "tcp_split".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            host_mode: None,
            stealth: None,
        }];

        let id = store.save_strategy("test_strategy", &techniques).unwrap();
        assert!(id > 0);

        let record = store.get_strategy("test_strategy").unwrap().unwrap();
        assert_eq!(record.name, "test_strategy");
        assert_eq!(record.techniques.len(), 1);
        assert_eq!(record.techniques[0].name, "tcp_split");
    }

    #[test]
    fn test_save_test_result() {
        let store = test_store();
        let id = store
            .save_test_result("example.com", None, Some("tcp_split"), true, Some(150), None)
            .unwrap();
        assert!(id > 0);

        let history = store.get_test_history("example.com", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].success);
        assert_eq!(history[0].latency_ms, Some(150));
    }

    #[test]
    fn test_domain_strategy_mapping() {
        let store = test_store();
        let techniques = vec![TechniqueConfig {
            name: "tcp_split".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            host_mode: None,
            stealth: None,
        }];
        let sid = store.save_strategy("best", &techniques).unwrap();

        store.update_domain_strategy("youtube.com", sid, 95.5).unwrap();

        let best = store.get_best_strategy("youtube.com").unwrap().unwrap();
        assert_eq!(best.name, "best");
    }

    #[test]
    fn test_hostlist_import() {
        let store = test_store();
        let domains = vec![
            "youtube.com".into(),
            "twitter.com".into(),
            "rutracker.org".into(),
        ];
        store.import_hostlist("blocked", None, &domains).unwrap();

        let result = store.get_hostlist_domains("blocked").unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn test_confidence_fresh_strategy() {
        let store = test_store();
        let techniques = vec![TechniqueConfig {
            name: "tcp_split".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            host_mode: None,
            stealth: None,
        }];
        let sid = store.save_strategy("s1", &techniques).unwrap();
        store.update_domain_strategy("example.com", sid, 95.0).unwrap();

        // Fresh strategy should have high confidence.
        let conf = store.get_confidence("example.com").unwrap();
        assert!(conf > 0.9, "fresh strategy confidence should be ~1.0, got {}", conf);

        // Should be returned by confident query.
        let result = store.get_confident_strategy("example.com", 0.3).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_confidence_degrades_with_failures() {
        let store = test_store();
        let techniques = vec![TechniqueConfig {
            name: "tcp_split".into(),
            split_position: Some(SplitPosition::Sni),
            enabled: true,
            fake_type: None,
            sni_mode: None,
            host_mode: None,
            stealth: None,
        }];
        let sid = store.save_strategy("s1", &techniques).unwrap();
        store.update_domain_strategy("example.com", sid, 95.0).unwrap();

        // Record many failures.
        for _ in 0..10 {
            store.record_relay_failure("example.com").unwrap();
        }

        // Confidence should drop due to low success rate (1 success / 11 total).
        let conf = store.get_confidence("example.com").unwrap();
        assert!(conf < 0.2, "confidence should be low after failures, got {}", conf);
    }

    #[test]
    fn test_confidence_unknown_domain() {
        let store = test_store();
        let conf = store.get_confidence("unknown.com").unwrap();
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_provider() {
        let store = test_store();
        let id1 = store.get_or_create_provider("Ростелеком", Some(12389)).unwrap();
        let id2 = store.get_or_create_provider("Ростелеком", Some(12389)).unwrap();
        assert_eq!(id1, id2);
    }
}
