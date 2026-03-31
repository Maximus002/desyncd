//! Database schema and migrations.

/// SQL statements to create/migrate the database schema.
pub const MIGRATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS strategies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    techniques_json TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS test_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    strategy_id INTEGER REFERENCES strategies(id),
    technique   TEXT,
    success     INTEGER NOT NULL DEFAULT 0,
    latency_ms  INTEGER,
    error_msg   TEXT,
    tested_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_test_results_domain
    ON test_results(domain, tested_at DESC);

CREATE TABLE IF NOT EXISTS domain_strategies (
    domain      TEXT PRIMARY KEY,
    strategy_id INTEGER NOT NULL REFERENCES strategies(id),
    score       REAL NOT NULL DEFAULT 0.0,
    last_tested TEXT,
    last_success TEXT
);

CREATE TABLE IF NOT EXISTS providers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    asn         INTEGER,
    dpi_type    TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS provider_strategies (
    provider_id INTEGER NOT NULL REFERENCES providers(id),
    strategy_id INTEGER NOT NULL REFERENCES strategies(id),
    score       REAL NOT NULL DEFAULT 0.0,
    PRIMARY KEY (provider_id, strategy_id)
);

CREATE TABLE IF NOT EXISTS hostlists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    source_url  TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hostlist_entries (
    hostlist_id INTEGER NOT NULL REFERENCES hostlists(id),
    domain      TEXT NOT NULL,
    PRIMARY KEY (hostlist_id, domain)
);
"#;
