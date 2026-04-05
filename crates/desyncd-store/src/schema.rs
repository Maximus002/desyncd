//! Database schema and versioned migrations.
//!
//! ## Why `PRAGMA user_version`?
//!
//! The previous implementation used a two-step approach: a base `MIGRATIONS`
//! string with `CREATE TABLE IF NOT EXISTS`, then an additive `MIGRATIONS_V2`
//! block whose errors were ignored (`let _ = conn.execute_batch(...)`) so
//! re-running wouldn't fail when columns already existed. That "ignore errors"
//! trick works for `ALTER TABLE ADD COLUMN` but silently breaks for anything
//! more complex (renames, type changes, constraints, data backfills): the
//! error is swallowed, the DB is left in a half-migrated state, and the next
//! query hits a missing column.
//!
//! This module replaces that with a proper versioned migration system using
//! SQLite's built-in `PRAGMA user_version` (a u32 in the database header).
//! Each migration targets a specific version. On open we read the current
//! version, apply any pending migrations in order, and bump `user_version`
//! inside the same transaction so a crash mid-migration can't leave us in an
//! inconsistent state.
//!
//! ## Adding a new migration
//!
//! 1. Bump [`LATEST_VERSION`].
//! 2. Add a new `const V{N}_...` SQL block.
//! 3. Add a new `if current < {N}` branch in [`migrate`].
//! 4. Write the migration so it's idempotent or guarded — a database that
//!    previously received the change through some other path (e.g. imported
//!    schema, manual intervention) should still converge.

use rusqlite::Connection;

/// Latest schema version. Bump this when adding a new migration.
pub const LATEST_VERSION: u32 = 2;

/// V1: initial schema.
///
/// All `CREATE TABLE` statements use `IF NOT EXISTS` so re-running on a
/// database that was created by the pre-versioned code path (which used the
/// old `MIGRATIONS` string) is a no-op.
const V1_SCHEMA: &str = r#"
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

CREATE INDEX IF NOT EXISTS idx_test_results_tested_at
    ON test_results(tested_at);

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

/// V2: add confidence tracking columns to `domain_strategies`.
///
/// `confidence` is the rolling probability that a stored strategy still
/// works; `success_count` / `fail_count` feed into it.
const V2_ADD_CONFIDENCE: &str = r#"
ALTER TABLE domain_strategies ADD COLUMN confidence REAL NOT NULL DEFAULT 1.0;
ALTER TABLE domain_strategies ADD COLUMN success_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domain_strategies ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0;
"#;

/// Read the current schema version via `PRAGMA user_version`.
pub fn get_user_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map(|v| v as u32)
}

/// Return true if `column` exists on `table`.
///
/// Used by migrations to make column-adding changes idempotent — for
/// databases where a column was added through the legacy "ignore errors on
/// `ALTER TABLE`" path before we had versioning.
fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply all pending migrations up to [`LATEST_VERSION`].
///
/// Each migration runs inside its own transaction and is only applied if the
/// current `PRAGMA user_version` is lower than its target. After a successful
/// migration, `user_version` is bumped inside the same transaction so a crash
/// mid-migration leaves the database at the previous version rather than
/// half-upgraded.
///
/// Migrations are written to be safe to re-run on a schema that already
/// contains their changes, because some existing databases were migrated via
/// the pre-versioning `MIGRATIONS_V2` ignore-errors path and still have
/// `user_version = 0` despite being at V2-equivalent schema.
pub fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let current = get_user_version(conn)?;

    if current < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(V1_SCHEMA)?;
        tx.execute_batch("PRAGMA user_version = 1")?;
        tx.commit()?;
    }

    if current < 2 {
        let tx = conn.transaction()?;
        // If the legacy ignore-errors path already added these columns on an
        // existing database, skip the ALTER to avoid "duplicate column" errors.
        if !column_exists(&tx, "domain_strategies", "confidence")? {
            tx.execute_batch(V2_ADD_CONFIDENCE)?;
        }
        tx.execute_batch("PRAGMA user_version = 2")?;
        tx.commit()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_db_migrates_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), LATEST_VERSION);
        assert!(column_exists(&conn, "domain_strategies", "confidence").unwrap());
        assert!(column_exists(&conn, "domain_strategies", "success_count").unwrap());
        assert!(column_exists(&conn, "domain_strategies", "fail_count").unwrap());
    }

    #[test]
    fn migrate_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        // Running it twice must not fail, and must leave user_version unchanged.
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn legacy_unmigrated_db_gets_v2_columns() {
        // Simulates a database that ran the old MIGRATIONS string (V1 only)
        // but never got MIGRATIONS_V2 applied. user_version is still 0, no
        // confidence columns.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V1_SCHEMA).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), 0);
        assert!(!column_exists(&conn, "domain_strategies", "confidence").unwrap());

        migrate(&mut conn).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), LATEST_VERSION);
        assert!(column_exists(&conn, "domain_strategies", "confidence").unwrap());
    }

    #[test]
    fn legacy_db_with_columns_still_gets_version_bumped() {
        // Simulates a database that ran both the old MIGRATIONS and
        // MIGRATIONS_V2 paths. user_version is still 0 (old code didn't set
        // it), but confidence columns already exist. migrate() must bump the
        // version without erroring on duplicate-column ALTER.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V1_SCHEMA).unwrap();
        conn.execute_batch(V2_ADD_CONFIDENCE).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), 0);

        migrate(&mut conn).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), LATEST_VERSION);
    }

    #[test]
    fn partial_crash_recovery() {
        // Simulates the case where the previous run applied V1 successfully
        // (user_version = 1) but crashed before V2. Next open must pick up
        // at V2 and finish.
        let mut conn = Connection::open_in_memory().unwrap();
        {
            let tx = conn.transaction().unwrap();
            tx.execute_batch(V1_SCHEMA).unwrap();
            tx.execute_batch("PRAGMA user_version = 1").unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(get_user_version(&conn).unwrap(), 1);
        assert!(!column_exists(&conn, "domain_strategies", "confidence").unwrap());

        migrate(&mut conn).unwrap();
        assert_eq!(get_user_version(&conn).unwrap(), LATEST_VERSION);
        assert!(column_exists(&conn, "domain_strategies", "confidence").unwrap());
    }
}
