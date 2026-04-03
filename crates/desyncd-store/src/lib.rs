//! SQLite persistence layer for desyncd.
//!
//! Stores learned strategies, test results, domain-strategy mappings,
//! provider profiles, and host lists.

pub mod schema;
pub mod queries;

use std::path::Path;
use std::sync::Mutex;
use rusqlite::Connection;
use tracing::info;

/// Persistent store backed by SQLite.
///
/// Thread-safe via internal Mutex. All DB operations lock briefly.
pub struct Store {
    conn: Mutex<Connection>,
}

// Safety: Connection access is serialized through Mutex.
unsafe impl Sync for Store {}

impl Store {
    /// Open (or create) a database at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        info!(?path, "store opened");
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Run schema migrations, enable WAL mode, and set performance pragmas.
    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -2000;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;"
        )?;
        conn.execute_batch(schema::MIGRATIONS)?;

        // Apply additive V2 migrations (new columns).
        // ALTER TABLE ... ADD COLUMN fails if column exists — we just ignore errors.
        for line in schema::MIGRATIONS_V2.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            let _ = conn.execute_batch(trimmed);
        }

        Ok(())
    }

    /// Execute a closure with the locked connection.
    pub fn with_conn<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T>,
    {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        f(&conn)
    }
}
