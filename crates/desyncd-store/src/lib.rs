//! SQLite persistence layer for desyncd.
//!
//! Stores learned strategies, test results, domain-strategy mappings,
//! provider profiles, and host lists.
//!
//! ## Connection strategy
//!
//! WAL mode lets SQLite serve one writer and any number of readers in
//! parallel. A single `Mutex<Connection>` shared between all threads throws
//! that away — every query, read or write, queues behind the mutex. We split
//! the pool so that:
//!
//! - a **dedicated write connection** serializes writes (WAL allows only one
//!   writer anyway, so the mutex models the real constraint);
//! - a **small pool of read connections** handles concurrent reads in
//!   parallel.
//!
//! Writes use [`Store::with_write_conn`]. Pure reads (SELECT only) use
//! [`Store::with_read_conn`]. Read-then-write operations (e.g.
//! `get_or_create_provider`, `import_hostlist`) must use the write lane so
//! the read and the subsequent write are serialized against other writers.

pub mod schema;
pub mod queries;

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use rusqlite::{Connection, OpenFlags};
use tracing::info;

/// Number of read-only connections in the pool.
///
/// WAL mode allows concurrent readers, so having several means adapt / probe
/// / relay hot paths can read in parallel without serializing behind each
/// other. Four is enough for the current workload and stays well under any
/// SQLite per-process limits.
const READ_POOL_SIZE: usize = 4;

/// Per-process counter used to generate unique shared-memory database names
/// for [`Store::open_memory`]. Each in-memory `Store` needs its own database
/// (otherwise tests running in parallel would stomp on each other), but also
/// needs to be shared across multiple connections within the same `Store`
/// (otherwise the read pool would see different, empty databases).
static MEMDB_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Persistent store backed by SQLite in WAL mode.
///
/// See the module-level docs for the read/write split rationale.
pub struct Store {
    /// Single write connection. WAL permits only one writer at a time, so
    /// the mutex models the real constraint rather than imposing a new one.
    write: Mutex<Connection>,

    /// Pool of read connections. Each is wrapped in its own mutex so they
    /// can be leased independently.
    reads: Vec<Mutex<Connection>>,

    /// Round-robin cursor for picking the next read connection. Monotonic
    /// increment with modulo at use — branch-free and race-tolerant (a
    /// collision just means two threads pick the same index, then one waits
    /// on the mutex, which is exactly what would happen anyway).
    read_cursor: AtomicUsize,
}

// Safety: all Connection access is serialized through Mutexes. `Connection`
// itself isn't Sync, but a Mutex<Connection> is.
unsafe impl Sync for Store {}

impl Store {
    /// Open (or create) a database at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::build(|| Connection::open(path), path.display().to_string())
    }

    /// Open an in-memory database (for testing).
    ///
    /// Uses SQLite's shared-cache URI form so the write connection and all
    /// read connections point at the same in-memory database. Each call gets
    /// a unique name so parallel tests don't interfere.
    pub fn open_memory() -> anyhow::Result<Self> {
        let id = MEMDB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let uri = format!("file:desyncd_memdb_{}?mode=memory&cache=shared", id);
        let uri_for_build = uri.clone();
        Self::build(
            move || {
                Connection::open_with_flags(
                    &uri_for_build,
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_CREATE
                        | OpenFlags::SQLITE_OPEN_URI,
                )
            },
            uri,
        )
    }

    /// Core builder — opens the write connection (and migrates through it),
    /// then opens the read pool. Factored out so `open` and `open_memory`
    /// share the migration + pool-construction path.
    fn build<F>(mut opener: F, label: String) -> anyhow::Result<Self>
    where
        F: FnMut() -> rusqlite::Result<Connection>,
    {
        // Writer is opened first. Migrations run on the writer so readers see
        // the final schema by the time they're opened.
        let mut write_conn = opener()?;
        apply_pragmas(&write_conn)?;
        schema::migrate(&mut write_conn)?;

        let mut reads = Vec::with_capacity(READ_POOL_SIZE);
        for _ in 0..READ_POOL_SIZE {
            let rc = opener()?;
            apply_pragmas(&rc)?;
            reads.push(Mutex::new(rc));
        }

        info!(
            path = %label,
            read_pool = READ_POOL_SIZE,
            "store opened"
        );

        Ok(Self {
            write: Mutex::new(write_conn),
            reads,
            read_cursor: AtomicUsize::new(0),
        })
    }

    /// Execute a closure with the write connection.
    ///
    /// Use this for any INSERT / UPDATE / DELETE, and for read-then-write
    /// patterns (e.g. `SELECT ... then INSERT IF NOT EXISTS`) where the read
    /// and the write must be serialized against other writers.
    pub fn with_write_conn<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T>,
    {
        let conn = self.write.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        f(&conn)
    }

    /// Execute a closure with a read connection from the pool.
    ///
    /// Use this for pure SELECT queries. WAL mode guarantees readers see a
    /// consistent snapshot as of the start of each statement, so concurrent
    /// writes on the writer don't block reads here.
    pub fn with_read_conn<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Connection) -> anyhow::Result<T>,
    {
        let idx = self.read_cursor.fetch_add(1, Ordering::Relaxed) % self.reads.len();
        let conn = self.reads[idx]
            .lock()
            .map_err(|e| anyhow::anyhow!("lock: {}", e))?;
        f(&conn)
    }
}

/// Apply per-connection pragmas.
///
/// `journal_mode = WAL` is database-wide and persists in the file header,
/// so it only actually takes effect once; for in-memory databases WAL isn't
/// supported and SQLite silently falls back to `memory` journal mode
/// (returning the chosen mode rather than erroring). The rest (`synchronous`,
/// `cache_size`, `temp_store`, `foreign_keys`) are per-connection and must
/// be set on every connection we open.
fn apply_pragmas(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -2000;
         PRAGMA temp_store = MEMORY;
         PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}
