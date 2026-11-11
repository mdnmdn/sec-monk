//! SQLite backend: two files (state, mirror), WAL, `synchronous=NORMAL`, `foreign_keys=ON`,
//! `busy_timeout=5000`; per file one write connection (the "write actor": a single-connection pool serializes
//! every write transaction in arrival order) and a small read-only pool.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

use crate::{SCHEMA_VERSION, StoreError, StoreResult, migrations};

mod bind;
mod mirror;
#[doc(hidden)]
pub use mirror::rows_page_sql;
mod state;

/// Options of [`SqliteStore::open`].
#[derive(Debug, Clone)]
pub struct StoreOptions {
    /// Connections of each read pool.
    pub read_connections: u32,
    /// Application version written to `store_meta.app_version`.
    pub app_version: String,
}

impl Default for StoreOptions {
    fn default() -> Self {
        StoreOptions {
            read_connections: 4,
            app_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// One database file: its write and read pools.
#[derive(Debug, Clone)]
pub(crate) struct Db {
    pub(crate) write: SqlitePool,
    pub(crate) read: SqlitePool,
    pub(crate) path: PathBuf,
}

/// Both databases. Implements [`crate::StateStore`] and [`crate::MirrorStore`]; cheap to clone.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pub(crate) state: Db,
    pub(crate) mirror: Db,
}

impl SqliteStore {
    /// Open (create 0600 if missing) both files, run the migrations, stamp `user_version` and `store_meta`.
    pub async fn open(
        state_path: &Path,
        mirror_path: &Path,
        opts: &StoreOptions,
    ) -> StoreResult<SqliteStore> {
        let state = open_db(state_path, opts, migrations::state_sqlite()).await?;
        let mirror = open_db(mirror_path, opts, migrations::mirror_sqlite()).await?;
        Ok(SqliteStore { state, mirror })
    }

    /// Open from `sqlite://<path>` URLs (`[database] state` / `mirror` of the config).
    pub async fn open_urls(
        state_url: &str,
        mirror_url: &str,
        opts: &StoreOptions,
    ) -> StoreResult<SqliteStore> {
        let path = |u: &str| {
            u.strip_prefix("sqlite://")
                .map(PathBuf::from)
                .ok_or_else(|| StoreError::Invalid(format!("not a sqlite:// URL: {u}")))
        };
        SqliteStore::open(&path(state_url)?, &path(mirror_url)?, opts).await
    }

    /// The state database file.
    pub fn state_path(&self) -> &Path {
        &self.state.path
    }

    /// The mirror database file.
    pub fn mirror_path(&self) -> &Path {
        &self.mirror.path
    }

    /// Read pool of the state database (extension point for read queries inside this crate).
    pub fn read_pool(&self) -> &SqlitePool {
        &self.state.read
    }

    /// Close every pool (WAL files are checkpointed by SQLite when the last connection closes).
    pub async fn close(&self) {
        for p in [
            &self.state.read,
            &self.mirror.read,
            &self.state.write,
            &self.mirror.write,
        ] {
            p.close().await;
        }
    }
}

async fn open_db(
    path: &Path,
    opts: &StoreOptions,
    migrator: sqlx::migrate::Migrator,
) -> StoreResult<Db> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    create_private_file(path)?;
    let base = SqliteConnectOptions::from_str("sqlite:")?
        .filename(path)
        .foreign_keys(true)
        .busy_timeout(Duration::from_millis(5000))
        .synchronous(SqliteSynchronous::Normal);
    let write = SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(1) // kept open for the app's lifetime: -wal/-shm exist for read-only readers
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(
            base.clone()
                .journal_mode(SqliteJournalMode::Wal)
                .create_if_missing(false),
        )
        .await?;
    migrator.run(&write).await?;
    let uv: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&write)
        .await?;
    if uv < SCHEMA_VERSION {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "PRAGMA user_version = {SCHEMA_VERSION}"
        )))
        .execute(&write)
        .await?;
    }
    let now = secmonk_model::time::now_iso();
    for (k, v) in [
        ("schema", SCHEMA_VERSION.to_string()),
        ("created_at", now),
        ("app_version", opts.app_version.clone()),
    ] {
        sqlx::query("INSERT INTO store_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING")
            .bind(k)
            .bind(v)
            .execute(&write)
            .await?;
    }
    sqlx::query("UPDATE store_meta SET value = ? WHERE key = 'app_version'")
        .bind(&opts.app_version)
        .execute(&write)
        .await?;
    let read = SqlitePoolOptions::new()
        .max_connections(opts.read_connections.max(1))
        .connect_with(base.read_only(true))
        .await?;
    Ok(Db {
        write,
        read,
        path: path.to_path_buf(),
    })
}

/// Create an empty database file with mode 0600 before SQLite would create it with the umask
/// (`db._create_private_file`). `-wal` / `-shm` inherit the main file's permissions.
fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    match o.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}
