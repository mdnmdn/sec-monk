//! Embedded migrations (no sqlx macros): one ordered list per database and dialect, checksummed by sqlx.
//! Forward-only and additive (R5). A database with an applied migration this list does not know is refused
//! by sqlx (`VersionMissing`, R7).

use std::borrow::Cow;

use sqlx::SqlStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};

/// (version, description, sql) of the state database, SQLite dialect.
const STATE_SQLITE: &[(i64, &str, &str)] = &[
    (
        1,
        "schema v3",
        include_str!("../migrations/state/sqlite/0001_schema_v3.sql"),
    ),
    (
        2,
        "node cache",
        include_str!("../migrations/state/sqlite/0002_node_cache.sql"),
    ),
];

/// (version, description, sql) of the mirror database, SQLite dialect.
const MIRROR_SQLITE: &[(i64, &str, &str)] = &[
    (
        1,
        "schema v3",
        include_str!("../migrations/mirror/sqlite/0001_schema_v3.sql"),
    ),
    (
        2,
        "source applied seq",
        include_str!("../migrations/mirror/sqlite/0002_source_applied.sql"),
    ),
    (
        3,
        "source applied generation",
        include_str!("../migrations/mirror/sqlite/0003_source_applied_generation.sql"),
    ),
    (
        4,
        "node versions",
        include_str!("../migrations/mirror/sqlite/0004_node_versions.sql"),
    ),
];

fn migrator(list: &'static [(i64, &'static str, &'static str)]) -> Migrator {
    Migrator::with_migrations(
        list.iter()
            .map(|(v, d, sql)| {
                Migration::new(
                    *v,
                    Cow::Borrowed(*d),
                    MigrationType::Simple,
                    SqlStr::from_static(sql),
                    false,
                )
            })
            .collect(),
    )
}

/// Migrator of the state database.
pub fn state_sqlite() -> Migrator {
    migrator(STATE_SQLITE)
}

/// Migrator of the mirror database.
pub fn mirror_sqlite() -> Migrator {
    migrator(MIRROR_SQLITE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory() -> sqlx::SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    async fn tables(pool: &sqlx::SqlitePool) -> Vec<String> {
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    /// Fresh database: every migration applies. Database at the previous version: only the new one runs, and the
    /// data of the older tables is untouched.
    #[tokio::test]
    async fn node_migrations_apply_fresh_and_on_the_previous_version() {
        for (list, newest, probe_new) in [
            (MIRROR_SQLITE, 4, "snapshot_diff"),
            (STATE_SQLITE, 2, "component_match"),
        ] {
            let fresh = memory().await;
            migrator(list).run(&fresh).await.unwrap();
            let t = tables(&fresh).await;
            assert!(t.iter().any(|n| n == probe_new), "{t:?}");

            let prev = memory().await;
            migrator(&list[..list.len() - 1]).run(&prev).await.unwrap();
            assert!(!tables(&prev).await.iter().any(|n| n == probe_new));
            sqlx::query("INSERT INTO store_meta(key, value) VALUES ('probe', 'kept')")
                .execute(&prev)
                .await
                .unwrap();
            migrator(list).run(&prev).await.unwrap();
            assert_eq!(tables(&prev).await, t);
            let v: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
                .fetch_one(&prev)
                .await
                .unwrap();
            assert_eq!(v, newest);
            let kept: String = sqlx::query_scalar("SELECT value FROM store_meta WHERE key='probe'")
                .fetch_one(&prev)
                .await
                .unwrap();
            assert_eq!(kept, "kept");
        }
    }
}
