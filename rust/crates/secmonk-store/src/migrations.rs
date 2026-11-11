//! Embedded migrations (no sqlx macros): one ordered list per database and dialect, checksummed by sqlx.
//! Forward-only and additive (R5). A database with an applied migration this list does not know is refused
//! by sqlx (`VersionMissing`, R7).

use std::borrow::Cow;

use sqlx::SqlStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};

/// (version, description, sql) of the state database, SQLite dialect.
const STATE_SQLITE: &[(i64, &str, &str)] = &[(
    1,
    "schema v3",
    include_str!("../migrations/state/sqlite/0001_schema_v3.sql"),
)];

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
