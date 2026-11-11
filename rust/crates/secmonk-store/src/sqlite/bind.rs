//! Values bound to statements built at run time (mirror rows), and their conversion from JSON.

use serde_json::Value;
use sqlx::query::Query;
use sqlx::sqlite::{Sqlite, SqliteArguments};

use crate::{StoreError, StoreResult, dumps};

/// A bindable SQLite value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Bind {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
}

impl Bind {
    /// A JSON value for column `col`: JSON columns become JSON text, scalars map to their SQLite type,
    /// arrays/objects in a scalar column are refused.
    pub(crate) fn from_json(
        table: &str,
        col: &str,
        v: &Value,
        json_col: bool,
    ) -> StoreResult<Bind> {
        if json_col {
            return Ok(dumps(v).map(Bind::Text).unwrap_or(Bind::Null));
        }
        Ok(match v {
            Value::Null => Bind::Null,
            Value::Bool(b) => Bind::Int(i64::from(*b)),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Bind::Int(i),
                None => Bind::Real(
                    n.as_f64()
                        .ok_or_else(|| StoreError::Invalid(format!("{table}.{col}: bad number")))?,
                ),
            },
            Value::String(s) => Bind::Text(s.clone()),
            Value::Array(_) | Value::Object(_) => {
                return Err(StoreError::Invalid(format!(
                    "{table}.{col}: structured value in a scalar column"
                )));
            }
        })
    }

    /// From a sea-query value (only the variants this crate produces).
    pub(crate) fn from_sea(v: sea_query::Value) -> StoreResult<Bind> {
        use sea_query::Value as V;
        Ok(match v {
            V::String(Some(s)) => Bind::Text(s),
            V::BigInt(Some(i)) => Bind::Int(i),
            V::Double(Some(f)) => Bind::Real(f),
            V::String(None) | V::BigInt(None) | V::Double(None) => Bind::Null,
            other => {
                return Err(StoreError::Invalid(format!(
                    "unexpected statement value {other:?}"
                )));
            }
        })
    }

    /// The sea-query value.
    pub(crate) fn to_sea(&self) -> sea_query::Value {
        use sea_query::Value as V;
        match self {
            Bind::Null => V::String(None),
            Bind::Int(i) => V::BigInt(Some(*i)),
            Bind::Real(f) => V::Double(Some(*f)),
            Bind::Text(s) => V::String(Some(s.clone())),
        }
    }

    pub(crate) fn bind_to<'q>(
        self,
        q: Query<'q, Sqlite, SqliteArguments>,
    ) -> Query<'q, Sqlite, SqliteArguments> {
        match self {
            Bind::Null => q.bind(None::<String>),
            Bind::Int(i) => q.bind(i),
            Bind::Real(f) => q.bind(f),
            Bind::Text(s) => q.bind(s),
        }
    }
}
