//! Tri-state optional fields: absent (`None`), `null` (`Some(None)`), value (`Some(Some(v))`).
//!
//! Use with `#[serde(default, deserialize_with = "secmonk_model::nullable::deserialize",
//! skip_serializing_if = "Option::is_none")]` on an `Option<Option<T>>` field, so a document round-trips
//! byte for byte whether a nullable key was absent or `null`.

use serde::{Deserialize, Deserializer};

/// Deserialize a present key (value or `null`) as `Some(..)`; an absent key falls back to `default`.
pub fn deserialize<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}
