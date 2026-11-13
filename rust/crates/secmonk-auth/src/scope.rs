//! Scopes.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::AuthError;

/// One permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `ui:read`: every GET of `/api`.
    UiRead,
    /// `ui:actions`: jobs, match, save.
    UiActions,
    /// `feed:read`: mirror feed.
    FeedRead,
    /// `match`: matching API.
    Match,
    /// `vulninfo:read`: vulnerability info API.
    VulninfoRead,
    /// `admin`: implies all.
    Admin,
}

impl Scope {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::UiRead => "ui:read",
            Scope::UiActions => "ui:actions",
            Scope::FeedRead => "feed:read",
            Scope::Match => "match",
            Scope::VulninfoRead => "vulninfo:read",
            Scope::Admin => "admin",
        }
    }

    /// Parse one scope name (no shorthand).
    pub fn parse(s: &str) -> Result<Scope, AuthError> {
        Ok(match s {
            "ui:read" => Scope::UiRead,
            "ui:actions" => Scope::UiActions,
            "feed:read" => Scope::FeedRead,
            "match" => Scope::Match,
            "vulninfo:read" => Scope::VulninfoRead,
            "admin" => Scope::Admin,
            other => return Err(AuthError::UnknownScope(other.to_string())),
        })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of scopes; `admin` implies every scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scopes(BTreeSet<Scope>);

impl Scopes {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse names, accepting the shorthand `ui` (= `ui:read` + `ui:actions`).
    pub fn parse<I, S>(names: I) -> Result<Scopes, AuthError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for n in names {
            match n.as_ref() {
                "ui" => {
                    set.insert(Scope::UiRead);
                    set.insert(Scope::UiActions);
                }
                other => {
                    set.insert(Scope::parse(other)?);
                }
            }
        }
        Ok(Scopes(set))
    }

    /// Parse a space separated list (the JWT `scp` claim).
    pub fn parse_spaced(s: &str) -> Result<Scopes, AuthError> {
        Scopes::parse(s.split_whitespace())
    }

    /// Add a scope.
    pub fn insert(&mut self, scope: Scope) {
        self.0.insert(scope);
    }

    /// Whether the set grants `scope` (`admin` grants everything).
    pub fn contains(&self, scope: Scope) -> bool {
        self.0.contains(&Scope::Admin) || self.0.contains(&scope)
    }

    /// Require a scope or fail with [`AuthError::Forbidden`].
    pub fn require(&self, scope: Scope) -> Result<(), AuthError> {
        if self.contains(scope) {
            Ok(())
        } else {
            Err(AuthError::Forbidden(scope))
        }
    }

    /// Iterate the explicitly listed scopes.
    pub fn iter(&self) -> impl Iterator<Item = Scope> + '_ {
        self.0.iter().copied()
    }

    /// True when no scope is listed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(s.as_str())?;
        }
        Ok(())
    }
}

impl Serialize for Scopes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter().map(|x| x.as_str()))
    }
}

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(d)?;
        Scopes::parse(names).map_err(serde::de::Error::custom)
    }
}
