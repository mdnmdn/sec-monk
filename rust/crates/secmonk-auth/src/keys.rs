//! API keys and the `api_keys.toml` store.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::fsutil;
use crate::scope::Scopes;
use crate::timefmt::{format_rfc3339, parse_rfc3339, unix_secs};
use crate::{AuthError, Result};

const PREFIX: &str = "smk_";

/// How a request carried its credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthVia {
    /// Directly with an API key (`Authorization: ApiKey …`).
    ApiKey,
    /// With a session JWT issued by this server after a login (any provider).
    Jwt,
    /// Directly with another provider's credential (a TLS client certificate, an external token).
    External,
}

/// Name of the API-key provider: the `prv` claim of the JWTs it backs and the `method` of its logins.
pub const API_KEY_PROVIDER: &str = "api_key";

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Stable subject id within its provider (the API key id; safe for logs). Rate limits and audit use
    /// `provider:key_id`.
    pub key_id: String,
    /// The provider that authenticated the subject ([`crate::AuthProvider::name`], `api_key` for API keys).
    pub provider: String,
    /// Key name.
    pub name: String,
    /// Granted scopes.
    pub scopes: Scopes,
    /// How the caller authenticated.
    pub via: AuthVia,
    /// Expiry (unix seconds) of the credential, if any.
    pub expires_at: Option<u64>,
}

/// Public parts of a freshly generated key: id and the hash to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    /// 8 lowercase hex chars.
    pub id: String,
    /// `hex(sha256(secret))`.
    pub hash: String,
}

fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

impl ApiKey {
    /// Generate a key. Returns the plaintext (`smk_<id>_<secret>`, shown once) and the storable parts.
    pub fn generate() -> Result<(String, ApiKey)> {
        let id = hex::encode(fsutil::random_bytes::<4>()?);
        let secret = URL_SAFE_NO_PAD.encode(fsutil::random_bytes::<32>()?);
        let hash = hash_secret(&secret);
        Ok((format!("{PREFIX}{id}_{secret}"), ApiKey { id, hash }))
    }
}

/// Strictly parse `smk_<id>_<secret>` into `(id, secret)`.
pub fn parse_api_key(s: &str) -> Result<(String, String)> {
    let bad = || AuthError::Malformed("not an API key".into());
    let rest = s.strip_prefix(PREFIX).ok_or_else(bad)?;
    let (id, secret) = rest.split_once('_').ok_or_else(bad)?;
    if id.len() != 8
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(bad());
    }
    // 32 bytes base64url without padding is exactly 43 chars; check canonical decoding.
    if secret.len() != 43 {
        return Err(bad());
    }
    match URL_SAFE_NO_PAD.decode(secret) {
        Ok(v) if v.len() == 32 => {}
        _ => return Err(bad()),
    }
    Ok((id.to_string(), secret.to_string()))
}

/// One `[[key]]` entry of `api_keys.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Public id.
    pub id: String,
    /// Unique human name.
    pub name: String,
    /// `hex(sha256(secret))`.
    pub hash: String,
    /// Granted scopes.
    pub scopes: Scopes,
    /// Creation time, RFC 3339 UTC.
    pub created: String,
    /// Optional expiry, RFC 3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Revoked flag.
    #[serde(default)]
    pub revoked: bool,
}

impl KeyRecord {
    fn expires_secs(&self) -> Option<u64> {
        self.expires
            .as_deref()
            .and_then(parse_rfc3339)
            .map(unix_secs)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct KeyFile {
    #[serde(default, rename = "key", skip_serializing_if = "Vec::is_empty")]
    keys: Vec<KeyRecord>,
}

/// The keys file in memory.
#[derive(Debug, Clone, Default)]
pub struct KeyStore {
    path: Option<PathBuf>,
    keys: Vec<KeyRecord>,
    loaded_mtime: Option<SystemTime>,
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

impl KeyStore {
    /// Load the store. A missing file is an empty store; a group/other-writable file is refused (unix).
    pub fn load(path: impl Into<PathBuf>) -> Result<KeyStore> {
        let path = path.into();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                fsutil::check_mode(&path, 0o022)?;
                let file: KeyFile = toml::from_str(&text)
                    .map_err(|e| AuthError::Format(format!("{}: {e}", path.display())))?;
                let mut seen = std::collections::HashSet::new();
                for k in &file.keys {
                    if !seen.insert(k.name.as_str()) {
                        return Err(AuthError::Format(format!(
                            "{}: duplicate key name {:?}",
                            path.display(),
                            k.name
                        )));
                    }
                }
                let loaded_mtime = mtime(&path);
                Ok(KeyStore {
                    path: Some(path),
                    keys: file.keys,
                    loaded_mtime,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeyStore {
                path: Some(path),
                keys: Vec::new(),
                loaded_mtime: None,
            }),
            Err(e) => Err(AuthError::io(format!("read {}", path.display()), e)),
        }
    }

    /// An in-memory store that cannot be saved (tests, auth disabled).
    pub fn in_memory() -> KeyStore {
        KeyStore::default()
    }

    /// The file path, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// True when the file's mtime differs from the one seen at load/save time.
    pub fn file_changed(&self) -> bool {
        match &self.path {
            Some(p) => mtime(p) != self.loaded_mtime,
            None => false,
        }
    }

    /// All records.
    pub fn list(&self) -> &[KeyRecord] {
        &self.keys
    }

    /// Create a key; returns the plaintext (shown once). Does not save; call [`KeyStore::save`].
    pub fn create(
        &mut self,
        name: &str,
        scopes: Scopes,
        expires: Option<SystemTime>,
    ) -> Result<String> {
        if name.trim().is_empty() {
            return Err(AuthError::Malformed("empty key name".into()));
        }
        if self.keys.iter().any(|k| k.name == name) {
            return Err(AuthError::DuplicateName(name.to_string()));
        }
        let (plaintext, key) = loop {
            let (p, k) = ApiKey::generate()?;
            if !self.keys.iter().any(|r| r.id == k.id) {
                break (p, k);
            }
        };
        self.keys.push(KeyRecord {
            id: key.id,
            name: name.to_string(),
            hash: key.hash,
            scopes,
            created: format_rfc3339(SystemTime::now()),
            expires: expires.map(format_rfc3339),
            revoked: false,
        });
        Ok(plaintext)
    }

    /// Revoke a key by id or name. Returns the revoked record's id.
    pub fn revoke(&mut self, id_or_name: &str) -> Result<String> {
        let idx = self
            .keys
            .iter()
            .position(|k| k.id == id_or_name)
            .or_else(|| self.keys.iter().position(|k| k.name == id_or_name))
            .ok_or_else(|| AuthError::NotFound(id_or_name.to_string()))?;
        self.keys[idx].revoked = true;
        Ok(self.keys[idx].id.clone())
    }

    /// Write the file atomically with mode 0600.
    pub fn save(&mut self) -> Result<()> {
        let path = self
            .path
            .clone()
            .ok_or_else(|| AuthError::Format("in-memory key store has no path".into()))?;
        let text = toml::to_string_pretty(&KeyFile {
            keys: self.keys.clone(),
        })
        .map_err(|e| AuthError::Format(format!("serialize keys: {e}")))?;
        fsutil::write_private(&path, text.as_bytes())?;
        self.loaded_mtime = mtime(&path);
        Ok(())
    }

    /// Verify a plaintext key and return its principal (`via = ApiKey`).
    pub fn verify(&self, plaintext: &str, now: SystemTime) -> Result<Principal> {
        let (id, secret) = parse_api_key(plaintext)?;
        let computed = hash_secret(&secret);
        let Some(rec) = self.keys.iter().find(|k| k.id == id) else {
            // Burn a comparison so unknown ids are not noticeably faster.
            let _ = computed.as_bytes().ct_eq(computed.as_bytes());
            return Err(AuthError::UnknownKey);
        };
        if !bool::from(computed.as_bytes().ct_eq(rec.hash.as_bytes())) {
            return Err(AuthError::InvalidCredentials);
        }
        if rec.revoked {
            return Err(AuthError::Revoked);
        }
        let now_s = unix_secs(now);
        let expires_at = rec.expires_secs();
        if rec.expires.is_some() && expires_at.is_none_or(|e| e <= now_s) {
            return Err(AuthError::Expired);
        }
        Ok(Principal {
            key_id: rec.id.clone(),
            provider: API_KEY_PROVIDER.into(),
            name: rec.name.clone(),
            scopes: rec.scopes.clone(),
            via: crate::AuthVia::ApiKey,
            expires_at,
        })
    }

    /// The record of a key that exists, is not revoked and not expired.
    pub fn active_record(&self, id: &str, now: SystemTime) -> Option<&KeyRecord> {
        let rec = self.keys.iter().find(|k| k.id == id)?;
        if rec.revoked {
            return None;
        }
        if rec.expires.is_some() && rec.expires_secs().is_none_or(|e| e <= unix_secs(now)) {
            return None;
        }
        Some(rec)
    }

    /// Whether the key exists, is not revoked and not expired.
    pub fn is_active(&self, id: &str, now: SystemTime) -> bool {
        self.active_record(id, now).is_some()
    }
}
