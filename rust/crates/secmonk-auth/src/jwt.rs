//! HS256 JWTs (no JWT crate) and the signing-secret file.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsutil;
use crate::keys::Principal;
use crate::scope::Scopes;
use crate::{AuthError, Result};

type HmacSha256 = Hmac<Sha256>;

/// The `iss` of the session tokens this server issues; a `Bearer` token with another issuer goes to the providers.
pub const ISSUER: &str = "secmonk";
const KID_LEN: usize = 8;
const MAX_SUBJECT_LEN: usize = 256;
const MAX_TOKEN_LEN: usize = 4096;
const IAT_LEEWAY_S: u64 = 30;
const MIN_SECRET_BYTES: usize = 32;

/// JWT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer, always `secmonk`.
    pub iss: String,
    /// Key id.
    pub sub: String,
    /// Scopes, space separated.
    pub scp: String,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
    /// Random token id.
    pub jti: String,
    /// The provider that authenticated the subject at login (absent in tokens of the first version: `api_key`).
    #[serde(default = "default_provider")]
    pub prv: String,
}

fn default_provider() -> String {
    crate::keys::API_KEY_PROVIDER.into()
}

impl Claims {
    /// The scopes of the `scp` claim.
    pub fn scopes(&self) -> Result<Scopes> {
        Scopes::parse_spaced(&self.scp)
    }
}

/// A freshly issued token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuedToken {
    /// The compact JWT.
    pub token: String,
    /// Expiry, unix seconds.
    pub expires_at: u64,
    /// Scopes carried by the token.
    pub scopes: Scopes,
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// Secret bytes that are overwritten with zeros when dropped (best effort: no `unsafe`, the optimizer is kept
/// from eliding the writes with `black_box`; copies made by the allocator on growth are not covered).
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// One HMAC key and its id.
struct SigningKey {
    kid: String,
    secret: SecretBytes,
}

impl SigningKey {
    fn new(secret: Vec<u8>) -> SigningKey {
        SigningKey {
            kid: key_id(&secret),
            secret: SecretBytes(secret),
        }
    }

    fn mac(&self) -> HmacSha256 {
        // HMAC accepts any key length.
        HmacSha256::new_from_slice(&self.secret.0).expect("hmac accepts any key length")
    }
}

/// The `kid` of a secret: the first 8 hex chars of its SHA-256 (public; identifies, never reveals).
pub fn key_id(secret: &[u8]) -> String {
    let mut h = hex::encode(Sha256::digest(secret));
    h.truncate(KID_LEN);
    h
}

#[derive(Deserialize)]
struct IssuerOnly {
    #[serde(default)]
    iss: Option<String>,
}

/// The `iss` claim of a compact JWT **without verifying it** (to route a `Bearer` token to the right verifier,
/// never to trust it). `None` for anything that is not a three-segment JWT with a JSON payload.
pub fn peek_issuer(token: &str) -> Option<String> {
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    let mut parts = token.split('.');
    let (_h, p, _s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(p).ok()?;
    serde_json::from_slice::<IssuerOnly>(&payload).ok()?.iss
}

/// The `sub` claim of a compact JWT **without verifying it** (throttle bucketing only).
pub(crate) fn peek_subject(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct SubOnly {
        #[serde(default)]
        sub: Option<String>,
    }
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    let p = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(p).ok()?;
    serde_json::from_slice::<SubOnly>(&payload)
        .ok()?
        .sub
        .filter(|s| !s.is_empty() && s.len() <= MAX_SUBJECT_LEN)
}

/// Issues and verifies HS256 tokens. Tokens carry the `kid` of the key that signed them; a signer built with
/// [`JwtSigner::with_previous`] still verifies tokens of the previous keys, so a secret can be rotated without
/// logging everyone out (drop the previous key once the longest token lifetime has passed).
pub struct JwtSigner {
    current: SigningKey,
    previous: Vec<SigningKey>,
    ttl_s: u64,
}

impl std::fmt::Debug for JwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSigner")
            .field("kid", &self.current.kid)
            .field("previous", &self.previous.len())
            .field("ttl_s", &self.ttl_s)
            .finish_non_exhaustive()
    }
}

impl JwtSigner {
    /// New signer with the HMAC secret and the token lifetime in seconds.
    pub fn new(secret: Vec<u8>, ttl_s: u64) -> JwtSigner {
        JwtSigner {
            current: SigningKey::new(secret),
            previous: Vec::new(),
            ttl_s,
        }
    }

    /// The same signer that also verifies tokens signed with `previous` secrets (rotation). A previous secret
    /// equal to the current one is ignored.
    #[must_use]
    pub fn with_previous(mut self, previous: Vec<Vec<u8>>) -> JwtSigner {
        for secret in previous {
            let k = SigningKey::new(secret);
            if k.kid != self.current.kid && !self.previous.iter().any(|p| p.kid == k.kid) {
                self.previous.push(k);
            }
        }
        self
    }

    /// Token lifetime in seconds.
    pub fn ttl_s(&self) -> u64 {
        self.ttl_s
    }

    /// The `kid` new tokens carry.
    pub fn kid(&self) -> &str {
        &self.current.kid
    }

    /// Issue a token for a principal. `exp` is `now + ttl`, capped at the principal's own expiry.
    pub fn issue(&self, principal: &Principal, now_s: u64) -> Result<IssuedToken> {
        let mut exp = now_s.saturating_add(self.ttl_s);
        if let Some(e) = principal.expires_at {
            exp = exp.min(e);
        }
        let claims = Claims {
            iss: ISSUER.into(),
            sub: principal.subject.clone(),
            scp: principal.scopes.to_string(),
            iat: now_s,
            exp,
            jti: hex::encode(fsutil::random_bytes::<16>()?),
            prv: principal.provider.clone(),
        };
        let header = Header {
            alg: "HS256".into(),
            typ: Some("JWT".into()),
            kid: Some(self.current.kid.clone()),
        };
        let enc = |v: &[u8]| URL_SAFE_NO_PAD.encode(v);
        let h = enc(&serde_json::to_vec(&header).map_err(|e| AuthError::Format(e.to_string()))?);
        let p = enc(&serde_json::to_vec(&claims).map_err(|e| AuthError::Format(e.to_string()))?);
        let signing_input = format!("{h}.{p}");
        let mut mac = self.current.mac();
        mac.update(signing_input.as_bytes());
        let sig = enc(&mac.finalize().into_bytes());
        Ok(IssuedToken {
            token: format!("{signing_input}.{sig}"),
            expires_at: exp,
            scopes: principal.scopes.clone(),
        })
    }

    /// The key a token names: by `kid` (current or previous), or the current key for a token without one
    /// (tokens of the first version).
    fn key_for(&self, kid: Option<&str>) -> Option<&SigningKey> {
        match kid {
            None => Some(&self.current),
            Some(k) => std::iter::once(&self.current)
                .chain(&self.previous)
                .find(|s| s.kid == k),
        }
    }

    /// Verify a token and return its claims.
    pub fn verify(&self, token: &str, now_s: u64) -> Result<Claims> {
        let malformed = |m: &str| AuthError::Malformed(m.to_string());
        if token.len() > MAX_TOKEN_LEN {
            return Err(malformed("token too long"));
        }
        let parts: Vec<&str> = token.split('.').collect();
        let [h, p, s] = parts[..] else {
            return Err(malformed("token must have three segments"));
        };
        let dec = |seg: &str| {
            URL_SAFE_NO_PAD
                .decode(seg)
                .map_err(|_| malformed("bad base64url segment"))
        };
        let header: Header =
            serde_json::from_slice(&dec(h)?).map_err(|_| malformed("bad header"))?;
        if header.alg != "HS256" {
            return Err(malformed("unsupported alg"));
        }
        let key = self
            .key_for(header.kid.as_deref())
            .ok_or(AuthError::InvalidCredentials)?;
        let sig = dec(s)?;
        let mut mac = key.mac();
        mac.update(h.as_bytes());
        mac.update(b".");
        mac.update(p.as_bytes());
        mac.verify_slice(&sig)
            .map_err(|_| AuthError::InvalidCredentials)?;
        let claims: Claims =
            serde_json::from_slice(&dec(p)?).map_err(|_| malformed("bad claims"))?;
        if claims.iss != ISSUER || claims.sub.is_empty() || claims.jti.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        if claims.exp <= now_s {
            return Err(AuthError::Expired);
        }
        if claims.iat > now_s.saturating_add(IAT_LEEWAY_S) {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(claims)
    }
}

/// Read the signing secret from `path` (hex), creating 32 random bytes (mode 0600, atomically) if missing.
/// An existing file readable by group/other is refused on unix.
pub fn load_or_create_secret(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        let fresh = hex::encode(fsutil::random_bytes::<32>()?);
        fsutil::create_private_new(path, fresh.as_bytes())?;
    }
    fsutil::check_mode(path, 0o077)?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| AuthError::io(format!("read {}", path.display()), e))?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| AuthError::Format(format!("{}: not a hex secret", path.display())))?;
    if bytes.len() < MIN_SECRET_BYTES {
        return Err(AuthError::Format(format!(
            "{}: secret shorter than {MIN_SECRET_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Decode a secret given in an environment variable: hex or base64 (standard or url-safe), at least 32 bytes.
pub fn secret_from_env_value(value: &str) -> Result<Vec<u8>> {
    let v = value.trim();
    let decoded = hex::decode(v)
        .ok()
        .or_else(|| STANDARD.decode(v).ok())
        .or_else(|| URL_SAFE.decode(v).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(v).ok());
    match decoded {
        Some(b) if b.len() >= MIN_SECRET_BYTES => Ok(b),
        Some(_) => Err(AuthError::Format(format!(
            "JWT secret must decode to at least {MIN_SECRET_BYTES} bytes"
        ))),
        None => Err(AuthError::Format("JWT secret must be hex or base64".into())),
    }
}
