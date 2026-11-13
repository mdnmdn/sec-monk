//! HS256 JWTs (no JWT crate) and the signing-secret file.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::fsutil;
use crate::keys::Principal;
use crate::scope::Scopes;
use crate::{AuthError, Result};

type HmacSha256 = Hmac<Sha256>;

const ISSUER: &str = "secmonk";
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
}

/// Issues and verifies HS256 tokens.
pub struct JwtSigner {
    secret: Vec<u8>,
    ttl_s: u64,
}

impl std::fmt::Debug for JwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSigner")
            .field("ttl_s", &self.ttl_s)
            .finish_non_exhaustive()
    }
}

impl JwtSigner {
    /// New signer with the HMAC secret and the token lifetime in seconds.
    pub fn new(secret: Vec<u8>, ttl_s: u64) -> JwtSigner {
        JwtSigner { secret, ttl_s }
    }

    /// Token lifetime in seconds.
    pub fn ttl_s(&self) -> u64 {
        self.ttl_s
    }

    fn mac(&self) -> HmacSha256 {
        // HMAC accepts any key length.
        HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length")
    }

    /// Issue a token for a principal. `exp` is `now + ttl`, capped at the principal's own expiry.
    pub fn issue(&self, principal: &Principal, now_s: u64) -> Result<IssuedToken> {
        let mut exp = now_s.saturating_add(self.ttl_s);
        if let Some(e) = principal.expires_at {
            exp = exp.min(e);
        }
        let claims = Claims {
            iss: ISSUER.into(),
            sub: principal.key_id.clone(),
            scp: principal.scopes.to_string(),
            iat: now_s,
            exp,
            jti: hex::encode(fsutil::random_bytes::<16>()?),
            prv: principal.provider.clone(),
        };
        let header = Header {
            alg: "HS256".into(),
            typ: Some("JWT".into()),
        };
        let enc = |v: &[u8]| URL_SAFE_NO_PAD.encode(v);
        let h = enc(&serde_json::to_vec(&header).map_err(|e| AuthError::Format(e.to_string()))?);
        let p = enc(&serde_json::to_vec(&claims).map_err(|e| AuthError::Format(e.to_string()))?);
        let signing_input = format!("{h}.{p}");
        let mut mac = self.mac();
        mac.update(signing_input.as_bytes());
        let sig = enc(&mac.finalize().into_bytes());
        Ok(IssuedToken {
            token: format!("{signing_input}.{sig}"),
            expires_at: exp,
            scopes: principal.scopes.clone(),
        })
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
        let sig = dec(s)?;
        let mut mac = self.mac();
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
