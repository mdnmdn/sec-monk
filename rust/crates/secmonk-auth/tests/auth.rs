//! Behaviour tests of the public API.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use secmonk_auth::*;

fn scopes(names: &[&str]) -> Scopes {
    Scopes::parse(names).unwrap()
}

fn at(s: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(s)
}

fn now_s(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn signer() -> JwtSigner {
    JwtSigner::new(vec![7u8; 32], 3600)
}

fn principal(scp: &[&str]) -> Principal {
    Principal {
        key_id: "abcd0123".into(),
        provider: "api_key".into(),
        name: "n".into(),
        scopes: scopes(scp),
        via: AuthVia::ApiKey,
        expires_at: None,
    }
}

#[test]
fn scope_parsing_and_implication() {
    let s = scopes(&["ui", "match"]);
    assert!(s.contains(Scope::UiRead) && s.contains(Scope::UiActions) && s.contains(Scope::Match));
    assert!(!s.contains(Scope::FeedRead));
    assert!(scopes(&["admin"]).contains(Scope::VulninfoRead));
    assert_eq!(s.to_string(), "ui:read ui:actions match");
    assert!(matches!(
        Scopes::parse(["nope"]),
        Err(AuthError::UnknownScope(_))
    ));
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, r#"["ui:read","ui:actions","match"]"#);
    assert_eq!(serde_json::from_str::<Scopes>(&json).unwrap(), s);
    assert!(serde_json::from_str::<Scopes>(r#"["x"]"#).is_err());
    assert!(matches!(
        s.require(Scope::Admin),
        Err(AuthError::Forbidden(Scope::Admin))
    ));
}

#[test]
fn key_generate_parse_verify() {
    let (plain, key) = ApiKey::generate().unwrap();
    let (id, secret) = parse_api_key(&plain).unwrap();
    assert_eq!(id, key.id);
    assert_eq!(id.len(), 8);
    assert_eq!(secret.len(), 43);
    assert!(parse_api_key("smk_xyz_abc").is_err());
    assert!(parse_api_key(&format!("{plain}=")).is_err());
    assert!(parse_api_key(&plain.replace("smk_", "smx_")).is_err());
    assert!(parse_api_key(&plain.to_uppercase()).is_err());

    let mut store = KeyStore::in_memory();
    let plain = store.create("ci", scopes(&["match"]), None).unwrap();
    let p = store.verify(&plain, SystemTime::now()).unwrap();
    assert_eq!(p.name, "ci");
    assert_eq!(p.via, AuthVia::ApiKey);
    // tampered secret
    let mut bad = plain.clone().into_bytes();
    let last = bad.len() - 1;
    bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
    let err = store
        .verify(&String::from_utf8(bad).unwrap(), SystemTime::now())
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));
    assert_eq!(err.public_message(), "invalid credentials");
    // unknown id
    let (other, _) = ApiKey::generate().unwrap();
    assert!(matches!(
        store.verify(&other, SystemTime::now()),
        Err(AuthError::UnknownKey)
    ));
}

#[test]
fn revoked_and_expired() {
    let mut store = KeyStore::in_memory();
    let plain = store
        .create("a", scopes(&["ui"]), Some(at(2_000_000_000)))
        .unwrap();
    assert!(store.verify(&plain, at(1_900_000_000)).is_ok());
    assert!(matches!(
        store.verify(&plain, at(2_000_000_000)),
        Err(AuthError::Expired)
    ));
    let id = store.revoke("a").unwrap();
    assert!(matches!(
        store.verify(&plain, at(1_900_000_000)),
        Err(AuthError::Revoked)
    ));
    assert!(!store.is_active(&id, at(1_900_000_000)));
    assert!(matches!(store.revoke("zzz"), Err(AuthError::NotFound(_))));
    assert!(matches!(
        store.create("a", scopes(&["ui"]), None),
        Err(AuthError::DuplicateName(_))
    ));
}

#[cfg(unix)]
#[test]
fn file_roundtrip_modes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    assert!(KeyStore::load(&path).unwrap().list().is_empty());

    let mut store = KeyStore::load(&path).unwrap();
    let plain = store
        .create("one", scopes(&["ui", "feed:read"]), Some(at(2_000_000_000)))
        .unwrap();
    store.create("two", scopes(&["admin"]), None).unwrap();
    store.revoke("two").unwrap();
    store.save().unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("[[key]]") && !text.contains(&plain[13..]));

    let back = KeyStore::load(&path).unwrap();
    assert_eq!(back.list(), store.list());
    assert!(back.verify(&plain, at(1_900_000_000)).is_ok());
    // no temp files left behind
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(matches!(KeyStore::load(&path), Err(AuthError::Format(_))));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(KeyStore::load(&path).is_err());
}

#[test]
fn jwt_roundtrip_and_failures() {
    let s = signer();
    let t = s.issue(&principal(&["ui", "match"]), 1000).unwrap();
    assert_eq!(t.expires_at, 4600);
    let c = s.verify(&t.token, 1500).unwrap();
    assert_eq!(
        (c.sub.as_str(), c.iss.as_str(), c.scp.as_str()),
        ("abcd0123", "secmonk", "ui:read ui:actions match")
    );
    assert_eq!(c.jti.len(), 32);
    // expired: no leeway
    assert!(matches!(s.verify(&t.token, 4600), Err(AuthError::Expired)));
    assert!(s.verify(&t.token, 4599).is_ok());
    // iat in the future beyond leeway
    assert!(s.verify(&t.token, 1000 - 31).is_err());
    assert!(s.verify(&t.token, 1000 - 30).is_ok());
    // wrong secret
    assert!(
        JwtSigner::new(vec![8u8; 32], 60)
            .verify(&t.token, 1500)
            .is_err()
    );

    let parts: Vec<&str> = t.token.split('.').collect();
    // tampered payload (admin scope) with the old signature
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    let payload = String::from_utf8(B.decode(parts[1]).unwrap())
        .unwrap()
        .replace("match", "admin");
    let forged = format!("{}.{}.{}", parts[0], B.encode(payload), parts[2]);
    assert!(s.verify(&forged, 1500).is_err());
    // tampered signature
    let mut sig = parts[2].to_string();
    sig.replace_range(0..1, if sig.starts_with('A') { "B" } else { "A" });
    assert!(
        s.verify(&format!("{}.{}.{sig}", parts[0], parts[1]), 1500)
            .is_err()
    );
    // extra segment, padding, length cap
    assert!(s.verify(&format!("{}.x", t.token), 1500).is_err());
    assert!(s.verify(&format!("{}=", t.token), 1500).is_err());
    assert!(s.verify(&"a".repeat(5000), 1500).is_err());
    assert!(s.verify("", 1500).is_err());
}

#[test]
fn jwt_alg_none_and_other_algs_rejected() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    let s = signer();
    let t = s.issue(&principal(&["admin"]), 1000).unwrap();
    let parts: Vec<&str> = t.token.split('.').collect();
    for alg in ["none", "HS384", "hs256", "RS256"] {
        let h = B.encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#));
        assert!(
            s.verify(&format!("{h}.{}.{}", parts[1], parts[2]), 1500)
                .is_err(),
            "{alg}"
        );
        assert!(
            s.verify(&format!("{h}.{}.", parts[1]), 1500).is_err(),
            "{alg} unsigned"
        );
    }
}

#[test]
fn jwt_requires_claims() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    use hmac::{Hmac, KeyInit, Mac};
    let sign = |payload: &str| {
        let h = B.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let input = format!("{h}.{}", B.encode(payload));
        let mut m = Hmac::<sha2::Sha256>::new_from_slice(&[7u8; 32]).unwrap();
        m.update(input.as_bytes());
        format!("{input}.{}", B.encode(m.finalize().into_bytes()))
    };
    let s = signer();
    let ok = r#"{"iss":"secmonk","sub":"a","scp":"ui:read","iat":1,"exp":9999,"jti":"j"}"#;
    assert!(s.verify(&sign(ok), 100).is_ok());
    assert!(
        s.verify(&sign(&ok.replace("secmonk", "other")), 100)
            .is_err()
    );
    for missing in [
        r#""sub":"a","#,
        r#""scp":"ui:read","#,
        r#""iat":1,"#,
        r#""jti":"j""#,
    ] {
        let p = ok.replace(missing, "");
        let p = p.replace(",}", "}");
        assert!(s.verify(&sign(&p), 100).is_err(), "missing {missing}");
    }
}

#[test]
fn secrets() {
    assert!(secret_from_env_value(&"ab".repeat(32)).is_ok());
    assert!(secret_from_env_value(&"ab".repeat(31)).is_err());
    assert_eq!(
        secret_from_env_value("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5")
            .unwrap()
            .len(),
        36
    );
    assert!(secret_from_env_value("short").is_err());
    assert!(secret_from_env_value("!!!not encoded at all, really not, no way!!!").is_err());

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("sub").join("jwt.key");
    let a = load_or_create_secret(&p).unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(load_or_create_secret(&p).unwrap(), a);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create_secret(&p).is_err());
    }
}

#[test]
fn authenticator_flow_and_revocation() {
    let mut store = KeyStore::in_memory();
    let plain = store.create("svc", scopes(&["match"]), None).unwrap();
    let auth = Authenticator::new(store, signer(), 600);
    let now = SystemTime::now();

    let issued = auth.exchange(&plain, now).unwrap();
    assert!(issued.scopes.contains(Scope::Match));
    let p = auth
        .authenticate(&format!("Bearer {}", issued.token), now)
        .unwrap();
    assert_eq!((p.via, p.name.as_str()), (AuthVia::Jwt, "svc"));
    assert_eq!(p.expires_at, Some(issued.expires_at));
    let p = auth.authenticate(&format!("apikey {plain}"), now).unwrap();
    assert_eq!(p.via, AuthVia::ApiKey);
    assert!(
        auth.authenticate(&format!("BEARER {}", issued.token), now)
            .is_ok()
    );

    for bad in [
        "",
        "Bearer",
        "Basic abc",
        &format!("Bearer {} extra", issued.token),
        "ApiKey nope",
    ] {
        assert!(auth.authenticate(bad, now).is_err(), "{bad:?}");
    }
    // expired token
    let later = now + Duration::from_secs(3601);
    assert!(matches!(
        auth.authenticate(&format!("Bearer {}", issued.token), later),
        Err(AuthError::Expired)
    ));
    assert!(auth.check_rate(&p, Instant::now()).is_ok());
}

#[cfg(unix)]
#[test]
fn revoked_key_jwt_rejected_after_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    let mut store = KeyStore::load(&path).unwrap();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    store.save().unwrap();
    let auth = Authenticator::new(KeyStore::load(&path).unwrap(), signer(), 600);
    let now = SystemTime::now();
    let tok = auth.exchange(&plain, now).unwrap().token;
    assert!(auth.authenticate(&format!("Bearer {tok}"), now).is_ok());

    // revoke through another handle on the file; the authenticator picks it up via mtime
    std::thread::sleep(Duration::from_millis(20));
    let mut other = KeyStore::load(&path).unwrap();
    other.revoke("svc").unwrap();
    other.save().unwrap();
    assert!(matches!(
        auth.authenticate(&format!("Bearer {tok}"), now),
        Err(AuthError::Revoked)
    ));
    assert!(auth.authenticate(&format!("ApiKey {plain}"), now).is_err());
    assert!(auth.exchange(&plain, now).is_err());
}

#[test]
fn revoked_key_jwt_rejected_in_memory() {
    let mut store = KeyStore::in_memory();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    let id = store.list()[0].id.clone();
    let auth = Authenticator::new(store, signer(), 600);
    let now = SystemTime::now();
    let tok = auth.exchange(&plain, now).unwrap().token;
    // a token for a key that is not in the store at all
    let ghost = signer()
        .issue(
            &Principal {
                key_id: "ffffffff".into(),
                ..principal(&["admin"])
            },
            now_s(now),
        )
        .unwrap();
    assert!(
        auth.authenticate(&format!("Bearer {}", ghost.token), now)
            .is_err()
    );
    assert!(auth.authenticate(&format!("Bearer {tok}"), now).is_ok());
    assert!(!id.is_empty());
}

#[test]
fn rate_limiter_refills() {
    let rl = RateLimiter::new(60); // 1 per second, burst 60
    let t0 = Instant::now();
    for _ in 0..60 {
        assert!(rl.check("k", t0));
    }
    assert!(!rl.check("k", t0));
    assert!(rl.check("other", t0));
    assert!(!rl.check("k", t0 + Duration::from_millis(500)));
    assert!(rl.check("k", t0 + Duration::from_millis(1100)));
    assert!(!rl.check("k", t0 + Duration::from_millis(1200)));
    // never exceeds capacity after a long idle
    let t1 = t0 + Duration::from_secs(3600);
    for _ in 0..60 {
        assert!(rl.check("k", t1));
    }
    assert!(!rl.check("k", t1));
}

#[test]
fn rate_limiter_memory_is_bounded() {
    let rl = RateLimiter::new(10);
    let t0 = Instant::now();
    for i in 0..12_000u64 {
        rl.check(&format!("k{i}"), t0 + Duration::from_millis(i));
    }
    // oldest entries were evicted, so the earliest key has a fresh full bucket again
    assert!(rl.check("k0", t0 + Duration::from_secs(20)));
}

#[test]
fn login_throttle() {
    let th = LoginThrottle::new();
    let t0 = Instant::now();
    for i in 0..9 {
        th.record_failure("1.2.3.4", t0 + Duration::from_secs(i));
        assert!(!th.is_blocked("1.2.3.4", t0 + Duration::from_secs(i)));
    }
    th.record_failure("1.2.3.4", t0 + Duration::from_secs(9));
    assert!(th.is_blocked("1.2.3.4", t0 + Duration::from_secs(10)));
    assert!(!th.is_blocked("5.6.7.8", t0 + Duration::from_secs(10)));
    assert!(th.is_blocked("1.2.3.4", t0 + Duration::from_secs(300)));
    assert!(!th.is_blocked("1.2.3.4", t0 + Duration::from_secs(310)));
    // failures spread beyond the window do not add up
    let th = LoginThrottle::new();
    for i in 0..20 {
        th.record_failure("a", t0 + Duration::from_secs(i * 100));
    }
    assert!(!th.is_blocked("a", t0 + Duration::from_secs(1900)));
}

#[test]
fn exchange_from_throttles_bad_logins() {
    let auth = Authenticator::new(KeyStore::in_memory(), signer(), 600);
    let (bad, _) = ApiKey::generate().unwrap();
    let t0 = Instant::now();
    for _ in 0..10 {
        assert!(matches!(
            auth.exchange_from("c", &bad, SystemTime::now(), t0),
            Err(AuthError::UnknownKey)
        ));
    }
    assert!(matches!(
        auth.exchange_from("c", &bad, SystemTime::now(), t0),
        Err(AuthError::RateLimited)
    ));
}

#[test]
fn public_messages_do_not_reveal() {
    for e in [
        AuthError::UnknownKey,
        AuthError::InvalidCredentials,
        AuthError::Expired,
        AuthError::Revoked,
    ] {
        assert_eq!(e.public_message(), "invalid credentials");
    }
}

/// A second strategy plugs in without touching the authenticator: a fake "proxy header" provider that trusts
/// `Authorization: Proxy <user>` and offers a `proxy` login.
#[derive(Debug)]
struct FakeProxy {
    revoked: std::sync::Mutex<bool>,
}

impl secmonk_auth::AuthProvider for FakeProxy {
    fn name(&self) -> &str {
        "proxy"
    }
    fn login_methods(&self) -> &[&str] {
        &["proxy"]
    }
    fn authenticate(
        &self,
        ctx: &secmonk_auth::RequestContext<'_>,
        _now: SystemTime,
    ) -> Option<secmonk_auth::Result<Principal>> {
        let (scheme, user) = ctx.authorization_parts()?.ok()?;
        scheme.eq_ignore_ascii_case("proxy").then(|| {
            Ok(Principal {
                key_id: user.to_owned(),
                provider: "proxy".into(),
                name: user.to_owned(),
                scopes: scopes(&["ui:read"]),
                via: AuthVia::External,
                expires_at: None,
            })
        })
    }
    fn login(
        &self,
        _m: &str,
        params: &serde_json::Value,
        _now: SystemTime,
    ) -> secmonk_auth::Result<Principal> {
        let user = params["user"].as_str().unwrap_or_default().to_owned();
        Ok(Principal {
            key_id: user.clone(),
            provider: "proxy".into(),
            name: user,
            scopes: scopes(&["match"]),
            via: AuthVia::External,
            expires_at: None,
        })
    }
    fn revalidate(&self, subject: &str, _now: SystemTime) -> secmonk_auth::Result<String> {
        if *self.revoked.lock().unwrap() {
            Err(secmonk_auth::AuthError::Revoked)
        } else {
            Ok(subject.to_owned())
        }
    }
}

#[test]
fn provider_chain_supports_another_strategy() {
    use std::sync::Arc;
    let mut store = KeyStore::in_memory();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    let proxy = Arc::new(FakeProxy {
        revoked: std::sync::Mutex::new(false),
    });
    let auth = Authenticator::with_providers(
        vec![
            Arc::new(secmonk_auth::ApiKeyProvider::new(store)),
            proxy.clone(),
        ],
        signer(),
        600,
    );
    let now = SystemTime::now();
    assert_eq!(auth.provider_names(), ["api_key", "proxy"]);
    assert_eq!(auth.login_methods(), ["api_key", "proxy"]);
    // direct credentials of both strategies
    assert_eq!(
        auth.authenticate(&format!("ApiKey {plain}"), now)
            .unwrap()
            .provider,
        "api_key"
    );
    let p = auth.authenticate("Proxy alice", now).unwrap();
    assert_eq!((p.provider.as_str(), p.via), ("proxy", AuthVia::External));
    // a session from the proxy login carries prv=proxy and is revalidated with that provider
    let tok = auth
        .login("proxy", &serde_json::json!({"user": "bob"}), now)
        .unwrap()
        .token;
    let p = auth.authenticate(&format!("Bearer {tok}"), now).unwrap();
    assert_eq!(
        (p.provider.as_str(), p.key_id.as_str(), p.via),
        ("proxy", "bob", AuthVia::Jwt)
    );
    assert!(p.scopes.contains(Scope::Match));
    *proxy.revoked.lock().unwrap() = true;
    assert!(auth.authenticate(&format!("Bearer {tok}"), now).is_err());
    // unknown login method and unknown scheme
    assert!(auth.login("oidc", &serde_json::json!({}), now).is_err());
    assert!(auth.authenticate("Digest x", now).is_err());
    assert!(matches!(
        auth.authenticate_request(&secmonk_auth::RequestContext::default(), now),
        Err(secmonk_auth::AuthError::Missing)
    ));
}
