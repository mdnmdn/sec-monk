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
        subject: "abcd0123".into(),
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

    // revoke through another handle on the file; the authenticator picks it up via the fingerprint (an explicit
    // reload here; requests look at the file at most once per second)
    let mut other = KeyStore::load(&path).unwrap();
    other.revoke("svc").unwrap();
    other.save().unwrap();
    assert!(auth.reload().unwrap());
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
                subject: "ffffffff".into(),
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
    let c = "1.2.3.4";
    for i in 0..9 {
        th.record_failure(c, Some("k1"), t0 + Duration::from_secs(i));
        assert!(!th.is_blocked(c, Some("k1"), t0 + Duration::from_secs(i)));
    }
    th.record_failure(c, Some("k1"), t0 + Duration::from_secs(9));
    let t10 = t0 + Duration::from_secs(10);
    // the key id is blocked from that client only; other ids and other clients go on
    assert!(th.is_blocked(c, Some("k1"), t10));
    assert!(!th.is_blocked(c, Some("k2"), t10));
    assert!(!th.is_blocked(c, None, t10));
    assert!(!th.is_blocked("5.6.7.8", Some("k1"), t10));
    // a success does not lift an active block
    th.record_success(c, Some("k1"), t10);
    assert!(th.is_blocked(c, Some("k1"), t0 + Duration::from_secs(300)));
    assert!(!th.is_blocked(c, Some("k1"), t0 + Duration::from_secs(310)));
    // failures spread beyond the window do not add up
    let th = LoginThrottle::new();
    for i in 0..20 {
        th.record_failure("a", Some("k"), t0 + Duration::from_secs(i * 100));
    }
    assert!(!th.is_blocked("a", Some("k"), t0 + Duration::from_secs(1900)));
    // a success forgets the pair's failures
    let th = LoginThrottle::new();
    for _ in 0..9 {
        th.record_failure("a", Some("k"), t0);
    }
    th.record_success("a", Some("k"), t0);
    th.record_failure("a", Some("k"), t0);
    assert!(!th.is_blocked("a", Some("k"), t0));
}

#[test]
fn login_throttle_per_client_cap() {
    let th = LoginThrottle::new();
    let t0 = Instant::now();
    // a guesser rotating key ids: 100 failures block the whole address
    for i in 0..LoginThrottle::CLIENT_MAX_FAILURES {
        assert!(!th.is_blocked("c", Some(&format!("id{i}")), t0));
        th.record_failure("c", Some(&format!("id{i}")), t0);
    }
    assert!(th.is_blocked("c", Some("fresh"), t0));
    assert!(th.is_blocked("c", None, t0));
    assert!(!th.is_blocked("other", None, t0));
    th.record_success("c", Some("fresh"), t0);
    assert!(
        th.is_blocked("c", None, t0),
        "success never clears the client block"
    );
}

#[test]
fn exchange_from_throttles_bad_logins() {
    let mut store = KeyStore::in_memory();
    let good = store.create("good", scopes(&["ui"]), None).unwrap();
    let auth = Authenticator::new(store, signer(), 600);
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
    // the burst against one key id does not lock out the other keys of the address
    assert!(
        auth.exchange_from("c", &good, SystemTime::now(), t0)
            .is_ok()
    );
}

#[test]
fn direct_credentials_are_throttled_too() {
    let mut store = KeyStore::in_memory();
    let good = store.create("good", scopes(&["ui"]), None).unwrap();
    let auth = Authenticator::new(store, signer(), 600);
    let (id, _) = parse_api_key(&good).unwrap();
    // the right id with a wrong secret, ten times
    let wrong = format!("smk_{id}_{}", "A".repeat(43));
    let t0 = Instant::now();
    let now = SystemTime::now();
    let hdr = format!("ApiKey {wrong}");
    let ctx = RequestContext::new(Some(&hdr), Some("10.0.0.1")).with_request("GET", "/api/meta");
    for _ in 0..10 {
        assert!(matches!(
            auth.authenticate_from(&ctx, now, t0),
            Err(AuthError::InvalidCredentials)
        ));
    }
    // now that id is blocked from that address, even with the right secret
    let ok = format!("ApiKey {good}");
    let ctx_ok = RequestContext::new(Some(&ok), Some("10.0.0.1"));
    assert!(matches!(
        auth.authenticate_from(&ctx_ok, now, t0),
        Err(AuthError::RateLimited)
    ));
    // and from another address it works
    let ctx_other = RequestContext::new(Some(&ok), Some("10.0.0.2"));
    assert!(auth.authenticate_from(&ctx_other, now, t0).is_ok());
    // a missing credential is not a failure
    let anon = RequestContext::new(None, Some("10.0.0.3"));
    for _ in 0..20 {
        assert!(matches!(
            auth.authenticate_from(&anon, now, t0),
            Err(AuthError::Missing)
        ));
    }
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
                subject: user.to_owned(),
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
            subject: user.clone(),
            provider: "proxy".into(),
            name: user,
            scopes: scopes(&["match"]),
            via: AuthVia::External,
            expires_at: None,
        })
    }
    fn revalidate(
        &self,
        subject: &str,
        _now: SystemTime,
    ) -> secmonk_auth::Result<secmonk_auth::Subject> {
        if *self.revoked.lock().unwrap() {
            Err(secmonk_auth::AuthError::Revoked)
        } else {
            Ok(secmonk_auth::Subject {
                name: subject.to_owned(),
                scopes: scopes(&["match"]),
            })
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
        (p.provider.as_str(), p.subject.as_str(), p.via),
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

#[cfg(unix)]
fn write_keys(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A broken keys file fails closed (API keys and their sessions refused) and recovers once fixed.
#[cfg(unix)]
#[test]
fn broken_keys_file_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    let mut store = KeyStore::load(&path).unwrap();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    store.save().unwrap();
    let good_text = std::fs::read_to_string(&path).unwrap();
    let provider =
        ApiKeyProvider::new(KeyStore::load(&path).unwrap()).with_check_interval(Duration::ZERO);
    let auth = Authenticator::with_providers(vec![std::sync::Arc::new(provider)], signer(), 600);
    let now = SystemTime::now();
    let tok = auth.exchange(&plain, now).unwrap().token;
    let bearer = format!("Bearer {tok}");
    let direct = format!("ApiKey {plain}");
    assert!(auth.authenticate(&bearer, now).is_ok());

    // a hand edit that breaks the TOML: everything API-key based is refused, not served from the old keys
    write_keys(&path, "[[key]]\nid = \"broken");
    for h in [&bearer, &direct] {
        let e = auth.authenticate(h, now).unwrap_err();
        assert!(matches!(e, AuthError::Unavailable(_)), "{e:?}");
        assert_eq!(e.http_status(), 503);
        assert_eq!(e.public_message(), "authentication unavailable");
    }
    assert!(auth.exchange(&plain, now).is_err());
    assert!(
        auth.reload().is_err(),
        "an explicit reload reports the broken file"
    );

    // fixed: served again
    write_keys(&path, &good_text);
    assert!(auth.authenticate(&bearer, now).is_ok());
    assert!(auth.authenticate(&direct, now).is_ok());
}

/// The file is looked at most once per interval: a change shows up only after it (or an explicit reload).
#[cfg(unix)]
#[test]
fn keys_file_checked_at_most_once_per_interval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    let mut store = KeyStore::load(&path).unwrap();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    store.save().unwrap();
    let auth = Authenticator::new(KeyStore::load(&path).unwrap(), signer(), 600);
    let now = SystemTime::now();
    let direct = format!("ApiKey {plain}");
    assert!(auth.authenticate(&direct, now).is_ok());
    let mut other = KeyStore::load(&path).unwrap();
    other.revoke("svc").unwrap();
    other.save().unwrap();
    // within the interval (the provider was built just now) the old snapshot answers without a stat
    assert!(auth.authenticate(&direct, now).is_ok());
    std::thread::sleep(KEYS_CHECK_INTERVAL + Duration::from_millis(50));
    assert!(matches!(
        auth.authenticate(&direct, now),
        Err(AuthError::Revoked)
    ));
}

/// The fingerprint is the whole identity: an atomic replace with the same length and the old mtime is seen.
#[cfg(unix)]
#[test]
fn fingerprint_sees_a_replace_with_the_same_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    let mut store = KeyStore::load(&path).unwrap();
    store.create("aaa", scopes(&["ui"]), None).unwrap();
    store.save().unwrap();
    let loaded = KeyStore::load(&path).unwrap();
    assert!(!loaded.file_changed());
    let old_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("aaa", "bbb");
    let tmp = dir.path().join("new.toml");
    write_keys(&tmp, &text);
    std::fs::File::options()
        .write(true)
        .open(&tmp)
        .unwrap()
        .set_modified(old_mtime)
        .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        old_mtime
    );
    assert!(loaded.file_changed(), "a new inode is a change");
}

/// A live session keeps only the scopes its key still has (and never gains new ones).
#[cfg(unix)]
#[test]
fn session_scopes_follow_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api_keys.toml");
    let mut store = KeyStore::load(&path).unwrap();
    let wide = store
        .create("wide", scopes(&["ui", "match"]), None)
        .unwrap();
    let narrow = store.create("narrow", scopes(&["ui:read"]), None).unwrap();
    store.save().unwrap();
    let auth = Authenticator::new(KeyStore::load(&path).unwrap(), signer(), 600);
    let now = SystemTime::now();
    let wide_tok = format!("Bearer {}", auth.exchange(&wide, now).unwrap().token);
    let narrow_tok = format!("Bearer {}", auth.exchange(&narrow, now).unwrap().token);

    // wide loses match and ui:actions; narrow becomes admin
    let mut recs = KeyStore::load(&path).unwrap().list().to_vec();
    recs[0].scopes = scopes(&["ui:read"]);
    recs[1].scopes = scopes(&["admin"]);
    let mut toml_text = String::new();
    for r in &recs {
        toml_text.push_str(&format!(
            "[[key]]\nid = \"{}\"\nname = \"{}\"\nhash = \"{}\"\nscopes = [{}]\ncreated = \"{}\"\n\n",
            r.id,
            r.name,
            r.hash,
            r.scopes
                .iter()
                .map(|s| format!("\"{}\"", s.as_str()))
                .collect::<Vec<_>>()
                .join(", "),
            r.created
        ));
    }
    write_keys(&path, &toml_text);
    auth.reload().unwrap();

    let p = auth.authenticate(&wide_tok, now).unwrap();
    assert_eq!(p.scopes, scopes(&["ui:read"]));
    let p = auth.authenticate(&narrow_tok, now).unwrap();
    assert_eq!(
        p.scopes,
        scopes(&["ui:read"]),
        "a session never gains scopes"
    );
    assert!(!p.scopes.contains(Scope::Admin));
}

#[test]
fn scope_intersection() {
    let i = |a: &[&str], b: &[&str]| scopes(a).intersection(&scopes(b));
    assert_eq!(i(&["admin"], &["ui"]), scopes(&["ui"]));
    assert_eq!(i(&["ui"], &["admin"]), scopes(&["ui"]));
    assert_eq!(i(&["admin"], &["admin"]), scopes(&["admin"]));
    assert_eq!(
        i(&["ui", "match"], &["match", "feed:read"]),
        scopes(&["match"])
    );
    assert!(i(&["ui"], &["match"]).is_empty());
}

#[test]
fn jwt_key_rotation_by_kid() {
    let old = JwtSigner::new(vec![1u8; 32], 3600);
    let new = JwtSigner::new(vec![2u8; 32], 3600);
    let rotated = JwtSigner::new(vec![2u8; 32], 3600).with_previous(vec![vec![1u8; 32]]);
    assert_eq!(old.kid(), key_id(&[1u8; 32]));
    assert_eq!(old.kid().len(), 8);
    assert_ne!(old.kid(), new.kid());
    let t_old = old.issue(&principal(&["ui"]), 1000).unwrap().token;
    let t_new = rotated.issue(&principal(&["ui"]), 1000).unwrap().token;
    // the header names the key
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    let header: serde_json::Value =
        serde_json::from_slice(&B.decode(t_old.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header["kid"], old.kid());
    // the rotated signer accepts both; a signer without the old key refuses the old token
    assert!(rotated.verify(&t_old, 1500).is_ok());
    assert!(rotated.verify(&t_new, 1500).is_ok());
    assert!(matches!(
        new.verify(&t_old, 1500),
        Err(AuthError::InvalidCredentials)
    ));
    assert!(old.verify(&t_new, 1500).is_err());
    // the debug output names the kid, never the secret
    let dbg = format!("{rotated:?}");
    assert!(dbg.contains(rotated.kid()) && !dbg.contains("[2, 2"));
}

/// A provider that claims `Bearer` tokens of another issuer (an OIDC access token) and reads a header.
#[derive(Debug)]
struct FakeOidc;

impl secmonk_auth::AuthProvider for FakeOidc {
    fn name(&self) -> &str {
        "oidc"
    }
    fn authenticate(
        &self,
        ctx: &secmonk_auth::RequestContext<'_>,
        _now: SystemTime,
    ) -> Option<secmonk_auth::Result<Principal>> {
        let (scheme, tok) = ctx.authorization_parts()?.ok()?;
        if !scheme.eq_ignore_ascii_case("bearer") || peek_issuer(tok).as_deref() != Some("idp") {
            return None;
        }
        Some(Ok(Principal {
            subject: ctx.header("x-tenant").unwrap_or("none").to_owned(),
            provider: "oidc".into(),
            name: ctx.path.unwrap_or("-").to_owned(),
            scopes: scopes(&["ui:read"]),
            via: AuthVia::External,
            expires_at: None,
        }))
    }
}

#[test]
fn bearer_tokens_route_by_issuer() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B;
    use std::sync::Arc;
    let mut store = KeyStore::in_memory();
    let plain = store.create("svc", scopes(&["ui"]), None).unwrap();
    let auth = Authenticator::with_providers(
        vec![
            Arc::new(secmonk_auth::ApiKeyProvider::new(store)),
            Arc::new(FakeOidc),
        ],
        signer(),
        600,
    );
    let now = SystemTime::now();
    let ours = auth.exchange(&plain, now).unwrap().token;
    assert_eq!(peek_issuer(&ours).as_deref(), Some(ISSUER));
    let p = auth.authenticate(&format!("Bearer {ours}"), now).unwrap();
    assert_eq!((p.provider.as_str(), p.via), ("api_key", AuthVia::Jwt));

    let foreign = format!(
        "{}.{}.sig",
        B.encode(r#"{"alg":"RS256"}"#),
        B.encode(r#"{"iss":"idp","sub":"x"}"#)
    );
    let hdr = format!("Bearer {foreign}");
    let headers: &[(&str, &str)] = &[("X-Tenant", "acme")];
    let ctx = RequestContext::new(Some(&hdr), Some("1.2.3.4"))
        .with_request("GET", "/api/meta")
        .with_headers(&headers);
    let p = auth.authenticate_request(&ctx, now).unwrap();
    assert_eq!(
        (p.provider.as_str(), p.subject.as_str(), p.name.as_str()),
        ("oidc", "acme", "/api/meta")
    );
    // a token nobody claims (not ours, not the IdP's) is refused as a credential failure
    let nobody = format!(
        "Bearer {}.{}.sig",
        B.encode(r#"{"alg":"HS256"}"#),
        B.encode(r#"{"iss":"elsewhere"}"#)
    );
    let e = auth.authenticate(&nobody, now).unwrap_err();
    assert_eq!(e.http_status(), 401);
    assert!(peek_issuer("not.a-jwt").is_none() && peek_issuer("a.b.c.d").is_none());
}

#[test]
fn error_statuses() {
    assert_eq!(AuthError::Missing.http_status(), 401);
    assert_eq!(AuthError::Revoked.http_status(), 401);
    assert_eq!(AuthError::Forbidden(Scope::Admin).http_status(), 403);
    assert_eq!(AuthError::RateLimited.http_status(), 429);
    assert_eq!(AuthError::Format("x".into()).http_status(), 500);
    assert_eq!(AuthError::UnknownKey.reason_class(), "unknown_key");
}
