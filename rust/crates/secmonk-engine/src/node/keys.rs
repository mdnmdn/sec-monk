//! The lookup keys of a component: a **superset** of the `affected` rows the Python matcher
//! (`src/secmonk/engine/match.py`) reads for it, as `pkg:<ecosystem>/<package>` and `prod:<product>` keys
//! (`secmonk_model::node::pkg_key` / `prod_key`: every key lowercase, the mirror derives its keys with the same
//! functions). A change of an `affected` row under one of these keys can change the component's match set; a key too
//! many only costs a re-match (proposal §3.3).
//!
//! Ported from `match.py` (`_match_package`, `_product_candidates`, the dispatch of `match_asset`), `purl.py`
//! (`PURL_TO_OSV`, `DISTRO_TO_OSV`, `osv_distro_ecosystem`, `osv_package_name`, `normalize_name`), `classify.py`
//! (`normalize_product_name`, the purl-derived ecosystem) and `sources/base.norm_vendor_product`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use secmonk_model::Category;
use secmonk_model::node::{ComponentIdentity, pkg_key, prod_key};
use serde_json::Value;

/// `purl.PURL_TO_OSV`.
fn purl_to_osv(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "pypi" => "PyPI",
        "npm" => "npm",
        "maven" => "Maven",
        "golang" => "Go",
        "cargo" => "crates.io",
        "gem" => "RubyGems",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "pub" => "Pub",
        "swift" => "SwiftURL",
        "hex" => "Hex",
        _ => return None,
    })
}

/// `purl.DISTRO_TO_OSV`.
fn distro_to_osv(id: &str) -> Option<&'static str> {
    Some(match id.to_lowercase().as_str() {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "alpine" => "Alpine",
        "wolfi" => "Wolfi",
        "chainguard" => "Chainguard",
        "rhel" | "redhat" => "Red Hat",
        "rocky" | "rocky-linux" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        "opensuse-leap" => "openSUSE",
        "sles" => "SUSE",
        _ => return None,
    })
}

/// `purl.osv_distro_ecosystem`: `("debian", "12")` -> `Debian:12`, `("alpine", "3.20.3")` -> `Alpine:v3.20`.
fn osv_distro_ecosystem(distro_id: &str, version_id: Option<&str>) -> Option<String> {
    let base = distro_to_osv(distro_id)?;
    let Some(v) = version_id.filter(|v| !v.is_empty()) else {
        return Some(base.to_owned());
    };
    if matches!(base, "Wolfi" | "Chainguard") {
        return Some(base.to_owned());
    }
    let major = v.split('.').next().unwrap_or(v);
    Some(match base {
        "Alpine" => {
            let parts: Vec<&str> = v.split('.').collect();
            if parts.len() >= 2 {
                format!("Alpine:v{}.{}", parts[0], parts[1])
            } else {
                format!("Alpine:v{v}")
            }
        }
        "Ubuntu" => format!("Ubuntu:{v}"),
        "Debian" | "Rocky Linux" | "AlmaLinux" | "Red Hat" => format!("{base}:{major}"),
        _ => format!("{base}:{v}"),
    })
}

/// The parts of a package URL the keys need (`pkg:type/namespace/name@version?qualifiers#subpath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Purl {
    pub(crate) kind: String,
    pub(crate) namespace: Option<String>,
    pub(crate) name: String,
    pub(crate) qualifiers: Vec<(String, String)>,
}

impl Purl {
    fn qualifier(&self, key: &str) -> Option<&str> {
        self.qualifiers
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Percent-decoding (invalid escapes kept as they are).
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(h) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(h);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A lenient purl parser (`None` when it is not a purl): enough for the type, namespace, name and qualifiers.
pub(crate) fn parse_purl(purl: &str) -> Option<Purl> {
    let rest = purl.strip_prefix("pkg:")?.trim_start_matches('/');
    let rest = rest.split_once('#').map_or(rest, |(a, _)| a);
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    // the version follows the last '@' of the last segment
    let (path, _version) = match path.rfind('@') {
        Some(i) if !path[i..].contains('/') => (&path[..i], Some(&path[i + 1..])),
        _ => (path, None),
    };
    let mut segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    let kind = segs.remove(0).to_lowercase();
    let name = decode(segs.pop()?);
    if name.is_empty() {
        return None;
    }
    let namespace =
        (!segs.is_empty()).then(|| segs.iter().map(|s| decode(s)).collect::<Vec<_>>().join("/"));
    let qualifiers = query
        .map(|q| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_lowercase(), decode(v)))
                .collect()
        })
        .unwrap_or_default();
    Some(Purl {
        kind,
        namespace,
        name,
        qualifiers,
    })
}

/// `purl.osv_package_name`: the package name as OSV spells it for a purl.
fn osv_package_name(p: &Purl) -> String {
    match (&p.namespace, p.kind.as_str()) {
        (Some(ns), "maven") => format!("{ns}:{}", p.name),
        (Some(ns), "npm" | "composer" | "golang" | "swift") => format!("{ns}/{}", p.name),
        _ => p.name.clone(),
    }
}

/// The ecosystem `classify` derives from a purl (language types, then distro packages).
fn purl_ecosystem(p: &Purl) -> Option<String> {
    if let Some(e) = purl_to_osv(&p.kind) {
        return Some(e.to_owned());
    }
    if matches!(p.kind.as_str(), "deb" | "rpm" | "apk") {
        let distro = p.qualifier("distro").unwrap_or("");
        let (did, ver) = distro.split_once('-').unwrap_or((distro, ""));
        let did = if did.is_empty() {
            p.namespace.as_deref().unwrap_or("")
        } else {
            did
        };
        return osv_distro_ecosystem(did, Some(ver).filter(|v| !v.is_empty()));
    }
    None
}

/// `purl.normalize_name`: PyPI collapses `-_.` runs to `-`; every key is lowercased anyway.
fn normalize_name(ecosystem: &str, name: &str) -> String {
    static PYPI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[-_.]+").expect("regex"));
    let n = name.trim();
    if ecosystem.split(':').next() == Some("PyPI") {
        PYPI.replace_all(n, "-").to_lowercase()
    } else {
        n.to_lowercase()
    }
}

/// `classify.normalize_product_name`: `Google Chrome (x64) 2024` -> `google chrome`.
pub(crate) fn normalize_product_name(name: &str) -> String {
    static APP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.app$").expect("regex"));
    static BREW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@[\d.]+$").expect("regex"));
    static NOISE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)\b(x64|x86|64-bit|32-bit|arm64|aarch64|universal|intel|apple silicon|\(x64\)|\(x86\)|desktop|app|for mac|for macos|beta|nightly|insiders?|community edition|ce)\b",
        )
        .expect("regex")
    });
    static YEAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(19|20)\d\d\b").expect("regex"));
    static OTHER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9+.# ]+").expect("regex"));
    let n = name.to_lowercase();
    let n = APP.replace(&n, "");
    let n = BREW.replace(&n, "");
    let n = NOISE.replace_all(&n, " ");
    let n = YEAR.replace_all(&n, " ");
    let n = OTHER.replace_all(&n, " ");
    n.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `sources/base.norm_vendor_product`: lowercase, `_` as a space, `n/a`-like values dropped.
fn norm_vendor_product(s: &str) -> Option<String> {
    let s = s.trim().to_lowercase();
    if matches!(s.as_str(), "" | "n/a" | "-" | "*" | "unknown") {
        return None;
    }
    Some(
        s.replace('_', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    )
    .filter(|s| !s.is_empty())
}

fn meta_str<'a>(c: &'a ComponentIdentity, key: &str) -> Option<&'a str> {
    c.meta
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// A scalar meta value as Python's `str(value)` would give for strings and numbers.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `match._product_candidates`: `meta.product`, `meta.product_alts`, `meta.brew_name` without `@N`, the normalized
/// name; each through `norm_vendor_product`.
fn product_candidates(c: &ComponentIdentity) -> BTreeSet<String> {
    static BREW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@[\d.]+$").expect("regex"));
    let mut cands: Vec<String> = Vec::new();
    if let Some(p) = c.meta.get("product").and_then(scalar) {
        cands.push(p);
    }
    match c.meta.get("product_alts") {
        Some(Value::Array(a)) => cands.extend(a.iter().filter_map(scalar)),
        Some(v) => cands.extend(scalar(v)),
        None => {}
    }
    if let Some(b) = c.meta.get("brew_name").and_then(scalar) {
        cands.push(BREW.replace(&b.to_lowercase(), "").into_owned());
    }
    cands.push(normalize_product_name(&c.name));
    cands
        .iter()
        .filter_map(|c| norm_vendor_product(c))
        .collect()
}

/// The lookup keys of `c` (sorted, distinct): a superset of the `affected` rows the matcher reads for it.
///
/// - **Package match** (an OSV ecosystem and category `library`, `os-package` or `runtime`, as `match_asset`
///   dispatches): `pkg:<ecosystem>/<name>` for the name normalized as `purl.normalize_name`, the plain name, the
///   purl's OSV package name (`group:artifact`, `@scope/name`, `module/path`) and `meta.source_package` (Debian,
///   Ubuntu and Alpine OSV records use source package names).
/// - **Product match** (everything else): `prod:<candidate>` for the product candidates of `_product_candidates`
///   (`meta.product`, `meta.product_alts`, `meta.brew_name` without `@N`, the normalized name). Vendor alternatives
///   are ignored: product keys have no vendor.
/// - A component whose ecosystem comes only from its purl (`classify` would derive it on the matcher's side) gets
///   both families.
pub fn component_lookup_keys(c: &ComponentIdentity) -> Vec<String> {
    let purl = c.purl.as_deref().and_then(parse_purl);
    let given = c.ecosystem.clone().filter(|e| !e.is_empty());
    let derived = purl.as_ref().and_then(purl_ecosystem);
    let ecosystem = given.clone().or(derived);
    let package_category = matches!(
        c.category,
        Category::Library | Category::OsPackage | Category::Runtime
    );
    // a purl-derived ecosystem makes classify default the category to library / os-package
    let package_route = ecosystem.is_some() && (package_category || given.is_none());
    let product_route = !(given.is_some() && package_category);
    let mut keys = BTreeSet::new();
    if package_route && let Some(eco) = ecosystem.as_deref() {
        let mut names: Vec<String> = vec![normalize_name(eco, &c.name), c.name.trim().to_owned()];
        if let Some(p) = &purl {
            names.push(normalize_name(eco, &osv_package_name(p)));
            names.push(normalize_name(eco, &p.name));
        }
        if let Some(sp) = meta_str(c, "source_package") {
            names.push(normalize_name(eco, sp));
        }
        if let Some(b) = meta_str(c, "brew_name") {
            names.push(normalize_name(eco, b));
        }
        for n in names.iter().filter(|n| !n.is_empty()) {
            keys.insert(pkg_key(eco, n));
        }
    }
    if product_route {
        for p in product_candidates(c) {
            keys.insert(prod_key(&p));
        }
    }
    keys.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ident(v: Value) -> ComponentIdentity {
        serde_json::from_value(v).unwrap()
    }

    fn keys(v: Value) -> Vec<String> {
        component_lookup_keys(&ident(v))
    }

    #[test]
    fn purls_parse() {
        let p = parse_purl("pkg:npm/%40angular/core@1.0.0?x=1#sub").unwrap();
        assert_eq!(p.kind, "npm");
        assert_eq!(p.namespace.as_deref(), Some("@angular"));
        assert_eq!(p.name, "core");
        assert_eq!(osv_package_name(&p), "@angular/core");
        let p = parse_purl("pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12").unwrap();
        assert_eq!(purl_ecosystem(&p).as_deref(), Some("Debian:12"));
        let p = parse_purl("pkg:apk/alpine/busybox@1.36.1-r5?distro=alpine-3.19.1").unwrap();
        assert_eq!(purl_ecosystem(&p).as_deref(), Some("Alpine:v3.19"));
        let p = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1").unwrap();
        assert_eq!(osv_package_name(&p), "org.apache.logging.log4j:log4j-core");
        assert!(parse_purl("not-a-purl").is_none());
        assert!(parse_purl("pkg:npm").is_none());
    }

    #[test]
    fn product_names_normalize_like_classify() {
        assert_eq!(
            normalize_product_name("Google Chrome (x64) 2024"),
            "google chrome"
        );
        assert_eq!(
            normalize_product_name("Visual Studio Code.app"),
            "visual studio code"
        );
        assert_eq!(normalize_product_name("openssl@3"), "openssl");
        assert_eq!(
            normalize_product_name("Notepad++ 8.6 (64-bit x64)"),
            "notepad++ 8.6"
        );
        assert_eq!(norm_vendor_product(" N/A "), None);
        assert_eq!(
            norm_vendor_product("Internet_Explorer"),
            Some("internet explorer".into())
        );
    }

    /// Representative components and the keys the Python matcher would query for them (must be a subset).
    #[test]
    fn keys_cover_what_the_matcher_reads() {
        let table: Vec<(Value, Vec<&str>)> = vec![
            // pypi: normalize_name collapses -_. and lowercases
            (
                json!({"name": "Flask_Login", "version": "0.6", "category": "library",
                       "purl": "pkg:pypi/flask-login@0.6", "ecosystem": "PyPI"}),
                vec!["pkg:pypi/flask-login"],
            ),
            // npm scoped
            (
                json!({"name": "@angular/core", "version": "1.0.0", "category": "library",
                       "purl": "pkg:npm/%40angular/core@1.0.0", "ecosystem": "npm"}),
                vec!["pkg:npm/@angular/core"],
            ),
            // maven: group:artifact
            (
                json!({"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "category": "library",
                       "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "ecosystem": "Maven"}),
                vec!["pkg:maven/org.apache.logging.log4j:log4j-core"],
            ),
            // golang module path (case kept by Python, lowercased in keys)
            (
                json!({"name": "github.com/BurntSushi/toml", "version": "v1.2.0", "category": "library",
                       "purl": "pkg:golang/github.com/BurntSushi/toml@v1.2.0", "ecosystem": "Go"}),
                vec!["pkg:go/github.com/burntsushi/toml"],
            ),
            // Go stdlib as a runtime
            (
                json!({"name": "stdlib", "version": "1.21.0", "category": "runtime",
                       "purl": "pkg:golang/stdlib@1.21.0", "ecosystem": "Go"}),
                vec!["pkg:go/stdlib"],
            ),
            // cargo
            (
                json!({"name": "tokio", "version": "1.0.0", "category": "library",
                       "purl": "pkg:cargo/tokio@1.0.0", "ecosystem": "crates.io"}),
                vec!["pkg:crates.io/tokio"],
            ),
            // deb: binary and source package names
            (
                json!({"name": "libssl3", "version": "3.0.11-1", "category": "os-package",
                       "purl": "pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12", "ecosystem": "Debian:12",
                       "meta": {"source_package": "openssl", "source_version": "3.0.11-1"}}),
                vec!["pkg:debian:12/libssl3", "pkg:debian:12/openssl"],
            ),
            // apk with an origin package
            (
                json!({"name": "libcrypto3", "version": "3.1.4-r1", "category": "os-package",
                       "purl": "pkg:apk/alpine/libcrypto3@3.1.4-r1?distro=alpine-3.19.0", "ecosystem": "Alpine:v3.19",
                       "meta": {"source_package": "openssl"}}),
                vec!["pkg:alpine:v3.19/libcrypto3", "pkg:alpine:v3.19/openssl"],
            ),
            // brew formula: product, brew name without @N, normalized name
            (
                json!({"name": "openssl@3", "version": "3.2.0", "category": "package",
                       "purl": "pkg:brew/openssl%403@3.2.0",
                       "meta": {"brew_kind": "formula", "brew_name": "openssl@3", "product": "openssl",
                                "product_source": "brew-seed"}}),
                vec!["prod:openssl"],
            ),
            // brew cask: a product with alternatives
            (
                json!({"name": "docker-compose", "version": "2.24.0", "category": "package",
                       "meta": {"brew_kind": "cask", "brew_name": "docker-compose",
                                "product": "compose", "product_alts": ["docker_compose"]}}),
                vec!["prod:compose", "prod:docker compose", "prod:docker-compose"],
            ),
            // macOS app with a product from the alias table
            (
                json!({"name": "Google Chrome.app", "version": "120.0", "category": "application",
                       "vendor": "google", "meta": {"product": "chrome", "product_source": "alias-table"}}),
                vec!["prod:chrome", "prod:google chrome"],
            ),
            // Windows program: normalized display name
            (
                json!({"name": "7-Zip 23.01 (x64)", "version": "23.01", "category": "application",
                       "vendor": "Igor Pavlov"}),
                vec!["prod:7 zip 23.01"],
            ),
            // the OS itself
            (
                json!({"name": "macOS", "version": "14.4", "category": "os", "vendor": "apple",
                       "meta": {"product": "macos"}}),
                vec!["prod:macos"],
            ),
        ];
        for (c, want) in table {
            let got = keys(c.clone());
            for w in &want {
                assert!(
                    got.iter().any(|g| g == w),
                    "{w} missing from {got:?} for {c}"
                );
            }
            assert!(
                got.iter().all(|k| *k == k.to_lowercase()),
                "keys are lowercase: {got:?}"
            );
            let sorted: BTreeSet<&String> = got.iter().collect();
            assert_eq!(sorted.len(), got.len(), "distinct");
        }
    }

    #[test]
    fn package_components_get_no_product_keys_and_products_no_package_keys() {
        let k = keys(
            json!({"name": "requests", "version": "2.0", "category": "library",
                            "purl": "pkg:pypi/requests@2.0", "ecosystem": "PyPI"}),
        );
        assert_eq!(k, ["pkg:pypi/requests"]);
        let k = keys(json!({"name": "Firefox", "version": "120", "category": "application"}));
        assert_eq!(k, ["prod:firefox"]);
        // an ecosystem known only from the purl: both families (classify runs again on the matcher side)
        let k = keys(
            json!({"name": "left-pad", "version": "1.0", "category": "application",
                            "purl": "pkg:npm/left-pad@1.0"}),
        );
        assert_eq!(k, ["pkg:npm/left-pad", "prod:left pad"]);
    }
}
