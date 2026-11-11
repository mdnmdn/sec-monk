//! The route table: the 22 `/api` routes of `rust/contracts/catalog/api-routes.json`, with the lookup rules of
//! `web/server.py` (exact paths first, then `/api/assets/<id>/sbom`, then `/api/jobs/<digits>`).

use http::Method;
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteId {
    Meta,
    Processes,
    ProcessesWatch,
    ProcessesSave,
    Overview,
    Assets,
    AssetDetail,
    Sbom,
    MatchAsset,
    Unmatched,
    Findings,
    VulnShow,
    VulnSearch,
    Sources,
    Collectors,
    JobsList,
    JobGet,
    JobStart,
    Discover,
    K8sKubeconfigs,
    DockerContexts,
    DockerContainers,
}

#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Number in the catalog (1..=22).
    pub n: u8,
    pub id: RouteId,
    pub method: &'static str,
    /// Path template; `{id}` is the only parameter.
    pub path: &'static str,
    /// Refused with 403 when actions are off (the optional HTTP binding on a non-loopback address).
    pub actions: bool,
}

const fn r(n: u8, id: RouteId, method: &'static str, path: &'static str, actions: bool) -> Route {
    Route {
        n,
        id,
        method,
        path,
        actions,
    }
}

/// The table, in catalog order.
pub const ROUTES: [Route; 22] = [
    r(1, RouteId::Meta, "GET", "/api/meta", false),
    r(2, RouteId::Processes, "GET", "/api/processes", false),
    r(
        3,
        RouteId::ProcessesWatch,
        "GET",
        "/api/processes/watch",
        false,
    ),
    r(
        4,
        RouteId::ProcessesSave,
        "POST",
        "/api/processes/save",
        false,
    ),
    r(5, RouteId::Overview, "GET", "/api/overview", false),
    r(6, RouteId::Assets, "GET", "/api/assets", false),
    r(7, RouteId::AssetDetail, "GET", "/api/assets/detail", false),
    r(8, RouteId::Sbom, "GET", "/api/assets/{id}/sbom", false),
    r(9, RouteId::MatchAsset, "POST", "/api/assets/match", false),
    r(10, RouteId::Unmatched, "GET", "/api/unmatched", false),
    r(11, RouteId::Findings, "GET", "/api/findings", false),
    r(12, RouteId::VulnShow, "GET", "/api/vulns/show", false),
    r(13, RouteId::VulnSearch, "GET", "/api/vulns/search", false),
    r(14, RouteId::Sources, "GET", "/api/sources", false),
    r(15, RouteId::Collectors, "GET", "/api/collectors", false),
    r(16, RouteId::JobsList, "GET", "/api/jobs", false),
    r(17, RouteId::JobGet, "GET", "/api/jobs/{id}", false),
    r(18, RouteId::JobStart, "POST", "/api/jobs", true),
    r(19, RouteId::Discover, "GET", "/api/discover", true),
    r(
        20,
        RouteId::K8sKubeconfigs,
        "GET",
        "/api/k8s/kubeconfigs",
        true,
    ),
    r(
        21,
        RouteId::DockerContexts,
        "GET",
        "/api/docker/contexts",
        true,
    ),
    r(
        22,
        RouteId::DockerContainers,
        "GET",
        "/api/docker/containers",
        true,
    ),
];

/// What a path segment `{id}` captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capture {
    None,
    /// The URL-decoded asset id of `/api/assets/<id>/sbom` (empty when the path has none).
    Asset(String),
    /// The digits of `/api/jobs/<digits>`.
    Job(String),
}

const SBOM_PREFIX: &str = "/api/assets/";
const SBOM_SUFFIX: &str = "/sbom";
const JOB_PREFIX: &str = "/api/jobs/";

pub fn route(id: RouteId) -> &'static Route {
    ROUTES
        .iter()
        .find(|r| r.id == id)
        .expect("every RouteId is in ROUTES")
}

/// Find the route for a method and a raw (still percent-encoded) path. `None`: unknown path or a path that does
/// not answer to this method (`web/server.py` answers 404 `no such endpoint` for both).
pub fn lookup(method: &Method, path: &str) -> Option<(&'static Route, Capture)> {
    let get = *method == Method::GET;
    let post = *method == Method::POST;
    if !get && !post {
        return None;
    }
    // Exact paths without parameters.
    if let Some(r) = ROUTES
        .iter()
        .find(|r| !r.path.contains('{') && r.path == path && r.method == method.as_str())
    {
        return Some((r, Capture::None));
    }
    if get && path.starts_with(SBOM_PREFIX) && path.ends_with(SBOM_SUFFIX) {
        // Python slices `path[12:-5]`: empty when the two overlap.
        let raw = path
            .get(SBOM_PREFIX.len()..path.len() - SBOM_SUFFIX.len())
            .unwrap_or("");
        let id = percent_decode_str(raw).decode_utf8_lossy().into_owned();
        return Some((route(RouteId::Sbom), Capture::Asset(id)));
    }
    if get
        && let Some(job) = path.strip_prefix(JOB_PREFIX)
        && !job.is_empty()
        && job.bytes().all(|b| b.is_ascii_digit())
    {
        return Some((route(RouteId::JobGet), Capture::Job(job.to_owned())));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CATALOG: &str = include_str!("../../../contracts/catalog/api-routes.json");

    fn concrete(path: &str) -> String {
        path.replace(
            "{id}",
            if path.starts_with("/api/jobs") {
                "42"
            } else {
                "a%2Fb%20c"
            },
        )
    }

    #[test]
    fn every_catalog_route_is_registered_with_its_method() {
        let cat: Value = serde_json::from_str(CATALOG).unwrap();
        let routes = cat["routes"].as_array().unwrap();
        assert_eq!(
            routes.len(),
            ROUTES.len(),
            "catalog and table have the same number of routes"
        );
        for c in routes {
            let n = c["n"].as_u64().unwrap() as u8;
            let (method, path) = (c["method"].as_str().unwrap(), c["path"].as_str().unwrap());
            let mine = ROUTES
                .iter()
                .find(|r| r.n == n)
                .unwrap_or_else(|| panic!("route {n} missing"));
            assert_eq!((mine.method, mine.path), (method, path), "route {n}");
            let actions = c["gate"].as_array().unwrap().iter().any(|g| g == "actions");
            assert_eq!(mine.actions, actions, "route {n} actions gate");
            let m: Method = method.parse().unwrap();
            let (found, _) =
                lookup(&m, &concrete(path)).unwrap_or_else(|| panic!("route {n} not found"));
            assert_eq!(found.n, n, "{method} {path}");
            let other = if method == "GET" {
                Method::POST
            } else {
                Method::GET
            };
            let shared = ROUTES
                .iter()
                .any(|r| r.path == path && r.method == other.as_str());
            if !shared {
                assert!(
                    lookup(&other, &concrete(path)).is_none(),
                    "{other} {path} must not answer"
                );
            }
        }
    }

    #[test]
    fn captures() {
        let (r, c) = lookup(&Method::GET, "/api/assets/host%3A1%2Fx/sbom").unwrap();
        assert_eq!(
            (r.id, c),
            (RouteId::Sbom, Capture::Asset("host:1/x".into()))
        );
        let (_, c) = lookup(&Method::GET, "/api/assets//sbom").unwrap();
        assert_eq!(c, Capture::Asset(String::new()));
        let (_, c) = lookup(&Method::GET, "/api/assets/sbom").unwrap();
        assert_eq!(c, Capture::Asset(String::new()));
        let (r, c) = lookup(&Method::GET, "/api/jobs/42").unwrap();
        assert_eq!((r.id, c), (RouteId::JobGet, Capture::Job("42".into())));
        assert!(lookup(&Method::GET, "/api/jobs/x").is_none());
        assert!(lookup(&Method::GET, "/api/jobs/").is_none());
        assert!(lookup(&Method::POST, "/api/jobs/1").is_none());
        assert!(lookup(&Method::GET, "/api/assets/detail/").is_none());
        assert!(lookup(&Method::GET, "/api/nope").is_none());
    }
}
