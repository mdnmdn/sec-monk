//! The Tauri command `secmonk_api` as a plain function: the webview sends `{method, path, headers, body}` over IPC
//! (when the page runs in the desktop window, `rust/ui/transport.js`), the router answers in process. No network,
//! no authentication: the window is local. Only `/api/` paths are accepted, so the command cannot be used to read
//! the UI files or reach anything else.

use std::collections::BTreeMap;

use base64::Engine as _;
use http::{Request, StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::router::{Router, error_response};

/// The `request` argument of the `secmonk_api` command.
#[derive(Debug, Clone, Deserialize)]
pub struct BridgeRequest {
    pub method: String,
    /// Path with query, `/api/findings?limit=5`.
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// The command's answer: `body` for text, `body_base64` for any other content type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

/// Answer one bridge request with the router (Host check passes with the router's own local authority).
pub async fn handle_bridge(router: &Router, req: BridgeRequest) -> BridgeResponse {
    match build(router, req) {
        Ok(request) => encode(router.handle(request).await),
        Err(e) => encode(error_response(&e)),
    }
}

fn build(router: &Router, req: BridgeRequest) -> Result<Request<Vec<u8>>, ApiError> {
    if !req.path.starts_with("/api/") || req.path.contains(['#', ' ', '\0']) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden")
            .with_hint("the window may only call /api/ routes"));
    }
    let authority = router.options().host_policy.local_authority();
    let mut b = Request::builder()
        .method(req.method.to_ascii_uppercase().as_str())
        .uri(format!("http://{authority}{}", req.path));
    for (k, v) in &req.headers {
        // the authority is ours; a page cannot pick another Host or smuggle framing headers
        if ["host", "content-length", "transfer-encoding", "connection"]
            .contains(&k.to_ascii_lowercase().as_str())
        {
            continue;
        }
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(req.body.unwrap_or_default().into_bytes())
        .map_err(|_| ApiError::bad_request("bad request"))
}

fn is_text(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ct.starts_with("text/")
        || matches!(ct.as_str(), "application/json" | "application/javascript")
        || ct.ends_with("+json")
}

fn encode(resp: http::Response<Vec<u8>>) -> BridgeResponse {
    let status = resp.status().as_u16();
    let mut headers = BTreeMap::new();
    for (k, v) in resp.headers() {
        if k != header::CONTENT_LENGTH
            && let Ok(v) = v.to_str()
        {
            headers.insert(k.as_str().to_owned(), v.to_owned());
        }
    }
    let content_type = headers.get("content-type").map_or("", String::as_str);
    let text = is_text(content_type);
    let body = resp.into_body();
    let (body, body_base64) = match (text, String::from_utf8(body)) {
        (true, Ok(s)) => (Some(s), None),
        (_, Ok(s)) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(s)),
        ),
        (_, Err(e)) => (
            None,
            Some(base64::engine::general_purpose::STANDARD.encode(e.into_bytes())),
        ),
    };
    BridgeResponse {
        status,
        headers,
        body,
        body_base64,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secmonk_engine::{EngineInfo, SkeletonEngine};

    use http::Response;

    use super::*;
    use crate::{HostPolicy, RouterOptions, StaticDir};

    fn router() -> Router {
        Router::new(
            Arc::new(SkeletonEngine::new(EngineInfo::new(
                "0.1.0",
                "/x/state.sqlite3",
            ))),
            RouterOptions {
                static_dir: StaticDir::new("/nonexistent"),
                host_policy: HostPolicy::scheme("secmonk"),
                actions: true,
            },
        )
    }

    fn request(method: &str, path: &str, csrf: bool) -> BridgeRequest {
        BridgeRequest {
            method: method.into(),
            path: path.into(),
            headers: if csrf {
                BTreeMap::from([("x-secmonk-request".to_owned(), "1".to_owned())])
            } else {
                BTreeMap::new()
            },
            body: None,
        }
    }

    #[tokio::test]
    async fn text_answers_carry_a_body() {
        let r = handle_bridge(&router(), request("GET", "/api/meta?x=1", true)).await;
        assert_eq!(r.status, 200);
        assert!(r.body_base64.is_none());
        let v: serde_json::Value = serde_json::from_str(r.body.as_deref().unwrap()).unwrap();
        assert_eq!(v["bind"], "secmonk://localhost");
        assert!(r.headers["content-type"].starts_with("application/json"));
        assert!(!r.headers.contains_key("content-length"));
        let wire = serde_json::to_value(&r).unwrap();
        assert!(wire.get("body_base64").is_none());
    }

    #[tokio::test]
    async fn the_router_rules_still_apply_and_only_api_is_reachable() {
        let r = handle_bridge(&router(), request("GET", "/api/meta", false)).await;
        assert_eq!(r.status, 403, "the CSRF header is still required");
        for path in [
            "/",
            "/static/js/boot.js",
            "/rust-ui/boot.js",
            "api/meta",
            "/apix",
        ] {
            let r = handle_bridge(&router(), request("GET", path, true)).await;
            assert_eq!(r.status, 403, "{path}");
        }
        let mut evil = request("GET", "/api/meta", true);
        evil.headers.insert("Host".into(), "evil.example".into());
        assert_eq!(
            handle_bridge(&router(), evil).await.status,
            200,
            "Host cannot be chosen by the page"
        );
        assert_eq!(
            handle_bridge(&router(), request("PUT", "/api/meta", true))
                .await
                .status,
            405
        );
    }

    #[test]
    fn other_content_types_are_base64() {
        let png = Response::builder()
            .header("content-type", "image/png")
            .header("content-length", 3)
            .body(vec![0x89, 0x50, 0xff])
            .unwrap();
        let r = encode(png);
        assert_eq!(r.body, None);
        assert_eq!(r.body_base64.as_deref(), Some("iVD/"));
        let js = Response::builder()
            .header("content-type", "text/javascript; charset=utf-8")
            .body(b"1".to_vec())
            .unwrap();
        assert_eq!(encode(js).body.as_deref(), Some("1"));
        let cdx = Response::builder()
            .header(
                "content-type",
                "application/vnd.cyclonedx+json; charset=utf-8",
            )
            .body(b"{}".to_vec())
            .unwrap();
        assert_eq!(encode(cdx).body.as_deref(), Some("{}"));
        // text that is not UTF-8 cannot travel as a string
        let bad = Response::builder()
            .header("content-type", "text/plain")
            .body(vec![0xff])
            .unwrap();
        assert_eq!(encode(bad).body_base64.as_deref(), Some("/w=="));
    }
}
