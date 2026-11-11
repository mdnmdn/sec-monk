//! Method names of `rust/contracts/catalog/module-methods.json` (each declared once there).

/// `collector.expand_targets` (probe, unary).
pub const COLLECTOR_EXPAND_TARGETS: &str = "collector.expand_targets";
/// `collector.collect` (probe, stream of `CollectItem`).
pub const COLLECTOR_COLLECT: &str = "collector.collect";
/// `discover.host` (probe).
pub const DISCOVER_HOST: &str = "discover.host";
/// `docker.contexts` (probe).
pub const DOCKER_CONTEXTS: &str = "docker.contexts";
/// `docker.containers` (probe).
pub const DOCKER_CONTAINERS: &str = "docker.containers";
/// `docker.image_check` (probe; the reuse rule).
pub const DOCKER_IMAGE_CHECK: &str = "docker.image_check";
/// `k8s.kubeconfigs` (probe).
pub const K8S_KUBECONFIGS: &str = "k8s.kubeconfigs";
/// `process.snapshot` (probe).
pub const PROCESS_SNAPSHOT: &str = "process.snapshot";
/// `source.sync` (source, stream of `RowsBatch`).
pub const SOURCE_SYNC: &str = "source.sync";
/// `source.ack` (source).
pub const SOURCE_ACK: &str = "source.ack";
/// `source.export` (source, stream of `RowsBatch`).
pub const SOURCE_EXPORT: &str = "source.export";
/// `engine.classify`.
pub const ENGINE_CLASSIFY: &str = "engine.classify";
/// `engine.match`.
pub const ENGINE_MATCH: &str = "engine.match";
/// `versions.compare`.
pub const VERSIONS_COMPARE: &str = "versions.compare";
/// `versions.in_range`.
pub const VERSIONS_IN_RANGE: &str = "versions.in_range";
/// `versions.first_fixed`.
pub const VERSIONS_FIRST_FIXED: &str = "versions.first_fixed";
/// `versions.scheme`.
pub const VERSIONS_SCHEME: &str = "versions.scheme";
/// `scoring.priority`.
pub const SCORING_PRIORITY: &str = "scoring.priority";
/// Prefix of the report payload methods (`reports.overview`, ...).
pub const REPORTS_PREFIX: &str = "reports.";
/// Prefix of the process monitor methods (`procmon.payload`, ...).
pub const PROCMON_PREFIX: &str = "procmon.";
/// The `notify` method carrying a structured log line.
pub const NOTIFY_LOG: &str = "log";

/// Methods that answer with a stream (`event`* + `end`).
pub const STREAM_METHODS: [&str; 3] = [COLLECTOR_COLLECT, SOURCE_SYNC, SOURCE_EXPORT];

/// Whether `name` is a syntactically valid method name (`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`).
pub fn is_valid_method(name: &str) -> bool {
    if name.len() > 128 {
        return false;
    }
    let mut parts = 0;
    for part in name.split('.') {
        let mut bytes = part.bytes();
        match bytes.next() {
            Some(b'a'..=b'z') => {}
            _ => return false,
        }
        if !bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')) {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}

/// Whether `name` is a valid module/collector/source slug (`^[a-z0-9][a-z0-9._-]{0,63}$`).
pub fn is_valid_slug(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b.iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names() {
        for m in [
            COLLECTOR_COLLECT,
            ENGINE_MATCH,
            "reports.asset_detail",
            "a.b-c.d_e",
        ] {
            assert!(is_valid_method(m), "{m}");
        }
        for m in ["collect", ".a", "a.", "A.b", "a..b", "a.1b", ""] {
            assert!(!is_valid_method(m), "{m}");
        }
    }

    #[test]
    fn slugs() {
        assert!(is_valid_slug("py-probe"));
        assert!(is_valid_slug("docker-engine"));
        assert!(!is_valid_slug("Py"));
        assert!(!is_valid_slug("-x"));
        assert!(!is_valid_slug(&"a".repeat(65)));
    }
}
