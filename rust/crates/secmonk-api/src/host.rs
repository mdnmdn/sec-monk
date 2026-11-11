//! Which `Host` / authority a request may carry (`web/server.py` `host_allowed`, and the scheme origin).

use std::collections::HashSet;
use std::net::IpAddr;

const LOOPBACK_NAMES: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

#[derive(Debug, Clone)]
pub enum HostPolicy {
    /// The custom scheme: no TCP listener, so the only valid authority is the app's own origin
    /// (`localhost`, from `secmonk://localhost`, or `<scheme>.localhost`, Tauri's form on Windows).
    Scheme { scheme: String },
    /// The optional dev HTTP binding: the rules of `server.py` (port must match, name must be a loopback name,
    /// the bind address, an `allow_hosts` entry, or any IP literal when bound to a wildcard address).
    Http {
        port: u16,
        names: HashSet<String>,
        wildcard: bool,
    },
}

impl HostPolicy {
    pub fn scheme(scheme: impl Into<String>) -> Self {
        Self::Scheme {
            scheme: scheme.into().to_ascii_lowercase(),
        }
    }

    /// `bind_host` is the listen address (`127.0.0.1`, `::1`, `0.0.0.0`...); `allow_hosts` are extra names
    /// (`--allow-host`; the caller adds the machine's host names for a wildcard bind).
    pub fn http(bind_host: &str, port: u16, allow_hosts: &[String]) -> Self {
        let bind = bind_host.to_ascii_lowercase();
        let mut names: HashSet<String> = LOOPBACK_NAMES.iter().map(|s| (*s).to_owned()).collect();
        names.insert(bind.clone());
        names.extend(allow_hosts.iter().map(|h| h.to_ascii_lowercase()));
        Self::Http {
            port,
            names,
            wildcard: bind == "0.0.0.0" || bind == "::",
        }
    }

    /// Is this `host[:port]` authority acceptable?
    pub fn allows(&self, authority: &str) -> bool {
        match self {
            Self::Scheme { scheme } => {
                let (name, port) = split_host(authority);
                port.is_none() && (name == "localhost" || name == format!("{scheme}.localhost"))
            }
            Self::Http {
                port,
                names,
                wildcard,
            } => {
                let (name, p) = split_host(authority);
                if p != Some(u32::from(*port)) || name.is_empty() {
                    return false;
                }
                names.contains(&name) || (*wildcard && name.parse::<IpAddr>().is_ok())
            }
        }
    }

    /// The origin the UI is served from, for `/api/meta` `bind`.
    pub fn bind_label(&self) -> String {
        match self {
            Self::Scheme { scheme } => format!("{scheme}://localhost"),
            Self::Http { port, .. } => format!("http://127.0.0.1:{port}"),
        }
    }

    /// `HostPolicy::Http` listens on a TCP port; the scheme does not.
    pub fn is_loopback_only(&self) -> bool {
        matches!(self, Self::Scheme { .. })
            || matches!(
                self,
                Self::Http {
                    wildcard: false,
                    ..
                }
            )
    }
}

/// `_split_host`: `Host` header -> (lower-case name, port). The port is `None` unless it is all digits.
pub fn split_host(value: &str) -> (String, Option<u32>) {
    let value = value.trim().to_ascii_lowercase();
    let (name, port) = if let Some(rest) = value.strip_prefix('[') {
        let (name, rest) = rest.split_once(']').unwrap_or((rest, ""));
        (
            name.to_owned(),
            rest.strip_prefix(':').unwrap_or("").to_owned(),
        )
    } else if value.matches(':').count() == 1 {
        let (n, p) = value.rsplit_once(':').unwrap_or((&value, ""));
        (n.to_owned(), p.to_owned())
    } else {
        (value.clone(), String::new())
    };
    let port = (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .then(|| port.parse().ok())
        .flatten();
    (name, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_python() {
        assert_eq!(
            split_host("localhost:8765"),
            ("localhost".into(), Some(8765))
        );
        assert_eq!(split_host("[::1]:8765"), ("::1".into(), Some(8765)));
        assert_eq!(split_host("Example"), ("example".into(), None));
        assert_eq!(split_host("a:b"), ("a".into(), None));
        assert_eq!(split_host("::1"), ("::1".into(), None));
    }

    #[test]
    fn scheme_origin_only() {
        let p = HostPolicy::scheme("secmonk");
        assert!(p.allows("localhost") && p.allows("secmonk.localhost") && p.allows("LOCALHOST"));
        assert!(
            !p.allows("evil.example")
                && !p.allows("localhost:8765")
                && !p.allows("")
                && !p.allows("other.localhost")
        );
    }

    #[test]
    fn http_rules() {
        let p = HostPolicy::http("127.0.0.1", 8765, &[]);
        assert!(p.allows("127.0.0.1:8765") && p.allows("localhost:8765") && p.allows("[::1]:8765"));
        assert!(
            !p.allows("localhost") && !p.allows("localhost:1") && !p.allows("evil.example:8765")
        );
        assert!(
            !p.allows("10.0.0.5:8765"),
            "an IP literal is only ours on a wildcard bind"
        );
        let w = HostPolicy::http("0.0.0.0", 8765, &["Box.Lan".into()]);
        assert!(
            w.allows("10.0.0.5:8765") && w.allows("box.lan:8765") && !w.allows("evil.example:8765")
        );
        assert!(!w.is_loopback_only() && p.is_loopback_only());
    }
}
