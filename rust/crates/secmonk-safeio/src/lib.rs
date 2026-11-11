//! Secret hygiene and bounded reads (`secmonk-safeio`): Rust ports of `secmonk/collectors/base.py`.
//!
//! Golden-tested against the Python outputs (`tests/golden/redaction.json`). Python regex details that matter
//! are reproduced by hand: the negative lookahead of `auth(?!ors?(?![a-z]))`, `$` matching before a final
//! newline, and `\s` including the ASCII separators `\x1c`..`\x1f` (Python's `str.isspace`).
//! The `regex` crate is linear-time, so untrusted text cannot cause catastrophic backtracking.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

pub mod within;

pub use within::{WithinError, read_within, resolve_within};

/// Placeholder for a redacted command argument or label (`base.REDACTED`).
pub const REDACTED: &str = "<redacted>";
/// Placeholder for a redacted option value in the run history.
pub const MASK: &str = "***";

/// Python's `\s` for str patterns (Unicode whitespace plus `\x1c`-`\x1f`).
const PY_WS: &str = r"\s\x1c-\x1f";

static SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)token|secret|passw(or)?d|passwd|api[-_]?key|apikey|credential|private[-_]?key")
        .unwrap()
});
static AUTH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)auth").unwrap());
static ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\A(-{0,2}[\w.-]+)=(.*)\z").unwrap());
static PATH_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)_(file|path)\n?\z").unwrap());
static SECRET_OPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)pass|token|secret|key\n?\z").unwrap());
static HOST_OPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)host|url|endpoint|socket").unwrap());
static SSHPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(\bsshpass\b(?:[{PY_WS}]+-\w+)*?[{PY_WS}]+-p)[{PY_WS}]*[^{PY_WS}]+"
    ))
    .unwrap()
});
static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r#"(?i)\b[a-z][a-z0-9+.-]*://[^{PY_WS}'"<>]+"#)).unwrap());

const PATH_OPTS: [&str; 6] = [
    "identity",
    "tls_ca",
    "tls_cert",
    "tls_key",
    "known_hosts",
    "ssh_config",
];

/// Whether a key name looks like it holds a secret (`base.looks_secret`).
pub fn looks_secret(key: &str) -> bool {
    SECRET_KEY.is_match(key)
        || AUTH
            .find_iter(key)
            .any(|m| !auth_exception(&key[m.end()..]))
}

/// The lookahead `(?!ors?(?![a-z]))` after `auth` (IGNORECASE): true when the text continues as the word
/// `author` / `authors` (so the key is not a secret, e.g. `authors`).
fn auth_exception(rest: &str) -> bool {
    let mut it = rest.chars();
    let (Some(o), Some(r)) = (it.next(), it.next()) else {
        return false;
    };
    if !(fold_eq(o, 'o') && fold_eq(r, 'r')) {
        return false;
    }
    let after: Vec<char> = it.take(2).collect();
    // `ors(?![a-z])`
    if after.first().is_some_and(|&c| fold_eq(c, 's'))
        && !after.get(1).is_some_and(|&c| is_ascii_letter_ci(c))
    {
        return true;
    }
    // `or(?![a-z])`
    !after.first().is_some_and(|&c| is_ascii_letter_ci(c))
}

/// Case-insensitive char equality as Python `re.IGNORECASE` does it for ASCII letters (with the two
/// non-ASCII folds that reach ASCII: `ſ` -> `s`, Kelvin sign -> `k`).
fn fold_eq(c: char, lower: char) -> bool {
    c.to_ascii_lowercase() == lower
        || (lower == 's' && c == '\u{17f}')
        || (lower == 'k' && c == '\u{212a}')
}

/// `[a-z]` under IGNORECASE.
fn is_ascii_letter_ci(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '\u{17f}' || c == '\u{212a}' || c == '\u{131}' || c == '\u{130}'
}

/// Drop the password (and, unless `keep_user`, the user name), query and fragment of a URL
/// (`base.strip_url_secrets`). Text without `://` (scp-like `git@host:path`) is returned unchanged.
pub fn strip_url_secrets(url: &str, keep_user: bool) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (mut authority, tail) = (rest[..auth_end].to_string(), &rest[auth_end..]);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = &tail[..path_end];
    if let Some(at) = authority.rfind('@') {
        let userinfo = &authority[..at];
        let hostport = &authority[at + 1..];
        let user = userinfo.split(':').next().unwrap_or("");
        authority = if keep_user && !user.is_empty() {
            format!("{user}@{hostport}")
        } else {
            hostport.to_string()
        };
    }
    format!("{scheme}://{authority}{path}")
}

/// Redact secret-looking arguments of a command (`base.redact_command` on a list): `--password x`,
/// `--token=x`, `KEY=x`, URLs with userinfo.
pub fn redact_command(args: &[String]) -> Vec<String> {
    let values: Vec<Value> = args.iter().map(|a| Value::String(a.clone())).collect();
    redact_command_values(&values)
        .into_iter()
        .map(|v| match v {
            Value::String(s) => s,
            other => other.to_string(),
        })
        .collect()
}

/// `base.redact_command` on a string: split on single spaces, redact, join.
pub fn redact_command_str(cmd: &str) -> String {
    let parts: Vec<String> = cmd.split(' ').map(str::to_string).collect();
    redact_command(&parts).join(" ")
}

/// `base.redact_command` on a JSON list (non-string items are kept as they are).
pub fn redact_command_values(args: &[Value]) -> Vec<Value> {
    let mut out = Vec::with_capacity(args.len());
    let mut hide_next = false;
    for a in args {
        let Value::String(a) = a else {
            out.push(a.clone());
            continue;
        };
        if hide_next {
            out.push(Value::String(REDACTED.into()));
            hide_next = false;
            continue;
        }
        if let Some(c) = ASSIGN.captures(a)
            && looks_secret(&c[1])
        {
            out.push(Value::String(format!("{}={REDACTED}", &c[1])));
        } else if a.starts_with('-') && looks_secret(a) {
            out.push(Value::String(a.clone()));
            hide_next = true;
        } else if a.contains("://") {
            let s = strip_url_secrets(a, false);
            out.push(Value::String(if s.is_empty() { a.clone() } else { s }));
        } else {
            out.push(Value::String(a.clone()));
        }
    }
    out
}

/// `redact_command` for any JSON value: a list or a string; anything else is returned unchanged.
pub fn redact_command_value(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(redact_command_values(a)),
        Value::String(s) => Value::String(redact_command_str(s)),
        other => other.clone(),
    }
}

/// Free text (an error, a log line) with every URL's password, query and fragment removed, user names kept
/// (`base.scrub_text`).
pub fn scrub_text(text: &str) -> String {
    if !text.contains("://") {
        return text.to_string();
    }
    URL.replace_all(text, |c: &regex::Captures<'_>| {
        let s = strip_url_secrets(&c[0], true);
        if s.is_empty() { c[0].to_string() } else { s }
    })
    .into_owned()
}

/// A collector option as stored in the run history (`base.redact_option`): secrets -> `***`, URL credentials
/// stripped, `ssh_option` commands through [`redact_command_str`], paths kept (scrubbed).
pub fn redact_option(key: &str, value: &Value) -> Value {
    if let Value::Array(items) = value {
        return Value::Array(items.iter().map(|v| redact_option(key, v)).collect());
    }
    let lower = key.to_lowercase();
    if PATH_OPTS.contains(&lower.as_str()) || PATH_SUFFIX.is_match(key) {
        return match value {
            Value::String(s) => Value::String(scrub_text(s)),
            other => other.clone(),
        };
    }
    if SECRET_OPT.is_match(key) || looks_secret(key) {
        return Value::String(MASK.into());
    }
    let Value::String(s) = value else {
        return value.clone();
    };
    if key == "ssh_option" {
        let r = redact_command_str(s);
        let r = if r.is_empty() { s.clone() } else { r };
        return Value::String(SSHPASS.replace_all(&r, "${1} ***").into_owned());
    }
    if s.contains("://") && HOST_OPT.is_match(key) {
        return Value::String(strip_url_secrets(s, true));
    }
    Value::String(scrub_text(s))
}

/// Container/image labels with secret-looking keys redacted and URL credentials stripped
/// (`base.redact_labels`).
pub fn redact_labels(labels: &Map<String, Value>) -> Map<String, Value> {
    labels
        .iter()
        .map(|(k, v)| {
            let v = if looks_secret(k) {
                Value::String(REDACTED.into())
            } else if let Value::String(s) = v
                && s.contains("://")
            {
                Value::String(strip_url_secrets(s, false))
            } else {
                v.clone()
            };
            (k.clone(), v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_lookahead() {
        for (k, want) in [
            ("auth", true),
            ("author", false),
            ("authors", false),
            ("authorsx", true),
            ("authored", true),
        ] {
            assert_eq!(looks_secret(k), want, "{k}");
        }
    }

    #[test]
    fn scrub_keeps_users() {
        assert_eq!(
            scrub_text("see https://u:p@h/x?t=1 now"),
            "see https://u@h/x now"
        );
    }
}
