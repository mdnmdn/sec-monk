//! Ports of the small `ops.py` / `web/jobs.py` helpers on request values: `parse_opts`, `_str_list`, `_opt_str`,
//! Python truthiness and `repr`, `str.splitlines`.

use serde_json::{Map, Value};

use crate::error::py_repr;

/// `ops.BOOL_OPTS`: collector options that really are booleans.
pub const BOOL_OPTS: [&str; 17] = [
    "binaries",
    "sudo",
    "all_kegs",
    "use_brew_cli",
    "include_system",
    "insecure_host_key",
    "xdev",
    "no_cache",
    "lang",
    "verbose",
    "allow_agent",
    "look_for_keys",
    "all",
    "tls_verify",
    "rescan",
    "kernel_threads",
    "packages",
];

/// `ops.LIST_OPTS`: collector options that are comma-separated lists.
pub const LIST_OPTS: [&str; 4] = ["exclude", "home", "ecosystems", "namespace"];

/// `ops.parse_opts`: `key=value` strings -> an ordered map (strings, booleans for `BOOL_OPTS`, lists for
/// `LIST_OPTS` with a comma; a repeated key accumulates into a list). `Err` = the `ValueError` text.
pub fn parse_opts(items: &[String]) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    for item in items {
        let (key, val) = match item.split_once('=') {
            Some((k, v)) if !k.is_empty() => (k, v),
            _ => return Err(format!("expected key=value, got {}", py_repr(item))),
        };
        let low = val.to_lowercase();
        let value = if BOOL_OPTS.contains(&key)
            && matches!(low.as_str(), "true" | "yes" | "false" | "no")
        {
            Value::Bool(low == "true" || low == "yes")
        } else if LIST_OPTS.contains(&key) && val.contains(',') {
            Value::Array(
                val.split(',')
                    .filter(|v| !v.is_empty())
                    .map(|v| Value::String(v.into()))
                    .collect(),
            )
        } else {
            Value::String(val.into())
        };
        match out.get_mut(key) {
            Some(prev) => {
                let mut list = match prev.take() {
                    Value::Array(a) => a,
                    other => vec![other],
                };
                match value {
                    Value::Array(a) => list.extend(a),
                    v => list.push(v),
                }
                *prev = Value::Array(list);
            }
            None => {
                out.insert(key.to_owned(), value);
            }
        }
    }
    Ok(out)
}

/// The key of a `key=value` item (`None` without `=`).
pub fn option_key(item: &str) -> Option<&str> {
    item.split_once('=').map(|(k, _)| k)
}

/// Python truthiness of a JSON value (`bool(x)`).
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `repr()` of a JSON value as it would arrive in Python (`None`, `True`, `'text'`, numbers, lists).
pub fn py_repr_value(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => py_repr(s),
        Value::Number(n) => n.to_string(),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(py_repr_value).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `str.splitlines()` (without the line ends).
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_break {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r'
                && let Some(&(j, '\n')) = chars.peek()
            {
                chars.next();
                end = j + 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `web/jobs._opt_str`: `None`/`null`/`""` -> `None`; a non-string -> `Err("<name>: expected a string")`; else the
/// stripped text or `None` when blank.
pub fn opt_str(v: Option<&Value>, name: &str) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let t = s.trim();
            Ok((!t.is_empty()).then(|| t.to_owned()))
        }
        Some(_) => Err(format!("{name}: expected a string")),
    }
}

/// `web/jobs._str_list`: `null` -> `[]`, a string -> comma split, a list of strings -> stripped, blanks dropped.
pub fn str_list(v: Option<&Value>, name: &str) -> Result<Vec<String>, String> {
    let items: Vec<String> = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) => s
            .split(',')
            .filter(|x| !x.trim().is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => {
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                match x {
                    Value::String(s) => out.push(s.clone()),
                    _ => return Err(format!("{name}: expected a list of strings")),
                }
            }
            out
        }
        Some(_) => return Err(format!("{name}: expected a list of strings")),
    };
    Ok(items
        .iter()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect())
}

/// `os.path.expanduser` for a leading `~` or `~/` (other users' `~name` stay as they are).
pub fn expand_user(path: &str) -> std::path::PathBuf {
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(std::path::PathBuf::from)
    };
    if path == "~" {
        if let Some(h) = home() {
            return h;
        }
    } else if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\"))
        && let Some(h) = home()
    {
        return h.join(rest);
    }
    std::path::PathBuf::from(path)
}

/// `f"{n:,}"`.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn parse_opts_like_python() {
        let m = parse_opts(&s(&[
            "sudo=YES",
            "exclude=a,b,",
            "exclude=c",
            "x=1=2",
            "home=h",
        ]))
        .unwrap();
        assert_eq!(
            Value::Object(m),
            json!({"sudo": true, "exclude": ["a", "b", "c"], "x": "1=2", "home": "h"})
        );
        assert_eq!(
            parse_opts(&s(&["rescan=maybe"])).unwrap()["rescan"],
            "maybe"
        );
        assert_eq!(
            parse_opts(&s(&["noequals"])).unwrap_err(),
            "expected key=value, got 'noequals'"
        );
        assert!(parse_opts(&s(&["=v"])).is_err());
    }

    #[test]
    fn small_helpers() {
        assert_eq!(splitlines("a\r\nb\rc\n\nd\n"), ["a", "b", "c", "", "d"]);
        assert_eq!(str_list(Some(&json!(" a, ,b ")), "x").unwrap(), ["a", "b"]);
        assert_eq!(
            str_list(Some(&json!([1])), "x").unwrap_err(),
            "x: expected a list of strings"
        );
        assert_eq!(opt_str(Some(&json!("  ")), "p").unwrap(), None);
        assert_eq!(
            opt_str(Some(&json!(3)), "p").unwrap_err(),
            "p: expected a string"
        );
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(12), "12");
        assert_eq!(py_repr_value(&json!(null)), "None");
        assert!(truthy(&json!("x")) && !truthy(&json!(0)) && !truthy(&json!([])));
    }
}
