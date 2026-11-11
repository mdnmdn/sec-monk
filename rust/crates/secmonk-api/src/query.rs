//! Query strings and parameter helpers with the semantics of `urllib.parse.parse_qs` and `web/data.py`
//! (`_one`, `_flag`, `_int`).

use std::collections::HashMap;

use percent_encoding::percent_decode_str;
use secmonk_engine::error::py_repr;

use crate::error::ApiError;

/// Parsed query: name -> values in order. Pairs with an empty value are dropped (`parse_qs` default).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Query(HashMap<String, Vec<String>>);

fn decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for pair in raw.unwrap_or("").split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            map.entry(decode(name)).or_default().push(decode(value));
        }
        Self(map)
    }

    pub fn all(&self, name: &str) -> &[String] {
        self.0.get(name).map_or(&[], Vec::as_slice)
    }

    /// `_one`: the last value, trimmed; blank is `None`.
    pub fn one(&self, name: &str) -> Option<String> {
        let v = self.all(name).last()?.trim();
        (!v.is_empty()).then(|| v.to_owned())
    }

    /// `_flag`: `1`, `true` or `yes`.
    pub fn flag(&self, name: &str) -> bool {
        matches!(self.one(name).as_deref(), Some("1" | "true" | "yes"))
    }

    /// `_int`: an integer within `lo..=hi`, else a 400 with Python's message.
    pub fn int(&self, name: &str, default: u32, lo: u32, hi: u32) -> Result<u32, ApiError> {
        let Some(v) = self.one(name) else {
            return Ok(default);
        };
        let digits = v.strip_prefix(['+', '-']).unwrap_or(&v);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ApiError::bad_request(format!(
                "{name}: expected an integer, got {}",
                py_repr(&v)
            )));
        }
        let shown = v.strip_prefix('+').unwrap_or(&v).trim_start_matches('0');
        let shown = if shown.is_empty() || shown == "-" {
            "0"
        } else {
            shown
        };
        match v.parse::<i64>() {
            Ok(n) if (i64::from(lo)..=i64::from(hi)).contains(&n) => Ok(n as u32),
            _ => Err(ApiError::bad_request(format!(
                "{name}: expected {lo}..{hi}, got {shown}"
            ))),
        }
    }

    /// Repeatable `opt=k=v` values, blanks dropped (`[o for o in q.get("opt", []) if o.strip()]`).
    pub fn options(&self, name: &str) -> Vec<String> {
        self.all(name)
            .iter()
            .filter(|o| !o.trim().is_empty())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_parse_qs() {
        let q = Query::parse(Some("a=1&a=2&b=&c&d=x%20y+z&e=%zz&opt=k%3Dv&opt= "));
        assert_eq!(q.all("a"), ["1", "2"]);
        assert!(q.all("b").is_empty() && q.all("c").is_empty());
        assert_eq!(q.one("d").as_deref(), Some("x y z"));
        assert_eq!(q.one("e").as_deref(), Some("%zz"));
        assert_eq!(q.one("a").as_deref(), Some("2"));
        assert_eq!(q.options("opt"), ["k=v"]);
        assert_eq!(q.one("opt").as_deref(), None, "a blank last value is None");
    }

    #[test]
    fn flags() {
        let q = Query::parse(Some("a=1&b=yes&c=true&d=0&e=TRUE"));
        assert!(q.flag("a") && q.flag("b") && q.flag("c"));
        assert!(!q.flag("d") && !q.flag("e") && !q.flag("zz"));
    }

    #[test]
    fn ints_and_their_messages() {
        let q = Query::parse(Some("limit=0&x=abc&y=5001&z=7&w=99999999999999999999"));
        assert_eq!(q.int("none", 200, 1, 5000).unwrap(), 200);
        assert_eq!(q.int("z", 200, 1, 5000).unwrap(), 7);
        assert_eq!(
            q.int("limit", 200, 1, 5000).unwrap_err().message,
            "limit: expected 1..5000, got 0"
        );
        assert_eq!(
            q.int("x", 200, 1, 5000).unwrap_err().message,
            "x: expected an integer, got 'abc'"
        );
        assert_eq!(
            q.int("y", 200, 1, 5000).unwrap_err().message,
            "y: expected 1..5000, got 5001"
        );
        assert_eq!(
            q.int("w", 200, 1, 5000).unwrap_err().message,
            "w: expected 1..5000, got 99999999999999999999"
        );
    }
}
