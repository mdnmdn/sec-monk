//! Python semantics the reference sources (`src/secmonk/sources/*.py`) rely on, for the native importers: string
//! whitespace, `float(str)`, truthiness, type names, `repr` / `str` of JSON values, `for` over a value, and the texts of
//! the exceptions a differential test compares.
//! Shared by every importer; an importer that needs another rule keeps it in its own module.

use std::borrow::Cow;

use serde_json::Value;

/// Python's `str.isspace()` for one character: Unicode whitespace plus the ASCII separators `\x1c`-`\x1f`.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Python's `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// Python's `str.split()` without arguments: runs of whitespace separate, empty parts dropped.
pub fn split_ws(s: &str) -> impl Iterator<Item = &str> {
    s.split(is_space).filter(|p| !p.is_empty())
}

/// Python's `float(str)`: surrounding whitespace, a sign, `_` between digits, exponents, Unicode decimal digits,
/// `nan`, `inf` / `infinity` (any case). `None` where Python raises `ValueError`.
pub fn float_str(s: &str) -> Option<f64> {
    let t = ascii_digits(strip(s));
    let t = t.as_ref();
    if t.is_empty() {
        return None;
    }
    if t.contains('_') {
        let b = t.as_bytes();
        let between_digits = b.iter().enumerate().all(|(i, c)| {
            *c != b'_'
                || (i > 0
                    && b[i - 1].is_ascii_digit()
                    && b.get(i + 1).is_some_and(u8::is_ascii_digit))
        });
        if !between_digits {
            return None;
        }
        t.replace('_', "").parse::<f64>().ok()
    } else {
        t.parse::<f64>().ok()
    }
}

/// The first code point of every run of ten Unicode decimal digits (category Nd), from Python 3.13's `unicodedata`
/// (Unicode 15.1): `float()` reads them as `0`-`9`.
const DECIMAL_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

/// Python's `str.isdecimal()` for one character (also what `re`'s `\d` matches): a Unicode decimal digit (category
/// Nd, the runs of [`DECIMAL_ZEROS`]).
pub fn is_decimal(c: char) -> bool {
    let u = u32::from(c);
    DECIMAL_ZEROS
        .partition_point(|z| *z <= u)
        .checked_sub(1)
        .is_some_and(|i| u - DECIMAL_ZEROS[i] < 10)
}

/// Unicode decimal digits replaced by ASCII ones, as Python's `float()` does before parsing; other characters kept.
fn ascii_digits(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        return Cow::Borrowed(s);
    }
    let digit = |c: char| -> Option<char> {
        let u = u32::from(c);
        let i = DECIMAL_ZEROS.partition_point(|z| *z <= u).checked_sub(1)?;
        let d = u - DECIMAL_ZEROS[i];
        (d < 10).then(|| char::from(b'0' + d as u8))
    };
    Cow::Owned(s.chars().map(|c| digit(c).unwrap_or(c)).collect())
}

/// Python's `bool(x)` of a value `json.loads` produced: `None`, `False`, `0`, `0.0`, `""`, `[]`, `{}` are false.
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

/// `type(x).__name__` of a value `json.loads` produced.
pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `AttributeError` text (without the class) of `x.<attr>` on a value of type `type_name`:
/// `'<type>' object has no attribute '<attr>'`.
pub fn no_attr(type_name: &str, attr: &str) -> String {
    format!("'{type_name}' object has no attribute '{attr}'")
}

/// Python's `repr(float)`: the shortest round-trip digits, exponent form below 1e-4 and from 1e16 (`1e-05`,
/// `1e+16`), else a `.0` added to integral values; `nan`, `inf`, `-inf`, `-0.0`.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let sign = if mant.starts_with('-') { "-" } else { "" };
    let digits = mant.trim_start_matches('-').replace('.', "");
    if !(-4..16).contains(&exp) {
        let m = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits
        };
        let s = if exp < 0 { '-' } else { '+' };
        format!("{sign}{m}e{s}{:02}", exp.unsigned_abs())
    } else if exp < 0 {
        let zeros = "0".repeat(exp.unsigned_abs() as usize - 1);
        format!("{sign}0.{zeros}{digits}")
    } else {
        let point = exp as usize + 1;
        if digits.len() <= point {
            format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
        } else {
            format!("{sign}{}.{}", &digits[..point], &digits[point..])
        }
    }
}

/// Python's `str.isprintable()` for one character, without the Unicode tables: the control, format, separator and
/// private-use ranges, and the non-characters. Unassigned code points count as printable here (Python escapes them).
pub fn is_printable(c: char) -> bool {
    let u = u32::from(c);
    if u < 0x7f {
        return u >= 0x20;
    }
    !matches!(u,
        0x7f..=0xa0 | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x1680 | 0x180e
        | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064 | 0x2066..=0x206f | 0x3000 | 0xd800..=0xf8ff
        | 0xfdd0..=0xfdef | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f
        | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f | 0xf0000..)
        && (u & 0xfffe) != 0xfffe
}

/// Python's `repr(str)`, appended to `out`: single quotes unless the text has one and no double quote; `\\`, `\t`,
/// `\n`, `\r` and the quote escaped; characters that are not printable ([`is_printable`]) as `\xNN`, `\uNNNN` or
/// `\UNNNNNNNN`.
pub fn repr_str_into(s: &str, out: &mut String) {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let u = u32::from(c);
                if u <= 0xff {
                    out.push_str(&format!("\\x{u:02x}"));
                } else if u <= 0xffff {
                    out.push_str(&format!("\\u{u:04x}"));
                } else {
                    out.push_str(&format!("\\U{u:08x}"));
                }
            }
        }
    }
    out.push(q);
}

/// Python's `repr(str)` ([`repr_str_into`]).
pub fn repr_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    repr_str_into(s, &mut out);
    out
}

/// `repr(x)` of a value `json.loads` produced: `None`, `True`, ints, [`float_repr`], [`repr_str`], lists and dicts.
pub fn repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                float_repr(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}: {}", repr_str(k), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `str(x)` of a value `json.loads` produced: a string itself, anything else its [`repr`].
pub fn str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => repr(other),
    }
}

/// `for x in (v or [])` over a value `json.loads` produced, lazily: the elements of a list (borrowed), the characters
/// of a string, the keys of an object (each a one-off string value, built as the iterator is read: a large string or
/// object costs nothing up front); nothing for an absent or falsy value. `Err`: Python's `TypeError` text (without
/// the class) for a truthy number or `true`.
pub fn iter_items(v: Option<&Value>) -> Result<Items<'_>, String> {
    match v {
        None => Ok(Items::Empty),
        Some(x) if !truthy(x) => Ok(Items::Empty),
        Some(Value::Array(a)) => Ok(Items::List(a.iter())),
        Some(Value::String(s)) => Ok(Items::Chars(s.chars())),
        Some(Value::Object(m)) => Ok(Items::Keys(m.keys())),
        Some(x) => Err(format!("'{}' object is not iterable", type_name(x))),
    }
}

/// The iterator of [`iter_items`].
#[derive(Debug)]
pub enum Items<'a> {
    /// Nothing to iterate.
    Empty,
    /// The elements of a list.
    List(std::slice::Iter<'a, Value>),
    /// The characters of a string.
    Chars(std::str::Chars<'a>),
    /// The keys of an object.
    Keys(serde_json::map::Keys<'a>),
}

impl<'a> Iterator for Items<'a> {
    type Item = Cow<'a, Value>;

    fn next(&mut self) -> Option<Cow<'a, Value>> {
        match self {
            Items::Empty => None,
            Items::List(i) => i.next().map(Cow::Borrowed),
            Items::Chars(c) => c.next().map(|c| Cow::Owned(Value::String(c.to_string()))),
            Items::Keys(k) => k.next().map(|k| Cow::Owned(Value::String(k.clone()))),
        }
    }
}

/// `str(UnicodeDecodeError)` of `bytes.decode("utf-8")` (strict) failing with `e` on `bytes`.
pub fn utf8_error(bytes: &[u8], e: &std::str::Utf8Error) -> String {
    let pos = e.valid_up_to();
    let b = bytes.get(pos).copied().unwrap_or(0);
    match e.error_len() {
        Some(_) => {
            let reason = if (0xC2..=0xF4).contains(&b) {
                "invalid continuation byte"
            } else {
                "invalid start byte"
            };
            format!("'utf-8' codec can't decode byte 0x{b:02x} in position {pos}: {reason}")
        }
        None if bytes.len() - pos > 1 => format!(
            "'utf-8' codec can't decode bytes in position {pos}-{}: unexpected end of data",
            bytes.len() - 1
        ),
        None => format!(
            "'utf-8' codec can't decode byte 0x{b:02x} in position {pos}: unexpected end of data"
        ),
    }
}

/// Bytes as UTF-8 text, or Python's `UnicodeDecodeError` text.
pub fn decode_utf8(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|e| utf8_error(bytes, &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_whitespace_and_truthiness_follow_python() {
        assert_eq!(float_str(" 1_0.5 "), Some(10.5));
        assert_eq!(float_str("\u{1c}2\u{a0}"), Some(2.0));
        assert_eq!(float_str("-inf"), Some(f64::NEG_INFINITY));
        assert!(float_str("NaN").unwrap().is_nan());
        assert_eq!(float_str("1__0"), None);
        assert_eq!(float_str(""), None);
        assert_eq!(float_str("０.５"), Some(0.5));
        assert_eq!(strip("\u{1f} a \u{3000}"), "a");
        assert_eq!(
            split_ws(" a\u{1c}b  c ").collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        for (v, t) in [
            (json!(null), false),
            (json!(0), false),
            (json!(0.0), false),
            (json!(""), false),
            (json!([]), false),
            (json!({}), false),
            (json!(false), false),
            (json!(2), true),
            (json!("0"), true),
            (json!([0]), true),
        ] {
            assert_eq!(truthy(&v), t, "{v}");
        }
        assert_eq!(type_name(&json!(1)), "int");
        assert_eq!(type_name(&json!(1.5)), "float");
        assert_eq!(type_name(&json!(null)), "NoneType");
    }

    #[test]
    fn reprs_follow_python() {
        // texts of Python 3.13 `repr`
        for (f, t) in [
            (1.0, "1.0"),
            (0.1, "0.1"),
            (123.5, "123.5"),
            (-123.456, "-123.456"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.5e-5, "1.5e-05"),
            (2.5e-5, "2.5e-05"),
            (0.0001, "0.0001"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (2.5e300, "2.5e+300"),
        ] {
            assert_eq!(float_repr(f), t, "{f}");
        }
        assert_eq!(repr_str("a"), "'a'");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("'\""), "'\\'\"'");
        assert_eq!(repr_str("a\\b\tc\x01\x7f"), "'a\\\\b\\tc\\x01\\x7f'");
        assert_eq!(
            repr_str("é\u{a0}\u{200b}\u{fffd}"),
            "'é\\xa0\\u200b\u{fffd}'"
        );
        assert_eq!(repr_str("\u{e0001}"), "'\\U000e0001'");
        assert_eq!(str_of(&json!(5041585)), "5041585");
        assert_eq!(str_of(&json!(2.0)), "2.0");
        assert_eq!(str_of(&json!(true)), "True");
        assert_eq!(str_of(&json!(null)), "None");
        assert_eq!(str_of(&json!("x\u{1}")), "x\u{1}");
        assert_eq!(
            str_of(&json!([1, "a", {"b": null, "c": true}, "\u{1}"])),
            "[1, 'a', {'b': None, 'c': True}, '\\x01']"
        );
        assert_eq!(no_attr("int", "get"), "'int' object has no attribute 'get'");
    }

    #[test]
    fn items_iterate_like_a_python_for_loop() {
        let all = |v: &Value| -> Vec<Value> {
            iter_items(Some(v)).unwrap().map(Cow::into_owned).collect()
        };
        assert_eq!(all(&json!([1, "a"])), vec![json!(1), json!("a")]);
        assert_eq!(all(&json!("ab")), vec![json!("a"), json!("b")]);
        assert_eq!(all(&json!({"k": 1, "l": 2})), vec![json!("k"), json!("l")]);
        for falsy in [
            json!(0),
            json!(""),
            json!(null),
            json!([]),
            json!({}),
            json!(false),
        ] {
            assert!(all(&falsy).is_empty(), "{falsy}");
        }
        assert!(iter_items(None).unwrap().next().is_none());
        assert_eq!(
            iter_items(Some(&json!(3))).unwrap_err(),
            "'int' object is not iterable"
        );
        assert_eq!(
            iter_items(Some(&json!(true))).unwrap_err(),
            "'bool' object is not iterable"
        );
        // lazy: the first character of a large string without building the others
        let big = Value::String("x".repeat(1 << 20));
        let mut it = iter_items(Some(&big)).unwrap();
        assert_eq!(it.next().as_deref(), Some(&json!("x")));
        assert!(matches!(it, Items::Chars(ref c) if c.as_str().len() == (1 << 20) - 1));
    }

    #[test]
    fn utf8_errors_read_like_python() {
        // texts of Python 3.13 `bytes.decode("utf-8")`
        assert_eq!(
            decode_utf8(b"ab\xffc").unwrap_err(),
            "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte"
        );
        assert_eq!(
            decode_utf8(b"\xe2\x28\xa1").unwrap_err(),
            "'utf-8' codec can't decode byte 0xe2 in position 0: invalid continuation byte"
        );
        assert_eq!(
            decode_utf8(b"x\xf0\x90\x80").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 1-3: unexpected end of data"
        );
        assert_eq!(
            decode_utf8(b"x\xe2").unwrap_err(),
            "'utf-8' codec can't decode byte 0xe2 in position 1: unexpected end of data"
        );
        assert_eq!(decode_utf8("ü".as_bytes()).unwrap(), "ü");
    }
}
