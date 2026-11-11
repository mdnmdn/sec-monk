//! The ports produce exactly the Python outputs recorded in `tests/golden/redaction.json`.

use secmonk_safeio::*;
use serde_json::Value;

fn golden() -> Value {
    serde_json::from_str(include_str!("golden/redaction.json")).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn looks_secret_matches_python() {
    for c in golden()["looks_secret"].as_array().unwrap() {
        assert_eq!(
            looks_secret(s(&c[0])),
            c[1].as_bool().unwrap(),
            "{:?}",
            c[0]
        );
    }
}

#[test]
fn strip_url_secrets_matches_python() {
    for c in golden()["strip_url_secrets"].as_array().unwrap() {
        assert_eq!(strip_url_secrets(s(&c[0]), false), s(&c[1]), "{:?}", c[0]);
        assert_eq!(
            strip_url_secrets(s(&c[0]), true),
            s(&c[2]),
            "{:?} keep_user",
            c[0]
        );
    }
}

#[test]
fn redact_command_matches_python() {
    let g = golden();
    for c in g["redact_command_list"].as_array().unwrap() {
        assert_eq!(redact_command_value(&c[0]), c[1], "{:?}", c[0]);
    }
    for c in g["redact_command_str"].as_array().unwrap() {
        assert_eq!(redact_command_str(s(&c[0])), s(&c[1]), "{:?}", c[0]);
    }
}

#[test]
fn scrub_text_matches_python() {
    for c in golden()["scrub_text"].as_array().unwrap() {
        match &c[0] {
            Value::String(t) => assert_eq!(scrub_text(t), s(&c[1]), "{t:?}"),
            _ => assert!(c[1].is_null()),
        }
    }
}

#[test]
fn redact_option_matches_python() {
    for c in golden()["redact_option"].as_array().unwrap() {
        assert_eq!(
            redact_option(s(&c[0]), &c[1]),
            c[2],
            "key {:?} value {:?}",
            c[0],
            c[1]
        );
    }
}

#[test]
fn redact_labels_matches_python() {
    for c in golden()["redact_labels"].as_array().unwrap() {
        let input = c[0].as_object().cloned().unwrap_or_default();
        assert_eq!(Value::Object(redact_labels(&input)), c[1], "{:?}", c[0]);
    }
}
