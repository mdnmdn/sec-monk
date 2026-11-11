//! Every wire and manifest example of `rust/contracts/examples` parses and round-trips.

use std::path::PathBuf;

use secmonk_proto::{Manifest, Message};
use serde_json::Value;

fn dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/examples")
        .join(rel)
}

fn files(rel: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

#[test]
fn wire_examples_round_trip() {
    let all = files("wire");
    assert!(all.len() >= 19);
    for p in all {
        let raw = std::fs::read(&p).unwrap();
        let msg = Message::from_slice(&raw).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let orig: Value = serde_json::from_slice(&raw).unwrap();
        let back: Value = serde_json::from_slice(&msg.to_vec()).unwrap();
        assert_eq!(back, orig, "{}", p.display());
    }
}

#[test]
fn manifest_examples_round_trip() {
    for p in files("module") {
        let orig: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let m: Manifest =
            serde_json::from_value(orig.clone()).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        m.validate()
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert_eq!(serde_json::to_value(&m).unwrap(), orig, "{}", p.display());
        // the same structure in TOML (the on-disk form)
        let toml_text = toml::to_string(&m).unwrap();
        let again: Manifest = toml::from_str(&toml_text).unwrap();
        assert_eq!(again, m);
    }
}
