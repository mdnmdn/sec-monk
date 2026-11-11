//! Every model type round-trips the contract examples (`rust/contracts/examples`): deserialize, serialize,
//! compare as JSON values.

use std::path::PathBuf;

use secmonk_model::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn example(rel: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/examples")
        .join(rel);
    serde_json::from_str(
        &std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
    )
    .unwrap()
}

fn round_trip<T: Serialize + DeserializeOwned>(v: &Value) -> T {
    let t: T =
        serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("deserialize: {e}\n{v}"));
    let back = serde_json::to_value(&t).unwrap();
    assert_eq!(&back, v, "round trip changed the document");
    t
}

#[test]
fn inventories() {
    let inv: Inventory = round_trip(&example("inventory/fs-npm-v3.json"));
    assert_eq!(inv.schema.as_deref(), Some(INVENTORY_SCHEMA));
    let legacy: Inventory = round_trip(&example("inventory/legacy-collect-O.json"));
    assert!(legacy.schema.is_none() && legacy.is_classified());
    assert_eq!(
        legacy.components[0].key(),
        "pkg:npm/%40babel/code-frame@7.12.13"
    );
}

#[test]
fn collect_stream_items() {
    let ev = example("wire/04-event-asset.json");
    assert!(matches!(
        round_trip::<CollectItem>(&ev["data"]),
        CollectItem::Asset {
            classified: false,
            ..
        }
    ));
    let ev = example("wire/05-event-components.json");
    assert!(matches!(
        round_trip::<CollectItem>(&ev["data"]),
        CollectItem::Components { .. }
    ));
    round_trip::<CollectParams>(&example("wire/03-req-collect.json")["params"]);
    round_trip::<CollectEnd>(&example("wire/07-end-collect.json")["result"]);
}

#[test]
fn engine_calls() {
    let req = example("wire/12-req-classify.json");
    let comps: Vec<Component> = round_trip(&req["params"]["components"]);
    assert_eq!(comps[2].key(), "pkg:pypi/requests@2.31.0");
    round_trip::<Vec<Component>>(&example("wire/13-res-classify.json")["result"]["components"]);
    round_trip::<MatchParams>(&example("wire/14-req-match.json")["params"]);
    let res: MatchResult = round_trip(&example("wire/15-res-match.json")["result"]);
    assert_eq!(res.finding_set.unwrap()[0].status, FindingStatus::Open);
}

#[test]
fn source_rows() {
    round_trip::<SyncParams>(&example("wire/16-req-sync.json")["params"]);
    let batch: RowsBatch = round_trip(&example("wire/17-event-rows.json")["data"]);
    assert!(batch.ops.iter().any(|o| o.table() == MirrorTable::Affected));
    round_trip::<SyncEnd>(&example("wire/18-end-sync.json")["result"]);
}

#[test]
fn process_snapshot() {
    let s: ProcessSnapshot = round_trip(&example("process/snapshot-linux.json"));
    assert_eq!(s.schema, PROCESS_SNAPSHOT_SCHEMA);
}

#[test]
fn jobs() {
    round_trip::<JobPayload>(&example("api/job.json"));
    round_trip::<Vec<JobPayload>>(&example("api/jobs.json"));
}

#[test]
fn component_key_without_purl() {
    let c = Component {
        name: "Google Chrome".into(),
        version: Some("131.0".into()),
        category: Category::Application,
        purl: None,
        cpe: None,
        vendor: Some("Google".into()),
        ecosystem: None,
        source_path: None,
        meta: Default::default(),
    };
    assert_eq!(c.key(), "name:application/google/google chrome@131.0");
}
