//! Cutting row operations into `secmonk-mirror-rows/1` batches: at most [`MAX_OPS`] operations and about
//! [`MAX_BYTES`] of JSON each (the limits of `py-sources`, `rows.schema.json` `ops.maxItems`).

use secmonk_model::{RowOp, RowsBatch};
use secmonk_traits::NATIVE_GENERATION;

/// Operations per batch.
pub const MAX_OPS: usize = 5_000;
/// Approximate JSON bytes per batch (a single larger operation travels alone).
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

/// Batch limits (tests use small ones to get several batches out of a small fixture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Operations per batch.
    pub ops: usize,
    /// JSON bytes per batch.
    pub bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            ops: MAX_OPS,
            bytes: MAX_BYTES,
        }
    }
}

/// Number `ops` into native batches of `source`, seqs from `first_seq`, in order.
pub fn cut(source: &str, ops: Vec<RowOp>, first_seq: u64, limits: Limits) -> Vec<RowsBatch> {
    let ops_cap = limits.ops.clamp(1, MAX_OPS);
    let mut out: Vec<RowsBatch> = Vec::new();
    let mut cur: Vec<RowOp> = Vec::new();
    let mut bytes = 0usize;
    let flush = |cur: &mut Vec<RowOp>, out: &mut Vec<RowsBatch>| {
        if !cur.is_empty() {
            out.push(RowsBatch {
                kind: "rows".into(),
                seq: first_seq + out.len() as u64,
                source: source.to_owned(),
                ops: std::mem::take(cur),
                generation: Some(NATIVE_GENERATION.to_owned()),
                acked_through: None,
            });
        }
    };
    for op in ops {
        let size = serde_json::to_string(&op).map_or(0, |s| s.len());
        if !cur.is_empty() && (cur.len() >= ops_cap || bytes + size > limits.bytes) {
            flush(&mut cur, &mut out);
            bytes = 0;
        }
        bytes += size;
        cur.push(op);
    }
    flush(&mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secmonk_model::MirrorTable;
    use serde_json::json;

    fn op(i: usize) -> RowOp {
        RowOp::Upsert {
            table: MirrorTable::Kev,
            row: json!({"cve_id": format!("CVE-{i}"), "source": "kev"})
                .as_object()
                .cloned()
                .unwrap(),
        }
    }

    #[test]
    fn batches_respect_both_limits_and_number_from_the_first_seq() {
        let b = cut(
            "kev",
            (0..7).map(op).collect(),
            5,
            Limits {
                ops: 3,
                bytes: 1 << 20,
            },
        );
        assert_eq!(
            b.iter().map(|b| (b.seq, b.ops.len())).collect::<Vec<_>>(),
            vec![(5, 3), (6, 3), (7, 1)]
        );
        assert!(b.iter().all(
            |b| b.generation.as_deref() == Some(NATIVE_GENERATION) && b.acked_through.is_none()
        ));
        let one = serde_json::to_string(&op(0)).unwrap().len();
        let b = cut(
            "kev",
            (0..4).map(op).collect(),
            1,
            Limits {
                ops: 100,
                bytes: one * 2,
            },
        );
        assert_eq!(b.len(), 2);
        let b = cut(
            "kev",
            (0..2).map(op).collect(),
            1,
            Limits { ops: 100, bytes: 1 },
        );
        assert_eq!(
            b.len(),
            2,
            "an operation above the byte limit travels alone"
        );
        assert!(cut("kev", vec![], 1, Limits::default()).is_empty());
    }
}
