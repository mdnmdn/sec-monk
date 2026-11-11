//! Cutting row operations into `secmonk-mirror-rows/1` batches: at most [`MAX_OPS`] operations and about
//! [`MAX_BYTES`] of JSON each (the limits of `py-sources`, `rows.schema.json` `ops.maxItems`). [`Cutter`] cuts as the
//! operations come (one batch in memory); [`cut`] numbers a list.

use secmonk_model::{RowOp, RowsBatch};
use secmonk_traits::NATIVE_GENERATION;

/// Operations per batch.
pub const MAX_OPS: usize = 5_000;
/// Approximate JSON bytes per batch (a single larger operation is sent in a batch of its own).
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

/// Cuts a sequence of operations into native batches of `source` as they come, seqs from `first_seq`: memory holds
/// one batch at a time (a large snapshot is never materialized as a list of operations).
#[derive(Debug)]
pub struct Cutter {
    source: String,
    next_seq: u64,
    ops_cap: usize,
    bytes_cap: usize,
    cur: Vec<RowOp>,
    bytes: usize,
    emitted: u64,
}

impl Cutter {
    /// A cutter for `source`, numbering from `first_seq`.
    pub fn new(source: &str, first_seq: u64, limits: Limits) -> Cutter {
        Cutter {
            source: source.to_owned(),
            next_seq: first_seq,
            ops_cap: limits.ops.clamp(1, MAX_OPS),
            bytes_cap: limits.bytes,
            cur: Vec::new(),
            bytes: 0,
            emitted: 0,
        }
    }

    /// Add one operation; returns the previous batch when this operation does not fit in it.
    pub fn push(&mut self, op: RowOp) -> Option<RowsBatch> {
        let size = serde_json::to_string(&op).map_or(0, |s| s.len());
        let full = !self.cur.is_empty()
            && (self.cur.len() >= self.ops_cap || self.bytes + size > self.bytes_cap);
        let out = if full { self.take() } else { None };
        self.bytes += size;
        self.cur.push(op);
        out
    }

    /// The last, incomplete batch (none when nothing is pending).
    pub fn finish(&mut self) -> Option<RowsBatch> {
        self.take()
    }

    /// Batches returned so far.
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Seq of the last batch returned (0 when none was).
    pub fn last_seq(&self) -> u64 {
        if self.emitted == 0 {
            0
        } else {
            self.next_seq - 1
        }
    }

    fn take(&mut self) -> Option<RowsBatch> {
        if self.cur.is_empty() {
            return None;
        }
        let batch = RowsBatch {
            kind: "rows".into(),
            seq: self.next_seq,
            source: self.source.clone(),
            ops: std::mem::take(&mut self.cur),
            generation: Some(NATIVE_GENERATION.to_owned()),
            acked_through: None,
        };
        self.next_seq += 1;
        self.emitted += 1;
        self.bytes = 0;
        Some(batch)
    }
}

/// Number `ops` into native batches of `source`, seqs from `first_seq`, in order.
pub fn cut(source: &str, ops: Vec<RowOp>, first_seq: u64, limits: Limits) -> Vec<RowsBatch> {
    let mut c = Cutter::new(source, first_seq, limits);
    let mut out: Vec<RowsBatch> = ops.into_iter().filter_map(|op| c.push(op)).collect();
    out.extend(c.finish());
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
            "an operation above the byte limit is sent in a batch of its own"
        );
        assert!(cut("kev", vec![], 1, Limits::default()).is_empty());
    }
}
