//! [`StoreMirrorView`]: the read-only [`MirrorView`] a native source gets (rust ADR-0011), over the engine's
//! `MirrorStore` (the row reads: rust ADR-0012). Reads only; a native source still writes nothing itself: its
//! batches are applied by the sync job.

use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::{JsonMap, MirrorTable};
use secmonk_store::{MirrorStore, StoreError};
use secmonk_traits::{
    AppliedMark, ErrorCode, MAX_VIEW_IDS, MAX_VIEW_PAGE, MirrorView, RowPage, StepResult, WireError,
};

/// A [`MirrorView`] over a [`MirrorStore`]. The composition root builds it from the store it gives the engine.
#[derive(Clone)]
pub struct StoreMirrorView {
    mirror: Arc<dyn MirrorStore>,
}

impl std::fmt::Debug for StoreMirrorView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreMirrorView").finish_non_exhaustive()
    }
}

impl StoreMirrorView {
    /// A view over `mirror`.
    pub fn new(mirror: Arc<dyn MirrorStore>) -> StoreMirrorView {
        StoreMirrorView { mirror }
    }
}

fn wire(e: StoreError) -> WireError {
    match e {
        StoreError::Invalid(m) => WireError::new(ErrorCode::InvalidParams, m),
        other => WireError::new(ErrorCode::Internal, format!("StoreError: {other}")),
    }
}

#[async_trait]
impl MirrorView for StoreMirrorView {
    async fn applied(&self, source: &str) -> StepResult<Option<AppliedMark>> {
        Ok(self
            .mirror
            .applied_state(source)
            .await
            .map_err(wire)?
            .map(|a| AppliedMark {
                seq: a.seq,
                generation: a.generation,
            }))
    }

    async fn count_rows(&self, table: MirrorTable, source: &str) -> StepResult<u64> {
        self.mirror.count_rows(table, source).await.map_err(wire)
    }

    async fn row_keys(&self, table: MirrorTable, source: &str) -> StepResult<Vec<JsonMap>> {
        self.mirror.row_keys(table, source).await.map_err(wire)
    }

    async fn rows_by_id(
        &self,
        table: MirrorTable,
        source: &str,
        ids: &[String],
    ) -> StepResult<Vec<JsonMap>> {
        if ids.len() > MAX_VIEW_IDS {
            return Err(WireError::new(
                ErrorCode::InvalidParams,
                format!("rows_by_id: {} ids (at most {MAX_VIEW_IDS})", ids.len()),
            ));
        }
        self.mirror
            .rows_by_id(table, source, ids)
            .await
            .map_err(wire)
    }

    async fn rows_page(
        &self,
        table: MirrorTable,
        source: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StepResult<RowPage> {
        if limit == 0 || limit > MAX_VIEW_PAGE {
            return Err(WireError::new(
                ErrorCode::InvalidParams,
                format!("rows_page: limit {limit} (1..={MAX_VIEW_PAGE})"),
            ));
        }
        let (rows, next) = self
            .mirror
            .rows_page(table, source, after, limit)
            .await
            .map_err(wire)?;
        Ok(RowPage { rows, next })
    }
}
