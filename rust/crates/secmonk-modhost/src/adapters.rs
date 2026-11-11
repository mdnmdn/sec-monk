//! The domain traits of `secmonk-traits` implemented over a module ([`ModuleHandle`]): the engine cannot
//! tell these from Rust implementations. Payloads are decoded into the `secmonk-model` types; a payload that
//! does not decode is a `protocol-error` (module output is untrusted input).

use std::cmp::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{
    AckParams, CollectEnd, CollectItem, CollectParams, Component, ExpandResult, MatchParams,
    MatchResult, RowsBatch, SyncEnd, SyncParams,
};
use secmonk_proto::{CollectorInfo, ErrorCode, Progress, SourceInfo, WireError, methods};
use secmonk_traits::{
    CallCtx, Classifier, Collector, Matcher, Probe, ProgressUpdate, Reporter, ResultStream, Source,
    StepResult, StreamMsg, VersionOracle,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::session::{CallOptions, StreamEvent};
use crate::supervisor::ModuleHandle;

/// Components per `engine.classify` call.
pub const CLASSIFY_CHUNK: usize = 5000;

fn options(ctx: &CallCtx) -> CallOptions {
    let progress = ctx.progress.clone().map(|cb| {
        let f: crate::session::ProgressFn = Arc::new(move |p: &Progress| {
            cb(ProgressUpdate {
                message: p.message.clone(),
                done: p.done,
                total: p.total,
                unit: p.unit.clone(),
            })
        });
        f
    });
    CallOptions {
        deadline: ctx.deadline,
        progress,
    }
}

fn decode<T: DeserializeOwned>(module: &str, what: &str, v: Value) -> StepResult<T> {
    serde_json::from_value(v)
        .map_err(|e| WireError::protocol(format!("{module}: invalid {what}: {e}")))
}

fn encode<T: Serialize>(v: &T) -> StepResult<Value> {
    serde_json::to_value(v).map_err(|e| WireError::internal("SerializeError", e))
}

async fn call<T: DeserializeOwned>(
    h: &ModuleHandle,
    method: &str,
    params: Value,
    ctx: &CallCtx,
) -> StepResult<T> {
    let s = h.session().await?;
    let v = s.call(method, params, options(ctx)).await?;
    decode(h.name(), method, v)
}

async fn stream<T, E>(
    h: &ModuleHandle,
    method: &str,
    params: Value,
    ctx: &CallCtx,
) -> StepResult<ResultStream<T, E>>
where
    T: DeserializeOwned + Send + 'static,
    E: DeserializeOwned + Send + 'static,
{
    let s = h.session().await?;
    let st = s.call_stream(method, params, options(ctx)).await?;
    let name = h.name().to_string();
    let method = method.to_string();
    Ok(Box::pin(st.map(move |item| match item? {
        StreamEvent::Item(v) => decode::<T>(&name, &method, v).map(StreamMsg::Item),
        StreamEvent::End(v) => {
            decode::<E>(&name, &method, v.unwrap_or(Value::Null)).map(StreamMsg::End)
        }
    })))
}

/// A probe module (`py-probe`) as [`Collector`] + [`Probe`].
#[derive(Debug, Clone)]
pub struct PyCollector {
    handle: ModuleHandle,
}

impl PyCollector {
    /// Over a handle.
    pub fn new(handle: ModuleHandle) -> PyCollector {
        PyCollector { handle }
    }
}

#[async_trait]
impl Collector for PyCollector {
    fn collectors(&self) -> Vec<CollectorInfo> {
        self.handle.provides().collectors().to_vec()
    }

    async fn expand_targets(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<Vec<Option<String>>> {
        let r: ExpandResult = call(
            &self.handle,
            methods::COLLECTOR_EXPAND_TARGETS,
            encode(&params)?,
            &ctx,
        )
        .await?;
        Ok(r.targets)
    }

    async fn collect(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
        stream(
            &self.handle,
            methods::COLLECTOR_COLLECT,
            encode(&params)?,
            &ctx,
        )
        .await
    }
}

#[async_trait]
impl Probe for PyCollector {
    fn methods(&self) -> Vec<String> {
        self.handle
            .provides()
            .methods()
            .iter()
            .filter(|m| !m.starts_with("collector."))
            .cloned()
            .collect()
    }

    async fn call(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value> {
        if !Probe::methods(self).iter().any(|m| m == method) {
            return Err(WireError::new(
                ErrorCode::UnknownMethod,
                format!("{}: no method {method:?}", self.handle.name()),
            ));
        }
        call(&self.handle, method, params, &ctx).await
    }
}

/// A source module (`py-sources`) as [`Source`].
#[derive(Debug, Clone)]
pub struct PySource {
    handle: ModuleHandle,
}

impl PySource {
    /// Over a handle.
    pub fn new(handle: ModuleHandle) -> PySource {
        PySource { handle }
    }
}

#[async_trait]
impl Source for PySource {
    fn sources(&self) -> Vec<SourceInfo> {
        self.handle.provides().sources().to_vec()
    }

    fn sync_all_order(&self) -> Vec<String> {
        self.handle.provides().sync_all_order.unwrap_or_default()
    }

    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        stream(&self.handle, methods::SOURCE_SYNC, encode(&params)?, &ctx).await
    }

    async fn ack(&self, source: &str, through_seq: u64, ctx: CallCtx) -> StepResult<()> {
        let p = AckParams {
            source: source.into(),
            through_seq,
        };
        let _: Value = call(&self.handle, methods::SOURCE_ACK, encode(&p)?, &ctx).await?;
        Ok(())
    }

    async fn export(
        &self,
        source: &str,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>> {
        let p = AckParams {
            source: source.into(),
            through_seq: 0,
        };
        stream(&self.handle, methods::SOURCE_EXPORT, encode(&p)?, &ctx).await
    }
}

/// An engine module (`py-engine`, `py-procmon`) as [`Classifier`], [`Matcher`], [`Reporter`],
/// [`VersionOracle`].
#[derive(Debug, Clone)]
pub struct PyEngine {
    handle: ModuleHandle,
}

impl PyEngine {
    /// Over a handle.
    pub fn new(handle: ModuleHandle) -> PyEngine {
        PyEngine { handle }
    }
}

#[derive(serde::Deserialize)]
struct Components {
    components: Vec<Component>,
}

#[async_trait]
impl Classifier for PyEngine {
    async fn classify(
        &self,
        components: Vec<Component>,
        ctx: CallCtx,
    ) -> StepResult<Vec<Component>> {
        let mut out = Vec::with_capacity(components.len());
        for chunk in components.chunks(CLASSIFY_CHUNK) {
            let r: Components = call(
                &self.handle,
                methods::ENGINE_CLASSIFY,
                json!({ "components": chunk }),
                &ctx,
            )
            .await?;
            if r.components.len() != chunk.len() {
                return Err(WireError::protocol(format!(
                    "{}: classify returned {} components for {}",
                    self.handle.name(),
                    r.components.len(),
                    chunk.len()
                )));
            }
            out.extend(r.components);
        }
        Ok(out)
    }
}

#[async_trait]
impl Matcher for PyEngine {
    async fn match_asset(&self, params: MatchParams, ctx: CallCtx) -> StepResult<MatchResult> {
        call(&self.handle, methods::ENGINE_MATCH, encode(&params)?, &ctx).await
    }
}

#[async_trait]
impl Reporter for PyEngine {
    fn methods(&self) -> Vec<String> {
        self.handle
            .provides()
            .methods()
            .iter()
            .filter(|m| {
                m.starts_with(methods::REPORTS_PREFIX) || m.starts_with(methods::PROCMON_PREFIX)
            })
            .cloned()
            .collect()
    }

    async fn report(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value> {
        if !Reporter::methods(self).iter().any(|m| m == method) {
            return Err(WireError::new(
                ErrorCode::UnknownMethod,
                format!("{}: no method {method:?}", self.handle.name()),
            ));
        }
        call(&self.handle, method, params, &ctx).await
    }
}

#[derive(serde::Deserialize)]
struct CompareResult {
    result: i64,
}
#[derive(serde::Deserialize)]
struct InRangeResult {
    affected: bool,
}
#[derive(serde::Deserialize)]
struct FirstFixedResult {
    fixed: Option<String>,
}
#[derive(serde::Deserialize)]
struct SchemeResult {
    scheme: String,
}
#[derive(serde::Deserialize)]
struct PriorityResult {
    priority: String,
}

#[async_trait]
impl VersionOracle for PyEngine {
    async fn compare(&self, a: &str, b: &str, scheme: &str, ctx: CallCtx) -> StepResult<Ordering> {
        let r: CompareResult = call(
            &self.handle,
            methods::VERSIONS_COMPARE,
            json!({"a": a, "b": b, "scheme": scheme}),
            &ctx,
        )
        .await?;
        Ok(r.result.cmp(&0))
    }

    async fn in_range(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<bool> {
        let p = json!({"version": version, "events": events, "scheme": scheme});
        let r: InRangeResult = call(&self.handle, methods::VERSIONS_IN_RANGE, p, &ctx).await?;
        Ok(r.affected)
    }

    async fn first_fixed(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<Option<String>> {
        let p = json!({"version": version, "events": events, "scheme": scheme});
        let r: FirstFixedResult =
            call(&self.handle, methods::VERSIONS_FIRST_FIXED, p, &ctx).await?;
        Ok(r.fixed)
    }

    async fn scheme(&self, ecosystem: Option<&str>, ctx: CallCtx) -> StepResult<String> {
        let r: SchemeResult = call(
            &self.handle,
            methods::VERSIONS_SCHEME,
            json!({"ecosystem": ecosystem}),
            &ctx,
        )
        .await?;
        Ok(r.scheme)
    }

    async fn priority(&self, params: Value, ctx: CallCtx) -> StepResult<String> {
        let r: PriorityResult = call(&self.handle, methods::SCORING_PRIORITY, params, &ctx).await?;
        Ok(r.priority)
    }
}
