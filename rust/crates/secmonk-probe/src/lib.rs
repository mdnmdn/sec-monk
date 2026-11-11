//! The local probe service (skeleton): one [`Probe`] in front of any number of [`Collector`] trait objects and one
//! optional method provider. It owns the **allowlist**: only registered collector names and the fixed, read-only
//! probe methods below are ever dispatched, whatever the UI or a job asks for. It never touches the store or the
//! engine (architecture: probe must not depend on `secmonk-store`).
//!
//! Tauri-free by design: a Linux headless build is engine + probe + the API over the loopback server.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::{CollectEnd, CollectItem, CollectParams};
use secmonk_proto::{CollectorInfo, ErrorCode};
use secmonk_traits::{CallCtx, Collector, Probe, ResultStream, StepError, StepResult};
use serde_json::Value;

/// Probe methods other than `collector.*` that may be dispatched (each fixed, read-only and documented in
/// `contracts/catalog/module-methods.json`).
pub const ALLOWED_METHODS: [&str; 6] = [
    "discover.host",
    "docker.contexts",
    "docker.containers",
    "docker.image_check",
    "k8s.kubeconfigs",
    "process.snapshot",
];

/// Registering a collector name twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("collector {0:?} is already registered")]
pub struct DuplicateCollector(pub String);

/// Collector allowlist and dispatch.
#[derive(Default)]
pub struct ProbeService {
    collectors: BTreeMap<String, Arc<dyn Collector>>,
    methods: Option<Arc<dyn Probe>>,
}

impl std::fmt::Debug for ProbeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeService")
            .field("collectors", &self.collectors.keys().collect::<Vec<_>>())
            .field("methods", &self.methods.is_some())
            .finish()
    }
}

impl ProbeService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow every collector `c` serves. A name served twice is refused (the allowlist stays unambiguous).
    pub fn register(&mut self, c: Arc<dyn Collector>) -> Result<(), DuplicateCollector> {
        let names: Vec<String> = c.collectors().into_iter().map(|i| i.name).collect();
        if let Some(dup) = names.iter().find(|n| self.collectors.contains_key(*n)) {
            return Err(DuplicateCollector(dup.clone()));
        }
        for n in names {
            self.collectors.insert(n, c.clone());
        }
        Ok(())
    }

    /// The provider of `discover.*`, `docker.*`, `k8s.*`, `process.*` (a module adapter or a Rust probe).
    pub fn with_methods(mut self, p: Arc<dyn Probe>) -> Self {
        self.methods = Some(p);
        self
    }

    pub fn allows_collector(&self, name: &str) -> bool {
        self.collectors.contains_key(name)
    }

    #[allow(clippy::result_large_err)] // WireError is 144 bytes (secmonk-proto); the trait fixes the error type
    fn lookup(&self, name: &str) -> StepResult<&Arc<dyn Collector>> {
        self.collectors.get(name).ok_or_else(|| {
            let known: Vec<&str> = self.collectors.keys().map(String::as_str).collect();
            StepError::new(
                ErrorCode::UnknownCollector,
                format!("collector: expected one of {}", known.join(", ")),
            )
        })
    }
}

#[async_trait]
impl Collector for ProbeService {
    fn collectors(&self) -> Vec<CollectorInfo> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for c in self.collectors.values() {
            for info in c.collectors() {
                if self.collectors.contains_key(&info.name) && seen.insert(info.name.clone()) {
                    out.push(info);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    async fn expand_targets(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<Vec<Option<String>>> {
        self.lookup(&params.collector)?
            .expand_targets(params, ctx)
            .await
    }

    async fn collect(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
        self.lookup(&params.collector)?.collect(params, ctx).await
    }
}

#[async_trait]
impl Probe for ProbeService {
    fn methods(&self) -> Vec<String> {
        match &self.methods {
            Some(p) => p
                .methods()
                .into_iter()
                .filter(|m| ALLOWED_METHODS.contains(&m.as_str()))
                .collect(),
            None => Vec::new(),
        }
    }

    async fn call(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value> {
        let provider = self
            .methods
            .as_ref()
            .filter(|_| ALLOWED_METHODS.contains(&method));
        match provider {
            Some(p) => p.call(method, params, ctx).await,
            None => Err(StepError::new(
                ErrorCode::UnknownMethod,
                format!("probe method {method:?} is not allowed"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use secmonk_model::{Asset, CollectEnd};
    use secmonk_traits::StreamMsg;

    struct Fake(&'static str);

    #[async_trait]
    impl Collector for Fake {
        fn collectors(&self) -> Vec<CollectorInfo> {
            vec![CollectorInfo {
                name: self.0.into(),
                description: "fake".into(),
                platforms: None,
            }]
        }
        async fn expand_targets(
            &self,
            p: CollectParams,
            _: CallCtx,
        ) -> StepResult<Vec<Option<String>>> {
            Ok(vec![p.target])
        }
        async fn collect(
            &self,
            _p: CollectParams,
            _: CallCtx,
        ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
            let asset = Asset {
                id: "dir:/x".into(),
                kind: "directory".into(),
                name: "x".into(),
                os_name: None,
                os_version: None,
                platform: None,
                meta: Default::default(),
            };
            let items = vec![
                Ok(StreamMsg::Item(CollectItem::Asset {
                    schema: "secmonk-inventory/1".into(),
                    collector: self.0.into(),
                    classified: false,
                    asset,
                })),
                Ok(StreamMsg::End(CollectEnd {
                    partial: false,
                    partial_reason: None,
                    components: 0,
                    warnings: 0,
                })),
            ];
            Ok(Box::pin(futures_util::stream::iter(items)))
        }
    }

    struct Methods;

    #[async_trait]
    impl Collector for Methods {
        fn collectors(&self) -> Vec<CollectorInfo> {
            vec![]
        }
        async fn expand_targets(
            &self,
            _: CollectParams,
            _: CallCtx,
        ) -> StepResult<Vec<Option<String>>> {
            Ok(vec![])
        }
        async fn collect(
            &self,
            _: CollectParams,
            _: CallCtx,
        ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
            Err(StepError::new(ErrorCode::Internal, "unused"))
        }
    }

    #[async_trait]
    impl Probe for Methods {
        fn methods(&self) -> Vec<String> {
            vec!["discover.host".into(), "engine.match".into()]
        }
        async fn call(&self, method: &str, _: Value, _: CallCtx) -> StepResult<Value> {
            Ok(serde_json::json!({"called": method}))
        }
    }

    fn params(c: &str) -> CollectParams {
        CollectParams {
            collector: c.into(),
            target: Some("t".into()),
            options: vec![],
        }
    }

    #[tokio::test]
    async fn dispatches_only_registered_collectors() {
        let mut s = ProbeService::new();
        s.register(Arc::new(Fake("fs"))).unwrap();
        s.register(Arc::new(Fake("npm"))).unwrap();
        assert_eq!(
            s.register(Arc::new(Fake("fs"))),
            Err(DuplicateCollector("fs".into()))
        );
        assert_eq!(
            s.collectors()
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["fs", "npm"]
        );
        assert_eq!(
            s.expand_targets(params("fs"), CallCtx::default())
                .await
                .unwrap(),
            vec![Some("t".to_owned())]
        );
        let mut stream = s.collect(params("npm"), CallCtx::default()).await.unwrap();
        assert!(matches!(
            stream.next().await,
            Some(Ok(StreamMsg::Item(CollectItem::Asset { .. })))
        ));
        let e = s
            .expand_targets(params("rm-rf"), CallCtx::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::UnknownCollector);
        assert_eq!(e.error, "collector: expected one of fs, npm");
    }

    #[tokio::test]
    async fn only_fixed_methods_pass() {
        let s = ProbeService::new().with_methods(Arc::new(Methods));
        assert_eq!(
            s.methods(),
            ["discover.host"],
            "engine.* is never a probe method"
        );
        let ok = s
            .call("discover.host", Value::Null, CallCtx::default())
            .await
            .unwrap();
        assert_eq!(ok["called"], "discover.host");
        let bad = s
            .call("engine.match", Value::Null, CallCtx::default())
            .await
            .unwrap_err();
        assert_eq!(bad.code, ErrorCode::UnknownMethod);
        let none = ProbeService::new()
            .call("discover.host", Value::Null, CallCtx::default())
            .await
            .unwrap_err();
        assert_eq!(none.code, ErrorCode::UnknownMethod);
    }
}
