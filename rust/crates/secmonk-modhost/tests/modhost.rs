//! Module host tests against `tests/fixtures/echo_module.py` (child stdio) and a Rust echo (in-proc):
//! handshake, unary and stream calls, concurrency, stray prints, cancel on drop, deadlines with cancel-then-kill,
//! crashes and restarts, hello checks, protocol errors, kill on drop, trait adapters, the registry.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_modhost::adapters::{PyCollector, PyEngine};
use secmonk_modhost::child::ChildModule;
use secmonk_modhost::hello::HostSettings;
use secmonk_modhost::inproc::{self, EventSink, RustModule};
use secmonk_modhost::registry::{ModuleEntry, Registry, read_manifest};
use secmonk_modhost::session::{CallOptions, StreamEvent};
use secmonk_modhost::supervisor::{ModuleHandle, ModuleState, Running, Starter, session_params};
use secmonk_proto::manifest::{Lifecycle, ModuleLimits};
use secmonk_proto::{ErrorCode, Manifest, WireError};
use secmonk_runtime::LaunchSpec;
use secmonk_traits::{CallCtx, Classifier, Collector, Probe, VersionOracle, collect};
use serde_json::{Value, json};

fn python() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/echo_module.py")
}

const METHODS: [&str; 16] = [
    "echo.unary",
    "echo.stream",
    "echo.sleep",
    "echo.hang",
    "echo.crash",
    "echo.log",
    "echo.print",
    "echo.garbage",
    "echo.big",
    "echo.pid",
    "echo.spawn_child",
    "echo.flood",
    "collector.collect",
    "collector.expand_targets",
    "engine.classify",
    "versions.compare",
];

fn entry(name: &str, max_restarts: u32, max_frame: u64) -> ModuleEntry {
    let m: Manifest = serde_json::from_value(json!({
        "schema": "secmonk-module/1", "name": name, "version": "0.0.1", "kind": "tool", "runtime": "python",
        "protocol": "secmonk-wire/1",
        "provides": {"collectors": [{"name": "echo-fs", "description": "test collector"}], "methods": METHODS},
        "capabilities": [], "platforms": ["macos", "linux", "windows"],
        "python": {"project": "python", "env": "test", "entry": ["-I"]}
    }))
    .unwrap();
    let limits = ModuleLimits {
        hello_timeout_s: Some(6),
        request_timeout_s: Some(20),
        cancel_grace_s: Some(1),
        max_frame: Some(max_frame),
        max_inflight: Some(8),
        memory_mb: None,
    };
    let lifecycle = Lifecycle {
        start: None,
        idle_timeout_s: None,
        max_restarts: Some(max_restarts),
        restart_window_s: Some(60),
    };
    ModuleEntry {
        limits: limits.resolved(),
        lifecycle: lifecycle.resolved(),
        manifest: m,
        available: true,
        source: None,
    }
}

fn spec(py: &Path, name: &str, flags: &[&str]) -> LaunchSpec {
    let mut args: Vec<std::ffi::OsString> = vec!["-I".into(), fixture().into(), name.into()];
    args.extend(flags.iter().map(Into::into));
    let mut env = std::collections::BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        std::env::var_os("PATH").unwrap_or_default(),
    );
    LaunchSpec {
        program: py.to_path_buf(),
        args,
        env,
        cwd: std::env::temp_dir(),
    }
}

fn handle_with(
    py: PathBuf,
    e: &ModuleEntry,
    flags: &'static [&'static str],
    starts: Arc<AtomicUsize>,
) -> ModuleHandle {
    let e2 = e.clone();
    let starter: Starter = Arc::new(move || {
        let py = py.clone();
        let e = e2.clone();
        let starts = starts.clone();
        Box::pin(async move {
            starts.fetch_add(1, Ordering::SeqCst);
            let (hs, cfg) = session_params(&e, &HostSettings::default());
            let c = ChildModule::spawn(&spec(&py, &e.manifest.name, flags), hs, cfg).await?;
            Ok(Running {
                session: c.session.clone(),
                child: Some(c),
            })
        })
    });
    ModuleHandle::new(e, starter)
}

macro_rules! need_python {
    () => {
        match python() {
            Some(p) => p,
            None => {
                eprintln!("python3 not found: skipped");
                return;
            }
        }
    };
}

/// Whether `pid` still exists (`kill(pid, 0)`; tokio reaps killed children through its SIGCHLD driver).
fn running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Some(p) = rustix::process::Pid::from_raw(pid as i32) else {
            return false;
        };
        match rustix::process::test_kill_process(p) {
            Ok(()) => true,
            Err(e) => e == rustix::io::Errno::PERM,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

async fn wait_gone(pid: u32) -> bool {
    for _ in 0..100 {
        if !running(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn unary_stream_concurrency_and_stray_prints() {
    let py = need_python!();
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    let s = h.session().await.unwrap();
    assert_eq!(s.peer().name, "echo");
    assert_eq!(h.state().await, ModuleState::Running);
    assert_eq!(
        s.call("echo.unary", json!({"a": 1}), CallOptions::default())
            .await
            .unwrap(),
        json!({"a": 1})
    );
    // stray print goes to stderr, the frame stream stays intact
    assert_eq!(
        s.call("echo.print", json!({}), CallOptions::default())
            .await
            .unwrap(),
        json!({"printed": true})
    );
    s.call("echo.log", json!({}), CallOptions::default())
        .await
        .unwrap();
    let mut st = s
        .call_stream("echo.stream", json!({"n": 50}), CallOptions::default())
        .await
        .unwrap();
    let mut items = 0;
    let mut end = None;
    while let Some(ev) = st.next().await {
        match ev.unwrap() {
            StreamEvent::Item(v) => {
                assert_eq!(v["k"], items);
                items += 1;
            }
            StreamEvent::End(v) => end = v,
        }
    }
    assert_eq!((items, end), (50, Some(json!({"count": 50}))));
    // 20 concurrent calls, answered out of order
    let calls = (0..20).map(|i| {
        let s = s.clone();
        async move {
            s.call("echo.unary", json!({"i": i}), CallOptions::default())
                .await
                .unwrap()
        }
    });
    let got = futures_util::future::join_all(calls).await;
    assert!(got.iter().enumerate().all(|(i, v)| v["i"] == i));
    assert_eq!(s.pending(), 0);
    let e = s
        .call("echo.nope", json!({}), CallOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownMethod);
}

#[tokio::test]
async fn progress_and_cancel_on_drop() {
    let py = need_python!();
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    let s = h.session().await.unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let seen2 = seen.clone();
    let opts = CallOptions {
        deadline: None,
        progress: Some(Arc::new(move |_| {
            seen2.fetch_add(1, Ordering::SeqCst);
        })),
    };
    let fut = s.call("echo.sleep", json!({"seconds": 30}), opts);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), fut)
            .await
            .is_err(),
        "dropped after 300 ms"
    );
    assert!(seen.load(Ordering::SeqCst) > 0, "progress frames delivered");
    // the cancelled request stays pending (holding its slot) until the module answers it
    let t0 = std::time::Instant::now();
    while s.pending() != 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the module answers the cancel"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // the module got the cancel and is still usable
    assert_eq!(
        s.call("echo.unary", json!({"x": 2}), CallOptions::default())
            .await
            .unwrap(),
        json!({"x": 2})
    );
}

#[tokio::test]
async fn deadline_cancels_then_kills() {
    let py = need_python!();
    let starts = Arc::new(AtomicUsize::new(0));
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], starts.clone());
    let s = h.session().await.unwrap();
    // the module honours cancel: timeout, session stays open
    let short = CallOptions {
        deadline: Some(Duration::from_millis(200)),
        progress: None,
    };
    let e = s
        .call("echo.sleep", json!({"seconds": 30}), short.clone())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    assert!(!s.is_closed());
    // the module ignores cancel: killed after the grace (1 s), timeout, then a restart on the next call
    let pid = h.pid().await.unwrap();
    let e = s.call("echo.hang", json!({}), short).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    assert!(s.is_closed());
    assert!(wait_gone(pid).await, "hung module killed");
    let s2 = h.session().await.unwrap();
    assert_ne!(h.pid().await.unwrap(), pid);
    assert_eq!(
        s2.call("echo.unary", json!({}), CallOptions::default())
            .await
            .unwrap(),
        json!({})
    );
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn crash_restart_and_give_up() {
    let py = need_python!();
    let starts = Arc::new(AtomicUsize::new(0));
    let h = handle_with(py, &entry("echo", 2, 16 << 20), &[], starts.clone());
    for round in 0..3 {
        let s = h.session().await.unwrap();
        let slow = s.clone();
        let pending = tokio::spawn(async move {
            slow.call("echo.sleep", json!({"seconds": 30}), CallOptions::default())
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let e = s
            .call("echo.crash", json!({}), CallOptions::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::ModuleCrashed, "round {round}");
        assert_eq!(
            pending.await.unwrap().unwrap_err().code,
            ErrorCode::ModuleCrashed
        );
    }
    // first start + 2 restarts allowed in the window, then failed
    let e = h.session().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ModuleUnavailable);
    assert_eq!(h.state().await, ModuleState::Failed);
    assert_eq!(starts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn hello_is_checked() {
    let py = need_python!();
    for (flags, what) in [
        (&["--no-hello"][..], "no hello within"),
        (&["--claim-extra"][..], "claims method extra.method"),
        (&["--bad-protocol"][..], "unsupported protocol"),
    ] {
        let e = entry("echo", 0, 16 << 20);
        let (hs, cfg) = session_params(&e, &HostSettings::default());
        let err = ChildModule::spawn(&spec(&py, "echo", flags), hs, cfg)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ModuleUnavailable, "{flags:?}");
        assert!(err.error.contains(what), "{flags:?}: {}", err.error);
    }
    // wrong name
    let e = entry("echo", 0, 16 << 20);
    let (hs, cfg) = session_params(&e, &HostSettings::default());
    let err = ChildModule::spawn(&spec(&py, "other", &[]), hs, cfg)
        .await
        .unwrap_err();
    assert!(err.error.contains("hello names module"), "{}", err.error);
}

#[tokio::test]
async fn protocol_errors_close_the_session() {
    let py = need_python!();
    let h = handle_with(
        py.clone(),
        &entry("echo", 3, 16 << 20),
        &[],
        Default::default(),
    );
    let s = h.session().await.unwrap();
    let pid = h.pid().await.unwrap();
    let e = s
        .call("echo.garbage", json!({}), CallOptions::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ProtocolError);
    assert!(s.is_closed());
    assert!(wait_gone(pid).await, "killed after a protocol error");
    // oversize: the host's limit is 64 KiB here
    let h = handle_with(py, &entry("echo", 3, 64 * 1024), &[], Default::default());
    let s = h.session().await.unwrap();
    let e = s
        .call(
            "echo.big",
            json!({"bytes": 200_000}),
            CallOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ProtocolError, "{}", e.error);
}

#[tokio::test]
async fn kill_on_drop_leaves_no_orphan() {
    let py = need_python!();
    let h = handle_with(
        py.clone(),
        &entry("echo", 3, 16 << 20),
        &[],
        Default::default(),
    );
    let s = h.session().await.unwrap();
    let pid = s
        .call("echo.pid", json!({}), CallOptions::default())
        .await
        .unwrap()["pid"]
        .as_u64()
        .unwrap() as u32;
    assert_eq!(
        h.pid().await,
        Some(pid),
        "the venv interpreter is the direct child (no uv parent)"
    );
    assert!(running(pid));
    drop(s);
    drop(h);
    assert!(
        wait_gone(pid).await,
        "module {pid} still running after the handle was dropped"
    );
    // graceful shutdown: EOF on stdin, the module exits by itself
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    h.session().await.unwrap();
    let pid = h.pid().await.unwrap();
    let t = std::time::Instant::now();
    h.shutdown().await;
    assert!(!running(pid));
    // M3: closing the session closes the module's stdin, so it leaves on EOF; the grace period (1 s here) is only
    // for modules that do not
    assert!(
        t.elapsed() < Duration::from_millis(600),
        "shutdown took {:?}: it waited for the grace period",
        t.elapsed()
    );
}

#[tokio::test]
async fn adapters_over_a_module() {
    let py = need_python!();
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    let c = PyCollector::new(h.clone());
    assert_eq!(c.collectors()[0].name, "echo-fs");
    assert!(Probe::methods(&c).contains(&"echo.pid".to_string()));
    let p = secmonk_model::CollectParams {
        collector: "echo-fs".into(),
        target: Some("/x".into()),
        options: vec![],
    };
    assert_eq!(
        c.expand_targets(p.clone(), CallCtx::default())
            .await
            .unwrap(),
        vec![Some("/x".into())]
    );
    let inv = collect::assemble(
        c.collect(p, CallCtx::default()).await.unwrap(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        (
            inv.components.len(),
            inv.warnings.len(),
            inv.asset.id.as_str()
        ),
        (3, 1, "dir:/x")
    );
    let e = PyEngine::new(h);
    let back = e
        .classify(inv.components.clone(), CallCtx::default())
        .await
        .unwrap();
    assert_eq!(back, inv.components);
    assert_eq!(
        e.compare("1.0", "2.0", "pypi", CallCtx::default())
            .await
            .unwrap(),
        std::cmp::Ordering::Less
    );
    let err = c
        .call("collector.collect", json!({}), CallCtx::default())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnknownMethod);
}

/// A Rust module served in process.
struct RustEcho(Manifest);

#[async_trait]
impl RustModule for RustEcho {
    fn manifest(&self) -> &Manifest {
        &self.0
    }

    async fn handle(
        &self,
        method: &str,
        params: Value,
        sink: EventSink,
    ) -> Result<Value, WireError> {
        match method {
            "echo.unary" => Ok(params),
            "collector.collect" => {
                sink.emit(json!({"kind": "asset", "schema": "secmonk-inventory/1", "collector": "echo-fs",
                    "classified": false, "asset": {"id": "dir:/r", "type": "directory", "name": "r"}}))?;
                Ok(
                    json!({"partial": false, "partial_reason": null, "components": 0, "warnings": 0}),
                )
            }
            "echo.hang" => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(Value::Null)
            }
            _ => Err(WireError::new(ErrorCode::UnknownMethod, method)),
        }
    }
}

#[tokio::test]
async fn inproc_transport() {
    let mut e = entry("rust-echo", 3, 16 << 20);
    e.manifest.runtime = secmonk_proto::manifest::ModuleRuntime::Rust;
    let module = Arc::new(RustEcho(e.manifest.clone()));
    let h = inproc::handle(module, &e, HostSettings::default());
    let s = h.session().await.unwrap();
    assert_eq!(s.peer().runtime.as_deref(), Some("rust"));
    assert_eq!(
        s.call("echo.unary", json!({"z": 1}), CallOptions::default())
            .await
            .unwrap(),
        json!({"z": 1})
    );
    let c = PyCollector::new(h.clone());
    let p = secmonk_model::CollectParams {
        collector: "echo-fs".into(),
        target: None,
        options: vec![],
    };
    let inv = collect::assemble(
        c.collect(p, CallCtx::default()).await.unwrap(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(inv.asset.id, "dir:/r");
    // cancel aborts the Rust task; the caller sees a timeout
    let short = CallOptions {
        deadline: Some(Duration::from_millis(100)),
        progress: None,
    };
    assert_eq!(
        s.call("echo.hang", json!({}), short)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Timeout
    );
    assert!(!s.is_closed());
}

#[test]
fn registry_from_manifests() {
    let ex = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/examples/module");
    let mut ms = Vec::new();
    for f in [
        "py-engine.json",
        "py-probe.json",
        "py-sources.json",
        "py-procmon.json",
        "rs-collect-fs.json",
    ] {
        ms.push((read_manifest(&ex.join(f)).unwrap(), Some(ex.join(f))));
    }
    let enabled: Vec<String> = ["py-engine", "py-probe", "py-sources"]
        .map(String::from)
        .into();
    let mut overrides = std::collections::BTreeMap::new();
    overrides.insert(
        "py-sources".to_string(),
        secmonk_config::ModuleOverride {
            request_timeout_s: Some(21600),
            ..Default::default()
        },
    );
    let r = Registry::from_manifests(
        ms.clone(),
        &enabled,
        &overrides,
        secmonk_config::TrustMode::Dev,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(r.iter().count(), 3);
    assert!(r.get("py-procmon").is_none(), "not enabled");
    assert_eq!(r.get("py-sources").unwrap().limits.request_timeout_s, 21600);
    assert_eq!(
        r.serving("engine.match").unwrap().manifest.name,
        "py-engine"
    );
    assert_eq!(
        r.eager()
            .iter()
            .map(|e| e.manifest.name.as_str())
            .collect::<Vec<_>>(),
        vec!["py-engine"]
    );
    // pinned mode without pins refuses
    let err = Registry::from_manifests(
        ms.clone(),
        &enabled,
        &Default::default(),
        secmonk_config::TrustMode::Pinned,
        &Default::default(),
    );
    assert!(err.is_err());
    // H1: the manifest's own `integrity` strings are not proof: a pin entry per module is what counts
    let pins: std::collections::BTreeMap<String, secmonk_config::ModulePin> = ms
        .iter()
        .map(|(m, _)| {
            (
                m.name.clone(),
                secmonk_config::ModulePin {
                    lock_sha256: Some("a".repeat(64)),
                    tree_sha256: Some("b".repeat(64)),
                },
            )
        })
        .collect();
    // M4: with pins, pinned mode starts; the runtime verifies the hashes at ensure_env and at every start
    let mut fixed = ms.clone();
    for (m, _) in &mut fixed {
        if let Some(py) = &mut m.python {
            py.entry = secmonk_modhost::registry::fixed_entry(&m.name);
        }
    }
    let ok = Registry::from_manifests(
        fixed.clone(),
        &enabled,
        &Default::default(),
        secmonk_config::TrustMode::Pinned,
        &pins,
    )
    .unwrap();
    assert_eq!(ok.iter().count(), 3);
    // a pin missing for one enabled module refuses
    let mut some = pins.clone();
    some.remove("py-engine");
    let err = Registry::from_manifests(
        fixed.clone(),
        &enabled,
        &Default::default(),
        secmonk_config::TrustMode::Pinned,
        &some,
    )
    .unwrap_err();
    assert!(err.to_string().contains("no [modules.pins] entry"), "{err}");
    // manifests are outside the tree hash: a changed `entry` (another module, extra flags, -c) is refused
    for bad in [
        vec!["-c".to_string(), "import os".into()],
        vec!["-m".into(), "evil".into()],
        {
            let mut e = secmonk_modhost::registry::fixed_entry("py-engine");
            e.push("--extra".into());
            e
        },
    ] {
        let mut tampered = fixed.clone();
        for (m, _) in &mut tampered {
            if let Some(py) = &mut m.python {
                py.entry = bad.clone();
            }
        }
        let err = Registry::from_manifests(
            tampered,
            &enabled,
            &Default::default(),
            secmonk_config::TrustMode::Pinned,
            &pins,
        )
        .unwrap_err();
        assert!(err.to_string().contains("python.entry"), "{err}");
    }
    // the real manifests of rust/python (W2.2), when present, parse and validate
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python/modules");
    if let Ok(rd) = std::fs::read_dir(&real) {
        for f in rd.flatten() {
            let p = f.path();
            if matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("toml" | "json")
            ) {
                read_manifest(&p).unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }
}

#[test]
fn host_hello_settings_and_grants() {
    let ex = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/examples/module");
    let engine = read_manifest(&ex.join("py-engine.json")).unwrap();
    let probe = read_manifest(&ex.join("py-probe.json")).unwrap();
    let s = HostSettings {
        min_confidence: 0.5,
        state_db: Some("/d/db/state.sqlite3".into()),
        mirror_db: Some("/d/db/mirror.sqlite3".into()),
        allow_db_read: true,
        process_target: None,
        process_options: vec![],
        modules_root: Some("/d/modules".into()),
    };
    let h = secmonk_modhost::hello::host_hello(&engine, &s, 1 << 24);
    let v = serde_json::to_value(&h).unwrap();
    assert_eq!(v["session"]["grants"]["db_read"]["uri_flags"], "mode=ro");
    assert_eq!(
        v["session"]["settings"]["module_dir"],
        "/d/modules/py-engine"
    );
    assert_eq!(
        v["session"]["settings"]["process"],
        json!({"target": null, "options": []})
    );
    assert_eq!(v["session"]["settings"]["min_confidence"], 0.5);
    // a module without db-read never gets the grant
    let h = secmonk_modhost::hello::host_hello(&probe, &s, 1 << 24);
    assert!(h.session.unwrap().grants.unwrap().db_read.is_none());
    // the frame round-trips through the envelope parser
    secmonk_proto::Message::from_slice(
        &secmonk_proto::Message::Hello(Box::new(secmonk_modhost::hello::host_hello(
            &engine,
            &s,
            1 << 24,
        )))
        .to_vec(),
    )
    .unwrap();
}

/// An entry with the lifecycle knobs the supervisor tests turn.
fn entry_life(max_restarts: u32, window_s: u64, idle_s: u64, max_inflight: u32) -> ModuleEntry {
    let mut e = entry("echo", max_restarts, 16 << 20);
    e.lifecycle.restart_window_s = window_s;
    e.lifecycle.idle_timeout_s = idle_s;
    e.limits.max_inflight = max_inflight;
    e
}

#[cfg(unix)]
#[tokio::test]
async fn a_kill_takes_the_whole_process_group() {
    // M2: what a module started (ssh, kubectl, ...) must die with it, on a timeout kill and on drop
    let py = need_python!();
    let h = handle_with(
        py.clone(),
        &entry("echo", 3, 16 << 20),
        &[],
        Default::default(),
    );
    let s = h.session().await.unwrap();
    let grandchild = s
        .call("echo.spawn_child", json!({}), CallOptions::default())
        .await
        .unwrap()["child_pid"]
        .as_u64()
        .unwrap() as u32;
    assert!(running(grandchild));
    let short = CallOptions {
        deadline: Some(Duration::from_millis(200)),
        progress: None,
    };
    let e = s.call("echo.hang", json!({}), short).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    assert!(
        wait_gone(grandchild).await,
        "grandchild {grandchild} survived the module's kill"
    );

    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    let s = h.session().await.unwrap();
    let grandchild = s
        .call("echo.spawn_child", json!({}), CallOptions::default())
        .await
        .unwrap()["child_pid"]
        .as_u64()
        .unwrap() as u32;
    drop(s);
    drop(h);
    assert!(
        wait_gone(grandchild).await,
        "grandchild {grandchild} survived the handle drop"
    );
}

#[tokio::test]
async fn deadline_kills_even_when_the_stream_consumer_is_stuck() {
    // M4: a stream whose buffer is full and whose consumer does not read must not stop the watchdog's kill
    let py = need_python!();
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], Default::default());
    let s = h.session().await.unwrap();
    let pid = h.pid().await.unwrap();
    let opts = CallOptions {
        deadline: Some(Duration::from_millis(200)),
        progress: None,
    };
    let _stuck = s
        .call_stream("echo.flood", json!({"n": 200}), opts)
        .await
        .unwrap();
    // never polled: the buffer (8) fills, the reader blocks; deadline 0.2 s + grace 1 s, then the kill
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(s.is_closed(), "the session must be closed by the watchdog");
    assert!(wait_gone(pid).await, "module {pid} was not killed");
}

#[tokio::test]
async fn a_finished_stream_releases_its_slot() {
    // max_inflight = 1: `source.sync` streams to its end, then `source.ack` must be able to run while the stream
    // object is still alive
    let py = need_python!();
    let h = handle_with(py, &entry_life(3, 60, 0, 1), &[], Default::default());
    let s = h.session().await.unwrap();
    let mut st = s
        .call_stream("echo.stream", json!({"n": 2}), CallOptions::default())
        .await
        .unwrap();
    while let Some(ev) = st.next().await {
        if matches!(ev.unwrap(), StreamEvent::End(_)) {
            break;
        }
    }
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        s.call("echo.unary", json!({"a": 1}), CallOptions::default()),
    )
    .await
    .expect("the call waited for a slot the finished stream still held");
    assert_eq!(r.unwrap(), json!({"a": 1}));
    drop(st);
}

#[tokio::test]
async fn idle_modules_stop_and_start_again_without_counting_as_crashes() {
    let py = need_python!();
    let starts = Arc::new(AtomicUsize::new(0));
    // max_restarts = 1: two idle cycles would exhaust it if they counted
    let h = handle_with(py, &entry_life(1, 60, 1, 4), &[], starts.clone());
    for round in 0..3 {
        let s = h.session().await.unwrap();
        let pid = h.pid().await.unwrap();
        s.call("echo.unary", json!({}), CallOptions::default())
            .await
            .unwrap();
        drop(s);
        tokio::time::sleep(Duration::from_millis(2300)).await;
        assert_eq!(h.state().await, ModuleState::Idle, "round {round}");
        assert!(wait_gone(pid).await, "idle module {pid} still running");
    }
    assert_eq!(starts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_busy_module_is_not_reaped_while_a_call_runs() {
    let py = need_python!();
    let h = handle_with(py, &entry_life(3, 60, 1, 4), &[], Default::default());
    let s = h.session().await.unwrap();
    let r = s
        .call(
            "echo.sleep",
            json!({"seconds": 2.5}),
            CallOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(r["slept"], 2.5);
}

#[tokio::test]
async fn failed_is_not_forever() {
    let py = need_python!();
    let starts = Arc::new(AtomicUsize::new(0));
    let h = handle_with(py, &entry_life(1, 2, 0, 4), &[], starts.clone());
    for _ in 0..2 {
        let s = h.session().await.unwrap();
        let _ = s
            .call("echo.crash", json!({}), CallOptions::default())
            .await;
    }
    assert_eq!(
        h.session().await.unwrap_err().code,
        ErrorCode::ModuleUnavailable
    );
    assert_eq!(h.state().await, ModuleState::Failed);
    // the window passes: the module may be tried again
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let s = h
        .session()
        .await
        .expect("a new start after the restart window");
    assert_eq!(
        s.call("echo.unary", json!({}), CallOptions::default())
            .await
            .unwrap(),
        json!({})
    );
    assert_ne!(h.state().await, ModuleState::Failed);
}

/// A dropped call keeps its `max_inflight` slot until the module's final frame; a module that ignores the cancel
/// is killed after the cancel grace, which then frees everything.
#[tokio::test]
async fn dropped_call_keeps_its_slot_until_the_module_answers() {
    let py = need_python!();
    let mut e = entry("echo", 3, 16 << 20);
    e.limits.max_inflight = 1;
    let h = handle_with(py, &e, &[], Default::default());
    let s = h.session().await.unwrap();
    let pid = h.pid().await.unwrap();

    // honours cancel: the slot is free again once the module answered
    let fut = s.call("echo.sleep", json!({"seconds": 30}), CallOptions::default());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), fut)
            .await
            .is_err()
    );
    assert_eq!(s.pending(), 1, "the cancelled request is still pending");
    let r = s
        .call("echo.unary", json!({"x": 1}), CallOptions::default())
        .await
        .unwrap();
    assert_eq!(r, json!({"x": 1}), "waits for the slot, then runs");

    // a stream dropped midway behaves the same
    let st = s
        .call_stream("echo.stream", json!({"n": 3}), CallOptions::default())
        .await
        .unwrap();
    drop(st);
    assert_eq!(
        s.call("echo.unary", json!({"x": 2}), CallOptions::default())
            .await
            .unwrap(),
        json!({"x": 2})
    );

    // ignores cancel: the next call cannot jump the queue; the watchdog kills the module after the grace (1 s)
    let fut = s.call("echo.hang", json!({}), CallOptions::default());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), fut)
            .await
            .is_err()
    );
    assert_eq!(s.pending(), 1);
    let next = tokio::time::timeout(
        Duration::from_millis(400),
        s.call("echo.unary", json!({}), CallOptions::default()),
    )
    .await;
    assert!(
        next.is_err(),
        "no free slot while the module is stuck on the cancelled request"
    );
    assert!(
        wait_gone(pid).await,
        "the stuck module is killed after the cancel grace"
    );
    assert!(s.is_closed());
}

#[tokio::test]
async fn a_closed_handle_never_restarts_and_state_does_not_wait_for_a_start() {
    let py = need_python!();
    let starts = Arc::new(AtomicUsize::new(0));
    let h = handle_with(py, &entry("echo", 3, 16 << 20), &[], starts.clone());
    h.session().await.unwrap();
    h.shutdown().await;
    assert_eq!(h.state().await, ModuleState::Closed);
    let e = h.session().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ModuleUnavailable);
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    // a slow start holds the lock: state() answers `Starting` at once
    let slow: Starter = Arc::new(|| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            Err(WireError::new(
                ErrorCode::ModuleUnavailable,
                "slow start failed",
            ))
        })
    });
    let h = ModuleHandle::new(&entry("echo", 3, 16 << 20), slow);
    let h2 = h.clone();
    let start = tokio::spawn(async move { h2.session().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t0 = std::time::Instant::now();
    assert_eq!(h.state().await, ModuleState::Starting);
    assert!(t0.elapsed() < Duration::from_millis(200));
    assert!(start.await.unwrap().is_err());
}
