"""k8s collector: fixed kubectl argv, cluster inventory, partial access, images, kubeconfig listing.

Offline: kubectl is a fake `_run` answering from tests/fixtures/collectors/k8s (synthetic)."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from secmonk.collectors import docker_image as di
from secmonk.collectors import k8s
from secmonk.collectors.base import REGISTRY

FX = Path(__file__).parent.parent / "fixtures" / "collectors" / "k8s"
D = "sha256:" + "1" * 64
E = "sha256:" + "2" * 64
FORBIDDEN = b'Error from server (Forbidden): pods is forbidden: User "dev" cannot list resource "pods" in API group ""'


class FakeKubectl:
    """Answers by the kubectl sub-command; `deny` / `fail` map a key to stderr."""

    def __init__(self, deny=(), fail=None, ns_allowed=None):
        self.calls: list[list[str]] = []
        self.deny, self.fail, self.ns_allowed = set(deny), fail or {}, ns_allowed

    def key(self, args: list[str]) -> str:
        rest = [a for a in args[1:] if not a.startswith("--kubeconfig") and not a.startswith("--context")
                and not a.startswith("--request-timeout")]
        if rest[:2] == ["config", "view"]:
            return "config-view"
        if rest[:2] == ["get", "--raw"]:
            return "version"
        if rest[1] == "pods":
            ns = next((a.split("=", 1)[1] for a in rest if a.startswith("--namespace=")), None)
            return f"pods:{ns}" if ns else "pods"
        return rest[1]

    def __call__(self, argv, timeout, cap=k8s.MAX_OUTPUT):
        self.calls.append(argv)
        key = self.key(argv)
        if key in self.fail:
            return 1, b"", self.fail[key]
        if key in self.deny or (key.startswith("pods:") and self.ns_allowed is not None
                                and key[5:] not in self.ns_allowed):
            return 1, b"", FORBIDDEN
        if key.startswith("pods:"):
            ns = key[5:]
            doc = json.loads((FX / "pods.json").read_text())
            doc["items"] = [p for p in doc["items"] if p["metadata"]["namespace"] == ns]
            return 0, json.dumps(doc).encode(), b""
        return 0, (FX / f"{key}.json").read_bytes(), b""


@pytest.fixture
def kubectl(monkeypatch):
    fake = FakeKubectl()
    monkeypatch.setattr(k8s, "_run", fake)
    monkeypatch.setattr(k8s.shutil, "which", lambda name: "/usr/local/bin/kubectl")
    return fake


def by_name(inv):
    return {c.name: c for c in inv.components}


def test_argv_is_fixed_and_read_only(kubectl):
    inv = REGISTRY["k8s"]().collect("k8s://demo", kubeconfig="/home/x/.kube/config", timeout="10")
    assert inv.asset.id == "k8s:demo-cluster@k8s.example.test:6443" and inv.asset.type == "cluster"
    for argv in kubectl.calls:
        assert argv[:4] == ["/usr/local/bin/kubectl", "--kubeconfig=/home/x/.kube/config", "--context=demo",
                            "--request-timeout=10s"]
        assert not any(w in argv for w in ("secrets", "configmaps", "delete", "apply", "exec", "--raw=false"))
    assert [kubectl.key(a) for a in kubectl.calls] == ["config-view", "version", "nodes", "namespaces", "pods"]
    assert kubectl.calls[-1][-4:] == ["pods", "--all-namespaces", "-o", "json"]


def test_cluster_inventory(kubectl):
    inv = REGISTRY["k8s"]().collect(None)
    a, c = inv.asset, by_name(inv)
    assert a.meta["context"] == "demo" and a.meta["server"] == "https://k8s.example.test:6443"
    assert a.os_version == "1.29.3" and a.platform == "linux/amd64" and a.meta["node_count"] == 3
    assert a.meta["distro"] == ["eks"] and a.meta["namespaces"] == ["default", "kube-system", "shop"]
    cp = c["Kubernetes"]
    assert cp.purl == "pkg:golang/k8s.io/kubernetes@v1.29.3" and cp.meta["vendor_build"]
    assert cp.cpe == "cpe:2.3:a:kubernetes:kubernetes:1.29.3:*:*:*:*:*:*:*"
    kubelets = [x for x in inv.components if x.name == "kubelet"]
    assert sorted((x.version, x.meta["nodes"]) for x in kubelets) == [("1.28.5", 1), ("1.29.0", 2)]
    assert kubelets[0].purl.endswith("#cmd/kubelet")
    rt = [x for x in inv.components if x.name == "containerd"]
    assert {x.version for x in rt} == {"1.7.11", "1.6.28"}
    assert rt[0].purl.startswith("pkg:golang/github.com/containerd/containerd@v")
    osc = {x.name: x for x in inv.components if x.category == "os"}
    assert osc["Amazon Linux"].version == "2" and osc["Amazon Linux"].purl == "pkg:generic/amzn@2"
    assert osc["Bottlerocket OS"].meta["kernel_versions"] == ["6.1.77"]
    assert a.meta["access"] == {"version": "ok", "nodes": "ok", "namespaces": "ok", "pods": "all"}
    assert not inv.partial
    imgs = {i["image"]: i for i in a.meta["images"]}
    assert imgs["nginx:1.25"]["ref"] == f"docker.io/library/nginx@{D}" and imgs["nginx:1.25"]["pinned"]
    assert imgs["nginx:1.25"]["pods"] == ["shop/web-1", "shop/web-2"]
    kp = imgs["registry.example.test/eks/kube-proxy:v1.29.0"]
    assert kp["privileged"] and kp["host_path"] and kp["host_network"] and kp["ref"].endswith(E)
    assert imgs["registry.example.test/shop/migrate:3"]["init"]
    assert imgs["busybox"] == {**imgs["busybox"], "ref": "busybox", "pinned": False}     # bare sha256: not pullable
    assert any("without a digest" in w and "busybox" in w for w in inv.warnings)


def test_partial_access_cluster_wide_pods_denied(kubectl):
    kubectl.deny = {"nodes", "pods"}
    kubectl.ns_allowed = {"shop"}
    inv = REGISTRY["k8s"]().collect("demo")
    acc = inv.asset.meta["access"]
    assert acc["nodes"] == "denied" and acc["pods"] == "namespaces: shop"
    assert acc["denied_namespaces"] == ["default", "kube-system"]
    assert inv.partial and "nodes" in inv.partial_reason and "pods in default, kube-system" in inv.partial_reason
    assert "Kubernetes" in by_name(inv) and "kubelet" not in by_name(inv)       # what was readable is kept
    assert {i["image"] for i in inv.asset.meta["images"]} == {"nginx:1.25", "registry.example.test/shop/migrate:3"}


def test_partial_access_falls_back_to_context_namespace(kubectl):
    kubectl.deny = {"pods", "namespaces", "version"}
    kubectl.ns_allowed = {"shop"}
    inv = REGISTRY["k8s"]().collect("demo")
    assert inv.asset.meta["access"]["pods"] == "namespaces: shop"           # context namespace from kubeconfig
    assert inv.asset.meta["access"]["version"] == "denied" and "Kubernetes" not in by_name(inv)
    assert inv.partial


def test_no_read_access_and_unreachable(kubectl):
    kubectl.deny = {"version", "nodes", "namespaces", "pods"}
    kubectl.ns_allowed = set()
    with pytest.raises(k8s.KubectlError, match="no read access to cluster demo-cluster"):
        REGISTRY["k8s"]().collect("demo")
    kubectl.deny = set()
    kubectl.fail = {"version": b"Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout\n"
                               b"token: eyJhbGciOiJSUzI1NiJ9.abcdefghijklmnop.sig"}
    with pytest.raises(k8s.KubectlError, match="not reachable") as ei:
        REGISTRY["k8s"]().collect("demo")
    assert "eyJhbGci" not in str(ei.value)


def test_options_are_validated(kubectl, monkeypatch):
    with pytest.raises(ValueError, match="invalid Kubernetes context"):
        REGISTRY["k8s"]().collect("k8s://bad\x01name")
    REGISTRY["k8s"]().collect("k8s://-oops")                  # any name: always passed as --context=<name>
    assert kubectl.calls[-1][1] == "--context=-oops"
    with pytest.raises(ValueError, match="invalid namespace"):
        REGISTRY["k8s"]().collect("demo", namespace="shop,Bad_NS")
    with pytest.raises(ValueError, match="timeout"):
        REGISTRY["k8s"]().collect("demo", timeout="soon")
    monkeypatch.setattr(k8s.shutil, "which", lambda name: None)
    with pytest.raises(k8s.KubectlError, match="kubectl not found"):
        REGISTRY["k8s"]().collect("demo")


def test_namespace_option_lists_per_namespace(kubectl):
    imgs = k8s.cluster_images("k8s://demo", namespace="shop")
    assert [kubectl.key(a) for a in kubectl.calls][-1] == "pods:shop"
    assert {i["ref"] for i in imgs} == {f"docker.io/library/nginx@{D}", "registry.example.test/shop/migrate:3"}


def test_run_caps_and_times_out(tmp_path):
    py = shutil.which("python3") or "python3"
    rc, out, err = k8s._run([py, "-c", "import sys; sys.stdout.write('x'*10); sys.stderr.write('e')"], 10)
    assert (rc, out, err) == (0, b"x" * 10, b"e")
    with pytest.raises(k8s.KubectlError, match="larger than"):
        k8s._run([py, "-c", "import sys; sys.stdout.write('x'*5000)"], 10, cap=100)
    with pytest.raises(k8s.KubectlError, match="timed out"):
        k8s._run([py, "-c", "import time; time.sleep(30)"], 0.5)


# --------------------------------------------------------------------------- kubeconfig listing

def test_list_k8s_contexts_never_returns_credentials(monkeypatch, tmp_path):
    kc = tmp_path / "config"
    kc.write_text((FX / "kubeconfig.yaml").read_text())
    monkeypatch.setenv("KUBECONFIG", f"{kc}{os.pathsep}{tmp_path / 'missing'}")
    ctxs = k8s.list_k8s_contexts()
    assert ctxs == [
        {"name": "demo", "cluster": "demo-cluster", "server": "https://k8s.example.test:6443", "namespace": "shop",
         "current": True},
        {"name": "kind-dev", "cluster": "kind-dev", "server": "https://127.0.0.1:41234", "namespace": None,
         "current": False}]
    text = json.dumps(ctxs)
    for secret in ("hunter2", "admin", "eyJ", "S0VZ", "secret-arg", "Q0VSV", "token"):
        assert secret not in text


def test_list_kubeconfigs(monkeypatch, tmp_path):
    home = tmp_path / "home"
    kube = home / ".kube"
    (kube / "cache").mkdir(parents=True)
    (kube / "kind").mkdir()
    (kube / "config").write_text((FX / "kubeconfig.yaml").read_text())
    (kube / "kind" / "dev.yaml").write_text("apiVersion: v1\nkind: Config\ncontexts:\n- name: k\n  context: {cluster: c}\n"
                                            "clusters:\n- name: c\n  cluster: {server: 'https://10.0.0.9:6443'}\n")
    (kube / "cache" / "config.json").write_text("{}")
    (kube / "notes.yaml").write_text("just: notes\n")
    (kube / "broken-config").write_text(": : :\n- [")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "gone.yaml"))
    res = {r["path"]: r for r in k8s.list_kubeconfigs()}
    assert res[str(tmp_path / "gone.yaml")]["error"] == "not found"        # named by $KUBECONFIG: reported
    assert [c["name"] for c in res[str(kube / "config")]["contexts"]] == ["demo", "kind-dev"]
    assert res[str(kube / "kind" / "dev.yaml")]["contexts"][0]["server"] == "https://10.0.0.9:6443"
    assert str(kube / "notes.yaml") not in res and str(kube / "broken-config") not in res
    assert not any("cache" in p for p in res)
    assert "eyJ" not in json.dumps(res)
    big = kube / "huge.yaml"
    big.write_bytes(b"#" * (k8s.MAX_KUBECONFIG + 1))
    assert k8s.list_kubeconfigs(kubeconfig=str(big))[0]["error"].startswith("larger than")


# --------------------------------------------------------------------------- docker-image list targets

def test_docker_image_accepts_a_comma_list():
    c = di.DockerImageCollector()
    assert c.expand_targets(f" nginx@{D}, busybox ,,nginx@{D}") == [f"nginx@{D}", "busybox"]
    assert c.expand_targets("alpine:3.20") == ["alpine:3.20"]
    assert c.expand_targets(None) == [None]


# --------------------------------------------------------------------------- review fixes (2026-11-11)

HOSTILE = [("/etc/hosts", "x1"), ("./x.tar", "x2"), ("nginx,/etc/passwd", "x3"), ("localhost:22/x", "x4"),
           ("~root/x", "x5"), ("-oProxy", "x6"), ("bad image", "x7"), ("ok/app:1\x00", "x8"),
           ("10.1.2.3:5000/team/app:2", "x9"), ("ghcr.io/team/app:1", "x10")]


def _pod(ns, name, containers, statuses):
    return {"metadata": {"namespace": ns, "name": name}, "spec": {"containers": containers},
            "status": {"containerStatuses": statuses}}


def test_hostile_image_strings_are_never_scanned_as_paths():
    pods = [_pod("x", n, [{"name": "c", "image": img}], []) for img, n in HOSTILE]
    warnings: list[str] = []
    imgs = {i["image"]: i for i in k8s.pod_images(pods, warnings)}
    for bad in ("/etc/hosts", "./x.tar", "nginx,/etc/passwd", "~root/x", "-oProxy", "bad image", "ok/app:1\x00"):
        assert imgs[bad]["invalid"] and imgs[bad]["refs"] == [] and imgs[bad]["ref"] is None
    assert imgs["localhost:22/x"]["private"] and imgs["10.1.2.3:5000/team/app:2"]["private"]
    assert not imgs["ghcr.io/team/app:1"]["private"] and imgs["ghcr.io/team/app:1"]["refs"] == ["ghcr.io/team/app:1"]
    assert any("7 image string(s) are not registry references" in w for w in warnings)
    # a hostile imageID cannot smuggle a path either
    assert k8s.pinned_ref("nginx", "docker-pullable:///etc/x@sha256:" + "1" * 64) == ("nginx", False)


def test_docker_image_registry_only_mode(tmp_path, monkeypatch):
    (tmp_path / "nginx").mkdir()
    (tmp_path / "img.tar").write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    c = di.DockerImageCollector()
    with pytest.raises(ValueError, match="not image references: '/etc/hosts', './img.tar'"):
        c.expand_targets("nginx@sha256:" + "1" * 64 + ",/etc/hosts,./img.tar", source="registry")
    with pytest.raises(ValueError, match="is not an image reference"):
        c.collect("img.tar/../img.tar", source="registry")
    seen = {}
    monkeypatch.setattr(di.DockerImageCollector, "_collect_registry",
                        lambda self, t, platform, opts: seen.setdefault("t", t))
    c.collect("nginx", source="registry")                    # ./nginx exists as a directory: still the registry
    assert seen["t"] == "nginx"
    with pytest.raises(ValueError, match="source must be auto or registry"):
        c.collect("nginx", source="disk")


def test_one_ref_per_distinct_digest():
    pods = [_pod("a", "p1", [{"name": "c", "image": "app:1"}], [{"name": "c", "imageID": f"docker.io/library/app@{D}"}]),
            _pod("b", "p2", [{"name": "c", "image": "app:1"}], [{"name": "c", "imageID": f"docker.io/library/app@{E}"}]),
            _pod("b", "p3", [{"name": "c", "image": "app:1"}], [{"name": "c", "imageID": f"docker.io/library/app@{D}"}])]
    (img,) = k8s.pod_images(pods)
    assert img["refs"] == [f"docker.io/library/app@{D}", f"docker.io/library/app@{E}"] and img["pinned"]


def test_errors_mark_the_inventory_partial(kubectl):
    kubectl.fail = {"nodes": b"kubectl output larger than 268435456 bytes"}
    inv = REGISTRY["k8s"]().collect("demo")
    assert inv.asset.meta["access"]["nodes"] == "error" and inv.partial and "nodes (error)" in inv.partial_reason


def test_per_namespace_loop_stops_at_first_error(kubectl):
    kubectl.deny = {"pods"}
    kubectl.fail = {"pods:default": b"Unable to connect to the server: i/o timeout"}
    inv = REGISTRY["k8s"]().collect("demo")
    keys = [kubectl.key(a) for a in kubectl.calls]
    assert keys.count("pods:default") == 1 and "pods:kube-system" not in keys and "pods:shop" not in keys
    assert inv.asset.meta["access"]["pods"] == "error"
    assert inv.asset.meta["access"]["denied_namespaces"] == ["default", "kube-system", "shop"]
    assert inv.partial


def test_pre_release_and_vendor_versions():
    assert k8s._semver("v1.30.0-rc.1") == "1.30.0-rc.1" and k8s._semver("v1.31.0-alpha.2+abc") == "1.31.0-alpha.2"
    assert k8s._semver("v1.29.3-eks-adc7111") == "1.29.3" and k8s._semver("v1.29.3+k3s1") == "1.29.3"
    c = k8s._k8s_component("Kubernetes", "v1.30.0-rc.1", None)
    assert c.purl == "pkg:golang/k8s.io/kubernetes@v1.30.0-rc.1" and c.cpe is None and c.meta["pre_release"]


def test_redaction():
    text = ('{"token":"abc123secret", "password": "pw1"} ya29.a0AfH6SMBxyz Authorization: Basic dXNlcjpwYXNz '
            'Bearer abcdefghijkl password=hunter2 eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig ' + "A" * 50)
    out = k8s.redact(text)
    for secret in ("abc123secret", "pw1", "ya29.a0", "dXNlcjpwYXNz", "abcdefghijkl", "hunter2", "eyJhbGci", "A" * 50):
        assert secret not in out, secret


def test_asset_id_includes_the_api_server():
    f = k8s.ClusterFacts(cluster="kubernetes", server="https://10.0.0.1:6443")
    g = k8s.ClusterFacts(cluster="kubernetes", server="https://10.0.0.2:6443")
    assert f.asset_id == "k8s:kubernetes@10.0.0.1:6443" != g.asset_id
    assert k8s.ClusterFacts(cluster="minikube").asset_id == "k8s:minikube"


def test_run_kills_the_process_group(tmp_path):
    import sys
    import time

    marker = tmp_path / "child-alive"
    child = tmp_path / "child.py"
    child.write_text(f"import time\ntime.sleep(3)\nopen({str(marker)!r}, 'w').write('x')\n")
    parent = tmp_path / "parent.py"
    parent.write_text(f"import subprocess, sys, time\nsubprocess.Popen([sys.executable, {str(child)!r}])\n"
                      "time.sleep(30)\n")
    t0 = time.monotonic()
    with pytest.raises(k8s.KubectlError, match="timed out"):
        k8s._run([sys.executable, str(parent)], 0.5)
    assert time.monotonic() - t0 < 10
    time.sleep(3.5)
    assert not marker.exists()                       # the exec-plugin-like grandchild died with kubectl


def test_kubeconfig_fifo_is_skipped(tmp_path):
    fifo = tmp_path / "config"
    os.mkfifo(fifo)
    assert k8s.list_kubeconfigs(kubeconfig=str(fifo))[0]["error"] == "not a regular file"


def test_request_timeout_is_at_least_one_second():
    assert "--request-timeout=1s" in k8s.Kubectl(timeout=0.2).argv("version")
    assert "--request-timeout=3s" in k8s.Kubectl(timeout=2.5).argv("version")
