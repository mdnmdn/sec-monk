"""Kubernetes cluster collector: control plane, node software and the images the cluster runs, through `kubectl`.

`kubectl` does the authentication (client certs, tokens, exec plugins such as `aws eks get-token`, OIDC), so the
collector only runs fixed, read-only commands with an argv list (no shell):

    kubectl [--kubeconfig=P] [--context=C] --request-timeout=Ns config view --minify -o json
    kubectl ... get --raw /version
    kubectl ... get nodes -o json
    kubectl ... get namespaces -o json
    kubectl ... get pods --all-namespaces -o json          (or --namespace=NS per selected namespace)

Secrets and configmaps are never read. Cluster answers are untrusted: output is size-capped and every field is
type-checked. Kubeconfig files are parsed (PyYAML, size-capped) only to list contexts; users, tokens, certificates
and exec settings are never returned. See _docs/tech/collectors/k8s.md.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import CAT_OS, CAT_RUNTIME, Asset, Component, Inventory
from .base import Collector, register

MAX_OUTPUT = 256 * 1024 * 1024       # one kubectl answer (pods of a large cluster)
MAX_STDERR = 64 * 1024
MAX_KUBECONFIG = 4 * 1024 * 1024
MAX_IMAGES = 2000                    # images kept in meta / returned by cluster_images
MAX_LIST = 50                        # pods / containers / namespaces listed per image
DEFAULT_TIMEOUT = 30                 # seconds per kubectl call (--request-timeout + local deadline)
K8S_PREFIX = "k8s://"
DEADLINE_FACTOR = 10                 # the whole probe may take this many per-call timeouts
_NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")       # DNS label
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


MAX_NS_CALLS = 200                   # per-namespace pod listings when the cluster-wide one is denied
_DENIED = re.compile(r"forbidden|unauthorized|cannot (list|get|watch)|permission denied|access denied",
                     re.IGNORECASE)
_SECRETISH = re.compile(
    r"""("(?:token|access_token|access-token|id-token|id_token|refresh-token|refresh_token|password|secret|"""
    r"""client-key-data|client-secret)"\s*:\s*"[^"]*")"""             # quoted JSON values
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]+"                       # JWT
    r"|ya29\.[A-Za-z0-9_.-]+"                                        # Google OAuth access token
    r"|(?i:bearer|basic)\s+[A-Za-z0-9+/=._~-]{8,}"                    # Authorization header values
    r"|(?i:token|password|passwd|pwd|secret|apikey|api-key|api_key)\s*[=:]\s*\S+"
    r"|[A-Za-z0-9+/]{40,}={0,2}")                                    # long base64


class KubectlError(RuntimeError):
    """kubectl missing, cluster unreachable, or a command failed (`denied`: refused by RBAC / authentication)."""

    def __init__(self, msg: str, *, denied: bool = False):
        super().__init__(msg)
        self.denied = denied


def redact(text: str) -> str:
    """kubectl / exec-plugin stderr without token-looking strings (quoted JSON secrets, JWTs, ya29. tokens,
    Bearer / Basic values, key=value secrets, long base64)."""
    return _SECRETISH.sub("<redacted>", text)


def _valid_name(v: Any) -> bool:
    """Context names are passed as `--context=<name>` (never a separate argument), so any printable name is safe."""
    return isinstance(v, str) and 0 < len(v) <= 253 and not any(ord(c) < 32 or ord(c) == 127 for c in v)


# --------------------------------------------------------------------------- running kubectl

def _kill(proc: subprocess.Popen) -> None:
    """Kill kubectl and what it started (exec credential plugins run in its process group)."""
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _run(argv: list[str], timeout: float, cap: int = MAX_OUTPUT) -> tuple[int, bytes, bytes]:
    """Run argv (no shell, own session) with a deadline and an output cap: (exit status, stdout, stderr). On the
    deadline or the cap the whole process group is killed. Replaced in tests."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
    except OSError as e:
        raise KubectlError(f"cannot run {argv[0]}: {e}") from e
    err = bytearray()

    def drain() -> None:
        try:
            for chunk in iter(lambda: proc.stderr.read(4096), b""):  # type: ignore[union-attr]
                if len(err) < MAX_STDERR:
                    err.extend(chunk)
        except (OSError, ValueError):
            pass

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    expired: list[bool] = []

    def expire() -> None:
        expired.append(True)
        _kill(proc)

    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    out = bytearray()
    too_big = False
    try:
        for chunk in iter(lambda: proc.stdout.read(1 << 20), b""):  # type: ignore[union-attr]
            out.extend(chunk)
            if len(out) > cap:
                too_big = True
                _kill(proc)
                break
        rc = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            _kill(proc)
            proc.wait()
        t.join(5)                        # the drain ends at EOF once the group is gone; only then close
        for f in (proc.stdout, proc.stderr):
            try:
                f.close()  # type: ignore[union-attr]
            except OSError:
                pass
    if too_big:
        raise KubectlError(f"kubectl output larger than {cap} bytes ({' '.join(argv[-4:])})")
    if expired:
        raise KubectlError(f"kubectl timed out after {timeout:g}s ({' '.join(argv[-4:])})")
    return rc, bytes(out), bytes(err)


@dataclass
class Kubectl:
    """Fixed kubectl invocations for one kubeconfig / context."""

    bin: str = "kubectl"
    kubeconfig: str | None = None
    context: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    deadline: float | None = None       # time.monotonic() after which no further call is started

    def argv(self, *args: str) -> list[str]:
        a = [self.bin]
        if self.kubeconfig:
            a.append(f"--kubeconfig={self.kubeconfig}")
        if self.context:
            a.append(f"--context={self.context}")
        a.append(f"--request-timeout={max(1, math.ceil(self.timeout))}s")
        return [*a, *args]

    def run(self, *args: str) -> bytes:
        argv = self.argv(*args)
        budget = self.timeout + 5
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise KubectlError(f"kubectl {' '.join(args)}: overall probe deadline reached")
            budget = min(budget, left)
        rc, out, err = _run(argv, budget)
        if rc != 0:
            msg = " | ".join(ln.strip() for ln in err.decode("utf-8", "replace").splitlines() if ln.strip())
            msg = redact(msg)[:600]
            raise KubectlError(f"kubectl {' '.join(args)} failed (rc={rc}): {msg or 'no stderr'}",
                               denied=bool(_DENIED.search(msg)))
        return out

    def json(self, *args: str) -> dict:
        out = self.run(*args)
        try:
            data = json.loads(out)
        except ValueError as e:
            raise KubectlError(f"kubectl {' '.join(args)}: invalid JSON ({e})") from e
        if isinstance(data, dict):
            return data
        raise KubectlError(f"kubectl {' '.join(args)}: expected a JSON object")


def make_kubectl(target: str | None, opts: dict[str, Any]) -> Kubectl:
    """Kubectl for `target` (`k8s://<context>`, `<context>`, or empty for the current context) and options
    `kubeconfig`, `context` (wins over the target), `kubectl` (binary; CLI only), `timeout`."""
    ctx = opts.get("context") or parse_target(target)
    if ctx is not None and not _valid_name(ctx):
        raise ValueError(f"invalid Kubernetes context name {str(ctx)[:80]!r}")
    kc = opts.get("kubeconfig") or None
    if kc is not None and (not isinstance(kc, str) or "\n" in kc or kc.startswith("-")):
        raise ValueError("invalid kubeconfig path")
    binary = opts.get("kubectl") or shutil.which("kubectl")
    if not binary:
        raise KubectlError("kubectl not found on PATH (install it, or pass -o kubectl=/path/to/kubectl)")
    try:
        timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError) as e:
        raise ValueError(f"timeout must be a number of seconds, got {opts.get('timeout')!r}") from e
    if not 0 < timeout <= 3600:
        raise ValueError("timeout must be between 0 and 3600 seconds")
    return Kubectl(bin=str(binary), kubeconfig=kc, context=ctx, timeout=timeout)


def parse_target(target: str | None) -> str | None:
    """`k8s://<context>` / `<context>` -> context name; None / "" / `k8s://` -> None (current context)."""
    t = (target or "").strip()
    t = t.removeprefix(K8S_PREFIX)
    return t.strip("/") or None


# --------------------------------------------------------------------------- cluster facts

@dataclass
class ClusterFacts:
    context: str | None = None
    cluster: str | None = None            # cluster name from the kubeconfig context
    server: str | None = None             # scheme://host[:port], no credentials
    version: dict = field(default_factory=dict)
    nodes: list[dict] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)
    pods: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    context_namespace: str | None = None
    access: dict = field(default_factory=dict)     # {version, nodes, namespaces, pods, denied_namespaces}

    @property
    def denied(self) -> list[str]:
        """What could not be read, refused or failed (empty: everything was read)."""
        a = self.access
        out = [f"{k} ({a[k]})" for k in ("version", "nodes", "namespaces") if a.get(k) in ("denied", "error")]
        if a.get("pods") in ("denied", "error"):
            out.append(f"pods ({a['pods']})")
        elif a.get("denied_namespaces"):
            out.append("pods in " + ", ".join(a["denied_namespaces"][:20]))
        return out

    @property
    def name(self) -> str:
        return self.cluster or (urlsplit(self.server).hostname if self.server else None) or self.context or "cluster"

    @property
    def asset_id(self) -> str:
        """`k8s:<cluster>@<server host[:port]>` (default names such as `kubernetes` or `minikube` repeat across
        clusters; the API server tells them apart), `k8s:<cluster>` when the server is unknown."""
        hostport = self.server.split("://", 1)[-1] if self.server else None
        return f"k8s:{self.name[:253]}" + (f"@{hostport}" if hostport else "")


def server_host(server: Any) -> str | None:
    """`scheme://host[:port]` of a kubeconfig server URL (userinfo, path and query dropped)."""
    if not isinstance(server, str) or "://" not in server:
        return None
    try:
        u = urlsplit(server)
        host = u.hostname or ""
        port = u.port
    except ValueError:
        return None
    if not host:
        return None
    host = f"[{host}]" if ":" in host else host
    return f"{u.scheme}://{host}" + (f":{port}" if port else "")


def _items(doc: dict) -> list[dict]:
    items = doc.get("items")
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list:
    return v if isinstance(v, list) else []


def _s(v: Any, cap: int = 256) -> str | None:
    return v[:cap] if isinstance(v, str) and v else None


def namespaces_opt(v: Any) -> list[str]:
    raw = v if isinstance(v, list) else str(v or "").split(",")
    out: list[str] = []
    for n in raw:
        n = str(n).strip()
        if not n:
            continue
        if not _NS_RE.match(n):
            raise ValueError(f"invalid namespace {n[:80]!r}")
        if n not in out:
            out.append(n)
    return out


def _slim_pod(p: dict) -> dict:
    """Only what pod_images reads (the rest of a pod object is dropped right after each kubectl answer)."""
    md, spec, st = _d(p.get("metadata")), _d(p.get("spec")), _d(p.get("status"))

    def cont(c: Any) -> dict | None:
        if not isinstance(c, dict):
            return None
        priv = _d(c.get("securityContext")).get("privileged") is True
        return {"name": _s(c.get("name"), 63), "image": _s(c.get("image"), 300), "privileged": priv}

    def stat_(c: Any) -> dict | None:
        return {"name": _s(c.get("name"), 63), "imageID": _s(c.get("imageID"), 400)} if isinstance(c, dict) else None

    return {
        "namespace": _s(md.get("namespace"), 63) or "", "name": _s(md.get("name"), 253) or "",
        "host_path": any(isinstance(v, dict) and "hostPath" in v for v in _l(spec.get("volumes"))),
        "host_network": any(spec.get(k) is True for k in ("hostNetwork", "hostPID", "hostIPC")),
        **{k: [x for c in _l(spec.get(k)) if (x := cont(c))]
           for k in ("initContainers", "containers", "ephemeralContainers")},
        "statuses": [x for k in ("containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses")
                     for c in _l(st.get(k)) if (x := stat_(c))]}


def _slim_node(n: dict) -> dict:
    info = _d(_d(n.get("status")).get("nodeInfo"))
    keys = ("kubeletVersion", "kubeProxyVersion", "containerRuntimeVersion", "osImage", "kernelVersion",
            "operatingSystem", "architecture")
    return {"metadata": {"name": _s(_d(n.get("metadata")).get("name"), 253)},
            "spec": {"providerID": _s(_d(n.get("spec")).get("providerID"), 300)},
            "status": {"nodeInfo": {k: _s(info.get(k), 200) for k in keys}}}


def _pods(kc: Kubectl, *args: str) -> list[dict]:
    doc = kc.json("get", "pods", *args, "-o", "json")
    out = [_slim_pod(p) for p in _items(doc)]
    doc.clear()
    return out


def _try(f: ClusterFacts, what: str, call: Callable[[], Any]) -> Any:
    """Run one read; RBAC / auth refusals become `access[what] = "denied"` + a warning, other failures a warning
    (`"error"`). Returns None when it failed."""
    try:
        res = call()
        f.access[what] = "ok"
        return res
    except KubectlError as e:
        f.access[what] = "denied" if e.denied else "error"
        f.warnings.append(f"{what}: {'access denied' if e.denied else 'failed'}: {e}")
        return None


def probe_cluster(kc: Kubectl, *, namespaces: list[str] | None = None, pods: bool = True) -> ClusterFacts:
    """Everything the collector and the discovery need, reading what the credentials allow: a refused read is
    recorded in `access` and a warning, and the rest goes on. Cluster-wide pods refused -> pods per namespace (the
    listed namespaces, else the context's namespace, else `default`). Raises KubectlError when the cluster cannot be
    reached (first call fails without an RBAC refusal) or when nothing at all could be read."""
    f = ClusterFacts(context=kc.context)
    if kc.deadline is None:
        kc.deadline = time.monotonic() + kc.timeout * DEADLINE_FACTOR
    try:
        view = kc.json("config", "view", "--minify", "-o", "json")
        ctxs = _l(view.get("contexts"))
        c0 = _d(ctxs[0]) if ctxs else {}
        f.context = f.context or _s(view.get("current-context"))
        f.cluster = _s(_d(c0.get("context")).get("cluster"))
        f.context_namespace = _s(_d(c0.get("context")).get("namespace"), 63)
        cls = _l(view.get("clusters"))
        f.server = server_host(_d(_d(cls[0]).get("cluster")).get("server")) if cls else None
    except KubectlError as e:
        f.warnings.append(f"kubeconfig: {e}")
    try:
        raw = kc.run("get", "--raw", "/version")
        ver = json.loads(raw)
        f.version = {k: _s(v, 120) for k, v in _d(ver).items() if isinstance(v, str)}
        f.access["version"] = "ok"
    except ValueError as e:
        f.access["version"] = "error"
        f.warnings.append(f"version: invalid JSON ({e})")
    except KubectlError as e:
        if not e.denied:
            raise KubectlError(f"cluster {f.name} not reachable: {e}") from e
        f.access["version"] = "denied"
        f.warnings.append(f"version: access denied: {e}")
    f.nodes = _try(f, "nodes", lambda: [_slim_node(n) for n in _items(kc.json("get", "nodes", "-o", "json"))]) or []
    f.namespaces = _try(f, "namespaces", lambda: [
        n for i in _items(kc.json("get", "namespaces", "-o", "json"))
        if (n := _s(_d(i.get("metadata")).get("name"), 63))]) or []
    if pods:
        _probe_pods(kc, f, namespaces)
    if not f.version and not f.nodes and f.access.get("namespaces") != "ok" and not f.pods:
        raise KubectlError(f"no read access to cluster {f.name}: " + "; ".join(f.warnings[-4:]), denied=True)
    return f


def _probe_pods(kc: Kubectl, f: ClusterFacts, namespaces: list[str] | None) -> None:
    allowed: list[str] = []
    denied: list[str] = []
    if not namespaces:
        try:
            f.pods = _pods(kc, "--all-namespaces")
            f.access["pods"] = "all"
            return
        except KubectlError as e:
            if not e.denied:
                f.access["pods"] = "error"
                f.warnings.append(f"pods: failed: {e}")
                return
            f.warnings.append("pods: cluster-wide listing denied; trying namespace by namespace")
        namespaces = f.namespaces or [f.context_namespace or "default"]
    if len(namespaces) > MAX_NS_CALLS:
        f.warnings.append(f"pods: only the first {MAX_NS_CALLS} of {len(namespaces)} namespaces are listed")
        namespaces = namespaces[:MAX_NS_CALLS]
    failed: str | None = None
    for i, ns in enumerate(namespaces):
        try:
            f.pods += _pods(kc, f"--namespace={ns}")
            allowed.append(ns)
        except KubectlError as e:
            if not e.denied:             # timeout, deadline, unreachable: the next namespaces would fail too
                failed = f"pods in {ns}: failed: {e}"
                denied += namespaces[i:]
                break
            denied.append(ns)
    if failed:
        f.warnings.append(failed + f" (stopped; {len(namespaces) - len(allowed)} namespace(s) not read)")
    if allowed:
        f.access["pods"] = f"namespaces: {', '.join(allowed[:50])}"
    else:
        f.access["pods"] = "error" if failed else "denied"
    if denied:
        f.access["denied_namespaces"] = denied[:500]
        if not failed or len(denied) > 1:
            f.warnings.append(f"pods: not read in {len(denied)} namespace(s): {', '.join(denied[:20])}")


# --------------------------------------------------------------------------- components

_PRE_RE = re.compile(r"^-(alpha|beta|rc)\.?(\d+)")


def _semver(git_version: str | None) -> str | None:
    """Upstream version of a build: `X.Y.Z`, or `X.Y.Z-rc.N` / `-alpha.N` / `-beta.N` for pre-releases (never
    folded into the release they precede); vendor suffixes (`-eks-…`, `+k3s1`) are dropped."""
    m = _VERSION_RE.match(git_version or "")
    if not m:
        return None
    pre = _PRE_RE.match((git_version or "")[m.end():])
    return ".".join(m.groups()) + (f"-{pre.group(1)}.{pre.group(2)}" if pre else "")


def distro_hints(f: ClusterFacts) -> list[str]:
    gv = (f.version.get("gitVersion") or "").lower()
    hints: list[str] = []
    for key, needle in (("eks", "-eks-"), ("gke", "-gke."), ("k3s", "+k3s"), ("rke2", "+rke2"),
                        ("openshift", "openshift")):
        if needle in gv:
            hints.append(key)
    for n in f.nodes:
        pid = str(_d(n.get("spec")).get("providerID") or "")
        name = str(_d(n.get("metadata")).get("name") or "")
        for key, needle in (("eks", "aws://"), ("gke", "gce://"), ("aks", "azure://"), ("kind", "kind://")):
            if pid.startswith(needle) and key not in hints:
                hints.append(key)
        if name == "orbstack" and "orbstack" not in hints:
            hints.append("orbstack")
        if name.endswith("-control-plane") and "kind" not in hints and not pid:
            hints.append("kind?")
    return hints


def _k8s_component(name: str, git_version: str, subpath: str | None, **meta: Any) -> Component | None:
    ver = _semver(git_version)
    if not ver:
        return None
    sub = f"#{subpath}" if subpath else ""
    pre = "-" in ver
    return Component(
        name=name, version=ver, category=CAT_RUNTIME, vendor="kubernetes",
        purl=f"pkg:golang/k8s.io/kubernetes@v{ver}{sub}",
        cpe=None if pre else f"cpe:2.3:a:kubernetes:kubernetes:{ver}:*:*:*:*:*:*:*",
        meta={"product": "kubernetes", "git_version": git_version[:80],
              **({"pre_release": True} if pre else {}),
              **({"vendor_build": True} if git_version.lstrip("v") != ver else {}), **meta})


_RUNTIMES = {
    "containerd": ("containerd", "linuxfoundation", "containerd", "github.com/containerd/containerd"),
    "cri-o": ("cri-o", "kubernetes", "cri-o", "github.com/cri-o/cri-o"),
    "docker": ("docker", "docker", "docker", None),
}

# osImage -> (os-release ID, display name) for the OS images the engine knows how to match
_OS_IMAGES = ((re.compile(r"^Ubuntu (\d+\.\d+)"), "ubuntu", "Ubuntu"),
              (re.compile(r"^Debian GNU/Linux (\d+)"), "debian", "Debian GNU/Linux"),
              (re.compile(r"^Amazon Linux (\d+)"), "amzn", "Amazon Linux"),
              (re.compile(r"^Red Hat Enterprise Linux.*?(\d+(?:\.\d+)?)"), "rhel", "Red Hat Enterprise Linux"),
              (re.compile(r"^Rocky Linux (\d+(?:\.\d+)?)"), "rocky", "Rocky Linux"),
              (re.compile(r"^AlmaLinux (\d+(?:\.\d+)?)"), "almalinux", "AlmaLinux"),
              (re.compile(r"^Alpine Linux v?(\d+\.\d+)"), "alpine", "Alpine Linux"),
              (re.compile(r"^Bottlerocket OS (\d+\.\d+\.\d+)"), "bottlerocket", "Bottlerocket OS"),
              (re.compile(r"^Flatcar Container Linux by Kinvolk (\d+\.\d+\.\d+)"), "flatcar", "Flatcar Container Linux"))


def node_components(nodes: list[dict]) -> list[Component]:
    """kubelet / kube-proxy / container runtime per distinct version, node OS per distinct image."""
    groups: dict[tuple[str, str], list[str]] = {}
    kernels: dict[str, set[str]] = {}
    for n in nodes:
        info = _d(_d(n.get("status")).get("nodeInfo"))
        node = _s(_d(n.get("metadata")).get("name"), 253) or "?"
        for key in ("kubeletVersion", "kubeProxyVersion", "containerRuntimeVersion", "osImage"):
            if v := _s(info.get(key), 200):
                groups.setdefault((key, v), []).append(node)
        if (img := _s(info.get("osImage"), 200)) and (k := _s(info.get("kernelVersion"), 120)):
            kernels.setdefault(img, set()).add(k)
    out: list[Component] = []
    for (key, v), names in groups.items():
        meta = {"nodes": len(names), "node_names": sorted(names)[:MAX_LIST]}
        c: Component | None = None
        if key == "kubeletVersion":
            c = _k8s_component("kubelet", v, "cmd/kubelet", **meta)
        elif key == "kubeProxyVersion":
            c = _k8s_component("kube-proxy", v, "cmd/kube-proxy", **meta)
        elif key == "containerRuntimeVersion":
            c = _runtime_component(v, meta)
        else:
            c = _os_component(v, sorted(kernels.get(v, ()))[:MAX_LIST], meta)
        if c:
            out.append(c)
    return out


def _runtime_component(v: str, meta: dict) -> Component | None:
    kind, _, ver = v.partition("://")
    spec = _RUNTIMES.get(kind)
    m = _VERSION_RE.match(ver)
    if not m:
        return None
    sem = ".".join(m.groups())
    if spec is None:
        return Component(name=kind[:60], version=sem, category=CAT_RUNTIME, meta={"runtime": v, **meta})
    name, vendor, product, module = spec
    return Component(name=name, version=sem, category=CAT_RUNTIME, vendor=vendor,
                     purl=f"pkg:golang/{module}@v{sem}" if module else None,
                     cpe=f"cpe:2.3:a:{vendor}:{product}:{sem}:*:*:*:*:*:*:*",
                     meta={"product": product, "runtime": v, **meta})


def _os_component(image: str, kernels: list[str], meta: dict) -> Component:
    for rx, did, name in _OS_IMAGES:
        if m := rx.match(image):
            ver = m.group(1)
            return Component(name=name, version=ver, category=CAT_OS, vendor=did, purl=f"pkg:generic/{did}@{ver}",
                             meta={"pretty_name": image, "id": did, "kernel_versions": kernels, **meta})
    return Component(name=image, version=None, category=CAT_OS,
                     meta={"pretty_name": image, "kernel_versions": kernels, "unrecognised": True, **meta})


# --------------------------------------------------------------------------- images

def pinned_ref(image: str | None, image_id: str | None) -> tuple[str | None, bool]:
    """(ref to pull, pinned?). A `repo@sha256:<digest>` imageID (`docker-pullable://` stripped) that is a valid
    registry reference pins the ref; a bare `sha256:` imageID (an image config id, not pullable) or none keeps the
    spec image (tag). Anything that is not a valid registry reference gives (None, False)."""
    from .docker_image import valid_image_ref

    iid = (image_id or "").split("://", 1)[-1]
    if re.fullmatch(r"[^@\s]{1,250}@sha256:[0-9a-f]{64}", iid) and valid_image_ref(iid):
        return iid, True
    return (image if valid_image_ref(image) else None), False


def pod_images(pods: list[dict], warnings: list[str] | None = None) -> list[dict]:
    """One entry per spec image used by the (slimmed, see `_slim_pod`) pods: {image, image_ids, ref, refs, pinned,
    private, invalid, namespaces, pods, containers, init, privileged, host_path, host_network}. `refs` holds one
    pinned ref per distinct digest the kubelet reported (a tag running as two builds is scanned twice), else the
    tag; `invalid` entries (paths, lists, garbage from a hostile spec) have no ref; `private` refs point at
    localhost / private / link-local registries."""
    from .docker_image import registry_is_private

    by: dict[str, dict] = {}
    dropped = 0
    for p in pods:
        if "statuses" not in p:                 # a full pod object (callers outside probe_cluster)
            p = _slim_pod(p)
        ns, pod = p["namespace"], p["name"]
        ids = {s_["name"]: s_["imageID"] for s_ in p["statuses"] if s_["name"]}
        for kind in ("initContainers", "containers", "ephemeralContainers"):
            for c in p[kind]:
                image = c["image"]
                if not image:
                    continue
                e = by.get(image)
                if e is None:
                    if len(by) >= MAX_IMAGES:
                        dropped += 1
                        continue
                    e = by[image] = {"image": image, "image_ids": [], "namespaces": [], "pods": [], "containers": [],
                                     "init": False, "privileged": False, "host_path": False, "host_network": False}
                iid = ids.get(c["name"])
                if iid and iid not in e["image_ids"] and len(e["image_ids"]) < 10:
                    e["image_ids"].append(iid)
                for k, v in (("namespaces", ns), ("pods", f"{ns}/{pod}"), ("containers", c["name"])):
                    if v and v not in e[k] and len(e[k]) < MAX_LIST:
                        e[k].append(v)
                e["init"] = e["init"] or kind == "initContainers"
                e["privileged"] = e["privileged"] or c["privileged"]
                e["host_path"] = e["host_path"] or p["host_path"]
                e["host_network"] = e["host_network"] or p["host_network"]
    if dropped and warnings is not None:
        warnings.append(f"more than {MAX_IMAGES} distinct images: {dropped} container(s) not listed")
    out = []
    invalid = []
    for e in by.values():
        refs: list[str] = []
        for iid in e["image_ids"]:
            ref, ok = pinned_ref(e["image"], iid)
            if ok and ref and ref not in refs:
                refs.append(ref)
        pinned = bool(refs)
        if not refs:
            tag_ref = pinned_ref(e["image"], None)[0]
            refs = [tag_ref] if tag_ref else []
        if not refs:
            invalid.append(e["image"])
        out.append({**e, "ref": refs[0] if refs else None, "refs": refs, "pinned": pinned, "invalid": not refs,
                    "private": any(registry_is_private(r) for r in refs)})
    if invalid and warnings is not None:
        warnings.append(f"{len(invalid)} image string(s) are not registry references and are not scanned: "
                        + ", ".join(repr(i[:80]) for i in invalid[:5]))
    return out


def node_platforms(nodes: list[dict]) -> list[str]:
    out: list[str] = []
    for n in nodes:
        info = _d(_d(n.get("status")).get("nodeInfo"))
        os_, arch = _s(info.get("operatingSystem"), 20), _s(info.get("architecture"), 20)
        if os_ and arch and f"{os_}/{arch}" not in out:
            out.append(f"{os_}/{arch}")
    return out


def cluster_images(target: str | None = None, **opts: Any) -> list[dict]:
    """Images the cluster runs (see `pod_images`), one entry per spec image, `ref` pinned to a digest when the
    kubelet reported one. Options as for the collector (kubeconfig, context, namespace, kubectl, timeout)."""
    kc = make_kubectl(target, opts)
    f = probe_cluster(kc, namespaces=namespaces_opt(opts.get("namespace")))
    return pod_images(f.pods)


# --------------------------------------------------------------------------- kubeconfig listing

def _load_kubeconfig(path: Path) -> dict:
    import yaml

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):        # a FIFO or device would block or never end
            raise ValueError("not a regular file")
        if st.st_size > MAX_KUBECONFIG:
            raise ValueError(f"larger than {MAX_KUBECONFIG} bytes")
        data = yaml.safe_load(fh.read(MAX_KUBECONFIG + 1))
    if isinstance(data, dict):
        return data
    raise ValueError("not a kubeconfig (no mapping)")


def _contexts_of(data: dict, current: str | None = None) -> list[dict]:
    """Context summaries: {name, cluster, server (scheme://host[:port]), namespace, current}; no user data."""
    clusters = {c.get("name"): _d(c.get("cluster")) for c in _l(data.get("clusters")) if isinstance(c, dict)}
    cur = current if current is not None else data.get("current-context")
    out = []
    for c in _l(data.get("contexts")):
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        ctx = _d(c.get("context"))
        cl = ctx.get("cluster") if isinstance(ctx.get("cluster"), str) else None
        out.append({"name": c["name"][:253], "cluster": cl[:253] if cl else None,
                    "server": server_host(clusters.get(cl, {}).get("server")),
                    "namespace": _s(ctx.get("namespace"), 63), "current": c["name"] == cur})
    return out


def default_kubeconfigs() -> list[Path]:
    """The files kubectl reads: $KUBECONFIG (os.pathsep list) or ~/.kube/config."""
    env = os.environ.get("KUBECONFIG")
    if env:
        return [Path(p).expanduser() for p in env.split(os.pathsep) if p]
    return [Path.home() / ".kube" / "config"]


def list_k8s_contexts(**opts: Any) -> list[dict]:
    """Contexts of the kubeconfig kubectl would use (opts['kubeconfig'], else $KUBECONFIG merged in order, else
    ~/.kube/config): [{name, cluster, server, namespace, current}]. First definition of a name wins, as in kubectl."""
    paths = [Path(opts["kubeconfig"]).expanduser()] if opts.get("kubeconfig") else default_kubeconfigs()
    merged: dict[str, list] = {"contexts": [], "clusters": []}
    current = None
    seen: dict[str, set] = {"contexts": set(), "clusters": set()}
    for p in paths:
        try:
            data = _load_kubeconfig(p)
        except Exception:  # noqa: BLE001, S112 - missing / unreadable / not YAML: kubectl skips it too
            continue
        current = current or (data.get("current-context") if isinstance(data.get("current-context"), str) else None)
        for key in ("contexts", "clusters"):
            for e in _l(data.get(key)):
                if isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"] not in seen[key]:
                    seen[key].add(e["name"])
                    merged[key].append(e)
    return _contexts_of(merged, current or "")


_KUBE_SKIP = {"cache", "http-cache", "kubens", "kubectx"}


def _looks_like_kubeconfig(p: Path) -> bool:
    n = p.name.lower()
    return n == "config" or "config" in n or n.endswith((".yaml", ".yml", ".conf", ".kubeconfig"))


def list_kubeconfigs(**opts: Any) -> list[dict]:
    """Kubeconfig files a picker can offer: $KUBECONFIG entries, ~/.kube/config and other kubeconfig-looking
    files in ~/.kube (one level of sub-directories; cache dirs skipped): [{path, contexts: [...], error}].
    Files that are not kubeconfigs are left out unless they were named by $KUBECONFIG / opts['kubeconfig']."""
    named = [Path(opts["kubeconfig"]).expanduser()] if opts.get("kubeconfig") else []
    named += default_kubeconfigs()
    kube = Path.home() / ".kube"
    found: list[Path] = []
    try:
        for p in sorted(kube.iterdir()) if kube.is_dir() else []:
            if p.is_dir() and p.name not in _KUBE_SKIP and not p.name.startswith("."):
                found += [q for q in sorted(p.iterdir())[:200] if q.is_file() and _looks_like_kubeconfig(q)]
            elif p.is_file() and _looks_like_kubeconfig(p):
                found.append(p)
    except OSError:
        pass
    out: list[dict] = []
    done: set[str] = set()
    for p in [*named, *found]:
        key = str(p)
        if key in done:
            continue
        done.add(key)
        explicit = p in named
        try:
            data = _load_kubeconfig(p)
            if not isinstance(data.get("contexts"), list) and data.get("kind") != "Config":
                raise ValueError("not a kubeconfig (no contexts)")
            out.append({"path": key, "contexts": _contexts_of(data), "error": None})
        except FileNotFoundError:
            if explicit:
                out.append({"path": key, "contexts": [], "error": "not found"})
        except Exception as e:  # noqa: BLE001 - yaml / permission / size
            if explicit:
                out.append({"path": key, "contexts": [], "error": str(e).splitlines()[0][:200] if str(e) else
                            type(e).__name__})
    return out


# --------------------------------------------------------------------------- collector

@register
class K8sCollector(Collector):
    name = "k8s"
    description = "Kubernetes cluster via kubectl: control plane, kubelet/runtime/OS per node, images in use"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        kc = make_kubectl(target, opts)
        f = probe_cluster(kc, namespaces=namespaces_opt(opts.get("namespace")))
        return cluster_inventory(f, self.name)


def cluster_inventory(f: ClusterFacts, collector: str = "k8s") -> Inventory:
    warnings = list(f.warnings)
    comps: list[Component] = []
    gv = f.version.get("gitVersion")
    if gv and (c := _k8s_component("Kubernetes", gv, None, role="control-plane",
                                   platform=f.version.get("platform"))):
        comps.append(c)
    elif gv:
        warnings.append(f"unrecognised Kubernetes version {gv!r}")
    comps += node_components(f.nodes)
    images = pod_images(f.pods, warnings)
    unpinned = [i["image"] for i in images if not i["pinned"] and not i["invalid"]]
    if unpinned:
        warnings.append(f"{len(unpinned)} image(s) without a digest from the kubelet, kept by tag: "
                        + ", ".join(unpinned[:10]) + (" ..." if len(unpinned) > 10 else ""))
    hints = distro_hints(f)
    name = f.name[:253]
    asset = Asset(
        id=f.asset_id, type="cluster", name=name, os_name="Kubernetes", os_version=_semver(gv),
        platform=", ".join(node_platforms(f.nodes)) or None,
        meta={"context": f.context, "server": f.server, "git_version": gv, "distro": hints,
              "node_count": len(f.nodes), "namespaces": f.namespaces[:500], "pod_count": len(f.pods),
              "image_count": len(images), "images": images[:MAX_IMAGES]})
    asset.meta["access"] = f.access
    inv = Inventory(asset=asset, collector=collector, components=comps, warnings=warnings)
    if f.denied:
        inv.mark_partial("partial access: not read: " + "; ".join(f.denied))
    return inv
