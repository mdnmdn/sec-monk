---
title: Kubernetes collector (k8s)
summary: How the k8s collector drives kubectl (fixed argv, caps, timeouts), maps version/nodes/pods to components and the image list, handles RBAC refusals (partial access), and lists kubeconfigs and contexts without credentials.
read_when: you change the kubectl calls, the cluster components or image list, the partial-access rules or the kubeconfig listing
type: tech
context: tech
status: implemented
tags: [collector, kubernetes, k8s, kubectl, rbac, images]
updated: 2026-11-11
verified: 2026-11-11
sample: synthetic
fixtures: tests/fixtures/collectors/k8s/
code: [src/secmonk/collectors/k8s.py]
related: [features/inventory-k8s.md, tech/discover.md, tech/collectors/docker-image.md, tech/engine/classification.md]
---

# Kubernetes collector (k8s)

## Summary

`collectors/k8s.py` (`K8sCollector`, name `k8s`) inventories a cluster through the system `kubectl`, which owns
authentication. Target: `k8s://<context>`, `<context>`, or empty for the current context; options `kubeconfig`,
`context` (wins over the target), `namespace` (comma list of DNS labels; default all), `timeout` (seconds per call,
default 30), `kubectl` (binary path; **command line only**: the web interface must refuse it, like `ssh_bin`).
Verified only against synthetic kubectl output (`tests/collectors/test_k8s.py`).

## Where the data lives

`Kubectl.argv`: `kubectl [--kubeconfig=P] [--context=C] --request-timeout=Ns <args>` (N at least 1). Values are
always passed in the `--flag=value` form, so any context name is safe (only control characters and names over 253
characters are refused). Calls, in order (`probe_cluster`, under an overall deadline of 10 x `timeout`):

| Call | Used for | Refused (RBAC) |
|---|---|---|
| `config view --minify -o json` | context, its cluster name and namespace, server (`server_host`: scheme, host, port) | warning only (local) |
| `get --raw /version` | control plane `gitVersion` | `access.version = denied`, no control-plane component; any other failure = cluster unreachable, raise |
| `get nodes -o json` | `status.nodeInfo`: kubelet, kube-proxy, container runtime, OS image, kernel, os/arch; `spec.providerID` | no node components |
| `get namespaces -o json` | namespace list (meta; per-namespace pod fallback) | `access.namespaces = denied` |
| `get pods --all-namespaces -o json` | images in use | per namespace: listed namespaces, else the context namespace, else `default` (at most 200 calls) |

`_run` executes argv without a shell in its own session (stdin closed), stdout capped at 256 MiB, stderr at
64 KiB; at the deadline (timeout + 5 s, or what is left of the overall deadline) or the cap the whole process group
is killed (exec credential plugins included), then waited for, and stderr is closed only after its reader ended.
`KubectlError.denied` is set when stderr says forbidden / unauthorized / cannot list. Stderr goes through `redact`
(quoted JSON secrets, JWTs, `ya29.` tokens, Bearer / Basic values, `password=`-style pairs, long base64) before it
reaches a message. A refused read is `access = denied`, any other failure (timeout, cap, invalid JSON) `error`: both
make the inventory **partial**. The per-namespace pod loop stops at the first non-refusal error (the remaining
namespaces would time out too). When nothing at all is readable, `probe_cluster` raises "no read access to cluster
…" with the last refusals. Each answer is reduced to the fields used right away (`_slim_pod`, `_slim_node`).

## Data format

Components (`cluster_inventory`, category `runtime` unless noted):

- `Kubernetes` (control plane): version = upstream `X.Y.Z` of `gitVersion`; purl `pkg:golang/k8s.io/kubernetes@vX.Y.Z`
  (OSV `Go`); CPE `cpe:2.3:a:kubernetes:kubernetes:X.Y.Z`; `meta.vendor_build` when the build carries a distribution
  suffix (`-eks-…`, `+k3s1`; recorded only, the engine does not use it yet). Pre-releases keep their suffix
  (`1.30.0-rc.1`, purl `v1.30.0-rc.1`) and get no CPE (`meta.pre_release`).
- `kubelet`, `kube-proxy`: one per distinct version, same purl with subpath `#cmd/kubelet` / `#cmd/kube-proxy` (keys
  stay distinct), `meta.nodes` / `node_names`.
- Container runtime: `containerd` (`pkg:golang/github.com/containerd/containerd`, CPE `linuxfoundation:containerd`),
  `cri-o` (`pkg:golang/github.com/cri-o/cri-o`, CPE `kubernetes:cri-o`), `docker` (CPE `docker:docker`); others by name.
- Node OS (category `os`): recognised `osImage` prefixes (Ubuntu, Debian, Amazon Linux, RHEL, Rocky, Alma, Alpine,
  Bottlerocket, Flatcar) -> name + version + `pkg:generic/<id>@<version>` like the rootfs OS component; others by
  name with `meta.unrecognised`. Kernel versions go to `meta.kernel_versions` (no kernel component).

Asset `k8s:<cluster name>@<server host[:port]>` (cluster name from the kubeconfig context, else the server host,
else the context; the API server part tells apart the many clusters called `kubernetes`, `default`, `minikube` or
`docker-desktop`; `k8s:<cluster name>` when the server is unknown), type
`cluster`, `os_name` Kubernetes, `os_version` control-plane version, `platform` the node platforms. Meta: `context`,
`server`, `git_version`, `distro` (hints from `gitVersion` / `providerID` / node names: eks, gke, aks, k3s, rke2,
openshift, kind, orbstack), `node_count`, `namespaces`, `pod_count`, `image_count`, `images`, `access`.

`pod_images` (also `cluster_images(target, **opts)`): one entry per spec image: `image`, `image_ids` (kubelet
`imageID`s), `refs` (one `repo@sha256:<64 hex>` per distinct digest from `imageID`, `docker-pullable://` stripped, so
a tag running as two builds is scanned twice; else the tag; a bare `sha256:` id is an image config id, not pullable),
`ref` (the first), `pinned`, `invalid` (the string is not a registry reference: no ref, warning), `private` (registry
is localhost or a loopback / private / link-local IP literal), `namespaces`, `pods`, `containers`, `init`,
`privileged`, `host_path`, `host_network` (hostNetwork/PID/IPC). Pod specs are untrusted: every ref must pass
`docker_image.valid_image_ref` (reference grammar + `parse_reference`; no leading `/ . ~ -`, no `,`, whitespace or
control characters). At most 2000 images (a warning says how many containers were left out), 50 names per list.

Kubeconfig listing (PyYAML `safe_load`, files capped at 4 MiB): `list_k8s_contexts(**opts)` merges `$KUBECONFIG`
(first definition of a name wins, as kubectl) or reads `opts['kubeconfig']` / `~/.kube/config`;
`list_kubeconfigs(**opts)` adds kubeconfig-looking files in `~/.kube` and one level below (`config`, `*config*`,
`*.yaml`, `*.yml`, `*.conf`, `*.kubeconfig`; `cache`, `http-cache` skipped). Entries: `{name, cluster, server,
namespace, current}`; files named explicitly but unreadable carry `error`. Users, tokens, certificates and exec
settings are never returned.

## Limitations / gotchas

- Managed control planes report a vendor build; upstream-version matching may flag CVEs the vendor already fixed.
- Images of pods that were never scheduled or never started have no `imageID`: they are scanned by tag.
- Multi-architecture clusters: discovery passes `platform=` only when every node has the same platform.
- Pods of more than 200 namespaces are not listed when only per-namespace access exists.
- Private registries: the docker-image collector pulls anonymously unless registry credentials are given.
