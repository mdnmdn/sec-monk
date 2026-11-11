---
title: Inventory of Kubernetes clusters
summary: Kubernetes cluster inventory via kubectl - control plane, kubelet/runtime/node OS per version, images pods run (digest-pinned for scanning), partial RBAC access, kubeconfig picking, criteria.
read_when: you change what sec-monk reads from a Kubernetes cluster, how a cluster or its images are selected and scanned, or how missing RBAC permissions are handled
type: feature
context: features
status: implemented
tags: [kubernetes, k8s, cluster, containers, images, inventory]
updated: 2026-11-11
verified: 2026-11-11
sample: synthetic
code: [src/secmonk/collectors/k8s.py, src/secmonk/discover.py, src/secmonk/collectors/docker_image.py]
related: [tech/collectors/k8s.md, features/inventory-docker.md, tech/discover.md, features/README.md]
---

# Inventory of Kubernetes clusters

## What the user gets

One asset per cluster (`k8s:<cluster name>@<API server host:port>`, type `cluster`) with the Kubernetes control-plane version, the kubelet,
kube-proxy and container runtime (containerd, CRI-O, Docker) versions of its nodes, and the node OS images, all as
components the engine matches against the mirror (OSV `Go` packages and NVD CPEs). The asset also lists every image
the pods run, with the namespaces, pods and risk flags (privileged, hostPath, host network) that use it; host auto
mode turns that list into image scans pinned by digest. sec-monk talks to the cluster only through the local
`kubectl`, so every authentication method kubectl supports works (certificates, tokens, `aws eks get-token`,
`gke-gcloud-auth-plugin`, OIDC).

## Usage

```bash
secmonk scan k8s                                   # current context of the local kubeconfig ($KUBECONFIG or ~/.kube/config)
secmonk scan k8s k8s://kind-dev                    # another context (also: plain `kind-dev`)
secmonk scan k8s k8s://prod -o kubeconfig=~/.kube/prod.yaml -o namespace=shop,payments -o timeout=60
secmonk scan k8s -o kubectl=/opt/bin/kubectl       # kubectl not on PATH (command line only)
secmonk scan-host k8s://prod                       # host auto mode: cluster + its images as candidates
secmonk scan docker-image 'nginx@sha256:…,registry.example/app@sha256:…'    # a comma list of images is one item
```

## Behaviour & rules

- Read-only and fixed: `config view --minify`, `get --raw /version`, `get nodes`, `get namespaces`, `get pods`
  (all namespaces, or `--namespace` per selected namespace). Secrets and config maps are never read. Output is
  size-capped (256 MiB per call) and type-checked; each call has a timeout (`-o timeout=`, default 30 s).
- **Partial access** (RBAC): every read that the cluster refuses is skipped, recorded in `meta.access`
  (`version`, `nodes`, `namespaces`: `ok` / `denied` / `error`; `pods`: `all`, `namespaces: a, b` or `denied`;
  `denied_namespaces`) and named in a warning; the inventory is then **partial** (also after a timeout or an
  oversized answer), so components seen earlier are not
  marked removed. Cluster-wide pods refused -> pods are listed namespace by namespace (the namespaces it may list,
  else the context's namespace, else `default`). Only when nothing at all is readable does the scan fail ("no read
  access"). An unreachable API server fails at once.
- Images: `status.imageID` of the kubelet gives `repo@sha256:<digest>` refs (`docker-pullable://` stripped), one
  per distinct digest; images without one (a bare `sha256:` id, or a container that never started) keep their tag
  and are named in a warning. Image strings from pod specs are untrusted: anything that is not a registry reference
  (`/etc/hosts`, `./x.tar`, lists, whitespace) is never scanned, and the image scans run with `source=registry` so
  the docker-image collector never reads a target as a local path. Images from localhost or private-IP registries
  are offered separately and never ticked by default. Scanned with the docker-image collector, digest refs give digest-based asset ids, so the same image used
  under several tags is one asset.
- Kubeconfig picking: the default is what kubectl uses (`$KUBECONFIG` list, else `~/.kube/config`, and its current
  context); `-o kubeconfig=` / `-o context=` (or `k8s://<context>`) choose explicitly. Listings for a picker show
  context, cluster, server (`scheme://host:port`) and namespace only: no users, tokens, certificates or exec settings.
- Distribution builds (`v1.29.3-eks-…`, `+k3s1`) are matched on their upstream version (`meta.vendor_build`): vendors
  backport fixes, so findings on these need a check of the vendor's bulletin.

## Acceptance criteria

- The synthetic EKS-shaped fixture gives `k8s:demo-cluster@k8s.example.test:6443` with Kubernetes 1.29.3, kubelet 1.29.0 (2 nodes) and
  1.28.5 (1 node), containerd 1.7.11 and 1.6.28, Amazon Linux 2 and Bottlerocket OS, 4 images (2 pinned by digest).
- With nodes and cluster-wide pods denied and only `shop` readable, the scan still succeeds, is partial and keeps the
  control plane and the `shop` images.
- Tokens from kubeconfigs or kubectl errors never appear in results, listings or messages.
- Not yet run against a real cluster: see [on-linux-docker.md](../plans/on-linux-docker.md) section K.

## Implemented by

[k8s collector](../tech/collectors/k8s.md), [host discovery](../tech/discover.md), [docker-image](../tech/collectors/docker-image.md)
