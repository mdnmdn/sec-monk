# k8s collector fixtures

Synthetic (2026-11-11), shaped like real `kubectl` JSON output of an EKS cluster: `version.json` (`get --raw /version`),
`nodes.json`, `namespaces.json`, `pods.json` (`get ... -o json`, trimmed to the fields the collector reads),
`config-view.json` (`kubectl config view --minify -o json`, credentials already redacted as kubectl does) and
`kubeconfig.yaml` (a kubeconfig with fake credentials, used to check that tokens, keys and exec args never leak).
No real cluster, host, account or user names; digests are placeholders.
