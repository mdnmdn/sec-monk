# Swift fixtures (`Package.resolved`)

Provenance: **synthetic**, written by hand on 2026-11-11 following the structure SwiftPM / Xcode emit for each
format version (field names, ordering, `" : "` spacing of v2/v3 as written by SwiftPM 5.6+). Package names,
repository URLs and versions are real public packages; revisions and `originHash` are made up. Hosts other than
github.com use `example.com`.

| File | Format | Covers |
|---|---|---|
| `v1/Package.resolved` | v1 (`object.pins[].repositoryURL`) | https and scp-style (`git@host:owner/repo.git`) URLs, a branch-only pin, swift-nio-http2 1.19.1 (vulnerable, GHSA-ccw9-q5h2-8c2w) |
| `v2/Package.resolved` | v2 (`pins[].location`, `kind`) | URL without `.git`, mixed-case repo (`marmelroy/Zip`), a `fileSystem` pin (skipped), vapor 4.40.0 |
| `v3/Package.resolved` | v3 (`originHash`) | registry pin (skipped with a warning), branch + revision pin without version, a URL with credentials (must be redacted in meta) |
| `osv-swifturl-GHSA-ccw9-q5h2-8c2w.json` | OSV record | real record from `SwiftURL/all.zip` (fetched 2026-11-11), `details` and `references` trimmed |
