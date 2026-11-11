# Dart fixtures (`pubspec.lock`)

Provenance: **synthetic**, written by hand on 2026-11-11 following the layout `dart pub get` / `flutter pub get`
write (header comment, `packages.<name>.{dependency, description, source, version}`, `sdks`). Package names and
versions are real pub.dev packages; `sha256` values and the git `resolved-ref` are made up. Non-pub.dev hosts and
the git remote use `example.com` / `example-org`.

| File | Layout | Covers |
|---|---|---|
| `flutter-app/pubspec.lock` | Dart 3 (`sha256`, `url: https://pub.dev`) | `direct main` / `direct dev` / `direct overridden` / `transitive`; `sdk` and `path` sources (skipped); a self-hosted package (skipped); a pub.dev mirror (`pub.flutter-io.cn`, kept); a `git` source with credentials in the URL (redacted); http 0.13.1 (vulnerable, GHSA-4rgh-jx4f-qfcq) |
| `legacy/pubspec.lock` | Dart 2 (`url: https://pub.dartlang.org`, no `sha256`) | legacy host is pub.dev; archive 3.3.7 (vulnerable, GHSA-9v85-q87q-g4vg) |
| `osv-pub-GHSA-4rgh-jx4f-qfcq.json` | OSV record | real record from `Pub/all.zip` (fetched 2026-11-11), `details` and `references` trimmed |
