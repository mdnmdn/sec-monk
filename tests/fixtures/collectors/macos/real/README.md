# macOS collector fixtures (real)

**Provenance: real, trimmed, captured 2026-11-08 on macOS 26.5 (build 25F71), Apple Silicon (arm64)**, in a session
under a host restriction that denied listing `/Applications`, `/System/Applications`, `~/Applications`, `/Users`,
`/var/db/receipts`, `/Library/LaunchDaemons`, `/Library/LaunchAgents` and executing `ps` / `launchctl list`
(see `_docs/tech/collectors/macos.md` "Limitations"). Only Apple-owned system files and command output are kept:
no host name, user name, serial or home path. Used by `tests/collectors/test_macos.py` and
`tests/collectors/test_process.py`.

| File | What | Trimming |
|---|---|---|
| `SystemVersion.plist` | `/System/Library/CoreServices/SystemVersion.plist` (XML) | none (`BuildID` is per build, not per machine) |
| `receipts/*.plist` | three Apple receipts from `/Library/Apple/System/Library/Receipts/` (binary plists): Command Line Tools, MobileAssets, an XProtect data update | 3 of the 87 present, copied byte for byte |
| `pkgutil-pkg-info.txt` | `pkgutil --pkg-info <id>` for the same three ids, blank line between them | none |
| `system_profiler-applications-restricted.json` | `system_profiler SPApplicationsDataType -json` in the restricted session: an empty array | none |
| `launchd/com.apple.familycircled.plist` | `/System/Library/LaunchAgents/com.apple.familycircled.plist`: an Apple-shipped XML plist whose prolog has **unquoted** attributes (`<?xml version=1.0 ...?>`, `<!DOCTYPE plist PUBLIC -//Apple//...>`, `<plist version=1.0>`); `plutil -lint` says OK, Python's `plistlib` rejects it | keys other than `Label`, `CFBundleIdentifier`, `Program` removed; prolog kept verbatim |

| `system_profiler-applications.json` | `system_profiler SPApplicationsDataType -json`, **second capture the same day with Full Disk Access** (707 apps) | 13 entries kept, one per `obtained_from` / `arch_kind` shape, incl. entries without `version` / `signed_by` and with `info`; nothing under `/Users`; values verbatim (`signed_by` holds public Developer ID names and Team IDs) |

The restricted session listed no third-party (non-`com.apple.*`) package. With Full Disk Access the same Mac had 157
third-party receipts in `/var/db/receipts`; they are checked live (see `_docs/tech/collectors/macos.md`) but not kept,
because ids and paths there are specific to this machine.
