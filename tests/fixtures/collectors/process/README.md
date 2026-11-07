# Process collector fixtures (synthetic)

Hand-made from documented formats; **not** captured on a real Mac yet (see `_docs/plans/on-macos.md` section F).
Used by `tests/collectors/test_process.py`.

| File | What | Format source |
|---|---|---|
| `snapshot.json` | `secmonk-process-snapshot/1`: 21 processes covering every launch kind (launchd daemon by label and by program, LaunchServices GUI app, helper child, user LaunchAgent in `~/Library`, Terminal -> login -> zsh -> tools, sshd session, cron), launch items, precomputed facts for Chrome (signature, quarantine + LaunchServices event, where-froms), a missing `/tmp/x`, and an agent-provided identity | `src/secmonk/collectors/process/snapshot.py` |
| `root/` | overlay copied on top of `../macos/root` at test time: launchd plists (system, user, a broken one, a stale one), placeholder executables, Terminal `Info.plist`, `opt/homebrew/bin/curl` symlink into the curl keg, a fake privileged helper with an embedded `__info_plist`. The test also copies `../../lang/go/hello-darwin-arm64` to `/usr/local/bin/hello` | launchd.plist(5) keys |
| `ps.txt`, `ps-args.txt` | `ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm=` / `-o pid=,args=` (C locale), incl. a login shell `-zsh` and secrets to redact | ps(1) on macOS |
| `launchctl-list.txt` | `launchctl list` (PID, Status, Label; `-` = not running) | launchctl(1) |
| `codesign-*.txt` | stderr of `codesign -dv --verbose=2` for a Developer ID app, an ad-hoc (linker-signed) binary, an unsigned file | codesign(1) |
| `pkgutil-file-info.txt` | `pkgutil --file-info /usr/local/bin/aws` | pkgutil(1) |

Placeholder executables contain text, not Mach-O: identity comes from the bundle / keg / embedded plist. User name
`alice`, host `fixture-mac`, team id and URLs are illustrative.
