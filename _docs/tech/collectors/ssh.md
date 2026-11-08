---
title: SSH collector (agentless)
summary: Agentless SSH inventory of Linux, macOS and Windows hosts covering fixed read-only harvest script, transports, safe extraction, asset ids.
read_when: you change how the SSH collector connects, what it runs on the host or how it extracts the harvest
type: tech
context: tech
status: implemented
tags: [collector, ssh, agentless, linux, macos, windows]
updated: 2026-11-08
verified: 2026-11-08
sample: mixed
fixtures: [tests/fixtures/collectors/docker/, tests/fixtures/collectors/macos/root]
code: src/secmonk/collectors/ssh.py, src/secmonk/collectors/harvest.py
related: [tech/collectors/rootfs.md, tech/collectors/macos.md, tech/collectors/docker-image.md, features/inventory-ssh.md]
---

# SSH collector (agentless)

Fixtures: the docker `debian-12` / `alpine-3.20` trees and the macOS root are used as fake remote roots.

## Summary

`secmonk scan ssh user@host[:port]` inventories a remote Linux server, macOS machine or Windows host (OpenSSH server) over SSH, read-only, with nothing
installed on the target. It does **not** re-implement any parsing: it *harvests* the metadata files the existing collectors
read into a private local temp directory and runs the normal collector on that directory ("harvest, then reuse").

```
detect OS  ->  one remote `find | tar` pipeline  ->  safe extract to temp dir  ->  rootfs / macOS collector  ->  rewrite asset
 (1 cmd)         (fixed, read-only script)            (no abs/.., devices, escaping links)       (unchanged code)
```

Verified only against fixture trees through a local `sh` (GNU find/tar) and an in-process paramiko server; **no real sshd, no real
macOS (BSD find / bsdtar) was available** - the macOS variant of the script is untested on a Mac.

## Where the data lives

### Remote prerequisites

POSIX `sh`, `find` (with `-print0`, `-xdev`, `-prune`, `-size -Nc`), `tar` (GNU or bsdtar: `--null --no-recursion -T - -czf -`
work on both), `gzip` (GNU tar's `-z`), `uname`, `cat`, `hostname`. `sw_vers` on macOS. Optional: passwordless `sudo -n`.
No Python, no agent, no writes: the harvest script only reads and prints.

### Commands executed remotely (the complete list)

Both are scripts fed on **stdin** of `sh -s` (so the remote login shell - bash, fish, csh - never parses them, and no quoting
survives a second shell):

1. **Detect** (`harvest.detect_script`): `uname -s`, `uname -m`, `cat /etc/os-release || cat /usr/lib/os-release`, `sw_vers`,
   `hostname`, each section introduced by an `@@secmonk:<name>@@` marker line (motd/rc-file noise before the first marker is ignored).
   `Darwin` -> macOS, `Linux` -> Linux, anything else is refused.
2. **Harvest** (`harvest.build_script`): `cd <root>`, print the marker `SECMONK-STREAM-BEGIN`, then
   `{ find ... -print0; find ... -print0; ... } | tar --null --no-recursion -T - -czf -`. The marker lets the client skip any
   login-shell output that precedes the tar bytes. `--no-recursion` is essential: directory entries (Homebrew Caskroom markers) are
   stored empty and the tar can never pull in a whole tree. All `find`s have `</dev/null 2>/dev/null` (permission-denied noise is
   dropped; unreadable files are simply missing - run with `-o sudo=true` for root-only files).

With `-o sudo=true` the harvest (not the detection) runs as `sudo -n sh -s`; if sudo wants a password it fails fast with a clear error.
Every remote command is logged with `-o verbose=true`. The script generator quotes every dynamic value with `shlex.quote`
(root, excludes), file names travel NUL-separated end to end, and the script is syntax-checked and static-checked in tests
(no `rm`/`mv`/`chmod`/redirects other than `/dev/null`).

### What is harvested (`harvest.py`, the reusable spec)

`HarvestSpec(os, root="/", lang=True, binaries=False, max_binary_bytes=50MB, max_meta_bytes=64MB, max_db_bytes=256MB, xdev=None, exclude=())`

| Group | Linux | macOS |
|---|---|---|
| OS + package DBs (explicit paths, always, even across mount points) | `rootfs.FIXED_PATHS` (os-release, alpine-release, debian_version, redhat-release, dpkg `status`, apk `installed`, `rpmdb.sqlite`(+`-wal`) and legacy `Packages*` for detection) + `var/lib/dpkg/status.d/*` | `System/Library/CoreServices/SystemVersion.plist`, `*.plist` in `var/db/receipts` and `Library/Apple/System/Library/Receipts` (Apple's own), Safari's `Info.plist` in the App cryptex (`System/Cryptexes/App/...`) |
| Apps | - | `*.app/Contents/Info.plist`, `*.app/Wrapper/*.app/Info.plist` (iOS apps), `_MASReceipt/receipt`, top-level `*.app` symlinks (extracted re-rooted, e.g. `Safari.app` -> cryptex) under `Applications`, `System/Applications`, `Users/*/Applications` (depth `macos.MAX_APP_DEPTH`; `Contents/{MacOS,Resources,PlugIns,XPCServices,Library,SharedSupport}` pruned), Info.plists of Electron / Chromium Embedded / Sparkle frameworks |
| Homebrew (`opt/homebrew`, `usr/local`, `home/linuxbrew/.linuxbrew`) | - | `Cellar/*/*/INSTALL_RECEIPT.json`, `.brew/*.rb`, `sbom.spdx.json`; `opt/*` symlinks; `Caskroom/*/*` dirs (empty markers), `Caskroom/*/*/*.app` markers, `.metadata/**/*.json|rb` (via `find`, which does not follow a renamed cask's `Caskroom/<old> -> <new>` link; a shell glob did and harvested the cask twice), `Caskroom/*` symlinks |
| Language dependency files (walk of the whole root) | by **name**: `PKG-INFO`, `pyvenv.cfg`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock`, `requirements*.txt`, `composer.lock`, `go.mod`, `go.sum`, `Cargo.lock`, `*.deps.json`, `packages.lock.json`, `project.assets.json`, `packages.config`, `*.csproj/.fsproj/.vbproj`, `Directory.Packages.props`, `pom.xml`, `gradle.lockfile`, `verification-metadata.xml`; by **path**: `*.dist-info/METADATA`, `*/conda-meta/*.json`, `*/node_modules/*/package.json` (+ `@scope`), `*/vendor/composer/installed.json`; plus a project `package.json` **only when a lockfile sits next to it** (second `find` with `-exec sh -c`) | same |
| Optional (`binaries=true`) | `*.jar/*.war/*.ear` anywhere, executables (`-perm -100`) in `*/bin/*`, `*/sbin/*`, each < `max_binary_mb` (for Go buildinfo / cargo-auditable / jar parsers) | same |

`lang_match()` is a Python mirror of the name filter; a test checks that everything `collectors/lang` wants by path is covered
(drift guard when parsers add new file names - extend `LANG_NAMES`/`LANG_PATHS` then).

Walk pruning (`find . -xdev ( -path ... -o -name .git ) -prune -o ...`):

* Linux: `/proc /sys /dev /run /tmp /var/tmp /var/cache /var/lib/docker /var/lib/containerd /snap /nix/store /lost+found`,
  `-xdev` (**default on**: a separate `/home` or `/opt` mount is then not walked - `-o xdev=false`; the fixed OS/DB paths are always read).
  `/nix/store` is pruned because it is huge and full of immutable duplicates (gap: Nix-managed software is not inventoried).
* macOS: `/Volumes /System /dev /cores /private/{tmp,var/folders,var/vm} /Library/Caches /Users/*/Library/Caches ...`, **no** `-xdev`
  (Catalina+ firmlinks put `/Users`, `/Applications`, `/opt` on the Data volume, which `-xdev` would skip). `/System` is only read via the
  explicit `System/Applications` find.
* Everywhere: `.git`, `.Trash`; extra `-o exclude=/data,/mnt/backup` (paths relative to the root, globs allowed, quoted).

Caps: per-file `-size -Nc` in `find` (remote), and locally while extracting: `max_files` (tar entries, default 200000) and `max_mb`
(extracted bytes, default 512). When a cap is hit the stream is aborted (the remote pipeline dies by SIGPIPE), a warning
`harvest truncated` is added and the partial inventory is returned (`asset.meta.truncated=true`).

### Safe extraction (`harvest.safe_extract`)

Streaming `tarfile` (`r|gz`), no `extractall`. Skipped and listed in warnings: absolute names, any `..`, NUL; device/fifo/special files;
symlinks whose lexical target leaves the root (**absolute targets are re-rooted** to relative ones, so `etc/os-release ->
/usr/lib/os-release` works for both `DirView` and `Path.resolve()`); hard links except to an already extracted regular file (stored as
copies); any entry whose parent path traverses a symlink or collides with a file (blocks `loop -> .` then `loop/x` tricks). Modes and owners
are ignored (files `0600`, dirs `0700`, no setuid). Temp dir: `tempfile.mkdtemp(prefix="secmonk-ssh-")` mode `0700`, removed in `finally`.

## Data format

Transports (`ssh.py`):

| | `OpenSSHTransport` | `ParamikoTransport` |
|---|---|---|
| Implementation | system `ssh` (`subprocess`) | paramiko (pure Python) |
| Auth | whatever ssh does: `~/.ssh/config`, agent, keys, `ProxyJump`, ControlMaster; `BatchMode=yes` so it never prompts | key file `-o identity=`, agent, `~/.ssh/id_*`, password from env `SECMONK_SSH_PASSWORD` (key passphrase `SECMONK_SSH_KEY_PASSPHRASE`) - never on a command line or in an option |
| Host keys | ssh's `known_hosts` (`StrictHostKeyChecking` from config; unknown host fails in BatchMode) | `~/.ssh/known_hosts` (or `-o known_hosts=file`) with `RejectPolicy`; `-o insecure_host_key=true` = AutoAdd, **unsafe** (also `StrictHostKeyChecking=no` for openssh) |
| Config | passthrough `-o ssh_option=ProxyJump=bastion` (comma-separate several), `-o identity=`, `-o ssh_bin=` | reads `HostName`, `Port`, `User`, `IdentityFile`, `ProxyCommand` from `~/.ssh/config` (or `-o ssh_config=`); **no `ProxyJump`** |
| Hardening | `ClearAllForwardings`, `ForwardAgent=no`, `ForwardX11=no`, `PermitLocalCommand=no`, `-T`, `ServerAliveInterval` | keepalive 15s |

Both implement `Transport.stream(cmd, timeout, stdin) -> Stream` (`read(n)`, `finish(abort)`; stderr drained in a thread, total-time watchdog) and
`Transport.run(...) -> (rc, stdout, stderr)`. Auto-selection (`-o transport=auto`, default): system `ssh` if on PATH and no
`SECMONK_SSH_PASSWORD` set, otherwise paramiko. Python callers may inject any `Transport` as `transport=`.

Options (`-o key=value`): `transport`, `identity`, `ssh_option`, `ssh_bin`, `known_hosts`, `insecure_host_key`, `allow_agent`, `look_for_keys`, `ssh_config`,
`connect_timeout` (15), `timeout` (total harvest seconds, 900), `sudo`, `lang` (true), `binaries`, `max_binary_mb` (50), `max_files`, `max_mb`, `xdev`,
`exclude`, `root` (path prefix for every remote path; default `/`; used by tests with fixture roots), `os` (`linux|macos|windows`: override the detected family; `windows` skips the POSIX probe),
`include_system` (macOS and Windows), `verbose`.

Target forms: `user@host`, `user@host:2222`, `ssh://user@host:2222`, `host`, `user@[fe80::1]:22`. Host/user are validated (no leading `-`, no spaces).

## Classification

Unchanged: Linux packages -> `os-package` with deb/apk/rpm PURLs and distro ecosystem (`collect_from_view`); apps/Homebrew/receipts -> as in
[macos.md](macos.md). Component `source_path` is the path on the remote machine. The asset is rewritten:

`Asset(id="ssh:<host>" (`ssh:<host>:<port>` for a non-22 port, IPv6 bracketed), type="server"|"desktop", name=<host>, os_name/os_version from the collector, platform="linux|darwin/<arch>",
meta={transport, user, port, remote_os, remote_hostname, harvested_files, harvested_bytes, sudo, truncated[, root]})`.

## Limitations

*Describes current behaviour. What is still to do (and how to verify it) is tracked in the plan [on-linux-docker.md](../../plans/on-linux-docker.md); measurements and real-data validation are in the [probe log](../../references/probes.md).*

* Language parsers are whatever `collectors/lang` has (all seven ecosystems, see [dependencies.md](dependencies.md)); the harvest only guarantees the *files* arrive, then the rootfs collector runs `walk_dir` over the temp dir. Jars and Go/Rust binaries are harvested only with `-o binaries=true`.
* `-path` globs over-approximate (`*/node_modules/*/package.json` also matches deeper fixture `package.json`s inside a package).
* Linux: `-xdev` skips separately mounted trees for the language walk (not for OS DBs); `/nix/store` and container storage are pruned.
  `var/lib/rpm -> usr/lib/sysimage/rpm` symlinked layouts harvest the DB twice (harmless).
* Without root some home directories / root-only trees are invisible; package DBs on Linux and `/Applications` on macOS are world-readable, so usually nothing is lost.
* Homebrew on Linux (`linuxbrew`) is harvested only on macOS profiles and `MacOSCollector` ignores that prefix. Other Unixes (BSD, AIX, Solaris) refused.
* No `ControlMaster` reuse: detect and harvest are two connections (OpenSSH). Paramiko has no `ProxyJump`.
* BSD `find`/`bsdtar` (macOS) run on a real Mac (macOS 26.5, 2026-11-08) through a local transport (no sshd: Remote Login
  was off): the macOS profile with `lang=false` gives exactly the direct `MacOSCollector` components (1122, 3139 files,
  25 s) except bundles whose `Contents` is itself a symlink (Multipass -> `/Library/Application Support/...`), not
  followed. `bsdtar` adds `._<name>` AppleDouble entries for files with extended attributes: the script sets
  `COPYFILE_DISABLE=1` (ignored by other tars). The `lang` walk of a whole developer Mac ran over 10 minutes (every
  `node_modules` under the home) and was stopped; use `-o lang=false` or `-o exclude=` there. Busybox `find`/`tar` (Alpine
  without GNU) are untested; busybox tar may lack `--null`.
* The inventory is a point-in-time view of files, not of running processes; remote clock/hostname are not verified.

## Windows targets (OpenSSH server)

Windows OpenSSH starts `cmd.exe` (or PowerShell) as the login shell, so the POSIX detection
script fails. The collector then probes `powershell … [Environment]::OSVersion.Platform`
(`Win32NT`) and, if it answers, runs the **read-only** inventory script
(`secmonk windows-script`, shipped in `src/secmonk/data/windows/`) via
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -` with the script on stdin
(compact form: no blank/comment lines). The JSON on stdout (BOM/banner tolerated) goes to
`windows.parse_inventory_json`. `-o os=windows` skips the POSIX probe.
Asset id, `ssh_*` timeouts and `include_system` behave as for POSIX targets. Tested with a fake transport only (`tests/collectors/test_ssh_windows.py`; no Windows host in the dev sandbox).

## Review fixes (2026-11)

- **Asset id**: `ssh:<host>` for port 22 / unset, `ssh:<host>:<port>` otherwise (`ssh:[::1]:2222` for IPv6). Two machines behind one
  NAT/jump address no longer collapse into one asset. Existing `ssh:<host>` assets of non-default ports are re-created on the next scan.
- **Machine identity**: the detect step reads (read-only) `/etc/machine-id` (fallback `/var/lib/dbus/machine-id`) or, on macOS,
  `ioreg -rd1 -c IOPlatformExpertDevice` (`IOPlatformUUID`). `asset.meta.machine_id` is `sha256("secmonk\0machine-id\0" + id)` (systemd asks
  that the raw machine id is never exposed) and `machine_id_source` is `machine-id` or `IOPlatformUUID`. Use it to recognise a host whose
  address or port changed.
- **Partial results**: `Inventory.partial`/`partial_reason` is set when the archive stream ended abnormally, timed out, hit the
  file/byte limits, or the remote command ended with 255/killed. If nothing was extracted and the end was abnormal, `SSHError` is
  raised (rc included) instead of storing an empty inventory. `_harvest()` returns `(stats, real rc, stderr, abnormal)`.
  See [data-model](../data-model.md) for how partial scans are stored.
- **Insecure host keys** (`-o insecure_host_key=true`, paramiko): keys are accepted for the connection only; `known_hosts` is loaded with
  `get_host_keys().load()` and a non-saving policy is used, so nothing is ever written back.

### Safer sudo (recommended setup)

`-o sudo=true` runs `sudo -n sh -s` with the script on stdin, which needs `NOPASSWD: ALL`-like rights for `sh`: that is root for anyone
who can use the account. Prefer a dedicated account and a root-owned wrapper that can only do what the harvest does:

1. Save the output of `secmonk` harvest script (`harvest.build_script`) as `/usr/local/libexec/secmonk-harvest` (root:root 0755, not writable by the scan user).
2. `/etc/sudoers.d/secmonk`: `secmonk-scan ALL=(root) NOPASSWD: /usr/local/libexec/secmonk-harvest` and `Defaults!/usr/local/libexec/secmonk-harvest !requiretty`.
3. Restrict the key in `authorized_keys` (`no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty`).
4. Scan with a wrapper-aware command (future option) or leave sudo off: without root only root-only files are missing (warned).

The wrapper approach keeps a stolen scan key from becoming a root shell. No code change is required for the current behaviour.
