---
title: SSH collector (agentless)
type: tech
context: tech
status: implemented
tags: [collector, ssh, agentless, linux, macos]
updated: 2026-11-07
sample: synthetic
fixtures: tests/fixtures/collectors/docker/ (debian-12, alpine-3.20) and tests/fixtures/collectors/macos/root, used as fake remote roots
code: src/secmonk/collectors/ssh.py, src/secmonk/collectors/harvest.py
related: [tech/collectors/rootfs.md, tech/collectors/macos.md, tech/collectors/docker-image.md, features/inventory-ssh.md]
---

# SSH collector (agentless)

## Summary

`secmonk scan ssh user@host[:port]` inventories a remote Linux server or macOS machine over SSH, read-only, with nothing
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
| OS + package DBs (explicit paths, always, even across mount points) | `rootfs.FIXED_PATHS` (os-release, alpine-release, debian_version, redhat-release, dpkg `status`, apk `installed`, `rpmdb.sqlite`(+`-wal`) and legacy `Packages*` for detection) + `var/lib/dpkg/status.d/*` | `System/Library/CoreServices/SystemVersion.plist`, `var/db/receipts/*.plist` |
| Apps | - | `*.app/Contents/Info.plist`, `_MASReceipt/receipt` under `Applications`, `System/Applications`, `Users/*/Applications` (depth `macos.MAX_APP_DEPTH`; `Contents/{MacOS,Resources,PlugIns,XPCServices,Library,SharedSupport}` pruned), Info.plists of Electron / Chromium Embedded / Sparkle frameworks |
| Homebrew (`opt/homebrew`, `usr/local`, `home/linuxbrew/.linuxbrew`) | - | `Cellar/*/*/INSTALL_RECEIPT.json`, `.brew/*.rb`, `sbom.spdx.json`; `opt/*` symlinks; `Caskroom/*/*` dirs (empty markers), `Caskroom/*/*/*.app` markers, `Caskroom/*/.metadata/**/*.json|rb` |
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
`exclude`, `root` (path prefix for every remote path; default `/`; used by tests with fixture roots), `os` (`linux|macos`: skip detection result),
`include_system` (macOS), `verbose`.

Target forms: `user@host`, `user@host:2222`, `ssh://user@host:2222`, `host`, `user@[fe80::1]:22`. Host/user are validated (no leading `-`, no spaces).

## Classification

Unchanged: Linux packages -> `os-package` with deb/apk/rpm PURLs and distro ecosystem (`collect_from_view`); apps/Homebrew/receipts -> as in
[macos.md](macos.md). Component `source_path` is the path on the remote machine. The asset is rewritten:

`Asset(id="ssh:<host>", type="server"|"desktop", name=<host>, os_name/os_version from the collector, platform="linux|darwin/<arch>",
meta={transport, user, port, remote_os, remote_hostname, harvested_files, harvested_bytes, sudo, truncated[, root]})`.

## Limitations

* Language parsers are whatever `collectors/lang` has (all seven ecosystems, see [dependencies.md](dependencies.md)); the harvest only guarantees the *files* arrive, then the rootfs collector runs `walk_dir` over the temp dir. Jars and Go/Rust binaries are harvested only with `-o binaries=true`.
* `-path` globs over-approximate (`*/node_modules/*/package.json` also matches deeper fixture `package.json`s inside a package).
* Linux: `-xdev` skips separately mounted trees for the language walk (not for OS DBs); `/nix/store` and container storage are pruned.
  `var/lib/rpm -> usr/lib/sysimage/rpm` symlinked layouts harvest the DB twice (harmless).
* Without root some home directories / root-only trees are invisible; package DBs on Linux and `/Applications` on macOS are world-readable, so usually nothing is lost.
* Homebrew on Linux (`linuxbrew`) is harvested only on macOS profiles and `MacOSCollector` ignores that prefix. Other Unixes (BSD, AIX, Solaris) refused.
* No `ControlMaster` reuse: detect and harvest are two connections (OpenSSH). Paramiko has no `ProxyJump`.
* BSD `find`/`bsdtar` (macOS), busybox `find`/`tar` (Alpine without GNU) are untested; the script avoids GNU-only flags on purpose
  (`-size -Nc`, `-perm -100`, `-mindepth/-maxdepth`, `--null --no-recursion -T -`), but busybox tar may lack `--null`.
* The inventory is a point-in-time view of files, not of running processes; remote clock/hostname are not verified.

## Windows targets (OpenSSH server)

Windows OpenSSH starts `cmd.exe` (or PowerShell) as the login shell, so the POSIX detection
script fails. The collector then probes `powershell … [Environment]::OSVersion.Platform`
(`Win32NT`) and, if it answers, runs the **read-only** inventory script
(`secmonk windows-script`, shipped in `src/secmonk/data/windows/`) via
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -` with the script on stdin
(compact form: no blank/comment lines). The JSON on stdout (BOM/banner tolerated) goes to
`windows.parse_inventory_json`. `-o os=windows` skips the POSIX probe.
Tested with a fake transport only (no Windows host in the dev sandbox).
