"""Process snapshot of a remote Linux host over ssh (agentless, read-only).

One fixed POSIX `sh` script (`SCRIPT`, constant text: nothing from the user, the target or the remote is ever
interpolated into it) is fed on stdin to `sh -s` (or `sudo -n sh -s`) through the ssh collector's transports. It
prints framed one-line records, every value from the target hex-encoded with `od` (process names, paths and command
lines may contain any byte), and also resolves package ownership of the running executables *on the remote*
(`dpkg-query -S`, `rpm -qf`, apk's `installed` database), quoting each path as `"$p"` after `--`. The output is capped
and parsed with the same pure parsers as the local backend (`linux.snapshot_from_capture`); owners become
`executables[path].identity`, so the analysis runs with nothing read on this machine.

See _docs/tech/collectors/process.md "Remote Linux over ssh" and _docs/decisions/0010-remote-process-snapshot.md.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .. import ssh
from ..harvest import opts_int
from ..rootfs import distro_ecosystem, parse_apk_installed, parse_dpkg_status
from . import linux
from .model import Snapshot

log = logging.getLogger("secmonk.ssh")

MARK = "@@SECMONK-PROCS/1@@"
MAX_OUTPUT = 32 * 1024 * 1024
DEFAULT_TIMEOUT = 300

# The whole script. `R` is the root prefix: empty on a real host (tests run the same text against a fixture tree by
# replacing that one line). Every file read is capped with `dd`; commands are read-only; no file is written.
SCRIPT = r"""# secmonk remote process snapshot (Linux), read-only. See secmonk _docs/tech/collectors/process.md
R=''
LC_ALL=C
export LC_ALL
hx() { od -An -v -tx1 | tr -d ' \n'; }
fx() { printf '%s' "$1" | hx; }
rec() {
  [ -f "$R$2" ] && [ -r "$R$2" ] || return 0
  printf '%s %s ' "$1" "$(fx "$2")"
  dd if="$R$2" bs="$3" count=1 2>/dev/null | hx
  echo
}
echo '@@SECMONK-PROCS/1@@ BEGIN'
printf 'H ostype '; { cat "$R/proc/sys/kernel/ostype" 2>/dev/null || uname -s 2>/dev/null; } | hx; echo
printf 'H hostname '; { cat "$R/proc/sys/kernel/hostname" 2>/dev/null || hostname 2>/dev/null; } | hx; echo
printf 'H boot_id '; cat "$R/proc/sys/kernel/random/boot_id" 2>/dev/null | hx; echo
printf 'H btime %s\n' "$(sed -n 's/^btime \([0-9][0-9]*\).*/\1/p' "$R/proc/stat" 2>/dev/null)"
printf 'H clk_tck %s\n' "$(getconf CLK_TCK 2>/dev/null)"
printf 'H uid %s\n' "$(id -u 2>/dev/null)"
printf 'H passwd '; cut -d: -f1,3 "$R/etc/passwd" 2>/dev/null | hx; echo
if [ -f "$R/etc/os-release" ]; then rec O /etc/os-release 65536; else rec O /usr/lib/os-release 65536; fi
rec V /etc/debian_version 256
exes=''
for d in "$R"/proc/[0-9]*; do
  p=${d##*/}
  case $p in ''|*[!0-9]*) continue ;; esac
  s=$(dd if="$d/stat" bs=4096 count=1 2>/dev/null | hx)
  [ -n "$s" ] || continue
  printf 'P %s %s\n' "$p" "$s"
  printf 's %s ' "$p"; grep -E '^(Name|PPid|Uid):' "$d/status" 2>/dev/null | hx; echo
  printf 'a %s ' "$p"; dd if="$d/cmdline" bs=65536 count=1 2>/dev/null | hx; echo
  printf 'g %s ' "$p"; dd if="$d/cgroup" bs=65536 count=1 2>/dev/null | hx; echo
  printf 'r %s %s\n' "$p" "$(stat -L -c '%d:%i' -- "$d/root" 2>/dev/null)"
  if x=$(readlink "$d/exe" 2>/dev/null) && [ -n "$x" ]; then
    printf 'e %s %s\n' "$p" "$(fx "$x")"
    case $x in *'
'*) ;; *) exes="$exes
$x" ;; esac
  elif [ -L "$d/exe" ]; then
    printf 'e %s !\n' "$p"
  fi
done
if command -v dpkg-query >/dev/null 2>&1; then
  printf 'T '
  dpkg-query -W -f='Package: ${Package}\nVersion: ${Version}\nArchitecture: ${Architecture}\nSource: ${Source}\nStatus: ${Status}\n\n' 2>/dev/null | hx
  echo
  printf 'L '; ( cd "$R/var/lib/dpkg/info" 2>/dev/null && stat -c '%Y %n' -- *.list 2>/dev/null ) | hx; echo
fi
rec K /lib/apk/db/installed 8388608
q='%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\t%{VENDOR}\n'
printf '%s\n' "$exes" | sort -u | {
  set --
  while IFS= read -r x; do
    case $x in /*) ;; *) continue ;; esac
    p=${x% (deleted)}
    printf 'F %s %s\n' "$(fx "$p")" "$(stat -c '%Y %s %u %a' -- "$R$p" 2>/dev/null)"
    set -- "$@" "$p"
    case $p in
      /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib32/*|/usr/lib64/*) set -- "$@" "${p#/usr}" ;;
      /bin/*|/sbin/*|/lib/*|/lib32/*|/lib64/*) set -- "$@" "/usr$p" ;;
    esac
    case $p in
      /snap/*/*/*)
        n=${p#/snap/}; sn=${n%%/*}; r=${n#*/}; r=${r%%/*}
        printf 'Y %s ' "$(fx "/snap/$sn/$r")"
        sed -n 's/^version:[[:space:]]*//p' "$R/snap/$sn/$r/meta/snap.yaml" 2>/dev/null | head -n 1 | hx
        echo ;;
    esac
  done
  [ $# -gt 0 ] || exit 0
  if command -v dpkg-query >/dev/null 2>&1; then
    printf 'S %s %s\n' "$(printf '%s\n' "$@" | hx)" "$(dpkg-query -S -- "$@" 2>/dev/null | hx)"
  elif command -v rpm >/dev/null 2>&1; then
    o=$(rpm -qf --queryformat "$q" -- "$@" 2>/dev/null)
    if [ "$(printf '%s\n' "$o" | wc -l | tr -d ' ')" = "$#" ]; then
      printf 'Q %s %s\n' "$(printf '%s\n' "$@" | hx)" "$(printf '%s\n' "$o" | hx)"
    else
      for p in "$@"; do
        printf 'Q %s %s\n' "$(fx "$p")" "$(rpm -qf --queryformat "$q" -- "$p" 2>/dev/null | hx)"
      done
    fi
  fi
}
own() {
  [ -L "$R$1" ] && return 1
  d=$(cd "$R${1%/*}" 2>/dev/null && pwd -P) || return 1
  case $d in "$R"/home/*|"$R"/root|"$R"/root/*) return 0 ;; esac
  return 1
}
unit() {
  if [ -L "$R$1" ] && [ "$(readlink "$R$1" 2>/dev/null)" = /dev/null ]; then
    printf 'M %s\n' "$(fx "$1")"
  else
    rec U "$1" 65536
  fi
}
for dir in /etc/systemd/system /usr/local/lib/systemd/system /lib/systemd/system /usr/lib/systemd/system \
           /etc/systemd/user /usr/local/lib/systemd/user /usr/lib/systemd/user; do
  for f in "$R$dir"/*.service "$R$dir"/*.timer; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    unit "${f#"$R"}"
  done
done
for f in "$R"/root/.config/systemd/user/*.service "$R"/root/.config/systemd/user/*.timer \
         "$R"/home/*/.config/systemd/user/*.service "$R"/home/*/.config/systemd/user/*.timer; do
  own "${f#"$R"}" || continue
  rec U "${f#"$R"}" 65536
done
for f in "$R"/etc/xdg/autostart/*.desktop; do
  rec A "${f#"$R"}" 65536
done
for f in "$R"/root/.config/autostart/*.desktop "$R"/home/*/.config/autostart/*.desktop; do
  own "${f#"$R"}" || continue
  rec A "${f#"$R"}" 65536
done
for f in "$R"/etc/crontab "$R"/etc/cron.d/* "$R"/var/spool/cron/crontabs/* "$R"/var/spool/cron/*; do
  rec C "${f#"$R"}" 65536
done
echo '@@SECMONK-PROCS/1@@ END'
"""


def _hex(s: str) -> bytes:
    try:
        return bytes.fromhex(s.strip())
    except ValueError:
        return b""


def _txt(s: str) -> str:
    return _hex(s).decode("utf-8", "replace")


def _num(s: str) -> int | None:
    return linux.to_int(s)


# caps on what a (possibly hostile) target can make us hold
MAX_PROCS = 100_000            # = snapshot.MAX_PROCESSES
MAX_FILES = 100_000
MAX_CONFIG_FILES = 20_000      # units, autostart files, crontabs, masked units (each)


def parse_output(data: bytes) -> linux.Capture:
    """Records of `SCRIPT` -> `Capture`. Pure; unknown or malformed records are skipped, counts are capped, and a
    last line without its newline (output cut by the size cap or a killed stream) is dropped."""
    cap = linux.Capture()
    procs: dict[int, linux.RawProc] = {}
    dropped: set[str] = set()
    if data and not data.endswith(b"\n"):
        data = data[:data.rfind(b"\n") + 1]
        cap.warnings.append("remote output ended in the middle of a record: the last record was dropped")
    configs = {"U": cap.units, "A": cap.autostart, "C": cap.crontabs}
    for line in data.decode("ascii", "replace").splitlines():
        if line.startswith(MARK):
            word = line[len(MARK):].strip()
            if word == "BEGIN":
                cap.begun = True
            elif word == "END" and cap.begun:
                cap.complete = True
            continue
        if not cap.begun or cap.complete:
            continue
        parts = line.split(" ", 2)
        tag = parts[0]
        a = parts[1] if len(parts) > 1 else ""
        b = parts[2] if len(parts) > 2 else ""
        if tag == "H":
            if a in ("btime", "clk_tck", "uid"):
                setattr(cap, a, _num(b))
            elif a in ("ostype", "hostname", "boot_id"):
                setattr(cap, a, _txt(b).strip()[:256])
            elif a == "passwd":
                cap.passwd = _txt(b)
        elif tag in ("P", "s", "a", "g", "e", "r") and (pid := _num(a)) is not None:
            raw = procs.get(pid)
            if raw is None:
                if len(procs) >= MAX_PROCS:
                    dropped.add("processes")
                    continue
                raw = procs[pid] = linux.RawProc(pid=pid)
            if tag == "P":
                raw.stat = _hex(b)
            elif tag == "s":
                raw.status = _txt(b)
            elif tag == "a":
                raw.cmdline = _hex(b)
            elif tag == "g":
                raw.cgroup = _txt(b)
            elif tag == "r":
                raw.root_id = b.strip() if re.fullmatch(r"\d{1,20}:\d{1,20}", b.strip()) else ""
            elif b.strip() == "!":
                raw.exe_denied = True
            else:
                raw.exe = _txt(b) or None
        elif tag == "O":
            cap.os_release = _txt(b)
        elif tag == "V":
            cap.debian_version = _txt(b)
        elif tag == "F":
            f = b.split()
            nums = [_num(x) for x in f[:3]]
            if len(f) == 4 and None not in nums and re.fullmatch(r"[0-7]{1,6}", f[3]):
                if len(cap.files) >= MAX_FILES:
                    dropped.add("executables")
                    continue
                cap.files[_txt(a)] = (nums[0], nums[1], nums[2], int(f[3], 8))
        elif tag == "S":
            cap.dpkg_search += _txt(b) + "\n"
        elif tag == "Q":
            paths = _txt(a).splitlines()
            out = _txt(b)
            rows = out.splitlines()
            if len(paths) == 1:
                cap.rpm_owner[paths[0]] = out
            elif len(paths) == len(rows):                    # batched: one line per queried path, in order
                for path, row in zip(paths, rows, strict=True):
                    cap.rpm_owner.setdefault(path, row)
        elif tag == "Y":
            v = _txt(b).strip().strip("'\"")
            if v:
                cap.snap_versions[_txt(a)] = v[:128]
        elif tag == "T":
            cap.dpkg_table = _txt(a)
        elif tag == "L":
            for row in _txt(a).splitlines():
                mt, _, path = row.partition(" ")
                if _num(mt) is not None and path.endswith(".list"):
                    cap.dpkg_lists[path.rsplit("/", 1)[-1][:-len(".list")].split(":", 1)[0]] = _num(mt)
        elif tag == "K":
            cap.apk_db = _txt(b)
        elif tag in configs or tag == "M":
            path = _txt(a)
            target = configs.get(tag, cap.masked)
            if not path.startswith("/"):
                continue
            if len(target) >= MAX_CONFIG_FILES:
                dropped.add({"U": "unit files", "A": "autostart files", "C": "crontabs", "M": "masked units"}[tag])
                continue
            target.append((path, _txt(b)) if tag in configs else path)
    cap.procs = [procs[k] for k in sorted(procs)]
    for what in sorted(dropped):
        cap.warnings.append(f"remote output: too many {what}; the rest was ignored")
    return cap


def _iso(ts: int | None) -> str | None:
    return linux.iso_time(ts)


def remote_executables(cap: linux.Capture, snap: Snapshot) -> int:
    """Facts and package identities computed on the target -> `snap.executables` (in place). Returns how many
    executables got a package identity."""
    osr = linux.os_release_of(snap.os)
    eco = distro_ecosystem(osr, cap.debian_version or None) if osr else None
    dpkg = {p["name"]: p for p in parse_dpkg_status(cap.dpkg_table)} if cap.dpkg_table else {}
    apk_pkgs = {p["name"]: p for p in parse_apk_installed(cap.apk_db)} if cap.apk_db else {}
    paths = {p.exe for p in snap.processes if p.exe}
    apk_files = linux.parse_apk_files(cap.apk_db, {v for p in paths for v in linux._variants(p)}) \
        if cap.apk_db else {}
    owners = linux.dpkg_search_index(cap.dpkg_search) if cap.dpkg_search else {}
    owned = 0
    for path in sorted(paths):
        facts = snap.executables.setdefault(path, {})
        st = cap.files.get(path)
        if st is not None and facts.get("exists") is not False:
            mtime, size, uid, mode = st
            facts.update({"exists": True, "size": size, "owner_uid": uid})
            if (iso := _iso(mtime)) is not None:
                facts["mtime"] = iso
            if mode & 0o002:
                facts["world_writable"] = True
        ident = None
        variants = linux._variants(path)
        if owners:
            names = [n for v in variants for n in owners.get(v, [])]
            for name in names:
                if name in dpkg:
                    c = linux.package_component("deb", dpkg[name], osr, eco)
                    when = cap.dpkg_lists.get(name)
                    ident = linux.identity_of(c, _iso(when) if when else None)
                    break
        elif cap.rpm_owner:
            rows = next((r for v in variants if (r := linux.parse_rpm_query(cap.rpm_owner.get(v, "")))), [])
            if rows:
                ident = linux.identity_of(linux.package_component("rpm", rows[0], osr, eco), rows[0]["install_time"])
        elif apk_files:
            name = next((apk_files[v] for v in variants if v in apk_files), None)
            if name in apk_pkgs:
                ident = linux.identity_of(linux.package_component("apk", apk_pkgs[name], osr, eco))
        if ident is None and path.startswith("/snap/"):
            snapdir = "/".join(path.split("/")[:4])
            if snapdir in cap.snap_versions:
                ident = {"name": path.split("/")[2], "version": cap.snap_versions[snapdir], "category": "application"}
        if ident is not None:
            facts["identity"] = ident
            owned += ident.get("category") == "os-package"
        if not facts:
            snap.executables.pop(path, None)
    return owned


def _read_capped(stream: ssh.Stream, cap: int) -> tuple[bytes, bool]:
    out = bytearray()
    while len(out) <= cap:
        chunk = stream.read(65536)
        if not chunk:
            return bytes(out), False
        out += chunk
    return bytes(out[:cap]), True


def take_remote_snapshot(target: str, **opts: Any) -> Snapshot:
    """`ssh://[user@]host[:port]` -> Snapshot of that Linux host. Options: the ssh collector's (`transport`
    openssh|paramiko|auto or a `Transport` instance, `identity`, `known_hosts`, `insecure_host_key`,
    `connect_timeout`, `ssh_option`, `ssh_bin`, `ssh_config`), `sudo` (`sudo -n`), `timeout` (seconds, default 300),
    `hostname`, and the snapshot options `args`, `kernel_threads`."""
    t = ssh.parse_target(target)
    if opts.get("verbose"):
        ssh._enable_verbose()
    injected = opts.get("transport")
    transport: ssh.Transport = injected if isinstance(injected, ssh.Transport) else ssh.make_transport(t, opts)
    sudo = linux._flag(opts.get("sudo"), False)
    timeout = opts_int(opts, "timeout", DEFAULT_TIMEOUT)
    cmd = "sudo -n sh -s" if sudo else "sh -s"
    log.debug("remote command: %s <<'EOF'\n%sEOF", cmd, SCRIPT)
    try:
        stream = transport.stream(cmd, timeout=timeout, stdin=SCRIPT.encode())
        try:
            data, truncated = _read_capped(stream, MAX_OUTPUT)
        except BaseException:
            stream.finish(abort=True)
            raise
        rc, err = stream.finish(abort=truncated)
    finally:
        if transport is not injected:
            transport.close()
    cap = parse_output(data)
    hint = " (sudo needs a NOPASSWD rule: sudo -n)" if sudo else ""
    if not cap.begun:
        if stream.timed_out:
            raise ssh.SSHError(f"remote process snapshot on {t} timed out after {timeout}s")
        raise ssh.SSHError(f"remote process snapshot on {t} produced nothing (rc={rc}): "
                           f"{ssh._stderr_text(err) or 'no stderr'}{hint}")
    if cap.ostype and cap.ostype.lower() != "linux":
        raise ssh.SSHError(f"remote process snapshot supports Linux only; {t} runs {cap.ostype!r}")
    if not cap.procs:
        raise ssh.SSHError(f"remote process snapshot on {t} listed no processes (no /proc?): "
                           f"{ssh._stderr_text(err) or 'no stderr'}")
    if truncated:
        cap.warnings.append(f"remote output exceeded {MAX_OUTPUT // (1024 * 1024)} MiB and was cut: snapshot partial")
    elif stream.timed_out:
        cap.warnings.append(f"remote process snapshot hit the {timeout}s timeout: snapshot partial")
    elif not cap.complete:
        cap.warnings.append(f"remote output ended early (rc={rc}): snapshot partial")
    if cap.uid not in (0, None):
        cap.warnings.append("remote user is not root: other users' executables and crontabs may be missing "
                            "(-o sudo=true with a NOPASSWD rule)")
    # keyed on the ssh target, not on what the host calls itself: many hosts are `localhost` / `ubuntu`, and a
    # hostile one could name itself after another asset. `-o hostname=` still overrides explicitly.
    host = opts.get("hostname") or ssh.ssh_asset_id(t)
    snap = linux.snapshot_from_capture(cap, opts, host)
    remote_executables(cap, snap)
    snap.source = {k: v for k, v in {"kind": "ssh", "target": str(t), "transport": transport.name, "sudo": sudo,
                                     "boot_id": cap.boot_id or None,
                                     "remote_hostname": cap.hostname or None}.items() if v is not None}
    return snap
