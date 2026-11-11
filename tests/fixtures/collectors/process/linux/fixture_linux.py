"""Synthetic Linux machine for the process monitor's Linux backend (see README.md in this folder).

`build_root(dest)` writes a Debian 12 tree with a `/proc` (stat, status, cmdline, cgroup, exe links), systemd units,
XDG autostart files, crontabs, a dpkg database with file lists, a snap and placeholder executables (the Go fixture
binary is copied in as /usr/local/bin/backup). `fake_bin(dest)` writes stand-ins for the GNU/Debian tools the remote
script calls (`stat -c`, `dpkg-query`, `id`) so the real script runs on any POSIX host against the tree.

`python fixture_linux.py --capture` regenerates `remote-output.txt` (the script's output on this tree).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[2]                      # tests/fixtures
BTIME = 1794290400                              # 2026-11-10T06:00:00Z
CLK_TCK = 100
CONTAINER_ID = "4f1c" + "0" * 56 + "beef"
PF_KTHREAD = 0x00200000

# pid, ppid, comm, uid, exe link target (None = no link), cgroup v2 path, cmdline argv, starttime ticks, flags
PROCS = [
    (1, 0, "systemd", 0, "/usr/lib/systemd/systemd", "/init.scope", ["/sbin/init", "splash"], 100, 0),
    (2, 0, "kthreadd", 0, None, "/", [], 100, PF_KTHREAD),
    (3, 2, "kworker/0:0-events", 0, None, "/", [], 101, PF_KTHREAD),
    (210, 1, "sshd", 0, "/usr/sbin/sshd", "/system.slice/ssh.service",
     ["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"], 1500, 0),
    (211, 1, "nginx", 0, "/usr/sbin/nginx", "/system.slice/nginx.service",
     ["nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"], 1600, 0),
    (212, 211, "nginx", 33, "/usr/sbin/nginx", "/system.slice/nginx.service", ["nginx: worker process"], 1601, 0),
    (300, 1, "cron", 0, "/usr/sbin/cron", "/system.slice/cron.service", ["/usr/sbin/cron", "-f"], 1700, 0),
    (301, 300, "cron", 0, "/usr/sbin/cron", "/system.slice/cron.service", ["/usr/sbin/CRON", "-f"], 90000, 0),
    (302, 301, "sh", 0, "/usr/bin/dash", "/system.slice/cron.service",
     ["/bin/sh", "-c", "test -x /usr/local/bin/backup && /usr/local/bin/backup --token=abc123"], 90001, 0),
    (303, 302, "backup", 0, "/usr/local/bin/backup", "/system.slice/cron.service",
     ["/usr/local/bin/backup", "--token=abc123"], 90002, 0),
    (400, 210, "sshd", 0, "/usr/sbin/sshd", "/user.slice/user-1000.slice/session-3.scope",
     ["sshd: alice [priv]"], 80000, 0),
    (401, 400, "sshd", 1000, "/usr/sbin/sshd", "/user.slice/user-1000.slice/session-3.scope",
     ["sshd: alice@pts/0"], 80001, 0),
    (402, 401, "bash", 1000, "/usr/bin/bash", "/user.slice/user-1000.slice/session-3.scope", ["-bash"], 80002, 0),
    (403, 402, "tool (x) y", 1000, "/home/alice/bin/tool", "/user.slice/user-1000.slice/session-3.scope",
     ["/home/alice/bin/tool", "--password", "hunter2", "a b"], 80100, 0),
    (404, 1, "olddaemon", 0, "/usr/bin/olddaemon (deleted)", "/system.slice/olddaemon.service",
     ["/usr/bin/olddaemon"], 2000, 0),
    (500, 1, "systemd", 1000, "/usr/lib/systemd/systemd",
     "/user.slice/user-1000.slice/user@1000.service/init.scope", ["/lib/systemd/systemd", "--user"], 70000, 0),
    (501, 500, "syncthing", 1000, "/usr/bin/syncthing",
     "/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service",
     ["/usr/bin/syncthing", "serve", "--no-browser"], 70100, 0),
    (502, 500, "firefox", 1000, "/snap/firefox/5000/usr/lib/firefox/firefox",
     "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox_firefox-4321.scope",
     ["/snap/firefox/5000/usr/lib/firefox/firefox"], 70200, 0),
    (503, 502, "Isolated Web Co", 1000, "/snap/firefox/5000/usr/lib/firefox/firefox",
     "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox_firefox-4321.scope",
     ["/snap/firefox/5000/usr/lib/firefox/firefox", "-contentproc"], 70300, 0),
    (504, 500, "nm-applet", 1000, "/usr/bin/nm-applet",
     "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-nm\\x2dapplet@autostart.service",
     ["nm-applet"], 70400, 0),
    (600, 1, "containerd-shim", 0, "/usr/bin/containerd-shim-runc-v2", "/system.slice/containerd.service",
     ["/usr/bin/containerd-shim-runc-v2", "-namespace", "moby", "-id", CONTAINER_ID], 3000, 0),
    (601, 600, "nginx", 0, "/usr/sbin/nginx", f"/system.slice/docker-{CONTAINER_ID}.scope",
     ["nginx: master process nginx -g daemon off;"], 3001, 0),
    (700, 1, "agetty", 0, "/usr/sbin/agetty", "/system.slice/system-getty.slice/getty@tty1.service",
     ["/sbin/agetty", "-o", "-p -- \\u", "--noclear", "-", "linux"], 1800, 0),
    (701, 1, "logrotate", 0, "/usr/sbin/logrotate", "/system.slice/logrotate.service",
     ["/usr/sbin/logrotate", "/etc/logrotate.conf"], 95000, 0),
    # a service confined to another root directory (RootDirectory= / chroot): same cgroup kind, other filesystem
    (702, 1, "named", 0, "/usr/sbin/named", "/system.slice/named.service", ["/usr/sbin/named", "-f"], 96000, 0),
    # setproctitle(): one argument holding the whole title, with a secret in it
    (703, 1, "worker", 0, "/usr/bin/dash", "/system.slice/worker.service",
     ["worker --api-key=K3Y --queue jobs"], 97000, 0),
    (704, 211, "nginx", 33, None, "/system.slice/nginx.service", [], 98000, 0),         # zombie (state Z)
]
ZOMBIES = {704}
CHROOTED = {702: "srv/named-chroot"}

DPKG = {   # package -> (version, source line or None, files)
    "openssh-server": ("1:9.2p1-2+deb12u3", "openssh", ["/usr/sbin/sshd"]),
    "nginx-core": ("1.22.1-9", "nginx", ["/usr/sbin/nginx"]),
    "cron": ("3.0pl1-162", None, ["/usr/sbin/cron"]),
    "bash": ("5.2.15-2+b7", None, ["/bin/bash"]),                     # merged-/usr: process runs /usr/bin/bash
    "dash": ("0.5.12-2", None, ["/bin/dash"]),
    "systemd": ("252.30-1~deb12u2", None, ["/lib/systemd/systemd"]),
    "util-linux": ("2.38.1-5+deb12u1", None, ["/sbin/agetty"]),
    "logrotate": ("3.21.0-1", None, ["/usr/sbin/logrotate"]),
    "syncthing": ("1.19.2~ds1-1+b4", None, ["/usr/bin/syncthing"]),
    "network-manager-gnome": ("1.30.0-2", None, ["/usr/bin/nm-applet"]),
    "libc6": ("2.36-9+deb12u8", "glibc", ["/lib/x86_64-linux-gnu/libc.so.6"]),
}
LIST_MTIME = 1790000000                         # 2026-09-21T...: install time of every package

UNITS = {
    "lib/systemd/system/ssh.service": "[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\n"
                                      "ExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n",
    "lib/systemd/system/nginx.service": "[Service]\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'\n",
    "etc/systemd/system/nginx.service": "[Unit]\nDescription=nginx (local override)\n[Service]\nType=forking\n"
                                        "ExecStart=\nExecStart=/usr/sbin/nginx \\\n  -g 'daemon on;'\n",
    "lib/systemd/system/cron.service": "[Service]\nExecStart=/usr/sbin/cron -f $EXTRA_OPTS\n",
    "lib/systemd/system/getty@.service": "[Service]\nExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear - $TERM\n",
    "lib/systemd/system/logrotate.service": "[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.conf\n",
    "lib/systemd/system/logrotate.timer": "[Timer]\nOnCalendar=daily\n",
    "lib/systemd/system/olddaemon.service": "[Service]\nExecStart=/usr/bin/olddaemon\n",
    "lib/systemd/system/containerd.service": "[Service]\nExecStart=/usr/bin/containerd\n",
    "lib/systemd/system/user@.service": "[Service]\nUser=%i\nExecStart=/lib/systemd/systemd --user\n",
    "etc/systemd/system/stale-agent.service": "[Service]\nExecStart=@/opt/gone/bin/agent agent --api-key=SECRETKEY\n",
    "home/alice/.config/systemd/user/syncthing.service": "[Service]\nExecStart=/usr/bin/syncthing serve --no-browser\n",
}
AUTOSTART = {
    "etc/xdg/autostart/nm-applet.desktop": "[Desktop Entry]\nName=Network\nExec=nm-applet\n",
    "etc/xdg/autostart/disabled.desktop": "[Desktop Entry]\nExec=/usr/bin/true\nX-GNOME-Autostart-enabled=false\n",
    "home/alice/.config/autostart/updater.desktop": "[Desktop Entry]\nName=Updater\n"
                                                    "Exec=/home/alice/.cache/upd/updater --quiet %u\n",
}
CRONTABS = {
    "etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                   "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n",
    "etc/cron.d/backup": "# nightly\n*/5 * * * * root test -x /usr/local/bin/backup && /usr/local/bin/backup "
                         "--token=abc123\n",
    "var/spool/cron/crontabs/alice": "@reboot /home/alice/bin/tool --daemon\n",
}
EXECUTABLES = ["usr/lib/systemd/systemd", "usr/sbin/sshd", "usr/sbin/nginx", "usr/sbin/cron", "usr/bin/bash",
               "usr/bin/dash", "home/alice/bin/tool", "usr/bin/olddaemon", "usr/bin/syncthing", "usr/bin/nm-applet",
               "usr/bin/containerd-shim-runc-v2", "usr/sbin/agetty", "usr/sbin/logrotate",
               "snap/firefox/5000/usr/lib/firefox/firefox"]


def _w(root: Path, rel: str, data: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        p.write_bytes(data)
    else:
        p.write_text(data)
    return p


def build_root(dest: Path) -> Path:
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    # /usr-merged layout: /bin, /sbin, /lib are links into /usr
    for d in ("usr/bin", "usr/sbin", "usr/lib"):
        (root / d).mkdir(parents=True, exist_ok=True)
    for name in ("bin", "sbin", "lib"):
        os.symlink(f"usr/{name}", root / name)
    _w(root, "proc/stat", f"cpu  1 2 3 4\nintr 0\nbtime {BTIME}\nprocesses 1000\n")
    _w(root, "proc/sys/kernel/ostype", "Linux\n")
    _w(root, "proc/sys/kernel/hostname", "fixture-linux\n")
    _w(root, "proc/sys/kernel/random/boot_id", "0f0e0d0c-0b0a-4908-8706-050403020100\n")
    for pid, ppid, comm, uid, exe, cg, argv, start, flags in PROCS:
        d = f"proc/{pid}"
        fields = ["Z" if pid in ZOMBIES else "S", str(ppid), str(pid), str(pid), "0", "-1", str(flags)] + ["0"] * 12 + [str(start)] + ["0"] * 30
        _w(root, f"{d}/stat", f"{pid} ({comm}) {' '.join(fields)}\n")
        _w(root, f"{d}/status", f"Name:\t{comm[:15]}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{pid}\n"
                                f"PPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        _w(root, f"{d}/cmdline", b"".join(a.encode() + b"\0" for a in argv))
        _w(root, f"{d}/cgroup", f"0::{cg}\n")
        if exe:
            os.symlink(exe, root / d / "exe")
        own_root = CHROOTED.get(pid, "")
        (root / own_root).mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(root / own_root, root / d), root / d / "root")   # what /proc/<pid>/root shows
    _w(root, "etc/os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
                               'VERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian\n')
    _w(root, "etc/debian_version", "12.7\n")
    _w(root, "etc/hostname", "fixture-linux\n")
    _w(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                           "alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash\n")
    status = []
    for pkg, (ver, src, files) in DPKG.items():
        status.append(f"Package: {pkg}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {ver}\n"
                      + (f"Source: {src}\n" if src else "") + "\n")
        name = "libc6:amd64" if pkg == "libc6" else pkg
        lst = _w(root, f"var/lib/dpkg/info/{name}.list", "/.\n/usr\n" + "".join(f + "\n" for f in files))
        os.utime(lst, (LIST_MTIME, LIST_MTIME))
    _w(root, "var/lib/dpkg/status", "".join(status))
    for rel, text in {**UNITS, **AUTOSTART, **CRONTABS}.items():
        _w(root, rel, text)
    os.symlink("/dev/null", root / "etc/systemd/system/masked.service")
    for rel in EXECUTABLES:
        p = _w(root, rel, f"placeholder for /{rel}\n")
        p.chmod(0o755)
    (root / "home/alice/bin/tool").chmod(0o777)                         # world-writable
    (root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "lang/go/hello-linux-amd64", root / "usr/local/bin/backup")
    # a user's autostart entry that is a symlink to a root-only file: never read
    os.symlink("/etc/shadow-fixture", root / "home/alice/.config/autostart/evil.desktop")
    _w(root, "etc/shadow-fixture", "[Desktop Entry]\nExec=/secret/from/shadow\n")
    _w(root, "usr/sbin/named", "placeholder\n")
    _w(root, "snap/firefox/5000/meta/snap.yaml", "name: firefox\nversion: 132.0-1\nsummary: x\n")
    return root


FAKE_STAT = r"""#!/bin/sh
# stand-in for GNU `stat [-L] -c FMT -- FILE...` (BSD stat has no -c): fixed times, real size, mode and inode
fmt=
while [ $# -gt 0 ]; do
  case $1 in -c) fmt=$2; shift 2 ;; -L) shift ;; --) shift; break ;; *) break ;; esac
done
rc=0
for f in "$@"; do
  [ -e "$f" ] || { rc=1; continue; }
  case $fmt in
    '%Y %n') echo "1790000000 $f" ;;
    '%d:%i') echo "1:$(ls -id "$f/" | awk '{print $1}')" ;;
    *) mode=755; [ "$(ls -l "$f" | cut -c9)" = w ] && mode=777
       echo "1790000000 $(wc -c < "$f" | tr -d ' ') 0 $mode" ;;
  esac
done
exit $rc
"""
FAKE_ID = "#!/bin/sh\necho 1000\n"


def fake_bin(dest: Path) -> Path:
    """Fake `stat`, `id` and `dpkg-query` (answers from DPKG) for running the remote script on the fixture tree."""
    dest.mkdir(parents=True, exist_ok=True)
    owners = "\n".join(f"    {f}) echo '{pkg}{':amd64' if pkg == 'libc6' else ''}: {f}' ;;"
                       for pkg, (_, _, files) in DPKG.items() for f in files)
    table = "".join(f"Package: {pkg}\\nVersion: {ver}\\nArchitecture: amd64\\nSource: {src or ''}\\n"
                    f"Status: install ok installed\\n\\n" for pkg, (ver, src, _) in DPKG.items())
    dpkg = (f"#!/bin/sh\ncase $1 in\n  -W) printf '{table}' ;;\n  -S)\n    shift 2; rc=0\n"
            f"    for a in \"$@\"; do\n    case $a in\n{owners}\n"
            "    *) echo \"dpkg-query: no path found matching pattern $a\" >&2; rc=1 ;;\n    esac\n    done\n"
            "    exit $rc ;;\nesac\n")
    for name, text in (("stat", FAKE_STAT), ("id", FAKE_ID), ("dpkg-query", dpkg)):
        p = dest / name
        p.write_text(text)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def run_script(script: str, root: Path, fakebin: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    """The remote script with its root prefix pointed at `root`, run by the local `sh`."""
    text = script.replace("\nR=''\n", f"\nR='{root}'\n", 1)
    env = {**os.environ, "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}"}
    return subprocess.run(["sh", "-s"], input=text.encode(), capture_output=True, timeout=timeout, env=env,
                          check=False)


if __name__ == "__main__" and "--capture" in sys.argv:
    sys.path.insert(0, str(FIXTURES.parents[1] / "src"))
    from secmonk.collectors.process.remote import SCRIPT

    with tempfile.TemporaryDirectory() as td:
        r = run_script(SCRIPT, build_root(Path(td) / "root"), fake_bin(Path(td) / "bin"))
        (HERE / "remote-output.txt").write_bytes(r.stdout)
        print(f"wrote remote-output.txt ({len(r.stdout)} bytes, rc={r.returncode})")
