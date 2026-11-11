"""Platform-neutral records of the process monitor.

Every platform backend (macOS and Linux, locally or over ssh; Windows planned, see
_docs/tech/collectors/process.md) produces a `Snapshot`: running processes, the launch items the OS
knows about (launchd plists, systemd units, Windows services / Run keys / scheduled tasks) and,
optionally, precomputed facts about executables. Everything after that (launch classification,
software identity, provenance, risk flags, components) is shared code.

A snapshot is also a file format (`secmonk-process-snapshot/1`, see snapshot.py), so a snapshot taken
on one machine can be analysed on another, and tests run on fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# How a process came to run. Generic kinds, the same on every platform; `LaunchInfo.mechanism`
# carries the platform-specific detail (launchd-daemon, systemd-unit, windows-service ...).
LAUNCH_KERNEL = "kernel"            # pid 0/1, kernel threads, the init system itself
LAUNCH_SERVICE = "service"          # system-wide service (launchd daemon, systemd system unit, Windows service)
LAUNCH_AGENT = "agent"              # per-user background service (launchd agent, systemd --user unit)
LAUNCH_LOGIN_ITEM = "login-item"    # started at login (macOS login item, Windows Run key, XDG autostart)
LAUNCH_SCHEDULED = "scheduled"      # cron, periodic, scheduled task
LAUNCH_GUI_APP = "gui-app"          # launched by the desktop (Finder/Dock/LaunchServices, explorer.exe)
LAUNCH_XPC = "xpc-service"          # on-demand helper of an app/framework (XPC service, COM server)
LAUNCH_INTERACTIVE = "interactive"  # started from a shell in a terminal
LAUNCH_REMOTE = "remote-session"    # started from a shell of a remote session (sshd)
LAUNCH_CHILD = "child"              # spawned by another (non-shell) process
LAUNCH_UNKNOWN = "unknown"
LAUNCH_KINDS = (LAUNCH_KERNEL, LAUNCH_SERVICE, LAUNCH_AGENT, LAUNCH_LOGIN_ITEM, LAUNCH_SCHEDULED, LAUNCH_GUI_APP,
                LAUNCH_XPC, LAUNCH_INTERACTIVE, LAUNCH_REMOTE, LAUNCH_CHILD, LAUNCH_UNKNOWN)


@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    exe: str | None                 # absolute path of the executable image as reported by the OS
    uid: int | None = None
    user: str | None = None
    started: str | None = None      # ISO 8601 (local time as reported when no zone is known)
    args: list[str] = field(default_factory=list)   # redacted (collectors/base.redact_command)
    name: str | None = None         # short name (comm) when `exe` is unknown
    label: str | None = None        # service manager job label when known (launchctl list, systemd unit, service name)
    cgroup: str | None = None       # Linux: control group path (systemd hierarchy) of the process
    container: dict[str, str] | None = None   # Linux: {"runtime": docker|containerd|cri-o|podman|lxc, "id", "pod"?}


@dataclass
class LaunchItem:
    """Something the OS is configured to start: a launchd plist, a systemd unit, a Run key ..."""

    mechanism: str                  # launchd-daemon | launchd-agent | launchd-system-daemon | launchd-system-agent | ...
    label: str
    program: str | None             # executable path (Program or ProgramArguments[0])
    args: list[str] = field(default_factory=list)
    source: str | None = None       # plist / unit / registry path that defines it
    scope: str | None = None        # system | user:<name>
    run_at_load: bool | None = None
    keep_alive: bool | None = None
    disabled: bool | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class LaunchInfo:
    kind: str                       # one of LAUNCH_KINDS
    mechanism: str | None = None    # platform detail: launchd-agent, terminal, sshd, cron, ...
    label: str | None = None        # launch item label / service name
    source: str | None = None       # file that configures the launch (plist path ...)
    parent_exe: str | None = None   # direct parent executable
    via: str | None = None          # the ancestor that explains the kind (Terminal.app, sshd, cron ...)
    evidence: str | None = None     # how it was decided: pid-label | exe-match | ancestry | parent


@dataclass
class Snapshot:
    platform: str                   # darwin | linux | windows
    host: str
    taken_at: str
    processes: list[ProcessRecord]
    launch_items: list[LaunchItem] = field(default_factory=list)
    os: dict[str, Any] = field(default_factory=dict)          # name, version, build
    # Precomputed facts per executable path (signature, quarantine, hashes ...) for snapshots taken
    # elsewhere; a live backend computes them lazily instead.
    executables: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # how the snapshot was taken: {"kind": "local"|"ssh", "target", "transport", "sudo", "boot_id", "remote_hostname"}
    source: dict[str, Any] = field(default_factory=dict)
