"""How did each process start? Shared launch classification over a `Snapshot`.

Evidence, strongest first:

1. ``pid-label``  the service manager names the job that owns the pid (`launchctl list`, systemd unit, service
   name) and the label is a known launch item (or a recognizable family such as LaunchServices'
   ``application.<bundle-id>.<n>.<n>`` labels for GUI apps).
2. ``exe-match``  the executable is the program of a configured launch item.
3. ``parent`` / ``ancestry``  the process tree: a child of init that lives in an app bundle is a GUI app,
   a child of a shell is interactive (remote when an `sshd` is above it, scheduled under `cron`), anything
   else is a child of its parent; `via` names the top ancestor below init that explains it.

Platform differences live in `PlatformHints` (names of init, shells, terminals, schedulers ...), so a
Linux or Windows backend only adds hints and launch items.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .model import (
    LAUNCH_AGENT,
    LAUNCH_CHILD,
    LAUNCH_GUI_APP,
    LAUNCH_INTERACTIVE,
    LAUNCH_KERNEL,
    LAUNCH_LOGIN_ITEM,
    LAUNCH_REMOTE,
    LAUNCH_SCHEDULED,
    LAUNCH_SERVICE,
    LAUNCH_UNKNOWN,
    LAUNCH_XPC,
    LaunchInfo,
    LaunchItem,
    ProcessRecord,
    Snapshot,
)

MAX_DEPTH = 64

MECHANISM_KIND = {
    "launchd-daemon": LAUNCH_SERVICE,
    "launchd-system-daemon": LAUNCH_SERVICE,
    "launchd-agent": LAUNCH_AGENT,
    "launchd-system-agent": LAUNCH_AGENT,
    "launchd-user-agent": LAUNCH_AGENT,
    "launchd-app-agent": LAUNCH_AGENT,      # macOS: plist inside an app bundle (SMAppService)
    "launchd-app-daemon": LAUNCH_SERVICE,
    "login-item": LAUNCH_LOGIN_ITEM,
    # Linux
    "systemd-system": LAUNCH_SERVICE,
    "systemd-user": LAUNCH_AGENT,
    "systemd-timer": LAUNCH_SCHEDULED,      # a service started by a .timer unit
    "xdg-autostart": LAUNCH_LOGIN_ITEM,
    "cron": LAUNCH_SCHEDULED,
    # planned backends (see _docs/tech/collectors/process.md)
    "windows-service": LAUNCH_SERVICE,
    "run-key": LAUNCH_LOGIN_ITEM,
    "startup-folder": LAUNCH_LOGIN_ITEM,
    "scheduled-task": LAUNCH_SCHEDULED,
}


@dataclass
class PlatformHints:
    init_pids: frozenset[int] = frozenset({1})
    kernel_pids: frozenset[int] = frozenset({0})
    shells: frozenset[str] = frozenset({"sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "nu",
                                        "login", "su", "sudo", "doas", "-sh", "-bash", "-zsh"})
    remote: frozenset[str] = frozenset({"sshd", "sshd-session", "mosh-server", "tailscaled"})
    schedulers: frozenset[str] = frozenset({"cron", "crond", "atd", "atrun", "periodic", "anacron"})
    terminals: frozenset[str] = frozenset({"terminal", "iterm2", "tmux", "screen", "alacritty", "kitty",
                                           "wezterm-gui", "warp", "ghostty", "hyper", "tabby", "code helper",
                                           "gnome-terminal-server", "konsole", "xterm"})
    app_bundle: re.Pattern[str] | None = None        # executable inside a GUI app bundle
    xpc_bundle: re.Pattern[str] | None = None        # executable inside an XPC service bundle
    gui_label: re.Pattern[str] | None = None         # service-manager label of a desktop-launched app
    gui_launchers: frozenset[str] = field(default_factory=frozenset)  # Finder, Dock, explorer.exe ...
    # programs never attributed to a launch item by path alone (see LaunchClassifier._generic_program)
    generic_programs: frozenset[str] = frozenset({"env", "nohup", "caffeinate", "open", "xargs", "timeout"})
    consoles: frozenset[str] = frozenset({"login", "getty", "agetty"})   # a local console session above a shell
    instance_suffix: re.Pattern[str] | None = None   # per-instance label suffix to strip before the plist lookup
    kthread_parents: frozenset[int] = frozenset()    # children of these pids without an executable are kernel threads
    # parents of a container's first process (a process below one of them is attributed to its container)
    container_shims: frozenset[str] = frozenset()
    # labels that name no launch item but say how the process started: (pattern, kind, mechanism), first match wins
    label_kinds: tuple[tuple[re.Pattern[str], str, str], ...] = ()
    # cgroup path -> service-manager unit the process belongs to (Linux). When known, a process is attributed to a
    # unit's launch item by executable only if it runs inside that unit (a container's nginx is not the host's
    # nginx.service, an sshd session process is not ssh.service)
    cgroup_unit: Callable[[str], str | None] | None = None


DARWIN = PlatformHints(
    app_bundle=re.compile(r"\.app/Contents/MacOS/[^/]+$"),
    xpc_bundle=re.compile(r"\.(?:xpc|appex)/Contents/MacOS/[^/]+$"),   # app extensions are XPC services too
    # application.<bundle id>.<n>.<n>, optionally .<UUID> (macOS 26.5: apps relaunched by the system, e.g. after an update)
    gui_label=re.compile(r"^application\.[^/]+\.\d+\.\d+(?:\.[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})?$"),
    gui_launchers=frozenset({"finder", "dock", "launchservicesd", "loginwindow"}),
    # launchd instance jobs: com.apple.loginwindow.<UUID>, com.apple.metadata.mds.index.<UUID> (macOS 26.5)
    instance_suffix=re.compile(r"\.[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"),
)
def systemd_unit(cgroup: str) -> str | None:
    """Innermost `.service` / `.scope` / `.socket` of a cgroup path; the `systemd --user` manager itself sits in
    `user@<uid>.service/init.scope` and belongs to `user@<uid>.service`."""
    segs = [s for s in cgroup.split("/") if s]
    idx = next((i for i in range(len(segs) - 1, -1, -1) if segs[i].endswith((".service", ".scope", ".socket"))),
               None)
    if idx is None:
        return None
    if segs[idx] == "init.scope" and idx > 0 and segs[idx - 1].endswith(".service"):
        idx -= 1
    return segs[idx]


LINUX = PlatformHints(
    kernel_pids=frozenset({0, 2}),                   # 2 = kthreadd
    kthread_parents=frozenset({2}),
    terminals=PlatformHints.terminals | frozenset({
        "gnome-terminal-server", "kgx", "ptyxis-agent", "konsole", "xfce4-terminal", "tilix", "terminator", "foot",
        "mate-terminal", "lxterminal", "qterminal", "urxvt", "st", "code", "tmux: server"}),
    gui_launchers=frozenset({"gnome-shell", "plasmashell", "kwin_wayland", "kwin_x11", "xfce4-panel", "xfdesktop",
                             "lxpanel", "mate-panel", "cinnamon", "budgie-panel"}),
    generic_programs=PlatformHints.generic_programs | frozenset({"systemd-run", "setsid", "flock", "run-parts",
                                                                 "ionice", "nice", "chrt", "runuser"}),
    consoles=frozenset({"login", "getty", "agetty", "mingetty"}),
    # template instances: getty@tty1.service -> getty@.service
    instance_suffix=re.compile(r"(?<=@)[^@/]+(?=\.(?:service|socket|timer)$)"),
    container_shims=frozenset({"containerd-shim", "containerd-shim-runc-v1", "containerd-shim-runc-v2",
                               "docker-containerd-shim", "conmon", "containerd-shim-kata-v2", "lxc-start"}),
    label_kinds=(
        # systemd-xdg-autostart-generator: app-<desktop>-<id>@autostart.service
        (re.compile(r"^app-.+@autostart\.service$"), LAUNCH_LOGIN_ITEM, "xdg-autostart"),
        # apps started by the desktop (GNOME, KDE) run in their own transient scope: app-<launcher>-<id>-<n>.scope
        (re.compile(r"^app-.+\.scope$"), LAUNCH_GUI_APP, "desktop"),
    ),
    cgroup_unit=systemd_unit,
)
GENERIC = PlatformHints()


def hints_for(platform: str) -> PlatformHints:
    return {"darwin": DARWIN, "linux": LINUX}.get(platform, GENERIC)


def _base(p: ProcessRecord | None) -> str:
    if p is None:
        return ""
    name = posixpath.basename(p.exe) if p.exe else (p.name or "")
    return name.lower()


def _bundle_name(p: ProcessRecord) -> str:
    """'Terminal' for /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal."""
    m = re.search(r"/([^/]+)\.app/Contents/MacOS/[^/]+$", p.exe or "")
    return (m.group(1) if m else _base(p)).lower()


class LaunchClassifier:
    def __init__(self, snap: Snapshot, hints: PlatformHints | None = None):
        self.snap = snap
        self.h = hints or hints_for(snap.platform)
        self.by_pid = {p.pid: p for p in snap.processes}
        self.items_by_label: dict[str, list[LaunchItem]] = {}
        self.items_by_program: dict[str, list[LaunchItem]] = {}
        for it in snap.launch_items:
            self.items_by_label.setdefault(it.label, []).append(it)
            if it.program:
                self.items_by_program.setdefault(it.program, []).append(it)

    # ------------------------------------------------------------------ public
    def classify(self, p: ProcessRecord) -> LaunchInfo:
        parent = self.by_pid.get(p.ppid)
        parent_exe = parent.exe if parent else None
        if p.pid in self.h.kernel_pids or p.pid in self.h.init_pids:
            return LaunchInfo(LAUNCH_KERNEL, mechanism="init", evidence="pid")
        if p.ppid in self.h.kthread_parents and not p.exe:
            return LaunchInfo(LAUNCH_KERNEL, mechanism="kernel-thread", parent_exe=parent_exe, evidence="parent")

        if p.label:
            info = self._from_label(p, parent_exe)
            if info:
                return info
        items = self._exe_items(p)
        if items:
            it = self._pick(items, p)
            return self._from_item(it, parent_exe, "exe-match")
        return self._from_tree(p, parent)

    def ancestors(self, p: ProcessRecord) -> list[ProcessRecord]:
        """Parents of `p`, nearest first (cycle-safe, capped)."""
        out: list[ProcessRecord] = []
        seen = {p.pid}
        cur = self.by_pid.get(p.ppid)
        while cur is not None and cur.pid not in seen and len(out) < MAX_DEPTH:
            out.append(cur)
            seen.add(cur.pid)
            cur = self.by_pid.get(cur.ppid)
        return out

    # ------------------------------------------------------------------ helpers
    def _exe_items(self, p: ProcessRecord) -> list[LaunchItem]:
        """Launch items whose program is the executable of `p` and that can have started it."""
        if not p.exe or self._generic_program(p.exe):
            return []
        return [it for it in self.items_by_program.get(p.exe, []) if self._can_have_started(it, p)]

    def _strip(self, label: str) -> str:
        return self.h.instance_suffix.sub("", label) if self.h.instance_suffix is not None else label

    def _can_have_started(self, it: LaunchItem, p: ProcessRecord) -> bool:
        if it.mechanism.startswith("systemd") and self.h.cgroup_unit is not None and p.cgroup:
            unit = self.h.cgroup_unit(p.cgroup)
            if unit is not None and self._strip(unit) != self._strip(it.label):
                return False            # the process runs in another unit / session scope / container
        if it.mechanism == "cron":
            # a crontab line runs its program under cron: the same binary started from a shell is not that job
            return any(_base(a) in self.h.schedulers for a in self.ancestors(p))
        return True

    def _generic_program(self, exe: str) -> bool:
        """Shells, interpreters and `env` run many unrelated things: a plist whose program is `/bin/sh` must not
        claim every shell on the machine (only a pid label can attribute those)."""
        from .backend import INTERPRETERS

        b = _base(ProcessRecord(0, 0, exe))
        return b in self.h.shells or b in self.h.generic_programs or bool(INTERPRETERS.match(b))

    @staticmethod
    def _pick(items: list[LaunchItem], p: ProcessRecord) -> LaunchItem:
        """Several plists may run the same program (one per user, or a daemon and an agent): prefer the scope of
        the process, then a plist that names its user, then a service for root and an agent for anyone else (a daemon
        without `UserName` runs as root; macOS 26.5: cfprefsd has both, the agent runs per user, `_locationd` too)."""
        if len(items) > 1 and p.user:
            for it in items:
                if it.scope == f"user:{p.user}":
                    return it
            if p.uid == 0:
                for it in items:
                    if it.scope == "system" and MECHANISM_KIND.get(it.mechanism) != LAUNCH_AGENT:
                        return it
            else:
                for it in items:
                    if it.meta.get("UserName") == p.user:
                        return it
                for it in items:
                    if MECHANISM_KIND.get(it.mechanism) == LAUNCH_AGENT:
                        return it
        return items[0]

    def _from_item(self, it: LaunchItem, parent_exe: str | None, evidence: str) -> LaunchInfo:
        kind = MECHANISM_KIND.get(it.mechanism, LAUNCH_UNKNOWN)
        return LaunchInfo(kind, mechanism=it.mechanism, label=it.label, source=it.source,
                          parent_exe=parent_exe, evidence=evidence)

    def _from_label(self, p: ProcessRecord, parent_exe: str | None) -> LaunchInfo | None:
        label = p.label or ""
        items = self.items_by_label.get(label)
        if not items and self.h.instance_suffix is not None:
            items = self.items_by_label.get(self.h.instance_suffix.sub("", label))
        if items:
            # one label can be both a system daemon and a per-user agent (com.apple.lsd, cloudd, ctkd ...)
            return self._from_item(self._pick(items, p), parent_exe, "pid-label")
        # a label that names no plist (login-item helpers run as `<TeamID>.<bundle id>`) but an executable that is
        # a launch item's program: that item
        exe_items = self._exe_items(p)
        if exe_items:
            return self._from_item(self._pick(exe_items, p), parent_exe, "exe-match")
        if self.h.gui_label and self.h.gui_label.match(label):
            return LaunchInfo(LAUNCH_GUI_APP, mechanism="launchservices", label=label, parent_exe=parent_exe,
                              evidence="pid-label")
        for pattern, kind, mechanism in self.h.label_kinds:
            if pattern.match(label):
                return LaunchInfo(kind, mechanism=mechanism, label=label, parent_exe=parent_exe, evidence="pid-label")
        if self.h.xpc_bundle and p.exe and self.h.xpc_bundle.search(p.exe):
            return LaunchInfo(LAUNCH_XPC, mechanism="xpc", label=label, parent_exe=parent_exe, evidence="pid-label")
        # a job without a plist on disk (submitted at runtime, or a plist we could not read)
        kind = LAUNCH_SERVICE if p.uid == 0 else LAUNCH_AGENT
        return LaunchInfo(kind, mechanism="service-manager", label=label, parent_exe=parent_exe,
                          evidence="pid-label")

    def _from_tree(self, p: ProcessRecord, parent: ProcessRecord | None) -> LaunchInfo:
        parent_exe = parent.exe if parent else None
        if parent is None:
            return LaunchInfo(LAUNCH_UNKNOWN, parent_exe=None, evidence="parent")
        exe = p.exe or ""
        if parent.pid in self.h.init_pids:
            if self.h.xpc_bundle and self.h.xpc_bundle.search(exe):
                return LaunchInfo(LAUNCH_XPC, mechanism="xpc", parent_exe=parent_exe, evidence="parent")
            if self.h.app_bundle and self.h.app_bundle.search(exe):
                return LaunchInfo(LAUNCH_GUI_APP, mechanism="launchservices", parent_exe=parent_exe,
                                  evidence="parent")
            kind = LAUNCH_SERVICE if p.uid == 0 else LAUNCH_AGENT
            return LaunchInfo(kind, mechanism="init", parent_exe=parent_exe, evidence="parent")

        chain = self.ancestors(p)
        pbase = _base(parent)
        if pbase in self.h.schedulers:
            return LaunchInfo(LAUNCH_SCHEDULED, mechanism=pbase, parent_exe=parent_exe, via=parent.exe,
                              evidence="parent")
        if pbase in self.h.shells or pbase.lstrip("-") in self.h.shells:
            console = None
            for a in chain:
                b = _base(a)
                if b in self.h.remote:
                    return LaunchInfo(LAUNCH_REMOTE, mechanism=b, parent_exe=parent_exe, via=a.exe,
                                      evidence="ancestry")
                if b in self.h.schedulers:
                    return LaunchInfo(LAUNCH_SCHEDULED, mechanism=b, parent_exe=parent_exe, via=a.exe,
                                      evidence="ancestry")
                if b in self.h.terminals or _bundle_name(a) in self.h.terminals:
                    return LaunchInfo(LAUNCH_INTERACTIVE, mechanism="terminal", parent_exe=parent_exe,
                                      via=a.exe, evidence="ancestry")
                if b in self.h.consoles:
                    console = console or a
            if console is not None:
                return LaunchInfo(LAUNCH_INTERACTIVE, mechanism=_base(console), parent_exe=parent_exe,
                                  via=console.exe, evidence="ancestry")
            # `sh -c` spawned by a daemon, an app or an updater: not interactive, a child of whatever owns the tree
        if pbase in self.h.gui_launchers:
            return LaunchInfo(LAUNCH_GUI_APP, mechanism=pbase, parent_exe=parent_exe, evidence="parent")
        if self.h.container_shims:
            shim = next((a for a in chain if _base(a) in self.h.container_shims), None)
            if shim is not None:
                cid = (p.container or {}).get("id")
                return LaunchInfo(LAUNCH_CHILD, mechanism="container", label=cid[:12] if cid else None,
                                  parent_exe=parent_exe, via=shim.exe, evidence="ancestry")
        # child of another process: name the top ancestor below init (the app / service that owns the tree)
        top = parent
        for a in chain:
            if a.pid in self.h.init_pids or a.pid in self.h.kernel_pids:
                break
            top = a
        return LaunchInfo(LAUNCH_CHILD, mechanism="spawn", parent_exe=parent_exe,
                          via=top.exe if top is not parent else None, evidence="parent")
