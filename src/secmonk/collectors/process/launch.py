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
    "login-item": LAUNCH_LOGIN_ITEM,
    # planned backends (see _docs/tech/collectors/process.md)
    "systemd-system": LAUNCH_SERVICE,
    "systemd-user": LAUNCH_AGENT,
    "xdg-autostart": LAUNCH_LOGIN_ITEM,
    "cron": LAUNCH_SCHEDULED,
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


DARWIN = PlatformHints(
    app_bundle=re.compile(r"\.app/Contents/MacOS/[^/]+$"),
    xpc_bundle=re.compile(r"\.xpc/Contents/MacOS/[^/]+$"),
    gui_label=re.compile(r"^application\.[^/]+\.\d+\.\d+$"),
    gui_launchers=frozenset({"finder", "dock", "launchservicesd", "loginwindow"}),
)
GENERIC = PlatformHints()


def hints_for(platform: str) -> PlatformHints:
    return DARWIN if platform == "darwin" else GENERIC


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
        self.items_by_label: dict[str, LaunchItem] = {}
        self.items_by_program: dict[str, list[LaunchItem]] = {}
        for it in snap.launch_items:
            self.items_by_label.setdefault(it.label, it)
            if it.program:
                self.items_by_program.setdefault(it.program, []).append(it)

    # ------------------------------------------------------------------ public
    def classify(self, p: ProcessRecord) -> LaunchInfo:
        parent = self.by_pid.get(p.ppid)
        parent_exe = parent.exe if parent else None
        if p.pid in self.h.kernel_pids or p.pid in self.h.init_pids:
            return LaunchInfo(LAUNCH_KERNEL, mechanism="init", evidence="pid")

        if p.label:
            info = self._from_label(p, parent_exe)
            if info:
                return info
        items = self.items_by_program.get(p.exe or "")
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
    @staticmethod
    def _pick(items: list[LaunchItem], p: ProcessRecord) -> LaunchItem:
        """Several plists may run the same program (one per user): prefer the scope of the process."""
        if len(items) > 1 and p.user:
            for it in items:
                if it.scope == f"user:{p.user}":
                    return it
            if p.uid == 0:
                for it in items:
                    if it.scope == "system":
                        return it
        return items[0]

    def _from_item(self, it: LaunchItem, parent_exe: str | None, evidence: str) -> LaunchInfo:
        kind = MECHANISM_KIND.get(it.mechanism, LAUNCH_UNKNOWN)
        return LaunchInfo(kind, mechanism=it.mechanism, label=it.label, source=it.source,
                          parent_exe=parent_exe, evidence=evidence)

    def _from_label(self, p: ProcessRecord, parent_exe: str | None) -> LaunchInfo | None:
        label = p.label or ""
        it = self.items_by_label.get(label)
        if it:
            return self._from_item(it, parent_exe, "pid-label")
        if self.h.gui_label and self.h.gui_label.match(label):
            return LaunchInfo(LAUNCH_GUI_APP, mechanism="launchservices", label=label, parent_exe=parent_exe,
                              evidence="pid-label")
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
            for a in chain[1:]:
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
            return LaunchInfo(LAUNCH_INTERACTIVE, mechanism="shell", parent_exe=parent_exe, evidence="ancestry")
        if pbase in self.h.gui_launchers:
            return LaunchInfo(LAUNCH_GUI_APP, mechanism=pbase, parent_exe=parent_exe, evidence="parent")
        # child of another process: name the top ancestor below init (the app / service that owns the tree)
        top = parent
        for a in chain:
            if a.pid in self.h.init_pids or a.pid in self.h.kernel_pids:
                break
            top = a
        return LaunchInfo(LAUNCH_CHILD, mechanism="spawn", parent_exe=parent_exe,
                          via=top.exe if top is not parent else None, evidence="parent")
