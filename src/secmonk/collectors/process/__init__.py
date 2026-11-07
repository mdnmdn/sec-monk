"""Process / executable monitor: running processes -> launch origin, software identity, provenance.

Layout (see _docs/tech/collectors/process.md):
  model.py      platform-neutral records (ProcessRecord, LaunchItem, LaunchInfo, Snapshot)
  snapshot.py   `secmonk-process-snapshot/1` JSON (offline analysis, fixtures, future agents)
  launch.py     shared launch classification (service / agent / gui-app / interactive / child ...)
  backend.py    backend interface + registry, filesystem-free base Inspector
  macos.py      macOS backend (ps, launchctl, launchd plists, bundles, Homebrew, codesign, quarantine)
  collector.py  the registered `process` collector + risk flags
"""

from . import collector  # noqa: F401  (registers the collector)
