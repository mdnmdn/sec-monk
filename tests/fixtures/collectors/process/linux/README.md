# Process collector fixtures: Linux backend (synthetic)

Hand-made from documented formats (proc(5), systemd.unit(5), systemd.service(5), the XDG autostart and desktop entry
specs, crontab(5), dpkg-query(1), rpm(8) query formats); **not** captured on a real Linux host yet (see
`_docs/plans/on-linux-docker.md` section F). Used by `tests/collectors/test_process_linux.py`.

| File | What | Format source |
|---|---|---|
| `fixture_linux.py` | builds a Debian 12 tree at test time: `/proc` with 27 processes (systemd, two kernel threads, ssh / nginx (master + worker) / cron services, a cron job `sh -c` -> Go binary, an sshd session -> bash -> a world-writable tool in `~/bin` whose `comm` contains spaces and parentheses, a daemon whose executable was deleted, the `systemd --user` manager with a user unit, a snap Firefox in a GNOME app scope and its child, an XDG-autostart applet, a docker container's nginx under `containerd-shim`, `getty@tty1`, a timer-started logrotate, a service with its own root directory (`/proc/<pid>/root` links to `/srv/named-chroot`, every other one to the tree root), a `setproctitle` worker with a secret in its single argument, a zombie without exe link), cgroup v2 paths, exe links (one ` (deleted)`); unit files (an `/etc` override hiding the vendor unit, an `ExecStart=` reset with continuation, a template, a timer, a masked unit linked to `/dev/null`, a unit whose program is missing, a user unit in `~/.config/systemd/user`); autostart entries (bare `Exec`, a disabled one, a per-user one with `%u`, a per-user symlink to a root-only file that must not be read); `/etc/crontab`, `/etc/cron.d/backup`, a user crontab; a dpkg database with `info/*.list` (merged-/usr paths, a multiarch `libc6:amd64.list`); a snap with `meta/snap.yaml`. The Go fixture binary `../../../lang/go/hello-linux-amd64` is copied in as `/usr/local/bin/backup`. Also fake `stat` (GNU `[-L] -c`), `id` and `dpkg-query` (`-W`, batched `-S`) so the real remote script runs on any POSIX `sh` against the tree | proc(5), systemd docs |
| `remote-output.txt` | output of `remote.SCRIPT` run on that tree with the fakes (non-root: `id -u` = 1000). Regenerate with `uv run python tests/fixtures/collectors/process/linux/fixture_linux.py --capture` after changing the script or the tree | `src/secmonk/collectors/process/remote.py` |

Host `fixture-linux`, user `alice`, the boot id, container id, versions and the `--token` / `--password` values are
illustrative. Placeholder executables contain text.
