"""SSH collector against a (fake) Windows OpenSSH server: detection fallback + PowerShell script."""

from __future__ import annotations

from pathlib import Path

from secmonk.collectors import ssh
from secmonk.collectors.windows import inventory_script

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "collectors" / "windows"


class _BytesStream(ssh.Stream):
    def __init__(self, out: bytes, rc: int, err: bytes = b""):
        self._out, self._rc, self._err, self.timed_out = out, rc, err, False

    def read(self, n: int = -1) -> bytes:
        data, self._out = (self._out, b"") if n < 0 else (self._out[:n], self._out[n:])
        return data

    def finish(self, abort: bool = False) -> tuple[int, bytes]:
        return self._rc, self._err


class FakeWindows(ssh.Transport):
    """Behaves like Windows OpenSSH with cmd.exe as default shell."""

    name = "fake-windows"

    def __init__(self, inventory: bytes):
        self.inventory = inventory
        self.calls: list[tuple[str, bytes | None]] = []

    def stream(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> ssh.Stream:
        self.calls.append((cmd, stdin))
        if cmd.startswith("sh "):
            return _BytesStream(b"", 1, b"'sh' is not recognized as an internal or external command")
        if "OSVersion.Platform" in cmd:
            return _BytesStream(b"Win32NT\r\n", 0)
        if cmd == ssh.SSHCollector.PS:
            assert stdin == inventory_script(compact=True).encode()
            # PowerShell may print a banner/progress before the JSON; the BOM must be tolerated too
            return _BytesStream(b"\xef\xbb\xbfWARNING: something\r\n" + self.inventory, 0)
        raise AssertionError(f"unexpected remote command {cmd!r}")

    def close(self) -> None:
        pass



def test_windows_detected_by_fallback_and_inventoried():
    t = FakeWindows((FIX / "inventory-win11.json").read_bytes())
    inv = ssh.SSHCollector().collect("admin@win-host", transport=t)
    assert inv.asset.id == "ssh:win-host"
    assert inv.asset.meta["transport"] == "fake-windows" and inv.asset.meta["remote_os"] == "windows"
    os_comp = next(c for c in inv.components if c.category == "os")
    assert os_comp.name.startswith("Windows 11") and os_comp.version.startswith("10.0.22631.")
    assert len(inv.components) > 10
    assert t.calls[0][0].startswith("sh ")          # tried POSIX first


def test_windows_forced_skips_posix_detection():
    t = FakeWindows((FIX / "inventory-server2022.json").read_bytes())
    inv = ssh.SSHCollector().collect("ssh://admin@srv:2222", transport=t, os="windows")
    assert [c for c, _ in t.calls] == [ssh.SSHCollector.PS]
    assert inv.asset.meta["port"] == 2222
    assert next(c for c in inv.components if c.category == "os").name.startswith("Windows Server 2022")
