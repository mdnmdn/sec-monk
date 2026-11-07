"""Windows collector: name normalization, OS identity, inventory/osquery parsing, live mode (fake
winreg) and an end-to-end match against REAL Microsoft CNA records from the CVE List."""

from __future__ import annotations

import json
import platform
import re
import sys
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors import windows as w
from secmonk.collectors.base import REGISTRY
from secmonk.db import connect
from secmonk.engine.classify import classify
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import CAT_APPLICATION, CAT_OS, CAT_PACKAGE, CAT_RUNTIME, CAT_SYSTEM_APP
from secmonk.sources import cvelist

ROOT = Path(__file__).parents[1]
FIX = ROOT / "fixtures" / "collectors" / "windows"
MS_CVES = ROOT / "fixtures" / "sources" / "cvelist" / "microsoft"
WIN11 = FIX / "inventory-win11.json"
SERVER = FIX / "inventory-server2022.json"
OSQUERY = FIX / "osquery-win11.json"


def _get(inv, name, category=None):
    for c in inv.components:
        if c.name == name and (category is None or c.category == category):
            return c
    raise AssertionError(f"{name} not in {[c.name for c in inv.components]}")


@pytest.fixture(scope="module")
def win11():
    return w.parse_inventory_json(w.load_json_file(WIN11))


def test_registered():
    assert REGISTRY["windows"] is w.WindowsCollector


# --------------------------------------------------------------------------- name normalization

@pytest.mark.parametrize("raw, name, ver, arch", [
    ("Mozilla Firefox (x64 en-US)", "Mozilla Firefox", None, "x64"),
    ("7-Zip 23.01 (x64)", "7-Zip", "23.01", "x64"),
    ("Notepad++ (64-bit x64)", "Notepad++", None, "x64"),
    ("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135",
     "Microsoft Visual C++ 2015-2022 Redistributable", "14.38.33135", "x64"),
    ("Adobe Acrobat (64-bit)", "Adobe Acrobat", None, "x64"),
    ("Google Chrome", "Google Chrome", None, None),
    ("Microsoft Edge", "Microsoft Edge", None, None),
    ("Zoom Workplace (64-bit)", "Zoom Workplace", None, "x64"),
    ("VLC media player", "VLC media player", None, None),
    ("Microsoft 365 Apps for enterprise - en-us", "Microsoft 365 Apps for enterprise", None, None),
    ("Microsoft Teams", "Microsoft Teams", None, None),
    ("Git", "Git", None, None),
    ("Python 3.12.4 (64-bit)", "Python", "3.12.4", "x64"),
    ("Node.js", "Node.js", None, None),
    ("WinRAR 7.01 (64-bit)", "WinRAR", "7.01", "x64"),
    ("PuTTY release 0.81 (64-bit)", "PuTTY", "0.81", "x64"),
    ("Wireshark 4.2.5 x64", "Wireshark", "4.2.5", "x64"),
    ("Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.38.33135", "Microsoft Visual C++ 2022 Minimum Runtime",
     "14.38.33135", "x86"),
    ("Visual Studio Community 2022", "Visual Studio Community 2022", None, None),
    ("PowerShell 7-x64", "PowerShell 7", None, "x64"),
])
def test_normalize_display_name(raw, name, ver, arch):
    assert w.normalize_display_name(raw) == (name, ver, arch)


@pytest.mark.parametrize("raw, vendor, product", [
    ("Mozilla Firefox (x64 en-US)", "mozilla", "firefox"),
    ("7-Zip 23.01 (x64)", "7-zip", "7-zip"),
    ("Notepad++ (64-bit x64)", "notepad-plus-plus", "notepad-plus-plus"),
    ("WinRAR 7.01 (64-bit)", "win.rar gmbh", "winrar"),
    ("PuTTY release 0.81 (64-bit)", "putty", "putty"),
    ("Wireshark 4.2.5 x64", "wireshark", "wireshark"),
    ("Google Chrome", "google", "chrome"),
    ("Microsoft Edge", "microsoft", "edge chromium"),
    ("Zoom Workplace (64-bit)", "zoom", "zoom"),
    ("VLC media player", "videolan", "vlc media player"),
    ("Microsoft 365 Apps for enterprise - en-us", "microsoft", "microsoft 365 apps for enterprise"),
    ("Microsoft Teams", "microsoft", "teams"),
    ("Git", "git-scm", "git"),
    ("Python 3.12.4 (64-bit)", "python", "python"),
    ("Node.js", "nodejs", "node.js"),
    ("Adobe Acrobat (64-bit)", "adobe", "acrobat"),
    ("Visual Studio Community 2022", "microsoft", "visual studio 2022"),
    ("Microsoft Visual Studio Code (User)", "microsoft", "visual studio code"),
])
def test_display_names_resolve_to_alias_table(raw, vendor, product):
    name, ver, _ = w.normalize_display_name(raw)
    c = classify(w.Component(name=name, version=ver or "1.0", category=CAT_APPLICATION,
                             meta={"product_hint": name.lower()}))
    assert (c.vendor, c.meta["product"], c.meta["product_source"]) == (vendor, product, "alias-table")


# --------------------------------------------------------------------------- OS identity

@pytest.mark.parametrize("info, name, product, family", [
    ({"product_name": "Windows 10 Pro", "current_build": "22631", "display_version": "23H2",
      "installation_type": "Client"}, "Windows 11 Version 23H2", "windows 11 version 22h3", "client"),
    ({"product_name": "Windows 10 Pro", "current_build": "22621", "display_version": "22H2"},
     "Windows 11 Version 22H2", "windows 11 version 22h2", "client"),
    ({"product_name": "Windows 10 Enterprise", "current_build": "19045", "display_version": "22H2"},
     "Windows 10 Version 22H2", "windows 10 version 22h2", "client"),
    ({"product_name": "Windows 10 Enterprise", "current_build": "17763", "release_id": "1809",
      "installation_type": "Client"}, "Windows 10 Version 1809", "windows 10 version 1809", "client"),
    ({"product_name": "Windows Server 2022 Datacenter", "current_build": "20348", "installation_type": "Server"},
     "Windows Server 2022", "windows server 2022", "server"),
    ({"product_name": "Windows Server 2019 Standard", "current_build": "17763", "installation_type": "Server Core"},
     "Windows Server 2019", "windows server 2019", "server"),
    ({"product_name": "Windows Server 2016 Standard", "current_build": "14393", "installation_type": "Server"},
     "Windows Server 2016", "windows server 2016", "server"),
    ({"product_name": "Windows Server 2025 Standard", "current_build": "26100", "installation_type": "Server"},
     "Windows Server 2025", "windows server 2025", "server"),
    ({"product_name": "Windows Server 2012 R2 Standard", "current_build": "9600", "installation_type": "Server"},
     "Windows Server 2012 R2", "windows server 2012 r2", "server"),
    ({"product_name": "Windows 11 Pro", "current_build": "26100", "display_version": "24H2"},
     "Windows 11 Version 24H2", "windows 11 version 24h2", "client"),
])
def test_windows_os_identity(info, name, product, family):
    ident = w.windows_os_identity(info)
    assert (ident["name"], ident["product"], ident["family"]) == (name, product, family)


def test_os_version_needs_ubr():
    warns: list[str] = []
    assert w._os_version({"current_build": "22631", "ubr": 3880, "major": 10, "minor": 0}, warns) == "10.0.22631.3880"
    assert w._os_version({"current_build": "9600", "ubr": 22134, "current_version": "6.3"}, warns) == "6.3.9600.22134"
    assert warns == []
    assert w._os_version({"current_build": "22631"}, warns) is None
    assert "UBR" in warns[0]


# --------------------------------------------------------------------------- inventory JSON

def test_asset_and_os(win11):
    a = win11.asset
    assert (a.id, a.type, a.name, a.platform) == ("windows:WS-ALICE01", "desktop", "WS-ALICE01", "windows/amd64")
    assert a.os_name == "Windows 11 Pro"            # registry ProductName says "Windows 10 Pro"
    assert a.os_version == "23H2 (build 22631.3880)"
    os_c = _get(win11, "Windows 11 Version 23H2", CAT_OS)
    assert os_c.version == "10.0.22631.3880" and os_c.vendor == "microsoft"
    assert os_c.meta["product"] == "windows 11 version 22h3"    # ARM64 spelling in CNA records
    assert os_c.meta["build"] == 22631 and os_c.meta["ubr"] == 3880
    assert os_c.meta["edition"] == "Professional" and os_c.meta["installation_type"] == "Client"
    assert os_c.meta["hotfixes"] == ["KB5027397", "KB5039212", "KB5040442"]
    assert os_c.meta["last_hotfix_on"] == "2024-07-17"
    assert os_c.cpe.startswith("cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.3880")
    assert not any(c.name.startswith("KB") for c in win11.components)      # hotfixes are meta only
    assert sum(1 for c in win11.components if c.category == CAT_OS) == 1


def test_server_asset():
    inv = w.parse_inventory_json(w.load_json_file(SERVER))
    assert inv.asset.type == "server" and inv.asset.os_name == "Windows Server 2022 Datacenter"
    os_c = _get(inv, "Windows Server 2022", CAT_OS)
    assert os_c.version == "10.0.20348.2655" and os_c.meta["product"] == "windows server 2022"


def test_programs_filtering_and_dedupe(win11):
    names = [c.name for c in win11.components]
    # skipped: SystemComponent=1, update entries (ParentKeyName / KB), Python sub-packages, .NET (taken from dirs)
    for gone in ("Intel(R) Wireless Bluetooth(R)", "Update for Windows (KB5001716)"):
        assert gone not in names
    assert not any("KB500" in n or "Core Interpreter" in n or "Standard Library" in n for n in names)
    assert not any(n.startswith("Microsoft .NET") or "Shared Framework" in n or "Desktop Runtime -" in n for n in names)
    # x86 + x64 VC++ redistributable merged into one component
    vc = [c for c in win11.components if c.name.startswith("Microsoft Visual C++")]
    assert len(vc) == 1 and vc[0].version == "14.38.33135.0"
    assert vc[0].meta["arch"] == "x64" and vc[0].meta["arch_variants"] == ["x64", "x86"]
    assert vc[0].meta["msi_product_code"] == "{E8B6A6E6-6F3B-4A0B-8ED0-6A0A3A9F1C11}"


def test_program_details(win11):
    py = _get(win11, "Python", CAT_APPLICATION)
    assert py.version == "3.12.4"                                   # not DisplayVersion 3.12.4150.0
    zoom = _get(win11, "Zoom Workplace")
    assert zoom.version == "6.0.11"                                 # '6.0.11 (33160)' cleaned
    fx = _get(win11, "Mozilla Firefox")
    assert fx.meta["display_name"] == "Mozilla Firefox 127.0.2 (x64 en-US)" and fx.meta["publisher"] == "Mozilla"
    assert fx.meta["install_location"] == r"C:\Program Files\Mozilla Firefox"
    assert fx.purl == "pkg:generic/mozilla/Mozilla%20Firefox@127.0.2"
    code = _get(win11, "Microsoft Visual Studio Code (User)")
    assert code.meta["scope"] == "user" and code.meta["users"] == ["alice"]
    assert _get(win11, "Microsoft Edge").meta["arch"] == "x86"      # WOW6432Node key
    # a name/version pair seen twice (machine + per-user) is one component
    assert len([c for c in win11.components if c.name == "Microsoft Teams"]) == 1
    assert len([c for c in win11.components if c.name == "Microsoft Teams classic"]) == 1


def test_appx(win11):
    shell = _get(win11, "Microsoft.Windows.ShellExperienceHost")
    assert shell.category == CAT_SYSTEM_APP
    teams = _get(win11, "MSTeams")
    assert teams.category == CAT_APPLICATION and teams.meta["product_hint"] == "microsoft teams"
    photos = [c for c in win11.components if c.name == "Microsoft.Windows.Photos"]
    assert len(photos) == 1 and sorted(photos[0].meta["arch_variants"]) == ["x64", "x86"]
    assert not any("VCLibs" in c.name for c in win11.components)    # frameworks skipped
    assert win11.asset.meta["appx_frameworks_skipped"] == 1
    inv = w.parse_inventory_json(w.load_json_file(WIN11), include_system=False)
    assert not any(c.category == CAT_SYSTEM_APP for c in inv.components)


def test_chocolatey_and_scoop(win11):
    jq = _get(win11, "jq", CAT_PACKAGE)
    assert jq.purl == "pkg:chocolatey/jq@1.7.1"
    # choco 7zip.install 23.1.0 / putty.install 0.81.0 are the same installs as the Uninstall entries
    assert not any(c.name in ("7zip.install", "putty.install") for c in win11.components)
    assert _get(win11, "7-Zip").meta["also_chocolatey"] == "7zip.install"
    assert _get(win11, "PuTTY").meta["also_chocolatey"] == "putty.install"
    sc = _get(win11, "ripgrep", CAT_PACKAGE)
    assert sc.purl == "pkg:generic/scoop/ripgrep@14.1.0" and sc.meta["scoop_bucket"] == "main"
    assert _get(win11, "7zip", CAT_PACKAGE).version == "24.07"      # different version: separate install


def test_dotnet(win11):
    rts = [c for c in win11.components if c.category == CAT_RUNTIME]
    assert {(c.name, c.version, c.meta["arch"]) for c in rts} == {
        (".NET 8.0", "8.0.8", "x64"), (".NET 6.0", "6.0.33", "x64"), (".NET 8.0", "8.0.8", "x86"),
        ("ASP.NET Core 8.0", "8.0.8", "x64"), (".NET Desktop Runtime 8.0", "8.0.8", "x64")}
    assert win11.asset.meta["dotnet_sdks"] == ["8.0.400"]
    assert win11.asset.meta["winget"][0]["id"] == "Microsoft.PowerToys"


def test_warnings(win11):
    assert any("bob" in x for x in win11.warnings)
    doc = json.loads(WIN11.read_text())
    doc["os"].pop("ubr")
    inv = w.parse_inventory_json(doc)
    assert _get(inv, "Windows 11 Version 23H2").version is None
    assert any("UBR" in x for x in inv.warnings)


def test_bad_documents():
    with pytest.raises(ValueError, match="schema"):
        w.parse_inventory_json({"schema": "other/1"})
    with pytest.raises(TypeError):
        w.parse_inventory_json([1])


def test_encodings(tmp_path):
    text = WIN11.read_text()
    for enc, name in (("utf-8-sig", "bom.json"), ("utf-16", "u16.json"), ("utf-8", "plain.json")):
        p = tmp_path / name
        p.write_bytes(text.encode(enc))
        assert w.load_json_file(p)["hostname"] == "WS-ALICE01"


# --------------------------------------------------------------------------- osquery

def test_osquery():
    inv = w.WindowsCollector().collect(None, osquery=str(OSQUERY))
    a = inv.asset
    assert a.id == "windows:WS-BOB02" and a.type == "desktop" and a.platform == "windows/amd64"
    os_c = _get(inv, "Windows 11 Version 23H2", CAT_OS)
    assert os_c.version == "10.0.22631.3880"
    assert os_c.meta["hotfixes"] == ["KB5040442"]
    names = [c.name for c in inv.components]
    assert "7-Zip" in names and "Notepad++" in names and "Python" in names
    assert not any("KB5001716" in n for n in names)
    assert _get(inv, "Python").meta["msi_product_code"] == "{7D1C0A52-9A1F-4A5E-A1C8-6B4A6A3F2C33}"
    assert any("osquery" in x for x in inv.warnings)


def test_osquery_without_ubr_disables_os_matching():
    data = json.loads(OSQUERY.read_text())
    data.pop("registry")
    data["os_version"][0].pop("revision")
    inv = w.parse_osquery(data)
    assert _get(inv, "Windows 11 Version 23H2").version is None


def test_collector_autodetects_osquery_target():
    assert w.WindowsCollector().collect(str(OSQUERY)).asset.id == "windows:WS-BOB02"


def test_collect_errors(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"foo": 1}')
    with pytest.raises(ValueError, match="neither"):
        w.WindowsCollector().collect(str(p))
    if sys.platform != "win32":
        with pytest.raises(ValueError, match="windows collector"):
            w.WindowsCollector().collect()
        with pytest.raises(RuntimeError):
            w.collect_live()


def test_cli_collect(tmp_path):
    res = CliRunner().invoke(app, ["collect", "windows", str(WIN11), "--db", str(tmp_path / "t.db"), "--quiet"])
    assert res.exit_code == 0, res.output


# --------------------------------------------------------------------------- script + ssh contract

def test_script_is_ascii_and_balanced():
    text = w.INVENTORY_SCRIPT_PATH.read_text(encoding="utf-8")
    assert text.isascii()
    assert text.count("{") == text.count("}") and text.count("(") == text.count(")")
    assert "secmonk-windows-inventory/1" in text and w.SCHEMA in text
    for forbidden in ("Set-ItemProperty", "Remove-ItemProperty", "New-Item", "Install-", "Invoke-WebRequest",
                      "Set-Content", "Out-File"):
        assert forbidden not in text                                 # read-only


def test_inventory_script_compact():
    full, compact = w.inventory_script(compact=False), w.inventory_script()
    assert compact.isascii() and "\n\n" not in compact.replace("\r\n", "\n")
    assert not any(ln.lstrip().startswith("#") for ln in compact.splitlines())
    assert "secmonk-windows-inventory/1" in compact and len(compact) < len(full)


# --------------------------------------------------------------------------- live mode (fake winreg)

class _FakeWinreg(types.SimpleNamespace):
    """Just enough of winreg: a dict {(hive, view, path): {"values": {...}}}; subkeys are derived."""

    def __init__(self, tree):
        super().__init__(HKEY_LOCAL_MACHINE="HKLM", HKEY_USERS="HKU", KEY_READ=1, KEY_WOW64_64KEY=0x100,
                         KEY_WOW64_32KEY=0x200)
        self.tree = tree

    def _view(self, access):
        return 32 if access & 0x200 else 64

    def OpenKey(self, parent, path, reserved=0, access=1):
        if isinstance(parent, tuple):
            hive, view, base = parent
            full = f"{base}\\{path}" if base else path
        else:
            hive, view, full = parent, self._view(access), path
        if not any(k[0] == hive and k[1] == view and (k[2] == full or k[2].startswith(full + "\\"))
                   for k in self.tree):
            raise OSError("not found")
        return (hive, view, full)

    def EnumKey(self, key, i):
        hive, view, base = key if isinstance(key, tuple) else (key, 64, "")
        subs: list[str] = []
        for (h, v, p) in self.tree:
            if h == hive and v == view and (p.startswith(base + "\\") if base else True):
                first = (p[len(base) + 1:] if base else p).split("\\")[0]
                if first not in subs:
                    subs.append(first)
        if i >= len(subs):
            raise OSError("done")
        return subs[i]

    def QueryValueEx(self, key, name):
        vals = self.tree.get(key, {})
        if name not in vals:
            raise OSError("no value")
        return vals[name], 1

    def CloseKey(self, key):
        pass


def test_live_mode_with_fake_winreg(monkeypatch):
    unin = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    sid = "S-1-5-21-1-2-3-1001"
    tree = {
        ("HKLM", 64, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"): {
            "ProductName": "Windows 10 Pro", "DisplayVersion": "23H2", "CurrentBuild": "22631", "UBR": 3880,
            "EditionID": "Professional", "InstallationType": "Client", "CurrentMajorVersionNumber": 10,
            "CurrentMinorVersionNumber": 0},
        ("HKLM", 64, unin + r"\7-Zip"): {"DisplayName": "7-Zip 23.01 (x64)", "DisplayVersion": "23.01",
                                         "Publisher": "Igor Pavlov"},
        ("HKLM", 64, unin + r"\KB1"): {"DisplayName": "Update for X (KB5001716)", "ParentKeyName": "OperatingSystem"},
        ("HKLM", 32, unin + r"\Notepad++"): {"DisplayName": "Notepad++ (64-bit x64)", "DisplayVersion": "8.6.4"},
        ("HKU", 64, sid + "\\" + unin + r"\slack"): {"DisplayName": "Slack", "DisplayVersion": "4.38.125"},
        ("HKU", 64, sid + "_Classes\\x"): {},
    }
    monkeypatch.setitem(sys.modules, "winreg", _FakeWinreg(tree))
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(w.shutil, "which", lambda _n: None)          # no PowerShell
    monkeypatch.setattr(w.socket, "gethostname", lambda: "LIVE01")
    monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    inv = w.WindowsCollector().collect()
    assert inv.asset.id == "windows:LIVE01"
    assert _get(inv, "Windows 11 Version 23H2", CAT_OS).version == "10.0.22631.3880"
    names = {c.name: c for c in inv.components}
    assert {"7-Zip", "Notepad++", "Slack"} <= set(names), sorted(names)
    assert not any("KB5001716" in n for n in names)
    assert names["Notepad++"].meta["arch"] == "x64" and names["Slack"].meta["scope"] == "user"
    assert any("Appx" in x for x in inv.warnings)


def test_live_filesystem_scanners(tmp_path):
    lib = tmp_path / "choco" / "lib" / "jq"
    lib.mkdir(parents=True)
    (lib / "jq.nuspec").write_text('<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">'
                                   "<metadata><id>jq</id><version>1.7.1</version><title>jq</title></metadata></package>")
    assert w._scan_chocolatey(tmp_path / "choco")[0]["version"] == "1.7.1"
    cur = tmp_path / "scoop" / "apps" / "ripgrep" / "current"
    cur.mkdir(parents=True)
    (cur / "manifest.json").write_text('{"version": "14.1.0"}')
    (cur / "install.json").write_text('{"bucket": "main", "architecture": "64bit"}')
    assert w._scan_scoop([tmp_path / "scoop"])[0]["bucket"] == "main"
    (tmp_path / "dotnet" / "shared" / "Microsoft.NETCore.App" / "8.0.8").mkdir(parents=True)
    assert w._scan_dotnet([(tmp_path / "dotnet", "x64")])[0]["version"] == "8.0.8"


# --------------------------------------------------------------------------- end to end on REAL Microsoft CNA data

@pytest.fixture
def db():
    c = connect(":memory:")
    for f in sorted(MS_CVES.glob("CVE-*.json")):
        assert cvelist.import_record(c, json.loads(f.read_text())) == f.stem
    yield c
    c.close()


def _findings(conn, asset):
    rows = conn.execute(
        """SELECT c.name, c.category, f.vuln_id, f.matched_by, f.confidence, f.fixed_version, f.status
           FROM finding f JOIN component c ON c.id = f.component_id WHERE f.asset_id = ?""", (asset,)).fetchall()
    return {(r["name"], r["vuln_id"]): r for r in rows}


def test_cna_record_shape(db):
    """Facts this implementation relies on (documented in references/windows-inventory.md)."""
    rows = db.execute("SELECT * FROM affected WHERE vuln_id='CVE-2024-38063' AND product='windows 11 version 23h2'"
                      ).fetchall()
    assert len(rows) == 1 and rows[0]["vendor"] == "microsoft" and rows[0]["range_type"] == "CVE"
    assert json.loads(rows[0]["events"]) == [{"introduced": "10.0.22631.0"}, {"fixed": "10.0.22631.4037"}]
    assert rows[0]["version_type"] == "custom"


def test_e2e_windows11_unpatched(db):
    inv = w.parse_inventory_json(w.load_json_file(WIN11))
    save_inventory(db, inv)
    stats = match_asset(db, inv.asset.id)
    assert stats["findings"] >= 8
    f = _findings(db, inv.asset.id)
    os_hit = f[("Windows 11 Version 23H2", "CVE-2024-38063")]
    assert os_hit["matched_by"] == "cve-product" and os_hit["category"] == "os"
    assert os_hit["fixed_version"] == "10.0.22631.4037" and os_hit["confidence"] == 0.8
    assert ("Windows 11 Version 23H2", "CVE-2025-21418") in f and ("Windows 11 Version 23H2", "CVE-2025-30400") in f
    # applications and runtimes through the CPE rows of the same CNA records
    assert f[("Microsoft Edge", "CVE-2024-43472")]["matched_by"] == "cpe-product"
    assert f[(".NET 8.0", "CVE-2024-38229")]["fixed_version"] == "8.0.10"
    assert ("ASP.NET Core 8.0", "CVE-2025-26682") in f
    assert f[("Visual Studio Community 2022", "CVE-2025-26682")]["fixed_version"] == "17.12.7"
    # .NET 6.0.33 is outside every range in the fixtures; Office rows have URL bounds -> not matchable
    assert (".NET 6.0", "CVE-2024-38229") not in f
    assert not any(k[0].startswith("Microsoft 365") for k in f)


def test_e2e_server_2022(db):
    inv = w.parse_inventory_json(w.load_json_file(SERVER))
    save_inventory(db, inv)
    match_asset(db, inv.asset.id)
    f = _findings(db, inv.asset.id)
    assert f[("Windows Server 2022", "CVE-2024-38063")]["fixed_version"] == "10.0.20348.2700"
    assert f[("Microsoft Edge", "CVE-2024-43472")]["status"] == "open"


@pytest.mark.parametrize("fixture, name, build, fix_ubr", [
    ("inventory-win11.json", "Windows 11 Version 23H2", 22631, 4037),
    ("inventory-server2022.json", "Windows Server 2022", 20348, 2700),
])
def test_e2e_patch_boundary(db, fixture, name, build, fix_ubr):
    doc = json.loads((FIX / fixture).read_text())
    doc["uninstall"] = []                       # isolate the OS component
    doc["dotnet_runtimes"] = []
    doc["os"]["ubr"] = fix_ubr - 1
    inv = w.parse_inventory_json(doc)
    save_inventory(db, inv)
    match_asset(db, inv.asset.id)
    assert (name, "CVE-2024-38063") in _findings(db, inv.asset.id)
    # install the fix (UBR == fixed build): the finding is gone (marked fixed on re-match)
    doc["os"]["ubr"] = fix_ubr
    inv = w.parse_inventory_json(doc)
    assert _get(inv, name).version == f"10.0.{build}.{fix_ubr}"
    save_inventory(db, inv)
    match_asset(db, inv.asset.id)
    assert _findings(db, inv.asset.id)[(name, "CVE-2024-38063")]["status"] == "fixed"


def test_e2e_fully_patched_has_no_os_findings(db):
    doc = json.loads(WIN11.read_text())
    doc["os"]["ubr"] = 9999
    inv = w.parse_inventory_json(doc)
    save_inventory(db, inv)
    match_asset(db, inv.asset.id)
    assert not [k for k in _findings(db, inv.asset.id) if k[0] == "Windows 11 Version 23H2"]


def test_e2e_osquery(db):
    inv = w.WindowsCollector().collect(None, osquery=str(OSQUERY))
    save_inventory(db, inv)
    match_asset(db, inv.asset.id)
    f = _findings(db, inv.asset.id)
    assert f[("Windows 11 Version 23H2", "CVE-2024-38063")]["matched_by"] == "cve-product"
    assert f[("Microsoft Edge", "CVE-2024-43472")]["matched_by"] == "cpe-product"


def test_arm64_23h2_spelling_also_matches(db):
    """CNA calls the ARM64 build of 23H2 'Windows 11 version 22H3' (CVE-2024-38063 has both rows)."""
    rows = db.execute("SELECT product FROM affected WHERE vuln_id='CVE-2024-38063' AND product LIKE 'windows 11%'"
                      ).fetchall()
    assert {"windows 11 version 22h3", "windows 11 version 23h2"} <= {r["product"] for r in rows}
    assert re.fullmatch(r"windows 11 version \w+", w.windows_os_identity(
        {"current_build": "22631", "display_version": "23H2"})["name"].lower())
