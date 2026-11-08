from __future__ import annotations

import errno
import json
import os
import plistlib
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.macos import (
    RECEIPT_DIRS,
    MacOSCollector,
    loads_plist,
    parse_brew_info_json,
    parse_system_profiler_json,
)
from secmonk.engine.classify import classify
from secmonk.models import CAT_APPLICATION, CAT_OS, CAT_PACKAGE, CAT_RUNTIME, CAT_SYSTEM_APP

FIX = Path(__file__).parents[1] / "fixtures" / "collectors" / "macos"
ROOT = FIX / "root"


def _inv(**opts):
    return MacOSCollector().collect(str(ROOT), **{"home": [], **opts})


def _get(inv, name, category=None):
    for c in inv.components:
        if c.name == name and (category is None or c.category == category):
            return c
    raise AssertionError(f"{name} not found in {[c.name for c in inv.components]}")


def test_registered():
    assert REGISTRY["macos"] is MacOSCollector


def test_os_and_asset():
    inv = _inv()
    os_c = _get(inv, "macOS", CAT_OS)
    assert os_c.version == "14.5"
    assert os_c.meta["build"] == "23F79"
    assert inv.asset.id == "macos:root"
    assert inv.asset.os_name == "macOS" and inv.asset.os_version == "14.5"
    assert inv.asset.type == "desktop"
    assert inv.warnings == []


def test_chrome_app():
    c = _get(_inv(), "Google Chrome", CAT_APPLICATION)
    assert c.version == "126.0.6478.127"
    assert c.meta["bundle_id"] == "com.google.Chrome"
    assert c.meta["vendor_hint"] == "google"
    assert c.vendor is None
    assert c.source_path == "/Applications/Google Chrome.app"
    assert c.meta["electron"] is False


def test_slack_electron_runtime():
    inv = _inv()
    slack = _get(inv, "Slack", CAT_APPLICATION)
    assert slack.meta["electron"] is True
    el = next(c for c in inv.components if c.name == "Electron" and c.meta["embedded_in"] == "Slack")
    assert el.category == CAT_RUNTIME
    assert el.version == "30.1.2"
    assert el.purl == "pkg:npm/electron@30.1.2"
    assert el.meta["bundle_id"] == "com.github.Electron"
    classify(el)
    assert el.ecosystem == "npm"


def test_binary_plist_app():
    plist = ROOT / "Applications/Utilities/Something.app/Contents/Info.plist"
    assert plist.read_bytes().startswith(b"bplist00")
    c = _get(_inv(), "Something", CAT_APPLICATION)
    assert c.version and c.meta["bundle_id"]
    assert c.source_path == "/Applications/Utilities/Something.app"


def test_safari_system_app_and_toggle():
    assert _get(_inv(), "Safari").category == CAT_SYSTEM_APP
    inv = _inv(include_system=False)
    assert not [c for c in inv.components if c.name == "Safari"]
    assert not [c for c in inv.components if c.meta.get("pkg_id", "").startswith("com.apple.")]


def test_brew_formulae():
    inv = _inv()
    ssl = _get(inv, "openssl@3", CAT_PACKAGE)
    assert ssl.version == "3.3.1"
    assert "openssl%403@3.3.1" in ssl.purl and ssl.purl.startswith("pkg:brew/")
    assert ssl.meta["brew_kind"] == "formula" and ssl.meta["brew_name"] == "openssl@3"
    assert ssl.meta["runtime_dependencies"] == 1
    assert ssl.meta["installed_on_request"] is False
    assert _get(inv, "curl", CAT_PACKAGE).version == "8.7.1"


def test_cask_deduped_against_app():
    inv = _inv()
    vscode = _get(inv, "Visual Studio Code", CAT_APPLICATION)
    assert vscode.meta["also_cask"] == "visual-studio-code"
    assert not [c for c in inv.components if c.meta.get("brew_kind") == "cask"]
    assert _get(inv, "Electron", CAT_RUNTIME).version in ("30.1.2", "29.4.0")
    versions = {c.version for c in inv.components if c.name == "Electron"}
    assert versions == {"30.1.2", "29.4.0"}


def test_pkgutil_receipts():
    inv = _inv()
    p = _get(inv, "com.example.pkg", CAT_PACKAGE)
    assert p.version == "1.4.2"
    assert p.meta["pkg_id"] == "com.example.pkg"
    assert p.meta["install_prefix"] == "/"
    apple = _get(inv, "com.apple.pkg.CLTools_Executables", CAT_PACKAGE)
    assert apple.meta["vendor_hint"] == "apple"


def test_parse_brew_info_json():
    comps = parse_brew_info_json(json.loads((FIX / "brew-info.json").read_text()))
    by = {c.name: c for c in comps}
    assert by["openssl@3"].version == "3.3.1" and "%40" in by["openssl@3"].purl
    assert by["curl"].version == "8.7.1"
    cask = next(c for c in comps if c.meta["brew_kind"] == "cask")
    assert cask.meta["brew_name"] == "visual-studio-code" and cask.category == CAT_APPLICATION
    assert cask.purl == "pkg:brew/homebrew/cask/visual-studio-code@1.90.0"


def test_revision_suffix_stripped():
    from secmonk.collectors.macos import _formula_component

    c = _formula_component("wget", "1.24.5_1", "homebrew/core")
    assert c.version == "1.24.5" and c.meta["brew_version"] == "1.24.5_1"


def test_parse_system_profiler_json():
    comps = parse_system_profiler_json(json.loads((FIX / "system_profiler-applications.json").read_text()))
    by = {c.name: c for c in comps}
    assert by["Google Chrome"].version == "126.0.6478.127"
    assert by["Safari"].category == CAT_SYSTEM_APP
    assert by["Slack"].meta["obtained_from"] == "mac_app_store"


def test_system_profiler_option_adds_only_new():
    base = len(_inv().components)
    inv = _inv(system_profiler=str(FIX / "system_profiler-applications.json"))
    assert len(inv.components) == base  # all three already present


def test_bad_bundle_warns(tmp_path):
    (tmp_path / "Applications/Bad.app/Contents").mkdir(parents=True)
    (tmp_path / "Applications/Bad.app/Contents/Info.plist").write_bytes(b"not a plist")
    inv = MacOSCollector().collect(str(tmp_path), home=[])
    assert any("Bad.app" in w for w in inv.warnings)


def test_classify_chrome():
    inv = _inv()
    for c in inv.components:
        classify(c)
    chrome = _get(inv, "Google Chrome")
    assert chrome.vendor == "google"
    assert chrome.meta["product"] == "chrome"
    assert chrome.cpe.startswith("cpe:2.3:a:google:chrome:")


def test_cli_collect(tmp_path):
    res = CliRunner().invoke(app, ["collect", "macos", str(ROOT), "--db", str(tmp_path / "t.db"), "--quiet"])
    assert res.exit_code == 0, res.output


# ----------------------------------------------------------------------------- real fixtures (macOS 26.5 arm64)

REAL = FIX / "real"


def _real_tree(tmp_path: Path) -> Path:
    """A root with the real SystemVersion.plist and Apple receipts (tests/fixtures/collectors/macos/real)."""
    cs = tmp_path / "System/Library/CoreServices"
    cs.mkdir(parents=True)
    shutil.copy(REAL / "SystemVersion.plist", cs / "SystemVersion.plist")
    rd = tmp_path / RECEIPT_DIRS[1]
    rd.mkdir(parents=True)
    for p in (REAL / "receipts").glob("*.plist"):
        shutil.copy(p, rd / p.name)
    return tmp_path


def _pkg_info() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for block in (REAL / "pkgutil-pkg-info.txt").read_text().strip().split("\n\n"):
        kv = dict(line.split(": ", 1) for line in block.strip().splitlines())
        out[kv["package-id"]] = kv
    return out


def test_real_os_and_apple_receipts_match_pkgutil(tmp_path):
    inv = MacOSCollector().collect(str(_real_tree(tmp_path)), home=[])
    os_c = _get(inv, "macOS", CAT_OS)
    assert (os_c.version, os_c.meta["build"]) == ("26.5", "25F71")
    info = _pkg_info()
    got = {c.meta["pkg_id"]: c for c in inv.components if c.meta.get("pkg_id")}
    assert set(got) == set(info) and len(info) == 3
    for pid, kv in info.items():
        c = got[pid]
        assert c.version == kv["version"]
        # receipts store InstallDate as naive UTC; pkgutil prints it as a unix time
        when = datetime.fromtimestamp(int(kv["install-time"]), UTC).replace(tzinfo=None)
        assert c.meta["install_date"][:19] == when.isoformat()
        assert c.meta["install_prefix"] == kv["location"]
        assert c.source_path == f"/{RECEIPT_DIRS[1]}/{pid}.plist"
    assert not [w for w in inv.warnings if "receipt" in w]


def test_receipt_in_both_dirs_counted_once(tmp_path):
    root = _real_tree(tmp_path)
    (root / RECEIPT_DIRS[0]).mkdir(parents=True)
    shutil.copy(REAL / "receipts/com.apple.pkg.MobileAssets.plist", root / RECEIPT_DIRS[0])
    inv = MacOSCollector().collect(str(root), home=[])
    assert [c.meta["pkg_id"] for c in inv.components if c.meta.get("pkg_id")].count("com.apple.pkg.MobileAssets") == 1


def test_receipt_id_with_trailing_space_is_stripped(tmp_path):
    # seen 2026-11-08: /var/db/receipts/"org.swiftwasm.2024116 .plist"; `pkgutil --pkgs` prints it stripped
    d = tmp_path / RECEIPT_DIRS[0]
    d.mkdir(parents=True)
    (d / "org.example.tool .plist").write_bytes(plistlib.dumps(
        {"PackageIdentifier": "org.example.tool ", "PackageVersion": "1.0", "InstallPrefixPath": "/"}))
    inv = MacOSCollector().collect(str(tmp_path), home=[])
    assert [c.name for c in inv.components if c.meta.get("pkg_id")] == ["org.example.tool"]


def test_real_unquoted_plist_prolog_is_parsed():
    data = (REAL / "launchd/com.apple.familycircled.plist").read_bytes()
    assert data.startswith(b"<?xml version=1.0 ")
    with pytest.raises(Exception):  # noqa: B017 - documents why loads_plist exists
        plistlib.loads(data)
    assert loads_plist(data)["Label"] == "com.apple.familycircled"
    with pytest.raises(Exception):  # noqa: B017 - garbage still fails
        loads_plist(b"<?xml version=1.0?><plist version=1.0><dict><key>a</key>")


def test_utf8_plist_declaring_utf16_is_parsed():
    # prolog bytes as shipped by Royal TSX 6 (2026-11-08: UTF-8 with BOM, declares utf-16); body synthetic
    data = (b'\xef\xbb\xbf<?xml version="1.0" encoding="utf-16"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
            b"<key>CFBundleShortVersionString</key><string>6.4.1</string></dict></plist>")
    with pytest.raises(Exception):  # noqa: B017 - expat refuses the mismatched declaration
        plistlib.loads(data)
    assert loads_plist(data)["CFBundleShortVersionString"] == "6.4.1"
    real16 = data[3:].decode().encode("utf-16")             # a genuine UTF-16 plist still parses as before
    assert loads_plist(real16)["CFBundleShortVersionString"] == "6.4.1"


def test_real_system_profiler_shape():
    data = json.loads((REAL / "system_profiler-applications.json").read_text())
    synthetic = json.loads((FIX / "system_profiler-applications.json").read_text())
    real_keys = {k for a in data["SPApplicationsDataType"] for k in a}
    assert {k for a in synthetic["SPApplicationsDataType"] for k in a} <= real_keys   # fixture shape is real
    by = {c.source_path: c for c in parse_system_profiler_json(data)}
    assert len(by) == len(data["SPApplicationsDataType"])
    assert by["/Applications/Xcode.app"].meta["obtained_from"] == "mac_app_store"
    assert by["/Applications/FortiToken.app"].meta["arch_kind"] == "arch_ios"
    assert by["/Applications/Xcode.app/Contents/Applications/Accessibility Inspector.app"].category == CAT_SYSTEM_APP
    assert by["/System/Library/CoreServices/PassViewer.app"].version is None          # no `version` key
    assert by["/Applications/1Password.app"].meta["signed_by"][0].startswith("Developer ID Application:")


def test_real_empty_system_profiler_warns(tmp_path):
    inv = MacOSCollector().collect(str(_real_tree(tmp_path)), home=[],
                                   system_profiler=str(REAL / "system_profiler-applications-restricted.json"))
    assert any("lists no applications" in w for w in inv.warnings)


# ----------------------------------------------------------------------------- restricted access (EPERM)

def _eperm(path) -> PermissionError:
    return PermissionError(errno.EPERM, "Operation not permitted", str(path))


def _deny_listing(monkeypatch, *dirs: Path) -> None:
    """Make `Path.iterdir` fail like macOS privacy protection (TCC) does: EPERM, even for the owner."""
    denied = {str(d) for d in dirs}
    real = Path.iterdir

    def iterdir(self):
        if str(self) in denied:
            raise _eperm(self)
        return real(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)


def _deny_open(monkeypatch, pred) -> None:
    real = os.open

    def fake_open(path, *a, **k):
        if pred(str(path)):
            raise _eperm(path)
        return real(path, *a, **k)

    monkeypatch.setattr(os, "open", fake_open)


def _restricted_tree(tmp_path: Path) -> Path:
    root = _real_tree(tmp_path)
    for rel in ("Applications/Utilities/Tool.app/Contents", "Applications/Ok.app/Contents",
                "System/Applications/Calc.app/Contents", "Users/alice/Applications", "var/db/receipts"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    for bundle in ("Applications/Utilities/Tool.app", "Applications/Ok.app", "System/Applications/Calc.app"):
        name = Path(bundle).stem
        (root / bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(
            {"CFBundleIdentifier": f"com.example.{name}", "CFBundleShortVersionString": "1.0"}))
    return root


def test_denied_directories_warn_instead_of_crashing(tmp_path, monkeypatch):
    root = _restricted_tree(tmp_path)
    _deny_listing(monkeypatch, root / "Users", root / "Applications", root / "System/Applications",
                  root / "var/db/receipts")
    inv = MacOSCollector().collect(str(root))           # no explicit homes: /Users is listed
    for label in ("/Users", "/Applications", "/System/Applications", "/var/db/receipts"):
        assert any(w.startswith(f"cannot list {label}:") and "Full Disk Access" in w for w in inv.warnings), label
    assert _get(inv, "macOS", CAT_OS).version == "26.5"            # what is readable still comes through
    assert len([c for c in inv.components if c.meta.get("pkg_id")]) == 3
    assert not [c for c in inv.components if c.category in (CAT_APPLICATION, CAT_SYSTEM_APP)]


def test_denied_subfolder_warns_and_other_apps_survive(tmp_path, monkeypatch):
    root = _restricted_tree(tmp_path)
    _deny_listing(monkeypatch, root / "Applications/Utilities")
    inv = MacOSCollector().collect(str(root), home=[])
    assert _get(inv, "Ok", CAT_APPLICATION).version == "1.0"
    assert any(w.startswith("cannot list /Applications/Utilities:") for w in inv.warnings)


def test_denied_plists_warn_with_hint(tmp_path, monkeypatch):
    root = _restricted_tree(tmp_path)
    _deny_open(monkeypatch, lambda p: p.endswith(("Ok.app/Contents/Info.plist", "SystemVersion.plist",
                                                    "MobileAssets.plist")))
    inv = MacOSCollector().collect(str(root), home=[])
    assert not [c for c in inv.components if c.category == CAT_OS]
    w = "\n".join(inv.warnings)
    assert "cannot read bundle /Applications/Ok.app: permission denied" in w
    assert "SystemVersion.plist: permission denied" in w
    assert "MobileAssets.plist: permission denied" in w
    assert "not found" not in w                                   # denied is not reported as missing
    assert _get(inv, "Tool", CAT_APPLICATION).version == "1.0"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root ignores directory modes")
def test_unreadable_applications_dir_with_real_permissions(tmp_path):
    root = _restricted_tree(tmp_path)
    (root / "Applications").chmod(0)
    try:
        inv = MacOSCollector().collect(str(root), home=[])
    finally:
        (root / "Applications").chmod(0o755)
    assert any(w.startswith("cannot list /Applications:") for w in inv.warnings)
    assert _get(inv, "Calc", CAT_SYSTEM_APP)


def test_cli_collect_denied_is_not_an_error(tmp_path, monkeypatch):
    root = _restricted_tree(tmp_path)
    _deny_listing(monkeypatch, root / "Applications")
    res = CliRunner().invoke(app, ["collect", "macos", str(root), "--db", str(tmp_path / "t.db"), "--quiet"])
    assert res.exit_code == 0, res.output
    assert "cannot list /Applications" in res.output and "Traceback" not in res.output


# ----------------------------------------------------------------------------- brew CLI merges into the walk

def _fake_brew(monkeypatch, payload: dict | None, captured: dict | None = None):
    import secmonk.collectors.macos as mac

    def run(cmd, **kw):
        if payload is None:
            raise subprocess.CalledProcessError(1, cmd, "", "Error: Unknown command")
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    monkeypatch.setattr(mac.shutil, "which", lambda name: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(mac.subprocess, "run", run)
    if captured is not None:
        real = mac.parse_brew_info_json

        def parse(data, all_kegs=False):
            captured["all_kegs"] = all_kegs
            return real(data, all_kegs=all_kegs)

        monkeypatch.setattr(mac, "parse_brew_info_json", parse)


def _live_brew(**opts) -> tuple[list, list[str]]:
    """The Homebrew step as on the live system (`live=True`), over the fixture root."""
    warnings: list[str] = []
    return MacOSCollector._brew(ROOT, True, {"use_brew_cli": True, **opts}, warnings), warnings


def test_brew_cli_enriches_walk_and_never_drops_walked_formulae(monkeypatch):
    """Real-prefix finding (2026-11-08): `brew info --installed` silently skips formulae (untapped taps,
    renamed leftovers) and other prefixes; the walk must stay authoritative."""
    payload = json.loads((FIX / "brew-info.json").read_text())
    payload["formulae"] = [f for f in payload["formulae"] if f["name"] != "curl"]      # CLI skips curl
    payload["formulae"].append({"name": "only-cli", "tap": "homebrew/core", "linked_keg": "1.0",
                                "installed": [{"version": "1.0", "runtime_dependencies": []}]})
    _fake_brew(monkeypatch, payload)
    walk = {c.purl: c for c in _inv().components if c.meta.get("brew_kind") == "formula"}
    comps, warnings = _live_brew()
    brew = [c for c in comps if c.meta.get("brew_kind") == "formula"]
    by = {c.purl: c for c in brew}
    assert set(walk) <= set(by) and len(brew) == len(by)                               # curl kept, no dupes
    ssl = by["pkg:brew/openssl%403@3.3.1"]
    assert ssl.meta["license"] == "Apache-2.0" and ssl.meta["brew_cli"] is True        # CLI-only fields added
    assert ssl.meta["installed_at"] == walk[ssl.purl].meta["installed_at"]             # walk values kept
    assert by["pkg:brew/only-cli@1.0"].meta["source"] == "brew-cli"
    assert "brew_cli" not in by["pkg:brew/curl@8.7.1"].meta
    assert warnings == []


def test_brew_cli_failure_keeps_walk(monkeypatch):
    _fake_brew(monkeypatch, None)
    comps, warnings = _live_brew()
    assert any(c.name == "curl" and c.version == "8.7.1" for c in comps)
    assert any(w.startswith("brew CLI failed, filesystem walk only") for w in warnings)


def test_brew_cli_receives_all_kegs(monkeypatch):
    captured: dict = {}
    _fake_brew(monkeypatch, json.loads((FIX / "brew-info.json").read_text()), captured)
    _live_brew(all_kegs=True)
    assert captured == {"all_kegs": True}
    _live_brew()
    assert captured == {"all_kegs": False}


def test_brew_cli_ignored_for_a_copied_tree(monkeypatch):
    """The CLI describes the host: never merge it into the inventory of another root."""
    import secmonk.collectors.macos as mac

    monkeypatch.setattr(mac.shutil, "which", lambda name: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(mac.subprocess, "run", lambda *a, **k: pytest.fail("ran the host's brew"))
    inv = _inv(use_brew_cli=True)
    assert any(w.startswith("use_brew_cli ignored: root is not the live system") for w in inv.warnings)
    assert _get(inv, "curl", CAT_PACKAGE).version == "8.7.1"
    assert not [c for c in inv.components if c.meta.get("brew_cli") or c.meta.get("source") == "brew-cli"]


def _cli_formula(name: str, version: str, *, linked: str | None = None, oldnames: list[str] | None = None,
                 versions: list[str] | None = None) -> dict:
    return {"name": name, "tap": "homebrew/core", "oldnames": oldnames or [], "linked_keg": linked,
            "homepage": f"https://example.org/{name}", "license": "MIT",
            "installed": [{"version": v, "runtime_dependencies": []} for v in versions or [version]]}


def test_merge_brew_matches_renamed_formula_by_oldname():
    """Real case (2026-11-08): the rack is still `Cellar/mprocs/<v>` (walk name), `brew info` reports the formula
    under its new name `dekit` with `oldnames: ["mprocs"]`: one component, not two."""
    from secmonk.collectors.homebrew import _formula_component
    from secmonk.collectors.macos import merge_brew

    walk = [_formula_component("mprocs", "0.7.3", "homebrew/core", active=True)]
    cli = parse_brew_info_json({"formulae": [_cli_formula("dekit", "0.7.3", linked="0.7.3",
                                                          oldnames=["mprocs"])]})
    assert cli[0].meta["brew_oldnames"] == ["mprocs"]
    (only,) = merge_brew(walk, cli)
    assert only.name == "mprocs" and only.purl == "pkg:brew/mprocs@0.7.3"           # walk identity kept
    assert only.meta["brew_cli"] is True and only.meta["brew_current_name"] == "dekit"
    assert only.meta["license"] == "MIT" and only.meta["brew_oldnames"] == ["mprocs"]


def test_merge_brew_active_keg_divergence_only_enriches():
    """Walk picks the opt link (1.0), the CLI picks linked_keg / the highest version (2.0): the CLI must not
    add a second active keg of the same formula, only formula-level facts and its own choice."""
    from secmonk.collectors.homebrew import _formula_component
    from secmonk.collectors.macos import merge_brew

    walk = [_formula_component("foo", "1.0", "homebrew/core", active=True, installed_on_request=True)]
    cli = parse_brew_info_json({"formulae": [_cli_formula("foo", "2.0", versions=["1.0", "2.0"])]})
    assert [c.version for c in cli] == ["2.0"]
    (only,) = merge_brew(walk, cli)
    assert only.version == "1.0" and only.meta["brew_cli_version"] == "2.0"
    assert only.meta["license"] == "MIT" and only.meta["brew_cli"] is True
    assert "brew_current_name" not in only.meta
    # with all_kegs the CLI's 1.0 keg matches exactly; 2.0 still is not appended
    (only,) = merge_brew([_formula_component("foo", "1.0", "homebrew/core", active=True)],
                         parse_brew_info_json({"formulae": [_cli_formula("foo", "2.0", versions=["1.0", "2.0"])]},
                                              all_kegs=True))
    assert only.version == "1.0"


def test_brew_cli_all_kegs_accepts_bool_and_strings(monkeypatch):
    captured: dict = {}
    _fake_brew(monkeypatch, json.loads((FIX / "brew-info.json").read_text()), captured)
    for value, expected in ((True, True), ("yes", True), ("1", True), (False, False), ("no", False)):
        _live_brew(all_kegs=value)
        assert captured == {"all_kegs": expected}, value
