from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.macos import (
    MacOSCollector,
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
