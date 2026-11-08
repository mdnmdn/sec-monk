from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors import homebrew as hb
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.homebrew import (
    HomebrewCollector,
    collect_prefixes,
    find_prefixes,
    parse_brew_info_json,
    parse_formula_rb,
    parse_sbom,
    registry_purl_from_url,
    repo_from_url,
    tag_from_url,
)
from secmonk.db import connect
from secmonk.engine.classify import brew_vendor_guess, classify
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import CAT_APPLICATION, CAT_LIBRARY, CAT_PACKAGE, Component
from secmonk.sources.base import SyncOptions
from secmonk.sources.cvelist import CveListSource

FIX = Path(__file__).parents[1] / "fixtures"
PREFIX = FIX / "collectors" / "homebrew" / "prefix"
REAL = FIX / "collectors" / "homebrew" / "real"
CVES = FIX / "sources" / "cvelist" / "brew"


def _inv(target=PREFIX, **opts):
    return HomebrewCollector().collect(str(target), **opts)


def _formulae(inv):
    return {(c.name, c.version): c for c in inv.components if c.meta.get("brew_kind") == "formula"}


def _cask(inv, token):
    return next(c for c in inv.components if c.meta.get("brew_name") == token)


def _keg(prefix: Path, name: str, version: str, rb: str = "", receipt: dict | None = None,
         sbom: dict | None = None, link: bool = True) -> Path:
    keg = prefix / "Cellar" / name / version
    (keg / ".brew").mkdir(parents=True)
    (keg / "INSTALL_RECEIPT.json").write_text(json.dumps(
        receipt if receipt is not None else {"source": {"tap": "homebrew/core"}, "installed_on_request": True}))
    if rb:
        (keg / ".brew" / f"{name}.rb").write_text(rb)
    if sbom:
        (keg / "sbom.spdx.json").write_text(json.dumps(sbom))
    if link:
        (prefix / "opt").mkdir(exist_ok=True)
        (prefix / "opt" / name).symlink_to(f"../Cellar/{name}/{version}")
    return keg


# --------------------------------------------------------------------------- kegs

def test_registered():
    assert REGISTRY["homebrew"] is HomebrewCollector


def test_active_keg_only_by_default():
    inv = _inv()
    jq = [c for c in inv.components if c.name == "jq" and c.meta.get("brew_kind") == "formula"]
    assert [c.version for c in jq] == ["1.8.2"]
    assert jq[0].meta["active"] is True and "active_guess" not in jq[0].meta
    assert jq[0].meta["linked"] is True and jq[0].meta["keg_only"] is False
    assert inv.warnings == []


def test_all_kegs_includes_inactive():
    inv = _inv(all_kegs="true")
    jq = {c.version: c for c in inv.components if c.name == "jq" and c.meta.get("brew_kind") == "formula"}
    assert set(jq) == {"1.8.1", "1.8.2"}
    assert jq["1.8.1"].meta["active"] is False and jq["1.8.2"].meta["active"] is True
    assert jq["1.8.1"].purl != jq["1.8.2"].purl


def test_keg_only_openssl_revision_stripped():
    ssl = _formulae(_inv())[("openssl@3", "3.6.4")]
    assert ssl.meta["brew_version"] == "3.6.4_1"
    assert ssl.meta["keg_only"] is True and ssl.meta["linked"] is False
    assert ssl.meta["installed_on_request"] is False
    assert ssl.meta["tap"] == "homebrew/core"
    assert ssl.purl == "pkg:brew/openssl%403@3.6.4_1"
    assert ssl.meta["license"] == "Apache-2.0"
    assert ssl.category == CAT_PACKAGE


def test_pinned_xz_and_license_list():
    xz = _formulae(_inv())[("xz", "5.8.4")]
    assert xz.meta["pinned"] is True
    assert xz.meta["license"] == "0BSD AND GPL-2.0-or-later"
    assert "pinned" not in _formulae(_inv())[("jq", "1.8.2")].meta


def test_formula_text_fields_and_runtime_deps():
    jq = _formulae(_inv())[("jq", "1.8.2")]
    assert jq.meta["homepage"] == "https://jqlang.github.io/jq/"
    assert jq.meta["source_url"].endswith("jq-1.8.2.tar.gz")      # not the `head` block url
    assert jq.meta["desc"].startswith("Lightweight")
    assert jq.meta["runtime_deps"] == ["oniguruma@6.9.10"]
    assert jq.meta["installed_at"]


def test_active_guess_without_opt_link(tmp_path):
    _keg(tmp_path, "wget", "1.21.4", link=False)
    _keg(tmp_path, "wget", "1.24.5_1", link=False)
    inv = _inv(tmp_path)
    (wget,) = _formulae(inv).values()
    assert wget.version == "1.24.5" and wget.meta["active_guess"] is True and wget.meta["active"] is True
    assert "keg_only" not in wget.meta            # no var/homebrew/linked dir: unknown
    assert len(_inv(tmp_path, all_kegs="true").components) == 2


def test_keg_without_receipt_and_corrupt_receipt(tmp_path):
    keg = _keg(tmp_path, "bad", "1.0")
    (keg / "INSTALL_RECEIPT.json").write_text("not json")
    k2 = _keg(tmp_path, "old", "0.9")
    (k2 / "INSTALL_RECEIPT.json").unlink()
    inv = _inv(tmp_path)
    assert {c.name for c in inv.components} == {"bad", "old"}
    assert any("INSTALL_RECEIPT.json" in w for w in inv.warnings)
    assert _formulae(inv)[("old", "0.9")].meta["no_receipt"] is True


# --------------------------------------------------------------------------- upstream identity

def test_upstream_repo_and_tag_from_url_and_sbom():
    f = _formulae(_inv())
    jq, xz, httpie = f[("jq", "1.8.2")], f[("xz", "5.8.4")], f[("httpie", "3.2.4")]
    assert jq.meta["upstream_repo"] == "github.com/jqlang/jq" and jq.meta["upstream_tag"] == "jq-1.8.2"
    assert jq.meta["upstream_version"] == "1.8.2"                 # from the SBOM source archive
    assert xz.meta["upstream_repo"] == "github.com/tukaani-project/xz" and xz.meta["upstream_tag"] == "v5.8.4"
    assert httpie.meta["upstream_repo"] == "github.com/httpie/cli" and httpie.meta["upstream_tag"] == "3.2.4"


def test_repo_from_url_patterns():
    assert repo_from_url("https://github.com/Foo/Bar.git") == "github.com/foo/bar"
    assert repo_from_url("https://jqlang.github.io/jq/") == "github.com/jqlang/jq"
    assert repo_from_url("https://raw.githubusercontent.com/o/r/HEAD/x") == "github.com/o/r"
    assert repo_from_url("https://gitlab.com/g/p/-/archive/v1/p-v1.tar.gz") == "gitlab.com/g/p"
    assert repo_from_url("https://gitlab.gnome.org/GNOME/gtk/-/archive/4/x.tar.gz") == "gitlab.gnome.org/GNOME/gtk"
    assert repo_from_url("https://codeberg.org/o/r/archive/v1.tar.gz") == "codeberg.org/o/r"
    assert repo_from_url("https://downloads.sourceforge.net/project/libpng/libpng16/1.6/x.tgz") \
        == "sourceforge.net/projects/libpng"
    assert repo_from_url("https://ftp.gnu.org/gnu/wget/wget-1.0.tar.gz") is None
    assert repo_from_url("https://github.com/downloads/x/y") is None
    assert tag_from_url("https://github.com/a/b/archive/refs/tags/v2.1.tar.gz") == "v2.1"
    assert tag_from_url("https://github.com/a/b/archive/v2.1.tar.gz") == "v2.1"
    assert tag_from_url("https://example.org/x/archive/v2.1.tar.gz") is None


def test_registry_purl_from_url():
    assert registry_purl_from_url(
        "https://files.pythonhosted.org/packages/ab/cd/Foo_Bar-1.2.3.tar.gz") == "pkg:pypi/foo-bar@1.2.3"
    assert registry_purl_from_url("https://registry.npmjs.org/@scope/pkg/-/pkg-4.5.6.tgz") \
        == "pkg:npm/%40scope/pkg@4.5.6"
    assert registry_purl_from_url("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz") \
        == "pkg:npm/left-pad@1.3.0"
    assert registry_purl_from_url("https://static.crates.io/crates/ripgrep/ripgrep-14.1.0.crate") \
        == "pkg:cargo/ripgrep@14.1.0"
    assert registry_purl_from_url("https://github.com/a/b/x.tar.gz") is None


def test_vendored_python_dists_as_pypi_libraries():
    inv = _inv()
    libs = {c.name: c for c in inv.components if c.category == CAT_LIBRARY}
    assert len(libs) == 14
    assert libs["requests"].purl == "pkg:pypi/requests@2.34.2"
    assert libs["urllib3"].version == "2.8.0"
    assert all(c.meta["via_brew"] == "httpie" for c in libs.values())
    assert "pkg:pypi/httpie@3.2.4" in {c.purl for c in libs.values()}
    assert libs["requests"].source_path.endswith("site-packages/requests-2.34.2.dist-info/METADATA")
    for c in libs.values():
        classify(c)
    assert libs["requests"].ecosystem == "PyPI"


def test_sbom_registry_purl_emits_library_component(tmp_path):
    sbom = {"packages": [
        {"SPDXID": "SPDXRef-Archive-yt-dlp-src", "name": "yt-dlp", "versionInfo": "2026.3.1",
         "downloadLocation": "https://files.pythonhosted.org/packages/aa/bb/yt_dlp-2026.3.1.tar.gz",
         "externalRefs": [
             {"referenceType": "purl", "referenceLocator": "pkg:brew/homebrew/core/yt-dlp@2026.3.1"},
             {"referenceType": "purl", "referenceLocator": "pkg:pypi/yt-dlp@2026.3.1"}]},
        {"SPDXID": "SPDXRef-Bottle-yt-dlp", "name": "yt-dlp", "versionInfo": "2026.3.1"}]}
    _keg(tmp_path, "yt-dlp", "2026.3.1", sbom=sbom)
    inv = _inv(tmp_path)
    (formula,) = _formulae(inv).values()
    assert formula.meta["upstream_purls"] == ["pkg:pypi/yt-dlp@2026.3.1"]
    (lib,) = [c for c in inv.components if c.category == CAT_LIBRARY]
    assert lib.purl == "pkg:pypi/yt-dlp@2026.3.1" and lib.version == "2026.3.1"
    assert lib.meta["via_brew"] == "yt-dlp"
    assert classify(lib).ecosystem == "PyPI"


def test_registry_purl_derived_from_formula_url_without_sbom(tmp_path):
    rb = ('class Foo < Formula\n  desc "x"\n  homepage "https://example.org"\n'
          '  url "https://registry.npmjs.org/foo-cli/-/foo-cli-2.0.1.tgz"\n  license "MIT"\nend\n')
    _keg(tmp_path, "foo-cli", "2.0.1", rb=rb)
    libs = [c for c in _inv(tmp_path).components if c.category == CAT_LIBRARY]
    assert [c.purl for c in libs] == ["pkg:npm/foo-cli@2.0.1"]


def test_vendored_node_modules_and_global_site_packages(tmp_path):
    keg = _keg(tmp_path, "nodecli", "1.0.0")
    nm = keg / "libexec/lib/node_modules/nodecli/node_modules/left-pad"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"name": "left-pad", "version": "1.3.0"}')
    g = tmp_path / "lib/node_modules/globalpkg"
    g.mkdir(parents=True)
    (g / "package.json").write_text('{"name": "globalpkg", "version": "2.0.0"}')
    libs = {c.name: c for c in _inv(tmp_path).components if c.category == CAT_LIBRARY}
    assert libs["left-pad"].meta["via_brew"] == "nodecli" and libs["left-pad"].purl == "pkg:npm/left-pad@1.3.0"
    sp = tmp_path / "lib/python3.14/site-packages/idna-3.20.dist-info"
    sp.mkdir(parents=True)
    (sp / "METADATA").write_text("Metadata-Version: 2.1\nName: idna\nVersion: 3.20\n")
    libs = {c.name: c for c in _inv(tmp_path).components if c.category == CAT_LIBRARY}
    assert libs["idna"].purl == "pkg:pypi/idna@3.20" and libs["idna"].meta["brew_global"] is True
    assert libs["globalpkg"].source_path.endswith("/lib/node_modules/globalpkg/package.json")
    assert libs["globalpkg"].meta["brew_global"] is True and "via_brew" not in libs["globalpkg"].meta


def test_shared_vendored_library_deduped_across_kegs(tmp_path):
    for n in ("a", "b"):
        keg = _keg(tmp_path, n, "1.0")
        d = keg / "libexec/lib/python3.15/site-packages/idna-3.20.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text("Metadata-Version: 2.1\nName: idna\nVersion: 3.20\n")
    (idna,) = [c for c in _inv(tmp_path).components if c.name == "idna"]
    assert idna.meta["via_brew"] == "a" and idna.meta["via_brew_all"] == ["a", "b"]


# --------------------------------------------------------------------------- formula text

def test_patched_cves_from_patch_stanzas():
    rb = '''class Foo < Formula
  desc "x"
  homepage "https://example.org"
  url "https://example.org/foo-1.0.tar.gz"
  license any_of: [
    "MIT",
    "Apache-2.0",
  ]
  deprecate! date: "2026-01-01", because: :unmaintained

  # Backport of the fix for CVE-2025-1111
  patch do
    url "https://example.org/fix.patch"
    sha256 "abc"
  end

  patch do
    url "https://github.com/foo/foo/commit/abc.patch?full_index=1"
    sha256 "abc"
    resolves "CVE-2025-2222" # also cve-2025-3333 in the description
  end

  patch :p1, <<~EOS
    CVE-2025-4444 inline
  EOS

  def install
    # CVE-2025-9999 is only mentioned in code, not a patch
  end
end
'''
    f = parse_formula_rb(rb)
    assert f["patched_cves"] == ["CVE-2025-1111", "CVE-2025-2222", "CVE-2025-3333", "CVE-2025-4444"]
    assert f["license"] == "MIT OR Apache-2.0"
    assert f["deprecated"] is True and "disabled" not in f
    assert f["url"] == "https://example.org/foo-1.0.tar.gz"


def test_stable_block_url_fallback():
    f = parse_formula_rb('class A < Formula\n  stable do\n    url "https://x.org/a-1.tgz"\n  end\nend\n')
    assert f["url"] == "https://x.org/a-1.tgz"


def test_patched_cves_in_component_meta(tmp_path):
    _keg(tmp_path, "jq", "1.7.1", rb='class Jq < Formula\n  patch do\n    url "x"\n    resolves "CVE-2025-48060"\n'
         '  end\nend\n')
    (jq,) = _formulae(_inv(tmp_path)).values()
    assert jq.meta["patched_cves"] == ["CVE-2025-48060"]


# --------------------------------------------------------------------------- casks

def test_casks_auto_updates_latest_and_plain():
    inv = _inv()
    chrome, fusion, boop = _cask(inv, "google-chrome"), _cask(inv, "autodesk-fusion"), _cask(inv, "boop")
    assert chrome.category == CAT_APPLICATION and chrome.name == "Google Chrome"
    assert chrome.version == "157.0.8103.39"
    assert chrome.meta["auto_updates"] is True and chrome.meta["version_stale_possible"] is True
    assert chrome.meta["cask_apps"] == ["Google Chrome.app"]
    assert fusion.version is None and fusion.meta["version_latest"] is True
    assert fusion.meta["brew_version"] == "latest" and "com.autodesk.fusion" in fusion.meta["cask_bundle_ids"]
    assert boop.version == "1.4.0" and "version_stale_possible" not in boop.meta
    assert boop.purl == "pkg:brew/homebrew/cask/boop@1.4.0"


def test_cask_minimal_json_metadata_and_pinned(tmp_path):
    cask = tmp_path / "Caskroom/foo"
    meta = cask / ".metadata/2.0/20261001000000.000/Casks"
    meta.mkdir(parents=True)
    (meta / "foo.json").write_text(json.dumps({"url_specs": {}, "version": "2.0"}))
    (cask / "2.0/Foo.app").mkdir(parents=True)
    (cask / "1.0").mkdir()
    (tmp_path / "var/homebrew/pinned_casks").mkdir(parents=True)
    (tmp_path / "var/homebrew/pinned_casks/foo").symlink_to("../../../Caskroom/foo/2.0")
    c = _cask(_inv(tmp_path), "foo")
    assert c.version == "2.0" and c.meta["cask_apps"] == ["Foo.app"] and c.meta["pinned"] is True


# --------------------------------------------------------------------------- prefixes

def test_linuxbrew_prefix_discovery(tmp_path):
    lb = tmp_path / "home/linuxbrew/.linuxbrew"
    shutil.copytree(PREFIX / "Cellar" / "xz", lb / "Cellar" / "xz")
    (lb / "opt").mkdir()
    (lb / "opt/xz").symlink_to("../Cellar/xz/5.8.4")
    assert find_prefixes(tmp_path) == [lb]
    inv = _inv(tmp_path)
    xz = _formulae(inv)[("xz", "5.8.4")]
    assert xz.source_path == "/home/linuxbrew/.linuxbrew/Cellar/xz/5.8.4"
    assert inv.asset.id == f"homebrew:{tmp_path.name}"
    assert _inv(lb).components[0].name == "xz"                    # target = the prefix itself


def test_home_linuxbrew_and_intel_prefixes(tmp_path):
    _keg(tmp_path / "usr/local", "a", "1.0")
    _keg(tmp_path / "home/alice/.linuxbrew", "b", "1.0")
    comps, warnings = collect_prefixes(tmp_path, {})
    assert {c.name for c in comps} == {"a", "b"} and warnings == []


def test_no_prefix_warns(tmp_path):
    inv = _inv(tmp_path)
    assert inv.components == [] and any("no Homebrew prefix" in w for w in inv.warnings)


def test_macos_collector_uses_homebrew_walk():
    from secmonk.collectors.homebrew import parse_brew_info_json
    from secmonk.collectors.macos import parse_brew_info_json as reexported
    assert reexported is parse_brew_info_json


# --------------------------------------------------------------------------- identity

def _formula(name, version="1.0", **meta):
    return Component(name=name, version=version, category=CAT_PACKAGE,
                     meta={"brew_name": name, "brew_kind": "formula", **meta})


def test_identity_seed_beats_alias_and_name():
    c = classify(_formula("curl", "8.7.1", homepage="https://curl.se"))
    assert (c.vendor, c.meta["product"], c.meta["product_source"]) == ("curl", "curl", "brew-seed")
    assert c.meta["vendor_alts"] == ["haxx"] and c.cpe.startswith("cpe:2.3:a:curl:curl:8.7.1")
    # `git` is in the alias table; seed has precedence only if present
    git = classify(_formula("git"))
    assert git.meta["product_source"] in ("brew-seed", "alias-table")
    py = classify(_formula("python@3.12", "3.12.4"))
    assert py.meta["product_source"] == "brew-seed" and py.meta["product"] == "cpython"
    assert py.vendor == "python software foundation"
    assert py.meta["product_alts"] == ["python"] and py.meta["vendor_alts"] == ["python"]


def test_identity_alias_table_when_not_in_seed(monkeypatch):
    from secmonk.engine import classify as cl

    monkeypatch.setattr(cl, "brew_seed", dict)
    c = classify(_formula("git"))
    assert c.meta["product_source"] == "alias-table" and c.vendor


def test_identity_name_vendor_from_upstream_repo_or_homepage():
    c = classify(_formula("zzz-tool", upstream_repo="github.com/acme-corp/zzz-tool"))
    assert c.meta["product_source"] == "brew-name-vendor"
    assert c.meta["vendor_hint"] == "acme-corp" and c.vendor is None
    c = classify(_formula("zzz-lib@2", homepage="https://www.zzz-lib.example.co.uk/docs"))
    assert c.meta["product_source"] == "brew-name-vendor" and c.meta["product"] == "zzz-lib"
    assert c.meta["vendor_hint"] == "example"
    assert brew_vendor_guess({"homepage": "https://jqlang.github.io/jq/"}) == "jqlang"
    assert brew_vendor_guess({"homepage": "https://github.com/x"}) is None


def test_identity_normalized_name_fallback():
    c = classify(_formula("portal"))
    assert c.meta["product_source"] == "normalized-name" and c.meta["product"] == "portal"
    assert "vendor_hint" not in c.meta


def test_classify_is_idempotent_for_brew():
    c = classify(_formula("curl", "8.7.1"))
    snapshot = (c.vendor, dict(c.meta), c.cpe)
    classify(c)
    assert (c.vendor, c.meta, c.cpe) == snapshot


# --------------------------------------------------------------------------- matching

def _vuln_prefix(tmp_path: Path, *, patched: str | None = None, version="1.7.1") -> Path:
    jq_rb = (PREFIX / "Cellar/jq/1.8.2/.brew/jq.rb").read_text().replace("1.8.2", version)
    if patched:
        jq_rb = jq_rb.replace('  depends_on "oniguruma"', f'  patch do\n    url "https://example.org/x.patch"\n'
                              f'    resolves "{patched}"\n  end\n\n  depends_on "oniguruma"', 1)
    _keg(tmp_path, "jq", version, rb=jq_rb)
    return tmp_path


def _scan(conn, prefix: Path):
    inv = _inv(prefix)
    save_inventory(conn, inv)
    stats = match_asset(conn, inv.asset.id)
    rows = conn.execute("SELECT f.*, c.name FROM finding f JOIN component c ON c.id=f.component_id "
                        "WHERE f.asset_id=?", (inv.asset.id,)).fetchall()
    return stats, rows


def test_match_brew_seed_finding(conn, tmp_path):
    CveListSource().sync(conn, SyncOptions(path=CVES))
    stats, rows = _scan(conn, _vuln_prefix(tmp_path))
    assert [(r["vuln_id"], r["matched_by"], r["name"]) for r in rows] == [("CVE-2025-48060", "cve-product", "jq")]
    assert rows[0]["confidence"] >= 0.8 and rows[0]["confidence"] == 0.85
    assert stats["patched"] == 0


def test_match_fixed_version_not_flagged(conn, tmp_path):
    CveListSource().sync(conn, SyncOptions(path=CVES))
    _, rows = _scan(conn, _vuln_prefix(tmp_path, version="1.8.2"))
    assert rows == []


def test_match_xz_range_and_vendor(conn, tmp_path):
    CveListSource().sync(conn, SyncOptions(path=CVES))
    _keg(tmp_path, "xz", "5.8.0")
    _, rows = _scan(conn, tmp_path)
    assert [r["vuln_id"] for r in rows] == ["CVE-2025-31115"] and rows[0]["confidence"] >= 0.8


def test_patched_cves_suppress_finding(conn, tmp_path):
    CveListSource().sync(conn, SyncOptions(path=CVES))
    stats, rows = _scan(conn, _vuln_prefix(tmp_path, patched="CVE-2025-48060"))
    assert rows == [] and stats["patched"] == 1


def test_scan_cli_homebrew_prefix(tmp_path):
    db = tmp_path / "t.db"
    c = connect(str(db))
    CveListSource().sync(c, SyncOptions(path=CVES))
    c.close()
    prefix = _vuln_prefix(tmp_path / "pfx")
    res = CliRunner().invoke(app, ["scan", "homebrew", str(prefix), "--db", str(db)])
    assert res.exit_code == 0, res.output
    c = connect(str(db))
    assert [r["vuln_id"] for r in c.execute("SELECT vuln_id FROM finding")] == ["CVE-2025-48060"]
    res = CliRunner().invoke(app, ["collect", "homebrew", str(PREFIX), "-o", "all_kegs=true", "--quiet",
                                   "--json", str(tmp_path / "inv.json"), "--db", str(db)])
    assert res.exit_code == 0, res.output
    versions = {c["version"] for c in json.loads((tmp_path / "inv.json").read_text())["components"]
                if c["name"] == "jq" and c["meta"].get("brew_kind") == "formula"}
    assert versions == {"1.8.1", "1.8.2"}


# --------------------------------------------------------------------------- real prefix (macOS 26.5 arm64)

def test_real_prefix_formulae_link_state():
    inv = _inv(REAL / "prefix")
    assert inv.warnings == []
    f = _formulae(inv)
    assert set(f) == {("xz", "5.8.3"), ("zlib", "1.2.13"), ("libpng", "1.6.58"), ("nomad", "1.6.3")}
    xz, zlib, png = f[("xz", "5.8.3")], f[("zlib", "1.2.13")], f[("libpng", "1.6.58")]
    assert xz.meta["linked"] is True and xz.meta["keg_only"] is False and xz.meta["tap"] == "homebrew/core"
    assert xz.meta["poured_from_bottle"] is True and xz.meta["homebrew_version"] == "5.1.3-4-g8fbdcb7"
    assert zlib.meta["keg_only"] is True and zlib.meta["linked"] is False       # `keg_only :provided_by_macos`
    # unlinked but NOT keg-only (`brew unlink`): link state alone must not imply keg_only
    assert png.meta["keg_only"] is False and png.meta["linked"] is False
    assert all(c.meta["active"] is True and "active_guess" not in c.meta for c in f.values())
    assert xz.meta["brew_prefix"] == str(REAL / "prefix")


def test_real_source_built_tap_formula_without_sbom():
    nomad = _formulae(_inv(REAL / "prefix"))[("nomad", "1.6.3")]
    assert nomad.purl == "pkg:brew/hashicorp/tap/nomad@1.6.3" and nomad.meta["tap"] == "hashicorp/tap"
    assert nomad.meta["poured_from_bottle"] is False and "upstream_version" not in nomad.meta
    assert nomad.meta["homepage"] == "https://www.nomadproject.io/"
    assert "source_url" not in nomad.meta        # `url` only inside `if OS.mac? && ...` blocks: not read


def test_real_sbom_shape_archive_has_no_registry_purl():
    """Real brew SBOMs: the `Archive-<f>-src` package has no purl (or only a pkg:brew one);
    the `pkg:brew/homebrew/core/<f>@<v>` purl sits on the `Bottle-<f>` package."""
    keg = REAL / "prefix/Cellar/xz/5.8.3"
    d = json.loads((keg / "sbom.spdx.json").read_text())
    bottle = next(p for p in d["packages"] if p["SPDXID"] == "SPDXRef-Bottle-xz")
    assert bottle["externalRefs"][0]["referenceLocator"] == "pkg:brew/homebrew/core/xz@5.8.3"
    s = parse_sbom(d)
    assert s["purls"] == [] and s["version"] == "5.8.3"
    assert s["download"].startswith("https://github.com/tukaani-project/xz/releases/download/v5.8.3/")
    xz = _formulae(_inv(REAL / "prefix"))[("xz", "5.8.3")]
    assert xz.meta["upstream_repo"] == "github.com/tukaani-project/xz" and xz.meta["upstream_tag"] == "v5.8.3"
    assert "upstream_purls" not in xz.meta


def test_real_casks_api_json_metadata_and_renamed_token(tmp_path):
    prefix = tmp_path / "prefix"
    shutil.copytree(REAL / "prefix", prefix, symlinks=True)
    # brew links Caskroom/<t>/<v>/<App>.app -> /Applications/<App>.app (absolute; dangling here, never followed)
    (prefix / "Caskroom/orbstack/1.11.3,19358/OrbStack.app").symlink_to(tmp_path / "Applications/OrbStack.app")
    inv = _inv(prefix)
    casks = {c.meta["brew_name"]: c for c in inv.components if c.meta.get("brew_kind") == "cask"}
    assert set(casks) == {"kopiaui", "orbstack", "redis-stack", "aws-vault-binary"}   # aws-vault -> symlink
    kopia, orb, redis = casks["kopiaui"], casks["orbstack"], casks["redis-stack"]
    # API-installed casks store a minimal `<token>.json` (no name/version/auto_updates): token as name
    assert kopia.name == "kopiaui" and kopia.version == "0.14.0" and kopia.meta["cask_apps"] == ["KopiaUI.app"]
    assert orb.version == "1.11.3,19358" and orb.purl == "pkg:brew/homebrew/cask/orbstack@1.11.3%2C19358"
    assert orb.meta["cask_apps"] == ["OrbStack.app"]        # `{}` JSON: from the Caskroom/<ver>/*.app symlink
    assert orb.meta["tap"] == "homebrew/cask" and orb.meta["installed_on_request"] is True
    assert redis.name == "Redis Stack" and redis.version == "7.2.0-6"            # third-party `.rb`
    assert casks["aws-vault-binary"].version == "6.6.2"


def test_real_brew_info_json_active_keg_and_parity_with_walk():
    data = json.loads((REAL / "brew-info.json").read_text())
    cli = {c.name: c for c in parse_brew_info_json(data)}
    ssl = [c for c in parse_brew_info_json(data) if c.name == "openssl@3"]
    assert [c.version for c in ssl] == ["3.6.3"]                 # linked_keg, not every installed[] keg
    assert {c.version for c in parse_brew_info_json(data, all_kegs=True) if c.name == "openssl@3"} == \
        {"3.6.2", "3.6.3"}
    assert cli["zlib"].meta["keg_only"] is True and cli["zlib"].meta["linked"] is False
    assert cli["xz"].meta["linked"] is True and cli["xz"].meta["active"] is True
    assert cli["OrbStack"].meta["auto_updates"] is True
    walk = {c.meta["brew_name"]: c.purl for c in _inv(REAL / "prefix").components if c.meta.get("brew_kind")}
    for token in ("xz", "zlib", "libpng", "kopiaui", "orbstack"):
        cli_purl = next(c.purl for c in cli.values() if c.meta["brew_name"] == token)
        assert cli_purl == walk[token], token


def test_opt_link_into_renamed_rack_is_ignored(tmp_path):
    """Real case: `opt/sdl2 -> ../Cellar/sdl2-compat/2.32.70` while `Cellar/sdl2` keeps old kegs."""
    _keg(tmp_path, "foo", "1.0", link=False)
    _keg(tmp_path, "foo", "2.0", link=False)
    _keg(tmp_path, "foo-compat", "1.0")
    (tmp_path / "opt/foo").symlink_to("../Cellar/foo-compat/1.0")     # same basename as foo's old keg
    foo = next(c for c in _inv(tmp_path).components if c.name == "foo")
    assert foo.version == "2.0" and foo.meta["active_guess"] is True


def test_same_formula_in_two_prefixes_keeps_both_locations(tmp_path):
    """Apple Silicon Mac with a leftover Intel /usr/local prefix: same purl in both."""
    _keg(tmp_path / "opt/homebrew", "pcre", "8.45")
    _keg(tmp_path / "usr/local", "pcre", "8.45")
    _keg(tmp_path / "usr/local", "lame", "3.100")
    comps, _ = collect_prefixes(tmp_path, {})
    (pcre,) = [c for c in comps if c.name == "pcre"]
    assert pcre.meta["paths"] == ["/opt/homebrew/Cellar/pcre/8.45", "/usr/local/Cellar/pcre/8.45"]
    assert next(c for c in comps if c.name == "lame").meta["brew_prefix"] == "/usr/local"
    # the first prefix's meta is kept; every prefix holding the same keg is listed
    assert pcre.meta["brew_prefix"] == "/opt/homebrew"
    assert pcre.meta["brew_prefixes"] == ["/opt/homebrew", "/usr/local"]
    assert "brew_prefixes" not in next(c for c in comps if c.name == "lame").meta


def test_live_known_prefix_uses_hostname_and_prefix(tmp_path, monkeypatch):
    _keg(tmp_path, "xz", "5.8.3")
    monkeypatch.setattr(hb, "KNOWN_PREFIXES", (str(tmp_path.resolve()).lstrip("/"),))
    monkeypatch.setattr(hb.socket, "gethostname", lambda: "testhost")
    assert _inv(tmp_path).asset.id == f"homebrew:testhost:{tmp_path.resolve()}"


def test_each_prefix_target_is_its_own_asset(conn, tmp_path, monkeypatch):
    """Scanning /opt/homebrew then /usr/local of the same host must not mark the first prefix's components
    removed: save_inventory diffs an asset against its latest complete scan."""
    from secmonk.engine.inventory import current_components

    arm, intel = tmp_path / "opt/homebrew", tmp_path / "usr/local"
    _keg(arm, "xz", "5.8.3")
    _keg(intel, "lame", "3.100")
    monkeypatch.setattr(hb, "KNOWN_PREFIXES", tuple(str(p.resolve()).lstrip("/") for p in (arm, intel)))
    monkeypatch.setattr(hb.socket, "gethostname", lambda: "testhost")
    inv_arm, inv_intel = _inv(arm), _inv(intel)
    assert inv_arm.asset.id != inv_intel.asset.id
    save_inventory(conn, inv_arm)
    save_inventory(conn, inv_intel)
    assert [r["name"] for r in current_components(conn, inv_arm.asset.id)] == ["xz"]
    assert [r["name"] for r in current_components(conn, inv_intel.asset.id)] == ["lame"]
    # the root (every prefix below it) keeps the bare host id
    assert _inv(tmp_path, hostname="testhost").asset.id == "homebrew:testhost"


def test_name_vendor_hint_lowers_confidence(conn, tmp_path):
    """Generic formula name matching a different vendor's product: below the default threshold."""
    CveListSource().sync(conn, SyncOptions(path=CVES))
    inv = _inv(tmp_path)  # empty: build the component by hand
    inv.components.append(Component(name="xz-fake", version="5.8.0", category=CAT_PACKAGE,
                                    meta={"brew_name": "xz-fake", "brew_kind": "formula", "product": "xz",
                                          "product_source": "brew-name-vendor", "vendor_hint": "ulikunitz"}))
    inv.components[-1].purl = "pkg:brew/xz-fake@5.8.0"
    save_inventory(conn, inv)
    match_asset(conn, inv.asset.id, min_confidence=0.0)
    (row,) = conn.execute("SELECT confidence FROM finding").fetchall()
    assert row["confidence"] == pytest.approx(0.3)
