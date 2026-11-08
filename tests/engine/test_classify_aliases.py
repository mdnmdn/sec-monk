"""Alias-table scoping (brew keys only for Homebrew components) and brew seed evidence order."""

from __future__ import annotations

from types import SimpleNamespace

from secmonk.engine import classify as cl
from secmonk.engine.classify import brew_aliases, brew_seed, classify, product_aliases
from secmonk.models import CAT_APPLICATION, CAT_PACKAGE, Component


def _app(name, version="1.0", **meta):
    return classify(Component(name, version, CAT_APPLICATION, source_path=f"/Applications/{name}.app",
                              meta=meta))


def _formula(name, version="1.0"):
    return classify(Component(name, version, CAT_PACKAGE, purl=f"pkg:brew/{name}@{version}",
                              meta={"brew_kind": "formula", "brew_name": name}))


# --------------------------------------------------------------------------- brew key scoping

def test_brew_keys_are_indexed_separately():
    assert "nomad" in brew_aliases() and "nomad" not in product_aliases()
    assert "visual studio code" in product_aliases() and "visual studio code" not in brew_aliases()


def test_app_named_like_a_brew_key_gets_no_brew_identity():
    # NoMAD.app (macOS AD helper) normalizes to 'nomad', the brew key of HashiCorp Nomad
    for c in (_app("NoMAD", "1.4.0", bundle_id="com.trusourcelabs.NoMAD"), _app("NoMAD.app"),
              _app("gd"), _app("fmt"), _app("Graphviz")):
        assert c.vendor != "hashicorp"
        assert c.meta["product_source"] == "normalized-name", c.name
        assert c.cpe is None


def test_windows_program_named_like_a_brew_key_gets_no_brew_identity():
    c = classify(Component("Nomad", "2.0", CAT_APPLICATION, meta={"product_hint": "Nomad"}))
    assert c.vendor is None and c.meta["product_source"] == "normalized-name"


def test_brew_formula_still_uses_brew_keys():
    c = _formula("nomad", "1.9.0")
    assert (c.vendor, c.meta["product"]) == ("hashicorp", "nomad")
    assert c.meta["product_source"] in ("alias-table", "brew-seed")
    # pkg:brew purl without brew meta is a Homebrew component too
    c = classify(Component("nomad", "1.9.0", CAT_PACKAGE, purl="pkg:brew/nomad@1.9.0"))
    assert c.vendor == "hashicorp"


def test_brew_formula_alias_without_seed(monkeypatch):
    monkeypatch.setattr(cl, "brew_seed", dict)
    c = _formula("nomad", "1.9.0")
    assert (c.vendor, c.meta["product"], c.meta["product_source"]) == ("hashicorp", "nomad", "alias-table")
    assert c.cpe == "cpe:2.3:a:hashicorp:nomad:1.9.0:*:*:*:*:*:*:*"


def test_cask_and_app_deduplicated_against_cask_use_brew_keys():
    cask = classify(Component("KopiaUI", "0.18.0", CAT_APPLICATION, purl="pkg:brew/homebrew/cask/kopiaui@0.18.0",
                              meta={"brew_kind": "cask", "brew_name": "kopiaui"}))
    assert (cask.vendor, cask.meta["product"]) == ("kopia", "kopia")
    # macOS collector folds the cask into the bundle: meta.also_cask carries the token
    app = _app("KopiaUI", "0.18.0", also_cask="kopiaui")
    assert (app.vendor, app.meta["product"], app.meta["product_source"]) == ("kopia", "kopia", "alias-table")
    # a direct-download KopiaUI.app (no cask) resolves through the `names` entry
    assert _app("KopiaUI", "0.18.0").meta["product"] == "kopia"


def test_app_aliases_unchanged():
    for c in (_app("Visual Studio Code", "1.95.0", bundle_id="com.microsoft.VSCode"),
              _app("Visual Studio Code", "1.95.0"), _app("Code", "1.95.0")):
        assert (c.vendor, c.meta["product"], c.meta["product_source"]) == \
            ("microsoft", "visual studio code", "alias-table")
    c = classify(Component("Microsoft Visual Studio Code (User)", "1.95.0", CAT_APPLICATION,
                           meta={"product_hint": "Microsoft Visual Studio Code (User)"}))
    assert c.meta["product"] == "visual studio code"
    c = _app("Google Chrome", "130.0", bundle_id="com.google.Chrome")
    assert c.cpe == "cpe:2.3:a:google:chrome:130.0:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------- seed evidence order

def test_nvd_cpe_evidence_ranks_after_manual():
    ranks = cl._SEED_EVIDENCE_RANK
    assert ranks["cve-affected"] < ranks["repo-url"] < ranks["manual"] < ranks["nvd-cpe"]


def test_brew_seed_sorts_nvd_cpe_last(monkeypatch):
    csv_text = ("formula,vendor,product,evidence\n"
                "zz,v1,p1,nvd-cpe\n"
                "zz,v2,p2,mystery\n"
                "zz,v3,p3,manual\n"
                "zz,v4,p4,cve-affected\n")
    fake = SimpleNamespace(joinpath=lambda _n: SimpleNamespace(read_text=lambda: csv_text))
    monkeypatch.setattr(cl, "resources", SimpleNamespace(files=lambda _pkg: fake))
    rows = brew_seed.__wrapped__()["zz"]
    assert [r["evidence"] for r in rows] == ["cve-affected", "manual", "nvd-cpe", "mystery"]


def test_real_seed_never_leads_with_nvd_cpe_when_a_cna_spelling_exists():
    for formula, rows in brew_seed().items():
        if any(r["evidence"] != "nvd-cpe" for r in rows):
            assert rows[0]["evidence"] != "nvd-cpe", formula
    assert brew_seed()["aom"][0] == {"vendor": "libaom", "product": "libaom", "evidence": "cve-affected"}
