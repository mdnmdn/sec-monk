"""scripts/docs.py: the repository docs pass the lint, and each check and writer behaves as _docs/_meta/tools.md says."""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "docs.py"
spec = importlib.util.spec_from_file_location("secmonk_docs_tool", SCRIPT)
docs = importlib.util.module_from_spec(spec)
sys.modules["secmonk_docs_tool"] = docs
spec.loader.exec_module(docs)

GOOD = ("title: T\nsummary: What is inside.\nread_when: you change T\ntype: feature\ncontext: features\n"
        "status: implemented\ntags: [x]\nupdated: 2026-11-07\nverified: 2026-11-07")


def _doc(tmp_path: Path, name: str, front: str, body: str = "# T\n") -> Path:
    p = tmp_path / name
    p.write_text(f"---\n{front}\n---\n{body}", encoding="utf-8")
    return p


def _loaded(p: Path, rel: str):
    d = docs.load_doc(p)
    d.rel = rel
    return d


def test_repo_docs_pass_the_lint(capsys):
    assert docs.main(["lint"]) == 0, capsys.readouterr().out


def test_check_doc_flags_convention_breaks(tmp_path):
    bad = ("title: T\nsummary: |\n  two\n  lines\ntype: reference\ncontext: tech\nstatus: bogus\ntags: [x]\n"
           "updated: 2026-11-07\nverified: 2999-01-01\nsample: fake\nreachable: maybe\nreview_cycle: weekly\n"
           "code: nope/missing.py\nrelated: [nope.md]")
    p = _doc(tmp_path, "bad.md", bad, "[a](missing.md) [b](#nowhere)\n```\n[skip](ignored.md)\n```\n")
    errs = "\n".join(docs.check_doc(p, "features/bad.md", docs.frontmatter(p)))
    for needle in ("missing read_when", "context 'tech' != folder 'features'", "type 'reference' must be 'feature'",
                   "status 'bogus'", "sample 'fake'", "reachable 'maybe'", "review_cycle 'weekly'",
                   "verified 2999-01-01 is in the future", "summary must be one non-empty line",
                   "code path not found", "related path not found", "broken link 'missing.md'", "anchor not found"):
        assert needle in errs, needle
    assert "ignored.md" not in errs


def test_check_doc_accepts_good_doc_and_yaml_booleans(tmp_path):
    p = _doc(tmp_path, "ok.md", GOOD + "\nreachable: no\ncode: [scripts/docs.py]\nfixtures: tests/*.py",
             "# Title\n[self](#title) [ext](https://example.org/x)\n")
    assert docs.check_doc(p, "features/ok.md", docs.frontmatter(p)) == []


def test_warnings_timelessness_open_work_and_link_repeats(tmp_path):
    body = ("# T\nThe parser previously skipped `currently` in code.\n## Known gaps\n"
            + "[x](a.md) " * 4 + "\n")
    d = _loaded(_doc(tmp_path, "w.md", GOOD, body), "tech/w.md")
    d.fm["status"] = "implemented"
    r = docs.Report()
    docs.check_l5(d, r)
    docs.check_l8(d, r)
    docs.check_l9(d, r)
    checks = [c for c, _, _ in r.warnings]
    assert checks.count("L5") == 1          # "previously"; `currently` inside a code span is ignored
    assert "L8" in checks and "L9" in checks


def test_plan_status_must_match_checkboxes(tmp_path):
    front = GOOD.replace("type: feature", "type: plan").replace("context: features", "context: plans")
    d = _loaded(_doc(tmp_path, "p.md", front.replace("implemented", "done") + "\nplatform: any",
                     "# P\n- [x] one\n- [ ] two\n"), "plans/p.md")
    r = docs.Report()
    docs.check_l7(d, r)
    assert [c for c, _, _ in r.errors] == ["L7"]


def test_set_field_rewrites_one_line_or_inserts_after_updated(tmp_path):
    p = _doc(tmp_path, "s.md", GOOD.replace("\nverified: 2026-11-07", ""), "# Body\nupdated: in body\n")
    assert docs.set_field(p, "verified", "2026-11-08")
    assert docs.set_field(p, "updated", "2026-11-09")
    assert not docs.set_field(p, "updated", "2026-11-09")
    text = p.read_text(encoding="utf-8")
    assert "updated: 2026-11-09\nverified: 2026-11-08\n" in text
    assert text.endswith("# Body\nupdated: in body\n")


def test_anchor_matching_for_touched():
    assert docs._anchor_matches("src/secmonk/sources/kev.py", "src/secmonk/sources/kev.py")
    assert docs._anchor_matches("tests/fixtures/sources/kev/", "tests/fixtures/sources/kev/a.json")
    assert docs._anchor_matches("tests/fixtures/lang/*", "tests/fixtures/lang/go/x")
    assert not docs._anchor_matches("src/secmonk/sources/kev.py", "src/secmonk/sources/kev.pyc.bak")


def test_new_scaffolds_from_template_and_refuses_overwrite(tmp_path, monkeypatch):
    root = tmp_path / "_docs"
    (root / "decisions").mkdir(parents=True)
    (root / "decisions" / "0007-x.md").write_text("x")
    monkeypatch.setattr(docs, "ROOT", root)
    monkeypatch.setattr(docs, "REPO", tmp_path)
    assert docs.run_new("decisions", "use-foo", None, "Use foo") == 0
    out = (root / "decisions" / "0008-use-foo.md").read_text(encoding="utf-8")
    assert "title: ADR-0008 — Use foo" in out and f"verified: {date.today().isoformat()}" in out
    with pytest.raises(SystemExit):
        docs.run_new("decisions", "Bad Slug", None, None)
