"""scripts/docs_index.py --check: the docs follow _docs/_meta/frontmatter.md and the index is current."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "docs_index.py"
spec = importlib.util.spec_from_file_location("docs_index", SCRIPT)
docs_index = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs_index)


def _doc(tmp_path: Path, name: str, front: str, body: str = "# T\n") -> Path:
    p = tmp_path / name
    p.write_text(f"---\n{front}\n---\n{body}", encoding="utf-8")
    return p


GOOD = "title: T\ntype: feature\ncontext: features\nstatus: implemented\ntags: [x]\nupdated: 2026-11-07"


def test_repo_docs_pass_the_check(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["docs_index.py", "--check"])
    assert docs_index.main() == 0, capsys.readouterr().out


def test_check_doc_flags_convention_breaks(tmp_path):
    bad = ("title: T\ntype: reference\ncontext: tech\nstatus: bogus\ntags: [x]\nupdated: 2026-11-07\n"
           "sample: fake\nreachable: maybe\ncode: nope/missing.py\nrelated: [nope.md]")
    p = _doc(tmp_path, "bad.md", bad, "[a](missing.md) [b](#nowhere)\n```\n[skip](ignored.md)\n```\n")
    errs = "\n".join(docs_index.check_doc(p, "features/bad.md", docs_index.frontmatter(p)))
    for needle in ("context 'tech' != folder 'features'", "type 'reference' must be 'feature'", "status 'bogus'",
                   "sample 'fake'", "reachable 'maybe'", "code path not found", "related path not found",
                   "broken link 'missing.md'", "anchor not found"):
        assert needle in errs, needle
    assert "ignored.md" not in errs


def test_check_doc_accepts_good_doc_and_yaml_booleans(tmp_path):
    p = _doc(tmp_path, "ok.md", GOOD + "\nreachable: no\ncode: [scripts/docs_index.py]\nfixtures: tests/*.py",
             "# Title\n[self](#title) [ext](https://example.org/x)\n")
    assert docs_index.check_doc(p, "features/ok.md", docs_index.frontmatter(p)) == []
