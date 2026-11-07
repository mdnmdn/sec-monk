"""Regenerate _docs/INDEX.md from the YAML frontmatter of every doc.

Usage: uv run python scripts/docs_index.py [--check]
--check exits 1 if INDEX.md is stale or a doc breaks the conventions of _docs/_meta/frontmatter.md:
required keys; `context` equals the top-level folder; `type` / `status` / `platform` / `sample` /
`reachable` are legal for that folder; `code`, `fixtures` and `related` point at existing paths
(`code`/`fixtures`: repo-relative, comma-separated or a YAML list, globs allowed; `related`: relative
to _docs/); relative markdown links and `#anchors` resolve (code fences and external links skipped).
"""

from __future__ import annotations

import glob
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "_docs"
REQUIRED = ("title", "type", "context", "status", "tags", "updated")
ORDER = ("product", "features", "tech", "references", "plans", "decisions", "meta")
# folder -> (type, legal statuses); see _docs/_meta/frontmatter.md
FOLDERS = {
    "product": ("product", {"draft", "reference"}),
    "features": ("feature", {"draft", "implemented", "blocked"}),
    "tech": ("tech", {"draft", "implemented"}),
    "references": ("reference", {"draft", "reference", "implemented", "blocked"}),
    "plans": ("plan", {"draft", "open", "done"}),
    "decisions": ("decision", {"draft", "proposed", "accepted", "superseded"}),
    "meta": ("meta", {"draft", "reference"}),
}
PLATFORMS = {"macos", "linux", "windows", "open-network", "any"}
SAMPLES = {"real", "synthetic", "mixed"}
REACHABLE = {"yes", "partial", "no"}
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def frontmatter(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    return yaml.safe_load(text[4:end]) if end > 0 else None


def _norm(value):
    """YAML 1.1 reads `no`/`yes` as booleans; map them back."""
    return {True: "yes", False: "no"}.get(value, value) if isinstance(value, bool) else value


def _paths(value) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def _slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    s = re.sub(r"[`*_]|<[^>]+>|\[|\]\([^)]*\)", "", heading.strip().lower())
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", s))


def _body(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    end = text.find("\n---", 4) if text.startswith("---\n") else -1
    return text[end + 4:] if end > 0 else text


def _prose_lines(path: Path) -> list[str]:
    """Body lines outside fenced code blocks."""
    out, fenced = [], False
    for line in _body(path).splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if not fenced:
            out.append(line)
    return out


_anchor_cache: dict[Path, set[str]] = {}


def _anchors(path: Path) -> set[str]:
    if path not in _anchor_cache:
        seen: dict[str, int] = {}
        out = set()
        for line in _prose_lines(path):
            m = re.match(r"#{1,6}\s+(.*?)\s*#*$", line)
            if m:
                s = _slug(m.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else f"{s}-{n}")
        _anchor_cache[path] = out
    return _anchor_cache[path]


def check_doc(p: Path, rel: str, fm: dict) -> list[str]:
    errs: list[str] = []
    folder = rel.split("/")[0].lstrip("_") if "/" in rel else ""
    if folder in FOLDERS:
        typ, statuses = FOLDERS[folder]
        if fm.get("context") != folder:
            errs.append(f"{rel}: context {fm.get('context')!r} != folder {folder!r}")
        if fm.get("type") != typ:
            errs.append(f"{rel}: type {fm.get('type')!r} must be {typ!r} in {folder}/")
        if fm.get("status") not in statuses:
            errs.append(f"{rel}: status {fm.get('status')!r} not one of {sorted(statuses)} in {folder}/")
        if "supersedes" in fm and folder != "decisions":
            errs.append(f"{rel}: supersedes is for decisions only")
        if "platform" in fm and folder != "plans":
            errs.append(f"{rel}: platform is for plans only")
        if folder == "plans" and fm.get("platform") not in PLATFORMS:
            errs.append(f"{rel}: platform {fm.get('platform')!r} not one of {sorted(PLATFORMS)}")
    elif folder:
        errs.append(f"{rel}: unknown top-level folder {folder!r}")
    if "sample" in fm and fm["sample"] not in SAMPLES:
        errs.append(f"{rel}: sample {fm['sample']!r} not one of {sorted(SAMPLES)}")
    if "reachable" in fm and _norm(fm["reachable"]) not in REACHABLE:
        errs.append(f"{rel}: reachable {fm['reachable']!r} not one of {sorted(REACHABLE)}")
    for key in ("code", "fixtures"):
        for item in _paths(fm.get(key)):
            if not (glob.glob(str(REPO / item)) or (REPO / item).exists()):
                errs.append(f"{rel}: {key} path not found: {item!r} (paths only; prose belongs in the body)")
    for item in _paths(fm.get("related")):
        if not (ROOT / item).exists():
            errs.append(f"{rel}: related path not found: {item!r}")
    for sup in _paths(fm.get("supersedes")):
        if not (ROOT / sup).exists():
            errs.append(f"{rel}: supersedes path not found: {sup!r}")
    for line in _prose_lines(p):
        for target in LINK.findall(line):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
                continue
            path_part, _, anchor = target.partition("#")
            dest = p if not path_part else (p.parent / path_part).resolve()
            if not dest.exists():
                errs.append(f"{rel}: broken link {target!r}")
            elif anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
                errs.append(f"{rel}: anchor not found in {dest.name}: #{anchor}")
    return errs


def main() -> int:
    docs, problems = [], []
    for p in sorted(ROOT.rglob("*.md")):
        rel = p.relative_to(ROOT).as_posix()
        if rel == "INDEX.md" or "/templates/" in f"/{rel}":
            continue
        fm = frontmatter(p)
        if not fm:
            problems.append(f"{rel}: missing frontmatter")
            continue
        missing = [k for k in REQUIRED if k not in fm]
        if missing:
            problems.append(f"{rel}: missing {', '.join(missing)}")
        problems += check_doc(p, rel, fm)
        docs.append((rel, fm))

    by_ctx: dict[str, list] = defaultdict(list)
    tags: dict[str, list] = defaultdict(list)
    for rel, fm in docs:
        by_ctx[fm.get("context", "?")].append((rel, fm))
        for t in fm.get("tags") or []:
            tags[t].append(rel)

    out = ["<!-- generated by scripts/docs_index.py — do not edit -->", "# Docs index", "",
           "Structure and conventions: [_meta/README.md](_meta/README.md).", ""]
    for ctx in sorted(by_ctx, key=lambda c: ORDER.index(c) if c in ORDER else 99):
        out += [f"## {ctx}", "", "| Doc | Status | Updated | Tags |", "|---|---|---|---|"]
        for rel, fm in by_ctx[ctx]:
            extra = f" · sample: {fm['sample']}" if fm.get("sample") else ""
            extra += f" · reachable: {_norm(fm['reachable'])}" if fm.get("reachable") is not None else ""
            out.append(f"| [{fm.get('title', rel)}]({rel}) | {fm.get('status')}{extra} | "
                       f"{fm.get('updated')} | {', '.join(fm.get('tags') or [])} |")
        out.append("")
    out += ["## By tag", ""]
    for t in sorted(tags):
        out.append(f"- **{t}**: " + ", ".join(f"[{Path(r).stem}]({r})" for r in tags[t]))
    out.append("")
    content = "\n".join(out)

    index = ROOT / "INDEX.md"
    if "--check" in sys.argv:
        stale = not index.exists() or index.read_text() != content
        for pr in problems:
            print(pr)
        if stale:
            print("INDEX.md is stale — run scripts/docs_index.py")
        return 1 if (problems or stale) else 0
    index.write_text(content)
    for pr in problems:
        print("warning:", pr)
    print(f"wrote {index.relative_to(ROOT.parent)} ({len(docs)} docs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
