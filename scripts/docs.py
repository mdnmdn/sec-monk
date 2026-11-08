"""Documentation maintenance for `_docs/`: lint, index, new, touched, drift, stamp, verify and more.

Run `uv run python scripts/docs.py <command>` or the `mise run docs-*` tasks. Reference: `_docs/_meta/tools.md`;
the checks (L1..L12) are defined in `_docs/_meta/librarian.md`, the fields in `_docs/_meta/frontmatter.md`.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "_docs"
INDEX = ROOT / "INDEX.md"
TEMPLATES = ROOT / "_meta" / "templates"
REVIEW_LOG = ROOT / "_meta" / "review-log.md"
DUTY_POINTER = "_docs/_meta/authoring.md"

REQUIRED = ("title", "type", "context", "status", "summary", "read_when", "tags", "updated", "verified")
ORDER = ("product", "features", "tech", "references", "plans", "decisions", "inbox", "meta")
# folder -> (type, legal statuses); see _docs/_meta/frontmatter.md
FOLDERS = {
    "product": ("product", {"draft", "reference"}),
    "features": ("feature", {"draft", "implemented", "blocked"}),
    "tech": ("tech", {"draft", "implemented"}),
    "references": ("reference", {"draft", "reference", "implemented", "blocked"}),
    "plans": ("plan", {"draft", "open", "done"}),
    "decisions": ("decision", {"draft", "proposed", "accepted", "superseded"}),
    "inbox": ("proposal", {"draft", "proposed", "accepted", "rejected"}),
    "meta": ("meta", {"draft", "reference"}),
}
# `docs.py new <kind>` -> default template in _docs/_meta/templates/
NEW_TEMPLATES = {
    "features": "feature.md", "tech": "tech.md", "references": "reference.md", "plans": "plan.md",
    "decisions": "decision.md", "inbox": "proposal.md",
}
PLATFORMS = {"macos", "linux", "windows", "open-network", "any"}
SAMPLES = {"real", "synthetic", "mixed"}
REACHABLE = {"yes", "partial", "no"}
CYCLE_DAYS = {"monthly": 30, "quarterly": 91, "yearly": 365}
SUMMARY_MAX = 220

LENGTH_CEILING = 500          # L4: split by reader intent above this
FENCE_LINES_MAX = 45          # L4: ASCII diagrams are allowed, listings are not
MAX_LINK_REPEATS = 3          # L9
FRESHNESS_TOLERANCE_DAYS = 2  # L11
INBOX_STALE_DAYS = 14         # L7
TIMELESS_FOLDERS = ("features", "tech")  # L5: describe the current state
# "no longer" / "not yet" are domain words here (findings "no longer detected", urgency "not yet assigned").
BANNED_PHRASES = ("used to", "previously", "currently", "will be", "has been added", "was changed")
INDEX_DOC = "README.md"  # folder indexes and catalogues: read by lookup, exempt from L4 and L9
OPEN_WORK_HEADING = re.compile(r"^#{2,6}\s+.*\b(TODO|Open questions|Known gaps?)\b", re.IGNORECASE)
OPEN_WORK_FOLDERS = ("features", "tech", "references", "product")  # L8: open work belongs in plans/

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")
CHECKBOX_OPEN = re.compile(r"^\s*[-*] \[ \]", re.MULTILINE)
CHECKBOX_DONE = re.compile(r"^\s*[-*] \[[xX]\]", re.MULTILINE)


# ---------------------------------------------------------------- loading


@dataclass
class Doc:
    path: Path
    rel: str                       # relative to _docs/
    fm: dict
    body: str
    prose: list[str] = field(default_factory=list)          # body lines outside fences
    fences: list[tuple[int, int]] = field(default_factory=list)  # (start line, length)

    @property
    def folder(self) -> str:
        return self.rel.split("/")[0].lstrip("_") if "/" in self.rel else ""

    @property
    def repo_rel(self) -> str:
        return f"_docs/{self.rel}"

    def anchors(self) -> list[str]:
        """`code` + `fixtures`: the repository paths this doc describes (drift and touched read them)."""
        return [*_paths(self.fm.get("code")), *_paths(self.fm.get("fixtures"))]


def frontmatter(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    return yaml.safe_load(text[4:end]) if end > 0 else None


def _split(text: str) -> tuple[str, str]:
    if not text.startswith("---\n"):
        return "", text
    end = text.find("\n---", 4)
    return (text[4:end], text[end + 4:]) if end > 0 else ("", text)


def load_doc(path: Path) -> Doc:
    head, body = _split(path.read_text(encoding="utf-8"))
    try:
        fm = yaml.safe_load(head) if head else None
    except yaml.YAMLError as e:
        fm = {"__error__": str(e).splitlines()[0]}
    rel = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name
    doc = Doc(path, rel, fm if isinstance(fm, dict) else {}, body)
    if fm is None:
        doc.fm = {"__error__": "missing frontmatter"}
    fenced, start = False, 0
    for i, line in enumerate(body.splitlines()):
        if FENCE.match(line):
            if fenced:
                doc.fences.append((start, i - start - 1))
            fenced, start = not fenced, i
            continue
        if not fenced:
            doc.prose.append(line)
    return doc


def is_doc(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return rel != "INDEX.md" and "/templates/" not in f"/{rel}"


def load_docs() -> list[Doc]:
    return [load_doc(p) for p in sorted(ROOT.rglob("*.md")) if is_doc(p)]


def select(docs: list[Doc], paths: list[str]) -> list[Doc]:
    if not paths:
        return docs
    wanted = {(Path.cwd() / p).resolve() for p in paths}
    picked = [d for d in docs if d.path.resolve() in wanted or any(w in d.path.resolve().parents for w in wanted)]
    if not picked:
        sys.exit(f"no document matches {' '.join(paths)}")
    return picked


def _norm(value):
    """YAML 1.1 reads `no`/`yes` as booleans; map them back."""
    return {True: "yes", False: "no"}.get(value, value) if isinstance(value, bool) else value


def _paths(value) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def as_date(value) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def git(*args: str) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _dirty() -> set[str]:
    """Repo-relative files that differ from HEAD (modified, staged or untracked)."""
    out = git("status", "--porcelain", "--untracked-files=all")
    return {line[3:].split(" -> ")[-1].strip('"') for line in out.splitlines() if len(line) > 3}


_DIRTY: set[str] | None = None


def file_date(repo_rel: str) -> date | None:
    """Date of the last change: today for uncommitted edits, else the last commit, else the mtime."""
    global _DIRTY
    if _DIRTY is None:
        _DIRTY = _dirty()
    path = REPO / repo_rel
    if repo_rel in _DIRTY or any(d.startswith(repo_rel.rstrip("/") + "/") for d in _DIRTY):
        return date.today()
    stamp = git("log", "-1", "--format=%cs", "--", repo_rel)
    if stamp:
        return date.fromisoformat(stamp)
    return date.fromtimestamp(path.stat().st_mtime) if path.exists() else None


def anchor_date(doc: Doc) -> tuple[date | None, list[str]]:
    """Latest change among the anchored paths (globs expanded), and the paths that moved."""
    best, files = None, []
    for anchor in doc.anchors():
        for item in sorted(glob.glob(str(REPO / anchor))) or [str(REPO / anchor)]:
            rel = Path(item).relative_to(REPO).as_posix() if Path(item).is_absolute() else item
            d = file_date(rel)
            if d and (best is None or d > best):
                best = d
            files.append((rel, d))
    return best, [f for f, d in files if d == best]


# ---------------------------------------------------------------- checks


@dataclass
class Report:
    errors: list[tuple[str, str, str]] = field(default_factory=list)    # (check, doc, message)
    warnings: list[tuple[str, str, str]] = field(default_factory=list)

    def err(self, check: str, doc: str, msg: str) -> None:
        self.errors.append((check, doc, msg))

    def warn(self, check: str, doc: str, msg: str) -> None:
        self.warnings.append((check, doc, msg))


def _slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    s = re.sub(r"[`*_]|<[^>]+>|\[|\]\([^)]*\)", "", heading.strip().lower())
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", s))


_anchor_cache: dict[Path, set[str]] = {}


def heading_anchors(path: Path) -> set[str]:
    if path not in _anchor_cache:
        seen: dict[str, int] = {}
        out = set()
        for line in load_doc(path).prose:
            m = re.match(r"#{1,6}\s+(.*?)\s*#*$", line)
            if m:
                s = _slug(m.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else f"{s}-{n}")
        _anchor_cache[path] = out
    return _anchor_cache[path]


def check_doc(p: Path, rel: str, fm: dict) -> list[str]:
    """L1 (frontmatter) and L2 (references) for one document; returns error messages."""
    doc = load_doc(p)
    doc.rel, doc.fm = rel, fm
    report = Report()
    check_l1(doc, report)
    check_l2(doc, report)
    return [msg for _, _, msg in report.errors]


def check_l1(doc: Doc, r: Report) -> None:
    fm, rel = doc.fm, doc.rel
    if "__error__" in fm:
        r.err("L1", rel, f"{rel}: {fm['__error__']}")
        return
    missing = [k for k in REQUIRED if k not in fm]
    if missing:
        r.err("L1", rel, f"{rel}: missing {', '.join(missing)}")
    folder = doc.folder
    if folder in FOLDERS:
        typ, statuses = FOLDERS[folder]
        if fm.get("context") != folder:
            r.err("L1", rel, f"{rel}: context {fm.get('context')!r} != folder {folder!r}")
        if fm.get("type") != typ:
            r.err("L1", rel, f"{rel}: type {fm.get('type')!r} must be {typ!r} in {folder}/")
        if fm.get("status") not in statuses:
            r.err("L1", rel, f"{rel}: status {fm.get('status')!r} not one of {sorted(statuses)} in {folder}/")
        if "supersedes" in fm and folder != "decisions":
            r.err("L1", rel, f"{rel}: supersedes is for decisions only")
        if "platform" in fm and folder != "plans":
            r.err("L1", rel, f"{rel}: platform is for plans only")
        if folder == "plans" and fm.get("platform") not in PLATFORMS:
            r.err("L1", rel, f"{rel}: platform {fm.get('platform')!r} not one of {sorted(PLATFORMS)}")
    elif folder:
        r.err("L1", rel, f"{rel}: unknown top-level folder {folder!r}")
    if "sample" in fm and fm["sample"] not in SAMPLES:
        r.err("L1", rel, f"{rel}: sample {fm['sample']!r} not one of {sorted(SAMPLES)}")
    if "reachable" in fm and _norm(fm["reachable"]) not in REACHABLE:
        r.err("L1", rel, f"{rel}: reachable {fm['reachable']!r} not one of {sorted(REACHABLE)}")
    if "review_cycle" in fm and fm["review_cycle"] not in CYCLE_DAYS:
        r.err("L1", rel, f"{rel}: review_cycle {fm['review_cycle']!r} not one of {sorted(CYCLE_DAYS)}")
    for key in ("updated", "verified"):
        if key in fm:
            d = as_date(fm[key])
            if d is None:
                r.err("L1", rel, f"{rel}: {key} {fm[key]!r} is not a YYYY-MM-DD date")
            elif d > date.today():
                r.err("L1", rel, f"{rel}: {key} {d} is in the future")
    for key in ("summary", "read_when"):
        val = fm.get(key)
        if key in fm and (not isinstance(val, str) or not val.strip() or "\n" in val.strip()):
            r.err("L1", rel, f"{rel}: {key} must be one non-empty line")
    if isinstance(fm.get("summary"), str) and len(fm["summary"]) > SUMMARY_MAX:
        r.warn("L1", rel, f"{rel}: summary is {len(fm['summary'])} chars (aim for <= {SUMMARY_MAX})")


def check_l2(doc: Doc, r: Report) -> None:
    fm, rel, p = doc.fm, doc.rel, doc.path
    for key in ("code", "fixtures"):
        for item in _paths(fm.get(key)):
            if not (glob.glob(str(REPO / item)) or (REPO / item).exists()):
                r.err("L2", rel, f"{rel}: {key} path not found: {item!r} (paths only; prose belongs in the body)")
    for item in _paths(fm.get("related")):
        if not (ROOT / item).exists():
            r.err("L2", rel, f"{rel}: related path not found: {item!r}")
    for sup in _paths(fm.get("supersedes")):
        if not (ROOT / sup).exists():
            r.err("L2", rel, f"{rel}: supersedes path not found: {sup!r}")
    for line in doc.prose:
        for target in LINK.findall(line):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
                continue
            path_part, _, anchor = target.partition("#")
            dest = p if not path_part else (p.parent / path_part).resolve()
            if not dest.exists():
                r.err("L2", rel, f"{rel}: broken link {target!r}")
            elif anchor and dest.suffix == ".md" and anchor not in heading_anchors(dest):
                r.err("L2", rel, f"{rel}: anchor not found in {dest.name}: #{anchor}")


def check_l4(doc: Doc, r: Report) -> None:
    if doc.path.name == INDEX_DOC:
        return
    n = len(doc.body.splitlines())
    if n > LENGTH_CEILING:
        r.warn("L4", doc.rel, f"{doc.rel}: {n} lines (ceiling {LENGTH_CEILING}): split by reader intent")
    for start, length in doc.fences:
        if length > FENCE_LINES_MAX:
            r.warn("L4", doc.rel, f"{doc.rel}: fenced block of {length} lines (max {FENCE_LINES_MAX}) "
                                  f"after body line {start + 1}: name the source file instead")


def check_l5(doc: Doc, r: Report) -> None:
    if doc.folder not in TIMELESS_FOLDERS or doc.fm.get("status") != "implemented":
        return
    for line in doc.prose:
        low = re.sub(r"`[^`]*`", "", line).lower()
        for phrase in BANNED_PHRASES:
            if re.search(rf"\b{re.escape(phrase)}\b", low):
                r.warn("L5", doc.rel, f"{doc.rel}: {phrase!r} in {line.strip()[:80]!r}: describe the current state")


def check_l7(doc: Doc, r: Report) -> None:
    fm, rel = doc.fm, doc.rel
    if doc.folder == "inbox" and fm.get("status") in ("draft", "proposed"):
        d = as_date(fm.get("updated"))
        if d and (date.today() - d).days > INBOX_STALE_DAYS:
            r.warn("L7", rel, f"{rel}: {fm.get('status')} for {(date.today() - d).days} days: decide it")
    if doc.folder == "plans":
        open_items = len(CHECKBOX_OPEN.findall(doc.body))
        if fm.get("status") == "done" and open_items:
            r.err("L7", rel, f"{rel}: status done but {open_items} unchecked item(s)")
        if fm.get("status") == "open" and not open_items and CHECKBOX_DONE.search(doc.body):
            r.warn("L7", rel, f"{rel}: every item is checked: set status done")


def check_l8(doc: Doc, r: Report) -> None:
    if doc.folder not in OPEN_WORK_FOLDERS:
        return
    for line in doc.prose:
        if OPEN_WORK_HEADING.match(line):
            r.warn("L8", doc.rel, f"{doc.rel}: heading {line.strip()!r}: open work belongs in plans/")


def check_l9(doc: Doc, r: Report) -> None:
    if doc.path.name == INDEX_DOC or doc.folder == "plans":  # plans cross-link by design
        return
    counts: dict[str, int] = defaultdict(int)
    for line in doc.prose:
        for target in LINK.findall(line):
            if target.startswith("#"):
                continue
            counts[target.partition("#")[0]] += 1
    for target, n in sorted(counts.items()):
        if n > MAX_LINK_REPEATS:
            r.warn("L9", doc.rel, f"{doc.rel}: {target} linked {n} times (max {MAX_LINK_REPEATS})")


def check_l10(r: Report) -> None:
    agents = REPO / "AGENTS.md"
    if not agents.exists() or DUTY_POINTER not in agents.read_text(encoding="utf-8"):
        r.err("L10", "AGENTS.md", f"AGENTS.md: the duty pointer to {DUTY_POINTER} is missing")


def stale_docs(docs: list[Doc], tolerance: int) -> list[tuple[Doc, date, date]]:
    """L11: documents whose file changed more than `tolerance` days after their `updated` date."""
    out = []
    for doc in docs:
        upd, fd = as_date(doc.fm.get("updated")), file_date(doc.repo_rel)
        if upd and fd and (fd - upd).days > tolerance:
            out.append((doc, upd, fd))
    return out


def run_lint(paths: list[str], as_json: bool, strict: bool) -> int:
    all_docs = load_docs()
    docs = select(all_docs, paths)
    r = Report()
    for doc in docs:
        check_l1(doc, r)
        if "__error__" in doc.fm:
            continue
        check_l2(doc, r)
        check_l4(doc, r)
        check_l5(doc, r)
        check_l7(doc, r)
        check_l8(doc, r)
        check_l9(doc, r)
    for doc, upd, fd in stale_docs(docs, FRESHNESS_TOLERANCE_DAYS):
        r.err("L11", doc.rel, f"{doc.rel}: changed on {fd}, updated says {upd}: run `docs.py stamp`")
    check_l10(r)
    if not paths and (not INDEX.exists() or INDEX.read_text(encoding="utf-8") != render_index(all_docs)):
        r.err("L12", "INDEX.md", "INDEX.md is stale: run `docs.py index`")
    if as_json:
        print(json.dumps({"errors": [dict(zip(("check", "doc", "message"), e, strict=True)) for e in r.errors],
                          "warnings": [dict(zip(("check", "doc", "message"), w, strict=True)) for w in r.warnings]},
                         indent=2))
    else:
        for check, _, msg in r.warnings:
            print(f"warning {check} {msg}")
        for check, _, msg in r.errors:
            print(f"error   {check} {msg}")
        print(f"{len(docs)} docs: {len(r.errors)} error(s), {len(r.warnings)} warning(s)", file=sys.stderr)
    return 1 if r.errors or (strict and r.warnings) else 0


# ---------------------------------------------------------------- index


def _cell(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def render_index(docs: list[Doc]) -> str:
    by_ctx: dict[str, list[Doc]] = defaultdict(list)
    tags: dict[str, list[str]] = defaultdict(list)
    for doc in docs:
        by_ctx[doc.fm.get("context", "?")].append(doc)
        for t in doc.fm.get("tags") or []:
            tags[t].append(doc.rel)
    out = ["<!-- generated by scripts/docs.py index — do not edit -->", "# Docs index", "",
           ("One row per document: open the ones whose *Read when* matches your task. Structure: "
            "[_meta/README.md](_meta/README.md). If you change a claim, follow "
            "[_meta/authoring.md](_meta/authoring.md)."), ""]
    for ctx in sorted(by_ctx, key=lambda c: ORDER.index(c) if c in ORDER else 99):
        out += [f"## {ctx}", "", "| Doc | Summary | Read when | Status | Verified |", "|---|---|---|---|---|"]
        for doc in by_ctx[ctx]:
            fm = doc.fm
            status = str(fm.get("status"))
            status += f" · sample: {fm['sample']}" if fm.get("sample") else ""
            status += f" · reachable: {_norm(fm['reachable'])}" if fm.get("reachable") is not None else ""
            out.append(f"| [{_cell(fm.get('title', doc.rel))}]({doc.rel}) | {_cell(fm.get('summary'))} | "
                       f"{_cell(fm.get('read_when'))} | {status} | {fm.get('verified')} |")
        out.append("")
    out += ["## By tag", ""]
    for t in sorted(tags):
        out.append(f"- **{t}**: " + ", ".join(f"[{Path(r).stem}]({r})" for r in tags[t]))
    out.append("")
    return "\n".join(out)


def run_index(check: bool) -> int:
    content = render_index(load_docs())
    if check:
        if not INDEX.exists() or INDEX.read_text(encoding="utf-8") != content:
            print("INDEX.md is stale: run `docs.py index`")
            return 1
        return 0
    INDEX.write_text(content, encoding="utf-8")
    print(f"wrote {INDEX.relative_to(REPO)}")
    return 0


# ---------------------------------------------------------------- writers


def set_field(path: Path, key: str, value: str) -> bool:
    """Rewrite (or add after `updated:`) one frontmatter line; nothing else in the file changes."""
    text = path.read_text(encoding="utf-8")
    head, body = _split(text)
    if not head:
        return False
    lines = head.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(f"{key}:"):
            if line == f"{key}: {value}":
                return False
            lines[i] = f"{key}: {value}"
            break
    else:
        at = next((i + 1 for i, line in enumerate(lines) if line.startswith("updated:")), len(lines))
        lines.insert(at, f"{key}: {value}")
    path.write_text("---\n" + "\n".join(lines) + "\n---" + body, encoding="utf-8")
    return True


def run_new(kind: str, slug: str, template: str | None, title: str | None) -> int:
    if kind not in NEW_TEMPLATES:
        sys.exit(f"kind must be one of {', '.join(NEW_TEMPLATES)} (product and meta: copy a sibling)")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)?", slug):
        sys.exit("slug: lowercase words joined by '-', optionally one sub-folder (collectors/foo)")
    tpl = TEMPLATES / (template or NEW_TEMPLATES[kind])
    if not tpl.exists():
        sys.exit(f"template not found: {tpl.relative_to(REPO)}")
    today = date.today().isoformat()
    name = slug
    if kind == "decisions":
        nums = [int(m.group(1)) for p in (ROOT / "decisions").glob("*.md") if (m := re.match(r"(\d{4})-", p.name))]
        number = f"{max(nums, default=0) + 1:04d}"
        name = f"{number}-{slug}"
    elif kind == "inbox":
        name = f"{today}-{slug}"
    dest = ROOT / kind / f"{name}.md"
    if dest.exists():
        sys.exit(f"refusing to overwrite {dest.relative_to(REPO)}")
    text = tpl.read_text(encoding="utf-8").replace("YYYY-MM-DD", today)
    if kind == "decisions":
        text = text.replace("NNNN", number)
    if title:
        text = re.sub(r"<[A-Z][^>]*>", title, text, count=2)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    print(f"wrote {dest.relative_to(REPO)}: fill summary, read_when, tags and the sections, then run "
          "`docs.py index`")
    return 0


def run_stamp(check: bool) -> int:
    stale = stale_docs(load_docs(), FRESHNESS_TOLERANCE_DAYS)
    for doc, upd, fd in stale:
        verb = "would stamp" if check else "stamped"
        if not check:
            set_field(doc.path, "updated", fd.isoformat())
        note = "  (updated now passes verified: check it, then `docs.py verify`)" \
            if as_date(doc.fm.get("verified")) and as_date(doc.fm.get("verified")) < fd else ""
        print(f"{verb} {doc.repo_rel}: updated {upd} -> {fd}{note}")
    if not stale:
        print("nothing to stamp")
    return 1 if check and stale else 0


def run_verify(paths: list[str]) -> int:
    if not paths:
        sys.exit("name the documents you checked: docs.py verify <paths>")
    today = date.today().isoformat()
    for doc in select(load_docs(), paths):
        changed = set_field(doc.path, "verified", today)
        print(f"{'verified' if changed else 'unchanged'} {doc.repo_rel}: {today}")
    return 0


def run_log(scope: str, checks: str, counts: str, notes: str) -> int:
    text = REVIEW_LOG.read_text(encoding="utf-8")
    row = f"| {date.today().isoformat()} | {_cell(scope)} | {_cell(checks)} | {_cell(counts)} | {_cell(notes)} |"
    lines = text.split("\n")
    last = max(i for i, line in enumerate(lines) if line.startswith("|"))
    lines.insert(last + 1, row)
    REVIEW_LOG.write_text("\n".join(lines), encoding="utf-8")
    print(f"appended to {REVIEW_LOG.relative_to(REPO)}: {row}")
    return 0


# ---------------------------------------------------------------- reports


def run_changed(days: int) -> int:
    stale = stale_docs(load_docs(), days)
    for doc, upd, fd in stale:
        print(f"{doc.repo_rel}: file {fd}, updated {upd} (+{(fd - upd).days}d)")
    if not stale:
        print(f"every document is within {days} day(s) of its updated date")
    return 0


def drift(docs: list[Doc]) -> list[tuple[Doc, date, date, list[str]]]:
    out = []
    for doc in docs:
        ver = as_date(doc.fm.get("verified"))
        if not ver or not doc.anchors():
            continue
        moved, files = anchor_date(doc)
        if moved and moved > ver:
            out.append((doc, ver, moved, files))
    return out


def run_drift() -> int:
    rows = drift(load_docs())
    for doc, ver, moved, files in rows:
        shown = ", ".join(files[:3]) + (f" (+{len(files) - 3})" if len(files) > 3 else "")
        print(f"{doc.repo_rel}: verified {ver}, anchors moved {moved}: {shown}")
    print(f"{len(rows)} document(s) to re-check; after reading one, run `docs.py verify <path>`", file=sys.stderr)
    return 0


def run_review() -> int:
    n = 0
    for doc in load_docs():
        ver = as_date(doc.fm.get("verified"))
        cycle = doc.fm.get("review_cycle", "quarterly")
        if ver and (date.today() - ver).days > CYCLE_DAYS.get(cycle, 91):
            n += 1
            print(f"{doc.repo_rel}: verified {ver}, cycle {cycle}")
    print(f"{n} document(s) past their review cycle", file=sys.stderr)
    return 0


def _changed_files() -> list[str]:
    files = set(_dirty())
    base = next((b for ref in ("origin/main", "origin/master", "main", "master")
                 if (b := git("merge-base", "HEAD", ref)) and b != git("rev-parse", "HEAD")), "")
    if base:  # committed on this branch but not on main; without a main branch: uncommitted files only
        files |= set(git("diff", "--name-only", base, "HEAD").splitlines())
    return sorted(f for f in files if f)


def _anchor_matches(anchor: str, path: str) -> bool:
    a = anchor.rstrip("/")
    return path == a or path.startswith(a + "/") or fnmatch.fnmatch(path, anchor) \
        or (any(c in anchor for c in "*?[") and fnmatch.fnmatch(path, anchor.rstrip("/") + "/*"))


def run_touched(paths: list[str]) -> int:
    files = [Path(p).resolve().relative_to(REPO).as_posix() if Path(p).exists() else p for p in paths] \
        or _changed_files()
    files = [f for f in files if not f.startswith("_docs/")]
    if not files:
        print("no changed source files")
        return 0
    hits: dict[str, list[str]] = defaultdict(list)
    for doc in load_docs():
        for f in files:
            if any(_anchor_matches(a, f) for a in doc.anchors()):
                hits[doc.repo_rel].append(f)
    for rel, fs in sorted(hits.items()):
        print(f"{rel}  <- {', '.join(sorted(set(fs))[:4])}{' …' if len(set(fs)) > 4 else ''}")
    orphans = [f for f in files if f.startswith("src/") and not any(f in fs for fs in hits.values())]
    if orphans:
        print("\nno document anchors: " + ", ".join(orphans[:10]) + (" …" if len(orphans) > 10 else ""))
    print(f"{len(hits)} document(s) to check for {len(files)} changed file(s)", file=sys.stderr)
    return 0


def run_stats() -> int:
    docs = load_docs()
    by_folder: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    for d in docs:
        by_folder[d.folder or "(root)"] += 1
        by_status[str(d.fm.get("status"))] += 1
    lengths = sorted((len(d.body.splitlines()), d.rel) for d in docs)
    no_anchor = [d.rel for d in docs if d.folder in ("features", "tech", "references") and not d.anchors()]
    verified = sorted((as_date(d.fm.get("verified")) or date.min, d.rel) for d in docs)
    print(f"documents: {len(docs)}")
    print("by folder: " + ", ".join(f"{k} {v}" for k, v in sorted(by_folder.items())))
    print("by status: " + ", ".join(f"{k} {v}" for k, v in sorted(by_status.items())))
    print(f"length: median {lengths[len(lengths) // 2][0]} lines, longest {lengths[-1][0]} ({lengths[-1][1]})")
    print(f"features/tech/references without code or fixtures anchors: {len(no_anchor)}"
          + (f" ({', '.join(no_anchor[:5])}{' …' if len(no_anchor) > 5 else ''})" if no_anchor else ""))
    print(f"oldest verification: {verified[0][0]} ({verified[0][1]})")
    plans = [d for d in docs if d.folder == "plans"]
    print(f"plans: {sum(len(CHECKBOX_OPEN.findall(d.body)) for d in plans)} open item(s), "
          f"{sum(len(CHECKBOX_DONE.findall(d.body)) for d in plans)} done")
    inbox = [d for d in docs if d.folder == "inbox"]
    print("inbox: " + (", ".join(f"{d.rel} ({d.fm.get('status')})" for d in inbox) or "empty"))
    last = [line for line in REVIEW_LOG.read_text(encoding="utf-8").splitlines()
            if line.startswith("| 20")] if REVIEW_LOG.exists() else []
    print(f"last maintenance pass: {last[-1].split('|')[1].strip() if last else 'none logged'}")
    return 0


def run_inbox() -> int:
    docs = [d for d in load_docs() if d.folder == "inbox"]
    for d in docs:
        upd = as_date(d.fm.get("updated"))
        age = (date.today() - upd).days if upd else "?"
        cited = [o.rel for o in load_docs() if o is not d and d.rel.split("/")[-1] in o.body]
        flag = "  STALE: decide it" if isinstance(age, int) and age > INBOX_STALE_DAYS \
            and d.fm.get("status") in ("draft", "proposed") else ""
        print(f"{d.repo_rel}: {d.fm.get('status')}, {age} day(s), cited by {len(cited)}{flag}")
    if not docs:
        print("inbox is empty")
    return 0


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="docs.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lint", help="run the mechanical checks L1 L2 L4 L5 L7 L8 L9 L10 L11 L12")
    p.add_argument("paths", nargs="*")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="fail on warnings too")
    p = sub.add_parser("index", help="regenerate _docs/INDEX.md")
    p.add_argument("--check", action="store_true", help="fail if stale, write nothing")
    p = sub.add_parser("new", help="scaffold a document from _docs/_meta/templates/")
    p.add_argument("kind", choices=sorted(NEW_TEMPLATES))
    p.add_argument("slug")
    p.add_argument("--template", help="template file name, e.g. reference-vuln-source.md")
    p.add_argument("--title")
    p = sub.add_parser("touched", help="documents whose code/fixtures anchors cover changed files")
    p.add_argument("paths", nargs="*")
    p = sub.add_parser("changed", help="documents whose file moved after their updated date (L11)")
    p.add_argument("days", nargs="?", type=int, default=FRESHNESS_TOLERANCE_DAYS)
    sub.add_parser("drift", help="documents whose anchors changed after verified (L3)")
    sub.add_parser("review", help="documents past their review_cycle")
    p = sub.add_parser("stamp", help="repair the updated date of documents L11 flags")
    p.add_argument("--check", action="store_true", help="show the plan, write nothing")
    p = sub.add_parser("verify", help="record that you checked the named documents")
    p.add_argument("paths", nargs="+")
    sub.add_parser("stats", help="library counts and health")
    sub.add_parser("inbox", help="the proposals waiting for a decision")
    p = sub.add_parser("log", help="append one row to _docs/_meta/review-log.md")
    p.add_argument("--scope", required=True)
    p.add_argument("--checks", default="L1-L12")
    p.add_argument("--counts", default="—")
    p.add_argument("--notes", default="—")
    a = ap.parse_args(argv)
    match a.cmd:
        case "lint":
            return run_lint(a.paths, a.json, a.strict)
        case "index":
            return run_index(a.check)
        case "new":
            return run_new(a.kind, a.slug, a.template, a.title)
        case "touched":
            return run_touched(a.paths)
        case "changed":
            return run_changed(a.days)
        case "drift":
            return run_drift()
        case "review":
            return run_review()
        case "stamp":
            return run_stamp(a.check)
        case "verify":
            return run_verify(a.paths)
        case "stats":
            return run_stats()
        case "inbox":
            return run_inbox()
        case "log":
            return run_log(a.scope, a.checks, a.counts, a.notes)
    return 2


if __name__ == "__main__":
    sys.exit(main())
