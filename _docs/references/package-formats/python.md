---
title: Python packages (PyPI, conda)
type: reference
context: references
status: implemented
tags: [package-format, dependencies, pypi]
updated: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/python/
code: src/secmonk/collectors/lang/python.py
related: [tech/collectors/dependencies.md]
---

# Python packages

PURL `pkg:pypi/<pep503-name>@<version>`, OSV ecosystem `PyPI`. The purl name is PEP 503 normalized
(`re.sub("[-_.]+", "-", n).lower()`, same as `engine.purl.normalize_name`) - note `packageurl` itself only lowercases
and maps `_` to `-`, so we normalize before building. The component `name` keeps the project's own spelling
(`Flask_Login`). conda packages are `pkg:conda/<name>@<version>` with **ecosystem None** (not matched against OSV PyPI).

## Parsers

| Parser | Match | Evidence |
|---|---|---|
| `python-dist-info` | `site-packages\|dist-packages/*.dist-info/METADATA` | installed |
| `python-egg-info` | `.../*.egg-info/PKG-INFO` in site/dist-packages | installed |
| `python-egg-info-file` | `.../dist-packages/<x>.egg-info` (single file, Debian) | installed |
| `conda-meta` | `conda-meta/*.json` | installed |
| `poetry-lock` | `poetry.lock` | lockfile |
| `pipfile-lock` | `Pipfile.lock` | lockfile |
| `uv-lock` | `uv.lock` | lockfile |
| `pdm-lock` | `pdm.lock` | lockfile |
| `requirements-txt` | `requirements*.txt`, `constraints*.txt`, `*-requirements.txt`, `requirements/*.txt` | manifest |

`pyproject.toml`, `Pipfile`, `setup.py` are not parsed (unpinned ranges). `.in` files are ignored.

## Fields

- **METADATA / PKG-INFO**: RFC 822 headers (`Name`, `Version`, `License-Expression`/`License`); body ignored. Meta
  `venv_root`: prefix before `lib/pythonX.Y/site-packages` or `Lib/site-packages` (a parser sees only path+bytes, so
  `pyvenv.cfg` is not consulted; the layout is what identifies the environment; walkers that read `pyvenv.cfg`
  can confirm it).
- **conda-meta/<name>-<ver>-<build>.json**: `name`, `version`, `channel` (URL or name -> meta `channel`, e.g.
  `conda-forge`), `build`, `subdir`. Python distributions installed by conda also carry a `dist-info` in
  site-packages, so they are additionally reported as PyPI via that parser. `history.json` (a list) is ignored.
- **poetry.lock**: `[[package]]` `name`, `version`; `groups = [...]` (Poetry >= 1.5; dev when `main` absent) or legacy
  `category = "dev"`; `source.type` directory/file skipped.
- **Pipfile.lock**: JSON `default` / `develop` (-> `dev`), `version: "==1.2.3"`; git/path/editable entries have no
  version and are skipped.
- **uv.lock**: `[[package]]` with `source = { registry|git|url|path|editable|virtual|directory }`; editable/virtual/
  directory skipped (the project itself). Dev is derived from the dependency graph: reachable only through the root's
  `[package.dev-dependencies]` => `dev`.
- **pdm.lock**: `groups = ["default"]` or other group => `dev` when `default` absent; repeated entries (extras
  combinations) are deduplicated; `editable = true` skipped.
- **requirements.txt**: only exact pins (`==`, `===`, no wildcard, no further `,` specifiers). Handles `\` continuations,
  `--hash` lines, comments (` #`), `pkg[extra1, extra2]` (meta `extras`), environment markers after `;` (meta
  `marker`), BOM. `-r`/`-c`/`-e`/`--*` lines and URL/path requirements are skipped (includes are NOT followed).

## Pitfalls

- Name spellings differ across files (`Flask_Login`, `flask-login`, `flask.login`): always compare PEP 503 forms.
- uv/pdm/poetry include markers and multiple platform variants; no environment resolution is done.
- A requirements pin is not proof of installation (evidence `manifest`).
- Poetry lock versions of transitive deps can differ from `pip freeze` in the image; installed metadata wins on dedupe.

## Fixtures

Real: `venv/lib/python3.13/site-packages/*.dist-info/METADATA` (headers only, from `uv pip install requests==2.25.0
urllib3==1.26.4`) + `venv/pyvenv.cfg`; `poetry/poetry.lock` (Poetry 2.5, lock-version 2.1), `uv/uv.lock` (uv 0.11),
`pdm/pdm.lock` (lock_version 4.5), `pipenv/Pipfile.lock` (spec 6). Synthetic: `requirements/requirements.txt`,
`egg/` (egg-info dir + single file), `conda/opt/conda/conda-meta/*.json`.
