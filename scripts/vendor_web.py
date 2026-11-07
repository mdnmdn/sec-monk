"""Vendor the web UI's JavaScript libraries into src/secmonk/web/static/vendor/ (ADR-0009).

    uv run python scripts/vendor_web.py            # fetch the pinned versions, verify, extract, write MANIFEST.json
    uv run python scripts/vendor_web.py --check    # offline: files match MANIFEST.json (also run by the tests)

Each package tarball comes from the npm registry and is verified against the registry's `dist.integrity` (sha512)
before anything is extracted; only the listed files are taken (no paths from the archive are trusted). To upgrade:
change VERSION below, run the script, update the <script> tags (app, _design pages, storybook; tests enforce it) and
re-run scripts/design_screenshots.js.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VENDOR = REPO / "src/secmonk/web/static/vendor"
REGISTRY = "https://registry.npmjs.org"

# package -> (version, files to copy from the tarball's package/ directory)
PACKAGES = {
    "vue": ("3.5.13", ["dist/vue.global.prod.js", "LICENSE"]),
    "vue-router": ("4.5.0", ["dist/vue-router.global.prod.js", "LICENSE"]),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch() -> None:
    sys.path.insert(0, str(REPO / "src"))
    from secmonk.sources.base import http_client

    manifest: dict = {"registry": REGISTRY, "packages": {}}
    with http_client(timeout=120) as http:
        for name, (version, files) in PACKAGES.items():
            meta = http.get(f"{REGISTRY}/{name}/{version}")
            meta.raise_for_status()
            dist = meta.json()["dist"]
            algo, _, digest = dist["integrity"].partition("-")
            if algo != "sha512":
                raise SystemExit(f"{name}: unexpected integrity algorithm {algo}")
            tgz = http.get(dist["tarball"])
            tgz.raise_for_status()
            if base64.b64encode(hashlib.sha512(tgz.content).digest()).decode() != digest:
                raise SystemExit(f"{name}@{version}: tarball does not match the registry integrity")
            out = VENDOR / f"{name}@{version}"
            out.mkdir(parents=True, exist_ok=True)
            entry = {"version": version, "tarball": dist["tarball"], "integrity": dist["integrity"], "files": {}}
            with tarfile.open(fileobj=io.BytesIO(tgz.content), mode="r:gz") as tf:
                for rel in files:
                    member = tf.getmember(f"package/{rel}")
                    if not member.isfile():
                        raise SystemExit(f"{name}: {rel} is not a regular file in the tarball")
                    data = tf.extractfile(member).read()
                    dest = out / Path(rel).name
                    dest.write_bytes(data)
                    entry["files"][f"{name}@{version}/{dest.name}"] = sha256(data)
            manifest["packages"][name] = entry
            print(f"vendored {name}@{version}: {', '.join(entry['files'])}")
    (VENDOR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


def check() -> list[str]:
    """Problems found (empty = ok): missing / modified / unlisted files."""
    problems: list[str] = []
    manifest = json.loads((VENDOR / "MANIFEST.json").read_text())
    listed: set[str] = set()
    for name, (version, _files) in PACKAGES.items():
        entry = manifest["packages"].get(name)
        if not entry or entry["version"] != version:
            problems.append(f"{name}: MANIFEST.json does not pin {version}")
            continue
        for rel, digest in entry["files"].items():
            listed.add(rel)
            p = VENDOR / rel
            if not p.is_file():
                problems.append(f"missing {rel}")
            elif sha256(p.read_bytes()) != digest:
                problems.append(f"modified {rel}")
    for p in VENDOR.rglob("*"):
        rel = p.relative_to(VENDOR).as_posix()
        if p.is_file() and rel not in listed and rel not in ("MANIFEST.json", "README.md"):
            problems.append(f"unlisted file {rel}")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="verify the vendored files offline")
    if ap.parse_args().check:
        problems = check()
        print("\n".join(problems) or "vendor ok")
        raise SystemExit(1 if problems else 0)
    fetch()


if __name__ == "__main__":
    main()
