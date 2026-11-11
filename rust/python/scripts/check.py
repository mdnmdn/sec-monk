"""One command for the Python side of the contracts: schemas, examples, catalog, manifests, golden outputs.

    uv run python scripts/check.py            # exit 1 on any failure
    uv run python scripts/check.py --manifests   # also rewrite modules/*.toml first

The full suite (protocol, conformance, safety, sources) is `uv run pytest -q`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str) -> int:
    print("$", " ".join(args))
    return subprocess.run(list(args), cwd=ROOT, check=False).returncode


def main() -> int:
    rc = 0
    if "--manifests" in sys.argv:
        rc |= run(sys.executable, "scripts/gen_manifests.py")
    rc |= run(sys.executable, "-m", "pytest", "-q", "tests/test_contracts.py")
    rc |= run(sys.executable, "scripts/golden.py")
    print("OK" if rc == 0 else "FAILED")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
