"""Golden outputs (rust/golden): normalized module outputs on the repo fixtures equal the stored files."""

from __future__ import annotations

import pytest

from scripts import golden


@pytest.fixture(scope="module")
def runner():
    r = golden.Runner()
    yield r
    r.close()


@pytest.mark.parametrize("case", golden.CASES, ids=[golden.case_file(c) for c in golden.CASES])
def test_matches_golden(runner, case):
    from normalize import dumps

    name = golden.case_file(case)
    params, out = runner.out(case)
    stored_params = golden.GOLDEN / f"{name}.params.json"
    stored_out = golden.GOLDEN / f"{name}.out.json"
    assert stored_out.exists(), f"no golden for {name}: run `uv run python scripts/golden.py --update`"
    assert stored_params.read_text() == dumps(params), f"params of {name} changed"
    assert stored_out.read_text() == dumps(out), f"{name} differs from its golden (review, then --update)"


def test_no_orphan_golden_files():
    expected = {golden.case_file(c) for c in golden.CASES}
    on_disk = {f"{p.parent.name}/{p.name[: -len('.out.json')]}" for p in golden.GOLDEN.glob("*/*.out.json")}
    assert on_disk == expected


def test_goldens_hold_no_machine_specific_text():
    """Nothing of the recording machine (its home, user name, temp dirs); the synthetic fixtures' own names stay."""
    import getpass
    import re
    from pathlib import Path

    names = {getpass.getuser(), Path.home().name} - {"", "root"}
    bad = re.compile("|".join([re.escape(str(Path.home())), "/private/var", "/var/folders",
                               *(rf"[/\\]{re.escape(n)}[/\\]" for n in names)]))
    for p in golden.GOLDEN.rglob("*.json"):
        assert not bad.search(p.read_text()), p
