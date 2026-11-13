# Golden outputs of the Python modules

Reference outputs for the Rust ports (rust/_docs/tech/component-lifecycle.md, stages 3 and 6). Each file pair records one
call of a module method on the repo fixtures (`tests/fixtures/`, read only):

```
<method>/<case>.params.json     the request params, fixture and repo paths as <fixtures> / <repo>
<method>/<case>.out.json        the normalized reply: {"result": ...} | {"error": {code, error}}
                                collector.collect -> {"asset", "components", "warnings", "end"}
                                source.sync       -> {"ops" (emission order, batches merged), "end" (+ "batches")}
```

- **Provenance**: recorded by `rust/python/scripts/golden.py --update` from the real modules (macOS arm64, Python 3.13,
  2026-11-11); the fixtures are real-trimmed or synthetic as their READMEs say. `sample: real output of the Python code`.
- **Normalization**: `normalize.json` (rules as data) and `normalize.py` (Python implementation): fixture, repo and data
  roots become `<fixtures>`, `<repo>`, `<data_dir>`; timestamps become `<ts>`, durations and pids `0`; lists named in `sort`
  are sorted by the listed keys. A Rust runner applies the same rules to its own output before comparing.
- **DB-backed cases** (`engine.*`, `reports.*`, `procmon.*`) run on the standard store of `rust/python/tests/dbfactory.py`:
  schema v3 state + mirror files filled from fixtures (kev, euvd and the Maven GHSA OSV record; the asset `dir:/srv/payments-api`
  with log4j-core 2.14.1 and left-pad 1.3.0, matched at confidence 0.5). `process-snapshot-file` cases use
  `tests/fixtures/collectors/process/snapshot.json`.
- **Check / update**: `cd rust/python && uv run python scripts/golden.py` compares, `--update` rewrites (review the diff);
  `uv run pytest -q tests/test_golden.py` does the same inside the suite and also rejects orphan files and machine-specific text.
- Not recorded (not deterministic or needs a live target): `discover.host`, `docker.containers`, `docker.image_check`,
  `source.ack`, `source.export` (covered by conformance and adapter tests).
- **Lookup keys** (`node/lookup-keys.components.json` -> `node/lookup-keys.expected.json`, not a module call): the
  `affected` keys the Python matcher (`engine/match.py`) queries for each classified component, recorded by
  `cd rust/python && uv run python scripts/lookup_keys_golden.py` (`--check` compares). The components are synthetic.
  `secmonk-engine` asserts `component_lookup_keys` returns a superset (`node::keys` tests).
