# Redaction golden data

`redaction.json` holds inputs and the outputs of the Python helpers in `src/secmonk/collectors/base.py`
(`looks_secret`, `strip_url_secrets`, `redact_command`, `redact_option`, `scrub_text`, `redact_labels`).
Sample: synthetic inputs, real Python outputs. Generated on 2026-11-11 from the repo root with

    uv run python -I rust/crates/secmonk-safeio/tests/golden/gen_redaction.py > rust/crates/secmonk-safeio/tests/golden/redaction.json

Regenerate when the Python helpers change; `tests/golden.rs` must stay green.
