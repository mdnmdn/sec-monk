# Vendored JavaScript libraries

Third-party files the web UI loads, shipped with the package so the UI works offline and the CSP allows no external
origin (ADR-0009). **Do not edit**: regenerate with `uv run python scripts/vendor_web.py` (downloads the pinned versions
from the npm registry, verifies the registry's sha512 integrity, extracts only the listed files, writes `MANIFEST.json`
with each file's sha256). `scripts/vendor_web.py --check` and `tests/test_web.py` verify the files against the manifest.

| Package | Version | Files | License |
|---|---|---|---|
| [vue](https://github.com/vuejs/core) | 3.5.13 | `vue.global.prod.js` (global build with the template compiler) | MIT (`LICENSE`) |
| [vue-router](https://github.com/vuejs/router) | 4.5.0 | `vue-router.global.prod.js` | MIT (`LICENSE`) |
