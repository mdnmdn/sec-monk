---
title: ADR-0009 — Web interface stack with vendored libraries
type: decision
context: decisions
status: accepted
tags: [web-ui, architecture, security]
updated: 2026-11-07
supersedes: decisions/0008-web-ui-stack.md
related: [features/web-ui.md, tech/web-ui.md, decisions/0001-language-python-uv-mise.md, decisions/0007-process-monitor.md]
code: src/secmonk/web/, scripts/vendor_web.py
---

# ADR-0009 — Web interface stack with vendored libraries, supersedes ADR-0008

## Context
ADR-0008 loaded Vue and Vue Router from unpkg.com. That made the UI depend on network access (it failed in restricted
environments, including the development sandbox), put a third-party origin in the Content-Security-Policy, and trusted
the CDN to serve the expected bytes on every page load. Everything else in ADR-0008 holds.

## Decision
Same stack as ADR-0008, restated in full, with the libraries **vendored**:

- **Server: Python stdlib** (`ThreadingHTTPServer`) in `src/secmonk/web/`, started by `secmonk ui`; static files + a small
  JSON API calling the CLI's modules. No new Python dependency.
- **Client: Vue 3 + Vue Router, no bundling**, classic scripts exposing globals, templates compiled in the browser.
- **Vendored libraries** in `src/secmonk/web/static/vendor/<pkg>@<version>/` (global production builds + LICENSE), shipped
  in the wheel. `scripts/vendor_web.py` downloads the pinned tarballs from the npm registry, verifies the registry's
  sha512 `integrity` before extracting, copies only the listed files and writes `MANIFEST.json` (sha256 per file);
  `--check` and `tests/test_web.py` verify the files offline. The app, the `_design` pages and the storybook reference
  the same vendored files by path. No page loads anything from another origin.
- **One component library** (`static/css/secmonk.css`, `js/secmonk-ui.js`, `js/secmonk-views.js`) loaded unchanged by the
  app, the design pages (with `MockSource`) and the storybook.
- **Local, no authentication**, with mitigations: loopback bind by default, `Host` allow-list (DNS rebinding), mutations
  POST + `X-SecMonk-Request: 1` (CSRF), strict CSP **without any external origin** (`script-src 'self' 'unsafe-eval'`),
  no `v-html` on data.

## Consequences
- The UI, the design pages and the screenshot script work fully offline; the CSP is tighter (no third-party origin);
  the bytes the browser runs are the ones reviewed and checksummed in the repository.
- ~185 KB of third-party JavaScript in the repository and the wheel; upgrades are explicit (change the version in
  `scripts/vendor_web.py`, run it, update the script tags — the tests reject mismatches, re-run the screenshots).
- `'unsafe-eval'` remains, for Vue's in-browser template compiler (no build step); removing it would need precompiled
  render functions, i.e. a build step.
