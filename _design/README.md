# `_design/` — interface design of sec-monk

Design system, sample pages and storybook of the local web interface (`secmonk ui`).
Requirements, views, navigation and interactions: [`_docs/features/web-ui.md`](../_docs/features/web-ui.md).
Architecture and API: [`_docs/tech/web-ui.md`](../_docs/tech/web-ui.md). Stack decision: [ADR-0009](../_docs/decisions/0009-web-ui-vendored-libraries.md).

| Path | What |
|---|---|
| [`index.html`](index.html) | Design overview: principles, links to every sample page and to the storybook. |
| [`storybook/index.html`](storybook/index.html) | Every shared component and view pattern, with variants and the template to copy (`stories.js`). |
| [`pages/*.html`](pages/) | Sample pages: the real app (`secmonk-views.js`) mounted on mock data at a given route. |
| [`mock/data.js`](mock/data.js) | Mock payloads, **generated** by `uv run python scripts/design_mock.py` from the test fixtures (do not edit). |
| `assets/design-boot.js` | Mounts the app with `MockSource` for the sample pages (`<body data-route data-watch data-click>`: route, mock watch, one click after render, e.g. the container preview of `scan-docker.html`). |
| `storybook/storybook.{js,css}` | The storybook frame only (navigation, canvas). |

## One component library, no copies

All pages load the files the app serves, by relative path:

```
src/secmonk/web/static/css/secmonk.css     tokens (light/dark) + every component style
src/secmonk/web/static/js/secmonk-ui.js    vocabulary, formatting, base Vue components (sm-*)
src/secmonk/web/static/js/secmonk-views.js store, ApiSource / MockSource, views, router, mountApp()
src/secmonk/web/static/vendor/             Vue + Vue Router (vendored, checksummed: scripts/vendor_web.py)
```

So a change to a component is visible at once in the storybook, in the sample pages and in the app. Rules:

- Never copy those files into `_design/`; `storybook.css` may only lay out the storybook page.
- A new component in `secmonk-ui.js` gets a story in `storybook/stories.js` (all variants and states).
- A new view gets a sample page in `pages/` (one per meaningful state) and a row in `index.html`.
- When the API payload changes, regenerate `mock/data.js` with `scripts/design_mock.py` and commit it.

## Viewing

Open `index.html` directly in a browser (`file://` works: classic scripts, mock as a JS file), or serve the repository
root: `python3 -m http.server -d . 8000` then `http://localhost:8000/_design/`. Vue 3.5.13 and Vue Router 4.5.0 are the
app's vendored copies (`src/secmonk/web/static/vendor`): no network needed.

## Screenshots

`node scripts/design_screenshots.js` regenerates `screenshots/*.png` (needs Node and the `playwright` package; headless
Chromium, 1440×900 at 2×, every external request aborted). It fails on any console error, so it doubles as an offline
smoke test of the pages.
Screenshots are documentation only, never a source of truth. `14-app-live-server-no-db.png` is the real app served by
`secmonk ui --snapshot …` without a database.
