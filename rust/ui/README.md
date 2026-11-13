# rust/ui: UI overlay for the Rust app

The Rust app serves the unchanged web UI from `src/secmonk/web/static` (`/static/*`) plus this overlay. The overlay
only changes how the UI reaches the API (design: [node-server-design §5](../_docs/plans/node-server-design.md)).
It never edits `src/`.

## Files (fixed set, embedded with `include_str!`)

| File | Served at | Role |
|---|---|---|
| `index.html` | `/`, `/index.html` | `static/index.html` plus transport, login, overlay CSS, `#secmonk-login`, own boot |
| `transport.js` | `/rust-ui/transport.js` | `window.SecMonkTransport`, `fetch` wrapper, token handling |
| `login.js` | `/rust-ui/login.js` | login form (DOM APIs only) |
| `boot.js` | `/rust-ui/boot.js` | waits for `ready()`, mounts the app, adds "Sign out" |
| `rust-ui.css` | `/rust-ui/rust-ui.css` | login card, sign-out button (tokens from `secmonk.css`) |

`test/transport.test.mjs` is not served. Run it with `node --test rust/ui/test/*.test.mjs` (Node 18+, no deps).
CSP stays `script-src 'self' 'unsafe-eval'; style-src 'self'`: no inline script or style anywhere.

## Transport

`transport.js` wraps `window.fetch`: only same-origin URLs whose path starts with `/api/` go through
`SecMonkTransport.request(method, path, {headers, body})` (which returns a real `Response`); everything else uses
the original `fetch`. `ApiSource` (including the SBOM blob download and `Content-Disposition`) works unchanged.

- **tauri** (`window.__TAURI_INTERNALS__.invoke` is a function): no network, no auth.
- **http**: `fetch(path)` with `Authorization: Bearer <jwt>` when a token is held.

### Tauri command contract

```
invoke("secmonk_api", { request: { method: "GET", path: "/api/x?y=1", headers: {name: value}, body: string | null } })
  -> { status: number, headers: {name: value}, body: string }            // UTF-8 text
  or { status, headers, body_base64: string }                             // non-text content types
```

`body_base64` is decoded into a `Uint8Array` for the `Response`. Header names are lower-case (from `Headers`).
Status 101/204/205/304 produce a body-less `Response`.

## Auth flow (http mode)

Endpoints used: `GET /auth/info` -> `{auth: bool, ...}`; `POST /auth/token` with JSON `{api_key}` ->
`{token, token_type, expires_at, scopes}` (error body `{error}` is shown as text); then `/api/*` with the Bearer token.

1. `ready()` reads `/auth/info`. No auth: mount. Auth on and an unexpired token in `sessionStorage`
   (`secmonk.token`, `secmonk.token_expires_at`): mount. Otherwise show the login form and mount after sign-in.
2. Sign-in exchanges the API key for a JWT, stores only the JWT, then reloads the page. The key is never stored,
   logged or put in a URL.
3. A JWT cannot renew itself without the key: 60 s before `expires_at` the token is dropped and the login form
   appears again. A 401 from `/api/` clears the token, shows the form and returns the 401 `Response` (the app shows
   its error panel).
4. "Sign out" (bottom right, only when auth is on) clears the token and reloads.
