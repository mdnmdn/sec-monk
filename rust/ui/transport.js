/* sec-monk UI transport for the Rust app (rust/ui/README.md).
 *
 * Classic script, loaded before secmonk-ui.js. Defines window.SecMonkTransport and wraps window.fetch so that the
 * unchanged ApiSource reaches the Rust router either through the Tauri command `secmonk_api` or over HTTP with a
 * Bearer token. Only same-origin /api/ URLs are routed; everything else uses the original fetch.
 * The API key is never stored or logged; only the short-lived JWT lives in sessionStorage.
 */
(function (global) {
  "use strict";
  const TOKEN_KEY = "secmonk.token";
  const EXPIRY_KEY = "secmonk.token_expires_at";
  const SKEW_MS = 60 * 1000;
  const originalFetch = global.fetch ? global.fetch.bind(global) : null;
  const tauri = global.__TAURI_INTERNALS__;
  const mode = tauri && typeof tauri.invoke === "function" ? "tauri" : "http";

  // ---- token storage (sessionStorage can throw or be missing: fall back to memory)
  let memory = {};
  const store = {
    get(k) { try { return global.sessionStorage.getItem(k); } catch (e) { return memory[k] ?? null; } },
    set(k, v) { try { global.sessionStorage.setItem(k, v); } catch (e) { memory[k] = v; } },
    del(k) { try { global.sessionStorage.removeItem(k); } catch (e) { delete memory[k]; } },
  };

  /** expires_at as epoch ms: accepts epoch seconds, epoch ms or an ISO string; NaN when unknown. */
  function toMillis(v) {
    if (v === null || v === undefined || v === "") return NaN;
    const n = Number(v);
    if (!Number.isNaN(n)) return n < 1e12 ? n * 1000 : n;
    return Date.parse(v);
  }
  function token() { return store.get(TOKEN_KEY); }
  function tokenValid() {
    if (!token()) return false;
    const exp = toMillis(store.get(EXPIRY_KEY));
    return Number.isNaN(exp) || exp - Date.now() > SKEW_MS;
  }
  function clearToken() { store.del(TOKEN_KEY); store.del(EXPIRY_KEY); }

  const T = {
    mode,
    authRequired: false,   // known after ready(); http mode only
    loginUI: null,         // set by login.js: {show(message), hide()}

    token,
    hasValidToken: tokenValid,

    showLogin(message) { if (this.loginUI) this.loginUI.show(message || ""); },

    /** Exchanges an API key for a JWT. Throws Error(message) on failure; the key is not kept. */
    async login(apiKey) {
      const res = await originalFetch("/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ api_key: apiKey }),
      });
      let body = null;
      try { body = await res.json(); } catch (e) { /* not JSON */ }
      if (!res.ok || !body || !body.token) throw new Error((body && (body.error || body.message)) || `HTTP ${res.status}`);
      store.set(TOKEN_KEY, body.token);
      store.set(EXPIRY_KEY, String(body.expires_at ?? ""));
      scheduleExpiry();
      if (loginDone) loginDone();
      return { expires_at: body.expires_at, scopes: body.scopes };
    },

    logout() { clearToken(); },

    /** Resolves when the app may mount (see README). */
    ready() { return readyPromise; },

    /** One request, always a real Response. */
    async request(method, path, { headers = {}, body = null } = {}) {
      if (mode === "tauri") return tauriRequest(method, path, headers, body);
      const h = { ...headers };
      if (token()) h.Authorization = "Bearer " + token();
      const res = await originalFetch(path, { method, headers: h, body: body === null ? undefined : body });
      if (res.status === 401 && T.authRequired) { clearToken(); T.showLogin("Session expired. Enter your API key."); }
      return res;
    },
  };

  async function tauriRequest(method, path, headers, body) {
    const r = await tauri.invoke("secmonk_api", { request: { method, path, headers: { ...headers }, body: body === undefined ? null : body } });
    let payload = r.body ?? "";
    if (r.body_base64 !== undefined && r.body_base64 !== null) {
      const bin = global.atob(r.body_base64);
      payload = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) payload[i] = bin.charCodeAt(i);
    }
    const noBody = [101, 204, 205, 304].includes(r.status);
    return new Response(noBody ? null : payload, { status: r.status, headers: r.headers || {} });
  }

  // ---- fetch wrapper: same-origin /api/ only
  async function wrappedFetch(input, init) {
    let url, method, headers, body = null;
    try {
      const req = typeof Request !== "undefined" && input instanceof Request ? input : null;
      url = new URL(req ? req.url : String(input && input.href ? input.href : input), global.location.href);
      if (url.origin !== global.location.origin || !url.pathname.startsWith("/api/")) return originalFetch(input, init);
      init = init || {};
      method = (init.method || (req && req.method) || "GET").toUpperCase();
      headers = new Headers(init.headers || (req && req.headers) || {});
      if (init.body !== undefined && init.body !== null) body = typeof init.body === "string" ? init.body : String(init.body);
      else if (req && method !== "GET" && method !== "HEAD") body = await req.text();
    } catch (e) {
      return originalFetch(input, init);
    }
    const plain = {};
    headers.forEach((v, k) => { plain[k] = v; });
    return T.request(method, url.pathname + url.search, { headers: plain, body });
  }
  if (originalFetch) global.fetch = wrappedFetch;

  // ---- expiry: a JWT cannot renew itself without the key, so ask for the key again shortly before it ends
  let expiryTimer = null;
  function scheduleExpiry() {
    if (expiryTimer) global.clearTimeout(expiryTimer);
    const exp = toMillis(store.get(EXPIRY_KEY));
    if (Number.isNaN(exp)) return;
    const wait = Math.min(Math.max(exp - SKEW_MS - Date.now(), 0), 2 ** 31 - 1);
    expiryTimer = global.setTimeout(() => { clearToken(); T.showLogin("Session expires soon. Enter your API key again."); }, wait);
  }

  // ---- ready()
  let loginDone = null;
  const readyPromise = (async () => {
    if (mode === "tauri") return;
    try {
      const res = await originalFetch("/auth/info", { headers: { Accept: "application/json" } });
      const info = res.ok ? await res.json() : null;
      T.authRequired = !!(info && info.auth);
    } catch (e) { T.authRequired = false; }
    if (!T.authRequired) return;
    if (tokenValid()) { scheduleExpiry(); return; }
    clearToken();
    await new Promise((resolve) => { loginDone = resolve; T.showLogin(""); });
  })();

  global.SecMonkTransport = T;
})(window);
