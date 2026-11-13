// Run: node --test rust/ui/test/   (Node >= 18, no dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SRC = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "transport.js"), "utf8");

/** Loads transport.js into a fake window. opts: {tauri, fetch, session, authInfo} */
function load({ tauri, fetchImpl, session = {} } = {}) {
  const calls = [];   // fetch calls other than the /auth/info probe
  const store = { ...session };
  const win = {
    location: { href: "http://127.0.0.1:8080/", origin: "http://127.0.0.1:8080" },
    sessionStorage: {
      getItem: (k) => (k in store ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
      removeItem: (k) => { delete store[k]; },
    },
    fetch: async (input, init) => { if (String(input) !== "/auth/info") calls.push({ input, init }); return fetchImpl ? fetchImpl(input, init) : new Response("{}", { status: 200 }); },
    setTimeout: () => 0, clearTimeout: () => {}, atob,
    Response, Headers, Request, URL, Uint8Array, Promise, JSON, Date, Number, Math, Error,
  };
  if (tauri) win.__TAURI_INTERNALS__ = tauri;
  win.window = win;
  vm.runInNewContext(SRC, win);
  return { win, calls, store, T: win.SecMonkTransport };
}
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json" } });

test("mode detection", () => {
  assert.equal(load().T.mode, "http");
  assert.equal(load({ tauri: {} }).T.mode, "http");
  assert.equal(load({ tauri: { invoke() {} } }).T.mode, "tauri");
});

test("wrapper routes only same-origin /api/ calls", async () => {
  const { win, calls } = load({ session: { "secmonk.token": "t" } });
  await win.fetch("/api/meta");
  await win.fetch("http://127.0.0.1:8080/api/x?y=1");
  await win.fetch("http://evil.example/api/meta");
  await win.fetch("/static/js/a.js");
  await win.fetch("/apix");
  assert.deepEqual(calls.map((c) => c.input), ["/api/meta", "/api/x?y=1", "http://evil.example/api/meta", "/static/js/a.js", "/apix"]);
  // the two API calls went through request() (they carry a path string and options), the others are untouched
  assert.equal(calls[2].init, undefined);
  assert.equal(calls[3].init, undefined);
  assert.ok(calls[0].init.headers.Authorization);
});

test("Bearer header only when a token is held; Request input works", async () => {
  const a = load();
  await a.win.fetch("/api/meta", { headers: { "X-SecMonk-Request": "1" } });
  assert.equal(a.calls[0].init.headers.Authorization, undefined);
  assert.equal(a.calls[0].init.headers["x-secmonk-request"], "1");
  const b = load({ session: { "secmonk.token": "abc" } });
  await b.win.fetch(new Request("http://127.0.0.1:8080/api/jobs", { method: "POST", body: "{}" }));
  assert.equal(b.calls[0].init.headers.Authorization, "Bearer abc");
  assert.equal(b.calls[0].init.method, "POST");
  assert.equal(b.calls[0].init.body, "{}");
});

test("tauri: invoke shape and text / base64 responses", async () => {
  const seen = [];
  const replies = [
    { status: 200, headers: { "content-type": "application/json" }, body: '{"a":1}' },
    { status: 200, headers: { "content-disposition": 'attachment; filename="x.cdx.json"' }, body_base64: Buffer.from([1, 2, 255]).toString("base64") },
  ];
  const { win, T } = load({ tauri: { invoke: async (cmd, args) => { seen.push([cmd, args]); return replies.shift(); } } });
  const r1 = await win.fetch("/api/meta?x=1", { method: "POST", headers: { "X-SecMonk-Request": "1" }, body: "{}" });
  assert.deepEqual(JSON.parse(JSON.stringify(seen[0])), ["secmonk_api", { request: { method: "POST", path: "/api/meta?x=1", headers: { "x-secmonk-request": "1" }, body: "{}" } }]);
  assert.ok(r1 instanceof Response);
  assert.deepEqual(await r1.json(), { a: 1 });
  const r2 = await win.fetch("/api/assets/1/sbom");
  assert.equal(seen[1][1].request.body, null);
  assert.equal(seen[1][1].request.method, "GET");
  assert.match(r2.headers.get("Content-Disposition"), /x\.cdx\.json/);
  assert.deepEqual([...new Uint8Array(await (await r2.blob()).arrayBuffer())], [1, 2, 255]);
  await T.ready();
});

test("401 clears the token and shows the login form", async () => {
  const shown = [];
  const { win, T, store } = load({
    session: { "secmonk.token": "old", "secmonk.token_expires_at": "9999999999" },
    fetchImpl: (input) => (String(input) === "/auth/info" ? json({ auth: true }) : json({ error: "no" }, 401)),
  });
  T.loginUI = { show: (m) => shown.push(m), hide() {} };
  await T.ready();
  assert.equal(T.authRequired, true);
  const res = await win.fetch("/api/meta");
  assert.equal(res.status, 401);
  assert.equal(store["secmonk.token"], undefined);
  assert.equal(shown.length, 1);
});

test("ready(): no auth resolves; auth without token waits for login", async () => {
  const none = load({ fetchImpl: () => json({ auth: false }) });
  await none.T.ready();
  assert.equal(none.T.authRequired, false);

  const { T, store, calls } = load({
    fetchImpl: (input, init) => (String(input) === "/auth/info" ? json({ auth: true })
      : json({ token: "jwt1", token_type: "Bearer", expires_at: 4102444800, scopes: ["ui"] })),
  });
  let shown = 0, done = false;
  T.loginUI = { show: () => { shown++; }, hide() {} };
  T.ready().then(() => { done = true; });
  await new Promise((r) => setImmediate(r));
  assert.equal(shown, 1);
  assert.equal(done, false);
  await T.login("smk_deadbeef_secret");
  await new Promise((r) => setImmediate(r));
  assert.equal(done, true);
  assert.equal(store["secmonk.token"], "jwt1");
  const post = calls.find((c) => String(c.input) === "/auth/token");
  assert.equal(post.init.body, JSON.stringify({ api_key: "smk_deadbeef_secret" }));
  assert.ok(!JSON.stringify(store).includes("smk_"));
});
