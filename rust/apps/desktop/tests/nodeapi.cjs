// Runs the UNCHANGED UI scripts (Vue, secmonk-ui.js, secmonk-views.js) in Node with a thin DOM stub and points
// their relative fetch() at the headless server (cargo run -p secmonk-api --example serve), as the webview would.
// Usage: node nodeapi.cjs <static dir> [base url, default http://127.0.0.1:18765/]
const fs = require("fs"), vm = require("vm"), assert = require("assert");
const S = require("path").resolve(process.argv[2] || "../../../../src/secmonk/web/static") + "/";
const BASE = process.argv[3] || "http://127.0.0.1:18765/";
const stub = () => new Proxy(function () {}, { get: (t, k) => k === Symbol.toPrimitive ? () => "" : stub(), apply: () => stub(), construct: () => stub() });
globalThis.window = globalThis; globalThis.self = globalThis;
globalThis.document = stub(); globalThis.location = { hash: "", href: BASE, origin: BASE.replace(/\/$/, "") };
globalThis.history = {}; globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.matchMedia = () => ({ matches: false, addEventListener() {} });
const realFetch = fetch;
globalThis.fetch = (u, o) => realFetch(new URL(u, BASE), o);
for (const f of ["vendor/vue@3.5.13/vue.global.prod.js", "vendor/vue-router@4.5.0/vue-router.global.prod.js", "js/secmonk-ui.js", "js/secmonk-views.js"]) {
  vm.runInThisContext(fs.readFileSync(S + f, "utf8"), { filename: f });
}
(async () => {
  const src = SecMonkUI.ApiSource("");
  const meta = await src.meta();
  assert.strictEqual(typeof meta.version, "string"); assert.strictEqual(meta.bind.startsWith("http"), true);
  console.log("meta ->", JSON.stringify(meta));
  const err = await src.overview().then(() => null, e => e);
  assert(err, "overview must fail without a database");
  assert.strictEqual(err.status, 404); assert.strictEqual(err.code, "no-db");
  console.log("overview ->", `status=${err.status} code=${err.code} msg=${err.message}`);
  const bare = await fetch("/api/meta"); assert.strictEqual(bare.status, 403);
  const r = await fetch("/api/meta", { headers: { "X-SecMonk-Request": "1" } });
  assert.strictEqual(r.status, 200);
  assert(r.headers.get("content-security-policy").includes("script-src 'self' 'unsafe-eval'"));
  console.log("OK (without header 403; CSP present). Host-check cases are covered by the Rust router tests: Node fetch cannot set Host.");
})().catch(e => { console.error("FAIL", e); process.exit(1); });
