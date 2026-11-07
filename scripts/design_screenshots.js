#!/usr/bin/env node
/* Screenshots of the _design sample pages and storybook (documentation only).
 *
 *   node scripts/design_screenshots.js                 # needs Node + the `playwright` package and its Chromium
 *   SECMONK_VENDOR=/path/to/vendor node scripts/...    # serve Vue from a local copy when unpkg.com is unreachable:
 *                                                        <vendor>/vue@3.5.13/dist/..., <vendor>/vue-router@4.5.0/dist/...
 *
 * Serves the repository root on a free port, opens every page in headless Chromium (1440x900, 2x), fails on any
 * console error or page error, writes _design/screenshots/<name>.png.
 */
"use strict";
const { chromium } = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..");
const OUT = path.join(REPO, "_design", "screenshots");
const VENDOR = process.env.SECMONK_VENDOR;
const SHOTS = [
  ["01-processes", "_design/pages/processes.html"],
  ["02-process-detail", "_design/pages/process-detail.html"],
  ["03-process-provenance", "_design/pages/process-detail-provenance.html"],
  ["04-processes-suspicious", "_design/pages/processes-suspicious.html"],
  ["05-software", "_design/pages/software-detail.html"],
  ["06-launch-items", "_design/pages/launch-items.html"],
  ["07-activity", "_design/pages/activity.html", 2500],
  ["08-planned", "_design/pages/planned.html"],
  ["09-processes-dark", "_design/pages/processes.html", 0, "dark"],
  ["10-storybook-badges", "_design/storybook/index.html#launch"],
  ["11-storybook-table", "_design/storybook/index.html#table"],
  ["12-storybook-detail", "_design/storybook/index.html#process-detail"],
  ["13-design-index", "_design/index.html"],
];
const TYPES = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };

function serve() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const p = path.normalize(path.join(REPO, decodeURIComponent(req.url.split("?")[0])));
      if (!p.startsWith(REPO) || !fs.existsSync(p) || !fs.statSync(p).isFile()) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "Content-Type": TYPES[path.extname(p)] || "application/octet-stream" });
      fs.createReadStream(p).pipe(res);
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const srv = await serve();
  const base = `http://127.0.0.1:${srv.address().port}/`;
  const browser = await chromium.launch();
  let failed = false;
  for (const [name, rel, wait = 0, scheme = "light"] of SHOTS) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
    if (VENDOR) {
      await ctx.route("https://unpkg.com/**", (route) => {
        const f = path.join(VENDOR, new URL(route.request().url()).pathname);
        route.fulfill({ path: f, contentType: "application/javascript" });
      });
    }
    const page = await ctx.newPage();
    const errors = [];
    page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") errors.push(`${m.type()}: ${m.text()}`); });
    page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
    await page.goto(base + rel, { waitUntil: "networkidle" });
    await page.waitForTimeout(600 + wait);
    await page.screenshot({ path: path.join(OUT, `${name}.png`) });
    if (errors.length) { failed = true; console.error(`${name}:\n  ` + errors.join("\n  ")); }
    else console.log(`${name}.png`);
    await ctx.close();
  }
  await browser.close();
  srv.close();
  process.exit(failed ? 1 : 0);
})();
