#!/usr/bin/env node
/* Screenshots of the _design sample pages and storybook (documentation only).
 *
 *   node scripts/design_screenshots.js      # needs Node + the `playwright` package and its Chromium; no network
 *                                            (Vue is vendored in src/secmonk/web/static/vendor)
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
const SHOTS = [
  ["01-processes", "_design/pages/processes.html"],
  ["02-process-detail", "_design/pages/process-detail.html"],
  ["03-process-provenance", "_design/pages/process-detail-provenance.html"],
  ["04-processes-suspicious", "_design/pages/processes-suspicious.html"],
  ["05-software", "_design/pages/software-detail.html"],
  ["06-launch-items", "_design/pages/launch-items.html"],
  ["07-activity", "_design/pages/activity.html", 2500],
  ["08-overview", "_design/pages/overview.html"],
  ["09-processes-dark", "_design/pages/processes.html", 0, "dark"],
  ["10-storybook-badges", "_design/storybook/index.html#launch"],
  ["11-storybook-table", "_design/storybook/index.html#table"],
  ["12-storybook-detail", "_design/storybook/index.html#process-detail"],
  ["13-design-index", "_design/index.html"],
  ["15-assets", "_design/pages/assets.html"],
  ["16-asset-detail", "_design/pages/asset-detail.html"],
  ["17-asset-components", "_design/pages/asset-components.html"],
  ["18-findings", "_design/pages/findings.html"],
  ["19-finding-detail", "_design/pages/finding-detail.html"],
  ["20-vulns", "_design/pages/vulns.html"],
  ["21-vuln-detail", "_design/pages/vuln-detail.html"],
  ["22-sources", "_design/pages/sources.html"],
  ["23-scan", "_design/pages/scan.html"],
  ["24-jobs", "_design/pages/jobs.html"],
  ["25-overview-dark", "_design/pages/overview.html", 0, "dark"],
  ["26-storybook-findings", "_design/storybook/index.html#finding-detail"],
  ["27-scan-docker", "_design/pages/scan-docker.html", 1500],
  ["28-storybook-job-result", "_design/storybook/index.html#job-result"],
  ["29-scan-host", "_design/pages/scan-host.html", 1500],
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
    await ctx.route(/^https?:\/\/(?!127\.0\.0\.1)/, (route) => route.abort());   // prove nothing external is needed
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
