/* App entry point (kept out of index.html: the CSP forbids inline scripts). */
(function () {
  "use strict";
  if (!window.Vue || !window.VueRouter) {
    document.getElementById("app").textContent =
      "Could not load Vue from https://unpkg.com (offline or blocked). The sec-monk UI needs it: see _docs/tech/web-ui.md.";
    return;
  }
  window.SecMonkUI.mountApp("#app", { source: window.SecMonkUI.ApiSource(), initialRoute: "/processes" });
})();
