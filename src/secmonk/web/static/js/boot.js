/* App entry point (kept out of index.html: the CSP forbids inline scripts). */
(function () {
  "use strict";
  if (!window.Vue || !window.VueRouter) {
    document.getElementById("app").textContent =
      "Could not load the vendored Vue files (/static/vendor). Reinstall sec-monk or run scripts/vendor_web.py.";
    return;
  }
  window.SecMonkUI.mountApp("#app", { source: window.SecMonkUI.ApiSource(), initialRoute: "/overview" });
})();
