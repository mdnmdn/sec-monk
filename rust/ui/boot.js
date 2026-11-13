/* App entry point of the Rust overlay: same as static/js/boot.js, but waits for the transport (login) first. */
(function () {
  "use strict";
  const T = window.SecMonkTransport;

  function addSignOut() {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "sm-btn sm-btn--sm rui-signout";
    b.textContent = "Sign out";
    b.addEventListener("click", () => { T.logout(); window.location.reload(); });
    document.body.append(b);
  }

  function mount() {
    if (!window.Vue || !window.VueRouter) {
      document.getElementById("app").textContent =
        "Could not load the vendored Vue files (/static/vendor). Reinstall sec-monk or run scripts/vendor_web.py.";
      return;
    }
    window.SecMonkUI.mountApp("#app", { source: window.SecMonkUI.ApiSource(), initialRoute: "/overview" });
    if (T.mode === "http" && T.authRequired) addSignOut();
  }

  T.ready().then(mount);
})();
