/* Boot for the design sample pages: the real app (secmonk-views.js) on the fixture mock (mock/data.js).
 * <body data-route="/processes/300" data-watch="1" data-click="css selector"> picks the route, optionally starts the mock
 * watch and clicks one element once the page has rendered (e.g. the container preview of the scan form). */
(function () {
  "use strict";
  if (!window.Vue || !window.VueRouter) {
    document.body.textContent = "Vue could not be loaded from src/secmonk/web/static/vendor. See _design/README.md.";
    return;
  }
  const b = document.body.dataset;
  const { store } = window.SecMonkUI.mountApp("#app", {
    source: window.SecMonkUI.MockSource(window.SECMONK_MOCK, { latency: 120 }),
    initialRoute: b.route || "/processes", design: true,
  });
  if (b.click) {
    let tries = 0;                                    // the view renders after the mock's first answers
    const t = setInterval(() => {
      const el = document.querySelector(b.click);
      if (el || ++tries > 40) { clearInterval(t); if (el) el.click(); }
    }, 100);
  }
  if (b.watch) {
    store.state.watch.interval = 5;
    store.startWatch();
    let n = 0;                                        // fast-forward: a few mock ticks so the feed has content
    const t = setInterval(() => { window.SecMonkUI.toasts.splice(0); n++ < 3 ? store.startWatch() : clearInterval(t); }, 400);
  }
})();
