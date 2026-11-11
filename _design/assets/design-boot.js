/* Boot for the design sample pages: the real app (secmonk-views.js) on the fixture mock (mock/data.js).
 * <body data-route="/processes/300" data-watch="1" data-click="css selector"> picks the route, optionally starts the mock
 * watch and clicks elements in turn once the page has rendered (`a ;; b`) (e.g. the container preview of the scan form). */
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
    // "sel1 ;; sel2": click each in turn once it exists (the view renders after the mock's answers)
    const steps = b.click.split(";;").map((x) => x.trim()).filter(Boolean);
    let tries = 0;
    const t = setInterval(() => {
      const el = steps.length && document.querySelector(steps[0]);
      if (el) { el.click(); steps.shift(); tries = 0; }
      if (!steps.length || ++tries > 60) clearInterval(t);
    }, 150);
  }
  if (b.watch) {
    store.state.watch.interval = 5;
    store.startWatch();
    let n = 0;                                        // fast-forward: a few mock ticks so the feed has content
    const t = setInterval(() => { window.SecMonkUI.toasts.splice(0); n++ < 3 ? store.startWatch() : clearInterval(t); }, 400);
  }
})();
