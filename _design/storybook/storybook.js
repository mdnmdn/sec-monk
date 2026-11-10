/* Storybook frame: lists SECMONK_STORIES, renders each variant with the shared components (installed exactly as the
 * app installs them) and shows the template as a usage snippet. View-level patterns get a mock store, like the
 * design pages. Deep link: index.html#<story-id>. */
(function () {
  "use strict";
  if (!window.Vue) { document.body.textContent = "Vue could not be loaded from src/secmonk/web/static/vendor."; return; }
  const { createApp, ref, computed, onMounted, defineComponent } = Vue;
  const UI = window.SecMonkUI;
  const stories = window.SECMONK_STORIES;

  const Variant = defineComponent({
    props: { v: Object },
    setup(props) {
      const comp = defineComponent({
        template: `<div>${props.v.template}</div>`,
        data: () => JSON.parse(JSON.stringify(props.v.data || {})),
        methods: props.v.methods || {},
      });
      return { comp };
    },
    template: `<section class="sb-variant"><h3 class="sb-variant__name">{{ v.name }}</h3>
      <div class="sb-canvas"><component :is="comp"/></div>
      <details class="sb-code"><summary>Usage</summary><pre class="sm-pre">{{ v.template.trim() }}</pre></details></section>`,
  });

  const App = {
    components: { Variant },
    setup() {
      const q = ref("");
      const current = ref((location.hash || "").slice(1) || stories[0].id);
      const groups = computed(() => {
        const out = [];
        for (const s of stories) {
          if (q.value && !(s.title + " " + s.group).toLowerCase().includes(q.value.toLowerCase())) continue;
          let g = out.find((x) => x.label === s.group);
          if (!g) out.push((g = { label: s.group, items: [] }));
          g.items.push(s);
        }
        return out;
      });
      const story = computed(() => stories.find((s) => s.id === current.value) || stories[0]);
      const pick = (id) => { current.value = id; history.replaceState(null, "", "#" + id); };
      window.addEventListener("hashchange", () => { current.value = location.hash.slice(1) || stories[0].id; });
      return { q, groups, story, pick, count: stories.length };
    },
    template: `<div class="sb">
      <aside class="sb-side"><div class="sb-brand"><span class="sm-brand__mark">◆</span> sec-monk <span class="sm-muted">storybook</span></div>
        <sm-search v-model="q" placeholder="Find a component" :hotkey="false"/>
        <nav v-for="g in groups" :key="g.label"><div class="sb-group">{{ g.label }}</div>
          <a v-for="s in g.items" :key="s.id" :href="'#' + s.id" :class="['sb-link', s.id === story.id && 'is-active']" @click.prevent="pick(s.id)">{{ s.title }}</a></nav>
        <div class="sb-foot sm-muted">{{ count }} stories · <a href="../index.html">design overview</a> · <sm-theme-toggle/></div></aside>
      <main class="sb-main"><header class="sb-head"><div class="sm-muted">{{ story.group }}</div><h1>{{ story.title }}</h1><p>{{ story.doc }}</p></header>
        <variant v-for="v in story.variants" :key="story.id + v.name" :v="v"/></main>
      <sm-toasts/></div>`,
  };

  const app = createApp(App);
  UI.install(app);
  // view-level patterns (process-detail, finding-detail ...) need the store the app provides: give them the mock one
  const store = UI.createStore(UI.MockSource(window.SECMONK_MOCK, { latency: 0 }));
  store.state.snap = JSON.parse(JSON.stringify(window.SECMONK_MOCK.snapshot));
  app.provide("store", store);
  for (const n of ["ProcessDetail", "FindingsTable", "FindingDetail", "JobResult", "JobTarget", "JobItems", "JobHistory", "HostCandidates", "HostScan", "SbomExport"]) app.component(n, UI.VIEWS[n]);
  // ProcessDetail uses vue-router only through its parent views; a memory router keeps $router available
  app.use(VueRouter.createRouter({ history: VueRouter.createMemoryHistory(), routes: [{ path: "/:p(.*)*", component: { template: "<div/>" } }] }));
  app.mount("#sb");
})();
