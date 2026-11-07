/* sec-monk views: store, data sources, navigation, pages and router.
 *
 * Classic script after vue, vue-router and secmonk-ui.js. Exposes SecMonkUI.mountApp(el, {source, initialRoute, design}).
 * The app passes ApiSource() (the local server); the _design sample pages pass MockSource(window.SECMONK_MOCK), so the
 * design shows exactly what the app renders. Feature areas register in NAV + ROUTES (see _docs/tech/web-ui.md,
 * "Adding a feature").
 */
(function (global) {
  "use strict";
  const { reactive, computed, ref, watch, createApp, onMounted } = global.Vue;
  const { createRouter, createWebHashHistory, useRoute, useRouter } = global.VueRouter;
  const UI = global.SecMonkUI;
  const { fmt } = UI;

  // ================================================================== data sources
  class ApiError extends Error {
    constructor(message, status, hint, code) { super(message); this.status = status; this.hint = hint; this.code = code; }
  }

  /** ?a=1&b=x from an object; empty / false / null values are left out, true becomes "1". */
  function qs(params) {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined || v === null || v === "" || v === false) continue;
      u.set(k, v === true ? "1" : String(v));
    }
    const s = u.toString();
    return s ? "?" + s : "";
  }

  /** Talks to `secmonk ui` (src/secmonk/web/server.py). Every method returns the payload of one API endpoint. */
  function ApiSource(base = "") {
    // every API call carries X-SecMonk-Request (the server's CSRF check covers GETs too: watch / refresh change state)
    async function call(path, opts = {}) {
      const headers = { Accept: "application/json", "X-SecMonk-Request": "1", ...(opts.headers || {}) };
      const res = await fetch(base + path, { ...opts, headers });
      let body = null;
      try { body = await res.json(); } catch (e) { /* non-JSON error page */ }
      if (!res.ok) throw new ApiError((body && body.error) || `HTTP ${res.status}`, res.status, body && body.hint, body && body.code);
      return body;
    }
    const post = (path, body) => call(path, body === undefined ? { method: "POST" }
      : { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
    return {
      kind: "api",
      meta: () => call("/api/meta"),
      processes: (refresh) => call("/api/processes" + (refresh ? "?refresh=1" : "")),
      watch: () => call("/api/processes/watch"),
      save: () => post("/api/processes/save"),
      overview: () => call("/api/overview"),
      assets: () => call("/api/assets"),
      asset: (id) => call("/api/assets/detail" + qs({ id })),
      matchAsset: (id) => post("/api/assets/match" + qs({ id })),
      unmatched: () => call("/api/unmatched"),
      findings: (params) => call("/api/findings" + qs(params)),
      vuln: (id, raw) => call("/api/vulns/show" + qs({ id, raw })),
      vulnSearch: (params) => call("/api/vulns/search" + qs(params)),
      sources: () => call("/api/sources"),
      collectors: () => call("/api/collectors"),
      jobs: () => call("/api/jobs"),
      job: (id) => call(`/api/jobs/${encodeURIComponent(id)}`),
      startJob: (body) => post("/api/jobs", body),
    };
  }

  /** Serves the fixture-derived mock (scripts/design_mock.py -> _design/mock/data.js) with the API's semantics. */
  function MockSource(data, { latency = 250 } = {}) {
    const clone = (v) => JSON.parse(JSON.stringify(v));
    const wait = (v) => new Promise((r) => setTimeout(() => r(clone(v)), latency));
    const fail = (status, message, code, hint) => new Promise((_, rej) => setTimeout(() => rej(new ApiError(message, status, hint, code)), latency));
    const lc = (s) => String(s || "").toLowerCase();
    let tick = 0;
    const jobs = clone(data.jobs || []);
    let jobSeq = jobs.reduce((m, j) => Math.max(m, j.id), 0);
    const strip = ({ _tpl, _ticks, ...j }) => j;
    const hidden = (p) => [...(p.hide_minor || p.hide_deferred ? data.triage.minor : []), ...(p.hide_deferred ? data.triage.deferred : [])];
    return {
      kind: "mock",
      meta: () => wait(data.meta),
      processes: () => wait({ ...data.snapshot }),
      watch: () => {
        const events = tick === 0 ? [] : (data.events || []).filter((_, i) => i % 3 === (tick - 1) % 3);
        tick++;
        return wait({ events, taken_at: new Date().toISOString(), baseline: tick === 1 });
      },
      save: () => wait({ asset: data.snapshot.asset, stats: { components: data.snapshot.summary.components, findings: 3 } }),
      overview: () => wait(data.overview),
      assets: () => wait(data.assets),
      asset: (id) => (data.asset_details[id] ? wait(data.asset_details[id]) : fail(404, `unknown asset '${id}'`, "unknown-asset")),
      matchAsset: (id) => (data.asset_details[id] ? wait({ asset: id, stats: data.asset_details[id].match_stats }) : fail(404, `unknown asset '${id}'`, "unknown-asset")),
      unmatched: () => wait(data.unmatched),
      findings: (p = {}) => {
        const hide = hidden(p);
        const limit = +p.limit || 200;
        const rows = data.findings.filter((f) => (p.all || f.status === "open") && (!p.asset || f.asset_id === p.asset)
          && (!p.priority || f.priority === p.priority) && (!p.fixable || f.fixed_version) && !(f.triage && hide.includes(f.triage)));
        return wait({ findings: rows.slice(0, limit), limit, limit_reached: rows.length >= limit });
      },
      vuln: (id) => {
        const v = data.vulns[data.vuln_ids[id] || id] || Object.values(data.vulns).find((x) => x.aliases.includes(id));
        return v ? wait({ ...v, query: id }) : fail(404, `unknown vulnerability id '${id}'`, "unknown-vuln", "Not in the local mirror.");
      },
      vulnSearch: (p = {}) => {
        if (!p.package && !p.ecosystem && !p.product) return fail(400, "give a package, an ecosystem and/or a product");
        const limit = +p.limit || 50;
        const rows = data.vuln_index.filter((r) => (!p.package || lc(r.package) === lc(p.package)) && (!p.ecosystem || r.ecosystem === p.ecosystem)
          && (!p.product || lc(r.product) === lc(p.product))).slice(0, limit);
        return wait({ results: rows, limit, limit_reached: rows.length >= limit });
      },
      sources: () => wait(data.sources),
      collectors: () => wait(data.collectors),
      jobs: () => wait(jobs.map((j) => { const { log, ...rest } = strip(j); return rest; })),
      job: (id) => {
        const j = jobs.find((x) => String(x.id) === String(id));
        if (!j) return fail(404, `no job ${id}`);
        if (j.status === "running" && --j._ticks <= 0) {      // a started mock job finishes after a few polls
          Object.assign(j, { status: j._tpl.status, log: j._tpl.log, result: j._tpl.result, error: j._tpl.error,
            finished: new Date().toISOString() });
        }
        return wait(strip(j));
      },
      startJob: (body) => {
        if (!data.meta.actions) return fail(403, "actions are disabled on this server");
        if (jobs.some((j) => j.status === "running")) return fail(409, "another job is running");
        const tpl = data.jobs.find((j) => j.kind === body.kind);
        if (!tpl) return fail(400, "kind: expected 'sync' or 'scan'");
        const title = body.kind === "scan" ? `scan ${body.collector}${body.target ? " " + body.target : ""}` : `sync ${(body.sources || []).join(", ")}`;
        const j = { ...clone(tpl), id: ++jobSeq, title, params: body, started: new Date().toISOString(), finished: null,
          status: "running", log: [tpl.log[0]], result: null, error: null, _tpl: tpl, _ticks: 3 };
        jobs.unshift(j);
        return wait(strip(j));
      },
    };
  }

  // ================================================================== store
  function createStore(source) {
    const state = reactive({
      source: source.kind, meta: null, snap: null, loading: false, saving: false, error: null,
      stale: 0,                                              // events seen since the snapshot was loaded
      watch: { on: false, interval: 10, last: null, events: [], unseen: 0, busy: false, error: null },
      dataVersion: 0,                                        // bumped when a job finishes: data views reload
      jobs: { list: [], loaded: false },                     // newest first (web/jobs.py; list rows carry no log)
    });
    let timer = null;
    let seq = 0;

    async function loadMeta() {
      try { state.meta = await source.meta(); } catch (e) { state.error = e; }
    }
    async function refresh(force = true) {
      state.loading = true;
      try {
        state.snap = await source.processes(force);
        state.error = null;
        state.stale = 0;
        if (force) UI.toast(`Snapshot ${fmt.time(state.snap.taken_at)} — ${fmt.plural(state.snap.summary.processes, "process", "processes")}`);
      } catch (e) {
        state.error = e;
        if (state.snap) UI.toast(e.message, "error", 8000);
      } finally { state.loading = false; }
    }
    async function save() {
      state.saving = true;
      try {
        const r = await source.save();
        const s = r.stats || {};
        UI.toast(`Saved ${r.asset}: ${s.components ?? "?"} components, ${s.findings ?? 0} findings`);
      } catch (e) { UI.toast(`Save failed: ${e.message}`, "error", 8000); }
      finally { state.saving = false; }
    }
    async function tick() {
      if (state.watch.busy) return;
      state.watch.busy = true;
      try {
        const r = await source.watch();
        state.watch.last = r.taken_at;
        state.watch.error = null;
        const time = fmt.time(r.taken_at);
        const fresh = (r.events || []).map((e) => ({ ...e, time, id: ++seq }));
        if (fresh.length) {
          state.watch.events.unshift(...fresh.reverse());
          state.watch.events.splice(500);
          state.watch.unseen += fresh.length;
          state.stale += fresh.length;
          const loud = fresh.filter((e) => (e.flags && e.flags.length) || UI.worstPriority(e.findings_detail) === "P1"
            || UI.worstPriority(e.findings_detail) === "P2" || e.event.endsWith("launch-item"));
          for (const e of loud.slice(0, 3)) {
            UI.toast(`${UI.EVENTS[e.event]?.label || e.event}: ${e.process || e.label || ""}`, "warn", 6000);
          }
        }
      } catch (e) {
        state.watch.error = e.message;
        UI.toast(`Watch: ${e.message}`, "error", 6000);
        stopWatch();
      } finally { state.watch.busy = false; }
    }
    function startWatch() {
      stopWatch();
      state.watch.on = true;
      tick();
      timer = setInterval(tick, state.watch.interval * 1000);
    }
    function stopWatch() {
      if (timer) clearInterval(timer);
      timer = null;
      state.watch.on = false;
    }
    function setInterval_(s) {
      state.watch.interval = s;
      if (state.watch.on) startWatch();
    }
    const byPid = computed(() => {
      const m = new Map();
      for (const r of state.snap?.processes || []) m.set(r.pid, r);
      return m;
    });

    // ---- background jobs (scan, sync): started here, polled until done, then every data view reloads
    const polling = new Set();
    const running = computed(() => state.jobs.list.filter((j) => j.status === "running"));
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    function upsertJob(j) {
      const i = state.jobs.list.findIndex((x) => x.id === j.id);
      if (i >= 0) state.jobs.list[i] = { ...state.jobs.list[i], ...j };
      else state.jobs.list.unshift(j);
      state.jobs.list.splice(20);
    }
    async function loadJobs() {
      try {
        const list = await source.jobs();
        for (const j of list.slice().reverse()) upsertJob(j);
        state.jobs.loaded = true;
        for (const j of list) if (j.status === "running") pollJob(j.id);
      } catch (e) { /* older server or no jobs: the jobs view shows the error */ }
    }
    async function pollJob(id) {
      if (polling.has(id)) return;
      polling.add(id);
      try {
        for (;;) {
          await sleep(1000);
          let j;
          try { j = await source.job(id); } catch (e) { UI.toast(`Job #${id}: ${e.message}`, "error", 8000); return; }
          upsertJob(j);
          if (j.status !== "running") {
            const kind = { ok: "info", partial: "warn" }[j.status] || "error";
            const label = UI.JOB_STATUS[j.status]?.label || j.status;
            UI.toast(`${label[0].toUpperCase() + label.slice(1)}: ${j.title}${j.error ? " — " + j.error : ""}`, kind, 8000);
            state.dataVersion++;
            loadMeta();
            return;
          }
        }
      } finally { polling.delete(id); }
    }
    async function startJob(body) {
      try {
        const j = await source.startJob(body);
        upsertJob(j);
        pollJob(j.id);
        UI.toast(`Started: ${j.title}`);
        return j;
      } catch (e) {
        UI.toast(e.message + (e.hint ? ` — ${e.hint}` : ""), "error", 8000);
        return null;
      }
    }
    return { state, source, loadMeta, refresh, save, startWatch, stopWatch, setInterval: setInterval_, byPid,
      running, loadJobs, startJob };
  }

  // ================================================================== navigation
  // Grouped like the CLI help: Monitor (procs), Inventory (inventory, scan), Risk (findings), Data (vuln, sources, sync).
  const NAV = [
    { label: "Overview", items: [{ id: "overview", label: "Dashboard", icon: "grid", to: "/overview" }] },
    { label: "Monitor", items: [
      { id: "processes", label: "Processes", icon: "cpu", to: "/processes" },
      { id: "software", label: "Software", icon: "package", to: "/software" },
      { id: "launch-items", label: "Launch items", icon: "rocket", to: "/launch-items" },
      { id: "activity", label: "Activity", icon: "activity", to: "/activity" },
    ] },
    { label: "Inventory", items: [
      { id: "assets", label: "Assets", icon: "server", to: "/assets" },
      { id: "scan", label: "Scan", icon: "target", to: "/scan" },
      { id: "unmatched", label: "Unmatched", icon: "help", to: "/unmatched" },
    ] },
    { label: "Risk", items: [{ id: "findings", label: "Findings", icon: "alert", to: "/findings" }] },
    { label: "Data", items: [
      { id: "vulns", label: "Vulnerabilities", icon: "shield", to: "/vulns" },
      { id: "sources", label: "Sources & sync", icon: "database", to: "/sources" },
    ] },
    { label: "System", items: [
      { id: "jobs", label: "Jobs", icon: "clock", to: "/jobs" },
      { id: "about", label: "About", icon: "info", to: "/about" },
    ] },
  ];

  function useStore() { return global.Vue.inject("store"); }

  /** Two-way binding of filter state <-> route query (filters survive reload and are shareable). */
  function useQueryState(defaults) {
    const route = useRoute();
    const router = useRouter();
    const s = reactive({});
    const read = () => {
      for (const [k, d] of Object.entries(defaults)) {
        const v = route.query[k];
        if (Array.isArray(d)) s[k] = v ? String(v).split(",").filter(Boolean) : [...d];
        else if (typeof d === "boolean") s[k] = v === "1";
        else s[k] = v != null ? String(v) : d;
      }
    };
    read();
    // the same view re-entered with another query (sidebar link, back / forward) must show that query's filters
    watch(() => route.query, read);
    watch(() => ({ ...s }), (v) => {
      const q = { ...route.query };
      for (const [k, d] of Object.entries(defaults)) {
        const cur = v[k];
        const empty = Array.isArray(d) ? !cur.length : typeof d === "boolean" ? !cur : cur === d;
        if (empty) delete q[k];
        else q[k] = Array.isArray(d) ? cur.join(",") : typeof d === "boolean" ? "1" : cur;
      }
      router.replace({ query: q });
    }, { deep: true });
    return s;
  }

  const includesQ = (q, ...vals) => {
    if (!q) return true;
    const needle = q.toLowerCase();
    return vals.some((v) => v != null && String(v).toLowerCase().includes(needle));
  };

  // ================================================================== shared page pieces
  const SnapshotGate = {
    name: "SnapshotGate",
    setup() {
      const store = useStore();
      // the snapshot is taken the first time a monitor view opens (other areas never need one)
      onMounted(() => { if (!store.state.snap && !store.state.loading && !store.state.error) store.refresh(false); });
      return { store };
    },
    template: `<div v-if="!store.state.snap">
      <div v-if="store.state.loading" class="sm-empty"><sm-spinner large/><div class="sm-empty__title">Taking a process snapshot…</div>
        <div class="sm-muted">Reading processes, launch items and identities; matching against the local mirror.</div></div>
      <sm-callout v-else-if="store.state.error" variant="error" :title="store.state.error.message">
        <div v-if="store.state.error.hint">{{ store.state.error.hint }}</div>
        <div class="sm-mt-2"><sm-button size="sm" icon="refresh" @click="store.refresh()">Try again</sm-button></div></sm-callout>
    </div><slot v-else :snap="store.state.snap"/>`,
  };

  const MonitorActions = {
    name: "MonitorActions",
    setup() { return { store: useStore() }; },
    template: `<sm-button icon="refresh" :loading="store.state.loading" @click="store.refresh()" title="Take a new snapshot">Refresh</sm-button>
      <sm-button icon="save" :loading="store.state.saving" :disabled="!store.state.snap" @click="store.save()"
        title="Persist asset process:&lt;host&gt; and its findings to the database">Save</sm-button>
      <sm-button :variant="store.state.watch.on ? '' : 'primary'" :active="store.state.watch.on"
        :icon="store.state.watch.on ? 'pause' : 'eye'" @click="store.state.watch.on ? store.stopWatch() : store.startWatch()"
        :title="store.state.watch.on ? 'Stop watching' : 'Re-snapshot every ' + store.state.watch.interval + ' s and report changes'">
        {{ store.state.watch.on ? 'Watching' : 'Watch' }}</sm-button>`,
  };

  const SnapshotNotes = {
    name: "SnapshotNotes",
    props: { snap: Object },
    setup() { return { store: useStore() }; },
    template: `<sm-callout v-if="!snap.matched" variant="info" title="No vulnerability database">
        Findings are not shown. Create the local mirror first, e.g. <code>secmonk sync kev epss osv -e Go -e npm</code>, then Refresh.</sm-callout>
      <sm-callout v-if="store.state.stale" variant="info" :title="store.state.stale + ' change(s) since this snapshot'">
        The watch reported new or changed executables / launch items. <a href="#" @click.prevent="store.refresh()">Refresh</a> to update the tables.</sm-callout>
      <sm-callout v-if="snap.warnings && snap.warnings.length" variant="warn" :title="snap.warnings.length + ' collector warning(s)'">
        <ul><li v-for="(w, i) in snap.warnings.slice(0, 8)" :key="i">{{ w }}</li></ul></sm-callout>`,
  };

  // ================================================================== process detail
  const ProcessDetail = {
    name: "ProcessDetail",
    props: { row: { type: Object, required: true }, inline: Boolean, note: String },
    emits: ["close", "open"],
    setup(props) {
      const store = useStore();
      const chain = computed(() => {
        const out = [];
        const seen = new Set();
        let cur = props.row;
        while (cur && !seen.has(cur.pid) && out.length < 64) {
          seen.add(cur.pid);
          out.unshift({ key: cur.pid, label: `${cur.process} (${cur.pid})`, current: cur.pid === props.row.pid });
          cur = store.byPid.value.get(cur.ppid);
        }
        return out;
      });
      const children = computed(() => (store.state.snap?.processes || []).filter((r) => r.ppid === props.row.pid && r.pid !== props.row.pid));
      const components = computed(() => (store.state.snap?.software || []).filter((s) => s.pids.includes(props.row.pid)));
      const prov = computed(() => props.row.provenance || {});
      const sig = computed(() => prov.value.signature || null);
      const sigText = computed(() => {
        const s = sig.value;
        if (!s) return null;
        if (s.unknown) return `unknown (${s.unknown})`;
        if (s.signed === false) return "unsigned";
        const who = s.mac_app_store ? "Mac App Store" : s.developer_id ? "Developer ID" : s.apple ? "Apple" : s.adhoc ? "ad-hoc" : "signed";
        return who + (s.verified === true ? " · verified" : s.verified === false ? " · INVALID" : "");
      });
      return { store, chain, children, components, prov, sig, sigText, METHODS: UI.METHODS, FLAGS: UI.FLAGS, fmt };
    },
    template: `<sm-drawer :inline="inline" :title="row.process" @close="$emit('close')">
      <template #subtitle>pid {{ row.pid }} · {{ row.user || '?' }}<template v-if="row.started"> · started {{ fmt.datetime(row.started) }}</template></template>
      <sm-callout v-if="note" variant="info">{{ note }}</sm-callout>
      <div v-if="row.exe"><sm-copy :value="row.exe"/></div>
      <div v-if="row.script" class="sm-muted">runs script <sm-copy :value="row.script"/></div>

      <sm-section title="Launch" icon="rocket">
        <div class="sm-mb-2"><sm-launch-badge :kind="row.launch"/></div>
        <sm-kv :rows="[
          { label: 'Mechanism', value: row.mechanism },
          { label: 'Job label', value: row.label, mono: true },
          { label: 'Configured in', value: row.launch_source, copy: true },
          { label: 'Explained by', value: row.via, mono: true },
          { label: 'Evidence', value: row.evidence },
          { label: 'Parent', value: row.parent_exe || (store.byPid.value.get(row.ppid) || {}).exe, mono: true },
        ]"/>
        <div v-if="chain.length > 1" class="sm-mt-3"><div class="sm-muted sm-mb-1">Ancestry</div>
          <sm-chain :items="chain" @pick="$emit('open', $event)"/></div>
        <div v-if="children.length" class="sm-mt-3"><div class="sm-muted sm-mb-1">Children ({{ children.length }})</div>
          <sm-chain :items="children.slice(0, 20).map(c => ({ key: c.pid, label: c.process + ' (' + c.pid + ')' }))" @pick="$emit('open', $event)"/></div>
      </sm-section>

      <sm-section title="Identity" icon="package">
        <sm-kv :rows="[
          { label: 'Software', value: row.identity || 'not identified' },
          { label: 'Category', value: row.category },
          { label: 'Method', value: row.identity_method && (row.identity_method + ' — ' + (METHODS[row.identity_method] || '')) },
        ]"/>
        <table v-if="components.length > 1" class="sm-table sm-table--static sm-mt-3">
          <thead><tr><th>Component</th><th>Version</th><th>Category</th><th>Findings</th></tr></thead>
          <tbody><tr v-for="c in components" :key="c.name + c.version"><td>{{ c.name }}</td><td class="sm-mono">{{ c.version }}</td>
            <td>{{ c.category }}</td><td><sm-findings-summary :findings="c.findings_detail" empty="—"/></td></tr></tbody></table>
      </sm-section>

      <sm-section title="Findings" icon="alert">
        <template #extra><sm-findings-summary :findings="row.findings_detail"/></template>
        <table v-if="row.findings_detail && row.findings_detail.length" class="sm-table sm-table--static">
          <thead><tr><th>Priority</th><th>Vulnerability</th><th>Component</th><th>Fixed in</th><th class="is-num">CVSS</th></tr></thead>
          <tbody><tr v-for="f in row.findings_detail" :key="f.vuln_id + f.component">
            <td><span class="sm-badges"><sm-priority :priority="f.priority || 'P4'"/><sm-badge v-if="f.kev" variant="kev">KEV</sm-badge></span></td>
            <td class="sm-mono">{{ f.vuln_id }}</td><td>{{ f.component }}</td><td class="sm-mono">{{ f.fixed_version || '—' }}</td>
            <td class="is-num">{{ f.cvss_score != null ? f.cvss_score.toFixed(1) : '' }}</td></tr></tbody></table>
        <div v-else class="sm-muted">{{ store.state.snap && !store.state.snap.matched ? 'Not matched: no vulnerability database.' : 'No open findings for this identity.' }}</div>
      </sm-section>

      <sm-section title="Provenance" icon="download">
        <sm-kv :rows="[
          { label: 'Downloaded by', value: prov.quarantine && (prov.quarantine.agent || (prov.quarantine.event || {}).agent) },
          { label: 'Downloaded at', value: prov.quarantine && fmt.datetime((prov.quarantine.event || {}).time || prov.quarantine.time) },
          { label: 'Download URL', value: prov.quarantine && prov.quarantine.event && prov.quarantine.event.data_url, copy: true },
          { label: 'From page', value: prov.quarantine && prov.quarantine.event && prov.quarantine.event.origin_url, copy: true },
          { label: 'Where from', value: !(prov.quarantine && prov.quarantine.event) && prov.where_froms && prov.where_froms[0], copy: true },
          { label: 'Signature', value: sigText },
          { label: 'Signed by', value: sig && sig.authority && sig.authority[0] },
          { label: 'Team ID', value: sig && sig.team_id, mono: true },
          { label: 'File created', value: prov.created && fmt.datetime(prov.created) },
          { label: 'SHA-256', value: prov.sha256, copy: true },
        ]"/>
        <div v-if="!Object.keys(prov).length" class="sm-muted">No provenance facts (not collected for this executable).</div>
      </sm-section>

      <sm-section v-if="row.flags && row.flags.length" title="Flags" icon="alert">
        <dl class="sm-kv"><template v-for="f in row.flags" :key="f"><dt><sm-flag :flag="f"/></dt><dd>{{ (FLAGS[f] || {}).text || '' }}</dd></template></dl>
      </sm-section>
    </sm-drawer>`,
  };

  // ================================================================== Processes
  const ProcessesView = {
    name: "ProcessesView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      const f = useQueryState({ q: "", kind: [], suspicious: false, mode: "tree" });
      const collapsed = reactive(new Set());
      const rows = computed(() => store.state.snap?.processes || []);
      const hasKids = computed(() => {
        const s = new Set();
        for (const r of rows.value) if (r.ppid !== r.pid) s.add(r.ppid);
        return s;
      });
      const filtering = computed(() => !!(f.q || f.kind.length || f.suspicious));
      const matches = (r) => includesQ(f.q, r.process, r.exe, r.label, r.identity, r.user, r.script, r.pid)
        && (!f.kind.length || f.kind.includes(r.launch)) && (!f.suspicious || r.findings || r.flags.length);
      const visible = computed(() => {
        const all = rows.value;
        if (f.mode === "flat") return all.filter(matches).slice().sort((a, b) => a.pid - b.pid);
        if (filtering.value) {
          const keep = new Set();
          for (const r of all) {
            if (!matches(r)) continue;
            let cur = r;
            while (cur && !keep.has(cur.pid)) { keep.add(cur.pid); cur = store.byPid.value.get(cur.ppid); }
          }
          return all.filter((r) => keep.has(r.pid));
        }
        const out = [];
        let hideBelow = null;
        for (const r of all) {
          if (hideBelow !== null) { if (r.depth > hideBelow) continue; hideBelow = null; }
          out.push(r);
          if (collapsed.has(r.pid)) hideBelow = r.depth;
        }
        return out;
      });
      const matchCount = computed(() => rows.value.filter(matches).length);
      const kindOptions = computed(() => Object.entries(store.state.snap?.summary.launch_kinds || {})
        .sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ value: k, label: (UI.LAUNCH[k] || {}).label || k, count: n })));
      const selected = computed(() => route.params.pid ? store.byPid.value.get(+route.params.pid) : null);
      const open = (pid) => router.push({ path: `/processes/${pid}`, query: route.query });
      const close = () => router.push({ path: "/processes", query: route.query });
      const toggle = (pid) => (collapsed.has(pid) ? collapsed.delete(pid) : collapsed.add(pid));
      const collapseAll = () => { for (const r of rows.value) if (hasKids.value.has(r.pid) && r.depth >= 1) collapsed.add(r.pid); };
      const expandAll = () => collapsed.clear();
      const columns = [
        { key: "pid", label: "PID", cls: "is-num", width: "64px" }, { key: "user", label: "User", width: "90px" },
        { key: "launch", label: "Launch", width: "150px" }, { key: "process", label: "Process" },
        { key: "identity", label: "Identity" }, { key: "findings", label: "Findings", width: "140px" },
        { key: "flags", label: "Flags" },
      ];
      return { store, f, visible, matchCount, kindOptions, selected, open, close, toggle, collapsed, hasKids,
        collapseAll, expandAll, columns, filtering, route, matches };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Processes" subtitle="What is running, how it was started, which software and version it is."><monitor-actions/></sm-page-header>
      <snapshot-gate v-slot="{ snap }">
        <div class="sm-stats">
          <sm-stat label="Processes" :value="snap.summary.processes" :hint="snap.host + ' · ' + $fmt.time(snap.taken_at)"/>
          <sm-stat label="With findings" :value="snap.matched ? snap.summary.with_findings : '—'" :variant="snap.summary.with_findings ? 'p1' : ''"
            clickable @click="f.suspicious = true" :hint="snap.matched ? 'click to filter' : 'no database'"/>
          <sm-stat label="Flagged" :value="snap.summary.flagged" :variant="snap.summary.flagged ? 'warn' : ''" clickable @click="f.suspicious = true" hint="risk heuristics"/>
          <sm-stat label="Software" :value="snap.summary.components" hint="distinct identities" clickable @click="$router.push('/software')"/>
          <sm-stat label="Launch items" :value="snap.summary.launch_items" :hint="snap.summary.missing_programs ? snap.summary.missing_programs + ' missing program' : 'configured'"
            :variant="snap.summary.missing_programs ? 'warn' : ''" clickable @click="$router.push('/launch-items')"/>
        </div>
        <snapshot-notes :snap="snap"/>
        <div class="sm-toolbar">
          <sm-search v-model="f.q" placeholder="Search name, path, label, identity, user"/>
          <sm-switch v-model="f.suspicious">Suspicious only</sm-switch>
          <span class="sm-toolbar__spacer"></span>
          <template v-if="f.mode === 'tree' && !filtering"><sm-button size="sm" variant="ghost" @click="expandAll">Expand all</sm-button>
            <sm-button size="sm" variant="ghost" @click="collapseAll">Collapse all</sm-button></template>
          <sm-segmented v-model="f.mode" :options="[{ value: 'tree', label: 'Tree', icon: 'tree' }, { value: 'flat', label: 'List', icon: 'list' }]"/>
        </div>
        <div class="sm-toolbar"><sm-chips v-model="f.kind" :options="kindOptions"/><span class="sm-toolbar__spacer"></span>
          <span class="sm-toolbar__count">{{ filtering ? matchCount + ' of ' + snap.summary.processes : visible.length + ' shown' }}</span></div>
        <sm-table :columns="columns" :rows="visible" row-key="pid" :selected="selected && selected.pid" label="Processes"
          :row-class="r => filtering && f.mode === 'tree' && !matches(r) ? 'is-dim' : ''" @select="r => open(r.pid)">
          <template #cell-launch="{ row }"><sm-launch-badge :kind="row.launch"/></template>
          <template #cell-process="{ row }"><div class="sm-tree-cell" :style="f.mode === 'tree' ? { '--depth': row.depth } : null">
            <button v-if="f.mode === 'tree'" type="button" :class="['sm-caret', !hasKids.has(row.pid) && 'sm-caret--leaf', !collapsed.has(row.pid) && 'is-open']"
              :aria-label="collapsed.has(row.pid) ? 'Expand' : 'Collapse'" @click.stop="toggle(row.pid)"><sm-icon name="chevron"/></button>
            <span class="sm-proc-name sm-truncate" :title="row.exe">{{ row.process }}</span>
            <span v-if="row.script" class="sm-proc-script sm-truncate">{{ row.script }}</span></div></template>
          <template #cell-identity="{ row }"><span class="sm-truncate" :title="row.identity_method">{{ row.identity }}</span></template>
          <template #cell-findings="{ row }"><sm-findings-summary :findings="row.findings_detail" :empty="snap.matched ? '' : '—'"/></template>
          <template #cell-flags="{ row }"><sm-flags :flags="row.flags"/></template>
          <template #empty><sm-empty title="No process matches the filters" icon="search">
            <sm-button size="sm" @click="f.q = ''; f.kind = []; f.suspicious = false">Clear filters</sm-button></sm-empty></template>
        </sm-table>
        <process-detail v-if="selected" :row="selected" @close="close" @open="open"/>
        <sm-drawer v-else-if="route.params.pid" title="Process not in this snapshot" @close="close">
          <sm-empty :title="'pid ' + route.params.pid + ' is not running anymore'" icon="cpu">Refresh to take a new snapshot.</sm-empty></sm-drawer>
      </snapshot-gate></div>`,
  };

  // ================================================================== Software
  const SoftwareView = {
    name: "SoftwareView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      const f = useQueryState({ q: "", cat: [], findings: false });
      const list = computed(() => (store.state.snap?.software || []).map((s) => ({ ...s, key: `${s.name}@${s.version || ""}@${s.category}` })));
      const catOptions = computed(() => {
        const c = {};
        for (const s of list.value) c[s.category] = (c[s.category] || 0) + 1;
        return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ value: k, label: k, count: n }));
      });
      const rows = computed(() => list.value.filter((s) => includesQ(f.q, s.name, s.version, s.purl, s.product, ...(s.executables || []))
        && (!f.cat.length || f.cat.includes(s.category)) && (!f.findings || s.findings))
        .sort((a, b) => (UI.worstPriority(a.findings_detail) || "P9").localeCompare(UI.worstPriority(b.findings_detail) || "P9")
          || b.count - a.count || a.name.localeCompare(b.name)));
      const selected = computed(() => route.params.key ? list.value.find((s) => s.key === route.params.key) : null);
      const open = (s) => router.push({ path: `/software/${encodeURIComponent(s.key)}`, query: route.query });
      const close = () => router.push({ path: "/software", query: route.query });
      const columns = [{ key: "name", label: "Software" }, { key: "version", label: "Version" }, { key: "category", label: "Category" },
        { key: "resolution", label: "Identified by" }, { key: "count", label: "Processes", cls: "is-num" }, { key: "launch", label: "Launch" },
        { key: "findings", label: "Findings" }, { key: "flags", label: "Flags" }];
      return { store, f, rows, catOptions, selected, open, close, columns, METHODS: UI.METHODS };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Running software" subtitle="One row per software identity behind the running executables."><monitor-actions/></sm-page-header>
      <snapshot-gate v-slot="{ snap }"><snapshot-notes :snap="snap"/>
        <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search software, version, purl, path"/>
          <sm-switch v-model="f.findings">With findings</sm-switch><span class="sm-toolbar__spacer"></span>
          <span class="sm-toolbar__count">{{ rows.length }} of {{ snap.software.length }}</span></div>
        <div class="sm-toolbar"><sm-chips v-model="f.cat" :options="catOptions"/></div>
        <sm-table :columns="columns" :rows="rows" row-key="key" :selected="selected && selected.key" label="Running software" @select="open">
          <template #cell-name="{ row }"><b>{{ row.name }}</b></template>
          <template #cell-version="{ row }"><span class="sm-mono">{{ row.version || '—' }}</span></template>
          <template #cell-category="{ row }"><sm-badge variant="outline">{{ row.category }}</sm-badge></template>
          <template #cell-resolution="{ row }"><span :title="METHODS[row.resolution]">{{ row.resolution }}</span></template>
          <template #cell-launch="{ row }"><span class="sm-badges"><sm-launch-badge v-for="k in row.launch" :key="k" :kind="k"/></span></template>
          <template #cell-findings="{ row }"><sm-findings-summary :findings="row.findings_detail" :empty="snap.matched ? '' : '—'"/></template>
          <template #cell-flags="{ row }"><sm-flags :flags="row.flags"/></template>
          <template #empty><sm-empty title="No software matches the filters" icon="search"/></template>
        </sm-table>
        <sm-drawer v-if="selected" :title="$fmt.identity(selected.name, selected.version)" :subtitle="selected.category + ' · ' + (selected.resolution || '')" @close="close">
          <sm-kv :rows="[{ label: 'Package URL', value: selected.purl, copy: true }, { label: 'Vendor', value: selected.vendor },
            { label: 'Product', value: selected.product }, { label: 'Identified by', value: METHODS[selected.resolution] },
            { label: 'Embedded in', value: selected.via_executable, mono: true }, { label: 'Users', value: selected.users.join(', ') }]"/>
          <sm-section title="Executables" icon="file"><div v-for="e in selected.executables" :key="e" class="sm-mb-1"><sm-copy :value="e"/></div></sm-section>
          <sm-section title="Processes" icon="cpu"><sm-chain :items="selected.pids.map(p => ({ key: p, label: ((store.byPid.value.get(p) || {}).process || '?') + ' (' + p + ')' }))"
            @pick="p => $router.push('/processes/' + p)"/></sm-section>
          <sm-section title="Findings" icon="alert">
            <table v-if="selected.findings_detail.length" class="sm-table sm-table--static"><thead><tr><th>Priority</th><th>Vulnerability</th><th>Fixed in</th><th class="is-num">CVSS</th></tr></thead>
              <tbody><tr v-for="x in selected.findings_detail" :key="x.vuln_id"><td><span class="sm-badges"><sm-priority :priority="x.priority || 'P4'"/><sm-badge v-if="x.kev" variant="kev">KEV</sm-badge></span></td>
                <td class="sm-mono">{{ x.vuln_id }}</td><td class="sm-mono">{{ x.fixed_version || '—' }}</td><td class="is-num">{{ x.cvss_score != null ? x.cvss_score.toFixed(1) : '' }}</td></tr></tbody></table>
            <div v-else class="sm-muted">{{ snap.matched ? 'No open findings.' : 'Not matched: no vulnerability database.' }}</div></sm-section>
          <sm-section v-if="selected.flags.length" title="Flags" icon="alert"><sm-flags :flags="selected.flags"/></sm-section>
        </sm-drawer>
      </snapshot-gate></div>`,
  };

  // ================================================================== Launch items
  const LaunchItemsView = {
    name: "LaunchItemsView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      const f = useQueryState({ q: "", kind: [], running: false, problems: false });
      // stable key (label + defining file): deep links survive refreshes and re-sorting
      const list = computed(() => (store.state.snap?.launch_items || []).map((it) => ({ ...it, key: `${it.label}|${it.source || ""}` })));
      const kindOptions = computed(() => {
        const c = {};
        for (const it of list.value) c[it.kind] = (c[it.kind] || 0) + 1;
        return Object.entries(c).map(([k, n]) => ({ value: k, label: (UI.LAUNCH[k] || {}).label || k, count: n }));
      });
      const rows = computed(() => list.value.filter((it) => includesQ(f.q, it.label, it.program, it.source, it.scope)
        && (!f.kind.length || f.kind.includes(it.kind)) && (!f.running || it.running_pids.length) && (!f.problems || it.missing_program))
        .sort((a, b) => (b.missing_program - a.missing_program) || (b.running_pids.length - a.running_pids.length) || a.label.localeCompare(b.label)));
      const selected = computed(() => route.params.key ? list.value.find((it) => it.key === route.params.key) : null);
      const open = (it) => router.push({ path: `/launch-items/${encodeURIComponent(it.key)}`, query: route.query });
      const close = () => router.push({ path: "/launch-items", query: route.query });
      const columns = [{ key: "label", label: "Label" }, { key: "kind", label: "Kind" }, { key: "scope", label: "Scope" },
        { key: "program", label: "Program" }, { key: "opts", label: "Options" }, { key: "running", label: "Running" }];
      return { store, f, rows, kindOptions, selected, open, close, columns };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Launch items" subtitle="What the system is configured to start (persistence): launchd daemons and agents."><monitor-actions/></sm-page-header>
      <snapshot-gate v-slot="{ snap }">
        <sm-callout v-if="snap.summary.missing_programs" variant="warn" :title="snap.summary.missing_programs + ' launch item(s) point to a program that does not exist'">
          Stale configuration after an uninstall, or a payload that was removed. <a href="#" @click.prevent="f.problems = true">Show them</a>.</sm-callout>
        <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search label, program, plist"/>
          <sm-switch v-model="f.running">Running only</sm-switch><sm-switch v-model="f.problems">Problems only</sm-switch>
          <span class="sm-toolbar__spacer"></span><span class="sm-toolbar__count">{{ rows.length }} of {{ snap.launch_items.length }}</span></div>
        <div class="sm-toolbar"><sm-chips v-model="f.kind" :options="kindOptions"/></div>
        <sm-table :columns="columns" :rows="rows" row-key="key" :selected="selected && selected.key" label="Launch items" @select="open">
          <template #cell-label="{ row }"><span class="sm-mono">{{ row.label }}</span></template>
          <template #cell-kind="{ row }"><sm-launch-badge :kind="row.kind" :title="row.mechanism"/></template>
          <template #cell-program="{ row }"><span class="sm-mono sm-truncate sm-cell-path" :title="row.program">{{ row.program }}</span>
            <sm-badge v-if="row.missing_program" variant="danger" class="sm-ml-2">missing</sm-badge></template>
          <template #cell-opts="{ row }"><span class="sm-badges"><sm-badge v-if="row.run_at_load" variant="outline">run at load</sm-badge>
            <sm-badge v-if="row.keep_alive" variant="outline">keep alive</sm-badge><sm-badge v-if="row.disabled" variant="outline">disabled</sm-badge></span></template>
          <template #cell-running="{ row }"><span v-if="row.running_pids.length" class="sm-badge sm-badge--ok">pid {{ row.running_pids.join(', ') }}</span>
            <span v-else class="sm-muted">—</span></template>
          <template #empty><sm-empty title="No launch item matches the filters" icon="search"/></template>
        </sm-table>
        <sm-drawer v-if="selected" :title="selected.label" :subtitle="selected.mechanism + ' · ' + (selected.scope || '')" @close="close">
          <sm-callout v-if="selected.missing_program" variant="warn" title="Program not found">The configured program does not exist on disk.</sm-callout>
          <sm-kv :rows="[{ label: 'Kind', value: ($options.LAUNCH[selected.kind] || {}).text }, { label: 'Program', value: selected.program, copy: true },
            { label: 'Arguments', value: selected.args.join(' '), mono: true }, { label: 'Defined in', value: selected.source, copy: true },
            { label: 'Run at load', value: selected.run_at_load == null ? null : String(selected.run_at_load) },
            { label: 'Keep alive', value: selected.keep_alive == null ? null : String(selected.keep_alive) },
            { label: 'Disabled', value: selected.disabled == null ? null : String(selected.disabled) }]"/>
          <sm-section title="Running processes" icon="cpu">
            <sm-chain v-if="selected.running_pids.length" :items="selected.running_pids.map(p => ({ key: p, label: ((store.byPid.value.get(p) || {}).process || '?') + ' (' + p + ')' }))"
              @pick="p => $router.push('/processes/' + p)"/><div v-else class="sm-muted">Not running in this snapshot.</div></sm-section>
        </sm-drawer>
      </snapshot-gate></div>`,
    LAUNCH: UI.LAUNCH,
  };

  // ================================================================== Activity
  const ActivityView = {
    name: "ActivityView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      onMounted(() => { store.state.watch.unseen = 0; });
      watch(() => store.state.watch.events.length, () => { if (route.name === "activity") store.state.watch.unseen = 0; });
      const selected = computed(() => route.params.id ? store.state.watch.events.find((e) => String(e.id) === route.params.id) : null);
      const openEvent = (e) => {
        if (e.event.endsWith("-executable")) router.push(`/activity/${e.id}`);
        else router.push({ path: "/launch-items", query: { q: e.label } });
      };
      const intervals = [5, 10, 30, 60].map((s) => ({ value: s, label: `every ${s} s` }));
      return { store, selected, openEvent, intervals, close: () => router.push("/activity") };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Activity" subtitle="Changes reported by the watch: new or replaced executables, launch items added, changed or removed.">
        <sm-select :options="intervals" :model-value="store.state.watch.interval" label="Interval" @update:model-value="store.setInterval"/>
        <sm-button :variant="store.state.watch.on ? '' : 'primary'" :icon="store.state.watch.on ? 'pause' : 'eye'"
          @click="store.state.watch.on ? store.stopWatch() : store.startWatch()">{{ store.state.watch.on ? 'Stop watching' : 'Start watching' }}</sm-button>
        <sm-button variant="ghost" :disabled="!store.state.watch.events.length" @click="store.state.watch.events.splice(0)">Clear</sm-button>
      </sm-page-header>
      <div class="sm-toolbar"><span v-if="store.state.watch.on" class="sm-badge sm-badge--live">watching · {{ store.state.watch.interval }} s</span>
        <span v-else class="sm-badge sm-badge--outline">stopped</span>
        <span class="sm-muted" v-if="store.state.watch.last">last check {{ $fmt.time(store.state.watch.last) }}</span>
        <span class="sm-muted" v-if="store.state.watch.busy"><sm-spinner/></span></div>
      <sm-card flush><div class="sm-feed" v-if="store.state.watch.events.length">
        <sm-feed-item v-for="e in store.state.watch.events" :key="e.id" :event="e" @open="openEvent"/></div>
        <sm-empty v-else :title="store.state.watch.on ? 'Watching — no changes yet' : 'Watch is stopped'" icon="activity">
          <div>{{ store.state.watch.on ? 'The first check is the baseline; anything new from now on appears here.' : 'Start watching to re-snapshot periodically and see what changes.' }}</div></sm-empty></sm-card>
      <process-detail v-if="selected && selected.pid != null" :row="selected" note="As seen by the watch when the event was reported." @close="close"
        @open="p => $router.push('/processes/' + p)"/>
    </div>`,
  };

  // ================================================================== data areas: shared pieces
  /**
   * Load data from the source. Reloads when deps() changes (then the old data is dropped) and when a job finished
   * (store.state.dataVersion; the old data stays visible meanwhile). Returns reactive {data, error, loading, reload}.
   */
  function useResource(fetcher, deps = () => null) {
    const store = useStore();
    const res = reactive({ data: null, error: null, loading: false, reload: null });
    let seq = 0;
    async function load() {
      const my = ++seq;
      res.loading = true;
      try {
        const d = await fetcher();
        if (my === seq) { res.data = d; res.error = null; }
      } catch (e) {
        if (my === seq) res.error = e;
      } finally {
        if (my === seq) res.loading = false;
      }
    }
    res.reload = load;
    watch(() => [JSON.stringify(deps() ?? null), store.state.dataVersion], (now, before) => {
      if (before && now[0] !== before[0]) { res.data = null; res.error = null; }
      load();
    }, { immediate: true });
    return res;
  }

  const fkey = (f) => `${f.asset_id}|${f.component_id}|${f.vuln_id}`;
  const statusVariant = (s) => ({ open: "warn", fixed: "ok" })[s] || "outline";

  /** No database yet: what to do first. */
  const NoDb = {
    name: "NoDb",
    props: { error: Object },
    template: `<sm-empty title="No vulnerability database yet" icon="database">
      <div class="sm-muted">{{ error && error.message }}</div>
      <div>Create the local mirror (Sources &amp; sync), then scan assets: findings appear here.</div>
      <div class="sm-badges sm-mt-2"><sm-button variant="primary" icon="database" @click="$router.push('/sources')">Sources &amp; sync</sm-button>
        <sm-button icon="target" @click="$router.push('/scan')">Scan a target</sm-button></div></sm-empty>`,
  };

  /** Loading / no database / error states around a useResource() result; the slot gets {data}. */
  const DataGate = {
    name: "DataGate",
    props: { res: { type: Object, required: true }, what: { type: String, default: "data" } },
    template: `<div v-if="res.data == null">
        <no-db v-if="res.error && res.error.code === 'no-db'" :error="res.error"/>
        <sm-callout v-else-if="res.error" variant="error" :title="res.error.message">
          <div v-if="res.error.hint">{{ res.error.hint }}</div>
          <div class="sm-mt-2"><sm-button size="sm" icon="refresh" @click="res.reload()">Try again</sm-button></div></sm-callout>
        <div v-else class="sm-empty"><sm-spinner large/><div class="sm-muted">Loading {{ what }}…</div></div>
      </div><template v-else><sm-callout v-if="res.error" variant="error" :title="res.error.message"/><slot :data="res.data"/></template>`,
  };

  /** Findings table (reports.finding_dict rows): Findings, asset detail, dashboard, vulnerability page, scan result. */
  const FindingsTable = {
    name: "FindingsTable",
    props: { rows: { type: Array, default: () => [] }, selected: String, showAsset: { type: Boolean, default: true },
      showVuln: { type: Boolean, default: true }, showStatus: Boolean, compact: Boolean, label: String },
    emits: ["select"],
    setup(props) {
      const columns = computed(() => [
        { key: "priority", label: "Priority", width: "104px" },
        ...(props.showVuln ? [{ key: "vuln_id", label: "Vulnerability" }] : []),
        { key: "component", label: "Component" },
        ...(props.showAsset ? [{ key: "asset_id", label: "Asset" }] : []),
        { key: "fixed_version", label: "Fixed in" }, { key: "severity", label: "Severity" },
        ...(props.compact ? [] : [{ key: "epss", label: "EPSS", cls: "is-num" }, { key: "triage", label: "Triage" }]),
        ...(props.showStatus ? [{ key: "status", label: "Status" }] : []),
      ]);
      const keyed = computed(() => (props.rows || []).map((f) => ({ ...f, key: fkey(f) })));
      return { columns, keyed, MATCHED_BY: UI.MATCHED_BY, statusVariant };
    },
    template: `<sm-table :columns="columns" :rows="keyed" row-key="key" :selected="selected" :label="label || 'Findings'"
      :row-class="r => r.status !== 'open' ? 'is-dim' : ''" @select="r => $emit('select', r)">
      <template #cell-priority="{ row }"><span class="sm-badges"><sm-priority :priority="row.priority || 'P4'"/>
        <sm-badge v-if="row.kev" variant="kev" title="Known exploited (CISA KEV)">KEV</sm-badge></span></template>
      <template #cell-vuln_id="{ row }"><span class="sm-mono sm-nowrap">{{ row.vuln_id }}</span></template>
      <template #cell-component="{ row }"><span class="sm-ident"><span class="sm-truncate"><b>{{ row.component }}</b> <span class="sm-mono">{{ row.version }}</span></span>
        <span class="sm-ident__sub" :title="MATCHED_BY[row.matched_by]">{{ row.matched_by }}<template v-if="row.confidence != null && row.confidence < 1"> · confidence {{ $fmt.score(row.confidence) }}</template></span></span></template>
      <template #cell-asset_id="{ row }"><span class="sm-mono sm-truncate sm-cell-path" :title="row.asset_id">{{ row.asset_id }}</span></template>
      <template #cell-fixed_version="{ row }"><span class="sm-mono">{{ row.fixed_version || '—' }}</span></template>
      <template #cell-severity="{ row }"><sm-severity :severity="row.severity" :score="row.cvss_score"/></template>
      <template #cell-epss="{ row }">{{ row.epss != null ? $fmt.score(row.epss, 3) : '' }}</template>
      <template #cell-triage="{ row }"><span v-if="row.triage" class="sm-badge sm-badge--outline" :title="row.triage_source">{{ row.triage }}</span></template>
      <template #cell-status="{ row }"><sm-badge :variant="statusVariant(row.status)">{{ row.status }}</sm-badge></template>
      <template #empty><slot name="empty"><sm-empty title="No findings" icon="check"/></slot></template>
    </sm-table>`,
  };

  /** Finding drawer: the finding, its component and asset, and the vulnerability as the mirror knows it. */
  const FindingDetail = {
    name: "FindingDetail",
    props: { finding: { type: Object, required: true }, inline: Boolean },
    emits: ["close"],
    setup(props) {
      const store = useStore();
      const vuln = useResource(() => store.source.vuln(props.finding.vuln_id), () => props.finding.vuln_id);
      return { vuln, UI, fmt, statusVariant };
    },
    template: `<sm-drawer :inline="inline" :title="finding.vuln_id" @close="$emit('close')">
      <template #subtitle>{{ fmt.identity(finding.component, finding.version) }} · <span class="sm-mono">{{ finding.asset_id }}</span></template>
      <div><div class="sm-badges"><sm-priority :priority="finding.priority || 'P4'"/><sm-badge v-if="finding.kev" variant="kev">KEV · known exploited</sm-badge>
        <sm-severity :severity="finding.severity" :score="finding.cvss_score"/><sm-badge :variant="statusVariant(finding.status)">{{ finding.status }}</sm-badge></div>
        <div class="sm-muted sm-mt-2">{{ UI.PRIORITY_TEXT[finding.priority] }}</div></div>
      <sm-section title="Finding" icon="alert">
        <sm-kv :rows="[
          { label: 'Component', value: fmt.identity(finding.component, finding.version) },
          { label: 'Fixed in', value: finding.fixed_version || 'no fixed version known' },
          { label: 'Category', value: finding.category }, { label: 'Ecosystem', value: finding.ecosystem },
          { label: 'Package URL', value: finding.purl, copy: true },
          { label: 'Matched by', value: finding.matched_by && (finding.matched_by + (finding.confidence != null ? ' · confidence ' + fmt.score(finding.confidence) : '') + ' — ' + (UI.MATCHED_BY[finding.matched_by] || '')) },
          { label: 'Distro triage', value: finding.triage && (finding.triage + (finding.triage_source ? ' (' + finding.triage_source + ')' : '')) },
          { label: 'EPSS', value: finding.epss != null ? fmt.score(finding.epss, 3) : null },
          { label: 'First seen', value: fmt.datetime(finding.first_seen) }, { label: 'Last seen', value: fmt.datetime(finding.last_seen) },
          { label: 'Fixed at', value: fmt.datetime(finding.fixed_at) },
        ]"/>
        <div v-if="finding.advisory_ids && finding.advisory_ids.length" class="sm-mt-3"><div class="sm-muted sm-mb-1">Matched advisories</div>
          <sm-chain :items="finding.advisory_ids.map(a => ({ key: a, label: a }))" @pick="a => $router.push({ name: 'vuln', params: { id: a } })"/></div>
        <div class="sm-badges sm-mt-3"><sm-button size="sm" icon="server" @click="$router.push({ name: 'asset', params: { id: finding.asset_id }, query: { tab: 'findings' } })">Open asset</sm-button>
          <sm-button size="sm" icon="shield" @click="$router.push({ name: 'vuln', params: { id: finding.vuln_id } })">Open vulnerability</sm-button></div>
      </sm-section>
      <sm-section title="Vulnerability" icon="shield">
        <div v-if="vuln.data == null && !vuln.error"><sm-spinner/></div>
        <div v-else-if="vuln.error" class="sm-muted">{{ vuln.error.message }}</div>
        <template v-else><p class="sm-prose sm-mt-0">{{ vuln.data.summary || 'No summary in the mirror.' }}</p>
          <sm-kv class="sm-mt-3" :rows="[
            { label: 'Aliases', value: vuln.data.aliases.join(', ') },
            { label: 'KEV', value: vuln.data.kev && ('added ' + vuln.data.kev.date_added + (vuln.data.kev.due_date ? ', due ' + vuln.data.kev.due_date : '')) },
            { label: 'Ransomware', value: vuln.data.kev && vuln.data.kev.ransomware },
            { label: 'EPSS', value: vuln.data.epss && (fmt.score(vuln.data.epss.score, 3) + ' (percentile ' + fmt.pct(vuln.data.epss.percentile) + ')') },
            { label: 'Sources', value: vuln.data.records.map(r => r.source).join(', ') },
          ]"/></template>
      </sm-section>
    </sm-drawer>`,
  };

  /** Result of a finished scan or sync job (web/jobs.py result shapes). */
  const JobResult = {
    name: "JobResult",
    props: { job: { type: Object, required: true } },
    setup(props) {
      const router = useRouter();
      const stats = computed(() => Object.entries(props.job.result?.stats || {}).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(" · "));
      const open = (f) => props.job.result.saved && router.push({ name: "findings", params: { key: f.key } });
      return { stats, open };
    },
    template: `<template v-if="job.result && job.kind === 'scan'">
        <div class="sm-badges"><b class="sm-mono">{{ job.result.asset }}</b><sm-findings-summary :counts="job.result.counts" empty="no findings"/>
          <sm-badge v-if="!job.result.saved" variant="outline" title="Matched in a temporary overlay: nothing was written">not saved</sm-badge>
          <sm-badge v-if="job.result.partial" variant="warn">partial</sm-badge></div>
        <div class="sm-muted">{{ stats }}</div>
        <sm-callout v-if="job.result.warnings.length" variant="warn" :title="job.result.warnings.length + ' collector warning(s)'">
          <ul><li v-for="(w, i) in job.result.warnings.slice(0, 8)" :key="i">{{ w }}</li></ul></sm-callout>
        <findings-table v-if="job.result.findings.length" :rows="job.result.findings.slice(0, 10)" :show-asset="false" compact label="Scan findings" @select="open"/>
        <div v-if="job.result.saved"><sm-button size="sm" icon="server" @click="$router.push({ name: 'asset', params: { id: job.result.asset } })">Open asset</sm-button></div>
      </template>
      <div v-else-if="job.result && job.kind === 'sync'" class="sm-table-wrap sm-table-wrap--auto"><table class="sm-table sm-table--static">
        <thead><tr><th>Source</th><th>Status</th><th class="is-num">Records</th><th class="is-num">Seconds</th><th>Message</th></tr></thead>
        <tbody><tr v-for="r in job.result.sources" :key="r.source"><td><b>{{ r.source }}</b></td>
          <td><sm-badge :variant="r.status === 'ok' ? 'ok' : r.status === 'partial' ? 'warn' : 'danger'">{{ r.status }}</sm-badge></td>
          <td class="is-num">{{ $fmt.num(r.records) }}</td><td class="is-num">{{ r.seconds }}</td><td>{{ r.message }}</td></tr></tbody></table></div>`,
  };

  /** Jobs of one kind (scan / sync), newest first, with their results. */
  const JobList = {
    name: "JobList",
    props: { kind: String, limit: { type: Number, default: 3 } },
    setup(props) {
      const store = useStore();
      const jobs = computed(() => store.state.jobs.list.filter((j) => !props.kind || j.kind === props.kind).slice(0, props.limit));
      return { jobs };
    },
    template: `<div v-if="jobs.length"><sm-job v-for="j in jobs" :key="j.id" :job="j"><job-result v-if="j.result" :job="j"/></sm-job></div>
      <div v-else class="sm-muted">Nothing run from this page since the server started.</div>`,
  };

  const ActionsOff = {
    name: "ActionsOff",
    setup() { return { store: useStore() }; },
    template: `<sm-callout v-if="store.state.meta && store.state.meta.actions === false" variant="warn" title="Scans and syncs are disabled on this server">
      The UI listens on a non-loopback address. Restart it with <code>--allow-actions</code> to run them from the browser, or use the command shown below.</sm-callout>`,
  };

  // ================================================================== Dashboard
  const OverviewView = {
    name: "OverviewView",
    setup() {
      const store = useStore();
      const router = useRouter();
      const res = useResource(() => store.source.overview());
      const risk = (a) => { const c = a.findings_by_priority; return c.kev * 1e8 + c.P1 * 1e6 + c.P2 * 1e4 + c.P3 * 1e2 + c.P4; };
      const assets = computed(() => (res.data?.assets || []).slice().sort((a, b) => risk(b) - risk(a) || a.id.localeCompare(b.id)).slice(0, 8));
      // per-ecosystem OSV rows are shown, internal cursors (cvelist:git, nvd:progress) are not
      const sources = computed(() => (res.data?.sources || []).filter((s) => !s.source.includes(":") || s.source.startsWith("osv:")));
      const go = (path, query) => router.push({ path, query });
      const assetCols = [{ key: "id", label: "Asset" }, { key: "risk", label: "Open findings", width: "200px" }];
      const srcCols = [{ key: "source", label: "Source" }, { key: "last_sync", label: "Last sync" }, { key: "records", label: "Records", cls: "is-num" }, { key: "status", label: "" }];
      return { res, assets, sources, go, assetCols, srcCols, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Dashboard" subtitle="Open findings across every scanned asset, the most urgent ones, and how fresh the vulnerability mirror is.">
        <sm-button icon="target" @click="go('/scan')">Scan</sm-button><sm-button icon="database" @click="go('/sources')">Sync</sm-button></sm-page-header>
      <data-gate :res="res" what="the dashboard" v-slot="{ data }">
        <sm-callout v-if="!data.sources.length" variant="warn" title="The vulnerability mirror is empty">
          Nothing can be matched yet. <a href="#/sources">Sync sources</a> (KEV, EPSS and the OSV ecosystems you use are a good start).</sm-callout>
        <sm-callout v-if="!data.totals.assets" variant="info" title="No assets yet">
          Scan a target — this machine, a project directory, a container image, an SSH host — to see its components and findings. <a href="#/scan">Scan a target</a>.</sm-callout>
        <div class="sm-stats">
          <sm-stat label="Open findings" :value="fmt.num(data.totals.open_findings)" :hint="'on ' + fmt.plural(data.totals.assets, 'asset')" clickable @click="go('/findings')"/>
          <sm-stat label="P1 · fix now" :value="data.totals.P1" :variant="data.totals.P1 ? 'p1' : ''" clickable @click="go('/findings', { priority: 'P1' })"/>
          <sm-stat label="P2 · fix soon" :value="data.totals.P2" :variant="data.totals.P2 ? 'warn' : ''" clickable @click="go('/findings', { priority: 'P2' })"/>
          <sm-stat label="Known exploited" :value="data.totals.kev" :variant="data.totals.kev ? 'p1' : ''" hint="in CISA KEV" clickable @click="go('/findings', { kev: '1' })"/>
          <sm-stat label="Fixable" :value="data.totals.fixable" hint="fixed version known" clickable @click="go('/findings', { fixable: '1' })"/>
          <sm-stat label="Components" :value="fmt.num(data.totals.components)" :hint="'latest scans of ' + fmt.plural(data.totals.assets, 'asset')" clickable @click="go('/assets')"/>
        </div>
        <div class="sm-grid-main">
          <sm-card title="Most urgent findings" icon="alert" flush>
            <template #actions><sm-button size="sm" variant="ghost" @click="go('/findings')">All findings</sm-button></template>
            <findings-table :rows="data.top_findings" compact label="Most urgent findings" @select="f => $router.push({ name: 'findings', params: { key: f.key } })">
              <template #empty><sm-empty title="No open findings" icon="check">Nothing matched on the scanned assets.</sm-empty></template></findings-table>
          </sm-card>
          <div class="sm-stack">
            <sm-card title="Assets at risk" icon="server" flush>
              <template #actions><sm-button size="sm" variant="ghost" @click="go('/assets')">All assets</sm-button></template>
              <sm-table :columns="assetCols" :rows="assets" row-key="id" label="Assets at risk" @select="a => $router.push({ name: 'asset', params: { id: a.id } })">
                <template #cell-id="{ row }"><span class="sm-ident"><b class="sm-truncate" :title="row.id">{{ row.name || row.id }}</b><span class="sm-ident__sub">{{ [row.type, row.os].filter(Boolean).join(' · ') }}</span></span></template>
                <template #cell-risk="{ row }"><sm-priority-bar :counts="row.findings_by_priority" legend/></template>
                <template #empty><sm-empty title="No assets" icon="server"/></template></sm-table>
            </sm-card>
            <sm-card title="Vulnerability mirror" icon="database" flush>
              <template #actions><sm-button size="sm" variant="ghost" @click="go('/sources')">Sources &amp; sync</sm-button></template>
              <sm-table :columns="srcCols" :rows="sources" row-key="source" label="Mirror freshness" @select="() => go('/sources')">
                <template #cell-source="{ row }"><b>{{ row.source }}</b></template>
                <template #cell-last_sync="{ row }"><span :class="fmt.ageDays(row.last_sync) > 7 && 'sm-is-stale'" :title="row.last_sync">{{ fmt.ago(row.last_sync) }}</span></template>
                <template #cell-records="{ row }">{{ fmt.num(row.records) }}</template>
                <template #cell-status="{ row }"><sm-badge :variant="row.status === 'ok' ? 'ok' : row.status === 'partial' ? 'warn' : 'danger'">{{ row.status }}</sm-badge></template>
                <template #empty><sm-empty title="Never synced" icon="database"/></template></sm-table>
            </sm-card>
          </div>
        </div>
      </data-gate></div>`,
  };

  // ================================================================== Assets
  const AssetsView = {
    name: "AssetsView",
    setup() {
      const store = useStore();
      const router = useRouter();
      const res = useResource(() => store.source.assets());
      const f = useQueryState({ q: "", type: [], findings: false });
      const all = computed(() => res.data || []);
      const typeOptions = computed(() => {
        const c = {};
        for (const a of all.value) c[a.type] = (c[a.type] || 0) + 1;
        return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ value: k, label: k, count: n }));
      });
      const risk = (a) => { const c = a.findings_by_priority || {}; return (c.kev || 0) * 1e8 + (c.P1 || 0) * 1e6 + (c.P2 || 0) * 1e4 + (c.P3 || 0) * 1e2 + (c.P4 || 0); };
      const rows = computed(() => all.value.filter((a) => includesQ(f.q, a.id, a.name, a.os, a.platform, a.type)
        && (!f.type.length || f.type.includes(a.type)) && (!f.findings || a.open_findings))
        .sort((a, b) => risk(b) - risk(a) || a.id.localeCompare(b.id)));
      const columns = [{ key: "id", label: "Asset" }, { key: "type", label: "Type" }, { key: "os", label: "OS / platform" },
        { key: "components", label: "Components", cls: "is-num" }, { key: "findings", label: "Open findings" },
        { key: "bar", label: "", width: "136px" }, { key: "last_seen", label: "Last scan" }];
      const open = (a) => router.push({ name: "asset", params: { id: a.id } });
      return { res, f, rows, typeOptions, columns, open, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Assets" subtitle="Every scanned target with its latest inventory and open findings (secmonk inventory assets).">
        <sm-button variant="ghost" icon="help" @click="$router.push('/unmatched')">Unmatched identities</sm-button>
        <sm-button variant="primary" icon="target" @click="$router.push('/scan')">Scan a target</sm-button></sm-page-header>
      <data-gate :res="res" what="assets" v-slot="{ data }">
        <sm-empty v-if="!data.length" title="No assets yet" icon="server"><div>Scan this machine, a directory, an image or a host to create one.</div>
          <sm-button variant="primary" icon="target" class="sm-mt-2" @click="$router.push('/scan')">Scan a target</sm-button></sm-empty>
        <template v-else>
          <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search id, name, OS"/><sm-switch v-model="f.findings">With open findings</sm-switch>
            <span class="sm-toolbar__spacer"></span><span class="sm-toolbar__count">{{ rows.length }} of {{ data.length }}</span></div>
          <div class="sm-toolbar"><sm-chips v-model="f.type" :options="typeOptions"/></div>
          <sm-table :columns="columns" :rows="rows" row-key="id" label="Assets" @select="open">
            <template #cell-id="{ row }"><span class="sm-ident"><b class="sm-truncate">{{ row.name || row.id }}</b><span class="sm-ident__sub" :title="row.id">{{ row.id }}</span></span></template>
            <template #cell-type="{ row }"><sm-badge variant="outline">{{ row.type }}</sm-badge></template>
            <template #cell-os="{ row }">{{ row.os || '—' }}<span v-if="row.platform" class="sm-muted"> · {{ row.platform }}</span></template>
            <template #cell-components="{ row }">{{ fmt.num(row.components) }}</template>
            <template #cell-findings="{ row }"><sm-findings-summary :counts="row.findings_by_priority" empty="none"/></template>
            <template #cell-bar="{ row }"><sm-priority-bar :counts="row.findings_by_priority"/></template>
            <template #cell-last_seen="{ row }"><span :title="row.last_seen">{{ fmt.ago(row.last_seen) }}</span></template>
            <template #empty><sm-empty title="No asset matches the filters" icon="search"/></template>
          </sm-table>
        </template>
      </data-gate></div>`,
  };

  const AssetDetailView = {
    name: "AssetDetailView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      const id = computed(() => route.params.id);
      const res = useResource(() => store.source.asset(id.value), () => id.value);
      const f = useQueryState({ tab: "findings", q: "", closed: false, prio: [], cat: [], withf: false, f: "" });
      const d = computed(() => res.data);
      const findings = computed(() => (d.value?.findings || []).filter((x) => (f.closed || x.status === "open")
        && (!f.prio.length || f.prio.includes(x.priority))
        && includesQ(f.q, x.vuln_id, x.component, x.version, x.fixed_version, x.triage, ...(x.advisory_ids || []))));
      const components = computed(() => (d.value?.components || []).filter((c) => includesQ(f.q, c.name, c.version, c.purl, c.cpe, c.path, c.ecosystem, c.vendor)
        && (!f.cat.length || f.cat.includes(c.category)) && (!f.withf || c.findings.total)));
      const catOptions = computed(() => {
        const c = {};
        for (const x of d.value?.components || []) c[x.category] = (c[x.category] || 0) + 1;
        return Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ value: k, label: k, count: n }));
      });
      const prioOptions = ["P1", "P2", "P3", "P4"].map((p) => ({ value: p, label: p }));
      const tabs = computed(() => [
        { value: "findings", label: "Findings", count: d.value ? d.value.summary.open.total : null },
        { value: "components", label: "Components", count: d.value ? d.value.components.length : null },
        { value: "scans", label: "Scans", count: d.value ? d.value.scans.length : null },
        { value: "details", label: "Details" },
      ]);
      const setTab = (t) => { f.tab = t; f.q = ""; };
      const selected = computed(() => (f.f ? (d.value?.findings || []).find((x) => fkey(x) === f.f) : null));
      const showComponent = (c) => { f.tab = "findings"; f.q = c.name; };
      const matching = ref(false);
      async function rematch() {
        matching.value = true;
        try {
          const r = await store.source.matchAsset(id.value);
          UI.toast(`Re-matched: ${Object.entries(r.stats || {}).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(" · ")}`);
          store.state.dataVersion++;
        } catch (e) { UI.toast(`Match failed: ${e.message}`, "error", 8000); }
        finally { matching.value = false; }
      }
      const rescan = () => router.push({ path: "/scan", query: { collector: d.value?.scans[0]?.collector } });
      const compCols = [{ key: "name", label: "Component" }, { key: "version", label: "Version" }, { key: "category", label: "Category" },
        { key: "eco", label: "Ecosystem / vendor" }, { key: "path", label: "Path" }, { key: "findings", label: "Open findings" }];
      const scanCols = [{ key: "id", label: "Scan", cls: "is-num", width: "64px" }, { key: "collector", label: "Collector" },
        { key: "started_at", label: "Started" }, { key: "components", label: "Components", cls: "is-num" }, { key: "state", label: "" }];
      const metaRows = computed(() => Object.entries(d.value?.asset.meta || {}).map(([k, v]) => ({
        label: k, value: v == null ? null : typeof v === "object" ? JSON.stringify(v) : String(v), mono: typeof v === "object" })));
      return { res, f, d, id, findings, components, catOptions, prioOptions, tabs, setTab, selected, showComponent, matching,
        rematch, rescan, compCols, scanCols, metaRows, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header :title="(d && (d.asset.name || d.asset.id)) || id" :subtitle="d ? [d.asset.type, [d.asset.os_name, d.asset.os_version].filter(Boolean).join(' '), d.asset.platform].filter(Boolean).join(' · ') : 'Asset'">
        <sm-button variant="ghost" icon="list" @click="$router.push('/assets')">All assets</sm-button>
        <sm-button icon="refresh" :loading="matching" :disabled="!d" @click="rematch" title="Match the stored inventory against the current mirror (secmonk match)">Re-match</sm-button>
        <sm-button icon="target" :disabled="!d" @click="rescan" title="Scan again with the same collector">Rescan</sm-button></sm-page-header>
      <data-gate :res="res" what="the asset" v-slot="{ data }">
        <div class="sm-muted"><span class="sm-mono">{{ data.asset.id }}</span> · last scan <span :title="data.asset.last_seen">{{ fmt.ago(data.asset.last_seen) }}</span>
          <template v-if="data.scans[0]"> with <b>{{ data.scans[0].collector }}</b></template></div>
        <sm-callout v-if="data.partial" variant="warn" title="Partial inventory">The latest scan was partial ({{ data.scans[0].partial_reason || 'see warnings' }}): components it did not see are kept from earlier scans.</sm-callout>
        <sm-callout v-if="data.warnings.length" variant="warn" :title="data.warnings.length + ' collector warning(s) in the latest scan'">
          <ul><li v-for="(w, i) in data.warnings.slice(0, 8)" :key="i">{{ w }}</li></ul></sm-callout>
        <div class="sm-stats">
          <sm-stat label="Open findings" :value="data.summary.open.total" clickable @click="setTab('findings')"/>
          <sm-stat label="P1" :value="data.summary.open.P1" :variant="data.summary.open.P1 ? 'p1' : ''" clickable @click="setTab('findings'); f.prio = ['P1']"/>
          <sm-stat label="P2" :value="data.summary.open.P2" :variant="data.summary.open.P2 ? 'warn' : ''" clickable @click="setTab('findings'); f.prio = ['P2']"/>
          <sm-stat label="Known exploited" :value="data.summary.open.kev" :variant="data.summary.open.kev ? 'p1' : ''"/>
          <sm-stat label="Components" :value="fmt.num(data.summary.components)" clickable @click="setTab('components')"/>
        </div>
        <sm-tabs :options="tabs" :model-value="f.tab" @update:model-value="setTab"/>
        <template v-if="f.tab === 'findings'">
          <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search vulnerability, component, fixed version"/>
            <sm-chips v-model="f.prio" :options="prioOptions"/><sm-switch v-model="f.closed">Include fixed</sm-switch>
            <span class="sm-toolbar__spacer"></span><span class="sm-toolbar__count">{{ findings.length }} shown</span></div>
          <findings-table :rows="findings" :show-asset="false" :show-status="f.closed" :selected="f.f" label="Asset findings" @select="x => f.f = x.key">
            <template #empty><sm-empty :title="data.findings.length ? 'No finding matches the filters' : 'No findings on this asset'" icon="check"/></template></findings-table>
        </template>
        <template v-else-if="f.tab === 'components'">
          <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search name, version, purl, path"/><sm-switch v-model="f.withf">With open findings</sm-switch>
            <span class="sm-toolbar__spacer"></span><span class="sm-toolbar__count">{{ components.length }} of {{ data.components.length }}</span></div>
          <div class="sm-toolbar"><sm-chips v-model="f.cat" :options="catOptions"/></div>
          <sm-table :columns="compCols" :rows="components" row-key="id" label="Components" @select="showComponent">
            <template #cell-name="{ row }"><span class="sm-ident"><b class="sm-truncate">{{ row.name }}</b><span class="sm-ident__sub" :title="row.purl || row.cpe">{{ row.purl || row.cpe }}</span></span></template>
            <template #cell-version="{ row }"><span class="sm-mono">{{ row.version || '—' }}</span></template>
            <template #cell-category="{ row }"><sm-badge variant="outline">{{ row.category }}</sm-badge></template>
            <template #cell-eco="{ row }">{{ row.ecosystem || row.vendor || '' }}</template>
            <template #cell-path="{ row }"><span class="sm-mono sm-truncate sm-cell-path" :title="row.path">{{ row.path }}</span></template>
            <template #cell-findings="{ row }"><sm-findings-summary :counts="row.findings"/></template>
            <template #empty><sm-empty title="No component matches the filters" icon="search"/></template>
          </sm-table>
        </template>
        <sm-table v-else-if="f.tab === 'scans'" :columns="scanCols" :rows="data.scans" row-key="id" static label="Scans">
          <template #cell-started_at="{ row }"><span :title="row.started_at">{{ fmt.datetime(row.started_at) }}</span></template>
          <template #cell-state="{ row }"><span class="sm-badges"><sm-badge v-if="row.partial" variant="warn" :title="row.partial_reason">partial</sm-badge>
            <sm-badge v-if="row.warnings.length" variant="outline" :title="row.warnings.join('\\n')">{{ row.warnings.length }} warning(s)</sm-badge></span></template>
        </sm-table>
        <div v-else class="sm-grid-2"><sm-card title="Asset" icon="server"><sm-kv :rows="[
            { label: 'Id', value: data.asset.id, copy: true }, { label: 'Type', value: data.asset.type }, { label: 'Name', value: data.asset.name },
            { label: 'OS', value: [data.asset.os_name, data.asset.os_version].filter(Boolean).join(' ') }, { label: 'Platform', value: data.asset.platform },
            { label: 'First seen', value: fmt.datetime(data.asset.first_seen) }, { label: 'Last seen', value: fmt.datetime(data.asset.last_seen) }]"/></sm-card>
          <sm-card title="Collector facts" icon="info"><sm-kv v-if="metaRows.length" :rows="metaRows"/><div v-else class="sm-muted">None recorded.</div></sm-card></div>
        <finding-detail v-if="selected" :finding="selected" @close="f.f = ''"/>
      </data-gate></div>`,
  };

  const UnmatchedView = {
    name: "UnmatchedView",
    setup() {
      const store = useStore();
      const res = useResource(() => store.source.unmatched());
      const f = useQueryState({ q: "" });
      const rows = computed(() => (res.data || []).map((r, i) => ({ ...r, key: `${r.category}|${r.name}|${r.version}|${i}` }))
        .filter((r) => includesQ(f.q, r.name, r.version, r.product, r.bundle_id)));
      const columns = [{ key: "name", label: "Application" }, { key: "version", label: "Version" }, { key: "category", label: "Category" },
        { key: "product", label: "Normalized product" }, { key: "bundle_id", label: "Bundle id" }];
      return { res, f, rows, columns };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Unmatched identities" subtitle="Applications whose product identity is only a normalized name (secmonk inventory unmatched)."/>
      <sm-callout variant="info" title="Candidates for the alias table">Name-based product matching is less reliable: add a vendor / product mapping for these in
        <code>data/product_aliases.yaml</code> so CVE and CPE records match them with full confidence.</sm-callout>
      <data-gate :res="res" what="unmatched identities" v-slot="{ data }">
        <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search name, product, bundle id"/><span class="sm-toolbar__spacer"></span>
          <span class="sm-toolbar__count">{{ rows.length }} of {{ data.length }}</span></div>
        <sm-table :columns="columns" :rows="rows" row-key="key" static label="Unmatched identities">
          <template #cell-name="{ row }"><b>{{ row.name }}</b></template>
          <template #cell-version="{ row }"><span class="sm-mono">{{ row.version }}</span></template>
          <template #cell-product="{ row }"><span class="sm-mono">{{ row.product }}</span></template>
          <template #cell-bundle_id="{ row }"><span class="sm-mono">{{ row.bundle_id }}</span></template>
          <template #empty><sm-empty title="Every application has a product identity" icon="check"/></template>
        </sm-table>
      </data-gate></div>`,
  };

  // ================================================================== Scan
  const shellArg = (v) => (/^[\w@%+=:,./-]+$/.test(v) ? v : `'${String(v).replace(/'/g, "'\\''")}'`);

  const ScanView = {
    name: "ScanView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const collectors = useResource(() => store.source.collectors());
      const form = reactive({ collector: route.query.collector || "fs", target: route.query.target || "", options: "", save: true, min_confidence: 0.5 });
      const info = computed(() => (collectors.data || []).find((c) => c.name === form.collector) || null);
      const hint = computed(() => UI.COLLECTOR_TARGETS[form.collector] || { placeholder: "target" });
      const busy = computed(() => store.running.value.length > 0);
      const actions = computed(() => !store.state.meta || store.state.meta.actions !== false);
      const opts = computed(() => form.options.split("\n").map((x) => x.trim()).filter(Boolean));
      const cli = computed(() => ["secmonk scan", form.collector, form.target && shellArg(form.target),
        ...opts.value.map((o) => `-o ${shellArg(o)}`), !form.save && "--no-save",
        +form.min_confidence !== 0.5 && `--min-confidence ${form.min_confidence}`].filter(Boolean).join(" "));
      const canRun = computed(() => actions.value && !busy.value && (hint.value.optional || form.target.trim()));
      const run = () => store.startJob({ kind: "scan", collector: form.collector, target: form.target.trim() || null,
        options: opts.value, save: form.save, min_confidence: +form.min_confidence });
      return { store, collectors, form, info, hint, busy, cli, canRun, run };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Scan a target" subtitle="Collect an inventory, save it and match it against the local mirror (secmonk scan)."/>
      <actions-off/>
      <sm-card title="Target" icon="target"><div class="sm-form">
        <sm-field label="Collector" :hint="info && info.description"><select class="sm-select" v-model="form.collector" aria-label="Collector">
          <option v-for="c in collectors.data || [{ name: form.collector }]" :key="c.name" :value="c.name">{{ c.name }}</option></select></sm-field>
        <sm-field label="Target" :hint="hint.optional ? 'optional' : 'required'"><input class="sm-input" v-model="form.target" :placeholder="hint.placeholder" @keydown.enter="canRun && run()"></sm-field>
        <sm-field label="Minimum confidence" hint="drop name-based matches below this (0–1)"><input class="sm-input" type="number" min="0" max="1" step="0.1" v-model="form.min_confidence"></sm-field>
        <sm-field label="Save"><sm-switch v-model="form.save">{{ form.save ? 'store the inventory and findings' : 'match only, write nothing' }}</sm-switch></sm-field>
        <sm-field label="Collector options" hint="one key=value per line, like -o (e.g. platform=linux/arm64, use_brew_cli=true, exclude=node_modules,dist)" wide>
          <textarea class="sm-input" v-model="form.options" rows="3" spellcheck="false"></textarea></sm-field>
        <div class="sm-form__actions"><sm-button variant="primary" icon="play" :loading="busy" :disabled="!canRun" @click="run">Run scan</sm-button>
          <span class="sm-muted">Same as</span><code>{{ cli }}</code></div>
      </div></sm-card>
      <sm-card title="Recent scans" icon="clock"><job-list kind="scan" :limit="3"/></sm-card>
    </div>`,
  };

  // ================================================================== Findings
  const FindingsView = {
    name: "FindingsView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      const f = useQueryState({ q: "", priority: "", asset: "", all: false, fixable: false, hide_minor: false, hide_deferred: false,
        kev: false, limit: "200" });
      const server = () => ({ priority: f.priority, asset: f.asset, all: f.all, fixable: f.fixable, hide_minor: f.hide_minor,
        hide_deferred: f.hide_deferred, limit: f.limit });
      const res = useResource(() => store.source.findings(server()), server);
      const assets = useResource(() => store.source.assets());
      const assetOptions = computed(() => [{ value: "", label: "All assets" }, ...(assets.data || []).map((a) => ({ value: a.id, label: a.name ? `${a.name} (${a.type})` : a.id }))]);
      const rows = computed(() => (res.data?.findings || []).filter((x) => (!f.kev || x.kev)
        && includesQ(f.q, x.vuln_id, x.component, x.version, x.asset_id, x.fixed_version, x.triage, ...(x.advisory_ids || []))));
      const selected = computed(() => (route.params.key ? (res.data?.findings || []).find((x) => fkey(x) === route.params.key) : null));
      const open = (x) => router.push({ name: "findings", params: { key: x.key }, query: route.query });
      const close = () => router.push({ name: "findings", query: route.query });
      const prioOptions = [{ value: "", label: "All" }, ...["P1", "P2", "P3", "P4"].map((p) => ({ value: p, label: p }))];
      const limits = ["200", "1000", "5000"].map((n) => ({ value: n, label: `up to ${n}` }));
      const clear = () => Object.assign(f, { q: "", priority: "", asset: "", all: false, fixable: false, hide_minor: false, hide_deferred: false, kev: false });
      return { res, f, rows, selected, open, close, prioOptions, limits, assetOptions, clear, route };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Findings" subtitle="Vulnerabilities matched on your assets, most urgent first (secmonk findings)."/>
      <div class="sm-toolbar"><sm-search v-model="f.q" placeholder="Search vulnerability, component, asset"/>
        <sm-segmented v-model="f.priority" :options="prioOptions"/>
        <select class="sm-select" v-model="f.asset" aria-label="Asset"><option v-for="o in assetOptions" :key="o.value" :value="o.value">{{ o.label }}</option></select></div>
      <div class="sm-toolbar"><sm-switch v-model="f.kev">Known exploited</sm-switch><sm-switch v-model="f.fixable">Fixable</sm-switch>
        <sm-switch v-model="f.hide_minor">Hide minor</sm-switch><sm-switch v-model="f.hide_deferred">Hide deferred</sm-switch>
        <sm-switch v-model="f.all">Include fixed</sm-switch><span class="sm-toolbar__spacer"></span>
        <span class="sm-toolbar__count" v-if="res.data">{{ rows.length }} shown</span><select class="sm-select" v-model="f.limit" aria-label="Limit"><option v-for="o in limits" :key="o.value" :value="o.value">{{ o.label }}</option></select></div>
      <data-gate :res="res" what="findings" v-slot="{ data }">
        <sm-callout v-if="data.limit_reached" variant="info" :title="'Showing the first ' + data.limit + ' findings'">
          Raise the limit or narrow the filters (priority, asset) to see the rest.</sm-callout>
        <findings-table :rows="rows" :show-status="f.all" :selected="route.params.key" @select="open">
          <template #empty><sm-empty :title="data.findings.length ? 'No finding matches the filters' : 'No open findings'" icon="check">
            <sm-button size="sm" @click="clear">Clear filters</sm-button></sm-empty></template></findings-table>
        <finding-detail v-if="selected" :finding="selected" @close="close"/>
        <sm-drawer v-else-if="route.params.key" title="Finding not in this list" @close="close">
          <sm-empty title="Not among the findings shown" icon="search">It may be fixed (turn on "Include fixed"), filtered out, or beyond the limit.</sm-empty></sm-drawer>
      </data-gate></div>`,
  };

  // ================================================================== Vulnerabilities
  const ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex", "Pub", "SwiftURL",
    "Alpine:v3.20", "Debian:12", "Ubuntu:24.04", "Rocky Linux:9", "Red Hat"];

  const VulnsView = {
    name: "VulnsView",
    setup() {
      const store = useStore();
      const router = useRouter();
      const f = useQueryState({ mode: "package", ecosystem: "", package: "", product: "", version: "" });
      const form = reactive({ id: "", ecosystem: f.ecosystem, package: f.package, product: f.product, version: f.version });
      watch(() => ({ ...f }), (v) => Object.assign(form, { ecosystem: v.ecosystem, package: v.package, product: v.product, version: v.version }));
      const searched = computed(() => (f.mode === "product" ? !!f.product : !!(f.package || f.ecosystem)));
      const params = () => (f.mode === "product" ? { product: f.product, version: f.version } : { ecosystem: f.ecosystem, package: f.package, version: f.version });
      const res = useResource(() => (searched.value ? store.source.vulnSearch(params()) : Promise.resolve(null)), () => [f.mode, params()]);
      const search = () => Object.assign(f, f.mode === "product" ? { product: form.product.trim(), version: form.version.trim(), ecosystem: "", package: "" }
        : { ecosystem: form.ecosystem.trim(), package: form.package.trim(), version: form.version.trim(), product: "" });
      const lookup = () => form.id.trim() && router.push({ name: "vuln", params: { id: form.id.trim() } });
      const example = (e) => { Object.assign(f, { product: "", ecosystem: "", package: "", version: "", ...e }); };
      const rows = computed(() => (res.data?.results || []).map((r, i) => ({ ...r, key: `${r.vuln_id}|${r.source}|${i}` })));
      const columns = [{ key: "vuln_id", label: "Vulnerability" }, { key: "where", label: "Affects" }, { key: "ranges", label: "Affected versions" },
        { key: "severity", label: "Severity" }, { key: "source", label: "Source" }];
      return { f, form, searched, res, search, lookup, example, rows, columns, ECOSYSTEMS, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Vulnerabilities" subtitle="Search the local mirror by package or product and version, or open an id (secmonk vuln search / show)."/>
      <div class="sm-grid-main">
        <sm-card title="Search affected packages" icon="search">
          <sm-segmented v-model="f.mode" :options="[{ value: 'package', label: 'Package (OSV)', icon: 'package' }, { value: 'product', label: 'Product (CVE / NVD)', icon: 'server' }]"/>
          <div class="sm-form sm-mt-3">
            <template v-if="f.mode === 'package'">
              <sm-field label="Ecosystem" hint="OSV name, release included for distros"><input class="sm-input" v-model="form.ecosystem" list="sm-ecosystems" placeholder="PyPI, npm, Debian:12…" @keydown.enter="search"></sm-field>
              <sm-field label="Package"><input class="sm-input" v-model="form.package" placeholder="e.g. django, org.apache.logging.log4j:log4j-core" @keydown.enter="search"></sm-field>
            </template>
            <sm-field v-else label="Product" hint="normalized product name, e.g. curl, openssl"><input class="sm-input" v-model="form.product" placeholder="curl" @keydown.enter="search"></sm-field>
            <sm-field label="Version" hint="optional: only advisories affecting it"><input class="sm-input" v-model="form.version" placeholder="4.2.1" @keydown.enter="search"></sm-field>
            <div class="sm-form__actions"><sm-button variant="primary" icon="search" @click="search">Search</sm-button></div>
          </div>
          <datalist id="sm-ecosystems"><option v-for="e in ECOSYSTEMS" :key="e" :value="e"></option></datalist>
        </sm-card>
        <sm-card title="Open an id" icon="shield"><div class="sm-form">
          <sm-field label="CVE, GHSA, OSV, EUVD… id" hint="aliases resolve to the canonical id" wide><input class="sm-input" v-model="form.id" placeholder="CVE-2021-44228" @keydown.enter="lookup"></sm-field>
          <div class="sm-form__actions"><sm-button icon="shield" :disabled="!form.id.trim()" @click="lookup">Open</sm-button></div></div></sm-card>
      </div>
      <template v-if="searched"><data-gate :res="res" what="results" v-slot="{ data }">
        <div class="sm-toolbar"><span class="sm-toolbar__count">{{ data.results.length }} result(s){{ data.limit_reached ? ' (limit reached)' : '' }}</span></div>
        <sm-table :columns="columns" :rows="rows" row-key="key" label="Search results" @select="r => $router.push({ name: 'vuln', params: { id: r.vuln_id } })">
          <template #cell-vuln_id="{ row }"><span class="sm-ident"><b class="sm-mono">{{ row.vuln_id }}</b><span class="sm-ident__sub" :title="row.summary">{{ row.summary }}</span></span></template>
          <template #cell-where="{ row }"><span class="sm-ident"><span class="sm-truncate">{{ row.package || row.product }}</span><span class="sm-ident__sub">{{ row.ecosystem || row.vendor }}</span></span></template>
          <template #cell-ranges="{ row }"><span class="sm-mono">{{ fmt.ranges(row.events, row.versions) }}</span></template>
          <template #cell-severity="{ row }"><sm-severity :severity="row.severity" :score="row.cvss_score"/></template>
          <template #cell-source="{ row }"><sm-badge variant="outline">{{ row.source }}</sm-badge> <span class="sm-muted">{{ row.range_type }}</span></template>
          <template #empty><sm-empty title="No advisory in the mirror" icon="check">Nothing affects this package / version in the synced sources.</sm-empty></template>
        </sm-table></data-gate></template>
      <sm-card v-else title="Examples" icon="info"><div class="sm-badges">
        <sm-button size="sm" @click="example({ mode: 'package', ecosystem: 'Maven', package: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' })">Maven log4j-core 2.14.1</sm-button>
        <sm-button size="sm" @click="example({ mode: 'package', ecosystem: 'Alpine:v3.20', package: 'xz' })">Alpine xz</sm-button>
        <sm-button size="sm" @click="example({ mode: 'product', product: 'curl', version: '8.7.1' })">product curl 8.7.1</sm-button>
        <sm-button size="sm" @click="$router.push({ name: 'vuln', params: { id: 'CVE-2021-44228' } })">CVE-2021-44228</sm-button></div></sm-card>
    </div>`,
  };

  const VulnDetailView = {
    name: "VulnDetailView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const id = computed(() => route.params.id);
      const res = useResource(() => store.source.vuln(id.value), () => id.value);
      const raw = reactive({ loading: false, data: null, error: null });
      watch(id, () => Object.assign(raw, { loading: false, data: null, error: null }));
      async function loadRaw() {
        raw.loading = true;
        try { raw.data = (await store.source.vuln(id.value, true)).raw || []; raw.error = null; }
        catch (e) { raw.error = e; } finally { raw.loading = false; }
      }
      const affected = computed(() => (res.data?.affected || []).map((a, i) => ({ ...a, key: i })));
      const refs = computed(() => [...new Set((res.data?.records || []).flatMap((r) => r.references))].map((u) => ({ u, href: fmt.safeUrl(u) })));
      const openFindings = computed(() => (res.data?.findings || []).filter((x) => x.status === "open").length);
      const affCols = [{ key: "where", label: "Package / product" }, { key: "ranges", label: "Affected versions" },
        { key: "type", label: "Type" }, { key: "source", label: "Source" }];
      return { res, id, raw, loadRaw, affected, refs, openFindings, affCols, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header :title="res.data ? res.data.id : id" :subtitle="res.data && res.data.summary ? fmt.short(res.data.summary, 200) : 'Vulnerability'">
        <sm-button variant="ghost" icon="search" @click="$router.push('/vulns')">Search</sm-button></sm-page-header>
      <data-gate :res="res" what="the vulnerability" v-slot="{ data }">
        <div class="sm-badges"><sm-severity :severity="data.severity" :score="data.cvss_score"/>
          <sm-badge v-if="data.kev" variant="kev">KEV · known exploited</sm-badge>
          <sm-badge v-if="data.epss" variant="info">EPSS {{ fmt.score(data.epss.score, 3) }}</sm-badge>
          <sm-badge v-if="openFindings" variant="danger">{{ fmt.plural(openFindings, 'open finding') }} on your assets</sm-badge>
          <span v-if="data.query !== data.id" class="sm-muted">{{ data.query }} is an alias of {{ data.id }}</span></div>
        <div class="sm-grid-main">
          <div class="sm-stack">
            <sm-card title="On your assets" icon="server" flush>
              <findings-table :rows="data.findings" compact show-status :show-vuln="false" label="Findings for this vulnerability"
                @select="x => $router.push({ name: 'findings', params: { key: x.key }, query: { all: '1' } })">
                <template #empty><sm-empty title="Not found on any scanned asset" icon="check"/></template></findings-table></sm-card>
            <sm-card title="Records by source" icon="file">
              <div v-for="r in data.records" :key="r.source + r.id" class="sm-record">
                <div class="sm-record__head"><sm-badge variant="outline">{{ r.source }}</sm-badge><b class="sm-mono">{{ r.id }}</b>
                  <sm-severity :severity="r.severity" :score="r.cvss_score"/><sm-badge v-if="r.withdrawn" variant="warn">withdrawn</sm-badge>
                  <sm-badge v-if="r.state && r.state !== 'PUBLISHED'" variant="outline">{{ r.state }}</sm-badge>
                  <span class="sm-muted" v-if="r.published">published {{ fmt.date(r.published) }}</span><span class="sm-muted" v-if="r.modified">· modified {{ fmt.date(r.modified) }}</span></div>
                <p v-if="r.summary" class="sm-prose sm-mt-0"><b>{{ r.summary }}</b></p>
                <p v-if="r.details && r.details !== r.summary" class="sm-prose sm-mt-2">{{ r.details }}</p>
                <sm-kv class="sm-mt-2" :rows="[{ label: 'CVSS vector', value: r.cvss_vector, mono: true }, { label: 'CVSS version', value: r.cvss_version },
                  { label: 'CWE', value: r.cwes.join(', ') }, { label: 'Withdrawn', value: r.withdrawn && fmt.date(r.withdrawn) }]"/>
              </div>
              <div v-if="!data.records.length" class="sm-muted">No vulnerability record (only KEV / EPSS / affected data).</div>
            </sm-card>
            <sm-card title="Affected" icon="package" flush>
              <sm-table :columns="affCols" :rows="affected" row-key="key" static label="Affected packages and products">
                <template #cell-where="{ row }"><span class="sm-ident"><span class="sm-truncate"><b>{{ row.package || row.product }}</b></span><span class="sm-ident__sub">{{ row.ecosystem || row.vendor }}</span></span></template>
                <template #cell-ranges="{ row }"><span class="sm-mono">{{ fmt.ranges(row.events, row.versions) || '—' }}</span>
                  <sm-badge v-if="row.status !== 'affected'" variant="outline" class="sm-ml-2">{{ row.status }}</sm-badge></template>
                <template #cell-type="{ row }"><span class="sm-muted">{{ row.range_type }}</span></template>
                <template #cell-source="{ row }"><sm-badge variant="outline">{{ row.source }}</sm-badge></template>
                <template #empty><sm-empty title="No affected ranges in the mirror" icon="package"/></template></sm-table>
              <sm-callout v-if="data.affected_limit_reached" variant="info" class="sm-mt-2">Only the first 200 affected entries are shown.</sm-callout>
            </sm-card>
            <sm-card title="Raw records" icon="file">
              <template #actions><sm-button size="sm" :loading="raw.loading" @click="loadRaw" v-if="!raw.data">Load</sm-button></template>
              <div v-if="raw.error" class="sm-muted">{{ raw.error.message }}</div>
              <template v-else-if="raw.data"><div v-for="(r, i) in raw.data" :key="i"><div class="sm-muted">{{ r.source }}</div><pre class="sm-pre">{{ JSON.stringify(r.data, null, 2) }}</pre></div>
                <div v-if="!raw.data.length" class="sm-muted">No raw record stored.</div></template>
              <div v-else class="sm-muted">The records exactly as each source published them (secmonk vuln show --raw).</div>
            </sm-card>
          </div>
          <div class="sm-stack">
            <sm-card title="Exploitation" icon="alert"><sm-kv :rows="[
                { label: 'CISA KEV', value: data.kev ? 'listed — known exploited' : 'not listed' },
                { label: 'KEV name', value: data.kev && data.kev.name }, { label: 'Added', value: data.kev && data.kev.date_added },
                { label: 'Due date', value: data.kev && data.kev.due_date }, { label: 'Ransomware', value: data.kev && data.kev.ransomware },
                { label: 'EPSS', value: data.epss ? fmt.score(data.epss.score, 4) : 'no score' },
                { label: 'Percentile', value: data.epss && fmt.pct(data.epss.percentile) }, { label: 'Scored on', value: data.epss && data.epss.date }]"/></sm-card>
            <sm-card v-if="data.aliases.length" title="Aliases" icon="link">
              <sm-chain :items="data.aliases.map(a => ({ key: a, label: a }))" @pick="a => $router.push({ name: 'vuln', params: { id: a } })"/></sm-card>
            <sm-card v-if="refs.length" title="References" icon="external"><ul class="sm-links">
              <li v-for="r in refs" :key="r.u"><a v-if="r.href" :href="r.href" target="_blank" rel="noopener noreferrer">{{ r.u }}</a><span v-else class="sm-mono">{{ r.u }}</span></li></ul></sm-card>
          </div>
        </div>
      </data-gate></div>`,
  };

  // ================================================================== Sources & sync
  const SourcesView = {
    name: "SourcesView",
    setup() {
      const store = useStore();
      const res = useResource(() => store.source.sources());
      const form = reactive({ sources: [], ecosystems: "", since: "", full: false, limit: "", path: "" });
      const worst = (xs) => (xs.includes("error") ? "error" : xs.includes("partial") ? "partial" : xs.length ? "ok" : null);
      const rows = computed(() => {
        const st = res.data?.status?.sources || [];
        return (res.data?.registry || []).map((r) => {
          const main = st.find((s) => s.source === r.name);
          const subs = st.filter((s) => s.source.startsWith(r.name + ":"));
          // OSV keeps one row per ecosystem (osv:PyPI…); other sub-rows are internal cursors
          const eco = r.name === "osv" ? subs : [];
          const agg = main || (subs.length ? { last_sync: subs.map((s) => s.last_sync).filter(Boolean).sort().pop() || null,
            records: subs.reduce((a, s) => a + (s.records || 0), 0), status: worst(subs.map((s) => s.status)), message: null } : {});
          return { ...r, last_sync: agg.last_sync || null, records: agg.records ?? null, status: agg.status || null,
            message: agg.message || null, ecosystems: eco.map((s) => ({ name: s.source.slice(4), records: s.records, status: s.status })) };
        });
      });
      const options = computed(() => [{ value: "all", label: "all" }, ...(res.data?.registry || []).map((r) => ({ value: r.name, label: r.name }))]);
      const toggle = (r) => { const s = new Set(form.sources); s.has(r.name) ? s.delete(r.name) : s.add(r.name); form.sources = [...s]; };
      const wantsEco = computed(() => form.sources.includes("osv") || form.sources.includes("all"));
      const busy = computed(() => store.running.value.length > 0);
      const actions = computed(() => !store.state.meta || store.state.meta.actions !== false);
      const list = (v) => v.split(/[\s,]+/).filter(Boolean);
      const cli = computed(() => ["secmonk sync", ...(form.sources.length ? form.sources : ["<source>"]),
        ...list(form.ecosystems).map((e) => `-e ${shellArg(e)}`), form.since && `--since ${shellArg(form.since)}`, form.full && "--full",
        form.limit && `-n ${form.limit}`, form.path && `--path ${shellArg(form.path)}`].filter(Boolean).join(" "));
      const run = () => store.startJob({ kind: "sync", sources: form.sources, ecosystems: list(form.ecosystems), since: form.since.trim() || null,
        full: form.full, limit: form.limit ? +form.limit : null, path: form.path.trim() || null });
      const columns = [{ key: "name", label: "Source" }, { key: "last_sync", label: "Last sync" }, { key: "records", label: "Records", cls: "is-num" },
        { key: "status", label: "Status" }, { key: "message", label: "Message" }];
      const TABLES = { vulnerability: "Vulnerability records", affected: "Affected ranges", kev: "KEV entries",
        epss: "EPSS scores", asset: "Assets", component: "Components", finding: "Findings" };
      return { res, form, rows, options, toggle, wantsEco, busy, actions, cli, run, columns, TABLES, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Sources &amp; sync" subtitle="What the local vulnerability mirror holds, how fresh each source is, and syncing it (secmonk status / sync)."/>
      <data-gate :res="res" what="sources" v-slot="{ data }">
        <sm-callout v-if="!data.db.exists" variant="info" title="No database yet">The first sync creates it at <code>{{ data.db.path }}</code>.
          A good start: <b>kev</b>, <b>epss</b> and <b>osv</b> with the ecosystems you use.</sm-callout>
        <div v-else class="sm-stats"><sm-stat v-for="(label, t) in TABLES" :key="t" :label="label" :value="fmt.num(data.status.tables[t])"/></div>
        <sm-table :columns="columns" :rows="rows" row-key="name" :row-class="r => form.sources.includes(r.name) ? 'is-selected' : ''" label="Sources" @select="toggle">
          <template #cell-name="{ row }"><span class="sm-ident"><b>{{ row.name }}</b><span class="sm-ident__sub" :title="row.description">{{ row.description }}</span>
            <span v-if="row.ecosystems.length" class="sm-badges sm-mt-1"><span v-for="e in row.ecosystems" :key="e.name" class="sm-badge sm-badge--outline">{{ e.name }} {{ fmt.num(e.records) }}</span></span></span></template>
          <template #cell-last_sync="{ row }"><span :class="fmt.ageDays(row.last_sync) > 7 && 'sm-is-stale'" :title="row.last_sync">{{ row.last_sync ? fmt.ago(row.last_sync) : 'never' }}</span></template>
          <template #cell-records="{ row }">{{ fmt.num(row.records) }}</template>
          <template #cell-status="{ row }"><sm-badge v-if="row.status" :variant="row.status === 'ok' ? 'ok' : row.status === 'partial' ? 'warn' : 'danger'">{{ row.status }}</sm-badge>
            <sm-badge v-if="!row.in_all" variant="outline" title="Not included in 'sync all'">manual</sm-badge></template>
          <template #cell-message="{ row }"><span class="sm-truncate sm-cell-path" :title="row.message">{{ row.message }}</span></template>
        </sm-table>
        <actions-off/>
        <sm-card title="Sync" icon="database"><div class="sm-form">
          <sm-field label="Sources" hint="click rows above or chips; 'all' = every source marked for sync all, in the recommended order" wide>
            <sm-chips v-model="form.sources" :options="options"/></sm-field>
          <sm-field v-if="wantsEco" label="OSV ecosystems" hint="comma separated; empty = every ecosystem (large)"><input class="sm-input" v-model="form.ecosystems" placeholder="PyPI, npm, Go, Debian:12"></sm-field>
          <sm-field label="Since" hint="only records modified since (ISO date or year)"><input class="sm-input" v-model="form.since" placeholder="2024-01-01"></sm-field>
          <sm-field label="Limit" hint="max records (debug)"><input class="sm-input" type="number" min="1" v-model="form.limit"></sm-field>
          <sm-field label="Import from a local file" hint="offline: a downloaded bulk file or directory on the server machine"><input class="sm-input" v-model="form.path" placeholder="/path/to/all.zip"></sm-field>
          <sm-field label="Full"><sm-switch v-model="form.full">ignore the stored delta cursor</sm-switch></sm-field>
          <div class="sm-form__actions"><sm-button variant="primary" icon="refresh" :loading="busy" :disabled="!actions || busy || !form.sources.length" @click="run">Run sync</sm-button>
            <span class="sm-muted">Same as</span><code>{{ cli }}</code></div>
        </div></sm-card>
        <sm-card title="Recent syncs" icon="clock"><job-list kind="sync" :limit="3"/></sm-card>
      </data-gate></div>`,
  };

  // ================================================================== Jobs, About
  const JobsView = {
    name: "JobsView",
    setup() {
      const store = useStore();
      const route = useRoute();
      const router = useRouter();
      onMounted(() => store.loadJobs());
      const detail = useResource(() => (route.params.id ? store.source.job(route.params.id) : Promise.resolve(null)), () => route.params.id);
      const selected = computed(() => {
        if (!route.params.id) return null;
        const l = store.state.jobs.list.find((j) => String(j.id) === String(route.params.id));
        return l && l.log ? l : detail.data || l || null;
      });
      const columns = [{ key: "id", label: "#", cls: "is-num", width: "48px" }, { key: "status", label: "Status" }, { key: "title", label: "Job" },
        { key: "started", label: "Started" }, { key: "finished", label: "Finished" }];
      const close = () => router.push("/jobs");
      return { store, selected, detail, columns, close, route, JOB_STATUS: UI.JOB_STATUS, fmt };
    },
    template: `<div class="sm-page">
      <sm-page-header title="Jobs" subtitle="Scans and syncs started from this interface since the server started (one at a time).">
        <sm-button icon="refresh" @click="store.loadJobs()">Refresh</sm-button></sm-page-header>
      <sm-table :columns="columns" :rows="store.state.jobs.list" row-key="id" :selected="selected && selected.id" label="Jobs" @select="j => $router.push('/jobs/' + j.id)">
        <template #cell-status="{ row }"><sm-badge :variant="(JOB_STATUS[row.status] || {}).variant || 'outline'">{{ (JOB_STATUS[row.status] || {}).label || row.status }}</sm-badge></template>
        <template #cell-title="{ row }"><b>{{ row.title }}</b><div v-if="row.error" class="sm-muted sm-truncate">{{ row.error }}</div></template>
        <template #cell-started="{ row }">{{ fmt.datetime(row.started) }}</template>
        <template #cell-finished="{ row }">{{ fmt.time(row.finished) }}</template>
        <template #empty><sm-empty title="No jobs yet" icon="clock"><div>Start a scan or a sync: it runs in the background and shows up here.</div>
          <div class="sm-badges sm-mt-2"><sm-button size="sm" icon="target" @click="$router.push('/scan')">Scan</sm-button>
            <sm-button size="sm" icon="database" @click="$router.push('/sources')">Sync</sm-button></div></sm-empty></template>
      </sm-table>
      <sm-drawer v-if="selected" :title="selected.title" :subtitle="'job #' + selected.id + ' · ' + selected.kind" @close="close">
        <sm-job :job="selected"><job-result v-if="selected.result" :job="selected"/></sm-job></sm-drawer>
      <sm-drawer v-else-if="route.params.id && detail.error" title="Job not found" @close="close"><sm-empty :title="detail.error.message" icon="clock"/></sm-drawer>
    </div>`,
  };

  const AboutView = {
    name: "AboutView",
    setup() { return { store: useStore() }; },
    template: `<div class="sm-page"><sm-page-header title="About" subtitle="sec-monk local interface"/>
      <div class="sm-grid-2"><sm-card title="This server" icon="server"><sm-kv v-if="store.state.meta" :rows="[
          { label: 'Version', value: store.state.meta.version }, { label: 'Data source', value: store.state.source === 'mock' ? 'mock data (design)' : 'local API' },
          { label: 'Mode', value: store.state.meta.mode }, { label: 'Platform', value: store.state.meta.platform },
          { label: 'Database', value: store.state.meta.db.path, copy: true }, { label: 'Database present', value: store.state.meta.db.exists ? 'yes' : 'no' },
          { label: 'Scans and syncs', value: store.state.meta.actions === false ? 'disabled (non-loopback address; --allow-actions)' : 'enabled' },
          { label: 'Listening on', value: store.state.meta.bind, mono: true }]"/><sm-spinner v-else/></sm-card>
        <sm-card title="Documentation" icon="file"><sm-kv :rows="[
          { label: 'Feature', value: '_docs/features/web-ui.md', mono: true }, { label: 'Technical', value: '_docs/tech/web-ui.md', mono: true },
          { label: 'Commands', value: '_docs/features/README.md', mono: true }, { label: 'Findings', value: '_docs/features/scan-and-findings.md', mono: true },
          { label: 'Process monitor', value: '_docs/features/process-monitor.md', mono: true },
          { label: 'Design system', value: '_design/README.md', mono: true }, { label: 'Storybook', value: '_design/storybook/index.html', mono: true }]"/></sm-card></div></div>`,
  };

  // ================================================================== shell + router
  const ROUTES = [
    { path: "/", redirect: "/overview" },
    { path: "/overview", name: "overview", component: OverviewView, meta: { nav: "overview", group: "Overview", title: "Dashboard" } },
    { path: "/processes/:pid?", name: "processes", component: ProcessesView, meta: { nav: "processes", group: "Monitor", title: "Processes" } },
    { path: "/software/:key?", name: "software", component: SoftwareView, meta: { nav: "software", group: "Monitor", title: "Software" } },
    { path: "/launch-items/:key?", name: "launch-items", component: LaunchItemsView, meta: { nav: "launch-items", group: "Monitor", title: "Launch items" } },
    { path: "/activity/:id?", name: "activity", component: ActivityView, meta: { nav: "activity", group: "Monitor", title: "Activity" } },
    { path: "/assets", name: "assets", component: AssetsView, meta: { nav: "assets", group: "Inventory", title: "Assets" } },
    { path: "/assets/:id", name: "asset", component: AssetDetailView, meta: { nav: "assets", group: "Inventory", title: "Assets", crumb: "id" } },
    { path: "/scan", name: "scan", component: ScanView, meta: { nav: "scan", group: "Inventory", title: "Scan" } },
    { path: "/unmatched", name: "unmatched", component: UnmatchedView, meta: { nav: "unmatched", group: "Inventory", title: "Unmatched" } },
    { path: "/findings/:key?", name: "findings", component: FindingsView, meta: { nav: "findings", group: "Risk", title: "Findings" } },
    { path: "/vulns", name: "vulns", component: VulnsView, meta: { nav: "vulns", group: "Data", title: "Vulnerabilities" } },
    { path: "/vulns/:id", name: "vuln", component: VulnDetailView, meta: { nav: "vulns", group: "Data", title: "Vulnerabilities", crumb: "id" } },
    { path: "/sources", name: "sources", component: SourcesView, meta: { nav: "sources", group: "Data", title: "Sources & sync" } },
    { path: "/jobs/:id?", name: "jobs", component: JobsView, meta: { nav: "jobs", group: "System", title: "Jobs" } },
    { path: "/about", name: "about", component: AboutView, meta: { nav: "about", group: "System", title: "About" } },
    { path: "/:pathMatch(.*)*", redirect: "/overview" },
  ];

  const App = {
    name: "SecMonkApp",
    props: { design: Boolean },
    setup() {
      const store = useStore();
      const route = useRoute();
      const nav = computed(() => NAV.map((g) => ({ ...g, items: g.items.map((i) => (
        i.id === "activity" ? { ...i, count: store.state.watch.unseen } : i.id === "jobs" ? { ...i, count: store.running.value.length } : i)) })));
      const s = computed(() => store.state.snap);
      const monitor = computed(() => route.meta.group === "Monitor");
      const crumb = computed(() => (route.meta.crumb ? route.params[route.meta.crumb] : null));
      return { store, route, nav, s, monitor, crumb };
    },
    template: `<div class="sm-shell">
      <div class="sm-brand"><span class="sm-brand__mark">◆</span><span class="sm-brand__text">sec-monk <span class="sm-brand__sub">local</span></span></div>
      <header class="sm-topbar"><div class="sm-topbar__crumbs"><span>{{ route.meta.group }}</span><span>/</span><b>{{ route.meta.title }}</b>
          <template v-if="crumb"><span>/</span><span class="sm-mono sm-truncate" :title="crumb">{{ crumb }}</span></template></div>
        <span class="sm-topbar__spacer"></span>
        <div class="sm-topbar__context" v-if="monitor && s"><span>{{ s.host }}</span><span class="sm-muted">·</span>
          <span>{{ (s.os && s.os.name) || s.platform }} {{ s.os && s.os.version }}</span><span class="sm-muted">·</span>
          <span :title="s.taken_at">{{ $fmt.time(s.taken_at) }}</span>
          <sm-badge :variant="s.source === 'live' ? 'info' : 'outline'" :title="s.source === 'live' ? 'Live snapshot of this machine' : 'Analysed from a snapshot file'">{{ s.source }}</sm-badge>
          <sm-badge :variant="s.matched ? 'ok' : 'warn'" :title="s.matched ? 'Matched against the local vulnerability mirror' : 'No vulnerability database'">{{ s.matched ? 'DB matched' : 'no DB' }}</sm-badge></div>
        <div class="sm-topbar__context" v-else-if="store.state.meta"><sm-badge :variant="store.state.meta.db.exists ? 'ok' : 'warn'" :title="store.state.meta.db.path">{{ store.state.meta.db.exists ? 'DB' : 'no DB' }}</sm-badge></div>
        <a v-if="store.running.value.length" href="#/jobs" class="sm-badge sm-badge--live" title="A job is running">{{ store.running.value[0].title }}</a>
        <span v-if="store.state.watch.on" class="sm-badge sm-badge--live" title="Watch running">watching · {{ store.state.watch.interval }} s</span>
        <sm-theme-toggle/></header>
      <aside class="sm-sidebar"><sm-nav :groups="nav" :active="route.meta.nav"/></aside>
      <main class="sm-main"><router-view/></main>
      <sm-toasts/><div v-if="design" class="sm-design-ribbon">DESIGN SAMPLE · MOCK DATA</div></div>`,
  };

  /**
   * Mount the application. opts.source: ApiSource() | MockSource(data); opts.initialRoute: e.g. "/processes/300";
   * opts.design: show the design ribbon. Returns {app, router, store}.
   */
  function mountApp(el, opts = {}) {
    const source = opts.source || ApiSource();
    const store = createStore(source);
    // set the start route before the router reads the URL (a replace() before mount loses to the initial navigation)
    if (opts.initialRoute && (!location.hash || location.hash === "#/" || location.hash === "#")) {
      history.replaceState(history.state, "", "#" + opts.initialRoute);
    }
    const router = createRouter({ history: createWebHashHistory(), routes: ROUTES });
    const app = createApp(App, { design: !!opts.design });
    UI.install(app);
    app.provide("store", store);
    for (const [n, c] of Object.entries({ SnapshotGate, MonitorActions, SnapshotNotes, ProcessDetail, NoDb, DataGate,
      FindingsTable, FindingDetail, JobResult, JobList, ActionsOff })) app.component(n, c);
    app.use(router);
    app.mount(el);
    store.loadMeta();
    store.loadJobs();
    return { app, router, store };
  }

  Object.assign(UI, { ApiSource, MockSource, ApiError, createStore, mountApp, NAV, ROUTES, useResource, fkey,
    VIEWS: { OverviewView, ProcessesView, SoftwareView, LaunchItemsView, ActivityView, AssetsView, AssetDetailView, ScanView,
      UnmatchedView, FindingsView, VulnsView, VulnDetailView, SourcesView, JobsView, AboutView, ProcessDetail, FindingDetail,
      FindingsTable, JobResult, DataGate, App } });
})(window);
