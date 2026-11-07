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
    constructor(message, status, hint) { super(message); this.status = status; this.hint = hint; }
  }

  /** Talks to `secmonk ui` (src/secmonk/web/server.py). */
  function ApiSource(base = "") {
    async function call(path, opts = {}) {
      const res = await fetch(base + path, { headers: { Accept: "application/json", ...(opts.headers || {}) }, ...opts });
      let body = null;
      try { body = await res.json(); } catch (e) { /* non-JSON error page */ }
      if (!res.ok) throw new ApiError((body && body.error) || `HTTP ${res.status}`, res.status, body && body.hint);
      return body;
    }
    const post = (path) => call(path, { method: "POST", headers: { "X-SecMonk-Request": "1" } });
    return {
      kind: "api",
      meta: () => call("/api/meta"),
      processes: (refresh) => call("/api/processes" + (refresh ? "?refresh=1" : "")),
      watch: () => call("/api/processes/watch"),
      save: () => post("/api/processes/save"),
    };
  }

  /** Serves the fixture-derived mock (scripts/design_mock.py -> _design/mock/data.js). */
  function MockSource(data, { latency = 250 } = {}) {
    const wait = (v) => new Promise((r) => setTimeout(() => r(JSON.parse(JSON.stringify(v))), latency));
    let tick = 0;
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
    };
  }

  // ================================================================== store
  function createStore(source) {
    const state = reactive({
      source: source.kind, meta: null, snap: null, loading: false, saving: false, error: null,
      stale: 0,                                              // events seen since the snapshot was loaded
      watch: { on: false, interval: 10, last: null, events: [], unseen: 0, busy: false, error: null },
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
    return { state, loadMeta, refresh, save, startWatch, stopWatch, setInterval: setInterval_, byPid };
  }

  // ================================================================== navigation (all phases)
  const NAV = [
    { label: "Overview", items: [{ id: "overview", label: "Dashboard", icon: "grid", to: "/overview", planned: true }] },
    { label: "Monitor", items: [
      { id: "processes", label: "Processes", icon: "cpu", to: "/processes" },
      { id: "software", label: "Software", icon: "package", to: "/software" },
      { id: "launch-items", label: "Launch items", icon: "rocket", to: "/launch-items" },
      { id: "activity", label: "Activity", icon: "activity", to: "/activity" },
    ] },
    { label: "Inventory", items: [{ id: "assets", label: "Assets", icon: "server", to: "/assets", planned: true }] },
    { label: "Risk", items: [{ id: "findings", label: "Findings", icon: "alert", to: "/findings", planned: true }] },
    { label: "Data", items: [
      { id: "vulns", label: "Vulnerabilities", icon: "shield", to: "/vulns", planned: true },
      { id: "sources", label: "Sources & sync", icon: "database", to: "/sources", planned: true },
    ] },
    { label: "System", items: [{ id: "about", label: "About", icon: "info", to: "/about" }] },
  ];

  const PLANNED = {
    overview: { title: "Dashboard", text: "Open findings by priority across all assets, KEV hits, newest findings and the freshness of the vulnerability mirror.",
      cli: "secmonk status\nsecmonk findings --priority P1" },
    assets: { title: "Assets", text: "Every scanned target (this Mac, Homebrew, images, containers, SSH hosts, Windows, repositories) with its components, scans and partial-scan state; start a scan.",
      cli: "secmonk inventory assets\nsecmonk inventory show <asset-id>\nsecmonk scan <collector> [target]" },
    findings: { title: "Findings", text: "Findings across assets with the CLI filters (priority, fixable, hide minor / deferred), finding detail with sources and distro triage, suppression.",
      cli: "secmonk findings --priority P2 --fixable --hide-minor" },
    vulns: { title: "Vulnerabilities", text: "Search the local mirror by package or product and version; one page per CVE / GHSA / OSV id with every source's facts.",
      cli: "secmonk vuln search --ecosystem PyPI --package django --version 4.2.1\nsecmonk vuln show CVE-2024-3094" },
    sources: { title: "Sources & sync", text: "Freshness and size of each vulnerability source; run a sync.",
      cli: "secmonk status\nsecmonk sync kev epss osv -e PyPI" },
  };

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
    setup() { return { store: useStore() }; },
    template: `<div v-if="!store.state.snap">
      <div v-if="store.state.loading" class="sm-empty"><sm-spinner large/><div class="sm-empty__title">Taking a process snapshot…</div>
        <div class="sm-muted">Reading processes, launch items and identities; matching against the local mirror.</div></div>
      <sm-callout v-else-if="store.state.error" variant="error" :title="store.state.error.message">
        <div v-if="store.state.error.hint">{{ store.state.error.hint }}</div>
        <div style="margin-top:8px"><sm-button size="sm" icon="refresh" @click="store.refresh()">Try again</sm-button></div></sm-callout>
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
        <div style="margin-bottom:8px"><sm-launch-badge :kind="row.launch"/></div>
        <sm-kv :rows="[
          { label: 'Mechanism', value: row.mechanism },
          { label: 'Job label', value: row.label, mono: true },
          { label: 'Configured in', value: row.launch_source, copy: true },
          { label: 'Explained by', value: row.via, mono: true },
          { label: 'Evidence', value: row.evidence },
          { label: 'Parent', value: row.parent_exe || (store.byPid.value.get(row.ppid) || {}).exe, mono: true },
        ]"/>
        <div v-if="chain.length > 1" style="margin-top:10px"><div class="sm-muted" style="margin-bottom:4px">Ancestry</div>
          <sm-chain :items="chain" @pick="$emit('open', $event)"/></div>
        <div v-if="children.length" style="margin-top:10px"><div class="sm-muted" style="margin-bottom:4px">Children ({{ children.length }})</div>
          <sm-chain :items="children.slice(0, 20).map(c => ({ key: c.pid, label: c.process + ' (' + c.pid + ')' }))" @pick="$emit('open', $event)"/></div>
      </sm-section>

      <sm-section title="Identity" icon="package">
        <sm-kv :rows="[
          { label: 'Software', value: row.identity || 'not identified' },
          { label: 'Category', value: row.category },
          { label: 'Method', value: row.identity_method && (row.identity_method + ' — ' + (METHODS[row.identity_method] || '')) },
        ]"/>
        <table v-if="components.length > 1" class="sm-table sm-table--static" style="margin-top:10px">
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
          <sm-section title="Executables" icon="file"><div v-for="e in selected.executables" :key="e" style="margin-bottom:4px"><sm-copy :value="e"/></div></sm-section>
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
      const list = computed(() => (store.state.snap?.launch_items || []).map((it, i) => ({ ...it, key: `${i}:${it.label}` })));
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
          <template #cell-program="{ row }"><span class="sm-mono sm-truncate" style="display:inline-block;max-width:380px" :title="row.program">{{ row.program }}</span>
            <sm-badge v-if="row.missing_program" variant="danger" style="margin-left:6px">missing</sm-badge></template>
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

  // ================================================================== Planned, About
  const PlannedView = {
    name: "PlannedView",
    setup() { const route = useRoute(); return { p: computed(() => PLANNED[route.meta.nav] || {}) }; },
    template: `<div class="sm-page"><sm-page-header :title="p.title" subtitle="Planned for a later phase."/>
      <div class="sm-placeholder"><sm-card title="What this view will show" icon="info"><p style="margin-top:0">{{ p.text }}</p>
        <div class="sm-muted">Available today from the command line:</div><pre>{{ p.cli }}</pre>
        <div class="sm-muted">See <code>_docs/features/README.md</code> for every command.</div></sm-card></div></div>`,
  };

  const AboutView = {
    name: "AboutView",
    setup() { return { store: useStore() }; },
    template: `<div class="sm-page"><sm-page-header title="About" subtitle="sec-monk local interface"/>
      <div class="sm-grid-2"><sm-card title="This server" icon="server"><sm-kv v-if="store.state.meta" :rows="[
          { label: 'Version', value: store.state.meta.version }, { label: 'Data source', value: store.state.source === 'mock' ? 'mock data (design)' : 'local API' },
          { label: 'Mode', value: store.state.meta.mode }, { label: 'Platform', value: store.state.meta.platform },
          { label: 'Database', value: store.state.meta.db.path, copy: true }, { label: 'Database present', value: store.state.meta.db.exists ? 'yes' : 'no' },
          { label: 'Listening on', value: store.state.meta.bind, mono: true }]"/><sm-spinner v-else/></sm-card>
        <sm-card title="Documentation" icon="file"><sm-kv :rows="[
          { label: 'Feature', value: '_docs/features/web-ui.md', mono: true }, { label: 'Technical', value: '_docs/tech/web-ui.md', mono: true },
          { label: 'Design system', value: '_design/README.md', mono: true }, { label: 'Storybook', value: '_design/storybook/index.html', mono: true },
          { label: 'Process monitor', value: '_docs/features/process-monitor.md', mono: true }]"/></sm-card></div></div>`,
  };

  // ================================================================== shell + router
  const ROUTES = [
    { path: "/", redirect: "/processes" },
    { path: "/processes/:pid?", name: "processes", component: ProcessesView, meta: { nav: "processes", group: "Monitor", title: "Processes" } },
    { path: "/software/:key?", name: "software", component: SoftwareView, meta: { nav: "software", group: "Monitor", title: "Software" } },
    { path: "/launch-items/:key?", name: "launch-items", component: LaunchItemsView, meta: { nav: "launch-items", group: "Monitor", title: "Launch items" } },
    { path: "/activity/:id?", name: "activity", component: ActivityView, meta: { nav: "activity", group: "Monitor", title: "Activity" } },
    ...Object.keys(PLANNED).map((id) => ({ path: `/${id}`, name: id, component: PlannedView,
      meta: { nav: id, group: NAV.find((g) => g.items.some((i) => i.id === id)).label, title: PLANNED[id].title } })),
    { path: "/about", name: "about", component: AboutView, meta: { nav: "about", group: "System", title: "About" } },
    { path: "/:pathMatch(.*)*", redirect: "/processes" },
  ];

  const App = {
    name: "SecMonkApp",
    props: { design: Boolean },
    setup() {
      const store = useStore();
      const route = useRoute();
      const nav = computed(() => NAV.map((g) => ({ ...g, items: g.items.map((i) => (i.id === "activity" ? { ...i, count: store.state.watch.unseen } : i)) })));
      const s = computed(() => store.state.snap);
      return { store, route, nav, s };
    },
    template: `<div class="sm-shell">
      <div class="sm-brand"><span class="sm-brand__mark">◆</span><span class="sm-brand__text">sec-monk <span class="sm-brand__sub">local</span></span></div>
      <header class="sm-topbar"><div class="sm-topbar__crumbs"><span>{{ route.meta.group }}</span><span>/</span><b>{{ route.meta.title }}</b></div>
        <span class="sm-topbar__spacer"></span>
        <div class="sm-topbar__context" v-if="s"><span>{{ s.host }}</span><span class="sm-muted">·</span>
          <span>{{ (s.os && s.os.name) || s.platform }} {{ s.os && s.os.version }}</span><span class="sm-muted">·</span>
          <span :title="s.taken_at">{{ $fmt.time(s.taken_at) }}</span>
          <sm-badge :variant="s.source === 'live' ? 'info' : 'outline'" :title="s.source === 'live' ? 'Live snapshot of this machine' : 'Analysed from a snapshot file'">{{ s.source }}</sm-badge>
          <sm-badge :variant="s.matched ? 'ok' : 'warn'" :title="s.matched ? 'Matched against the local vulnerability mirror' : 'No vulnerability database'">{{ s.matched ? 'DB matched' : 'no DB' }}</sm-badge></div>
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
    for (const [n, c] of Object.entries({ SnapshotGate, MonitorActions, SnapshotNotes, ProcessDetail })) app.component(n, c);
    app.use(router);
    app.mount(el);
    store.loadMeta();
    store.refresh(false);
    return { app, router, store };
  }

  Object.assign(UI, { ApiSource, MockSource, createStore, mountApp, NAV, PLANNED, ROUTES,
    VIEWS: { ProcessesView, SoftwareView, LaunchItemsView, ActivityView, PlannedView, AboutView, ProcessDetail, App } });
})(window);
