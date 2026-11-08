/* Stories: one entry per shared component (src/secmonk/web/static/js/secmonk-ui.js) and per view-level pattern
 * (secmonk-views.js). Each variant is a real Vue template rendered with the shared components; the template text is
 * shown as the usage snippet. Rule: a new component in secmonk-ui.js gets a story here (see _design/README.md). */
(function (global) {
  "use strict";
  const M = global.SECMONK_MOCK;
  const proc = (pid) => M.snapshot.processes.find((p) => p.pid === pid);
  const sampleFindings = [
    { vuln_id: "CVE-2021-44228", priority: "P1", kev: true, cvss_score: 10, fixed_version: "2.15.0", component: "log4j-core" },
    { vuln_id: "CVE-2024-6197", priority: "P2", kev: false, cvss_score: 7.5, fixed_version: "8.9.0", component: "curl" },
    { vuln_id: "GO-2022-1059", priority: "P3", kev: false, cvss_score: 7.5, fixed_version: "0.3.8", component: "golang.org/x/text" },
    { vuln_id: "CVE-2024-7264", priority: "P4", kev: false, cvss_score: 6.5, fixed_version: "8.9.1", component: "curl" },
  ];
  const tableRows = M.snapshot.processes.slice(9, 15);
  const finding = (vid) => M.findings.find((f) => f.vuln_id === vid);
  const scanJob = M.jobs.find((j) => j.kind === "scan");
  const syncJob = M.jobs.find((j) => j.kind === "sync");

  global.SECMONK_STORIES = [
    // ------------------------------------------------------------------ foundations
    { id: "colors", group: "Foundations", title: "Colors & tokens",
      doc: "CSS custom properties on :root (light) redefined for dark mode. Components use tokens only, never raw colors.",
      variants: [{ name: "Palette", template: `<div class="sb-swatches"><div v-for="t in tokens" :key="t" class="sb-swatch">
        <span class="sb-swatch__chip" :style="{ background: 'var(' + t + ')' }"></span><code>{{ t }}</code></div></div>`,
        data: { tokens: ["--sm-bg", "--sm-surface", "--sm-surface-2", "--sm-border", "--sm-text", "--sm-text-2", "--sm-text-3",
          "--sm-accent", "--sm-accent-soft", "--sm-sidebar", "--sm-p1", "--sm-p2", "--sm-p3", "--sm-p4", "--sm-kev", "--sm-ok",
          "--sm-warn", "--sm-danger", "--sm-info", "--sm-k-service", "--sm-k-agent", "--sm-k-gui", "--sm-k-interactive",
          "--sm-k-remote", "--sm-k-child"] } }] },
    { id: "type", group: "Foundations", title: "Typography",
      doc: "System UI font, 14 px base; monospace for paths, ids, hashes and versions.",
      variants: [{ name: "Scale", template: `<div style="display:grid;gap:8px">
        <div class="sm-page-header__title">Page title 20/650</div><div style="font-size:16px;font-weight:650">Drawer title 16/650</div>
        <div>Body 14 — what is running, how it was started.</div><div class="sm-muted" style="font-size:12.5px">Secondary 12.5 muted</div>
        <div class="sm-section__title">Section title</div><div><span class="sm-mono">/opt/homebrew/Cellar/curl/8.7.1/bin/curl</span> mono</div>
        <div>Keyboard: <kbd>/</kbd> search, <kbd>Esc</kbd> close</div></div>` }] },
    { id: "icons", group: "Foundations", title: "Icons (sm-icon)",
      doc: "Inline stroke icons (Feather style), currentColor. <sm-icon name size='lg'>. Names are fixed constants in secmonk-ui.js.",
      variants: [{ name: "All icons", template: `<div class="sb-icons"><div v-for="n in names" :key="n" class="sb-icon"><sm-icon :name="n" size="lg"/><code>{{ n }}</code></div></div>`,
        data: { names: Object.keys(global.SecMonkUI.ICONS) } }] },

    // ------------------------------------------------------------------ actions
    { id: "button", group: "Actions", title: "Button (sm-button)",
      doc: "Props: variant (primary | ghost | danger), size (sm), icon, icon-only (+ title as label), loading, disabled, active.",
      variants: [
        { name: "Variants", template: `<sm-button>Default</sm-button> <sm-button variant="primary" icon="eye">Watch</sm-button>
<sm-button variant="ghost">Ghost</sm-button> <sm-button variant="danger">Delete</sm-button>` },
        { name: "States", template: `<sm-button loading>Refresh</sm-button> <sm-button disabled icon="save">Save</sm-button>
<sm-button active icon="pause">Watching</sm-button>` },
        { name: "Sizes & icon-only", template: `<sm-button size="sm">Small</sm-button> <sm-button icon-only icon="refresh" title="Refresh"/>
<sm-button size="sm" icon-only icon="x" title="Close"/>` },
      ] },
    { id: "theme", group: "Actions", title: "Theme toggle (sm-theme-toggle)",
      doc: "Cycles system → light → dark; stored in localStorage (secmonk.theme), applied as data-theme on <html>.",
      variants: [{ name: "Default", template: `<sm-theme-toggle/>` }] },

    // ------------------------------------------------------------------ status
    { id: "badge", group: "Status", title: "Badge (sm-badge)",
      doc: "Props: variant (p1..p4 | kev | ok | warn | danger | info | outline | live).",
      variants: [{ name: "Variants", template: `<span class="sm-badges"><sm-badge>neutral</sm-badge><sm-badge variant="ok">DB matched</sm-badge>
<sm-badge variant="warn">no DB</sm-badge><sm-badge variant="danger">missing</sm-badge><sm-badge variant="info">live</sm-badge>
<sm-badge variant="outline">application</sm-badge><sm-badge variant="kev">KEV</sm-badge><sm-badge variant="live">watching · 10 s</sm-badge></span>` }] },
    { id: "priority", group: "Status", title: "Priority & findings summary",
      doc: "sm-priority (priority, count) and sm-findings-summary (findings: [{priority, kev}], empty) — the findings cell of every table.",
      variants: [
        { name: "Priorities", template: `<span class="sm-badges"><sm-priority priority="P1"/><sm-priority priority="P2"/><sm-priority priority="P3"/><sm-priority priority="P4" :count="3"/></span>` },
        { name: "Summary", template: `<sm-findings-summary :findings="findings"/>`, data: { findings: sampleFindings } },
        { name: "Empty", template: `<sm-findings-summary :findings="[]" empty="—"/>` },
      ] },
    { id: "severity", group: "Status", title: "Severity (sm-severity)",
      doc: "Severity label of a vulnerability record (CRITICAL / HIGH / MEDIUM / LOW) in the priority colors, with the CVSS score. '—' when unknown.",
      variants: [{ name: "Levels", template: `<span class="sm-badges"><sm-severity severity="CRITICAL" :score="10"/><sm-severity severity="HIGH" :score="7.5"/>
<sm-severity severity="MEDIUM" :score="5.3"/><sm-severity severity="LOW"/><sm-severity :score="6.1"/><sm-severity/></span>` }] },
    { id: "priority-bar", group: "Status", title: "Priority bar (sm-priority-bar)",
      doc: "Open findings of an asset per priority as a stacked bar; legend adds the numbers. Green when there is none.",
      variants: [
        { name: "Bars", template: `<div style="display:grid;gap:8px"><sm-priority-bar :counts="{ P1: 1, P2: 3, P3: 8, P4: 2 }" legend/>
<sm-priority-bar :counts="{ P3: 2, P4: 1 }" legend/><sm-priority-bar :counts="{}" legend/></div>` },
        { name: "From the mock assets", template: `<div style="display:grid;gap:8px"><div v-for="a in assets" :key="a.id" class="sm-toolbar">
  <code style="width:220px">{{ a.id }}</code><sm-priority-bar :counts="a.findings_by_priority" legend/></div></div>`, data: { assets: M.assets } },
      ] },
    { id: "launch", group: "Status", title: "Launch badge (sm-launch-badge)",
      doc: "How a process started. Props: kind (one of the launch kinds), detail. Tooltip explains the kind.",
      variants: [{ name: "All kinds", template: `<span class="sm-badges"><sm-launch-badge v-for="k in kinds" :key="k" :kind="k"/></span>`,
        data: { kinds: Object.keys(global.SecMonkUI.LAUNCH) } },
        { name: "With detail", template: `<sm-launch-badge kind="agent" detail="com.sync.agent"/>` }] },
    { id: "flags", group: "Status", title: "Flags (sm-flag, sm-flags)",
      doc: "Risk heuristics from the collector; level drives the color (high | warn | info); hover shows the explanation.",
      variants: [{ name: "All flags", template: `<sm-flags :flags="flags"/>`, data: { flags: Object.keys(global.SecMonkUI.FLAGS) } }] },
    { id: "event-badge", group: "Status", title: "Event badge (sm-event-badge)",
      doc: "Watch event types.",
      variants: [{ name: "All", template: `<span class="sm-badges"><sm-event-badge v-for="e in events" :key="e" :event="e"/></span>`,
        data: { events: Object.keys(global.SecMonkUI.EVENTS) } }] },
    { id: "spinner", group: "Status", title: "Spinner (sm-spinner)", doc: "Props: large, label (aria).",
      variants: [{ name: "Sizes", template: `<sm-spinner/> <sm-spinner large/>` }] },

    // ------------------------------------------------------------------ inputs
    { id: "search", group: "Inputs", title: "Search (sm-search)",
      doc: "v-model string; `/` focuses it from anywhere (hotkey prop), Esc clears.",
      variants: [{ name: "Default", template: `<sm-search v-model="q" placeholder="Search name, path, label"/> <span class="sm-muted">value: {{ q }}</span>`, data: { q: "" } }] },
    { id: "chips", group: "Inputs", title: "Chips (sm-chip, sm-chips)",
      doc: "Multi-select filter. options: [{value, label, count}], v-model: array.",
      variants: [{ name: "Launch-kind filter", template: `<sm-chips v-model="sel" :options="opts"/> <div class="sm-muted" style="margin-top:6px">{{ sel }}</div>`,
        data: { sel: ["agent"], opts: [{ value: "service", label: "service", count: 4 }, { value: "agent", label: "agent", count: 1 },
          { value: "gui-app", label: "app", count: 3 }, { value: "interactive", label: "interactive", count: 4 }] } }] },
    { id: "switch", group: "Inputs", title: "Switch (sm-switch)", doc: "v-model boolean, label in the slot.",
      variants: [{ name: "Default", template: `<sm-switch v-model="on">Suspicious only</sm-switch> <span class="sm-muted">{{ on }}</span>`, data: { on: true } }] },
    { id: "segmented", group: "Inputs", title: "Segmented (sm-segmented)", doc: "Single choice. options: [{value, label, icon}].",
      variants: [{ name: "View mode", template: `<sm-segmented v-model="mode" :options="[{ value: 'tree', label: 'Tree', icon: 'tree' }, { value: 'flat', label: 'List', icon: 'list' }]"/>`, data: { mode: "tree" } }] },
    { id: "select", group: "Inputs", title: "Select (sm-select)", doc: "options: [{value, label}], numeric values stay numbers.",
      variants: [{ name: "Interval", template: `<sm-select v-model="s" label="Interval" :options="[{ value: 5, label: 'every 5 s' }, { value: 10, label: 'every 10 s' }]"/> <span class="sm-muted">{{ s }}</span>`, data: { s: 10 } }] },

    // ------------------------------------------------------------------ content
    { id: "tabs", group: "Inputs", title: "Tabs (sm-tabs)", doc: "Sections of a detail page. options [{value, label, count}], v-model.",
      variants: [{ name: "Asset tabs", template: `<sm-tabs v-model="t" :options="[{ value: 'findings', label: 'Findings', count: 2 }, { value: 'components', label: 'Components', count: 18 },
  { value: 'scans', label: 'Scans', count: 2 }, { value: 'details', label: 'Details' }]"/>
<div class="sm-muted" style="margin-top:6px">tab: {{ t }}</div>`, data: { t: "findings" } }] },
    { id: "field", group: "Inputs", title: "Form field (sm-field) and form layout",
      doc: "Label + control + hint. Put fields in .sm-form (responsive grid); `wide` spans the row; .sm-form__actions for the buttons. Controls: .sm-input, .sm-select, textarea.sm-input, sm-switch, sm-chips.",
      variants: [{ name: "Scan form", template: `<div class="sm-form">
  <sm-field label="Collector" hint="Language dependencies in a folder"><select class="sm-select" v-model="c"><option>fs</option><option>rootfs</option></select></sm-field>
  <sm-field label="Target" hint="required"><input class="sm-input" v-model="t" placeholder="/path/to/project"></sm-field>
  <sm-field label="Save"><sm-switch v-model="s">store the inventory and findings</sm-switch></sm-field>
  <sm-field label="Collector options" hint="one key=value per line" wide><textarea class="sm-input" rows="2"></textarea></sm-field>
  <div class="sm-form__actions"><sm-button variant="primary" icon="play">Run scan</sm-button><span class="sm-muted">Same as</span><code>secmonk scan {{ c }} {{ t }}</code></div>
</div>`, data: { c: "fs", t: "/srv/web-frontend", s: true } }] },
    { id: "page-header", group: "Content", title: "Page header (sm-page-header)", doc: "Title, subtitle, actions slot. Top of every view.",
      variants: [{ name: "With actions", template: `<sm-page-header title="Processes" subtitle="What is running, how it was started.">
  <sm-button icon="refresh">Refresh</sm-button><sm-button icon="save">Save</sm-button><sm-button variant="primary" icon="eye">Watch</sm-button>
</sm-page-header>` }] },
    { id: "stat", group: "Content", title: "Stat card (sm-stat)", doc: "label, value, hint, variant (p1 | warn), clickable (emits click).",
      variants: [{ name: "Row", template: `<div class="sm-stats"><sm-stat label="Processes" value="412" hint="mbp · 10:02"/>
<sm-stat label="With findings" value="7" variant="p1" clickable hint="click to filter"/><sm-stat label="Flagged" value="3" variant="warn"/>
<sm-stat label="Software" value="138" hint="distinct identities"/></div>` }] },
    { id: "card", group: "Content", title: "Card (sm-card)", doc: "title, icon, flush (no body padding), actions slot.",
      variants: [{ name: "Default", template: `<sm-card title="This server" icon="server"><template #actions><sm-button size="sm" variant="ghost">Edit</sm-button></template>
  Body content.</sm-card>` }] },
    { id: "kv", group: "Content", title: "Key / value (sm-kv)", doc: "rows: [{label, value, mono, copy}]; empty values are skipped.",
      variants: [{ name: "Launch facts", template: `<sm-kv :rows="[{ label: 'Mechanism', value: 'launchd-agent' }, { label: 'Job label', value: 'com.sync.agent', mono: true },
  { label: 'Configured in', value: '/Users/alice/Library/LaunchAgents/com.sync.agent.plist', copy: true }, { label: 'Skipped', value: null }]"/>` }] },
    { id: "copy", group: "Content", title: "Copy value (sm-copy)", doc: "Mono value with a copy button (toast feedback).",
      variants: [{ name: "Hash", template: `<sm-copy value="0f3a9c1e5b7d2a4f6e8c0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a" display="0f3a9c1e…"/>` }] },
    { id: "section", group: "Content", title: "Section (sm-section)", doc: "Titled block inside a drawer; extra slot next to the title.",
      variants: [{ name: "Default", template: `<sm-section title="Findings" icon="alert"><template #extra><sm-findings-summary :findings="f"/></template>Section body.</sm-section>`, data: { f: sampleFindings } }] },
    { id: "callout", group: "Content", title: "Callout (sm-callout)", doc: "variant info | warn | error; title; slot. Error callouts are role=alert.",
      variants: [{ name: "Variants", template: `<div style="display:grid;gap:8px"><sm-callout title="No vulnerability database">Run <code>secmonk sync kev epss</code>.</sm-callout>
<sm-callout variant="warn" title="1 launch item points to a missing program">Stale configuration.</sm-callout>
<sm-callout variant="error" title="Live snapshots are not implemented on linux">Start with --snapshot FILE.</sm-callout></div>` }] },
    { id: "empty", group: "Content", title: "Empty state (sm-empty)", doc: "title, icon, slot for text / action.",
      variants: [{ name: "No match", template: `<sm-empty title="No process matches the filters" icon="search"><sm-button size="sm">Clear filters</sm-button></sm-empty>` }] },
    { id: "chain", group: "Content", title: "Chain (sm-chain)", doc: "Ancestry / list of clickable items: items [{key, label, current}], emits pick.",
      variants: [{ name: "Ancestry", template: `<sm-chain :items="[{ key: 1, label: 'launchd (1)' }, { key: 400, label: 'Terminal (400)' }, { key: 402, label: 'zsh (402)' }, { key: 403, label: 'curl (403)', current: true }]" @pick="k => picked = k"/>
<div class="sm-muted" style="margin-top:6px">picked: {{ picked }}</div>`, data: { picked: null } }] },

    // ------------------------------------------------------------------ data
    { id: "table", group: "Data", title: "Table (sm-table)",
      doc: "columns [{key, label, cls, width}], rows, row-key, selected, row-class(fn), static; slots cell-<key> and empty; emits select.",
      variants: [
        { name: "Processes (tree cells)", template: `<sm-table :columns="cols" :rows="rows" row-key="pid" :selected="sel" @select="r => sel = r.pid">
  <template #cell-launch="{ row }"><sm-launch-badge :kind="row.launch"/></template>
  <template #cell-process="{ row }"><div class="sm-tree-cell" :style="{ '--depth': row.depth - 2 }"><span class="sm-proc-name">{{ row.process }}</span></div></template>
  <template #cell-flags="{ row }"><sm-flags :flags="row.flags"/></template>
</sm-table>`, data: { sel: 403, rows: tableRows, cols: [{ key: "pid", label: "PID", cls: "is-num" }, { key: "user", label: "User" },
          { key: "launch", label: "Launch" }, { key: "process", label: "Process" }, { key: "identity", label: "Identity" }, { key: "flags", label: "Flags" }] } },
        { name: "Empty", template: `<sm-table :columns="[{ key: 'a', label: 'Label' }]" :rows="[]"><template #empty><sm-empty title="Nothing here" icon="inbox"/></template></sm-table>` },
      ] },
    { id: "feed", group: "Data", title: "Feed item (sm-feed-item)", doc: "One watch event (procmon.event_dict shape); emits open.",
      variants: [{ name: "Events", template: `<sm-card flush><div class="sm-feed"><sm-feed-item v-for="e in events" :key="e.id" :event="e"/></div></sm-card>`,
        data: { events: M.events.map((e, i) => ({ ...e, id: i, time: "10:04:1" + i })) } }] },
    { id: "job", group: "Data", title: "Job (sm-job)",
      doc: "A background scan or sync (web/jobs.py): status badge, title, time, log; the result goes in the slot (job-result). Status: running | ok | partial | error.",
      variants: [
        { name: "Running", template: `<sm-job :job="{ id: 3, kind: 'sync', title: 'sync osv', status: 'running', started: '2026-11-07T10:00:00Z', log: ['syncing osv…', 'osv: PyPI 1,204 records'] }"/>` },
        { name: "Done (scan)", template: `<sm-job :job="job"/>`, data: { job: scanJob } },
        { name: "Failed", template: `<sm-job :job="{ id: 4, kind: 'scan', title: 'scan ssh admin@build-01', status: 'error', started: '2026-11-07T10:00:00Z', finished: '2026-11-07T10:00:12Z',
  error: 'ConnectionError: timed out', log: ['collecting with ssh on admin@build-01…', 'error: ConnectionError: timed out'] }"/>` },
      ] },
    { id: "drawer", group: "Data", title: "Drawer (sm-drawer)", doc: "Detail panel: title, subtitle, actions slot; Esc / close emits close. `inline` renders it in the flow (storybook, print).",
      variants: [{ name: "Inline", template: `<sm-drawer inline title="com.sync.agent" subtitle="launchd-agent · user:alice">
  <sm-kv :rows="[{ label: 'Program', value: '/Users/alice/Library/Application Support/Sync/syncd', copy: true }]"/></sm-drawer>` }] },

    // ------------------------------------------------------------------ navigation / feedback
    { id: "nav", group: "Navigation", title: "Sidebar nav (sm-nav)", doc: "groups [{label, items: [{id, label, icon, to, planned, count}]}], active id. Planned items show 'soon'.",
      variants: [{ name: "App navigation", template: `<div style="background:var(--sm-sidebar);padding:8px;border-radius:8px;width:230px"><sm-nav :groups="nav" active="processes"/></div>`,
        data: { nav: global.SecMonkUI.NAV.map((g) => ({ ...g, items: g.items.map((i) => (i.id === "activity" ? { ...i, count: 3 } : i)) })) } }] },
    { id: "toast", group: "Navigation", title: "Toasts (SecMonkUI.toast)", doc: "SecMonkUI.toast(message, kind = info | warn | error, ms). Rendered by <sm-toasts/> in the shell.",
      variants: [{ name: "Trigger", template: `<sm-button @click="t('Snapshot 10:02:13 — 412 processes')">Info</sm-button> <sm-button @click="t('new launch item: com.example.newagent', 'warn')">Warn</sm-button>
<sm-button @click="t('Save failed: database is locked', 'error')">Error</sm-button>`, methods: { t: (m, k) => global.SecMonkUI.toast(m, k) } }] },

    // ------------------------------------------------------------------ patterns (view-level, secmonk-views.js)
    { id: "process-detail", group: "Patterns", title: "Process detail (process-detail)",
      doc: "The detail drawer of the Processes view (secmonk-views.js), here inline on mock data: launch, identity, findings, provenance, flags.",
      variants: [
        { name: "curl from Terminal (brew keg, findings)", template: `<process-detail inline :row="row"/>`, data: { row: proc(403) } },
        { name: "Downloaded app (provenance)", template: `<process-detail inline :row="row"/>`, data: { row: proc(310) } },
        { name: "Agent in a user folder (flags)", template: `<process-detail inline :row="row"/>`, data: { row: proc(320) } },
      ] },
    { id: "findings-table", group: "Patterns", title: "Findings table (findings-table)",
      doc: "The findings list of Findings, asset detail, dashboard, vulnerability page and scan results (reports.finding_dict rows). Props: show-asset, show-vuln, show-status, compact, selected; emits select.",
      variants: [
        { name: "All findings (with status)", template: `<findings-table :rows="rows" show-status :selected="sel" @select="r => sel = r.key"/>`, data: { rows: M.findings, sel: null } },
        { name: "Compact, one asset", template: `<findings-table :rows="rows" compact :show-asset="false"/>`, data: { rows: M.findings.filter((f) => f.asset_id === "process:fixture-mac") } },
      ] },
    { id: "finding-detail", group: "Patterns", title: "Finding detail (finding-detail)",
      doc: "The finding drawer (secmonk-views.js), inline here: priority and why, match method and confidence, triage, timeline, advisories, and the vulnerability as the mirror knows it (KEV, EPSS).",
      variants: [
        { name: "Log4Shell (P1, KEV)", template: `<finding-detail inline :finding="f"/>`, data: { f: finding("CVE-2021-44228") } },
        { name: "Fixed finding", template: `<finding-detail inline :finding="f"/>`, data: { f: M.findings.find((f) => f.status === "fixed") } },
      ] },
    { id: "job-result", group: "Patterns", title: "Job result (job-result)",
      doc: "What a finished job produced: a scan's asset, stats and findings; a sync's per-source status. Used inside sm-job.",
      variants: [
        { name: "Scan", template: `<sm-job :job="job"><job-result :job="job"/></sm-job>`, data: { job: scanJob } },
        { name: "Sync", template: `<sm-job :job="job" :log="false"><job-result :job="job"/></sm-job>`, data: { job: syncJob } },
      ] },
    { id: "toolbar", group: "Patterns", title: "Toolbar composition",
      doc: "Search + toggles left, view controls right; second row: filter chips + result count. Same in every list view.",
      variants: [{ name: "Processes toolbar", template: `<div style="display:grid;gap:8px"><div class="sm-toolbar"><sm-search v-model="q" placeholder="Search"/><sm-switch v-model="s">Suspicious only</sm-switch>
  <span class="sm-toolbar__spacer"></span><sm-segmented v-model="m" :options="[{ value: 'tree', label: 'Tree', icon: 'tree' }, { value: 'flat', label: 'List', icon: 'list' }]"/></div>
<div class="sm-toolbar"><sm-chips v-model="k" :options="[{ value: 'agent', label: 'agent', count: 1 }, { value: 'service', label: 'service', count: 4 }]"/>
  <span class="sm-toolbar__spacer"></span><span class="sm-toolbar__count">5 of 21</span></div></div>`, data: { q: "", s: false, m: "tree", k: [] } }] },
  ];
})(window);
