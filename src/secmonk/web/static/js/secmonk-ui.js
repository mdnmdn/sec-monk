/* sec-monk UI kit: formatting helpers, vocabulary (launch kinds, flags, methods, severities, jobs) and the base Vue
 * components.
 *
 * Classic script (no modules, no bundler): needs the global `Vue` (vendored in static/vendor) and defines `window.SecMonkUI`.
 * Loaded unchanged by the app, the _design sample pages and the storybook; every component here has a story in
 * _design/storybook/stories.js. Untrusted data is only ever rendered with {{ }} / attribute bindings (never v-html).
 * Docs: _docs/tech/web-ui.md.
 */
(function (global) {
  "use strict";
  const { reactive, ref, computed, onMounted, onBeforeUnmount, watch } = global.Vue;

  // ------------------------------------------------------------------ formatting
  const fmt = {
    time(iso) {
      if (!iso) return "";
      const d = new Date(iso);
      return isNaN(d) ? String(iso) : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    },
    datetime(iso) {
      if (!iso) return "";
      const d = new Date(iso);
      return isNaN(d) ? String(iso) : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    },
    basename(p) { return p ? String(p).replace(/\\/g, "/").split("/").filter(Boolean).pop() || p : ""; },
    plural(n, word, many) { return `${n} ${n === 1 ? word : (many || word + "s")}`; },
    identity(name, version) { return name ? (version ? `${name} ${version}` : name) : ""; },
    short(s, n = 16) { return s && s.length > n ? s.slice(0, n) + "…" : s || ""; },
    date(iso) {
      if (!iso) return "";
      const d = new Date(iso);
      return isNaN(d) ? String(iso) : d.toLocaleDateString([], { dateStyle: "medium" });
    },
    /** "3 h ago", "12 d ago" (falls back to the raw value) */
    ago(iso) {
      if (!iso) return "never";
      const d = new Date(iso);
      if (isNaN(d)) return String(iso);
      const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
      if (s < 90) return "just now";
      if (s < 5400) return `${Math.round(s / 60)} min ago`;
      if (s < 129600) return `${Math.round(s / 3600)} h ago`;
      return `${Math.round(s / 86400)} d ago`;
    },
    ageDays(iso) { const d = new Date(iso); return iso && !isNaN(d) ? (Date.now() - d.getTime()) / 86400000 : null; },
    num(n) { return n == null ? "" : Number(n).toLocaleString(); },
    score(n, digits = 1) { return n == null ? "" : Number(n).toFixed(digits); },
    pct(n) { return n == null ? "" : `${(Number(n) * 100).toFixed(1)}%`; },
    /** OSV-style events [{introduced}, {fixed}, ...] + explicit versions -> ">= 2.13.0, < 2.15.0; = 1.2" */
    ranges(events, versions) {
      const parts = [];
      let cur = [];
      for (const e of events || []) {
        if (e.introduced != null) { if (cur.length) parts.push(cur.join(", ")); cur = e.introduced === "0" ? [] : [`>= ${e.introduced}`]; }
        else if (e.introduced_exclusive != null) { if (cur.length) parts.push(cur.join(", ")); cur = [`> ${e.introduced_exclusive}`]; }
        else if (e.fixed != null) { cur.push(`< ${e.fixed}`); parts.push(cur.join(", ")); cur = []; }
        else if (e.last_affected != null) { cur.push(`<= ${e.last_affected}`); parts.push(cur.join(", ")); cur = []; }
        else if (e.limit != null) { cur.push(`< ${e.limit} (limit)`); parts.push(cur.join(", ")); cur = []; }
      }
      if (cur.length) parts.push(cur.join(", "));
      else if ((events || []).length && !parts.length) parts.push("all versions");
      const vs = versions || [];
      if (vs.length) parts.push(vs.length > 6 ? `= ${vs.slice(0, 6).join(", ")} … (+${vs.length - 6})` : `= ${vs.join(", ")}`);
      return parts.join("; ");
    },
    /** Only http(s) URLs become links: advisory references are data and could carry javascript: URLs. */
    safeUrl(u) { return typeof u === "string" && /^https?:\/\//i.test(u) ? u : null; },
  };

  // ------------------------------------------------------------------ vocabulary (mirrors collectors/process)
  const LAUNCH = {
    kernel: { label: "kernel", text: "The kernel or the init system itself (pid 0 / 1)." },
    service: { label: "service", text: "System-wide background service started by the service manager (launchd daemon)." },
    agent: { label: "agent", text: "Per-user background service (launchd agent in a user session)." },
    "login-item": { label: "login item", text: "Started automatically at login." },
    scheduled: { label: "scheduled", text: "Started by a scheduler (cron, periodic, at)." },
    "gui-app": { label: "app", text: "Application opened from the desktop (Finder, Dock, LaunchServices)." },
    "xpc-service": { label: "xpc", text: "On-demand helper service of an app or framework (XPC)." },
    interactive: { label: "interactive", text: "Started from a shell in a terminal or a console login." },
    "remote-session": { label: "remote", text: "Started from a shell of a remote session (sshd)." },
    child: { label: "child", text: "Spawned by another process (not a shell)." },
    unknown: { label: "unknown", text: "Origin could not be determined." },
  };
  const FLAGS = {
    "exe-missing": { level: "high", text: "The executable no longer exists on disk: deleted or replaced while running (updates, droppers)." },
    "unsigned": { level: "high", text: "The executable has no code signature." },
    "adhoc-signed": { level: "warn", text: "Ad-hoc signature: no identity, typical of locally built or modified binaries." },
    "signature-invalid": { level: "high", text: "codesign --verify failed: the binary or its bundle was modified after signing, or the certificate is revoked." },
    "downloaded": { level: "info", text: "Carries a quarantine attribute: it was downloaded (browser, mail, AirDrop...)." },
    "world-writable": { level: "high", text: "Any user can overwrite this executable." },
    "translocated": { level: "warn", text: "Running from App Translocation: launched straight from a disk image or the Downloads folder." },
    "user-writable-path": { level: "warn", text: "Runs from a folder an ordinary user can write to (home, /tmp, /Volumes...)." },
    "root-from-user-path": { level: "high", text: "Runs as root from a user-writable folder: whoever controls that folder controls root." },
    "persistent-from-user-path": { level: "high", text: "Starts automatically (service/agent/login item) from a user-writable folder: a classic persistence pattern." },
    "unidentified": { level: "info", text: "No package identity (bundle, Homebrew, receipt, build info): cannot be matched against advisories." },
  };
  const METHODS = {
    "app-bundle": "Read from the enclosing .app bundle (Info.plist), helpers resolved to their host app.",
    "brew-keg": "Homebrew formula keg (Cellar/<formula>/<version>) with its install receipt.",
    "brew-cask": "Homebrew cask (Caskroom/<token>/<version>).",
    "os": "Part of the operating system: versioned with macOS.",
    "pkgutil": "Owned by an installer package receipt (pkgutil --file-info).",
    "go-binary": "Go build information embedded in the binary (main module + dependencies).",
    "rust-binary": "cargo-auditable dependency list embedded in the binary.",
    "info-plist": "Info.plist embedded in the Mach-O (__TEXT,__info_plist).",
    "snapshot": "Identity provided by the snapshot file (computed on the target).",
    "path-only": "Guessed from the path only (snapshot analysed without the target's files): no version.",
    "none": "Not identified.",
  };
  const EVENTS = {
    "new-executable": { label: "new exe", cls: "info" },
    "changed-executable": { label: "changed exe", cls: "warn" },
    "new-launch-item": { label: "new launch item", cls: "warn" },
    "changed-launch-item": { label: "changed launch item", cls: "warn" },
    "removed-launch-item": { label: "removed launch item", cls: "outline" },
  };

  // ------------------------------------------------------------------ vocabulary (mirrors engine/ and web/jobs.py)
  const SEVERITY = {
    CRITICAL: { variant: "p1", label: "critical" }, HIGH: { variant: "p2", label: "high" },
    MEDIUM: { variant: "p3", label: "medium" }, MODERATE: { variant: "p3", label: "moderate" },
    LOW: { variant: "p4", label: "low" }, NONE: { variant: "outline", label: "none" },
  };
  const PRIORITY_TEXT = {
    P1: "Fix now: known exploited (KEV), or critical and likely to be exploited.",
    P2: "Fix soon: high severity or elevated exploitation probability.",
    P3: "Plan: medium severity, or downgraded by distro triage.",
    P4: "Low: low severity or minor distro triage.",
  };
  const MATCHED_BY = {
    "osv-package": "Exact package match: ecosystem + package name + version range (OSV).",
    "cve-product": "Product name match against CVE List affected entries (name-based: see confidence).",
    "cpe-product": "Product match against NVD CPE applicability (name-based: see confidence).",
  };
  const JOB_STATUS = {
    running: { variant: "live", label: "running" }, ok: { variant: "ok", label: "done" },
    partial: { variant: "warn", label: "partial" }, error: { variant: "danger", label: "failed" },
  };
  /** Where a job was started (job.origin). */
  const JOB_ORIGIN = { ui: "Started from this web interface", cli: "Run from the command line (secmonk scan / sync)" };
  /** What to type as the target of each collector (secmonk scan <collector> <target>). */
  const COLLECTOR_TARGETS = {
    macos: { placeholder: "(this Mac) or a mounted root, e.g. /Volumes/Backup", optional: true },
    homebrew: { placeholder: "(default prefix) or e.g. /opt/homebrew", optional: true },
    rootfs: { placeholder: "/path/to/extracted/rootfs" },
    fs: { placeholder: "/path/to/project or directory" },
    "docker-image": { placeholder: "alpine:3.20, image.tar or an OCI layout dir" },
    "docker-engine": { placeholder: "web, api-*, re:^shop-, image:nginx:*",
      help: "comma separated: container names or ids, globs (web-*), re:<regex> (search); images: image:<ref>, image:* (every tagged image), image:<glob>, image:re:<regex>, each scanned once per image Id; container patterns see running containers unless 'include stopped'" },
    ssh: { placeholder: "user@host[:port]" },
    windows: { placeholder: "/path/to/inventory.json (from secmonk windows-script)" },
    process: { placeholder: "(this machine) or a snapshot.json", optional: true },
  };

  /** Priority counts from a findings list: [{priority, kev}] -> {P1: n, ..., kev: n} */
  function countFindings(list) {
    const c = { P1: 0, P2: 0, P3: 0, P4: 0, kev: 0, total: 0 };
    for (const f of list || []) {
      if (c[f.priority] !== undefined) c[f.priority]++;
      if (f.kev) c.kev++;
      c.total++;
    }
    return c;
  }
  function worstPriority(list) {
    const c = countFindings(list);
    return ["P1", "P2", "P3", "P4"].find((p) => c[p] > 0) || null;
  }

  // ------------------------------------------------------------------ toasts (global store)
  const toasts = reactive([]);
  let toastId = 0;
  function toast(message, kind = "info", ms = 4000) {
    const id = ++toastId;
    toasts.push({ id, message: String(message), kind });
    if (ms) setTimeout(() => dismiss(id), ms);
    return id;
  }
  function dismiss(id) {
    const i = toasts.findIndex((t) => t.id === id);
    if (i >= 0) toasts.splice(i, 1);
  }

  // ------------------------------------------------------------------ theme
  const theme = ref((() => { try { return localStorage.getItem("secmonk.theme") || "system"; } catch (e) { return "system"; } })());
  function applyTheme(v) {
    theme.value = v;
    const root = document.documentElement;
    if (v === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", v);
    try { localStorage.setItem("secmonk.theme", v); } catch (e) { /* private mode */ }
  }

  // ------------------------------------------------------------------ icons (Feather-style strokes, inline)
  const ICONS = {
    cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
    package: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96 12 12.01l8.73-5.05M12 22.08V12"/>',
    rocket: '<path d="M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2"/><path d="M15 9a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/><path d="M12 2c4 2 6 6 6 10l-3 3H9l-3-3c0-4 2-8 6-10z"/>',
    activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
    alert: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    pause: '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    chevron: '<polyline points="9 18 15 12 9 6"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    tree: '<path d="M6 3v12M6 9h8M6 15h8"/><circle cx="17" cy="9" r="2"/><circle cx="17" cy="15" r="2"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    sun: '<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
    monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><path d="M12 15V3"/>',
    help: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01"/>',
    play: '<polygon points="5 3 19 12 5 21 5 3"/>',
    clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><path d="M10 14 21 3"/>',
    target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  };

  // ------------------------------------------------------------------ components
  const SmIcon = {
    name: "SmIcon",
    props: { name: { type: String, required: true }, size: { type: String, default: "" } },
    computed: { svg() { return ICONS[this.name] || ICONS.help; } },
    // the SVG path strings are static constants above (never data): safe for innerHTML
    template: `<svg :class="['sm-icon', size && 'sm-icon--' + size]" viewBox="0 0 24 24" aria-hidden="true" v-html="svg"></svg>`,
  };

  const SmButton = {
    name: "SmButton",
    props: { variant: { type: String, default: "" }, size: String, icon: String, loading: Boolean,
      disabled: Boolean, active: Boolean, title: String, iconOnly: Boolean },
    emits: ["click"],
    template: `<button type="button" :class="['sm-btn', variant && 'sm-btn--' + variant, size && 'sm-btn--' + size,
        iconOnly && 'sm-btn--icon', active && 'is-active']" :disabled="disabled || loading" :title="title"
        :aria-label="iconOnly ? title : null" @click="$emit('click', $event)">
      <span v-if="loading" class="sm-spinner"></span><sm-icon v-else-if="icon" :name="icon"/>
      <slot/></button>`,
  };

  const SmBadge = {
    name: "SmBadge",
    props: { variant: { type: String, default: "" }, title: String },
    template: `<span :class="['sm-badge', variant && 'sm-badge--' + variant]" :title="title"><slot/></span>`,
  };

  const SmPriority = {
    name: "SmPriority",
    props: { priority: { type: String, required: true }, count: Number },
    template: `<span :class="['sm-badge', 'sm-badge--' + priority.toLowerCase()]" :title="'Priority ' + priority">
      {{ priority }}<template v-if="count != null">×{{ count }}</template></span>`,
  };

  /** Findings cell: from a list (findings: [{priority, kev}]) or from counts ({P1..P4, kev}). */
  const SmFindingsSummary = {
    name: "SmFindingsSummary",
    props: { findings: { type: Array, default: () => [] }, counts: Object, empty: { type: String, default: "" } },
    computed: {
      c() {
        if (!this.counts) return countFindings(this.findings);
        const c = { P1: 0, P2: 0, P3: 0, P4: 0, kev: 0, ...this.counts };
        return { ...c, total: c.P1 + c.P2 + c.P3 + c.P4 };
      },
    },
    template: `<span class="sm-badges">
      <template v-for="p in ['P1','P2','P3','P4']" :key="p"><sm-priority v-if="c[p]" :priority="p" :count="c[p]"/></template>
      <span v-if="c.kev" class="sm-badge sm-badge--kev" title="Known exploited (CISA KEV)">KEV {{ c.kev }}</span>
      <span v-if="!c.total && empty" class="sm-muted">{{ empty }}</span></span>`,
  };

  /** Severity label (CRITICAL / HIGH / …) with an optional CVSS score. */
  const SmSeverity = {
    name: "SmSeverity",
    props: { severity: String, score: Number },
    computed: { info() { return SEVERITY[(this.severity || "").toUpperCase()] || null; } },
    template: `<span v-if="info || score != null" :class="['sm-badge', 'sm-badge--' + (info ? info.variant : 'outline')]"
      :title="'Severity ' + (severity || '?') + (score != null ? ' · CVSS ' + score.toFixed(1) : '')">
      {{ (info ? info.label : 'cvss') + (score != null ? ' ' + score.toFixed(1) : '') }}</span>
      <span v-else class="sm-muted">—</span>`,
  };

  /** Stacked bar of open findings per priority. counts: {P1..P4}; legend shows the numbers. */
  const SmPriorityBar = {
    name: "SmPriorityBar",
    props: { counts: { type: Object, default: () => ({}) }, legend: Boolean },
    computed: {
      segs() { return ["P1", "P2", "P3", "P4"].map((p) => ({ p, n: this.counts[p] || 0 })).filter((s) => s.n); },
      total() { return this.segs.reduce((a, s) => a + s.n, 0); },
    },
    template: `<span class="sm-pbar-wrap"><span class="sm-pbar" role="img"
      :aria-label="total ? segs.map(s => s.p + ': ' + s.n).join(', ') : 'no open findings'">
      <span v-for="s in segs" :key="s.p" :class="['sm-pbar__seg', 'sm-pbar__seg--' + s.p.toLowerCase()]"
        :style="{ flexGrow: s.n }" :title="s.p + ': ' + s.n"></span><span v-if="!total" class="sm-pbar__none"></span></span>
      <span v-if="legend" class="sm-pbar__legend"><template v-if="total"><span v-for="s in segs" :key="s.p">{{ s.p }} {{ s.n }}</span></template>
      <span v-else class="sm-muted">none</span></span></span>`,
  };

  const SmLaunchBadge = {
    name: "SmLaunchBadge",
    props: { kind: { type: String, required: true }, detail: String },
    computed: { info() { return LAUNCH[this.kind] || LAUNCH.unknown; } },
    template: `<span :class="['sm-badge', 'sm-badge--kind', 'sm-badge--k-' + (kind in $options.LAUNCH ? kind : 'unknown')]"
      :title="info.text">{{ info.label }}<span v-if="detail" class="sm-badge__detail">{{ detail }}</span></span>`,
    LAUNCH,
  };

  const SmFlag = {
    name: "SmFlag",
    props: { flag: { type: String, required: true } },
    computed: { info() { return FLAGS[this.flag] || { level: "warn", text: this.flag }; } },
    template: `<span :class="['sm-flag', info.level !== 'warn' && 'sm-flag--' + info.level]" :title="info.text">{{ flag }}</span>`,
  };

  const SmFlags = {
    name: "SmFlags",
    props: { flags: { type: Array, default: () => [] } },
    template: `<span class="sm-badges"><sm-flag v-for="f in flags" :key="f" :flag="f"/></span>`,
  };

  const SmChip = {
    name: "SmChip",
    props: { on: Boolean, count: Number },
    emits: ["toggle"],
    template: `<button type="button" :class="['sm-chip', on && 'is-on']" :aria-pressed="on" @click="$emit('toggle')">
      <slot/><span v-if="count != null" class="sm-chip__count">{{ count }}</span></button>`,
  };

  /** Multi-select chips. options: [{value, label, count?}], v-model: array of values */
  const SmChips = {
    name: "SmChips",
    props: { options: { type: Array, default: () => [] }, modelValue: { type: Array, default: () => [] } },
    emits: ["update:modelValue"],
    methods: {
      toggle(v) {
        const s = new Set(this.modelValue);
        s.has(v) ? s.delete(v) : s.add(v);
        this.$emit("update:modelValue", [...s]);
      },
    },
    template: `<span class="sm-chips" role="group"><sm-chip v-for="o in options" :key="o.value" :on="modelValue.includes(o.value)"
      :count="o.count" @toggle="toggle(o.value)">{{ o.label }}</sm-chip></span>`,
  };

  const SmSearch = {
    name: "SmSearch",
    props: { modelValue: { type: String, default: "" }, placeholder: { type: String, default: "Search" },
      hotkey: { type: Boolean, default: true } },
    emits: ["update:modelValue"],
    setup(props) {
      const input = ref(null);
      const onKey = (e) => {
        if (!props.hotkey || e.key !== "/" || e.metaKey || e.ctrlKey) return;
        const t = e.target;
        if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
        e.preventDefault();
        input.value && input.value.focus();
      };
      onMounted(() => document.addEventListener("keydown", onKey));
      onBeforeUnmount(() => document.removeEventListener("keydown", onKey));
      return { input };
    },
    template: `<label class="sm-search"><sm-icon name="search"/><span class="sm-visually-hidden">{{ placeholder }}</span>
      <input ref="input" type="search" :placeholder="placeholder" :value="modelValue"
        @input="$emit('update:modelValue', $event.target.value)" @keydown.esc="$emit('update:modelValue', '')">
      <kbd v-if="hotkey && !modelValue">/</kbd></label>`,
  };

  const SmSwitch = {
    name: "SmSwitch",
    props: { modelValue: Boolean },
    emits: ["update:modelValue"],
    template: `<label class="sm-switch"><input type="checkbox" :checked="modelValue"
      @change="$emit('update:modelValue', $event.target.checked)"><span class="sm-switch__track"></span><slot/></label>`,
  };

  /** options: [{value, label, icon?}] */
  const SmSegmented = {
    name: "SmSegmented",
    props: { options: { type: Array, required: true }, modelValue: [String, Number] },
    emits: ["update:modelValue"],
    template: `<span class="sm-segmented" role="group"><button v-for="o in options" :key="o.value" type="button"
      :class="{ 'is-on': o.value === modelValue }" :aria-pressed="o.value === modelValue"
      @click="$emit('update:modelValue', o.value)"><sm-icon v-if="o.icon" :name="o.icon"/>{{ o.label }}</button></span>`,
  };

  const SmSelect = {
    name: "SmSelect",
    props: { options: { type: Array, required: true }, modelValue: [String, Number], label: String },
    emits: ["update:modelValue"],
    template: `<select class="sm-select" :aria-label="label" :value="modelValue"
      @change="$emit('update:modelValue', isNaN(+$event.target.value) ? $event.target.value : +$event.target.value)">
      <option v-for="o in options" :key="o.value" :value="o.value">{{ o.label }}</option></select>`,
  };

  /** Tabs. options: [{value, label, count?}], v-model: value. */
  const SmTabs = {
    name: "SmTabs",
    props: { options: { type: Array, required: true }, modelValue: [String, Number] },
    emits: ["update:modelValue"],
    template: `<div class="sm-tabs" role="tablist"><button v-for="o in options" :key="o.value" type="button" role="tab"
      :class="['sm-tab', o.value === modelValue && 'is-on']" :aria-selected="o.value === modelValue"
      @click="$emit('update:modelValue', o.value)">{{ o.label }}<span v-if="o.count != null" class="sm-tab__count">{{ o.count }}</span></button></div>`,
  };

  /** Labelled form control: <sm-field label hint><input class="sm-input"></sm-field>. */
  const SmField = {
    name: "SmField",
    props: { label: String, hint: String, wide: Boolean },
    template: `<label :class="['sm-field', wide && 'sm-field--wide']"><span class="sm-field__label">{{ label }}</span><slot/>
      <span v-if="hint" class="sm-field__hint">{{ hint }}</span></label>`,
  };

  /** A scan / sync run (web/jobs.py, also CLI runs): status, origin, timing, log; result in the default slot, buttons in
   * the `actions` slot. Emits close if closable. */
  const SmJob = {
    name: "SmJob",
    props: { job: { type: Object, required: true }, log: { type: Boolean, default: true }, closable: Boolean },
    emits: ["close"],
    computed: {
      st() { return JOB_STATUS[this.job.status] || { variant: "outline", label: this.job.status }; },
      secs() {
        const a = new Date(this.job.started), b = this.job.finished ? new Date(this.job.finished) : null;
        return b && !isNaN(a) && !isNaN(b) ? Math.max(0, Math.round((b - a) / 1000)) : null;
      },
    },
    template: `<section class="sm-job"><header class="sm-job__header"><span :class="['sm-badge', 'sm-badge--' + st.variant]">{{ st.label }}</span>
      <b class="sm-job__title">{{ job.title }}</b><span v-if="job.origin" class="sm-badge sm-badge--outline" :title="ORIGIN[job.origin] || job.origin">{{ job.origin }}</span>
      <span class="sm-muted">#{{ job.id }} · {{ fmt.datetime(job.started) }}<template v-if="secs != null"> · {{ secs }} s</template></span>
      <span class="sm-toolbar__spacer"></span><slot name="actions"/><sm-button v-if="closable" size="sm" variant="ghost" icon-only icon="x" title="Close" @click="$emit('close')"/></header>
      <div v-if="job.error" class="sm-job__error">{{ job.error }}</div>
      <pre v-if="log && job.log && job.log.length" class="sm-log">{{ job.log.join('\\n') }}</pre>
      <div v-if="$slots.default" class="sm-job__result"><slot/></div></section>`,
    setup() { return { fmt, ORIGIN: JOB_ORIGIN }; },
  };

  /** One-line outcome of a job from its `summary` (reports.job_summary): scan findings + targets, sync records. */
  const SmJobSummary = {
    name: "SmJobSummary",
    props: { job: { type: Object, required: true } },
    computed: { s() { return this.job.summary || {}; } },
    template: `<span class="sm-badges"><template v-if="job.kind === 'scan' && s.targets != null">
        <sm-findings-summary v-if="s.errors < s.targets" :counts="s" empty="no findings"/>
        <span class="sm-muted">{{ fmt.plural(s.targets, 'target') }} · {{ fmt.num(s.components) }} components</span>
        <sm-badge v-if="s.errors" variant="danger">{{ s.errors }} failed</sm-badge></template>
      <template v-else-if="job.kind === 'sync' && s.sources != null">
        <span class="sm-muted">{{ fmt.plural(s.sources, 'source') }} · {{ fmt.num(s.records) }} records</span>
        <sm-badge v-if="s.errors" variant="danger">{{ s.errors }} failed</sm-badge></template>
      <span v-else class="sm-muted">{{ job.status === 'running' ? 'running…' : '—' }}</span></span>`,
    setup() { return { fmt }; },
  };

  const SmCard = {
    name: "SmCard",
    props: { title: String, icon: String, flush: Boolean },
    template: `<section class="sm-card"><header v-if="title || $slots.actions" class="sm-card__header">
      <h3 class="sm-card__title"><sm-icon v-if="icon" :name="icon"/>{{ title }}</h3><slot name="actions"/></header>
      <div :class="['sm-card__body', flush && 'sm-card__body--flush']"><slot/></div></section>`,
  };

  const SmStat = {
    name: "SmStat",
    props: { label: String, value: [String, Number], hint: String, variant: String, clickable: Boolean },
    emits: ["click"],
    template: `<component :is="clickable ? 'button' : 'div'" :type="clickable ? 'button' : null"
      :class="['sm-stat', variant && 'sm-stat--' + variant]" @click="clickable && $emit('click')">
      <span class="sm-stat__label">{{ label }}</span><span class="sm-stat__value">{{ value }}</span>
      <span v-if="hint" class="sm-stat__hint">{{ hint }}</span></component>`,
  };

  /** rows: [{label, value, mono?, copy?}] — rows whose value is null / undefined / '' / false are skipped */
  const SmKv = {
    name: "SmKv",
    props: { rows: { type: Array, default: () => [] } },
    template: `<dl class="sm-kv"><template v-for="r in rows" :key="r.label"><template v-if="r.value !== undefined && r.value !== null && r.value !== '' && r.value !== false">
      <dt>{{ r.label }}</dt><dd><sm-copy v-if="r.copy" :value="String(r.value)"/><span v-else-if="r.mono" class="sm-mono">{{ r.value }}</span>
      <template v-else>{{ r.value }}</template></dd></template></template><slot/></dl>`,
  };

  const SmCopy = {
    name: "SmCopy",
    props: { value: { type: String, required: true }, display: String },
    methods: {
      async copy() {
        try { await navigator.clipboard.writeText(this.value); toast("Copied", "info", 1500); }
        catch (e) { toast("Copy failed (clipboard not available)", "error"); }
      },
    },
    template: `<span class="sm-copy"><span class="sm-copy__value">{{ display || value }}</span>
      <button type="button" class="sm-copy__btn" title="Copy" aria-label="Copy" @click.stop="copy"><sm-icon name="copy"/></button></span>`,
  };

  /**
   * Data table. columns: [{key, label, cls?, width?}]; rows: array; rowKey: field name.
   * Cell content: slot `cell-<key>` ({row}) or row[key]. Emits `select(row)` on click / Enter.
   */
  const SmTable = {
    name: "SmTable",
    props: { columns: { type: Array, required: true }, rows: { type: Array, default: () => [] },
      rowKey: { type: String, default: "id" }, selected: [String, Number], rowClass: Function,
      static: Boolean, label: String },
    emits: ["select"],
    template: `<div class="sm-table-wrap"><table :class="['sm-table', static && 'sm-table--static']" :aria-label="label">
      <thead><tr><th v-for="c in columns" :key="c.key" :class="c.cls" :style="c.width ? { width: c.width } : null">{{ c.label }}</th></tr></thead>
      <tbody><tr v-for="r in rows" :key="r[rowKey]" :class="[r[rowKey] === selected && 'is-selected', rowClass && rowClass(r)]"
        :tabindex="static ? null : 0" @click="!static && $emit('select', r)" @keydown.enter="!static && $emit('select', r)">
        <td v-for="c in columns" :key="c.key" :class="c.cls"><slot :name="'cell-' + c.key" :row="r">{{ r[c.key] }}</slot></td>
      </tr></tbody></table><slot name="empty" v-if="!rows.length"/></div>`,
  };

  const SmDrawer = {
    name: "SmDrawer",
    props: { title: String, subtitle: String, inline: Boolean },
    emits: ["close"],
    setup(props, { emit }) {
      const onKey = (e) => { if (e.key === "Escape" && !props.inline) emit("close"); };
      onMounted(() => document.addEventListener("keydown", onKey));
      onBeforeUnmount(() => document.removeEventListener("keydown", onKey));
    },
    template: `<aside :class="['sm-drawer', inline && 'sm-drawer--inline']" role="dialog" :aria-label="title">
      <header class="sm-drawer__header"><div class="sm-drawer__heading"><div class="sm-drawer__title">{{ title }}</div>
      <div v-if="subtitle || $slots.subtitle" class="sm-drawer__subtitle"><slot name="subtitle">{{ subtitle }}</slot></div></div>
      <slot name="actions"/><sm-button variant="ghost" icon-only icon="x" title="Close (Esc)" @click="$emit('close')"/></header>
      <div class="sm-drawer__body"><slot/></div></aside>`,
  };

  const SmSection = {
    name: "SmSection",
    props: { title: String, icon: String },
    template: `<section><h4 class="sm-section__title"><sm-icon v-if="icon" :name="icon"/>{{ title }}<slot name="extra"/></h4><slot/></section>`,
  };

  const SmCallout = {
    name: "SmCallout",
    props: { variant: { type: String, default: "info" }, title: String },
    computed: { icon() { return this.variant === "info" ? "info" : "alert"; } },
    template: `<div :class="['sm-callout', 'sm-callout--' + variant]" :role="variant === 'error' ? 'alert' : 'status'">
      <sm-icon :name="icon"/><div><div v-if="title" class="sm-callout__title">{{ title }}</div><slot/></div></div>`,
  };

  const SmEmpty = {
    name: "SmEmpty",
    props: { title: String, icon: { type: String, default: "inbox" } },
    template: `<div class="sm-empty"><sm-icon :name="icon"/><div class="sm-empty__title">{{ title }}</div><slot/></div>`,
  };

  const SmSpinner = {
    name: "SmSpinner",
    props: { large: Boolean, label: { type: String, default: "Loading" } },
    template: `<span :class="['sm-spinner', large && 'sm-spinner--lg']" role="status" :aria-label="label"></span>`,
  };

  /** items: [{label, key, current?}] — emits pick(key) */
  const SmChain = {
    name: "SmChain",
    props: { items: { type: Array, default: () => [] } },
    emits: ["pick"],
    template: `<nav class="sm-chain" aria-label="Ancestry"><template v-for="(it, i) in items" :key="it.key">
      <span v-if="i" class="sm-chain__sep">›</span>
      <button type="button" :class="['sm-chain__item', it.current && 'is-current']" :disabled="it.current"
        @click="$emit('pick', it.key)">{{ it.label }}</button></template></nav>`,
  };

  const SmEventBadge = {
    name: "SmEventBadge",
    props: { event: { type: String, required: true } },
    computed: { info() { return EVENTS[this.event] || { label: this.event, cls: "outline" }; } },
    template: `<span :class="['sm-badge', 'sm-badge--' + info.cls]">{{ info.label }}</span>`,
  };

  /** One activity event (see procmon.event_dict). Emits open(event). */
  const SmFeedItem = {
    name: "SmFeedItem",
    props: { event: { type: Object, required: true } },
    emits: ["open"],
    computed: {
      isExe() { return this.event.event.endsWith("-executable"); },
      title() { return this.isExe ? (this.event.process || fmt.basename(this.event.exe)) : this.event.label; },
    },
    template: `<div class="sm-feed__item" tabindex="0" @click="$emit('open', event)" @keydown.enter="$emit('open', event)">
      <span class="sm-feed__time">{{ event.time }}</span><span><sm-event-badge :event="event.event"/></span>
      <div class="sm-feed__main"><div class="sm-feed__title"><b>{{ title }}</b>
        <template v-if="isExe"><span class="sm-muted">pid {{ event.pid }} · {{ event.user }}</span><sm-launch-badge :kind="event.launch"/></template>
        <span v-else class="sm-muted">{{ event.mechanism }} · {{ event.scope }}</span></div>
        <div class="sm-feed__path">{{ isExe ? event.exe : event.program }}<template v-if="event.previous_program"> (was {{ event.previous_program }})</template></div>
        <div v-if="isExe" class="sm-badges"><span v-if="event.identity">{{ event.identity }}</span>
          <sm-findings-summary :findings="event.findings_detail"/><sm-flags :flags="event.flags"/></div></div></div>`,
  };

  const SmPageHeader = {
    name: "SmPageHeader",
    props: { title: String, subtitle: String },
    template: `<header class="sm-page-header"><div class="sm-page-header__text"><h1 class="sm-page-header__title">{{ title }}</h1>
      <div v-if="subtitle" class="sm-page-header__subtitle">{{ subtitle }}</div></div>
      <div class="sm-page-header__actions"><slot/></div></header>`,
  };

  const SmToasts = {
    name: "SmToasts",
    setup() { return { toasts, dismiss }; },
    template: `<div class="sm-toasts" aria-live="polite"><div v-for="t in toasts" :key="t.id" :class="['sm-toast', t.kind !== 'info' && 'sm-toast--' + t.kind]">
      <span>{{ t.message }}</span><button type="button" class="sm-toast__close" aria-label="Dismiss" @click="dismiss(t.id)"><sm-icon name="x"/></button></div></div>`,
  };

  const SmThemeToggle = {
    name: "SmThemeToggle",
    setup() {
      const order = ["system", "light", "dark"];
      const icon = computed(() => ({ system: "monitor", light: "sun", dark: "moon" })[theme.value]);
      const next = () => applyTheme(order[(order.indexOf(theme.value) + 1) % order.length]);
      onMounted(() => applyTheme(theme.value));
      return { theme, icon, next };
    },
    template: `<sm-button variant="ghost" icon-only :icon="icon" :title="'Theme: ' + theme + ' (click to change)'" @click="next"/>`,
  };

  /** groups: [{label, items: [{id, label, icon, to, planned?, count?}]}]; active: id; emits go(item) */
  const SmNav = {
    name: "SmNav",
    props: { groups: { type: Array, required: true }, active: String },
    emits: ["go"],
    template: `<nav class="sm-nav" aria-label="Main"><template v-for="g in groups" :key="g.label">
      <div class="sm-nav__group">{{ g.label }}</div>
      <a v-for="it in g.items" :key="it.id" :href="'#' + it.to" :class="['sm-nav__item', it.id === active && 'is-active', it.planned && 'is-planned']"
        :title="it.label + (it.planned ? ' (planned)' : '')" :aria-current="it.id === active ? 'page' : null"
        @click="$emit('go', it)"><sm-icon :name="it.icon"/><span class="sm-nav__label">{{ it.label }}</span>
        <span v-if="it.count" class="sm-nav__count">{{ it.count }}</span><span v-else-if="it.planned" class="sm-nav__tag">soon</span></a>
    </template></nav>`,
  };

  const COMPONENTS = { SmIcon, SmButton, SmBadge, SmPriority, SmFindingsSummary, SmSeverity, SmPriorityBar, SmLaunchBadge,
    SmFlag, SmFlags, SmChip, SmChips, SmSearch, SmSwitch, SmSegmented, SmSelect, SmTabs, SmField, SmJob, SmJobSummary, SmCard, SmStat,
    SmKv, SmCopy, SmTable, SmDrawer, SmSection, SmCallout, SmEmpty, SmSpinner, SmChain, SmEventBadge, SmFeedItem,
    SmPageHeader, SmToasts, SmThemeToggle, SmNav };

  function install(app) {
    for (const [name, c] of Object.entries(COMPONENTS)) app.component(name, c);
    app.config.globalProperties.$fmt = fmt;
    return app;
  }

  global.SecMonkUI = Object.assign(global.SecMonkUI || {}, {
    fmt, LAUNCH, FLAGS, METHODS, EVENTS, SEVERITY, PRIORITY_TEXT, MATCHED_BY, JOB_STATUS, JOB_ORIGIN, COLLECTOR_TARGETS, ICONS,
    COMPONENTS, install, toast, dismiss, toasts, theme, applyTheme, countFindings, worstPriority,
  });
})(window);
