---
title: Plan - on an open network (source validation)
type: plan
context: plans
status: open
platform: open-network
tags: [plan, vuln-source, sync, network]
updated: 2026-11-07
related: [references/vuln-sources/README.md, features/vuln-sync.md, references/vuln-sources/distros.md, references/vuln-sources/debian-tracker.md]
---

# Plan: validate vulnerability sources from an unrestricted network

Any OS works (Linux/macOS/Windows with bash or WSL). The dev sandbox blocked: `security-tracker.debian.org`, `salsa.debian.org`, `secdb.alpinelinux.org`,
`access.redhat.com`, `security.access.redhat.com`, `api.first.org`/`epss.cyentia.com`, `services.nvd.nist.gov`, `euvdservices.enisa.europa.eu`, `www.cisa.gov`,
`api.msrc.microsoft.com`, `api.osv.dev`, `formulae.brew.sh`, `repology.org`, GitHub releases/API. Importers for all of them exist and pass **synthetic-fixture** tests; the job
is to replace the synthetic fixtures with real (trimmed) samples, correct wrong assumptions, and record sizes/timings.

Ordered by value (what blocks real scan quality first). Each item: sync, inspect, **fix the importer if the assumption fails**, swap the fixture, flip `sample:`/`reachable:` in the source doc.

## First hour: sync everything and print counts

```bash
#!/usr/bin/env bash
# first-hour.sh - run from the repo root on an open network. Continues on failure; read the summary at the end.
set -u
DB=${DB:-/tmp/first-hour.db}; LOG=/tmp/first-hour.log; : > "$LOG"
export NVD_API_KEY=${NVD_API_KEY:-}            # request one at https://nvd.nist.gov/developers/request-an-api-key (free)
run() { local t0=$(date +%s); echo "=== $* ===" | tee -a "$LOG"; "$@" >>"$LOG" 2>&1; echo "    exit=$? $(( $(date +%s)-t0 ))s" | tee -a "$LOG"; }
S="uv run secmonk"
run $S sync kev epss --db "$DB"                                   # small snapshots; official URLs first, mirror fallback (see message)
run $S sync debian-tracker --db "$DB"                             # JSON, then compare with salsa clone below
run $S sync msrc --since 2025-01-01 --db "$DB"
run $S sync euvd --limit 300 --db "$DB"
run $S sync nvd --since 2026-10-01 --db "$DB"                     # slow without a key (6 s/request)
run $S sync cvelist --since 2025 --db "$DB"                       # sparse git clone
run $S sync osv -e Debian -e Alpine -e "Rocky Linux" -e AlmaLinux -e "Red Hat" -e PyPI -e npm -e Maven -e Go -e crates.io -e RubyGems -e NuGet -e Packagist --db "$DB"
run $S sync cvelist --id @referenced --db "$DB"
echo; $S status --db "$DB" | tee -a "$LOG"
sqlite3 "$DB" <<'SQL'
.headers on
select 'vulnerability' t, source, count(*) n from vulnerability group by source;
select 'affected' t, count(*) n from affected;
select 'alias' t, count(*) n from alias;
select 'kev' t, count(*) n from kev;
select 'epss' t, count(*) n, max(score) mx from epss;
select 'distro_triage' t, status, count(*) n from distro_triage group by status;
select 'distro_triage_urg' t, urgency, count(*) n from distro_triage group by urgency;
select 'osv_ecosystems' t, ecosystem, count(*) n from affected group by ecosystem order by n desc limit 25;
SQL
ls -lh "$DB"
echo "--- reachability (HTTP code) ---"
for u in https://security-tracker.debian.org/tracker/data/json https://salsa.debian.org/security-tracker-team/security-tracker \
  https://secdb.alpinelinux.org/v3.20/main.json https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-3094.json \
  https://api.first.org/data/v1/epss?cve=CVE-2021-44228 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 \
  https://euvdservices.enisa.europa.eu/api/lastvulnerabilities https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  https://api.msrc.microsoft.com/cvrf/v3.0/updates https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q https://formulae.brew.sh/api/formula/jq.json \
  https://repology.org/api/v1/project/jq https://cveawg.mitre.org/api/cve/CVE-2021-44228; do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -m 20 -r 0-200 "$u")" "$u"; done
```

Expected result: every `sync` prints `ok`; non-zero counts in the table above; `distro_triage` has rows for `Debian:*`. Paste the summary (counts, sizes, durations) into [features/vuln-sync.md](../features/vuln-sync.md)
and each source doc's Status/TODO. Everything below is the follow-up per source.

## 1. Debian Security Tracker (highest value: drives `distro_triage`, P4/P3 capping)

- [ ] **JSON import: real field names and vocabulary.**
  ```bash
  curl -sO https://security-tracker.debian.org/tracker/data/json
  python3 - <<'P'
  import json,collections
  d=json.load(open('json')); c=collections.Counter(); keys=collections.Counter(); urg=collections.Counter(); st=collections.Counter()
  for pkg,cves in d.items():
      for cve,rec in cves.items():
          keys.update(rec.keys())
          for rel,r in rec.get('releases',{}).items():
              c[rel]+=1; keys.update('rel.'+k for k in r); urg[r.get('urgency')]+=1; st[r.get('status')]+=1
  print(c.most_common(20)); print(keys); print(urg); print(st)
  P
  uv run secmonk sync debian-tracker --db /tmp/t.db
  sqlite3 /tmp/t.db "select status,urgency,nodsa,count(*) from distro_triage group by 1,2,3 order by 4 desc limit 40"
  sqlite3 /tmp/t.db "select * from distro_triage where cve_id='CVE-2019-1010022'"
  ```
  Verify (the assumptions listed in [debian-tracker.md](../references/vuln-sources/debian-tracker.md)): `nodsa_reason` spelling/values; meaning of the trailing `*` on urgency; whether open entries omit `fixed_version` or use `""`;
  release keys (`bullseye`, `bookworm`, `trixie`, `sid`, `bookworm (security)`?) and the codename -> `Debian:<major>` mapping; `repositories` shape; status vocabulary (`resolved|open|undetermined|not-affected`?). Fix `src/secmonk/sources/debian_tracker.py`, replace `tests/fixtures/sources/debian-tracker/tracker-sample.json`.
- [ ] **salsa repo (text import) agrees with the JSON.**
  ```bash
  git clone --depth 1 https://salsa.debian.org/security-tracker-team/security-tracker.git /tmp/st
  uv run secmonk sync debian-tracker --path /tmp/st --db /tmp/t2.db
  diff <(sqlite3 /tmp/t.db "select ecosystem,package,cve_id,status from distro_triage order by 1,2,3") <(sqlite3 /tmp/t2.db "select ecosystem,package,cve_id,status from distro_triage order by 1,2,3") | head
  ```
  Verify: repo import is a documented subset; the sid policy (unbracketed `<unfixed>`, `<no-dsa>`, `<postponed>`) matches tracker semantics; decide `Debian:sid` storage. Replace `tests/fixtures/sources/debian-tracker/repo/data/{CVE,DSA,DLA}/list`.
- [ ] **Effect on real scans.** `uv run secmonk scan docker-image python:3.12-slim --db /tmp/t.db; uv run secmonk findings --hide-minor --db /tmp/t.db | wc -l` vs the 2026-11-07 baseline (193 findings, 46 *unimportant*; [matching.md](../tech/engine/matching.md)).
  Record the new counts there. Run on bookworm and trixie images.

## 2. OSV and the other bulk feeds

- [ ] **`api.osv.dev`** reachable? `curl -s https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q | jq .id; curl -s -d '{"package":{"name":"jinja2","ecosystem":"PyPI"},"version":"2.4.1"}' https://api.osv.dev/v1/query | jq '.vulns|length'`.
  Verify field parity with the bulk records (no `modified_id.csv` needed); decide on an online fallback (`/v1/querybatch`) for single-package scans in [osv.md](../references/vuln-sources/osv.md).
- [ ] **Full multi-ecosystem OSV sync: size and time** (default set ~434 MB download estimate; Ubuntu 809 MB; Chainguard 1.17 GB; Wolfi 309 MB).
  ```bash
  /usr/bin/time -v uv run secmonk sync osv -e PyPI -e npm -e Maven -e Go -e crates.io -e RubyGems -e NuGet -e Packagist -e Debian -e Alpine -e "Red Hat" -e "Rocky Linux" -e AlmaLinux --db /tmp/osv.db 2>&1 | egrep 'Elapsed|Maximum resident'
  ls -lh /tmp/osv.db; uv run secmonk sync osv -e PyPI --db /tmp/osv.db      # delta: should take seconds and touch few rows
  ```
  Verify against estimates in [osv.md](../references/vuln-sources/osv.md) (0.6-1 GB SQLite; 1.5 GB JSON): record real numbers; peak RSS; delta correctness (`modified_id.csv` newest-first, cursor, withdrawn removal; full-sync fallback thresholds).
- [ ] **Ubuntu OSV (809 MB) sizing and record shape.**
  ```bash
  curl -sI https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip | grep -i content-length
  /usr/bin/time -v uv run secmonk sync osv -e Ubuntu --db /tmp/ubu.db 2>&1 | egrep 'Elapsed|Maximum resident'
  sqlite3 /tmp/ubu.db "select json_extract(extra,'$.raw_ecosystem'),count(*) from affected where ecosystem like 'Ubuntu%' group by 1 order by 2 desc limit 20"
  ```
  Verify: raw ecosystem strings (`Ubuntu:22.04:LTS`, `Ubuntu:Pro:18.04:LTS`, `:Pro:FIPS`?), normalization to `Ubuntu:<ver>`, open-range behaviour, `severity` priority-word, size on disk. Decision: default-off vs on. Feeds [next-sources.md](next-sources.md) Ubuntu CVE tracker.
- [ ] **Sample Wolfi, Chainguard, SUSE, openSUSE, Mageia, openEuler, Azure Linux** (stream the first N entries, do not download 1 GB):
  ```bash
  for e in Wolfi Chainguard SUSE openSUSE Mageia openEuler "Azure Linux" Echo MinimOS Root; do
    curl -s -r 0-4000000 "https://osv-vulnerabilities.storage.googleapis.com/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$e")/all.zip" -o /tmp/z.part && unzip -l /tmp/z.part 2>/dev/null | head -5; done
  uv run secmonk sync osv -e Wolfi --limit 200 --db /tmp/w.db   # simpler: --limit is the debug cap
  ```
  Verify: ecosystem naming, package name = source vs binary, purl types (`pkg:apk/wolfi`, `pkg:rpm/suse`), open-range ratio. Save one real record each as fixture; update [distros.md](../references/vuln-sources/distros.md) table ("Not sampled" cells).
- [ ] **Red Hat OSV source vs binary package naming** (multi-binary advisory) and `Red Hat:enterprise_linux:9::appstream` repo-suffix handling. Pick RHSA-2024:xxxx for a source RPM with many binaries (`kernel`, `openssl`); check `affected[].package.name` and the epoch in versions; run a real UBI9/Rocky9 scan (needs [on-linux-docker.md](on-linux-docker.md)).
- [ ] **GHSA cross-check**: `git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database` (raw/git reachable in the sandbox, API not); compare a GHSA in OSV bulk vs the repo (aliases, severity, `database_specific.github_reviewed`). Unreviewed advisories: see [next-sources.md](next-sources.md).

## 3. EPSS, KEV, NVD, EUVD (prioritization inputs; fixtures are synthetic or mirror-derived)

- [ ] **EPSS** (`api.first.org`, `epss.cyentia.com`).
  ```bash
  curl -s 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228' | jq .
  curl -s https://epss.cyentia.com/epss_scores-current.csv.gz | gunzip | head -4
  curl -sI 'https://api.first.org/data/v1/epss?limit=100000' | head; uv run secmonk sync epss --db /tmp/t.db; sqlite3 /tmp/t.db "select count(*),max(score) from epss"
  ```
  Verify: exact header/comment line (`#model_version:...,score_date:...`), decimal width, daily file size (~250k rows), API max `limit` and rate limits; importer skips `#` lines. Replace the synthetic CSV; update [epss.md](../references/vuln-sources/epss.md) TODO.
- [ ] **KEV official URL** (`www.cisa.gov/.../known_exploited_vulnerabilities.json`) is reachable and `count` == array length; compare with the `cisagov/kev-data` mirror (fallback order in `sources/kev.py`); `uv run secmonk sync kev` message must say which URL served. Check `knownRansomwareCampaignUse` values and `dueDate`. Update [kev.md](../references/vuln-sources/kev.md) (reachable: yes).
- [ ] **NVD API 2.0 with/without API key.**
  ```bash
  curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228' | jq '.vulnerabilities[0].cve | {id,vulnStatus,configurations:(.configurations|length)}'
  curl -s -H "apiKey: $NVD_API_KEY" 'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2026-11-01T00:00:00.000&lastModEndDate=2026-11-05T00:00:00.000&resultsPerPage=2000' | jq '.totalResults'
  /usr/bin/time uv run secmonk sync nvd --since 2026-10-01 --limit 500 --db /tmp/t.db
  ```
  Verify: rate limit (5 req/30 s keyless, 50/30 s with key) and 429 handling; `vulnStatus` values (incl. `Not Scheduled`/`Deferred`); **April-2026 enrichment change**: share of CVEs published after April 2026 with empty `configurations`; the 120-day max window rule for date ranges.
  Replace the synthetic `cve-2021-44228.json` with a real response; update [nvd.md](../references/vuln-sources/nvd.md) and flag the CPE-less fraction in [matching.md](../tech/engine/matching.md).
- [ ] **EUVD** (fields unverified: endpoints, params, envelope, product shape).
  ```bash
  curl -s 'https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities?size=3' | jq .
  curl -s 'https://euvdservices.enisa.europa.eu/api/lastvulnerabilities' | jq '.[0]|keys'
  curl -s 'https://euvdservices.enisa.europa.eu/api/vulnerabilities?page=0&size=2' | jq 'keys'
  curl -s 'https://euvdservices.enisa.europa.eu/api/search?text=log4j&size=2' | jq .
  ```
  Verify: `items`/`total` envelope vs bare array, `aliases` newline-separated string, `enisaIdProduct[]` shape (products with vendor/product/version?), `epss`, `baseScore` types, pagination and rate limits.
  Fix `src/secmonk/sources/euvd.py`, replace `exploited-sample.json`, update [euvd.md](../references/vuln-sources/euvd.md).
- [ ] **CVE List v5 modes untested here**: (a) release zip `all_CVEs_at_midnight.zip` bulk path (no git), (b) `cveawg.mitre.org/api/cve/<id>`, (c) the **sparse-git `sync cvelist --since`** mode over a long period, (d) `delta.json` polling.
  ```bash
  curl -sL -o /tmp/cves.zip https://github.com/CVEProject/cvelistV5/releases/latest/download/$(date +%Y-%m-%d)_all_CVEs_at_midnight.zip.zip   # name varies, check the release page
  uv run secmonk sync cvelist --path /tmp/cves-extracted --db /tmp/c.db
  time uv run secmonk sync cvelist --since 2018 --db /tmp/c2.db; du -sh ~/.cache/secmonk 2>/dev/null
  ```
  Verify: timings and sizes vs the sandbox numbers in [cvelist-v5.md](../references/vuln-sources/cvelist-v5.md) (2025 set: 45,479 records); importer idempotent with `dateUpdated`.

## 4. Microsoft, Homebrew, distro tracker hosts

- [ ] **MSRC CVRF v3 schema validation (synthetic fixture so far).**
  ```bash
  curl -s -H 'Accept: application/json' https://api.msrc.microsoft.com/cvrf/v3.0/updates | jq '.value[0]'
  curl -s -H 'Accept: application/json' https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug -o /tmp/2024-Aug.json; ls -lh /tmp/2024-Aug.json
  jq '.Vulnerability[]|select(.CVE=="CVE-2024-38063")|.Remediations[]|{Type,Description:.Description.Value,FixedBuild,Supercedence,ProductID}' /tmp/2024-Aug.json | head -40
  jq '.ProductTree|keys' /tmp/2024-Aug.json
  ```
  Verify: `FixedBuild` really exists (and its position), `ProductTree` flat vs nested `Branch`, `Supercedence` text, CVSS fields, `Threats`; `Accept` header requirement; whole-history sync size. Fix `src/secmonk/sources/msrc.py`,
  replace `cvrf-2024-Aug.synthetic.json`, flip [msrc.md](../references/vuln-sources/msrc.md) `status: blocked` -> `implemented`. The Windows end-to-end is in [on-windows.md](on-windows.md) section D.
- [ ] **formulae.brew.sh API + Homebrew analytics** (blocked in sandbox; shape taken from brew source).
  ```bash
  curl -s https://formulae.brew.sh/api/formula/jq.json | jq 'keys'
  curl -s https://formulae.brew.sh/api/formula.json | jq 'length'
  curl -s https://formulae.brew.sh/api/analytics/install-on-request/365d.json | jq '.items[:20]'
  curl -s https://formulae.brew.sh/api/advisories.json | jq 'length'
  ```
  Verify: `installed[]`-free API shape (`versions.stable`, `revision`, `urls.stable.url`, `tap_git_head`, `ruby_source_path`, `patch` info), advisories feed shape. Use the install-weighted analytics to re-pick the popular formula set (197 hand-picked so far) and re-measure `brew_cpe_seed` coverage; update [references/homebrew.md](../references/homebrew.md) (`reachable`).
- [ ] **Re-probe the four blocked distro hosts** (Alpine secdb, Red Hat Security Data API, Red Hat CSAF/VEX, Debian tracker): record HTTP code, a real sample, rate limits in [distros.md](../references/vuln-sources/distros.md); samples go to `tests/fixtures/sources/<name>/real/` (they are inputs for [next-sources.md](next-sources.md) items - do **not** build the importers here).
  ```bash
  curl -s https://secdb.alpinelinux.org/v3.20/main.json | jq '.packages[0], (.packages|length)'
  curl -s https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-3094.json | jq '.vulnerabilities[0].product_status|keys'
  curl -s 'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-44228.json' | jq 'keys'
  ```
- [ ] **Ubuntu `ubuntu.com` JSON API availability** (reachable from the dev sandbox on 2026-11-07 for `cves.json`/`notices.json`; per-CVE `.json` flaky 503/000): measure from an open network: `time curl -s 'https://ubuntu.com/security/cves.json?limit=100&offset=0' | jq '.cves|length'`; rate limit / pagination for a full crawl (~15 k+ CVEs). Input to [next-sources.md](next-sources.md) Ubuntu.

## 5. Wrap-up

- [ ] Fill `reachable:` / `sample:` in each `references/vuln-sources/*.md` frontmatter; add a "Validated YYYY-MM-DD from <network>" line per source; update the table in [references/vuln-sources/README.md](../references/vuln-sources/README.md) (❌ -> ✅); regenerate INDEX.
