#!/usr/bin/env bash
# Probe every external endpoint sec-monk's docs depend on and print one status line each.
# Read-only: HEAD requests, or a 1-byte range GET (R) where a server rejects HEAD. No downloads.
# Documented in _docs/references/probes.md. Usage:
#   scripts/probe_sources.sh [group]      group = vuln | registry | vendor (default: all)
#   TIMEOUT=20 scripts/probe_sources.sh   per-request timeout in seconds (default 15)
# Output: "<code> <group> <label> <url>"; code 000 = no connection (DNS/proxy/firewall), 403 from a
# sandbox proxy = blocked by egress policy. Honours HTTPS_PROXY / CA bundle settings of the shell.
set -u
TIMEOUT="${TIMEOUT:-15}"
ONLY="${1:-all}"
UA="secmonk-probe/1 (read-only)"

# group|method(H=HEAD,R=range GET)|label|url
ENDPOINTS='
vuln|H|cvelist raw record|https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/44xxx/CVE-2021-44228.json
vuln|H|cvelist delta.json|https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json
vuln|H|cvelist deltaLog.json|https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json
vuln|R|cvelist git (smart HTTP)|https://github.com/CVEProject/cvelistV5.git/info/refs?service=git-upload-pack
vuln|H|cvelist release zips|https://github.com/CVEProject/cvelistV5/releases
vuln|H|CVE Services API|https://cveawg.mitre.org/api/cve/CVE-2021-44228
vuln|H|GitHub REST API|https://api.github.com/repos/CVEProject/cvelistV5
vuln|H|OSV ecosystems.txt|https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
vuln|H|OSV PyPI all.zip|https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
vuln|H|OSV PyPI modified_id.csv|https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv
vuln|H|OSV Debian all.zip|https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip
vuln|H|OSV Alpine all.zip|https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip
vuln|H|OSV single record|https://osv-vulnerabilities.storage.googleapis.com/Maven/GHSA-jfh8-c2jp-5v3q.json
vuln|H|OSV API (api.osv.dev)|https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q
vuln|H|GHSA raw advisory|https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json
vuln|R|GHSA git (smart HTTP)|https://github.com/github/advisory-database.git/info/refs?service=git-upload-pack
vuln|H|KEV cisa.gov|https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
vuln|H|KEV GitHub mirror|https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
vuln|H|EPSS bulk|https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
vuln|H|EPSS API|https://api.first.org/data/v1/epss?cve=CVE-2021-44228
vuln|H|NVD CVE API 2.0|https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
vuln|H|NVD mirror (fkie-cad)|https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-2026/CVE-2026-174xx/CVE-2026-17406.json
vuln|H|EUVD API|https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities?size=1
vuln|H|MSRC CVRF updates|https://api.msrc.microsoft.com/cvrf/v3.0/updates
vuln|H|Debian tracker JSON|https://security-tracker.debian.org/tracker/data/json
vuln|R|Debian tracker git (salsa)|https://salsa.debian.org/security-tracker-team/security-tracker.git/info/refs?service=git-upload-pack
vuln|R|Ubuntu CVE list|https://ubuntu.com/security/cves.json?limit=1
vuln|R|Ubuntu notices|https://ubuntu.com/security/notices.json?limit=1
vuln|H|Alpine secdb|https://secdb.alpinelinux.org/v3.20/main.json
vuln|H|Red Hat Security Data API|https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-44228.json
vuln|H|Red Hat CSAF VEX|https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-44228.json
registry|H|Docker Hub /v2/|https://registry-1.docker.io/v2/
registry|R|Docker Hub token|https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull
registry|R|mirror.gcr.io /v2/|https://mirror.gcr.io/v2/
registry|R|ghcr.io /v2/|https://ghcr.io/v2/
registry|R|ghcr.io token|https://ghcr.io/token?scope=repository:homebrew/core/jq:pull
registry|R|public.ecr.aws token|https://public.ecr.aws/token/?scope=repository:docker/library/rockylinux:pull
registry|H|quay.io /v2/|https://quay.io/v2/
registry|H|registry.access.redhat.com /v2/|https://registry.access.redhat.com/v2/
registry|H|Homebrew bottle blobs host|https://pkg-containers.githubusercontent.com/
registry|H|PyPI JSON API|https://pypi.org/pypi/requests/2.25.0/json
registry|R|PyPI files host|https://files.pythonhosted.org/
registry|H|npm registry|https://registry.npmjs.org/lodash/4.17.20
registry|H|crates.io sparse index|https://index.crates.io/sm/al/smallvec
registry|H|Maven Central|https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom
registry|H|Go module proxy|https://proxy.golang.org/golang.org/x/text/@v/v0.3.7.info
registry|H|NuGet index|https://api.nuget.org/v3/index.json
registry|H|Packagist|https://repo.packagist.org/p2/guzzlehttp/guzzle.json
vendor|H|Homebrew formula API|https://formulae.brew.sh/api/formula/jq.json
vendor|H|homebrew-core raw formula|https://raw.githubusercontent.com/Homebrew/homebrew-core/main/Formula/j/jq.rb
vendor|H|homebrew advisory-database|https://raw.githubusercontent.com/Homebrew/advisory-database/main/data/repology.json
vendor|H|Repology|https://repology.org/api/v1/project/jq
vendor|H|NVD web|https://nvd.nist.gov/
vendor|H|ENISA EUVD web|https://euvd.enisa.europa.eu/
vendor|H|Debian site|https://www.debian.org/security/
vendor|H|GitHub HTML|https://github.com/CVEProject/cvelistV5
'

printf '%s\n' "$ENDPOINTS" | while IFS='|' read -r group method label url; do
  [ -z "${url:-}" ] && continue
  [ "$ONLY" != all ] && [ "$ONLY" != "$group" ] && continue
  if [ "$method" = R ]; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -r 0-0 -A "$UA" "$url" 2>/dev/null)
  else
    code=$(curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -I -A "$UA" "$url" 2>/dev/null)
  fi
  printf '%s %s %s %s\n' "${code:-000}" "$group" "$label" "$url"
done
