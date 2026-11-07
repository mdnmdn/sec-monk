"""CISA Known Exploited Vulnerabilities (KEV) source.

Spec: _docs/references/vuln-sources/kev.md. The feed is a small full snapshot, so every sync
replaces the whole `kev` table. The feed's `catalogVersion` is returned as the cursor.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import httpx

from ..db import dumps, transaction
from .base import Source, SyncOptions, SyncResult, http_client, register, store_raw

OFFICIAL_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
)

# Fields with a dedicated column; everything else is kept in `kev.extra`.
_MAPPED = {
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
    "knownRansomwareCampaignUse",
}

_INSERT = """INSERT OR REPLACE INTO kev
    (cve_id, vendor, product, name, date_added, due_date, ransomware, source, extra)
    VALUES (?,?,?,?,?,?,?,'kev',?)"""


def _download(url: str) -> Any:
    with http_client(timeout=60.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _load(opts: SyncOptions) -> tuple[dict[str, Any], str]:
    """Return (feed document, human-readable origin). Official feed first, mirror on any error."""
    if opts.path:
        return json.loads(Path(opts.path).read_text(encoding="utf-8")), f"from file {opts.path}"
    try:
        return _download(OFFICIAL_URL), f"from {OFFICIAL_URL}"
    except (httpx.HTTPError, OSError, ValueError) as official_err:  # fall back to the GitHub mirror
        opts.log(f"kev: official feed failed ({official_err}); trying mirror")
        doc = _download(MIRROR_URL)
        return doc, f"from mirror {MIRROR_URL} (official failed: {official_err})"


@register
class KevSource(Source):
    name = "kev"
    description = "CISA Known Exploited Vulnerabilities catalog (full snapshot)"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        try:
            doc, origin = _load(opts)
            entries = doc["vulnerabilities"]
            if doc.get("count") not in (None, len(entries)):
                opts.log(f"kev: feed count {doc.get('count')} != {len(entries)} entries; using entries")

            with transaction(conn):
                conn.execute("DELETE FROM kev")
                for e in entries:
                    cve = e["cveID"]
                    store_raw(conn, self.name, cve, e, modified=e.get("dateAdded"))
                    conn.execute(_INSERT, (
                        cve,
                        e.get("vendorProject"),
                        e.get("product"),
                        e.get("vulnerabilityName"),
                        e.get("dateAdded"),
                        e.get("dueDate"),
                        1 if e.get("knownRansomwareCampaignUse") == "Known" else 0,
                        dumps({k: v for k, v in e.items() if k not in _MAPPED}),
                    ))
        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            return SyncResult(self.name, status="error", message=str(e))

        return SyncResult(
            self.name,
            records=len(entries),
            status="ok",
            cursor=doc.get("catalogVersion"),
            message=f"{len(entries)} entries {origin}",
        )
