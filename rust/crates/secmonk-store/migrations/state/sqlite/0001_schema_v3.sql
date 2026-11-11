-- Schema v3, state database (rust/_docs/tech/data-model.md "State database").
-- v2-compatible superset of src/secmonk/db.py SCHEMA (inventory, findings, run history): same tables, columns, types.
-- v3 additions (nullable or defaulted, R2): scan.partial / partial_reason / job_id; component.product /
-- product_source / bundle_id (+ index); job.log_lines; table store_meta. Promoted columns are written together
-- with their JSON keys (R4). scan.job_id has no foreign key: old job rows are pruned (JOB_KEEP).

CREATE TABLE asset (
    id            TEXT PRIMARY KEY,
    type          TEXT NOT NULL,
    name          TEXT,
    os_name       TEXT,
    os_version    TEXT,
    platform      TEXT,
    meta          TEXT,
    first_seen    TEXT,
    last_seen     TEXT
);

CREATE TABLE scan (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      TEXT NOT NULL REFERENCES asset(id),
    collector     TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    components    INTEGER DEFAULT 0,
    meta          TEXT,
    partial       INTEGER NOT NULL DEFAULT 0,
    partial_reason TEXT,
    job_id        INTEGER
);
CREATE INDEX ix_scan_asset ON scan(asset_id, id);

CREATE TABLE component (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key           TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    version       TEXT,
    category      TEXT NOT NULL,
    ecosystem     TEXT,
    purl          TEXT,
    cpe           TEXT,
    vendor        TEXT,
    meta          TEXT,
    product       TEXT,
    product_source TEXT,
    bundle_id     TEXT
);
CREATE INDEX ix_component_product_source ON component(product_source);

CREATE TABLE asset_component (
    asset_id      TEXT NOT NULL REFERENCES asset(id),
    component_id  INTEGER NOT NULL REFERENCES component(id),
    source_path   TEXT,
    first_seen    TEXT,
    last_seen     TEXT,
    last_scan_id  INTEGER,
    paths         TEXT,
    meta          TEXT,
    PRIMARY KEY (asset_id, component_id)
);

CREATE TABLE finding (
    asset_id      TEXT NOT NULL,
    component_id  INTEGER NOT NULL,
    vuln_id       TEXT NOT NULL,
    advisory_ids  TEXT,
    matched_by    TEXT,
    confidence    REAL,
    fixed_version TEXT,
    severity      TEXT,
    cvss_score    REAL,
    epss          REAL,
    kev           INTEGER DEFAULT 0,
    priority      TEXT,
    status        TEXT DEFAULT 'open',
    first_seen    TEXT,
    last_seen     TEXT,
    fixed_at      TEXT,
    triage        TEXT,
    triage_source TEXT,
    PRIMARY KEY (asset_id, component_id, vuln_id)
);

CREATE TABLE job (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    origin        TEXT NOT NULL,
    title         TEXT,
    params        TEXT,
    status        TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    error         TEXT,
    result        TEXT,
    log           TEXT,
    summary       TEXT,
    owner         TEXT,
    log_lines     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_job_kind ON job(kind, id);

CREATE TABLE store_meta (
    key           TEXT PRIMARY KEY,
    value         TEXT
);
