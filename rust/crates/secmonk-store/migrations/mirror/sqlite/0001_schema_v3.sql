-- Schema v3, mirror database (rust/_docs/tech/data-model.md "Mirror database").
-- v2-compatible superset of src/secmonk/db.py SCHEMA (vulnerability data part): same tables, columns, types.
-- v3 changes: alias.kind NOT NULL DEFAULT 'alias'; index affected(source, vuln_id); table store_meta.

CREATE TABLE source_sync (
    source        TEXT PRIMARY KEY,
    last_sync     TEXT,
    cursor        TEXT,
    records       INTEGER DEFAULT 0,
    status        TEXT,
    message       TEXT
);

CREATE TABLE raw_record (
    source        TEXT NOT NULL,
    record_id     TEXT NOT NULL,
    modified      TEXT,
    fetched_at    TEXT NOT NULL,
    data          TEXT NOT NULL,
    PRIMARY KEY (source, record_id)
);

CREATE TABLE vulnerability (
    source        TEXT NOT NULL,
    id            TEXT NOT NULL,
    summary       TEXT,
    details       TEXT,
    published     TEXT,
    modified      TEXT,
    withdrawn     TEXT,
    state         TEXT,
    severity      TEXT,
    cvss_score    REAL,
    cvss_vector   TEXT,
    cvss_version  TEXT,
    cwes          TEXT,
    extra         TEXT,
    PRIMARY KEY (source, id)
);
CREATE INDEX ix_vuln_id ON vulnerability(id);

CREATE TABLE alias (
    vuln_id       TEXT NOT NULL,
    alias         TEXT NOT NULL,
    source        TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'alias',
    PRIMARY KEY (vuln_id, alias, source)
);
CREATE INDEX ix_alias_alias ON alias(alias);

CREATE TABLE affected (
    rowid_        INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    ecosystem     TEXT,
    package       TEXT,
    purl          TEXT,
    vendor        TEXT,
    product       TEXT,
    cpe           TEXT,
    range_type    TEXT,
    version_type  TEXT,
    events        TEXT,
    versions      TEXT,
    status        TEXT DEFAULT 'affected',
    extra         TEXT
);
CREATE INDEX ix_aff_pkg ON affected(ecosystem, package);
CREATE INDEX ix_aff_prod ON affected(product, vendor);
CREATE INDEX ix_aff_vuln ON affected(vuln_id);
CREATE INDEX ix_aff_source_vuln ON affected(source, vuln_id);

CREATE TABLE kev (
    cve_id        TEXT PRIMARY KEY,
    vendor        TEXT,
    product       TEXT,
    name          TEXT,
    date_added    TEXT,
    due_date      TEXT,
    ransomware    TEXT,
    source        TEXT DEFAULT 'kev',
    extra         TEXT
);

CREATE TABLE epss (
    cve_id        TEXT PRIMARY KEY,
    score         REAL,
    percentile    REAL,
    date          TEXT,
    source        TEXT DEFAULT 'epss'
);

CREATE TABLE distro_triage (
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    status        TEXT,
    urgency       TEXT,
    fixed_version TEXT,
    nodsa         TEXT,
    note          TEXT,
    advisory      TEXT,
    source        TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, cve_id, source)
);
CREATE INDEX ix_triage_cve ON distro_triage(cve_id);

CREATE TABLE store_meta (
    key           TEXT PRIMARY KEY,
    value         TEXT
);
