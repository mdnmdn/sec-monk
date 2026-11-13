-- Additive (R5): mirror-node versions (rust/_docs/tech/data-model.md "Mirror database", node-server-design.md §6).
-- Per-record deltas read `vulnerability` by (source, modified) (proposal §3.2 rule 4).
CREATE INDEX ix_vuln_source_modified ON vulnerability(source, modified);

-- The version a COMPLETE import of the source reached (proposal §3.2 rule 1): written by the engine after an ok run
-- only, so a partial or failed run leaves it where it was. kind: 'record' | 'snapshot'.
CREATE TABLE source_version (
    source        TEXT PRIMARY KEY,
    version       TEXT,
    importer      TEXT,
    kind          TEXT,
    completed_at  TEXT
);

-- Snapshot sources (kev, epss, debian-tracker): what changed between two versions, newest few kept, so a follower
-- one version behind gets a delta instead of the whole snapshot. ids / keys: JSON lists (vulnerability ids, lookup
-- keys such as 'pkg:Debian:12/openssl').
CREATE TABLE snapshot_diff (
    source        TEXT NOT NULL,
    version       TEXT NOT NULL,
    prev_version  TEXT,
    created_at    TEXT NOT NULL,
    ids           TEXT NOT NULL,
    keys          TEXT NOT NULL,
    PRIMARY KEY (source, version)
);
