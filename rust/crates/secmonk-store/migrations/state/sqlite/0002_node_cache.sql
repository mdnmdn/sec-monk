-- Additive (R5): the match-service cache of a state node (rust/_docs/tech/data-model.md "State database",
-- node-server-design.md §6). Keyed by component key (`component.key`), no foreign key: rows are replaced whole per
-- key and outlive a component's removal until replaced.

-- The complete match set of a component key. A component that matched nothing is one row with vuln_id = ''
-- ("answered, no match"), so "never asked" and "asked, nothing" differ. as_of: JSON {"matcher", "since"}.
CREATE TABLE component_match (
    component_key TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    advisory_ids  TEXT,
    matched_by    TEXT,
    confidence    REAL,
    fixed_version TEXT,
    triage        TEXT,
    triage_source TEXT,
    as_of         TEXT,
    PRIMARY KEY (component_key, vuln_id)
);

-- The lookup keys ('pkg:<ecosystem>/<package>', 'prod:<product>') the match used: a changed key re-matches the component.
CREATE TABLE component_lookup (
    component_key TEXT NOT NULL,
    lookup_key    TEXT NOT NULL,
    PRIMARY KEY (component_key, lookup_key)
);
CREATE INDEX ix_component_lookup_key ON component_lookup(lookup_key);

-- Summaries fetched from a remote mirror (state-only node); data: JSON of the summary.
CREATE TABLE vuln_summary (
    id            TEXT PRIMARY KEY,
    data          TEXT NOT NULL,
    fetched_at    TEXT NOT NULL
);

-- Small named values of the node's sync with an upstream (the last `since` map).
CREATE TABLE node_sync (
    name          TEXT PRIMARY KEY,
    value         TEXT
);
