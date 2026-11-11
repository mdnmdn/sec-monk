-- Additive (R5): the last row batch applied per source (rust ADR-0010, data-model.md "Mirror database").
-- Written in the same transaction as the batch; a replayed batch (seq <= this) is skipped, so a host stop between
-- apply and source.ack never applies a batch twice (affected rows have no natural key).
CREATE TABLE source_applied (
    source        TEXT PRIMARY KEY,
    seq           INTEGER NOT NULL,
    applied_at    TEXT
);
