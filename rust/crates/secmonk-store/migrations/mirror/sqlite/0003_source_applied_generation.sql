-- Additive (R5): the staging generation the applied seq belongs to (rust ADR-0010, data-model.md "Mirror database").
-- Seqs compare only within one generation of the module's staging database: a batch of another generation (staging
-- recreated) is never skipped, the source is repaired from source.export instead. NULL = recorded before W4.4 (one
-- repair on the first generation-aware sync).
ALTER TABLE source_applied ADD COLUMN generation TEXT;
