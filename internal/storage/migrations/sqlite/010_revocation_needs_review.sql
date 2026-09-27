-- Follow-up migration; never rewrite the initial 000-007 artifacts.
-- Execute statements under the migration runner exclusive lock.

ALTER TABLE revocations ADD COLUMN needs_review INTEGER NOT NULL DEFAULT 0 CHECK (needs_review IN (0,1));
