-- Follow-up migration; never rewrite the initial 000-007 artifacts.
-- Execute statements under the migration runner exclusive lock.

ALTER TABLE audit_events ALTER COLUMN scope_kind SET NOT NULL;
