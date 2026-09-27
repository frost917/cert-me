-- Follow-up migration; never rewrite the initial 000-007 artifacts.
-- Execute statements under the migration runner exclusive lock.

ALTER TABLE audit_events ADD COLUMN scope_kind VARCHAR(32) CONSTRAINT ck_audit_events_scope_kind CHECK (scope_kind IN ('installation','authorities'));
