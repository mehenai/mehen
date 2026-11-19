-- Additive only. The order the cron prunes enrolments that never reached a
-- workspace in (directory/workspace-maintenance.ts): expired, oldest first,
-- so each bounded batch reads its rows from the index instead of sorting
-- the table.
CREATE INDEX IF NOT EXISTS enrolments_settled ON enrolments(status, created_at);
