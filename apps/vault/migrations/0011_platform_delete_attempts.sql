-- Additive only. When the cron last tried to delete a subject marked
-- deleting, NULL until it first tries: the sweep takes the subjects it has
-- tried least recently first, so subjects that keep failing never block the
-- rest of the queue.
ALTER TABLE managed_workspaces ADD COLUMN delete_attempted_at INTEGER;
CREATE INDEX managed_workspaces_deleting ON managed_workspaces(status, delete_attempted_at, created_at);
