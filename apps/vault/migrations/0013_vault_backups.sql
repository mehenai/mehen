-- Additive only. The operator's backup of every workspace object
-- (docs/OPERATIONS.md, Backup and recovery):
-- - vault_backup_runs: one row per workspace and UTC date, written by the
--   cron after it asks the object to dump itself to VAULT_BACKUPS at
--   ws/<tenant>/<date>.bin; bytes and sha256 are the R2 object's, which the
--   operator's weekly pull checks every copy against. A failed run is tried
--   again on later runs that day; an ok one is never changed.
-- - vault_restore_intents: a restore the operator script records, after the
--   tenant id is typed back, with a digest over every field; the cron checks
--   the digest in every state (it catches accidental edits only: anyone who
--   can write this table can compute it) and carries it out (pitr: a Durable Object bookmark, kept with
--   the undo bookmark; dump: a day's dump into an empty object). Holds no
--   secret and no plaintext.

CREATE TABLE vault_backup_runs (
  tenant TEXT NOT NULL REFERENCES workspaces(id),
  date TEXT NOT NULL CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
  outcome TEXT NOT NULL CHECK (outcome IN ('ok','failed')),
  bytes INTEGER,
  sha256 TEXT CHECK (sha256 IS NULL OR (length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
  root_version INTEGER,
  error TEXT,
  attempts INTEGER NOT NULL DEFAULT 1,
  attempted_at INTEGER NOT NULL,
  PRIMARY KEY (tenant, date),
  CHECK ((outcome='ok') = (bytes IS NOT NULL AND sha256 IS NOT NULL AND root_version IS NOT NULL)),
  CHECK ((outcome='failed') = (error IS NOT NULL))
);
CREATE INDEX vault_backup_runs_date ON vault_backup_runs(date, outcome);

CREATE TABLE vault_restore_intents (
  id TEXT PRIMARY KEY CHECK (length(id)=36 AND substr(id,1,4)='vri_' AND substr(id,5) NOT GLOB '*[^0-9a-f]*'),
  tenant TEXT NOT NULL REFERENCES workspaces(id),
  source TEXT NOT NULL CHECK (source IN ('pitr','dump')),
  target TEXT NOT NULL,
  actor TEXT NOT NULL CHECK (actor GLOB 'operator:?*'),
  intent_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','restarting','done','failed','expired')),
  bookmark TEXT,
  undo_bookmark TEXT,
  error TEXT,
  completed_at INTEGER,
  CHECK (expires_at=created_at+3600000),
  CHECK (source!='dump' OR target GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
);
CREATE INDEX vault_restore_intents_state ON vault_restore_intents(state, created_at);
CREATE UNIQUE INDEX vault_restore_intents_live ON vault_restore_intents(tenant) WHERE state IN ('pending','restarting');
