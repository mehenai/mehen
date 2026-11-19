-- Additive only. The operator console in the web app:
-- - the operator role on an account, set and cleared only by the operator
--   script (an explicit operator: actor and a fresh operation id, like
--   can_create_workspaces), whose trigger writes the operator event and the
--   account's notice in the same statement;
-- - a platform's admins, added and removed by the operator, each change
--   kept as a row (ended, never deleted) and recorded in platform_events;
-- - removing a platform: when it was asked and by whom, and once its
--   subjects are purged, the slug it had, freed for a new registration
--   while the row, its keys, its events and its subjects' tombstones stay.

ALTER TABLE accounts ADD COLUMN is_operator INTEGER NOT NULL DEFAULT 0 CHECK (is_operator IN (0,1));
ALTER TABLE accounts ADD COLUMN is_operator_op TEXT;
ALTER TABLE accounts ADD COLUMN is_operator_by TEXT CHECK (is_operator_by IS NULL OR is_operator_by GLOB 'operator:?*');

CREATE TRIGGER account_operator_role
AFTER UPDATE OF is_operator ON accounts
WHEN OLD.is_operator IS NOT NEW.is_operator
BEGIN
  SELECT CASE WHEN NEW.is_operator_by IS NOT NULL THEN 1 ELSE RAISE(ABORT,'explicit operator actor required') END;
  SELECT CASE WHEN NEW.is_operator_op IS NOT NULL AND NEW.is_operator_op IS NOT OLD.is_operator_op THEN 1 ELSE RAISE(ABORT,'fresh operator operation required') END;
  INSERT INTO account_events(id,account,at,action,detail)
  VALUES ('evt_' || lower(hex(randomblob(16))),NEW.id,CAST(unixepoch('subsec')*1000 AS INTEGER),
    CASE NEW.is_operator WHEN 1 THEN 'operator.grant_operator' ELSE 'operator.revoke_operator' END,
    json_object('by',NEW.is_operator_by,'operator',NEW.is_operator));
  INSERT INTO account_notices(id,account,kind,payload,at)
  VALUES ('ntc_' || lower(hex(randomblob(16))),NEW.id,'workspace',
    json_object('change','operator_role','operator',NEW.is_operator,'by',NEW.is_operator_by),CAST(unixepoch('subsec')*1000 AS INTEGER));
END;

CREATE TABLE platform_admins (
  id TEXT PRIMARY KEY CHECK (substr(id,1,4)='pad_'),
  platform TEXT NOT NULL REFERENCES platforms(id),
  account TEXT NOT NULL REFERENCES accounts(id),
  added_at INTEGER NOT NULL,
  added_by TEXT NOT NULL CHECK (added_by GLOB 'operator:?*'),
  removed_at INTEGER,
  removed_by TEXT CHECK (removed_by IS NULL OR removed_by GLOB 'operator:?*'),
  CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);
CREATE UNIQUE INDEX platform_admins_live ON platform_admins(platform, account) WHERE removed_at IS NULL;
CREATE INDEX platform_admins_account ON platform_admins(account, platform) WHERE removed_at IS NULL;

ALTER TABLE platforms ADD COLUMN removing_at INTEGER;
ALTER TABLE platforms ADD COLUMN removing_by TEXT CHECK (removing_by IS NULL OR removing_by GLOB 'operator:?*');
ALTER TABLE platforms ADD COLUMN removed_at INTEGER;
-- The slug the platform had, once removed_at is set and slug holds the
-- reserved removed- form.
ALTER TABLE platforms ADD COLUMN removed_slug TEXT;
CREATE INDEX platforms_removing ON platforms(removing_at) WHERE removing_at IS NOT NULL AND removed_at IS NULL;
