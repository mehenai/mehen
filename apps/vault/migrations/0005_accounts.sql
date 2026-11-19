-- Alex chose a fresh start: discard the old directory, do not backfill data.
-- DIRECTORY wipes old DO data separately in its cutover class migration.
PRAGMA defer_foreign_keys = true;

DROP TABLE IF EXISTS security_notices;

DROP TABLE IF EXISTS recovery_codes;

DROP TABLE IF EXISTS recovery_batches;

DROP TABLE IF EXISTS passkeys;

DROP TABLE IF EXISTS web_sessions;

DROP TABLE IF EXISTS challenges;

DROP TABLE IF EXISTS invites;

DROP TABLE IF EXISTS oauth_states;

DROP TABLE IF EXISTS enrolments;

DROP TABLE IF EXISTS enrol_nonces;

DROP TABLE IF EXISTS auth_attempts;

DROP TABLE IF EXISTS members;

DROP TABLE IF EXISTS tenants;

CREATE TABLE accounts (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 5 AND 68 AND substr(id,1,4) = 'acc_' AND substr(id,5) NOT GLOB '*[^A-Za-z0-9_-]*'),
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','deleting','deleted')),
  security_epoch INTEGER NOT NULL DEFAULT 0 CHECK (security_epoch >= 0),
  security_transition TEXT,
  restricted_until INTEGER,
  restricted_reason TEXT CHECK (restricted_reason IN ('recovery','reset','break-glass')),
  can_create_workspaces INTEGER NOT NULL DEFAULT 0 CHECK (can_create_workspaces IN (0,1)),
  can_create_workspaces_op TEXT,
  can_create_workspaces_by TEXT CHECK (can_create_workspaces_by IS NULL OR can_create_workspaces_by GLOB 'operator:?*'),
  last_workspace TEXT,
  recovery_setup_at INTEGER,
  recovery_setup_kind TEXT CHECK (recovery_setup_kind IN ('codes','passkey')),
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  CHECK ((restricted_until IS NULL) = (restricted_reason IS NULL)),
  CHECK ((recovery_setup_at IS NULL) = (recovery_setup_kind IS NULL)),
  CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

CREATE TABLE workspaces (
  id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 4 AND 67 AND substr(id,1,3) = 'tn_' AND substr(id,4) NOT GLOB '*[^A-Za-z0-9_-]*'),
  slug TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 3 AND 40 AND slug GLOB '[a-z]*' AND substr(slug,-1) GLOB '[a-z0-9]' AND slug NOT GLOB '*[^a-z0-9-]*' AND slug NOT LIKE '%--%' AND slug NOT LIKE 'legacy-%'),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('creating','active','deleting','deleted')),
  created_by TEXT REFERENCES accounts(id),
  created_at INTEGER NOT NULL,
  delete_after INTEGER,
  display_rev INTEGER NOT NULL DEFAULT 1,
  CHECK (status != 'deleting' OR delete_after IS NOT NULL)
);

CREATE TABLE workspace_slugs (
  slug TEXT PRIMARY KEY NOT NULL CHECK (length(slug) BETWEEN 3 AND 40 AND slug GLOB '[a-z]*' AND substr(slug,-1) GLOB '[a-z0-9]' AND slug NOT GLOB '*[^a-z0-9-]*' AND slug NOT LIKE '%--%' AND slug NOT LIKE 'legacy-%'),
  workspace TEXT NOT NULL REFERENCES workspaces(id),
  retired_at INTEGER NOT NULL
);

CREATE TABLE workspace_slug_reservations (
  id TEXT PRIMARY KEY,
  workspace TEXT NOT NULL UNIQUE REFERENCES workspaces(id),
  new_slug TEXT NOT NULL UNIQUE,
  old_slug TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TRIGGER workspace_slugs_slug_insert BEFORE INSERT ON workspace_slugs
WHEN EXISTS (SELECT 1 FROM workspaces WHERE slug = NEW.slug)
BEGIN
  SELECT RAISE(ABORT, 'name not available');
END;

CREATE TRIGGER workspace_slugs_slug_update BEFORE UPDATE OF slug ON workspace_slugs
WHEN EXISTS (SELECT 1 FROM workspaces WHERE slug = NEW.slug)
BEGIN
  SELECT RAISE(ABORT, 'name not available');
END;

CREATE TRIGGER workspaces_slug_insert BEFORE INSERT ON workspaces
WHEN EXISTS (SELECT 1 FROM workspace_slugs WHERE slug = NEW.slug)
BEGIN
  SELECT RAISE(ABORT, 'name not available');
END;

CREATE TRIGGER workspaces_slug_update BEFORE UPDATE OF slug ON workspaces
WHEN EXISTS (SELECT 1 FROM workspace_slugs WHERE slug = NEW.slug)
BEGIN
  SELECT RAISE(ABORT, 'name not available');
END;

CREATE TABLE memberships (
  id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 5 AND 68 AND substr(id,1,4) = 'mem_' AND substr(id,5) NOT GLOB '*[^A-Za-z0-9_-]*'),
  account TEXT NOT NULL REFERENCES accounts(id),
  workspace TEXT NOT NULL REFERENCES workspaces(id),
  state TEXT NOT NULL CHECK (state IN ('joining','member','left')),
  role_hint TEXT NOT NULL CHECK (role_hint IN ('owner','admin','member','guest')),
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX memberships_live ON memberships(account,workspace) WHERE state != 'left';

CREATE INDEX memberships_workspace ON memberships(workspace,state);

CREATE TABLE account_security_transitions (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  reserved_epoch INTEGER NOT NULL CHECK (reserved_epoch > 0),
  kind TEXT NOT NULL CHECK (kind IN ('factor.remove','sessions.end','recovery.start','recovery.cancel','break-glass','account.delete','identity.unlink')),
  target_restrictions TEXT NOT NULL CHECK (json_valid(target_restrictions)),
  effects TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(effects)),
  commit_restriction TEXT CHECK (commit_restriction IS NULL OR json_valid(commit_restriction)),
  revoked_sessions TEXT NOT NULL CHECK (json_valid(revoked_sessions)),
  removed_factors TEXT NOT NULL CHECK (json_valid(removed_factors)),
  targets TEXT NOT NULL CHECK (json_valid(targets)),
  acknowledged TEXT NOT NULL CHECK (json_valid(acknowledged)),
  state TEXT NOT NULL CHECK (state IN ('pending','committed')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  committed_at INTEGER,
  commit_delivery TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(commit_delivery)),
  next_retry_at INTEGER,
  last_retry_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX account_security_pending ON account_security_transitions(account) WHERE state='pending';

CREATE INDEX account_security_retry ON account_security_transitions(state,next_retry_at);

CREATE TABLE passkeys (
  credential_id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT,
  name TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  handle TEXT NOT NULL UNIQUE,
  aaguid TEXT,
  device_type TEXT CHECK (device_type IN ('singleDevice','multiDevice')),
  backed_up INTEGER,
  added_via TEXT NOT NULL CHECK (added_via IN ('signup','settings','recovery','reset','break-glass')),
  last_used_client TEXT,
  last_used_place TEXT
);

CREATE INDEX passkeys_account ON passkeys(account);

CREATE TABLE web_sessions (
  token_hash TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('web','recovery','app')),
  method TEXT NOT NULL CHECK (method IN ('signup','passkey','recovery','reset')),
  passkey TEXT,
  lineage TEXT CHECK (lineage IS NULL OR json_valid(lineage)),
  client TEXT NOT NULL,
  place TEXT
);

CREATE INDEX web_sessions_account ON web_sessions(account);

CREATE INDEX web_sessions_passkey ON web_sessions(passkey);

CREATE TABLE recovery_codes (
  code_hash TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  batch TEXT NOT NULL,
  position INTEGER NOT NULL CHECK (position BETWEEN 1 AND 10),
  status TEXT NOT NULL CHECK (status IN ('pending','active','used','revoked')),
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by_session TEXT
);

CREATE INDEX recovery_codes_account ON recovery_codes(account);

CREATE INDEX recovery_codes_batch ON recovery_codes(batch);

CREATE TABLE recovery_batches (
  batch TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  confirm_position INTEGER NOT NULL CHECK (confirm_position BETWEEN 1 AND 10),
  tries INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);

CREATE INDEX recovery_batches_account ON recovery_batches(account);

CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  account TEXT REFERENCES accounts(id),
  workspace TEXT,
  security_epoch INTEGER,
  factor TEXT,
  context TEXT,
  expires_at INTEGER NOT NULL
);

CREATE INDEX challenges_expiry ON challenges(expires_at);

CREATE TABLE account_notices (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  kind TEXT NOT NULL CHECK (kind IN ('recovery','reset','break-glass','identity','workspace')),
  source_workspace TEXT REFERENCES workspaces(id),
  source_notice TEXT UNIQUE,
  payload TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload)),
  at INTEGER NOT NULL,
  client TEXT,
  place TEXT,
  restricted_until INTEGER,
  resolved_at INTEGER,
  resolved_by TEXT,
  outcome TEXT CHECK (outcome IN ('cancel','keep','confirmed','removed'))
);

CREATE INDEX account_notices_account ON account_notices(account,resolved_at,at);

CREATE TABLE invite_codes (
  code_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('join','break-glass')),
  workspace TEXT REFERENCES workspaces(id),
  invite TEXT,
  account TEXT REFERENCES accounts(id),
  email TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by_account TEXT REFERENCES accounts(id),
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('pending','active')),
  reservation_expires_at INTEGER,
  CHECK (state!='pending' OR reservation_expires_at IS NOT NULL),
  CHECK ((kind='join' AND workspace IS NOT NULL AND invite IS NOT NULL AND account IS NULL) OR (kind='break-glass' AND account IS NOT NULL AND workspace IS NULL AND invite IS NULL))
);

CREATE INDEX invite_codes_workspace ON invite_codes(workspace);

CREATE TABLE account_events (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  at INTEGER NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL CHECK (json_valid(detail)),
  mirrored_to TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(mirrored_to)),
  targets TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(targets)),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts>=0),
  next_retry_at INTEGER
);

CREATE INDEX account_events_account ON account_events(account,at);
CREATE INDEX account_events_retry ON account_events(COALESCE(next_retry_at,0),at,id);

CREATE TRIGGER account_workspace_allowlist
AFTER UPDATE OF can_create_workspaces ON accounts
WHEN OLD.can_create_workspaces IS NOT NEW.can_create_workspaces
BEGIN
  SELECT CASE WHEN NEW.can_create_workspaces_by IS NOT NULL THEN 1 ELSE RAISE(ABORT,'explicit operator actor required') END;
  SELECT CASE WHEN NEW.can_create_workspaces_op IS NOT NULL AND NEW.can_create_workspaces_op IS NOT OLD.can_create_workspaces_op THEN 1 ELSE RAISE(ABORT,'fresh operator operation required') END;
  INSERT INTO account_events(id,account,at,action,detail)
  VALUES ('evt_' || lower(hex(randomblob(16))),NEW.id,CAST(unixepoch('subsec')*1000 AS INTEGER),
    CASE NEW.can_create_workspaces WHEN 1 THEN 'operator.allow_workspaces' ELSE 'operator.deny_workspaces' END,
    json_object('by',NEW.can_create_workspaces_by,'allowed',NEW.can_create_workspaces));
  INSERT INTO account_notices(id,account,kind,payload,at)
  VALUES ('ntc_' || lower(hex(randomblob(16))),NEW.id,'workspace',
    json_object('change','workspace_creation','allowed',NEW.can_create_workspaces,'by',NEW.can_create_workspaces_by),CAST(unixepoch('subsec')*1000 AS INTEGER));
END;

CREATE TABLE enrolments (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  jwk TEXT NOT NULL,
  thumbprint TEXT NOT NULL,
  name TEXT NOT NULL,
  backend TEXT NOT NULL,
  host TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'rejected', 'expired')),
  tenant TEXT,
  device TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  scope TEXT,
  group_attempts INTEGER NOT NULL DEFAULT 0,
  workspace_intent TEXT NOT NULL,
  owner_intent TEXT NOT NULL CHECK (json_valid(owner_intent)),
  approved_by_account TEXT REFERENCES accounts(id),
  start_at INTEGER NOT NULL,
  start_place TEXT,
  start_client_label TEXT NOT NULL,
  acceptance_digest TEXT,
  accepted_by_account TEXT REFERENCES accounts(id),
  accepted_by_member TEXT,
  accepted_at INTEGER,
  admission_digest TEXT,
  admitted_by_account TEXT REFERENCES accounts(id),
  admitted_at INTEGER,
  pending_state TEXT CHECK (pending_state IN ('pending_owner_acceptance','pending_admission')),
  identity_rule_revision INTEGER,
  gate_generation INTEGER,
  resolved_owner TEXT CHECK (resolved_owner IS NULL OR json_valid(resolved_owner)),
  discard_pending INTEGER NOT NULL DEFAULT 0 CHECK (discard_pending IN (0,1)),
  discard_device TEXT,
  mirror_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (mirror_acknowledged IN (0,1)),
  reconciled_at INTEGER,
  CHECK (discard_pending=0 OR discard_device IS NOT NULL),
  CHECK ((status = 'pending') = (pending_state IS NOT NULL)),
  CHECK ((acceptance_digest IS NULL) = (accepted_by_account IS NULL) AND (acceptance_digest IS NULL) = (accepted_by_member IS NULL) AND (acceptance_digest IS NULL) = (accepted_at IS NULL)),
  CHECK ((admission_digest IS NULL) = (admitted_by_account IS NULL) AND (admission_digest IS NULL) = (admitted_at IS NULL))
);

CREATE INDEX enrolments_pending ON enrolments (status, expires_at);

CREATE INDEX enrolments_thumbprint ON enrolments (thumbprint, status);

CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  connect TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  account TEXT NOT NULL REFERENCES accounts(id),
  membership TEXT NOT NULL,
  initiating_session TEXT NOT NULL,
  security_epoch INTEGER NOT NULL,
  intent TEXT NOT NULL CHECK (intent IN ('create','rotate')),
  target_id TEXT,
  target_revision INTEGER,
  client_id TEXT,
  client_revision INTEGER,
  dependency_revision INTEGER,
  cancelled_at INTEGER
);

CREATE TABLE enrol_nonces (
  id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

CREATE INDEX enrol_nonces_expiry ON enrol_nonces (expires_at);

CREATE TABLE auth_attempts (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);
