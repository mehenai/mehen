-- Sign-in beyond one passkey: named and described passkeys, recovery
-- codes, sessions with metadata, member status and restriction, reset
-- links, security notices and attempt counters.

-- Passkeys: a public handle, what the authenticator said, where it was last used.
ALTER TABLE passkeys ADD COLUMN handle TEXT;
UPDATE passkeys SET handle = 'pk_' || lower(hex(randomblob(10))) WHERE handle IS NULL;
CREATE UNIQUE INDEX passkeys_handle ON passkeys (handle);
-- Code from before 0004 still runs for a few minutes after it is applied
-- and inserts passkeys without a handle: give them one in the same shape
-- directoryId("pk") makes, 20 lower-case hex digits.
CREATE TRIGGER passkeys_fill_handle AFTER INSERT ON passkeys WHEN NEW.handle IS NULL
BEGIN
  UPDATE passkeys SET handle = 'pk_' || lower(hex(randomblob(10))) WHERE credential_id = NEW.credential_id;
END;
ALTER TABLE passkeys ADD COLUMN aaguid TEXT;
ALTER TABLE passkeys ADD COLUMN device_type TEXT CHECK (device_type IN ('singleDevice', 'multiDevice'));
ALTER TABLE passkeys ADD COLUMN backed_up INTEGER;
ALTER TABLE passkeys ADD COLUMN added_via TEXT NOT NULL DEFAULT 'signup' CHECK (added_via IN ('signup', 'settings', 'recovery', 'reset', 'break-glass'));
ALTER TABLE passkeys ADD COLUMN last_used_client TEXT;
ALTER TABLE passkeys ADD COLUMN last_used_place TEXT;

-- Sessions: an id for the list, a kind, how it was opened, from where.
ALTER TABLE web_sessions ADD COLUMN id TEXT;
UPDATE web_sessions SET id = 'ses_' || lower(hex(randomblob(10))) WHERE id IS NULL;
CREATE UNIQUE INDEX web_sessions_id ON web_sessions (id);
-- The same for sessions opened by code from before 0004.
CREATE TRIGGER web_sessions_fill_id AFTER INSERT ON web_sessions WHEN NEW.id IS NULL
BEGIN
  UPDATE web_sessions SET id = 'ses_' || lower(hex(randomblob(10))) WHERE token_hash = NEW.token_hash;
END;
ALTER TABLE web_sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'web' CHECK (kind IN ('web', 'recovery', 'app'));
ALTER TABLE web_sessions ADD COLUMN method TEXT NOT NULL DEFAULT 'passkey' CHECK (method IN ('signup', 'passkey', 'recovery', 'reset'));
ALTER TABLE web_sessions ADD COLUMN passkey TEXT;
ALTER TABLE web_sessions ADD COLUMN client TEXT NOT NULL DEFAULT 'A browser';
ALTER TABLE web_sessions ADD COLUMN place TEXT;
CREATE INDEX web_sessions_passkey ON web_sessions (passkey);

-- Members: confirmed or not, removed, and the cooling-off after a recovery.
ALTER TABLE members ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('unconfirmed', 'active', 'removed'));
ALTER TABLE members ADD COLUMN restricted_until INTEGER;
ALTER TABLE members ADD COLUMN restricted_reason TEXT CHECK (restricted_reason IN ('recovery', 'reset', 'break-glass'));

-- Invites: a join (as today) or a reset of one member's sign-in.
ALTER TABLE invites ADD COLUMN kind TEXT NOT NULL DEFAULT 'join' CHECK (kind IN ('join', 'reset'));
ALTER TABLE invites ADD COLUMN member TEXT;

-- Recovery codes, hashed. A batch is pending until one code is typed back.
CREATE TABLE recovery_codes (
  code_hash TEXT PRIMARY KEY,
  member TEXT NOT NULL REFERENCES members (id),
  batch TEXT NOT NULL,
  position INTEGER NOT NULL CHECK (position BETWEEN 1 AND 10),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'used', 'revoked')),
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by_session TEXT
);
CREATE INDEX recovery_codes_member ON recovery_codes (member, status);
CREATE INDEX recovery_codes_batch ON recovery_codes (batch);

-- The confirmation a pending batch waits for, and how many tries are left.
CREATE TABLE recovery_batches (
  batch TEXT PRIMARY KEY,
  member TEXT NOT NULL REFERENCES members (id),
  confirm_position INTEGER NOT NULL CHECK (confirm_position BETWEEN 1 AND 10),
  tries INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);

-- Wrong recovery codes per client network per hour.
CREATE TABLE auth_attempts (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);

-- What every member, and every agent, is told about.
CREATE TABLE security_notices (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL REFERENCES tenants (id),
  member TEXT NOT NULL REFERENCES members (id),
  kind TEXT NOT NULL CHECK (kind IN ('recovery', 'reset', 'break-glass', 'join')),
  at INTEGER NOT NULL,
  client TEXT,
  place TEXT,
  restricted_until INTEGER,
  resolved_at INTEGER,
  resolved_by TEXT,
  outcome TEXT CHECK (outcome IN ('cancel', 'keep', 'confirmed', 'removed'))
);
CREATE INDEX security_notices_tenant ON security_notices (tenant, resolved_at);
-- The open notice behind a member's cooling-off, newest first, for sessionInfo.
CREATE INDEX security_notices_member ON security_notices (member, kind, resolved_at, at);
