-- The global directory. No secrets: which tenant a member and a passkey
-- belong to, web sessions, invites, single-use challenges, pending device
-- enrolments and OAuth state values. Tokens and codes are stored hashed.

CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE members (
  id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL REFERENCES tenants (id),
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX members_tenant ON members (tenant);

CREATE TABLE passkeys (
  credential_id TEXT PRIMARY KEY,
  member TEXT NOT NULL REFERENCES members (id),
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT,
  name TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX passkeys_member ON passkeys (member);

CREATE TABLE web_sessions (
  token_hash TEXT PRIMARY KEY,
  member TEXT NOT NULL REFERENCES members (id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX web_sessions_member ON web_sessions (member);

CREATE TABLE invites (
  code_hash TEXT PRIMARY KEY,
  tenant TEXT,
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  created_by TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by TEXT
);

CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  member TEXT,
  context TEXT,
  expires_at INTEGER NOT NULL
);

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
  expires_at INTEGER NOT NULL
);

CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  connect TEXT NOT NULL,
  member TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
