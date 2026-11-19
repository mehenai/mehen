-- Additive only. Platform mode: a business the operator registered (a
-- platform), its keys, one managed workspace per subject it names, and the
-- record of what the operator and the platform did. None of it holds a
-- secret: a platform key row is the public half, and a subject's secrets
-- live in its own workspace object.
CREATE TABLE platforms (
  id TEXT PRIMARY KEY CHECK (substr(id,1,4)='plt_' AND length(id) BETWEEN 8 AND 68 AND substr(id,5) NOT GLOB '*[^A-Za-z0-9_-]*'),
  slug TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 3 AND 40 AND slug GLOB '[a-z]*' AND slug NOT GLOB '*[^a-z0-9-]*' AND slug NOT LIKE '%--%'),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  status TEXT NOT NULL CHECK (status IN ('active','suspended','retiring','retired')),
  -- PlatformLimits, set by the operator.
  limits TEXT NOT NULL CHECK (json_valid(limits)),
  -- PlatformDefaults, set by the platform.
  defaults TEXT NOT NULL CHECK (json_valid(defaults)),
  defaults_rev INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL CHECK (created_by GLOB 'operator:?*'),
  status_at INTEGER NOT NULL,
  status_by TEXT NOT NULL CHECK (status_by GLOB 'operator:?*' OR status_by='system'),
  status_reason TEXT,
  retire_after INTEGER,
  CHECK ((status='retiring') = (retire_after IS NOT NULL))
);

CREATE TABLE platform_keys (
  id TEXT PRIMARY KEY CHECK (substr(id,1,4)='pky_'),
  platform TEXT NOT NULL REFERENCES platforms(id),
  jwk TEXT NOT NULL CHECK (json_valid(jwk)),
  thumbprint TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  -- Set when the key is rotated out: refused from then on.
  expires_at INTEGER,
  revoked_at INTEGER,
  revoked_by TEXT
);
CREATE INDEX platform_keys_platform ON platform_keys(platform);

CREATE TABLE managed_workspaces (
  tenant TEXT PRIMARY KEY CHECK (substr(tenant,1,3)='tn_'),
  platform TEXT NOT NULL REFERENCES platforms(id),
  -- NULL once purged; subject_hash (SHA-256 of platform, newline, subject)
  -- stays as the tombstone.
  subject TEXT,
  subject_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('creating','active','deleting','deleted','purged')),
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  purge_after INTEGER,
  final_audit_head TEXT
);
CREATE UNIQUE INDEX managed_workspaces_live ON managed_workspaces(platform, subject) WHERE status IN ('creating','active','deleting');
CREATE INDEX managed_workspaces_due ON managed_workspaces(status, purge_after);
CREATE INDEX managed_workspaces_platform ON managed_workspaces(platform, tenant);

CREATE TABLE platform_events (
  id TEXT PRIMARY KEY,
  platform TEXT NOT NULL REFERENCES platforms(id),
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL CHECK (json_valid(detail))
);
CREATE INDEX platform_events_platform ON platform_events(platform, at);
