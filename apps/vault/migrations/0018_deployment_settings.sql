-- Additive only. What a deployment decides for every account, and reading
-- every operator change in one place:
-- - deployment_settings: one row per setting the operators have set
--   (workspace_creation, signup_mode; the protocol's DEPLOYMENT_SETTINGS),
--   with who set it last. The value in force is this one capped by the
--   deploy's ceiling (WORKSPACE_CREATION, SIGNUP_MODE_MAX); no row means
--   what the deployment did before settings. Every change is also a
--   deployment_events row, so this table holds only the latest.
-- - indexes for the Operator area's Audit view, which reads
--   deployment_events, platform_events and the operator.* rows of
--   account_events newest first, a page at a time.

CREATE TABLE deployment_settings (
  key TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
  value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 64),
  updated_at INTEGER NOT NULL,
  updated_by TEXT NOT NULL CHECK (updated_by GLOB 'operator:?*')
);

CREATE INDEX platform_events_at ON platform_events(at, id);
CREATE INDEX account_events_operator ON account_events(at, id) WHERE action GLOB 'operator.*';
