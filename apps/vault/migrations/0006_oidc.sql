-- First-release OIDC schema, applied after the fresh-start account directory.
-- Release one has no refresh tokens, envelopes or background gates.
CREATE TABLE oidc_identities (
 id TEXT PRIMARY KEY, account TEXT NOT NULL REFERENCES accounts(id), provider TEXT NOT NULL CHECK (provider='google'),
 issuer TEXT NOT NULL CHECK (issuer='https://accounts.google.com'), subject TEXT NOT NULL,
 email TEXT NOT NULL, domain TEXT, name TEXT, email_verified INTEGER NOT NULL CHECK (email_verified=1),
 linked_at INTEGER NOT NULL, last_verified_at INTEGER NOT NULL, UNIQUE(issuer,subject)
);
CREATE INDEX oidc_identities_account ON oidc_identities(account);
CREATE TABLE oidc_flows (
 state_hash TEXT PRIMARY KEY, cookie_hash TEXT NOT NULL, provider TEXT NOT NULL CHECK (provider='google'),
 purpose TEXT NOT NULL CHECK (purpose IN ('signin','invite','link','gate')), account TEXT REFERENCES accounts(id),
 session TEXT, security_epoch INTEGER, invite_hash TEXT, workspace TEXT REFERENCES workspaces(id),
 rule_revision INTEGER, gate_generation INTEGER, nonce TEXT NOT NULL, pkce_verifier TEXT NOT NULL,
 next_path TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 app_session_hash TEXT, app_pkce_challenge TEXT, app_launched_at INTEGER, check_context TEXT CHECK (check_context IS NULL OR json_valid(check_context)), consumed_at INTEGER,
 CHECK (purpose != 'gate' OR (workspace IS NOT NULL AND rule_revision IS NOT NULL AND gate_generation IS NOT NULL)),
 CHECK (purpose != 'link' OR (account IS NOT NULL AND session IS NOT NULL AND security_epoch IS NOT NULL)),
 CHECK (purpose != 'invite' OR invite_hash IS NOT NULL),
 CHECK ((app_session_hash IS NULL AND app_pkce_challenge IS NULL) OR (purpose='gate' AND app_session_hash IS NOT NULL AND app_pkce_challenge IS NOT NULL))
);
CREATE INDEX oidc_flows_expiry ON oidc_flows(expires_at);
CREATE TABLE oidc_results (
 id TEXT PRIMARY KEY, cookie_hash TEXT NOT NULL, provider TEXT NOT NULL CHECK (provider='google'),
 issuer TEXT NOT NULL CHECK (issuer='https://accounts.google.com'), subject TEXT NOT NULL,
 email TEXT NOT NULL, domain TEXT, name TEXT, email_verified INTEGER NOT NULL CHECK (email_verified=1),
 purpose TEXT NOT NULL CHECK (purpose IN ('signin','invite','link','gate')), account TEXT REFERENCES accounts(id),
 session TEXT, security_epoch INTEGER, invite_hash TEXT, workspace TEXT REFERENCES workspaces(id),
 rule_revision INTEGER, gate_generation INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 app_session_hash TEXT, app_pkce_challenge TEXT, check_context TEXT CHECK (check_context IS NULL OR json_valid(check_context)), consumed_at INTEGER, joining_membership TEXT, joining_identity TEXT,
 state TEXT NOT NULL DEFAULT 'unused' CHECK (state IN ('unused','joining','consumed')),
 CHECK (purpose != 'gate' OR (workspace IS NOT NULL AND rule_revision IS NOT NULL AND gate_generation IS NOT NULL)),
 CHECK (purpose != 'link' OR (account IS NOT NULL AND session IS NOT NULL AND security_epoch IS NOT NULL)),
 CHECK (purpose != 'invite' OR invite_hash IS NOT NULL),
 CHECK ((app_session_hash IS NULL AND app_pkce_challenge IS NULL) OR (purpose='gate' AND app_session_hash IS NOT NULL AND app_pkce_challenge IS NOT NULL))
);
CREATE INDEX oidc_results_expiry ON oidc_results(expires_at);
CREATE TABLE session_identity_checks (
 id TEXT NOT NULL UNIQUE, session TEXT NOT NULL, workspace TEXT NOT NULL REFERENCES workspaces(id), member TEXT NOT NULL,
 identity TEXT NOT NULL REFERENCES oidc_identities(id), account TEXT NOT NULL REFERENCES accounts(id),
 session_kind TEXT NOT NULL CHECK (session_kind IN ('web','app')), security_epoch INTEGER NOT NULL,
 claims TEXT NOT NULL CHECK (json_valid(claims)), rule_revision INTEGER NOT NULL, gate_generation INTEGER NOT NULL,
 sequence INTEGER NOT NULL, started_at INTEGER NOT NULL, succeeded_at INTEGER NOT NULL,
 purpose TEXT NOT NULL CHECK (purpose='session'), expires_at INTEGER NOT NULL, PRIMARY KEY(session,workspace)
);
CREATE TABLE operation_identity_checks (
 id TEXT PRIMARY KEY, session TEXT NOT NULL, workspace TEXT NOT NULL REFERENCES workspaces(id), member TEXT NOT NULL,
 identity TEXT NOT NULL REFERENCES oidc_identities(id), account TEXT NOT NULL REFERENCES accounts(id),
 session_kind TEXT NOT NULL CHECK (session_kind IN ('web','app')), security_epoch INTEGER NOT NULL,
 claims TEXT NOT NULL CHECK (json_valid(claims)), rule_revision INTEGER NOT NULL, gate_generation INTEGER NOT NULL,
 sequence INTEGER NOT NULL, started_at INTEGER NOT NULL, succeeded_at INTEGER NOT NULL,
 purpose TEXT NOT NULL CHECK (purpose IN ('enrolment','acceptance','rescope','activation','promotion','rule')),
 subject_digest TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE INDEX operation_identity_checks_subject ON operation_identity_checks(workspace,subject_digest,consumed_at);
CREATE TABLE app_gate_codes (
 code_hash TEXT PRIMARY KEY, app_session_hash TEXT NOT NULL, account TEXT NOT NULL REFERENCES accounts(id),
 security_epoch INTEGER NOT NULL, app_pkce_challenge TEXT NOT NULL, workspace TEXT NOT NULL REFERENCES workspaces(id), member TEXT NOT NULL,
 rule_revision INTEGER NOT NULL, gate_generation INTEGER NOT NULL, result TEXT NOT NULL UNIQUE REFERENCES oidc_results(id),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + 300000), consumed_at INTEGER
);
CREATE INDEX app_gate_codes_expiry ON app_gate_codes(expires_at);
