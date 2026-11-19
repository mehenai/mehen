-- Identity: what device enrolment and the step-up nonces need beyond 0001.

-- The scope chosen at approval and who approved it, so the new key's poll
-- can learn its scope before it has ever reached the tenant vault.
ALTER TABLE enrolments ADD COLUMN scope TEXT;
ALTER TABLE enrolments ADD COLUMN approved_by TEXT;
CREATE INDEX enrolments_pending ON enrolments (status, expires_at);

-- Proof ids already seen on the enrolment routes, which no tenant vault
-- guards yet. Kept until the proof could no longer pass the skew check.
CREATE TABLE enrol_nonces (
  id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX enrol_nonces_expiry ON enrol_nonces (expires_at);

CREATE INDEX challenges_expiry ON challenges (expires_at);
CREATE INDEX invites_tenant ON invites (tenant);
