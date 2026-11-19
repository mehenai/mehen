-- Additive only. The renewable enrolment lease (the hard cap, renewal
-- metadata and the expiry reason), the hidden fingerprint group chosen once
-- at start, the start session label, the account a connect code claimed the
-- attempt for, the hashed connect codes and the inbox indexes. Rows that
-- exist when this applies keep their life: their hard cap is their expiry.
ALTER TABLE enrolments ADD COLUMN hard_expires_at INTEGER;
ALTER TABLE enrolments ADD COLUMN renewed_at INTEGER;
ALTER TABLE enrolments ADD COLUMN renewals INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrolments ADD COLUMN expired_reason TEXT CHECK (expired_reason IS NULL OR expired_reason IN ('hard_cap','superseded','discarded','source'));
ALTER TABLE enrolments ADD COLUMN hidden_group INTEGER CHECK (hidden_group IS NULL OR hidden_group IN (0,1,2,3));
ALTER TABLE enrolments ADD COLUMN start_session TEXT;
ALTER TABLE enrolments ADD COLUMN claimed_account TEXT REFERENCES accounts(id);
UPDATE enrolments SET hard_expires_at=expires_at WHERE hard_expires_at IS NULL;
CREATE INDEX enrolments_intent ON enrolments(status, workspace_intent, expires_at);
CREATE INDEX enrolments_tenant ON enrolments(status, tenant);
CREATE TABLE enrol_connect_codes (
  code_hash TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  workspace TEXT NOT NULL REFERENCES workspaces(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK (expires_at=created_at+86400000)
);
CREATE UNIQUE INDEX enrol_connect_codes_live ON enrol_connect_codes(account, workspace);
