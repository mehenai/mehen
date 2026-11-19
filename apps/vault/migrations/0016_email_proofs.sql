-- Additive only. An email-bound invitation's address proved by a six-digit
-- code the vault emails to it (src/directory/email-proof.ts), beside Google's
-- proof in oidc_results. One row per code sent:
-- - invite_hash is invite_codes.code_hash; email is the invitation's address
--   (canonical lower case), copied when the code is sent and compared again
--   wherever the proof is used.
-- - code_hash is an HMAC of the row id and the code under a key derived from
--   ROOT_KEYS version key_version, so a copy of this table alone cannot
--   recover a code; the code itself is never stored.
-- - cookie_hash binds the row to the browser it was sent from (the SHA-256 of
--   its __Host-mehen_email cookie); account, session and security_epoch the
--   signed-in account that asked, if any, as oidc_results does.
-- - sends_window is this send's number among the invitation's sends in the
--   hour before it: at most 3. attempts counts wrong codes: at 5 the code is dead.
--   Rows are kept a day, so the invitation's sends that day (at most 5) and
--   wrong codes across all its rows that day (at most 10) can be counted, and
--   the address's sends across all its invitations (at most 5 an hour, 10 a
--   day).
-- - state: sent (a code is out), verified (the code was typed back: the row is
--   now a proof for ten minutes), joining (an account holds it, as an
--   oidc_results row does), consumed (used, replaced or ended).

CREATE TABLE email_proofs (
  id TEXT PRIMARY KEY,
  invite_hash TEXT NOT NULL,
  email TEXT NOT NULL CHECK (email = lower(trim(email)) AND email LIKE '%_@_%'),
  code_hash TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  cookie_hash TEXT NOT NULL,
  account TEXT REFERENCES accounts(id),
  session TEXT,
  security_epoch INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  sends_window INTEGER NOT NULL CHECK (sends_window BETWEEN 1 AND 3),
  state TEXT NOT NULL DEFAULT 'sent' CHECK (state IN ('sent','verified','joining','consumed')),
  verified_at INTEGER,
  joining_membership TEXT,
  consumed_at INTEGER,
  CHECK (state NOT IN ('verified','joining') OR verified_at IS NOT NULL),
  CHECK (state != 'joining' OR account IS NOT NULL)
);
CREATE INDEX email_proofs_invite ON email_proofs(invite_hash, created_at);
CREATE INDEX email_proofs_email ON email_proofs(email, created_at);
CREATE INDEX email_proofs_expiry ON email_proofs(expires_at);
