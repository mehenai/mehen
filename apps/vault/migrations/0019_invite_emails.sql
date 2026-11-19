-- Additive only. Invitation links the vault emailed to the invited address
-- as the invitation was made (src/directory/invite-email.ts), one row per
-- email sent, so the sends can be counted. Never the link or its code.
-- - email is the invitation's address (canonical lower case); inviter the
--   account that made the invitation; workspace the workspace it is to.
-- - An inviter is sent at most 10 an hour and 30 a day; one address at most
--   3 a day across every inviter and workspace. Each limit is a condition of
--   the INSERT that counts the send. Rows are kept a day, then swept
--   (workspace-maintenance.ts).

CREATE TABLE invite_emails (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL CHECK (email = lower(trim(email)) AND email LIKE '%_@_%'),
  inviter TEXT NOT NULL,
  workspace TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX invite_emails_email ON invite_emails(email, created_at);
CREATE INDEX invite_emails_inviter ON invite_emails(inviter, created_at);
