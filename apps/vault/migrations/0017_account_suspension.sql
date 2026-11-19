-- Additive only. An operator's suspension of an account (the Accounts view
-- in the Operator area, directory/operator-accounts.ts): when it was
-- suspended and by which operator, both NULL while it is not. A suspended
-- account cannot sign in, sign up, step up or use a session; lifting clears
-- both. Its status stays as it is, so the accounts table needs no rebuild.

ALTER TABLE accounts ADD COLUMN suspended_at INTEGER;
ALTER TABLE accounts ADD COLUMN suspended_by TEXT CHECK (suspended_by IS NULL OR suspended_by GLOB 'operator:?*');
