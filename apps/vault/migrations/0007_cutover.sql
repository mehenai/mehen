-- Applied only after the destructive fresh-start directory and OIDC schemas.
CREATE TABLE workspace_cutover (
  id INTEGER PRIMARY KEY CHECK (id=1),
  generation TEXT NOT NULL CHECK (generation='workspaces-fresh-v1')
);
INSERT INTO workspace_cutover(id,generation) VALUES (1,'workspaces-fresh-v1');

-- The operator writes hashes only. Cron applies the existing account security
-- barrier before making a link redeemable; an unavailable target never waives it.
CREATE TABLE account_break_glass_intents (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL REFERENCES accounts(id),
  actor TEXT NOT NULL CHECK (actor GLOB 'operator:?*'),
  code_hash TEXT NOT NULL UNIQUE,
  notice TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','ready','redeemed','expired')),
  transition_id TEXT,
  CHECK (expires_at=created_at+3600000)
);
CREATE INDEX account_break_glass_pending ON account_break_glass_intents(state,created_at);
CREATE UNIQUE INDEX account_break_glass_live ON account_break_glass_intents(account) WHERE state IN ('pending','ready');
CREATE TRIGGER account_break_glass_issue AFTER INSERT ON account_break_glass_intents
BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM accounts WHERE id=NEW.account AND status='active') THEN 1 ELSE RAISE(ABORT,'active account required') END;
  INSERT INTO account_events(id,account,at,action,detail,targets)
  VALUES (NEW.id,NEW.account,NEW.created_at,'operator.break_glass',json_object('by',NEW.actor,'intent',NEW.id),
    '[]');
  INSERT INTO account_notices(id,account,kind,payload,at,client,restricted_until)
  VALUES (NEW.notice,NEW.account,'break-glass',json_object('by',NEW.actor,'intent',NEW.id),NEW.created_at,'Independent operator',NULL);
END;
