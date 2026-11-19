-- Additive only. Several operators, and the changes that need two of them:
-- - operator_proposals: one operator proposes a change (its kind, target and
--   parameters, bound by the digest of their canonical JSON), a different
--   operator approves it within 24 hours, and the vault applies it in one
--   guarded batch; an operator role granted is also accepted by the target
--   with their own passkey before it is set. One open proposal per kind and
--   target. The CHECKs refuse an approval by the proposer and a proposal,
--   approval or decline by the account it names, whatever writes the row.
-- - deployment_events: every operator action from now on, the app's and the
--   operator script's, with who proposed (actor) and who approved
--   (approver, for a two-operator change).

CREATE TABLE operator_proposals (
  id TEXT PRIMARY KEY CHECK (substr(id,1,4)='opp_'),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 128),
  params TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
  digest TEXT NOT NULL,
  proposed_by TEXT NOT NULL REFERENCES accounts(id),
  proposed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > proposed_at),
  approved_by TEXT REFERENCES accounts(id),
  approved_at INTEGER,
  declined_by TEXT REFERENCES accounts(id),
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','applied','declined','expired','cancelled')),
  closed_at INTEGER,
  CHECK (approved_by IS NULL OR approved_by != proposed_by),
  CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
  CHECK (target != proposed_by AND (approved_by IS NULL OR target != approved_by)),
  CHECK (declined_by IS NULL OR declined_by != proposed_by),
  CHECK (declined_by IS NULL OR declined_by != target),
  CHECK ((state = 'open') = (closed_at IS NULL)),
  CHECK (state != 'applied' OR approved_by IS NOT NULL),
  CHECK (state != 'declined' OR declined_by IS NOT NULL)
);
CREATE UNIQUE INDEX operator_proposals_open ON operator_proposals(kind, target) WHERE state = 'open';
CREATE INDEX operator_proposals_expiry ON operator_proposals(expires_at) WHERE state = 'open';
CREATE INDEX operator_proposals_recent ON operator_proposals(proposed_at);

CREATE TABLE deployment_events (
  id TEXT PRIMARY KEY CHECK (substr(id,1,4)='dpe_'),
  at INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  actor TEXT NOT NULL CHECK (actor GLOB 'operator:?*' OR actor = 'system'),
  approver TEXT CHECK (approver IS NULL OR approver GLOB 'operator:?*'),
  target TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details))
);
CREATE INDEX deployment_events_at ON deployment_events(at, id);
