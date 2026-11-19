// Workspace approval registration, immutable migrations and shared digests.
import { createHash } from "node:crypto"
import { canonicalJson } from "@mehen/protocol"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { one,type Area,type VaultContext } from "../core.ts"
import type { ApprovalPresentation } from "../services.ts"
import { workspaceApprovalOps, WORKSPACE_APPROVAL_MIGRATION, WORKSPACE_APPROVAL_BINDING_MIGRATION, WORKSPACE_APPROVAL_WORKLOAD_MIGRATION, WORKSPACE_APPROVAL_BATCH_MIGRATION } from "./approvals-workspace.ts"
import { WORKSPACE_PROTECTED_GRANTS_MIGRATION } from "./projects-workspace.ts"
import { workspaceApprovalBatchOps } from "./approvals-batch-workspace.ts"

export const APPROVAL_TTL_MS = 3600_000
export const BINDING_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
const BINDING_CODE_LENGTH = 6

// base64url(SHA-256(canonical JSON)): the digest every approval and step-up uses.
export function digestOf(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("base64url")
}

export function parseOpInput<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input ?? {})
  if (!result.success) {
    const issue = result.error.issues[0]
    throw new VaultError("bad_request", `Invalid request: ${issue ? `${issue.path.join(".") || "body"} ${issue.message}` : "bad shape"}.`)
  }
  return result.data
}

export const approvalsArea: Area = {
  name: "approvals",
  workspaceOps: { ...workspaceApprovalOps, ...workspaceApprovalBatchOps },
  migrations: [
    `CREATE TABLE approvals (
       id TEXT PRIMARY KEY,
       device TEXT NOT NULL,
       device_name TEXT NOT NULL,
       session TEXT,
       item TEXT NOT NULL,
       digest TEXT NOT NULL,
       subject TEXT NOT NULL,
       presentation TEXT NOT NULL,
       binding_code TEXT NOT NULL,
       status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       decided_by TEXT,
       decided_at INTEGER,
       receipt TEXT
     );
     CREATE INDEX approvals_device_digest ON approvals (device, digest, status);
     CREATE TABLE grants (
       id TEXT PRIMARY KEY,
       approval TEXT NOT NULL REFERENCES approvals (id),
       device TEXT NOT NULL,
       digest TEXT NOT NULL,
       uses_left INTEGER,
       expires_at INTEGER NOT NULL
     );
     CREATE INDEX grants_device_digest ON grants (device, digest);
     CREATE INDEX grants_approval ON grants (approval);`,
    `ALTER TABLE approvals ADD COLUMN policy_status TEXT;
     ALTER TABLE approvals ADD COLUMN policy_terms TEXT;
     UPDATE approvals SET policy_status = 'stale' WHERE status = 'pending';
     DROP INDEX grants_device_digest;
     DROP INDEX grants_approval;
     ALTER TABLE grants RENAME TO grants_unguarded;
     CREATE TABLE grants (
       id TEXT PRIMARY KEY, approval TEXT REFERENCES approvals(id), device TEXT NOT NULL, digest TEXT NOT NULL,
       uses_left INTEGER, expires_at INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'exact',
       selector TEXT NOT NULL, snapshot TEXT, guard_digest TEXT, scope_json TEXT, policy_mode TEXT,
       revoked_at INTEGER, revoked_by TEXT, invalid_reason TEXT, created_at INTEGER NOT NULL,
       source_proposal TEXT, parent_override TEXT, item TEXT,
       CHECK ((approval IS NOT NULL AND source_proposal IS NULL) OR (approval IS NULL AND source_proposal IS NOT NULL))
     );
     INSERT INTO grants (id, approval, device, digest, uses_left, expires_at, selector, revoked_at, invalid_reason, created_at)
       SELECT id, approval, device, digest, uses_left, expires_at, json_object('device',device,'session',NULL),
         CASE WHEN (uses_left IS NULL OR uses_left > 0) AND expires_at > CAST(unixepoch('subsec') * 1000 AS INTEGER) THEN CAST(unixepoch('subsec') * 1000 AS INTEGER) ELSE NULL END,
         CASE WHEN (uses_left IS NULL OR uses_left > 0) AND expires_at > CAST(unixepoch('subsec') * 1000 AS INTEGER) THEN 'policy-guard-upgrade' ELSE NULL END,
         0 FROM grants_unguarded;
     DROP TABLE grants_unguarded;
     CREATE INDEX grants_device_digest ON grants(device, digest);
     CREATE INDEX grants_approval ON grants(approval);`,
    WORKSPACE_APPROVAL_MIGRATION,
    WORKSPACE_PROTECTED_GRANTS_MIGRATION,
    WORKSPACE_APPROVAL_BINDING_MIGRATION,
    WORKSPACE_APPROVAL_WORKLOAD_MIGRATION,
    WORKSPACE_APPROVAL_BATCH_MIGRATION,
  ],
  // Keyed by approval id, for cards with a `settled` form: an approval that
  // expires undecided stops keeping what only its pending card showed.
  async alarm(ctx, key) {
    const row = one(ctx.sql.exec<ApprovalRow>("SELECT * FROM approvals WHERE id = ?", key))
    if (!row || row.status !== "pending") return
    if (ctx.now() < row.expires_at) {
      ctx.schedule("approvals", key, row.expires_at)
      return
    }
    settlePresentation(ctx, row)
  },
}

// Replaces a stored card with its settled form, once nobody needs to decide it.
function settlePresentation(ctx: VaultContext, row: Pick<ApprovalRow, "id" | "presentation">): void {
  const { settled, ...card } = JSON.parse(row.presentation) as ApprovalPresentation
  if (settled === undefined) return
  ctx.sql.exec("UPDATE approvals SET presentation = ? WHERE id = ?", JSON.stringify({ ...card, details: settled.details, body: settled.body }), row.id)
}

type ApprovalRow = { id: string; status: "pending" | "approved" | "denied"; expires_at: number; presentation: string }

export function bindingCode(): string {
  const out: string[] = []
  const limit = 256 - (256 % BINDING_CODE_ALPHABET.length)
  while (out.length < BINDING_CODE_LENGTH) {
    for (const b of crypto.getRandomValues(new Uint8Array(BINDING_CODE_LENGTH * 2))) {
      if (b < limit && out.length < BINDING_CODE_LENGTH) out.push(BINDING_CODE_ALPHABET[b % BINDING_CODE_ALPHABET.length] as string)
    }
  }
  return out.join("")
}
