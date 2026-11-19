// The terms of the operator's two proposal kinds that act on a workspace
// (OPERATOR_PROPOSAL_KINDS in operator-proposals.ts): the workspace id they
// target, and a restore's source and point. A restore records exactly the
// vault_restore_intents row scripts/vault-backup.ts records, so its terms
// take the script's own forms: a point in time as an ISO time in UTC with
// milliseconds, a dump as its UTC date.

import { z } from "zod"

// A workspace id as the vault reaches its object (vault/client.ts).
export const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/
export const WorkspaceIdSchema = z.string().regex(WORKSPACE_ID)

const PITR_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const DUMP_DATE = /^\d{4}-\d{2}-\d{2}$/

export const RestorePointSchema = z.string().regex(PITR_TIME).refine((value) => !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value, "Not a time.")
export const RestoreDateSchema = z.string().regex(DUMP_DATE).refine((value) => !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().startsWith(value), "Not a calendar date.")

// `pitr`: back to that moment, within the last 30 days; `dump`: from that
// day's dump, into an empty object only.
export const WorkspaceRestoreParamsSchema = z.discriminatedUnion("source", [
  z.strictObject({ source: z.literal("pitr"), target: RestorePointSchema }),
  z.strictObject({ source: z.literal("dump"), target: RestoreDateSchema }),
])
export type WorkspaceRestoreParams = z.infer<typeof WorkspaceRestoreParamsSchema>
