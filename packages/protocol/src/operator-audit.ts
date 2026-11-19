// The Operator area's Audit view (CONSOLE_ROUTES.operatorAudit): one
// read-only list, newest first, across every operator and deployment
// change the database records: deployment_events (the operators' changes
// and proposals), platform_events (everything done to a platform) and the
// operator.* rows of account_events (the operator script's flags on an
// account). It is a D1 record, not a hash chain: whoever can write D1 can
// change it, which is why Cloudflare's audit log is the second record.

import { z } from "zod"
import { OperatorAccountRefSchema, OperatorProposalStateSchema } from "./operator-proposals.ts"

const Iso = z.iso.datetime()

export const OPERATOR_AUDIT_PAGE_SIZE = 50
export const OPERATOR_AUDIT_FILTER_MAX = 128

// What the Audit view says about itself.
export const OPERATOR_AUDIT_RECORD_WORDS = "This is a record in the database (D1), not a hash chain: anyone with write access to D1 can change it, which is why Cloudflare's audit log is the second record."

// ---------------------------------------------------------------- the query

const Filter = z.string().trim().min(1).max(OPERATOR_AUDIT_FILTER_MAX)

// `actor`, `action` and `target` each match any part of the row's (the
// actor also matches the approver, and a platform's target its id too);
// `from` and `to` are whole UTC days, both included; `before` is the
// `next` of the page before.
export const OperatorAuditQuerySchema = z.strictObject({
  actor: Filter.optional(),
  action: Filter.optional(),
  target: Filter.optional(),
  from: z.iso.date().optional(),
  to: z.iso.date().optional(),
  before: z.string().regex(/^\d{1,16}\.[A-Za-z0-9_-]{1,128}$/).optional(),
})
export type OperatorAuditQuery = z.infer<typeof OperatorAuditQuerySchema>
export const OPERATOR_AUDIT_FILTERS = ["actor", "action", "target", "from", "to"] as const

// The query from an address's search parameters: an empty field, as a
// form sends one, is no filter.
export function operatorAuditQuery(params: URLSearchParams): { ok: true; query: OperatorAuditQuery } | { ok: false } {
  const given = Object.fromEntries([...params].filter(([, value]) => value.trim() !== ""))
  const parsed = OperatorAuditQuerySchema.safeParse(given)
  return parsed.success ? { ok: true, query: parsed.data } : { ok: false }
}

// The query as search parameters, without `before` unless asked.
export function operatorAuditSearch(query: OperatorAuditQuery, before?: string): string {
  const params = new URLSearchParams()
  for (const key of OPERATOR_AUDIT_FILTERS) {
    const value = query[key]
    if (value !== undefined) params.set(key, value)
  }
  if (before !== undefined) params.set("before", before)
  const text = params.toString()
  return text === "" ? "" : `?${text}`
}

// ---------------------------------------------------------------- the answer

export const OperatorAuditSourceSchema = z.enum(["deployment", "platform", "account"])
export type OperatorAuditSource = z.infer<typeof OperatorAuditSourceSchema>

// The proposal a deployment event belongs to, as it stands now: its kind,
// its outcome, and who proposed, approved or declined it.
export const OperatorAuditProposalSchema = z.strictObject({
  id: z.string(),
  kind: z.string(),
  state: OperatorProposalStateSchema,
  proposedBy: OperatorAccountRefSchema,
  approvedBy: OperatorAccountRefSchema.nullable(),
  declinedBy: OperatorAccountRefSchema.nullable(),
})
export type OperatorAuditProposal = z.infer<typeof OperatorAuditProposalSchema>

// One row. `actor` and `approver` as the record names them
// (operator:<who>, admin:<account id>, platform:<key id> or system), with
// the account's name when they name one; `target` an account id, a
// platform's slug or a setting's key, with the account's or platform's
// name; `details` ids, counts and reasons, never a secret.
export const OperatorAuditEventSchema = z.strictObject({
  id: z.string(),
  at: Iso,
  source: OperatorAuditSourceSchema,
  action: z.string(),
  actor: z.string(),
  actorName: z.string().nullable(),
  approver: z.string().nullable(),
  approverName: z.string().nullable(),
  target: z.string(),
  targetName: z.string().nullable(),
  details: z.record(z.string(), z.unknown()),
  proposal: OperatorAuditProposalSchema.nullable(),
})
export type OperatorAuditEvent = z.infer<typeof OperatorAuditEventSchema>

export const OperatorAuditPageSchema = z.strictObject({ events: z.array(OperatorAuditEventSchema).max(OPERATOR_AUDIT_PAGE_SIZE), next: z.string().nullable() })
export type OperatorAuditPage = z.infer<typeof OperatorAuditPageSchema>
