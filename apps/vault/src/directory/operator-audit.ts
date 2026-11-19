// The Audit view's read (OperatorAuditPage in the protocol): one list,
// newest first, across deployment_events, platform_events (but a
// platform's rolling activity row, which is a counter, not an event) and
// the operator.* rows of account_events, which the operator script's
// flags write through their triggers. Read-only: nothing here writes.
//
// Each page is OPERATOR_AUDIT_PAGE_SIZE rows after the cursor (time, then
// id: every source's ids have their own prefix, so the order is total).
// Names are added for the accounts and platforms a row names, and a
// deployment event that belongs to a proposal carries the proposal's
// outcome and who proposed, approved or declined it.

import { ACCOUNT_ID, OPERATOR_AUDIT_PAGE_SIZE, type OperatorAuditEvent, type OperatorAuditPage, type OperatorAuditProposal, type OperatorAuditQuery, type OperatorAuditSource, type OperatorProposalState, OperatorAuditPageSchema } from "@mehen/protocol"
import type { Env } from "../env.ts"

const DAY_MS = 86_400_000

type Row = { id: string; at: number; source: OperatorAuditSource; action: string; actor: string; approver: string | null; target: string; target_name: string | null; details: string }

// Every source in one shape. `target_alt` is what the target filter also
// matches: a platform's id beside its slug.
const UNION = `SELECT id,at,'deployment' AS source,kind AS action,actor,approver,target,target AS target_alt,NULL AS target_name,details FROM deployment_events
  UNION ALL
  SELECT e.id,e.at,'platform',e.action,e.actor,NULL,COALESCE(p.removed_slug,p.slug),p.id,p.name,e.detail FROM platform_events e JOIN platforms p ON p.id=e.platform WHERE e.action!='platform.activity'
  UNION ALL
  SELECT id,at,'account',action,COALESCE(json_extract(detail,'$.by'),'system'),NULL,account,account,NULL,detail FROM account_events WHERE action GLOB 'operator.*'`

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

function dayStart(day: string): number {
  return Date.parse(`${day}T00:00:00Z`)
}

function accountOf(actor: string | null): string | null {
  if (actor === null) return null
  const account = actor.includes(":") ? actor.slice(actor.indexOf(":") + 1) : actor
  return ACCOUNT_ID.test(account) ? account : null
}

type ProposalRow = { id: string; kind: string; state: OperatorProposalState; proposed_by: string; approved_by: string | null; declined_by: string | null }

export async function operatorAuditPage(env: Env, query: OperatorAuditQuery): Promise<OperatorAuditPage> {
  const before = query.before === undefined ? null : { at: Number(query.before.slice(0, query.before.indexOf("."))), id: query.before.slice(query.before.indexOf(".") + 1) }
  const from = query.from === undefined ? null : dayStart(query.from)
  const to = query.to === undefined ? null : dayStart(query.to) + DAY_MS
  const actor = query.actor ?? null
  const action = query.action ?? null
  const target = query.target ?? null
  const rows = await env.DB.prepare(`SELECT id,at,source,action,actor,approver,target,target_name,details FROM (${UNION})
    WHERE (? IS NULL OR instr(actor,?)>0 OR instr(COALESCE(approver,''),?)>0)
      AND (? IS NULL OR instr(action,?)>0)
      AND (? IS NULL OR instr(target,?)>0 OR instr(target_alt,?)>0)
      AND (? IS NULL OR at>=?) AND (? IS NULL OR at<?)
      AND (? IS NULL OR at<? OR (at=? AND id<?))
    ORDER BY at DESC,id DESC LIMIT ?`)
    .bind(actor, actor, actor, action, action, target, target, target, from, from, to, to, before?.at ?? null, before?.at ?? null, before?.at ?? null, before?.id ?? null, OPERATOR_AUDIT_PAGE_SIZE + 1)
    .all<Row>()
  const page = rows.results.slice(0, OPERATOR_AUDIT_PAGE_SIZE)
  const details = page.map((row) => JSON.parse(row.details) as Record<string, unknown>)
  const proposalIds = [...new Set(page.flatMap((row, i) => (row.source === "deployment" && typeof details[i]?.proposal === "string" ? [details[i].proposal as string] : [])))]
  const proposals = proposalIds.length === 0 ? [] : (await env.DB.prepare(`SELECT id,kind,state,proposed_by,approved_by,declined_by FROM operator_proposals WHERE id IN (${proposalIds.map(() => "?").join(",")})`).bind(...proposalIds).all<ProposalRow>()).results
  const accounts = [...new Set([
    ...page.flatMap((row) => [accountOf(row.actor), accountOf(row.approver), ACCOUNT_ID.test(row.target) ? row.target : null]),
    ...proposals.flatMap((p) => [p.proposed_by, p.approved_by, p.declined_by]),
  ].filter((account): account is string => account !== null))]
  const names = new Map(accounts.length === 0 ? [] : (await env.DB.prepare(`SELECT id,name FROM accounts WHERE id IN (${accounts.map(() => "?").join(",")})`).bind(...accounts).all<{ id: string; name: string }>()).results.map((row) => [row.id, row.name]))
  const ref = (account: string) => ({ account, name: names.get(account) ?? account })
  const proposalOf = new Map<string, OperatorAuditProposal>(proposals.map((p) => [p.id, { id: p.id, kind: p.kind, state: p.state, proposedBy: ref(p.proposed_by), approvedBy: p.approved_by === null ? null : ref(p.approved_by), declinedBy: p.declined_by === null ? null : ref(p.declined_by) }]))
  const nameOf = (actorOrAccount: string | null) => {
    const account = accountOf(actorOrAccount)
    return account === null ? null : (names.get(account) ?? null)
  }
  const events: OperatorAuditEvent[] = page.map((row, i) => {
    const detail = details[i] ?? {}
    return {
      id: row.id,
      at: iso(row.at),
      source: row.source,
      action: row.action,
      actor: row.actor,
      actorName: nameOf(row.actor),
      approver: row.approver,
      approverName: nameOf(row.approver),
      target: row.target,
      targetName: row.target_name ?? (ACCOUNT_ID.test(row.target) ? (names.get(row.target) ?? null) : null),
      details: detail,
      proposal: row.source === "deployment" && typeof detail.proposal === "string" ? (proposalOf.get(detail.proposal) ?? null) : null,
    }
  })
  const last = page.at(-1)
  return OperatorAuditPageSchema.parse({ events, next: rows.results.length > OPERATOR_AUDIT_PAGE_SIZE && last ? `${last.at}.${last.id}` : null })
}
