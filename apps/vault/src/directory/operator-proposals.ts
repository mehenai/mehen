// Two-operator proposals (operator-proposals.ts in the protocol), the same
// for every kind; what one kind checks and applies is in
// operator-proposal-kinds.ts.
//
// - Proposing, approving, accepting, declining and cancelling each check
//   everything first and say plainly what stops them, then call `confirm`
//   (the route's passkey step-up, where there is one), then write one batch
//   whose guards check it all again: the proposal still open, unexpired and
//   with the digest signed, and every operator in it still holding the role
//   with every requirement of an operator account met.
// - Applying writes the effect, the deployment_events row (actor
//   operator:<proposer>, approver operator:<approver>) and a notice to every
//   operator account, together. Proposing, approving, declining, cancelling
//   and expiry each write their own deployment_events row and notices too.
// - A one-operator kind (resigning, freezing a workspace, narrowing a
//   setting, or the Accounts view's brakes and workspace creation) applies
//   when proposed. Every change but one to your own role needs an operator
//   account with every requirement met.
// - A kind that changes something outside D1 (freezing a workspace) does
//   so after the last passkey, with the operator and the kind's check read
//   again just before it, and just before the batch that records it. No
//   guard can take that change back, so when the batch's guards then fail
//   its deployment_events row and notices are written anyway, marked
//   `unguarded` with the reason.
// - Expiry is the cron's, and also runs before every read and write here,
//   so a proposal past its 24 hours is never shown as open or acted on.

import { NEEDS_SECOND_OPERATOR_WORDS, OPERATOR_EVENTS_SHOWN, OPERATOR_PROPOSAL_TTL_MS, OPERATOR_PROPOSALS_RECENT, type OperatorCandidate, type OperatorInvitation, type OperatorProposalKind, OperatorProposalKindSchema, type OperatorProposalState, type OperatorProposalTerms, type OperatorProposalView, type OperatorsView, ACCOUNT_ID, WORKSPACE_ID, operatorProposalDigest, operatorProposalRule, operatorRequirementsRefusal } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { randomId } from "../vault/core.ts"
import { accountBatch, accountGuard } from "./account-store.ts"
import { OPERATOR_KIND_HANDLERS } from "./operator-proposal-kinds.ts"
import { missingOf, operatorAccountFacts, operatorFactsColumns, operatorReadySql, requireOperatorReady } from "./operator-requirements.ts"

export const NEEDS_SECOND_OPERATOR = NEEDS_SECOND_OPERATOR_WORDS.change

type Confirm = () => Promise<unknown>

type ProposalRow = { id: string; kind: string; target: string; params: string; digest: string; proposed_by: string; proposed_at: number; expires_at: number; approved_by: string | null; approved_at: number | null; declined_by: string | null; state: OperatorProposalState; closed_at: number | null }

const PROPOSAL_COLUMNS = "id,kind,target,params,digest,proposed_by,proposed_at,expires_at,approved_by,approved_at,declined_by,state,closed_at"

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

function termsOf(row: ProposalRow): OperatorProposalTerms {
  return { kind: OperatorProposalKindSchema.parse(row.kind), target: row.target, params: JSON.parse(row.params) as Record<string, unknown> }
}

// The row, once its stored kind, target and params give its stored digest
// again: what is applied is what every passkey on it confirmed.
async function signedRow(row: ProposalRow): Promise<ProposalRow> {
  if ((await operatorProposalDigest(termsOf(row))) !== row.digest) throw new VaultError("conflict", "This proposal's stored terms are not the ones proposed; propose it again.")
  return row
}

export async function operatorCount(env: Env): Promise<number> {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM accounts WHERE is_operator=1 AND status='active'").first<{ n: number }>())?.n ?? 0
}

// The name of the account or workspace a proposal names.
async function targetName(env: Env, target: string): Promise<string> {
  const table = WORKSPACE_ID.test(target) ? "workspaces" : "accounts"
  return (await env.DB.prepare(`SELECT name FROM ${table} WHERE id=?`).bind(target).first<{ name: string }>())?.name ?? target
}

// The account still an operator with every requirement met, in the batch.
export function readyOperator(env: Env, account: string, now: number): D1PreparedStatement {
  return accountGuard(env, `EXISTS (SELECT 1 FROM accounts a WHERE a.id=? AND a.status='active' AND a.is_operator=1 AND ${operatorReadySql("a")})`, [account, now])
}

function stillOperator(env: Env, account: string): D1PreparedStatement {
  return accountGuard(env, "EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND is_operator=1)", [account])
}

// The proposal still open, unexpired, with this digest, and approved or
// not as `approved` says.
function stillOpen(env: Env, row: ProposalRow, now: number, approved: "approved" | "unapproved" | "either"): D1PreparedStatement {
  const approval = approved === "approved" ? " AND approved_by=?" : approved === "unapproved" ? " AND approved_by IS NULL" : ""
  return accountGuard(env, `EXISTS (SELECT 1 FROM operator_proposals WHERE id=? AND state='open' AND expires_at>? AND digest=?${approval})`, [row.id, now, row.digest, ...(approved === "approved" ? [row.approved_by ?? ""] : [])])
}

export function deploymentEvent(env: Env, event: { kind: string; actor: string; approver: string | null; target: string; details: Record<string, unknown> }, now: number): D1PreparedStatement {
  return env.DB.prepare("INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) VALUES (?,?,?,?,?,?,?)").bind(randomId("dpe"), now, event.kind, event.actor, event.approver, event.target, JSON.stringify(event.details))
}

type NoticeEvent = "proposed" | "approved" | "applied" | "declined" | "cancelled"

// A notice to every operator account, as the role stands at this point of
// the batch, and to each of `also` that is not one.
function operatorNotices(env: Env, payload: Record<string, unknown>, now: number, also: string[] = []): D1PreparedStatement[] {
  const text = JSON.stringify(payload)
  return [
    env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) SELECT 'ntc_' || lower(hex(randomblob(16))),id,'workspace',?,? FROM accounts WHERE is_operator=1 AND status='active'").bind(text, now),
    ...also.map((account) => env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) SELECT ?,id,'workspace',?,? FROM accounts WHERE id=? AND is_operator=0").bind(randomId("ntc"), text, now, account)),
  ]
}

function noticePayload(event: NoticeEvent, kind: OperatorProposalKind, target: string, proposal: string | null, by: string): Record<string, unknown> {
  return { change: "operator_proposal", event, kind, target, proposal, by: `operator:${by}` }
}

// Whether a guard (accountGuard) holds now.
async function holds(env: Env, guard: D1PreparedStatement): Promise<boolean> {
  try {
    await accountBatch(env, [guard])
    return true
  } catch (error) {
    if (error instanceof VaultError && error.code === "conflict") return false
    throw error
  }
}

export const STANDING_CHANGED = "You no longer hold the operator role with every requirement met, so nothing changed."

// Why a change made outside D1 was recorded without its guards, as the
// deployment_events row's `reason` and in the answer.
const UNGUARDED = {
  "operator-changed": "Your standing as an operator changed while this ran, so its record is marked unguarded.",
  "target-changed": "Its target changed while this ran, so its record is marked unguarded.",
} as const

async function batch(env: Env, statements: D1PreparedStatement[]): Promise<void> {
  try {
    await accountBatch(env, statements)
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) throw new VaultError("conflict", "There is already an open proposal for that; approve, decline or cancel it first.")
    if (error instanceof VaultError && error.code === "conflict") throw new VaultError("conflict", "Nothing changed: the proposal or an operator changed while this ran. Read it again.")
    throw error
  }
}

// ---------------------------------------------------------------- expiry

// Each expiring proposal's notice goes to every operator and, for an
// approved one its target was to accept, to that target too.
export async function expireOperatorProposals(env: Env, now = Date.now()): Promise<void> {
  const due = await env.DB.prepare("SELECT 1 FROM operator_proposals WHERE state='open' AND expires_at<=? LIMIT 1").bind(now).first()
  if (!due) return
  const accepted = OperatorProposalKindSchema.options.filter((kind) => operatorProposalRule(kind).accept)
  await env.DB.batch([
    env.DB.prepare("INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) SELECT 'dpe_' || lower(hex(randomblob(16))),?,'proposal.expire','system',NULL,target,json_object('proposal',id,'kind',kind,'proposedBy','operator:' || proposed_by) FROM operator_proposals WHERE state='open' AND expires_at<=?").bind(now, now),
    env.DB.prepare(`INSERT INTO account_notices(id,account,kind,payload,at) SELECT 'ntc_' || lower(hex(randomblob(16))),a.id,'workspace',json_object('change','operator_proposal','event','expired','kind',p.kind,'target',p.target,'proposal',p.id,'by','system'),?
      FROM operator_proposals p JOIN accounts a ON a.is_operator=1 AND a.status='active' WHERE p.state='open' AND p.expires_at<=?`).bind(now, now),
    env.DB.prepare(`INSERT INTO account_notices(id,account,kind,payload,at) SELECT 'ntc_' || lower(hex(randomblob(16))),a.id,'workspace',json_object('change','operator_proposal','event','expired','kind',p.kind,'target',p.target,'proposal',p.id,'by','system'),?
      FROM operator_proposals p JOIN accounts a ON a.id=p.target AND a.is_operator=0 WHERE p.state='open' AND p.expires_at<=? AND p.approved_by IS NOT NULL AND p.kind IN (${accepted.map(() => "?").join(",")})`).bind(now, now, ...accepted),
    env.DB.prepare("UPDATE operator_proposals SET state='expired',closed_at=? WHERE state='open' AND expires_at<=?").bind(now, now),
  ])
}

// ---------------------------------------------------------------- proposing

function refuseSelf(kind: OperatorProposalKind, target: string, account: string, approving: boolean): void {
  const rule = operatorProposalRule(kind)
  if (rule.target === "other" && target === account) throw new VaultError("forbidden", approving ? "Nobody may approve a change to their own account." : "Nobody may propose a change to their own account.")
  if (rule.target === "self" && target !== account) throw new VaultError("forbidden", "This change is only ever to your own account.")
}

// Proposes `terms` as `account`, or applies a one-operator kind at once.
export async function proposeOperatorChange(env: Env, account: string, terms: OperatorProposalTerms, digest: string, confirm: Confirm, now = Date.now()): Promise<{ done: string; proposal: string | null }> {
  await expireOperatorProposals(env, now)
  const rule = operatorProposalRule(terms.kind)
  const handler = OPERATOR_KIND_HANDLERS[terms.kind]
  refuseSelf(terms.kind, terms.target, account, false)
  if (rule.operators === 2 && (await operatorCount(env)) < 2) throw new VaultError("forbidden", NEEDS_SECOND_OPERATOR)
  if (rule.target === "other") await requireOperatorReady(env, account, now)
  await handler.check(env, terms, now)
  if (rule.operators === 2 && (await env.DB.prepare("SELECT 1 FROM operator_proposals WHERE kind=? AND target=? AND state='open'").bind(terms.kind, terms.target).first())) throw new VaultError("conflict", "There is already an open proposal for that; approve, decline or cancel it first.")
  await confirm()
  const name = await targetName(env, terms.target)
  if (rule.operators === 1) {
    const standing = rule.target === "self" ? stillOperator(env, account) : readyOperator(env, account, now)
    const notices = (notify: string[]) => (handler.tellsOperators === false ? [] : operatorNotices(env, noticePayload("applied", terms.kind, terms.target, null, account), now, notify))
    const recorded = (details: Record<string, unknown>) => deploymentEvent(env, { kind: terms.kind, actor: `operator:${account}`, approver: null, target: terms.target, details }, now)
    if (!handler.applying) {
      const applied = await handler.apply(env, terms, account, now)
      await batch(env, [standing, ...handler.guards(env, terms, now), ...notices([]), ...applied.statements, recorded({ digest, ...applied.details })])
      await handler.after?.(env, terms, now)
      return { done: handler.done(name, terms), proposal: null }
    }
    if (!(await holds(env, standing))) throw new VaultError("forbidden", STANDING_CHANGED)
    await handler.check(env, terms, now)
    const applying = await handler.applying(env, terms, account)
    const applied = await handler.apply(env, terms, account, now)
    try {
      await accountBatch(env, [standing, ...handler.guards(env, terms, now), ...notices(applying.notify), ...applied.statements, recorded({ digest, ...applied.details })])
      await handler.after?.(env, terms, now)
      return { done: handler.done(name, terms), proposal: null }
    } catch (error) {
      if (!(error instanceof VaultError && error.code === "conflict")) throw error
      const reason = (await holds(env, standing)) ? "target-changed" : "operator-changed"
      await accountBatch(env, [...notices(applying.notify), recorded({ digest, unguarded: true, reason })])
      await handler.after?.(env, terms, now)
      return { done: `${handler.done(name, terms)} ${UNGUARDED[reason]}`, proposal: null }
    }
  }
  const id = randomId("opp")
  await batch(env, [
    readyOperator(env, account, now),
    ...handler.guards(env, terms, now),
    env.DB.prepare("INSERT INTO operator_proposals(id,kind,target,params,digest,proposed_by,proposed_at,expires_at) VALUES (?,?,?,?,?,?,?,?)").bind(id, terms.kind, terms.target, JSON.stringify(terms.params), digest, account, now, now + OPERATOR_PROPOSAL_TTL_MS),
    deploymentEvent(env, { kind: "proposal.open", actor: `operator:${account}`, approver: null, target: terms.target, details: { proposal: id, kind: terms.kind, digest, ...handler.proposed?.(terms) } }, now),
    ...operatorNotices(env, noticePayload("proposed", terms.kind, terms.target, id, account), now),
  ])
  return { done: `Proposed. Another operator approves it within 24 hours${rule.accept ? `, then ${name} accepts it with their own passkey` : ""}.`, proposal: id }
}

// ---------------------------------------------------------------- deciding

async function openProposal(env: Env, id: string, now: number): Promise<ProposalRow> {
  await expireOperatorProposals(env, now)
  const row = await env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE id=?`).bind(id).first<ProposalRow>()
  if (!row) throw new VaultError("not_found", "No such proposal.")
  if (row.state === "expired") throw new VaultError("conflict", "This proposal expired; propose it again.")
  if (row.state !== "open") throw new VaultError("conflict", `This proposal is ${row.state} already.`)
  return signedRow(row)
}

// The proposer and, once there is one, the approver: each still an
// operator with every requirement met.
async function operatorsStillReady(env: Env, accounts: string[], now: number): Promise<void> {
  for (const account of accounts) {
    const facts = await env.DB.prepare(`SELECT a.name,a.is_operator,${operatorFactsColumns("a")} FROM accounts a WHERE a.id=? AND a.status='active'`).bind(account).first<{ name: string; is_operator: number; recovery_ready: number; passkeys: number; security_keys: number; restricted_until: number | null; security_transition: string | null }>()
    if (!facts || facts.is_operator !== 1) throw new VaultError("conflict", "An operator on this proposal no longer holds the role; propose it again.")
    const missing = missingOf(facts, now)
    if (missing.length > 0) throw new VaultError("conflict", operatorRequirementsRefusal(missing, `${facts.name}'s account`))
  }
}

export async function approveOperatorProposal(env: Env, account: string, id: string, digest: string, confirm: Confirm, now = Date.now()): Promise<{ done: string }> {
  const row = await openProposal(env, id, now)
  const terms = termsOf(row)
  const rule = operatorProposalRule(terms.kind)
  const handler = OPERATOR_KIND_HANDLERS[terms.kind]
  if (row.proposed_by === account) throw new VaultError("forbidden", "You proposed this; a different operator approves it.")
  refuseSelf(terms.kind, terms.target, account, true)
  if (row.approved_by !== null) throw new VaultError("conflict", "This proposal is approved already; it waits for its target to accept.")
  if (digest !== row.digest) throw new VaultError("conflict", "This proposal is not the one you read. Read it again.")
  await requireOperatorReady(env, account, now)
  await operatorsStillReady(env, [row.proposed_by], now)
  await handler.check(env, terms, now)
  await confirm()
  const name = await targetName(env, terms.target)
  const head = [stillOpen(env, row, now, "unapproved"), readyOperator(env, row.proposed_by, now), readyOperator(env, account, now), ...handler.guards(env, terms, now)]
  if (rule.accept) {
    await batch(env, [
      ...head,
      env.DB.prepare("UPDATE operator_proposals SET approved_by=?,approved_at=? WHERE id=?").bind(account, now, row.id),
      deploymentEvent(env, { kind: "proposal.approve", actor: `operator:${row.proposed_by}`, approver: `operator:${account}`, target: terms.target, details: { proposal: row.id, kind: terms.kind, digest: row.digest } }, now),
      ...operatorNotices(env, noticePayload("approved", terms.kind, terms.target, row.id, account), now, [terms.target]),
    ])
    return { done: `Approved. ${name} accepts it with their own passkey on Your account, before it expires.` }
  }
  const applying = handler.applying ? await handler.applying(env, terms, row.proposed_by) : { notify: [] }
  const applied = await handler.apply(env, terms, row.proposed_by, now)
  await batch(env, [
    ...head,
    ...operatorNotices(env, noticePayload("applied", terms.kind, terms.target, row.id, account), now, applying.notify),
    env.DB.prepare("UPDATE operator_proposals SET approved_by=?,approved_at=?,state='applied',closed_at=? WHERE id=?").bind(account, now, now, row.id),
    ...applied.statements,
    deploymentEvent(env, { kind: terms.kind, actor: `operator:${row.proposed_by}`, approver: `operator:${account}`, target: terms.target, details: { proposal: row.id, digest: row.digest, ...applied.details } }, now),
  ])
  await handler.after?.(env, terms, now)
  return { done: handler.done(name, terms) }
}

// Declining (another operator, never the one the change names) and
// cancelling (the proposer) are brakes: no passkey, but still an operator
// write.
export async function closeOperatorProposal(env: Env, account: string, id: string, decision: "decline" | "cancel", now = Date.now()): Promise<{ done: string }> {
  const row = await openProposal(env, id, now)
  const terms = termsOf(row)
  if (decision === "decline" && row.proposed_by === account) throw new VaultError("forbidden", "You proposed this; cancel it instead.")
  if (decision === "decline" && operatorProposalRule(terms.kind).target === "other" && row.target === account) throw new VaultError("forbidden", "Nobody may decline a change to their own account.")
  if (decision === "cancel" && row.proposed_by !== account) throw new VaultError("forbidden", "Only the operator who proposed it cancels it; decline it instead.")
  await requireOperatorReady(env, account, now)
  const state = decision === "decline" ? "declined" : "cancelled"
  await batch(env, [
    stillOpen(env, row, now, "either"),
    readyOperator(env, account, now),
    env.DB.prepare(`UPDATE operator_proposals SET state=?,closed_at=?${decision === "decline" ? ",declined_by=?" : ""} WHERE id=?`).bind(...(decision === "decline" ? [state, now, account, row.id] : [state, now, row.id])),
    deploymentEvent(env, { kind: `proposal.${decision}`, actor: `operator:${account}`, approver: null, target: terms.target, details: { proposal: row.id, kind: terms.kind, proposedBy: `operator:${row.proposed_by}` } }, now),
    ...operatorNotices(env, noticePayload(state, terms.kind, terms.target, row.id, account), now, operatorProposalRule(terms.kind).accept && row.approved_by !== null ? [terms.target] : []),
  ])
  return { done: decision === "decline" ? "Declined. Nothing changed." : "Cancelled. Nothing changed." }
}

// ---------------------------------------------------------------- accepting

// The open, approved proposal of a kind the target accepts, naming this
// account; not_found for any other, the same for one that is not theirs.
async function invitationRow(env: Env, account: string, id: string | null, now: number): Promise<ProposalRow | null> {
  await expireOperatorProposals(env, now)
  const kinds = OperatorProposalKindSchema.options.filter((kind) => operatorProposalRule(kind).accept)
  const rows = await env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE target=? AND state='open' AND approved_by IS NOT NULL AND expires_at>? AND kind IN (${kinds.map(() => "?").join(",")}) ORDER BY approved_at DESC,id`).bind(account, now, ...kinds).all<ProposalRow>()
  const row = rows.results.find((candidate) => id === null || candidate.id === id)
  return row ? signedRow(row) : null
}

export const NO_INVITATION = "No operator role is waiting for you to accept it."

export async function hasOperatorInvitation(env: Env, account: string, id: string, now = Date.now()): Promise<boolean> {
  return (await invitationRow(env, account, id, now)) !== null
}

export async function acceptOperatorProposal(env: Env, account: string, id: string, digest: string, confirm: Confirm, now = Date.now()): Promise<{ done: string }> {
  const row = await invitationRow(env, account, id, now)
  if (!row || row.approved_by === null) throw new VaultError("not_found", NO_INVITATION)
  if (digest !== row.digest) throw new VaultError("conflict", "This is not the role you read. Read it again.")
  const terms = termsOf(row)
  const handler = OPERATOR_KIND_HANDLERS[terms.kind]
  const facts = await operatorAccountFacts(env, account, now)
  if (facts && facts.missing.length > 0) throw new VaultError("forbidden", operatorRequirementsRefusal(facts.missing), { next: { url: `${env.VAULT_ORIGIN}/account`, say: "Your account page shows your passkeys, your recovery and any cooling-off; come back once nothing is missing." } })
  await handler.check(env, terms, now)
  await operatorsStillReady(env, [row.proposed_by, row.approved_by], now)
  await confirm()
  const applying = handler.applying ? await handler.applying(env, terms, row.proposed_by) : { notify: [] }
  const applied = await handler.apply(env, terms, row.proposed_by, now)
  await batch(env, [
    stillOpen(env, row, now, "approved"),
    readyOperator(env, row.proposed_by, now),
    readyOperator(env, row.approved_by, now),
    ...handler.guards(env, terms, now),
    ...operatorNotices(env, noticePayload("applied", terms.kind, terms.target, row.id, row.approved_by), now, applying.notify),
    env.DB.prepare("UPDATE operator_proposals SET state='applied',closed_at=? WHERE id=?").bind(now, row.id),
    ...applied.statements,
    deploymentEvent(env, { kind: terms.kind, actor: `operator:${row.proposed_by}`, approver: `operator:${row.approved_by}`, target: terms.target, details: { proposal: row.id, digest: row.digest, acceptedAt: iso(now), ...applied.details } }, now),
  ])
  await handler.after?.(env, terms, now)
  return { done: "Accepted. You are an operator: the Operator area is in your menu." }
}

// ---------------------------------------------------------------- reads

type Names = Map<string, string>

// The names of these accounts and workspaces, by id.
export async function namesOf(env: Env, ids: Iterable<string>): Promise<Names> {
  const unique = [...new Set(ids)]
  const lookups = [{ table: "accounts", list: unique.filter((id) => !WORKSPACE_ID.test(id)) }, { table: "workspaces", list: unique.filter((id) => WORKSPACE_ID.test(id)) }].filter(({ list }) => list.length > 0)
  const rows = await Promise.all(lookups.map(({ table, list }) => env.DB.prepare(`SELECT id,name FROM ${table} WHERE id IN (${list.map(() => "?").join(",")})`).bind(...list).all<{ id: string; name: string }>()))
  return new Map(rows.flatMap((result) => result.results.map((row) => [row.id, row.name] as const)))
}

function ref(names: Names, account: string): { account: string; name: string } {
  return { account, name: names.get(account) ?? account }
}

function proposalView(row: ProposalRow, names: Names): OperatorProposalView {
  const terms = termsOf(row)
  const rule = operatorProposalRule(terms.kind)
  return {
    id: row.id,
    kind: terms.kind,
    target: row.target,
    targetName: ACCOUNT_ID.test(row.target) || WORKSPACE_ID.test(row.target) ? (names.get(row.target) ?? null) : null,
    params: terms.params,
    digest: row.digest,
    proposedBy: ref(names, row.proposed_by),
    proposedAt: iso(row.proposed_at),
    expiresAt: iso(row.expires_at),
    approvedBy: row.approved_by === null ? null : ref(names, row.approved_by),
    approvedAt: row.approved_at === null ? null : iso(row.approved_at),
    declinedBy: row.declined_by === null ? null : ref(names, row.declined_by),
    state: row.state,
    closedAt: row.closed_at === null ? null : iso(row.closed_at),
    awaiting: row.state !== "open" ? null : row.approved_by === null ? "approval" : rule.accept ? "acceptance" : null,
  }
}

function proposalAccounts(rows: ProposalRow[]): string[] {
  return rows.flatMap((row) => [row.target, row.proposed_by, ...(row.approved_by ? [row.approved_by] : []), ...(row.declined_by ? [row.declined_by] : [])])
}

// The open proposal of this kind for this target, if there is one.
export async function openOperatorProposal(env: Env, kind: OperatorProposalKind, target: string, now = Date.now()): Promise<OperatorProposalView | null> {
  await expireOperatorProposals(env, now)
  const row = await env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE kind=? AND target=? AND state='open'`).bind(kind, target).first<ProposalRow>()
  return row ? proposalView(row, await namesOf(env, proposalAccounts([row]))) : null
}

export async function readOperatorProposal(env: Env, id: string): Promise<OperatorProposalView | null> {
  const row = await env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE id=?`).bind(id).first<ProposalRow>()
  return row ? proposalView(row, await namesOf(env, proposalAccounts([row]))) : null
}

export async function operatorsView(env: Env, you: string, now = Date.now()): Promise<OperatorsView> {
  await expireOperatorProposals(env, now)
  const [operators, open, recent, events] = await Promise.all([
    env.DB.prepare(`SELECT a.id,a.name,a.is_operator_by,(SELECT MAX(at) FROM account_events WHERE account=a.id AND action='operator.grant_operator') AS since,
      (SELECT MAX(last_seen_at) FROM web_sessions WHERE account=a.id AND kind IN ('web','app')) AS last_seen,${operatorFactsColumns("a")}
      FROM accounts a WHERE a.is_operator=1 AND a.status='active' ORDER BY since IS NULL,since,a.id`).all<{ id: string; name: string; is_operator_by: string | null; since: number | null; last_seen: number | null; recovery_ready: number; passkeys: number; security_keys: number; restricted_until: number | null; security_transition: string | null }>(),
    env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE state='open' ORDER BY proposed_at,id`).all<ProposalRow>(),
    env.DB.prepare(`SELECT ${PROPOSAL_COLUMNS} FROM operator_proposals WHERE state!='open' ORDER BY closed_at DESC,id DESC LIMIT ?`).bind(OPERATOR_PROPOSALS_RECENT).all<ProposalRow>(),
    env.DB.prepare("SELECT id,at,kind,actor,approver,target,details FROM deployment_events ORDER BY at DESC,id DESC LIMIT ?").bind(OPERATOR_EVENTS_SHOWN).all<{ id: string; at: number; kind: string; actor: string; approver: string | null; target: string; details: string }>(),
  ])
  const names = await namesOf(env, proposalAccounts([...open.results, ...recent.results]))
  return {
    you,
    operators: operators.results.map((row) => ({ account: row.id, name: row.name, since: row.since === null ? null : iso(row.since), grantedBy: row.is_operator_by, passkeys: row.passkeys, securityKeys: row.security_keys, recoveryReady: row.recovery_ready === 1, lastSeenAt: row.last_seen === null ? null : iso(row.last_seen), missing: missingOf(row, now) })),
    open: open.results.map((row) => proposalView(row, names)),
    recent: recent.results.map((row) => proposalView(row, names)),
    events: events.results.map((row) => ({ id: row.id, at: iso(row.at), kind: row.kind, actor: row.actor, approver: row.approver, target: row.target, details: JSON.parse(row.details) as Record<string, unknown> })),
  }
}

// An active account by its id, or by the email of the Google identity
// linked to it; null when none matches.
export async function operatorCandidate(env: Env, query: string, now = Date.now()): Promise<OperatorCandidate | null> {
  const row = ACCOUNT_ID.test(query)
    ? await env.DB.prepare("SELECT id,name,is_operator FROM accounts WHERE id=? AND status='active'").bind(query).first<{ id: string; name: string; is_operator: number }>()
    : await env.DB.prepare("SELECT a.id,a.name,a.is_operator FROM oidc_identities i JOIN accounts a ON a.id=i.account WHERE lower(i.email)=lower(?) AND a.status='active' ORDER BY i.linked_at,a.id LIMIT 1").bind(query).first<{ id: string; name: string; is_operator: number }>()
  if (!row) return null
  return { account: row.id, name: row.name, operator: row.is_operator === 1, missing: (await operatorAccountFacts(env, row.id, now))?.missing ?? [] }
}

export async function operatorInvitation(env: Env, account: string, now = Date.now()): Promise<OperatorInvitation | null> {
  const row = await invitationRow(env, account, null, now)
  if (!row || row.approved_by === null) return null
  const names = await namesOf(env, [row.proposed_by, row.approved_by])
  return { proposal: row.id, digest: row.digest, proposedBy: ref(names, row.proposed_by), approvedBy: ref(names, row.approved_by), expiresAt: iso(row.expires_at), missing: (await operatorAccountFacts(env, account, now))?.missing ?? [] }
}
