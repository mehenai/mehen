// The Accounts view's reads (OperatorAccountList and OperatorAccountDetail
// in the protocol), and the proposer taking an approved recovery's link.
//
// - The list is one bounded page, newest account first, searched by name,
//   id or linked Google email and filtered; passkeys and sessions are counts
//   and metadata, never keys, hashes or tokens.
// - The recovery link: approving account.break_glass records an intent whose
//   code nobody holds (operator-account-kinds.ts). Once the cron has put the
//   security barrier in place and the intent is ready, the operator who
//   proposed it, and only they, takes the link: a fresh code replaces the
//   unheld one, and the deployment event that records it is also what stops
//   it being shown a second time.

import { ACCOUNT_ID, OPERATOR_ACCOUNT_EVENTS_SHOWN, OPERATOR_ACCOUNT_WORKSPACES_SHOWN, OPERATOR_ACCOUNTS_PAGE, PENDING_RESTRICTION_UNTIL, type OperatorAccountBreakGlass, type OperatorAccountDetail, type OperatorAccountList, type OperatorAccountListQuery, type OperatorAccountSummary, type OperatorBreakGlassLink, type OperatorProposalView } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountBatch, accountGuard } from "./account-store.ts"
import { deploymentEvent, operatorCount, readOperatorProposal, readyOperator } from "./operator-proposals.ts"
import { operatorRequirementsMissing, requireOperatorReady, securityKeySql } from "./operator-requirements.ts"
import { authenticatorWords } from "./passkey-admin.ts"
import { randomToken, sha256Text } from "./session.ts"
import { workspaceCreationDefault, workspaceCreationSource } from "./workspace-creation.ts"

const DAY_MS = 86_400_000

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

type SummaryRow = { id: string; name: string; status: OperatorAccountSummary["status"]; created_at: number; deleted_at: number | null; is_operator: number; suspended_at: number | null; restricted_until: number | null; restricted_reason: "recovery" | "reset" | "break-glass" | null; security_transition: string | null; recovery_setup_kind: "codes" | "passkey" | null; can_create_workspaces: number; can_create_workspaces_by: string | null; email: string | null; last_seen: number | null; workspaces: number; passkeys: number; synced: number; security_keys: number }

const SUMMARY_COLUMNS = `a.id,a.name,a.status,a.created_at,a.deleted_at,a.is_operator,a.suspended_at,a.restricted_until,a.restricted_reason,a.security_transition,a.recovery_setup_kind,a.can_create_workspaces,a.can_create_workspaces_by,
  (SELECT email FROM oidc_identities WHERE account=a.id ORDER BY linked_at,id LIMIT 1) AS email,
  (SELECT MAX(last_seen_at) FROM web_sessions WHERE account=a.id) AS last_seen,
  (SELECT COUNT(DISTINCT workspace) FROM memberships WHERE account=a.id AND state IN ('joining','member')) AS workspaces,
  (SELECT COUNT(*) FROM passkeys p WHERE p.account=a.id) AS passkeys,
  (SELECT COUNT(*) FROM passkeys p WHERE p.account=a.id AND p.backed_up=1) AS synced,
  (SELECT COUNT(*) FROM passkeys p WHERE p.account=a.id AND ${securityKeySql("p")}) AS security_keys`

function summaryOf(row: SummaryRow, now: number): OperatorAccountSummary {
  const coolingOff = row.restricted_until !== null && row.restricted_reason !== null && row.restricted_until > now ? { reason: row.restricted_reason, until: row.restricted_until >= PENDING_RESTRICTION_UNTIL ? null : iso(row.restricted_until) } : null
  return {
    account: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    createdAt: iso(row.created_at),
    operator: row.is_operator === 1,
    suspendedAt: row.suspended_at === null ? null : iso(row.suspended_at),
    coolingOff,
    transitionPending: row.security_transition !== null,
    recovery: row.recovery_setup_kind,
    lastSeenAt: row.last_seen === null ? null : iso(row.last_seen),
    workspaces: row.workspaces,
    passkeys: { count: row.passkeys, synced: row.synced, securityKeys: row.security_keys },
    workspaceCreation: workspaceCreationSource(row),
  }
}

const LIVE_MEMBERSHIP = "EXISTS (SELECT 1 FROM memberships m WHERE m.account=a.id AND m.state IN ('joining','member'))"

// Only these source-owned predicates enter the query; each binds `now` or
// nothing.
const FILTERS: Readonly<Record<OperatorAccountListQuery["filter"], { sql: string; now: boolean }>> = {
  all: { sql: "1", now: false },
  suspended: { sql: "a.suspended_at IS NOT NULL", now: false },
  "cooling-off": { sql: "a.restricted_until>?", now: true },
  "no-recovery": { sql: "a.status='active' AND a.recovery_setup_kind IS NULL", now: false },
  "no-workspace": { sql: `a.status='active' AND NOT ${LIVE_MEMBERSHIP}`, now: false },
  operators: { sql: "a.is_operator=1", now: false },
}

export async function operatorAccountList(env: Env, you: string, query: OperatorAccountListQuery, now = Date.now()): Promise<OperatorAccountList> {
  const where: string[] = []
  const values: (string | number)[] = []
  const filter = FILTERS[query.filter]
  where.push(filter.sql)
  if (filter.now) values.push(now)
  const q = query.q ?? ""
  if (q !== "") {
    where.push("(a.id=? OR instr(lower(a.name),lower(?))>0 OR EXISTS (SELECT 1 FROM oidc_identities i WHERE i.account=a.id AND instr(lower(i.email),lower(?))>0))")
    values.push(q, q, q)
  }
  if (query.before !== undefined) {
    const [at, id] = query.before.split("~") as [string, string]
    where.push("(a.created_at<? OR (a.created_at=? AND a.id<?))")
    values.push(Number(at), Number(at), id)
  }
  const rows = await env.DB.prepare(`SELECT ${SUMMARY_COLUMNS} FROM accounts a WHERE ${where.join(" AND ")} ORDER BY a.created_at DESC,a.id DESC LIMIT ?`).bind(...values, OPERATOR_ACCOUNTS_PAGE + 1).all<SummaryRow>()
  const page = rows.results.slice(0, OPERATOR_ACCOUNTS_PAGE)
  const last = page.at(-1)
  return {
    you,
    operators: await operatorCount(env),
    workspaceCreation: await workspaceCreationDefault(env),
    missing: await operatorRequirementsMissing(env, you, now),
    accounts: page.map((row) => summaryOf(row, now)),
    next: rows.results.length > OPERATOR_ACCOUNTS_PAGE && last ? `${last.created_at}~${last.id}` : null,
  }
}

type IntentRow = { id: string; actor: string; state: "pending" | "ready"; expires_at: number; taken: number }

// The account's recovery link while one is live, and whether its link was
// taken already.
async function liveIntent(env: Env, account: string, now: number): Promise<IntentRow | null> {
  return env.DB.prepare(`SELECT i.id,i.actor,i.state,i.expires_at,EXISTS (SELECT 1 FROM deployment_events e WHERE e.kind='account.break_glass_link' AND e.target=i.account AND json_extract(e.details,'$.intent')=i.id) AS taken
    FROM account_break_glass_intents i WHERE i.account=? AND i.state IN ('pending','ready') AND i.expires_at>? ORDER BY i.created_at DESC LIMIT 1`).bind(account, now).first<IntentRow>()
}

export async function operatorAccountDetail(env: Env, you: string, account: string, now = Date.now()): Promise<OperatorAccountDetail | null> {
  const row = await env.DB.prepare(`SELECT ${SUMMARY_COLUMNS} FROM accounts a WHERE a.id=?`).bind(account).first<SummaryRow>()
  if (!row) return null
  const [emails, workspaces, passkeys, sessions, events, open, intent] = await Promise.all([
    env.DB.prepare("SELECT email FROM oidc_identities WHERE account=? ORDER BY linked_at,id").bind(account).all<{ email: string }>(),
    env.DB.prepare("SELECT w.id,w.slug,w.name,m.role_hint,m.state,m.updated_at FROM memberships m JOIN workspaces w ON w.id=m.workspace WHERE m.account=? ORDER BY m.state='left',m.updated_at DESC,w.id LIMIT ?").bind(account, OPERATOR_ACCOUNT_WORKSPACES_SHOWN).all<{ id: string; slug: string; name: string; role_hint: "owner" | "admin" | "member" | "guest"; state: "joining" | "member" | "left"; updated_at: number }>(),
    env.DB.prepare("SELECT name,transports,backed_up,added_via,created_at,last_used_at FROM passkeys WHERE account=? ORDER BY created_at,handle").bind(account).all<{ name: string | null; transports: string | null; backed_up: number | null; added_via: OperatorAccountDetail["passkeys"][number]["addedVia"]; created_at: number; last_used_at: number | null }>(),
    env.DB.prepare(`SELECT
      SUM(kind='web' AND expires_at>? AND last_seen_at>?) AS web,SUM(kind='app' AND expires_at>? AND last_seen_at>?) AS app,SUM(kind='recovery' AND expires_at>?) AS recovery,MAX(last_seen_at) AS last_seen
      FROM web_sessions s WHERE s.account=? AND NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.revoked_sessions) r WHERE t.account=s.account AND t.state='pending' AND r.value=s.id)`).bind(now, now - 7 * DAY_MS, now, now - 7 * DAY_MS, now, account).first<{ web: number | null; app: number | null; recovery: number | null; last_seen: number | null }>(),
    env.DB.prepare("SELECT id,at,action,detail FROM account_events WHERE account=? ORDER BY at DESC,id DESC LIMIT ?").bind(account, OPERATOR_ACCOUNT_EVENTS_SHOWN).all<{ id: string; at: number; action: string; detail: string }>(),
    env.DB.prepare("SELECT id FROM operator_proposals WHERE target=? AND state='open' AND expires_at>? ORDER BY proposed_at,id").bind(account, now).all<{ id: string }>(),
    liveIntent(env, account, now),
  ])
  const proposals = (await Promise.all(open.results.map((p) => readOperatorProposal(env, p.id)))).filter((p): p is OperatorProposalView => p !== null)
  const breakGlass: OperatorAccountBreakGlass | null = intent === null ? null : { intent: intent.id, state: intent.state, expiresAt: iso(intent.expires_at), proposedBy: intent.actor, yours: intent.actor === `operator:${you}`, linkTaken: intent.taken === 1 }
  return {
    you,
    operators: await operatorCount(env),
    workspaceCreationDefault: await workspaceCreationDefault(env),
    missing: await operatorRequirementsMissing(env, you, now),
    account: summaryOf(row, now),
    emails: emails.results.map((e) => e.email),
    deletedAt: row.deleted_at === null ? null : iso(row.deleted_at),
    workspaces: workspaces.results.map((w) => ({ workspace: w.id, slug: w.slug, name: w.name, roleHint: w.role_hint, state: w.state, since: iso(w.updated_at) })),
    passkeys: passkeys.results.map((p) => {
      const transports: unknown = JSON.parse(p.transports ?? "[]")
      return { name: p.name, authenticator: authenticatorWords(Array.isArray(transports) ? transports.filter((t): t is string => typeof t === "string") : []), synced: p.backed_up === null ? null : p.backed_up === 1, addedVia: p.added_via, createdAt: iso(p.created_at), lastUsedAt: p.last_used_at === null ? null : iso(p.last_used_at) }
    }),
    sessions: { web: sessions?.web ?? 0, app: sessions?.app ?? 0, recovery: sessions?.recovery ?? 0, lastSeenAt: sessions?.last_seen == null ? null : iso(sessions.last_seen) },
    events: events.results.map((e) => ({ id: e.id, at: iso(e.at), action: e.action, detail: JSON.parse(e.detail) as Record<string, unknown> })),
    open: proposals,
    breakGlass,
  }
}

// ---------------------------------------------------------------- the recovery link

// The intent ready to redeem, as scripts/break-glass.ts waits for it: the
// barrier committed on every workspace and its code live.
const READY = `i.state='ready' AND i.expires_at>? AND EXISTS (SELECT 1 FROM account_security_transitions t JOIN accounts a ON a.id=t.account JOIN invite_codes c ON c.code_hash=i.code_hash
  WHERE t.id=i.transition_id AND t.state='committed' AND a.status='active' AND a.security_transition IS NULL AND a.security_epoch=t.reserved_epoch AND c.kind='break-glass' AND c.state='active' AND c.used_at IS NULL AND c.expires_at>?)`
const NOT_TAKEN = "NOT EXISTS (SELECT 1 FROM deployment_events e WHERE e.kind='account.break_glass_link' AND e.target=i.account AND json_extract(e.details,'$.intent')=i.id)"

export async function takeBreakGlassLink(env: Env, operator: string, account: string, intent: string, confirm: () => Promise<unknown>, now = Date.now()): Promise<OperatorBreakGlassLink> {
  if (!ACCOUNT_ID.test(account)) throw new VaultError("not_found", "No such account.")
  await requireOperatorReady(env, operator, now)
  const row = await env.DB.prepare(`SELECT i.id,i.actor,i.state,i.expires_at,i.code_hash,NOT ${NOT_TAKEN} AS taken,${READY} AS ready FROM account_break_glass_intents i WHERE i.id=? AND i.account=?`).bind(now, now, intent, account).first<{ id: string; actor: string; state: string; expires_at: number; code_hash: string; taken: number; ready: number }>()
  if (!row) throw new VaultError("not_found", "No recovery link is on its way for this account.")
  if (row.actor !== `operator:${operator}`) throw new VaultError("forbidden", "Only the operator who proposed recovering this account's access takes its link.")
  if (row.taken === 1) throw new VaultError("conflict", "This link was shown once already and is not shown again. If it was lost, let it expire and propose recovering access again.")
  if (row.state === "pending" && row.expires_at > now) throw new VaultError("conflict", "Not yet: every workspace still has to end the account's old sessions and passkeys. Try again in a minute.")
  if (row.ready !== 1) throw new VaultError("conflict", "This recovery link expired or was used; propose recovering access again.")
  await confirm()
  const code = randomToken(24)
  const hash = await sha256Text(code)
  try {
    await accountBatch(env, [
      readyOperator(env, operator, now),
      accountGuard(env, `EXISTS (SELECT 1 FROM account_break_glass_intents i WHERE i.id=? AND i.account=? AND i.code_hash=? AND ${READY} AND ${NOT_TAKEN})`, [row.id, account, row.code_hash, now, now]),
      env.DB.prepare("UPDATE invite_codes SET code_hash=? WHERE code_hash=? AND kind='break-glass' AND account=?").bind(hash, row.code_hash, account),
      env.DB.prepare("UPDATE account_break_glass_intents SET code_hash=? WHERE id=? AND account=? AND state='ready'").bind(hash, row.id, account),
      deploymentEvent(env, { kind: "account.break_glass_link", actor: `operator:${operator}`, approver: null, target: account, details: { intent: row.id } }, now),
    ])
  } catch (error) {
    if (error instanceof VaultError && error.code === "conflict") throw new VaultError("conflict", "Nothing shown: the recovery link changed while this ran. Read the account again.")
    throw error
  }
  return { link: `${env.VAULT_ORIGIN}/signup#${code}`, expiresAt: iso(row.expires_at) }
}
