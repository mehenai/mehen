// What the Accounts view's proposal kinds check and apply (the kinds in
// OPERATOR_PROPOSAL_KINDS; operator-proposals.ts runs them like every
// other):
//
// - account.workspace_creation: one operator allows, denies or returns one
//   account's workspace creation to the deployment default. It writes the
//   columns scripts/operator.ts writes, with the operator event and notice
//   the 0005 trigger writes when the flag changes, and the same rows written
//   here when it does not. Only the account is told.
// - account.suspend and account.lift_suspension: one operator, never on an
//   operator account. Suspending deletes every session in its batch and
//   raises the security epoch in every workspace after it (the cron's when
//   that fails), and each workspace's owners and admins get a notice;
//   lifting clears the flag and the person signs in again.
// - account.break_glass: two operators, never on an operator account (its
//   proposer, who alone takes the link, would hold a second operator
//   account). Approving records the intent scripts/break-glass.ts records,
//   as the proposer, with a code nobody holds; the cron installs the
//   security barrier as for the script, and the proposer takes the link,
//   once (operator-accounts.ts).
// - account.delete: two operators, the name typed back (the proposal keeps
//   only its hash), only for an account in no workspace and no platform's
//   admin, and never an operator's. The account keeps its row and its
//   events; its name, passkeys, sessions, recovery codes, linked identities
//   and notices go.

import { DELETED_ACCOUNT_NAME, type OperatorProposalTerms, accountDeleteNameHash, type WorkspaceCreationSource, AccountBreakGlassParamsSchema, AccountDeleteParamsSchema, AccountWorkspaceCreationChoiceSchema } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountEvent, accountGuard } from "./account-store.ts"
import { endSuspendedAccountSessions } from "./account-suspension.ts"
import type { OperatorKindHandler } from "./operator-proposal-kinds.ts"
import { randomToken } from "./session.ts"
import { workspaceCreationSource } from "./workspace-creation.ts"

type AccountRow = { name: string; is_operator: number; suspended_at: number | null; security_transition: string | null; can_create_workspaces: number; can_create_workspaces_by: string | null }

async function activeAccount(env: Env, account: string): Promise<AccountRow> {
  const row = await env.DB.prepare("SELECT name,is_operator,suspended_at,security_transition,can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id=? AND status='active'").bind(account).first<AccountRow>()
  if (!row) throw new VaultError("not_found", "No active account has that id.")
  return row
}

function notOperator(row: AccountRow, change: string): void {
  if (row.is_operator === 1) throw new VaultError("forbidden", `${row.name} is an operator, and an operator's account is never ${change}. End their operator role first.`)
}

function accountNotice(env: Env, account: string, payload: Record<string, unknown>, now: number): D1PreparedStatement {
  return env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) VALUES (?,?,'workspace',?,?)").bind(`ntc_${crypto.randomUUID().replaceAll("-", "")}`, account, JSON.stringify(payload), now)
}

// ---------------------------------------------------------------- workspace creation

const CREATION_SOURCE = { allow: "operator-allowed", deny: "operator-denied", default: "default" } as const satisfies Record<string, WorkspaceCreationSource>
const CREATION_WORDS: Readonly<Record<WorkspaceCreationSource, string>> = { "operator-allowed": "allowed by an operator", "operator-denied": "denied by an operator", default: "the deployment default" }

function creationChoice(terms: OperatorProposalTerms) {
  return AccountWorkspaceCreationChoiceSchema.parse(terms.params.creation)
}

const workspaceCreation: OperatorKindHandler = {
  async check(env, terms) {
    const row = await activeAccount(env, terms.target)
    const source = workspaceCreationSource(row)
    if (source === CREATION_SOURCE[creationChoice(terms)]) throw new VaultError("conflict", `${row.name}'s workspace creation is ${CREATION_WORDS[source]} already.`)
  },
  guards: () => [],
  // The flag's trigger writes the event and notice only when the flag
  // changes; the rows before the UPDATE write them, from the state it
  // replaces, when it does not. The last guard checks the UPDATE landed.
  apply(env, terms, proposer, now) {
    const by = `operator:${proposer}`
    const op = crypto.randomUUID()
    const choice = creationChoice(terms)
    const unchanged = (value: 0 | 1) => [
      env.DB.prepare(`INSERT INTO account_events(id,account,at,action,detail,targets) SELECT ?,id,?,?,?,'[]' FROM accounts WHERE id=? AND status='active' AND can_create_workspaces=${value}`).bind(`evt_${crypto.randomUUID()}`, now, value === 1 ? "operator.allow_workspaces" : "operator.deny_workspaces", JSON.stringify({ by, allowed: value }), terms.target),
      env.DB.prepare(`INSERT INTO account_notices(id,account,kind,payload,at) SELECT ?,id,'workspace',?,? FROM accounts WHERE id=? AND status='active' AND can_create_workspaces=${value}`).bind(`ntc_${crypto.randomUUID().replaceAll("-", "")}`, JSON.stringify({ change: "workspace_creation", allowed: value, by }), now, terms.target),
    ]
    const landed = accountGuard(env, "EXISTS (SELECT 1 FROM accounts WHERE id=? AND can_create_workspaces_op=?)", [terms.target, op])
    const details = { creation: choice }
    if (choice === "default") return {
      statements: [
        env.DB.prepare("UPDATE accounts SET can_create_workspaces_by=NULL,can_create_workspaces_op=? WHERE id=? AND status='active' AND can_create_workspaces_by IS NOT NULL").bind(op, terms.target),
        landed,
        env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets) VALUES (?,?,?,'operator.default_workspaces',?,'[]')").bind(`evt_${crypto.randomUUID()}`, terms.target, now, JSON.stringify({ by, allowed: null })),
        accountNotice(env, terms.target, { change: "workspace_creation", allowed: null, by }, now),
      ],
      details,
    }
    const value = choice === "allow" ? 1 : 0
    return {
      statements: [
        ...unchanged(value),
        env.DB.prepare(`UPDATE accounts SET can_create_workspaces=${value},can_create_workspaces_by=?,can_create_workspaces_op=? WHERE id=? AND status='active'`).bind(by, op, terms.target),
        landed,
      ],
      details,
    }
  },
  done: (name, terms) => {
    const choice = creationChoice(terms)
    return choice === "default" ? `${name}'s workspace creation follows the deployment default again.` : `${name} ${choice === "allow" ? "may" : "may not"} create workspaces.`
  },
  tellsOperators: false,
}

// ---------------------------------------------------------------- suspension

const suspend: OperatorKindHandler = {
  async check(env, terms) {
    const row = await activeAccount(env, terms.target)
    notOperator(row, "suspended")
    if (row.suspended_at !== null) throw new VaultError("conflict", `${row.name}'s account is suspended already.`)
  },
  guards: (env, terms) => [accountGuard(env, "EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND is_operator=0 AND suspended_at IS NULL)", [terms.target])],
  // Every session ends here, in the batch, so lifting the suspension never
  // brings one back.
  apply: (env, terms, proposer, now) => ({
    statements: [
      env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by=? WHERE id=? AND status='active' AND is_operator=0 AND suspended_at IS NULL").bind(now, `operator:${proposer}`, terms.target),
      env.DB.prepare("DELETE FROM web_sessions WHERE account=?").bind(terms.target),
      accountEvent(env, terms.target, "account.suspend", { by: `operator:${proposer}` }, now),
      accountNotice(env, terms.target, { change: "account_suspension", suspended: true, by: `operator:${proposer}` }, now),
    ],
  }),
  // Each workspace raises the account's security epoch; when this fails,
  // the cron reserves it again (reconcileSuspendedAccounts).
  async after(env, terms, now) {
    try {
      await endSuspendedAccountSessions(env, terms.target, now)
    } catch {
      console.error(JSON.stringify({ at: "account.suspend.sessions_pending", account: terms.target }))
    }
  },
  done: (name) => `${name}'s account is suspended: every session ends, and they cannot sign in until an operator lifts it.`,
}

const liftSuspension: OperatorKindHandler = {
  async check(env, terms) {
    const row = await activeAccount(env, terms.target)
    if (row.suspended_at === null) throw new VaultError("conflict", `${row.name}'s account is not suspended.`)
  },
  guards: (env, terms) => [accountGuard(env, "EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND suspended_at IS NOT NULL)", [terms.target])],
  apply: (env, terms, proposer, now) => ({
    statements: [
      env.DB.prepare("UPDATE accounts SET suspended_at=NULL,suspended_by=NULL WHERE id=? AND status='active' AND suspended_at IS NOT NULL").bind(terms.target),
      accountEvent(env, terms.target, "account.lift_suspension", { by: `operator:${proposer}` }, now),
      accountNotice(env, terms.target, { change: "account_suspension", suspended: false, by: `operator:${proposer}` }, now),
    ],
  }),
  done: (name) => `${name}'s suspension is lifted; they sign in again with their passkey.`,
}

// ---------------------------------------------------------------- recovering access

const LIVE_INTENT = "EXISTS (SELECT 1 FROM account_break_glass_intents WHERE account=? AND state IN ('pending','ready') AND expires_at>?)"

// How the proposer verified the person, out of band.
function verifiedBy(terms: OperatorProposalTerms): Record<string, unknown> {
  return { verified: AccountBreakGlassParamsSchema.parse(terms.params).verified }
}

const breakGlass: OperatorKindHandler = {
  async check(env, terms, now) {
    const row = await activeAccount(env, terms.target)
    notOperator(row, "recovered in the app")
    if (row.suspended_at !== null) throw new VaultError("conflict", `${row.name}'s account is suspended; lift the suspension before recovering their access.`)
    if (await env.DB.prepare(`SELECT 1 AS live WHERE ${LIVE_INTENT}`).bind(terms.target, now).first()) throw new VaultError("conflict", `A recovery link for ${row.name} is already on its way; it expires within the hour.`)
  },
  guards: (env, terms, now) => [accountGuard(env, `EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND is_operator=0 AND suspended_at IS NULL) AND NOT ${LIVE_INTENT}`, [terms.target, terms.target, now])],
  // The intent the script records, as the proposer. Its code is one nobody
  // holds: the proposer's link replaces it, once the barrier is in place.
  // The 0007 trigger writes the account's event and notice.
  apply: (env, terms, proposer, now) => ({
    statements: [
      env.DB.prepare("INSERT INTO account_break_glass_intents(id,account,actor,code_hash,notice,created_at,expires_at) VALUES (?,?,?,?,?,?,?)").bind(`bgi_${crypto.randomUUID().replaceAll("-", "")}`, terms.target, `operator:${proposer}`, randomToken(32), `ntc_${crypto.randomUUID().replaceAll("-", "")}`, now, now + 3_600_000),
    ],
    details: verifiedBy(terms),
  }),
  proposed: verifiedBy,
  done: (name) => `Approved. Recovering ${name}'s access has begun: once every workspace has ended their old sessions and passkeys, the operator who proposed it takes the single-use link on ${name}'s page, once, within the hour.`,
}

// ---------------------------------------------------------------- deleting

const LIVE_MEMBERSHIP = "EXISTS (SELECT 1 FROM memberships WHERE account=? AND state IN ('joining','member'))"
const LIVE_PLATFORM_ADMIN = "EXISTS (SELECT 1 FROM platform_admins WHERE account=? AND removed_at IS NULL)"

const deleteAccount: OperatorKindHandler = {
  async check(env, terms) {
    const row = await activeAccount(env, terms.target)
    notOperator(row, "deleted")
    if (AccountDeleteParamsSchema.parse(terms.params).nameHash !== await accountDeleteNameHash(terms.target, row.name)) throw new VaultError("bad_request", "Type the account's name exactly as shown to confirm.")
    const workspaces = await env.DB.prepare("SELECT w.name,w.slug FROM memberships m JOIN workspaces w ON w.id=m.workspace WHERE m.account=? AND m.state IN ('joining','member') ORDER BY w.slug LIMIT 20").bind(terms.target).all<{ name: string; slug: string }>()
    if (workspaces.results.length > 0) throw new VaultError("conflict", `${row.name} is still a member of ${workspaces.results.map((w) => `${w.name} (${w.slug})`).join(", ")}. Each workspace's owners remove them first.`)
    const platforms = await env.DB.prepare("SELECT p.name,p.slug FROM platform_admins pa JOIN platforms p ON p.id=pa.platform WHERE pa.account=? AND pa.removed_at IS NULL ORDER BY p.slug LIMIT 20").bind(terms.target).all<{ name: string; slug: string }>()
    if (platforms.results.length > 0) throw new VaultError("conflict", `${row.name} is still an admin of ${platforms.results.map((p) => `${p.name} (${p.slug})`).join(", ")}. Remove them on each platform's page first.`)
    if (row.security_transition !== null) throw new VaultError("conflict", `A security change to ${row.name}'s account is still reaching their workspaces; delete it once that finishes.`)
  },
  // The typed name is checked against its hash in check, which runs at
  // proposing and again at approving.
  guards: (env, terms) => [accountGuard(env, `EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND is_operator=0 AND security_transition IS NULL) AND NOT ${LIVE_MEMBERSHIP} AND NOT ${LIVE_PLATFORM_ADMIN}`, [terms.target, terms.target, terms.target])],
  apply: (env, terms, proposer, now) => {
    const account = terms.target
    const by = `operator:${proposer}`
    return {
      statements: [
        ...["session_identity_checks", "operation_identity_checks", "oidc_identities", "web_sessions", "passkeys", "recovery_codes", "recovery_batches", "challenges", "account_notices"].map((table) => env.DB.prepare(`DELETE FROM ${table} WHERE account=?`).bind(account)),
        env.DB.prepare("UPDATE account_break_glass_intents SET state='expired' WHERE account=? AND state IN ('pending','ready')").bind(account),
        env.DB.prepare("UPDATE accounts SET status='deleted',deleted_at=?,name=?,recovery_setup_at=NULL,recovery_setup_kind=NULL WHERE id=? AND status='active' AND is_operator=0").bind(now, DELETED_ACCOUNT_NAME, account),
        accountEvent(env, account, "account.delete", { by }, now),
      ],
    }
  },
  done: (name) => `${name}'s account is deleted. Its events stay.`,
}

export const ACCOUNT_KIND_HANDLERS = {
  "account.workspace_creation": workspaceCreation,
  "account.suspend": suspend,
  "account.lift_suspension": liftSuspension,
  "account.break_glass": breakGlass,
  "account.delete": deleteAccount,
} as const satisfies Record<string, OperatorKindHandler>
