// What each kind of operator proposal (OPERATOR_PROPOSAL_KINDS in the
// protocol) checks and applies: the operator role, and a workspace's
// restore and freeze (an account's are in operator-account-kinds.ts, a
// deployment setting's in deployment-settings.ts).
// operator-proposals.ts runs every kind the
// same way: these say only what is particular to one. A kind added here and
// in the protocol needs nothing else.
//
// The operator role is the one Worker write of accounts.is_operator: the
// statements below, run only inside an applied proposal's guarded batch
// (or, for resigning, the resigning operator's own). The 0012 trigger still
// refuses a change without an explicit operator: actor and a fresh
// operation id, and writes the operator event and the target's notice.

import { NEEDS_SECOND_OPERATOR_WORDS, type OperatorProposalKind, type OperatorProposalTerms, WorkspaceRestoreParamsSchema, operatorRequirementsRefusal } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountGuard } from "./account-store.ts"
import { DEPLOYMENT_SETTING_KIND_HANDLERS } from "./deployment-settings.ts"
import { ACCOUNT_KIND_HANDLERS } from "./operator-account-kinds.ts"
import { operatorWorkspaceClient } from "./operator-workspace-client.ts"
import { operatorAccountFacts, operatorReadySql } from "./operator-requirements.ts"
import { newRestoreIntent, restoreIntentDigest, restoreIntentInsert, restorePointInWindow } from "./vault-backups.ts"

export const LAST_OPERATOR = NEEDS_SECOND_OPERATOR_WORDS.resign

export type OperatorKindApplied = { statements: D1PreparedStatement[]; details?: Record<string, unknown> }

export type OperatorKindHandler = {
  // Refuses, in plain words and before any passkey, a change that cannot
  // apply to its target now.
  check(env: Env, terms: OperatorProposalTerms, now: number): Promise<void>
  // What must still hold when it applies: guards at the head of the batch.
  guards(env: Env, terms: OperatorProposalTerms, now: number): D1PreparedStatement[]
  // What applying changes outside D1, if anything (a workspace object's own
  // freeze), after the last passkey and just before the batch that records
  // it; and the accounts beyond the operators that the notice of it also
  // goes to. Throws, so nothing is recorded, when it finds the change made
  // already.
  applying?(env: Env, terms: OperatorProposalTerms, proposer: string): Promise<{ notify: string[] }>
  // The effect, after the guards, and what its deployment_events row adds
  // to name what it made; `proposer` is the account that proposed.
  apply(env: Env, terms: OperatorProposalTerms, proposer: string, now: number): OperatorKindApplied | Promise<OperatorKindApplied>
  // What the vault answers once it has applied, with the target's name.
  done(targetName: string, terms: OperatorProposalTerms): string
  // What still follows once the batch has applied, outside it; a failure
  // here is the cron's to finish.
  after?(env: Env, terms: OperatorProposalTerms, now: number): Promise<void>
  // What a two-operator proposal's proposal.open row records besides its
  // digest.
  proposed?(terms: OperatorProposalTerms): Record<string, unknown>
  // false for a change only its target is told of; every operator is told
  // of every other.
  tellsOperators?: false
}

type TargetRow = { name: string; is_operator: number }

async function activeAccount(env: Env, account: string): Promise<TargetRow> {
  const row = await env.DB.prepare("SELECT name,is_operator FROM accounts WHERE id=? AND status='active'").bind(account).first<TargetRow>()
  if (!row) throw new VaultError("not_found", "No active account has that id.")
  return row
}

async function otherOperators(env: Env, account: string): Promise<number> {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM accounts WHERE is_operator=1 AND status='active' AND id!=?").bind(account).first<{ n: number }>())?.n ?? 0
}

function roleChange(env: Env, target: string, value: 0 | 1, by: string): D1PreparedStatement {
  return env.DB.prepare(`UPDATE accounts SET is_operator=${value},is_operator_by=?,is_operator_op=? WHERE id=? AND status='active' AND is_operator=${1 - value}`).bind(`operator:${by}`, crypto.randomUUID(), target)
}

// The role ends for `target` only while another operator keeps it.
function notLast(env: Env, target: string): D1PreparedStatement {
  return accountGuard(env, "EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND is_operator=1) AND EXISTS (SELECT 1 FROM accounts WHERE is_operator=1 AND status='active' AND id!=?)", [target, target])
}

async function roleEnds(env: Env, target: string): Promise<void> {
  const row = await activeAccount(env, target)
  if (row.is_operator !== 1) throw new VaultError("conflict", `${row.name} is not an operator.`)
  if ((await otherOperators(env, target)) === 0) throw new VaultError("conflict", LAST_OPERATOR)
}

// ---------------------------------------------------------------- workspaces

async function workspaceNamed(env: Env, tenant: string): Promise<{ name: string; status: string }> {
  const row = await env.DB.prepare("SELECT name,status FROM workspaces WHERE id=?").bind(tenant).first<{ name: string; status: string }>()
  if (!row) throw new VaultError("not_found", "No workspace has that id.")
  return row
}

function activeWorkspace(env: Env, tenant: string): D1PreparedStatement {
  return accountGuard(env, "EXISTS (SELECT 1 FROM workspaces WHERE id=? AND status='active')", [tenant])
}

function liveRestore(env: Env, tenant: string): D1PreparedStatement {
  return accountGuard(env, "NOT EXISTS (SELECT 1 FROM vault_restore_intents WHERE tenant=? AND state IN ('pending','restarting'))", [tenant])
}

function recordedDump(env: Env, tenant: string, date: string): D1PreparedStatement {
  return accountGuard(env, "EXISTS (SELECT 1 FROM vault_backup_runs WHERE tenant=? AND date=? AND outcome='ok')", [tenant, date])
}

// The workspace's owners as the object says, or as the directory's hints
// say when the object cannot answer (a lost workspace, being restored).
async function workspaceOwners(env: Env, tenant: string): Promise<string[]> {
  try {
    return (await operatorWorkspaceClient(env).view(tenant)).owners.map((o) => o.account)
  } catch {
    return (await env.DB.prepare("SELECT account FROM memberships WHERE workspace=? AND state='member' AND role_hint='owner' ORDER BY account").bind(tenant).all<{ account: string }>()).results.map((row) => row.account)
  }
}

// The restore intent scripts/vault-backup.ts records, with the same
// checks first: a recorded dump of that day, or a point within the last 30
// days, and no other restore of the workspace in progress. The cron does
// the rest (vault-backups.ts), as for the script's. Only an active
// workspace: one being created has nothing to restore, and a restore does
// not stop a deletion.
const workspaceRestore: OperatorKindHandler = {
  async check(env, terms, now) {
    const workspace = await workspaceNamed(env, terms.target)
    if (workspace.status !== "active") throw new VaultError("conflict", `${workspace.name} is ${workspace.status}; only an active workspace is restored.`)
    const params = WorkspaceRestoreParamsSchema.parse(terms.params)
    if (params.source === "dump" && !(await env.DB.prepare("SELECT 1 FROM vault_backup_runs WHERE tenant=? AND date=? AND outcome='ok'").bind(terms.target, params.target).first())) throw new VaultError("conflict", "There is no recorded dump of that workspace on that day.")
    if (params.source === "pitr" && !restorePointInWindow(params.target, now)) throw new VaultError("conflict", "A point-in-time restore reaches back at most 30 days, and not into the future.")
    const live = await env.DB.prepare("SELECT id FROM vault_restore_intents WHERE tenant=? AND state IN ('pending','restarting')").bind(terms.target).first<{ id: string }>()
    if (live) throw new VaultError("conflict", `Restore ${live.id} of this workspace is still in progress.`)
  },
  guards(env, terms) {
    const params = WorkspaceRestoreParamsSchema.parse(terms.params)
    return [activeWorkspace(env, terms.target), liveRestore(env, terms.target), ...(params.source === "dump" ? [recordedDump(env, terms.target, params.target)] : [])]
  },
  applying: async (env, terms) => ({ notify: await workspaceOwners(env, terms.target) }),
  async apply(env, terms, proposer, now) {
    const params = WorkspaceRestoreParamsSchema.parse(terms.params)
    const intent = newRestoreIntent({ tenant: terms.target, actor: `operator:${proposer}`, source: params.source, target: params.target }, now)
    return { statements: [restoreIntentInsert(env, intent, await restoreIntentDigest(intent))], details: { intent: intent.id } }
  },
  done: (name) => `Approved. The restore of ${name} is recorded, and the cron carries it out within the hour. Its owners re-apply what it undid, then unfreeze it.`,
}

// The workspace's own freeze, pulled by one operator as a brake. The
// object freezes first, in its own audit chain as the operator; the batch
// then records it (proposeOperatorChange). An owner's freeze that landed
// first is not recorded as the operator's. Only an owner unfreezes it.
const workspaceFreeze: OperatorKindHandler = {
  async check(env, terms) {
    const workspace = await workspaceNamed(env, terms.target)
    if (workspace.status !== "active") throw new VaultError("conflict", `${workspace.name} is ${workspace.status}, so there is nothing to freeze.`)
    if ((await operatorWorkspaceClient(env).view(terms.target)).frozen) throw new VaultError("conflict", `${workspace.name} is frozen already.`)
  },
  guards: (env, terms) => [activeWorkspace(env, terms.target)],
  async applying(env, terms, proposer) {
    const answer = await operatorWorkspaceClient(env).freeze(terms.target, proposer)
    if (answer.already) throw new VaultError("conflict", `${(await workspaceNamed(env, terms.target)).name} is frozen already.`)
    return { notify: answer.notify }
  },
  apply: () => ({ statements: [] }),
  done: (name) => `${name} is frozen. Its owners unfreeze it from its home page, with a passkey.`,
}

export const OPERATOR_KIND_HANDLERS: Readonly<Record<OperatorProposalKind, OperatorKindHandler>> = {
  // The target's account must have everything an operator account needs,
  // when proposed, approved and accepted.
  "operator.grant": {
    async check(env, terms, now) {
      const row = await activeAccount(env, terms.target)
      if (row.is_operator === 1) throw new VaultError("conflict", `${row.name} is an operator already.`)
      const facts = await operatorAccountFacts(env, terms.target, now)
      if (facts && facts.missing.length > 0) throw new VaultError("forbidden", operatorRequirementsRefusal(facts.missing, `${row.name}'s account`))
    },
    guards: (env, terms, now) => [accountGuard(env, `EXISTS (SELECT 1 FROM accounts a WHERE a.id=? AND a.status='active' AND a.is_operator=0 AND ${operatorReadySql("a")})`, [terms.target, now])],
    apply: (env, terms, proposer) => ({ statements: [roleChange(env, terms.target, 1, proposer)] }),
    done: (name) => `${name} is an operator.`,
  },
  "operator.revoke": {
    check: (env, terms) => roleEnds(env, terms.target),
    guards: (env, terms) => [notLast(env, terms.target)],
    apply: (env, terms, proposer) => ({ statements: [roleChange(env, terms.target, 0, proposer)] }),
    done: (name) => `${name} is no longer an operator.`,
  },
  // Your own role, so it only removes power: no requirement to meet.
  "operator.resign": {
    check: (env, terms) => roleEnds(env, terms.target),
    guards: (env, terms) => [notLast(env, terms.target)],
    apply: (env, terms, proposer) => ({ statements: [roleChange(env, terms.target, 0, proposer)] }),
    done: () => "You are no longer an operator.",
  },
  "workspace.restore": workspaceRestore,
  "workspace.freeze": workspaceFreeze,
  ...ACCOUNT_KIND_HANDLERS,
  ...DEPLOYMENT_SETTING_KIND_HANDLERS,
}
