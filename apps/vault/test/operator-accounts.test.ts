// The Accounts view (routes/console-accounts.ts, directory/operator-accounts.ts)
// and its proposal kinds (directory/operator-account-kinds.ts) through the
// real Worker, with real web sessions, the real passkey step-up and the
// directory's real security transitions against stand-in workspaces.

import { describe, expect, it, vi } from "vitest"
import { type OperatorAccountDetail, accountDeleteNameHash, type OperatorAccountList, type OperatorBreakGlassLink, type OperatorProposalAnswer, type OperatorProposalKind, NEEDS_SECOND_OPERATOR_WORDS, operatorApproveStepUpAction, operatorBreakGlassLinkStepUpAction, operatorProposeStepUpAction } from "@mehen/protocol"
import { reconcileAccountBreakGlass, accountBreakGlassOptions } from "../src/directory/account-break-glass.ts"
import { mirrorAccountEvents } from "../src/directory/account-events.ts"
import { ACCOUNT_SUSPENDED, reconcileSuspendedAccounts } from "../src/directory/account-suspension.ts"
import { accountBatch } from "../src/directory/account-store.ts"
import { ACCOUNT_KIND_HANDLERS } from "../src/directory/operator-account-kinds.ts"
import { assertAccountStepUpAllowed } from "../src/directory/workspace-stepup.ts"
import { currentAccountAppSession } from "../src/directory/workspace-app-session.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { confirmAccountRecoveryCodes, issueAccountRecoveryCodes, startAccountRecovery } from "../src/directory/workspace-recovery.ts"
import { sha256Text } from "../src/directory/session.ts"
import { assertion } from "./e2e/passkeys.ts"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"
import { successfulDirectoryClient } from "./directory-test-support.ts"
import { DEFAULT_WORKSPACE_ANSWER, type WorkspaceAnswer } from "./platform-fixtures.ts"

const HIDDEN = { error: "not_found", message: "No such operation." }
const OPERATOR_START = "/api/operator/stepup/start"
const WORK = "tn_Beta1234567"

// The workspaces' side of the directory's security transitions and event
// mirrors, as a live workspace answers them.
const ACCESS_ANSWER: WorkspaceAnswer = (call) => {
  switch (call.op) {
    case "access.security.install":
    case "access.security.commit":
      return { ok: true, value: { installedEpoch: (call.input as { committedEpoch: number }).committedEpoch } }
    case "access.account_event":
      return { ok: true, value: { mirrored: true } }
    case "access.security.restriction":
    case "access.session_revoke":
      return { ok: true, value: {} }
    default:
      return DEFAULT_WORKSPACE_ANSWER(call)
  }
}

type Setup = ConsoleFixture & { alex: Person; tom: Person; kim: Person }

// Alex and Tom are operators (unless `alone`, when only Alex is); Kim is not.
async function setup(alone = false): Promise<Setup> {
  const f = await consoleFixture(ACCESS_ANSWER)
  for (const account of alone ? ["acc_owner"] : ["acc_owner", "acc_admin"]) await f.grantOperator(account)
  return { ...f, alex: await f.person("acc_owner"), tom: await f.person("acc_admin"), kim: await f.person("acc_kim") }
}

async function propose(f: ConsoleFixture, who: Person, kind: OperatorProposalKind, target: string, params: Record<string, unknown> = {}): Promise<Response> {
  const terms = { kind, target, params }
  const stepUp = await f.proof(who, OPERATOR_START, await operatorProposeStepUpAction(terms))
  return f.request("/api/operator/proposals", who, { ...terms, stepUp })
}

async function approve(f: ConsoleFixture, who: Person, proposal: { id: string; digest: string }): Promise<Response> {
  const stepUp = await f.proof(who, OPERATOR_START, operatorApproveStepUpAction(proposal.id, proposal.digest))
  return f.request(`/api/operator/proposals/${proposal.id}`, who, { decision: "approve", digest: proposal.digest, stepUp })
}

async function refused(response: Response, status: number, message: string): Promise<void> {
  expect({ status: response.status, message: ((await response.json()) as { message: string }).message }).toEqual({ status, message })
}

async function detail(f: ConsoleFixture, who: Person, account: string): Promise<OperatorAccountDetail> {
  return answer<OperatorAccountDetail>(await f.request(`/api/operator/accounts/${account}`, who))
}

async function list(f: ConsoleFixture, who: Person, query = ""): Promise<OperatorAccountList> {
  return answer<OperatorAccountList>(await f.request(`/api/operator/accounts${query}`, who))
}

async function accountEvents(f: ConsoleFixture, account: string, action: string): Promise<{ detail: Record<string, unknown>; targets: string[] }[]> {
  const rows = await f.env.DB.prepare("SELECT detail,targets FROM account_events WHERE account=? AND action=? ORDER BY at,rowid").bind(account, action).all<{ detail: string; targets: string }>()
  return rows.results.map((row) => ({ detail: JSON.parse(row.detail) as Record<string, unknown>, targets: JSON.parse(row.targets) as string[] }))
}

async function accountNotices(f: ConsoleFixture, account: string, change: string): Promise<Record<string, unknown>[]> {
  const rows = await f.env.DB.prepare("SELECT payload FROM account_notices WHERE account=? AND json_extract(payload,'$.change')=? ORDER BY at,rowid").bind(account, change).all<{ payload: string }>()
  return rows.results.map((row) => JSON.parse(row.payload) as Record<string, unknown>)
}

async function deploymentEvents(f: ConsoleFixture, kind: string): Promise<{ actor: string; approver: string | null; target: string; details: Record<string, unknown> }[]> {
  const rows = await f.env.DB.prepare("SELECT actor,approver,target,details FROM deployment_events WHERE kind=? ORDER BY at,rowid").bind(kind).all<{ actor: string; approver: string | null; target: string; details: string }>()
  return rows.results.map((row) => ({ ...row, details: JSON.parse(row.details) as Record<string, unknown> }))
}

// The operators told of an applied change, sorted.
async function operatorsTold(f: ConsoleFixture, kind: string): Promise<string[]> {
  const rows = await f.env.DB.prepare("SELECT account FROM account_notices WHERE json_extract(payload,'$.change')='operator_proposal' AND json_extract(payload,'$.event')='applied' AND json_extract(payload,'$.kind')=? ORDER BY account").bind(kind).all<{ account: string }>()
  return rows.results.map((row) => row.account)
}

// A passkey sign-in, as the sign-in page makes one.
async function signIn(f: ConsoleFixture, who: Person): Promise<Response> {
  const started = await answer<{ flow: string; options: { challenge: string } }>(await f.request("/api/auth/signin/options", undefined, {}))
  return f.request("/api/auth/signin/verify", undefined, { flow: started.flow, response: await assertion(who.passkey, started.options.challenge, ++who.counter) })
}

describe("who sees the Accounts view", () => {
  it("gives every Accounts route not_found to an account without the role, and to anyone signed out", async () => {
    const f = await setup()
    for (const who of [f.kim, undefined]) {
      expect({ status: (await f.request("/api/operator/accounts", who)).status }).toEqual({ status: 404 })
      expect(await (await f.request("/api/operator/accounts?q=kim", who)).json()).toEqual(HIDDEN)
      expect(await (await f.request("/api/operator/accounts/acc_kim", who)).json()).toEqual(HIDDEN)
      expect(await (await f.request("/api/operator/accounts/acc_kim/break-glass-link", who, { intent: "bgi_x" })).json()).toEqual(HIDDEN)
    }
  })

  it("refuses the recovery link's step-up on the account route", async () => {
    const f = await setup()
    expect(await (await f.request("/api/account/stepup/start", f.alex, { action: operatorBreakGlassLinkStepUpAction("bgi_x") })).json()).toEqual(HIDDEN)
  })
})

describe("the accounts list", () => {
  it("is searched by name, id or a linked Google email, and filtered", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO oidc_identities(id,account,provider,issuer,subject,email,email_verified,linked_at,last_verified_at) VALUES ('oid_kim','acc_kim','google','https://accounts.google.com','sub-kim','kim.lee@example.com',1,?,?)").bind(now, now),
      f.env.DB.prepare("INSERT INTO accounts(id,name,created_at) VALUES ('acc_loner','Loner',?)").bind(now - 1000),
    ])
    const names = (page: OperatorAccountList) => page.accounts.map((a) => a.account).sort()
    expect(names(await list(f, f.alex, "?q=KIM"))).toEqual(["acc_kim"])
    expect(names(await list(f, f.alex, "?q=acc_kim"))).toEqual(["acc_kim"])
    expect(names(await list(f, f.alex, "?q=lee%40example"))).toEqual(["acc_kim"])
    expect(names(await list(f, f.alex, "?filter=operators"))).toEqual(["acc_admin", "acc_owner"])
    expect(names(await list(f, f.alex, "?filter=no-workspace"))).toEqual(["acc_loner"])
    expect(names(await list(f, f.alex, "?filter=suspended"))).toEqual([])
    const kim = (await list(f, f.alex, "?q=acc_kim")).accounts[0]
    expect(kim).toMatchObject({ account: "acc_kim", name: "Kim", email: "kim.lee@example.com", status: "active", operator: false, suspendedAt: null, coolingOff: null, transitionPending: false, workspaces: 1, passkeys: { count: 2, synced: 0, securityKeys: 1 }, workspaceCreation: "default", lastSeenAt: expect.any(String) })
    expect((await f.request("/api/operator/accounts?filter=everyone", f.alex)).status).toBe(400)
  })

  it("is one bounded page at a time, newest first, with the next page's cursor", async () => {
    const f = await setup()
    const base = Date.now() - 86_400_000
    await f.env.DB.batch(Array.from({ length: 60 }, (_, i) => f.env.DB.prepare("INSERT INTO accounts(id,name,created_at) VALUES (?,?,?)").bind(`acc_bulk${String(i).padStart(2, "0")}`, `Bulk ${i}`, base - i * 1000)))
    const first = await list(f, f.alex)
    expect(first.accounts).toHaveLength(50)
    expect(first.next).not.toBeNull()
    const second = await list(f, f.alex, `?before=${encodeURIComponent(first.next!)}`)
    expect(second.next).toBeNull()
    const all = [...first.accounts, ...second.accounts].map((a) => a.account)
    expect(new Set(all).size).toBe(65)
    expect(all.at(-1)).toBe("acc_bulk59")
    const times = [...first.accounts, ...second.accounts].map((a) => Date.parse(a.createdAt))
    expect([...times].sort((a, b) => b - a)).toEqual(times)
  })

  it("never carries a public key, a credential id or a session hash", async () => {
    const f = await setup()
    const keys = await f.env.DB.prepare("SELECT credential_id FROM passkeys WHERE account='acc_kim'").all<{ credential_id: string }>()
    const sessions = await f.env.DB.prepare("SELECT token_hash,id FROM web_sessions WHERE account='acc_kim'").all<{ token_hash: string; id: string }>()
    const text = JSON.stringify([await list(f, f.alex), await detail(f, f.alex, "acc_kim")])
    for (const k of keys.results) expect(text).not.toContain(k.credential_id)
    for (const s of sessions.results) {
      expect(text).not.toContain(s.token_hash)
      expect(text).not.toContain(s.id)
    }
    expect(text).not.toContain("public_key")
  })
})

describe("one account", () => {
  it("shows its workspaces with the role as a hint, passkeys and sessions as metadata, and its events newest first", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail,targets) VALUES ('evt_a','acc_kim',?,'account.signin','{}','[]'),('evt_b','acc_kim',?,'account.signout','{}','[]')").bind(now - 2000, now - 1000),
    ])
    const kim = await detail(f, f.alex, "acc_kim")
    expect(kim.workspaces).toEqual([{ workspace: WORK, slug: "northwind", name: "Work", roleHint: expect.any(String), state: "member", since: expect.any(String) }])
    expect(kim.passkeys.map((p) => p.authenticator).sort()).toEqual(["A security key", "Built into a device"].sort())
    expect(kim.passkeys.every((p) => Object.keys(p).sort().join() === "addedVia,authenticator,createdAt,lastUsedAt,name,synced")).toBe(true)
    expect(kim.sessions).toEqual({ web: 1, app: 0, recovery: 0, lastSeenAt: expect.any(String) })
    expect(kim.events.slice(0, 2).map((e) => e.id)).toEqual(["evt_b", "evt_a"])
    expect(kim.you).toBe("acc_owner")
    expect(kim.operators).toBe(2)
    expect(kim.breakGlass).toBeNull()
    expect((await f.request("/api/operator/accounts/acc_nobody", f.alex)).status).toBe(404)
  })
})

describe("workspace creation for one account", () => {
  it("allows, denies and returns to the default with one operator's passkey, writing the rows the script writes and telling only the account", async () => {
    const f = await setup()
    const allowed = await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.workspace_creation", "acc_kim", { creation: "allow" }))
    expect(allowed).toEqual({ done: "Kim may create workspaces.", proposal: null })
    expect(await f.env.DB.prepare("SELECT can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id='acc_kim'").first()).toEqual({ can_create_workspaces: 1, can_create_workspaces_by: "operator:acc_owner" })
    await refused(await propose(f, f.alex, "account.workspace_creation", "acc_kim", { creation: "allow" }), 409, "Kim's workspace creation is allowed by an operator already.")

    expect((await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.workspace_creation", "acc_kim", { creation: "default" }))).done).toBe("Kim's workspace creation follows the deployment default again.")
    expect((await detail(f, f.alex, "acc_kim")).account.workspaceCreation).toBe("default")
    // The flag is still 1 under the default, so allowing again changes no
    // value: the event and the notice are written all the same.
    await answer(await propose(f, f.tom, "account.workspace_creation", "acc_kim", { creation: "allow" }))
    await answer(await propose(f, f.alex, "account.workspace_creation", "acc_kim", { creation: "deny" }))
    expect((await detail(f, f.alex, "acc_kim")).account.workspaceCreation).toBe("operator-denied")

    expect((await accountEvents(f, "acc_kim", "operator.allow_workspaces")).map((e) => e.detail)).toEqual([{ by: "operator:acc_owner", allowed: 1 }, { by: "operator:acc_admin", allowed: 1 }])
    expect((await accountEvents(f, "acc_kim", "operator.deny_workspaces")).map((e) => e.detail)).toEqual([{ by: "operator:acc_owner", allowed: 0 }])
    expect((await accountEvents(f, "acc_kim", "operator.default_workspaces")).map((e) => e.detail)).toEqual([{ by: "operator:acc_owner", allowed: null }])
    expect(await accountNotices(f, "acc_kim", "workspace_creation")).toEqual([
      { change: "workspace_creation", allowed: 1, by: "operator:acc_owner" },
      { change: "workspace_creation", allowed: null, by: "operator:acc_owner" },
      { change: "workspace_creation", allowed: 1, by: "operator:acc_admin" },
      { change: "workspace_creation", allowed: 0, by: "operator:acc_owner" },
    ])
    expect((await deploymentEvents(f, "account.workspace_creation")).map((e) => [e.actor, e.target, e.details.creation])).toEqual([
      ["operator:acc_owner", "acc_kim", "allow"],
      ["operator:acc_owner", "acc_kim", "default"],
      ["operator:acc_admin", "acc_kim", "allow"],
      ["operator:acc_owner", "acc_kim", "deny"],
    ])
    expect(await operatorsTold(f, "account.workspace_creation")).toEqual([])
  })

  it("needs an operator account with every requirement met", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_owner'").run()
    expect((await f.request(OPERATOR_START, f.alex, { action: await operatorProposeStepUpAction({ kind: "account.workspace_creation", target: "acc_kim", params: { creation: "allow" } }) })).status).toBe(403)
  })
})

describe("suspending an account", () => {
  it("ends every session, refuses sign-in and step-up in plain words, tells every operator and the account, and lifting lets them back", async () => {
    const f = await setup()
    expect((await f.request("/api/account/sessions", f.kim)).status).toBe(200)
    const done = await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.suspend", "acc_kim"))
    expect(done.done).toBe("Kim's account is suspended: every session ends, and they cannot sign in until an operator lifts it.")
    expect(await f.env.DB.prepare("SELECT suspended_at IS NOT NULL AS suspended,suspended_by,security_transition FROM accounts WHERE id='acc_kim'").first()).toEqual({ suspended: 1, suspended_by: "operator:acc_owner", security_transition: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account='acc_kim'").first()).toEqual({ n: 0 })
    expect((await f.request("/api/account/sessions", f.kim)).status).toBe(401)
    await refused(await signIn(f, f.kim), 403, ACCOUNT_SUSPENDED)

    expect(await operatorsTold(f, "account.suspend")).toEqual(["acc_admin", "acc_owner"])
    expect(await accountNotices(f, "acc_kim", "account_suspension")).toEqual([{ change: "account_suspension", suspended: true, by: "operator:acc_owner" }])
    // The event reaches each of Kim's workspaces, which tells its owners and admins.
    expect((await accountEvents(f, "acc_kim", "account.suspend")).map((e) => e.targets)).toEqual([[WORK]])
    await mirrorAccountEvents(f.env)
    expect(f.calls.filter((c) => c.op === "access.account_event" && (c.input as { action: string }).action === "account.suspend").map((c) => c.tenant)).toEqual([WORK])
    expect((await list(f, f.alex, "?filter=suspended")).accounts.map((a) => a.account)).toEqual(["acc_kim"])
    await refused(await propose(f, f.alex, "account.suspend", "acc_kim"), 409, "Kim's account is suspended already.")

    expect((await answer<OperatorProposalAnswer>(await propose(f, f.tom, "account.lift_suspension", "acc_kim"))).done).toBe("Kim's suspension is lifted; they sign in again with their passkey.")
    expect(await f.env.DB.prepare("SELECT suspended_at,suspended_by FROM accounts WHERE id='acc_kim'").first()).toEqual({ suspended_at: null, suspended_by: null })
    expect(await answer(await signIn(f, f.kim))).toEqual({ account: "acc_kim" })
    expect(await operatorsTold(f, "account.lift_suspension")).toEqual(["acc_admin", "acc_owner"])
    expect((await accountNotices(f, "acc_kim", "account_suspension")).at(-1)).toEqual({ change: "account_suspension", suspended: false, by: "operator:acc_admin" })
    await refused(await propose(f, f.tom, "account.lift_suspension", "acc_kim"), 409, "Kim's account is not suspended.")
  })

  // Without the cron: the proposal itself raises the epoch once its batch lands.
  it("raises the account's security epoch in each workspace straight after the batch", async () => {
    const f = await setup()
    const epoch = (await f.env.DB.prepare("SELECT security_epoch FROM accounts WHERE id='acc_kim'").first<{ security_epoch: number }>())!.security_epoch
    await answer(await propose(f, f.alex, "account.suspend", "acc_kim"))
    expect((await f.env.DB.prepare("SELECT state,effects FROM account_security_transitions WHERE account='acc_kim'").all()).results).toEqual([{ state: "committed", effects: JSON.stringify([{ kind: "sessions.end" }]) }])
    expect(await f.env.DB.prepare("SELECT security_epoch,security_transition FROM accounts WHERE id='acc_kim'").first()).toEqual({ security_epoch: epoch + 1, security_transition: null })
    expect(f.calls.filter((c) => c.op === "access.security.commit").map((c) => c.tenant)).toEqual([WORK])
  })

  // The workspaces' epoch is raised after the batch; here that fails (a
  // transition it cannot read blocks the reservation) and the cron does it.
  it("ends every session in its own batch, so lifting never brings an old cookie back, and the cron reaches the workspaces when the first try fails", async () => {
    const f = await setup()
    const app = "b".repeat(43)
    const now = Date.now()
    const passkey = (await f.env.DB.prepare("SELECT credential_id FROM passkeys WHERE account='acc_kim' AND added_via='signup'").first<{ credential_id: string }>())!.credential_id
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,passkey,client) VALUES (?,'ses_kimapp','acc_kim',?,?,?,'app','passkey',?,'Native app')").bind(await sha256Text(app), now, now + 86_400_000, now, passkey),
      f.env.DB.prepare("UPDATE accounts SET security_transition='trn_unreadable' WHERE id='acc_kim'"),
    ])
    const epoch = (await f.env.DB.prepare("SELECT security_epoch FROM accounts WHERE id='acc_kim'").first<{ security_epoch: number }>())!.security_epoch
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    try { await answer(await propose(f, f.alex, "account.suspend", "acc_kim")) } finally { errors.mockRestore() }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE account='acc_kim'").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions WHERE account='acc_kim'").first()).toEqual({ n: 0 })

    await f.env.DB.prepare("UPDATE accounts SET security_transition=NULL WHERE id='acc_kim'").run()
    await reconcileSuspendedAccounts(f.env, undefined, Date.now())
    await reconcileSuspendedAccounts(f.env, undefined, Date.now())
    expect((await f.env.DB.prepare("SELECT state,effects FROM account_security_transitions WHERE account='acc_kim'").all()).results).toEqual([{ state: "committed", effects: JSON.stringify([{ kind: "sessions.end" }]) }])
    expect(await f.env.DB.prepare("SELECT security_epoch,security_transition FROM accounts WHERE id='acc_kim'").first()).toEqual({ security_epoch: epoch + 1, security_transition: null })

    await answer(await propose(f, f.tom, "account.lift_suspension", "acc_kim"))
    expect((await f.request("/api/account/sessions", f.kim)).status).toBe(401)
    expect(await currentAccountAppSession(new Request("https://vault.test/api/account", { headers: { authorization: `Bearer ${app}` } }), f.env)).toBeNull()
  })

  // The suspension is lifted between the cron's read of suspended accounts
  // and its reservation of the epoch raise.
  it("never raises the epoch from the cron for a suspension lifted while it runs", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE accounts SET security_transition='trn_unreadable' WHERE id='acc_kim'").run()
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    try { await answer(await propose(f, f.alex, "account.suspend", "acc_kim")) } finally { errors.mockRestore() }
    await f.env.DB.prepare("UPDATE accounts SET security_transition=NULL WHERE id='acc_kim'").run()
    const epoch = (await f.env.DB.prepare("SELECT security_epoch FROM accounts WHERE id='acc_kim'").first<{ security_epoch: number }>())!.security_epoch
    const db = f.env.DB
    const liftedMidRun = new Proxy(db, {
      get(target, key) {
        if (key !== "prepare") {
          const value: unknown = Reflect.get(target, key, target)
          return typeof value === "function" ? value.bind(target) : value
        }
        return (sql: string) => {
          const statement = target.prepare(sql)
          if (!sql.includes("ORDER BY a.suspended_at")) return statement
          return { all: async () => {
            const rows = await statement.all()
            await answer(await propose(f, f.tom, "account.lift_suspension", "acc_kim"))
            return rows
          } }
        }
      },
    })
    await reconcileSuspendedAccounts({ ...f.env, DB: liftedMidRun }, undefined, Date.now())
    expect(await f.env.DB.prepare("SELECT suspended_at,security_epoch,security_transition FROM accounts WHERE id='acc_kim'").first()).toEqual({ suspended_at: null, security_epoch: epoch, security_transition: null })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_security_transitions WHERE account='acc_kim'").first()).toEqual({ n: 0 })
  })

  it("refuses the session and every step-up of an account suspended while signed in", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_owner' WHERE id='acc_kim'").bind(Date.now()).run()
    expect((await f.request("/api/account/sessions", f.kim)).status).toBe(401)
    expect((await f.request("/api/account/stepup/start", f.kim, { action: { type: "passkey.add" } })).status).toBe(401)
    await expect(assertAccountStepUpAllowed(f.env, "acc_kim", { type: "recovery.generate" })).rejects.toThrow(ACCOUNT_SUSPENDED)
  })

  it("refuses a suspended account's recovery code before anything changes", async () => {
    const f = await setup()
    const kim = (await currentAccountSession(new Request(f.env.VAULT_ORIGIN, { headers: { cookie: f.kim.cookie } }), f.env))!
    const issued = await issueAccountRecoveryCodes(f.env, kim)
    await confirmAccountRecoveryCodes(f.env, kim, issued.batch, issued.codes[issued.confirmPosition - 1]!)
    await f.env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_owner' WHERE id='acc_kim'").bind(Date.now()).run()
    await expect(startAccountRecovery(f.env, new Request(f.env.VAULT_ORIGIN), issued.codes[0]!, successfulDirectoryClient())).rejects.toThrow(ACCOUNT_SUSPENDED)
    expect(await f.env.DB.prepare("SELECT security_transition FROM accounts WHERE id='acc_kim'").first()).toEqual({ security_transition: null })
  })

  it("refuses the app's session of a suspended account", async () => {
    const f = await setup()
    const token = "a".repeat(43)
    const now = Date.now()
    const passkey = (await f.env.DB.prepare("SELECT credential_id FROM passkeys WHERE account='acc_kim' AND added_via='signup'").first<{ credential_id: string }>())!.credential_id
    await f.env.DB.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,passkey,client) VALUES (?,'ses_kimapp','acc_kim',?,?,?,'app','passkey',?,'Native app')").bind(await sha256Text(token), now, now + 86_400_000, now, passkey).run()
    const request = () => new Request("https://vault.test/api/account", { headers: { authorization: `Bearer ${token}` } })
    expect(await currentAccountAppSession(request(), f.env)).toMatchObject({ account: "acc_kim" })
    await f.env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_owner' WHERE id='acc_kim'").bind(now).run()
    expect(await currentAccountAppSession(request(), f.env)).toBeNull()
  })

  it("never suspends an operator, nor yourself", async () => {
    const f = await setup()
    const tom = (await f.env.DB.prepare("SELECT name FROM accounts WHERE id='acc_admin'").first<{ name: string }>())!.name
    await refused(await propose(f, f.alex, "account.suspend", "acc_admin"), 403, `${tom} is an operator, and an operator's account is never suspended. End their operator role first.`)
    await refused(await propose(f, f.alex, "account.suspend", "acc_owner"), 403, "Nobody may propose a change to their own account.")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM accounts WHERE suspended_at IS NOT NULL").first()).toEqual({ n: 0 })
  })
})

describe("recovering access to an account", () => {
  const VERIFIED = "Video call with Kim; matched the passport photo and their manager confirmed."

  it("needs a second operator; until there is one it says so", async () => {
    const f = await setup(true)
    await refused(await propose(f, f.alex, "account.break_glass", "acc_kim", { verified: VERIFIED }), 403, NEEDS_SECOND_OPERATOR_WORDS.change)
  })

  it("is proposed with how the person was verified, approved by another operator, and its link shown once to the proposer only", async () => {
    const f = await setup()
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.break_glass", "acc_kim", { verified: VERIFIED }), 201)).proposal!
    expect((await deploymentEvents(f, "proposal.open"))[0]?.details).toMatchObject({ kind: "account.break_glass", verified: VERIFIED })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_break_glass_intents").first()).toEqual({ n: 0 })

    await answer(await approve(f, f.tom, open))
    const intent = await f.env.DB.prepare("SELECT id,actor,state FROM account_break_glass_intents WHERE account='acc_kim'").first<{ id: string; actor: string; state: string }>()
    expect(intent).toMatchObject({ actor: "operator:acc_owner", state: "pending" })
    expect((await accountEvents(f, "acc_kim", "operator.break_glass")).map((e) => e.detail)).toEqual([{ by: "operator:acc_owner", intent: intent!.id }])
    expect((await deploymentEvents(f, "account.break_glass"))[0]).toMatchObject({ actor: "operator:acc_owner", approver: "operator:acc_admin", target: "acc_kim", details: { verified: VERIFIED } })
    expect((await detail(f, f.alex, "acc_kim")).breakGlass).toMatchObject({ intent: intent!.id, state: "pending", yours: true, linkTaken: false })
    expect((await detail(f, f.tom, "acc_kim")).breakGlass).toMatchObject({ yours: false })
    const path = "/api/operator/accounts/acc_kim/break-glass-link"
    await refused(await f.request(path, f.alex, { intent: intent!.id }), 409, "Not yet: every workspace still has to end the account's old sessions and passkeys. Try again in a minute.")

    await reconcileAccountBreakGlass(f.env, successfulDirectoryClient())
    await refused(await f.request(path, f.tom, { intent: intent!.id }), 403, "Only the operator who proposed recovering this account's access takes its link.")
    const stepUp = await f.proof(f.alex, OPERATOR_START, operatorBreakGlassLinkStepUpAction(intent!.id))
    const shown = await answer<OperatorBreakGlassLink>(await f.request(path, f.alex, { intent: intent!.id, stepUp }))
    expect(shown.link.startsWith(`${f.env.VAULT_ORIGIN}/signup#`)).toBe(true)
    const code = shown.link.split("#")[1]!
    expect(await accountBreakGlassOptions(f.env, code)).toMatchObject({ options: expect.anything() })
    await refused(await f.request(path, f.alex, { intent: intent!.id }), 409, "This link was shown once already and is not shown again. If it was lost, let it expire and propose recovering access again.")
    expect((await detail(f, f.alex, "acc_kim")).breakGlass).toMatchObject({ state: "ready", linkTaken: true })
    expect(await deploymentEvents(f, "account.break_glass_link")).toEqual([{ actor: "operator:acc_owner", approver: null, target: "acc_kim", details: { intent: intent!.id } }])
    expect(JSON.stringify(await f.env.DB.prepare("SELECT * FROM deployment_events").all())).not.toContain(code)
  })

  it("asks for the passkey before showing the link", async () => {
    const f = await setup()
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.break_glass", "acc_kim", { verified: VERIFIED }), 201)).proposal!
    await answer(await approve(f, f.tom, open))
    await reconcileAccountBreakGlass(f.env, successfulDirectoryClient())
    const intent = (await f.env.DB.prepare("SELECT id FROM account_break_glass_intents WHERE account='acc_kim'").first<{ id: string }>())!.id
    expect((await f.request("/api/operator/accounts/acc_kim/break-glass-link", f.alex, { intent })).status).toBe(403)
    expect(await deploymentEvents(f, "account.break_glass_link")).toEqual([])
  })

  // Its proposer alone takes the link, so recovering an operator's access
  // would hand them a second operator account.
  it("never recovers an operator's access: refused when proposed, when approved, and by its batch guard", async () => {
    const f = await setup()
    const operatorWords = (name: string) => `${name} is an operator, and an operator's account is never recovered in the app. End their operator role first.`
    const tom = (await f.env.DB.prepare("SELECT name FROM accounts WHERE id='acc_admin'").first<{ name: string }>())!.name
    await refused(await propose(f, f.alex, "account.break_glass", "acc_admin", { verified: VERIFIED }), 403, operatorWords(tom))
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM operator_proposals").first()).toEqual({ n: 0 })

    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.break_glass", "acc_kim", { verified: VERIFIED }), 201)).proposal!
    await f.grantOperator("acc_kim")
    await refused(await approve(f, f.tom, open), 403, operatorWords("Kim"))
    const terms = { kind: "account.break_glass" as const, target: "acc_kim", params: { verified: VERIFIED } }
    const handler = ACCOUNT_KIND_HANDLERS["account.break_glass"]
    await expect(accountBatch(f.env, [...handler.guards(f.env, terms, Date.now()), ...(await handler.apply(f.env, terms, "acc_owner", Date.now())).statements])).rejects.toThrow("Account state changed. Try again.")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_break_glass_intents").first()).toEqual({ n: 0 })
  })

  it("refuses a suspended account's recovery link", async () => {
    const f = await setup()
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.break_glass", "acc_kim", { verified: VERIFIED }), 201)).proposal!
    await answer(await approve(f, f.tom, open))
    await reconcileAccountBreakGlass(f.env, successfulDirectoryClient())
    const intent = (await f.env.DB.prepare("SELECT id FROM account_break_glass_intents WHERE account='acc_kim'").first<{ id: string }>())!.id
    const stepUp = await f.proof(f.alex, OPERATOR_START, operatorBreakGlassLinkStepUpAction(intent))
    const code = (await answer<OperatorBreakGlassLink>(await f.request("/api/operator/accounts/acc_kim/break-glass-link", f.alex, { intent, stepUp }))).link.split("#")[1]!
    await f.env.DB.prepare("UPDATE accounts SET suspended_at=?,suspended_by='operator:acc_admin' WHERE id='acc_kim'").bind(Date.now()).run()
    await expect(accountBreakGlassOptions(f.env, code)).rejects.toThrow(ACCOUNT_SUSPENDED)
  })
})

describe("deleting an account", () => {
  // What the page sends: the hash of the name typed back, never the name.
  const typed = async (target: string, name: string) => ({ nameHash: await accountDeleteNameHash(target, name) })

  it("needs a second operator; until there is one it says so", async () => {
    const f = await setup(true)
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account='acc_kim'").run()
    await refused(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "Kim")), 403, NEEDS_SECOND_OPERATOR_WORDS.change)
  })

  it("is refused while the account is in a workspace, naming each, and for a name typed wrong or an operator", async () => {
    const f = await setup()
    await refused(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "Kim")), 409, "Kim is still a member of Work (northwind). Each workspace's owners remove them first.")
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account='acc_kim'").run()
    await refused(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "kim")), 400, "Type the account's name exactly as shown to confirm.")
    await refused(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_member", "Kim")), 400, "Type the account's name exactly as shown to confirm.")
    const tom = (await f.env.DB.prepare("SELECT name FROM accounts WHERE id='acc_admin'").first<{ name: string }>())!.name
    await f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account='acc_admin'").run()
    await refused(await propose(f, f.alex, "account.delete", "acc_admin", await typed("acc_admin", tom)), 403, `${tom} is an operator, and an operator's account is never deleted. End their operator role first.`)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM operator_proposals").first()).toEqual({ n: 0 })
  })

  it("is refused while the account is a platform's admin, naming each platform, at proposing and by its batch guard", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.batch([
      f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account='acc_kim'"),
      f.env.DB.prepare("INSERT INTO platforms (id,slug,name,status,limits,defaults,created_at,created_by,status_at,status_by) VALUES ('plt_globex0001','globex','Globex','active','{}','{}',?,'operator:acc_owner',?,'operator:acc_owner')").bind(now, now),
      f.env.DB.prepare("INSERT INTO platform_admins (id,platform,account,added_at,added_by) VALUES ('pad_kim0001','plt_globex0001','acc_kim',?,'operator:acc_owner')").bind(now),
    ])
    await refused(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "Kim")), 409, "Kim is still an admin of Globex (globex). Remove them on each platform's page first.")
    const terms = { kind: "account.delete" as const, target: "acc_kim", params: await typed("acc_kim", "Kim") }
    const handler = ACCOUNT_KIND_HANDLERS["account.delete"]
    await expect(accountBatch(f.env, [...handler.guards(f.env, terms, now), ...(await handler.apply(f.env, terms, "acc_owner", now)).statements])).rejects.toThrow("Account state changed. Try again.")
    expect(await f.env.DB.prepare("SELECT status FROM accounts WHERE id='acc_kim'").first()).toEqual({ status: "active" })

    await f.env.DB.prepare("UPDATE platform_admins SET removed_at=?,removed_by='operator:acc_owner' WHERE id='pad_kim0001'").bind(now).run()
    expect((await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "Kim"))).status).toBe(201)
  })

  it("once approved, keeps the account's row and events and deletes its name, passkeys, sessions, recovery codes, Google sign-ins and notices, the proposal keeping only the name's hash", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.batch([
      f.env.DB.prepare("UPDATE memberships SET state='left' WHERE account='acc_kim'"),
      f.env.DB.prepare("INSERT INTO oidc_identities(id,account,provider,issuer,subject,email,email_verified,linked_at,last_verified_at) VALUES ('oid_kim','acc_kim','google','https://accounts.google.com','sub-kim','kim@example.com',1,?,?)").bind(now, now),
      f.env.DB.prepare("INSERT INTO recovery_codes(code_hash,account,batch,position,status,created_at) VALUES ('kim-code','acc_kim','kim-batch',1,'active',?)").bind(now),
      f.env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) VALUES ('ntc_kimwork','acc_kim','workspace',?,?)").bind(JSON.stringify({ change: "member_joined", workspace: "Kim's Bakery", client: "Safari on Mac", place: "Utrecht" }), now),
    ])
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, "account.delete", "acc_kim", await typed("acc_kim", "Kim")), 201)).proposal!
    expect(await f.env.DB.prepare("SELECT status FROM accounts WHERE id='acc_kim'").first()).toEqual({ status: "active" })
    const before = await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE account='acc_kim'").first<{ n: number }>()
    expect((await answer<{ done: string }>(await approve(f, f.tom, open))).done).toBe("Kim's account is deleted. Its events stay.")
    expect(await f.env.DB.prepare("SELECT status,name,deleted_at IS NOT NULL AS deleted FROM accounts WHERE id='acc_kim'").first()).toEqual({ status: "deleted", name: "Deleted account", deleted: 1 })
    for (const table of ["passkeys", "web_sessions", "recovery_codes", "oidc_identities", "account_notices"]) expect(await f.env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE account='acc_kim'`).first(), table).toEqual({ n: 0 })
    expect((await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE account='acc_kim'").first<{ n: number }>())!.n).toBe(before!.n + 1)
    expect((await accountEvents(f, "acc_kim", "account.delete")).map((e) => e.detail)).toEqual([{ by: "operator:acc_owner" }])
    expect(await deploymentEvents(f, "account.delete")).toEqual([{ actor: "operator:acc_owner", approver: "operator:acc_admin", target: "acc_kim", details: { proposal: open.id, digest: open.digest } }])
    expect((await f.request("/api/account/sessions", f.kim)).status).toBe(401)
    expect((await detail(f, f.alex, "acc_kim"))).toMatchObject({ account: { status: "deleted", name: "Deleted account" }, deletedAt: expect.any(String) })
    expect(await f.env.DB.prepare("SELECT params FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ params: JSON.stringify(await typed("acc_kim", "Kim")) })
  })
})
