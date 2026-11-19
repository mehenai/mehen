// The Audit and Settings views (routes/console-audit-settings.ts, and the
// settings.narrow and settings.widen proposals through
// routes/console-operators.ts) through the real Worker, with real web
// sessions and the real passkey step-up.

import { describe, expect, it } from "vitest"
import { type OperatorAuditPage, type OperatorProposalAnswer, type OperatorProposalTerms, type OperatorSettingsView, DEPLOYMENT_SETTING_NOT_BUILT, OPERATOR_AUDIT_PAGE_SIZE, deploymentSettingCeilingWords, operatorApproveStepUpAction, operatorProposeStepUpAction } from "@mehen/protocol"
import { accountBatch } from "../src/directory/account-store.ts"
import { DEPLOYMENT_SETTING_KIND_HANDLERS, WIDENING_CANCELLED_REASON } from "../src/directory/deployment-settings.ts"
import { NEEDS_SECOND_OPERATOR, approveOperatorProposal, proposeOperatorChange } from "../src/directory/operator-proposals.ts"
import { workspaceCreationDefault } from "../src/directory/workspace-creation.ts"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"

const HIDDEN = { error: "not_found", message: "No such operation." }
const OPERATOR_START = "/api/operator/stepup/start"

type Setup = ConsoleFixture & { alex: Person; tom: Person; kim: Person }

// Alex and Tom are operators; Kim is not. The deploy allows every account
// to create workspaces and anything up to open sign-up.
async function setup(): Promise<Setup> {
  const f = await consoleFixture()
  for (const account of ["acc_owner", "acc_admin"]) await f.grantOperator(account)
  f.env.WORKSPACE_CREATION = "accounts"
  f.env.SIGNUP_MODE_MAX = "open"
  return { ...f, alex: await f.person("acc_owner"), tom: await f.person("acc_admin"), kim: await f.person("acc_kim") }
}

function narrow(key: string, value: string): OperatorProposalTerms {
  return { kind: "settings.narrow", target: key, params: { value } }
}

// A widening names the value in force it was proposed from.
function widen(key: string, value: string, from: string): OperatorProposalTerms {
  return { kind: "settings.widen", target: key, params: { value, from } }
}

async function propose(f: ConsoleFixture, who: Person, terms: OperatorProposalTerms): Promise<Response> {
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

async function settings(f: Setup): Promise<OperatorSettingsView> {
  return answer<OperatorSettingsView>(await f.request("/api/operator/settings", f.alex))
}

async function valueOf(f: Setup, key: string): Promise<string | undefined> {
  return (await settings(f)).settings.find((s) => s.key === key)?.value
}

describe("who reads the Audit and Settings views", () => {
  it("gives both not_found to an account without the role, and to anyone signed out", async () => {
    const f = await setup()
    for (const who of [f.kim, undefined]) {
      for (const path of ["/api/operator/audit", "/api/operator/settings"]) {
        const response = await f.request(path, who)
        expect({ status: response.status, body: await response.json() }).toEqual({ status: 404, body: HIDDEN })
      }
    }
  })

  it("answers the wrong method on a console API path with not_found to anyone but an operator", async () => {
    const f = await setup()
    // GET-only and POST-only operator routes, the Workspaces and Accounts
    // views' among them, each with the other method.
    const wrong: [string, string][] = [["/api/operator/audit", "POST"], ["/api/operator/proposals", "GET"], ["/api/operator/workspaces", "POST"], ["/api/operator/workspaces/tn_Beta1234567", "POST"], ["/api/operator/accounts", "POST"], ["/api/operator/accounts/acc_kim", "POST"], ["/api/operator/accounts/acc_kim/break-glass-link", "GET"]]
    for (const [path, method] of wrong) {
      for (const who of [f.kim, undefined]) {
        const response = await f.request(path, who, method === "POST" ? {} : undefined, method)
        expect({ path, status: response.status, body: await response.json() }).toEqual({ path, status: 404, body: HIDDEN })
      }
      expect((await f.request(path, f.alex, method === "POST" ? {} : undefined, method)).status).toBe(405)
    }
  })

  it("reads a signed-in non-operator's session for an unknown console API path as for a wrong method, and answers both byte for byte alike", async () => {
    const f = await setup()
    // A session last seen two hours ago is marked seen again when it is read.
    const stale = () => f.env.DB.prepare("UPDATE web_sessions SET last_seen_at=? WHERE account='acc_kim'").bind(Date.now() - 2 * 3_600_000).run()
    const read = async () => ((await f.env.DB.prepare("SELECT last_seen_at FROM web_sessions WHERE account='acc_kim'").first<{ last_seen_at: number }>())?.last_seen_at ?? 0) > Date.now() - 60_000
    const seen = []
    for (const [path, method] of [["/api/operator/proposals", "GET"], ["/api/operator/no-such-view", "GET"]] as const) {
      await stale()
      const response = await f.request(path, f.kim, undefined, method)
      seen.push({ status: response.status, headers: [...response.headers], body: await response.text(), sessionRead: await read() })
    }
    expect(seen[0]).toMatchObject({ status: 404, body: JSON.stringify(HIDDEN), sessionRead: true })
    expect(seen[1]).toEqual(seen[0])
  })
})

describe("the Settings view", () => {
  it("shows each setting in force, the deploy's ceiling, and nothing stored yet", async () => {
    const f = await setup()
    const view = await settings(f)
    expect(view).toMatchObject({ you: "acc_owner", operators: 2, missing: [], open: [], history: [] })
    expect(view.settings).toEqual([
      { key: "workspace_creation", value: "accounts", stored: null, ceiling: "accounts", updatedAt: null, updatedBy: null, updatedByName: null },
      { key: "signup_mode", value: "invite", stored: null, ceiling: "open", updatedAt: null, updatedBy: null, updatedByName: null },
    ])
  })

  it("narrows at once with one operator's passkey, and the vault's own workspace creation follows", async () => {
    const f = await setup()
    const done = await answer<OperatorProposalAnswer>(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    expect(done.done).toBe("Saved. Workspace creation is Only accounts an operator allows now.")
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
    expect(await workspaceCreationDefault(f.env)).toBe("operator")
    const view = await settings(f)
    expect(view.settings[0]).toMatchObject({ stored: "operator", updatedBy: "operator:acc_owner", updatedByName: "owner" })
    expect(view.history.map((e) => e.kind)).toEqual(["settings.narrow"])
    expect(await f.env.DB.prepare("SELECT kind,actor,target,json_extract(details,'$.params.value') AS value FROM deployment_events WHERE kind='settings.narrow'").first()).toEqual({ kind: "settings.narrow", actor: "operator:acc_owner", target: "workspace_creation", value: "operator" })
  })

  it("widens only once a second operator approves, and never past the deploy's ceiling", async () => {
    const f = await setup()
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, widen("workspace_creation", "accounts", "operator")), 201)).proposal!
    expect(open).toMatchObject({ kind: "settings.widen", target: "workspace_creation", state: "open" })
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
    expect((await settings(f)).open.map((p) => p.id)).toEqual([open.id])
    await answer(await approve(f, f.tom, open))
    expect(await valueOf(f, "workspace_creation")).toBe("accounts")
    expect(await f.env.DB.prepare("SELECT updated_by FROM deployment_settings WHERE key='workspace_creation'").first()).toEqual({ updated_by: "operator:acc_owner" })
    // The ceiling holds against two operators.
    f.env.SIGNUP_MODE_MAX = "request"
    await refused(await propose(f, f.alex, widen("signup_mode", "open", "invite")), 403, deploymentSettingCeilingWords("signup_mode", "request"))
  })

  it("refuses a narrowing that widens, a widening that narrows, and a value already in force", async () => {
    const f = await setup()
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    await refused(await propose(f, f.alex, narrow("workspace_creation", "accounts")), 403, "That widens workspace creation, which needs a second operator: propose it instead.")
    await refused(await propose(f, f.alex, widen("signup_mode", "invite", "invite")), 409, "Sign-up is Invitation only already.")
    await refused(await propose(f, f.tom, widen("workspace_creation", "operator", "operator")), 409, "Workspace creation is Only accounts an operator allows already.")
  })

  it("narrows a stored value above a ceiling a later deploy lowered, so raising the ceiling again does not bring it back", async () => {
    const f = await setup()
    await f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('workspace_creation','accounts',?,'operator:acc_admin')").bind(Date.now()).run()
    f.env.WORKSPACE_CREATION = "operator"
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    expect(await f.env.DB.prepare("SELECT value FROM deployment_settings WHERE key='workspace_creation'").first()).toEqual({ value: "operator" })
    await refused(await propose(f, f.alex, narrow("workspace_creation", "operator")), 409, "Workspace creation is Only accounts an operator allows already.")
    f.env.WORKSPACE_CREATION = "accounts"
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
  })

  it("refuses a value the vault does not do yet, widening or narrowing to it", async () => {
    const f = await setup()
    await refused(await propose(f, f.alex, widen("signup_mode", "open", "invite")), 403, DEPLOYMENT_SETTING_NOT_BUILT)
    await refused(await propose(f, f.alex, widen("signup_mode", "request", "invite")), 403, DEPLOYMENT_SETTING_NOT_BUILT)
    // Stored open, as the operator script could; narrowing to request access is refused too.
    await f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('signup_mode','open',?,'operator:acc_admin')").bind(Date.now()).run()
    await refused(await propose(f, f.alex, narrow("signup_mode", "request")), 403, DEPLOYMENT_SETTING_NOT_BUILT)
    await answer(await propose(f, f.alex, narrow("signup_mode", "invite")))
    expect(await valueOf(f, "signup_mode")).toBe("invite")
  })

  it("a widening applies only from the value in force it was proposed from", async () => {
    const f = await setup()
    await refused(await propose(f, f.alex, widen("signup_mode", "open", "request")), 409, "Sign-up is Invitation only now, not Request access as this widening says: read it again.")
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, widen("workspace_creation", "accounts", "operator")), 201)).proposal!
    // Set wider meanwhile, as the operator script would.
    await f.env.DB.prepare("UPDATE deployment_settings SET value='accounts' WHERE key='workspace_creation'").run()
    await refused(await approve(f, f.tom, open), 409, "Workspace creation is Every account now, not Only accounts an operator allows as this widening says: read it again.")
    expect(await valueOf(f, "workspace_creation")).toBe("accounts")
  })

  it("a widening's batch guard holds the value in force it was proposed from", async () => {
    const f = await setup()
    const guards = DEPLOYMENT_SETTING_KIND_HANDLERS["settings.widen"].guards(f.env, widen("signup_mode", "open", "invite"), Date.now())
    await accountBatch(f.env, guards)
    // Narrower than open still, but no longer the value it was proposed from.
    await f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('signup_mode','request',?,'operator:acc_admin')").bind(Date.now()).run()
    await expect(accountBatch(f.env, DEPLOYMENT_SETTING_KIND_HANDLERS["settings.widen"].guards(f.env, widen("signup_mode", "open", "invite"), Date.now()))).rejects.toThrow("Account state changed")
  })

  it("a narrowing cancels every open widening of the setting, so an approval on its way cannot undo it", async () => {
    const f = await setup()
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, widen("workspace_creation", "accounts", "operator")), 201)).proposal!
    // Set wider meanwhile, as the operator script would; Tom pulls the brake.
    await f.env.DB.prepare("UPDATE deployment_settings SET value='accounts' WHERE key='workspace_creation'").run()
    await answer(await propose(f, f.tom, narrow("workspace_creation", "operator")))
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "cancelled" })
    expect(await f.env.DB.prepare("SELECT actor,target,json_extract(details,'$.proposal') AS proposal,json_extract(details,'$.reason') AS reason FROM deployment_events WHERE kind='proposal.cancel'").all()).toMatchObject({ results: [{ actor: "operator:acc_admin", target: "workspace_creation", proposal: open.id, reason: WIDENING_CANCELLED_REASON }] })
    expect(await f.env.DB.prepare("SELECT account,json_extract(payload,'$.proposal') AS proposal,json_extract(payload,'$.reason') AS reason FROM account_notices WHERE json_extract(payload,'$.event')='cancelled'").all()).toMatchObject({ results: [{ account: "acc_owner", proposal: open.id, reason: WIDENING_CANCELLED_REASON }] })
    await refused(await approve(f, f.tom, open), 409, "This proposal is cancelled already.")
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
    expect((await settings(f)).open).toEqual([])
  })

  it("the batch checks the setting again: moved between the check and the write, neither a narrowing nor an approval applies", async () => {
    const f = await setup()
    const moveTo = (value: string) => async () => f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('workspace_creation',?,?,'operator:acc_admin') ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(value, Date.now()).run()
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, widen("workspace_creation", "accounts", "operator")), 201)).proposal!
    await expect(approveOperatorProposal(f.env, "acc_admin", open.id, open.digest, moveTo("accounts"))).rejects.toThrow("Nothing changed")
    expect(await valueOf(f, "workspace_creation")).toBe("accounts")
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "open" })
    await expect(proposeOperatorChange(f.env, "acc_owner", narrow("workspace_creation", "operator"), "digest", moveTo("operator"))).rejects.toThrow("Nothing changed")
    expect(await valueOf(f, "workspace_creation")).toBe("operator")
  })

  it("with one operator, widening says it needs a second; narrowing still works", async () => {
    const f = await consoleFixture()
    await f.grantOperator("acc_owner")
    f.env.WORKSPACE_CREATION = "accounts"
    const alex = await f.person("acc_owner")
    await answer(await propose(f, alex, narrow("workspace_creation", "operator")))
    await refused(await propose(f, alex, widen("workspace_creation", "accounts", "operator")), 403, NEEDS_SECOND_OPERATOR)
  })
})

describe("the Audit view", () => {
  it("lists deployment, platform and operator account events newest first, with the proposal's outcome and names", async () => {
    const f = await setup()
    const now = Date.now()
    await answer(await propose(f, f.alex, narrow("workspace_creation", "operator")))
    const open = (await answer<OperatorProposalAnswer>(await propose(f, f.alex, widen("workspace_creation", "accounts", "operator")), 201)).proposal!
    await answer(await approve(f, f.tom, open))
    await f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail) VALUES ('evt_audit','acc_kim',?,'operator.allow_workspaces',json_object('by','operator:acc_owner','allowed',1))").bind(now + 60_000).run()
    const page = await answer<OperatorAuditPage>(await f.request("/api/operator/audit", f.alex))
    expect(page.events[0]).toMatchObject({ id: "evt_audit", source: "account", action: "operator.allow_workspaces", actor: "operator:acc_owner", actorName: "owner", target: "acc_kim", targetName: "Kim" })
    const widened = page.events.find((e) => e.action === "settings.widen")!
    expect(widened).toMatchObject({ source: "deployment", actor: "operator:acc_owner", approver: "operator:acc_admin", approverName: "admin", target: "workspace_creation", proposal: { id: open.id, kind: "settings.widen", state: "applied", proposedBy: { account: "acc_owner" }, approvedBy: { account: "acc_admin" }, declinedBy: null } })
    const at = page.events.map((e) => e.at)
    expect([...at].sort().reverse()).toEqual(at)
    // Filters: by actor, action and target, and by day.
    const byAction = await answer<OperatorAuditPage>(await f.request("/api/operator/audit?action=settings.narrow", f.alex))
    expect(byAction.events.map((e) => e.action)).toEqual(["settings.narrow"])
    const byTarget = await answer<OperatorAuditPage>(await f.request("/api/operator/audit?target=acc_kim", f.alex))
    expect(byTarget.events.map((e) => e.id)).toEqual(["evt_audit"])
    const byActor = await answer<OperatorAuditPage>(await f.request("/api/operator/audit?actor=acc_admin", f.alex))
    // Tom only approved: the applied widening names him as its approver.
    expect(byActor.events.map((e) => [e.action, e.actor, e.approver])).toEqual([["settings.widen", "operator:acc_owner", "operator:acc_admin"]])
    const tomorrow = new Date(now + 2 * 86_400_000).toISOString().slice(0, 10)
    expect((await answer<OperatorAuditPage>(await f.request(`/api/operator/audit?from=${tomorrow}`, f.alex))).events).toEqual([])
    const refusedFilter = await f.request("/api/operator/audit?from=yesterday", f.alex)
    expect(refusedFilter.status).toBe(400)
  })

  it("lists a platform's events under its name, finds them by the platform's id, and never lists its activity counter", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.prepare("INSERT INTO platforms (id,slug,name,status,limits,defaults,created_at,created_by,status_at,status_by) VALUES ('plt_audit0001','globex','Globex','active','{}','{}',?,'operator:acc_owner',?,'operator:acc_owner')").bind(now, now).run()
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES ('pev_audit_suspend','plt_audit0001',?,'operator:acc_owner','operator.suspend','{\"reason\":\"Key leaked\"}')").bind(now),
      f.env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES ('pev_audit_activity','plt_audit0001',?,'system','platform.activity','{}')").bind(now + 1000),
    ])
    const page = await answer<OperatorAuditPage>(await f.request("/api/operator/audit", f.alex))
    expect(page.events.find((e) => e.id === "pev_audit_suspend")).toMatchObject({ source: "platform", action: "operator.suspend", actor: "operator:acc_owner", actorName: "owner", target: "globex", targetName: "Globex", details: { reason: "Key leaked" } })
    expect(page.events.map((e) => e.id)).not.toContain("pev_audit_activity")
    const byPlatformId = await answer<OperatorAuditPage>(await f.request("/api/operator/audit?target=plt_audit0001", f.alex))
    expect(byPlatformId.events.map((e) => e.id)).toEqual(["pev_audit_suspend"])
    expect((await answer<OperatorAuditPage>(await f.request("/api/operator/audit?action=platform.activity", f.alex))).events).toEqual([])
  })

  it("pages through every row exactly once", async () => {
    const f = await setup()
    const at = Date.now()
    const statements = Array.from({ length: OPERATOR_AUDIT_PAGE_SIZE + 5 }, (_, i) => f.env.DB.prepare("INSERT INTO deployment_events(id,at,kind,actor,target) VALUES (?,?,'proposal.open','operator:acc_owner','acc_kim')").bind(`dpe_page_${String(i).padStart(3, "0")}`, at - (i % 3)))
    await f.env.DB.batch(statements)
    const seen: string[] = []
    let next: string | null = null
    do {
      const page: OperatorAuditPage = await answer<OperatorAuditPage>(await f.request(`/api/operator/audit?action=proposal.open${next === null ? "" : `&before=${next}`}`, f.alex))
      seen.push(...page.events.map((e) => e.id))
      next = page.next
    } while (next !== null)
    expect(seen.length).toBe(OPERATOR_AUDIT_PAGE_SIZE + 5)
    expect(new Set(seen).size).toBe(seen.length)
  })
})
