import { seedAccountRecoverySetup } from "./directory-test-support.ts"
import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beforeEach, describe, expect, it } from "vitest"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { reserveWorkspace,initialiseWorkspace,reconcileCreatingWorkspaces } from "../src/directory/workspace-index.ts"
import { reserveAccountSecurity } from "../src/directory/account-security.ts"
import type { WorkspaceInitialisationClient } from "../src/directory/workspace-client.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
async function account() { const a = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env); if (!a) throw new Error("Missing account"); return a }
const accounts = () => ({ ...f.env,WORKSPACE_CREATION: "accounts" })
async function ready() { await seedAccountRecoverySetup(f.env,f.account) }
async function deny() { await ready(); await f.env.DB.prepare("UPDATE accounts SET can_create_workspaces_by='operator:test',can_create_workspaces_op=lower(hex(randomblob(16))) WHERE id=?").bind(f.account).run() }
async function allow() { await seedAccountRecoverySetup(f.env,f.account); await f.env.DB.prepare("UPDATE accounts SET can_create_workspaces=1,can_create_workspaces_by='operator:test',can_create_workspaces_op=lower(hex(randomblob(16))),recovery_setup_at=?,recovery_setup_kind='codes' WHERE id=?").bind(Date.now(),f.account).run() }
async function narrowCreation() { await f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('workspace_creation','operator',?,'operator:test')").bind(Date.now()).run() }
function client(): WorkspaceInitialisationClient { return { async install(_w,i) { return { installedEpoch: i.committedEpoch } },async init(_w,i) { return { member: i.member } } } }
const input = { name: "Client",slug: "client-test" }
const action = { type: "workspace.create" as const,...input }
describe("workspace index reservations",() => {
  it("under the operator default, refuses an account the operator never allowed, without any reservation",async () => {
    await ready()
    for (const env of [f.env,{ ...f.env,WORKSPACE_CREATION: undefined },{ ...f.env,WORKSPACE_CREATION: "Accounts" }]) await expectDirectoryRefusal(reserveWorkspace(env,await account(),input,action),{ error: "forbidden",message: "You are not allowed to do that." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
  })
  it("under the accounts default, an account the operator never flagged creates a workspace",async () => {
    await ready()
    const reservation = await reserveWorkspace(accounts(),await account(),input,action)
    expect(await f.env.DB.prepare("SELECT status,created_by FROM workspaces WHERE id=?").bind(reservation.workspace.id).first()).toEqual({ status: "creating",created_by: f.account })
  })
  it("an account the operator denied is refused under the accounts default, without any reservation",async () => {
    await deny()
    await expectDirectoryRefusal(reserveWorkspace(accounts(),await account(),input,action),{ error: "forbidden",message: "You are not allowed to do that." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
  })
  it("an account the operator allowed creates under the operator default",async () => {
    await allow()
    await reserveWorkspace(f.env,await account(),input,action)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating' AND created_by=?").bind(f.account).first()).toEqual({ n: 1 })
  })
  it("the reservation's own guard applies the rule: a deny between the check and the write refuses it",async () => {
    await ready()
    const env = accounts(),actor = await account()
    const batch = env.DB.batch.bind(env.DB)
    const db = new Proxy(env.DB,{ get(target,key) {
      if (key === "batch") return async (statements: D1PreparedStatement[]) => { await target.prepare("UPDATE accounts SET can_create_workspaces_by='operator:test',can_create_workspaces_op=lower(hex(randomblob(16))) WHERE id=?").bind(f.account).run(); return batch(statements) }
      const value = Reflect.get(target,key) as unknown
      return typeof value === "function" ? value.bind(target) : value
    } })
    await expectDirectoryRefusal(reserveWorkspace({ ...env,DB: db },actor,input,action),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
  })
  it("under the accounts ceiling, the operators' workspace_creation setting of operator refuses an account never flagged, and an allowed one still creates",async () => {
    await ready()
    await narrowCreation()
    await expectDirectoryRefusal(reserveWorkspace(accounts(),await account(),input,action),{ error: "forbidden",message: "You are not allowed to do that." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
    await allow()
    await reserveWorkspace(accounts(),await account(),input,action)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating' AND created_by=?").bind(f.account).first()).toEqual({ n: 1 })
  })
  it("the reservation's own guard reads the setting: narrowed between the check and the write, it refuses",async () => {
    await ready()
    const env = accounts(),actor = await account()
    const batch = env.DB.batch.bind(env.DB)
    const db = new Proxy(env.DB,{ get(target,key) {
      if (key === "batch") return async (statements: D1PreparedStatement[]) => { await narrowCreation(); return batch(statements) }
      const value = Reflect.get(target,key) as unknown
      return typeof value === "function" ? value.bind(target) : value
    } })
    await expectDirectoryRefusal(reserveWorkspace({ ...env,DB: db },actor,input,action),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
  })
  it("an allow-listed creator still needs recovery setup before any owner activation",async () => {
    await allow()
    await f.env.DB.batch([f.env.DB.prepare("DELETE FROM recovery_codes WHERE account=?").bind(f.account),f.env.DB.prepare("UPDATE accounts SET recovery_setup_at=NULL,recovery_setup_kind=NULL WHERE id=?").bind(f.account)])
    await expectDirectoryRefusal(reserveWorkspace(f.env,await account(),input,action),{ error: "forbidden",message: "Set up account recovery before activation.", next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." } })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status='creating'").first()).toEqual({ n: 0 })
    await allow()
    const reservation = await reserveWorkspace(f.env,await account(),input,action)
    await f.env.DB.batch([f.env.DB.prepare("DELETE FROM recovery_codes WHERE account=?").bind(f.account),f.env.DB.prepare("UPDATE accounts SET recovery_setup_at=NULL,recovery_setup_kind=NULL WHERE id=?").bind(f.account)])
    await expectDirectoryRefusal(initialiseWorkspace(f.env,reservation,client()),{ error: "forbidden",message: "Set up account recovery before activation.", next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "Save recovery codes or add a second passkey before activating a membership." } })
    expect(await f.env.DB.prepare("SELECT state FROM memberships WHERE id=?").bind(reservation.member).first()).toEqual({ state: "joining" })
  })
  it("reserves D1 before the DO, and retries an unavailable DO without losing its index target",async () => {
    await allow()
    const reservation = await reserveWorkspace(f.env,await account(),input,action)
    expect(await f.env.DB.prepare("SELECT id,state FROM memberships WHERE workspace=?").bind(reservation.workspace.id).first()).toEqual({ id: reservation.member,state: "joining" })
    const unavailable = client(); unavailable.init = async () => { throw new Error("unavailable") }
    await expect(initialiseWorkspace(f.env,reservation,unavailable)).rejects.toThrow("unavailable")
    expect(await f.env.DB.prepare("SELECT status FROM workspaces WHERE id=?").bind(reservation.workspace.id).first()).toEqual({ status: "creating" })
    await reconcileCreatingWorkspaces(f.env,client())
    expect(await f.env.DB.prepare("SELECT status FROM workspaces WHERE id=?").bind(reservation.workspace.id).first()).toEqual({ status: "active" })
    expect(await f.env.DB.prepare("SELECT id,state FROM memberships WHERE workspace=?").bind(reservation.workspace.id).first()).toEqual({ id: reservation.member,state: "member" })
  })
  it("a tightening during DO initialisation keeps the reservation and refuses finalisation",async () => {
    await allow()
    const reservation = await reserveWorkspace(f.env,await account(),input,action)
    const c = client()
    c.init = async (_w,i) => { await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "sessions.end" },revokedSessionIds: [f.session],removedFactorIds: [] }); return { member: i.member } }
    await expectDirectoryRefusal(initialiseWorkspace(f.env,reservation,c),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT state FROM memberships WHERE workspace=?").bind(reservation.workspace.id).first()).toEqual({ state: "joining" })
    const targets = await f.env.DB.prepare("SELECT targets FROM account_security_transitions WHERE account=?").bind(f.account).first<{ targets: string }>()
    expect(JSON.parse(targets?.targets ?? "[]")).toContainEqual({ workspace: reservation.workspace.id,membership: reservation.member,state: "joining" })
  })
  it("occupied/reserved/alias names refuse identically without a new reservation",async () => {
    await allow()
    await f.env.DB.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES ('old-name',?,?)").bind(f.workspaces.personal,Date.now()).run()
    for (const slug of ["api","alex","old-name"]) await expectDirectoryRefusal(reserveWorkspace(f.env,await account(),{ ...input,slug },{ ...action,slug }),{ error: "conflict",message: "name not available" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces").first()).toEqual({ n: 2 })
  })
  it("an account that already created ten workspaces creates an eleventh: no cap on how many",async () => {
    await ready(); const actor = await account()
    for (let i=0;i<8;i++) await reserveWorkspace(accounts(),actor,{ name: "Client",slug: `client-${i}` },{ type: "workspace.create",name: "Client",slug: `client-${i}` })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE created_by=?").bind(f.account).first()).toEqual({ n: 10 })
    const eleventh = await reserveWorkspace(accounts(),actor,{ name: "Eleventh",slug: "eleventh" },{ type: "workspace.create",name: "Eleventh",slug: "eleventh" })
    expect(await f.env.DB.prepare("SELECT id FROM workspaces WHERE slug='eleventh'").first()).toEqual({ id: eleventh.workspace.id })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE created_by=?").bind(f.account).first()).toEqual({ n: 11 })
  })
  it("same-slug concurrent reservations have one winner and generic loser",async () => {
    await allow(); const a = await account()
    const results = await Promise.allSettled([reserveWorkspace(f.env,a,input,action),reserveWorkspace(f.env,a,input,action)])
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1)
    const loser = results.find(r => r.status === "rejected")
    expect(loser?.status === "rejected" ? loser.reason : null).toMatchObject({ code: "conflict",message: "name not available" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE slug=?").bind(input.slug).first()).toEqual({ n: 1 })
  })
})
