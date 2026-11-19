import { seedAccountRecoverySetup } from "./directory-test-support.ts"
import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beforeEach,describe,expect,it } from "vitest"
import { reserveWorkspaceSlug,finaliseWorkspaceSlug,reconcileWorkspaceMetadata } from "../src/directory/workspace-aliases.ts"
import { reserveWorkspace } from "../src/directory/workspace-index.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { responseFor } from "../src/http.ts"
import type { WorkspaceMetadataClient } from "../src/directory/workspace-client.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
function metadata(): WorkspaceMetadataClient { return { async metadata(workspace) { return { workspace: { id: workspace,slug: workspace === f.workspaces.personal ? "alex" : "northwind",name: "Name" },displayRev: 1,appliedReservations: [] } },async membership() { throw new Error("unused") } } }
const workspace = () => ({ id: f.workspaces.personal,slug: "alex",name: "Personal" })
describe("permanent workspace aliases",() => {
  it("a crash before DO apply releases expired reservation without taking the name",async () => {
    const r = await reserveWorkspaceSlug(f.env,f.account,workspace(),"new-name")
    expect(await f.env.DB.prepare("SELECT slug FROM workspaces WHERE id=?").bind(r.workspace).first()).toEqual({ slug: "alex" })
    await reconcileWorkspaceMetadata(f.env,metadata(),r.expiresAt+1)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slug_reservations").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slugs").first()).toEqual({ n: 0 })
  })
  it("a crash after DO apply finalises canonical slug and reserves old alias forever",async () => {
    const r = await reserveWorkspaceSlug(f.env,f.account,workspace(),"new-name"),c = metadata()
    c.metadata = async id => ({ workspace: { ...workspace(),id,slug: "new-name" },displayRev: 2,appliedReservations: [r.id] })
    await reconcileWorkspaceMetadata(f.env,c,r.expiresAt+1)
    expect(await f.env.DB.prepare("SELECT slug,display_rev FROM workspaces WHERE id=?").bind(r.workspace).first()).toEqual({ slug: "new-name",display_rev: 2 })
    expect(await f.env.DB.prepare("SELECT slug,workspace FROM workspace_slugs").first()).toEqual({ slug: "alex",workspace: r.workspace })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slug_reservations").first()).toEqual({ n: 0 })
  })
  it("a delayed slug finalisation cannot overwrite a newer display name",async () => {
    const r = await reserveWorkspaceSlug(f.env,f.account,workspace(),"new-name")
    await f.env.DB.prepare("UPDATE workspaces SET name='Newest',display_rev=3 WHERE id=?").bind(r.workspace).run()
    await finaliseWorkspaceSlug(f.env,r,{ workspace: { ...workspace(),slug: "new-name",name: "Older" },displayRev: 2,appliedReservations: [r.id] })
    expect(await f.env.DB.prepare("SELECT name,slug,display_rev FROM workspaces WHERE id=?").bind(r.workspace).first()).toEqual({ name: "Newest",slug: "new-name",display_rev: 3 })
  })
  it("does not finalise an unapplied or foreign reservation",async () => {
    const r = await reserveWorkspaceSlug(f.env,f.account,workspace(),"new-name")
    await expectDirectoryRefusal(finaliseWorkspaceSlug(f.env,r,{ workspace: { ...workspace(),slug: "new-name" },displayRev: 2,appliedReservations: [] }),{ error: "conflict",message: "Workspace metadata changed. Try again." })
    expect(await f.env.DB.prepare("SELECT slug FROM workspaces WHERE id=?").bind(r.workspace).first()).toEqual({ slug: "alex" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slugs").first()).toEqual({ n: 0 })
  })
  it("five aliases work, the sixth has the exact namespace refusal and reserves nothing",async () => {
    let current = workspace()
    for (let i=0;i<5;i++) { const r = await reserveWorkspaceSlug(f.env,f.account,current,`renamed-${i}`); current = { ...current,slug: r.newSlug }; await finaliseWorkspaceSlug(f.env,r,{ workspace: current,displayRev: i+2,appliedReservations: [r.id] }) }
    await expectDirectoryRefusal(reserveWorkspaceSlug(f.env,f.account,current,"sixth-name"),{ error: "conflict",message: "name not available" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slug_reservations").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slugs").first()).toEqual({ n: 5 })
  })
  it("concurrent reservations for one slug have one winner and no foreign metadata",async () => {
    const other = { id: f.workspaces.work,slug: "northwind",name: "Work" }
    const results = await Promise.allSettled([reserveWorkspaceSlug(f.env,f.account,workspace(),"same-name"),reserveWorkspaceSlug(f.env,f.account,other,"same-name")])
    expect(results.filter(x => x.status === "fulfilled")).toHaveLength(1)
    const loser = results.find(x => x.status === "rejected")
    const error = loser?.status === "rejected" ? loser.reason : null
    const response = responseFor(error)
    expect(response.status).toBe(409)
    expect(await response.text()).toBe('{"error":"conflict","message":"name not available"}')
  })
  it("workspace create and rename share the 20/hour global miss budget; all names then refuse identically",async () => {
    await seedAccountRecoverySetup(f.env,f.account)
    await f.env.DB.prepare("UPDATE accounts SET can_create_workspaces=1,can_create_workspaces_by='operator:test',can_create_workspaces_op=lower(hex(randomblob(16))),recovery_setup_at=?,recovery_setup_kind='codes' WHERE id=?").bind(Date.now(),f.account).run()
    const a = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env)
    if (!a) throw new Error("Missing account")
    const now = Date.now()
    for (let i=0;i<20;i++) await expectDirectoryRefusal(reserveWorkspaceSlug(f.env,f.account,workspace(),"api",now),{ error: "conflict",message: "name not available" })
    const bodies = []
    for (const slug of ["free-name","alex","api"]) { try { await reserveWorkspace(f.env,a,{ slug,name: "Name" },{ type: "workspace.create",slug,name: "Name" },{ now }) } catch (error) { const response = responseFor(error); expect(response.status).toBe(429); bodies.push(await response.text()) } }
    expect(bodies).toHaveLength(3)
    expect(new Set(bodies).size).toBe(1)
    expect(JSON.parse(bodies[0] as string)).toEqual({ error: "rate_limited",message: "Too many unavailable names; try again later.",retryAfter: Math.ceil((3600000-now%3600000)/1000) })
    expect((await f.env.DB.prepare("SELECT detail FROM account_events WHERE action='account.workspace_name_limit'").all()).results).toEqual([{ detail: '{"count":20}' }])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspace_slug_reservations").first()).toEqual({ n: 0 })
  })
})

it("an interrupted rename gives a precise conflict, not a raw D1 error",async () => {
  await reserveWorkspaceSlug(f.env,f.account,workspace(),"first-name")
  await expectDirectoryRefusal(reserveWorkspaceSlug(f.env,f.account,workspace(),"second-name"),{ error: "conflict",message: "A workspace rename is still in progress." })
  expect(await f.env.DB.prepare("SELECT new_slug FROM workspace_slug_reservations WHERE workspace=?").bind(workspace().id).first()).toEqual({ new_slug: "first-name" })
})
