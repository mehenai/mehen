import { createExecutionContext } from "cloudflare:test"
import { beforeEach,describe,expect,it,vi } from "vitest"
import { workspaceDirectoryPrefix } from "../src/routes/directory.ts"
import { accountRoutes,requireAccount } from "../src/routes/account.ts"
import { workspaceAccountRoutes,workspaceDirectoryRoutes } from "../src/routes/workspaces.ts"
import { reserveAccountSecurity } from "../src/directory/account-security.ts"
import { maintainWorkspaceDirectory } from "../src/directory/workspace-maintenance.ts"
import { findRoute } from "../src/router.ts"
import { responseFor,json } from "../src/http.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
async function call(path: string,method = "GET",body?: unknown,options: { cookie?: string; origin?: string } = {}) {
  const routes = [...accountRoutes,...workspaceAccountRoutes],url = new URL(`https://vault.test${path}`),found = findRoute(routes,method,path)
  if (!found || found === "method") return json({ error: "not_found",message: "No such operation." },404)
  const request = new Request(url,{ method,headers: { cookie: options.cookie ?? f.cookie,origin: options.origin ?? f.env.VAULT_ORIGIN,"content-type": "application/json" },...(body === undefined ? {} : { body: JSON.stringify(body) }) })
  try { return await found.route.handler({ request,env: f.env,url,params: found.params,ctx: createExecutionContext() }) } catch (error) { return responseFor(error) }
}
describe("additive directory route arrays",() => {
  it("the owned Google callback refuses missing protocol state instead of falling through",async () => {
    const url = new URL(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback`)
    await expect(workspaceDirectoryPrefix({ request: new Request(url),env: f.env,url,params: {},ctx: createExecutionContext() })).rejects.toMatchObject({ code: "identity_required" })
  })
  it("reserved and legacy-prefix names keep the frozen refusal and exhausted names share one rate body",async () => {
    const clock = vi.spyOn(Date,"now").mockReturnValue(Date.now())
    try {
      const bodies = []
      for (const slug of ["api","legacy-private"]) {
        const response = await call("/api/workspaces","POST",{ name: "Name",slug })
        expect(response.status).toBe(409)
        bodies.push(await response.json())
      }
      expect(bodies).toEqual([{ error: "conflict",message: "name not available" },{ error: "conflict",message: "name not available" }])
      await f.env.DB.prepare("UPDATE auth_attempts SET count=20 WHERE key=?").bind(`workspace-name:${f.account}`).run()
      const refused = []
      for (const slug of ["free-name","alex","legacy-private"]) {
        const response = await call("/api/workspaces","POST",{ name: "Name",slug })
        expect(response.status).toBe(429); refused.push(await response.json())
      }
      expect(refused[0]).toEqual(refused[1]); expect(refused[1]).toEqual(refused[2])
      expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces").first()).toEqual({ n: 2 })
    } finally { clock.mockRestore() }
  })
  it("same-origin enforcement runs before any account mutation",async () => {
    const response = await call("/api/account/recovery/generate","POST",{},{ origin: "https://foreign.test" })
    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: "forbidden",message: "Cross-site request refused." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM recovery_codes").first()).toEqual({ n: 0 })
  })
  it("events/notices and passkey/session views contain only the current account's rows",async () => {
    await f.env.DB.prepare("INSERT INTO account_events(id,account,at,action,detail) VALUES ('evt_foreign','acc_guest',?,'account.signin','{}')").bind(Date.now()).run()
    const response = await call("/api/account/events")
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual([])
    expect((await call("/api/account/sessions")).status).toBe(200)
    expect(await (await call("/api/account/passkeys")).json()).toEqual({ passkeys: [] })
  })
  it("unauthenticated and app-cookie account requests refuse identically",async () => {
    const first = await call("/api/account/events","GET",undefined,{ cookie: "unknown" })
    await f.env.DB.prepare("UPDATE web_sessions SET kind='app'").run()
    const second = await call("/api/account/events")
    expect(first.status).toBe(401); expect(second.status).toBe(401)
    expect(await first.text()).toBe(await second.text())
  })
  it("no owner reset, transfer or account deletion route is exported",() => {
    const paths = [...accountRoutes,...workspaceAccountRoutes,...workspaceDirectoryRoutes].map(route => route.path)
    expect(paths.some(path => /reset|transfer/.test(path))).toBe(false)
    expect(paths).not.toContain("/api/account/delete")
  })
})

describe("pending status and non-blocking roll-forward",() => {
  it("returns pending status while workspace projections are unavailable, without waiting for the retry",async () => {
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_other"] })
    const namespace = new Proxy(f.env.TENANT_VAULT,{ get(target,key,receiver) {
      if (key === "getByName") return (name: string) => new Proxy(target.getByName(name),{ get(stub,property,stubReceiver) {
        if (property === "invoke") return async () => { throw new Error("unavailable") }
        return Reflect.get(stub,property,stubReceiver)
      } })
      return Reflect.get(target,key,receiver)
    } })
    const env = { ...f.env,TENANT_VAULT: namespace },ctx = createExecutionContext(),scheduled: Promise<unknown>[] = []
    let completed = false
    vi.spyOn(ctx,"waitUntil").mockImplementation(promise => { scheduled.push(promise.finally(() => { completed = true })) })
    const url = new URL(`${env.VAULT_ORIGIN}/api/account`),rc = { request: new Request(url,{ headers: { cookie: f.cookie } }),env,ctx,url,params: {} }
    expect((await requireAccount(rc)).transition).toBe(id)
    expect(scheduled).toHaveLength(1)
    expect(completed).toBe(false)
    const account = accountRoutes.find(route => route.path === "/api/account")!
    let error: unknown
    try { await account.handler(rc) } catch (e) { error = e }
    const response = responseFor(error)
    expect(response.status).toBe(502)
    expect(await response.json()).toEqual({ error: "upstream_failed",message: "Workspace security metadata is temporarily unavailable.",retryAfter: 60,next: { url: `${env.VAULT_ORIGIN}/api/account/security-transition`,say: "Check the pending account security transition and retry the workspace list." } })
    const status = accountRoutes.find(route => route.path === "/api/account/security-transition")!
    expect(await (await status.handler(rc)).json()).toEqual({ pendingTransition: { id,reservedEpoch: 1,targets: 2,acknowledged: 0,state: "pending" },recoverySetupRequired: true })
    await Promise.all(scheduled)
    expect(await env.DB.prepare("SELECT security_epoch,security_transition FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 0,security_transition: id })
  })
})

it("request roll-forward respects the atomic one-minute retry lease",async () => {
  const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_other"] }),installs: string[] = []
  const namespace = new Proxy(f.env.TENANT_VAULT,{ get(target,key,receiver) {
    if (key === "getByName") return (workspace: string) => new Proxy(target.getByName(workspace),{ get(stub,property,stubReceiver) {
      if (property === "invoke") return async (call: { op: string }) => { if (call.op === "access.security.install") installs.push(workspace); throw new Error("unavailable") }
      return Reflect.get(stub,property,stubReceiver)
    } })
    return Reflect.get(target,key,receiver)
  } })
  for (let i=0;i<2;i++) {
    const ctx = createExecutionContext(),tasks: Promise<unknown>[] = [],url = new URL(`${f.env.VAULT_ORIGIN}/api/account`)
    vi.spyOn(ctx,"waitUntil").mockImplementation(promise => { tasks.push(promise) })
    await requireAccount({ env: { ...f.env,TENANT_VAULT: namespace },ctx,url,request: new Request(url,{ headers: { cookie: f.cookie } }),params: {} })
    await Promise.all(tasks)
  }
  expect(installs.sort()).toEqual([f.workspaces.personal,f.workspaces.work].sort())
  expect(await f.env.DB.prepare("SELECT attempts FROM account_security_transitions WHERE id=?").bind(id).first()).toEqual({ attempts: 1 })
})

it("recovery returns its ceremony cookie even while every install is unavailable",async () => {
  const { issueAccountRecoveryCodes,confirmAccountRecoveryCodes } = await import("../src/directory/workspace-recovery.ts")
  const { currentAccountSession } = await import("../src/directory/account-session.ts")
  const { retryAccountSecurity } = await import("../src/directory/account-security.ts")
  const { successfulDirectoryClient } = await import("./directory-test-support.ts")
  const { readCookie,SESSION_COOKIE,sha256Text } = await import("../src/directory/session.ts")
  const account = await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: f.cookie } }),f.env)
  if (!account) throw new Error("Missing account")
  const codes = await issueAccountRecoveryCodes(f.env,account)
  await confirmAccountRecoveryCodes(f.env,account,codes.batch,codes.codes[codes.confirmPosition-1]!)
  const namespace = new Proxy(f.env.TENANT_VAULT,{ get(target,key,receiver) {
    if (key === "getByName") return (workspace: string) => new Proxy(target.getByName(workspace),{ get(stub,property,stubReceiver) {
      if (property === "invoke") return async () => { throw new Error("unavailable") }
      return Reflect.get(stub,property,stubReceiver)
    } })
    return Reflect.get(target,key,receiver)
  } })
  const route = accountRoutes.find(route => route.path === "/api/auth/recovery")!,url = new URL(`${f.env.VAULT_ORIGIN}/api/auth/recovery`),request = new Request(url,{ method: "POST",headers: { origin: f.env.VAULT_ORIGIN,"sec-fetch-site": "same-origin","sec-fetch-mode": "cors" },body: JSON.stringify({ code: codes.codes[0] }) })
  const response = await route.handler({ request,url,env: { ...f.env,TENANT_VAULT: namespace },params: {},ctx: createExecutionContext() })
  expect(response.status).toBe(202)
  const body = await response.json() as { pending: boolean; transition: string },token = readCookie(new Request(url,{ headers: { cookie: response.headers.get("set-cookie") ?? "" } }),SESSION_COOKIE)
  expect(body.pending).toBe(true); expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
  await retryAccountSecurity(f.env,body.transition,successfulDirectoryClient())
  expect(await f.env.DB.prepare("SELECT kind FROM web_sessions WHERE token_hash=?").bind(await sha256Text(token!)).first()).toEqual({ kind: "recovery" })
})
