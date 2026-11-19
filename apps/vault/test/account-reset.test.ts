import { createExecutionContext } from "cloudflare:test"
import { beforeEach,describe,expect,it } from "vitest"
import { workspaceDirectoryPrefix } from "../src/routes/directory.ts"
import { responseFor } from "../src/http.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
describe("account reset is not a workspace power",() => {
  it("refuses every legacy owner reset path uniformly, without reading factors or invoking a vault",async () => {
    const env = { ...f.env,DB: new Proxy(f.env.DB,{ get() { throw new Error("Reset touched D1") } }),TENANT_VAULT: new Proxy(f.env.TENANT_VAULT,{ get() { throw new Error("Reset invoked a vault") } }) }
    for (const path of ["/api/members/mem_member/reset","/api/account/reset","/api/members/mem_owner/reset","/api/members/mem_unindexed/reset"]) {
      const url = new URL(`${f.env.VAULT_ORIGIN}${path}`)
      let error: unknown
      try { await workspaceDirectoryPrefix({ request: new Request(url,{ method: "POST",headers: { cookie: f.cookie,origin: f.env.VAULT_ORIGIN },body: "{}" }),env,url,params: {},ctx: createExecutionContext() }) } catch (e) { error = e }
      const response = responseFor(error)
      expect(response.status).toBe(404)
      expect(await response.json()).toEqual({ error: "not_found",message: "No such operation." })
    }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual({ n: 1 })
  })
  it("the account's older factor, not any owner role, controls recovery resolution",async () => {
    const url = new URL(`${f.env.VAULT_ORIGIN}/api/account/recovery/ntc_foreign/resolve`)
    let error: unknown
    try { await workspaceDirectoryPrefix({ request: new Request(url,{ method: "POST",headers: { cookie: f.cookie,origin: f.env.VAULT_ORIGIN,"content-type": "application/json" },body: JSON.stringify({ outcome: "keep" }) }),env: f.env,url,params: {},ctx: createExecutionContext() }) } catch (e) { error = e }
    expect(await responseFor(error).json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(await f.env.DB.prepare("SELECT restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ restricted_until: null })
  })
})
