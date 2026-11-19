import { applyD1Migrations,createExecutionContext,runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { expect,it,vi } from "vitest"
import worker from "../src/index.ts"
import { initialiseWorkspaceGeneration } from "../src/vault/workspace-vault.ts"
import { WORKSPACE_GENERATION } from "../src/directory/workspace-cutover.ts"
import { freshTenant } from "./helpers.ts"
import { createWorkspaceFixture,resetWorkspaceDatabase } from "./workspace-fixtures.ts"

const refusal = { error: "upstream_failed",message: "Workspaces are unavailable until the fresh-start cutover completes.",retryAfter: 60 }
it("P3-14: the default-on Worker refuses every route and cron before the legacy D1 wipe, with no writes or workspace RPC",async () => {
  const db = env.MIGRATION_DB
  await resetWorkspaceDatabase(db)
  await applyD1Migrations(db,env.TEST_LEGACY_MIGRATIONS)
  await db.prepare("INSERT INTO tenants(id,name,created_at) VALUES ('tn_old','Old data',1)").run()
  const bindings = { ...env,DB: db,TENANT_VAULT: new Proxy(env.TENANT_VAULT,{ get() { throw new Error("No DO may be reached before D1 wipe") } }) }
  for (const path of ["/healthz","/api/account","/api/auth/signup/options","/api/w/alex","/w/alex/","/v1/me","/app/v1/session"]) {
    const response = await worker.fetch(new Request(`https://vault.test${path}`),bindings,createExecutionContext())
    expect(response.status).toBe(502)
    expect(await response.json()).toEqual(refusal)
  }
  await expect(worker.scheduled({} as ScheduledController,bindings)).rejects.toMatchObject({ code: "upstream_failed" })
  expect((await db.prepare("SELECT * FROM tenants").all()).results).toEqual([{ id: "tn_old",name: "Old data",created_at: 1 }])
  expect(await db.prepare("SELECT name FROM sqlite_master WHERE name='accounts'").first()).toBeNull()
})
it("P3-14: missing generation and a stale or unavailable bound DO generation refuse before signup can create state",async () => {
  const f = await createWorkspaceFixture()
  const request = () => new Request<unknown,IncomingRequestCfProperties>("https://vault.test/api/auth/signup/options",{ method: "POST",headers: { origin: "https://vault.test","content-type": "application/json" },body: JSON.stringify({ invite: "test-bootstrap-code",name: "First" }) })
  const before = (await f.env.DB.prepare("SELECT * FROM accounts").all()).results
  for (const generation of ["legacy",null]) {
    const namespace = new Proxy(f.env.TENANT_VAULT,{ get(target,key) {
      if (key === "getByName") return () => ({ async cutoverGeneration() { if (generation === null) throw new Error("old class has no method"); return generation } })
      return Reflect.get(target,key)
    } })
    const response = await worker.fetch(request(),{ ...f.env,TENANT_VAULT: namespace },createExecutionContext())
    expect(response.status).toBe(502)
    expect(await response.json()).toEqual(refusal)
  }
  await f.env.DB.prepare("DELETE FROM workspace_cutover").run()
  expect(await (await worker.fetch(request(),f.env,createExecutionContext())).json()).toEqual(refusal)
  expect((await f.env.DB.prepare("SELECT * FROM accounts").all()).results).toEqual(before)
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
})
it("P3-14: the fresh class rejects legacy SQL storage without migration or adoption",async () => {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  expect(await stub.cutoverGeneration()).toBe(WORKSPACE_GENERATION)
  await runInDurableObject(stub,instance => {
    const sql = instance.context.sql
    sql.exec("DROP TABLE _workspace_generation")
    sql.exec("INSERT INTO tenant_state(key,value) VALUES ('legacy-sentinel','old')")
    const before = sql.exec("SELECT * FROM tenant_state").toArray()
    expect(() => initialiseWorkspaceGeneration(sql)).toThrow("Legacy vault storage cannot serve workspaces")
    expect(sql.exec("SELECT * FROM tenant_state").toArray()).toEqual(before)
    expect(sql.exec("SELECT name FROM sqlite_master WHERE name='_workspace_generation'").toArray()).toEqual([])
  })
})
it("every old member/role operation is refused even on a never-initialised fresh workspace",async () => {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  for (const op of ["tenant.status","tenant.identity","tenant.unfreeze","devices.register"]) {
    expect(await stub.invoke({ op,input: undefined,auth: { kind: "system",reason: "old call" } })).toEqual({ ok: false,error: { status: 404,vaultError: { error: "not_found",message: "No such operation." } } })
  }
  expect(await stub.invoke({ op: "items.list",input: undefined,auth: { kind: "member",member: "mem_old",role: "owner" } })).toEqual({ ok: false,error: { status: 403,vaultError: { error: "forbidden",message: "You are not allowed to do that." } } })
})

it("workspace freeze and exact owner unfreeze roll back completely on audit failure",async () => {
  const { accessFixture,accessSnapshot,inAccess,workspaceInvoke,accountAuth } = await import("./access-test-support.ts")
  const { tenant } = await accessFixture()
  for (const change of ["freeze","unfreeze"] as const) {
    await inAccess(tenant,ctx => ctx.sql.exec(`CREATE TRIGGER cutover_freeze_audit BEFORE INSERT ON audit WHEN NEW.action='workspace.${change}' BEGIN SELECT RAISE(ABORT,'audit-fault'); END`))
    const before = await accessSnapshot(tenant)
    const auth = change === "unfreeze" ? accountAuth("owner",{ type: "workspace.unfreeze" }) : accountAuth("member")
    expect(await workspaceInvoke(tenant,`access.${change}`,{},auth)).toEqual({ ok: false,error: { status: 500,vaultError: { error: "internal",message: "Something went wrong inside the vault." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant,ctx => ctx.sql.exec("DROP TRIGGER cutover_freeze_audit"))
    expect(await workspaceInvoke(tenant,`access.${change}`,{},auth)).toEqual({ ok: true,value: {} })
  }
})


it("the fresh class accepts Cloudflare-internal SQL tables before creating its marker",async () => {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  await runInDurableObject(stub,async (instance,state) => {
    await state.storage.put("guard-test",true)
    const sql = instance.context.sql
    for (const { name } of sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT GLOB '__cf_*'").toArray()) sql.exec(`DROP TABLE "${name}"`)
    sql.exec("CREATE TABLE IF NOT EXISTS __cf_kv(key TEXT PRIMARY KEY,value BLOB)")
    // workerd reserves and hides _cf_METADATA from user SQL. Overlay that
    // internal catalogue row while retaining real SQL filtering and storage.
    const catalogue = new Proxy(sql,{ get(target,key) {
      if (key === "exec") return (query: string,...values: (string | number | null | ArrayBuffer)[]) => target.exec(query.replace("FROM sqlite_master","FROM (SELECT name,type FROM sqlite_master UNION ALL SELECT '_cf_METADATA','table')"),...values)
      return Reflect.get(target,key)
    } })
    expect(catalogue.exec("SELECT name FROM sqlite_master WHERE name IN ('__cf_kv','_cf_METADATA') ORDER BY name").toArray()).toEqual([{ name: "__cf_kv" },{ name: "_cf_METADATA" }])
    expect(() => initialiseWorkspaceGeneration(catalogue)).not.toThrow()
    expect(sql.exec("SELECT generation FROM _workspace_generation").toArray()).toEqual([{ generation: WORKSPACE_GENERATION }])
  })
})

it("the limiter refuses before any cutover probe, even with an incomplete directory",async () => {
  const f = await createWorkspaceFixture()
  await f.env.DB.prepare("DELETE FROM workspace_cutover").run()
  const probe = vi.fn(() => { throw new Error("Rate-limited requests must not probe the DO") })
  const bindings = { ...f.env,TENANT_VAULT: new Proxy(f.env.TENANT_VAULT,{ get() { return probe } }),RATE_LIMITER: { limit: async () => ({ success: false }) } as unknown as RateLimit }
  const response = await worker.fetch(new Request("https://vault.test/healthz"),bindings,createExecutionContext())
  expect(response.status).toBe(429)
  expect(await response.json()).toEqual({ error: "rate_limited",message: "Too many requests; slow down." })
  expect(probe).not.toHaveBeenCalled()
})

it("health caches only success for less than 60 seconds and rechecks deleted markers at expiry",async () => {
  const f = await createWorkspaceFixture(),clock = vi.spyOn(Date,"now").mockReturnValue(Date.now())
  let reads = 0
  const db = new Proxy(f.env.DB,{ get(target,key) {
    if (key === "prepare") return (query: string) => { reads++; return target.prepare(query) }
    return Reflect.get(target,key)
  } })
  const probe = vi.fn(() => ({ cutoverGeneration: async () => WORKSPACE_GENERATION }))
  const bindings = { ...f.env,DB: db,TENANT_VAULT: new Proxy(f.env.TENANT_VAULT,{ get(target,key) { return key === "getByName" ? probe : Reflect.get(target,key) } }) }
  const request = () => worker.fetch(new Request("https://vault.test/healthz"),bindings,createExecutionContext())
  try {
    expect((await request()).status).toBe(200)
    expect(probe).toHaveBeenCalledTimes(1)
    expect(reads).toBe(1)
    await f.env.DB.prepare("DELETE FROM workspace_cutover").run()
    clock.mockReturnValue(Date.now()+59_999)
    expect((await request()).status).toBe(200)
    expect(probe).toHaveBeenCalledTimes(1)
    expect(reads).toBe(1)
    clock.mockReturnValue(Date.now()+1)
    const expired = await request()
    expect(expired.status).toBe(502)
    expect(await expired.json()).toEqual(refusal)
    expect(reads).toBe(2)
    expect(probe).toHaveBeenCalledTimes(1)
    await f.env.DB.prepare("INSERT INTO workspace_cutover VALUES (1,?)").bind(WORKSPACE_GENERATION).run()
    expect((await request()).status).toBe(200)
    expect(probe).toHaveBeenCalledTimes(2)
    expect(reads).toBe(3)
  } finally { clock.mockRestore() }
})

it("a valid D1 generation marker cannot hide a recreated legacy member table",async () => {
  const f = await createWorkspaceFixture()
  await f.env.DB.prepare("CREATE TABLE members(id TEXT PRIMARY KEY)").run()
  const probe = vi.fn(() => { throw new Error("Legacy D1 must refuse before the DO probe") })
  const bindings = { ...f.env,TENANT_VAULT: new Proxy(f.env.TENANT_VAULT,{ get() { return probe } }) }
  const response = await worker.fetch(new Request("https://vault.test/healthz"),bindings,createExecutionContext())
  expect(response.status).toBe(502)
  expect(await response.json()).toEqual(refusal)
  expect(probe).not.toHaveBeenCalled()
  expect(await f.env.DB.prepare("SELECT generation FROM workspace_cutover WHERE id=1").first()).toEqual({ generation: WORKSPACE_GENERATION })
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM members").first()).toEqual({ n: 0 })
})
