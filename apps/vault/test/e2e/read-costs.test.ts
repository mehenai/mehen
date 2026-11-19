// What one read costs a full workspace (the Northwind shape from production:
// about 150 credentials, 6 projects of about 60 variables, 3 people, 10
// machines, open approvals and adoptions), counted, never timed: how many
// times the workspace builds its evaluator state, how many statements its
// storage runs, and how many D1 round trips the Worker makes.
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { expect, it, vi } from "vitest"
import { adoptionSealContext, canonicalJson, importSealPublicKey, seal, type AdoptionCreated, type WorkspaceRef } from "@mehen/protocol"
import type { AccountInvocationAuth } from "../../src/vault/core.ts"
import { AREAS } from "../../src/vault/registry.ts"
import { rows } from "../../src/vault/core.ts"
import { items } from "../../src/vault/areas/items.ts"
import { checkedCredential } from "../../src/vault/areas/items-workspace.ts"
import { accessState, principalOf, setting } from "../../src/vault/areas/workspace-runtime.ts"
import { variableChange } from "../../src/ui/client/workspace-logic.ts"
import { body, journey, type Machine } from "./workspace-journey.ts"
import { projectSigned } from "./ui-projects-journey.ts"
import { fixtureSql } from "../fixture-sql.ts"

type Journey = Awaited<ReturnType<typeof journey>>
type Seeded = Journey & { work: WorkspaceRef; agent: Machine; peer: Machine; projects: string[] }

// Statements only their builder runs: one per evaluator state, one per
// credentials provider, one per projects provider.
const ACCESS_STATE_READ = "SELECT id,owner_kind,owner_id,scope,revoked_at FROM devices WHERE owner_kind IS NOT NULL"
const CREDENTIALS_READ = "SELECT id, slug, kind, tags, home_kind, home_id FROM items"
const PROJECTS_READ = "SELECT id,slug FROM projects ORDER BY id"
// The Worker's session lookup, workspace resolve and session identity check.
const SESSION_READ = "SELECT s.account,s.id,s.kind,s.expires_at,s.last_seen_at,a.name"
const WORKSPACE_READ = "SELECT w.id,w.slug,w.name,m.id AS membership FROM workspaces w JOIN memberships m ON m.workspace=w.id AND m.account=?"
const CHECK_READ = "SELECT id,rule_revision AS identityRuleRev"

async function adoption(f: Journey, machine: Machine, ref: string, slug: string): Promise<void> {
  const created = await body<AdoptionCreated>(await f.deviceCall(machine, "/v1/adoptions", { machine: "office", expectedItems: 1 }), 201)
  const key = await seal(await importSealPublicKey(created.sealKey.jwk), "sk-proj-read-costs-not-a-real-secret", adoptionSealContext(created.adoption, ref, "key"))
  const item = { ref, slug, kind: "api-key", provider: "openai", binding: null, injection: null, home: { kind: "workspace" }, tags: [], publicFields: {}, sealed: { key }, sources: [{ path: "/srv/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: null }
  await body(await f.deviceCall(machine, `/v1/adoptions/${created.adoption}/items`, { items: [item] }))
}

// The real parts through the Worker (people, projects, one credential, two
// machines, three run approvals, two adoptions), then the bulk as copies of
// the real rows: 149 more credentials, 360 variables, 8 more machines.
async function fullWorkspace(): Promise<Seeded> {
  const f = await journey()
  await f.recoverySetup(f.alex)
  await f.createWorkspace(f.alex, "alex", "Personal")
  const work = await f.createWorkspace(f.alex, "northwind", "Northwind")
  const platform = (await f.project(f.alex, work)).id
  const mia = await f.guest(f.alex, work, platform, "Mia")
  await body(await f.memberChange(f.alex, work, mia.member!, "role", "member"))
  const ada = await f.guest(f.alex, work, platform, "Ada")
  await body(await f.memberChange(f.alex, work, ada.member!, "role", "admin"))
  const projects = [platform]
  for (const slug of ["api", "web", "billing", "search", "infra"]) projects.push((await f.project(f.alex, work, slug)).id)
  await f.credential(f.alex, work, "seed-key", { kind: "workspace" })
  await body(await projectSigned(f, f.alex, work, variableChange(platform, "prod", "TOKEN", null, { kind: "item", item: "seed-key", field: "key" })))
  const machine = await f.protectedMachine(f.alex, work)
  const peer = await f.machine(mia, work)
  for (const command of ["deploy", "migrate", "backfill"]) await body(await f.deviceCall(machine, "/v1/runs", { project: platform, env: "prod", envSource: "flag", remote: null, worktree: "/read-costs", head: null, vars: ["TOKEN"], command: `node ${command}.js`, argv: ["node", `${command}.js`] }), 409)
  await adoption(f, machine, "a001", "adopted-one")
  await adoption(f, machine, "a002", "adopted-two")
  const alexMember = await f.member(f.alex, work)
  await runInDurableObject(env.TENANT_VAULT.getByName(work.id), (instance) => {
    const sql = fixtureSql(instance.context)
    const copy = (table: string, row: Record<string, SqlStorageValue>) => sql.exec(`INSERT INTO ${table}(${Object.keys(row).join(",")}) VALUES (${Object.keys(row).map(() => "?").join(",")})`, ...Object.values(row))
    const item = sql.exec<Record<string, SqlStorageValue>>("SELECT * FROM items WHERE slug='seed-key'").one()
    const secrets = sql.exec<Record<string, SqlStorageValue>>("SELECT * FROM item_secrets WHERE item=?", item.id).toArray()
    const slugs: string[] = []
    for (let n = 1; n < 150; n++) {
      const id = `itm_readcost${n}`, slug = `key-${String(n).padStart(3, "0")}`
      const home = n % 3 === 0 ? { home_kind: "member", home_id: alexMember } : n % 3 === 1 ? { home_kind: "project", home_id: projects[n % projects.length]! } : { home_kind: "workspace", home_id: null }
      copy("items", { ...item, id, slug, ...home })
      for (const secret of secrets) copy("item_secrets", { ...secret, item: id })
      slugs.push(slug)
    }
    projects.forEach((project, p) => {
      for (const environment of ["dev", "staging", "prod"]) for (let v = 0; v < 20; v++) {
        const name = `VAR_${v}`
        if (environment === "prod" && project === platform && name === "TOKEN") continue
        const reference = v % 2 === 0 ? { item: slugs[(p * 20 + v) % slugs.length]!, field: "key", plain: null } : { item: null, field: null, plain: `value-${v}` }
        sql.exec("INSERT INTO vars(project,env,name,item,field,plain,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?)", project, environment, name, reference.item, reference.field, reference.plain, alexMember, Date.now())
      }
    })
    const device = sql.exec<Record<string, SqlStorageValue>>("SELECT * FROM devices WHERE id=?", machine.device).one()
    for (let n = 0; n < 8; n++) copy("devices", { ...device, id: `dev_readcost${n}`, name: `machine-${n}`, thumbprint: `${"ABCDEFGH"[n]}${String(device.thumbprint).slice(1)}`, enrolment: null })
  })
  return { ...f, work, agent: machine, peer, projects }
}

type D1Count = { roundTrips: number; queries: string[] }
// Every statement the Worker sends D1, and every round trip: one per
// first/all/run/raw, one per batch however many statements it carries.
function countD1(db: D1Database, count: D1Count): D1Database {
  const real = new WeakMap<object, D1PreparedStatement>()
  const statement = (prepared: D1PreparedStatement, query: string): D1PreparedStatement => {
    const proxy = new Proxy(prepared, { get(target, key) {
      if (key === "bind") return (...values: unknown[]) => statement(target.bind(...values), query)
      const value = Reflect.get(target, key, target) as unknown
      if (typeof value !== "function") return value
      if (key === "first" || key === "all" || key === "run" || key === "raw") return (...args: unknown[]) => { count.roundTrips++; count.queries.push(query); return (value as (...a: unknown[]) => unknown).apply(target, args) }
      return (value as (...a: unknown[]) => unknown).bind(target)
    } })
    real.set(proxy, prepared)
    return proxy
  }
  return new Proxy(db, { get(target, key) {
    if (key === "prepare") return (query: string) => statement(target.prepare(query), query)
    if (key === "batch") return (statements: D1PreparedStatement[]) => { count.roundTrips++; count.queries.push(`batch of ${statements.length}`); return target.batch(statements.map((s) => real.get(s) ?? s)) }
    const value = Reflect.get(target, key, target) as unknown
    return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value
  } })
}

type Cost = { status: number; invocations: number; accessStates: number; credentialReads: number; projectReads: number; statements: number; rowsRead: number; d1: number; d1Queries: string[]; serverTiming: string | null; ms: number }
// One read's cost in the work workspace's object and in D1.
async function cost(f: Seeded, read: () => Promise<Response>): Promise<Cost> {
  const stub = env.TENANT_VAULT.getByName(f.work.id)
  const exec = await runInDurableObject(stub, (instance) => vi.spyOn(instance.context.sql, "exec"))
  const db = f.env.DB, vaults = f.env.TENANT_VAULT, count: D1Count = { roundTrips: 0, queries: [] }
  let invocations = 0
  f.env.DB = countD1(db, count)
  f.env.TENANT_VAULT = new Proxy(vaults, { get(target, key) {
    if (key !== "getByName") return Reflect.get(target, key, target) as unknown
    return (name: string) => {
      const object = target.getByName(name)
      return name !== f.work.id ? object : new Proxy(object, { get(o, prop) { if (prop === "invoke") invocations++; return Reflect.get(o, prop, o) as unknown } })
    }
  } })
  try {
    const started = performance.now()
    const response = await read()
    await response.arrayBuffer()
    const ms = Math.round(performance.now() - started)
    const queries = exec.mock.calls.map((call) => call[0])
    const rowsRead = exec.mock.results.reduce((n, result) => n + (result.type === "return" ? result.value.rowsRead : 0), 0)
    return { status: response.status, invocations, accessStates: queries.filter((q) => q === ACCESS_STATE_READ).length, credentialReads: queries.filter((q) => q === CREDENTIALS_READ).length, projectReads: queries.filter((q) => q === PROJECTS_READ).length, statements: queries.length, rowsRead, d1: count.roundTrips, d1Queries: count.queries, serverTiming: response.headers.get("server-timing"), ms }
  } finally {
    f.env.DB = db
    f.env.TENANT_VAULT = vaults
    exec.mockRestore()
  }
}

it("counts what each read costs a full workspace", async () => {
  const f = await fullWorkspace()
  const page = (path: string) => () => f.request(path, f.alex, undefined, { accept: "text/html" })
  const costs = {
    inbox: await cost(f, () => f.request("/api/w/northwind/inbox", f.alex)),
    needsYou: await cost(f, () => f.request("/api/needs-you", f.alex)),
    me: await cost(f, () => f.deviceCall(f.agent, "/v1/me")),
    devices: await cost(f, () => f.request("/api/w/northwind/devices", f.alex)),
    items: await cost(f, () => f.request("/api/w/northwind/items", f.alex)),
    projects: await cost(f, () => f.request("/api/w/northwind/projects", f.alex)),
    home: await cost(f, page("/w/northwind/")),
    credentials: await cost(f, page("/w/northwind/credentials")),
  }
  for (const c of Object.values(costs)) expect(c.status).toBe(200)
  // The workspace builds its evaluator state once and every later call reuses
  // it until the object is next written: the first read builds it, and so does
  // /v1/me, whose signed call records its nonce and the machine's last use
  // before it decides (areas/devices.ts); the reads
  // after it write nothing, so they build nothing. Home reads the posture
  // nudges too (routes/ui.ts), one bounded query over daily counts, and with
  // MANDATES on the mandates list for its strip of machines carrying on
  // without asking, one bounded query that stops at 100 mandates
  // (areas/mandates-workspace.ts).
  expect(Object.fromEntries(Object.entries(costs).map(([read, c]) => [read, [c.invocations, c.accessStates, c.credentialReads, c.projectReads]]))).toEqual({
    inbox: [1, 1, 1, 1], needsYou: [1, 0, 0, 0], me: [1, 1, 1, 1], devices: [1, 0, 0, 0], items: [1, 0, 0, 0], projects: [1, 0, 0, 0], home: [10, 0, 0, 0], credentials: [3, 0, 0, 0],
  })
  // A page and the reads it dispatches look its session, its workspace and
  // its identity check up once each (page-reads.ts).
  const lookups = (c: Cost) => [SESSION_READ, WORKSPACE_READ, CHECK_READ].map((read) => c.d1Queries.filter((q) => q.startsWith(read)).length)
  expect({ home: lookups(costs.home), credentials: lookups(costs.credentials) }).toEqual({ home: [1, 1, 1], credentials: [1, 1, 1] })
  expect(Object.fromEntries(Object.entries(costs).map(([read, c]) => [read, c.d1]))).toEqual({ inbox: 5, needsYou: 6, me: 1, devices: 4, items: 4, projects: 4, home: 12, credentials: 11 })
}, 120_000)

// With MANDATES on: 40 mandates on the workspace's machines, eight of them
// live, behind 400 closed proposals, and an ask from a machine of the
// reader's own and one from a machine of someone else's.
it("counts what the mandates list and an ask's page cost a full workspace with mandates", async () => {
  const f = await fullWorkspace()
  const ask = async (machine: Machine) => (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/relay", { item: "key-149", method: "POST", url: "https://api.openai.com/v1/assistants", headers: [] }), 409)).approval
  const own = await ask(f.agent), others = await ask(f.peer)
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => {
    const sql = instance.context.sql, now = Date.now()
    const terms = JSON.stringify({ device: "dev_readcost0", items: "all", classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 }, ttlDays: 30, schedule: null, note: "Read costs" })
    for (let n = 0; n < 40; n++) {
      const id = `mdt_readcost${String(n).padStart(2, "0")}`, device = `dev_readcost${n % 8}`
      sql.exec("INSERT INTO mandates(id,device,signer_member,terms,digest,state,rev,basis,created_at,expires_at) VALUES (?,?,?,?,?,?,1,?,?,?)", id, device, "mem_absent", terms, "digest", n < 8 ? "active" : "stopped", "{}", now - n * 1000, now + 30 * 86_400_000)
      for (let p = 0; p < 10; p++) sql.exec("INSERT INTO mandate_proposals(id,device,terms,reason,created_at,expires_at,closed_at,mandate_id) VALUES (?,?,?,?,?,?,?,?)", `mdp_readcost${n}x${p}`, device, terms, "Read costs", now - 1000, now, now, p === 0 ? id : null)
    }
  })
  const page = (path: string) => () => f.request(path, f.alex, undefined, { accept: "text/html" })
  const costs = {
    mandates: await cost(f, () => f.request("/api/w/northwind/mandates", f.alex)),
    ownAsk: await cost(f, page(`/w/northwind/a/${own}`)),
    othersAsk: await cost(f, page(`/w/northwind/a/${others}`)),
  }
  for (const c of Object.values(costs)) expect(c.status).toBe(200)
  // The list reads each mandate's proposal by its index, never all 400
  // proposals for each of 40 mandates (over 16,000 rows). The ask page asks
  // whether a mandate could cover the ask only for the machine's owner, so
  // the reader of another's machine's ask costs one call less; for the
  // owner, that call reads the ask too, to check they may see it. Each
  // access state built reads the shares whose end is settled, one join;
  // each call checks for a management guard marker left behind, and each
  // read of the access state reads the access revision first, one row by
  // its key, so a write by any route rebuilds it (areas/management-guard.ts).
  expect(Object.fromEntries(Object.entries(costs).map(([read, c]) => [read, [c.invocations, c.accessStates, c.statements, c.d1]]))).toEqual({ mandates: [1, 1, 248, 4], ownAsk: [4, 0, 32, 11], othersAsk: [3, 0, 20, 11] })
  expect(costs.mandates.rowsRead).toBeLessThan(2_500)
  const cover = async (approval: string) => (await (await page(`/w/northwind/a/${approval}`)()).text()).includes('data-region="mandate-cover"')
  expect([await cover(own), await cover(others)]).toEqual([true, false])
}, 120_000)

it("answers every read the same from one shared state as from a state built afresh for each check", async () => {
  const f = await fullWorkspace()
  const session = await f.db.prepare("SELECT s.id,a.security_epoch FROM web_sessions s JOIN accounts a ON a.id=s.account WHERE s.account=? ORDER BY s.created_at DESC LIMIT 1").bind(f.alex.account).first<{ id: string; security_epoch: number }>()
  const auth: AccountInvocationAuth = { kind: "account", account: f.alex.account, session: session!.id, securityEpoch: session!.security_epoch, sessionCheck: null, restrictedUntil: null }
  const reads: [string, unknown][] = [["pending.inbox", { enrolments: [] }], ["pending.list", {}], ["devices.list", {}], ["items.list", {}], ["projects.list", undefined], ["access.members.list", {}], ["access.invites.list", {}], ["access.settings", undefined]]
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), async (instance) => {
    const workspace = setting<WorkspaceRef | null>(instance.context, "workspace", null)
    for (const [op, input] of reads) {
      const shared = await instance.invoke({ op, input, auth })
      const spec = AREAS.map((area) => area.workspaceOps?.[op]).find((s) => s !== undefined)!
      const afresh = await spec.handler(instance.context, principalOf(instance.context, auth), input, { auth, workspace: workspace! })
      expect(shared).toEqual({ ok: true, value: expect.anything() })
      expect(canonicalJson((shared as { value: unknown }).value), op).toBe(canonicalJson(afresh))
      if (op === "pending.inbox") expect((afresh as { items: { ask?: { detail?: { kind: string } } }[] }).items.map((i) => i.ask?.detail?.kind)).toEqual(["approval", "approval", "approval", "adoption", "adoption"])
    }
  })
}, 120_000)

it("reads the evaluator's credentials and references from their own columns, equal to what whole credentials give", async () => {
  const f = await fullWorkspace()
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => {
    const ctx = instance.context
    const exec = vi.spyOn(ctx.sql, "exec")
    const state = accessState(ctx)
    // Per member, environment and team, never per credential or variable.
    expect(exec.mock.calls.length).toBeLessThan(state.credentials.length / 2)
    exec.mockRestore()
    const whole = rows(ctx.sql.exec<{ slug: string }>("SELECT id, slug FROM items")).map(({ slug }) => checkedCredential(ctx, slug)!)
    expect(state.credentials).toEqual(whole.map((c) => ({ id: c.id, slug: c.slug, home: c.home, tags: c.tags })))
    expect(state.credentials.length).toBeGreaterThanOrEqual(150)
    const references = state.projects.flatMap((p) => p.environments.flatMap((e) => e.references.map((r) => ({ project: p.id, environment: e.name, ...r }))))
    const stored = rows(ctx.sql.exec<{ project: string; env: string; name: string; item: string; field: string }>("SELECT project,env,name,item,field FROM vars WHERE item IS NOT NULL"))
    expect(references.length).toBe(stored.length)
    for (const r of references) {
      const row = stored.find((v) => v.project === r.project && v.env === r.environment && v.name === r.variable)!
      const credential = items.getItem(ctx, row.item)!
      expect({ item: r.item, field: r.field, home: r.home }).toEqual({ item: credential.id, field: row.field, home: whole.find((c) => c.id === credential.id)!.home })
    }
    expect(references.length).toBeGreaterThanOrEqual(180)
  })
}, 120_000)

it("a machine's next call keeps its imported key and prunes nonces at most every 30 seconds", async () => {
  const f = await fullWorkspace()
  const stub = env.TENANT_VAULT.getByName(f.work.id)
  expect((await f.deviceCall(f.agent, "/v1/me")).status).toBe(200)
  const exec = await runInDurableObject(stub, (instance) => vi.spyOn(instance.context.sql, "exec"))
  try {
    expect((await f.deviceCall(f.agent, "/v1/me")).status).toBe(200)
    expect(exec.mock.calls.filter((call) => String(call[0]).startsWith("DELETE FROM device_nonces")).length).toBe(0)
  } finally {
    exec.mockRestore()
  }
}, 120_000)
