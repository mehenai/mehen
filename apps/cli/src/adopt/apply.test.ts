import { afterEach, describe, expect, it } from "bun:test"
import { mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import type { AdoptionStatus } from "@mehen/protocol/adopt"
import type { Project } from "@mehen/protocol/api"
import { adoptionStatus } from "../operations.ts"
import { FakeVaultApi, tempDir } from "../run/fake-vault-api.ts"
import { VaultApiError } from "../vault-api.ts"
import { type ApplyContext, type StoredItems, applyPlan, envCheck, outcomes, storedItems, storedSources, unappliedSources } from "./apply.ts"
import { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, AdoptPlanSchema, type PlanItem, buildPlan, checkPlan, sourceKeys } from "./plan.ts"
import { scan, sourceKey } from "./scan.ts"
import { verifyPlan } from "./verify.ts"

const OPENAI = "sk-proj-SENTINELopenai0123456789abcdef"
const OPENAI_PROD = "sk-proj-SENTINELprod0123456789abcdefgh"
const SESSION = "SENTINEL-session-secret-0123456789"
const VAULT = "https://vault.test"
const PROJECT = "prj_billing01"
const ENV_TEXT = `OPENAI_API_KEY=${OPENAI}\nSESSION_SECRET=${SESSION}\nLOG_LEVEL=debug\n`
const dirs: string[] = []
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function machine(options: { commit?: boolean; env?: string } = {}): Promise<{ home: string; repo: string; plan: AdoptPlan }> {
  const home = realpathSync(tempDir("mehen-adopt-apply-"))
  dirs.push(home)
  const repo = join(home, "code", "billing-api")
  mkdirSync(repo, { recursive: true })
  const git = (...args: string[]) => Bun.spawnSync(["git", "-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd: repo })
  git("init", "-q")
  git("remote", "add", "origin", "https://github.com/acme/billing-api")
  writeFileSync(join(repo, ".env"), options.env ?? ENV_TEXT)
  writeFileSync(join(repo, ".env.production"), `OPENAI_API_KEY=${OPENAI_PROD}\n`)
  if (options.commit) {
    git("add", "-f", ".env")
    git("commit", "-qm", "x")
  }
  const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
  const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "per-project" })
  return { home, repo, plan }
}

function batch(plan: AdoptPlan): AdoptionStatus {
  return { adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [{ device: "dev_test", name: "test-mac", items: plan.items.length }], created: plan.items.filter((i) => i.include).map((i) => ({ ref: i.ref, slug: i.slug })), refused: [] }
}

function approved(plan: AdoptPlan): StoredItems {
  return storedItems([{ status: batch(plan), refs: null, sources: null }])
}

// A vault whose project keeps the variables apply sets.
function vault(): { api: FakeVaultApi; project: Project } {
  const project: Project = { id: PROJECT, slug: "billing-api", remotes: ["github.com/acme/billing-api"], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }, { name: "prod", protected: true, fences: [] }], vars: [] }
  const api = new FakeVaultApi().on("GET", `/v1/projects/${PROJECT}`, () => project)
  for (const name of ["OPENAI_API_KEY", "SESSION_SECRET", "LOG_LEVEL", "EXTRA_TOKEN", "FIREBASE_WEB_API_KEY"]) {
    api.on("PUT", `/v1/projects/${PROJECT}/vars/${name}`, (body) => {
      const { env, item, field, plain } = body as { env: string; item?: string; field?: string; plain?: string }
      project.vars = [...project.vars.filter((v) => !(v.name === name && v.env === env)), { name, env, source: plain !== undefined ? "plain" : "item", item: item ?? null, field: field ?? null }]
      return project
    })
  }
  return { api, project }
}

function context(api: FakeVaultApi, home: string, guard = new OutputGuard()): ApplyContext {
  return { api, config: { vault: VAULT, tenant: "tn_test00000001", device: "dev_test", workspaceSlug: "test-space" }, guard, home, projects: { "billing-api": PROJECT } }
}

const all = { repos: null, env: null, dryRun: false }

describe("apply", () => {
  it("writes mehen.toml with \"vault\" only, sets the variables, lists the protected ones and leaves every source byte as it was", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const [result] = await applyPlan(plan, approved(plan), context(api, home), all)
    const manifest = readFileSync(join(repo, "mehen.toml"), "utf8")
    expect(manifest).toContain(`project = "${PROJECT}"`)
    expect(manifest).toContain('OPENAI_API_KEY = "vault"\nSESSION_SECRET = "vault"\nLOG_LEVEL = "vault"\n')
    expect(manifest).not.toContain("debug")
    expect(manifest).not.toContain("SENTINEL")
    expect(result?.manifest.state).toBe("written")
    const puts = api.calls.filter((c) => c.method === "PUT").map((c) => [c.path.split("/").pop(), c.body])
    expect(puts).toEqual([
      ["OPENAI_API_KEY", { env: "dev", item: "openai-billing-api", field: "key" }],
      ["SESSION_SECRET", { env: "dev", item: "session-secret-billing-api", field: "value" }],
      ["LOG_LEVEL", { env: "dev", plain: "debug" }],
    ])
    expect(JSON.stringify(api.calls)).not.toContain("SENTINEL")
    expect(result?.humanSets).toEqual([{ variable: "OPENAI_API_KEY", env: "prod", item: "openai-billing-api-prod" }])
    expect(result?.checks.find((c) => c.env === "dev")).toMatchObject({ ok: true, unresolved: [] })
    // mehen.toml is one per repo: prod lacks the dev-only names as well as the one a human sets.
    expect(result?.checks.find((c) => c.env === "prod")).toMatchObject({ ok: false, unresolved: ["OPENAI_API_KEY", "SESSION_SECRET", "LOG_LEVEL"] })
    expect(readFileSync(join(repo, ".env"), "utf8")).toBe(ENV_TEXT)
    expect(result?.committed).toEqual([])
  })

  it("applying again leaves mehen.toml byte for byte and each item mapping as it was, and sets each plain value again, which changes nothing", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    const manifest = readFileSync(join(repo, "mehen.toml"), "utf8")
    const puts = () => api.calls.filter((c) => c.method === "PUT").map((c) => [c.path.split("/").pop(), c.body])
    expect(puts()).toHaveLength(3)
    const [again] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(puts().slice(3)).toEqual([["LOG_LEVEL", { env: "dev", plain: "debug" }]])
    expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toBe(manifest)
    expect(again?.manifest.state).toBe("exists")
    expect(again?.vars.map((v) => [v.variable, v.set, v.unchanged])).toEqual([["OPENAI_API_KEY", "item", true], ["SESSION_SECRET", "item", true], ["LOG_LEVEL", "plain", false]])
    expect(again?.checks.map((c) => c.ok)).toEqual([true])
  })

  // Seen in review: apply left any plain value the vault already had, so on
  // a project that existed before, the file's value was never set and
  // retire, which compares only secrets, could take the file away.
  it("the first apply on a project whose vault has another plain value sets the file's value", async () => {
    const { home, plan } = await machine()
    const { api, project } = vault()
    const plain = new Map([["LOG_LEVEL", "info"]])
    project.vars = [{ name: "LOG_LEVEL", env: "dev", source: "plain", item: null, field: null }]
    api.on("PUT", `/v1/projects/${PROJECT}/vars/LOG_LEVEL`, (body) => {
      plain.set("LOG_LEVEL", (body as { plain: string }).plain)
      return project
    })
    const [result] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(plain.get("LOG_LEVEL")).toBe("debug")
    expect(result?.vars.find((v) => v.variable === "LOG_LEVEL")).toMatchObject({ set: "plain", unchanged: false, why: null })
  })

  // Seen in review: apply took whatever the batch created under a ref, so
  // after a re-plan renumbered the items a variable could get another
  // credential.
  it("after a re-plan, a created row under another item's name is not this plan's item and sets nothing", async () => {
    const { home, plan } = await machine()
    const { api } = vault()
    const ref = (slug: string) => plan.items.find((i) => i.slug === slug)?.ref as string
    const openai = ref("openai-billing-api")
    const session = ref("session-secret-billing-api")
    const status: AdoptionStatus = { ...batch(plan), created: [{ ref: "a7kq001", slug: "session-secret-billing-api" }, { ref: "a7kq002", slug: "openai-billing-api" }] }
    const stored = storedItems([{ status, refs: { [openai]: "a7kq001", [session]: "a7kq002" }, sources: null }])
    const [result] = await applyPlan(plan, stored, context(api, home), { ...all, env: "dev" })
    expect(result?.vars.filter((v) => v.variable !== "LOG_LEVEL").map((v) => [v.variable, v.set, v.why])).toEqual([
      ["OPENAI_API_KEY", null, `the batch stored session-secret-billing-api for ${openai}, not this plan's item openai-billing-api`],
      ["SESSION_SECRET", null, `the batch stored openai-billing-api for ${session}, not this plan's item session-secret-billing-api`],
    ])
    expect(api.calls.filter((c) => c.method === "PUT").map((c) => c.path.split("/").pop())).toEqual(["LOG_LEVEL"])
  })

  // Seen in review: the newest batch recorded for a plan ref replaced the
  // older ones, so a stale slug there hid the row an older batch created.
  it("takes a created row from any approved batch that stored the plan item's own name for its ref", async () => {
    const { home, plan } = await machine()
    const { api } = vault()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api")?.ref as string
    const older: AdoptionStatus = { ...batch(plan), created: [{ ref: "a7kq001", slug: "openai-billing-api" }] }
    const newer: AdoptionStatus = { ...batch(plan), adoption: "adp_test02", created: [{ ref: "a7kq001", slug: "openai-old-name" }] }
    const stored = storedItems([{ status: older, refs: { [openai]: "a7kq001" }, sources: null }, { status: newer, refs: { [openai]: "a7kq001" }, sources: null }])
    const [result] = await applyPlan(plan, stored, context(api, home), { ...all, env: "dev" })
    expect(result?.vars.find((v) => v.variable === "OPENAI_API_KEY")).toMatchObject({ set: "item", item: "openai-billing-api" })
    const stale = storedItems([{ status: newer, refs: { [openai]: "a7kq001" }, sources: null }])
    const [refused] = await applyPlan(plan, stale, context(vault().api, home), { ...all, env: "dev", dryRun: true })
    expect(refused?.vars.find((v) => v.variable === "OPENAI_API_KEY")?.why).toBe(`the batch stored openai-old-name for ${openai}, not this plan's item openai-billing-api`)
  })

  it("with no ref map for a batch, matches its created rows by name only", async () => {
    const { home, plan } = await machine()
    const { api } = vault()
    const status: AdoptionStatus = { ...batch(plan), created: [{ ref: "a001", slug: "session-secret-billing-api" }, { ref: "azzz002", slug: "openai-billing-api" }] }
    const [result] = await applyPlan(plan, storedItems([{ status, refs: null, sources: null }]), context(api, home), { ...all, env: "dev" })
    expect(result?.vars.map((v) => [v.variable, v.item])).toEqual([
      ["OPENAI_API_KEY", "openai-billing-api"],
      ["SESSION_SECRET", "session-secret-billing-api"],
      ["LOG_LEVEL", null],
    ])
  })

  // Seen in review: a stored slug alone let a new value take another
  // value's name, as plan refs are positional.
  it("keeps per stored slug the sources its rows came from, and none from a batch with no sources recorded or not approved", () => {
    const status: AdoptionStatus = { adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [], created: [{ ref: "a7kq001", slug: "openai" }, { ref: "a7kq002", slug: "stripe" }] }
    const refs = { a001: "a7kq001", a002: "a7kq002" }
    const sources = { a001: ["/code/api/.env\u0000OPENAI_API_KEY\u0000"] }
    expect(storedSources([{ status, refs, sources }])).toEqual(new Map([["openai", new Set(["/code/api/.env\u0000OPENAI_API_KEY\u0000"])]]))
    expect(storedSources([{ status, refs, sources: null }])).toEqual(new Map())
    expect(storedSources([{ status, refs: null, sources }])).toEqual(new Map())
    expect(storedSources([{ status: { ...status, status: "open" }, refs, sources }])).toEqual(new Map())
  })

  it("leaves a workspace credential alone when its batch recorded no sources for it, and a project item as before", async () => {
    const { home, plan } = await machine()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as AdoptPlan["items"][number]
    openai.slug = "openai"
    openai.home = { kind: "workspace" }
    const refs = Object.fromEntries(plan.items.map((i) => [i.ref, i.ref]))
    for (const stored of [approved(plan), storedItems([{ status: batch(plan), refs, sources: null }])]) {
      const [result] = await applyPlan(plan, stored, context(vault().api, home), { ...all, env: "dev", dryRun: true })
      expect(result?.vars.filter((v) => v.variable !== "LOG_LEVEL").map((v) => [v.variable, v.set, v.why])).toEqual([
        ["OPENAI_API_KEY", null, "the batch stored openai without recording which files it came from: if it holds this value, set this item's exists to true and include to false in the plan; otherwise plan again"],
        ["SESSION_SECRET", "item", null],
      ])
    }
  })

  // Seen in review: apply never ran plan --check's rebinding check, so a
  // plan edited after submit could move a bound variable onto another held
  // item.
  it("leaves a variable on the item it is bound to rather than move it onto another held item, unless an approved batch stored that item from the variable", async () => {
    const { home, repo, plan } = await machine()
    for (const item of plan.items) {
      item.include = false
      item.exists = true
    }
    const openai = plan.items.find((i) => i.slug === "openai-billing-api")?.ref as string
    const bound = () => {
      const v = vault()
      v.project.vars = [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai", field: "key" }]
      return v
    }
    const keyOf = (variable: string) => sourceKey({ path: join(repo, ".env"), variable, pointer: null })
    const storedFrom = (variable: string, appliedAt?: string, bound?: string[]) => storedItems([{ status: { ...batch(plan), created: [{ ref: "a7kq001", slug: "openai-billing-api" }] }, refs: { [openai]: "a7kq001" }, sources: { [openai]: [keyOf(variable)] }, appliedAt, bound }])
    const row = async (stored: StoredItems) => {
      const { api } = bound()
      const [result] = await applyPlan(plan, stored, context(api, home), { ...all, env: "dev" })
      return [result?.vars.find((v) => v.variable === "OPENAI_API_KEY"), api.calls.filter((c) => c.method === "PUT").map((c) => c.path.split("/").pop())]
    }
    const left = { set: null, item: null, why: "set to openai by another machine: left as it was, as apply moves a bound variable only onto an item already in the vault that this machine's approved batch, not yet applied, stored from it; map it to the item holding its value, or skip it" }
    expect(await row(approved(plan))).toEqual([expect.objectContaining(left), ["SESSION_SECRET", "LOG_LEVEL"]])
    expect(await row(storedFrom("SESSION_SECRET"))).toEqual([expect.objectContaining(left), ["SESSION_SECRET", "LOG_LEVEL"]])
    expect(await row(storedFrom("OPENAI_API_KEY"))).toEqual([expect.objectContaining({ set: "item", item: "openai-billing-api", why: null }), ["OPENAI_API_KEY", "SESSION_SECRET", "LOG_LEVEL"]])
    // Seen in review: once the batch is applied, a variable a human has
    // since bound to another item stays there.
    expect(await row(storedFrom("OPENAI_API_KEY", "2026-11-03T10:00:00.000Z"))).toEqual([expect.objectContaining(left), ["SESSION_SECRET", "LOG_LEVEL"]])
    // Seen in review: so does one apply bound in a part of the batch, as
    // with --repo or a target that failed; one it has not bound does not.
    expect(await row(storedFrom("OPENAI_API_KEY", undefined, [keyOf("OPENAI_API_KEY")]))).toEqual([expect.objectContaining(left), ["SESSION_SECRET", "LOG_LEVEL"]])
    expect(await row(storedFrom("OPENAI_API_KEY", undefined, [keyOf("SESSION_SECRET")]))).toEqual([expect.objectContaining({ set: "item", item: "openai-billing-api", why: null }), ["OPENAI_API_KEY", "SESSION_SECRET", "LOG_LEVEL"]])
    expect(await row(storedFrom("OPENAI_API_KEY", "2026-11-03T10:00:00.000Z", []))).toEqual([expect.objectContaining(left), ["SESSION_SECRET", "LOG_LEVEL"]])
  })

  // Adopt reconcile: a plan 0.3.15 or earlier wrote has no connectors, no compare
  // marks and no file times; it still loads, checks and applies.
  it("loads, checks and applies a plan written by 0.3.15", async () => {
    const { home, repo, plan } = await machine()
    const { connectors: _, ...rest } = plan
    const older = JSON.parse(JSON.stringify({ ...rest, items: plan.items.map(({ compare: _c, ...i }) => i), sources: Object.fromEntries(Object.entries(plan.sources).map(([id, { mtime: _m, ...s }]) => [id, s])) }))
    expect(JSON.stringify(older)).not.toMatch(/"compare"|"connectors"|"mtime"/)
    const parsed = AdoptPlanSchema.parse(older)
    expect(checkPlan(parsed)).toMatchObject({ ok: true, problems: [], compares: [], leftAlone: [] })
    const { api } = vault()
    const [result] = await applyPlan(parsed, approved(parsed), context(api, home), all)
    expect([result?.error, result?.vars.filter((v) => v.set !== null).map((v) => `${v.env} ${v.variable}`)]).toEqual([null, ["dev OPENAI_API_KEY", "dev SESSION_SECRET", "dev LOG_LEVEL"]])
    expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toContain('OPENAI_API_KEY = "vault"')
  })

  // Adopt reconcile: a compare row's outcome is created (kept as a new item,
  // perhaps under a new name), mapped (the vault's value kept) or replaced
  // (the holder now holding this value); each binds to the slug it names.
  it("binds a compare row's variables to the slug its mapped, replaced or created outcome names", async () => {
    const { home, repo, plan } = await machine()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    openai.compare = true
    const keyOf = (variable: string) => sourceKey({ path: join(repo, ".env"), variable, pointer: null })
    const decided = (outcome: Partial<AdoptionStatus>) => {
      const status = { ...batch(plan), created: batch(plan).created?.filter((c) => c.ref !== "a7kq001" && c.ref !== openai.ref), ...outcome }
      const refs = Object.fromEntries(plan.items.map((i) => [i.ref, i.ref === openai.ref ? "a7kq001" : i.ref]))
      return storedItems([{ status, refs, sources: { [openai.ref]: [keyOf("OPENAI_API_KEY")] } }])
    }
    const row = async (stored: StoredItems) => {
      const { api } = vault()
      const [result] = await applyPlan(plan, stored, context(api, home), { ...all, env: "dev" })
      return result?.vars.find((v) => v.variable === "OPENAI_API_KEY")
    }
    expect(await row(decided({ mapped: [{ ref: "a7kq001", slug: "openai-billing-api" }] }))).toMatchObject({ set: "item", item: "openai-billing-api", why: null })
    expect(await row(decided({ replaced: [{ ref: "a7kq001", slug: "openai-billing-api" }] }))).toMatchObject({ set: "item", item: "openai-billing-api", why: null })
    expect(await row(decided({ created: [{ ref: "a7kq001", slug: "openai-billing-api-2" }] }))).toMatchObject({ set: "item", item: "openai-billing-api-2", why: null })
    // A row the vault left undecided binds nothing.
    expect(await row(decided({}))).toMatchObject({ set: null, why: "openai-billing-api was not stored by the batch" })
    // The status as a vault from before the outcomes sends it still parses.
    const older = new FakeVaultApi().on("GET", "/v1/adoptions/adp_test01", () => ({ adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [], created: [{ ref: "a7kq001", slug: "openai-billing-api" }] }))
    expect(outcomes(await adoptionStatus(older, "adp_test01"))).toEqual([{ ref: "a7kq001", slug: "openai-billing-api" }])
  })

  // Adopt reconcile: apply never moves a variable bound to another item, for
  // a new item as for one already in the vault; a variable the vault
  // repointed at approval to the row's new slug is bound already.
  it("leaves a variable another machine set to another item even for a new item, and finds one already bound to the row's own slug done", async () => {
    const { home, plan } = await machine()
    const run = async (current: string) => {
      const v = vault()
      v.project.vars = [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: current, field: "key" }]
      const [result] = await applyPlan(plan, approved(plan), context(v.api, home), { ...all, env: "dev" })
      return [result?.vars.find((r) => r.variable === "OPENAI_API_KEY"), v.api.calls.filter((c) => c.method === "PUT").map((c) => c.path.split("/").pop())]
    }
    expect(await run("openai-mini")).toEqual([
      expect.objectContaining({ set: null, item: null, why: "set to openai-mini by another machine: left as it was, as apply moves a bound variable only onto an item already in the vault that this machine's approved batch, not yet applied, stored from it; map it to the item holding its value, or skip it" }),
      ["SESSION_SECRET", "LOG_LEVEL"],
    ])
    expect(await run("openai-billing-api")).toEqual([expect.objectContaining({ set: "item", item: "openai-billing-api", why: null, unchanged: true }), ["SESSION_SECRET", "LOG_LEVEL"]])
  })

  // Seen in review: with the batch's sources recorded, as every real submit
  // records them, the exception for a variable this machine's batch stored
  // an item from moved another machine's variable onto a new item, and a
  // renamed compare row's variable off the holder the reviewer left it on,
  // while plan --check said apply leaves it.
  it("leaves a variable bound to another item for a new item and for a compare row kept under a new name, even with the batch's sources recorded, as plan --check says", async () => {
    const { home, plan } = await machine()
    const project = (plan.repos[0] as AdoptPlan["repos"][number]).project
    project.id = PROJECT
    project.create = false
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    const refs = Object.fromEntries(plan.items.map((i) => [i.ref, i.ref]))
    const sources = Object.fromEntries(plan.items.map((i) => [i.ref, sourceKeys(plan, i)]))
    const run = async (status: AdoptionStatus, current: string) => {
      const batches = [{ status, refs, sources }]
      const v = vault()
      v.project.vars = [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: current, field: "key" }]
      const [result] = await applyPlan(plan, storedItems(batches), context(v.api, home), { ...all, env: "dev" })
      const check = checkPlan(plan, { boundVars: new Map([[PROJECT, [{ name: "OPENAI_API_KEY", env: "dev", item: current }]]]), unappliedSlugs: unappliedSources(batches) })
      return { row: result?.vars.find((r) => r.variable === "OPENAI_API_KEY"), puts: v.api.calls.filter((c) => c.method === "PUT").map((c) => c.path.split("/").pop()), problems: check.problems, leftAlone: check.leftAlone }
    }
    // A new item beside another machine's binding.
    expect(await run(batch(plan), "openai")).toEqual({
      row: expect.objectContaining({ set: null, item: null, why: expect.stringMatching(/^set to openai by another machine: left as it was/) }),
      puts: ["SESSION_SECRET", "LOG_LEVEL"],
      problems: [],
      leftAlone: [{ project: "billing-api", env: "dev", variable: "OPENAI_API_KEY", item: "openai" }],
    })
    // A compare row the reviewer kept as a new item, its variable left on the holder.
    openai.exists = true
    openai.compare = true
    const renamed: AdoptionStatus = { ...batch(plan), created: [...(batch(plan).created ?? []).filter((c) => c.ref !== openai.ref), { ref: openai.ref, slug: "openai-billing-api-2" }] }
    expect(await run(renamed, "openai-billing-api")).toEqual({
      row: expect.objectContaining({ set: null, item: null, why: expect.stringMatching(/^set to openai-billing-api by another machine: left as it was/) }),
      puts: ["SESSION_SECRET", "LOG_LEVEL"],
      problems: [],
      leftAlone: [],
    })
  })

  // Seen in review: a plain mapping was set over a variable another machine
  // had bound to an item, while an item mapping there is left alone.
  it("leaves a config variable another machine bound to an item as it was, as plan --check says", async () => {
    const { home, plan } = await machine()
    const project = (plan.repos[0] as AdoptPlan["repos"][number]).project
    project.id = PROJECT
    project.create = false
    const v = vault()
    v.project.vars = [{ name: "LOG_LEVEL", env: "dev", source: "item", item: "log-level", field: "value" }]
    const [result] = await applyPlan(plan, approved(plan), context(v.api, home), { ...all, env: "dev" })
    expect(result?.vars.find((r) => r.variable === "LOG_LEVEL")).toMatchObject({ set: null, item: null, why: expect.stringMatching(/^set to log-level by another machine: left as it was/) })
    expect(v.api.calls.filter((c) => c.method === "PUT").map((c) => c.path.split("/").pop())).toEqual(["OPENAI_API_KEY", "SESSION_SECRET"])
    expect(v.project.vars.find((x) => x.name === "LOG_LEVEL")).toMatchObject({ source: "item", item: "log-level" })
    const check = checkPlan(plan, { boundVars: new Map([[PROJECT, [{ name: "LOG_LEVEL", env: "dev", item: "log-level" }]]]) })
    expect(check).toMatchObject({ ok: true, problems: [], leftAlone: [{ project: "billing-api", env: "dev", variable: "LOG_LEVEL", item: "log-level" }] })
  })

  // Seen in review: once an older batch had created the item's own name,
  // a newer batch keeping a rotated value as a new item under the same ref
  // was ignored, so a new variable got the value the reviewer judged
  // different, and one the vault repointed was called another machine's.
  it("binds to the outcome of the newest approved batch that decided the ref, over an older batch that created the item's own name", async () => {
    const { home, plan } = await machine()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    const refs = { [openai.ref]: "a7kq001" }
    const sources = { [openai.ref]: sourceKeys(plan, openai) }
    const first: AdoptionStatus = { ...batch(plan), created: [{ ref: "a7kq001", slug: "openai-billing-api" }] }
    const second: AdoptionStatus = { ...batch(plan), adoption: "adp_test02", created: [{ ref: "a7kq001", slug: "openai-billing-api-2" }] }
    // Planned again after the first batch was applied: the item is proven, so it went as a compare row.
    openai.exists = true
    openai.compare = true
    const stored = storedItems([{ status: first, refs, sources, appliedAt: "2026-11-03T10:00:00.000Z" }, { status: second, refs, sources }])
    const run = async (current: string | null) => {
      const v = vault()
      if (current) v.project.vars = [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: current, field: "key" }]
      const [result] = await applyPlan(plan, stored, context(v.api, home), { ...all, env: "dev" })
      return result?.vars.find((r) => r.variable === "OPENAI_API_KEY")
    }
    expect(await run(null)).toMatchObject({ set: "item", item: "openai-billing-api-2", why: null, unchanged: false })
    expect(await run("openai-billing-api-2")).toMatchObject({ set: "item", item: "openai-billing-api-2", why: null, unchanged: true })
  })

  // Adopt reconcile: a Google token's variable maps to a connection, set
  // once that exact connection exists and otherwise left with the command.
  it("sets a connection's variable only to the exact connection the plan named, of its provider, and otherwise prints mehen connect", async () => {
    const { home, plan } = await machine({ env: `${ENV_TEXT}GMAIL_REFRESH_TOKEN=1//0gSENTINELrefresh0123456789abcdef\n` })
    expect(plan.repos[0]?.files.find((f) => f.path === ".env")?.vars.GMAIL_REFRESH_TOKEN).toEqual({ connection: "google-gmail" })
    const run = async (connections: { slug: string; kind: string; provider: string }[], bound: string | null = null) => {
      const v = vault()
      if (bound) v.project.vars = [{ name: "GMAIL_REFRESH_TOKEN", env: "dev", source: "item", item: bound, field: "access_token" }]
      v.api.on("GET", "/v1/items?kind=oauth-connection", () => ({ items: connections }))
      const puts: unknown[] = []
      v.api.on("PUT", `/v1/projects/${PROJECT}/vars/GMAIL_REFRESH_TOKEN`, (body) => {
        puts.push(body)
        return v.project
      })
      const [result] = await applyPlan(plan, approved(plan), context(v.api, home), { ...all, env: "dev" })
      return [result?.vars.find((r) => r.variable === "GMAIL_REFRESH_TOKEN"), puts]
    }
    const waiting = { set: null, item: null, why: 'google-gmail is not a google-gmail connection yet: mehen connect google-gmail --name google-gmail --reason "adopt: GMAIL_REFRESH_TOKEN"' }
    expect(await run([])).toEqual([expect.objectContaining(waiting), []])
    expect(await run([{ slug: "google-gmail", kind: "oauth-connection", provider: "google-gmail" }])).toEqual([expect.objectContaining({ set: "item", item: "google-gmail", why: null }), [{ env: "dev", item: "google-gmail", field: "access_token" }]])
    // Another connection of the provider that appears later, or the slug as another provider's: left.
    expect(await run([{ slug: "gmail-work", kind: "oauth-connection", provider: "google-gmail" }])).toEqual([expect.objectContaining(waiting), []])
    expect(await run([{ slug: "google-gmail", kind: "oauth-connection", provider: "google-drive" }])).toEqual([expect.objectContaining(waiting), []])
    // Bound to another item by another machine: left as it was.
    expect(await run([{ slug: "google-gmail", kind: "oauth-connection", provider: "google-gmail" }], "gmail-alex")).toEqual([expect.objectContaining({ set: null, why: expect.stringMatching(/^set to gmail-alex by another machine: left as it was/) }), []])
  })

  // Seen on a real machine: CLICKHOUSE_USERNAME=default in one repo stopped
  // the mehen.toml of every repo applied after it with "internal error:
  // output withheld", since the template's default_env line contains it,
  // and a value equal to the workspace name would stop its label the same
  // way. The guard holds what earlier targets' files gave it.
  it("writes mehen.toml when a value read sits inside the template or the workspace label", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const guard = new OutputGuard()
    guard.add("default", "unknown")
    guard.add("Billing Crew", "unknown")
    const ctx = context(api, home, guard)
    ctx.config = { ...ctx.config, workspaceName: "Billing Crew" }
    const [result] = await applyPlan(plan, approved(plan), ctx, { ...all, env: "dev" })
    expect(result?.manifest.state).toBe("written")
    const manifest = readFileSync(join(repo, "mehen.toml"), "utf8")
    expect(manifest).toContain('default_env = "dev"')
    expect(manifest).toContain("# workspace Billing Crew (test-space)")
    expect(manifest).not.toContain("SENTINEL")
  })

  it("refuses before approval, and a dry run sets nothing and writes nothing", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    expect(applyPlan(plan, storedItems([{ status: { ...batch(plan), status: "open" }, refs: null, sources: null }]), context(api, home), all)).rejects.toMatchObject({ code: "conflict" })
    const [result] = await applyPlan(plan, approved(plan), context(api, home), { ...all, dryRun: true })
    expect(result?.manifest.state).toBe("would-write")
    expect(api.calls.some((c) => c.method === "PUT")).toBe(false)
    expect(() => readFileSync(join(repo, "mehen.toml"))).toThrow()
  })

  it("prints the lines to add to an existing mehen.toml, and stops on a committed value for an adopted name", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const head = `project = "${PROJECT}"\nworkspace = "tn_test00000001"\nvault = "${VAULT}"\ndefault_env = "dev"\n\n[vars]\n`
    writeFileSync(join(repo, "mehen.toml"), `${head}OPENAI_API_KEY = "vault"\n`)
    const [merge] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(merge?.manifest).toMatchObject({ state: "merge", add: ['SESSION_SECRET = "vault"', 'LOG_LEVEL = "vault"'] })
    expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toBe(`${head}OPENAI_API_KEY = "vault"\n`)
    writeFileSync(join(repo, "mehen.toml"), `${head}LOG_LEVEL = "info"\n`)
    const [refused] = await applyPlan(plan, approved(plan), context(api, home), all)
    expect(refused?.error).toContain('gives LOG_LEVEL a committed value; change it to "vault" first')
  })

  it("never sets a secret as a plain value, even when an edited plan maps it to one", async () => {
    const { home, repo, plan } = await machine()
    writeFileSync(join(repo, ".env"), ENV_TEXT.replace(SESSION, "Summer2024!"))
    const file = plan.repos[0]?.files.find((f) => f.path === ".env") as AdoptPlan["repos"][number]["files"][number]
    const session = plan.items.find((i) => i.slug === "session-secret-billing-api")
    file.vars.SESSION_SECRET = { plain: session?.fields.value?.from[0] as string }
    const { api } = vault()
    const [result] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(result?.vars.find((v) => v.variable === "SESSION_SECRET")).toMatchObject({ set: null, why: "a secret cannot be a plain value" })
    expect(api.calls.some((c) => c.path.endsWith("/vars/SESSION_SECRET"))).toBe(false)
    expect(result?.vars.find((v) => v.variable === "LOG_LEVEL")).toMatchObject({ set: "plain" })
  })

  // Seen in review: a Firebase web key planned as plain config was skipped
  // by apply because its AIza shape looks like a secret, so mehen run no
  // longer delivered it.
  it("sets a Firebase web key's variable to its generic item, which plan --check accepts", async () => {
    const { home, plan } = await machine({ env: `FIREBASE_WEB_API_KEY=AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tUvW\nLOG_LEVEL=debug\n` })
    const firebase = plan.items.find((i) => i.slug === "firebase-web-api-key-billing-api")
    expect(firebase).toMatchObject({ include: true, kind: "generic", provider: null, binding: null })
    expect(checkPlan(plan)).toMatchObject({ ok: true, problems: [] })
    const { api } = vault()
    const [result] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(result?.vars.find((v) => v.variable === "FIREBASE_WEB_API_KEY")).toMatchObject({ set: "item", item: "firebase-web-api-key-billing-api", why: null })
    expect(api.calls.find((c) => c.path.endsWith("/vars/FIREBASE_WEB_API_KEY"))?.body).toEqual({ env: "dev", item: "firebase-web-api-key-billing-api", field: "value" })
    expect(JSON.stringify(api.calls)).not.toContain("AIza")
  })

  it("reports a vault call that fails on its row and sets the rest", async () => {
    const { home, plan } = await machine()
    const { api } = vault()
    api.on("PUT", `/v1/projects/${PROJECT}/vars/SESSION_SECRET`, () => {
      throw new VaultApiError(403, { error: "forbidden", message: "no" })
    })
    const [result] = await applyPlan(plan, approved(plan), context(api, home), { ...all, env: "dev" })
    expect(result?.vars.map((v) => [v.variable, v.set, v.why])).toEqual([
      ["OPENAI_API_KEY", "item", null],
      ["SESSION_SECRET", null, "the vault refused it: forbidden"],
      ["LOG_LEVEL", "plain", null],
    ])
    expect(result?.checks.map((c) => c.env)).toEqual(["dev"])
  })

  // Seen in review: a machine may not point a variable at a workspace
  // credential in a project shared with a guest or a team, and the row said
  // only "forbidden" once the credential was already workspace-wide.
  it("says why the vault refuses a variable a workspace credential backs, and how to keep one item per project", async () => {
    const { home, plan } = await machine()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as AdoptPlan["items"][number]
    openai.slug = "openai"
    openai.home = { kind: "workspace" }
    const { api } = vault()
    for (const name of ["OPENAI_API_KEY", "SESSION_SECRET"]) {
      api.on("PUT", `/v1/projects/${PROJECT}/vars/${name}`, () => {
        throw new VaultApiError(403, { error: "forbidden", message: "no" })
      })
    }
    const refs = Object.fromEntries(plan.items.map((i) => [i.ref, i.ref]))
    const stored = storedItems([{ status: batch(plan), refs, sources: { [openai.ref]: sourceKeys(plan, openai) } }])
    const [result] = await applyPlan(plan, stored, context(api, home), { ...all, env: "dev" })
    expect(result?.vars.map((v) => [v.variable, v.set, v.why])).toEqual([
      ["OPENAI_API_KEY", null, "the vault refused it: forbidden; openai is a workspace credential, and the project is possibly shared with a guest or a team, where a machine may not set one, or this machine may not edit the project: an owner or admin sets it on the project page or re-homes it, or plan again with mehen adopt plan --per-project for one item per project"],
      ["SESSION_SECRET", null, "the vault refused it: forbidden"],
      ["LOG_LEVEL", "plain", null],
    ])
  })

  it("names a source file git tracks so its values get rotated", async () => {
    const { home, repo, plan } = await machine({ commit: true })
    const { api } = vault()
    const [result] = await applyPlan(plan, approved(plan), context(api, home), all)
    expect(result?.committed).toEqual([join(repo, ".env")])
  })
})

describe("verify", () => {
  it("covers every name, runs the env check and one read-only relay call per item with a check", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const ctx = context(api, home)
    await applyPlan(plan, approved(plan), ctx, all)
    api.relayHandler = () => new Response(null, { status: 200, headers: { "Mehen-Upstream": "1" } })
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: null, session: null, now: new Date("2026-11-01T12:00:00Z") })
    const dev = report.targets[0]?.coverage.filter((c) => c.env === "dev")
    expect(dev?.map((c) => [c.variable, c.state])).toEqual([["OPENAI_API_KEY", "covered"], ["SESSION_SECRET", "covered"], ["LOG_LEVEL", "covered"]])
    expect(report.targets[0]?.coverage.find((c) => c.env === "prod")).toMatchObject({ variable: "OPENAI_API_KEY", state: "gap", why: "does not resolve for env=prod" })
    expect(api.relayCalls.map((r) => [r.item, r.method, r.url, r.context?.environment])).toEqual([
      ["openai-billing-api", "GET", "https://api.openai.com/v1/models", "dev"],
      ["openai-billing-api-prod", "GET", "https://api.openai.com/v1/models", "prod"],
    ])
    expect(api.relayCalls[0]?.context?.project).toBe(PROJECT)
    expect(report.items.map((i) => [i.slug, i.check])).toEqual([["openai-billing-api", "ok"], ["session-secret-billing-api", "none"], ["openai-billing-api-prod", "ok"]])
    expect(report.ok).toBe(false)
    expect(JSON.stringify(report)).not.toContain("SENTINEL")
    expect(readFileSync(join(repo, ".env"), "utf8")).toBe(ENV_TEXT)
  })

  it("a variable whose item the plan leaves unticked is skipped by apply and verify, not a gap", async () => {
    const { home, plan } = await machine()
    const session = plan.items.find((i) => i.slug === "session-secret-billing-api") as AdoptPlan["items"][number]
    session.include = false
    const { api } = vault()
    const ctx = context(api, home)
    const [result] = await applyPlan(plan, approved(plan), ctx, { ...all, env: "dev" })
    expect(result?.vars.find((v) => v.variable === "SESSION_SECRET")).toMatchObject({ set: null, why: "session-secret-billing-api is not included in the plan" })
    api.relayHandler = () => new Response(null, { status: 200, headers: { "Mehen-Upstream": "1" } })
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: null, session: null, now: new Date() })
    expect(report.targets[0]?.coverage.find((c) => c.variable === "SESSION_SECRET")).toMatchObject({ state: "skipped", why: "session-secret-billing-api is not included in the plan" })
  })

  it("a name added since the plan is a gap, and a refused or failing check is reported, never a value", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const ctx = context(api, home)
    await applyPlan(plan, approved(plan), ctx, { ...all, env: "dev" })
    writeFileSync(join(repo, ".env"), `${ENV_TEXT}EXTRA_TOKEN=SENTINEL-extra-0123456789\n`)
    let n = 0
    api.relayHandler = () => {
      n += 1
      if (n === 1) return new Response(null, { status: 401, headers: { "Mehen-Upstream": "1" } })
      throw new VaultApiError(403, { error: "approval_required", message: "needs approval" })
    }
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: [repo], session: null, now: new Date() })
    expect(report.targets[0]?.coverage.find((c) => c.variable === "EXTRA_TOKEN")).toMatchObject({ state: "gap", why: "not in the plan" })
    expect(report.items.map((i) => [i.slug, i.check, i.status, i.why])).toEqual([
      ["openai-billing-api", "failed", 401, "GET /v1/models answered 401"],
      ["session-secret-billing-api", "none", null, "its template has no read-only check"],
      ["openai-billing-api-prod", "refused", null, "the vault refused the call: approval_required"],
    ])
    expect(ctx.guard.clean("SENTINEL-extra-0123456789")).toBe(false)
    expect(JSON.stringify(report)).not.toContain("SENTINEL")
  })

  // Seen on a real machine: a repo whose every credential the plan leaves
  // out gets no mehen.toml from apply, and verify reported its plain names
  // as gaps and failed the batch.
  it("verify leaves out a repo apply left alone, since nothing in it is adopted", async () => {
    const { home, repo, plan } = await machine()
    for (const item of plan.items) item.include = false
    const { api } = vault()
    const ctx = context(api, home)
    expect(await applyPlan(plan, approved(plan), ctx, all)).toEqual([])
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: null, session: null, now: new Date() })
    expect(report).toEqual({ ok: true, targets: [], items: [] })
    expect(() => readFileSync(join(repo, "mehen.toml"))).toThrow()
  })

  // On a second machine the credentials a repo uses are often in the vault
  // already (exists, so not included): the repo is still bound.
  it("binds and verifies a repo whose credentials are all in the vault already", async () => {
    const { home, repo, plan } = await machine()
    for (const item of plan.items) {
      item.include = false
      item.exists = true
    }
    const { api } = vault()
    const ctx = context(api, home)
    const [result] = await applyPlan(plan, approved(plan), ctx, { ...all, env: "dev" })
    expect(result?.manifest.state).toBe("written")
    expect(readFileSync(join(repo, "mehen.toml"), "utf8")).toContain('OPENAI_API_KEY = "vault"')
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: null, session: null, now: new Date() })
    expect(report.targets.map((t) => t.target)).toEqual([repo])
  })

  // Seen on a real machine: a repo without mehen.toml said only "mehen env
  // check failed", since the check answered with an error, not a report.
  it("the env check says why it could not run", async () => {
    const { home, repo } = await machine()
    const { api } = vault()
    const check = await envCheck(repo, "dev", context(api, home))
    expect(check).toMatchObject({ env: "dev", ok: false, declared: [], unresolved: [] })
    expect(check.why).toStartWith(`no mehen.toml in ${repo}`)
  })

  it("a line the parser rejected is a gap, so a name dotenv would load is never missed", async () => {
    const { home, repo, plan } = await machine()
    const { api } = vault()
    const ctx = context(api, home)
    await applyPlan(plan, approved(plan), ctx, { ...all, env: "dev" })
    writeFileSync(join(repo, ".env"), `${ENV_TEXT}EXTRA_TOKEN: SENTINEL-extra-0123456789\n`)
    const report = await verifyPlan(plan, approved(plan), ctx, { repos: [repo], session: null, now: new Date() })
    expect(report.targets[0]?.coverage.filter((c) => c.state === "gap" && c.env === "dev")).toEqual([{ file: join(repo, ".env"), env: "dev", variable: "line 4", state: "gap", why: "not NAME=value" }])
    expect(report.ok).toBe(false)
    expect(JSON.stringify(report)).not.toContain("SENTINEL")
  })
})
