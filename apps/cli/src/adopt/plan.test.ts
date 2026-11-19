import { afterEach, describe, expect, it } from "bun:test"
import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { leaseOnlyBinding, leaseOnlyRefusal } from "@mehen/protocol/binding"
import type { CliError } from "../errors.ts"
import { FakeVaultApi, tempDir } from "../run/fake-vault-api.ts"
import { VaultApiError } from "../vault-api.ts"
import { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, type ExistingProject, type FolderHome, type PlanConnector, type PlanContext, type PlanItem, type VarMapping, type VisibleItem, AdoptPlanSchema, GOOGLE_SERVICE_UNKNOWN, MAX_FIELD_SOURCES, activeRepos, batchGroup, buildPlan, checkPlan, liveKeyListing, packBatches, parseFolderHome, sharedIfAllowed, vaultFacts } from "./plan.ts"
import { envForFile } from "./sources.ts"
import { type ScanResult, scan, sourceKey } from "./scan.ts"

const dirs: string[] = []
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function fixture(): Promise<{ home: string; repo: string; result: ScanResult }> {
  const home = realpathSync(tempDir("mehen-adopt-plan-"))
  dirs.push(home)
  const repo = join(home, "code", "billing-api")
  mkdirSync(repo, { recursive: true })
  Bun.spawnSync(["git", "init", "-q"], { cwd: repo })
  Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/billing-api"], { cwd: repo })
  const key = "sk-proj-0123456789abcdefghijklmnop"
  writeFileSync(join(repo, ".env"), `OPENAI_API_KEY=${key}\nLOG_LEVEL=debug\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=abcdEFGH1234ijklMNOP5678qrstUVWX90yzABCD\nSESSION_SECRET=s3cr3t-s3cr3t-value-1234\nGREETING=hello there\n`)
  writeFileSync(join(repo, ".env.production"), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n")
  mkdirSync(join(home, ".local-secrets"))
  writeFileSync(join(home, ".local-secrets", "openai.env"), `OPENAI_API_KEY=${key}\n`)
  const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
  return { home, repo, result }
}

// A repository checked out four times: the main checkout, two worktrees
// and a clone elsewhere, all with one origin.
function checkouts(): { home: string; main: string; roots: string[] } {
  const home = realpathSync(tempDir("mehen-adopt-plan-"))
  dirs.push(home)
  const main = join(home, "code", "app")
  const roots = [main, join(main, ".worktrees", "a"), join(main, ".worktrees", "b"), join(home, "code", "other", "app")]
  for (const root of roots) {
    mkdirSync(root, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: root })
    Bun.spawnSync(["git", "remote", "add", "origin", "git@github.com:acme/app.git"], { cwd: root })
  }
  return { home, main, roots }
}

// Repositories under ~/code, each with an origin of its own.
function repositories(...names: string[]): { home: string; roots: string[] } {
  const home = realpathSync(tempDir("mehen-adopt-plan-"))
  dirs.push(home)
  const roots = names.map((name) => {
    const root = join(home, "code", name)
    mkdirSync(root, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: root })
    Bun.spawnSync(["git", "remote", "add", "origin", `https://github.com/acme/${name}`], { cwd: root })
    return root
  })
  return { home, roots }
}

const OPENAI = "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n"

const scanCode = (home: string) => scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })

// Two repos under ~/code, homed in the workspace with --home, so equal
// values across them merge into one item: each named file holds one live key.
function twoRepos(files: Record<string, string>): { home: string; homes: Map<string, FolderHome> } {
  const home = realpathSync(tempDir("mehen-adopt-plan-"))
  dirs.push(home)
  const code = join(home, "code")
  for (const [name, file] of Object.entries(files)) {
    mkdirSync(join(code, name), { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: join(code, name) })
    Bun.spawnSync(["git", "remote", "add", "origin", `https://github.com/acme/${name}`], { cwd: join(code, name) })
    writeFileSync(join(code, name, file), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n")
  }
  return { home, homes: new Map([[code, { home: "workspace", project: null }]]) }
}

const LIVE_KEY_SKIP = { skip: "a live key: only the protected environment gets it" }

function context(home: string, overrides: Partial<PlanContext> = {}): PlanContext {
  return { workspace: "acme", vault: "https://vault.example", machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "workspace", ...overrides }
}

// What this machine's approved batches stored: per slug, the repos whose
// .env OPENAI_API_KEY the row came from.
const storedFrom = (stored: Record<string, string[]>) => new Map(Object.entries(stored).map(([slug, roots]) => [slug, new Set(roots.map((root) => sourceKey({ path: join(root, ".env"), variable: "OPENAI_API_KEY", pointer: null })))]))

// Items in the vault by slug, none of them stored by adopt.
const visible = (...slugs: string[]) => new Map<string, VisibleItem>(slugs.map((slug) => [slug, { kind: "generic", provider: null, tags: [] }]))

const ADOPTED_OPENAI: VisibleItem = { kind: "api-key", provider: "openai", tags: ["adopted", "billing"] }
const ADOPTED_STRIPE: VisibleItem = { kind: "api-key", provider: "stripe", tags: ["adopted"] }

// An adopted item held as `slug` that this machine's approved batch stored
// from `variable` in the file at `path`.
const storedItem = (slug: string, item: VisibleItem, path: string, variable: string): Pick<PlanContext, "visibleItems" | "storedSlugs"> => ({ visibleItems: new Map([[slug, item]]), storedSlugs: new Map([[slug, new Set([sourceKey({ path, variable, pointer: null })])]]) })

// A repo's existing project with a dev environment, binding OPENAI_API_KEY
// there to `item` when one is named.
const boundProject = (root: string, slug: string, item: string | null): [string, ExistingProject] => [root, { id: `prj_${slug}0001`, slug, environments: [{ name: "dev", protected: false }], vars: item === null ? [] : [{ name: "OPENAI_API_KEY", env: "dev", item }] }]

describe("plan", () => {
  it("proposes items with homes per folder and maps every name in a repo file", async () => {
    const { home, repo, result } = await fixture()
    const plan = AdoptPlanSchema.parse(buildPlan(result, context(home)))
    const summary = plan.items.map((i) => [i.slug, i.kind, i.provider, i.home.kind === "project" ? i.home.project : i.home.kind, i.include])
    expect(summary).toEqual([
      ["openai-local-secrets", "api-key", "openai", "private", true],
      ["openai-billing-api", "api-key", "openai", "billing-api", true],
      ["aws-billing-api", "cloud-access-key", null, "billing-api", true],
      ["session-secret-billing-api", "generic", null, "billing-api", true],
      ["stripe-billing-api-prod", "api-key", "stripe", "billing-api", true],
    ])
    const aws = plan.items[2]
    expect(Object.keys(aws?.fields ?? {})).toEqual(["secret_access_key"])
    expect(Object.keys(aws?.publicFields ?? {})).toEqual(["access_key_id"])
    expect(plan.repos).toHaveLength(1)
    expect(plan.repos[0]?.project).toEqual({ slug: "billing-api", id: null, create: true, environments: ["dev", "prod"] })
    const dev = plan.repos[0]?.files.find((f) => f.path === ".env")
    expect(dev?.env).toBe("dev")
    expect(Object.fromEntries(Object.entries(dev?.vars ?? {}).map(([k, v]) => [k, Object.keys(v)[0]]))).toEqual({ OPENAI_API_KEY: "item", LOG_LEVEL: "plain", AWS_ACCESS_KEY_ID: "item", AWS_SECRET_ACCESS_KEY: "item", SESSION_SECRET: "item", GREETING: "skip" })
    expect(plan.folders.map((f) => [f.path.slice(home.length), f.home, f.project])).toEqual([["/.local-secrets", "private", null], ["/code/billing-api", "project", "billing-api"]])
    expect(JSON.stringify(plan)).not.toContain("0123456789abcdef")
    const check = checkPlan(plan)
    expect(check.problems).toEqual([])
    expect(check.humanSets).toEqual([{ project: "billing-api", env: "prod", variable: "STRIPE_SECRET_KEY", item: "stripe-billing-api-prod" }])
    expect(repo).toBe(plan.repos[0]?.root as string)
  })

  // Adopt reconcile: a Google token is a connection made once, never an
  // item; its variable maps to the connection apply sets once it exists.
  it("lists Google tokens as connectors with a connection mapping, never items, and keeps the client pair an item", async () => {
    const home = realpathSync(tempDir("mehen-adopt-plan-"))
    dirs.push(home)
    const repo = join(home, "code", "mailer")
    mkdirSync(repo, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: repo })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/mailer"], { cwd: repo })
    writeFileSync(join(repo, ".env"), "GMAIL_REFRESH_TOKEN=1//0gSENTINELrefresh0123456789abcdef\nGOOGLE_REFRESH_TOKEN=1//0gSENTINELother0123456789abcdefg\nGOOGLE_CLIENT_ID=1234-abc.apps.googleusercontent.com\nGOOGLE_CLIENT_SECRET=GOCSPX-SENTINELsecret0123456789ab\n")
    const result = await scanCode(home)
    const planned = (visibleItems: PlanContext["visibleItems"]) => AdoptPlanSchema.parse(buildPlan(result, context(home, { visibleItems })))
    const plan = planned(new Map())
    expect(plan.items.map((i) => [i.slug, i.kind, i.provider])).toEqual([["google-oauth-client-mailer", "oauth-client", "google-oauth-client"]])
    const vars = plan.repos[0]?.files[0]?.vars
    expect([vars?.GMAIL_REFRESH_TOKEN, vars?.GOOGLE_REFRESH_TOKEN]).toEqual([{ connection: "google-gmail" }, { skip: GOOGLE_SERVICE_UNKNOWN }])
    const at = (c: PlanConnector) => plan.sources[c.source]?.variable
    expect(plan.connectors?.map((c) => [at(c), c.provider, c.why, c.command])).toEqual([
      ["GMAIL_REFRESH_TOKEN", "google-gmail", "a Google OAuth token: connect google-gmail once instead; the vault never imports a token", 'mehen connect google-gmail --name google-gmail --reason "adopt: GMAIL_REFRESH_TOKEN"'],
      ["GOOGLE_REFRESH_TOKEN", null, "a Google OAuth token for a service its name does not say: connect the Google service it uses; the vault never imports a token", 'mehen connect <google-gmail|google-calendar|google-drive> --name <slug> --reason "<why>"'],
    ])
    expect(JSON.stringify(plan)).not.toContain("SENTINEL")
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 1, problems: [] })
    // The one connection of its provider already held is the one it uses, and the plan says so.
    const connection: VisibleItem = { kind: "oauth-connection", provider: "google-gmail", tags: [] }
    const held = planned(new Map([["gmail-alex", connection]]))
    expect(held.repos[0]?.files[0]?.vars.GMAIL_REFRESH_TOKEN).toEqual({ connection: "gmail-alex" })
    expect(held.connectors?.[0]?.why).toBe("a Google OAuth token: connect google-gmail once instead; the vault never imports a token; uses the existing connection gmail-alex; to use another account, connect one with --name and map it")
    // Two held: none is picked.
    expect(planned(new Map([["gmail-alex", connection], ["gmail-work", connection]])).repos[0]?.files[0]?.vars.GMAIL_REFRESH_TOKEN).toEqual({ connection: "google-gmail" })
    // A connection mapping no connector names is a problem.
    const edited = structuredClone(plan)
    ;(edited.repos[0]?.files[0] as { vars: Record<string, VarMapping> }).vars.GOOGLE_REFRESH_TOKEN = { connection: "google-gmail" }
    expect(checkPlan(edited).problems.map((p) => p.problem)).toEqual(["GOOGLE_REFRESH_TOKEN maps to connection google-gmail, but no connector in the plan with a provider names it"])
    // A plan written before connectors still loads and checks.
    const { connectors: _, ...older } = plan
    ;(older.repos[0]?.files[0] as { vars: Record<string, VarMapping> }).vars.GMAIL_REFRESH_TOKEN = { skip: "not adopted" }
    expect(checkPlan(AdoptPlanSchema.parse(older))).toMatchObject({ ok: true, problems: [] })
  })

  // One MacBook plans 255 items; four machines pass the 500 a batch holds.
  it("checks a plan over 500 items clean and counts the batches it takes, each project whole", async () => {
    const { home, result } = await fixture()
    const plan = buildPlan(result, context(home))
    const base = plan.items.find((i) => i.include && i.home.kind === "project") as PlanItem
    const copies = (n: number, from: number, home: PlanItem["home"]): PlanItem[] => Array.from({ length: n }, (_, k) => ({ ...base, ref: `a${(from + k).toString(36).padStart(4, "0")}`, slug: `copy-${from + k}`, home }))
    plan.items.push(...copies(300, 2000, { kind: "project", project: "billing-api" }), ...copies(320, 4000, { kind: "private" }))
    const check = checkPlan(plan)
    expect(check.problems).toEqual([])
    expect(check.included).toBeGreaterThan(620)
    expect(check.batches).toBe(2)
    const batches = packBatches(plan.items.filter((i) => i.include && !i.exists), batchGroup)
    expect(batches.map((b) => new Set(b.map(batchGroup)).size)).toEqual([1, 1])
    expect(checkPlan({ ...plan, items: plan.items.slice(0, 10) }).batches).toBe(1)
  })

  it("packs groups whole into the first batch with room, largest first, and splits only a group larger than a batch", () => {
    const items = (group: string, n: number) => Array.from({ length: n }, () => group)
    const sizes = (batches: string[][]) => batches.map((b) => [...new Set(b)].map((g) => `${g}${b.filter((x) => x === g).length}`).join(" "))
    expect(sizes(packBatches([...items("d", 40), ...items("c", 150), ...items("a", 300), ...items("b", 250)], (g) => g))).toEqual(["d40 c150 a300", "b250"])
    expect(sizes(packBatches(items("e", 1100), (g) => g))).toEqual(["e500", "e500", "e100"])
    // Batches joined with 120 and 0 places left, then a new one.
    expect(sizes(packBatches([...items("x", 100), ...items("y", 80)], (g) => g, [120, 0]))).toEqual(["x100", "", "y80"])
    expect(packBatches([], (g: string) => g)).toEqual([])
  })

  it("merges equal values that land in one home into one item", async () => {
    const { home, result } = await fixture()
    const homes = new Map<string, FolderHome>([[join(home, ".local-secrets"), { home: "project", project: "billing-api" }]])
    const plan = buildPlan(result, context(home, { homes }))
    const openai = plan.items.filter((i) => i.provider === "openai")
    expect(openai).toHaveLength(1)
    expect(openai[0]?.fields.key?.from).toHaveLength(2)
    expect(openai[0]?.note).toBe("same value in 2 files")
    expect(checkPlan(plan).problems).toEqual([])
  })

  it("makes a value equal in two repos one workspace credential that both projects' variables use", async () => {
    const { home, roots } = repositories("api", "web")
    const [api, web] = roots as [string, string]
    writeFileSync(join(api, ".env"), `${OPENAI}SESSION_SECRET=s3cr3t-api-value-12345678\n`)
    writeFileSync(join(web, ".env"), OPENAI)
    const plan = buildPlan(await scanCode(home), context(home))
    expect(plan.items.map((i) => [i.slug, i.home, Object.values(i.fields)[0]?.from.map((s) => plan.sources[s]?.path), i.note])).toEqual([
      ["openai", { kind: "workspace" }, [join(api, ".env"), join(web, ".env")], "used by 2 projects (api, web): one workspace credential; every member's machine may use it"],
      ["session-secret-api", { kind: "project", project: "api" }, [join(api, ".env")], null],
    ])
    const openai = plan.items[0] as PlanItem
    expect(plan.repos.map((r) => [r.project.slug, r.files[0]?.vars.OPENAI_API_KEY])).toEqual([
      ["api", { item: openai.ref, field: "key" }],
      ["web", { item: openai.ref, field: "key" }],
    ])
    expect(activeRepos(plan)).toHaveLength(2)
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 2, sharedWorkspace: 1 })
  })

  // Seen in review: a protected value merged into a workspace credential
  // was reachable by every member's machine until a human wired it in, and
  // then only an owner or admin could set it.
  it("makes one credential only of values all in unprotected environments, and keeps a protected value one item per project", async () => {
    const { home, roots } = repositories("api", "billing", "web")
    const [api, billing, web] = roots as [string, string, string]
    writeFileSync(join(api, ".env"), OPENAI)
    writeFileSync(join(billing, ".env.production"), OPENAI)
    writeFileSync(join(web, ".env"), OPENAI)
    const plan = buildPlan(await scanCode(home), context(home))
    expect(plan.items.map((i) => [i.slug, i.home, i.fields.key?.from.length])).toEqual([
      ["openai", { kind: "workspace" }, 2],
      ["openai-billing-prod", { kind: "project", project: "billing" }, 1],
    ])
    expect(checkPlan(plan)).toMatchObject({ ok: true, sharedWorkspace: 1 })
    // An existing project's protected environment counts as prod does, and
    // two protected values in two projects stay one item each.
    const existing = new Map([[web, { id: "prj_web00001", slug: "web", environments: [{ name: "dev", protected: true }], vars: [] }]])
    const guarded = buildPlan(await scanCode(home), context(home, { existing }))
    expect(guarded.items.map((i) => [i.slug, i.home, i.fields.key?.from.map((s) => guarded.sources[s]?.path)])).toEqual([
      ["openai-api", { kind: "project", project: "api" }, [join(api, ".env")]],
      ["openai-billing-prod", { kind: "project", project: "billing" }, [join(billing, ".env.production")]],
      ["openai-web", { kind: "project", project: "web" }, [join(web, ".env")]],
    ])
    expect(checkPlan(guarded)).toMatchObject({ ok: true, sharedWorkspace: 0 })
  })

  it("never makes one credential of a private value and a project's", async () => {
    const { home, result } = await fixture()
    const search = join(home, "code", "search-api")
    mkdirSync(search)
    Bun.spawnSync(["git", "init", "-q"], { cwd: search })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/search-api"], { cwd: search })
    writeFileSync(join(search, ".env"), "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n")
    const rescanned = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    expect(result.entries.length).toBeGreaterThan(0)
    const plan = buildPlan(rescanned, context(home))
    expect(plan.items.filter((i) => i.provider === "openai").map((i) => [i.slug, i.home, i.note])).toEqual([
      ["openai-local-secrets", { kind: "private" }, null],
      ["openai", { kind: "workspace" }, "used by 2 projects (billing-api, search-api): one workspace credential; every member's machine may use it"],
    ])
    expect(checkPlan(plan).problems).toEqual([])
  })

  it("keeps one item per project for a folder given a home with --home, and with --per-project", async () => {
    const { home, roots } = repositories("api", "web")
    const [api, web] = roots as [string, string]
    writeFileSync(join(api, ".env"), OPENAI)
    writeFileSync(join(web, ".env"), OPENAI)
    const perProject = [
      ["openai-api", "project:api", null],
      ["openai-web", "project:web", null],
    ]
    const summary = (plan: AdoptPlan) => plan.items.map((i) => [i.slug, batchGroup(i), i.note])
    const homes = new Map<string, FolderHome>([[web, { home: "project", project: "web" }]])
    const chosen = buildPlan(await scanCode(home), context(home, { homes }))
    expect(summary(chosen)).toEqual(perProject)
    const flagged = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project" }))
    expect(summary(flagged)).toEqual(perProject)
    expect(checkPlan(flagged)).toMatchObject({ ok: true, sharedWorkspace: 0 })
  })

  it("names a workspace credential apart from another item in the vault, and never merges an item the vault already has", async () => {
    const { home, roots } = repositories("api", "web")
    for (const root of roots) writeFileSync(join(root, ".env"), OPENAI)
    const summary = (plan: AdoptPlan) => plan.items.map((i) => [i.slug, i.home.kind, i.include, i.exists])
    const adoptedOpenai: VisibleItem = { kind: "api-key", provider: "openai", tags: ["adopted"] }
    for (const other of [{ ...adoptedOpenai, kind: "generic" }, { ...adoptedOpenai, provider: "anthropic" }] satisfies VisibleItem[]) {
      const taken = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", other]]) }))
      expect(summary(taken)).toEqual([["openai-2", "workspace", true, false]])
    }
    // An item of its kind and provider made by hand may be this value too.
    const byHand = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", { ...adoptedOpenai, tags: [] }]]) }))
    expect(byHand.items.map((i) => [i.slug, i.include, i.exists, i.compare])).toEqual([["openai", true, false, true]])
    const stored = buildPlan(await scanCode(home), context(home, storedItem("openai-web", ADOPTED_OPENAI, join(roots[1] as string, ".env"), "OPENAI_API_KEY")))
    expect(stored.items.map((i) => [i.slug, i.home.kind, i.include, i.exists, i.compare])).toEqual([
      ["openai-api", "project", true, false, false],
      ["openai-web", "project", true, true, true],
    ])
  })

  // Before: a second plan after the batch was approved named the shared
  // credential openai-2, uploaded it again and re-pointed every project at
  // it. Seen in review since: kind, provider and the adopted tag say nothing
  // of the value, so another admin's openai took this value's variables and
  // the value was never uploaded.
  it("reuses a held bare name only when a project binds the group's variable to it or this machine's batch stored it from one of the group's sources", async () => {
    const { home, roots } = repositories("api", "web")
    const [api, web] = roots as [string, string]
    for (const root of roots) writeFileSync(join(root, ".env"), OPENAI)
    const held = new Map([["openai", ADOPTED_OPENAI]])
    const summary = (plan: AdoptPlan) => plan.items.map((i) => [i.slug, i.home.kind, i.include, i.exists])
    // Unproven, it is a compare row under that name, never a second copy.
    const unproven = buildPlan(await scanCode(home), context(home, { visibleItems: held }))
    expect(summary(unproven)).toEqual([["openai", "workspace", true, false]])
    expect(unproven.items[0]?.note).toBe("compare with openai in the vault: the reviewer decides which value it keeps; used by 2 projects (api, web): one workspace credential; every member's machine may use it")
    expect(checkPlan(unproven)).toMatchObject({ ok: true, included: 1 })
    const stored = buildPlan(await scanCode(home), context(home, { visibleItems: held, storedSlugs: storedFrom({ openai: [web] }) }))
    expect(summary(stored)).toEqual([["openai", "workspace", true, true]])
    // A batch that stored openai from no source of this group proves nothing.
    const elsewhere = buildPlan(await scanCode(home), context(home, { visibleItems: held, storedSlugs: new Map([["openai", new Set([sourceKey({ path: join(home, "code", "other", ".env"), variable: "OPENAI_API_KEY", pointer: null })])]]) }))
    expect(summary(elsewhere)).toEqual([["openai", "workspace", true, false]])
    const bound = buildPlan(await scanCode(home), context(home, { visibleItems: held, existing: new Map([boundProject(api, "api", "openai"), boundProject(web, "web", null)]) }))
    expect(summary(bound)).toEqual([["openai", "workspace", true, true]])
    const openai = bound.items[0] as PlanItem
    expect(bound.repos.map((r) => r.files[0]?.vars.OPENAI_API_KEY)).toEqual([
      { item: openai.ref, field: "key" },
      { item: openai.ref, field: "key" },
    ])
    expect(checkPlan(bound)).toMatchObject({ ok: true, included: 1, compares: [{ ref: openai.ref, slug: "openai" }] })
    // A project binding the variable to another item outweighs both.
    const split = buildPlan(await scanCode(home), context(home, { visibleItems: held, storedSlugs: storedFrom({ openai: [api, web] }), existing: new Map([boundProject(api, "api", "openai"), boundProject(web, "web", "openai-web")]) }))
    expect(summary(split)).toEqual([["openai", "workspace", true, false]])
    // The bare name held by another kind: the next name, bound, is reused.
    const next = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", { ...ADOPTED_OPENAI, kind: "generic" }], ["openai-2", ADOPTED_OPENAI]]), storedSlugs: storedFrom({ "openai-2": [api, web] }) }))
    expect(next.items.map((i) => [i.slug, i.include, i.exists, i.compare])).toEqual([["openai-2", true, true, true]])
  })

  // Seen in review: with many projects the list came first and the 300
  // character cap cut off how to reuse the held name.
  it("keeps the whole reuse note and names only the first few projects of a workspace credential many projects use", async () => {
    const names = Array.from({ length: 12 }, (_, i) => `service-${i + 10}`)
    const { home, roots } = repositories(...names)
    for (const root of roots) writeFileSync(join(root, ".env"), OPENAI)
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", ADOPTED_OPENAI]]) }))
    expect(plan.items.map((i) => [i.slug, i.include])).toEqual([["openai", true]])
    expect(plan.items[0]?.note).toBe(`compare with openai in the vault: the reviewer decides which value it keeps; used by 12 projects (${names.slice(0, 3).join(", ")} and 9 more): one workspace credential; every member's machine may use it`)
  })

  // Seen in review: another owner's or admin's machine planned worker and
  // jobs, which share a key of their own, and found Alice's openai. Since
  // adopt reconcile the value goes as a compare row against Alice's, and
  // the reviewer sees whether they differ.
  it("sends a value of its own as a compare row when another admin's adopted item of the same kind holds the bare name", async () => {
    const { home, roots } = repositories("jobs", "worker")
    for (const root of roots) writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-proj-zyxwvutsrqponmlkjihgfedcba\n")
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", ADOPTED_OPENAI]]) }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists, i.compare])).toEqual([["openai", true, false, true]])
    const ref = (plan.items[0] as PlanItem).ref
    expect(plan.repos.map((r) => r.files[0]?.vars.OPENAI_API_KEY)).toEqual([
      { item: ref, field: "key" },
      { item: ref, field: "key" },
    ])
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 1, sharedWorkspace: 1 })
  })

  // Seen in review: this machine stored two groups as openai and openai-2;
  // a new repo of the second group sorted first and took openai, so the
  // plan swapped both groups' keys and apply re-pointed every project.
  it("keeps each of one machine's two groups on the name its projects bind when a new repo reorders them", async () => {
    const { home, roots } = repositories("aaa-new", "api", "jobs", "web", "worker")
    const [fresh, api, jobs, web, worker] = roots as [string, string, string, string, string]
    for (const root of [api, web]) writeFileSync(join(root, ".env"), OPENAI)
    for (const root of [fresh, jobs, worker]) writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-proj-zyxwvutsrqponmlkjihgfedcba\n")
    const existing = new Map([boundProject(api, "api", "openai"), boundProject(web, "web", "openai"), boundProject(jobs, "jobs", "openai-2"), boundProject(worker, "worker", "openai-2")])
    const storedSlugs = storedFrom({ openai: [api, web], "openai-2": [jobs, worker] })
    const visibleItems = new Map([["openai", ADOPTED_OPENAI], ["openai-2", ADOPTED_OPENAI]])
    const slugsOf = (plan: AdoptPlan) => plan.items.map((i) => [i.slug, i.exists, i.fields.key?.from.map((s) => dirname(plan.sources[s]?.path as string))])
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems, storedSlugs, existing }))
    expect(slugsOf(plan)).toEqual([
      ["openai-2", true, [fresh, jobs, worker]],
      ["openai", true, [api, web]],
    ])
    const slugOf = (ref: string) => plan.items.find((i) => i.ref === ref)?.slug
    expect(plan.repos.map((r) => [r.project.slug, slugOf((r.files[0]?.vars.OPENAI_API_KEY as { item: string }).item)])).toEqual([
      ["aaa-new", "openai-2"],
      ["api", "openai"],
      ["jobs", "openai-2"],
      ["web", "openai"],
      ["worker", "openai-2"],
    ])
    // Approved but nothing applied yet: only the batch's sources tell the groups apart.
    expect(slugsOf(buildPlan(await scanCode(home), context(home, { visibleItems, storedSlugs })))).toEqual([
      ["openai-2", true, [fresh, jobs, worker]],
      ["openai", true, [api, web]],
    ])
  })

  // Seen in review: this machine stored and applied api and web's key as
  // openai; a new pair holding another key sorted first, took openai as
  // already stored, and apply bound the pair to api and web's key.
  it("uploads a new group's value under a name of its own when this machine's batch stored the held name from another group's sources", async () => {
    const { home, roots } = repositories("aaa", "api", "bbb", "web")
    const [aaa, api, bbb, web] = roots as [string, string, string, string]
    for (const root of [api, web]) writeFileSync(join(root, ".env"), OPENAI)
    for (const root of [aaa, bbb]) writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-proj-zyxwvutsrqponmlkjihgfedcba\n")
    const existing = new Map([boundProject(api, "api", "openai"), boundProject(web, "web", "openai")])
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems: new Map([["openai", ADOPTED_OPENAI]]), storedSlugs: storedFrom({ openai: [api, web] }), existing }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists, i.fields.key?.from.map((s) => dirname(plan.sources[s]?.path as string))])).toEqual([
      ["openai-2", true, false, [aaa, bbb]],
      ["openai", true, true, [api, web]],
    ])
    // openai is proven the other group's value, so this one is no compare row.
    expect(plan.items.map((i) => i.compare)).toEqual([false, true])
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 2, compares: [{ ref: plan.items[1]?.ref, slug: "openai" }] })
  })

  // Seen on a real machine (3 Nov): 0.3.8 stored a gateway key as
  // openai-northwind and the OpenAI key as openai, binding each variable to
  // its own. 0.3.9's plan named the OpenAI key's item openai-northwind, found
  // the name held and marked it existing, so apply would have moved three
  // variables onto the gateway key, and plan --check passed it clean.
  it("keeps a project's variables on the one held item they are bound to, never on a held item that only has the name the plan computes", async () => {
    const { home, roots } = repositories("northwind")
    const [root] = roots as [string]
    const key = "sk-proj-0123456789abcdefghijklmnop"
    const openaiVars = ["OPENAI_API_KEY", "LITELLM_OPENAI_API_KEY", "org__lqnc85_OPENAI_API_KEY"]
    writeFileSync(join(root, ".env"), `${openaiVars.map((name) => `${name}=${key}\n`).join("")}ALT_GATEWAY_API_KEY=sk-gw-zyxwvutsrqponmlkjihgfedcba\n`)
    const vars = [...openaiVars.map((name) => ({ name, env: "dev", item: "openai" })), { name: "ALT_GATEWAY_API_KEY", env: "dev", item: "openai-northwind" }]
    const existing = new Map<string, ExistingProject>([[root, { id: "prj_northwind01", slug: "northwind", environments: [{ name: "dev", protected: false }], vars }]])
    const visibleItems = new Map([["openai", ADOPTED_OPENAI], ["openai-northwind", ADOPTED_OPENAI]])
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems, existing }))
    const file = plan.repos[0]?.files[0] as AdoptPlan["repos"][number]["files"][number]
    const itemFor = (variable: string) => {
      const m = file.vars[variable] as VarMapping
      return "item" in m ? plan.items.find((i) => i.ref === m.item) : undefined
    }
    expect(openaiVars.map((v) => [v, itemFor(v)?.slug, itemFor(v)?.include, itemFor(v)?.exists])).toEqual(openaiVars.map((v) => [v, "openai", true, true]))
    expect(plan.items.find((i) => i.slug === "openai")?.fields.key?.from.map((s) => plan.sources[s]?.variable)).toEqual(openaiVars)
    expect(itemFor("ALT_GATEWAY_API_KEY")).toMatchObject({ slug: "alt-gateway-api-key-northwind", include: true, exists: false })
    // The gateway key is uploaded and the OpenAI key goes as a compare row
    // against openai, and check passes with the bindings. The gateway key's
    // variable, bound to another item, is one apply leaves as it is.
    const boundVars = new Map([["prj_northwind01", vars]])
    expect(checkPlan(plan, { boundVars })).toMatchObject({ ok: true, included: 2, problems: [], compares: [{ slug: "openai" }], leftAlone: [{ project: "northwind", env: "dev", variable: "ALT_GATEWAY_API_KEY", item: "openai-northwind" }] })
    expect(checkPlan(plan).leftAlone).toEqual([])
    // The plan 0.3.9 wrote: check now refuses each move onto another held item.
    ;(plan.items.find((i) => i.slug === "openai") as PlanItem).slug = "openai-northwind"
    const moved = (variable: string) => `${variable} for dev in project northwind uses openai in the vault; this plan moves it to openai-northwind, another item already there that may hold another value: map it to the item holding its value, or skip it`
    expect(checkPlan(plan, { boundVars }).problems.map((p) => p.problem)).toEqual(openaiVars.map(moved))
    expect(checkPlan(plan).problems).toEqual([])
  })

  // Seen in review: on the same machine, once the batch storing the gateway
  // key under its own name was approved and before apply, the gateway
  // variable was still bound to openai-northwind, so the plan uploaded a
  // second copy as -2 and check refused the name the batch stored.
  it("plans again after approval and before apply onto the name the batch stored from a variable, and still never moves the OpenAI variables onto the gateway key", async () => {
    const { home, roots } = repositories("northwind")
    const [root] = roots as [string]
    const env = join(root, ".env")
    const openaiVars = ["OPENAI_API_KEY", "LITELLM_OPENAI_API_KEY", "org__lqnc85_OPENAI_API_KEY"]
    writeFileSync(env, `${openaiVars.map((name) => `${name}=sk-proj-0123456789abcdefghijklmnop\n`).join("")}ALT_GATEWAY_API_KEY=sk-gw-zyxwvutsrqponmlkjihgfedcba\n`)
    const keyOf = (variable: string) => sourceKey({ path: env, variable, pointer: null })
    // 0.3.8: the gateway key stored and bound as openai-northwind, the OpenAI key as openai.
    const vars = [...openaiVars.map((name) => ({ name, env: "dev", item: "openai" })), { name: "ALT_GATEWAY_API_KEY", env: "dev", item: "openai-northwind" }]
    const existing = new Map<string, ExistingProject>([[root, { id: "prj_northwind01", slug: "northwind", environments: [{ name: "dev", protected: false }], vars }]])
    // Then a batch stored the gateway key as alt-gateway-api-key-northwind, approved, not applied.
    const gateway: VisibleItem = { kind: "generic", provider: null, tags: ["adopted"] }
    const visibleItems = new Map([["openai", ADOPTED_OPENAI], ["openai-northwind", ADOPTED_OPENAI], ["alt-gateway-api-key-northwind", gateway]])
    const storedSlugs = new Map([["openai", new Set(openaiVars.map(keyOf))], ["openai-northwind", new Set([keyOf("ALT_GATEWAY_API_KEY")])], ["alt-gateway-api-key-northwind", new Set([keyOf("ALT_GATEWAY_API_KEY")])]])
    const unappliedSlugs = new Map([["alt-gateway-api-key-northwind", new Set([keyOf("ALT_GATEWAY_API_KEY")])]])
    const plan = buildPlan(await scanCode(home), context(home, { visibleItems, existing, storedSlugs, unappliedSlugs }))
    const file = plan.repos[0]?.files[0] as AdoptPlan["repos"][number]["files"][number]
    const itemFor = (variable: string) => {
      const m = file.vars[variable] as VarMapping
      return "item" in m ? plan.items.find((i) => i.ref === m.item) : undefined
    }
    expect(itemFor("ALT_GATEWAY_API_KEY")).toMatchObject({ slug: "alt-gateway-api-key-northwind", include: true, exists: true, compare: true })
    expect(openaiVars.map((v) => itemFor(v)?.slug)).toEqual(["openai", "openai", "openai"])
    expect(plan.items.map((i) => i.slug).sort()).toEqual(["alt-gateway-api-key-northwind", "openai"])
    const boundVars = new Map([["prj_northwind01", vars]])
    expect(checkPlan(plan, { boundVars, unappliedSlugs })).toMatchObject({ ok: true, included: 2, problems: [] })
    // Without the batch's record the move is refused, as for any held item.
    expect(checkPlan(plan, { boundVars }).problems.map((p) => p.problem)).toEqual(["ALT_GATEWAY_API_KEY for dev in project northwind uses openai-northwind in the vault; this plan moves it to alt-gateway-api-key-northwind, another item already there that may hold another value: map it to the item holding its value, or skip it"])
    // openai-northwind was stored from the gateway variable, never from the
    // OpenAI ones, so the move is refused even were the 0.3.8 batch not yet applied.
    ;(plan.items.find((i) => i.slug === "openai") as PlanItem).slug = "openai-northwind"
    expect(checkPlan(plan, { boundVars, unappliedSlugs: storedSlugs }).problems.map((p) => p.problem)).toEqual(openaiVars.map((variable) => `${variable} for dev in project northwind uses openai in the vault; this plan moves it to openai-northwind, another item already there that may hold another value: map it to the item holding its value, or skip it`))
  })

  // Adopt reconcile: a second machine's value under a name the vault holds
  // became a second copy, openai-api-2, beside the first, and an item
  // proven held was never sent again, so a value rotated since went unseen.
  it("sends a value under a held name of its kind and provider as a compare row, proven or not, and takes the next name only past an item of another kind", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), OPENAI)
    const plan = (overrides: Partial<PlanContext>) => scanCode(home).then((result) => buildPlan(result, context(home, { sharedValues: "per-project", ...overrides })))
    const summary = (p: AdoptPlan) => p.items.map((i) => [i.slug, i.include, i.exists, i.compare, i.note])
    const held = new Map([["openai-api", ADOPTED_OPENAI]])
    const unproven = await plan({ visibleItems: held })
    expect(summary(unproven)).toEqual([["openai-api", true, false, true, "compare with openai-api in the vault: the reviewer decides which value it keeps"]])
    const ref = (unproven.items[0] as PlanItem).ref
    expect(checkPlan(unproven)).toMatchObject({ ok: true, included: 1, compares: [{ ref, slug: "openai-api" }] })
    const proven = await plan({ visibleItems: held, storedSlugs: storedFrom({ "openai-api": [api] }) })
    expect(summary(proven)).toEqual([["openai-api", true, true, true, "compare with openai-api in the vault, which mappings use already"]])
    expect(checkPlan(proven)).toMatchObject({ ok: true, included: 1, compares: [{ ref, slug: "openai-api" }] })
    // Unticked, a proven item is not sent and its mappings still use it.
    ;(proven.items[0] as PlanItem).include = false
    expect(checkPlan(proven)).toMatchObject({ ok: true, included: 0, compares: [] })
    expect(activeRepos(proven)).toHaveLength(1)
    // A held item of another kind or provider is not this value.
    expect(summary(await plan({ visibleItems: visible("openai-api") }))).toEqual([["openai-api-2", true, false, false, null]])
    expect(JSON.stringify(unproven)).not.toContain("0123456789abcdef")
  })

  it("reuses a project item's computed name as proven only with evidence it holds this value, and otherwise compares with it", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), OPENAI)
    const summary = (plan: AdoptPlan) => plan.items.map((i) => [i.slug, i.include, i.exists, i.note])
    const plan = (overrides: Partial<PlanContext>) => scanCode(home).then((result) => buildPlan(result, context(home, { sharedValues: "per-project", ...overrides })))
    const held = new Map([["openai-api", ADOPTED_OPENAI]])
    const reused = [["openai-api", true, true, "compare with openai-api in the vault, which mappings use already"]]
    // No evidence: kind, provider and the adopted tag say nothing of the value.
    expect(summary(await plan({ visibleItems: held }))).toEqual([["openai-api", true, false, "compare with openai-api in the vault: the reviewer decides which value it keeps"]])
    expect(summary(await plan({ visibleItems: visible("openai-api") }))).toEqual([["openai-api-2", true, false, null]])
    // Plan again on this machine once the batch is approved, before apply.
    expect(summary(await plan({ visibleItems: held, storedSlugs: storedFrom({ "openai-api": [api] }) }))).toEqual(reused)
    // Plan again after apply, or a second machine with the same repo: its project binds the variable to the item.
    expect(summary(await plan({ visibleItems: held, existing: new Map([boundProject(api, "api", "openai-api")]) }))).toEqual(reused)
    // Bound to one held item of its kind, whatever its name.
    const openai = await plan({ visibleItems: new Map([["openai", ADOPTED_OPENAI], ["openai-api", ADOPTED_OPENAI]]), existing: new Map([boundProject(api, "api", "openai")]) })
    expect(summary(openai)).toEqual([["openai", true, true, "compare with openai in the vault, which mappings use already"]])
    expect(checkPlan(openai, { boundVars: new Map([["prj_api0001", [{ name: "OPENAI_API_KEY", env: "dev", item: "openai" }]]]) })).toMatchObject({ ok: true, included: 1 })
    // Bound to an item of another kind: no evidence.
    expect(summary(await plan({ visibleItems: new Map([["openai", { ...ADOPTED_OPENAI, kind: "generic" }]]), existing: new Map([boundProject(api, "api", "openai")]) }))).toEqual([["openai-api", true, false, null]])
    // Bound to another item until apply moves it, while this machine's approved batch stored the name from the variable.
    expect(summary(await plan({ visibleItems: held, storedSlugs: storedFrom({ "openai-api": [api] }), unappliedSlugs: storedFrom({ "openai-api": [api] }), existing: new Map([boundProject(api, "api", "openai-other")]) }))).toEqual(reused)
  })

  // Seen in review: a value in .env and .env.production is one item, and
  // apply never sets the prod variable, so a second machine with no batch
  // of its own found a variable unbound and uploaded a second copy.
  it("reuses the item a project binds a value's variables to when the only unbound ones are in environments apply never sets", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), OPENAI)
    writeFileSync(join(api, ".env.production"), OPENAI)
    writeFileSync(join(api, ".env.staging"), OPENAI)
    // Bound only in dev: prod is protected, and the project has no staging.
    const vars = [{ name: "OPENAI_API_KEY", env: "dev", item: "openai-api" }]
    const existing = new Map<string, ExistingProject>([[api, { id: "prj_api0001", slug: "api", environments: [{ name: "dev", protected: false }, { name: "prod", protected: true }], vars }]])
    const plan = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["openai-api", ADOPTED_OPENAI]]), existing }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists])).toEqual([["openai-api", true, true]])
    // No move onto another held item; staging is for a human to add.
    expect(checkPlan(plan, { boundVars: new Map([["prj_api0001", vars]]) }).problems.map((p) => p.problem)).toEqual(["the project has no environment staging"])
    // A staging the project protects is one apply never sets either.
    const protectedStaging = new Map<string, ExistingProject>([[api, { ...(existing.get(api) as ExistingProject), environments: [{ name: "dev", protected: false }, { name: "prod", protected: true }, { name: "staging", protected: true }] }]])
    expect(buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["openai-api", ADOPTED_OPENAI]]), existing: protectedStaging })).items.map((i) => [i.slug, i.include, i.exists])).toEqual([["openai-api", true, true]])
  })

  it("does not take as proven the item a project binds a value's dev variable to when it binds the prod one to another item, and compares with it", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), OPENAI)
    writeFileSync(join(api, ".env.production"), OPENAI)
    const vars = [{ name: "OPENAI_API_KEY", env: "dev", item: "openai-api" }, { name: "OPENAI_API_KEY", env: "prod", item: "openai-prod" }]
    const existing = new Map<string, ExistingProject>([[api, { id: "prj_api0001", slug: "api", environments: [{ name: "dev", protected: false }, { name: "prod", protected: true }], vars }]])
    const plan = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["openai-api", ADOPTED_OPENAI], ["openai-prod", ADOPTED_OPENAI]]), existing }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists, i.compare])).toEqual([["openai-api", true, false, true]])
  })

  // Seen in review: apply skips a live key's dev variable and a human sets
  // prod, so a second machine found dev unbound and uploaded a second copy
  // of the production key.
  it("reuses the item a project binds a live key's prod variable to when its dev variable, which apply never sets, is unbound", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    const live = "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n"
    writeFileSync(join(api, ".env"), live)
    writeFileSync(join(api, ".env.production"), live)
    const vars = [{ name: "STRIPE_SECRET_KEY", env: "prod", item: "stripe-live" }]
    const existing = new Map<string, ExistingProject>([[api, { id: "prj_api0001", slug: "api", environments: [{ name: "dev", protected: false }, { name: "prod", protected: true }], vars }]])
    const plan = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["stripe-live", ADOPTED_STRIPE]]), existing }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists])).toEqual([["stripe-live", true, true]])
    const ref = (plan.items[0] as PlanItem).ref
    expect(plan.repos[0]?.files.map((f) => [f.env, f.vars.STRIPE_SECRET_KEY])).toEqual([["dev", LIVE_KEY_SKIP], ["prod", { item: ref, field: "key" }]])
    expect(checkPlan(plan, { boundVars: new Map([["prj_api0001", vars]]) }).problems).toEqual([])
    // Nothing bound: no evidence.
    const unbound = new Map<string, ExistingProject>([[api, { ...(existing.get(api) as ExistingProject), vars: [] }]])
    expect(buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["stripe-live", ADOPTED_STRIPE]]), existing: unbound })).items.map((i) => [i.slug, i.include, i.exists])).toEqual([["stripe-api", true, false]])
  })

  // Seen in review: the plan took a batch's record from any of a value's
  // variables, while check wants each variable bound elsewhere to have its
  // own, so a twin added to the file after submit and bound to another item
  // was planned onto a name check then refused.
  it("reuses the name a batch not yet applied stored only when it stored it from every one of the value's variables bound to another item", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), `${OPENAI}LITELLM_OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n`)
    const keyOf = (variable: string) => sourceKey({ path: join(api, ".env"), variable, pointer: null })
    const plan = async (vars: ExistingProject["vars"], variables: string[]) => {
      const existing = new Map<string, ExistingProject>([[api, { id: "prj_api0001", slug: "api", environments: [{ name: "dev", protected: false }], vars }]])
      const unappliedSlugs = new Map([["openai-api", new Set(variables.map(keyOf))]])
      const built = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems: new Map([["openai-api", ADOPTED_OPENAI]]), existing, storedSlugs: unappliedSlugs, unappliedSlugs }))
      return { slugs: built.items.map((i) => [i.slug, i.include, i.exists]), problems: checkPlan(built, { boundVars: new Map([["prj_api0001", vars]]), unappliedSlugs }).problems }
    }
    const old = { name: "OPENAI_API_KEY", env: "dev", item: "openai-old" }
    const twin = { name: "LITELLM_OPENAI_API_KEY", env: "dev", item: "openai-other" }
    expect(await plan([old, twin], ["OPENAI_API_KEY"])).toEqual({ slugs: [["openai-api", true, false]], problems: [] })
    expect(await plan([old, twin], ["OPENAI_API_KEY", "LITELLM_OPENAI_API_KEY"])).toEqual({ slugs: [["openai-api", true, true]], problems: [] })
    // The twin bound nowhere: check has no binding to keep.
    expect(await plan([old], ["OPENAI_API_KEY"])).toEqual({ slugs: [["openai-api", true, true]], problems: [] })
  })

  // Seen in review: once the batch was applied, a human who moved the
  // variable to an item made by hand, as when rotating the key, had a plan
  // again move it back onto the item the batch stored, which may hold the
  // old key, and check passed it.
  it("compares a variable a human bound to another item after apply with the item the applied batch stored, never as proven, and check passes the plan clean", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), OPENAI)
    const visibleItems = new Map([["openai-api", ADOPTED_OPENAI], ["openai-rotated", { ...ADOPTED_OPENAI, tags: [] }]])
    const existing = new Map([boundProject(api, "api", "openai-rotated")])
    const plan = buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems, existing, storedSlugs: storedFrom({ "openai-api": [api] }) }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists, i.note])).toEqual([["openai-api", true, false, "compare with openai-api in the vault: the reviewer decides which value it keeps"]])
    const boundVars = new Map([["prj_api0001", [{ name: "OPENAI_API_KEY", env: "dev", item: "openai-rotated" }]]])
    expect(checkPlan(plan, { boundVars, unappliedSlugs: new Map() })).toMatchObject({ ok: true, included: 1, problems: [] })
    // The plan round 2 wrote: check refuses the move once the batch is applied.
    Object.assign(plan.items[0] as PlanItem, { slug: "openai-api", include: false, exists: true })
    expect(checkPlan(plan, { boundVars, unappliedSlugs: new Map() }).problems.map((p) => p.problem)).toEqual(["OPENAI_API_KEY for dev in project api uses openai-rotated in the vault; this plan moves it to openai-api, another item already there that may hold another value: map it to the item holding its value, or skip it"])
  })

  it("reuses the item a project binds a value's variables to only when it binds every one of them to one adopted item", async () => {
    const { home, roots } = repositories("api")
    const [api] = roots as [string]
    writeFileSync(join(api, ".env"), `${OPENAI}LITELLM_OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n`)
    const slugs = async (vars: ExistingProject["vars"], visibleItems: Map<string, VisibleItem>) => {
      const existing = new Map<string, ExistingProject>([[api, { id: "prj_api0001", slug: "api", environments: [{ name: "dev", protected: false }], vars }]])
      return buildPlan(await scanCode(home), context(home, { sharedValues: "per-project", visibleItems, existing })).items.map((i) => [i.slug, i.include, i.exists])
    }
    const both = (item: string, other: string) => [{ name: "OPENAI_API_KEY", env: "dev", item }, { name: "LITELLM_OPENAI_API_KEY", env: "dev", item: other }]
    const held = new Map([["openai", ADOPTED_OPENAI], ["openai-other", ADOPTED_OPENAI]])
    expect(await slugs(both("openai", "openai"), held)).toEqual([["openai", true, true]])
    // Only some of the variables bound.
    expect(await slugs([{ name: "OPENAI_API_KEY", env: "dev", item: "openai" }], held)).toEqual([["openai-api", true, false]])
    // The variables bound to two different items in the project.
    expect(await slugs(both("openai", "openai-other"), held)).toEqual([["openai-api", true, false]])
    // The bound item not tagged adopted, as one a human made by hand.
    expect(await slugs(both("openai", "openai"), new Map([["openai", { ...ADOPTED_OPENAI, tags: ["billing"] }]]))).toEqual([["openai-api", true, false]])
    // The computed name takes the same evidence: only some of the variables bound to it is none.
    const computed = new Map([["openai-api", ADOPTED_OPENAI]])
    expect(await slugs(both("openai-api", "openai-api"), computed)).toEqual([["openai-api", true, true]])
    expect(await slugs([{ name: "OPENAI_API_KEY", env: "dev", item: "openai-api" }], computed)).toEqual([["openai-api", true, false]])
  })

  // Seen in review: a member's plan built the owner's plan only to count
  // what it kept apart, and failed when that plan broke the schema.
  it("counts the values an owner's machine would share, and none when that plan would break the schema", async () => {
    const { home, roots } = repositories("api", "web")
    for (const root of roots) writeFileSync(join(root, ".env"), OPENAI)
    const result = await scanCode(home)
    expect(sharedIfAllowed(result, context(home, { sharedValues: "per-project" }))).toBe(1)
    // Each project's copies fit one item; together they are more than a field takes.
    const half = MAX_FIELD_SOURCES / 2 + 1
    const id = (n: number) => `s${n.toString(2).padStart(12, "a").replaceAll("0", "a").replaceAll("1", "b")}`
    const entries = result.entries.flatMap((entry, k) => Array.from({ length: half }, (_, n) => ({ ...entry, id: id(k * half + n), path: join(entry.repo?.root as string, `svc-${n}`, ".env") })))
    const many = { ...result, entries }
    const perProject = buildPlan(many, context(home, { sharedValues: "per-project" }))
    expect(perProject.items.map((i) => i.fields.key?.from.length)).toEqual([half, half])
    expect(sharedIfAllowed(many, context(home, { sharedValues: "per-project" }))).toBe(0)
  })

  it("keeps one item per project when the copies would differ in kind or provider", async () => {
    const { home, roots } = repositories("api", "ci", "web")
    const [api, ci, web] = roots as [string, string, string]
    const value = "sk_test_0123456789abcdefghijkl"
    writeFileSync(join(api, ".env"), `STRIPE_SECRET_KEY=${value}\n`)
    writeFileSync(join(ci, ".env"), `GITHUB_TOKEN=${value}\n`)
    writeFileSync(join(web, ".env"), `STRIPE_SECRET_KEY=${value}\n`)
    const result = await scanCode(home)
    expect(new Set(result.entries.map((e) => e.dup)).size).toBe(1)
    const plan = buildPlan(result, context(home))
    expect(plan.items.map((i) => [i.slug, i.kind, i.provider, i.home.kind, i.note])).toEqual([
      ["stripe-api", "api-key", "stripe", "project", null],
      ["github-pat-ci", "api-key", "github-pat", "project", null],
      ["stripe-web", "api-key", "stripe", "project", null],
    ])
    expect(checkPlan(plan)).toMatchObject({ ok: true, sharedWorkspace: 0 })
  })

  // Seen on a real machine: app, app-2 ... app-6 for one
  // remote, which submit could not create, and every worktree's .env its own items.
  it("gives every worktree and clone of one repository one project, and one item per distinct value", async () => {
    const { home, roots } = checkouts()
    const [main, a, b, clone] = roots as [string, string, string, string]
    const openai = "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n"
    const session = "SESSION_SECRET=s3cr3t-s3cr3t-value-1234\n"
    writeFileSync(join(main, ".env"), `${openai}${session}`)
    writeFileSync(join(a, ".env"), `${openai}${session}`)
    writeFileSync(join(b, ".env.staging"), openai)
    writeFileSync(join(clone, ".env"), `${openai}STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n`)
    const plan = buildPlan(await scanCode(home), context(home))
    expect(plan.repos.map((r) => [r.root, r.project])).toEqual(roots.sort().map((root) => [root, { slug: "app", id: null, create: true, environments: ["dev", "staging"] }]))
    expect(plan.items.map((i) => [i.slug, i.home, Object.values(i.fields)[0]?.from.length])).toEqual([
      ["openai-app", { kind: "project", project: "app" }, 4],
      ["session-secret-app", { kind: "project", project: "app" }, 2],
      ["stripe-app", { kind: "project", project: "app" }, 1],
    ])
    expect(activeRepos(plan)).toHaveLength(4)
    expect(checkPlan(plan).problems).toEqual([])
    const existing = { id: "prj_app00001", slug: "app", environments: [{ name: "dev", protected: false }, { name: "staging", protected: false }], vars: [] }
    const named = buildPlan(await scanCode(home), context(home, { existing: new Map([[a, existing]]) }))
    expect(new Set(named.repos.map((r) => JSON.stringify(r.project)))).toEqual(new Set([JSON.stringify({ slug: "app", id: "prj_app00001", create: false, environments: ["dev", "staging"] })]))
  })

  // Seen on a real machine: one value in 48 files, and `plan --check`
  // refused the plan `plan` wrote: "Too big: expected array to have <=32 items".
  it("writes a value found in 48 files as one item its own check accepts, and refuses to build a plan the schema refuses", async () => {
    const { home, main } = checkouts()
    for (let n = 0; n < 48; n++) {
      mkdirSync(join(main, `svc-${n}`))
      writeFileSync(join(main, `svc-${n}`, ".env"), "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n")
    }
    const result = await scanCode(home)
    const plan = buildPlan(result, context(home))
    expect(plan.items.map((i) => [i.slug, i.fields.key?.from.length])).toEqual([["openai-app", 48]])
    expect(AdoptPlanSchema.safeParse(JSON.parse(JSON.stringify(plan))).success).toBe(true)
    expect(checkPlan(plan).problems).toEqual([])
    const entry = result.entries[0] as ScanResult["entries"][number]
    const many = { ...result, entries: Array.from({ length: MAX_FIELD_SOURCES + 1 }, (_, n) => ({ ...entry, id: `s${n.toString(2).padStart(12, "a").replaceAll("0", "a").replaceAll("1", "b")}`, path: join(main, `svc-${n}`, ".env") })) }
    expect(() => buildPlan(many, context(home))).toThrow("mehen adopt plan built a plan that mehen adopt plan --check would refuse (items.0.fields.key.from: ")
  })

  it("advises skipping the folder with the most copies only when a field has too many sources, and otherwise names what the plan breaks", async () => {
    const { home, main } = checkouts()
    writeFileSync(join(main, ".env"), "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n")
    const result = await scanCode(home)
    const entry = result.entries[0] as ScanResult["entries"][number]
    const refusal = (scan: ScanResult) => {
      try {
        buildPlan(scan, context(home))
      } catch (error) {
        return error as CliError
      }
      throw new Error("buildPlan built a plan the schema refuses")
    }
    const many = { ...result, entries: Array.from({ length: MAX_FIELD_SOURCES + 1 }, (_, n) => ({ ...entry, dup: "d1", id: `s${n.toString(2).padStart(12, "a").replaceAll("0", "a").replaceAll("1", "b")}`, path: join(main, `svc-${n}`, ".env") })) }
    expect(refusal(many).next).toEqual({ command: "mehen adopt plan --home <folder>=skip", say: "Tell the human which folder holds the most copies; skip it with --home, or move copies aside, and plan again." })
    const long = { ...result, entries: [{ ...entry, path: join(main, "a".repeat(1100), ".env") }] }
    const plain = refusal(long)
    expect(plain.message).toStartWith(`mehen adopt plan built a plan that mehen adopt plan --check would refuse (sources.${entry.id}.path: `)
    expect(plain.next?.command).toBeUndefined()
    expect(plain.next?.say).toStartWith(`Tell the human the plan breaks a rule at sources.${entry.id}.path (`)
    expect(plain.next?.say).not.toContain("most copies")
  })

  // Adopt reconcile: a second machine's fresh clone has no mehen.toml, so its
  // plan created a second project for a repo that already was one.
  it("finds each repo's project by the remote the vault binds to it before its mehen.toml, once per remote", async () => {
    const home = realpathSync(tempDir("mehen-adopt-plan-"))
    dirs.push(home)
    const [clone, worktree, named, alone] = ["clone", "worktree", "named", "alone"].map((name) => {
      const root = join(home, "code", name)
      mkdirSync(root, { recursive: true })
      return root
    }) as [string, string, string, string]
    writeFileSync(join(named, "mehen.toml"), 'project = "prj_named0001"\n')
    writeFileSync(join(worktree, "mehen.toml"), 'project = "prj_named0001"\n')
    const project = (id: string, slug: string) => ({ id, slug, remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }, { name: "prod", protected: true, fences: [] }], vars: [{ name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-api", field: "key" }] })
    const binding = { id: "prj_billing01", slug: "billing-api", defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: ["OPENAI_API_KEY"] }] }
    const lookup = (remote: string) => `/v1/projects?remote=${encodeURIComponent(remote)}`
    const api = new FakeVaultApi()
      .on("GET", "/v1/me", () => ({ tenant: "tn_test00000001", device: "dev_test", name: "test-mac", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] }, frozen: false, ownerRole: "admin" }))
      .on("GET", "/v1/items", () => ({ items: [] }))
      .on("GET", lookup("github.com/acme/billing-api"), () => binding)
      .on("GET", lookup("github.com/acme/other"), () => {
        throw new VaultApiError(404, { error: "not_found", message: "No project is bound to that remote." })
      })
      .on("GET", "/v1/projects/prj_billing01", () => project("prj_billing01", "billing-api"))
      .on("GET", "/v1/projects/prj_named0001", () => project("prj_named0001", "named"))
    const facts = await vaultFacts(api, [{ root: clone, remote: "github.com/acme/billing-api" }, { root: worktree, remote: "github.com/acme/billing-api" }, { root: named, remote: "github.com/acme/other" }, { root: alone, remote: null }], [], { ownerIsMember: true })
    // The remote outweighs a mehen.toml naming another project; no remote, or none bound, falls back to it.
    expect([...facts.existing].map(([root, p]) => [root, p.slug])).toEqual([[clone, "billing-api"], [worktree, "billing-api"], [named, "named"]])
    expect(facts.existing.get(clone)?.vars).toEqual([{ name: "OPENAI_API_KEY", env: "dev", item: "openai-api" }])
    expect([...(facts.protectedEnvs.get("prj_billing01") ?? [])]).toEqual(["prod"])
    expect(api.calls.filter((c) => c.path.startsWith("/v1/projects?")).map((c) => c.path)).toEqual([lookup("github.com/acme/billing-api"), lookup("github.com/acme/other")])
  })

  // Seen in review: a repo whose remote the vault binds to one project and
  // whose committed mehen.toml names another landed in the remote's
  // project, and apply then refused its mehen.toml.
  it("leaves every variable of a repo whose mehen.toml names another project than its remote's alone, uploads its items, and plan --check says why from the plan alone", async () => {
    const { home, roots } = repositories("billing-api", "search-api", "tools")
    const [billing, search, tools] = roots as [string, string, string]
    for (const root of roots) writeFileSync(join(root, ".env"), `${OPENAI}LOG_LEVEL=debug\n`)
    writeFileSync(join(billing, "mehen.toml"), 'project = "prj_named0001"\n')
    writeFileSync(join(search, "mehen.toml"), 'project = "prj_gone00001"\n')
    writeFileSync(join(tools, "mehen.toml"), 'project = "tools"\n')
    const project = (id: string, slug: string) => ({ id, slug, remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }], vars: [] })
    const binding = (id: string, slug: string) => ({ id, slug, defaultEnv: "dev", environments: [{ name: "dev", protected: false, variables: [] }] })
    const lookup = (remote: string) => `/v1/projects?remote=${encodeURIComponent(remote)}`
    const api = new FakeVaultApi()
      .on("GET", "/v1/me", () => ({ tenant: "tn_test00000001", device: "dev_test", name: "test-mac", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] }, frozen: false, ownerRole: "admin" }))
      .on("GET", "/v1/items", () => ({ items: [] }))
      .on("GET", lookup("github.com/acme/billing-api"), () => binding("prj_billing01", "billing-api"))
      .on("GET", lookup("github.com/acme/search-api"), () => binding("prj_search001", "search-api"))
      .on("GET", lookup("github.com/acme/tools"), () => binding("prj_tools0001", "tools"))
      .on("GET", "/v1/projects/prj_billing01", () => project("prj_billing01", "billing-api"))
      .on("GET", "/v1/projects/prj_search001", () => project("prj_search001", "search-api"))
      .on("GET", "/v1/projects/prj_tools0001", () => project("prj_tools0001", "tools"))
      .on("GET", "/v1/projects/prj_named0001", () => project("prj_named0001", "named"))
      .on("GET", "/v1/projects/prj_gone00001", () => {
        throw new VaultApiError(404, { error: "not_found", message: "No such project." })
      })
    const result = await scanCode(home)
    const facts = await vaultFacts(api, roots.map((root) => ({ root, remote: `github.com/acme/${root.split("/").pop()}` })), [], { ownerIsMember: true })
    // A mehen.toml naming the remote's project by its slug agrees with it.
    const mismatches = [{ root: billing, manifest: "named", bound: "billing-api" }, { root: search, manifest: null, bound: "search-api" }]
    expect([...facts.projectMismatch.values()]).toEqual(mismatches)
    const plan = buildPlan(result, context(home, { existing: facts.existing, projectMismatch: facts.projectMismatch, sharedValues: "per-project" }))
    const varsOf = (root: string) => plan.repos.find((r) => r.root === root)?.files.map((f) => f.vars)
    expect(varsOf(billing)).toEqual([{ OPENAI_API_KEY: { skip: "mehen.toml names project named; the vault binds this repo's remote to project billing-api" }, LOG_LEVEL: { skip: "mehen.toml names project named; the vault binds this repo's remote to project billing-api" } }])
    expect(varsOf(search)).toEqual([{ OPENAI_API_KEY: { skip: "mehen.toml names another project; the vault binds this repo's remote to project search-api" }, LOG_LEVEL: { skip: "mehen.toml names another project; the vault binds this repo's remote to project search-api" } }])
    // Apply never reaches those repos' mehen.toml; their items still upload.
    expect(activeRepos(plan).map((r) => r.root)).toEqual([tools])
    expect(plan.items.map((i) => [i.slug, i.include])).toEqual([["openai-billing-api", true], ["openai-search-api", true], ["openai-tools", true]])
    // plan passes the facts; plan --check reads the same from the plan's skips.
    expect(checkPlan(plan, { projectMismatch: [...facts.projectMismatch.values()] })).toMatchObject({ ok: true, included: 3, projectMismatch: mismatches })
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 3, projectMismatch: mismatches })
  })

  it("skips a folder, and leaves an existing slug to the vault", async () => {
    const { home, repo, result } = await fixture()
    const homes = new Map<string, FolderHome>([[join(home, ".local-secrets"), { home: "skip", project: null }]])
    const plan = buildPlan(result, context(home, { homes, ...storedItem("openai-billing-api", ADOPTED_OPENAI, join(repo, ".env"), "OPENAI_API_KEY") }))
    expect(plan.items.some((i) => i.folder.endsWith(".local-secrets"))).toBe(false)
    expect(plan.items.find((i) => i.slug === "openai-billing-api")).toMatchObject({ include: true, exists: true, compare: true })
  })

  // Before: a repo with only stale names still got a project, so submit
  // created an empty project and apply wrote a mehen.toml into the clone.
  it("brings no repo whose every credential is stale or unticked, or that has only plain config", async () => {
    const { home, result } = await fixture()
    const clone = join(home, "code", "someone-elses-tool")
    mkdirSync(join(clone, "tests"), { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: clone })
    writeFileSync(join(clone, "tests", ".env"), "SAMPLE_API_KEY=sample-0123456789abcdefghij\nHELLO=world\n")
    // Plain config alone gives Mehen nothing to deliver either.
    const configOnly = join(home, "code", "config-only")
    mkdirSync(configOnly, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: configOnly })
    writeFileSync(join(configOnly, ".env"), "LOG_LEVEL=debug\nNODE_ENV=development\n")
    const rescanned = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    expect(rescanned.entries.some((e) => e.path.startsWith(clone))).toBe(true)
    const plan = buildPlan(rescanned, context(home))
    expect(plan.items.find((i) => i.folder === clone)?.include).toBe(false)
    expect(plan.repos.map((r) => r.root)).toContain(configOnly)
    expect(activeRepos(plan).map((r) => r.root)).toEqual([join(home, "code", "billing-api")])
    // Ticked again by hand, its repo is back.
    for (const item of plan.items) if (item.folder === clone) item.include = true
    expect(activeRepos(plan).map((r) => r.root)).toEqual([join(home, "code", "billing-api"), clone])
    expect(result.entries.length).toBeGreaterThan(0)
  })

  it("check refuses a private credential behind a variable and a device that may not create projects", async () => {
    const { home, result } = await fixture()
    const plan: AdoptPlan = buildPlan(result, context(home))
    const openai = plan.items.find((i) => i.slug === "openai-billing-api")
    if (!openai) throw new Error("no item")
    openai.home = { kind: "private" }
    const check = checkPlan(plan, { canCreateProjects: false })
    expect(check.ok).toBe(false)
    expect(check.problems.map((p) => p.problem)).toEqual([
      "OPENAI_API_KEY maps to openai-billing-api, a private credential, which cannot back a project variable; give it a project or workspace home",
      "this machine may not create projects (billing-api); a human creates them, then put each id in the plan with create: false",
    ])
  })

  // Seen on a real machine: one Google OAuth client in six checkouts was six items.
  it("merges a credential of several parts repeated in two checkouts into one item, and keeps a partial match apart", async () => {
    const { home, roots } = checkouts()
    const [main, a, , clone] = roots as [string, string, string, string]
    const id = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
    writeFileSync(join(main, ".env"), `${id}AWS_SECRET_ACCESS_KEY=abcdEFGH1234ijklMNOP5678qrstUVWX90yzABCD\n`)
    writeFileSync(join(a, ".env"), `${id}AWS_SECRET_ACCESS_KEY=abcdEFGH1234ijklMNOP5678qrstUVWX90yzABCD\n`)
    // In another folder, so the newer file supersedes nothing.
    mkdirSync(join(clone, "deploy"))
    writeFileSync(join(clone, "deploy", ".env"), `${id}AWS_SECRET_ACCESS_KEY=zyxwVUTS9876rqpoNMLK5432jihgFEDC10baZYXW\n`)
    const result = await scanCode(home)
    const ids = result.entries.filter((e) => e.variable === "AWS_ACCESS_KEY_ID")
    expect(ids.map((e) => [e.class, e.field])).toEqual([["secret", "access_key_id"], ["secret", "access_key_id"], ["secret", "access_key_id"]])
    expect(new Set(ids.map((e) => e.dup)).size).toBe(1)
    expect(ids[0]?.dup).not.toBeNull()
    const plan = buildPlan(result, context(home))
    const source = (ref: string | { from: string } | undefined) => (typeof ref === "object" ? plan.sources[ref.from]?.path : ref)
    expect(plan.items.map((i) => [i.slug, i.kind, i.fields.secret_access_key?.from.map((s) => plan.sources[s]?.path), source(i.publicFields.access_key_id), i.note])).toEqual([
      ["aws-app", "cloud-access-key", [join(main, ".env"), join(a, ".env")], join(a, ".env"), "same value in 2 files"],
      ["aws-app-2", "cloud-access-key", [join(clone, "deploy", ".env")], join(clone, "deploy", ".env"), null],
    ])
    expect(checkPlan(plan).problems).toEqual([])
  })

  // Seen on a real machine: CLICKHOUSE_PASSWORD for dev came from the root
  // .env and from tooling/scripts/clickhouse/.env, and apply's last PUT won.
  it("maps a variable files disagree on from the file nearest the root, and still adopts the other value", async () => {
    const { home, main } = checkouts()
    mkdirSync(join(main, "tooling", "scripts", "clickhouse"), { recursive: true })
    writeFileSync(join(main, ".env"), "CLICKHOUSE_PASSWORD=chRoot-0123456789abcdefXYZ\n")
    writeFileSync(join(main, "tooling", "scripts", "clickhouse", ".env"), "CLICKHOUSE_PASSWORD=chTool-0123456789abcdefXYZ\n")
    const plan = buildPlan(await scanCode(home), context(home))
    const vars = (path: string) => plan.repos[0]?.files.find((f) => f.path === path)?.vars.CLICKHOUSE_PASSWORD
    expect(plan.items.map((i) => [i.slug, i.include, plan.sources[i.fields.value?.from[0] as string]?.path])).toEqual([
      ["clickhouse-password-app", true, join(main, ".env")],
      ["clickhouse-password-app-2", true, join(main, "tooling", "scripts", "clickhouse", ".env")],
    ])
    expect(vars(".env")).toEqual({ item: plan.items[0]?.ref as string, field: "value" })
    expect(vars("tooling/scripts/clickhouse/.env")).toEqual({ skip: "another file sets CLICKHOUSE_PASSWORD for dev (.env); the vault holds one value per environment" })
    expect(checkPlan(plan).problems).toEqual([])
  })

  it("maps a variable files disagree on from a fresh source over a stale one, an override file over its base, the main checkout over a worktree", async () => {
    const { home, roots } = checkouts()
    const [main, a, b] = roots as [string, string, string, string]
    const { utimesSync } = await import("node:fs")
    const yesterday = new Date(Date.now() - 86_400_000)
    // The main checkout's key is older, so the worktree's newer one supersedes it.
    writeFileSync(join(main, ".env"), "OPENAI_API_KEY=sk-proj-main0123456789abcdefghijklm\n")
    utimesSync(join(main, ".env"), yesterday, yesterday)
    writeFileSync(join(a, ".env"), "OPENAI_API_KEY=sk-proj-wtree0123456789abcdefghijkl\n")
    // .env.local overrides .env whatever the file times say.
    writeFileSync(join(b, ".env.local"), "SESSION_SECRET=s3cr3t-local-value-123456\n")
    utimesSync(join(b, ".env.local"), yesterday, yesterday)
    writeFileSync(join(b, ".env"), "SESSION_SECRET=s3cr3t-base-value-1234567\n")
    // Both fresh and as deep: the shorter root wins.
    writeFileSync(join(main, ".envrc"), "export DATABASE_PASSWORD=dbMain-0123456789abcdefXYZ\n")
    writeFileSync(join(a, ".envrc"), "export DATABASE_PASSWORD=dbWtree-0123456789abcdefXY\n")
    for (const root of [main, a]) utimesSync(join(root, ".envrc"), yesterday, yesterday)
    const plan = buildPlan(await scanCode(home), context(home))
    const mapped = (root: string, path: string, variable: string) => {
      const m = plan.repos.find((r) => r.root === root)?.files.find((f) => f.path === path)?.vars[variable]
      return m && "item" in m ? plan.sources[plan.items.find((i) => i.ref === m.item)?.fields[m.field]?.from[0] as string]?.path : m
    }
    expect(mapped(a, ".env", "OPENAI_API_KEY")).toBe(join(a, ".env"))
    expect(mapped(main, ".env", "OPENAI_API_KEY")).toEqual({ skip: `another file sets OPENAI_API_KEY for dev (${join(a, ".env")}); the vault holds one value per environment` })
    expect(mapped(b, ".env.local", "SESSION_SECRET")).toBe(join(b, ".env.local"))
    expect(mapped(b, ".env", "SESSION_SECRET")).toEqual({ skip: "another file sets SESSION_SECRET for dev (.env.local); the vault holds one value per environment" })
    expect(mapped(main, ".envrc", "DATABASE_PASSWORD")).toBe(join(main, ".envrc"))
    expect(mapped(a, ".envrc", "DATABASE_PASSWORD")).toEqual({ skip: `another file sets DATABASE_PASSWORD for dev (${join(main, ".envrc")}); the vault holds one value per environment` })
    expect(checkPlan(plan).problems).toEqual([])
  })

  it("maps a variable two services disagree on from the first unit, and still adopts the other value", async () => {
    const home = realpathSync(tempDir("mehen-adopt-plan-"))
    dirs.push(home)
    const config = join(home, ".config")
    mkdirSync(join(config, "systemd", "user"), { recursive: true })
    for (const name of ["alpha", "beta"]) {
      mkdirSync(join(config, name))
      writeFileSync(join(config, name, "svc.env"), `API_TOKEN=${name}-token-0123456789abcdefghij\n`)
      writeFileSync(join(config, "systemd", "user", `${name}.service`), `[Service]\nEnvironmentFile=%h/.config/${name}/svc.env\nExecStart=/usr/bin/${name}\n`)
    }
    const result = await scan({ home, machine: "test-mac", roots: [{ path: config, depth: 4 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard(), platform: "linux" })
    const plan = buildPlan(result, context(home))
    expect(plan.items.map((i) => [i.slug, i.include])).toEqual([["api-token-test-mac-services", true], ["api-token-test-mac-services-2", true]])
    expect(plan.services.map((s) => [s.unit.slice(home.length), s.vars.API_TOKEN])).toEqual([
      ["/.config/systemd/user/alpha.service", { item: plan.items[0]?.ref as string, field: "value" }],
      ["/.config/systemd/user/beta.service", { skip: `another unit sets API_TOKEN for local (${join(config, "systemd", "user", "alpha.service")}); the vault holds one value per environment` }],
    ])
    expect(checkPlan(plan).problems).toEqual([])
    const beta = plan.services[1] as AdoptPlan["services"][number]
    beta.vars.API_TOKEN = { item: plan.items[1]?.ref as string, field: "value" }
    expect(checkPlan(plan).problems.map((p) => p.problem)).toEqual([`API_TOKEN for local in project test-mac-services is set by ${plan.services[0]?.unit} and by ${beta.unit} to different values; the vault holds one value per environment, so skip one`])
  })

  it("check refuses a variable of one project and environment mapped from two files to different values", async () => {
    const { home, main } = checkouts()
    mkdirSync(join(main, "tools"))
    writeFileSync(join(main, ".env"), "CLICKHOUSE_PASSWORD=chRoot-0123456789abcdefXYZ\n")
    writeFileSync(join(main, "tools", ".env"), "CLICKHOUSE_PASSWORD=chTool-0123456789abcdefXYZ\n")
    const plan = buildPlan(await scanCode(home), context(home))
    const tools = plan.repos[0]?.files.find((f) => f.path === "tools/.env")
    if (!tools) throw new Error("no file")
    tools.vars.CLICKHOUSE_PASSWORD = { item: plan.items[1]?.ref as string, field: "value" }
    expect(checkPlan(plan).problems.map((p) => p.problem)).toEqual([`CLICKHOUSE_PASSWORD for dev in project app is set by ${join(main, ".env")} and by ${join(main, "tools", ".env")} to different values; the vault holds one value per environment, so skip one`])
  })

  it("check refuses checkouts of one project that disagree on its id or create", async () => {
    const { home, roots } = checkouts()
    for (const root of roots) writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n")
    const plan: AdoptPlan = JSON.parse(JSON.stringify(buildPlan(await scanCode(home), context(home))))
    expect(checkPlan(plan).problems).toEqual([])
    const edited = plan.repos[1] as AdoptPlan["repos"][number]
    edited.project = { ...edited.project, id: "prj_app00001", create: false }
    expect(checkPlan(plan).problems.map((p) => p.problem)).toEqual(["the repos or services naming project app disagree on its id or create; give each the same id and create"])
  })

  it("check refuses fields the kind does not have and sources the scan did not group", async () => {
    const { home, result } = await fixture()
    const plan = buildPlan(result, context(home))
    const item = plan.items.find((i) => i.slug === "session-secret-billing-api")
    const other = plan.items.find((i) => i.slug === "openai-billing-api")
    if (!item || !other) throw new Error("no item")
    item.fields = { value: { from: [...(item.fields.value?.from ?? []), ...(other.fields.key?.from ?? [])] }, nope: { from: item.fields.value?.from ?? [] } }
    expect(checkPlan(plan).problems.map((p) => p.problem)).toEqual(["nope is not a secret field of generic", "value takes several sources that the scan did not find equal"])
  })

  it("check refuses a kind the relay injects with no hosts, as the vault does, and keeps the rest lease-only", async () => {
    const { home, result } = await fixture()
    const plan = buildPlan(result, context(home))
    const item = plan.items.find((i) => i.slug === "session-secret-billing-api")
    if (!item) throw new Error("no item")
    const from = item.fields.value?.from ?? []
    expect(checkPlan(plan).problems).toEqual([])
    const refusals = (kind: PlanItem["kind"], field: string, binding: PlanItem["binding"]) => {
      Object.assign(item, { kind, binding, fields: { [field]: { from } } })
      return checkPlan(plan).problems.filter((p) => p.where === null).map((p) => p.problem)
    }
    expect(refusals("oauth-connection", "access_token", null)).toEqual([leaseOnlyRefusal("oauth-connection")])
    expect(refusals("api-key", "key", leaseOnlyBinding())).toEqual(["An api-key credential is sent to a service: name the hosts it may go to with --host."])
    expect(refusals("api-key", "key", { hosts: ["api.example.com"] })).toEqual([])
    expect(refusals("hmac-key", "key", null)).toEqual([])
    expect(refusals("database-url", "url", null)).toEqual([])
  })

  it("check refuses a proposed injection on a kind the relay never puts into a request, as the vault does", async () => {
    const { home, result } = await fixture()
    const plan = buildPlan(result, context(home))
    const item = plan.items.find((i) => i.slug === "session-secret-billing-api")
    if (!item) throw new Error("no item")
    const from = item.fields.value?.from ?? []
    const refusals = (kind: PlanItem["kind"], injection: PlanItem["injection"]) => {
      Object.assign(item, { kind, binding: { hosts: ["api.example.com"] }, injection, fields: { key: { from } } })
      return checkPlan(plan).problems.filter((p) => p.where === null).map((p) => p.problem)
    }
    const injection = { in: "header" as const, name: "X-Api-Key", format: "{key}" }
    expect(refusals("hmac-key", injection)).toEqual(["The relay never puts a Signing secret (HMAC) into a request, so it takes no injection. Leave it out."])
    expect(refusals("hmac-key", null)).toEqual([])
    expect(refusals("api-key", injection)).toEqual([])
  })

  it("keeps another environment's and another repo's own key ticked, and a possibly stale one easy to re-tick", async () => {
    const { home, repo } = await fixture()
    writeFileSync(join(repo, ".env.production"), "OPENAI_API_KEY=sk-proj-prod0123456789abcdefghijklmn\n")
    const other = join(home, "code", "search-api")
    mkdirSync(other)
    Bun.spawnSync(["git", "init", "-q"], { cwd: other })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/search-api"], { cwd: other })
    writeFileSync(join(other, ".env"), "OPENAI_API_KEY=sk-proj-search0123456789abcdefghijk\n")
    writeFileSync(join(home, ".local-secrets", "openai-old.env"), "OPENAI_API_KEY=sk-proj-older0123456789abcdefghijkl\n")
    const { utimesSync } = await import("node:fs")
    const yesterday = new Date(Date.now() - 86_400_000)
    utimesSync(join(home, ".local-secrets", "openai-old.env"), yesterday, yesterday)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, context(home))
    const openai = plan.items.filter((i) => i.provider === "openai").map((i) => [i.slug, i.include])
    expect(openai).toEqual([
      ["openai-local-secrets", false],
      ["openai-local-secrets-2", true],
      ["openai-billing-api", true],
      ["openai-billing-api-prod", true],
      ["openai-search-api", true],
    ])
    const old = plan.items.find((i) => i.slug === "openai-local-secrets")
    expect(old?.note).toBe("possibly stale (superseded by a newer file): check before revoking at the provider; set include to true to adopt it")
    expect(plan.possiblyStale).toEqual([{ source: old?.fields.key?.from[0] as string, why: "superseded by a newer file" }])
    expect(plan.sources[old?.fields.key?.from[0] as string]?.path).toBe(join(home, ".local-secrets", "openai-old.env"))
  })

  it("keeps a value ticked when a stale copy of it sits beside a fresh one", async () => {
    const { home } = await fixture()
    const key = "sk-proj-0123456789abcdefghijklmnop"
    writeFileSync(join(home, ".local-secrets", "openai.env.bak-20261027"), `OPENAI_API_KEY=${key}\n`)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, context(home))
    const openai = plan.items.filter((i) => i.provider === "openai")
    expect(openai.map((i) => [i.slug, i.include, i.fields.key?.from.length])).toEqual([["openai-local-secrets", true, 2]])
    expect(openai[0]?.note).toBe("1 copy possibly stale (backup copy); same value in 2 files")
    expect(plan.possiblyStale.map((p) => p.why)).toEqual(["backup copy"])
  })

  // Seen on a real machine: .env.bak-20260908-174826 became the environment
  // bak-20260908-174826 with 75 secrets and 52 plain variables mapped.
  it("maps every variable of a backup copy to skip, adds no environment, and makes no item of a value only the copy holds but lists it as possibly stale", async () => {
    const { home, main } = checkouts()
    const live = "OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnop\n"
    writeFileSync(join(main, ".env"), `${live}SESSION_SECRET=s3cr3t-s3cr3t-value-1234\n`)
    writeFileSync(join(main, ".env.bak-20260908-174826"), `${live}OLD_SECRET=old-s3cr3t-value-0123456789\nLOG_LEVEL=debug\n`)
    writeFileSync(join(main, ".env.production.bak"), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n")
    const plan = buildPlan(await scanCode(home), context(home))
    const bak = join(main, ".env.bak-20260908-174826")
    expect(plan.repos[0]?.project.environments).toEqual(["dev"])
    expect(plan.items.map((i) => [i.slug, i.include, Object.values(i.fields)[0]?.from.map((s) => plan.sources[s]?.path)])).toEqual([
      ["openai-app", true, [join(main, ".env"), bak]],
      ["session-secret-app", true, [join(main, ".env")]],
    ])
    const files = Object.fromEntries((plan.repos[0]?.files ?? []).map((f) => [f.path, [f.env, f.vars]]))
    expect(files[".env.bak-20260908-174826"]).toEqual(["dev", { OPENAI_API_KEY: { skip: "backup copy" }, OLD_SECRET: { skip: "backup copy" }, LOG_LEVEL: { skip: "backup copy" } }])
    expect(files[".env.production.bak"]).toEqual(["prod", { STRIPE_SECRET_KEY: { skip: "backup copy" } }])
    // A value only a backup copy holds is listed, so the human can add it or revoke it.
    const variableOf = (id: string) => plan.sources[id]?.variable
    expect(plan.possiblyStale.map((p) => [variableOf(p.source), p.why])).toEqual([
      ["OPENAI_API_KEY", "backup copy"],
      ["OLD_SECRET", "backup copy only: not adopted; add it by hand if you still use it, or revoke it"],
      ["STRIPE_SECRET_KEY", "backup copy only: not adopted; add it by hand if you still use it, or revoke it"],
    ])
    // The snapshot still holds every copy: it takes every source's file.
    expect(new Set(Object.values(plan.sources).map((s) => s.path))).toEqual(new Set([join(main, ".env"), bak, join(main, ".env.production.bak")]))
    expect(checkPlan(plan).problems).toEqual([])
  })

  // Seen on a real machine: the vault refused an oauth-client's client_id at
  // submit, since a public field is kept in the clear and this one looked like a secret.
  it("leaves out an item whose public field looks like a secret, and check lists it and refuses it ticked", async () => {
    const { home, main } = checkouts()
    writeFileSync(join(main, ".env"), "GOOGLE_CLIENT_ID=123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com\nGOOGLE_CLIENT_SECRET=GOCSPX-abcdefghijklmnopqrstuvwx12\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=abcdEFGH1234ijklMNOP5678qrstUVWX90yzABCD\n")
    const result = await scanCode(home)
    expect(result.entries.map((e) => [e.variable, e.publicLooksSecret])).toEqual([["GOOGLE_CLIENT_ID", true], ["GOOGLE_CLIENT_SECRET", false], ["AWS_ACCESS_KEY_ID", false], ["AWS_SECRET_ACCESS_KEY", false]])
    const plan = buildPlan(result, context(home))
    expect(plan.items.map((i) => [i.slug, i.kind, i.include, i.note])).toEqual([
      ["google-oauth-client-app", "oauth-client", false, "the vault keeps public fields in the clear and this one looks like a secret; add it by hand from the web app"],
      ["aws-app", "cloud-access-key", true, null],
    ])
    const google = plan.items[0] as PlanItem
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 1, byHand: [{ ref: google.ref, slug: "google-oauth-client-app", field: "client_id" }] })
    google.include = true
    expect(checkPlan(plan).problems.map((p) => p.problem)).toEqual(["client_id is a public field, which the vault keeps in the clear, and its value looks like a secret; set include to false and add google-oauth-client-app by hand from the web app"])
  })

  // Seen on a real machine (0.3.8): check passed, then the vault refused a
  // key file kept whole because its own name looked like a secret.
  it("labels a file item whose name looks like a secret with its slug, or else file, notes it, and check passes", async () => {
    const home = realpathSync(tempDir("mehen-adopt-plan-"))
    dirs.push(home)
    const secrets = join(home, ".local-secrets")
    mkdirSync(secrets)
    const pem = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49\n-----END PRIVATE KEY-----\n"
    writeFileSync(join(secrets, "apple-app-AuthKey_2X9KQ7M4PA.p8"), pem)
    writeFileSync(join(secrets, "ghp_abcdefghijkl.pem"), pem.replace("MIGT", "MIGU"))
    writeFileSync(join(secrets, "AuthKey_ABC123.p8"), pem.replace("MIGT", "MIGV"))
    const result = await scan({ home, machine: "test-mac", roots: [{ path: secrets, depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, context(home, { sharedValues: "per-project" }))
    expect(plan.items.map((i) => [i.slug, i.kind, i.include, i.publicFields, i.note])).toEqual([
      ["authkey-abc123-local-secrets", "file", true, { filename: "AuthKey_ABC123.p8" }, null],
      ["apple-app-authkey-2x9kq7m4pa-local-secrets", "file", true, { filename: "file.p8" }, "the file's name looks like a secret, so it is stored named file.p8; its contents are unchanged"],
      ["ghp-abcdefghijkl-local-secrets", "file", true, { filename: "ghp-abcdefghijkl-local-secrets.pem" }, "the file's name looks like a secret, so it is stored named ghp-abcdefghijkl-local-secrets.pem; its contents are unchanged"],
    ])
    expect(checkPlan(plan)).toMatchObject({ ok: true, included: 3, problems: [] })
  })

  it("check refuses a public field set in the plan that the vault would refuse, naming the item and field but never the value", async () => {
    const home = realpathSync(tempDir("mehen-adopt-plan-"))
    dirs.push(home)
    const secrets = join(home, ".local-secrets")
    mkdirSync(secrets)
    writeFileSync(join(secrets, "AuthKey_ABC123.p8"), "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49\n-----END PRIVATE KEY-----\n")
    const result = await scan({ home, machine: "test-mac", roots: [{ path: secrets, depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, context(home))
    const item = plan.items[0] as PlanItem
    item.publicFields.filename = "AuthKey_SENTINELq8vN2xL7pR4tY9wK3mB6cH1.p8"
    const check = checkPlan(plan)
    expect(check.ok).toBe(false)
    expect(check.problems).toEqual([{ ref: item.ref, where: null, problem: 'the vault would refuse authkey-abc123-local-secrets: "filename" looks like a secret; send it sealed, as a secret field.' }])
    expect(JSON.stringify(check)).not.toContain("SENTINEL")
  })

  // Seen on a real machine: Stripe secret keys in .env files mapped to dev,
  // which every colleague's machine running the project's dev would get.
  it("leaves a live key in a file for an environment that is not protected unticked with a note, keeps one in a prod file ticked, and check lists it", async () => {
    const { home, main } = checkouts()
    writeFileSync(join(main, ".env"), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\nSTRIPE_TEST_KEY=sk_test_0123456789abcdefghijkl\n")
    writeFileSync(join(main, ".env.staging"), "STRIPE_RESTRICTED_KEY=rk_live_0123456789abcdefghijkl\n")
    writeFileSync(join(main, ".env.production"), "STRIPE_SECRET_KEY=sk_live_9876543210zyxwvutsrqponm\n")
    const result = await scanCode(home)
    expect(result.entries.map((e) => [e.variable, e.liveKey])).toEqual([["STRIPE_SECRET_KEY", true], ["STRIPE_TEST_KEY", false], ["STRIPE_SECRET_KEY", true], ["STRIPE_RESTRICTED_KEY", true]])
    const note = (env: string) => `a live stripe key in a ${env} file: every machine that runs app ${env} would get it. Adopt it into a protected environment on the project page, or tick it if ${env} really uses live keys.`
    const plan = buildPlan(result, context(home))
    expect(plan.items.map((i) => [i.slug, i.include, i.note])).toEqual([
      ["stripe-app", false, note("dev")],
      ["stripe-app-2", true, null],
      ["stripe-app-prod", true, null],
      ["stripe-app-staging", false, note("staging")],
    ])
    const check = checkPlan(plan)
    expect(check).toMatchObject({ ok: true, included: 2 })
    expect(check.liveKeys).toEqual([
      { ref: (plan.items[0] as PlanItem).ref, slug: "stripe-app", provider: "stripe", envs: ["app dev"], skipped: [], kept: [], exists: false },
      { ref: (plan.items[3] as PlanItem).ref, slug: "stripe-app-staging", provider: "stripe", envs: ["app staging"], skipped: [], kept: [], exists: false },
    ])
    expect(check.liveKeys.map(liveKeyListing)).toEqual(["stripe-app (app dev)", "stripe-app-staging (app staging)"])
    // Ticked by the human, it is no longer listed.
    ;(plan.items[0] as PlanItem).include = true
    expect(checkPlan(plan).liveKeys.map((k) => k.slug)).toEqual(["stripe-app-staging"])
    // A protected environment of an existing project counts as protected,
    // found by the project's id.
    for (const repo of plan.repos) Object.assign(repo.project, { id: "prj_app00001", create: false })
    expect(checkPlan(plan, { protectedEnvs: new Map([["app", new Set(["staging"])]]) }).liveKeys.map((k) => k.slug)).toEqual(["stripe-app-staging"])
    expect(checkPlan(plan, { protectedEnvs: new Map([["prj_app00001", new Set(["staging"])]]) }).liveKeys).toEqual([])
    const existing = new Map([[main, { id: "prj_app01", slug: "app", environments: [{ name: "dev", protected: false }, { name: "staging", protected: true }, { name: "prod", protected: true }], vars: [] }]])
    expect(buildPlan(result, context(home, { existing })).items.map((i) => [i.slug, i.include])).toEqual([["stripe-app", false], ["stripe-app-2", true], ["stripe-app-prod", true], ["stripe-app-staging", true]])
    expect(JSON.stringify(plan)).not.toContain("0123456789abcdef")
  })

  // Seen in review: one live key in .env and .env.production merged into one
  // item, which the dev file unticked, so prod lost its mapping too.
  it("keeps a live key also in a prod file ticked for prod, skips its dev variable and check lists it", async () => {
    const { home, main } = checkouts()
    const live = "sk_live_0123456789abcdefghijkl"
    writeFileSync(join(main, ".env"), `STRIPE_SECRET_KEY=${live}\n`)
    writeFileSync(join(main, ".env.staging"), `STRIPE_SECRET_KEY=${live}\n`)
    writeFileSync(join(main, ".env.production"), `STRIPE_SECRET_KEY=${live}\n`)
    const plan = buildPlan(await scanCode(home), context(home))
    expect(plan.items.map((i) => [i.slug, i.include])).toEqual([["stripe-app", true]])
    const ref = (plan.items[0] as PlanItem).ref
    const skip = { skip: "a live key: only the protected environment gets it" }
    expect(plan.repos[0]?.files.map((f) => [f.env, f.vars.STRIPE_SECRET_KEY])).toEqual([
      ["dev", skip],
      ["prod", { item: ref, field: "key" }],
      ["staging", skip],
    ])
    const check = checkPlan(plan)
    expect(check).toMatchObject({ ok: true, included: 1, humanSets: [{ project: "app", env: "prod", variable: "STRIPE_SECRET_KEY", item: "stripe-app" }] })
    expect(check.liveKeys).toEqual([{ ref, slug: "stripe-app", provider: "stripe", envs: [], skipped: ["app dev", "app staging"], kept: ["app prod"], exists: false }])
    expect(check.liveKeys.map(liveKeyListing)).toEqual(["stripe-app (kept for app prod, skipped in app dev and app staging)"])
  })

  // Seen in review: a live key whose slug was already in the vault was
  // mapped into dev with no note, and apply bound it.
  it("skips the dev variable of a live key already in the vault and check lists it as already in the vault", async () => {
    const { home, main } = checkouts()
    writeFileSync(join(main, ".env"), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n")
    const plan = buildPlan(await scanCode(home), context(home, storedItem("stripe-app", ADOPTED_STRIPE, join(main, ".env"), "STRIPE_SECRET_KEY")))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists])).toEqual([["stripe-app", false, true]])
    const ref = (plan.items[0] as PlanItem).ref
    expect(plan.repos[0]?.files[0]?.vars.STRIPE_SECRET_KEY).toEqual({ skip: "a live key: only the protected environment gets it" })
    const check = checkPlan(plan)
    expect(check).toMatchObject({ ok: true, humanSets: [] })
    expect(check.liveKeys).toEqual([{ ref, slug: "stripe-app", provider: "stripe", envs: [], skipped: ["app dev"], kept: [], exists: true }])
    expect(check.liveKeys.map(liveKeyListing)).toEqual(["stripe-app (already in the vault, skipped in app dev)"])
  })

  // Seen in review: one live key in api's .env.production and web's .env,
  // merged into one workspace item, stayed ticked for api prod while web's
  // dev variable kept its mapping, and check listed nothing.
  it("skips the dev variable of a live key in another project's file and check lists it with that project", async () => {
    const { home, homes } = twoRepos({ api: ".env.production", web: ".env" })
    const plan = buildPlan(await scanCode(home), context(home, { homes }))
    expect(plan.items.map((i) => [i.slug, i.include, i.home.kind])).toEqual([["stripe-api-prod", true, "workspace"]])
    const ref = (plan.items[0] as PlanItem).ref
    expect(plan.repos.map((r) => [r.project.slug, r.files[0]?.env, r.files[0]?.vars.STRIPE_SECRET_KEY])).toEqual([
      ["api", "prod", { item: ref, field: "key" }],
      ["web", "dev", LIVE_KEY_SKIP],
    ])
    const check = checkPlan(plan)
    expect(check).toMatchObject({ ok: true, included: 1 })
    expect(check.liveKeys).toEqual([{ ref, slug: "stripe-api-prod", provider: "stripe", envs: [], skipped: ["web dev"], kept: ["api prod"], exists: false }])
    expect(check.liveKeys.map(liveKeyListing)).toEqual(["stripe-api-prod (kept for api prod, skipped in web dev)"])
    // Mapped back by hand, it is still listed, under web's dev.
    ;(plan.repos[1]?.files[0] as AdoptPlan["repos"][number]["files"][number]).vars.STRIPE_SECRET_KEY = { item: ref, field: "key" }
    expect(checkPlan(plan).liveKeys.map(liveKeyListing)).toEqual(["stripe-api-prod (web dev: kept for api prod)"])
  })

  it("skips the dev variables of a live key already in the vault in every project and check lists each", async () => {
    const { home, homes } = twoRepos({ api: ".env", web: ".env" })
    const plan = buildPlan(await scanCode(home), context(home, { homes, ...storedItem("stripe-api", ADOPTED_STRIPE, join(home, "code", "api", ".env"), "STRIPE_SECRET_KEY") }))
    expect(plan.items.map((i) => [i.slug, i.include, i.exists])).toEqual([["stripe-api", false, true]])
    const ref = (plan.items[0] as PlanItem).ref
    expect(plan.repos.map((r) => [r.project.slug, r.files[0]?.vars.STRIPE_SECRET_KEY])).toEqual([["api", LIVE_KEY_SKIP], ["web", LIVE_KEY_SKIP]])
    expect(checkPlan(plan).liveKeys.map(liveKeyListing)).toEqual(["stripe-api (already in the vault, skipped in api dev and web dev)"])
    // Mapped back and ticked by hand, it is still listed, under web's dev.
    ;(plan.repos[1]?.files[0] as AdoptPlan["repos"][number]["files"][number]).vars.STRIPE_SECRET_KEY = { item: ref, field: "key" }
    ;(plan.items[0] as PlanItem).include = true
    expect(checkPlan(plan).liveKeys.map(liveKeyListing)).toEqual(["stripe-api (web dev: already in the vault, skipped in api dev)"])
  })

  // Seen in review: one live key in two projects' .env became the workspace
  // credential stripe, whose note named only api's dev, though every
  // member's machine would get it.
  it("keeps a live key in two projects' dev files one item per project, each unticked, and check lists each with its own project", async () => {
    const { home, roots } = repositories("api", "web")
    for (const root of roots) writeFileSync(join(root, ".env"), "STRIPE_SECRET_KEY=sk_live_0123456789abcdefghijkl\n")
    const plan = buildPlan(await scanCode(home), context(home))
    expect(plan.items.map((i) => [i.slug, i.home, i.include])).toEqual([
      ["stripe-api", { kind: "project", project: "api" }, false],
      ["stripe-web", { kind: "project", project: "web" }, false],
    ])
    const check = checkPlan(plan)
    expect(check).toMatchObject({ ok: true, included: 0, sharedWorkspace: 0 })
    expect(check.liveKeys.map(liveKeyListing)).toEqual(["stripe-api (api dev)", "stripe-web (web dev)"])
  })

  // Seen in review: an id or ordering that looks random was mapped to a
  // plain value, which apply and the vault refuse, though the check passed.
  it("skips a config value that looks like a secret rather than mapping it to a plain value", async () => {
    const { home, main } = checkouts()
    writeFileSync(join(main, ".env"), "MENU_ORDER=Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG\nSTRIPE_PRO_PRICE_ID=price_1OaBcDeFgHiJkLmNoPqRsTuV\nTEMPLATE_ORDERING=tpl_9fK2xQ7mLp3Rz8Vb,tpl_4Hn6Wc1Ys5Ue0Jd\nLOG_LEVEL=debug\n")
    const result = await scanCode(home)
    expect(result.entries.map((e) => [e.variable, e.class, e.configLooksSecret])).toEqual([
      ["MENU_ORDER", "config", true],
      ["STRIPE_PRO_PRICE_ID", "config", true],
      ["TEMPLATE_ORDERING", "config", false],
      ["LOG_LEVEL", "config", false],
    ])
    const plan = buildPlan(result, context(home))
    const skip = { skip: "looks like a secret, so it is not set as a plain value: store it with mehen request or set it by hand" }
    const vars = plan.repos[0]?.files[0]?.vars ?? {}
    expect(vars).toMatchObject({ MENU_ORDER: skip, STRIPE_PRO_PRICE_ID: skip })
    expect(Object.keys(vars.TEMPLATE_ORDERING ?? {})).toEqual(["plain"])
    expect(Object.keys(vars.LOG_LEVEL ?? {})).toEqual(["plain"])
    expect(checkPlan(plan)).toMatchObject({ ok: true, humanSets: [] })
    expect(JSON.stringify(plan)).not.toContain("Zx9qW2vB")
  })

  it("maps a public field on its own to a plain value the check accepts", async () => {
    const { home, repo } = await fixture()
    writeFileSync(join(repo, ".env.staging"), "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, context(home))
    expect(Object.keys(plan.repos[0]?.files.find((f) => f.path === ".env.staging")?.vars.AWS_ACCESS_KEY_ID ?? {})).toEqual(["plain"])
    expect(checkPlan(plan).problems).toEqual([])
  })

  it("reads environments from file names and folder homes from --home", () => {
    expect(["/r/.env", "/r/.env.local", "/r/.env.production", "/r/.env.staging", "/r/.dev.vars", "/r/.env.preview", "/r/.env.production.local", "/r/.env.development.local"].map(envForFile)).toEqual(["dev", "dev", "prod", "staging", "dev", "preview", "prod", "dev"])
    expect(parseFolderHome("/a/b=private")).toEqual({ folder: "/a/b", home: { home: "private", project: null } })
    expect(parseFolderHome("/a=project:billing-api")).toEqual({ folder: "/a", home: { home: "project", project: "billing-api" } })
    expect(parseFolderHome("/a=project")).toBeNull()
  })
})
