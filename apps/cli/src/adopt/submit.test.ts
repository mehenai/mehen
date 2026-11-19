import { afterEach, describe, expect, it } from "bun:test"
import { mkdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { ADOPTION_LIMITS, ADOPTION_REF, AdoptionIndex, type AdoptionItemUploadInput, type AdoptionStatus, adoptionSealContext } from "@mehen/protocol/adopt"
import type { Me } from "@mehen/protocol/api"
import { generateSealKeyPair, openText, type SealedBox } from "@mehen/protocol/seal"
import { FakeVaultApi, tempDir } from "../run/fake-vault-api.ts"
import { VaultApiError } from "../vault-api.ts"
import { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, type PlanItem, buildPlan } from "./plan.ts"
import { scan, sourceKey } from "./scan.ts"
import { readState } from "./state.ts"
import { applyPlan, mappedItem, storedItems, storedSources } from "./apply.ts"
import { type SubmitContext, SubmitStopped, batchRef, chunkUploads, machineTag, submitPlan } from "./submit.ts"
import { verifyPlan } from "./verify.ts"

const OPENAI = "sk-proj-SENTINELopenai0123456789abcdef"
const SESSION = "SENTINEL-session-secret-0123456789"
const PRIVATE = "sk-ant-api03-SENTINELanthropic0123456789"
const VAULT = "https://vault.test"
const dirs: string[] = []
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const ME: Me = { tenant: "tn_test00000001", device: "dev_test", name: "test-mac", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "lease"] }, frozen: false, fingerprint: "0000-0000-0000-0000", capabilities: { environmentV2: true, runBaseUrl: true, runFiles: false, sealedEnvImport: true, policyV1: true } }

async function machine(): Promise<{ home: string; repo: string; plan: AdoptPlan }> {
  const home = realpathSync(tempDir("mehen-adopt-submit-"))
  dirs.push(home)
  const repo = join(home, "code", "billing-api")
  mkdirSync(repo, { recursive: true })
  Bun.spawnSync(["git", "init", "-q"], { cwd: repo })
  Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/billing-api"], { cwd: repo })
  writeFileSync(join(repo, ".env"), `OPENAI_API_KEY=${OPENAI}\nSESSION_SECRET=${SESSION}\nLOG_LEVEL=debug\n`)
  mkdirSync(join(home, ".local-secrets"))
  writeFileSync(join(home, ".local-secrets", "anthropic.env"), `ANTHROPIC_API_KEY=${PRIVATE}\n`)
  const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
  const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "per-project" })
  return { home, repo, plan }
}

// A value read that has reached an item's source mtime, which the vault
// keeps in the clear.
const LEAKED = "SENTINEL-leaked-0123456789"
const leakInto = (plan: AdoptPlan, item: PlanItem) => {
  for (const id of Object.values(item.fields).flatMap((f) => f.from)) (plan.sources[id] as AdoptPlan["sources"][string]).mtime = LEAKED
}

async function vault(options: { me?: Me; kid?: string } = {}) {
  const keys = await generateSealKeyPair()
  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey
  const sealKey = { jwk: { kty: "EC" as const, crv: "P-256" as const, x: jwk.x as string, y: jwk.y as string }, kid: "k1" }
  const uploads: AdoptionItemUploadInput[] = []
  const api = new FakeVaultApi()
    .on("GET", "/v1/me", () => options.me ?? ME)
    .on("GET", "/v1/items", () => ({ items: [] }))
    .on("GET", "/v1/seal-key", () => sealKey)
    .on("POST", "/v1/projects", (body) => ({ id: "prj_billing01", slug: (body as { slug: string }).slug, remotes: [], defaultEnv: "dev", environments: [] }))
    .on("POST", "/v1/adoptions", () => ({ adoption: "adp_test01", url: `${VAULT}/w/test-space/b/adp_test01`, expiresAt: "2026-11-02T10:00:00.000Z", sealKey: { ...sealKey, kid: options.kid ?? "k1" }, limits: ADOPTION_LIMITS }))
    .on("POST", "/v1/adoptions/adp_test01/items", (body) => {
      const items = (body as { items: AdoptionItemUploadInput[] }).items
      uploads.push(...items)
      return { adoption: "adp_test01", accepted: items.map((i) => i.ref), refused: [] }
    })
  return { api, keys, uploads }
}

type Row = { device: string; item: AdoptionItemUploadInput }
type SharedBatch = { status: AdoptionStatus["status"]; rows: Map<string, Row>; names: Map<string, string> }

// One vault several machines talk to, keeping batches as the vault does:
// rows keyed by batch and ref alone, whichever machine sent them, at most
// maxItems rows in a batch, a name staged in an open batch refused
// anywhere else (each refusal a name miss) but for one compare row naming
// a row staged in the same batch, an open batch's status naming its staged
// rows, and an approved one reporting each compare row as mapped, the
// reviewer keeping the value the batch already held.
async function sharedVault() {
  const keys = await generateSealKeyPair()
  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey
  const sealKey = { jwk: { kty: "EC" as const, crv: "P-256" as const, x: jwk.x as string, y: jwk.y as string }, kid: "k1" }
  const expiresAt = "2026-11-02T10:00:00.000Z"
  const batches = new Map<string, SharedBatch>()
  const misses = { count: 0 }
  const statusOf = (id: string): AdoptionStatus => {
    const batch = batches.get(id) as SharedBatch
    const machines = [...batch.names].map(([device, name]) => ({ device, name, items: [...batch.rows.values()].filter((r) => r.device === device).length }))
    const rows = [...batch.rows]
    const outcome = (compare: boolean) => rows.filter(([, r]) => (r.item.compare === true) === compare).map(([ref, r]) => ({ ref, slug: r.item.slug }))
    return { adoption: id, status: batch.status, expiresAt, machines, ...(batch.status === "approved" ? { created: outcome(false), mapped: outcome(true) } : {}), ...(batch.status === "open" ? { staged: rows.map(([ref, r]) => ({ ref, slug: r.item.slug, machine: batch.names.get(r.device) ?? r.device })) } : {}) }
  }
  const nameStaged = (slug: string) => [...batches.values()].some((b) => b.status === "open" && [...b.rows.values()].some((r) => r.item.slug === slug))
  const create = (device: string, name: string) => {
    const id = `adp_test0${batches.size + 1}`
    batches.set(id, { status: "open", rows: new Map(), names: new Map([[device, name]]) })
    return { adoption: id, url: `${VAULT}/w/test-space/b/${id}`, expiresAt, sealKey, limits: ADOPTION_LIMITS }
  }
  const apiFor = (device: string, name: string) => {
    const api = new FakeVaultApi()
      .on("GET", "/v1/me", () => ({ ...ME, device, name }))
      .on("GET", "/v1/items", () => ({ items: [] }))
      .on("GET", "/v1/seal-key", () => sealKey)
      .on("POST", "/v1/projects", (body) => ({ id: "prj_billing01", slug: (body as { slug: string }).slug, remotes: [], defaultEnv: "dev", environments: [] }))
      .on("POST", "/v1/adoptions", () => create(device, name))
    for (let n = 1; n <= 9; n++) {
      const id = `adp_test0${n}`
      api.on("GET", `/v1/adoptions/${id}`, () => statusOf(id))
      api.on("POST", `/v1/adoptions/${id}/cancel`, () => {
        ;(batches.get(id) as SharedBatch).status = "cancelled"
        return statusOf(id)
      })
      api.on("POST", `/v1/adoptions/${id}/items`, (body) => {
        const batch = batches.get(id) as SharedBatch
        batch.names.set(device, name)
        const accepted: string[] = []
        const refused: { ref: string; reason: string }[] = []
        for (const item of (body as { items: AdoptionItemUploadInput[] }).items) {
          const rows = [...batch.rows.values()]
          const compares = item.compare === true && rows.some((r) => r.item.slug === item.slug && r.item.compare !== true) && !rows.some((r) => r.item.slug === item.slug && r.item.compare === true)
          if (batch.rows.has(item.ref)) refused.push({ ref: item.ref, reason: "This row is already in the batch with different contents." })
          else if (nameStaged(item.slug) && !compares) {
            misses.count++
            refused.push({ ref: item.ref, reason: "name not available" })
          } else if (batch.rows.size >= ADOPTION_LIMITS.maxItems) refused.push({ ref: item.ref, reason: `This batch is full: at most ${ADOPTION_LIMITS.maxItems} credentials.` })
          else {
            batch.rows.set(item.ref, { device, item })
            accepted.push(item.ref)
          }
        }
        return { adoption: id, accepted, refused }
      })
    }
    return api
  }
  // Another machine's rows, staged without values.
  const fill = (id: string, device: string, n: number) => {
    const batch = batches.get(id) as SharedBatch
    batch.names.set(device, device)
    // Refs and slugs as the vault's status schema takes them: a ref of a
    // letter of the device and a base-36 count, apart from the plan's a001.
    for (let i = 0; i < n; i++) batch.rows.set(`a${device.at(-1)}${i.toString(36).padStart(3, "0")}`, { device, item: { slug: `${device.replace("_", "-")}-${i}` } as AdoptionItemUploadInput })
  }
  return { keys, batches, statusOf, create, fill, apiFor, misses }
}

// Copies of the plan's openai item, as many and in the homes asked for,
// each its own ref and slug.
function grow(plan: AdoptPlan, homes: { project?: number; private?: number; workspace?: number }): void {
  const base = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
  let n = 1000
  const add = (count: number, home: PlanItem["home"]) => {
    for (let k = 0; k < count; k++, n++) plan.items.push({ ...base, ref: `a${n.toString(36).padStart(4, "0")}`, slug: `copy-${n}`, home })
  }
  add(homes.project ?? 0, { kind: "project", project: "billing-api" })
  add(homes.private ?? 0, { kind: "private" })
  add(homes.workspace ?? 0, { kind: "workspace" })
}

const homeOf = (row: Row) => row.item.home.kind

const OTHER_OPENAI = "sk-proj-SENTINELother9876543210zyxwvu"

function repository(home: string, name: string, env: string): string {
  const root = join(home, "code", name)
  mkdirSync(root, { recursive: true })
  Bun.spawnSync(["git", "init", "-q"], { cwd: root })
  Bun.spawnSync(["git", "remote", "add", "origin", `https://github.com/acme/${name}`], { cwd: root })
  writeFileSync(join(root, ".env"), env)
  return root
}

async function workspacePlan(home: string): Promise<AdoptPlan> {
  const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
  return buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "workspace" })
}

// billing-api and search-api share one key as the workspace credential
// openai, submitted into a batch of this machine's own; then aaa and bbb
// hold another key, which sorts first, so a plan made again before approval
// gives that key openai and the first key's plan ref.
async function replannedOwnBatch() {
  const { home, repo } = await machine()
  const search = repository(home, "search-api", `OPENAI_API_KEY=${OPENAI}\n`)
  const plan = await workspacePlan(home)
  const shared = await sharedVault()
  const first = await submitPlan(input(plan, home), context(shared.apiFor("dev_test", "test-mac"), home))
  const adoption = first.batches[0]?.adoption as string
  const pair = ["aaa", "bbb"].map((name) => repository(home, name, `OPENAI_API_KEY=${OTHER_OPENAI}\n`))
  const again = await workspacePlan(home)
  const keysOf = (p: AdoptPlan, slug: string) => p.items.find((i) => i.slug === slug)?.fields.key?.from.map((id) => sourceKey(p.sources[id] as { path: string; variable: string | null; pointer: string | null }))
  const firstKeys = [repo, search].map((root) => sourceKey({ path: join(root, ".env"), variable: "OPENAI_API_KEY", pointer: null }))
  const pairKeys = pair.map((root) => sourceKey({ path: join(root, ".env"), variable: "OPENAI_API_KEY", pointer: null }))
  expect([keysOf(plan, "openai"), keysOf(again, "openai"), again.items.find((i) => i.slug === "openai")?.ref]).toEqual([firstKeys, pairKeys, plan.items.find((i) => i.slug === "openai")?.ref])
  return { home, plan, again, shared, adoption, firstKeys, pairKeys }
}

function context(api: FakeVaultApi, home: string, guard = new OutputGuard()): SubmitContext {
  return { api, config: { vault: VAULT, tenant: "tn_test00000001", workspaceSlug: "test-space", owner: { kind: "member", member: "mem_alex0001", name: "Alex" } }, vault: { vaultUrl: VAULT, workspaceSlug: "test-space" }, stateDir: join(home, "state"), guard }
}

const input = (plan: AdoptPlan, home: string, join: string[] = []) => ({ plan, join, reason: null, session: null, machine: "test-mac", home })

describe("submit", () => {
  it("seals each secret to its batch, ref and field, creates the project first, and sends no value in the clear", async () => {
    const { home, plan } = await machine()
    const { api, keys, uploads } = await vault()
    const guard = new OutputGuard()
    const result = await submitPlan(input(plan, home), context(api, home, guard))
    expect(result).toMatchObject({ batches: [{ adoption: "adp_test01", joined: false, uploaded: { items: 3, fields: 3 } }], refused: [], projects: [{ slug: "billing-api", id: "prj_billing01", created: true }] })
    expect(String(result.batches[0]?.link.url)).toBe(`${VAULT}/w/test-space/b/adp_test01`)
    const order = api.calls.map((c) => `${c.method} ${c.path}`)
    expect(order.indexOf("POST /v1/projects")).toBeLessThan(order.indexOf("POST /v1/adoptions/adp_test01/items"))
    expect(JSON.stringify(api.calls)).not.toContain("SENTINEL")
    expect(uploads.map((u) => [u.slug, u.home])).toEqual([
      ["anthropic-local-secrets", { kind: "member", member: "mem_alex0001" }],
      ["openai-billing-api", { kind: "project", project: "prj_billing01" }],
      ["session-secret-billing-api", { kind: "project", project: "prj_billing01" }],
    ])
    const openai = uploads[1] as AdoptionItemUploadInput
    expect(openai.repo).toEqual({ remote: "github.com/acme/billing-api", env: "dev" })
    expect(await openText(keys.privateKey, openai.sealed.key as SealedBox, adoptionSealContext("adp_test01", openai.ref, "key"))).toBe(OPENAI)
    expect(openText(keys.privateKey, openai.sealed.key as SealedBox, adoptionSealContext("adp_test01", "a999", "key"))).rejects.toThrow()
    expect(guard.clean(`x ${OPENAI} x`)).toBe(false)
    const state = await readState(join(home, "state"))
    expect(state.adoptions.map((a) => a.adoption)).toEqual(["adp_test01"])
    expect(state.projects).toEqual({ "billing-api": "prj_billing01" })
  })

  // Adopt reconcile: each source carries its file's mtime, and after the
  // rows submit sends the plan's index, value-free, for the inventory page.
  it("sends each source's mtime and then the plan's index, every item with no value, and passes the index through the guard", async () => {
    const { home, repo, plan } = await machine()
    const { api, uploads } = await vault()
    const indexes: unknown[] = []
    api.on("POST", "/v1/adoptions/index", (body) => {
      indexes.push(body)
      return {}
    })
    const result = await submitPlan(input(plan, home), context(api, home))
    expect(result.index).toEqual({ state: "sent", bytes: expect.any(Number) })
    const mtime = statSync(join(repo, ".env")).mtime.toISOString()
    expect(uploads.find((u) => u.slug === "openai-billing-api")?.sources).toEqual([{ path: join(repo, ".env"), variable: "OPENAI_API_KEY", stale: [], mtime }])
    const order = api.calls.map((c) => `${c.method} ${c.path}`)
    expect(order.indexOf("POST /v1/adoptions/index")).toBeGreaterThan(order.lastIndexOf("POST /v1/adoptions/adp_test01/items"))
    const index = AdoptionIndex.parse(indexes[0])
    expect(index.machine).toBe("test-mac")
    expect(index.items.map((i) => [i.ref, i.slug, i.home, i.project, i.include, i.exists, i.storeOnly])).toEqual(plan.items.map((i) => [i.ref, i.slug, i.home.kind, i.home.kind === "project" ? "prj_billing01" : null, i.include, false, false]))
    expect(index.items.find((i) => i.slug === "openai-billing-api")?.uses).toEqual([{ project: "prj_billing01", env: "dev", variable: "OPENAI_API_KEY", field: "key" }])
    expect(JSON.stringify(indexes)).not.toContain("SENTINEL")
    // The guard checks the index before it leaves: one holding a value stays
    // here, and the rows already in stand.
    const again = await machine()
    const guard = new OutputGuard()
    guard.add(LEAKED, "secret")
    // The index lists an unticked item, which no row carries.
    const unticked = again.plan.items.find((i) => i.slug.startsWith("anthropic")) as PlanItem
    unticked.include = false
    leakInto(again.plan, unticked)
    const withheld = await vault()
    const kept = await submitPlan(input(again.plan, again.home), context(withheld.api, again.home, guard))
    expect([kept.index.state, kept.batches[0]?.uploaded.items]).toEqual(["withheld", 2])
    expect(withheld.api.calls.some((c) => c.path === "/v1/adoptions/index")).toBe(false)
  })

  // Seen in review: only a row's sealed values were protected, so a value
  // read that reached its name, sources or repo went to the vault in the clear.
  it("sends no row whose parts the vault keeps in the clear hold a value the guard knows, and says so without the value", async () => {
    const { home, plan } = await machine()
    const { api, uploads } = await vault()
    const guard = new OutputGuard()
    guard.add(LEAKED, "secret")
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    leakInto(plan, openai)
    const result = await submitPlan(input(plan, home), context(api, home, guard))
    const reason = "the output guard found a value read in what the vault keeps in the clear (its name, sources, repo or public fields), so it was not sent; scan and plan again"
    expect(result.refused).toEqual([{ ref: openai.ref, reason }])
    expect([result.skipped.unsupported, result.batches[0]?.uploaded.items]).toEqual([1, 2])
    expect(uploads.map((u) => u.slug).sort()).toEqual(plan.items.filter((i) => i !== openai).map((i) => i.slug).sort())
    // The index names the same mtime, so the guard holds it back too.
    expect(result.index.state).toBe("withheld")
    expect(JSON.stringify(api.calls.map((c) => c.body))).not.toContain(LEAKED)
  })

  it("says nothing of an index an older vault does not know, reports one that fails, and sends none over the vault's body limit", async () => {
    const { home, plan } = await machine()
    const { api } = await vault()
    api.on("POST", "/v1/adoptions/index", () => {
      throw new VaultApiError(404, { error: "not_found", message: "Not found." })
    })
    const result = await submitPlan(input(plan, home), context(api, home))
    expect(result.index).toEqual({ state: "absent", bytes: expect.any(Number) })
    expect(result.batches[0]?.uploaded.items).toBe(3)
    // Any other failure is reported, never thrown: the rows are in.
    const down = await vault()
    down.api.on("POST", "/v1/adoptions/index", () => {
      throw new Error("socket hang up")
    })
    const offline = await machine()
    expect((await submitPlan(input(offline.plan, offline.home), context(down.api, offline.home))).index).toEqual({ state: "refused", bytes: expect.any(Number) })
    const big = await machine()
    // 300 unticked copies, each found in 32 places: indexed, never uploaded.
    grow(big.plan, { project: 300 })
    const from = big.plan.items.find((i) => i.slug === "openai-billing-api")?.fields.key?.from[0] as string
    for (const item of big.plan.items.filter((i) => i.slug.startsWith("copy-"))) Object.assign(item, { include: false, fields: { key: { from: Array(32).fill(from) } } })
    const large = await vault()
    const sent = await submitPlan(input(big.plan, big.home), context(large.api, big.home))
    expect(sent.index.state).toBe("oversize")
    expect(sent.index.bytes).toBeGreaterThan(ADOPTION_LIMITS.maxChunkBytes)
    expect(large.api.calls.some((c) => c.path === "/v1/adoptions/index")).toBe(false)
  })

  // Adopt reconcile: an item already in the vault was never sent, so a value
  // rotated since was not seen; a plan of 0.3.15 marks none as compare.
  it("sends each compare row sealed with compare: true under the held name, reports it with no result, and leaves an older plan's existing item unsent", async () => {
    const { home, plan } = await machine()
    const openai = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    Object.assign(openai, { exists: true, compare: true })
    const { api, keys, uploads } = await vault()
    const result = await submitPlan(input(plan, home), context(api, home))
    const sent = uploads.find((u) => u.slug === "openai-billing-api") as AdoptionItemUploadInput
    expect(uploads.map((u) => [u.slug, u.compare ?? false])).toEqual([
      ["anthropic-local-secrets", false],
      ["openai-billing-api", true],
      ["session-secret-billing-api", false],
    ])
    expect(await openText(keys.privateKey, sent.sealed.key as SealedBox, adoptionSealContext("adp_test01", sent.ref, "key"))).toBe(OPENAI)
    expect(result.compared).toEqual([{ ref: openai.ref, slug: "openai-billing-api", adoption: "adp_test01" }])
    expect([result.skipped.exists, result.batches[0]?.uploaded.items]).toEqual([0, 3])
    expect(JSON.stringify(result)).not.toMatch(/same|differs|unknown|SENTINEL/)
    // A 0.3.15 plan: exists, unticked, no compare mark.
    const { home: older, plan: old } = await machine()
    const kept = old.items.find((i) => i.slug === "openai-billing-api") as PlanItem
    Object.assign(kept, { exists: true, include: false })
    const before = await vault()
    const unsent = await submitPlan(input(old, older), context(before.api, older))
    expect([before.uploads.map((u) => u.slug), unsent.skipped.exists, unsent.compared]).toEqual([["anthropic-local-secrets", "session-secret-billing-api"], 1, []])
  })

  // Seen on a real machine: a second project for the same remote, which the
  // vault refuses, failed the whole submit.
  it("creates a project shared by a repository's worktrees once", async () => {
    const { home, repo } = await machine()
    const worktree = join(repo, ".worktrees", "feature")
    mkdirSync(worktree, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: worktree })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/billing-api"], { cwd: worktree })
    writeFileSync(join(worktree, ".env"), `OPENAI_API_KEY=${OPENAI}\nSESSION_SECRET=${SESSION}\n`)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "per-project" })
    expect(plan.repos.map((r) => [r.root, r.project.slug])).toEqual([[repo, "billing-api"], [worktree, "billing-api"]])
    const { api, uploads } = await vault()
    const submitted = await submitPlan(input(plan, home), context(api, home))
    expect(api.calls.filter((c) => c.method === "POST" && c.path === "/v1/projects")).toHaveLength(1)
    expect(submitted.projects).toEqual([{ slug: "billing-api", id: "prj_billing01", created: true }])
    expect(uploads.map((u) => [u.slug, u.sources.length])).toEqual([
      ["anthropic-local-secrets", 1],
      ["openai-billing-api", 2],
      ["session-secret-billing-api", 2],
    ])
  })

  it("uploads a value two projects share as one workspace credential that both projects' variables name", async () => {
    const { home, repo } = await machine()
    const search = join(home, "code", "search-api")
    mkdirSync(search, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: search })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/search-api"], { cwd: search })
    writeFileSync(join(search, ".env"), `OPENAI_API_KEY=${OPENAI}\n`)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "workspace" })
    const { api, keys, uploads } = await vault()
    const submitted = await submitPlan(input(plan, home), context(api, home))
    expect(submitted.projects.map((p) => p.slug)).toEqual(["billing-api", "search-api"])
    expect(uploads.map((u) => [u.slug, u.home, u.sources.map((s) => s.path)])).toEqual([
      ["openai", { kind: "workspace" }, [join(repo, ".env"), join(search, ".env")]],
      ["session-secret-billing-api", { kind: "project", project: "prj_billing01" }, [join(repo, ".env")]],
    ])
    const openai = uploads[0] as AdoptionItemUploadInput
    expect(await openText(keys.privateKey, openai.sealed.key as SealedBox, adoptionSealContext("adp_test01", openai.ref, "key"))).toBe(OPENAI)
    // Once approved, each project's OPENAI_API_KEY names the one credential.
    const state = await readState(join(home, "state"))
    const status: AdoptionStatus = { adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [], created: uploads.map((u) => ({ ref: u.ref, slug: u.slug })) }
    const stored = storedItems([{ status, refs: state.adoptions[0]?.refs ?? null, sources: state.adoptions[0]?.sources ?? null }])
    const mapped = plan.repos.map((r) => {
      const m = r.files[0]?.vars.OPENAI_API_KEY
      return [r.project.slug, m && "item" in m ? mappedItem(plan, stored, m.item) : m]
    })
    expect(mapped).toEqual([
      ["billing-api", { slug: "openai" }],
      ["search-api", { slug: "openai" }],
    ])
    // The state keeps where each row's value came from, never the value,
    // so a later plan reuses openai for this value only.
    const ref = plan.items.find((i) => i.slug === "openai")?.ref as string
    expect(state.adoptions[0]?.sources?.[ref]).toEqual([join(repo, ".env"), join(search, ".env")].map((path) => sourceKey({ path, variable: "OPENAI_API_KEY", pointer: null })))
    expect(JSON.stringify(state)).not.toContain(OPENAI)
    const storedSlugs = storedSources([{ status, refs: state.adoptions[0]?.refs ?? null, sources: state.adoptions[0]?.sources ?? null }])
    const again = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map([["openai", { kind: "api-key", provider: "openai", tags: ["adopted"] }]]), homes: new Map(), existing: new Map(), storedSlugs, unappliedSlugs: new Map(), sharedValues: "workspace" })
    expect(again.items.find((i) => i.home.kind === "workspace")).toMatchObject({ slug: "openai", exists: true, include: true, compare: true })
  })

  // Seen in review: a bare name such as openai is often another member's
  // private item this machine cannot see, and the refusal said only "name
  // not available".
  it("says how to fix a workspace credential's name the vault refuses, and leaves a project item's refusal as the vault gave it", async () => {
    const { home } = await machine()
    const search = join(home, "code", "search-api")
    mkdirSync(search, { recursive: true })
    Bun.spawnSync(["git", "init", "-q"], { cwd: search })
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/search-api"], { cwd: search })
    writeFileSync(join(search, ".env"), `OPENAI_API_KEY=${OPENAI}\n`)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "workspace" })
    const { api } = await vault()
    api.on("POST", "/v1/adoptions/adp_test01/items", (body) => ({ adoption: "adp_test01", accepted: [], refused: (body as { items: AdoptionItemUploadInput[] }).items.map((i) => ({ ref: i.ref, reason: "name not available" })) }))
    const submitted = await submitPlan(input(plan, home), context(api, home))
    const ref = (slug: string) => plan.items.find((i) => i.slug === slug)?.ref as string
    expect(submitted.refused).toEqual([
      { ref: ref("openai"), reason: "name not available: the workspace already has openai, perhaps an item, request or batch this machine cannot see; rename the item in the plan (its slug) and run mehen adopt plan --check, or plan again with --per-project, then submit again" },
      { ref: ref("session-secret-billing-api"), reason: "name not available" },
    ])
  })

  it("uploads a key kept whole in .local-secrets as an item named by its file, and its token beside it", async () => {
    const { home } = await machine()
    const pem = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49SENTINELp8key0123456789abcdef\n-----END PRIVATE KEY-----\n"
    const token = "SENTINELtok9fQ2xLm7Rv4Kp8Zw3Hn6Jd1Bs5Yc0Ta"
    writeFileSync(join(home, ".local-secrets", "apple-AuthKey_ABC123.p8"), pem)
    writeFileSync(join(home, ".local-secrets", "ci-executor-token"), `${token}\n`)
    const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard() })
    const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "per-project" })
    expect(plan.items.map((i) => [i.slug, i.kind, i.include, Object.keys(i.fields), i.publicFields])).toEqual([
      ["anthropic-local-secrets", "api-key", true, ["key"], {}],
      ["apple-authkey-abc123-local-secrets", "file", true, ["content"], { filename: "apple-AuthKey_ABC123.p8" }],
      ["ci-executor-token-local-secrets", "generic", true, ["value"], {}],
    ])
    const { api, keys, uploads } = await vault()
    const submitted = await submitPlan(input(plan, home), context(api, home))
    expect(submitted.batches.map((b) => b.uploaded)).toEqual([{ items: 3, fields: 3 }])
    expect(JSON.stringify(api.calls)).not.toContain("SENTINEL")
    const sealed = (slug: string, field: string) => {
      const upload = uploads.find((u) => u.slug === slug) as AdoptionItemUploadInput
      return openText(keys.privateKey, upload.sealed[field] as SealedBox, adoptionSealContext("adp_test01", upload.ref, field))
    }
    expect(await sealed("apple-authkey-abc123-local-secrets", "content")).toBe(pem)
    expect(await sealed("ci-executor-token-local-secrets", "value")).toBe(token)
  })

  it("refuses a vault without adoption before reading any file", async () => {
    const { home, plan } = await machine()
    const { api } = await vault({ me: { ...ME, capabilities: { ...ME.capabilities, sealedEnvImport: false } } })
    const guard = new OutputGuard()
    expect(submitPlan(input(plan, home), context(api, home, guard))).rejects.toMatchObject({ code: "not_available" })
    await Bun.sleep(10)
    expect(guard.size).toBe(0)
    expect(api.calls.map((c) => c.path)).toEqual(["/v1/me"])
  })

  it("refuses a batch whose seal key is not the one the vault publishes, and uploads nothing", async () => {
    const { home, plan } = await machine()
    const { api, uploads } = await vault({ kid: "k2" })
    expect(submitPlan(input(plan, home), context(api, home))).rejects.toThrow("is not the key the vault publishes")
    await Bun.sleep(20)
    expect(uploads).toEqual([])
    expect(api.called("POST", "/v1/projects")).toBe(false)
  })

  it("skips a value that changed since the scan and uploads the rest", async () => {
    const { home, repo, plan } = await machine()
    writeFileSync(join(repo, ".env"), `SESSION_SECRET=${SESSION}\nLOG_LEVEL=debug\n`)
    const { api, uploads } = await vault()
    const result = await submitPlan(input(plan, home), context(api, home))
    expect(result.skipped.changed).toBe(1)
    expect(result.refused).toEqual([{ ref: plan.items.find((i) => i.slug === "openai-billing-api")?.ref as string, reason: "changed since scan" }])
    expect(uploads.map((u) => u.slug)).toEqual(["anthropic-local-secrets", "session-secret-billing-api"])
  })

  it("--join fills another machine's open batch with the published key; a closed one is refused", async () => {
    const { home, plan } = await machine()
    const { api, uploads } = await vault()
    api.on("GET", "/v1/adoptions/adp_test01", () => ({ adoption: "adp_test01", status: "open", expiresAt: "2026-11-02T10:00:00.000Z", machines: [] }))
    const result = await submitPlan(input(plan, home, ["adp_test01"]), context(api, home))
    expect(result.batches.map((b) => b.joined)).toEqual([true])
    expect(api.called("POST", "/v1/adoptions")).toBe(false)
    expect(uploads).toHaveLength(3)
    api.on("GET", "/v1/adoptions/adp_test01", () => ({ adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [] }))
    expect(submitPlan(input(plan, home, ["adp_test01"]), context(api, home))).rejects.toMatchObject({ code: "conflict" })
  })

  // Seen in review: every plan numbers its items from a001 and the vault
  // keys a batch's rows by ref alone, so a second machine's --join was
  // refused row by row as "already in the batch". And machines with the same
  // repo plan the same names, which the vault refuses in a second row, each
  // refusal spending the name budget. Then the second machine skipped the
  // names, so the reviewer never saw whether its values were the same.
  it("two machines in one batch: the second machine's names the first staged go as compare rows under refs of its own, sealed, and none is refused", async () => {
    const office = await machine()
    const laptop = await machine()
    const own = (plan: AdoptPlan, slug: string) => {
      const item = plan.items.find((i) => i.slug === "anthropic-local-secrets") as PlanItem
      item.slug = slug
    }
    own(office.plan, "anthropic-office")
    own(laptop.plan, "anthropic-laptop")
    const shared = await sharedVault()
    const officeApi = shared.apiFor("dev_office", "office")
    const laptopApi = shared.apiFor("dev_laptop", "laptop")
    const first = await submitPlan(input(office.plan, office.home), context(officeApi, office.home))
    const adoption = first.batches[0]?.adoption as string
    const second = await submitPlan(input(laptop.plan, laptop.home, [adoption]), context(laptopApi, laptop.home))
    expect([first.batches[0]?.uploaded.items, second.batches.map((b) => [b.adoption, b.uploaded.items]), second.refused, shared.misses.count]).toEqual([3, [[adoption, 3]], [], 0])
    const ref = (plan: AdoptPlan, slug: string) => plan.items.find((i) => i.slug === slug)?.ref as string
    const compareSlugs = ["openai-billing-api", "session-secret-billing-api"]
    expect([second.shared, second.skipped.shared]).toEqual([[], 0])
    expect(second.compared).toEqual(compareSlugs.map((slug) => ({ ref: ref(laptop.plan, slug), slug, adoption })))
    const batch = shared.batches.get(adoption) as SharedBatch
    expect([...batch.rows.values()].map((r) => [r.device, r.item.slug, r.item.compare ?? false]).sort()).toEqual([
      ["dev_laptop", "anthropic-laptop", false],
      ["dev_laptop", "openai-billing-api", true],
      ["dev_laptop", "session-secret-billing-api", true],
      ["dev_office", "anthropic-office", false],
      ["dev_office", "openai-billing-api", false],
      ["dev_office", "session-secret-billing-api", false],
    ])
    for (const r of batch.rows.keys()) expect(r).toMatch(ADOPTION_REF)
    for (const slug of ["anthropic-laptop", "openai-billing-api"]) {
      const row = [...batch.rows.entries()].find(([, r]) => r.device === "dev_laptop" && r.item.slug === slug) as [string, Row]
      expect(row[0].startsWith(`a${machineTag("dev_laptop", 3)}`)).toBe(true)
      expect(await openText(shared.keys.privateKey, row[1].item.sealed.key as SealedBox, adoptionSealContext(adoption, row[0], "key"))).toBe(slug === "openai-billing-api" ? OPENAI : PRIVATE)
    }
    // The laptop records its own rows and their sources, never the office's.
    const recorded = (await readState(join(laptop.home, "state"))).adoptions[0]
    for (const slug of compareSlugs) expect(recorded?.refs?.[ref(laptop.plan, slug)]).toBe(batchRef(ref(laptop.plan, slug), "dev_laptop"))
    expect(Object.keys(recorded?.sources ?? {}).sort()).toEqual(laptop.plan.items.map((i) => i.ref).sort())
  })

  // Seen in review: a workspace credential's name carries no project, so
  // another machine's openai may be another key, and sharing it by name
  // pointed this machine's projects at that key. Then --join stopped; now
  // it goes as a compare row and the reviewer sees whether they differ.
  it("--join sends a workspace credential whose name a joined batch holds as a compare row against that row, never sharing it", async () => {
    const office = await machine()
    const laptop = await machine()
    for (const { plan } of [office, laptop]) {
      const item = plan.items.find((i) => i.slug === "openai-billing-api") as PlanItem
      item.slug = "openai"
      item.home = { kind: "workspace" }
    }
    const shared = await sharedVault()
    const first = await submitPlan(input(office.plan, office.home), context(shared.apiFor("dev_office", "office"), office.home))
    const adoption = first.batches[0]?.adoption as string
    const laptopApi = shared.apiFor("dev_laptop", "laptop")
    const second = await submitPlan(input(laptop.plan, laptop.home, [adoption]), context(laptopApi, laptop.home))
    const openaiRef = laptop.plan.items.find((i) => i.slug === "openai")?.ref as string
    expect([second.refused, second.shared]).toEqual([[], []])
    expect(second.compared).toContainEqual({ ref: openaiRef, slug: "openai", adoption })
    const row = (shared.batches.get(adoption) as SharedBatch).rows.get(batchRef(openaiRef, "dev_laptop"))
    expect([row?.item.slug, row?.item.compare, row?.item.home]).toEqual(["openai", true, { kind: "workspace" }])
    expect(JSON.stringify(laptopApi.calls)).not.toContain(OPENAI)
  })

  // Seen in review: plan refs are positions, so a plan made again can give
  // another value the ref of this machine's own row, and --join shared that
  // row by ref, so apply bound the new value's variables to the old key.
  // Then --join stopped; now the new value goes as a compare row, which the
  // vault refuses under the ref its row already holds, and the sources
  // recorded for that row stay those of the value it holds.
  it("--join on this machine's own open batch sends a workspace credential whose row was submitted from other sources as a compare row, never sharing that row", async () => {
    const { home, again, shared, adoption, firstKeys } = await replannedOwnBatch()
    const api = shared.apiFor("dev_test", "test-mac")
    const ref = again.items.find((i) => i.slug === "openai")?.ref as string
    const submitted = await submitPlan(input(again, home, [adoption]), context(api, home))
    // Plan refs are positions: openai-2 now has the ref the batch holds
    // session-secret-billing-api under, which goes as a compare row of its own.
    const refOf = (slug: string) => again.items.find((i) => i.slug === slug)?.ref as string
    const different = "This row is already in the batch with different contents."
    expect([submitted.shared, submitted.refused]).toEqual([[], [{ ref, reason: different }, { ref: refOf("openai-2"), reason: different }]])
    expect(submitted.compared).toEqual([{ ref: refOf("session-secret-billing-api"), slug: "session-secret-billing-api", adoption }])
    const sent = api.calls.find((c) => c.path === `/v1/adoptions/${adoption}/items`)?.body as { items: AdoptionItemUploadInput[] }
    expect(sent.items.map((i) => [i.slug, i.compare ?? false])).toEqual([["openai", true], ["openai-2", false], ["session-secret-billing-api", true]])
    expect((await readState(join(home, "state"))).adoptions[0]?.sources?.[ref]).toEqual(firstKeys)
  })

  // Seen in review: apply and verify bound a workspace credential's
  // variables to the row stored under its plan ref and name, which a plan
  // made again before approval gives another value.
  it("apply and verify leave a workspace credential alone when its batch stored the name for its ref from other files", async () => {
    const { home, plan, again, shared, adoption } = await replannedOwnBatch()
    ;(shared.batches.get(adoption) as SharedBatch).status = "approved"
    const recorded = (await readState(join(home, "state"))).adoptions[0]
    const stored = storedItems([{ status: shared.statusOf(adoption), refs: recorded?.refs ?? null, sources: recorded?.sources ?? null }])
    const ref = again.items.find((i) => i.slug === "openai")?.ref as string
    expect(mappedItem(again, stored, ref)).toEqual({ why: `the batch stored openai for ${ref} from other files; plan again` })
    expect(mappedItem(plan, stored, ref)).toEqual({ slug: "openai" })
    const options = { repos: null, session: null, now: new Date("2026-11-01T12:00:00Z") }
    const verified = async (p: AdoptPlan) => {
      const api = new FakeVaultApi()
      api.relayHandler = () => new Response(null, { status: 200, headers: { "Mehen-Upstream": "1" } })
      const report = await verifyPlan(p, stored, { api, config: { vault: VAULT, tenant: "tn_test00000001", device: "dev_test", workspaceSlug: "test-space" }, guard: new OutputGuard(), home, projects: {} }, options)
      return [report.items.some((i) => i.slug === "openai"), api.relayCalls.map((r) => r.item)]
    }
    expect(await verified(plan)).toEqual([true, ["openai"]])
    expect(await verified(again)).toEqual([false, []])
  })

  it("re-submitting the same plan into its own batch shares its rows and keeps the sources that prove a workspace credential's name", async () => {
    const { home } = await machine()
    repository(home, "search-api", `OPENAI_API_KEY=${OPENAI}\n`)
    const plan = await workspacePlan(home)
    const shared = await sharedVault()
    const first = await submitPlan(input(plan, home), context(shared.apiFor("dev_test", "test-mac"), home))
    const adoption = first.batches[0]?.adoption as string
    const before = (await readState(join(home, "state"))).adoptions[0]?.sources
    const again = await submitPlan(input(plan, home, [adoption]), context(shared.apiFor("dev_test", "test-mac"), home))
    expect([again.skipped.shared, again.refused]).toEqual([2, []])
    const recorded = (await readState(join(home, "state"))).adoptions[0]
    expect(recorded?.sources).toEqual(before)
    ;(shared.batches.get(adoption) as SharedBatch).status = "approved"
    const stored = storedSources([{ status: shared.statusOf(adoption), refs: recorded?.refs ?? null, sources: recorded?.sources ?? null }])
    expect(stored.get("openai")).toEqual(new Set(before?.[plan.items.find((i) => i.slug === "openai")?.ref as string]))
  })

  // Seen in review: the sources were recorded before the upload, so a row
  // the vault refused (its ref already held another value) gave the old
  // row the new value's sources.
  it("a re-upload the vault refuses leaves the sources recorded for the row it already holds", async () => {
    const { home, again, shared, adoption, firstKeys, pairKeys } = await replannedOwnBatch()
    const older = shared.apiFor("dev_test", "test-mac")
    older.on("GET", `/v1/adoptions/${adoption}`, () => {
      const { staged: _staged, ...status } = shared.statusOf(adoption)
      return status
    })
    const ref = again.items.find((i) => i.slug === "openai")?.ref as string
    const submitted = await submitPlan(input(again, home, [adoption]), context(older, home))
    expect(submitted.refused).toContainEqual({ ref, reason: "This row is already in the batch with different contents." })
    const recorded = (await readState(join(home, "state"))).adoptions[0]
    ;(shared.batches.get(adoption) as SharedBatch).status = "approved"
    const stored = storedSources([{ status: shared.statusOf(adoption), refs: recorded?.refs ?? null, sources: recorded?.sources ?? null }])
    expect(stored.get("openai")).toEqual(new Set(firstKeys))
    expect(pairKeys.some((k) => stored.get("openai")?.has(k))).toBe(false)
  })

  it("--join on a vault whose status does not name the staged rows sends every item and says a shared name may be refused", async () => {
    const office = await machine()
    const laptop = await machine()
    const shared = await sharedVault()
    const first = await submitPlan(input(office.plan, office.home), context(shared.apiFor("dev_office", "office"), office.home))
    const adoption = first.batches[0]?.adoption as string
    const laptopApi = shared.apiFor("dev_laptop", "laptop")
    laptopApi.on("GET", `/v1/adoptions/${adoption}`, () => {
      const { staged: _staged, ...older } = shared.statusOf(adoption)
      return older
    })
    const second = await submitPlan(input(laptop.plan, laptop.home, [adoption]), context(laptopApi, laptop.home))
    expect([second.shared, second.unchecked]).toEqual([[], [adoption]])
    expect(second.refused.map((r) => r.reason)).toEqual(["name not available", "name not available", "name not available"])
    expect(shared.misses.count).toBe(3)
  })

  // Seen in review: the older vault's refusal invites a retry once the vault
  // names its staged rows, and the refused ref recorded by the first try
  // was kept in place of the other machine's row. Now the retry sends each
  // name the other machine staged as a compare row of its own.
  it("a --join retried against a vault that names its staged rows sends the other machine's names as compare rows, and records their sources", async () => {
    const office = await machine()
    const laptop = await machine()
    const shared = await sharedVault()
    const first = await submitPlan(input(office.plan, office.home), context(shared.apiFor("dev_office", "office"), office.home))
    const adoption = first.batches[0]?.adoption as string
    const older = shared.apiFor("dev_laptop", "laptop")
    older.on("GET", `/v1/adoptions/${adoption}`, () => {
      const { staged: _staged, ...status } = shared.statusOf(adoption)
      return status
    })
    const refusedTry = await submitPlan(input(laptop.plan, laptop.home, [adoption]), context(older, laptop.home))
    expect(refusedTry.refused.map((r) => r.reason)).toEqual(["name not available", "name not available", "name not available"])
    const retry = await submitPlan(input(laptop.plan, laptop.home, [adoption]), context(shared.apiFor("dev_laptop", "laptop"), laptop.home))
    expect([retry.skipped.shared, retry.refused, retry.compared.length]).toEqual([0, [], 3])
    const ref = (slug: string) => laptop.plan.items.find((i) => i.slug === slug)?.ref as string
    const recorded = (await readState(join(laptop.home, "state"))).adoptions[0]
    expect(recorded?.refs?.[ref("openai-billing-api")]).toBe(batchRef(ref("openai-billing-api"), "dev_laptop"))
    expect(Object.keys(recorded?.sources ?? {}).sort()).toEqual(laptop.plan.items.map((i) => i.ref).sort())
  })

  // Seen in review: a machine whose device id changed re-submitted under a
  // new tag, and the refs the vault refused replaced the ones it took.
  it("a re-submit under another machine tag keeps the refs the vault took, and records new ones only once taken", async () => {
    const { home, plan } = await machine()
    const shared = await sharedVault()
    const first = await submitPlan(input(plan, home), context(shared.apiFor("dev_before", "test-mac"), home))
    const adoption = first.batches[0]?.adoption as string
    const before = (await readState(join(home, "state"))).adoptions[0]?.refs
    const after = shared.apiFor("dev_after", "test-mac")
    after.on("GET", `/v1/adoptions/${adoption}`, () => {
      const { staged: _staged, ...older } = shared.statusOf(adoption)
      return older
    })
    const again = await submitPlan(input(plan, home, [adoption]), context(after, home))
    expect(again.refused.map((r) => r.reason)).toEqual(["name not available", "name not available", "name not available"])
    expect((await readState(join(home, "state"))).adoptions[0]?.refs).toEqual(before)
    // Once the old rows are gone, the vault takes the new ones and they are recorded.
    ;(shared.batches.get(adoption) as SharedBatch).rows.clear()
    await submitPlan(input(plan, home, [adoption]), context(after, home))
    const now = (await readState(join(home, "state"))).adoptions[0]?.refs ?? {}
    expect(Object.entries(now).map(([planRef, ref]) => [planRef, ref])).toEqual(Object.keys(before ?? {}).map((planRef) => [planRef, batchRef(planRef, "dev_after")]))
  })

  it("--join refuses a batch where another machine has this machine's tag, and sends nothing", async () => {
    const { home, plan } = await machine()
    const shared = await sharedVault()
    let twin = 0
    while (machineTag(`dev_twin${twin}`, 3) !== machineTag("dev_test", 3)) twin++
    const theirs = shared.apiFor(`dev_twin${twin}`, "twin")
    await theirs.request("POST", "/v1/adoptions", {})
    const ours = shared.apiFor("dev_test", "test-mac")
    expect(submitPlan(input(plan, home, ["adp_test01"]), context(ours, home))).rejects.toThrow("Rows from this machine and from twin could share refs in adp_test01; nothing was sent.")
    await Bun.sleep(20)
    expect(ours.calls.some((c) => c.path === "/v1/adoptions/adp_test01/items" || c.path === "/v1/projects")).toBe(false)
  })

  it("a batch ref is a, three characters of the device's tag and the plan ref's digits; two when the digits are long", () => {
    const tag3 = machineTag("dev_test", 3)
    expect(batchRef("a001", "dev_test")).toBe(`a${tag3}001`)
    expect(batchRef("a0001", "dev_test")).toBe(`a${tag3}0001`)
    expect(batchRef("a00001", "dev_test")).toBe(`a${machineTag("dev_test", 2)}00001`)
    for (const ref of ["a001", "a0001", "a00001", "azzz"]) expect(batchRef(ref, "dev_test")).toMatch(ADOPTION_REF)
    expect(batchRef("a001", "dev_test")).not.toBe(batchRef("a001", "dev_other"))
  })

  // One MacBook plans 255 items, so four machines pass the 500 a batch holds.
  it("splits more than 500 items into batches of at most 500, each home whole, each sealed to its own batch and recorded as one submit", async () => {
    const { home, plan } = await machine()
    grow(plan, { project: 300, private: 320 })
    const shared = await sharedVault()
    const api = shared.apiFor("dev_test", "test-mac")
    const result = await submitPlan(input(plan, home), context(api, home))
    expect(result.batches.map((b) => [b.adoption, b.joined, b.uploaded.items])).toEqual([["adp_test01", false, 321], ["adp_test02", false, 302]])
    expect(result.refused).toEqual([])
    expect(api.calls.filter((c) => c.method === "POST" && c.path === "/v1/adoptions").map((c) => (c.body as { expectedItems: number }).expectedItems)).toEqual([321, 302])
    for (const id of ["adp_test01", "adp_test02"]) {
      const rows = (shared.batches.get(id) as SharedBatch).rows
      expect(new Set([...rows.values()].map(homeOf)).size).toBe(1)
      const [ref, row] = [...rows.entries()].at(-1) as [string, Row]
      expect(await openText(shared.keys.privateKey, row.item.sealed.key as SealedBox, adoptionSealContext(id, ref, "key"))).toBe(OPENAI)
    }
    expect(JSON.stringify(api.calls)).not.toContain("SENTINEL")
    const state = await readState(join(home, "state"))
    expect(state.adoptions.map((a) => [a.adoption, Object.keys(a.refs ?? {}).length])).toEqual([["adp_test01", 321], ["adp_test02", 302]])
    expect(new Set(state.adoptions.map((a) => a.submit)).size).toBe(1)
    // The first approved, the second still open.
    ;(shared.batches.get("adp_test01") as SharedBatch).status = "approved"
    const stored = storedItems(state.adoptions.map((a) => ({ status: shared.statusOf(a.adoption), refs: a.refs ?? null, sources: a.sources ?? null })))
    expect(stored.adoptions).toEqual(["adp_test01"])
    expect(stored.slugs.get(plan.items.find((i) => i.slug === "anthropic-local-secrets")?.ref as string)).toEqual(new Set(["anthropic-local-secrets"]))
    const openai = plan.items.find((i) => i.slug === "openai-billing-api")?.ref as string
    expect(mappedItem(plan, stored, openai)).toEqual({ why: "openai-billing-api is in adp_test02, which is not approved yet" })
  })

  it("--join fills the joined batches in order up to their room, each home whole, then opens a new batch for the rest", async () => {
    const { home, plan } = await machine()
    grow(plan, { project: 60, private: 40, workspace: 30 })
    const shared = await sharedVault()
    shared.create("dev_office", "office")
    shared.create("dev_mini", "mini")
    shared.fill("adp_test01", "dev_office", ADOPTION_LIMITS.maxItems - 50)
    shared.fill("adp_test02", "dev_mini", ADOPTION_LIMITS.maxItems - 70)
    const api = shared.apiFor("dev_test", "test-mac")
    const result = await submitPlan(input(plan, home, ["adp_test01", "adp_test02"]), context(api, home))
    expect(result.batches.map((b) => [b.adoption, b.joined, b.uploaded.items])).toEqual([["adp_test01", true, 41], ["adp_test02", true, 62], ["adp_test03", false, 30]])
    expect(result.refused).toEqual([])
    const mine = (id: string) => [...new Set([...(shared.batches.get(id) as SharedBatch).rows.values()].filter((r) => r.device === "dev_test").map(homeOf))]
    expect([mine("adp_test01"), mine("adp_test02"), mine("adp_test03")]).toEqual([["member"], ["project"], ["workspace"]])
    expect((shared.batches.get("adp_test01") as SharedBatch).rows.size).toBe(ADOPTION_LIMITS.maxItems - 9)
  })

  it("refuses, before any batch is opened, a plan needing more new batches than may be open at once", async () => {
    const { home, plan } = await machine()
    grow(plan, { project: 450, private: 450, workspace: 450 })
    const extra = plan.items.slice(-400).map((i, k) => ({ ...i, ref: `a${(5000 + k).toString(36)}`, slug: `extra-${k}`, home: { kind: "project" as const, project: "prj_other0001" } }))
    plan.items.push(...extra)
    const shared = await sharedVault()
    const api = shared.apiFor("dev_test", "test-mac")
    expect(submitPlan(input(plan, home), context(api, home))).rejects.toThrow(`The plan needs 4 new batches of at most ${ADOPTION_LIMITS.maxItems} items, and at most ${ADOPTION_LIMITS.maxOpenPerMember} can be open at once; nothing was sent.`)
    await Bun.sleep(50)
    expect(api.called("POST", "/v1/adoptions")).toBe(false)
  })

  it("cancels the batches it opened when the vault refuses the next one, and uploads nothing", async () => {
    const { home, plan } = await machine()
    grow(plan, { project: 450, private: 450 })
    const shared = await sharedVault()
    const api = shared.apiFor("dev_test", "test-mac")
    api.on("POST", "/v1/adoptions", () => {
      if (shared.batches.size > 0) throw new VaultApiError(429, { error: "rate_limited", message: "There are already 3 open adoption batches." })
      return shared.create("dev_test", "test-mac")
    })
    expect(submitPlan(input(plan, home), context(api, home))).rejects.toMatchObject({ status: 429 })
    await Bun.sleep(50)
    expect(shared.statusOf("adp_test01").status).toBe("cancelled")
    expect(api.calls.some((c) => /^\/v1\/adoptions\/.*\/items$/.test(c.path) || c.path === "/v1/projects")).toBe(false)
  })

  // Seen in review: once the batches were open, a failed upload left them
  // open, unlisted, and holding the member's room for open batches.
  it("when the second batch's upload fails, cancels the batches it opened and names every batch still open", async () => {
    const { home, plan } = await machine()
    grow(plan, { project: 60, private: 300 })
    const shared = await sharedVault()
    shared.create("dev_office", "office")
    shared.fill("adp_test01", "dev_office", ADOPTION_LIMITS.maxItems - 100)
    const api = shared.apiFor("dev_test", "test-mac")
    api.on("POST", "/v1/adoptions/adp_test02/items", () => {
      throw new VaultApiError(429, { error: "rate_limited", message: "Too many names were unavailable." })
    })
    const error = await submitPlan(input(plan, home, ["adp_test01"]), context(api, home)).then(
      () => null,
      (e: unknown) => e,
    )
    expect(error).toBeInstanceOf(SubmitStopped)
    const stopped = error as SubmitStopped
    expect(stopped.code).toBe("rate_limited")
    expect(stopped.message).toBe("The submit stopped after its batches were opened: Too many names were unavailable. This submit cancelled adp_test02, which it opened; adp_test01 is still open with 62 items from this machine (joined).")
    expect(stopped.open.map((b) => ({ ...b, url: String(b.url) }))).toEqual([{ adoption: "adp_test01", url: `${VAULT}/w/test-space/b/adp_test01`, expiresAt: "2026-11-02T10:00:00.000Z", joined: true, items: 62 }])
    expect([shared.statusOf("adp_test01").status, shared.statusOf("adp_test02").status]).toEqual(["open", "cancelled"])
    const recorded = (await readState(join(home, "state"))).adoptions
    expect(recorded.map((a) => a.adoption)).toEqual(["adp_test01"])
    // The rows adp_test01 took keep the sources recorded for them.
    expect(Object.keys(recorded[0]?.sources ?? {})).toHaveLength(62)
  })

  // Adopt reconcile: plan finds every project bound to a remote this machine
  // may use, so a remote the vault calls taken is one it cannot see.
  it("says to ask an owner or admin to share the project when the vault calls a repo's remote taken", async () => {
    const { home, plan } = await machine()
    const { api } = await vault()
    api.on("POST", "/v1/projects", () => {
      throw new VaultApiError(409, { error: "conflict", message: "That remote is taken." })
    })
    const error = (await submitPlan(input(plan, home), context(api, home)).catch((e: unknown) => e)) as SubmitStopped
    expect(error.message).toContain("The vault would not create project billing-api: the slug is taken, or github.com/acme/billing-api is already the remote of a project this machine cannot use")
    expect(error.next).toEqual({ command: "mehen adopt plan", say: "Ask an owner or admin to share the project with remote github.com/acme/billing-api with you, then plan again so this repo lands in it; or, if only the slug is taken, choose another slug for billing-api in the plan." })
  })

  it("a batch it opened and cannot cancel is named as still open", async () => {
    const { home, plan } = await machine()
    const shared = await sharedVault()
    const api = shared.apiFor("dev_test", "test-mac")
    api.on("POST", "/v1/projects", () => {
      throw new VaultApiError(500, { error: "internal", message: "The vault failed." })
    })
    api.on("POST", "/v1/adoptions/adp_test01/cancel", () => {
      throw new VaultApiError(500, { error: "internal", message: "The vault failed." })
    })
    const error = (await submitPlan(input(plan, home), context(api, home)).catch((e: unknown) => e)) as SubmitStopped
    expect(error.message).toBe("The submit stopped after its batches were opened: The vault failed. adp_test01 is still open with 0 items from this machine (opened by this submit, which could not cancel it).")
    expect(error.open.map((b) => [b.adoption, b.joined])).toEqual([["adp_test01", false]])
  })

  // Seen in review: a batch this run opened is on the member's pending list,
  // so another machine could join it before the failed run cancelled it.
  it("leaves open a batch it opened where another machine has staged rows, and names that machine", async () => {
    const { home, plan } = await machine()
    const shared = await sharedVault()
    const api = shared.apiFor("dev_test", "test-mac")
    api.on("POST", "/v1/projects", () => {
      shared.fill("adp_test01", "dev_office", 2)
      ;(shared.batches.get("adp_test01") as SharedBatch).names.set("dev_office", "office")
      throw new VaultApiError(500, { error: "internal", message: "The vault failed." })
    })
    const error = (await submitPlan(input(plan, home), context(api, home)).catch((e: unknown) => e)) as SubmitStopped
    expect(error.message).toBe("The submit stopped after its batches were opened: The vault failed. adp_test01 is still open with 0 items from this machine (opened by this submit; left open for office, which staged rows in it).")
    expect(error.open.map((b) => [b.adoption, b.joined, b.others])).toEqual([["adp_test01", false, ["office"]]])
    expect(api.called("POST", "/v1/adoptions/adp_test01/cancel")).toBe(false)
    expect(shared.statusOf("adp_test01").status).toBe("open")
    expect((await readState(join(home, "state"))).adoptions.map((a) => a.adoption)).toEqual(["adp_test01"])
  })

  it("a batch of another member is refused by the vault, and the refusal says so without a value", async () => {
    const { home, plan } = await machine()
    const { api } = await vault()
    api.on("GET", "/v1/adoptions/adp_other1", () => {
      throw new VaultApiError(403, { error: "forbidden", message: "This batch belongs to another member." })
    })
    expect(submitPlan(input(plan, home, ["adp_other1"]), context(api, home))).rejects.toMatchObject({ status: 403, body: { error: "forbidden" } })
  })

  it("refuses a private item on a machine no member owns, and a plan for another workspace", async () => {
    const { home, plan } = await machine()
    const { api, uploads } = await vault()
    api.on("GET", "/v1/projects/prj_billing01", () => ({ id: "prj_billing01", slug: "billing-api", remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }], vars: [] }))
    const ctx = context(api, home)
    const team = { ...ctx, config: { ...ctx.config, owner: { kind: "team" as const, team: "tm_ops00001", name: "Ops" } } }
    expect(submitPlan(input(plan, home), team)).rejects.toThrow("The plan has 1 problem")
    for (const repo of plan.repos) repo.project = { ...repo.project, id: "prj_billing01", create: false }
    const result = await submitPlan(input(plan, home), team)
    expect(result.refused.map((r) => r.reason)).toContain("a private home needs a machine owned by a member")
    expect(uploads.some((u) => u.home.kind === "member")).toBe(false)
    expect(submitPlan(input({ ...plan, workspace: "elsewhere" }, home), ctx)).rejects.toMatchObject({ code: "workspace_mismatch" })
  })

  it("chunks uploads under the body limit and 200 items", () => {
    const item = (ref: string, size: number): AdoptionItemUploadInput => ({ ref, slug: "x-slug", kind: "generic", provider: null, binding: null, injection: null, home: { kind: "workspace" }, tags: [], publicFields: {}, sealed: {}, sources: [{ path: "x".repeat(size), stale: [] }], repo: null })
    const sizes = chunkUploads(Array.from({ length: 450 }, (_, i) => item(`a${i.toString(36).padStart(3, "0")}`, 10))).map((c) => c.length)
    expect(sizes).toEqual([200, 200, 50])
    const big = chunkUploads(Array.from({ length: 5 }, (_, i) => item(`a00${i}`, 1000)), 2500)
    expect(big.map((c) => c.length)).toEqual([2, 2, 1])
    for (const chunk of big) expect(JSON.stringify({ items: chunk }).length).toBeLessThanOrEqual(2500)
  })
})
