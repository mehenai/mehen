import { afterEach, describe, expect, it } from "bun:test"
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import type { AdoptionStatus } from "@mehen/protocol/adopt"
import type { Project } from "@mehen/protocol/api"
import { writeNewFile } from "../backup/files.ts"
import type { SnapshotRecord } from "../backup/state.ts"
import { FakeVaultApi, tempDir } from "../run/fake-vault-api.ts"
import type { RunLogEntry } from "../run/run-log.ts"
import { type ApplyContext, applyPlan, storedItems } from "./apply.ts"
import { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, buildPlan } from "./plan.ts"
import { type Compared, NOT_INDEXED, QUARANTINE_DIR, QUARANTINE_INDEX, type RetireInputs, type RetireOptions, assessRetire, quarantine, retireFailed, retireFile, retireReport, unfinishedMoves, unretire } from "./retire.ts"
import { scan } from "./scan.ts"

const OPENAI = "sk-proj-SENTINELopenai0123456789abcdef"
const OPENAI_PROD = "sk-proj-SENTINELprod0123456789abcdefgh"
const SESSION = "SENTINEL-session-secret-0123456789"
const CI_TOKEN = "SENTINEL-ci-deploy-token-0123456789"
const VAULT = "https://vault.test"
const PROJECT = "prj_billing01"
const ENV_TEXT = `OPENAI_API_KEY=${OPENAI}\nSESSION_SECRET=${SESSION}\nLOG_LEVEL=debug\n`
const APPLIED = "2026-10-01T09:00:00.000Z"
const SNAPSHOT = "snp_test00000001"
const dirs: string[] = []
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

type Machine = { home: string; repo: string; env: string; ci: string; plan: AdoptPlan; ctx: ApplyContext; api: FakeVaultApi; adoptDir: string; inputs: RetireInputs; options: RetireOptions }

function run(root: string, at: string, exit: number | string = 0): RunLogEntry {
  return { at, endedAt: at, exit, root, project: PROJECT, env: "dev", service: false }
}

// What `mehen backup compare --json` says when every secret of the plan matched.
function comparedAll(plan: AdoptPlan, overrides: Partial<Compared> = {}): Compared {
  const secret = new Set(plan.items.filter((i) => i.include || i.exists).flatMap((i) => Object.values(i.fields).flatMap((f) => f.from)))
  const matching = Object.entries(plan.sources).flatMap(([id, s]) => (secret.has(id) ? [{ path: s.path, variable: s.variable, pointer: s.pointer, item: "x", field: "x" }] : []))
  return { snapshot: SNAPSHOT, export: "bkx_test0001", exportedAt: "2026-10-06T09:00:00.000Z", matching, different: [], missing: [], ...overrides }
}

// A machine whose batch was approved and applied, whose repo ran cleanly
// under mehen run over four days, with a snapshot holding every file and a
// compare that matched: its .env is ready.
async function machine(): Promise<Machine> {
  const home = realpathSync(tempDir("mehen-adopt-retire-"))
  dirs.push(home)
  const repo = join(home, "code", "billing-api")
  mkdirSync(repo, { recursive: true })
  mkdirSync(join(home, ".local-secrets"))
  Bun.spawnSync(["git", "init", "-q"], { cwd: repo })
  Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/billing-api"], { cwd: repo })
  const env = join(repo, ".env")
  writeFileSync(env, ENV_TEXT)
  chmodSync(env, 0o640)
  writeFileSync(join(repo, ".env.production"), `OPENAI_API_KEY=${OPENAI_PROD}\n`)
  const ci = join(home, ".local-secrets", "ci.env")
  writeFileSync(ci, `CI_DEPLOY_TOKEN=${CI_TOKEN}\n`)
  const guard = new OutputGuard()
  const result = await scan({ home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 3 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard })
  const plan = buildPlan(result, { workspace: "test-space", vault: VAULT, machine: "test-mac", home, visibleItems: new Map(), homes: new Map(), existing: new Map(), storedSlugs: new Map(), unappliedSlugs: new Map(), sharedValues: "per-project" })
  const project: Project = { id: PROJECT, slug: "billing-api", remotes: ["github.com/acme/billing-api"], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }, { name: "prod", protected: true, fences: [] }], vars: [] }
  const api = new FakeVaultApi().on("GET", `/v1/projects/${PROJECT}`, () => project)
  for (const name of ["OPENAI_API_KEY", "SESSION_SECRET", "LOG_LEVEL", "EXTRA_TOKEN"]) {
    api.on("PUT", `/v1/projects/${PROJECT}/vars/${name}`, (body) => {
      const { env: e, item, field, plain } = body as { env: string; item?: string; field?: string; plain?: string }
      project.vars = [...project.vars.filter((v) => !(v.name === name && v.env === e)), { name, env: e, source: plain !== undefined ? "plain" : "item", item: item ?? null, field: field ?? null }]
      return project
    })
  }
  api.relayHandler = () => new Response(null, { status: 200, headers: { "Mehen-Upstream": "1" } })
  const ctx: ApplyContext = { api, config: { vault: VAULT, tenant: "tn_test00000001", device: "dev_test", workspaceSlug: "test-space" }, guard, home, projects: { "billing-api": PROJECT } }
  const created = plan.items.filter((i) => i.include).map((i) => ({ ref: i.ref, slug: i.slug }))
  const status: AdoptionStatus = { adoption: "adp_test01", status: "approved", expiresAt: "2026-11-02T10:00:00.000Z", machines: [], created, refused: [] }
  const stored = storedItems([{ status, refs: null, sources: null }])
  await applyPlan(plan, stored, ctx, { repos: null, env: null, dryRun: false })
  const files = [...new Set(Object.values(plan.sources).map((s) => s.path))]
  // Taken after the files were written: a snapshot from before would see them as changed.
  const snapshot: SnapshotRecord = { id: SNAPSHOT, archive: join(home, "Backups", `${SNAPSHOT}.age`), planPath: join(home, "plan.json"), planDigest: "0".repeat(64), paths: files, createdAt: new Date(Date.now() + 3_600_000).toISOString(), selfCheck: "passed" }
  const inputs: RetireInputs = {
    plan,
    planPath: join(home, "plan.json"),
    stored,
    batches: [{ adoption: "adp_test01", planRefs: new Set(created.map((c) => c.ref)), appliedAt: APPLIED }],
    snapshots: [snapshot],
    runs: [run(repo, "2026-10-02T09:00:00.000Z"), run(repo, "2026-10-03T09:00:00.000Z"), run(repo, "2026-10-05T09:00:00.000Z")],
    compared: { path: join(home, "compare.json"), result: comparedAll(plan) },
  }
  const options: RetireOptions = { repos: [], paths: [], minRuns: 3, minDays: 2, now: new Date("2026-10-07T09:00:00.000Z"), session: null }
  return { home, repo, env, ci, plan, ctx, api, adoptDir: join(home, "mehen", "adopt", "test-mac"), inputs, options }
}

// Every line of the quarantine index, parsed.
function indexLines(adoptDir: string): Record<string, unknown>[] {
  return readFileSync(join(adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX), "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

// The newest line for a quarantined file, which ends its move.
function quarantinedLine(adoptDir: string): Record<string, unknown> {
  const line = indexLines(adoptDir).filter((l) => "ino" in l).at(-1)
  if (line === undefined) throw new Error("no file is in quarantine")
  return line
}

function quarantinedPath(adoptDir: string): string {
  return quarantinedLine(adoptDir).quarantined as string
}

function filesUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? filesUnder(join(dir, e.name)) : [join(dir, e.name)]))
}

// No value, part of one, or hash of a moved file's bytes in anything retire
// wrote under the adopt dir, the quarantined copies themselves aside.
function expectNoValueUnder(adoptDir: string, contents: readonly string[]): void {
  const index = join(adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
  const needles = contents.map((c) => new Bun.CryptoHasher("sha256").update(c).digest("hex"))
  for (const value of [OPENAI, SESSION, CI_TOKEN]) for (let i = 0; i + 6 <= value.length; i++) needles.push(value.slice(i, i + 6))
  const written = filesUnder(adoptDir).filter((f) => f === index || !f.startsWith(join(adoptDir, QUARANTINE_DIR)))
  expect(written).toContain(index)
  for (const file of written) for (const needle of needles) expect(readFileSync(file, "utf8").includes(needle), `${file}: ${needle}`).toBe(false)
  expect(readFileSync(index, "utf8")).not.toMatch(/"sha256"\s*:/)
}

async function reasonsFor(m: Machine, path: string, options: Partial<RetireOptions> = {}): Promise<{ state: string; reasons: string[]; notes: string[] }> {
  const { files } = await assessRetire(m.inputs, m.ctx, { ...m.options, ...options })
  const file = files.find((f) => f.path === path)
  if (!file) throw new Error(`${path} was not listed`)
  return { state: file.state, reasons: file.reasons, notes: file.notes }
}

describe("adopt retire, without --yes", () => {
  it("lists every source file as ready or held, with each reason, and changes nothing", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const report = retireReport(files, [])
    expect(report.files.map((f) => [f.path, f.state])).toEqual([
      [m.ci, "held"],
      [m.env, "ready"],
      [join(m.repo, ".env.production"), "held"],
    ])
    expect(report.files.find((f) => f.path === join(m.repo, ".env.production"))?.reasons).toEqual([
      "1 name would be lost: OPENAI_API_KEY (does not resolve for env=prod)",
      `mehen env check --env prod does not pass in ${m.repo}: OPENAI_API_KEY, SESSION_SECRET, LOG_LEVEL do not resolve`,
    ])
    expect(report).toMatchObject({ moved: 0, held: 2 })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(existsSync(m.adoptDir)).toBe(false)
    expect(JSON.stringify(report)).not.toContain("SENTINEL")
  })

  it("--repo and --path select the files listed", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, { ...m.options, paths: [m.ci] })
    expect(files.map((f) => f.path)).toEqual([m.ci])
    const repo = await assessRetire(m.inputs, m.ctx, { ...m.options, repos: [m.repo] })
    expect(repo.files.map((f) => f.path)).toEqual([m.env, join(m.repo, ".env.production")])
  })
})

describe("adopt retire holds a file, each reason on its own", () => {
  it("a file that is not a .env or NAME=value lines", async () => {
    const m = await machine()
    for (const source of Object.values(m.plan.sources)) if (source.path === m.env) source.type = "envrc"
    expect(await reasonsFor(m, m.env)).toMatchObject({ state: "held", reasons: ["edit by hand: a .envrc is a script direnv runs; take the exports out of it yourself"] })
  })

  it("a symbolic link", async () => {
    const m = await machine()
    const elsewhere = join(m.home, "elsewhere.env")
    writeFileSync(elsewhere, ENV_TEXT)
    rmSync(m.env)
    symlinkSync(elsewhere, m.env)
    const held = await reasonsFor(m, m.env)
    expect(held.reasons[0]).toBe("it is a symbolic link; retire moves only a regular file")
  })

  // Seen in review: the quarantined copy shared its inode with the file's
  // other names, so its 0600 mode and any edit through them reached it.
  it("a file with other hard links", async () => {
    const m = await machine()
    linkSync(m.env, join(m.home, "billing.env"))
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["it has other names (1 more hard link); retire moves only a file with one, since the others would share the quarantined copy"])
  })

  it("a file git tracks", async () => {
    const m = await machine()
    Bun.spawnSync(["git", "add", "-f", ".env"], { cwd: m.repo })
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["this file is committed; rotate these values instead"])
  })

  it("a file changed since the snapshot holding it, or one no snapshot holds", async () => {
    const m = await machine()
    const snapshot = m.inputs.snapshots[0] as SnapshotRecord
    m.inputs.snapshots = [{ ...snapshot, createdAt: "2026-01-01T00:00:00.000Z" }]
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`it changed after snapshot ${SNAPSHOT} was taken; take a new snapshot: mehen backup snapshot --plan ${m.inputs.planPath} --to <dir outside your repos> --recipient <age1...>, then export and compare again`])
    m.inputs.snapshots = []
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`no snapshot on this machine holds it; take a new snapshot: mehen backup snapshot --plan ${m.inputs.planPath} --to <dir outside your repos> --recipient <age1...>`])
  })

  it("a gap: a name Mehen does not provide", async () => {
    const m = await machine()
    writeFileSync(m.env, `${ENV_TEXT}EXTRA_TOKEN=SENTINEL-extra-0123456789\n`)
    const held = await reasonsFor(m, m.env)
    expect(held.reasons).toEqual(["1 name would be lost: EXTRA_TOKEN (not in the plan)"])
    expect(JSON.stringify(held)).not.toContain("SENTINEL")
  })

  it("a name the human left out of Mehen", async () => {
    const m = await machine()
    const session = m.plan.items.find((i) => i.slug === "session-secret-billing-api") as AdoptPlan["items"][number]
    session.include = false
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["1 name is not in Mehen: SESSION_SECRET (session-secret-billing-api is not included in the plan)"])
  })

  it("a failed live check", async () => {
    const m = await machine()
    m.api.relayHandler = () => new Response(null, { status: 401, headers: { "Mehen-Upstream": "1" } })
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["the live check of openai-billing-api failed: GET /v1/models answered 401"])
  })

  it("too few clean runs, runs too close together, or a newest run that failed", async () => {
    const m = await machine()
    const runs = m.inputs.runs
    m.inputs.runs = runs.slice(0, 2)
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`2 clean runs under mehen run in ${m.repo} since adp_test01 was applied; 3 needed`])
    m.inputs.runs = [run(m.repo, "2026-10-02T09:00:00.000Z"), run(m.repo, "2026-10-02T15:00:00.000Z"), run(m.repo, "2026-10-03T08:00:00.000Z")]
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`the clean runs in ${m.repo} since adp_test01 was applied span 1.0 days; 2 days needed between the first and the last`])
    m.inputs.runs = [...runs, run(m.repo, "2026-10-06T09:00:00.000Z", "SIGTERM")]
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`the newest run in ${m.repo}, at 2026-10-06T09:00:00.000Z, exited SIGTERM`])
    // A crash after mehen run passed on a stop is not clean either.
    m.inputs.runs = [...runs, { ...run(m.repo, "2026-10-06T09:00:00.000Z", "SIGSEGV"), signal: "SIGTERM", forwarded: true }]
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`the newest run in ${m.repo}, at 2026-10-06T09:00:00.000Z, exited SIGSEGV`])
    // Runs before the batch was applied do not count.
    m.inputs.runs = runs.map((r) => ({ ...r, at: r.at.replace("2026-10", "2026-09") }))
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`0 clean runs under mehen run in ${m.repo} since adp_test01 was applied; 3 needed`])
  })

  // Seen in review: a dev server stopped with Ctrl-C, or a service its
  // manager stopped, never counted, so its .env was held for ever.
  it("a run whose child ended on a SIGINT or SIGTERM mehen run passed on from its parent counts as clean", async () => {
    const m = await machine()
    const stopped = (at: string, signal: "SIGINT" | "SIGTERM", exit: number | string = signal): RunLogEntry => ({ ...run(m.repo, at, exit), signal, forwarded: true })
    m.inputs.runs = [stopped("2026-10-02T09:00:00.000Z", "SIGINT"), stopped("2026-10-03T09:00:00.000Z", "SIGTERM"), stopped("2026-10-05T09:00:00.000Z", "SIGINT", 130)]
    expect(await reasonsFor(m, m.env)).toMatchObject({ state: "ready", reasons: [] })
  })

  it("a batch applied before this machine recorded when", async () => {
    const m = await machine()
    m.inputs.batches = m.inputs.batches.map((b) => ({ ...b, appliedAt: null }))
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["this machine has no record of when adp_test01 was applied; run mehen adopt apply again (it changes nothing already set)"])
  })

  it("a file no program reads under mehen run, unless --path says nothing reads it", async () => {
    const m = await machine()
    expect((await reasonsFor(m, m.ci)).reasons).toEqual([`nothing runs these under mehen run yet; switch the program that reads ${m.ci} to mehen run first`])
    expect(await reasonsFor(m, m.ci, { paths: [m.ci] })).toEqual({ state: "ready", reasons: [], notes: ["named with --path: not checked for runs under mehen run, since you say nothing reads it any more"] })
  })

  it("no compare, a compare from an older mehen, of another snapshot, of an export older than the batch, or one that differs", async () => {
    const m = await machine()
    const compared = m.inputs.compared as NonNullable<RetireInputs["compared"]>
    m.inputs.compared = null
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`no backup compare: take an export with mehen backup export --to <dir>, save mehen adopt status adp_test01 --json > adoption.json, then on the key machine run mehen backup compare ${join(m.home, "Backups", `${SNAPSHOT}.age`)} <export>.age --identity - --map adoption.json --json > compare.json and give it with --compared compare.json`])
    const { exportedAt: _at, matching: _matching, ...old } = compared.result
    m.inputs.compared = { ...compared, result: old }
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`${compared.path} is from an older mehen; run mehen backup compare --json again with this one`])
    m.inputs.compared = { ...compared, result: { ...compared.result, snapshot: "snp_other0000001" } }
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`the compare used snapshot snp_other0000001, not ${SNAPSHOT}, the newest snapshot holding this file; compare again with ${join(m.home, "Backups", `${SNAPSHOT}.age`)}`])
    m.inputs.compared = { ...compared, result: { ...compared.result, exportedAt: "2026-09-30T09:00:00.000Z" } }
    expect((await reasonsFor(m, m.env)).reasons).toEqual([`export bkx_test0001 was taken at 2026-09-30T09:00:00.000Z, before adp_test01 was applied at ${APPLIED}; take a new export and compare again`])
    const openai = (compared.result.matching ?? []).find((s) => s.path === m.env && s.variable === "OPENAI_API_KEY") as NonNullable<Compared["matching"]>[number]
    const rest = (compared.result.matching ?? []).filter((s) => s !== openai)
    m.inputs.compared = { ...compared, result: { ...compared.result, matching: rest, different: [openai] } }
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["OPENAI_API_KEY differs from Mehen in export bkx_test0001"])
    m.inputs.compared = { ...compared, result: { ...compared.result, matching: rest, missing: [{ ...openai, why: "not in this export" }] } }
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["the compare could not check OPENAI_API_KEY: not in this export"])
    m.inputs.compared = { ...compared, result: { ...compared.result, matching: rest } }
    expect((await reasonsFor(m, m.env)).reasons).toEqual(["the compare did not check OPENAI_API_KEY; compare with the map of the batch that holds it"])
  })
})

describe("adopt retire --yes and unretire", () => {
  it("moves a ready file to quarantine, writes its index line, and unretire puts it back byte for byte with its mode", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const report = retireReport(files, await unfinishedMoves(m.adoptDir))
    expect(report).toMatchObject({ moved: 1, held: 2, unfinished: [] })
    expect(retireFailed(report)).toBe(false)
    expect(existsSync(m.env)).toBe(false)
    const moved = files.find((f) => f.path === m.env)
    const to = (moved?.notes.find((n) => n.startsWith("moved to ")) ?? "").slice("moved to ".length)
    expect(to).toMatch(new RegExp(`^${join(m.adoptDir, QUARANTINE_DIR, "2026-10-07")}/[0-9a-f]{16}/\\.env$`))
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(to).mode & 0o777).toBe(0o600)
    for (const dir of [join(m.adoptDir, QUARANTINE_DIR), join(m.adoptDir, QUARANTINE_DIR, "2026-10-07")]) expect(lstatSync(dir).mode & 0o777).toBe(0o700)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const [moving, line, ...rest] = indexLines(m.adoptDir) as [Record<string, unknown>, { refs: string[] }]
    expect(rest).toEqual([])
    expect(moving).toEqual({ moving: expect.stringMatching(/^mv_/), path: m.env, aside: expect.stringMatching(new RegExp(`^${m.repo}/\\.\\.env\\.retiring_`)), quarantined: to, at: "2026-10-07T09:00:00.000Z" })
    const refs = m.plan.items.filter((i) => i.slug === "openai-billing-api" || i.slug === "session-secret-billing-api").map((i) => i.ref).sort()
    const held = lstatSync(to)
    expect({ ...line, refs: [...line.refs].sort() } as unknown).toEqual({ path: m.env, quarantined: to, dev: held.dev, ino: held.ino, mtimeMs: held.mtimeMs, ctimeMs: held.ctimeMs, mode: 0o640, at: "2026-10-07T09:00:00.000Z", adoption: "adp_test01", refs, ended: moving.moving })
    expect(lstatSync(index).mode & 0o777).toBe(0o600)
    expectNoValueUnder(m.adoptDir, [ENV_TEXT])

    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date("2026-10-08T09:00:00.000Z"), guard: m.ctx.guard })
    expect(back).toEqual({ files: [{ path: m.env, state: "restored", reasons: [], quarantined: to }], restored: 1, refused: 0, unfinished: [] })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(m.env).mode & 0o777).toBe(0o640)
    expect(existsSync(to)).toBe(false)
    expect(indexLines(m.adoptDir).at(-1)).toEqual({ restored: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: to })
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard })).files[0]?.reasons).toEqual(["it is not in quarantine"])
  })

  it("across volumes it renames the original aside, copies it, reads the copy back, then unlinks it", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const links: string[] = []
    const crossDevice = {
      link: async (from: string) => {
        links.push(from)
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: crossDevice })
    expect(links).toHaveLength(1)
    expect(links[0]).toMatch(new RegExp(`^${m.repo}/\\.\\.env\\.retiring_`))
    expect(files.find((f) => f.path === m.env)?.state).toBe("moved")
    expect(existsSync(m.env)).toBe(false)
    const to = quarantinedPath(m.adoptDir)
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(to).mode & 0o777).toBe(0o600)
    expectNoValueUnder(m.adoptDir, [ENV_TEXT])
    const back = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard, fs: crossDevice })
    expect(back.restored).toBe(1)
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(m.env).mode & 0o777).toBe(0o640)
  })

  // Seen in review: unretire renamed the quarantined copy to a hidden name
  // before copying it, so a crash during the copy left it where nothing named it.
  it("across volumes, unretire copies straight from the quarantined copy, which stays where the index says until the copy is read back", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    let atCrash: string[] = []
    const crossDevice = {
      link: async () => {
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
      // The state a crash during the copy leaves.
      writeNewFile: async (path: string, bytes: Uint8Array, attributes?: { mode?: number }) => {
        atCrash = readdirSync(dirname(to))
        await writeNewFile(path, bytes, attributes)
      },
    }
    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: crossDevice })
    expect(atCrash).toEqual([".env"])
    expect(back.files).toEqual([{ path: m.env, state: "restored", reasons: [], quarantined: to }])
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(m.env).mode & 0o777).toBe(0o640)
    expect(readdirSync(dirname(to))).toEqual([])
  })

  it("across volumes, a file an editor saves over as it moves is never deleted: the new file stays where it was", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const saved = `${ENV_TEXT}SAVED=1\n`
    const editorSaves = {
      link: async () => {
        // An editor writes a temp file and renames it over the original.
        writeFileSync(`${m.env}.swp`, saved)
        renameSync(`${m.env}.swp`, m.env)
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: editorSaves })
    const to = quarantinedPath(m.adoptDir)
    expect(files.find((f) => f.path === m.env)).toMatchObject({ state: "moved", reasons: [], notes: [`moved to ${to}`] })
    expect(readFileSync(m.env, "utf8")).toBe(saved)
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(readdirSync(m.repo).filter((n) => n.startsWith(".env")).sort()).toEqual([".env", ".env.production"])
  })

  // Seen in review: a hard link at the new path then an unlink of the
  // original deleted whatever had been saved at the original path between.
  it("on one volume, a file an editor saves over as it moves is never deleted: the new file stays where it was", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const saved = `${ENV_TEXT}SAVED=1\n`
    const editorSaves = {
      link: async (from: string, to: string) => {
        linkSync(from, to)
        writeFileSync(`${m.env}.swp`, saved)
        renameSync(`${m.env}.swp`, m.env)
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: editorSaves })
    const to = quarantinedPath(m.adoptDir)
    expect(files.find((f) => f.path === m.env)).toMatchObject({ state: "moved", reasons: [], notes: [`moved to ${to}`] })
    expect(readFileSync(m.env, "utf8")).toBe(saved)
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(readdirSync(m.repo).filter((n) => n.startsWith(".env")).sort()).toEqual([".env", ".env.production"])
  })

  // Seen in review: the move read the file again itself, so a change after
  // retire's last check moved values no check had seen.
  it("the move takes only the file retire checked last: one changed since is left where it was", async () => {
    const m = await machine()
    const checked = lstatSync(m.env)
    writeFileSync(m.env, "# edited\n", { flag: "a" })
    const to = join(m.home, "quarantined.env")
    const aside = join(m.repo, ".env.aside")
    await expect(retireFile(m.env, aside, to, checked)).rejects.toThrow(`${m.env} changed while it was being moved`)
    expect(readFileSync(m.env, "utf8")).toBe(`${ENV_TEXT}# edited\n`)
    expect(existsSync(to)).toBe(false)
    expect(readdirSync(m.repo).filter((n) => n.startsWith(".env")).sort()).toEqual([".env", ".env.production"])
    const unchanged = lstatSync(m.env)
    expect(await retireFile(m.env, aside, to, unchanged)).toEqual([])
    expect(readFileSync(to, "utf8")).toBe(`${ENV_TEXT}# edited\n`)
    expect(existsSync(m.env)).toBe(false)
  })

  it("a file is not moved when the quarantine index cannot record its move", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    mkdirSync(join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX), { recursive: true })
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    expect(files.find((f) => f.path === m.env)).toMatchObject({ state: "failed", reasons: ["the quarantine index could not record the move (EISDIR)"], notes: [] })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(readdirSync(m.repo).filter((n) => n.startsWith(".env")).sort()).toEqual([".env", ".env.production"])
  })

  // Seen in review: a crash between the steps of a move left the original
  // renamed aside, or in quarantine, with nothing in the index naming it.
  it("a move a crash cut short is named by retire, even without --yes, and by unretire, with where the file is", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    let atCrash = ""
    const recordsTheIndex = {
      link: async (from: string, to: string) => {
        atCrash = readFileSync(index, "utf8")
        linkSync(from, to)
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: recordsTheIndex })
    // The state a crash just before the link leaves: the original renamed
    // aside, and only the line saying its move began.
    const moving = JSON.parse(atCrash.trim()) as { moving: string; aside: string; quarantined: string }
    expect(atCrash.trim().split("\n")).toHaveLength(1)
    renameSync(moving.quarantined, moving.aside)
    writeFileSync(index, atCrash)
    const then = `then delete the line with "moving":"${moving.moving}" from ${index}`
    const aside = { path: m.env, at: "2026-10-07T09:00:00.000Z", aside: moving.aside, quarantined: moving.quarantined, note: `a move of ${m.env} begun at 2026-10-07T09:00:00.000Z never finished: the original is at ${moving.aside}; move it back to ${m.env} by hand, ${then}` }
    expect(await unfinishedMoves(m.adoptDir)).toEqual([aside])
    expect(await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).toEqual({ files: [], restored: 0, refused: 0, unfinished: [aside] })
    // A crash after the link instead: the file in quarantine with no line for it.
    renameSync(moving.aside, moving.quarantined)
    expect((await unfinishedMoves(m.adoptDir))[0]?.note).toBe(`a move of ${m.env} begun at 2026-10-07T09:00:00.000Z never finished: it is at ${moving.quarantined}, which unretire cannot put back; move it to ${m.env} by hand, ${then}`)
    expect(readFileSync(moving.quarantined, "utf8")).toBe(ENV_TEXT)
  })

  it("a move that fails with the original put back leaves no unfinished move", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const refuses = {
      link: async () => {
        throw Object.assign(new Error("operation not permitted"), { code: "EPERM" })
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: refuses })
    expect(files.find((f) => f.path === m.env)).toMatchObject({ state: "failed", reasons: ["operation not permitted"], notes: [] })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(indexLines(m.adoptDir).map((l) => Object.keys(l)[0])).toEqual(["moving", "ended"])
    expect(await unfinishedMoves(m.adoptDir)).toEqual([])
  })

  // Seen in review: a move whose ending line could not be written was
  // later reported as a file in neither place, though it never left its path.
  it("a move that never began, whose ending line could not be written, is named as one that looks never to have moved", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const refusesAndLocksTheIndex = {
      link: async () => {
        chmodSync(index, 0o400)
        throw Object.assign(new Error("operation not permitted"), { code: "EPERM" })
      },
    }
    try {
      await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: refusesAndLocksTheIndex })
    } finally {
      chmodSync(index, 0o600)
    }
    expect(files.find((f) => f.path === m.env)).toMatchObject({ state: "failed", reasons: ["operation not permitted"], notes: [] })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    const [moving, ...rest] = indexLines(m.adoptDir) as [{ moving: string; aside: string; quarantined: string }]
    expect(rest).toEqual([])
    expect((await unfinishedMoves(m.adoptDir))[0]?.note).toBe(`a move of ${m.env} begun at 2026-10-07T09:00:00.000Z never finished: it looks never to have moved, since ${m.env} is there and neither ${moving.aside} nor ${moving.quarantined} is; make sure ${m.env} is the file you expect, then delete the line with "moving":"${moving.moving}" from ${index}`)
  })

  it("a file that moved is reported moved, with a note naming where it is, and retire fails, when the index line cannot be written", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const indexBreaks = {
      link: async (from: string, to: string) => {
        linkSync(from, to)
        rmSync(index)
        mkdirSync(index)
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: indexBreaks })
    const file = files.find((f) => f.path === m.env)
    expect(existsSync(m.env)).toBe(false)
    expect(file?.state).toBe("moved")
    const to = (file?.notes[0] ?? "").slice("moved to ".length)
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(file?.notes).toEqual([`moved to ${to}`, `${NOT_INDEXED} (EISDIR); if mehen adopt unretire ${m.env} does not put it back, move ${to} to ${m.env} by hand`])
    expect(retireReport(files, [])).toMatchObject({ moved: 1 })
    expect(retireFailed(retireReport(files, []))).toBe(true)
  })

  it("a file whose bytes differ once linked is reported moved, with its index line and a note naming where it is", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    const changesAsItMoves = {
      link: async (from: string, to: string) => {
        linkSync(from, to)
        writeFileSync(to, "# edited\n", { flag: "a" })
      },
    }
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard, fs: changesAsItMoves })
    const file = files.find((f) => f.path === m.env)
    const to = quarantinedPath(m.adoptDir)
    expect(file).toMatchObject({ state: "moved", reasons: [], notes: [`moved to ${to}`, `${m.env} changed as it moved; compare ${to} with what you expect by hand`] })
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard })).restored).toBe(1)
  })

  it("a file that changed after it was checked is not moved, and the others still are", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, { ...m.options, paths: [m.ci, m.env] })
    expect(files.map((f) => f.state)).toEqual(["ready", "ready"])
    writeFileSync(m.env, `${ENV_TEXT}# edited\n`)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    expect(files.map((f) => [f.path, f.state])).toEqual([[m.ci, "moved"], [m.env, "failed"]])
    expect(files[1]?.reasons).toEqual(["it changed while retire ran; run retire again"])
    expect(readFileSync(m.env, "utf8")).toBe(`${ENV_TEXT}# edited\n`)
    expect(existsSync(m.ci)).toBe(false)
  })

  // Seen in review: unretire rewrote the index, so a line a retire added
  // between its read and its rename was lost.
  it("unretire only adds a restored line to the index, leaving every line before it as it was", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const [moving, ours] = readFileSync(index, "utf8").trim().split("\n") as [string, string]
    const newer = JSON.stringify({ ...JSON.parse(ours), path: join(m.home, "elsewhere", ".env"), from: "a newer mehen" })
    // A line an older unretire rewrote with restored in it is still read as put back.
    const rewritten = JSON.stringify({ ...JSON.parse(ours), path: join(m.home, "older", ".env"), restored: "2026-10-07T10:00:00.000Z" })
    const before = `not json\n${moving}\n${ours}\n${newer}\n${rewritten}\n`
    writeFileSync(index, before)
    const back = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date("2026-10-08T09:00:00.000Z"), guard: m.ctx.guard })
    expect(back.files.map((f) => [f.path, f.state])).toEqual([[m.env, "restored"]])
    expect(readFileSync(index, "utf8")).toBe(`${before}${JSON.stringify({ restored: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: to })}\n`)
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([])
  })

  it("a file retired again to the same quarantine path after unretire put it back can be put back again", async () => {
    const m = await machine()
    const retireOnce = async () => {
      const { files } = await assessRetire(m.inputs, m.ctx, m.options)
      await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
      expect(files.find((f) => f.path === m.env)?.state).toBe("moved")
    }
    await retireOnce()
    const to = quarantinedPath(m.adoptDir)
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard })).restored).toBe(1)
    await retireOnce()
    expect(quarantinedPath(m.adoptDir)).toBe(to)
    const again = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })
    expect(again.files).toEqual([{ path: m.env, state: "restored", reasons: [], quarantined: to }])
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
  })

  // Seen in review: unretire rewrote the index from what it read at the
  // start, so a line a retire added meanwhile was lost.
  it("unretire keeps an index line added while it ran", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const added = JSON.stringify({ ...quarantinedLine(m.adoptDir), path: join(m.home, "elsewhere", ".env") })
    const retireAppends = {
      link: async (from: string, to: string) => {
        linkSync(from, to)
        writeFileSync(index, `${added}\n`, { flag: "a" })
      },
    }
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date("2026-10-08T09:00:00.000Z"), guard: m.ctx.guard, fs: retireAppends })).restored).toBe(1)
    expect(readFileSync(index, "utf8").trim().split("\n").slice(-2)).toEqual([added, JSON.stringify({ restored: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: quarantinedPath(m.adoptDir) })])
  })

  it("unretire still reports a file it put back when the index cannot mark it restored, with a note saying so", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const to = quarantinedPath(m.adoptDir)
    const indexLocks = {
      link: async (from: string, dest: string) => {
        linkSync(from, dest)
        chmodSync(index, 0o400)
      },
    }
    try {
      const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: indexLocks })
      expect(back.files).toEqual([{ path: m.env, state: "restored", reasons: [`${m.env} is back, but the quarantine index could not mark it restored (EACCES), so unretire still lists it`], quarantined: to }])
    } finally {
      chmodSync(index, 0o600)
    }
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(indexLines(m.adoptDir).filter((l) => "restored" in l)).toEqual([])
  })

  it("unretire never overwrites a file that appears at the original path as it moves", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const appears = (path: string) => writeFileSync(path, "NEW=1\n")
    // Whichever call moves the file, something is written at its new path just before.
    const fs = {
      rename: async (from: string, dest: string) => {
        appears(dest)
        renameSync(from, dest)
      },
      link: async (from: string, dest: string) => {
        appears(dest)
        linkSync(from, dest)
      },
    }
    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs })
    expect(back.files[0]).toMatchObject({ state: "refused", reasons: [`something is already at ${m.env}`] })
    expect(readFileSync(m.env, "utf8")).toBe("NEW=1\n")
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
  })

  // Seen in review: once the link was made, a file renamed over the
  // original path was unlinked as if it were mehen's own.
  it("unretire never deletes a file renamed over the original path once its link is made, and leaves the copy in quarantine", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const editorSaves = {
      link: async (from: string, dest: string) => {
        linkSync(from, dest)
        writeFileSync(`${dest}.swp`, "NEW=1\n")
        renameSync(`${dest}.swp`, dest)
      },
    }
    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: editorSaves })
    expect(back.files).toEqual([{ path: m.env, state: "refused", reasons: [`something other than ${to} appeared at ${m.env} as it was put back; ${m.env} is left as it is and the copy is kept in quarantine, but unretire will not put it back now: once ${m.env} is sorted, move ${to} there by hand`], quarantined: to }])
    expect(readFileSync(m.env, "utf8")).toBe("NEW=1\n")
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(quarantinedLine(m.adoptDir).restored).toBeUndefined()
  })

  it("across volumes, unretire never deletes a file renamed over the original path as it copies, and keeps the copy in quarantine", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const editorSaves = {
      link: async () => {
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
      writeNewFile: async (path: string, bytes: Uint8Array, attributes?: { mode?: number }) => {
        await writeNewFile(path, bytes, attributes)
        writeFileSync(`${path}.swp`, "NEW=1\n")
        renameSync(`${path}.swp`, path)
      },
    }
    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: editorSaves })
    expect(back.files).toEqual([{ path: m.env, state: "refused", reasons: [`${m.env} does not read back as ${to} was, so ${to} is kept in quarantine; compare them by hand`], quarantined: to }])
    expect(readFileSync(m.env, "utf8")).toBe("NEW=1\n")
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(indexLines(m.adoptDir).filter((l) => "restored" in l)).toEqual([])
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files.map((f) => [f.path, f.quarantined])).toEqual([[m.env, to]])
  })

  // Seen in review: a copy that could not be known as the original was
  // marked restored, so unretire never named the kept copy again.
  it("across volumes, a quarantined copy that changes as it is copied is kept, still listed, and not marked restored", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const changesAsItCopies = {
      link: async () => {
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
      writeNewFile: async (path: string, bytes: Uint8Array, attributes?: { mode?: number }) => {
        await writeNewFile(path, bytes, attributes)
        utimesSync(to, new Date("2026-10-09T09:00:00.000Z"), new Date("2026-10-09T09:00:00.000Z"))
      },
    }
    const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: changesAsItCopies })
    expect(back.files).toEqual([{ path: m.env, state: "refused", reasons: [`${to} changed as it was copied to ${m.env}, so it is kept in quarantine; compare them by hand`], quarantined: to }])
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(indexLines(m.adoptDir).filter((l) => "restored" in l)).toEqual([])
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files.map((f) => [f.path, f.quarantined])).toEqual([[m.env, to]])
  })

  it("unretire reports a file put back when only the quarantined copy could not be unlinked, leaving both", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const folderLocks = {
      link: async (from: string, dest: string) => {
        linkSync(from, dest)
        chmodSync(dirname(to), 0o500)
      },
    }
    try {
      const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: folderLocks })
      expect(back.files).toEqual([{ path: m.env, state: "restored", reasons: [`${to} could not be unlinked (EACCES), so the copy is still in quarantine too; delete it once ${m.env} is right`], quarantined: to }])
    } finally {
      chmodSync(dirname(to), 0o700)
    }
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(m.env).ino).toBe(lstatSync(to).ino)
  })

  // Seen in review: a crash after the file was back but before the index
  // said so left a note to compare it with a quarantined copy that was gone.
  it("unretire marks a file restored that an earlier unretire put back without marking it", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    // A crash before the mode was set back leaves the file with the quarantined copy's 0600.
    renameSync(to, m.env)
    expect(lstatSync(m.env).mode & 0o777).toBe(0o600)
    const back = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date("2026-10-08T09:00:00.000Z"), guard: m.ctx.guard })
    expect(back).toEqual({ files: [{ path: m.env, state: "restored", reasons: ["it was already back; an earlier unretire put it back but could not mark it restored"], quarantined: to }], restored: 1, refused: 0, unfinished: [] })
    expect(indexLines(m.adoptDir).at(-1)).toEqual({ restored: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: to })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(lstatSync(m.env).mode & 0o777).toBe(0o640)
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([])
  })

  // Seen in review: across volumes the copy at the path is a new file, so a
  // crash before the restored line left unretire refusing on every run and
  // pointing at a quarantined copy that was gone.
  it("across volumes, unretire marks a file restored that an earlier unretire copied back without marking it", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const crossDevice = {
      link: async () => {
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
    }
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date("2026-10-08T09:00:00.000Z"), guard: m.ctx.guard, fs: crossDevice })).restored).toBe(1)
    const copy = lstatSync(m.env)
    const lines = readFileSync(index, "utf8").trim().split("\n")
    expect(lines.slice(-2).map((l) => JSON.parse(l))).toEqual([
      { copied: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: to, dev: copy.dev, ino: copy.ino, mtimeMs: copy.mtimeMs },
      { restored: "2026-10-08T09:00:00.000Z", path: m.env, quarantined: to },
    ])
    // The state a crash before the restored line leaves.
    writeFileSync(index, `${lines.slice(0, -1).join("\n")}\n`)
    const back = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date("2026-10-08T10:00:00.000Z"), guard: m.ctx.guard, fs: crossDevice })
    expect(back).toEqual({ files: [{ path: m.env, state: "restored", reasons: ["it was already back; an earlier unretire put it back but could not mark it restored"], quarantined: to }], restored: 1, refused: 0, unfinished: [] })
    expect(indexLines(m.adoptDir).at(-1)).toEqual({ restored: "2026-10-08T10:00:00.000Z", path: m.env, quarantined: to })
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([])
  })

  it("across volumes, unretire keeps the quarantined copy when the index cannot record the copy it made at the path", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const indexLocks = {
      link: async () => {
        throw Object.assign(new Error("cross-device link"), { code: "EXDEV" })
      },
      writeNewFile: async (path: string, bytes: Uint8Array, attributes?: { mode?: number }) => {
        await writeNewFile(path, bytes, attributes)
        chmodSync(index, 0o400)
      },
    }
    try {
      const back = await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard, fs: indexLocks })
      expect(back.files[0]?.reasons[0]).toBe(`the quarantine index could not record the copy at ${m.env} (EACCES), so ${to} is still in quarantine too; delete it once ${m.env} is right`)
    } finally {
      chmodSync(index, 0o600)
    }
    expect(readFileSync(m.env, "utf8")).toBe(ENV_TEXT)
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
  })

  it("unretire does not take a file on another device for one it put back, even with the same inode and mtime", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const index = join(m.adoptDir, QUARANTINE_DIR, QUARANTINE_INDEX)
    const [moving, line] = indexLines(m.adoptDir) as [Record<string, unknown>, { dev: number }]
    writeFileSync(index, `${JSON.stringify(moving)}\n${JSON.stringify({ ...line, dev: line.dev + 1 })}\n`)
    renameSync(to, m.env)
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([{ path: m.env, state: "refused", reasons: [`${m.env} exists; compare it with ${to} by hand`], quarantined: to }])
  })

  it("unretire still refuses a file at the original path that is not the quarantined copy, or was changed, when that copy is gone", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const refused = { path: m.env, state: "refused" as const, reasons: [`${m.env} exists; compare it with ${to} by hand`], quarantined: to }
    renameSync(to, m.env)
    utimesSync(m.env, new Date("2026-10-09T09:00:00.000Z"), new Date("2026-10-09T09:00:00.000Z"))
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([refused])
    rmSync(m.env)
    writeFileSync(m.env, ENV_TEXT)
    expect((await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })).files).toEqual([refused])
    expect(indexLines(m.adoptDir).filter((l) => "restored" in l)).toEqual([])
  })

  it("unretire refuses a quarantined copy replaced by another file, even one with the same bytes", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    const ino = lstatSync(to).ino
    writeFileSync(`${to}.new`, ENV_TEXT, { mode: 0o600 })
    renameSync(`${to}.new`, to)
    expect(lstatSync(to).ino).not.toBe(ino)
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard })).files[0]?.reasons).toEqual([`${to} changed in quarantine; compare it with what you expect by hand`])
    expect(existsSync(m.env)).toBe(false)
  })

  it("unretire refuses, per file, when something is at the original path now, and leaves the quarantined copy", async () => {
    const m = await machine()
    const { files } = await assessRetire(m.inputs, m.ctx, m.options)
    await quarantine(files, { adoptDir: m.adoptDir, planPath: m.inputs.planPath, now: m.options.now, guard: m.ctx.guard })
    const to = quarantinedPath(m.adoptDir)
    writeFileSync(m.env, "NEW=1\n")
    const refused = await unretire({ adoptDir: m.adoptDir, paths: null, now: new Date(), guard: m.ctx.guard })
    expect(refused).toEqual({ files: [{ path: m.env, state: "refused", reasons: [`${m.env} exists; compare it with ${to} by hand`], quarantined: to }], restored: 0, refused: 1, unfinished: [] })
    expect(readFileSync(m.env, "utf8")).toBe("NEW=1\n")
    expect(readFileSync(to, "utf8")).toBe(ENV_TEXT)
    expect(quarantinedLine(m.adoptDir).restored).toBeUndefined()
    // A quarantined copy changed since it moved is not put back either.
    rmSync(m.env)
    writeFileSync(to, `${ENV_TEXT}# edited\n`)
    expect((await unretire({ adoptDir: m.adoptDir, paths: [m.env], now: new Date(), guard: m.ctx.guard })).files[0]?.reasons).toEqual([`${to} changed in quarantine; compare it with what you expect by hand`])
    expect(existsSync(m.env)).toBe(false)
  })
})
