// mehen adopt: move the credentials already on this machine into the vault
// without any of them passing through an agent's context. scan and plan
// read names only; submit seals values in this process and uploads them for
// one passkey review; apply and verify wire repos and services to the vault
// copy; inventory lists the plan and what became of each batch. No
// subcommand rewrites or deletes a source file; only retire --yes, a
// human's step, moves one into quarantine, and unretire puts it back.
//
// Everything this command writes, to a terminal, a file or an error, goes
// through one OutputGuard built from every value the process read.

import { lstat, realpath } from "node:fs/promises"
import { basename, dirname, join, resolve } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import type { ParsedArgs } from "../args.ts"
import { type AdoptPlan, AdoptPlanSchema, type FolderHome, type PlanContext, activeRepos, activeServices, buildPlan, checkPlan, liveKeyListing, parseFolderHome, parsePlan, sharedIfAllowed, unmatchedHomes, vaultFacts } from "../adopt/plan.ts"
import { OutputGuard } from "../adopt/output-guard.ts"
import { type OpenBatch, SubmitStopped, storedSlugsFor, submitPlan, workspaceMatches } from "../adopt/submit.ts"
import { ADOPTION_ID, ADOPTION_LIMITS, type AdoptionStatus } from "@mehen/protocol/adopt"
import { adoptionAsk, askNext, askRootFor, askUrlFor, requestedBy, withContext } from "../ask.ts"
import { addLedgerEntry, findLedgerEntry, readLedger, removeLedgerEntry } from "../ledger.ts"
import { adoptionStatus } from "../operations.ts"
import { runWait, timeoutSeconds } from "./intake.ts"
import { ScanResultSchema, readScan, scanReport, scanSummary, scanToFile } from "../adopt/scan.ts"
import { sourceType } from "../adopt/sources.ts"
import { type ApplyContext, type TargetResult, applyPlan, boundSources, outcomes, storedItems, storedSources } from "../adopt/apply.ts"
import { PLAN_FILE, SCAN_FILE, adoptDir, machineName, readPrivateJson, readState, statusByPlanRefs, writePrivateFile, writeState } from "../adopt/state.ts"
import { type VerifyReport, verifyPlan } from "../adopt/verify.ts"
import { type AdoptInventory, type InventoryBatch, batchRows, inventoryItems, inventoryLines } from "../adopt/inventory.ts"
import { type AppliedBatch, ComparedSchema, LEFT_ASIDE, NOT_INDEXED, QUARANTINE_DIR, type RetireInputs, type RetireReport, assessRetire, planFiles, quarantine, retireFailed, retireReport, unfinishedMoves, unretire } from "../adopt/retire.ts"
import { readRegularFile } from "../backup/files.ts"
import { requireSnapshot } from "../backup/guard.ts"
import { readSnapshotRecords } from "../backup/state.ts"
import { resolveHome } from "../home.ts"
import { readRunLog, runLogPath } from "../run/run-log.ts"
import type { Command } from "../command.ts"
import { type Env, homeDir } from "../config.ts"
import { CliError, usageError } from "../errors.ts"
import { printAsk, printLine, table } from "../output.ts"
import { openSession, sessionLabel } from "../session.ts"
import { type Text, plainText, segments } from "../tty.ts"
import { VaultApiError } from "../vault-api.ts"

const HELP = "mehen adopt --help"
const SUBMIT_COMMAND = "mehen adopt submit"

// Every line of output, checked by the guard first.
export class AdoptOutput {
  constructor(
    readonly guard: OutputGuard,
    readonly json: boolean,
  ) {}

  line(text: Text): void {
    this.guard.assertClean(plainText(text))
    printLine(text)
  }

  result(value: unknown): void {
    const text = JSON.stringify(value)
    this.guard.assertClean(text)
    process.stdout.write(`${text}\n`)
  }
}

type FlagName = "root" | "no-defaults" | "depth" | "include" | "exclude" | "out" | "scan" | "home" | "check" | "plan" | "join" | "snapshot" | "reason" | "wait" | "timeout" | "adoption" | "repo" | "env" | "dry-run" | "path" | "compared" | "min-runs" | "min-days" | "yes" | "all" | "per-project"

// `positionals`: how many, or "paths" for any number of file paths.
const SUBCOMMANDS: Record<string, { flags: FlagName[]; positionals: number | "paths" }> = {
  scan: { flags: ["root", "no-defaults", "depth", "include", "exclude", "out"], positionals: 0 },
  plan: { flags: ["scan", "out", "home", "check", "plan", "per-project"], positionals: 0 },
  submit: { flags: ["plan", "join", "snapshot", "reason", "wait", "timeout"], positionals: 0 },
  status: { flags: [], positionals: 1 },
  cancel: { flags: [], positionals: 1 },
  apply: { flags: ["plan", "adoption", "repo", "env", "dry-run"], positionals: 0 },
  verify: { flags: ["plan", "adoption", "repo"], positionals: 0 },
  retire: { flags: ["plan", "repo", "path", "compared", "min-runs", "min-days", "yes"], positionals: 0 },
  unretire: { flags: ["all"], positionals: "paths" },
  inventory: { flags: ["plan"], positionals: 0 },
}

const ALL_FLAGS: FlagName[] = ["root", "no-defaults", "depth", "include", "exclude", "out", "scan", "home", "check", "plan", "join", "snapshot", "reason", "wait", "timeout", "adoption", "repo", "env", "dry-run", "path", "compared", "min-runs", "min-days", "yes", "all", "per-project"]
const MAX_UNRETIRE_PATHS = 100

function given(args: ParsedArgs, name: FlagName): boolean {
  return args.bool(name) || args.string(name) !== null || args.list(name).length > 0
}

function intFlag(args: ParsedArgs, name: string, fallback: number, max: number, min = 1): number {
  const text = args.string(name)
  if (text === null) return fallback
  const value = Number(text)
  if (!Number.isInteger(value) || value < min || value > max) throw usageError(`--${name} must be a whole number from ${min} to ${max}.`, HELP)
  return value
}

function pathFlag(args: ParsedArgs, name: string, fallback: string): string {
  const text = args.string(name)
  return text === null ? fallback : resolve(text)
}

// --out never replaces a file adopt did not write: a file adopt reads
// credentials from, or anything already there that is not a scan or a plan.
async function outFlag(args: ParsedArgs): Promise<string | null> {
  const text = args.string("out")
  if (text === null) return null
  const path = resolve(text)
  const refuse = (why: string) => new CliError("conflict", `--out ${path} ${why}; mehen adopt never replaces it.`, { command: HELP, say: "Give --out a new path, or move that file aside." })
  if (sourceType(path) !== null) throw refuse("is a file adopt reads credentials from")
  try {
    await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return path
    throw refuse("cannot be checked")
  }
  const raw = await readPrivateJson(path, "plan").catch(() => null)
  if (!ScanResultSchema.safeParse(raw).success && !AdoptPlanSchema.safeParse(raw).success) throw refuse("is already there and is not an adopt scan or plan file")
  return path
}

// ---------------------------------------------------------------- scan

async function runScan(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const roots = args.list("root")
  if (args.bool("no-defaults") && roots.length === 0) throw usageError("--no-defaults scans only the --root folders; give at least one.", HELP)
  const { result, path } = await scanToFile(env, { roots, defaults: !args.bool("no-defaults"), depth: intFlag(args, "depth", 6, 32), include: args.list("include"), exclude: args.list("exclude"), out: await outFlag(args) }, out.guard)
  if (out.json) {
    out.result(scanReport(result, path))
    return EXIT.ok
  }
  for (const error of result.errors.slice(0, 20)) out.line(`${error.path}:${error.line}: ${error.why}`)
  if (result.errors.length > 20) out.line(`... and ${result.errors.length - 20} more lines that did not parse (listed in ${path})`)
  out.line(scanSummary(result, path))
  out.line(`then:    mehen adopt plan --scan ${path}`)
  return EXIT.ok
}

// ---------------------------------------------------------------- plan

async function runPlan(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const dir = adoptDir(env)
  if (args.bool("check")) {
    if (given(args, "scan") || given(args, "home") || given(args, "out") || given(args, "per-project")) throw usageError("plan --check takes only --plan.", HELP)
    return checkPlanFile(pathFlag(args, "plan", join(dir, PLAN_FILE)), env, out)
  }
  if (given(args, "plan")) throw usageError("--plan goes with --check; to write the plan elsewhere use --out.", HELP)
  const outPath = await outFlag(args)
  const homes = new Map<string, FolderHome>()
  for (const text of args.list("home")) {
    const parsed = parseFolderHome(text)
    if (!parsed) throw usageError(`--home ${JSON.stringify(text)} is not <folder>=private|workspace|project:<slug>|skip.`, HELP)
    // The scan holds real paths; a folder named through a symlink is matched by its real path.
    const folder = resolve(parsed.folder)
    homes.set(await realpath(folder).catch(() => folder), parsed.home)
  }
  const scanPath = pathFlag(args, "scan", join(dir, SCAN_FILE))
  const scan = await readScan(scanPath)
  const unmatched = unmatchedHomes(scan, homes)
  if (unmatched.length) throw usageError(`--home ${unmatched.join(", ")}: no folder the scan found is there or below it, so it would change nothing.`, HELP)
  const session = await openSession(env)
  const repos = [...new Map(scan.entries.flatMap((e) => (e.repo ? [[e.repo.root, e.repo.remote] as const] : []))).entries()].map(([root, remote]) => ({ root, remote }))
  const facts = await vaultFacts(session.api, repos, [], { ownerIsMember: session.config.owner?.kind === "member" })
  const workspace = session.config.workspaceSlug ?? session.config.tenant
  // Only an owner's or admin's machine may store a workspace credential.
  const mayShare = facts.ownerRole === "owner" || facts.ownerRole === "admin"
  const { storedSlugs, unappliedSlugs } = await storedSlugsFor(session.api, dir, workspace)
  const context: PlanContext = { workspace, vault: session.vaultUrl, machine: machineName(), home: homeDir(env), visibleItems: facts.visibleItems, homes, existing: facts.existing, projectMismatch: facts.projectMismatch, storedSlugs, unappliedSlugs, sharedValues: mayShare && !args.bool("per-project") ? "workspace" : "per-project" }
  const plan = buildPlan(scan, context)
  const check = checkPlan(plan, { protectedEnvs: facts.protectedEnvs, canCreateProjects: facts.canCreateProjects, boundVars: facts.boundVars, unappliedSlugs, projectMismatch: [...facts.projectMismatch.values()] })
  const keptPerProject = !mayShare && !args.bool("per-project") && sharedIfAllowed(scan, context) > 0
  const path = outPath ?? join(dir, PLAN_FILE)
  await writePrivateFile(path, `${JSON.stringify(plan, null, 2)}\n`, out.guard)
  const counts = { items: plan.items.length, included: check.included, repos: activeRepos(plan).length, services: activeServices(plan).length, possiblyStale: plan.possiblyStale.length, storeOnly: plan.storeOnly.length, liveKeys: check.liveKeys.length }
  if (out.json) {
    out.result({ plan: path, workspace, ...counts, folders: plan.folders, check, connectors: plan.connectors ?? [], sharedValues: { home: context.sharedValues, why: keptPerProject ? SHARED_KEPT_PER_PROJECT : null } })
    return EXIT.ok
  }
  out.line(`planned ${counts.items} items (${counts.included} to upload${comparesNote(check)}${batchesNote(check)}) for workspace ${workspace} from ${Object.keys(plan.sources).length} names in ${plan.folders.length} folders, ${counts.repos} repos and ${counts.services} services; ${counts.possiblyStale} possibly stale (check before revoking at the provider), ${counts.storeOnly} stored only, ${counts.liveKeys} live ${counts.liveKeys === 1 ? "key" : "keys"} held back; wrote ${path}`)
  const rows: Text[][] = [["FOLDER", "HOME", "ITEMS"], ...plan.folders.map((f) => [f.path, f.home === "project" ? `project:${f.project ?? "?"}` : f.home, String(f.items)])]
  for (const line of table(rows)) out.line(line)
  printCheck(check, out)
  for (const line of connectorLines(plan)) out.line(line)
  if (keptPerProject) out.line(SHARED_KEPT_PER_PROJECT)
  out.line("then:    review the plan; change a folder with --home <folder>=private|workspace|project:<slug>|skip and plan again, or edit the file and run mehen adopt plan --check")
  return EXIT.ok
}

// Each login or OAuth token the plan makes a connection instead of
// uploading, by where it was read: names and paths only.
function connectorLines(plan: AdoptPlan): Text[] {
  return (plan.connectors ?? []).map((c) => {
    const source = plan.sources[c.source]
    const where = source ? `${source.path}${source.variable ? ` ${source.variable}` : source.pointer ? ` ${source.pointer}` : ""}` : c.source
    return segments(`connector, never uploaded: ${where}: ${c.why}${c.command ? `; then: ${c.command}` : ""}`)
  })
}

const SHARED_KEPT_PER_PROJECT = "values shared by several projects stay one per project: only an owner's or admin's machine can store workspace credentials"

function comparesNote(check: ReturnType<typeof checkPlan>): string {
  return check.compares.length ? `, ${check.compares.length} of them to compare with an item in the vault` : ""
}

// A batch holds at most ADOPTION_LIMITS.maxItems; submit splits a bigger plan.
function batchesNote(check: ReturnType<typeof checkPlan>): string {
  return check.batches > 1 ? ` in ${check.batches} batches, each approved on its own` : ""
}

function printCheck(check: ReturnType<typeof checkPlan>, out: AdoptOutput): void {
  const n = check.sharedWorkspace
  if (n > 0) out.line(n === 1 ? "1 value shared by several projects becomes a workspace credential" : `${n} values shared by several projects become workspace credentials`)
  for (const p of check.problems) out.line(`problem: ${p.ref ?? p.where ?? "plan"}: ${p.problem}`)
  for (const m of check.projectMismatch) out.line(`problem: ${m.root}: mehen.toml names ${m.manifest === null ? "another project" : `project ${m.manifest}`}, but the vault binds this repo's remote to project ${m.bound}; its variables are left alone: fix mehen.toml or the remote, then plan again`)
  if (check.byHand.length) out.line(`add these by hand from the web app (the vault keeps public fields in the clear, and each looks like a secret): ${check.byHand.map((b) => `${b.slug} (${b.field})`).join("; ")}`)
  if (check.liveKeys.length) out.line(`live keys held back from environments that are not protected (every machine that runs the project there would get them, so each is left unticked or its variable there skipped; adopt it into a protected environment on the project page, or tick it if the environment really uses live keys): ${check.liveKeys.map(liveKeyListing).join("; ")}`)
  if (check.humanSets.length) out.line(`a human sets these on the project page (protected environments): ${check.humanSets.map((h) => `${h.project} ${h.env}: ${h.variable} to ${h.item}`).join("; ")}`)
  for (const c of check.compares) out.line(compareLine(c))
  for (const l of check.leftAlone) out.line(segments(`${l.project} ${l.env}: ${l.variable}: set to ${l.item ?? "an item this machine cannot see"} by another machine; apply leaves it`))
}

// A compare row as plan and submit print it: never how the values compare,
// which no device learns.
function compareLine(row: { ref: string; slug: string }): Text {
  return segments(`${row.ref}: compare with ${row.slug} in the vault`)
}

async function checkPlanFile(path: string, env: Env, out: AdoptOutput): Promise<number> {
  const plan = parsePlan(await readPrivateJson(path, "plan"), path)
  const session = await openSession(env)
  const ids = [...plan.repos, ...plan.services].flatMap((r) => (r.project.id ? [r.project.id] : []))
  const facts = await vaultFacts(session.api, [], ids, { ownerIsMember: session.config.owner?.kind === "member" })
  const check = checkPlan(plan, { protectedEnvs: facts.protectedEnvs, canCreateProjects: facts.canCreateProjects, boundVars: facts.boundVars, unappliedSlugs: (await storedSlugsFor(session.api, adoptDir(env), plan.workspace)).unappliedSlugs })
  if (out.json) out.result({ plan: path, ...check })
  else {
    printCheck(check, out)
    if (check.ok) out.line(`${path} checks clean: ${check.included} items to upload${comparesNote(check)}${batchesNote(check)}`)
  }
  if (!check.ok) throw new CliError("bad_request", `The plan has ${check.problems.length} problem${check.problems.length === 1 ? "" : "s"}.`, { command: `mehen adopt plan --check --plan ${path}`, say: "Fix each problem in the plan file, then check it again." })
  return EXIT.ok
}

// ---------------------------------------------------------------- submit, status, cancel

function adoptionId(text: string | undefined): string {
  if (!text || !ADOPTION_ID.test(text)) throw usageError(`${JSON.stringify(text ?? "")} is not an adoption id (adp_...).`, HELP)
  return text
}

async function runSubmit(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const dir = adoptDir(env)
  const joinIds = [...new Set(args.list("join").map((id) => adoptionId(id)))]
  const reason = args.string("reason")
  if (reason !== null && (reason.length === 0 || reason.length > 500)) throw usageError("--reason takes 1 to 500 characters.", HELP)
  const timeout = timeoutSeconds(args.string("timeout"), HELP)
  const planPath = pathFlag(args, "plan", join(dir, PLAN_FILE))
  const plan = parsePlan(await readPrivateJson(planPath, "plan"), planPath)
  // Each machine, joining or not, needs its own snapshot before anything
  // reaches the vault.
  const snapshotFlag = args.string("snapshot")
  const snapshot = await requireSnapshot({ planPath, env, ...(snapshotFlag !== null ? { snapshot: snapshotFlag } : {}) })
  const session = await openSession(env)
  const now = new Date()
  const by = requestedBy(env)
  // Each batch's ask, recorded in the ledger so `mehen pending` lists it.
  const record = async (list: Omit<OpenBatch, "joined">[]) => {
    const ledger = await readLedger(session.configDir, session.ledger, now)
    const asks = []
    for (const batch of list) {
      const ask = withContext(adoptionAsk({ id: batch.adoption, url: batch.url, items: batch.items, machine: by.device, expiresAt: batch.expiresAt, requestedBy: by }), session.context)
      out.guard.assertClean(JSON.stringify(ask))
      if (!findLedgerEntry(ledger, ask.id)) await addLedgerEntry(session.configDir, session.ledger, { ask, slug: null, command: SUBMIT_COMMAND, now })
      asks.push(ask)
    }
    return asks
  }
  let result: Awaited<ReturnType<typeof submitPlan>>
  try {
    result = await submitPlan(
      { plan, join: joinIds, reason, session: sessionLabel(env), machine: machineName(), home: homeDir(env) },
      { api: session.api, config: session.config, vault: session.ledger, stateDir: dir, guard: out.guard },
    )
  } catch (error) {
    // The stop names the batches still open, so a ledger that cannot be
    // written must not replace it.
    if (error instanceof SubmitStopped) await record(error.open).catch(() => undefined)
    throw error
  }
  const asks = await record(result.batches.map((b) => ({ adoption: b.adoption, url: b.link.url, expiresAt: b.expiresAt, items: b.uploaded.items })))
  const batches = result.batches.map((batch, i) => ({ adoption: batch.adoption, url: batch.link.url, expiresAt: batch.expiresAt, joined: batch.joined, uploaded: batch.uploaded, ask: asks[i] as (typeof asks)[number] }))
  const first = batches[0] as (typeof batches)[number]
  const uploaded = { items: batches.reduce((n, b) => n + b.uploaded.items, 0), fields: batches.reduce((n, b) => n + b.uploaded.fields, 0) }
  const ids = batches.map((b) => b.adoption)
  const separately = `${ids.length} batches (${ids.join(", ")}): each is approved on its own, at its own link`
  if (out.json) {
    // The first batch's fields at the top, as for one batch; every batch in `batches`.
    out.result({ adoption: first.adoption, url: first.url, expiresAt: first.expiresAt, snapshot: snapshot.id, joined: first.joined, uploaded, skipped: result.skipped, refused: result.refused, shared: result.shared, compared: result.compared, unchecked: result.unchecked, index: result.index, projects: result.projects, ask: first.ask, next: askNext(first.ask, { now }), batches: batches.map((b) => ({ ...b, next: askNext(b.ask, { now }) })) })
  } else {
    for (const p of result.projects.filter((x) => x.created)) out.line(`created project ${p.slug} (${p.id})`)
    for (const r of result.refused) out.line(segments(`not uploaded: ${r.ref}: ${r.reason}`))
    for (const s of result.shared) out.line(segments(`not uploaded: ${s.slug}: this machine's own row for it is already in ${s.adoption}, so it was not sent again`))
    for (const c of result.compared) out.line(compareLine(c))
    if (result.index.state === "oversize") out.line(`the plan's index is ${result.index.bytes} bytes, over the vault's ${ADOPTION_LIMITS.maxChunkBytes}, so it was not sent; the inventory page does not list this machine's items`)
    if (result.index.state === "withheld") out.line("the plan's index was not sent: the output guard found a value in it; the rows above are in, and the inventory page does not list this machine's items")
    if (result.index.state === "refused") out.line(`the plan's index was not sent (${result.index.error ?? "the vault could not be reached"}); the rows above are in, and the inventory page does not list this machine's items`)
    if (result.unchecked.length) out.line(`${result.unchecked.join(", ")} ${result.unchecked.length === 1 ? "does" : "do"} not list the names already in it (an older vault): a name another machine put there may be refused`)
    const left = Object.entries(result.skipped).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`)
    const tail = `${left.length ? `; skipped ${left.join(", ")}` : ""}; snapshot ${snapshot.id} holds every file the plan names`
    batches.forEach((b, i) => out.line(`uploaded ${b.uploaded.items} item${b.uploaded.items === 1 ? "" : "s"} from ${by.device} to ${b.adoption}${i === batches.length - 1 ? tail : ""}`))
    if (batches.length > 1) out.line(`this machine's items are in ${separately}`)
    const then = args.bool("wait") ? null : `${ids.map((id) => `mehen wait ${id}`).join(", ")}, then mehen adopt apply`
    batches.forEach((b, i) => printAsk(b.ask, { env, noQr: args.bool("no-qr"), now, then: i === batches.length - 1 ? then : null }))
  }
  if (!args.bool("wait")) return EXIT.ok
  for (const id of ids) {
    const code = await runWait(env, id, { json: out.json, events: false, noQr: args.bool("no-qr"), timeoutSeconds: timeout, showAsk: false })
    if (code !== EXIT.ok) return code
  }
  return EXIT.ok
}

async function runStatus(id: string, env: Env, out: AdoptOutput): Promise<number> {
  const session = await openSession(env)
  const status = await statusByPlanRefs(env, await adoptionStatus(session.api, id))
  const link = askUrlFor(session.ledger, "adoption", id)
  if (out.json) {
    out.result({ ...status, url: link?.url ?? null })
    return EXIT.ok
  }
  out.line(`${id}: ${status.status}, expires ${status.expiresAt}${link ? `; ${link.url}` : ""}`)
  for (const m of status.machines) out.line(segments(`  ${m.name}: ${m.items} item${m.items === 1 ? "" : "s"}`))
  for (const c of status.created ?? []) out.line(segments(`  created ${c.ref}: ${c.slug}`))
  for (const c of status.mapped ?? []) out.line(segments(`  mapped ${c.ref}: ${c.slug}`))
  for (const c of status.replaced ?? []) out.line(segments(`  replaced ${c.ref}: ${c.slug}`))
  for (const r of status.refused ?? []) out.line(segments(`  refused ${r.ref}: ${r.reason}`))
  return EXIT.ok
}

async function runCancel(id: string, env: Env, out: AdoptOutput): Promise<number> {
  const session = await openSession(env)
  const status = await session.api.request<AdoptionStatus>("POST", `/v1/adoptions/${id}/cancel`, {})
  await removeLedgerEntry(session.configDir, session.ledger, id).catch(() => undefined)
  if (out.json) out.result({ adoption: id, status: status.status })
  else out.line(`${id} is ${status.status}; its staged credentials are gone and nothing was stored`)
  return EXIT.ok
}

// ---------------------------------------------------------------- apply, verify

// The plan, the approved batches and what apply and verify need from the
// session. Without --adoption, every batch this machine recorded for the
// plan's workspace that is open or approved, since applying again is safe;
// the open ones are listed, not applied.
async function approvedRun(args: ParsedArgs, env: Env, out: AdoptOutput) {
  const dir = adoptDir(env)
  const planPath = pathFlag(args, "plan", join(dir, PLAN_FILE))
  const plan = parsePlan(await readPrivateJson(planPath, "plan"), planPath)
  const repos = args.list("repo").map((r) => resolve(r))
  const unknown = repos.filter((r) => !plan.repos.some((p) => p.root === r))
  if (unknown.length) throw usageError(`${unknown.join(", ")} ${unknown.length === 1 ? "is not a repo" : "are not repos"} in ${planPath}.`, HELP)
  const state = await readState(dir)
  const named = args.string("adoption")
  // Batches recorded for another workspace's plan map other items.
  const recorded = state.adoptions.filter((a) => a.workspace === plan.workspace)
  const namedRecord = recorded.find((a) => a.adoption === named)
  const records = named !== null ? [{ adoption: adoptionId(named), refs: namedRecord?.refs, sources: namedRecord?.sources, appliedAt: namedRecord?.appliedAt, bound: namedRecord?.bound }] : recorded
  if (records.length === 0) throw new CliError("not_found", "This machine has not submitted an adoption.", { command: SUBMIT_COMMAND, say: "Submit the plan first, or name the batch with --adoption <adp_id>." })
  const session = await openSession(env)
  const batches: { status: AdoptionStatus; refs: Record<string, string> | null; sources: Record<string, string[]> | null; appliedAt?: string; bound?: string[] }[] = []
  for (const record of records) {
    const status = await adoptionStatus(session.api, record.adoption)
    if (named !== null || status.status === "open" || status.status === "approved") batches.push({ status, refs: record.refs ?? null, sources: record.sources ?? null, appliedAt: record.appliedAt, bound: record.bound })
  }
  if (batches.length === 0) throw new CliError("not_found", `None of the ${records.length} batches this machine recorded for ${plan.workspace} is open or approved.`, { command: SUBMIT_COMMAND, say: "Submit the plan again, or name a batch with --adoption <adp_id>." })
  const stored = storedItems(batches)
  const notApproved = batches.map((b) => b.status).filter((s) => s.status !== "approved")
  if (stored.adoptions.length === 0) {
    const first = notApproved.find((s) => s.status === "open") ?? (notApproved[0] as AdoptionStatus)
    const which = notApproved.length === 1 ? `Adoption ${first.adoption} is ${first.status}` : `None of this machine's ${notApproved.length} open batches is approved (${notApproved.map((s) => `${s.adoption} ${s.status}`).join(", ")})`
    throw new CliError("conflict", `${which}; this step runs after a human approves it.`, { command: `mehen wait ${first.adoption}`, say: "Wait for the approval, then run it again." })
  }
  const ctx: ApplyContext = { api: session.api, config: { ...session.config, vault: session.vaultUrl }, guard: out.guard, home: homeDir(env), projects: state.projects }
  return { dir, planPath, plan, state, stored, batches, notApproved, ctx, repos: repos.length ? repos : null }
}

// The batches a run left alone: one still open is applied by a later run.
function notApprovedLines(notApproved: readonly AdoptionStatus[], step: "apply" | "verify"): string[] {
  return notApproved.map((s) => (s.status === "open" ? `${s.adoption} is waiting for approval; run mehen adopt ${step} again once it is approved` : `${s.adoption} is ${s.status}: nothing from it was stored`))
}

function applyLines(result: TargetResult): string[] {
  const lines: string[] = []
  const project = result.project ? ` (project ${result.project.slug})` : ""
  if (result.error) return [`${result.target}${project}: not applied: ${result.error}`]
  const set = result.vars.filter((v) => v.set !== null).length
  const unchanged = result.vars.filter((v) => v.unchanged).length
  lines.push(`${result.target}${project}: mehen.toml ${result.manifest.state}; ${set} of ${result.vars.length} variables set${unchanged ? ` (${unchanged === set ? "all" : unchanged} already in the vault, left as they were)` : ""}`)
  if (result.manifest.add.length) lines.push(`  add to ${result.manifest.path} under [vars]: ${result.manifest.add.join(", ")}`)
  for (const v of result.vars.filter((x) => x.set === null && x.why !== null)) lines.push(`  ${v.env}: ${v.variable}: ${v.why}`)
  if (result.humanSets.length) lines.push(`  set these on the project page: ${result.humanSets.map((h) => `${h.env}: ${h.variable} to ${h.item}`).join("; ")}`)
  for (const c of result.checks) lines.push(c.ok ? `  env=${c.env}: every declared variable resolves` : `  env=${c.env}: ${c.why ?? `${c.unresolved.join(", ")} do not resolve`}`)
  for (const file of result.committed) lines.push(`  ${file} is committed to git; rotate these values, history still holds them`)
  for (const line of result.unitChange) lines.push(`  ${line}`)
  return lines
}

// The plan refs a batch decided, by this machine's plan.
function batchPlanRefs(status: AdoptionStatus, refs: Readonly<Record<string, string>> | null): Set<string> {
  const planRefOf = new Map(Object.entries(refs ?? {}).map(([planRef, ref]) => [ref, planRef]))
  return new Set(outcomes(status).flatMap((c) => (refs === null ? [c.ref] : planRefOf.has(c.ref) ? [planRefOf.get(c.ref) as string] : [])))
}

// The plan refs of the items a repo or service target maps.
function targetItemRefs(plan: AdoptPlan, target: string): string[] {
  const repo = plan.repos.find((r) => r.root === target)?.files.flatMap((f) => Object.values(f.vars)) ?? []
  const service = Object.values(plan.services.find((s) => s.unit === target)?.vars ?? {})
  return [...repo, ...service].flatMap((m) => ("item" in m ? [m.item] : []))
}

type Unrecorded = { adoption: string; why: string }

// Records, per approved batch apply has not yet applied all of, the source
// keys of the variables it set, or found already set, to an item the batch
// stored from them; and when apply first applied all of the batch, once
// every target mapping one of its items applied without an error and no
// --repo or --env left part of it out; a batch it could not record as
// applied is returned.
async function recordApplied(run: Awaited<ReturnType<typeof approvedRun>>, results: readonly TargetResult[], subset: boolean, guard: OutputGuard): Promise<Unrecorded[]> {
  const unrecorded: Unrecorded[] = []
  const at = new Date().toISOString()
  let recorded = false
  const bound = boundSources(run.plan, results)
  for (const record of run.state.adoptions.filter((a) => run.stored.adoptions.includes(a.adoption) && a.appliedAt === undefined)) {
    const batch = run.batches.find((b) => b.status.adoption === record.adoption)
    const recordedSources = batch ? storedSources([batch]) : new Map<string, Set<string>>()
    const before = new Set(record.bound ?? [])
    const keys = new Set([...before, ...[...bound].flatMap(([slug, set]) => [...set].filter((key) => recordedSources.get(slug)?.has(key)))])
    if (record.bound === undefined || keys.size > before.size) {
      record.bound = [...keys]
      recorded = true
    }
    const planRefs = batch ? batchPlanRefs(batch.status, batch.refs) : new Set<string>()
    const failed = results.filter((r) => r.error !== null && targetItemRefs(run.plan, r.target).some((ref) => planRefs.has(ref))).map((r) => r.target)
    if (subset) unrecorded.push({ adoption: record.adoption, why: "--repo or --env applied only part of it; run mehen adopt apply without them" })
    else if (failed.length) unrecorded.push({ adoption: record.adoption, why: `${failed.join(", ")} ${failed.length === 1 ? "was" : "were"} not applied; fix ${failed.length === 1 ? "it" : "them"} and run mehen adopt apply again` })
    else {
      record.appliedAt = at
      recorded = true
    }
  }
  if (recorded) await writeState(run.dir, run.state, guard)
  return unrecorded
}

async function runApply(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const envName = args.string("env")
  const run = await approvedRun(args, env, out)
  const { plan, stored, notApproved, ctx, repos } = run
  const dryRun = args.bool("dry-run")
  const results: TargetResult[] = []
  let unrecorded: Unrecorded[] = []
  let threw = true
  try {
    await applyPlan(plan, stored, ctx, { repos, env: envName, dryRun }, results)
    threw = false
  } finally {
    // A target that threw still leaves recorded what the targets before it
    // bound, never when the batch was applied, and its error is the one
    // apply fails with.
    if (!dryRun) {
      const recording = recordApplied(run, results, threw || repos !== null || envName !== null, out.guard)
      unrecorded = threw ? await recording.catch(() => []) : await recording
    }
  }
  const ok = results.every((r) => r.error === null && r.checks.every((c) => c.ok))
  const waiting = notApproved.filter((s) => s.status === "open").map((s) => s.adoption)
  if (out.json) out.result({ adoption: stored.adoptions[0], adoptions: stored.adoptions, waiting, dryRun: args.bool("dry-run"), ok, targets: results, unrecorded })
  else {
    out.line(`applying ${stored.adoptions.join(", ")}`)
    for (const result of results) for (const line of applyLines(result)) out.line(line)
    for (const u of unrecorded) out.line(`when ${u.adoption} was applied is not recorded: ${u.why}`)
    for (const line of notApprovedLines(notApproved, "apply")) out.line(line)
    if (results.length === 0) out.line("the plan has no repo or service to apply")
    out.line("no source file was moved, rewritten or deleted")
    out.line(args.bool("dry-run") ? "then:    mehen adopt apply" : "then:    mehen adopt verify")
  }
  return ok ? EXIT.ok : EXIT.human
}

function verifyLines(report: VerifyReport): string[] {
  const lines: string[] = []
  for (const t of report.targets) {
    const covered = t.coverage.filter((c) => c.state === "covered").length
    const skipped = t.coverage.filter((c) => c.state === "skipped").length
    const gaps = t.coverage.filter((c) => c.state === "gap")
    lines.push(`${t.target}: ${covered} covered, ${skipped} skipped, ${gaps.length} gap${gaps.length === 1 ? "" : "s"}`)
    for (const g of gaps) lines.push(`  gap: ${g.file}: ${g.variable} (env=${g.env}): ${g.why}`)
  }
  for (const i of report.items) lines.push(`${i.slug}: ${i.check}${i.status !== null ? ` (${i.status})` : ""}${i.why && i.check !== "ok" ? `: ${i.why}` : ""}`)
  return lines
}

async function runVerify(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const { dir, plan, state, stored, notApproved, ctx, repos } = await approvedRun(args, env, out)
  const report = await verifyPlan(plan, stored, ctx, { repos, session: sessionLabel(env), now: new Date() })
  for (const { ref, why: _why, ...result } of report.items) state.verify[ref] = result
  await writeState(dir, state, out.guard)
  const waiting = notApproved.filter((s) => s.status === "open").map((s) => s.adoption)
  if (out.json) out.result({ adoption: stored.adoptions[0], adoptions: stored.adoptions, waiting, ...report })
  else {
    for (const line of verifyLines(report)) out.line(line)
    for (const line of notApprovedLines(notApproved, "verify")) out.line(line)
    out.line(report.ok ? "verified: every name is provided by Mehen or skipped, and every live check passed; the local files are untouched" : "not verified: fix each gap or failed check above, then run mehen adopt verify again; the local files are untouched")
  }
  return report.ok ? EXIT.ok : EXIT.human
}

// ---------------------------------------------------------------- retire, unretire

// A file path as the scan recorded it: its folder's real path, the file
// itself not followed.
async function realFile(text: string): Promise<string> {
  const path = resolve(text)
  return join(await realpath(dirname(path)).catch(() => dirname(path)), basename(path))
}

const COMPARE_SAY = "Save `mehen backup compare <snp_id>.age <export>.age --identity - --map <file> --json` to a file and name it with --compared."

async function readCompared(text: string | null): Promise<RetireInputs["compared"]> {
  if (text === null) return null
  const path = resolve(text)
  const read = await readRegularFile(path, { maxBytes: 16 * 1_048_576, ownOnly: false })
  if (read === null) throw new CliError("not_found", `There is no compare output at ${path}.`, { command: HELP, say: COMPARE_SAY })
  let raw: unknown = null
  try {
    raw = JSON.parse(Buffer.from(read.bytes).toString("utf8"))
  } catch {
    raw = null
  }
  const parsed = ComparedSchema.safeParse(raw)
  if (!parsed.success) throw new CliError("bad_request", `${path} is not the output of \`mehen backup compare --json\`.`, { command: HELP, say: COMPARE_SAY })
  return { path, result: parsed.data }
}

function count(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

function retireLines(report: RetireReport, yes: boolean, folder: string): string[] {
  const lines = report.unfinished.map((u) => u.note)
  for (const f of report.files) {
    if (f.state === "moved") lines.push(`moved ${f.path} to quarantine${f.notes.some((n) => n.startsWith(NOT_INDEXED)) ? "" : `; put it back with: mehen adopt unretire ${f.path}`}`)
    else if (f.state === "failed") lines.push(`failed ${f.path}: ${f.reasons.join("; ")}${f.notes.some((n) => n.startsWith(LEFT_ASIDE)) ? "" : "; it is still where it was"}`)
    else {
      lines.push(`${f.state === "ready" ? "ready" : "held "} ${f.path}`)
      for (const reason of f.reasons) lines.push(`  ${reason}`)
    }
    for (const note of f.notes.filter((n) => !n.startsWith("moved to "))) lines.push(`  note: ${note}`)
  }
  const ready = report.files.filter((f) => f.state === "ready").length
  const failed = report.files.filter((f) => f.state === "failed").length
  if (!yes) lines.push(`${ready} ready, ${report.held} held; nothing was moved. Run the same command with --yes to move the ready ${ready === 1 ? "file" : "files"} to ${folder}`)
  else {
    lines.push(`moved ${count(report.moved, "file")} to ${folder}; nothing was deleted, and that folder is yours to delete when you are sure`)
    if (failed) lines.push(`${count(failed, "ready file")} could not be moved`)
  }
  return lines
}

async function runRetire(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const yes = args.bool("yes")
  const minRuns = intFlag(args, "min-runs", 3, 1000)
  const minDays = intFlag(args, "min-days", 2, 365, 0)
  const compared = await readCompared(args.string("compared"))
  const { dir, planPath, plan, state, batches, stored, ctx, repos } = await approvedRun(args, env, out)
  const files = planFiles(plan)
  const paths = await Promise.all(args.list("path").map(realFile))
  const unknown = paths.filter((p) => !files.includes(p))
  if (unknown.length) throw usageError(`${unknown.join(", ")} ${unknown.length === 1 ? "is not a file" : "are not files"} in ${planPath}.`, HELP)
  const applied: AppliedBatch[] = batches
    .filter((b) => b.status.status === "approved")
    .map(({ status, refs }) => ({ adoption: status.adoption, planRefs: batchPlanRefs(status, refs), appliedAt: state.adoptions.find((a) => a.adoption === status.adoption)?.appliedAt ?? null }))
  const snapshots = await readSnapshotRecords(env)
  const runs = await readRunLog(runLogPath(resolveHome(env).root)).catch(() => [])
  const now = new Date()
  const { files: checked } = await assessRetire({ plan, planPath, stored, batches: applied, snapshots, runs, compared }, ctx, { repos: repos ?? [], paths, minRuns, minDays, now, session: sessionLabel(env) })
  const folder = join(dir, QUARANTINE_DIR)
  const unfinished = await unfinishedMoves(dir)
  if (yes) {
    const ready = checked.filter((f) => f.state === "ready").length
    if (!out.json) out.line(`moving ${count(ready, "file")} to quarantine in ${folder}`)
    await quarantine(checked, { adoptDir: dir, planPath, now, guard: out.guard })
  }
  const report = retireReport(checked, unfinished)
  if (out.json) out.result(report)
  else for (const line of retireLines(report, yes, folder)) out.line(line)
  return retireFailed(report) ? EXIT.error : EXIT.ok
}

async function runUnretire(rest: string[], args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const all = args.bool("all")
  if (all === rest.length > 0) throw usageError("mehen adopt unretire takes the paths to put back, or --all.", HELP)
  const paths = rest.length ? await Promise.all(rest.map(realFile)) : null
  const report = await unretire({ adoptDir: adoptDir(env), paths, now: new Date(), guard: out.guard })
  if (out.json) out.result(report)
  else {
    for (const u of report.unfinished) out.line(u.note)
    for (const f of report.files) {
      out.line(f.state === "restored" ? `put ${f.path} back from ${f.quarantined}` : `not put back: ${f.path}: ${f.reasons.join("; ")}`)
      if (f.state === "restored") for (const reason of f.reasons) out.line(`  note: ${reason}`)
    }
    const none = report.unfinished.length ? "nothing else is in quarantine for unretire to put back" : "nothing is in quarantine"
    out.line(report.files.length === 0 ? none : `${report.restored} put back, ${report.refused} left as ${report.refused === 1 ? "it was" : "they were"}`)
  }
  return report.refused ? EXIT.error : EXIT.ok
}

// ---------------------------------------------------------------- inventory

// The plan's items and, from the device answer for each batch this machine
// recorded for the plan's workspace, what became of its rows; never an
// account-only read.
async function runInventory(args: ParsedArgs, env: Env, out: AdoptOutput): Promise<number> {
  const dir = adoptDir(env)
  const planPath = pathFlag(args, "plan", join(dir, PLAN_FILE))
  const plan = parsePlan(await readPrivateJson(planPath, "plan"), planPath)
  const session = await openSession(env)
  const workspace = session.config.workspaceSlug ?? session.config.tenant
  if (!workspaceMatches(plan, session.config)) throw new CliError("workspace_mismatch", `${planPath} is a plan for workspace ${plan.workspace}, not ${workspace}.`, { command: `mehen adopt inventory --workspace ${plan.workspace}`, say: "Name the plan's workspace with --workspace, or plan again for this one." })
  const batches: InventoryBatch[] = []
  for (const record of (await readState(dir)).adoptions.filter((a) => a.workspace === plan.workspace)) {
    const url = askUrlFor(session.ledger, "adoption", record.adoption)?.url ?? null
    const status = await adoptionStatus(session.api, record.adoption).catch((error: unknown) => {
      if (error instanceof VaultApiError && error.status === 404) return null
      throw error
    })
    if (status === null) {
      batches.push({ adoption: record.adoption, status: null, expiresAt: null, url, rows: [] })
      continue
    }
    const byPlan = await statusByPlanRefs(env, status)
    batches.push({ adoption: record.adoption, status: byPlan.status, expiresAt: byPlan.expiresAt, url, rows: batchRows(byPlan, record.refs ? Object.keys(record.refs) : null) })
  }
  const root = askRootFor(session.ledger)
  printInventory({ plan: planPath, workspace: plan.workspace, machine: plan.machine, items: inventoryItems(plan), batches, url: root ? `${root.url}adopt` : null }, out)
  return EXIT.ok
}

// Every line through the output guard, as everything adopt prints.
export function printInventory(inventory: AdoptInventory, out: AdoptOutput): void {
  if (out.json) out.result(inventory)
  else for (const line of inventoryLines(inventory)) out.line(line)
}

// ---------------------------------------------------------------- the command

export const adoptCommand: Command = {
  summary: "adopt the credentials already on this machine (mehen adopt scan|plan|submit|status|cancel|apply|verify|retire|unretire|inventory)",
  spec: {
    usage: "mehen adopt scan [--root <dir>]... [--no-defaults] [--depth <n>] [--include <glob>]... [--exclude <glob>]... [--out <path>] | plan [--scan <path>] [--home <folder>=<home>]... [--per-project] [--out <path>] | plan --check [--plan <path>] | submit [--plan <path>] [--join <adp_id>]... [--snapshot <snp_id>] [--reason <text>] [--wait] [--timeout <duration>] | status <adp_id> | cancel <adp_id> | apply [--plan <path>] [--adoption <adp_id>] [--repo <dir>]... [--env <env>] [--dry-run] | verify [--plan <path>] [--adoption <adp_id>] [--repo <dir>]... | retire [--plan <path>] [--repo <dir>]... [--path <file>]... --compared <compare.json> [--min-runs <n>] [--min-days <n>] [--yes] | unretire (<path>... | --all) | inventory [--plan <path>]",
    flags: {
      root: { type: "list" },
      "no-defaults": { type: "boolean" },
      depth: { type: "string" },
      include: { type: "list" },
      exclude: { type: "list" },
      out: { type: "string" },
      scan: { type: "string" },
      home: { type: "list" },
      check: { type: "boolean" },
      plan: { type: "string" },
      join: { type: "list" },
      snapshot: { type: "string" },
      reason: { type: "string" },
      wait: { type: "boolean" },
      timeout: { type: "string" },
      adoption: { type: "string" },
      repo: { type: "list" },
      env: { type: "string" },
      "dry-run": { type: "boolean" },
      path: { type: "list" },
      compared: { type: "string" },
      "min-runs": { type: "string" },
      "min-days": { type: "string" },
      yes: { type: "boolean" },
      all: { type: "boolean" },
      "per-project": { type: "boolean" },
    },
    positionals: { min: 1, max: 1 + MAX_UNRETIRE_PATHS },
  },
  examples: [
    ["adopt", "scan"],
    ["adopt", "scan", "--root", "~/code/billing-api", "--no-defaults", "--json"],
    ["adopt", "plan", "--home", "/Users/sam/.local-secrets=private"],
    ["adopt", "plan", "--per-project"],
    ["adopt", "plan", "--check"],
    ["adopt", "submit", "--reason", "move this machine's keys into the vault"],
    ["adopt", "submit", "--join", "adp_7Hq2xK"],
    ["adopt", "submit", "--join", "adp_7Hq2xK", "--join", "adp_9Rt4mW"],
    ["adopt", "submit", "--snapshot", "snp_4fQ9cR2mT7"],
    ["adopt", "status", "adp_7Hq2xK", "--json"],
    ["adopt", "apply", "--dry-run"],
    ["adopt", "apply", "--repo", "~/code/billing-api", "--env", "dev"],
    ["adopt", "verify", "--json"],
    ["adopt", "retire", "--compared", "/Users/sam/Backups/mehen/compare.json"],
    ["adopt", "retire", "--compared", "/Users/sam/Backups/mehen/compare.json", "--repo", "/Users/sam/code/billing-api", "--yes"],
    ["adopt", "retire", "--path", "/Users/sam/.local-secrets/ci.env", "--compared", "/Users/sam/Backups/mehen/compare.json", "--json"],
    ["adopt", "unretire", "/Users/sam/code/billing-api/.env"],
    ["adopt", "unretire", "--all", "--json"],
    ["adopt", "inventory"],
    ["adopt", "inventory", "--workspace", "acme", "--json"],
  ],
  notes: [
    "scan and plan print names, paths, kinds and counts, never a value; the files they write are 0600 under the mehen config root.",
    "No adopt subcommand rewrites or deletes a source file. Only retire --yes moves one, into a quarantine folder under the mehen root, and unretire puts it back.",
    "plan makes a value equal in two or more projects one workspace credential, which every member's machine may use, when this machine's owner is an owner or admin; --per-project keeps one item per project instead. A private home, a folder given a home with --home, a name already in the vault, a live key and a value with any copy in a protected environment are never merged; a protected value stays one item per project.",
    `submit seals each value in this process to the vault's key and uploads it into a batch of at most ${ADOPTION_LIMITS.maxItems} items; a human approves each batch with one passkey at the link it prints. A bigger plan is split into several batches, each project's items in one batch where they fit, and each batch is approved on its own.`,
    "--join adds this machine's items to an open batch of the same member's; given more than once, it fills the batches in order. What does not fit goes into a new batch, and submit prints every batch it used. An item whose name a joined batch already holds, from another machine with the same repo, goes as a compare row under that name; only this machine's own row is not sent again.",
    "plan and submit send a value whose name the vault already holds, in an item of its kind and provider, as a compare row under that name and print it as compare with <slug> in the vault; an item already proven in the vault goes as one too, so a value changed since is seen. The vault compares it with the holder for the reviewer alone, who keeps the vault's value, replaces it or keeps both; no answer to a machine says how they compare.",
    `submit sends each source's path, name and the time its file last changed with the row, and after the rows the plan's index for the inventory page: every item, ticked or not, with where it was found and the variables it backs, built from the plan and never a value. A vault without the index is not told; an index over ${ADOPTION_LIMITS.maxChunkBytes} bytes is not sent, and submit says so.`,
    "submit is refused, and nothing is sent, until a passed `mehen backup snapshot` on this machine holds every file the plan names unchanged; --join is no exception. It uses the newest such snapshot, or the one --snapshot names.",
    "apply and verify take every batch this machine submitted to for the plan's workspace that is open or approved, or the one --adoption names; they apply the approved ones and list those still waiting, so run apply again after each approval.",
    "apply, after approval, writes a mehen.toml where there is none (and prints the lines to add where there is one), sets each mapped variable in the vault, and prints the change a service unit needs; it never edits a unit. It records when it first applied a batch once every repo and service using it applied without an error, with no --repo or --env; --json lists each batch it could not record in unrecorded, with why.",
    "plan lists the gh login, Google OAuth tokens (1//, ya29. and a Google *_REFRESH_TOKEN), gcloud ADC and the Cloudflare CLI login as connectors, never uploaded, each with the mehen connect that replaces it where there is one; a Google token whose name says no service names none. A variable holding one maps to { connection: <slug> }: the one connection of that provider already in the vault, which the plan names, or one named for the provider. apply sets it once exactly that connection exists and otherwise prints the command.",
    "apply binds a compare row's variables to the slug the reviewer's decision names: the vault's item when its value was kept or replaced, or the new item when both were kept. It never moves a variable another machine or a human bound to another item: it prints set to <slug> by another machine and leaves it, as plan --check does.",
    "verify checks that every name in each source is provided by Mehen or skipped, runs mehen env check, and makes one read-only call through relay per item whose template has one.",
    "retire, a human's step, lists every source file of the plan (or those --repo and --path select) as ready or held with every reason, and without --yes changes nothing. A file is ready only when it is a .env or a NAME=value file in .local-secrets; it is a regular file with no other hard link that git does not track, unchanged since the newest snapshot holding it; verify covers every name in it, with nothing skipped, its env check passing and each live check ok or none; its repo or service ran cleanly under mehen run at least --min-runs times (3) over at least --min-days days (2) since its batch was applied, the newest run clean too, where clean is exit 0 or a SIGINT or SIGTERM mehen run passed on from its parent, never a crash (--path names a file nothing reads any more, such as a long-running service's, and skips this); and --compared, the `mehen backup compare --json` of that snapshot against an export taken after the batch was applied, has every variable of it matching. --json prints { files: [{ path, state, reasons, notes }], moved, held, unfinished }, with state ready, held, moved or failed.",
    "retire --yes moves exactly the ready files to adopt/<machine>/quarantine/<date>/<path hash>/<name> under the mehen root (0600, folders 0700), checking each again just before it moves, and prints how to put each back; nothing is deleted. Each move is written to quarantine/index.jsonl before it begins, and retire and unretire list in unfinished, as { path, at, aside, quarantined, note }, any a crash cut short, with where the file is. It exits 1 if a ready file could not be moved, or moved with an index line it could not write or save. An agent runs it only when the human asked for it.",
    "unretire puts quarantined files back with their recorded modes, each path given or --all, and refuses a file whose path is taken now. --json prints { files: [{ path, state, reasons, quarantined }], restored, refused, unfinished }, with state restored or refused; it exits 1 if any was refused.",
    "inventory lists this machine's plan, every item ticked or not, with its kind, home, files, when each changed and the variables it backs, and for each batch this machine submitted to what became of its rows (created, mapped, replaced, refused, left out or waiting), read from the plan, the local state and each batch's status, then the link to the workspace's inventory page. It reads nothing only an account sees, and never prints a value or how a compare row compared; a batch the vault no longer answers for (for example after this machine re-enrolled) is listed with its outcomes unknown. --json prints { plan, workspace, machine, items, batches, url }.",
  ],
  async run({ args, json, env }) {
    const out = new AdoptOutput(new OutputGuard(), json)
    try {
      const [sub, ...rest] = args.positionals
      const spec = sub ? SUBCOMMANDS[sub] : undefined
      if (!sub || !spec) throw usageError(`Unknown adopt step ${JSON.stringify(sub ?? "")}; use one of ${Object.keys(SUBCOMMANDS).join(", ")}.`, HELP)
      if (spec.positionals === "paths" ? rest.length > MAX_UNRETIRE_PATHS : rest.length !== spec.positionals) throw usageError(`mehen adopt ${sub} takes ${spec.positionals === "paths" ? `at most ${MAX_UNRETIRE_PATHS} paths` : spec.positionals === 0 ? "no other arguments" : "an adp_ id"}.`, HELP)
      const stray = ALL_FLAGS.filter((f) => given(args, f) && !spec.flags.includes(f))
      if (stray.length) throw usageError(`mehen adopt ${sub} does not take ${stray.map((f) => `--${f}`).join(", ")}.`, HELP)
      if (sub === "scan") return await runScan(args, env, out)
      if (sub === "plan") return await runPlan(args, env, out)
      if (sub === "submit") return await runSubmit(args, env, out)
      if (sub === "status") return await runStatus(adoptionId(rest[0]), env, out)
      if (sub === "apply") return await runApply(args, env, out)
      if (sub === "verify") return await runVerify(args, env, out)
      if (sub === "retire") return await runRetire(args, env, out)
      if (sub === "unretire") return await runUnretire(rest, args, env, out)
      if (sub === "inventory") return await runInventory(args, env, out)
      return await runCancel(adoptionId(rest[0]), env, out)
    } catch (error) {
      throw out.guard.error(error)
    }
  },
}
