// mehen adopt apply: wire each repo and service in the plan to the vault
// copy of what was approved. It writes a mehen.toml where there is none (and
// prints the lines to merge where there is one), sets each mapped variable
// in the vault (plain config as a vault plain value, never a literal in the
// committed file), and runs `mehen env check` per environment. It never
// moves, rewrites or deletes a source file, and never edits a service unit:
// the unit change is printed for a human or the tool that owns the unit.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import type { AdoptionStatus } from "@mehen/protocol/adopt"
import type { ItemSummary, Project } from "@mehen/protocol/api"
import { KINDS } from "@mehen/protocol/kinds"
import { secretLikeness } from "@mehen/protocol/secret-likeness"
import { CliError } from "../errors.ts"
import { listItems } from "../operations.ts"
import { envCommand } from "../run/env.ts"
import { CommandError, type Deps } from "../run/deps.ts"
import { manifestText } from "../run/init.ts"
import { MANIFEST_FILE, type Manifest, parseManifest } from "../run/manifest.ts"
import { type VaultApi, VaultApiError } from "../vault-api.ts"
import type { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, type PlanProject, type VarMapping, activeRepos, activeServices, connectorFor, isPublicSource, serviceSourcePaths, sourceKeys, variableSourceKeys } from "./plan.ts"
import { readSourceValues } from "./values.ts"

export type ApplyContext = {
  api: VaultApi
  config: Deps["config"]
  guard: OutputGuard
  home: string
  // Project slug to prj_ id, for the projects submit created.
  projects: Record<string, string>
}

export type ApplyOptions = { repos: string[] | null; env: string | null; dryRun: boolean }

// `unchanged`: the vault already had this item mapping, and apply left it
// alone; never true of a plain value, which apply always sets.
export type VarResult = { variable: string; env: string; set: "item" | "plain" | null; item: string | null; why: string | null; unchanged: boolean }
// `declared` and `resolved` are variable names from mehen.toml; `why` says
// why the check could not run (no mehen.toml, an unknown environment).
export type CheckResult = { env: string; ok: boolean; declared: string[]; unresolved: string[]; why: string | null }

export type TargetResult = {
  // A repo root, or a service unit's path.
  target: string
  kind: "repo" | "service"
  project: { slug: string; id: string } | null
  manifest: { path: string; state: "written" | "exists" | "merge" | "would-write" | "refused"; add: string[] }
  vars: VarResult[]
  // Variables in protected environments, which a human sets on the project page.
  humanSets: { variable: string; env: string; item: string }[]
  checks: CheckResult[]
  // The service unit change a human makes; empty for a repo.
  unitChange: string[]
  // Source files git tracks: their values are in history, so rotate them.
  committed: string[]
  error: string | null
}

// `paths`: the files the variable is read from.
type Wanted = { variable: string; env: string; mapping: VarMapping; paths: string[] }

function projectIdFor(project: PlanProject, ctx: ApplyContext): string | null {
  return project.id ?? ctx.projects[project.slug] ?? null
}

// Every row an approved batch decided, with the slug its variables use: a
// created row its new item (a compare row kept as a new item included), a
// mapped row the item that already held the name, and a replaced row that
// item, now holding the row's value. An older vault reports created only.
export function outcomes(status: AdoptionStatus): { ref: string; slug: string }[] {
  return [...(status.created ?? []), ...(status.mapped ?? []), ...(status.replaced ?? [])]
}

// What approved batches stored for this machine's plan: per plan ref, every
// slug a row's outcome names for it, across batches, and per such slug
// the source keys recorded for the plan ref in the batches that decided
// it; per plan ref, the slug the newest approved batch that decided it
// names (`newest`, batches oldest first, as state.ts keeps them); the
// slugs decided in a batch this machine has no ref map for; per plan ref
// in a batch still open, that batch; and per slug approved batches
// created, the source keys recorded for it whose variables apply has not
// yet bound (as unappliedSources). `refs` maps a plan ref to its
// row's ref in the batch and `sources` a plan ref to its source keys
// (state.ts); either is null when this machine recorded none for the batch.
export type StoredItems = { adoptions: string[]; slugs: ReadonlyMap<string, ReadonlySet<string>>; newest: ReadonlyMap<string, string>; sources: ReadonlyMap<string, ReadonlyMap<string, ReadonlySet<string>>>; unmapped: ReadonlySet<string>; waiting: ReadonlyMap<string, string>; unapplied: ReadonlyMap<string, ReadonlySet<string>> }

export function storedItems(batches: readonly { status: AdoptionStatus; refs: Readonly<Record<string, string>> | null; sources: Readonly<Record<string, readonly string[]>> | null; appliedAt?: string; bound?: readonly string[] }[]): StoredItems {
  const adoptions: string[] = []
  const slugs = new Map<string, Set<string>>()
  const newest = new Map<string, string>()
  const sourcesOf = new Map<string, Map<string, Set<string>>>()
  const unmapped = new Set<string>()
  const waiting = new Map<string, string>()
  for (const { status, refs, sources } of batches) {
    if (status.status === "open") for (const planRef of Object.keys(refs ?? {})) waiting.set(planRef, status.adoption)
    if (status.status !== "approved") continue
    adoptions.push(status.adoption)
    if (refs === null) {
      for (const c of outcomes(status)) unmapped.add(c.slug)
      continue
    }
    const planRefOf = new Map(Object.entries(refs).map(([planRef, ref]) => [ref, planRef]))
    for (const c of outcomes(status)) {
      const planRef = planRefOf.get(c.ref)
      if (planRef === undefined) continue
      slugs.set(planRef, (slugs.get(planRef) ?? new Set()).add(c.slug))
      newest.set(planRef, c.slug)
      const bySlug = sourcesOf.get(planRef) ?? new Map<string, Set<string>>()
      bySlug.set(c.slug, new Set([...(bySlug.get(c.slug) ?? []), ...(sources?.[planRef] ?? [])]))
      sourcesOf.set(planRef, bySlug)
    }
  }
  return { adoptions, slugs, newest, sources: sourcesOf, unmapped, waiting, unapplied: unappliedSources(batches) }
}

// Per slug approved batches created or replaced with a row's value, the
// source keys this machine recorded for the plan ref its row was uploaded
// under (state.ts `sources`). A batch with no ref map or no sources
// recorded gives none. A mapped row is no evidence: the reviewer may have
// kept the held value over a differing one.
export function storedSources(batches: readonly { status: AdoptionStatus; refs: Readonly<Record<string, string>> | null; sources: Readonly<Record<string, readonly string[]>> | null }[]): Map<string, Set<string>> {
  const stored = new Map<string, Set<string>>()
  for (const { status, refs, sources } of batches) {
    if (status.status !== "approved" || refs === null || sources === null) continue
    const planRefOf = new Map(Object.entries(refs).map(([planRef, ref]) => [ref, planRef]))
    for (const c of [...(status.created ?? []), ...(status.replaced ?? [])]) {
      const planRef = planRefOf.get(c.ref)
      const keys = planRef === undefined ? undefined : sources[planRef]
      if (keys?.length) stored.set(c.slug, new Set([...(stored.get(c.slug) ?? []), ...keys]))
    }
  }
  return stored
}

// As storedSources, for the batches apply has not applied all of
// (state.ts `appliedAt`), less the source keys whose variables apply has
// bound (`bound`): the only evidence that outweighs a project binding a
// variable to another item, since once apply has bound it, a binding to
// another item is a human's.
export function unappliedSources(batches: readonly { status: AdoptionStatus; refs: Readonly<Record<string, string>> | null; sources: Readonly<Record<string, readonly string[]>> | null; appliedAt?: string; bound?: readonly string[] }[]): Map<string, Set<string>> {
  return storedSources(
    batches.flatMap(({ appliedAt, bound = [], ...b }) => {
      if (appliedAt !== undefined) return []
      return [{ ...b, sources: b.sources && Object.fromEntries(Object.entries(b.sources).map(([planRef, keys]) => [planRef, keys.filter((key) => !bound.includes(key))])) }]
    }),
  )
}

// Per slug, the source keys of the variables `results` set to that item or
// found already set to it.
export function boundSources(plan: AdoptPlan, results: readonly TargetResult[]): Map<string, Set<string>> {
  const bound = new Map<string, Set<string>>()
  for (const result of results) {
    const repo = result.kind === "repo" ? plan.repos.find((r) => r.root === result.target) : undefined
    const service = result.kind === "service" ? plan.services.find((s) => s.unit === result.target) : undefined
    for (const row of result.vars) {
      if (row.set !== "item" || row.item === null) continue
      const paths = repo ? repo.files.filter((f) => f.env === row.env && "item" in (f.vars[row.variable] ?? {})).map((f) => join(repo.root, f.path)) : service ? serviceSourcePaths(service) : []
      bound.set(row.item, new Set([...(bound.get(row.item) ?? []), ...variableSourceKeys(plan, paths, row.variable)]))
    }
  }
  return bound
}

// The vault slug a mapping's item has, or why the variable is left alone.
// A row's outcome counts only under the plan item's own name: after a
// re-plan a ref can name another credential. The one exception is a slug
// the batch recorded one of the item's own sources for, as a compare row
// the reviewer kept as a new item, which outweighs an item already in the
// vault; the newest approved batch's such slug outweighs an older batch's
// outcome, the item's own name included. A workspace credential's name carries no project, so its row
// counts only when the batch recorded one of the item's own sources for
// the ref (as plan.ts reuses a held name).
export function mappedItem(plan: AdoptPlan, stored: StoredItems, ref: string): { slug: string } | { why: string } {
  const item = plan.items.find((i) => i.ref === ref)
  if (!item) return { why: `${ref} is not in the plan` }
  const slugs = stored.slugs.get(ref)
  const fromOwnSources = (slug: string) => {
    const recorded = stored.sources.get(ref)?.get(slug)
    return recorded !== undefined && recorded.size > 0 && sourceKeys(plan, item).some((key) => recorded.has(key))
  }
  const newest = stored.newest.get(ref)
  const renamed = newest !== undefined && fromOwnSources(newest) ? (newest === item.slug ? [] : [newest]) : slugs === undefined || slugs.has(item.slug) ? [] : [...slugs].filter(fromOwnSources)
  if ((item.include || item.exists) && renamed.length === 1) return { slug: renamed[0] as string }
  if (item.exists) return { slug: item.slug }
  if (!item.include) return { why: `${item.slug} is not included in the plan${item.note ? ` (${item.note})` : ""}`.slice(0, 300) }
  if (slugs?.has(item.slug) || (slugs === undefined && stored.unmapped.has(item.slug))) {
    if (item.home.kind !== "workspace" || fromOwnSources(item.slug)) return { slug: item.slug }
    const recorded = stored.sources.get(ref)?.get(item.slug)
    return { why: (recorded?.size ? `the batch stored ${item.slug} for ${ref} from other files; plan again` : `the batch stored ${item.slug} without recording which files it came from: if it holds this value, set this item's exists to true and include to false in the plan; otherwise plan again`).slice(0, 300) }
  }
  if (slugs !== undefined) return { why: `the batch stored ${[...slugs].join(", ")} for ${ref}, not this plan's item ${item.slug}`.slice(0, 300) }
  const waiting = stored.waiting.get(ref)
  return { why: waiting ? `${item.slug} is in ${waiting}, which is not approved yet` : `${item.slug} was not stored by the batch` }
}

// Whether git tracks `path` in the work tree at or above `root`; false
// outside one.
export function tracked(root: string, path: string): boolean {
  const result = Bun.spawnSync(["git", "-C", root, "ls-files", "--error-unmatch", "--", path], { stdout: "ignore", stderr: "ignore" })
  return result.exitCode === 0
}

function captureWriter(): Deps["stdout"] & { text(): string } {
  let text = ""
  const decoder = new TextDecoder()
  return { write: (chunk: string | Uint8Array) => (text += typeof chunk === "string" ? chunk : decoder.decode(chunk)), text: () => text }
}

// `mehen env check --env <env> --json` in this process, from `dir`.
export async function envCheck(dir: string, env: string, ctx: Pick<ApplyContext, "api" | "config">): Promise<CheckResult> {
  const stdout = captureWriter()
  const stderr = captureWriter()
  try {
    await envCommand(["check", "--env", env, "--json"], { api: ctx.api, config: ctx.config, stdout, stderr, cwd: dir, env: {} })
    const report = JSON.parse(stdout.text()) as { ok: boolean; variables: { name: string; resolved: boolean }[] } | { error: string; message?: string }
    // A check that could not run (no mehen.toml, say) answers with an error.
    if ("error" in report) return { env, ok: false, declared: [], unresolved: [], why: typeof report.message === "string" ? report.message : report.error }
    return { env, ok: report.ok, declared: report.variables.map((v) => v.name), unresolved: report.variables.filter((v) => !v.resolved).map((v) => v.name), why: null }
  } catch (error) {
    const why = error instanceof CommandError || error instanceof CliError ? error.message : "mehen env check failed"
    return { env, ok: false, declared: [], unresolved: [], why }
  }
}

// The manifest for one target: written when absent, otherwise read and
// compared. A literal value for a name adopt maps stops the target.
function manifestFor(dir: string, project: Project, names: string[], ctx: ApplyContext, dryRun: boolean): TargetResult["manifest"] & { conflict: string | null } {
  const path = join(dir, MANIFEST_FILE)
  if (!existsSync(path)) {
    // The head is fixed text and the vault's own ids and names, none of it
    // read from a file, so only the lines naming variables are checked: a
    // value read that sits inside the head (default in default_env, or the
    // workspace's name) is not leaked by writing it.
    const lines = names.map((n) => `${n} = "vault"\n`).join("")
    const text = `${manifestText(project, ctx.config)}${lines}`
    if (dryRun) return { path, state: "would-write", add: [], conflict: null }
    ctx.guard.assertClean(lines)
    mkdirSync(dir, { recursive: true })
    writeFileSync(path, text, { flag: "wx", mode: 0o644 })
    return { path, state: "written", add: [], conflict: null }
  }
  let manifest: Manifest
  try {
    manifest = parseManifest(path, readFileSync(path, "utf8"))
  } catch {
    return { path, state: "refused", add: [], conflict: `${path} is not a mehen.toml mehen can read` }
  }
  if (manifest.project !== project.id && manifest.project !== project.slug) return { path, state: "refused", add: [], conflict: `${path} names project ${manifest.project}, not ${project.slug} (${project.id})` }
  const plain = names.filter((n) => manifest.vars.some((v) => v.name === n && v.source === "plain"))
  if (plain.length) return { path, state: "refused", add: [], conflict: `${path} gives ${plain.join(", ")} a committed value; change ${plain.length === 1 ? "it" : "them"} to "vault" first` }
  const add = names.filter((n) => !manifest.vars.some((v) => v.name === n)).map((n) => `${n} = "vault"`)
  return { path, state: add.length ? "merge" : "exists", add, conflict: null }
}

// Why apply leaves a variable bound to another item, as plan --check says.
export function setElsewhere(current: string | null): string {
  return `set to ${current ?? "an item this machine cannot see"} by another machine: left as it was, as apply moves a bound variable only onto an item already in the vault that this machine's approved batch, not yet applied, stored from it; map it to the item holding its value, or skip it`
}

// The vault refuses a machine a workspace credential in a project shared
// with a guest or a team, which the plan cannot see, and in a project it
// may not edit; its refusal does not say which.
function workspaceSetRefused(slug: string): string {
  return `the vault refused it: forbidden; ${slug} is a workspace credential, and the project is possibly shared with a guest or a team, where a machine may not set one, or this machine may not edit the project: an owner or admin sets it on the project page or re-homes it, or plan again with mehen adopt plan --per-project for one item per project`
}

async function applyTarget(plan: AdoptPlan, stored: StoredItems, target: { kind: "repo" | "service"; key: string; dir: string; project: PlanProject; wanted: Wanted[]; unitChange: string[]; committed: string[] }, ctx: ApplyContext, options: ApplyOptions): Promise<TargetResult> {
  const result: TargetResult = { target: target.key, kind: target.kind, project: null, manifest: { path: join(target.dir, MANIFEST_FILE), state: "refused", add: [] }, vars: [], humanSets: [], checks: [], unitChange: target.unitChange, committed: target.committed, error: null }
  const id = projectIdFor(target.project, ctx)
  if (id === null) {
    result.error = `project ${target.project.slug} has no id yet; mehen adopt submit creates it`
    return result
  }
  const project = await ctx.api.request<Project>("GET", `/v1/projects/${encodeURIComponent(id)}`)
  result.project = { slug: project.slug, id: project.id }
  const wanted = target.wanted.filter((w) => options.env === null || w.env === options.env)
  const names = [...new Set(wanted.filter((w) => !("skip" in w.mapping)).map((w) => w.variable))]
  const { conflict, ...manifest } = manifestFor(target.dir, project, names, ctx, options.dryRun)
  result.manifest = manifest
  if (conflict) {
    result.error = conflict
    return result
  }
  const protectedEnvs = new Set(project.environments.filter((e) => e.protected).map((e) => e.name))
  const plainAllowed = (id: string) => {
    const source = plan.sources[id]
    return source !== undefined && (source.class === "config" || isPublicSource(source))
  }
  const plainIds = wanted.flatMap((w) => ("plain" in w.mapping && plainAllowed(w.mapping.plain) ? [w.mapping.plain] : []))
  const values = await readSourceValues(plan, plainIds, ctx.home, ctx.guard)
  // The OAuth connections this machine can see, read once and only when a
  // variable maps to one.
  let seen: Promise<ItemSummary[]> | null = null
  const connections = () => (seen ??= listItems(ctx.api, { kind: "oauth-connection" }).then((list) => list.items))
  for (const { variable, env, mapping, paths } of wanted) {
    const row: VarResult = { variable, env, set: null, item: null, why: null, unchanged: false }
    result.vars.push(row)
    const current = project.vars.find((v) => v.name === variable && v.env === env)
    if ("skip" in mapping) {
      row.why = mapping.skip
      continue
    }
    if (!project.environments.some((e) => e.name === env)) {
      row.why = `project ${project.slug} has no environment ${env}`
      continue
    }
    let body: { env: string; item?: string; field?: string; plain?: string }
    if ("item" in mapping) {
      const mapped = mappedItem(plan, stored, mapping.item)
      if ("why" in mapped) {
        row.why = mapped.why
        continue
      }
      const slug = mapped.slug
      // As plan --check: a variable bound to another item is never moved,
      // since that item may hold another value, another machine's or one a
      // human chose, unless the plan's own item is already in the vault and
      // an approved batch of this machine's apply has not yet bound stored
      // it from that variable. A new item, or a compare row kept under a new
      // name, never moves it: a variable the vault moved when the reviewer
      // kept both is bound to this slug already, and changes nothing.
      const item = plan.items.find((i) => i.ref === mapping.item)
      const rebinds = () => item?.exists === true && slug === item.slug && variableSourceKeys(plan, paths, variable).some((key) => stored.unapplied.get(slug)?.has(key))
      if (current?.source === "item" && current.item !== slug && !rebinds()) {
        row.why = setElsewhere(current.item).slice(0, 300)
        continue
      }
      row.item = slug
      if (protectedEnvs.has(env)) {
        row.why = "protected environment: a human sets it on the project page"
        result.humanSets.push({ variable, env, item: slug })
        continue
      }
      body = { env, item: slug, field: mapping.field }
    } else if ("connection" in mapping) {
      // Only the exact connection the plan named, of the provider its
      // connector expects; never another that appears later.
      const slug = mapping.connection
      const connector = connectorFor(plan, paths, variable)
      const held = (await connections()).find((c) => c.slug === slug)
      if (connector?.provider == null) {
        row.why = `no connector in the plan with a provider names ${variable}; plan again`
        continue
      }
      if (held === undefined || held.kind !== "oauth-connection" || held.provider !== connector.provider) {
        row.why = `${slug} is not a ${connector.provider} connection yet: ${connector.command ?? `mehen connect ${connector.provider}`}`.slice(0, 300)
        continue
      }
      if (current?.source === "item" && current.item !== slug) {
        row.why = setElsewhere(current.item).slice(0, 300)
        continue
      }
      row.item = slug
      if (protectedEnvs.has(env)) {
        row.why = "protected environment: a human sets it on the project page"
        result.humanSets.push({ variable, env, item: slug })
        continue
      }
      body = { env, item: slug, field: KINDS["oauth-connection"].primary as string }
    } else {
      if (!plainAllowed(mapping.plain)) {
        row.why = "a secret cannot be a plain value"
        continue
      }
      // As an item mapping: a variable bound to an item is never overwritten.
      if (current?.source === "item") {
        row.why = setElsewhere(current.item).slice(0, 300)
        continue
      }
      const read = values.get(mapping.plain)
      if (!read?.ok) {
        row.why = read?.why ?? "changed since scan"
        continue
      }
      if (secretLikeness(read.value)) {
        row.why = "looks like a secret, so it is not set as a plain value"
        continue
      }
      if (protectedEnvs.has(env)) {
        row.why = "protected environment: a human sets it on the project page"
        result.humanSets.push({ variable, env, item: "(plain value)" })
        continue
      }
      body = { env, plain: read.value }
    }
    // An item mapping the vault already has is left as it is. A plain
    // value is not shown to a device, so apply cannot tell whether the
    // vault's is the file's: it is set every time, and the same value
    // again changes nothing.
    row.unchanged = body.item !== undefined && current?.source === "item" && current.item === body.item && current.field === body.field
    if (!options.dryRun && !row.unchanged) {
      try {
        await ctx.api.request<Project>("PUT", `/v1/projects/${encodeURIComponent(project.id)}/vars/${variable}`, body)
      } catch (error) {
        const workspace = "item" in mapping && plan.items.find((i) => i.ref === mapping.item)?.home.kind === "workspace"
        row.why = !(error instanceof VaultApiError) ? "the vault call did not complete" : error.body.error === "forbidden" && workspace ? workspaceSetRefused(row.item as string) : `the vault refused it: ${error.body.error}`
        continue
      }
    }
    row.set = "plain" in mapping ? "plain" : "item"
  }
  if (!options.dryRun && (manifest.state === "written" || manifest.state === "exists" || manifest.state === "merge")) {
    for (const env of [...new Set(wanted.map((w) => w.env))]) result.checks.push(await envCheck(target.dir, env, ctx))
  }
  return result
}

function unitChange(service: AdoptPlan["services"][number], names: string[]): string[] {
  const run = `mehen run --env ${service.env} --`
  if (service.type === "launchd") {
    return [
      `in ${service.unit}:`,
      `  ProgramArguments: put ${run} before the existing arguments`,
      `  WorkingDirectory: ${service.dir}`,
      ...(names.length ? [`  EnvironmentVariables: remove ${names.join(", ")}`] : []),
      "then reload it (launchctl bootout and bootstrap, or the tool that owns it)",
    ]
  }
  return [
    `in ${service.unit}:`,
    `  ExecStart=: put ${run} before the existing command`,
    `  WorkingDirectory=${service.dir}`,
    ...(service.envFile ? [`  EnvironmentFile=${service.envFile}: remove the line`] : []),
    ...(names.length ? [`  Environment=: remove ${names.join(", ")}`] : []),
    "then systemctl --user daemon-reload and restart it (or the tool that owns it)",
  ]
}

// Each target's result is pushed to `results` as it finishes, so a caller
// still has the targets before one that threw.
export async function applyPlan(plan: AdoptPlan, stored: StoredItems, ctx: ApplyContext, options: ApplyOptions, results: TargetResult[] = []): Promise<TargetResult[]> {
  if (stored.adoptions.length === 0) throw new CliError("conflict", "No adoption batch is approved yet; apply runs after a human approves one.", { say: "Wait for the approval, then apply." })
  for (const repo of activeRepos(plan)) {
    if (options.repos !== null && !options.repos.includes(repo.root)) continue
    const wanted = repo.files.flatMap((f) => Object.entries(f.vars).map(([variable, mapping]) => ({ variable, env: f.env, mapping, paths: [join(repo.root, f.path)] })))
    const committed = repo.files.filter((f) => tracked(repo.root, f.path)).map((f) => join(repo.root, f.path))
    results.push(await applyTarget(plan, stored, { kind: "repo", key: repo.root, dir: repo.root, project: repo.project, wanted, unitChange: [], committed }, ctx, options))
  }
  if (options.repos === null) {
    for (const service of activeServices(plan)) {
      const wanted = Object.entries(service.vars).map(([variable, mapping]) => ({ variable, env: service.env, mapping, paths: serviceSourcePaths(service) }))
      const names = wanted.filter((w) => !("skip" in w.mapping)).map((w) => w.variable)
      results.push(await applyTarget(plan, stored, { kind: "service", key: service.unit, dir: service.dir, project: service.project, wanted, unitChange: unitChange(service, names), committed: [] }, ctx, options))
    }
  }
  return results
}
