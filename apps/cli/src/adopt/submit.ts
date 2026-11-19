// mehen adopt submit: read the values the plan names, seal each secret field
// to the vault in this process, and upload them into one batch a person
// approves with one passkey. Values exist only between the read and the
// seal; what leaves this module is ids, slugs, counts and the checked link.

import { createHash } from "node:crypto"
import { ADOPTION_ID, ADOPTION_LIMITS, ADOPTION_REF, type AdoptionCreated, type AdoptionIndexInput, type AdoptionItemUploadInput, type AdoptionStatus, type AdoptionUploaded, adoptionSealContext } from "@mehen/protocol/adopt"
import { type Me, PUBLIC_SEAL_KEY_PATH, type Project } from "@mehen/protocol/api"
import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { publicFieldRefusal } from "@mehen/protocol/secret-likeness"
import { type CredentialHome, NAME_UNAVAILABLE } from "@mehen/protocol/workspace"
import { type AskLink, type AskVault, askUrl, askUrlFor } from "../ask.ts"
import type { Config } from "../config.ts"
import { CliError } from "../errors.ts"
import type { VaultApi } from "../vault-api.ts"
import { VaultApiError } from "../vault-api.ts"
import { adoptionStatus } from "../operations.ts"
import { storedSources, unappliedSources } from "./apply.ts"
import type { OutputGuard } from "./output-guard.ts"
import { type AdoptPlan, type PlanContext, type PlanItem, type PlanProject, type PlanSource, activeRepos, activeServices, batchGroup, checkPlan, includedItems, packBatches, sendsRow, sourceKeys, uploadedSources, vaultFacts } from "./plan.ts"
import { type AdoptState, readState, writeState } from "./state.ts"
import { readSourceValues } from "./values.ts"

export type SubmitInput = {
  plan: AdoptPlan
  // Open batches to fill first, in order; empty to start new ones.
  join: string[]
  reason: string | null
  session: string | null
  machine: string
  home: string
}

export type SubmitContext = {
  api: VaultApi
  config: Pick<Config, "vault" | "tenant" | "workspaceSlug" | "owner">
  vault: AskVault
  stateDir: string
  guard: OutputGuard
}

// `exists`: items already in the vault that go as no compare row.
// `shared`: items whose own row a joined batch already holds.
export type SubmitSkipped = { exists: number; unsupported: number; changed: number; excluded: number; shared: number }

// One batch this submit uploaded into, each approved on its own.
export type SubmitBatch = {
  adoption: string
  link: AskLink
  expiresAt: string
  joined: boolean
  uploaded: { items: number; fields: number }
}

export type SubmitResult = {
  batches: SubmitBatch[]
  skipped: SubmitSkipped
  // Per ref, why this machine or the vault left it out. Reasons are fixed
  // text from this module or the vault's refusal, never a value.
  refused: { ref: string; reason: string }[]
  projects: { slug: string; id: string; created: boolean }[]
  // Per plan ref not uploaded because a joined batch already holds this
  // machine's own row for it: the batch and the machine.
  shared: { ref: string; slug: string; adoption: string; machine: string }[]
  // Per plan ref the vault took as a compare row: the name it compares
  // with and the batch it went to. No device answer says how they compare.
  compared: { ref: string; slug: string; adoption: string }[]
  // Joined batches whose status does not name their rows (a vault older
  // than that field): a name another machine put there may be refused.
  unchecked: string[]
  index: IndexSent
}

const SUBMIT = "mehen adopt submit"

// A batch a stopped submit leaves open: one it joined, one it opened and
// could not cancel, or one it opened where other machines (`others`, by
// name) have staged rows. `items`: this machine's rows the vault took into it.
export type OpenBatch = { adoption: string; url: AskLink["url"]; expiresAt: string; joined: boolean; items: number; others?: string[] }

// A submit that stopped after its batches were opened. The ones it opened
// are cancelled; `open` is every batch still open, which the caller records
// so `mehen pending` lists them.
export class SubmitStopped extends CliError {
  readonly open: OpenBatch[]

  constructor(code: CliError["code"], message: string, next: CliError["next"], open: OpenBatch[]) {
    super(code, message, next)
    this.open = open
  }
}

// The slugs this machine's approved batches stored for the workspace, each
// with the sources its rows came from: one evidence a plan takes that a
// held name is its value. `unappliedSlugs`: the same, less the sources
// whose variables apply has bound and the batches it applied all of
// (unappliedSources), the only ones that outweigh a project binding the
// variables to another item. A batch the vault no longer answers for, or
// one recorded without sources, proves nothing.
export async function storedSlugsFor(api: VaultApi, dir: string, workspace: string): Promise<Pick<PlanContext, "storedSlugs" | "unappliedSlugs">> {
  const batches: { status: AdoptionStatus; refs: Record<string, string> | null; sources: Record<string, string[]> | null; appliedAt?: string; bound?: string[] }[] = []
  for (const record of (await readState(dir)).adoptions.filter((a) => a.workspace === workspace && a.refs && a.sources)) {
    const status = await adoptionStatus(api, record.adoption).catch((error: unknown) => {
      if (error instanceof VaultApiError) return null
      throw error
    })
    if (status?.status === "approved") batches.push({ status, refs: record.refs ?? null, sources: record.sources ?? null, appliedAt: record.appliedAt, bound: record.bound })
  }
  return { storedSlugs: storedSources(batches), unappliedSlugs: unappliedSources(batches) }
}

export function workspaceMatches(plan: AdoptPlan, config: SubmitContext["config"]): boolean {
  return plan.workspace === config.workspaceSlug || plan.workspace === config.tenant
}

// What the vault must support, checked before any file is read.
async function requireAdoption(api: VaultApi): Promise<Me> {
  const me = await api.request<Me>("GET", "/v1/me")
  if (!me.capabilities?.sealedEnvImport) throw new CliError("not_available", "This vault does not take adopted credentials yet; nothing was read or sent.", { say: "Update the vault, then submit again." })
  if (me.workload) throw new CliError("forbidden", "A workload cannot adopt credentials; nothing was read or sent.", { say: "Run mehen adopt from the machine's own enrolment." })
  return me
}

type SealKey = { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }

function sameKey(a: SealKey, b: SealKey): boolean {
  return a.kid === b.kid && a.jwk.x === b.jwk.x && a.jwk.y === b.jwk.y && a.jwk.crv === b.jwk.crv
}

// The key the vault publishes; a batch's key must be the same one.
async function publishedSealKey(api: VaultApi): Promise<SealKey> {
  const key = await api.request<SealKey>("GET", PUBLIC_SEAL_KEY_PATH)
  if (!key || typeof key.kid !== "string" || key.jwk?.kty !== "EC" || key.jwk.crv !== "P-256" || typeof key.jwk.x !== "string" || typeof key.jwk.y !== "string") {
    throw new CliError("internal", "The vault's seal key is not one mehen can use; nothing was sent.", { say: "Check the vault URL and try again." })
  }
  return { kid: key.kid, jwk: { kty: "EC", crv: "P-256", x: key.jwk.x, y: key.jwk.y } }
}

function batchLink(vault: AskVault, adoption: string, given: string | undefined): AskLink {
  const sent = given ? askUrl(given, vault) : null
  const link = sent && sent.route?.prefix === "b" && sent.route.id === adoption ? sent : askUrlFor(vault, "adoption", adoption)
  if (!link) throw new CliError("internal", `The vault returned a review link mehen cannot check for ${adoption}.`, { say: "Check the vault URL and try again." })
  return link
}

// A batch keys its rows by ref alone, and every machine's plan numbers its
// items from a001, so each machine uploads under refs of its own: a, a tag
// from its device id, then the plan ref's digits. Two characters of tag
// when three would make the ref too long.
export function machineTag(device: string, length: 2 | 3): string {
  const n = createHash("sha256").update(device).digest().readUInt32BE(0)
  return (n % 36 ** length).toString(36).padStart(length, "0")
}

export function batchRef(planRef: string, device: string): string {
  const digits = planRef.slice(1)
  return `a${machineTag(device, digits.length <= 4 ? 3 : 2)}${digits}`
}

// Another machine in the batch whose tag is this one's: its rows could
// carry this machine's refs.
function sameTag(a: string, b: string): boolean {
  return machineTag(a, 3) === machineTag(b, 3) || machineTag(a, 2) === machineTag(b, 2)
}

type Batch = { adoption: string; link: AskLink; expiresAt: string; sealKey: SealKey; joined: boolean }

// An included item read as the plan says, its values in memory only.
// `compare`: sent under a name the vault or a joined batch holds.
type Ready = { item: PlanItem; secrets: Record<string, string>; publicFields: Record<string, string>; compare: boolean }

type Joined = Batch & { room: number; staged: AdoptionStatus["staged"] }

// An open batch to fill, with the room it has left: what every machine
// has staged in it counts.
async function joinBatch(id: string, ctx: SubmitContext, device: string, published: SealKey): Promise<Joined> {
  const status = await adoptionStatus(ctx.api, id)
  if (status.status !== "open") throw new CliError("conflict", `Adoption ${id} is ${status.status}; it takes no more uploads.`, { command: SUBMIT, say: "Submit without --join to start a new batch." })
  const clash = status.machines.find((m) => m.device !== device && sameTag(m.device, device))
  if (clash) throw new CliError("conflict", `Rows from this machine and from ${clash.name} could share refs in ${id}; nothing was sent.`, { command: SUBMIT, say: "Submit without --join to start a batch of this machine's own." })
  const staged = status.machines.reduce((n, m) => n + m.items, 0)
  return { adoption: id, link: batchLink(ctx.vault, id, undefined), expiresAt: status.expiresAt, sealKey: published, joined: true, room: Math.max(ADOPTION_LIMITS.maxItems - staged, 0), staged: status.staged }
}

async function createBatch(input: SubmitInput, ctx: SubmitContext, published: SealKey, expectedItems: number): Promise<Batch> {
  const created = await ctx.api.request<AdoptionCreated>("POST", "/v1/adoptions", {
    machine: input.machine,
    expectedItems: Math.min(Math.max(expectedItems, 1), ADOPTION_LIMITS.maxItems),
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.session ? { session: input.session } : {}),
  })
  if (!ADOPTION_ID.test(created.adoption)) throw new CliError("internal", "The vault returned an adoption id mehen does not recognise.", { say: "Check the vault URL and try again." })
  if (!sameKey(created.sealKey, published)) throw new CliError("internal", `The seal key for ${created.adoption} is not the key the vault publishes; nothing was sent.`, { command: `mehen adopt cancel ${created.adoption}`, say: "Cancel the batch and report this; do not submit again until it is explained." })
  return { adoption: created.adoption, link: batchLink(ctx.vault, created.adoption, created.url), expiresAt: created.expiresAt, sealKey: created.sealKey, joined: false }
}

// The projects the plan creates, created once: an id from an earlier
// submit (the state file) is used again. A project already in the vault
// is never created, so every repo's counts, as for a repo whose variables
// the plan skips because its mehen.toml names another project, whose items
// still go to the project its remote is.
async function ensureProjects(plan: AdoptPlan, ctx: SubmitContext, state: AdoptState): Promise<SubmitResult["projects"]> {
  const out: SubmitResult["projects"] = []
  const seen = new Set<string>()
  const existing = plan.repos.filter((r) => !r.project.create).map((r) => ({ project: r.project, remote: r.remote }))
  const planned: { project: PlanProject; remote: string | null }[] = [...activeRepos(plan).map((r) => ({ project: r.project, remote: r.remote })), ...activeServices(plan).map((s) => ({ project: s.project, remote: null })), ...existing]
  for (const { project, remote } of planned) {
    if (seen.has(project.slug)) continue
    seen.add(project.slug)
    if (!project.create) {
      if (project.id) out.push({ slug: project.slug, id: project.id, created: false })
      continue
    }
    const known = state.projects[project.slug]
    if (known) {
      out.push({ slug: project.slug, id: known, created: false })
      continue
    }
    let made: Project
    try {
      made = await ctx.api.request<Project>("POST", "/v1/projects", { slug: project.slug, remote, environments: project.environments.map((name) => ({ name, protected: false })), defaultEnv: project.environments.find((e) => e !== "prod" && e !== "production") ?? "dev" })
    } catch (error) {
      if (error instanceof VaultApiError && (error.body.error === "conflict" || error.body.error === "not_found")) {
        // plan found every project bound to a remote this machine may use,
        // so a taken remote is a project this machine cannot see.
        const taken = remote === null ? "the slug is taken" : `the slug is taken, or ${remote} is already the remote of a project this machine cannot use`
        throw new CliError("conflict", `The vault would not create project ${project.slug}: ${taken}.`, { command: "mehen adopt plan", say: remote === null ? `Choose another slug for ${project.slug} in the plan, or put the existing project's prj_ id there with create: false.` : `Ask an owner or admin to share the project with remote ${remote} with you, then plan again so this repo lands in it; or, if only the slug is taken, choose another slug for ${project.slug} in the plan.` })
      }
      throw error
    }
    state.projects[project.slug] = made.id
    await writeState(ctx.stateDir, state, ctx.guard)
    out.push({ slug: project.slug, id: made.id, created: true })
  }
  return out
}

async function stopSubmit(error: unknown, created: readonly Batch[], joined: readonly Batch[], took: ReadonlyMap<string, number>, device: string, ctx: SubmitContext): Promise<SubmitStopped> {
  const cancelled: string[] = []
  const open: OpenBatch[] = []
  const still = (batch: Batch, others?: string[]) => open.push({ adoption: batch.adoption, url: batch.link.url, expiresAt: batch.expiresAt, joined: batch.joined, items: took.get(batch.adoption) ?? 0, ...(others ? { others } : {}) })
  for (const batch of joined) still(batch)
  for (const batch of created) {
    // Another machine may have joined it from the pending list: its rows stay.
    const status = await adoptionStatus(ctx.api, batch.adoption).catch(() => null)
    const others = (status?.machines ?? []).filter((m) => m.device !== device && m.items > 0).map((m) => m.name)
    if (others.length) {
      still(batch, others)
      continue
    }
    const done = await ctx.api.request("POST", `/v1/adoptions/${batch.adoption}/cancel`, {}).then(
      () => true,
      () => false,
    )
    if (done) cancelled.push(batch.adoption)
    else still(batch)
  }
  if (cancelled.length) {
    const state = await readState(ctx.stateDir).catch(() => null)
    if (state) {
      state.adoptions = state.adoptions.filter((a) => !cancelled.includes(a.adoption))
      await writeState(ctx.stateDir, state, ctx.guard).catch(() => undefined)
    }
  }
  const cause = (error instanceof Error ? error.message : "the submit did not complete").replace(/[.\s]+$/, "")
  const items = (n: number) => `${n} item${n === 1 ? "" : "s"} from this machine`
  const parts = [
    ...(cancelled.length ? [`This submit cancelled ${cancelled.join(", ")}, which it opened`] : []),
    ...open.map((b) => `${b.adoption} is still open with ${items(b.items)} (${b.joined ? "joined" : b.others ? `opened by this submit; left open for ${b.others.join(", ")}, which staged rows in it` : "opened by this submit, which could not cancel it"})`),
  ]
  const code = error instanceof CliError ? error.code : error instanceof VaultApiError ? error.body.error : "failed"
  const next = open.length ? { command: `mehen adopt status ${(open[0] as OpenBatch).adoption}`, say: "Approve or cancel (mehen adopt cancel <adp_id>) each batch still open, then submit again." } : error instanceof CliError && error.next ? error.next : { command: SUBMIT, say: "Fix the cause, then submit again." }
  return new SubmitStopped(code, `The submit stopped after its batches were opened: ${cause}. ${parts.join("; ")}.`, next, open)
}

function credentialHome(item: PlanItem, projects: Map<string, string>, owner: SubmitContext["config"]["owner"]): CredentialHome | string {
  if (item.home.kind === "workspace") return { kind: "workspace" }
  if (item.home.kind === "private") return owner?.kind === "member" ? { kind: "member", member: owner.member } : "a private home needs a machine owned by a member"
  const id = projects.get(item.home.project) ?? (/^prj_/.test(item.home.project) ? item.home.project : null)
  return id ? { kind: "project", project: id } : `project ${item.home.project} has no id`
}

const CLEAR_PARTS_WITHHELD = "the output guard found a value read in what the vault keeps in the clear (its name, sources, repo or public fields), so it was not sent; scan and plan again"

// Whether the parts of a row the vault keeps in the clear hold no value the
// guard knows: all but the sealed values, and of the public fields only
// those the plan wrote, since one read from a source is that source's own
// value, sent in the clear by design once publicFieldRefusal passed it.
function keptInClearIsClean(upload: AdoptionItemUploadInput, item: PlanItem, guard: OutputGuard): boolean {
  const { sealed: _sealed, publicFields, ...clear } = upload
  const written = Object.fromEntries(Object.entries(publicFields).filter(([field]) => typeof item.publicFields[field] === "string"))
  return guard.clean(JSON.stringify({ ...clear, publicFields: written }))
}

// Where a value was found, as an upload or the index names it: never the value.
function sourceRef(s: PlanSource | undefined): AdoptionItemUploadInput["sources"][number] {
  return { path: s?.path ?? "", ...(s?.variable ? { variable: s.variable } : {}), ...(s?.pointer ? { pointer: s.pointer } : {}), stale: s?.stale ?? [], ...(s?.mtime ? { mtime: s.mtime } : {}) }
}

// The index of this machine's plan for the inventory page: every item,
// ticked or not, with where it was found and the variables it backs. Built
// from the plan alone, so nothing in it comes from a value. A project is
// named by its prj_ id, or by its slug while submit has not created it.
export function adoptionIndex(plan: AdoptPlan, machine: string, projects: ReadonlyMap<string, string>): AdoptionIndexInput {
  const projectOf = (project: PlanProject) => project.id ?? projects.get(project.slug) ?? project.slug
  const targets = [
    ...plan.repos.flatMap((r) => r.files.map((f) => ({ project: projectOf(r.project), env: f.env, vars: f.vars }))),
    ...plan.services.map((s) => ({ project: projectOf(s.project), env: s.env, vars: s.vars })),
  ]
  const storeOnly = new Set(plan.storeOnly.map((s) => s.ref))
  return {
    machine,
    items: plan.items.slice(0, ADOPTION_LIMITS.maxIndexItems).map((item) => ({
      ref: item.ref,
      slug: item.slug,
      kind: item.kind,
      provider: item.provider,
      home: item.home.kind,
      project: item.home.kind === "project" ? (projects.get(item.home.project) ?? item.home.project) : null,
      include: item.include,
      exists: item.exists,
      storeOnly: storeOnly.has(item.ref),
      sources: uploadedSources(item).map((id) => sourceRef(plan.sources[id])),
      uses: targets.flatMap((t) => Object.entries(t.vars).flatMap(([variable, m]) => ("item" in m && m.item === item.ref ? [{ project: t.project, env: t.env, variable, field: m.field }] : []))).slice(0, 64),
    })),
  }
}

// What became of the index: sent; not sent to a vault older than the
// index (404, said nowhere); over the vault's body limit, so not sent;
// withheld, as the output guard found a value in it; or refused, with the
// vault's code when it gave one. A submit whose rows are in never fails on
// its index.
export type IndexSent = { state: "sent" | "absent" | "oversize" | "withheld" | "refused"; bytes: number; error?: string }

async function sendIndex(index: AdoptionIndexInput, ctx: SubmitContext): Promise<IndexSent> {
  const text = JSON.stringify(index)
  const bytes = new TextEncoder().encode(text).length
  if (bytes > ADOPTION_LIMITS.maxChunkBytes) return { state: "oversize", bytes }
  if (!ctx.guard.clean(text)) return { state: "withheld", bytes }
  try {
    await ctx.api.request("POST", "/v1/adoptions/index", index)
    return { state: "sent", bytes }
  } catch (error) {
    if (error instanceof VaultApiError && error.status === 404) return { state: "absent", bytes }
    return { state: "refused", bytes, ...(error instanceof VaultApiError ? { error: error.body.error } : {}) }
  }
}

function repoOf(plan: AdoptPlan, item: PlanItem): AdoptionItemUploadInput["repo"] {
  for (const repo of plan.repos) {
    for (const file of repo.files) {
      if (Object.values(file.vars).some((m) => "item" in m && m.item === item.ref)) return { remote: repo.remote, env: file.env }
    }
  }
  return null
}

// Chunks under the vault's body limit and its 200 items per upload.
export function chunkUploads(items: AdoptionItemUploadInput[], maxBytes: number = ADOPTION_LIMITS.maxChunkBytes): AdoptionItemUploadInput[][] {
  const chunks: AdoptionItemUploadInput[][] = []
  let current: AdoptionItemUploadInput[] = []
  let size = 16
  for (const item of items) {
    const bytes = JSON.stringify(item).length + 1
    if (current.length && (current.length >= 200 || size + bytes > maxBytes)) {
      chunks.push(current)
      current = []
      size = 16
    }
    current.push(item)
    size += bytes
  }
  if (current.length) chunks.push(current)
  return chunks
}

export async function submitPlan(input: SubmitInput, ctx: SubmitContext): Promise<SubmitResult> {
  const me = await requireAdoption(ctx.api)
  const { plan } = input
  if (!workspaceMatches(plan, ctx.config)) throw new CliError("workspace_mismatch", `The plan is for workspace ${plan.workspace}, not this machine's ${ctx.config.workspaceSlug ?? ctx.config.tenant}.`, { command: "mehen adopt plan", say: "Plan again with --workspace set to the workspace you mean." })
  const ids = [...plan.repos, ...plan.services].flatMap((r) => (r.project.id ? [r.project.id] : []))
  const facts = await vaultFacts(ctx.api, [], ids, { me, ownerIsMember: ctx.config.owner?.kind === "member" })
  const check = checkPlan(plan, { protectedEnvs: facts.protectedEnvs, canCreateProjects: facts.canCreateProjects, boundVars: facts.boundVars, unappliedSlugs: (await storedSlugsFor(ctx.api, ctx.stateDir, plan.workspace)).unappliedSlugs })
  if (!check.ok) throw new CliError("bad_request", `The plan has ${check.problems.length} problem${check.problems.length === 1 ? "" : "s"}; nothing was read or sent.`, { command: "mehen adopt plan --check", say: "Fix each problem the check lists, then submit again." })
  const skipped: SubmitSkipped = { exists: plan.items.filter((i) => i.exists && !sendsRow(i)).length, unsupported: 0, changed: 0, excluded: plan.items.filter((i) => !i.include && !i.exists).length, shared: 0 }
  const refused: SubmitResult["refused"] = []
  const included = includedItems(plan)
  if (included.length === 0) throw new CliError("bad_request", "The plan includes no item to upload.", { command: "mehen adopt plan", say: "Set include: true on the items to adopt, then submit again." })

  // Values, in memory only.
  const sourceIds = included.flatMap((item) => [...Object.values(item.fields).flatMap((f) => f.from), ...Object.values(item.publicFields).flatMap((p) => (typeof p === "string" ? [] : [p.from]))])
  const values = await readSourceValues(plan, sourceIds, input.home, ctx.guard)
  const ready: Ready[] = []
  for (const item of included) {
    const secrets: Record<string, string> = {}
    const publicFields: Record<string, string> = {}
    let why: string | null = null
    for (const [field, source] of Object.entries(item.fields)) {
      const read = source.from.map((id) => values.get(id))
      const failed = read.find((r) => !r?.ok)
      if (failed) {
        why = failed.ok ? null : failed.why
        break
      }
      const distinct = new Set(read.map((r) => (r as { value: string }).value))
      if (distinct.size !== 1) {
        why = "changed since scan: the sources are no longer equal"
        break
      }
      secrets[field] = [...distinct][0] as string
    }
    for (const [field, source] of why ? [] : Object.entries(item.publicFields)) {
      if (typeof source === "string") {
        publicFields[field] = source
        continue
      }
      const read = values.get(source.from)
      if (!read?.ok) {
        why = read?.why ?? "changed since scan"
        break
      }
      if (publicFieldRefusal(item.kind, field, read.value)) {
        why = `the public field ${field} looks like a secret`
        break
      }
      publicFields[field] = read.value
    }
    if (why) {
      if (why.startsWith("changed")) skipped.changed++
      else skipped.unsupported++
      refused.push({ ref: item.ref, reason: why })
      continue
    }
    ready.push({ item, secrets, publicFields, compare: item.compare === true })
  }
  if (ready.length === 0) throw new CliError("bad_request", "No included item could be read as the plan says; nothing was sent.", { command: "mehen adopt scan", say: "Scan and plan again: the files changed since the scan." })

  const device = me.device
  const refs: Record<string, string> = {}
  for (const { item } of ready) refs[item.ref] = batchRef(item.ref, device)
  const uploadable = ready.filter(({ item }) => {
    if (ADOPTION_REF.test(refs[item.ref] as string)) return true
    skipped.unsupported++
    refused.push({ ref: item.ref, reason: "its ref is too long to upload: at most 5 characters after the a" })
    delete refs[item.ref]
    return false
  })
  if (uploadable.length === 0) throw new CliError("bad_request", "No included item has a ref that can be uploaded; nothing was sent.", { command: "mehen adopt plan", say: "Plan again: the plan's refs were edited." })

  // Batches to fill: the joined ones in the order given, then new ones of
  // at most maxItems, each project's items in one batch where they fit.
  const published = await publishedSealKey(ctx.api)
  const joined: Joined[] = []
  for (const id of input.join) joined.push(await joinBatch(id, ctx, device, published))
  // A name a joined batch already holds goes as a compare row, so the
  // reviewer sees whether the values agree; only this machine's own row
  // is not sent again.
  const holders = new Map<string, { adoption: string; ref: string; machine: string }>()
  for (const batch of joined) for (const row of batch.staged ?? []) if (!holders.has(row.slug)) holders.set(row.slug, { adoption: batch.adoption, ref: row.ref, machine: row.machine })
  // This machine's own row: the ref this plan ref uploads under, recorded
  // from one of the item's sources. Plan refs are positions, so after a
  // plan made again the same ref can hold another value.
  const state = await readState(ctx.stateDir)
  const ownRows = new Set(
    uploadable.flatMap(({ item }) => {
      const holder = holders.get(item.slug)
      if (holder === undefined || holder.ref !== refs[item.ref]) return []
      const recorded = state.adoptions.find((a) => a.adoption === holder.adoption)?.sources?.[item.ref] ?? []
      return sourceKeys(plan, item).some((key) => recorded.includes(key)) ? [item.ref] : []
    }),
  )
  const shared: SubmitResult["shared"] = []
  const sharedRefs = new Map<string, Record<string, string>>()
  const sending = uploadable.filter((ready) => {
    const { item } = ready
    const holder = holders.get(item.slug)
    if (holder === undefined) return true
    if (!ownRows.has(item.ref)) {
      ready.compare = true
      return true
    }
    shared.push({ ref: item.ref, slug: item.slug, adoption: holder.adoption, machine: holder.machine })
    sharedRefs.set(holder.adoption, { ...sharedRefs.get(holder.adoption), [item.ref]: holder.ref })
    skipped.shared++
    return false
  })
  const unchecked = joined.filter((b) => b.staged === undefined).map((b) => b.adoption)
  const packed = packBatches(sending, (r) => batchGroup(r.item), joined.map((b) => b.room))
  const needed = packed.length - joined.length
  if (needed > ADOPTION_LIMITS.maxOpenPerMember) throw new CliError("bad_request", `The plan needs ${needed} new batches of at most ${ADOPTION_LIMITS.maxItems} items, and at most ${ADOPTION_LIMITS.maxOpenPerMember} can be open at once; nothing was sent.`, { command: "mehen adopt plan --check", say: "Set include: false on some items and submit them once these batches are approved." })
  const created: Batch[] = []
  try {
    for (const items of packed.slice(joined.length)) created.push(await createBatch(input, ctx, published, items.length))
  } catch (error) {
    for (const batch of created) await ctx.api.request("POST", `/v1/adoptions/${batch.adoption}/cancel`, {}).catch(() => undefined)
    throw error
  }
  const filling = [...joined, ...created].map((batch, i) => ({ batch, items: packed[i] ?? [], shared: sharedRefs.get(batch.adoption) ?? {} })).filter((f) => f.items.length > 0 || Object.keys(f.shared).length > 0)
  const took = new Map<string, number>()
  let filled: Awaited<ReturnType<typeof fillBatches>>
  try {
    filled = await fillBatches(input, ctx, state, filling, refs, skipped, refused, took)
  } catch (error) {
    // The rows the vault took keep the sources recorded for them.
    await writeState(ctx.stateDir, state, ctx.guard).catch(() => undefined)
    throw await stopSubmit(error, created, joined, took, device, ctx)
  }
  const index = await sendIndex(adoptionIndex(input.plan, input.machine, new Map(filled.projects.map((p) => [p.slug, p.id]))), ctx)
  return { ...filled, shared, unchecked, index }
}

// A workspace credential's name carries no project, so it often meets an
// item, request or batch the vault counts and this machine cannot see.
function workspaceNameRefused(slug: string): string {
  return `${NAME_UNAVAILABLE.message}: the workspace already has ${slug}, perhaps an item, request or batch this machine cannot see; rename the item in the plan (its slug) and run mehen adopt plan --check, or plan again with --per-project, then submit again`
}

// The state, the projects and the uploads, once the batches are open.
// `took` counts the rows each batch has taken so far.
// `shared`: plan ref to this machine's own row that a joined batch holds.
async function fillBatches(input: SubmitInput, ctx: SubmitContext, state: AdoptState, filling: { batch: Batch; items: Ready[]; shared: Record<string, string> }[], refs: Record<string, string>, skipped: SubmitSkipped, refused: SubmitResult["refused"], took: Map<string, number>): Promise<Omit<SubmitResult, "shared" | "unchecked" | "index">> {
  const { plan } = input
  const submitted = new Date().toISOString()
  // A plan ref this run uploads, already recorded in the batch under
  // another ref (this machine's tag changed with its device id), keeps that
  // row until the vault takes the new one. Its sources are recorded only
  // once the vault takes it: a refused row leaves the batch's row as it was.
  const replacing = new Set<string>()
  for (const { batch, items, shared } of filling) {
    const uploading = Object.fromEntries(items.map(({ item }) => [item.ref, refs[item.ref] as string]))
    const batchRefs = { ...shared, ...uploading }
    const recorded = state.adoptions.find((a) => a.adoption === batch.adoption)
    const sources = { ...recorded?.sources }
    for (const [planRef, ref] of Object.entries(uploading)) {
      const before = recorded?.refs?.[planRef]
      if (before !== undefined && before !== ref) {
        batchRefs[planRef] = before
        replacing.add(`${batch.adoption}/${ref}`)
      }
    }
    state.adoptions = state.adoptions.filter((a) => a !== recorded)
    state.adoptions.push({ adoption: batch.adoption, url: batch.link.url, expiresAt: batch.expiresAt, workspace: plan.workspace, joined: batch.joined, refs: { ...recorded?.refs, ...batchRefs }, sources, submit: submitted, bound: recorded?.bound ?? [] })
  }
  await writeState(ctx.stateDir, state, ctx.guard)
  const projects = await ensureProjects(plan, ctx, state)
  const projectIds = new Map(projects.map((p) => [p.slug, p.id]))
  const planRefOf = new Map(Object.entries(refs).map(([planRef, ref]) => [ref, planRef]))
  const batches: SubmitBatch[] = []
  const compared: SubmitResult["compared"] = []
  let recordedTaken = false
  for (const { batch, items } of filling) {
    const key = await importSealPublicKey(batch.sealKey.jwk)
    const uploads: AdoptionItemUploadInput[] = []
    for (const { item, secrets, publicFields, compare } of items) {
      const ref = refs[item.ref] as string
      const home = credentialHome(item, projectIds, ctx.config.owner)
      if (typeof home === "string") {
        skipped.unsupported++
        refused.push({ ref: item.ref, reason: home })
        continue
      }
      const sealed: AdoptionItemUploadInput["sealed"] = {}
      for (const [field, value] of Object.entries(secrets)) sealed[field] = await seal(key, value, adoptionSealContext(batch.adoption, ref, field))
      const sources = uploadedSources(item).map((id) => {
        const s = plan.sources[id]
        return sourceRef(s)
      })
      const upload: AdoptionItemUploadInput = { ref, slug: item.slug, kind: item.kind, provider: item.provider, binding: item.provider ? null : (item.binding ?? null), injection: item.provider ? null : item.injection, home, tags: item.tags, publicFields, sealed, sources, repo: repoOf(plan, item), ...(compare ? { compare: true } : {}) }
      if (!keptInClearIsClean(upload, item, ctx.guard)) {
        skipped.unsupported++
        refused.push({ ref: item.ref, reason: CLEAR_PARTS_WITHHELD })
        continue
      }
      uploads.push(upload)
    }
    let accepted = 0
    let fields = 0
    for (const chunk of chunkUploads(uploads)) {
      const answer = await ctx.api.request<AdoptionUploaded>("POST", `/v1/adoptions/${batch.adoption}/items`, { items: chunk })
      const taken = new Set(Array.isArray(answer.accepted) ? answer.accepted : [])
      for (const item of chunk) {
        if (!taken.has(item.ref)) continue
        accepted++
        fields += Object.keys(item.sealed).length
        const record = state.adoptions.find((a) => a.adoption === batch.adoption)
        const planRef = planRefOf.get(item.ref)
        const planItem = planRef === undefined ? undefined : items.find((i) => i.item.ref === planRef)?.item
        if (planRef !== undefined && item.compare) compared.push({ ref: planRef, slug: item.slug, adoption: batch.adoption })
        if (record === undefined || planRef === undefined || planItem === undefined) continue
        record.sources = { ...record.sources, [planRef]: sourceKeys(plan, planItem) }
        if (replacing.has(`${batch.adoption}/${item.ref}`) && record.refs) record.refs[planRef] = item.ref
        recordedTaken = true
      }
      took.set(batch.adoption, accepted)
      for (const r of Array.isArray(answer.refused) ? answer.refused : []) {
        const planRef = planRefOf.get(String(r.ref)) ?? String(r.ref)
        const item = items.find((i) => i.item.ref === planRef)?.item
        const reason = String(r.reason)
        refused.push({ ref: planRef.slice(0, 16), reason: (item?.home.kind === "workspace" && reason === NAME_UNAVAILABLE.message ? workspaceNameRefused(item.slug) : reason).slice(0, 300) })
      }
    }
    batches.push({ adoption: batch.adoption, link: batch.link, expiresAt: batch.expiresAt, joined: batch.joined, uploaded: { items: accepted, fields } })
  }
  if (recordedTaken) await writeState(ctx.stateDir, state, ctx.guard)
  return { batches, skipped, refused, projects, compared }
}
