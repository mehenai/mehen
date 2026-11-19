// The plan: what adopt proposes to store and how each repo and service
// will read it, one editable JSON file per machine. It holds no value, no
// length and no hash of one; the only things derived from a value are a
// well-known prefix name in `reason` and the scan's random duplicate labels.
//
// `plan` builds it from the scan; `plan --check` (and submit, before it reads
// a file) checks an edited one against the rules that would otherwise fail
// late: slugs, kinds and fields, homes, a private credential mapped to a
// variable, and variables in a protected environment, which a human sets.

import { readFileSync } from "node:fs"
import { basename, dirname, extname, join, relative, sep } from "node:path"
import { ADOPTION_LIMITS, ADOPTION_REF } from "@mehen/protocol/adopt"
import { BACKUP_LIMITS } from "@mehen/protocol/backup"
import { NATURAL_INJECTION, isLeaseOnly, leaseOnlyAllowed, leaseOnlyRefusal } from "@mehen/protocol/binding"
import { BindingSchema, EnvName, InjectionSchema, type ItemSummary, KindSchema, type Me, type Project, Slug, Tag, VarName } from "@mehen/protocol/api"
import { type ItemKind, KINDS, isSlug } from "@mehen/protocol/kinds"
import { publicFieldRefusal } from "@mehen/protocol/secret-likeness"
import { getTemplate } from "@mehen/protocol/templates"
import { z } from "zod"
import { CliError } from "../errors.ts"
import { listItems } from "../operations.ts"
import { boundProject } from "../run/bound-project.ts"
import { slugFrom } from "../run/init.ts"
import { findManifest, parseManifest } from "../run/manifest.ts"
import { type VaultApi, VaultApiError } from "../vault-api.ts"
import { fileStemName, isPublicField } from "./classify.ts"
import { type ScanEntry, type ScanResult, folderOf, sourceKey } from "./scan.ts"
import { backupBase, backupCopy, envForFile, overridesFile } from "./sources.ts"

export const SOURCE_ID = /^s[a-z2-7]{4,12}$/
const SourceId = z.string().regex(SOURCE_ID)
const Ref = z.string().regex(ADOPTION_REF)
const FieldName = z.string().min(1).max(64)

// Sources a field takes: scan entries, not files. One value in four
// variables across 600 files is 2400 sources, though a snapshot holds the
// 600 files. As many as a snapshot holds files is far above the 48 seen on
// a real machine.
export const MAX_FIELD_SOURCES = BACKUP_LIMITS.maxFiles

const PlanHome = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("private") }),
  z.strictObject({ kind: z.literal("workspace") }),
  // A project slug from repos[] or services[], or a prj_ id.
  z.strictObject({ kind: z.literal("project"), project: z.string().min(1).max(64) }),
])
export type PlanHome = z.infer<typeof PlanHome>

const PlanItem = z.strictObject({
  ref: Ref,
  include: z.boolean(),
  slug: Slug,
  kind: KindSchema,
  provider: z.string().max(64).nullable(),
  // Only without a template.
  binding: BindingSchema.nullable(),
  injection: InjectionSchema.nullable(),
  home: PlanHome,
  tags: z.array(Tag).max(16),
  // Secret fields: one or more sources; several only when the scan put them
  // in one duplicate group, and submit re-checks they are equal.
  fields: z.record(FieldName, z.strictObject({ from: z.array(SourceId).min(1).max(MAX_FIELD_SOURCES) })),
  // Public fields: a literal, or a source submit reads.
  publicFields: z.record(FieldName, z.union([z.string().max(4096), z.strictObject({ from: SourceId })])),
  folder: z.string().min(1).max(1024),
  dup: z.string().max(16).nullable(),
  // A visible vault item already has this slug and the evidence says it
  // holds this value: mappings use the existing item.
  exists: z.boolean(),
  note: z.string().max(300).nullable(),
  // The slug is held in the vault, by an item proven this value (exists)
  // or one of its kind and provider that may be: the row goes under that
  // name for the vault to compare with the holder, and the reviewer
  // decides. Absent in older plans, whose exists items are never sent.
  compare: z.boolean().optional(),
})
export type PlanItem = z.infer<typeof PlanItem>

const PlanSource = z.strictObject({
  path: z.string().min(1).max(1024),
  type: z.enum(["dotenv", "envrc", "json", "secrets-file", "plist", "systemd", "gh-hosts", "kubeconfig", "talosconfig", "gcloud-adc", "wrangler", "docker"]),
  variable: VarName.nullable(),
  pointer: z.string().max(512).nullable(),
  class: z.enum(["secret", "config", "unknown"]),
  kind: KindSchema.nullable(),
  provider: z.string().max(64).nullable(),
  field: FieldName.nullable(),
  reason: z.string().max(200),
  dup: z.string().max(16).nullable(),
  stale: z.array(z.string().max(80)).max(4),
  status: z.enum(["new", "unsupported", "dynamic", "skipped", "connector"]),
  // A public field whose value looks like a secret (the scan's
  // publicLooksSecret); absent in older plans.
  publicLooksSecret: z.boolean().optional(),
  // A config value that looks like a secret (the scan's configLooksSecret);
  // absent in older plans.
  configLooksSecret: z.boolean().optional(),
  // A secret shaped like a production key (the scan's liveKey); absent in
  // older plans.
  liveKey: z.boolean().optional(),
  // When the file last changed (the scan's mtime); absent in older plans.
  mtime: z.iso.datetime().optional(),
})
export type PlanSource = z.infer<typeof PlanSource>

const VarMapping = z.union([
  z.strictObject({ item: Ref, field: FieldName }),
  // A non-secret value apply sets as a vault plain variable, never in mehen.toml.
  z.strictObject({ plain: SourceId }),
  z.strictObject({ skip: z.string().min(1).max(200) }),
  // An OAuth connection made with mehen connect, never uploaded: apply sets
  // the variable to that item once it exists. Absent in older plans.
  z.strictObject({ connection: Slug }),
])
export type VarMapping = z.infer<typeof VarMapping>

// A login or OAuth token the plan never uploads (a source of status
// connector): `provider` the template a connection uses, null when none
// fits; `command` the mehen connect that makes it, null when there is none.
const PlanConnector = z.strictObject({ source: SourceId, provider: z.string().max(64).nullable(), why: z.string().max(300), command: z.string().max(300).nullable() })
export type PlanConnector = z.infer<typeof PlanConnector>

export const GOOGLE_SERVICE_UNKNOWN = "connect the Google service it uses, then map it to { connection }"
const GOOGLE_CONNECT_ANY = 'mehen connect <google-gmail|google-calendar|google-drive> --name <slug> --reason "<why>"'

const BACKUP_ONLY = "backup copy only: not adopted; add it by hand if you still use it, or revoke it"
const CONFIG_LOOKS_SECRET = "looks like a secret, so it is not set as a plain value: store it with mehen request or set it by hand"
const PUBLIC_LOOKS_SECRET = "the vault keeps public fields in the clear and this one looks like a secret; add it by hand from the web app"

// What a mapping sets the variable to: an item's field, a plain source or
// a connection; null for a skip.
function targetOf(m: VarMapping): string | null {
  return "item" in m ? `${m.item}\u0000${m.field}` : "plain" in m ? m.plain : "connection" in m ? `connection\u0000${m.connection}` : null
}

const PlanProject = z.strictObject({ slug: Slug, id: z.string().max(64).nullable(), create: z.boolean(), environments: z.array(EnvName).min(1).max(16) })
export type PlanProject = z.infer<typeof PlanProject>

const PlanRepo = z.strictObject({
  root: z.string().min(1).max(1024),
  remote: z.string().max(300).nullable(),
  project: PlanProject,
  // `path` is relative to the root.
  files: z.array(z.strictObject({ path: z.string().min(1).max(1024), env: EnvName, vars: z.record(VarName, VarMapping) })),
})
export type PlanRepo = z.infer<typeof PlanRepo>

const PlanService = z.strictObject({
  unit: z.string().min(1).max(1024),
  type: z.enum(["launchd", "systemd"]),
  envFile: z.string().max(1024).nullable(),
  // Where apply writes the service's mehen.toml.
  dir: z.string().min(1).max(1024),
  project: PlanProject,
  env: EnvName,
  vars: z.record(VarName, VarMapping),
})
export type PlanService = z.infer<typeof PlanService>

export const FOLDER_HOMES = ["private", "workspace", "project", "skip"] as const
export type FolderHome = { home: (typeof FOLDER_HOMES)[number]; project: string | null }

export const AdoptPlanSchema = z.strictObject({
  version: z.literal(1),
  machine: z.string().min(1).max(64),
  // The workspace slug this plan uploads to; a folder for another
  // workspace is planned again with that --workspace.
  workspace: z.string().min(1).max(64),
  vault: z.string().min(1).max(300),
  scan: z.string(),
  // Per source folder, the home its credentials get (decisions 4 and 5).
  folders: z.array(z.strictObject({ path: z.string().min(1).max(1024), home: z.enum(FOLDER_HOMES), project: Slug.nullable(), items: z.number().int().min(0) })),
  items: z.array(PlanItem).max(4 * ADOPTION_LIMITS.maxItems),
  sources: z.record(SourceId, PlanSource),
  repos: z.array(PlanRepo),
  services: z.array(PlanService),
  storeOnly: z.array(z.strictObject({ ref: Ref, why: z.string().max(200) })),
  // Possibly stale or archived values: not adopted by default (decision 7);
  // a human checks each before revoking it at the provider.
  possiblyStale: z.array(z.strictObject({ source: SourceId, why: z.string().max(200) })),
  // Files apply never rewrites: settings and login state (decision 8, section 16).
  manual: z.array(z.strictObject({ source: SourceId, why: z.string().max(200) })),
  // Logins and OAuth tokens made into connections, never uploaded. Absent
  // in older plans.
  connectors: z.array(PlanConnector).optional(),
})
export type AdoptPlan = z.infer<typeof AdoptPlanSchema>

function schemaIssues(error: z.ZodError): string {
  return error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "(top)"}: ${i.message}`).join("; ")
}

export function parsePlan(raw: unknown, path: string): AdoptPlan {
  const parsed = AdoptPlanSchema.safeParse(raw)
  if (parsed.success) return parsed.data
  const where = schemaIssues(parsed.error)
  throw new CliError("bad_request", `${path} is not an adopt plan: ${where}.`, { command: "mehen adopt plan --check", say: "Fix the plan file where it says, or build it again with mehen adopt plan." })
}

const PROTECTED_BY_VAULT = new Set(["prod", "production"])

// `protectedEnvs`: the environments each existing project protects, by
// project id, which a rename leaves as it is; `project` is null for one
// submit creates.
function isProtectedEnv(project: string | null, env: string, protectedEnvs: ReadonlyMap<string, ReadonlySet<string>> | undefined): boolean {
  return PROTECTED_BY_VAULT.has(env) || (project !== null && (protectedEnvs?.get(project)?.has(env) ?? false))
}

// An item holding a live key read from a repo file for an environment that
// is not protected: every machine that runs the project there would get it.
// Each environment is named with its project, as `web dev`, since one item
// can hold files of several projects. `envs`: those environments where its
// variable maps to the item; `skipped`: those where the plan skips it;
// `kept`: the protected environments whose files hold it too; `exists`:
// already in the vault.
export type LiveKey = { ref: string; slug: string; provider: string | null; envs: string[]; skipped: string[]; kept: string[]; exists: boolean }

const LIVE_KEY_SKIP = "a live key: only the protected environment gets it"

export function liveKeysOutsideProtected(plan: Pick<AdoptPlan, "items" | "sources" | "repos">, protectedEnvs?: ReadonlyMap<string, ReadonlySet<string>>): LiveKey[] {
  const fileOf = new Map<string, { project: PlanProject; env: string; vars: Record<string, VarMapping> }>()
  for (const repo of plan.repos) for (const file of repo.files) fileOf.set(join(repo.root, file.path), { project: repo.project, env: file.env, vars: file.vars })
  const found: LiveKey[] = []
  for (const item of plan.items) {
    const envs = new Set<string>()
    const skipped = new Set<string>()
    const kept = new Set<string>()
    for (const id of Object.values(item.fields).flatMap((f) => f.from)) {
      const source = plan.sources[id]
      const file = source?.liveKey ? fileOf.get(source.path) : undefined
      if (!source || !file) continue
      const env = `${file.project.slug} ${file.env}`
      const mapping = source.variable === null ? undefined : file.vars[source.variable]
      if (isProtectedEnv(file.project.id, file.env, protectedEnvs)) kept.add(env)
      else if (mapping && "skip" in mapping) skipped.add(env)
      else envs.add(env)
    }
    if (envs.size || skipped.size) found.push({ ref: item.ref, slug: item.slug, provider: item.provider, envs: [...envs].sort(), skipped: [...skipped].sort(), kept: [...kept].sort(), exists: item.exists })
  }
  return found
}

// A workspace credential's projects, the first few by name, so the note
// stays within its 300 characters.
function usedByNote(projects: readonly string[]): string {
  const named = projects.length > 3 ? `${projects.slice(0, 3).join(", ")} and ${projects.length - 3} more` : projects.join(", ")
  return `used by ${projects.length} projects (${named}): one workspace credential; every member's machine may use it`
}

function liveKeyNote(live: LiveKey): string {
  const [project, env] = ([...live.envs, ...live.skipped][0] as string).split(" ")
  return `a live ${live.provider ? `${live.provider} ` : ""}key in a ${env} file: every machine that runs ${project} ${env} would get it. Adopt it into a protected environment on the project page, or tick it if ${env} really uses live keys.`
}

// One entry under plan --check's live keys heading.
export function liveKeyListing(live: LiveKey): string {
  const states = [...(live.exists ? ["already in the vault"] : []), ...(live.kept.length ? [`kept for ${live.kept.join(" and ")}`] : []), ...(live.skipped.length ? [`skipped in ${live.skipped.join(" and ")}`] : [])]
  return `${live.slug} (${[live.envs.join(" and "), states.join(", ")].filter((part) => part !== "").join(": ")})`
}

// What a plan needs of a vault item: whether adopt stored it, and as what.
export type VisibleItem = Pick<ItemSummary, "kind" | "provider" | "tags">

// `vars`: the variables bound to an item, by name, environment and item
// slug; `item` is null for one outside this machine's reach.
export type ExistingProject = { id: string; slug: string; environments: { name: string; protected: boolean }[]; vars: { name: string; env: string; item: string | null }[] }

// A repo whose committed mehen.toml names one project while the vault binds
// its remote to another: `manifest` is the slug of the project mehen.toml
// names, null for one this machine cannot see; `bound` is the remote's.
export type ProjectMismatch = { root: string; manifest: string | null; bound: string }

const MISMATCH_SKIP = /^mehen\.toml names (?:project ([a-z][a-z0-9-]*)|another project); the vault binds this repo's remote to project ([a-z][a-z0-9-]*)$/

// Why plan skips every variable of such a repo, which plan --check reads
// back from the plan. Two slugs of 64 characters would pass the 200 a
// skip holds, so the one mehen.toml names is then left out.
export function projectMismatchSkip(mismatch: ProjectMismatch): string {
  const named = (manifest: string | null) => `mehen.toml names ${manifest === null ? "another project" : `project ${manifest}`}; the vault binds this repo's remote to project ${mismatch.bound}`
  const text = named(mismatch.manifest)
  return text.length <= 200 ? text : named(null)
}

function projectMismatchOf(root: string, mapping: VarMapping): ProjectMismatch | null {
  const match = "skip" in mapping ? MISMATCH_SKIP.exec(mapping.skip) : null
  return match ? { root, manifest: match[1] ?? null, bound: match[2] as string } : null
}

export type PlanContext = {
  workspace: string
  vault: string
  machine: string
  home: string
  // The vault items this machine can see, by slug.
  visibleItems: ReadonlyMap<string, VisibleItem>
  // Per folder (a repo root or a file's folder), the home chosen with --home.
  homes: ReadonlyMap<string, FolderHome>
  // The project each repo already is, by repo root (vaultFacts).
  existing: ReadonlyMap<string, ExistingProject>
  // The repos whose mehen.toml names another project than the one the
  // vault binds their remote to, by repo root: their variables are skipped.
  projectMismatch?: ReadonlyMap<string, ProjectMismatch>
  // The slugs this machine's approved batches stored for this workspace,
  // each with the source keys (scan.ts sourceKey) its rows came from.
  storedSlugs: ReadonlyMap<string, ReadonlySet<string>>
  // As storedSlugs, from the approved batches apply has not yet applied all
  // of (state.ts appliedAt), less the sources whose variables apply has
  // bound (bound): until then the projects still bind those variables as
  // they were, and once bound a binding to another item is a human's.
  unappliedSlugs: ReadonlyMap<string, ReadonlySet<string>>
  // Where a value equal in two or more projects goes: one workspace
  // credential, or one item per project.
  sharedValues: "workspace" | "per-project"
}

function uniqueSlug(base: string, taken: Set<string>): string {
  const clean = (text: string) => text.slice(0, 64).replace(/-+$/, "")
  let slug = clean(base)
  if (!isSlug(slug)) slug = clean(`item-${base}`.replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-"))
  for (let n = 2; taken.has(slug); n++) slug = `${clean(base).slice(0, 60)}-${n}`
  taken.add(slug)
  return slug
}

function contextSlug(folder: string): string {
  return slugFrom(basename(folder).replace(/^\.+/, "")) || "local"
}

// The name an item's parts share in one file: AWS for AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY; the registry for a docker login.
function partGroup(entry: ScanEntry): string {
  if (entry.provider) return entry.provider
  if (entry.pointer !== null && entry.variable === null) return entry.pointer.replace(/\/[^/]*$/, "")
  return (entry.variable ?? "").replace(/_?(ACCESS_KEY_ID|SECRET_ACCESS_KEY|PASSWORD|PASSWD|PASS|USERNAME|USER|HOST|CLIENT_ID|CLIENT_SECRET)$/, "")
}

const MULTI_FIELD: ReadonlySet<ItemKind> = new Set(["cloud-access-key", "smtp-imap", "basic-auth", "oauth-client"])

function homeLabel(home: PlanHome): string {
  return home.kind === "project" ? `project:${home.project}` : home.kind
}

// Whether these variables use an item the plan includes. A repo or service
// with none (every credential stale, unticked or skipped, or only plain
// config such as a launchd PATH) gets no project, no mehen.toml and no
// variable: Mehen has nothing to deliver to it.
// A credential the plan stores, or one already in the vault that the
// mappings use: a second machine's repos are bound to those too.
export function usesAdoptedItem(plan: Pick<AdoptPlan, "items">, vars: Record<string, VarMapping>): boolean {
  return Object.values(vars).some((m) => "item" in m && plan.items.some((i) => i.ref === m.item && (i.include || i.exists)))
}

export function activeRepos(plan: AdoptPlan): AdoptPlan["repos"] {
  return plan.repos.filter((r) => r.files.some((f) => usesAdoptedItem(plan, f.vars)))
}

export function activeServices(plan: AdoptPlan): AdoptPlan["services"] {
  return plan.services.filter((s) => usesAdoptedItem(plan, s.vars))
}

// The home chosen for a folder or for the nearest folder above it, so
// --home ~/code/research=skip covers every repo under it.
export function chosenHome(homes: ReadonlyMap<string, FolderHome>, folder: string): FolderHome | undefined {
  for (let dir = folder; ; dir = dirname(dir)) {
    const home = homes.get(dir)
    if (home) return home
    if (dirname(dir) === dir) return undefined
  }
}

// The --home folders that are neither a folder the scan found nor above one.
export function unmatchedHomes(scan: ScanResult, homes: ReadonlyMap<string, FolderHome>): string[] {
  const folders = [...new Set(scan.entries.map(folderOf))]
  return [...homes.keys()].filter((dir) => !folders.some((f) => f === dir || f.startsWith(dir.endsWith(sep) ? dir : `${dir}${sep}`)))
}

export function buildPlan(scan: ScanResult, ctx: PlanContext, now = new Date()): AdoptPlan {
  const sources: AdoptPlan["sources"] = {}
  for (const e of scan.entries) {
    sources[e.id] = { path: e.path, type: e.type, variable: e.variable, pointer: e.pointer, class: e.class, kind: e.kind, provider: e.provider, field: e.field, reason: e.reason.slice(0, 200), dup: e.dup, stale: e.stale, status: e.status, publicLooksSecret: e.publicLooksSecret, configLooksSecret: e.configLooksSecret, liveKey: e.liveKey, ...(e.mtime === undefined ? {} : { mtime: e.mtime }) }
  }
  const projectSlugs = new Set<string>()
  const repoProjects = new Map<string, PlanProject>()
  const existingOf = new Map<PlanProject, ExistingProject>()
  // A skipped folder brings no repo: no project, no mehen.toml, no variable.
  const skipped = (folder: string) => chosenHome(ctx.homes, folder)?.home === "skip"
  const repoRoots = [...new Set(scan.entries.filter((e) => e.category === "repo" && e.repo).map((e) => (e.repo as { root: string }).root))].filter((root) => !skipped(root)).sort()
  const remoteOf = (root: string) => scan.entries.find((e) => e.repo?.root === root)?.repo?.remote ?? null
  // Every worktree and clone of one repository shares its project: the vault
  // binds a remote to one project. A repo without an origin is its own.
  const checkouts = new Map<string, string[]>()
  for (const root of repoRoots) {
    const repository = remoteOf(root) ?? root
    checkouts.set(repository, [...(checkouts.get(repository) ?? []), root])
  }
  for (const roots of checkouts.values()) {
    const first = roots[0] as string
    const existing = roots.map((root) => ctx.existing.get(root)).find((p) => p !== undefined)
    let project: PlanProject
    if (existing) {
      projectSlugs.add(existing.slug)
      project = { slug: existing.slug, id: existing.id, create: false, environments: existing.environments.map((e) => e.name) }
      existingOf.set(project, existing)
    } else {
      const slug = uniqueSlug(slugFrom(remoteOf(first)?.split("/").pop() ?? basename(first)) || "project", projectSlugs)
      project = { slug, id: null, create: true, environments: ["dev"] }
    }
    for (const root of roots) repoProjects.set(root, project)
  }
  const servicesSlug = uniqueSlug(`${slugFrom(ctx.machine) || "machine"}-services`, projectSlugs)
  const servicesProject: PlanProject = { slug: servicesSlug, id: null, create: true, environments: ["local"] }

  const folderHome = (entry: ScanEntry): FolderHome => {
    const chosen = chosenHome(ctx.homes, folderOf(entry))
    if (chosen) return chosen
    if (entry.category === "repo" && entry.repo) return { home: "project", project: repoProjects.get(entry.repo.root)?.slug ?? null }
    if (entry.category === "service") return { home: "project", project: servicesSlug }
    return { home: entry.home === "project" ? "private" : entry.home, project: null }
  }
  const homeOf = (entry: ScanEntry): PlanHome => {
    const f = folderHome(entry)
    if (f.home === "project" && f.project) return { kind: "project", project: f.project }
    return f.home === "workspace" ? { kind: "workspace" } : { kind: "private" }
  }

  // Group the parts of one credential, then merge equal values that would
  // land in the same home into one item. Backup copies come last, so a
  // live file starts each item.
  const candidates = scan.entries
    .filter((e) => e.class === "secret" && e.status === "new" && e.kind !== null && e.field !== null && folderHome(e).home !== "skip")
    .sort((a, b) => Number(backupCopy(a.path)) - Number(backupCopy(b.path)))
  const groups = new Map<string, ScanEntry[]>()
  for (const e of candidates) {
    const key = MULTI_FIELD.has(e.kind as ItemKind) ? `${e.path}\u0000${e.kind}\u0000${partGroup(e)}` : e.id
    groups.set(key, [...(groups.get(key) ?? []), e])
  }
  // `twins`: each part's field and duplicate label, equal for copies of one
  // credential; null when a part's value is unique. `projects`: for a
  // workspace credential made of equal values in several projects, those
  // projects.
  type Draft = { entries: ScanEntry[]; kind: ItemKind; provider: string | null; home: PlanHome; twins: string | null; copies: number; projects: string[] | null }
  const drafts: Draft[] = []
  const asConfig = new Set<string>()
  for (const parts of groups.values()) {
    const first = parts[0] as ScanEntry
    let kind = first.kind as ItemKind
    if (!parts.some((p) => !isPublicField(kind, p.field as string))) {
      for (const p of parts) asConfig.add(p.id)
      continue
    }
    let provider = first.provider
    if (provider === null && (kind === "api-key" || kind === "bearer-token")) kind = "generic"
    if (provider !== null && !getTemplate(provider)) provider = null
    const home = homeOf(first)
    const twins = parts.every((p) => p.dup !== null) ? parts.map((p) => `${p.field}\u0000${p.dup}`).sort().join("\u0001") : null
    const twin = twins === null ? undefined : drafts.find((d) => d.twins === twins && d.kind === kind && d.provider === provider && homeLabel(d.home) === homeLabel(home))
    if (twin) {
      twin.entries.push(...parts)
      twin.copies++
    } else drafts.push({ entries: [...parts], kind, provider, home, twins, copies: 1, projects: null })
  }
  // A value found only in backup copies makes no item and is listed as
  // possibly stale; a copy of a live value is a source of its item, so
  // submit checks the copies agree.
  const live = (d: Draft) => d.entries.some((e) => !backupCopy(e.path))
  const fieldName = (d: Draft, e: ScanEntry) => (d.kind === "generic" && (d.entries[0]?.kind === "api-key" || d.entries[0]?.kind === "bearer-token") ? "value" : (e.field as string))
  const dockerHost = (d: Draft) => {
    const first = d.entries[0] as ScanEntry
    return d.kind === "basic-auth" && first.type === "docker" ? first.reason.replace(/^docker login for /, "") : null
  }
  const fileName = (d: Draft) => basename((d.entries[0] as ScanEntry).path).replace(/^\.+/, "") || "file"
  const slugBase = (d: Draft) => {
    const first = d.entries[0] as ScanEntry
    return d.provider ?? ((MULTI_FIELD.has(d.kind) ? slugFrom(partGroup(first)) : first.variable ? slugFrom(first.variable) : first.type === "secrets-file" ? slugFrom(fileStemName(first.path)) : "") || d.kind)
  }
  const envSuffix = (d: Draft) => {
    const first = d.entries[0] as ScanEntry
    const env = first.category === "repo" ? envForFile(first.path) : null
    return env && env !== "dev" ? `-${env}` : ""
  }
  const itemSlug = (d: Draft) => slugFrom(`${slugBase(d)}-${d.home.kind === "project" ? d.home.project : contextSlug(folderOf(d.entries[0] as ScanEntry))}${envSuffix(d)}`)

  // The item slugs an existing project binds an entry's variable to in the
  // environment its file is for; null when no existing project holds it,
  // or when it is unbound where apply never sets it, which says nothing: an
  // environment protected or one the project lacks, or a live key's
  // variable, which the plan skips outside a protected one.
  const bindingOf = (e: ScanEntry): (string | null)[] | null => {
    const project = e.repo && e.variable !== null && !backupCopy(e.path) ? existingOf.get(repoProjects.get(e.repo.root) as PlanProject) : undefined
    if (!project) return null
    const env = envForFile(e.path)
    const items = project.vars.filter((v) => v.name === e.variable && v.env === env).map((v) => v.item)
    const applySets = !PROTECTED_BY_VAULT.has(env) && project.environments.some((x) => x.name === env && !x.protected)
    return items.length > 0 || (applySets && !e.liveKey) ? items : null
  }
  // Per variable of a draft that an existing project holds, its bindingOf.
  const bindingsOf = (d: Draft) => d.entries.flatMap((e) => {
    const items = bindingOf(e)
    return items === null ? [] : [items]
  })
  // The one item existing projects bind every variable of a draft they
  // hold to, or null.
  const boundItemOf = (d: Draft) => {
    const bindings = bindingsOf(d)
    const items = new Set(bindings.flat())
    return bindings.length > 0 && bindings.every((b) => b.length > 0) && items.size === 1 ? ([...items][0] ?? null) : null
  }
  // Kind, provider and the adopted tag say nothing of the value, so a held
  // item is reused only with evidence it holds this draft's. A workspace
  // credential's: a project binds one of its variables to it and none to
  // another item, or this machine's approved batch stored it from one of
  // the draft's sources and no project binds another. A project's: a
  // project binds every one of its variables to it; or this machine's
  // approved batch stored it from one of the draft's sources and no project
  // binds another; or such a batch not yet applied stored it, whatever the
  // bindings say until apply moves them, from every one of its variables a
  // project binds to another item, as plan --check asks.
  const provenFor = (d: Draft) => {
    const bound = bindingsOf(d).flat()
    const boundItem = boundItemOf(d)
    const storedIn = (slugs: ReadonlyMap<string, ReadonlySet<string>>, s: string) => d.entries.some((e) => slugs.get(s)?.has(sourceKey(e)))
    const movedFromOwnSource = (s: string) => d.entries.every((e) => (bindingOf(e) ?? []).every((b) => b === s) || ctx.unappliedSlugs.get(s)?.has(sourceKey(e)))
    const evidence = d.projects
      ? (s: string) => bound.every((b) => b === s) && (bound.length > 0 || storedIn(ctx.storedSlugs, s))
      : (s: string) => boundItem === s || (bound.every((b) => b === s) && storedIn(ctx.storedSlugs, s)) || (storedIn(ctx.unappliedSlugs, s) && movedFromOwnSource(s))
    return (s: string) => {
      const held = ctx.visibleItems.get(s)
      return held !== undefined && held.kind === d.kind && held.provider === d.provider && held.tags.includes("adopted") && evidence(s)
    }
  }

  // The environments each existing project protects, by project id.
  const existingProtected = new Map([...ctx.existing.values()].map((p) => [p.id, new Set(p.environments.filter((e) => e.protected).map((e) => e.name))]))

  // Equal values in two or more projects become one workspace credential:
  // one copy to rotate and one approval. Never a private home, a folder
  // given a home with --home, an item already in the vault, a value only
  // in backup copies, a live key, which stays one item per project for a
  // human to place, or a value with any source in a protected
  // environment, which every member's machine could use until a human set
  // it and then only an owner or admin could set; and only when every copy
  // would be the same item: kind, provider, fields and binding.
  if (ctx.sharedValues === "workspace") {
    const envOfEntry = (e: ScanEntry) => (e.category === "service" ? "local" : envForFile(backupCopy(e.path) ? backupBase(e.path) : e.path))
    const unprotected = (d: Draft) => {
      const project = d.home.kind === "project" ? d.home.project : ""
      const id = [...repoProjects.values()].find((p) => p.slug === project)?.id ?? null
      return d.entries.every((e) => !isProtectedEnv(id, envOfEntry(e), existingProtected))
    }
    const shape = (d: Draft) => JSON.stringify([d.kind, d.provider, [...new Set(d.entries.map((e) => fieldName(d, e)))].sort(), dockerHost(d), d.kind === "file" ? fileName(d) : null])
    const sharing = new Map<string, Draft[]>()
    for (const d of drafts) {
      if (d.twins === null || d.home.kind !== "project" || !live(d) || d.entries.some((e) => e.liveKey)) continue
      if (d.entries.some((e) => chosenHome(ctx.homes, folderOf(e)) !== undefined) || ctx.visibleItems.has(itemSlug(d)) || !unprotected(d)) continue
      sharing.set(d.twins, [...(sharing.get(d.twins) ?? []), d])
    }
    for (const group of sharing.values()) {
      const projects = [...new Set(group.map((d) => (d.home.kind === "project" ? d.home.project : "")))]
      if (projects.length < 2 || new Set(group.map(shape)).size > 1) continue
      const first = group[0] as Draft
      const shared: Draft = { entries: group.flatMap((d) => d.entries), kind: first.kind, provider: first.provider, home: { kind: "workspace" }, twins: first.twins, copies: group.reduce((n, d) => n + d.copies, 0), projects }
      drafts.splice(drafts.indexOf(first), 1, shared)
      for (const d of group.slice(1)) drafts.splice(drafts.indexOf(d), 1)
    }
  }

  // Whether another draft of this plan is proven the value of held slug s.
  const provers = new Map<Draft, (s: string) => boolean>()
  const provenByAnother = (d: Draft, s: string) =>
    drafts.some((o) => {
      if (o === d || !live(o)) return false
      if (!provers.has(o)) provers.set(o, provenFor(o))
      return (provers.get(o) as (s: string) => boolean)(s)
    })

  const slugs = new Set<string>()
  const items: PlanItem[] = []
  const storeOnly: AdoptPlan["storeOnly"] = []
  const possiblyStale: AdoptPlan["possiblyStale"] = []
  const manual: AdoptPlan["manual"] = []
  const itemOf = new Map<string, { ref: string; field: string }>()
  drafts.filter(live).forEach((d, index) => {
    const ref = `a${(index + 1).toString(36).padStart(3, "0")}`
    const first = d.entries[0] as ScanEntry
    const fields: PlanItem["fields"] = {}
    const publicFields: PlanItem["publicFields"] = {}
    for (const e of d.entries) {
      const field = fieldName(d, e)
      if (isPublicField(d.kind, field)) publicFields[field] = { from: e.id }
      else fields[field] = { from: [...(fields[field]?.from ?? []), e.id] }
      itemOf.set(e.id, { ref, field })
    }
    const derivedName = d.kind === "file" && !("filename" in publicFields) ? fileName(d) : null
    if (derivedName !== null) publicFields.filename = derivedName
    const notes: string[] = []
    if (d.projects) notes.push(usedByNote(d.projects))
    let include = true
    if (d.entries.some((e) => e.publicLooksSecret)) {
      include = false
      notes.push(PUBLIC_LOOKS_SECRET)
    }
    const missing = KINDS[d.kind].fields.filter((f) => f.required && !(f.name in fields) && !(f.name in publicFields)).map((f) => f.name)
    if (missing.length) {
      include = false
      notes.push(`missing ${missing.join(", ")}`)
    }
    let binding: PlanItem["binding"] = null
    const host = dockerHost(d)
    if (host !== null) {
      binding = { hosts: [host] }
      include = false
      notes.push("custom binding: check the registry host")
    }
    if (d.provider === null && (first.kind === "api-key" || first.kind === "bearer-token")) notes.push("no template: stored as generic; give it kind api-key and a binding to relay it")
    // A value also in a fresh file is current; only one found nowhere else
    // fresh is left unticked.
    const staleEntries = d.entries.filter((e) => e.stale.length)
    const stale = [...new Set(staleEntries.flatMap((e) => e.stale))]
    for (const e of staleEntries) possiblyStale.push({ source: e.id, why: e.stale.join(", ").slice(0, 200) })
    if (staleEntries.length && staleEntries.length === d.entries.length) {
      include = false
      notes.push(`possibly stale (${stale.join(", ")}): check before revoking at the provider; set include to true to adopt it`)
    } else if (staleEntries.length) notes.push(`${staleEntries.length} ${staleEntries.length === 1 ? "copy" : "copies"} possibly stale (${stale.join(", ")})`)
    if (d.copies > 1 && !d.projects) notes.push(`same value in ${d.copies} files`)
    // The one held item existing projects bind every variable of the draft
    // to is reused whatever its name, except for a workspace credential,
    // which is named without a project. Otherwise the computed name, or the
    // next one, proven this draft's. Failing that, the first held item of
    // its kind and provider that may be it and no other draft proves: the
    // row goes under that name as a compare row, never a second copy.
    const proven = provenFor(d)
    const bound = d.projects ? null : boundItemOf(d)
    let slug: string
    if (bound !== null && !slugs.has(bound) && proven(bound)) slug = bound
    else {
      const taken = new Set(slugs)
      const maybe: string[] = []
      for (;;) {
        slug = uniqueSlug(d.projects ? slugFrom(`${slugBase(d)}${envSuffix(d)}`) : itemSlug(d), taken)
        const held = ctx.visibleItems.get(slug)
        if (held === undefined || proven(slug)) break
        if (held.kind === d.kind && held.provider === d.provider && !provenByAnother(d, slug)) maybe.push(slug)
      }
      if (!ctx.visibleItems.has(slug) && maybe.length) slug = maybe[0] as string
    }
    slugs.add(slug)
    const compare = ctx.visibleItems.has(slug)
    const exists = compare && proven(slug)
    if (compare) notes.unshift(exists ? `compare with ${slug} in the vault, which mappings use already` : `compare with ${slug} in the vault: the reviewer decides which value it keeps`)
    // The vault refuses a file name that looks like a secret; only the
    // label changes, never the file's bytes.
    if (derivedName !== null && publicFieldRefusal("file", "filename", derivedName) !== null) {
      const ext = extname(derivedName)
      const neutral = publicFieldRefusal("file", "filename", `${slug}${ext}`) === null ? `${slug}${ext}` : `file${ext}`
      publicFields.filename = neutral
      notes.push(`the file's name looks like a secret, so it is stored named ${neutral}; its contents are unchanged`)
    }
    const why = d.entries.map((e) => e.storeOnly).find((w) => w !== null)
    if (why) storeOnly.push({ ref, why: why.slice(0, 200) })
    for (const e of d.entries) {
      if (e.category === "settings") manual.push({ source: e.id, why: "settings file: never rewritten; remove the value by hand once verify passes" })
      if (e.category === "login") manual.push({ source: e.id, why: "login file: stays in place (decision 8)" })
    }
    items.push({ ref, include, slug, kind: d.kind, provider: d.provider, binding, injection: null, home: d.home, tags: ["adopted"], fields, publicFields, folder: folderOf(first), dup: d.copies > 1 && !MULTI_FIELD.has(d.kind) ? first.dup : null, exists, note: notes.length ? notes.join("; ").slice(0, 300) : null, compare })
  })
  for (const d of drafts) if (!live(d)) for (const e of d.entries) possiblyStale.push({ source: e.id, why: BACKUP_ONLY })

  // Each login or OAuth token becomes a connection, made once and never
  // uploaded: the one connection of its provider the vault already holds,
  // or one named for the provider. The plan names the one it picks, so a
  // person sees it before apply binds to it.
  const connectionOf = (provider: string): { slug: string; held: boolean } => {
    const held = [...ctx.visibleItems].filter(([, v]) => v.kind === "oauth-connection" && v.provider === provider).map(([slug]) => slug)
    return held.length === 1 ? { slug: held[0] as string, held: true } : { slug: provider, held: false }
  }
  const connectors: PlanConnector[] = []
  for (const e of scan.entries) {
    if (e.status !== "connector" || backupCopy(e.path) || folderHome(e).home === "skip") continue
    const why = e.why ?? e.reason
    if (e.provider === null) {
      connectors.push({ source: e.id, provider: null, why: why.slice(0, 300), command: e.kind === "oauth-connection" ? GOOGLE_CONNECT_ANY : null })
      continue
    }
    const connection = connectionOf(e.provider)
    const note = connection.held ? `; uses the existing connection ${connection.slug}; to use another account, connect one with --name and map it` : ""
    const reason = e.variable ? `adopt: ${e.variable}` : `adopt: ${e.reason}`
    connectors.push({ source: e.id, provider: e.provider, why: `${why}${note}`.slice(0, 300), command: `mehen connect ${e.provider} --name ${connection.slug} --reason "${reason}"`.slice(0, 300) })
  }

  const mapping = (e: ScanEntry): VarMapping => {
    if (backupCopy(e.path)) return { skip: "backup copy" }
    if (e.status === "connector") return e.provider === null ? { skip: GOOGLE_SERVICE_UNKNOWN } : { connection: connectionOf(e.provider).slug }
    const target = itemOf.get(e.id)
    if (target) {
      const item = items.find((i) => i.ref === target.ref) as PlanItem
      return { item: target.ref, field: target.field }
    }
    // apply and the vault refuse a plain value that looks like a secret.
    if (e.configLooksSecret) return { skip: CONFIG_LOOKS_SECRET }
    if (e.class === "config" || asConfig.has(e.id)) return { plain: e.id }
    return { skip: (e.why ?? e.reason).slice(0, 200) || "not adopted" }
  }

  // Every file or unit that sets a variable of a project in an environment,
  // by project, environment and variable: the vault holds one value there.
  type Claim = { variable: string; env: string; vars: Record<string, VarMapping>; source: ScanEntry; root: string | null; where: string }
  const claims = new Map<string, Claim[]>()
  const varsOf = (project: PlanProject, env: string, list: ScanEntry[], root: string | null, where: string): Record<string, VarMapping> => {
    const vars: Record<string, VarMapping> = {}
    const sources = new Map<string, ScanEntry>()
    for (const e of list) {
      vars[e.variable as string] = mapping(e)
      sources.set(e.variable as string, e)
    }
    for (const [variable, source] of sources) {
      const key = `${project.slug}\u0000${env}\u0000${variable}`
      claims.set(key, [...(claims.get(key) ?? []), { variable, env, vars, source, root, where }])
    }
    return vars
  }

  const repos: PlanRepo[] = []
  for (const root of repoRoots) {
    const entries = scan.entries.filter((e) => e.category === "repo" && e.repo?.root === root && e.variable !== null && (e.type === "dotenv" || e.type === "envrc"))
    const project = repoProjects.get(root) as PlanProject
    const byFile = new Map<string, ScanEntry[]>()
    for (const e of entries) byFile.set(e.path, [...(byFile.get(e.path) ?? []), e])
    // A backup copy is for its base file's environment and adds none.
    const envOf = (path: string) => envForFile(backupCopy(path) ? backupBase(path) : path)
    // apply would refuse such a repo's mehen.toml, so none of its variables is set.
    const mismatch = ctx.projectMismatch?.get(root)
    const varsFor = (path: string, list: ScanEntry[]): Record<string, VarMapping> => (mismatch ? Object.fromEntries(list.map((e) => [e.variable as string, { skip: projectMismatchSkip(mismatch) }])) : varsOf(project, envOf(path), list, root, path))
    const files = [...byFile.entries()].map(([path, list]) => ({ path: relative(root, path), env: envOf(path), vars: varsFor(path, list) }))
    if (project.create) project.environments = [...new Set([...project.environments, ...files.filter((f) => !backupCopy(f.path)).map((f) => f.env)])]
    repos.push({ root, remote: remoteOf(root), project, files })
  }

  const services: PlanService[] = []
  for (const unit of scan.units) {
    const entries = scan.entries.filter((e) => e.unit === unit.path && e.variable !== null)
    if (entries.length === 0 || skipped(dirname(unit.path))) continue
    const envFile = unit.envFiles.find((f) => entries.some((e) => e.path === f)) ?? null
    const name = basename(unit.path).replace(/\.(plist|service)$/, "")
    const vars = varsOf(servicesProject, "local", entries, null, unit.path)
    services.push({ unit: unit.path, type: unit.type, envFile, dir: envFile ? dirname(envFile) : join(ctx.home, ".config", name), project: servicesProject, env: "local", vars })
  }

  // Where files disagree on a variable, one wins and the rest are skipped,
  // first difference first: a source not possibly stale; an override file
  // over its base; the file nearest its checkout root; the main checkout
  // (the shorter root) over a worktree; the lexically first path. A losing
  // secret is still its own item; it backs no variable.
  const depth = (c: Claim) => (c.root === null ? 0 : relative(c.root, c.where).split(sep).length)
  const order = (a: Claim, b: Claim) =>
    Number(a.source.stale.length > 0) - Number(b.source.stale.length > 0) ||
    Number(overridesFile(b.where, a.where)) - Number(overridesFile(a.where, b.where)) ||
    depth(a) - depth(b) ||
    (a.root?.length ?? 0) - (b.root?.length ?? 0) ||
    (a.where < b.where ? -1 : a.where > b.where ? 1 : 0)
  for (const list of claims.values()) {
    const set = list.filter((c) => targetOf(c.vars[c.variable] as VarMapping) !== null)
    if (new Set(set.map((c) => targetOf(c.vars[c.variable] as VarMapping))).size < 2) continue
    const winner = [...set].sort(order)[0] as Claim
    const won = targetOf(winner.vars[winner.variable] as VarMapping)
    for (const c of set) {
      if (targetOf(c.vars[c.variable] as VarMapping) === won) continue
      const named = winner.root === null ? `another unit sets ${c.variable} for ${c.env} (${winner.where})` : `another file sets ${c.variable} for ${c.env} (${winner.root === c.root ? relative(winner.root, winner.where) : winner.where})`
      c.vars[c.variable] = { skip: `${named}; the vault holds one value per environment`.slice(0, 200) }
    }
  }

  // A live key in a file for an environment that is not protected starts
  // unticked; one in a prod file stays ticked, and a human sets its variable.
  // Held in both, it stays ticked for prod and the other files' variables
  // are skipped, as are those of one already in the vault, which goes as a
  // compare row only when a prod file holds it.
  for (const live of liveKeysOutsideProtected({ items, sources, repos }, existingProtected)) {
    const item = items.find((i) => i.ref === live.ref) as PlanItem
    if (live.kept.length === 0) item.include = false
    if (live.kept.length === 0 && !live.exists) {
      item.note = [liveKeyNote(live), item.note].filter((n) => n !== null).join("; ").slice(0, 300)
      continue
    }
    for (const repo of repos) {
      for (const file of repo.files) {
        if (isProtectedEnv(repo.project.id, file.env, existingProtected)) continue
        for (const [variable, m] of Object.entries(file.vars)) if ("item" in m && m.item === live.ref) file.vars[variable] = { skip: LIVE_KEY_SKIP }
      }
    }
  }

  const counts = new Map<string, number>()
  for (const item of items) counts.set(item.folder, (counts.get(item.folder) ?? 0) + 1)
  const folderPaths = [...new Set(scan.entries.map((e) => folderOf(e)))].sort()
  const folders = folderPaths.map((path) => {
    const sample = scan.entries.find((e) => folderOf(e) === path) as ScanEntry
    const f = folderHome(sample)
    return { path, home: f.home, project: f.project, items: counts.get(path) ?? 0 }
  })
  const plan: AdoptPlan = { version: 1, machine: ctx.machine, workspace: ctx.workspace, vault: ctx.vault, scan: scan.scannedAt || now.toISOString(), folders, items, sources, repos, services, storeOnly, possiblyStale, manual, connectors }
  // Never a plan `plan --check` refuses to read.
  const parsed = AdoptPlanSchema.safeParse(plan)
  if (!parsed.success) {
    // Only a field with more sources than a snapshot holds is fixed by
    // skipping the folder with the most copies.
    const tooManySources = parsed.error.issues.some((i) => i.path.at(-1) === "from")
    const broken = parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "(top)"} (${i.message})`).join("; ")
    const next = tooManySources
      ? { command: "mehen adopt plan --home <folder>=skip", say: "Tell the human which folder holds the most copies; skip it with --home, or move copies aside, and plan again." }
      : { say: `Tell the human the plan breaks a rule at ${broken}; nothing was written.` }
    throw new CliError("failed", `mehen adopt plan built a plan that mehen adopt plan --check would refuse (${schemaIssues(parsed.error)}); nothing was written.`, next)
  }
  return plan
}

// ---------------------------------------------------------------- check

export type PlanProblem = { ref: string | null; where: string | null; problem: string }
export type HumanSets = { project: string; env: string; variable: string; item: string }
// An item whose public field looks like a secret: a human adds it from the
// web app, and submit never sends it.
export type ByHand = { ref: string; slug: string; field: string }
// `batches`: how many batches submit splits the included items into, each
// approved on its own. `sharedWorkspace`: included workspace credentials
// that variables of two or more projects use. `liveKeys`: items holding a
// live key from a file for an environment that is not protected, unticked
// or with that file's variable skipped. `compares`: the rows submit sends
// under a name the vault holds, for it to compare with the holder.
// `leftAlone`: variables mapped to an item this plan uploads, a connection
// or a plain value that a project binds to another item, which apply
// leaves as they are (`item` null for an item this machine cannot see). `projectMismatch`: repos whose
// mehen.toml names another project than their remote's, whose variables
// the plan skips; they stop nothing.
export type LeftAlone = { project: string; env: string; variable: string; item: string | null }
export type PlanCheck = { ok: boolean; included: number; batches: number; sharedWorkspace: number; problems: PlanProblem[]; humanSets: HumanSets[]; byHand: ByHand[]; liveKeys: LiveKey[]; compares: { ref: string; slug: string }[]; leftAlone: LeftAlone[]; projectMismatch: ProjectMismatch[] }

export type CheckOptions = {
  // Protected environments of existing projects, by project id.
  protectedEnvs?: ReadonlyMap<string, ReadonlySet<string>>
  // Whether this device may create projects (null: unknown, not checked).
  canCreateProjects?: boolean | null
  // The variables existing projects bind to an item, by project id.
  boundVars?: ReadonlyMap<string, ExistingProject["vars"]>
  // The slugs this machine's approved batches stored, each with the source
  // keys its rows came from whose variables apply has not yet bound
  // (PlanContext's unappliedSlugs).
  unappliedSlugs?: ReadonlyMap<string, ReadonlySet<string>>
  // The repos vaultFacts found a mehen.toml naming another project than
  // their remote's; a plan's own skips say the same for plan --check.
  projectMismatch?: readonly ProjectMismatch[]
}

// The connector a variable read from one of `paths` comes from.
export function connectorFor(plan: AdoptPlan, paths: readonly string[], variable: string): PlanConnector | undefined {
  return (plan.connectors ?? []).find((c) => {
    const source = plan.sources[c.source]
    return source !== undefined && source.variable === variable && paths.includes(source.path)
  })
}

// A source holding a public field of its kind, such as an access key id.
export function isPublicSource(source: PlanSource): boolean {
  return source.kind !== null && source.field !== null && isPublicField(source.kind, source.field)
}

// Whether submit uploads the item: an item already in the vault only as a
// compare row, which an older plan never marks.
export function sendsRow(item: PlanItem): boolean {
  return item.include && (!item.exists || item.compare === true)
}

export function includedItems(plan: AdoptPlan): PlanItem[] {
  return plan.items.filter(sendsRow)
}

// The plan sources an item's upload names, at most 32.
export function uploadedSources(item: PlanItem): string[] {
  return [...Object.values(item.fields).flatMap((f) => f.from), ...Object.values(item.publicFields).flatMap((p) => (typeof p === "string" ? [] : [p.from]))].slice(0, 32)
}

// The source keys of `variable` in the files at `paths`: where that
// variable's own value was found.
export function variableSourceKeys(plan: Pick<AdoptPlan, "sources">, paths: readonly string[], variable: string): string[] {
  return Object.values(plan.sources).flatMap((s) => (s.variable === variable && paths.includes(s.path) ? [sourceKey(s)] : []))
}

// The files a service's variables are read from: its unit and its
// environment file.
export function serviceSourcePaths(service: PlanService): string[] {
  return service.envFile ? [service.unit, service.envFile] : [service.unit]
}

// Where an item's upload says its value came from, as the state records it.
export function sourceKeys(plan: AdoptPlan, item: PlanItem): string[] {
  return uploadedSources(item).flatMap((id) => {
    const source = plan.sources[id]
    return source ? [sourceKey(source)] : []
  })
}

// What an item travels with when a submit fills several batches: its
// project, or else its home.
export function batchGroup(item: PlanItem): string {
  return item.home.kind === "project" ? `project:${item.home.project}` : item.home.kind
}

// Items into batches: one per entry of `rooms` (batches already open, with
// that much room left), then new batches of `size`. Each group goes whole
// into the first batch with room for it, largest group first; a group
// larger than a whole batch first fills new batches of its own. Each
// batch keeps the items' own order.
export function packBatches<T>(items: readonly T[], groupOf: (item: T) => string, rooms: readonly number[] = [], size: number = ADOPTION_LIMITS.maxItems): T[][] {
  const groups = new Map<string, T[]>()
  for (const item of items) {
    const key = groupOf(item)
    groups.set(key, [...(groups.get(key) ?? []), item])
  }
  const bins = rooms.map((room) => ({ room, items: [] as T[] }))
  for (const group of [...groups.values()].sort((a, b) => b.length - a.length)) {
    let rest = group
    for (; rest.length > size; rest = rest.slice(size)) bins.push({ room: size, items: rest.slice(0, size) })
    const bin = bins.find((b) => b.room - b.items.length >= rest.length)
    if (bin) bin.items.push(...rest)
    else bins.push({ room: size, items: [...rest] })
  }
  const order = new Map(items.map((item, i) => [item, i]))
  return bins.map((b) => b.items.sort((x, y) => (order.get(x) as number) - (order.get(y) as number)))
}

export function checkPlan(plan: AdoptPlan, options: CheckOptions = {}): PlanCheck {
  const problems: PlanProblem[] = []
  const humanSets: HumanSets[] = []
  const byHand: ByHand[] = []
  const leftAlone: LeftAlone[] = []
  const problem = (ref: string | null, where: string | null, text: string) => problems.push({ ref, where, problem: text })
  const refs = new Set<string>()
  const slugs = new Set<string>()
  const projects = new Map<string, PlanProject>()
  const disagree = new Set<string>()
  for (const { project } of [...plan.repos, ...plan.services]) {
    const seen = projects.get(project.slug)
    if (seen && (seen.id !== project.id || seen.create !== project.create)) disagree.add(project.slug)
    if (!seen) projects.set(project.slug, project)
  }
  for (const slug of disagree) problem(null, null, `the repos or services naming project ${slug} disagree on its id or create; give each the same id and create`)
  const knownProject = (p: string) => projects.has(p) || [...projects.values()].some((x) => x.id === p) || /^prj_[A-Za-z0-9_-]{1,60}$/.test(p)
  for (const item of plan.items) {
    if (refs.has(item.ref)) problem(item.ref, null, "this ref is used twice")
    refs.add(item.ref)
    if (item.exists && !sendsRow(item)) continue
    for (const [name, value] of Object.entries(item.publicFields)) {
      if (typeof value === "string" || !plan.sources[value.from]?.publicLooksSecret) continue
      byHand.push({ ref: item.ref, slug: item.slug, field: name })
      if (item.include) problem(item.ref, null, `${name} is a public field, which the vault keeps in the clear, and its value looks like a secret; set include to false and add ${item.slug} by hand from the web app`)
    }
    if (!item.include) continue
    if (slugs.has(item.slug)) problem(item.ref, null, `the slug ${item.slug} is used twice`)
    slugs.add(item.slug)
    const spec = KINDS[item.kind]
    if (item.provider !== null) {
      const template = getTemplate(item.provider)
      if (!template) problem(item.ref, null, `there is no template ${item.provider}`)
      else if (template.kind !== item.kind) problem(item.ref, null, `template ${item.provider} is for ${template.kind}, not ${item.kind}`)
      if (item.binding !== null || item.injection !== null) problem(item.ref, null, "a template item takes no binding or injection")
    } else {
      if ((!item.binding?.hosts.length || isLeaseOnly(item.binding)) && !leaseOnlyAllowed(item.kind)) problem(item.ref, null, leaseOnlyRefusal(item.kind))
      if (item.injection !== null && NATURAL_INJECTION[item.kind] === null) problem(item.ref, null, `The relay never puts a ${spec.label} into a request, so it takes no injection. Leave it out.`)
    }
    for (const name of Object.keys(item.fields)) {
      const f = spec.fields.find((x) => x.name === name)
      if (!f || !f.secret) problem(item.ref, null, `${name} is not a secret field of ${item.kind}`)
    }
    // A source's value is not in the plan: the scan judged it (byHand) and
    // submit checks it once read.
    for (const [name, value] of Object.entries(item.publicFields)) {
      const refusal = publicFieldRefusal(item.kind, name, typeof value === "string" ? value : "")
      if (refusal) problem(item.ref, null, `the vault would refuse ${item.slug}: ${refusal}`)
    }
    for (const f of spec.fields) if (f.required && !(f.name in item.fields) && !(f.name in item.publicFields)) problem(item.ref, null, `the required field ${f.name} is missing`)
    if (Object.keys(item.fields).length === 0) problem(item.ref, null, "no secret field to upload")
    for (const [name, source] of Object.entries(item.fields)) {
      const from = source.from.map((id) => plan.sources[id])
      if (from.some((s) => s === undefined)) problem(item.ref, null, `${name} names a source that is not in sources`)
      else if (from.length > 1 && (from[0]?.dup === null || from.some((s) => s?.dup !== from[0]?.dup))) problem(item.ref, null, `${name} takes several sources that the scan did not find equal`)
    }
    for (const [name, value] of Object.entries(item.publicFields)) if (typeof value !== "string" && !plan.sources[value.from]) problem(item.ref, null, `${name} names a source that is not in sources`)
    if (item.home.kind === "project" && !knownProject(item.home.project)) problem(item.ref, null, `project ${item.home.project} is not in repos or services`)
  }
  // Per project, environment and variable, the first target set and where.
  const setBy = new Map<string, { target: string; where: string }>()
  const conflicting = new Set<string>()
  // Per item ref, the projects whose variables use it.
  const usedBy = new Map<string, Set<string>>()
  // `paths`: the files the variables were read from.
  const checkVars = (project: PlanProject, env: string, vars: Record<string, VarMapping>, where: string, paths: readonly string[]) => {
    const protectedEnv = isProtectedEnv(project.id, env, options.protectedEnvs)
    for (const [variable, m] of Object.entries(vars)) {
      if ("skip" in m) continue
      if ("item" in m) usedBy.set(m.item, new Set([...(usedBy.get(m.item) ?? []), project.slug]))
      const target = targetOf(m) as string
      const key = `${project.slug}\u0000${env}\u0000${variable}`
      const first = setBy.get(key)
      if (!first) setBy.set(key, { target, where })
      else if (first.target !== target && !conflicting.has(key)) {
        conflicting.add(key)
        problem(null, where, `${variable} for ${env} in project ${project.slug} is set by ${first.where} and by ${where} to different values; the vault holds one value per environment, so skip one`)
      }
      if ("plain" in m) {
        const s = plan.sources[m.plain]
        if (!s) problem(null, where, `${variable} names a source that is not in sources`)
        else if (s.class === "secret" && !isPublicSource(s)) problem(null, where, `${variable} is a secret, not plain config`)
        if (protectedEnv && !first) humanSets.push({ project: project.slug, env, variable, item: "(plain value)" })
        const current = (project.id === null ? undefined : options.boundVars?.get(project.id))?.find((v) => v.name === variable && v.env === env)
        if (!first && current !== undefined) leftAlone.push({ project: project.slug, env, variable, item: current.item })
        continue
      }
      if ("connection" in m) {
        if (connectorFor(plan, paths, variable)?.provider == null) problem(null, where, `${variable} maps to connection ${m.connection}, but no connector in the plan with a provider names it`)
        if (protectedEnv && !first) humanSets.push({ project: project.slug, env, variable, item: m.connection })
        const current = (project.id === null ? undefined : options.boundVars?.get(project.id))?.find((v) => v.name === variable && v.env === env)
        if (!first && current !== undefined && current.item !== m.connection) leftAlone.push({ project: project.slug, env, variable, item: current.item })
        continue
      }
      const item = plan.items.find((i) => i.ref === m.item)
      if (!item) {
        problem(null, where, `${variable} maps to ${m.item}, which is not in items`)
        continue
      }
      if (!(m.field in item.fields) && !(m.field in item.publicFields)) problem(item.ref, where, `${variable} maps to field ${m.field}, which ${item.ref} does not have`)
      if (item.home.kind === "private" && (item.include || item.exists)) problem(item.ref, where, `${variable} maps to ${item.slug}, a private credential, which cannot back a project variable; give it a project or workspace home`)
      if (item.home.kind === "project" && item.home.project !== project.slug && item.home.project !== project.id) problem(item.ref, where, `${variable} maps to ${item.slug}, which belongs to project ${item.home.project}; a project credential backs only its own project's variables`)
      // Moving a bound variable onto another item swaps its value for
      // whatever that item holds, unless the item is already in the vault
      // and this machine's approved batch not yet applied stored it from
      // this variable: apply leaves it, and a plan saying the value is
      // already in another held item is wrong.
      const current = (project.id === null ? undefined : options.boundVars?.get(project.id))?.find((v) => v.name === variable && v.env === env)
      const rebinds = () => item.exists && variableSourceKeys(plan, paths, variable).some((key) => options.unappliedSlugs?.get(item.slug)?.has(key))
      const elsewhere = !first && current !== undefined && current.item !== item.slug && !rebinds()
      if (elsewhere && !item.exists && sendsRow(item)) leftAlone.push({ project: project.slug, env, variable, item: current.item })
      if (elsewhere && item.exists) problem(item.ref, where, `${variable} for ${env} in project ${project.slug} uses ${current.item ?? "an item this machine cannot see"} in the vault; this plan moves it to ${item.slug}, another item already there that may hold another value: map it to the item holding its value, or skip it`)
      if (protectedEnv && !first && (item.include || item.exists)) humanSets.push({ project: project.slug, env, variable, item: item.slug })
    }
  }
  for (const repo of plan.repos) {
    if (!repo.project.create && repo.project.id === null) problem(null, repo.root, "the project has neither an id nor create: true")
    for (const file of repo.files) {
      if (!repo.project.environments.includes(file.env) && Object.values(file.vars).some((m) => !("skip" in m))) problem(null, join(repo.root, file.path), `the project has no environment ${file.env}`)
      checkVars(repo.project, file.env, file.vars, join(repo.root, file.path), [join(repo.root, file.path)])
    }
  }
  for (const service of plan.services) checkVars(service.project, service.env, service.vars, service.unit, serviceSourcePaths(service))
  const creating = [...projects.values()].filter((p) => p.create)
  if (creating.length && options.canCreateProjects === false) problem(null, null, `this machine may not create projects (${creating.map((p) => p.slug).join(", ")}); a human creates them, then put each id in the plan with create: false`)
  const included = includedItems(plan)
  const sharedWorkspace = included.filter((i) => i.home.kind === "workspace" && (usedBy.get(i.ref)?.size ?? 0) > 1).length
  // A human ticking a key held only in unprotected files takes it there; one
  // also kept for a protected environment, or already in the vault, is
  // listed while any unprotected variable still maps to it.
  const liveKeys = liveKeysOutsideProtected(plan, options.protectedEnvs).filter((k) => k.skipped.length || !plan.items.find((i) => i.ref === k.ref)?.include || (k.envs.length && (k.kept.length || k.exists)))
  const compares = included.filter((i) => i.compare === true).map((i) => ({ ref: i.ref, slug: i.slug }))
  const projectMismatch = new Map((options.projectMismatch ?? []).map((m) => [m.root, m]))
  for (const repo of plan.repos) {
    const mismatch = repo.files.flatMap((f) => Object.values(f.vars)).map((m) => projectMismatchOf(repo.root, m)).find((m) => m !== null)
    if (mismatch && !projectMismatch.has(repo.root)) projectMismatch.set(repo.root, mismatch)
  }
  return { ok: problems.length === 0, included: included.length, batches: packBatches(included, batchGroup).length, sharedWorkspace, problems, humanSets, byHand, liveKeys, compares, leftAlone, projectMismatch: [...projectMismatch.values()] }
}

// How many values an owner's or admin's machine would make workspace
// credentials: what a member's plan says it kept one per project. None
// when that plan, which this machine never writes, would break the schema.
export function sharedIfAllowed(scan: ScanResult, ctx: PlanContext): number {
  try {
    return checkPlan(buildPlan(scan, { ...ctx, sharedValues: "workspace" })).sharedWorkspace
  } catch {
    return 0
  }
}

// A --home value: <folder>=private|workspace|project:<slug>|skip.
export function parseFolderHome(text: string): { folder: string; home: FolderHome } | null {
  const eq = text.lastIndexOf("=")
  if (eq <= 0) return null
  const folder = text.slice(0, eq)
  const value = text.slice(eq + 1)
  if (value === "private" || value === "workspace" || value === "skip") return { folder, home: { home: value, project: null } }
  const project = /^project:(.+)$/.exec(value)?.[1]
  if (project && isSlug(project)) return { folder, home: { home: "project", project } }
  return null
}

// ---------------------------------------------------------------- vault facts

// `ownerRole`: the role of this machine's owner; null from an older vault.
// `projectMismatch`: by repo root, each repo whose mehen.toml names another
// project than the one the vault binds its remote to.
export type VaultFacts = { visibleItems: Map<string, VisibleItem>; existing: Map<string, ExistingProject>; canCreateProjects: boolean; protectedEnvs: Map<string, Set<string>>; boundVars: Map<string, ExistingProject["vars"]>; ownerRole: NonNullable<Me["ownerRole"]> | null; projectMismatch: Map<string, ProjectMismatch> }

async function readProject(api: VaultApi, id: string): Promise<ExistingProject | null> {
  try {
    const project = await api.request<Project>("GET", `/v1/projects/${encodeURIComponent(id)}`)
    return { id: project.id, slug: project.slug, environments: project.environments.map((e) => ({ name: e.name, protected: e.protected })), vars: project.vars.filter((v) => v.source === "item").map((v) => ({ name: v.name, env: v.env, item: v.item })) }
  } catch (error) {
    if (error instanceof VaultApiError && (error.status === 404 || error.status === 403)) return null
    throw error
  }
}

// Read-only calls only: who this device is, the items it can see, and the
// project each repo already is: the one the vault binds its remote to, so
// every machine's checkout of a repo lands in one project, else the one its
// mehen.toml names; and each repo where the two disagree.
export type FactsOptions = { me?: Me; ownerIsMember: boolean }

export async function vaultFacts(api: VaultApi, repos: readonly { root: string; remote: string | null }[], projectIds: readonly string[], options: FactsOptions): Promise<VaultFacts> {
  const me = options.me ?? (await api.request<Me>("GET", "/v1/me"))
  const visibleItems = new Map((await listItems(api, {})).items.map((i): [string, VisibleItem] => [i.slug, { kind: i.kind, provider: i.provider, tags: i.tags }]))
  const existing = new Map<string, ExistingProject>()
  const protectedEnvs = new Map<string, Set<string>>()
  const boundVars = new Map<string, ExistingProject["vars"]>()
  const remember = (project: ExistingProject) => {
    protectedEnvs.set(project.id, new Set(project.environments.filter((e) => e.protected).map((e) => e.name)))
    boundVars.set(project.id, project.vars)
  }
  const byRemote = new Map<string, ExistingProject | null>()
  const remoteProject = async (remote: string | null) => {
    if (remote === null) return null
    if (!byRemote.has(remote)) {
      const bound = await boundProject(api, remote)
      byRemote.set(remote, bound === null ? null : await readProject(api, bound.id))
    }
    return byRemote.get(remote) ?? null
  }
  // The project id or slug a repo's mehen.toml names, if it can be read.
  const manifestNames = (root: string) => {
    const path = findManifest(root, root)
    if (path === null) return null
    try {
      return parseManifest(path, readFileSync(path, "utf8")).project
    } catch {
      return null
    }
  }
  const projectMismatch = new Map<string, ProjectMismatch>()
  for (const { root, remote } of repos) {
    const bound = await remoteProject(remote)
    const named = manifestNames(root)
    const project = bound ?? (named === null ? null : await readProject(api, named))
    // As apply's manifestFor, which refuses such a mehen.toml. The project
    // it names only labels the problem, so one the vault will not show is
    // another project.
    if (bound !== null && named !== null && named !== bound.id && named !== bound.slug) projectMismatch.set(root, { root, manifest: (await readProject(api, named).catch(() => null))?.slug ?? null, bound: bound.slug })
    if (project) {
      existing.set(root, project)
      remember(project)
    }
  }
  for (const id of projectIds) {
    const project = await readProject(api, id)
    if (project) remember(project)
  }
  // As the vault's project.init rule: a member's machine, not a workload,
  // with no project limit in its scope.
  return { visibleItems, existing, canCreateProjects: options.ownerIsMember && !me.workload && me.scope.projects.length === 0, protectedEnvs, boundVars, ownerRole: me.ownerRole ?? null, projectMismatch }
}
