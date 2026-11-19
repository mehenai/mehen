// What the commands and the MCP tools do, without any output: both call
// these, so `mehen ls` and `vault_list` cannot drift apart.

import {
  type ApprovalBundleStatus,
  type ApprovalStatus,
  ConnectCreate,
  type ConnectCreated,
  type ConnectStatus,
  type EnrolStatus,
  type Injection,
  IntakeCreate,
  type IntakeCreated,
  type IntakeStatus,
  type ItemDescription,
  type ItemDescriptionPosture,
  type ItemList,
  type ItemSummary,
  ITEM_HEADER,
  PushRequest,
  type PushRequestInput,
  RelayRequest,
  type RelayRequestInput,
} from "@mehen/protocol/api"
import type { MandateProposalStatus } from "@mehen/protocol/mandate-terms"
import type { PolicyProposalStatus, PolicyRuleProposalStatus } from "@mehen/protocol/policy-mode"
import { type PushDestination, type PushProvider, type PushRecordView, type PushResult, parsePushDestination, pushDestinationWords } from "@mehen/protocol/push"
import { type AdoptionStatus, AdoptionStatusSchema } from "@mehen/protocol/adopt"
import { type Bytes, base64UrlEncode } from "@mehen/protocol/bytes"
import { KINDS, isItemKind, isSlug } from "@mehen/protocol/kinds"
import { OAUTH_PROVIDERS, type OAuthProviderTemplate, getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import type { z } from "zod"
import { relativeExpiry } from "./ask.ts"
import { CliError, usageError } from "./errors.ts"
import { MANDATES_OFF_LINE } from "./mandate-operations.ts"
import { type VaultApi, VaultApiError, retrySafeMethod } from "./vault-api.ts"

export function zodMessage(error: z.ZodError): string {
  return error.issues.map((issue) => (issue.path.length ? `${issue.path.join(".")}: ${issue.message}` : issue.message)).join("; ")
}

function requireSlug(slug: string, what: string): string {
  if (!isSlug(slug)) throw usageError(`${JSON.stringify(slug)} is not a valid ${what}: lower case letters, digits and single dashes, 2 to 64 characters, starting with a letter.`)
  return slug
}

// ---------------------------------------------------------------- items

export type ItemFilters = { tag?: string | null; kind?: string | null; provider?: string | null }

export async function listItems(api: VaultApi, filters: ItemFilters): Promise<ItemList> {
  const query = new URLSearchParams()
  if (filters.tag) query.set("tag", filters.tag)
  if (filters.kind) {
    if (!isItemKind(filters.kind)) throw usageError(`Unknown kind ${JSON.stringify(filters.kind)}. The kinds are ${Object.keys(KINDS).join(", ")}.`, "mehen ls --help")
    query.set("kind", filters.kind)
  }
  if (filters.provider) query.set("provider", filters.provider)
  const qs = query.toString()
  const list = await api.request<ItemList>("GET", `/v1/items${qs ? `?${qs}` : ""}`)
  return { items: (list.items ?? []).map(pickSummary) }
}

// The public summary of an item, field by field: what `mehen ls`, `mehen show`
// and `mehen wait` hand on, so nothing the vault adds later passes unreviewed.
export function pickSummary(item: ItemSummary): ItemSummary {
  return {
    slug: item.slug,
    kind: item.kind,
    provider: item.provider,
    account: item.account,
    accountVerified: item.accountVerified,
    tags: item.tags,
    ceiling: item.ceiling,
    hosts: item.hosts,
    status: item.status,
    ...(item.review ? { review: { reason: item.review.reason, since: item.review.since } } : {}),
    updatedAt: item.updatedAt,
  }
}

// "needs review: <reason>", for an item a human should look at.
export function reviewNote(item: ItemSummary): string | null {
  return item.review ? `needs review: ${item.review.reason}` : null
}

// Public metadata only: known fields are copied one by one, so anything the
// vault might add later never passes through unreviewed.
function pickDescription(item: ItemDescription): ItemDescription {
  return {
    ...pickSummary(item),
    description: item.description,
    publicFields: item.publicFields,
    secretFields: (item.secretFields ?? []).map((f) => ({ name: f.name, set: f.set, length: f.length, prefix: f.prefix, fingerprint: f.fingerprint })),
    binding: item.binding,
    policy: item.policy,
    injection: item.injection,
    version: item.version,
    lastUsedAt: item.lastUsedAt,
    rotatedAt: item.rotatedAt,
    ...(item.policyFloor !== undefined ? { policyFloor: item.policyFloor } : {}),
    ...(item.posture !== undefined ? { posture: pickPosture(item.posture) } : {}),
    ...(item.pushes !== undefined ? { pushes: item.pushes.map(pickPushRecord) } : {}),
  }
}

// How careful the credential is, as the vault tells this machine: the level,
// whether it lets this key through and the catalogue, each field copied.
function pickPosture(posture: ItemDescriptionPosture): ItemDescriptionPosture {
  const catalogue = posture.catalogue === null ? null : { template: posture.catalogue.template, version: posture.catalogue.version }
  return { level: posture.level, coversThisKey: posture.coversThisKey === true, catalogue }
}

// Never `by`: the vault does not send a machine who asked, and nothing here
// prints it.
function pickPushRecord(p: PushRecordView): PushRecordView {
  return { push: p.push, destination: p.destination, words: p.words, field: p.field, version: p.version, current: p.current, via: p.via, state: p.state, outcome: p.outcome, providerStatus: p.providerStatus, at: p.at }
}

export async function showItem(api: VaultApi, slug: string): Promise<ItemDescription> {
  requireSlug(slug, "item name")
  return pickDescription(await api.request<ItemDescription>("GET", `/v1/items/${slug}`))
}

// ---------------------------------------------------------------- durations

const DURATION = /^(\d+)\s*(s|m|h|)$/
const UNIT_SECONDS = { "": 1, s: 1, m: 60, h: 3600 } as const

// "0", "90", "30s", "10m" or "2h" as seconds; anything else ("soon") is a
// usage error that names the flag.
export function parseDurationSeconds(text: string, options: { max: number; flag: string; help: string }): number {
  const match = DURATION.exec(text.trim())
  const seconds = match ? Number(match[1]) * UNIT_SECONDS[match[2] as keyof typeof UNIT_SECONDS] : Number.NaN
  if (!Number.isFinite(seconds) || seconds > options.max) {
    throw usageError(`${options.flag} takes a number of seconds, or a duration such as 30s, 10m or 2h, up to ${durationText(options.max)}; 0 checks once.`, options.help)
  }
  return seconds
}

// "30 s", "10 min", "2 h", "1 h 30 min": the same units the flags take.
export function durationText(seconds: number): string {
  const whole = Math.max(0, Math.round(seconds))
  if (whole < 60) return `${whole} s`
  if (whole < 3600) return `${Math.round(whole / 60)} min`
  const hours = Math.floor(whole / 3600)
  const minutes = Math.round((whole - hours * 3600) / 60)
  return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`
}

// "57:40" or "23:59:40": what the countdown line shows.
export function clockDown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000))
  const seconds = total % 60
  const minutes = Math.floor(total / 60) % 60
  const hours = Math.floor(total / 3600)
  const mmss = `${hours > 0 ? String(minutes).padStart(2, "0") : minutes}:${String(seconds).padStart(2, "0")}`
  return hours > 0 ? `${hours}:${mmss}` : mmss
}

// ---------------------------------------------------------------- intake and connect

const BARE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/

// One word for a shell: bare when it needs nothing, else single-quoted, so
// the commands mehen records and prints run as printed.
export function shellWord(text: string): string {
  return BARE_WORD.test(text) ? text : `'${text.replaceAll("'", `'\\''`)}'`
}

export type IntakeInput = {
  kind: string
  name: string
  provider: string | null
  reason: string | null
  tags: string[]
  // A proposed binding and injection, for a credential no template covers.
  hosts: string[]
  paths: string[]
  injection: Injection | null
  session: string | null
  // --new: supersede this machine's open intake for the slug instead of
  // getting its link again.
  fresh?: boolean
  // Where the credential belongs (design 7.1): always explicit, private by
  // default; project needs the project id (resolveHome).
  home: ProposedHome
}

// ---------------------------------------------------------------- homes

export type HomeKind = "private" | "project" | "workspace"
export const HOME_KINDS: readonly HomeKind[] = ["private", "project", "workspace"]
export type ProposedHome = { home: "private" } | { home: "workspace" } | { home: "project"; project: string }

const PROJECT_ID = /^prj_[A-Za-z0-9_-]{1,60}$/

// The proposed home from --home and --project, or a tool's arguments:
// private unless said otherwise (the safe default, 15.7); project needs an
// explicit project id or the bound checkout's own manifest project, never a
// foreign per-call cwd. The vault decides whether the home is permitted.
export function resolveHome(input: { home: string | null; project: string | null; manifestProject: string | null; help: string }): ProposedHome {
  const home = input.home ?? "private"
  if (!(HOME_KINDS as readonly string[]).includes(home)) throw usageError(`--home must be one of ${HOME_KINDS.join(", ")}.`, input.help)
  if (home === "private" || home === "workspace") {
    if (input.project !== null) throw usageError("--project only goes with --home project.", input.help)
    return { home }
  }
  const project = input.project ?? input.manifestProject
  if (project === null) throw usageError("--home project needs --project <prj_id>, or a checkout whose mehen.toml names the project.", input.help)
  if (!PROJECT_ID.test(project)) throw usageError(`${JSON.stringify(project)} is not a project id (prj_...).`, input.help)
  return { home: "project", project }
}

// Where an ask that cannot use a private home is told to go instead: the
// command line's flags, or the MCP tool's arguments.
export type HomeSurface = "cli" | "mcp"

// A private home (the default) is usable only through a machine accepted
// with the private-credentials tick: on by default for a member's own
// machine, off for a guest's, never on a team's.
// `defaulted`: no home was given, so the message says where the ask went.
export function privateHomeUnavailable(surface: HomeSurface, redo: string | null, defaulted: boolean): CliError {
  const project = surface === "cli" ? "--home project --project <prj_id>" : 'home: "project" with project: "<prj_id>"'
  const workspace = surface === "cli" ? "--home workspace" : 'home: "workspace"'
  const where = defaulted ? ", which is where an ask goes when no home is given" : ""
  return new CliError("forbidden", `This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home${where}.`, {
    ...(redo !== null ? { command: redo } : {}),
    say: `Ask again in a project you can edit with ${project}, or with ${workspace} if the person is a workspace owner or admin; otherwise ask the human to open this machine's page under Machines in the web app and allow it to use their private credentials, then ask again.`,
  })
}

// Runs an ask (an intake or a connection) and, when the vault refuses one
// for a private home, reads /v1/me once: a machine without private
// credentials gets privateHomeUnavailable instead of the vault's refusal,
// which an older vault words as not_found. The read happens only after a
// refusal, so an ask that succeeds costs no extra round trip, and nothing
// is created either way. Any other refusal, or a read that fails, is the
// vault's own.
export async function withPrivateHomeExplained<T>(api: VaultApi, home: ProposedHome, refusal: () => CliError, ask: () => Promise<T>): Promise<T> {
  try {
    return await ask()
  } catch (error) {
    if (home.home !== "private" || !(error instanceof VaultApiError) || (error.body.error !== "not_found" && error.body.error !== "forbidden")) throw error
    const privateCredentials = await api
      .request<{ scope?: { privateCredentials?: unknown } }>("GET", "/v1/me")
      .then((me) => me.scope?.privateCredentials)
      .catch(() => undefined)
    if (privateCredentials === false) throw refusal()
    throw error
  }
}

function homeWords(home: ProposedHome): string[] {
  const words = ["--home", home.home]
  if (home.home === "project") words.push("--project", home.project)
  return words
}

// The mehen request that makes this intake, as a shell command: recorded in
// the ledger so an expired link's next.command is the exact re-request.
export function requestCommandText(input: IntakeInput): string {
  const words = ["mehen", "request", input.kind, "--name", input.name]
  if (input.provider) words.push("--provider", input.provider)
  if (input.reason) words.push("--reason", input.reason)
  for (const tag of input.tags) words.push("--tag", tag)
  for (const host of input.hosts) words.push("--host", host)
  for (const path of input.paths) words.push("--path", path)
  if (input.injection?.in === "header") words.push("--header", input.injection.name, "--format", input.injection.format)
  words.push(...homeWords(input.home))
  return words.map(shellWord).join(" ")
}

export async function requestIntake(api: VaultApi, input: IntakeInput): Promise<IntakeCreated> {
  if (!isItemKind(input.kind)) throw usageError(`Unknown kind ${JSON.stringify(input.kind)}; \`mehen guide\` lists the kinds.`, "mehen guide")
  requireSlug(input.name, "item name")
  if (!input.reason) throw usageError("Say why you need it with --reason; the human sees it.", "mehen request --help")
  if (input.paths.length && !input.hosts.length) throw usageError("--path narrows a proposed binding; name its hosts with --host too.", "mehen request --help")
  const parsed = IntakeCreate.safeParse({
    kind: input.kind,
    slug: input.name,
    ...(input.provider ? { provider: input.provider } : {}),
    reason: input.reason,
    ...(input.tags.length ? { tags: input.tags } : {}),
    ...(input.hosts.length ? { binding: { hosts: input.hosts, ...(input.paths.length ? { paths: input.paths } : {}) } } : {}),
    ...(input.injection ? { injection: input.injection } : {}),
    ...(input.session ? { session: input.session } : {}),
    ...(input.fresh ? { fresh: true } : {}),
  })
  if (!parsed.success) throw usageError(`Invalid intake request: ${zodMessage(parsed.error)}`, "mehen request --help")
  return api.request<IntakeCreated>("POST", "/v1/intakes", { ...parsed.data, ...input.home })
}

export type ConnectInput = {
  provider: string
  // Null: pick the one matching client (chooseOauthClient), or with
  // requestClient let the vault ask for one first.
  client: string | null
  name: string | null
  scopes: string[]
  expect: string | null
  reason: string | null
  session: string | null
  // --request-client: when no client exists, the vault chains an intake for
  // it to this connect (V-4), so one command asks for both.
  requestClient?: boolean
  // Tags for the client item that intake creates.
  clientTags?: string[]
  fresh?: boolean
  home: ProposedHome
}

export function connectCommandText(input: ConnectInput): string {
  const words = ["mehen", "connect", input.provider]
  if (input.client) words.push("--client", input.client)
  if (input.name) words.push("--name", input.name)
  if (input.scopes.length) words.push("--scopes", input.scopes.join(","))
  if (input.expect) words.push("--expect", input.expect)
  if (input.reason) words.push("--reason", input.reason)
  for (const tag of input.clientTags ?? []) words.push("--client-tag", tag)
  if (input.requestClient) words.push("--request-client")
  words.push(...homeWords(input.home))
  return words.map(shellWord).join(" ")
}

export function knownOauthProvider(id: string): OAuthProviderTemplate {
  const provider = getOAuthProvider(id)
  if (!provider) throw usageError(`Unknown OAuth provider ${JSON.stringify(id)}. Known: ${Object.keys(OAUTH_PROVIDERS).join(", ")}.`, "mehen templates")
  return provider
}

export type MissingClientInput = {
  provider: OAuthProviderTemplate
  name: string | null
  expect: string | null
  reason: string
  vaultUrl: string
  // The connection's home: the client it needs is asked for with the same one.
  home: ProposedHome
}

// The reason the client intake carries: what the client is for, then why
// the connection is wanted, so the intake page and the ask read the same.
export function clientRequestReason(input: Pick<MissingClientInput, "provider" | "expect" | "reason">): string {
  return `connect ${input.provider.displayName}${input.expect ? ` as ${input.expect}` : ""}: ${input.reason}`
}

export const OAUTH_CALLBACK_PATH = "/oauth/callback"

// client_missing (exit 4): no OAuth client for the provider exists, so a
// human must add one first. `request` is exactly the arguments of `mehen
// request` / vault_request, and `setup` what the human needs at the provider.
export function missingClientError(input: MissingClientInput): CliError {
  const template = input.provider.clientTemplate
  const clientDisplay = getTemplate(template)?.displayName ?? `${template} item`
  const reason = clientRequestReason(input)
  const request = { kind: "oauth-client" as const, name: template, provider: template, reason }
  return new CliError(
    "client_missing",
    `No ${clientDisplay} is in the vault yet; a ${input.provider.displayName} connection needs one (template ${template}).`,
    {
      command: requestCommandText({ kind: request.kind, name: request.name, provider: request.provider, reason, tags: [], hosts: [], paths: [], injection: null, session: null, home: input.home }),
      say: `Ask the human for a ${clientDisplay} first, then run this command again; or repeat it with --request-client to ask for both at once.`,
    },
    { request, setup: { redirectUri: `${input.vaultUrl}${OAUTH_CALLBACK_PATH}`, docsUrl: getTemplate(template)?.docsUrl ?? null } },
  )
}

export type OauthClientChoice = { client: string; account: string | null }

// The oauth-client items made from the provider's client template that this
// machine may use. One is the client to use; several is a usage error that
// lists them (`choices` in --json); none is null, so the caller can refuse
// with client_missing or let the vault ask for one.
export async function chooseOauthClient(api: VaultApi, provider: OAuthProviderTemplate): Promise<OauthClientChoice | null> {
  const { items: clients } = await listItems(api, { kind: "oauth-client", provider: provider.clientTemplate })
  if (clients.length === 0) return null
  if (clients.length > 1) {
    const choices = clients.map((c) => ({ slug: c.slug, account: c.account }))
    throw new CliError(
      "usage",
      `Several ${provider.displayName} OAuth clients exist (${clients.map((c) => c.slug).join(", ")}); name one with --client.`,
      { command: `mehen connect ${provider.id} --client ${clients[0]?.slug ?? "<client>"} ...`, say: `Pick one of ${clients.map((c) => c.slug).join(", ")} with --client.` },
      { choices },
    )
  }
  const only = clients[0] as ItemSummary
  return { client: only.slug, account: only.account }
}

export async function createConnect(api: VaultApi, input: ConnectInput): Promise<ConnectCreated> {
  if (!input.client && !input.requestClient) throw usageError("Name the OAuth client item with --client, or add --request-client to ask a human for one.", "mehen connect --help")
  if (!input.name) throw usageError("Name the connection item to create with --name.", "mehen connect --help")
  if (!input.reason) throw usageError("Say why you need it with --reason; the human sees it.", "mehen connect --help")
  if (input.client) requireSlug(input.client, "client item name")
  requireSlug(input.name, "connection item name")
  const parsed = ConnectCreate.safeParse({
    provider: input.provider,
    ...(input.client ? { client: input.client } : {}),
    slug: input.name,
    ...(input.scopes.length ? { scopes: input.scopes } : {}),
    ...(input.expect ? { expect: input.expect } : {}),
    reason: input.reason,
    ...(input.session ? { session: input.session } : {}),
    ...(input.requestClient ? { requestClient: true } : {}),
    ...(input.clientTags?.length ? { clientTags: input.clientTags } : {}),
    ...(input.fresh ? { fresh: true } : {}),
  })
  if (!parsed.success) throw usageError(`Invalid connect request: ${zodMessage(parsed.error)}`, "mehen connect --help")
  return api.request<ConnectCreated>("POST", "/v1/connect", { ...parsed.data, ...input.home })
}

// ---------------------------------------------------------------- wait

// GET /v1/adoptions/:id, parsed with the strict AdoptionStatusSchema, so
// no compare result reaches this machine; `mapped`, `replaced` and `staged`
// are absent from an older vault. Text another machine chose is cut to the
// length mehen prints.
export async function adoptionStatus(api: VaultApi, id: string): Promise<AdoptionStatus> {
  const answer = await api.request<unknown>("GET", `/v1/adoptions/${id}`)
  const parsed = AdoptionStatusSchema.safeParse(answer)
  if (!parsed.success) {
    const said = (answer as { status?: unknown } | null)?.status
    if (!["open", "approved", "cancelled", "expired"].includes(String(said))) throw unexpected(id, said)
    throw new CliError("internal", `The vault's status for ${id} is not one mehen can read.`, { say: "Check the vault URL and try again; if it keeps failing, report it with this message." })
  }
  const status = parsed.data
  return {
    ...status,
    adoption: id,
    machines: status.machines.map((m) => ({ ...m, name: m.name.slice(0, 64) })),
    ...(status.refused ? { refused: status.refused.map((r) => ({ ...r, reason: r.reason.slice(0, 300) })) } : {}),
    ...(status.staged ? { staged: status.staged.map((r) => ({ ...r, machine: r.machine.slice(0, 64) })) } : {}),
  }
}

export type WaitKind = "intake" | "approval" | "connect" | "enrol" | "policy" | "adoption" | "bundle" | "mandate"

export type EnrolActive = Extract<EnrolStatus, { status: "active" }>

export type WaitResult =
  | { kind: "intake"; status: IntakeStatus }
  | { kind: "approval"; status: ApprovalStatus }
  | { kind: "connect"; status: ConnectStatus }
  | { kind: "enrol"; status: EnrolActive }
  | { kind: "policy"; status: PolicyProposalStatus | PolicyRuleProposalStatus }
  | { kind: "adoption"; status: AdoptionStatus }
  | { kind: "bundle"; status: ApprovalBundleStatus }
  // Signed, or settled by another mandate signed for this machine first
  // (state expired, with that mandate).
  | { kind: "mandate"; status: MandateProposalStatus & { mandate: string } }

const WAIT_PREFIXES: Record<string, { kind: WaitKind; path: string; label: string }> = {
  int: { kind: "intake", path: "/v1/intakes/", label: "Intake" },
  apr: { kind: "approval", path: "/v1/approvals/", label: "Approval" },
  con: { kind: "connect", path: "/v1/connect/", label: "Connection" },
  pol: { kind: "policy", path: "/v1/policy/proposals/", label: "Policy proposal" },
  enr: { kind: "enrol", path: "/v1/enrol/", label: "Enrolment" },
  adp: { kind: "adoption", path: "/v1/adoptions/", label: "Adoption" },
  bnd: { kind: "bundle", path: "/v1/approvals/bundles/", label: "Bundle" },
  mdp: { kind: "mandate", path: "/v1/mandates/proposals/", label: "Mandate proposal" },
}

// The id prefixes mehen wait follows, for the guide's test.
export const WAIT_ID_PREFIXES = Object.keys(WAIT_PREFIXES)

export type WaitTarget = { kind: WaitKind; path: string; label: string }

export function waitTarget(id: string): WaitTarget {
  const match = /^(int|apr|con|enr|pol|adp|bnd|mdp)_[A-Za-z0-9_-]{1,60}$/.exec(id)
  const target = match ? WAIT_PREFIXES[match[1] as string] : undefined
  if (!target) throw usageError(`${JSON.stringify(id)} is not an intake (int_), approval (apr_), connection (con_), enrolment (enr_), policy proposal (pol_), adoption (adp_), bundle (bnd_) or mandate proposal (mdp_) id.`, "mehen wait --help")
  return { ...target, path: target.path + id }
}

export function isWaitKind(value: unknown): value is WaitKind {
  return value === "intake" || value === "approval" || value === "connect" || value === "enrol" || value === "policy" || value === "adoption" || value === "bundle" || value === "mandate"
}

// Resolves after ms, or at once when the signal aborts (the caller then
// checks the signal).
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve()
    const timer = setTimeout(done, ms)
    function done(): void {
      clearTimeout(timer)
      signal?.removeEventListener("abort", done)
      resolve()
    }
    signal?.addEventListener("abort", done, { once: true })
  })
}

function unexpected(id: string, status: unknown): CliError {
  return new CliError("internal", `The vault returned an unknown status ${JSON.stringify(status)} for ${id}.`)
}

// What the ledger knows about the ask being waited on, when this machine
// made it: the command that re-issues it (next.command once the link is
// gone) and, for an intake this machine superseded, the newer intake's id.
export type WaitLedger = { reissueCommand: string | null; replacedBy: string | null }

const NO_LEDGER: WaitLedger = { reissueCommand: null, replacedBy: null }

const GENERIC_REISSUE: Record<WaitKind, string> = {
  intake: "mehen request <kind> --name <slug> --reason <why>",
  connect: "mehen connect <provider> --name <slug> --reason <why>",
  approval: "",
  policy: "",
  adoption: "mehen adopt submit",
  enrol: "mehen enrol --workspace <slug>",
  bundle: "mehen plan submit <plan.json>",
  mandate: "mehen mandate propose --items <slug> --classes <class> --note <why>",
}

function policyShow(item: string | undefined): string {
  return item && isSlug(item) ? `mehen policy show ${item}` : "mehen pending"
}

function staleNext(item: string | undefined) {
  return { command: policyShow(item), say: "Access changed after this request was reviewed. Read the current policy and ask the human before proposing again." }
}

const APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/

// superseded (mehen 0.3.17 on): a newer ask from this machine to the same
// place replaced the approval. replacedBy goes into the next command only
// when it is an approval id; otherwise mehen pending lists the newer ask.
function supersededError(id: string, approval: ApprovalStatus): CliError {
  const { replacedBy: given, ...status } = approval
  const newer = typeof given === "string" && APPROVAL_ID.test(given) ? given : null
  return new CliError(
    "superseded",
    `A newer request to the same place replaced ${id}.`,
    newer ? { command: `mehen wait ${newer}`, say: `Wait on ${newer}; if you meant both, send them together with mehen plan submit.` } : { command: "mehen pending", say: "Wait on the newer ask instead (mehen pending lists it); if you meant both, send them together with mehen plan submit." },
    { ...status, ...(newer ? { replacedBy: newer } : {}), kind: "approval", id },
  )
}

const APPROVAL_STATUSES: ReadonlySet<unknown> = new Set<ApprovalStatus["status"]>(["pending", "approved", "denied", "expired", "used", "revoked", "stale", "superseded"])

// A bundle settles once none of its asks is pending, as the vault's long
// poll does: all approved (or used) is the result; otherwise the worst of
// the rest names the error, a denial, stop or replacement first (exit 5),
// and next.say names the approved ones, which stay usable.
function settleBundle(id: string, value: unknown): WaitResult | null {
  const approvals = (value as { approvals?: unknown }).approvals
  if (!Array.isArray(approvals) || !approvals.every((a) => typeof a === "object" && a !== null && APPROVAL_ID.test(String(a.id)) && APPROVAL_STATUSES.has(a.status))) {
    throw new CliError("internal", `The vault's status for ${id} is not one mehen can read.`, { say: "Check the vault URL and try again; if it keeps failing, report it with this message." })
  }
  const asks = (approvals as { id: string; status: ApprovalStatus["status"] }[]).map(({ id, status }) => ({ id, status }))
  if (asks.some((a) => a.status === "pending")) return null
  const usable = asks.filter((a) => a.status === "approved" || a.status === "used").map((a) => a.id)
  if (usable.length === asks.length) return { kind: "bundle", status: { bundle: id, approvals: asks } }
  const counts = new Map<string, number>()
  for (const a of asks) if (a.status !== "approved" && a.status !== "used") counts.set(a.status, (counts.get(a.status) ?? 0) + 1)
  const tally = [...counts].map(([status, n]) => `${n} ${status === "revoked" ? "stopped" : status}`).join(", ")
  const message = `${usable.length} of ${asks.length} requests in ${id} ${usable.length === 1 ? "was" : "were"} approved; ${tally}.`
  const kept = usable.length ? `The approved ones stay usable: repeat each with its --approval (${usable.join(", ")}). ` : ""
  const extras = { bundle: id, approvals: asks }
  if (counts.has("denied") || counts.has("revoked") || counts.has("superseded")) throw new CliError("denied", message, { say: `${kept}Do not retry the others or work around them without asking the human.` }, extras)
  if (counts.has("stale")) throw new CliError("stale", message, { command: "mehen pending", say: `${kept}Access changed for the others after they were asked for; read the current policy and ask the human before asking again.` }, extras)
  throw new CliError("expired", message, { say: `${kept}The others expired before a decision; submit a plan of just those to ask again, and share the link sooner.` }, extras)
}

const MANDATE_ID = /^mdt_[A-Za-z0-9_-]{1,60}$/

// A mandate proposal is done once a person signs it, or signs this machine
// another mandate first, which settles it; one that expired with no
// mandate signed changed nothing.
function settleMandate(id: string, value: unknown): WaitResult | null {
  const v = value as Partial<MandateProposalStatus>
  if (v.proposal !== id || typeof v.expiresAt !== "string" || !(v.mandate === null || (typeof v.mandate === "string" && MANDATE_ID.test(v.mandate)))) {
    throw new CliError("internal", `The vault's status for ${id} is not one mehen can read.`, { say: "Check the vault URL and try again; if it keeps failing, report it with this message." })
  }
  const status = { proposal: id, state: v.state, mandate: v.mandate, expiresAt: v.expiresAt }
  if (v.state === "open") return null
  if ((v.state === "signed" || v.state === "expired") && status.mandate) return { kind: "mandate", status: { ...status, state: v.state, mandate: status.mandate } }
  if (v.state === "expired") throw new CliError("expired", `Mandate proposal ${id} expired before anyone signed it; nothing changed.`, { command: GENERIC_REISSUE.mandate, say: "Carry on asking for each request; propose again, with only what the asks name, if more asks like these will follow." }, { id, expiresAt: status.expiresAt })
  throw unexpected(id, v.state)
}

// Every outcome as a sentence. Returns the result once decided, throws for
// a decision against (the error's message is the sentence, its next the
// way on), and null while a human still has to act.
export function settle(kind: WaitKind, id: string, value: unknown, ledger: WaitLedger = NO_LEDGER): WaitResult | null {
  if (kind === "bundle") return settleBundle(id, value)
  if (kind === "mandate") return settleMandate(id, value)
  const status = (value as { status?: unknown }).status
  const again = { command: `mehen wait ${id}` }
  const reissue = ledger.reissueCommand ?? GENERIC_REISSUE[kind]
  if (kind === "intake") {
    const intake = value as IntakeStatus
    if (status === "completed") return { kind, status: intake }
    if (status === "open") return null
    if (status === "expired") {
      throw new CliError("expired", `The link for intake ${id} expired before a human added the credential.`, { command: reissue, say: "Ask for the credential again: the command makes a fresh link to share." })
    }
    if (status === "cancelled") {
      if (intake.superseded) {
        const newer = ledger.replacedBy
        throw new CliError("cancelled", `Intake ${id} was replaced by a newer link from this machine (mehen request --new)${newer ? `: ${newer}` : ""}.`, {
          ...(newer ? { command: `mehen wait ${newer}` } : { command: "mehen pending" }),
          say: newer ? `Wait on the newer link, ${newer}, instead.` : "Wait on the newer link instead; `mehen pending` lists it.",
        })
      }
      throw new CliError("cancelled", `The human cancelled intake ${id} without adding the credential.`, { say: "The human chose not to provide this credential; ask them before requesting it again." })
    }
    throw unexpected(id, status)
  }
  if (kind === "adoption") {
    const adoption = value as AdoptionStatus
    if (status === "approved") return { kind, status: adoption }
    if (status === "open") return null
    if (status === "expired") throw new CliError("expired", `Adoption ${id} expired before a human approved it; nothing was stored.`, { command: reissue, say: "Submit the plan again; it makes a fresh batch to review." })
    if (status === "cancelled") throw new CliError("cancelled", `Adoption ${id} was cancelled; nothing was stored.`, { say: "The batch was cancelled; ask the human before submitting it again." })
    throw unexpected(id, status)
  }
  if (kind === "policy") {
    const proposal = value as PolicyProposalStatus | PolicyRuleProposalStatus
    if (status === "pending") return null
    if (status === "approved") return { kind, status: proposal }
    const extras = { ...proposal, kind, id }
    if (status === "denied") throw new CliError("denied", `The human denied policy proposal ${id}.`, { say: "The human denied this change. Do not retry without asking them." }, extras)
    if (status === "expired") throw new CliError("expired", `Policy proposal ${id} expired.`, { command: policyShow(proposal.item), say: "stage" in proposal ? "This standing rule proposal expired before anyone approved it. Check the item's rules with mehen policy show, and propose it again only if the agent still needs it." : "This policy proposal expired. Check current access before asking for a new window." }, extras)
    if (status === "cancelled") throw new CliError("cancelled", `Policy proposal ${id} was cancelled.`, { command: "mehen pending", say: "This policy proposal was cancelled. Do not request it again without asking the human." }, extras)
    if (status === "stale") throw new CliError("stale", `Access changed for policy proposal ${id}.`, staleNext(proposal.item), extras)
    throw unexpected(id, status)
  }
  if (kind === "approval") {
    const approval = value as ApprovalStatus
    if (status === "approved" || status === "used") return pushFinished(id, approval) ? { kind, status: approval } : null
    if (status === "pending") return null
    if (status === "revoked") throw new CliError("denied", `Approval ${id} was stopped.`, { say: "This approval or grant was stopped. Do not retry it or work around it; ask the human before proposing access again." }, { ...approval, kind, id })
    if (status === "stale") throw new CliError("stale", `Access changed for approval ${id}.`, staleNext(approval.item), { ...approval, kind, id })
    if (status === "superseded") throw supersededError(id, approval)
    if (status === "denied") throw new CliError("denied", `The human denied approval ${id}: ${approval.summary}.`, { say: "The request was denied; do not retry it without asking the human." })
    if (status === "expired" && approval.approvedAt !== undefined) throw new CliError("expired", `Approval ${id} was approved but expired before the request used it: ${approval.summary}.`, { say: "Send the approved request again as soon as the approval comes, with --approval and the same bytes. Repeating it now asks for a fresh approval." }, { ...approval, kind, id })
    if (status === "expired") throw new CliError("expired", `Approval ${id} expired before a decision: ${approval.summary}.`, { say: "Repeat the original request to get a fresh approval link, and share it sooner." })
    throw unexpected(id, status)
  }
  if (kind === "enrol") {
    const enrolment = value as EnrolStatus
    // The active answer is verified against the enrolment's intent by the
    // finish step (activate.ts finishAttempt) before anything is written.
    if (status === "active") return { kind, status: enrolment as EnrolActive }
    if (status === "pending" || status === "pending_owner_acceptance" || status === "pending_admission") return null
    if (status === "rejected") throw new CliError("rejected", `The enrolment ${id} was rejected in the vault.`, { say: "A human rejected this machine; ask them before enrolling it again." })
    if (status === "expired") throw new CliError("expired", `The enrolment link for ${id} expired before anyone accepted it.`, { command: reissue, say: "Run `mehen enrol --workspace <slug>` again; it keeps the key and issues a fresh link." })
    throw unexpected(id, status)
  }
  const connect = value as ConnectStatus
  if (status === "completed") return { kind, status: connect }
  if (status === "open") return null
  if (status === "mismatch") {
    throw new CliError("mismatch", connect.message ?? `Connection ${id} was signed in as ${connect.account ?? "a different account"}, not the expected one.`, {
      ...again,
      say: "The account the human signed in with is not the one expected; the vault is holding the connection until the human decides.",
    })
  }
  if (status === "failed") throw new CliError("failed", `Connection ${id} failed: ${connect.message ?? "the vault did not say why"}.`, { command: reissue, say: "Start the connection again; the command makes a fresh link to share." })
  if (status === "expired") throw new CliError("expired", `The link for connection ${id} expired before the human finished signing in.`, { command: reissue, say: "Start the connection again; the command makes a fresh link to share." })
  throw unexpected(id, status)
}

const PUSH_PROVIDER_NAMES: Record<PushProvider, string> = { github: "GitHub", vercel: "Vercel", cloudflare: "Cloudflare", fly: "Fly" }

// An approval that asked for a push (ApprovalStatus.push) is spent the
// moment a human approves it; the wait ends once the push has: true when it
// is done (or in a state this mehen does not know, as an older mehen would
// end), false while it waits to be sent, and the refusal for a push that
// did not go through. None of them suggests pushing again.
function pushFinished(id: string, approval: ApprovalStatus): boolean {
  const push = approval.push
  if (push === undefined) return true
  if (push.state === "pending" || push.state === "queued" || push.state === "sending") return false
  const destination = parsePushDestination(push.destination)
  const provider = destination ? PUSH_PROVIDER_NAMES[destination.provider] : "the provider"
  const extras = { ...approval, kind: "approval" as const, id }
  const noRetry = "do not push again without asking them."
  if (push.state === "failed" && typeof push.providerStatus === "number") {
    throw new CliError("provider_refused", `${capitalised(provider)} refused the push (${push.providerStatus}): ${approval.summary}.`, { say: `Tell the human that ${provider} answered ${push.providerStatus}; ${noRetry} Nothing changes until the token's access, the destination or the name is fixed.` }, { ...extras, providerStatus: push.providerStatus })
  }
  // The vault records failed without a status only for a provider's rate
  // limit (vault routes/push.ts sendPush, push/common.ts answerError),
  // which writes nothing.
  if (push.state === "failed") throw new CliError("failed", `The push failed and nothing is known to have been written: ${approval.summary}.`, { say: `Tell the human; ${noRetry}` }, extras)
  if (push.state === "not_sent") throw new CliError("failed", `Mehen did not send the push; nothing was written: ${approval.summary}.`, { say: `The approval is spent. Tell the human; ${noRetry}` }, extras)
  if (push.state === "unknown") throw new CliError("failed", `Mehen could not confirm the push: ${approval.summary}.`, { say: `Check ${provider}${destination ? ` for ${destination.name}` : ""} first, then tell the human; ${noRetry}` }, extras)
  return true
}

// An approval a human has approved whose push the vault has queued or is
// sending: nobody has to act, so a wait builds no ask for it. The
// destination in words, or null for any other status.
export function pushBeingSent(kind: WaitKind, value: unknown): string | null {
  if (kind !== "approval") return null
  const approval = value as ApprovalStatus
  if (approval.status !== "approved" && approval.status !== "used") return null
  const push = approval.push
  if (push?.state !== "queued" && push?.state !== "sending") return null
  const destination = parsePushDestination(push.destination)
  return destination ? pushDestinationWords(destination) : "the destination"
}

function capitalised(text: string): string {
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}`
}

export type WaitPending = { expiresAt: string | null; value: unknown }

export type WaitOptions = {
  timeoutMs: number // 0: check once
  intervalMs: number // minimum spacing between polls when the vault answers at once
  ledger?: WaitLedger
  // When the link expires, as far as the caller knows (the ledger); every
  // pending status the vault sends updates it.
  expiresAt?: string | null
  // Called with every status that still waits on a human, so a caller can
  // show the link's remaining life and build an ask from it.
  onPending?: (pending: WaitPending) => void
  // The caller giving up (an MCP request cancelled by its host): the poll in
  // flight is aborted, no further poll is signed or sent, and waitFor
  // rejects with the signal's reason.
  signal?: AbortSignal
}

// The first poll answers at once (so the link's expiry and a settled state
// show without delay); later ones long-poll. An enrolment status route does
// not long-poll, so those are spaced by intervalMs.
export async function waitFor(api: VaultApi, id: string, options: WaitOptions): Promise<WaitResult> {
  const target = waitTarget(id)
  const deadline = Date.now() + options.timeoutMs
  const once = options.timeoutMs === 0
  let expiresAt = options.expiresAt ?? null
  let sending = false
  const cancel = options.signal
  for (let poll = 0; ; poll++) {
    cancel?.throwIfAborted()
    const started = Date.now()
    const longPoll = !once && poll > 0 && target.kind !== "enrol"
    const pollTimeout = longPoll ? AbortSignal.timeout(Math.max(deadline - started, 1)) : undefined
    const signals = [pollTimeout, cancel].filter((s): s is AbortSignal => s !== undefined)
    const signal = signals.length ? AbortSignal.any(signals) : undefined
    let value: unknown
    try {
      value = await api.request<unknown>("GET", longPoll ? `${target.path}?wait=1` : target.path, undefined, signal ? { signal } : {})
    } catch (error) {
      cancel?.throwIfAborted()
      if (pollTimeout?.aborted) break
      throw error instanceof VaultApiError && error.body.error === "not_found" ? waitNotFound(target, id, error) : error
    }
    const result = settle(target.kind, id, value, options.ledger)
    if (result) return result
    const sent = (value as { expiresAt?: unknown }).expiresAt
    if (typeof sent === "string") expiresAt = sent
    sending = pushBeingSent(target.kind, value) !== null
    options.onPending?.({ expiresAt, value })
    if (once || Date.now() >= deadline) break
    const pause = Math.min(options.intervalMs - (Date.now() - started), deadline - Date.now())
    if (pause > 0) await sleep(pause, cancel)
    cancel?.throwIfAborted()
    if (Date.now() >= deadline) break
  }
  if (sending) {
    throw new CliError("timeout", `The push was approved and is still being sent. Wait again with mehen wait ${id}; do not push again.`, {
      command: `mehen wait ${id}`,
      say: "The human approved the push and the vault is still sending it; wait again, and do not push again without asking the human.",
    })
  }
  throw new CliError("timeout", timeoutMessage(target, id, options.timeoutMs, expiresAt, new Date()), {
    command: `mehen wait ${id}`,
    say: "A human has not acted yet; wait again, and remind them of the link if needed.",
  })
}

// An id the vault does not know, in the workspace asked: a typo, another
// workspace's ask or one long gone. mehen pending lists this machine's
// open asks, and mehen mandate ls its mandate proposals; a vault without
// the route (or, for a mandate proposal, without mandates) says so instead.
function waitNotFound(target: WaitTarget, id: string, error: VaultApiError): CliError {
  const context = error.context ? { context: error.context } : {}
  if (error.body.message === "No such route.") {
    if (target.kind === "mandate") return new CliError("not_found", MANDATES_OFF_LINE, { say: "Carry on asking for each request as before; do not propose a mandate again." }, context)
    return new CliError("not_found", `This vault cannot be asked about ${id}: it is older than this kind of ask.`, { command: "mehen pending", say: "List what is still waiting for a human with mehen pending." }, context)
  }
  if (target.kind === "mandate") {
    return new CliError("not_found", `No such ${target.label.toLowerCase()} ${id} in this workspace.`, { command: "mehen mandate ls", say: "`mehen mandate ls` lists this machine's open mandate proposals in this workspace; wait on the id it shows, naming another workspace with --workspace when there are several." }, context)
  }
  return new CliError("not_found", `No such ${target.label.toLowerCase()} ${id} in this workspace.`, { command: "mehen pending", say: "mehen pending lists this machine's open asks, in every workspace; wait on the id it shows, naming its workspace with --workspace when there are several." }, context)
}

// "Approval apr_x is still waiting for a human after 10 min; the link
// expires in 48 min."
function timeoutMessage(target: WaitTarget, id: string, timeoutMs: number, expiresAt: string | null, now: Date): string {
  const base = `${target.label} ${id} is still waiting for a human${timeoutMs > 0 ? ` after ${durationText(timeoutMs / 1000)}` : ""}`
  const relative = expiresAt ? relativeExpiry(expiresAt, now) : null
  if (relative === "expired") return `${base}; the link has expired.`
  return relative ? `${base}; the link expires ${relative}.` : `${base}.`
}

// ---------------------------------------------------------------- relay

export type FetchInput = {
  item: string | null
  run: string | null
  method: string
  url: string
  headers: [string, string][]
  body: Bytes | null
  approval: string | null
  // --replaces: this machine's open ask (apr_) to the same place that this
  // request replaces when it is held for approval (relayReplaces).
  replaces?: string | null
  session: string | null
  // The item-use context (design 15.5): the project and environment a
  // protected, team or guest credential is used for. Never a workspace
  // switch; its absence never falls back to contextless protected use.
  context?: { project: string; environment: string } | null
}

// --project and --env together, or neither.
export function fetchContext(project: string | null, environment: string | null, help: string): { project: string; environment: string } | null {
  if (project === null && environment === null) return null
  if (project === null || environment === null) throw usageError("--project and --env go together: the project id and the environment the credential is used for.", help)
  if (!PROJECT_ID.test(project)) throw usageError(`${JSON.stringify(project)} is not a project id (prj_...).`, help)
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(environment)) throw usageError(`${JSON.stringify(environment)} is not an environment name.`, help)
  return { project, environment }
}

export function relayRequest(input: FetchInput): RelayRequestInput {
  if ((input.item === null) === (input.run === null)) throw usageError("Name exactly one of an item or a run (--run).", "mehen fetch --help")
  if (input.item !== null) requireSlug(input.item, "item name")
  const parsed = RelayRequest.safeParse({
    ...(input.context ? { context: input.context } : {}),
    ...(input.item !== null ? { item: input.item } : {}),
    ...(input.run !== null ? { run: input.run } : {}),
    method: input.method.toUpperCase(),
    url: input.url,
    headers: input.headers,
    ...(input.body !== null ? { body: base64UrlEncode(input.body) } : {}),
    ...(input.session ? { session: input.session } : {}),
    ...(input.approval ? { approval: input.approval } : {}),
    ...(input.replaces ? { replaces: input.replaces } : {}),
  })
  if (!parsed.success) throw usageError(`Invalid request: ${zodMessage(parsed.error)}`, "mehen fetch --help")
  return parsed.data
}

// --replaces (mehen fetch) or replaces (vault_fetch): an approval id, checked
// here so a typo never reaches the vault. Whether it is an open ask of this
// machine to the same place is the vault's to say.
export function relayReplaces(text: string | null, surface: HomeSurface): string | null {
  if (text === null) return null
  const option = surface === "cli" ? "--replaces" : "replaces"
  if (!APPROVAL_ID.test(text)) throw usageError(`${option} takes the id of this machine's open ask (apr_...) that this request replaces; ${JSON.stringify(text)} is not one.`, surface === "cli" ? "mehen fetch --help" : "vault_fetch")
  return text
}

const REPLACING_UNAVAILABLE = "Replacing an ask is not available yet."

// A vault without batch approvals refuses a replace as forbidden; the way on
// is the same request without it. Any other refusal is the vault's own.
export function replacingRefused(error: unknown, request: RelayRequestInput, surface: HomeSurface): unknown {
  if (request.replaces === undefined || !(error instanceof VaultApiError) || error.body.error !== "forbidden" || error.body.next !== undefined || error.body.message !== REPLACING_UNAVAILABLE) return error
  return new CliError("forbidden", REPLACING_UNAVAILABLE, { say: `This vault does not replace asks yet. Send the same request again without ${surface === "cli" ? "--replaces" : "replaces"}; ${request.replaces} stays open until a human decides it or it expires.` })
}

export function parseHeader(text: string): [string, string] {
  const colon = text.indexOf(":")
  const name = colon === -1 ? "" : text.slice(0, colon).trim()
  if (!name || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) throw usageError(`Header ${JSON.stringify(text)} must look like "Name: value".`, "mehen fetch --help")
  return [name, text.slice(colon + 1).trim()]
}

export type UpstreamHead = {
  status: number
  statusText: string
  item: string | null // Mehen-Item: which item, and which account, acted
  headers: Record<string, string>
}

export function upstreamHead(response: Response): UpstreamHead {
  const headers: Record<string, string> = {}
  response.headers.forEach((value, name) => {
    headers[name] = value
  })
  return { status: response.status, statusText: response.statusText, item: response.headers.get(ITEM_HEADER), headers }
}

// Reads up to `limit` bytes of a body and cancels the rest.
export async function readLimited(response: Response, limit: number): Promise<{ bytes: Bytes; truncated: boolean; size: number | null }> {
  const chunks: Bytes[] = []
  let total = 0
  let truncated = false
  if (response.body) {
    const reader = response.body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = new Uint8Array(value)
      if (total + chunk.length > limit) {
        chunks.push(chunk.subarray(0, limit - total))
        total = limit
        truncated = true
        await reader.cancel()
        break
      }
      chunks.push(chunk)
      total += chunk.length
    }
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  const length = response.headers.get("content-length")
  return { bytes, truncated, size: length && /^\d+$/.test(length) ? Number(length) : null }
}

// The body as text, or base64url when it is not UTF-8.
// --select (mehen fetch) and `select` (vault_fetch): one part of a JSON body,
// by a path of keys and array indexes: `data.0.id`, `.data[0].id`,
// `items[2]["display name"]`, or `.` for the whole body. A key or index
// that is not there selects null, as jq does.
const SELECT_TOKEN = /\.?([A-Za-z0-9_$-]+)|\[(\d+)\]|\["((?:[^"\\]|\\.)*)"\]/y

// `option` names the flag or argument in messages: --select for mehen fetch,
// select for vault_fetch.
export type SelectOption = { option: string; help: string }
const FETCH_SELECT: SelectOption = { option: "--select", help: "mehen fetch --help" }

export function parseSelectPath(path: string, { option, help }: SelectOption = FETCH_SELECT): (string | number)[] {
  const text = path.trim()
  if (text === "") throw usageError(`${option} needs a path such as data.0.id, or . for the whole body.`, help)
  if (text === ".") return []
  const out: (string | number)[] = []
  SELECT_TOKEN.lastIndex = 0
  while (SELECT_TOKEN.lastIndex < text.length) {
    const at = SELECT_TOKEN.lastIndex
    const match = SELECT_TOKEN.exec(text)
    if (!match) throw usageError(`${option} ${JSON.stringify(path)} is not a path mehen can read at character ${at + 1}; use keys and indexes such as data.0.id or items[2]["display name"].`, help)
    if (match[1] !== undefined) out.push(/^\d+$/.test(match[1]) ? Number(match[1]) : match[1])
    else if (match[2] !== undefined) out.push(Number(match[2]))
    else out.push(JSON.parse(`"${match[3] ?? ""}"`) as string)
  }
  return out
}

export type Selected = { found: boolean; value: unknown }

export function selectJson(value: unknown, path: readonly (string | number)[]): Selected {
  let current: unknown = value
  for (const step of path) {
    if (Array.isArray(current) && typeof step === "number" && step < current.length) current = current[step]
    else if (typeof current === "object" && current !== null && !Array.isArray(current) && Object.hasOwn(current, String(step))) current = (current as Record<string, unknown>)[String(step)]
    else return { found: false, value: null }
  }
  return { found: true, value: current }
}

// What --select picks from the upstream body. A body that is not JSON has
// nothing to pick from: for a read, a usage error saying to run it again
// without the option; for a write, which a second send could repeat, the
// body as it came with a note, never advice to send it again.
export type SelectedBody = { json: true; picked: Selected } | { json: false; note: string }

export function selectBody(bytes: Bytes, status: number, method: string, path: readonly (string | number)[], { option, help }: SelectOption = FETCH_SELECT): SelectedBody {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
  } catch {
    const notJson = `The upstream answered ${status} with a body that is not JSON, so ${option} has nothing to pick from.`
    if (retrySafeMethod(method)) throw usageError(`${notJson} The request was sent; run it again without ${option} to see the body.`, help)
    return { json: false, note: `${notJson} The request was sent and may have taken effect: here is the body as it came. Do not send it again to see it.` }
  }
  return { json: true, picked: selectJson(value, path) }
}

export function bodyForJson(bytes: Bytes): { body: string } | { bodyBase64: string } {
  try {
    return { body: new TextDecoder("utf-8", { fatal: true }).decode(bytes) }
  } catch {
    return { bodyBase64: base64UrlEncode(bytes) }
  }
}

// ---------------------------------------------------------------- push

// What mehen push and vault_push send to POST /v1/push. The destination is
// already canonical (the protocol's parser for mehen push's text, its
// schema for vault_push's JSON), so what a human approves is what was asked.
export type PushInput = { item: string; field: string | null; to: PushDestination; with: string | null; reason: string | null }

export function pushRequest(input: PushInput, help: string): PushRequestInput {
  requireSlug(input.item, "item name")
  if (input.with !== null) requireSlug(input.with, "credential to push with")
  const parsed = PushRequest.safeParse({
    item: input.item,
    ...(input.field !== null ? { field: input.field } : {}),
    to: input.to,
    ...(input.with !== null ? { with: input.with } : {}),
    ...(input.reason ? { reason: input.reason } : {}),
  })
  if (!parsed.success) throw usageError(`Invalid push: ${zodMessage(parsed.error)}`, help)
  return parsed.data
}

// `<item>[#<field>]`: the credential and, after #, which secret field.
export function pushItemArgument(text: string, help: string): { item: string; field: string | null } {
  const hash = text.indexOf("#")
  if (hash === -1) return { item: text, field: null }
  if (hash === text.length - 1) throw usageError("Name the field after #, or leave # out to push the credential's main field.", help)
  return { item: text.slice(0, hash), field: text.slice(hash + 1) }
}

export function pushDestinationArgument(text: string, help: string): PushDestination {
  const parsed = parsePushDestination(text)
  if (!parsed) {
    throw usageError(
      `${JSON.stringify(text)} is not a push destination. Use github:<owner>/<repo>/<NAME>, github:<owner>/<repo>/env/<environment>/<NAME>, github:<owner>/<repo>/dependabot/<NAME>, vercel:<project>[@<team>]/<production|preview|development>/<NAME> or cloudflare:<account id>/<script>/<NAME>, in ASCII; a GitHub name may not start with GITHUB_.`,
      help,
    )
  }
  return parsed
}

// The canonical destination in words, as the card says it; the string as
// it is when this mehen cannot read it.
export function pushWords(destination: string): string {
  const parsed = parsePushDestination(destination)
  return parsed ? pushDestinationWords(parsed) : destination
}

// POST /v1/push answers PushResult only for the same push done in the last
// ten minutes; otherwise it refuses approval_required with the ask.
export async function requestPush(api: VaultApi, request: PushRequestInput): Promise<PushResult> {
  const r = await api.request<PushResult>("POST", "/v1/push", request)
  return { push: r.push, item: r.item, field: r.field, version: r.version, destination: r.destination, via: r.via, outcome: r.outcome, at: r.at }
}

export { showPolicy, previewPolicy, proposePolicy, cancelPolicy, stopPolicy, convenienceProposal, type PolicyProposalResult, type PolicyConvenience } from "./policy-operations.ts"
