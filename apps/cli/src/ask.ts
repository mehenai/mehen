// The one way mehen asks a human to open a link (UX-MEHEN-TOOLS 2.2). Every
// command that hands over a link builds an Ask, and the same object is
// rendered as terminal text, as the `ask` field of --json output and as the
// text and resource link of an MCP result, so the three cannot drift.
//
// The field names are a contract with the native apps that render asks:
// do not rename them.

import { hostname } from "node:os"
import { ADOPTION_ID } from "@mehen/protocol/adopt"
import type { NextStep } from "@mehen/protocol/api"
import { getOAuthProvider, getTemplate } from "@mehen/protocol/templates"
import type { Backend, Env } from "./config.ts"
import { CliError, type CliErrorCode } from "./errors.ts"
import { renderQr } from "./qr.ts"
import { type QrChoice, type Segment, type Styler, plainStyler, plainText, segments, visibleText } from "./tty.ts"

// bundle: several relay requests a human approves together (bnd_, /g/).
// mandate: a mandate this machine proposed (mdp_), signed on its sign page,
// whose link carries the id in its query.
export type AskKind = "enrol" | "intake" | "connect" | "reconnect" | "approval" | "policy" | "adoption" | "bundle" | "unfreeze" | "mandate"
// The kinds whose link is a route with the ask's own id, which mehen wait follows.
export type WaitableAskKind = Exclude<AskKind, "unfreeze" | "mandate">

// codes: a bundle's binding codes in the agent's order, "K7Q2MX, 9PZ4QA (2)".
export type AskCheckLabel = "fingerprint" | "code" | "account" | "asked by" | "codes"

export type AskCheck = { label: AskCheckLabel; value: string }

export type RequestedBy = { device: string; session: string | null }

// Own-call provenance (design 15.6, 15.8): the origin, workspace and device
// of the authenticated call that raised the ask, so a client shows a trusted
// card only for its own call. Absent on an ask from before enrolment.
export type AskContext = { origin: string; workspace: { id: string; slug: string; name: string } | null; device: string | null }

export type Ask = {
  kind: AskKind
  id: string
  url: string
  title: string
  what: string
  check: AskCheck | null
  expiresAt: string | null
  account: string | null
  requestedBy: RequestedBy
  wait: string | null
  context?: AskContext
  // An enrolment's intent, labelled as intent: the workspace slug and team
  // the machine asked to join, never a verified identity (context.workspace
  // stays null until the slot is verified). With `claimed`, present on every
  // enrol ask and absent on every other kind.
  intent?: { workspace: string; team: string | null }
  // Whether the attempt was started with a connect code (claimed for the
  // account that issued it). Never the code itself.
  claimed?: boolean
  // An approval in a review group or bundle with other open asks: the
  // Review together page (/g/), how many of its asks are open and, from a
  // vault that sends one, the group code that page shows.
  group?: { id: string; url: string; open: number; code?: string }
}

export function withContext<A extends Ask | null>(ask: A, context: AskContext | null | undefined): A {
  return ask && context ? { ...ask, context } : ask
}

// The vault a link is checked against: the origin with the context's
// canonical workspace slug (an enrolled context, or an enrolment's validated
// intent), which alone admits a workspace ask link, and only one prefixed
// /w/<slug>/... with that slug. With no slug known, only the account-level
// security anchor passes: under the fresh-start model there is no legacy
// workspace for an unprefixed ask route to belong to, so none is trusted
// (design 15.6). A bare string is an origin with no slug.
export type AskVault = string | { vaultUrl: string; workspaceSlug?: string | null }

export function askVaultUrl(vault: AskVault | null | undefined): string | null {
  if (vault === null || vault === undefined) return null
  return typeof vault === "string" ? vault : vault.vaultUrl
}

function askVaultSlug(vault: AskVault | null | undefined): string | null {
  return typeof vault === "object" && vault !== null ? (vault.workspaceSlug ?? null) : null
}

const WORKSPACE_PREFIX = /^\/w\/([a-z][a-z0-9-]{1,38}[a-z0-9])(\/.*)$/

export const ASK_TITLES: Record<AskKind, string> = {
  enrol: "Approve this machine",
  intake: "Add a credential",
  connect: "Connect an account",
  reconnect: "Reconnect an account",
  approval: "Approve a request",
  policy: "Allow from now on",
  adoption: "Review adopted credentials",
  bundle: "Approve requests together",
  unfreeze: "Unfreeze the vault",
  mandate: "Trust this machine",
}

// The lifetime each kind of link has when the vault did not say, as a human
// would put it. Null when there is no link lifetime to speak of.
// An enrolment link has no fixed lifetime the CLI knows: the vault renews it
// in place while mehen waits, so only its recorded expiresAt counts.
export const DOCUMENTED_LIFETIME: Record<AskKind, string | null> = {
  enrol: null,
  intake: "about 24 hours",
  connect: "about 15 minutes",
  reconnect: "about 15 minutes",
  approval: "about an hour",
  policy: "about an hour",
  adoption: "about 24 hours",
  bundle: "about an hour",
  unfreeze: null,
  mandate: "about 7 days",
}

const BACKEND_LABEL: Record<Backend, string> = { "secure-enclave": "Secure Enclave", software: "software" }

const SESSION_LABEL = /^[A-Za-z0-9_.:-]{1,120}$/

// Who the page will say asked: this machine's name in the workspace (the
// slot's recorded config.name) or, when none is recorded, its short host
// name, and the MEHEN_SESSION label when it is one the vault would accept.
export function requestedBy(env: Env, machineName: string | null = null): RequestedBy {
  const device = machineName ?? ((hostname().split(".")[0] ?? "machine").slice(0, 64) || "machine")
  const session = env.MEHEN_SESSION && SESSION_LABEL.test(env.MEHEN_SESSION) ? env.MEHEN_SESSION : null
  return { device, session }
}

export function askedBy(by: RequestedBy): string {
  return by.session ? `${by.device}, session ${by.session}` : by.device
}

const BUNDLE_ID = /^bnd_[A-Za-z0-9_-]{1,60}$/
// A Review together page: a bundle, or a machine's review group.
const REVIEW_ID = /^(?:bnd|grp)_[A-Za-z0-9_-]{1,60}$/
// A Review together page's group code, in the binding codes' alphabet.
export const GROUP_CODE = /^[ABCDEFGHJKMNPQRSTVWXYZ2-9]{6}$/

// The ids an Ask may carry, by kind: the vault's prefix and alphabet, and
// nothing else, so an id can go into a wait command or a line of text. An
// enrolment's ask id is enr_; its link carries the code (isAskId).
const WAIT_ID: Record<WaitableAskKind, RegExp> = {
  enrol: /^enr_[A-Za-z0-9_-]{1,60}$/,
  intake: /^int_[A-Za-z0-9_-]{1,60}$/,
  connect: /^con_[A-Za-z0-9_-]{1,60}$/,
  reconnect: /^con_[A-Za-z0-9_-]{1,60}$/,
  approval: /^apr_[A-Za-z0-9_-]{1,60}$/,
  policy: /^pol_[A-Za-z0-9_-]{1,60}$/,
  adoption: ADOPTION_ID,
  bundle: BUNDLE_ID,
}

export function isWaitId(kind: WaitableAskKind, id: unknown): id is string {
  return typeof id === "string" && WAIT_ID[kind].test(id)
}

// Every builder takes its id through this: "" for an ask with no id yet,
// otherwise an id the vault could have issued, or the ask is refused.
function askId(kind: WaitableAskKind, id: string): string {
  if (id === "" || isWaitId(kind, id)) return id
  throw new CliError("internal", `The vault returned an id mehen does not recognise for ${kind === "approval" ? "an approval" : `a ${kind}`}.`, {
    say: "The vault's answer did not look like one mehen knows; check the vault URL and try again.",
  })
}

// A minute per call fits inside every harness's shell tool limit (Claude
// Code's Bash stops at 2 min); a wait that times out exits 4 with the ask.
function waitCommand(kind: WaitableAskKind, id: string): string | null {
  return isWaitId(kind, id) ? `mehen wait ${id} --timeout 60 --json` : null
}

// ---------------------------------------------------------------- the link

// A link that has been checked against the vault this machine uses: same
// scheme, host and port, no userinfo, no query or fragment, a path that is
// one of the vault's ask routes, and nothing a terminal would hide or obey.
// Every builder takes one, so the only way to put a url on an Ask is
// askUrl() below; the QR code is drawn from the very same string.
declare const askUrlBrand: unique symbol
export type AskUrl = string & { readonly [askUrlBrand]: true }

// Which ask route the link is, parsed once by askUrl relative to the vault's
// own path, so nobody reparses the pathname later. Null for the vault root
// (the unfreeze link), or the security anchor in notice-only mode. "items"
// is a credential's own page, where the vault
// sends a human to replace a credential it can no longer use (needs_reauth
// for an API key, or an OAuth client whose secret the provider rejected);
// its id is the item's slug. "devices" (no id) and "projects" (a project
// id) are the pages the vault names when only a human can change a machine's
// scope or a project's settings; they are never an ask of their own.
// "sign-mandate" is a mandate proposal's sign page, /sign-mandate?proposal=<mdp_>,
// the one ask route with a query; its id is the proposal's. "mandates" is
// one mandate's own page (/mandates/<mdt_>), where its signer resumes,
// stops or signs it again; this machine never acts there.
export type AskRoutePrefix = "e" | "i" | "c" | "a" | "p" | "b" | "g" | "items" | "devices" | "projects" | "sign-mandate" | "mandates"
export type AskRoute = { prefix: AskRoutePrefix; id: string } | null

// `workspace` is the slug of a prefixed link, null for an unprefixed one.
export type AskLink = { url: AskUrl; route: AskRoute; workspace: string | null }

const ASK_ROUTE = /^\/(?:([eicapbg])\/([A-Za-z0-9_-]{1,64}))?$/
const ITEM_ROUTE = /^\/items\/([a-z][a-z0-9-]{1,63})$/
const PAGE_ROUTE = /^\/(?:(devices)|projects\/(prj_[A-Za-z0-9_-]{1,64}))$/
const MANDATE_PROPOSAL_ID = /^mdp_[A-Za-z0-9_-]{1,60}$/
const MANDATE_PROPOSAL_QUERY = /^\?proposal=(mdp_[A-Za-z0-9_-]{1,60})$/
const MANDATE_ID = /^mdt_[A-Za-z0-9_-]{1,60}$/
const MANDATE_PAGE_ROUTE = /^\/mandates\/(mdt_[A-Za-z0-9_-]{1,60})$/
const ASK_URL_MAX_LENGTH = 2048

// The checked link with its route, or null when it is not one this mehen may
// hand to a human. Notice-only mode accepts just /settings#security, not
// an ask route. `vaultUrl` is the resolved vault URL (resolveVaultUrl:
// https, no trailing slash, no query or fragment).
export function askUrl(raw: unknown, vaultScope: AskVault | null | undefined, options: { purpose?: "security-notice" } = {}): AskLink | null {
  const vaultUrl = askVaultUrl(vaultScope)
  const slug = askVaultSlug(vaultScope)
  if (typeof raw !== "string" || !vaultUrl || raw.length === 0 || raw.length > ASK_URL_MAX_LENGTH) return null
  if (visibleText(raw) !== raw || /\s/.test(raw)) return null
  let link: URL
  let vault: URL
  try {
    link = new URL(raw)
    vault = new URL(vaultUrl)
  } catch {
    return null
  }
  if (link.username !== "" || link.password !== "") return null
  if (link.origin !== vault.origin || link.origin === "null") return null
  // Only notice delivery may hand over the security anchor; ordinary asks
  // and error links keep their existing fragment-free contract.
  if (options.purpose === "security-notice") {
    const base = vault.pathname.replace(/\/+$/, "")
    return raw === `${vault.origin}${base}/settings#security` ? { url: raw as AskUrl, route: null, workspace: null } : null
  }
  // A query is a mandate proposal's alone, exactly ?proposal=<mdp_ id>.
  const proposal = link.search === "" ? null : MANDATE_PROPOSAL_QUERY.exec(link.search)
  if (link.search !== "" && proposal === null) return null
  if (link.hash !== "" || raw.split("?").length !== (proposal ? 2 : 1) || raw.includes("#") || raw.includes("\\")) return null
  const base = vault.pathname.replace(/\/+$/, "")
  if (!link.pathname.startsWith(base)) return null
  let path = link.pathname.slice(base.length)
  // A workspace ask link is this context's only under its own canonical
  // slug (threat T1): any other slug, alias included, and any unprefixed
  // route are refused, and the caller rebuilds the link from the id. With
  // no slug known nothing is trusted.
  const prefixed = WORKSPACE_PREFIX.exec(path)
  if (!prefixed || slug === null || prefixed[1] !== slug) return null
  const workspace = prefixed[1] as string
  path = prefixed[2] as string
  if (proposal) return path === "/sign-mandate" ? { url: link.href as AskUrl, route: { prefix: "sign-mandate", id: proposal[1] as string }, workspace } : null
  const mandate = MANDATE_PAGE_ROUTE.exec(path)
  if (mandate) return { url: link.href as AskUrl, route: { prefix: "mandates", id: mandate[1] as string }, workspace }
  const item = ITEM_ROUTE.exec(path)
  // The same slug rule as the vault's: no trailing or doubled hyphen.
  if (item) return item[1]!.endsWith("-") || item[1]!.includes("--") ? null : { url: link.href as AskUrl, route: { prefix: "items", id: item[1]! }, workspace }
  const page = PAGE_ROUTE.exec(path)
  if (page) return { url: link.href as AskUrl, route: page[1] ? { prefix: "devices", id: "" } : { prefix: "projects", id: page[2]! }, workspace }
  const match = ASK_ROUTE.exec(path)
  if (!match || (match[1] === "p" && !isAskId("policy", match[2])) || (match[1] === "b" && !isAskId("adoption", match[2])) || (match[1] === "g" && !REVIEW_ID.test(match[2]!))) return null
  // The link as the browser reads it, so what is printed and what the QR
  // encodes is one canonical string.
  const route: AskRoute = match[1] ? { prefix: match[1] as AskRoutePrefix, id: match[2] as string } : null
  return { url: link.href as AskUrl, route, workspace }
}

export const ROUTE_PREFIX: Record<WaitableAskKind, AskRoutePrefix> = { enrol: "e", intake: "i", connect: "c", reconnect: "c", approval: "a", policy: "p", adoption: "b", bundle: "g" }

// What an id may look like before it goes into a path: the vault's prefix
// for the kind and the id alphabet, nothing else. An enrol link carries the
// enrolment code, not the enr_ id.
const ASK_ID: Record<WaitableAskKind, RegExp> = {
  enrol: /^[A-Za-z0-9]{6,32}$/,
  intake: /^int_[A-Za-z0-9_-]{1,60}$/,
  connect: /^con_[A-Za-z0-9_-]{1,60}$/,
  reconnect: /^con_[A-Za-z0-9_-]{1,60}$/,
  approval: /^apr_[A-Za-z0-9_-]{1,60}$/,
  policy: /^pol_[A-Za-z0-9_-]{1,60}$/,
  adoption: ADOPTION_ID,
  bundle: BUNDLE_ID,
}

export function isAskId(kind: WaitableAskKind, id: unknown): id is string {
  return typeof id === "string" && ASK_ID[kind].test(id)
}

// The vault's own link for an id or code, built here rather than taken from
// a response. The id is checked against the kind's prefix and alphabet
// before it goes anywhere near a path; one that fails gives no link at all.
// The vault's route under the context's canonical slug, built here rather
// than taken from a response. With no slug known there is no link to build:
// an ask is never promoted into a workspace it cannot be proven to belong to.
export function askUrlFor(vault: AskVault, kind: WaitableAskKind, id: string): AskLink | null {
  if (!isAskId(kind, id)) return null
  const slug = askVaultSlug(vault)
  if (slug === null) return null
  return askUrl(`${askVaultUrl(vault) as string}/w/${slug}/${ROUTE_PREFIX[kind]}/${id}`, vault)
}

// A mandate proposal's sign page under the canonical slug.
export function mandateProposalUrlFor(vault: AskVault, id: string): AskLink | null {
  const slug = askVaultSlug(vault)
  if (!MANDATE_PROPOSAL_ID.test(id) || slug === null) return null
  return askUrl(`${askVaultUrl(vault) as string}/w/${slug}/sign-mandate?proposal=${id}`, vault)
}

// One mandate's page under the canonical slug.
export function mandatePageUrlFor(vault: AskVault, id: string): AskLink | null {
  const slug = askVaultSlug(vault)
  if (!MANDATE_ID.test(id) || slug === null) return null
  return askUrl(`${askVaultUrl(vault) as string}/w/${slug}/mandates/${id}`, vault)
}

// The workspace's root under its canonical slug (the unfreeze page).
export function askRootFor(vault: AskVault): AskLink | null {
  const slug = askVaultSlug(vault)
  if (slug === null) return null
  return askUrl(`${askVaultUrl(vault) as string}/w/${slug}/`, vault)
}

// ---------------------------------------------------------------- builders

export type EnrolAskInput = {
  id: string
  url: AskUrl
  name: string
  backend: Backend
  fingerprint: string
  expiresAt: string | null
  requestedBy: RequestedBy
  intent?: { workspace: string; team: string | null }
  claimed?: boolean
}

export function enrolAsk(input: EnrolAskInput): Ask {
  const id = askId("enrol", input.id)
  const intent = input.intent ? { intent: { workspace: input.intent.workspace, team: input.intent.team }, claimed: input.claimed ?? false } : {}
  return {
    kind: "enrol",
    id,
    url: input.url,
    title: ASK_TITLES.enrol,
    what: `Approve ${input.name} (${BACKEND_LABEL[input.backend]} key) and choose what it may use`,
    check: { label: "fingerprint", value: input.fingerprint },
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: waitCommand("enrol", id),
    ...intent,
  }
}

export type IntakeAskInput = {
  id: string
  url: AskUrl
  name: string
  kind: string
  provider: string | null
  reason: string | null
  // Proposed hosts, for a credential no template covers.
  hosts?: string[]
  // For an oauth-client intake: the redirect URI the human must register.
  redirectUri?: string | null
  expiresAt: string | null
  requestedBy: RequestedBy
}

export function intakeAsk(input: IntakeAskInput): Ask {
  const template = input.provider ? getTemplate(input.provider) : null
  const display = template?.displayName ?? input.kind
  const hosts = template?.binding.hosts ?? input.hosts ?? []
  const detail = input.redirectUri ? `${display}, redirect URI ${input.redirectUri}` : hosts.length ? `${display}, goes to ${hosts.join(", ")}` : display
  const reason = input.reason ? ` so the agent can ${input.reason}` : ""
  const id = askId("intake", input.id)
  return {
    kind: "intake",
    id,
    url: input.url,
    title: ASK_TITLES.intake,
    what: `Add ${input.name} (${detail})${reason}`,
    check: { label: "asked by", value: askedBy(input.requestedBy) },
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: waitCommand("intake", id),
  }
}

export type AdoptionAskInput = {
  id: string
  url: AskUrl
  // Items this machine uploaded into the batch.
  items: number
  machine: string
  expiresAt: string | null
  requestedBy: RequestedBy
}

export function adoptionAsk(input: AdoptionAskInput): Ask {
  const id = askId("adoption", input.id)
  return {
    kind: "adoption",
    id,
    url: input.url,
    title: ASK_TITLES.adoption,
    what: `Review and approve ${input.items} credential${input.items === 1 ? "" : "s"} adopted from ${input.machine}; they go into the vault, never to the agent`,
    check: { label: "asked by", value: askedBy(input.requestedBy) },
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: waitCommand("adoption", id),
  }
}

export type ConnectAskInput = {
  id: string
  url: AskUrl
  name: string
  provider: string
  account: string | null
  reason: string | null
  expiresAt: string | null
  requestedBy: RequestedBy
}

function providerDisplay(provider: string): string {
  return getOAuthProvider(provider)?.displayName ?? provider
}

export function connectAsk(input: ConnectAskInput): Ask {
  const as = input.account ? ` as ${input.account}` : ""
  const reason = input.reason ? ` so the agent can ${input.reason}` : ""
  const id = askId("connect", input.id)
  return {
    kind: "connect",
    id,
    url: input.url,
    title: ASK_TITLES.connect,
    what: `Connect ${input.name} to ${providerDisplay(input.provider)}${as}${reason}`,
    check: input.account ? { label: "account", value: input.account } : null,
    expiresAt: input.expiresAt,
    account: input.account,
    requestedBy: input.requestedBy,
    wait: waitCommand("connect", id),
  }
}

export type ReauthAskInput = Omit<ConnectAskInput, "reason">

export function reauthAsk(input: ReauthAskInput): Ask {
  const as = input.account ? ` as ${input.account}` : ""
  const id = askId("reconnect", input.id)
  return {
    kind: "reconnect",
    id,
    url: input.url,
    title: ASK_TITLES.reconnect,
    what: `Reconnect ${input.name} to ${providerDisplay(input.provider)}${as}`,
    check: input.account ? { label: "account", value: input.account } : null,
    expiresAt: input.expiresAt,
    account: input.account,
    requestedBy: input.requestedBy,
    wait: waitCommand("reconnect", id),
  }
}

export type ApprovalAskInput = {
  id: string
  url: AskUrl
  summary: string
  // The vault's binding code; null when the vault did not send one. Never
  // made up here.
  bindingCode: string | null
  item?: string | null
  account?: string | null
  expiresAt: string | null
  requestedBy: RequestedBy
}

export function approvalAsk(input: ApprovalAskInput): Ask {
  const from = input.item ? `, from ${input.item}${input.account ? ` (${input.account})` : ""}` : ""
  const id = askId("approval", input.id)
  return {
    kind: "approval",
    id,
    url: input.url,
    title: ASK_TITLES.approval,
    what: `${input.summary}${from}`,
    check: input.bindingCode ? { label: "code", value: input.bindingCode } : null,
    expiresAt: input.expiresAt,
    account: input.account ?? null,
    requestedBy: input.requestedBy,
    wait: waitCommand("approval", id),
  }
}

export function policyAsk(input: Omit<ApprovalAskInput, "item" | "account">): Ask {
  if (!isWaitId("policy", input.id)) throw new CliError("internal", "The vault returned an invalid policy proposal id.")
  const route = new URL(input.url).pathname.split("/").slice(-2)
  if (route[0] !== "p" || route[1] !== input.id) throw new CliError("internal", "The policy link does not match its proposal id.")
  return {
    kind: "policy",
    id: input.id,
    url: input.url,
    title: ASK_TITLES.policy,
    what: input.summary,
    check: input.bindingCode ? { label: "code", value: input.bindingCode } : null,
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: waitCommand("policy", input.id),
  }
}

export type BundleAskInput = {
  id: string
  url: AskUrl
  // The binding codes of the bundle's asks in the plan's order; null when
  // the vault did not send one for every ask. Never made up here.
  codes: string[] | null
  // The bundle's one group code, which its page shows; the check when the
  // vault sent it, in place of every ask's code.
  code?: string | null
  // How many of the plan's requests wait in the bundle.
  asks: number
  // The plan's reason, the agent's own words.
  reason: string | null
  expiresAt: string | null
  requestedBy: RequestedBy
}

// The check is the bundle's group code when the vault sent one; else the
// codes check reads "K7Q2MX, 9PZ4QA (2)": every code, in the agent's order,
// as the page lists them, then how many.
export function bundleAsk(input: BundleAskInput): Ask {
  const id = askId("bundle", input.id)
  const reason = input.reason ? `: ${input.reason}` : ""
  return {
    kind: "bundle",
    id,
    url: input.url,
    title: ASK_TITLES.bundle,
    what: `Approve ${input.asks} request${input.asks === 1 ? "" : "s"} together${reason}`,
    check: input.code ? { label: "code", value: input.code } : input.codes && input.codes.length > 0 ? { label: "codes", value: `${input.codes.join(", ")} (${input.codes.length})` } : null,
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: waitCommand("bundle", id),
  }
}

export type MandateAskInput = {
  id: string
  url: AskUrl
  // What the proposed mandate lets this machine do, in plain words.
  what: string
  expiresAt: string | null
  requestedBy: RequestedBy
}

// The person signs on the page with their passkey, or not; mehen wait
// follows it until they do or it expires.
export function mandateAsk(input: MandateAskInput): Ask {
  if (!MANDATE_PROPOSAL_ID.test(input.id)) throw new CliError("internal", "The vault returned an invalid mandate proposal id.")
  return {
    kind: "mandate",
    id: input.id,
    url: input.url,
    title: ASK_TITLES.mandate,
    what: input.what,
    check: { label: "asked by", value: askedBy(input.requestedBy) },
    expiresAt: input.expiresAt,
    account: null,
    requestedBy: input.requestedBy,
    wait: `mehen wait ${input.id} --timeout 60 --json`,
  }
}

export function unfreezeAsk(input: { url: AskUrl; requestedBy: RequestedBy; what?: string }): Ask {
  return {
    kind: "unfreeze",
    id: "",
    url: input.url,
    title: ASK_TITLES.unfreeze,
    what: input.what ?? "Unfreeze the vault after reviewing the audit log",
    check: null,
    expiresAt: null,
    account: null,
    requestedBy: input.requestedBy,
    wait: null,
  }
}

// ---------------------------------------------------------------- synthesis from an error

// The fields of an error body the synthesis reads. `expiresAt` is optional so
// this works before and after the server starts sending it.
export type AskErrorBody = {
  message: string
  next?: NextStep | null
  approval?: string
  bindingCode?: string
  expiresAt?: string | null
  // approval_required only: the review group or bundle (ApiError.group), as
  // the vault sent it; askGroup checks it.
  group?: unknown
}

export type AskErrorContext = { requestedBy: RequestedBy; vaultUrl: AskVault | null }

// What synthesis found: an ask, or none, and whether the error carried a
// link that failed askUrl (so the caller can warn and must not print it).
export type AskSynthesis = { ask: Ask | null; refusedLink: boolean }

const LINK_CODES: ReadonlySet<CliErrorCode> = new Set<CliErrorCode>(["approval_required", "needs_reauth", "intake_required", "device_pending", "frozen"])

// The review group an approval's refusal names, when its id is a group's or
// a bundle's, its link is this vault's /g/ page for that id and its count is
// a count; `refusedLink` when it carried a link that is not.
export function askGroup(raw: unknown, vault: AskVault | null): { group: Ask["group"] | null; refusedLink: boolean } {
  if (typeof raw !== "object" || raw === null) return { group: null, refusedLink: false }
  const { id, url, open, code } = raw as Record<string, unknown>
  if (typeof id !== "string" || !REVIEW_ID.test(id) || typeof open !== "number" || !Number.isInteger(open) || open < 0) return { group: null, refusedLink: false }
  const link = askUrl(url, vault)
  if (!link || link.route?.prefix !== "g" || link.route.id !== id) return { group: null, refusedLink: typeof url === "string" }
  return { group: { id, url: link.url, open, ...(typeof code === "string" && GROUP_CODE.test(code) ? { code } : {}) }, refusedLink: false }
}

// An Ask for a vault refusal that hands over a link, or none when the error
// is not one of those or carries no usable link. Copies `approval`,
// `bindingCode`, `message` and `expiresAt` from the body; the link is taken
// only through askUrl against the configured vault, never invents a check
// value or an expiry.
export function askFromError(code: CliErrorCode, body: AskErrorBody, context: AskErrorContext): AskSynthesis {
  const none: AskSynthesis = { ask: null, refusedLink: false }
  if (!LINK_CODES.has(code)) return none
  const raw = body.next?.url
  const link = askUrl(raw, context.vaultUrl)
  const refusedLink = typeof raw === "string" && raw !== "" && link === null
  const refused: AskSynthesis = { ask: null, refusedLink: true }
  const expiresAt = typeof body.expiresAt === "string" ? body.expiresAt : null
  const what = body.message.replace(/\.$/, "")
  const by = context.requestedBy
  // The id for a kind: the checked link's route id when the link has one of
  // the right prefix (a route of another prefix is not this kind's link); a
  // body id must be well formed and, when the route has an id, equal to it.
  const idFor = (kind: WaitableAskKind, bodyId: string | undefined): { id: string } | { bad: true } => {
    if (bodyId !== undefined && !isWaitId(kind, bodyId)) return { bad: true }
    if (link?.route) {
      if (link.route.prefix !== ROUTE_PREFIX[kind] || !isWaitId(kind, link.route.id)) return { bad: true }
      if (bodyId !== undefined && bodyId !== link.route.id) return { bad: true }
      return { id: link.route.id }
    }
    return { id: bodyId ?? "" }
  }
  if (code === "approval_required") {
    const found = idFor("approval", body.approval)
    if ("bad" in found) return refused
    const target = link ?? (found.id && context.vaultUrl ? askUrlFor(context.vaultUrl, "approval", found.id) : null)
    if (!target) return { ask: null, refusedLink }
    const group = askGroup(body.group, context.vaultUrl)
    const ask = approvalAsk({ id: found.id, url: target.url, summary: what, bindingCode: body.bindingCode ?? null, expiresAt, requestedBy: by })
    return { ask: group.group ? { ...ask, group: group.group } : ask, refusedLink: refusedLink || group.refusedLink }
  }
  if (code === "frozen") {
    if (link?.route) return refused
    const target = link ?? (context.vaultUrl ? askRootFor(context.vaultUrl) : null)
    if (!target) return { ask: null, refusedLink }
    return { ask: unfreezeAsk({ url: target.url, requestedBy: by, what }), refusedLink }
  }
  if (!link) return { ask: null, refusedLink }
  const url = link.url
  if (code === "needs_reauth") {
    // A credential to replace on its own page: nothing to wait on, the human
    // replaces it and the agent tries again.
    if (link.route?.prefix === "items") return { ask: reauthAskFromLink("", url, what, expiresAt, by), refusedLink }
    const found = idFor("reconnect", undefined)
    if ("bad" in found) return refused
    return { ask: reauthAskFromLink(found.id, url, what, expiresAt, by), refusedLink }
  }
  if (link.route?.prefix === "items") return refused
  if (code === "intake_required") {
    const found = idFor("intake", undefined)
    if ("bad" in found) return refused
    return { ask: { kind: "intake", id: found.id, url, title: ASK_TITLES.intake, what, check: { label: "asked by", value: askedBy(by) }, expiresAt, account: null, requestedBy: by, wait: waitCommand("intake", found.id) }, refusedLink }
  }
  if (link.route && (link.route.prefix !== "e" || !isAskId("enrol", link.route.id))) return refused
  return { ask: { kind: "enrol", id: "", url, title: ASK_TITLES.enrol, what, check: null, expiresAt, account: null, requestedBy: by, wait: null }, refusedLink }
}

function reauthAskFromLink(id: string, url: AskUrl, what: string, expiresAt: string | null, by: RequestedBy): Ask {
  return { kind: "reconnect", id, url, title: ASK_TITLES.reconnect, what, check: null, expiresAt, account: null, requestedBy: by, wait: waitCommand("reconnect", id) }
}

// The ask a CliError carries: one attached by the command that threw it (its
// url already went through askUrl), or one synthesised from the vault's
// error body against the configured vault URL.
export function askForError(error: CliError, env: Env, vaultUrl: AskVault | null): AskSynthesis {
  if (error.extras.ask) return { ask: error.extras.ask, refusedLink: false }
  // The failing call's own provenance (vault-api.ts CallContext) decides the
  // slug a link is checked and built under; the rendering-time selection is
  // only a fallback when the error carries none.
  const call = error.extras.context ?? null
  const vault: AskVault | null = call ? { vaultUrl: call.origin, workspaceSlug: call.workspace?.slug ?? null } : vaultUrl
  const synthesis = askFromError(
    error.code,
    { message: error.message, next: error.next, ...(error.extras.approval ? { approval: error.extras.approval } : {}), ...(error.extras.bindingCode ? { bindingCode: error.extras.bindingCode } : {}), ...(error.extras.expiresAt ? { expiresAt: error.extras.expiresAt } : {}), ...(error.extras.group !== undefined ? { group: error.extras.group } : {}) },
    { requestedBy: requestedBy(env), vaultUrl: vault },
  )
  return { ...synthesis, ask: withContext(synthesis.ask, call) }
}

// The sentence printed in place of a link mehen would not hand over.
export function refusedLinkWarning(vault: AskVault | null): string {
  const vaultUrl = askVaultUrl(vault)
  return vaultUrl
    ? `The vault returned a link that is not on ${vaultUrl}, so mehen did not show it. Check MEHEN_VAULT_URL and the vault before opening anything.`
    : "The vault returned a link mehen could not check against a vault URL, so mehen did not show it."
}

// ---------------------------------------------------------------- expiry wording

export type ClockOptions = { now?: Date; timeZone?: string }

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

// "in 58 min", "in 24 h", "in 3 days", "in under a minute", or "expired".
export function relativeExpiry(expiresAt: string, now: Date): string | null {
  const at = Date.parse(expiresAt)
  if (!Number.isFinite(at)) return null
  const left = at - now.getTime()
  if (left <= 0) return "expired"
  if (left < MINUTE) return "in under a minute"
  if (left < HOUR) return `in ${Math.ceil(left / MINUTE)} min`
  if (left < 2 * DAY) return `in ${Math.round(left / HOUR)} h`
  return `in ${Math.round(left / DAY)} days`
}

function dayKey(date: Date, timeZone: string | undefined): string {
  return new Intl.DateTimeFormat("en-GB", { ...(timeZone ? { timeZone } : {}), year: "numeric", month: "2-digit", day: "2-digit" }).format(date)
}

// "17:12", "tomorrow 17:20" or "25 Oct 17:20", in local time (or the given
// zone), so a human can read the clock on the wall against it.
export function clockText(expiresAt: string, options: ClockOptions = {}): string | null {
  const at = Date.parse(expiresAt)
  if (!Number.isFinite(at)) return null
  const date = new Date(at)
  const now = options.now ?? new Date()
  const zone = options.timeZone
  const time = new Intl.DateTimeFormat("en-GB", { ...(zone ? { timeZone: zone } : {}), hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(date)
  const day = dayKey(date, zone)
  if (day === dayKey(now, zone)) return time
  if (day === dayKey(new Date(now.getTime() + DAY), zone)) return `tomorrow ${time}`
  const calendar = new Intl.DateTimeFormat("en-GB", { ...(zone ? { timeZone: zone } : {}), day: "numeric", month: "short" }).format(date)
  return `${calendar} ${time}`
}

// The expires: line: relative then absolute, "expired", or "unknown" with the
// kind's documented lifetime when the vault did not say.
export function expiryText(ask: Pick<Ask, "kind" | "expiresAt">, options: ClockOptions = {}): string {
  const now = options.now ?? new Date()
  if (ask.expiresAt) {
    const relative = relativeExpiry(ask.expiresAt, now)
    const clock = clockText(ask.expiresAt, { now, ...(options.timeZone ? { timeZone: options.timeZone } : {}) })
    if (relative === "expired") return "expired"
    if (relative && clock) return `${relative} (${clock})`
    if (relative) return relative
  }
  const lifetime = DOCUMENTED_LIFETIME[ask.kind]
  return lifetime ? `unknown (${lifetime})` : "unknown"
}

// ---------------------------------------------------------------- rendering

function lowerFirst(text: string): string {
  const second = text.charAt(1)
  return second && second === second.toUpperCase() && second !== second.toLowerCase() ? text : text.charAt(0).toLowerCase() + text.slice(1)
}

// "the page shows code K7Q2MX": always where to look, then what to compare.
// The value is its own segment so it can be bold without the sentence
// around it ever being parsed for style.
export function checkSentence(check: AskCheck, bold: (text: string) => Segment = (text) => ({ text })): Segment[] {
  const value = bold(check.value)
  if (check.label === "fingerprint") return segments("the page shows fingerprint  ", value)
  if (check.label === "code") return segments("the page shows code ", value)
  if (check.label === "account") return segments("the page shows account ", value, "; sign in as that account")
  if (check.label === "codes") return segments("the page shows codes ", value)
  return segments("the page says it was asked by ", value)
}

export type AskTextOptions = ClockOptions & {
  style?: Styler
  // Draw a QR code of the link between open: and what:, with this scheme.
  qr?: QrChoice
  indent?: number
  // Replaces the then: line (for example "vault_wait { ... }" in MCP, or
  // "mehen keeps waiting" while enrolling). Null drops the line.
  then?: string | null
  // Appended to the expires: line after "; ".
  expiresNote?: string
}

const LABEL_WIDTH = 8

// The ask block as lines of segments. open: is always the second line, so
// an eye or a regex can find the link; the check sentence always starts "the
// page". Every text segment is spelled out at the terminal boundary; only
// the segments the styler made carry a style.
export function askLines(ask: Ask, options: AskTextOptions = {}): Segment[][] {
  const s = options.style ?? plainStyler()
  const pad = " ".repeat(options.indent ?? 2)
  const label = (name: string) => s.dim(`${name}:`.padEnd(LABEL_WIDTH))
  // The QR is drawn from the url exactly as the open: line prints it. An Ask
  // built through askUrl prints its url unchanged; one that somehow was not
  // gets no QR, so the code can never carry what the eye does not see.
  const lines: Segment[][] = [segments(s.accent("Human needed:"), ` ${lowerFirst(ask.title)}`), segments(`${pad}`, label("open"), ` ${ask.url}`)]
  if (options.qr && visibleText(ask.url) === ask.url) {
    for (const row of renderQr(ask.url, { scheme: options.qr.scheme }).split("\n")) lines.push(segments(`${pad}${row}`))
  }
  lines.push(segments(pad, label("what"), ` ${ask.what}`))
  if (ask.check) lines.push(segments(pad, label("check"), " ", checkSentence(ask.check, s.bold)))
  // An approval in a review group: the person may decide it there, where the page shows the group's code.
  if (ask.group?.code) lines.push(segments(pad, label("group"), ` ${ask.group.url}; the page shows code `, s.bold(ask.group.code)))
  if (ask.kind !== "unfreeze") {
    const expiry = expiryText(ask, options)
    lines.push(segments(pad, label("expires"), " ", expiry === "expired" ? s.danger(expiry) : expiry, options.expiresNote ? `; ${options.expiresNote}` : ""))
  }
  const then = options.then === undefined ? ask.wait : options.then
  if (then) lines.push(segments(pad, label("then"), ` ${then}`))
  return lines
}

// The block as plain text with every character spelled out: for MCP content
// and for anything that is not a terminal. Styles are dropped.
export function askText(ask: Ask, options: AskTextOptions = {}): string {
  return askLines(ask, options)
    .map((line) => visibleText(plainText(line)))
    .join("\n")
}

// One sentence an agent can say to its human, generated from the ask.
export function askSay(ask: Ask, options: ClockOptions = {}): string {
  const now = options.now ?? new Date()
  const clauses: string[] = []
  if (ask.kind === "enrol") clauses.push(`Approve this machine at ${ask.url}`)
  else if (ask.kind === "approval") clauses.push(`Approve the request at ${ask.url}: ${ask.what}`)
  else if (ask.kind === "policy") return `Review this policy change in the vault at ${ask.url}${ask.check?.label === "code" ? ` and check the code ${ask.check.value}` : ""}. No access has changed yet.`
  else if (ask.kind === "unfreeze") return `Unfreeze the vault at ${ask.url} with your passkey after reviewing the audit log.`
  else if (ask.kind === "mandate") return `Review what this machine asks to do without asking you at ${ask.url}: ${ask.what.replace(/\.+$/, "")}. Nothing changes until you sign it with your passkey.`
  else clauses.push(`Open ${ask.url} to ${lowerFirst(ask.what)}`)
  if (ask.check?.label === "fingerprint") clauses.push(`the page should show fingerprint ${ask.check.value}`)
  else if (ask.check?.label === "code") clauses.push(`the page should show code ${ask.check.value}`)
  else if (ask.check?.label === "account") clauses.push(`sign in as ${ask.check.value}`)
  else if (ask.check?.label === "codes") clauses.push(`the page should show codes ${ask.check.value}`)
  if (ask.kind === "intake") clauses.push("it goes into the vault, never to the agent")
  if (ask.expiresAt) {
    const relative = relativeExpiry(ask.expiresAt, now)
    if (relative === "expired") clauses.push("the link has expired")
    else if (relative) clauses.push(`it expires ${relative}`)
  } else {
    const lifetime = DOCUMENTED_LIFETIME[ask.kind]
    if (lifetime) clauses.push(`the link lasts ${lifetime}`)
  }
  return `${clauses.join("; ")}.`
}

// The compatible `next` for a result that carries an ask: the same link, the
// wait command (or the one given) and the generated sentence.
export function askNext(ask: Ask, options: ClockOptions & { command?: string | null } = {}): NextStep {
  const command = options.command === undefined ? ask.wait : options.command
  return { url: ask.url, ...(command ? { command } : {}), say: askSay(ask, options) }
}

// The MCP content item a host renders as a button.
export type AskResourceLink = { type: "resource_link"; uri: string; name: string; description: string; mimeType: "text/html" }

export function askResourceLink(ask: Ask): AskResourceLink {
  const check = ask.check ? ` (${ask.check.label} ${ask.check.value})` : ""
  return { type: "resource_link", uri: ask.url, name: `${ask.title}${check}`, description: ask.what, mimeType: "text/html" }
}
