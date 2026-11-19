// A mock vault for the CLI's tests: Bun.serve on 127.0.0.1:0 that verifies
// every Mehen-Proof with protocol's parseProof and verifyProof, so a request
// signed over the wrong body, URL or key is refused exactly as the real
// vault would refuse it.

import { compareVersions } from "@mehen/protocol/version"
import {
  type ApiError,
  type ApprovalStatus,
  type ConnectStatus,
  type DeviceScope,
  ERROR_HEADER,
  type ErrorCode,
  IntakeCreate,
  type IntakeStatus,
  type ItemDescription,
  ITEM_HEADER,
  RelayRequest,
  type RelayRequestInput,
  UPSTREAM_HEADER,
} from "@mehen/protocol/api"
import { type DeviceJwk, PROOF_HEADER, type ProofClaims, bodyHash, importDeviceKey, jwkThumbprint, parseProof, verifyProof } from "@mehen/protocol/proof"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { type OwnerRef, type WorkspaceDeviceScope, type WorkspaceRef, WorkspaceEnrolStartSchema } from "@mehen/protocol/workspace"
import { type Config, writeConfig } from "../config.ts"
import { createDeviceKey, writeKeyScope } from "../device-key.ts"
import { activeSlotPath } from "../home.ts"
import type { LedgerScope } from "../ledger.ts"

// Open asks in the mock live about two hours from when the tests load, so no
// assertion depends on the wall clock (a fixed date expired at midnight).
export const MOCK_EXPIRES_AT = new Date(Date.now() + 2 * 3_600_000 + 60_000).toISOString()

// The mock's one workspace: its id is the proof tenant (design 1.2).
export const MOCK_TENANT = "tn_mock0000000001"
export const MOCK_WORKSPACE: WorkspaceRef = { id: MOCK_TENANT, slug: "mock-space", name: "Mock Space" }
export const MOCK_OWNER: OwnerRef = { kind: "member", member: "mem_mock1", name: "Test Owner" }

const STATUS_FOR: Partial<Record<ErrorCode, number>> = {
  unauthenticated: 401,
  proof_invalid: 401,
  device_revoked: 401,
  device_pending: 403,
  forbidden: 403,
  not_found: 404,
  approval_required: 409,
  conflict: 409,
  binding_refused: 403,
  policy_denied: 403,
  bad_request: 400,
  frozen: 423,
  rate_limited: 429,
  workload_ended: 403,
  workload_required: 403,
}

export function vaultError(error: ErrorCode, message: string, extra: Omit<ApiError, "error" | "message"> = {}): Response {
  return Response.json({ error, message, ...extra }, { status: STATUS_FOR[error] ?? 400, headers: { [ERROR_HEADER]: "1" } })
}

export type SeenRequest = { method: string; path: string; search: string; claims: ProofClaims; body: string }

// One enrolment attempt. The lease fields are optional so a test can plant
// an attempt with only what it needs: a missing expiresAt is the mock's
// default lease from now, a missing hardExpiresAt a day from now.
type Enrolment = {
  id: string
  jwk: DeviceJwk
  name: string
  backend: string
  polls: number
  workspace: string
  owner: { kind: "self" } | { kind: "team"; team: string }
  expiresAt?: number
  hardExpiresAt?: number
  renewedAt?: number | null
  renewals?: number
  // Settled at the vault independent of the poll script: a newer attempt
  // with the same key superseded it, or it reached its hard cap.
  settled?: "superseded" | "hard_cap"
}

// The vault's lease behaviour the mock speaks:
// "current" is S1a's (hardExpiresAt on start and poll, renew in place,
// expired with a reason); "pre0008" is a vault from before migration 0008
// (no hardExpiresAt, expired without a reason, and renew answered 404 as an
// unknown route or, with renew409, a 409 carrying neither retryAfter nor the
// enrolment).
export type EnrolMode = "current" | "pre0008"

export type MockRoute = (request: Request, seen: SeenRequest) => Response | Promise<Response>

// What GET /v1/pending serves (the protocol's PendingAsk, every field past
// the id optional so a test can serve a sparse or hostile entry); the mock
// answers 404 until a test sets `pending`, so the ledger fallback is what
// runs by default.
export type MockPendingEntry = {
  kind: "intake" | "connect" | "approval"
  id: string
  url: string
  title?: string | null
  expiresAt: string | null
  requestedBy?: { device: string; deviceName: string; session: string | null } | null
  item?: string | null
  provider?: string | null
  kindRequested?: string | null
  account?: string | null
  bindingCode?: string | null
}

export const SCOPE: DeviceScope & { modes: WorkspaceDeviceScope["modes"] } = { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "placeholder"] }
// The complete scope a workspace vault returns on activation and status.
export const WORKSPACE_SCOPE: WorkspaceDeviceScope = { ...SCOPE, privateCredentials: false }

export function item(slug: string, extra: Partial<ItemDescription> = {}): ItemDescription {
  return {
    slug,
    kind: "api-key",
    provider: "openai",
    account: null,
    accountVerified: false,
    tags: ["ai"],
    ceiling: "placeholder",
    hosts: ["api.openai.com"],
    status: "active",
    updatedAt: "2026-10-24T00:00:00.000Z",
    description: null,
    publicFields: {},
    secretFields: [{ name: "key", set: true, length: 51, prefix: "sk-proj-", fingerprint: "abcdefabcdef" }],
    binding: { hosts: ["api.openai.com"] },
    policy: { default: "allow", rules: [] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    version: 1,
    lastUsedAt: null,
    rotatedAt: null,
    ...extra,
  }
}

// The device id the mock activates an enrolment as (a valid dev_ id).
export function deviceFor(enrolment: string): string {
  return `dev_for${enrolment.replace(/[^A-Za-z0-9]/g, "")}`
}

export class MockVault {
  readonly server: ReturnType<typeof Bun.serve>
  readonly seen: SeenRequest[] = []
  readonly enrolments = new Map<string, Enrolment>()
  // Each device belongs to one workspace: its proof tenant must match.
  readonly devices = new Map<string, { jwk: DeviceJwk; revoked: boolean; tenant?: string }>()
  readonly items: ItemDescription[] = [item("openai-personal"), item("github-work", { kind: "bearer-token", provider: "github-pat", tags: ["code"], hosts: ["api.github.com"] })]
  // Statuses served in order to successive polls; the last one repeats.
  readonly sequences = new Map<string, unknown[]>()
  // How many polls an enrolment stays pending, and what it becomes.
  enrolOutcome: { pendingPolls: number; result: "active" | "rejected" | "expired" } = { pendingPolls: 2, result: "active" }
  enrolMode: EnrolMode = "current"
  // pre0008 only: how the old vault answers a renew.
  renew409 = false
  // The lease a start or a renewal gives, the hard cap from the start, and
  // how often a renewal is allowed.
  enrolLeaseMs = 60_000
  enrolHardMs = 86_400_000
  renewIntervalMs = 60_000
  // Renewals the mock answered, by enrolment id, in order.
  readonly renewed: string[] = []
  // The workspace and owner the mock activates enrolments into and reports
  // on /v1/me; a test changes them to stand in for a rename, an alias or a
  // wrong-workspace acceptance.
  workspace: WorkspaceRef = { ...MOCK_WORKSPACE }
  owner: OwnerRef = { ...MOCK_OWNER }
  // When set, the active answer is this instead (a legacy or hostile shape).
  activeAnswer: ((enrolment: Enrolment, device: string) => unknown) | null = null
  // Revocations the mock accepted, by device id.
  readonly revoked: string[] = []
  // The device enrolSoftware made last, for the ledger identity tests read under.
  lastDevice: string | null = null
  // Other workspaces enrolSoftware was told about, by id, for /v1/me.
  readonly workspaces = new Map<string, WorkspaceRef>()
  // When set, every default pending or open status carries this expiresAt,
  // as the real vault does.
  statusExpiresAt: string | null = null
  // Enrolments started per key thumbprint, so a test can prove a renewed
  // link reused the key.
  readonly enrolmentsByThumbprint = new Map<string, number>()
  pending: MockPendingEntry[] | null = null
  notices: unknown[] | undefined = undefined
  // GET /v1/pending's top-level `groups` (PendingGroup[]); absent when undefined.
  groups: unknown[] | undefined = undefined
  // POST /v1/approvals/bundles holds every request for approval; each
  // bundle's asks, which GET /v1/approvals/bundles/:id reports pending
  // unless `sequences` has "bundle:<id>".
  readonly bundles = new Map<string, string[]>()
  // The group code POST /v1/approvals/bundles answers with; none when undefined.
  bundleCode: string | undefined = undefined
  // The origin the mock writes into the links it hands back (enrol, intake,
  // connect); null for its own. A test sets it to prove a foreign link is
  // refused, as a vault whose VAULT_ORIGIN differs from the URL a device
  // talks to would produce.
  linkOrigin: string | null = null
  // The workspace slug the mock's links are prefixed with (/w/<slug>/...),
  // as the vault's workspace routes are; null emits the legacy unprefixed
  // route, which a workspace context never trusts.
  linkSlug: string | null | undefined = undefined
  frozen = false
  // GET /v1/me carries the device key's fingerprint, as the vault does; a
  // test turns it off to stand in for a vault from before it did.
  meFingerprint = true
  // GET /healthz, unauthenticated as on the vault; a test sets the Date
  // header it sends (a clock skew) or replaces the answer.
  healthz: () => Response = () => Response.json({ ok: true }, { headers: { date: new Date().toUTCString() } })
  relay: (request: RelayRequestInput) => Response = defaultRelay
  readonly overrides = new Map<string, MockRoute>()
  // The /v1 version seam as the vault runs it: `cliAdvice` is
  // sent as Mehen-Cli on every /v1 response; with `cliMinimum`, an
  // identified mehen below it is refused 426 cli_outdated (freeze and
  // self-revoke exempt); `outdatedFrom` refuses every /v1 request from the
  // Nth on (counted from 1), whatever the agent, for refusals mid-command.
  cliAdvice: string | null = null
  cliMinimum: string | null = null
  outdatedFrom: number | null = null
  readonly userAgents: string[] = []
  // Every request refused cli_outdated, as "METHOD /path".
  readonly outdated: string[] = []
  v1Count = 0
  private readonly jtis = new Set<string>()
  private counter = 0

  constructor() {
    this.server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (request) => this.handle(request) })
  }

  get url(): string {
    return `http://127.0.0.1:${this.server.port}`
  }

  stop(): void {
    this.server.stop(true)
  }

  private id(prefix: string): string {
    this.counter += 1
    return `${prefix}_mock${this.counter}`
  }

  // Enrols a software key straight into the mock and writes a config (with
  // the workspace display fields, as mehen enrol writes them) and key scope
  // into the workspace's slot under the config root `root`
  // (workspaces/<originKey>/<tn_id>/), so tests other than the enrol flow
  // start from an enrolled machine. `slotDir` names that directory.
  async enrolSoftware(root: string, options: { fingerprint?: string; config?: Partial<Config> } = {}): Promise<string> {
    const device = this.id("dev")
    const config: Config = { vault: this.url, tenant: MOCK_TENANT, device, backend: "software", ...(options.fingerprint ? { fingerprint: options.fingerprint } : {}), workspaceSlug: this.workspace.slug, workspaceName: this.workspace.name, owner: this.owner, ...options.config }
    const dir = activeSlotPath(root, config.vault, config.tenant)
    const { jwk } = await createDeviceKey(dir, "software", {})
    this.devices.set(device, { jwk, revoked: false, tenant: config.tenant })
    if (config.tenant !== this.workspace.id && config.workspaceSlug && config.workspaceName) this.workspaces.set(config.tenant, { id: config.tenant, slug: config.workspaceSlug, name: config.workspaceName })
    await writeConfig(dir, config)
    await writeKeyScope(dir, "software", { vault: config.vault, tenant: config.tenant })
    this.lastDevice = device
    return device
  }

  // The slot enrolSoftware writes under `root` for a workspace (the mock's
  // own by default) at this vault, or at `origin`.
  slotDir(root: string, tenant: string = MOCK_TENANT, origin: string = this.url): string {
    return activeSlotPath(root, origin, tenant)
  }

  // The ledger identity of the last enrolSoftware context, or the enrol
  // scope (no workspace or device yet) before one exists.
  ledgerScope(): LedgerScope {
    return this.lastDevice ? { vaultUrl: this.url, workspace: MOCK_TENANT, device: this.lastDevice, workspaceSlug: this.workspace.slug } : { vaultUrl: this.url, workspace: null, device: null }
  }

  // The vault a link is checked against from the mock's workspace: its
  // origin and canonical slug (ask.ts AskVault).
  askVault(): { vaultUrl: string; workspaceSlug: string } {
    return { vaultUrl: this.url, workspaceSlug: this.workspace.slug }
  }

  // A link on the vault's workspace route for the device that asked.
  link(tenant: string | undefined, route: string): string {
    const slug = this.linkSlug === undefined ? (tenant === undefined || tenant === this.workspace.id ? this.workspace.slug : (this.workspaces.get(tenant)?.slug ?? this.workspace.slug)) : this.linkSlug
    return `${this.linkOrigin ?? this.url}${slug === null ? "" : `/w/${slug}`}${route}`
  }

  // The vault sends expiresAt on every open ask status (V-4); a test can pin it.
  private withExpiry<T extends object>(status: T): T & { expiresAt: string } {
    return { ...status, expiresAt: this.statusExpiresAt ?? MOCK_EXPIRES_AT }
  }

  private async authenticate(request: Request, url: URL, bytes: Uint8Array<ArrayBuffer>): Promise<SeenRequest | Response> {
    const token = request.headers.get(PROOF_HEADER)
    if (!token) return vaultError("unauthenticated", "Missing Mehen-Proof.", { next: { command: "mehen enrol", say: "Enrol this machine." } })
    let proof: ReturnType<typeof parseProof>
    try {
      proof = parseProof(token)
    } catch {
      return vaultError("proof_invalid", "The Mehen-Proof header is malformed.")
    }
    const { claims } = proof
    const text = new TextDecoder().decode(bytes)
    let jwk: DeviceJwk | undefined
    if (claims.ten === "enrol" && claims.dev === "new") {
      if (request.method !== "POST" || url.pathname !== "/v1/enrol") return vaultError("unauthenticated", "A new key may only start an enrolment.")
      const start = WorkspaceEnrolStartSchema.safeParse(JSON.parse(text))
      if (!start.success) return vaultError("bad_request", "Invalid enrolment: a workspace and owner intent are required.")
      jwk = start.data.jwk
    } else if (claims.ten === "enrol") {
      const enrolment = this.enrolments.get(claims.dev)
      if (!enrolment || (url.pathname !== `/v1/enrol/${claims.dev}` && url.pathname !== `/v1/enrol/${claims.dev}/renew`)) return vaultError("unauthenticated", "Unknown enrolment.")
      jwk = enrolment.jwk
    } else {
      const device = this.devices.get(claims.dev)
      if (!device || claims.ten !== (device.tenant ?? MOCK_TENANT)) return vaultError("unauthenticated", "Unknown device.", { next: { command: "mehen enrol", say: "Enrol this machine." } })
      if (device.revoked) return vaultError("device_revoked", "This device was revoked.", { next: { command: "mehen enrol", say: "Enrol again." } })
      jwk = device.jwk
    }
    const check = await verifyProof(proof, await importDeviceKey(jwk), { method: request.method, url: request.url, bodyHash: await bodyHash(bytes) })
    if (!check.ok) return vaultError("proof_invalid", `The proof does not match the request (${check.reason}).`)
    if (this.jtis.has(claims.jti)) return vaultError("proof_invalid", "Replayed proof.")
    this.jtis.add(claims.jti)
    return { method: request.method, path: url.pathname, search: url.search, claims, body: text }
  }

  private next<T>(key: string, fallback: T): T {
    const queue = this.sequences.get(key)
    if (!queue || queue.length === 0) return fallback
    return (queue.length > 1 ? queue.shift() : queue[0]) as T
  }

  // What a poll (or a settled renew refusal) answers for an attempt: the
  // scripted outcome after `pendingPolls` polls, or what the attempt settled
  // as at the vault; a pending answer carries the attempt's own lease.
  private enrolStatus(enrolment: Enrolment, poll: boolean): unknown {
    const now = Date.now()
    if (poll) enrolment.polls += 1
    const expired = (reason: string) => (this.enrolMode === "current" ? { status: "expired", reason } : { status: "expired" })
    if (enrolment.settled) return expired(enrolment.settled)
    if (enrolment.hardExpiresAt !== undefined && enrolment.hardExpiresAt <= now) return expired("hard_cap")
    if (enrolment.polls <= this.enrolOutcome.pendingPolls) {
      const expiresAt = enrolment.expiresAt !== undefined ? new Date(enrolment.expiresAt).toISOString() : (this.statusExpiresAt ?? MOCK_EXPIRES_AT)
      const hard = enrolment.hardExpiresAt !== undefined ? new Date(enrolment.hardExpiresAt).toISOString() : null
      return { status: enrolment.owner.kind === "team" ? "pending_admission" : "pending_owner_acceptance", expiresAt, ...(this.enrolMode === "current" && hard ? { hardExpiresAt: hard } : {}) }
    }
    if (this.enrolOutcome.result === "expired") return expired("hard_cap")
    if (this.enrolOutcome.result !== "active") return { status: this.enrolOutcome.result }
    const device = deviceFor(enrolment.id)
    // The activated device keeps a revocation across polls, unless a test
    // reused the enrolment id for another key.
    const known = this.devices.get(device)
    if (!known || known.jwk.x !== enrolment.jwk.x || known.jwk.y !== enrolment.jwk.y) this.devices.set(device, { jwk: enrolment.jwk, revoked: false })
    if (this.activeAnswer) return this.activeAnswer(enrolment, device)
    const owner: OwnerRef = enrolment.owner.kind === "team" ? { kind: "team", team: `team_${enrolment.owner.team}`, name: enrolment.owner.team } : this.owner
    return { status: "active", tenant: this.workspace.id, workspace: this.workspace, device, scope: WORKSPACE_SCOPE, owner }
  }

  private async handle(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (!url.pathname.startsWith("/v1/")) return this.route(request, url)
    this.userAgents.push(request.headers.get("user-agent") ?? "")
    this.v1Count += 1
    const agent = /^mehen\/(\d+\.\d+\.\d+)/.exec(request.headers.get("user-agent") ?? "")?.[1]
    const exempt = request.method === "POST" && (url.pathname === "/v1/freeze" || url.pathname === "/v1/devices/self/revoke")
    const below = this.cliMinimum !== null && agent !== undefined && compareVersions(agent, this.cliMinimum) < 0
    let response: Response
    if (!exempt && (below || (this.outdatedFrom !== null && this.v1Count >= this.outdatedFrom))) {
      this.outdated.push(`${request.method} ${url.pathname}`)
      response = Response.json({ error: "cli_outdated", message: `This machine's mehen ${agent ?? "?"} is older than the vault supports (${this.cliMinimum ?? "?"}).`, next: { command: "mehen update --json", say: "Update mehen on this machine, then run the command again." } }, { status: 426, headers: { "Mehen-Error": "1" } })
    } else response = await this.route(request, url)
    if (this.cliAdvice === null) return response
    const out = new Response(response.body, response)
    out.headers.set("Mehen-Cli", this.cliAdvice)
    return out
  }

  private async route(request: Request, url: URL): Promise<Response> {
    if (request.method === "GET" && url.pathname === "/healthz") return this.healthz()
    const bytes = new Uint8Array(await request.arrayBuffer())
    const seen = await this.authenticate(request, url, bytes)
    if (seen instanceof Response) return seen
    this.seen.push(seen)
    const route = `${request.method} ${url.pathname}`
    const override = this.overrides.get(route)
    if (override) return override(request, seen)
    const body = seen.body ? (JSON.parse(seen.body) as Record<string, unknown>) : {}
    const parts = url.pathname.split("/").slice(2)

    if (route === "POST /v1/enrol") {
      const start = WorkspaceEnrolStartSchema.parse(body)
      const id = this.id("enr")
      const now = Date.now()
      const thumbprint = await jwkThumbprint(start.jwk)
      // A new attempt for the same key supersedes the older pending ones.
      for (const other of this.enrolments.values()) if (other.settled === undefined && (await jwkThumbprint(other.jwk)) === thumbprint) other.settled = "superseded"
      this.enrolments.set(id, { id, jwk: start.jwk, name: start.name, backend: start.backend, polls: 0, workspace: start.workspace, owner: start.owner, expiresAt: now + this.enrolLeaseMs, hardExpiresAt: now + this.enrolHardMs, renewedAt: null, renewals: 0 })
      this.enrolmentsByThumbprint.set(thumbprint, (this.enrolmentsByThumbprint.get(thumbprint) ?? 0) + 1)
      return Response.json({
        enrolment: id,
        code: "ABCD2345",
        url: `${this.linkOrigin ?? this.url}${this.linkSlug === null ? "" : `/w/${this.linkSlug ?? start.workspace}`}/e/ABCD2345`,
        fingerprint: "xxxx",
        expiresAt: new Date(now + this.enrolLeaseMs).toISOString(),
        ...(this.enrolMode === "current" ? { hardExpiresAt: new Date(now + this.enrolHardMs).toISOString() } : {}),
      })
    }
    if (request.method === "POST" && parts[0] === "enrol" && parts[1] && parts[2] === "renew") {
      const enrolment = this.enrolments.get(parts[1]) as Enrolment
      if (this.enrolMode === "pre0008") return this.renew409 ? vaultError("conflict", "Conflict.") : vaultError("not_found", `No route ${route}.`)
      const now = Date.now()
      const status = this.enrolStatus(enrolment, false)
      if ((status as { status: string }).status !== "pending_owner_acceptance" && (status as { status: string }).status !== "pending_admission") {
        return Response.json({ error: "conflict", message: "This enrolment can no longer be renewed.", enrolment: status }, { status: 409, headers: { [ERROR_HEADER]: "1" } })
      }
      if (enrolment.renewedAt !== null && enrolment.renewedAt !== undefined && now - enrolment.renewedAt < this.renewIntervalMs) {
        return Response.json({ error: "conflict", message: "This enrolment was renewed less than a minute ago; keep waiting.", retryAfter: Math.max(1, Math.ceil((enrolment.renewedAt + this.renewIntervalMs - now) / 1000)) }, { status: 409, headers: { [ERROR_HEADER]: "1" } })
      }
      const hard = enrolment.hardExpiresAt ?? now + this.enrolHardMs
      enrolment.expiresAt = Math.min(now + this.enrolLeaseMs, hard)
      enrolment.hardExpiresAt = hard
      enrolment.renewedAt = now
      enrolment.renewals = (enrolment.renewals ?? 0) + 1
      this.renewed.push(enrolment.id)
      return Response.json({ enrolment: enrolment.id, expiresAt: new Date(enrolment.expiresAt).toISOString(), hardExpiresAt: new Date(hard).toISOString() })
    }
    if (request.method === "GET" && parts[0] === "enrol" && parts[1]) {
      const enrolment = this.enrolments.get(parts[1]) as Enrolment
      return Response.json(this.enrolStatus(enrolment, true))
    }
    if (route === "GET /v1/me") {
      const jwk = this.devices.get(seen.claims.dev)?.jwk
      const fingerprint = jwk ? fingerprintOf(await jwkThumbprint(jwk)) : undefined
      const tenant = this.devices.get(seen.claims.dev)?.tenant ?? MOCK_TENANT
      const workspace = tenant === this.workspace.id ? this.workspace : (this.workspaces.get(tenant) ?? { ...this.workspace, id: tenant })
      return Response.json({ tenant, device: seen.claims.dev, name: "test-machine", scope: WORKSPACE_SCOPE, frozen: this.frozen, workspace, owner: this.owner, displayRev: 1, ...(this.meFingerprint && fingerprint ? { fingerprint } : {}) })
    }
    if (route === "GET /v1/items") {
      const tag = url.searchParams.get("tag")
      const kind = url.searchParams.get("kind")
      const provider = url.searchParams.get("provider")
      const items = this.items.filter((i) => (!tag || i.tags.includes(tag)) && (!kind || i.kind === kind) && (!provider || i.provider === provider))
      return Response.json({ items })
    }
    if (request.method === "GET" && parts[0] === "items" && parts[1]) {
      const found = this.items.find((i) => i.slug === parts[1])
      return found ? Response.json(found) : vaultError("not_found", `No item ${parts[1]}.`, { next: { command: "mehen ls", say: "List the items." } })
    }
    if (route === "POST /v1/intakes") {
      const parsed = IntakeCreate.safeParse(body)
      if (!parsed.success) return vaultError("bad_request", "Invalid intake.")
      const intake = this.id("int")
      return Response.json({ intake, url: this.link(seen.claims.ten, `/i/${intake}`), expiresAt: MOCK_EXPIRES_AT })
    }
    if (request.method === "GET" && parts[0] === "intakes" && parts[1]) {
      return Response.json(this.next<IntakeStatus>(`intake:${parts[1]}`, this.withExpiry({ intake: parts[1], status: "open" })))
    }
    if (route === "POST /v1/approvals/bundles") {
      const requests = Array.isArray(body.requests) ? body.requests : []
      const bundle = this.id("bnd")
      const results = requests.map((_, index) => ({ index, outcome: "ask", approval: this.id("apr"), bindingCode: `CODE${index + 1}` }))
      this.bundles.set(bundle, results.map((r) => r.approval))
      return Response.json({ bundle, url: this.link(seen.claims.ten, `/g/${bundle}`), expiresAt: MOCK_EXPIRES_AT, ...(this.bundleCode === undefined ? {} : { code: this.bundleCode }), results })
    }
    if (request.method === "GET" && parts[0] === "approvals" && parts[1] === "bundles" && parts[2]) {
      const approvals = (this.bundles.get(parts[2]) ?? []).map((id) => ({ id, status: "pending" }))
      return Response.json(this.next(`bundle:${parts[2]}`, { bundle: parts[2], approvals }))
    }
    if (request.method === "GET" && parts[0] === "approvals" && parts[1]) {
      return Response.json(this.next<ApprovalStatus>(`approval:${parts[1]}`, this.withExpiry({ approval: parts[1], status: "pending", bindingCode: "K7Q2", summary: "Send an email" })))
    }
    if (route === "GET /v1/pending") {
      if (this.pending === null) return vaultError("not_found", "No route GET /v1/pending.")
      return Response.json({ pending: this.pending, ...(this.notices === undefined ? {} : { notices: this.notices }), ...(this.groups === undefined ? {} : { groups: this.groups }) })
    }
    if (route === "POST /v1/connect") {
      const connect = this.id("con")
      return Response.json({ connect, url: this.link(seen.claims.ten, `/c/${connect}`), expiresAt: MOCK_EXPIRES_AT })
    }
    if (request.method === "GET" && parts[0] === "connect" && parts[1]) {
      return Response.json(this.next<ConnectStatus>(`connect:${parts[1]}`, this.withExpiry({ connect: parts[1], status: "open" })))
    }
    if (request.method === "DELETE" && parts[0] === "runs" && parts[1]) return Response.json({})
    if (route === "POST /v1/relay") {
      const parsed = RelayRequest.safeParse(body)
      if (!parsed.success) return vaultError("bad_request", "Invalid relay request.")
      return this.relay(parsed.data)
    }
    if (route === "POST /v1/devices/self/revoke") {
      const device = this.devices.get(seen.claims.dev)
      if (device) device.revoked = true
      this.revoked.push(seen.claims.dev)
      return Response.json({})
    }
    if (route === "POST /v1/freeze") {
      this.frozen = true
      return Response.json({})
    }
    return vaultError("not_found", `No route ${route}.`)
  }
}

// Answers like an upstream: echoes the request, streamed in two chunks.
function defaultRelay(request: RelayRequestInput): Response {
  const encoder = new TextEncoder()
  const echo = JSON.stringify({ method: request.method, url: request.url, headers: request.headers, body: request.body ?? null })
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(echo.slice(0, 10)))
      controller.enqueue(encoder.encode(echo.slice(10)))
      controller.close()
    },
  })
  return new Response(stream, { status: 200, headers: { [UPSTREAM_HEADER]: "1", [ITEM_HEADER]: `${request.item ?? request.run} (alex@example.com)`, "content-type": "application/json" } })
}
