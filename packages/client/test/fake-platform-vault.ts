// The vault's platform side as a fetch function. Before any route runs it
// checks a request the way D0 1.3 says the vault does: no Mehen-Proof beside
// the platform proof, the proof parses with parsePlatformProof, its key is
// known and belongs to the platform it names, verifyPlatformProof accepts
// it (signature, method, URL, body hash, skew and `sub` against the path),
// and its nonce is unspent. Then it finds the PLATFORM_ROUTES row, checks the
// path's parameters, the query and the body with the row's own schemas, and
// answers the row's fixture, or a handler's answer.

import { ERROR_HEADER, type ErrorCode, HTTP_STATUS_FOR_ERROR } from "@mehen/protocol/api"
import {
  DEFAULT_PLATFORM_LIMITS,
  INITIAL_PLATFORM_DEFAULTS,
  PLATFORM_PROOF_HEADER,
  PLATFORM_ROUTES,
  type PlatformProofClaims,
  type PlatformRoute,
  type PlatformRouteName,
  parsePlatformProof,
  platformDeviceScope,
  verifyPlatformProof,
} from "@mehen/protocol/platform"
import { type DeviceJwk, PROOF_HEADER, bodyHash, importDeviceKey } from "@mehen/protocol/proof"

export const ORIGIN = "https://vault.example"
export const PLATFORM = "plt_globex0001"
export const PLATFORM_KEY = "pky_globex0001"
export const SUBJECT = "globex_subject0001"
export const MANAGED_TENANT = "tn_managed0001"
export const AGENT_DEVICE = "dev_agent0001"
export const INTAKE = "int_intake0001"
export const CONNECT = "con_connect0001"
export const APPROVAL = "apr_approval0001"
export const PROJECT = "prj_project0001"
export const DIGEST = "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c"

const AT = "2026-10-29T10:00:00.000Z"
const LATER = "2026-10-29T10:15:00.000Z"

export type PlatformSeen = {
  route: PlatformRoute
  method: string
  path: string
  search: string
  url: string
  headers: Headers
  claims: PlatformProofClaims
  params: Record<string, string>
  body: string
  json: unknown
}

export type PlatformHandler = (seen: PlatformSeen) => Response | Promise<Response>

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } })
}

export function refuse(code: ErrorCode, message: string, extra: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify({ error: code, message, ...extra }), { status: HTTP_STATUS_FOR_ERROR[code], headers: { "content-type": "application/json; charset=utf-8", [ERROR_HEADER]: "1" } })
}

export const ITEM = { slug: "openai", kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: ["globex"], ceiling: "relay", hosts: ["api.openai.com"], status: "active", updatedAt: AT }
export const GMAIL_ITEM = { ...ITEM, slug: "gmail", kind: "oauth-connection", provider: "google-gmail", account: "jim@example.com", accountVerified: true, hosts: ["gmail.googleapis.com"] }
const SUBJECT_VIEW = { subject: SUBJECT, status: "active", createdAt: AT, counts: { devices: 1, items: 1, projects: 0 } }
const DEVICE_VIEW = { device: AGENT_DEVICE, tenant: MANAGED_TENANT, name: "agent-1", label: "agent:1", scope: platformDeviceScope(["relay", "placeholder"]), createdAt: AT, revoked: false }
const APPROVAL_VIEW = {
  approval: APPROVAL,
  status: "pending",
  digest: DIGEST,
  device: AGENT_DEVICE,
  workload: { id: "wl_workload0001", label: "grant:g1" },
  item: "gmail",
  request: { method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", contentType: "application/json", contentEncoding: null, headersSha256: "h", bodySha256: "b" },
  title: "Send an email",
  warnings: [],
  constraints: { uses: 1, ttlSeconds: 900 },
  expiresAt: LATER,
  decidedBy: null,
}
const PROJECT_VIEW = { id: PROJECT, slug: "agent-one", defaultEnv: "computers", environments: [{ name: "computers" }], vars: [{ name: "REGION", env: "computers", source: "plain", value: "eu" }] }
export const SEAL_KEY_ID = "seal-2026"

// A valid answer for every route, with the row's first success status.
export function fixtureAnswers(sealJwk: DeviceJwk): Record<PlatformRouteName, unknown> {
  return {
    "platform.view": { platform: { id: PLATFORM, slug: "globex", name: "Globex", status: "active" }, limits: DEFAULT_PLATFORM_LIMITS, defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 3, usage: { subjects: 1 }, keys: [{ id: PLATFORM_KEY, createdAt: AT, expiresAt: null, revoked: false }] },
    "subjects.list": { subjects: [{ subject: SUBJECT, status: "active", createdAt: AT }], next: null },
    "subjects.ensure": SUBJECT_VIEW,
    "subjects.get": SUBJECT_VIEW,
    "subjects.remove": { subject: SUBJECT, status: "deleted", purgeAfter: "2026-11-28T10:00:00.000Z" },
    "devices.create": DEVICE_VIEW,
    "devices.list": { devices: [{ ...DEVICE_VIEW, lastSeenAt: null, liveWorkloads: 0 }] },
    "devices.revoke": { ...DEVICE_VIEW, revoked: true },
    "items.list": { items: [ITEM] },
    "items.remove": { slug: "openai", deleted: true, providerRevoked: false },
    "intakes.create": {
      intake: INTAKE,
      sealKey: { jwk: sealJwk, kid: SEAL_KEY_ID },
      fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }],
      binding: { hosts: ["api.openai.com"], known: true },
      rotates: false,
      setup: null,
      expiresAt: LATER,
    },
    "intakes.submit": { item: ITEM },
    "intakes.cancel": {},
    "connects.start": { connect: CONNECT, authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth?client_id=jims-client&state=s", expiresAt: LATER },
    "connects.finish": { connect: CONNECT, status: "completed", item: GMAIL_ITEM },
    "connects.get": { connect: CONNECT, status: "open", expiresAt: LATER },
    "connects.cancel": {},
    "approvals.list": { approvals: [APPROVAL_VIEW] },
    "approvals.get": APPROVAL_VIEW,
    "approvals.decide": { ...APPROVAL_VIEW, status: "approved", decidedBy: { platform: PLATFORM, key: PLATFORM_KEY, ref: "card:42" } },
    "projects.create": PROJECT_VIEW,
    "projects.get": PROJECT_VIEW,
    "projects.setVar": PROJECT_VIEW,
    "projects.remove": { deleted: true },
    "audit.read": { events: [], verified: true, next: null, filtered: false, head: null },
    "workspace.freeze": { frozen: true },
    "workspace.unfreeze": { frozen: false },
    "defaults.put": { defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 4 },
    "subjects.removeAll": { deleting: 1 },
  }
}

// The row whose method and path match, with the path's parameters, or null.
function matchRoute(method: string, pathname: string): { route: PlatformRoute; params: Record<string, string> } | null {
  const segments = pathname.split("/")
  for (const route of PLATFORM_ROUTES as readonly PlatformRoute[]) {
    if (route.method !== method) continue
    const pattern = route.path.split("/")
    if (pattern.length !== segments.length) continue
    const params: Record<string, string> = {}
    const matched = pattern.every((part, i) => {
      const segment = segments[i] ?? ""
      if (!part.startsWith(":")) return part === segment
      params[part.slice(1)] = decodeURIComponent(segment)
      return segment !== ""
    })
    if (matched) return { route, params }
  }
  return null
}

export class FakePlatformVault {
  readonly keys = new Map<string, { platform: string; jwk: DeviceJwk }>()
  readonly seen: PlatformSeen[] = []
  private readonly handlers = new Map<string, PlatformHandler>()
  private readonly nonces = new Set<string>()
  private readonly answers: Record<PlatformRouteName, unknown>

  constructor(sealJwk: DeviceJwk) {
    this.answers = fixtureAnswers(sealJwk)
  }

  on(name: PlatformRouteName, handler: PlatformHandler): this {
    this.handlers.set(name, handler)
    return this
  }

  get last(): PlatformSeen {
    const seen = this.seen.at(-1)
    if (!seen) throw new Error("the fake platform vault has seen no request")
    return seen
  }

  readonly fetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url)
    if (url.origin !== ORIGIN) throw new TypeError(`the fake vault is ${ORIGIN}, not ${url.origin}`)
    const bytes = new Uint8Array(await request.arrayBuffer())
    if (request.headers.has(PROOF_HEADER)) return refuse("bad_request", "Send one proof, not both.")
    const header = request.headers.get(PLATFORM_PROOF_HEADER)
    if (!header) return refuse("unauthenticated", "Missing Mehen-Platform-Proof.")
    if (!request.headers.get("user-agent")?.startsWith("mehen-client/")) return refuse("bad_request", "The fake vault expects the client's user agent.")
    let proof: ReturnType<typeof parsePlatformProof>
    try {
      proof = parsePlatformProof(header)
    } catch {
      return refuse("proof_invalid", "The Mehen-Platform-Proof header is malformed.")
    }
    const key = this.keys.get(proof.kid)
    if (!key || key.platform !== proof.claims.plt) return refuse("unauthenticated", "Unknown platform key.")
    const checked = await verifyPlatformProof(proof, await importDeviceKey(key.jwk), { method: request.method, url: request.url, bodyHash: await bodyHash(bytes) })
    if (!checked.ok) return refuse("proof_invalid", `The proof does not verify (${checked.reason}).`)
    const nonce = `${proof.kid}:${proof.claims.jti}`
    if (this.nonces.has(nonce)) return refuse("proof_invalid", "This Mehen-Proof has already been used.")
    this.nonces.add(nonce)

    const found = matchRoute(request.method, url.pathname)
    if (found === null) return refuse("not_found", "No such route.")
    const { route, params } = found
    for (const [name, schema] of Object.entries(route.params)) {
      if (!schema.safeParse(params[name]).success) return refuse("bad_request", `The ${name} is not valid.`)
    }
    const query = Object.fromEntries(url.searchParams)
    if (route.query === null ? url.search !== "" : !route.query.safeParse(query).success) return refuse("bad_request", "The query is not valid.")
    const body = new TextDecoder().decode(bytes)
    let parsed: unknown
    if (route.body === null) {
      if (body !== "") return refuse("bad_request", "This route takes no body.")
    } else {
      try {
        parsed = JSON.parse(body)
      } catch {
        return refuse("bad_request", "The body is not JSON.")
      }
      if (request.headers.get("content-type") !== "application/json" || !route.body.safeParse(parsed).success) return refuse("bad_request", "The body is not valid.")
    }
    const seen: PlatformSeen = { route, method: request.method, path: url.pathname, search: url.search, url: request.url, headers: request.headers, claims: checked.claims, params, body, json: parsed }
    this.seen.push(seen)
    const handler = this.handlers.get(route.name)
    return handler ? handler(seen) : json(this.answers[route.name as PlatformRouteName], route.status[0])
  }
}
