// A vault as a fetch function. It checks every request the way the real one
// does before any route runs: the Mehen-Proof parses, names this tenant (or
// "enrol"), verifies against the key it was given for that signer (the
// device's, the workload's, or the enrolling key), matches the method, URL
// and body hash, and is never replayed. Then it answers the route's fixture.

import { ERROR_HEADER, type ErrorCode, HTTP_STATUS_FOR_ERROR, ITEM_HEADER, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { type DeviceJwk, PROOF_HEADER, type ProofClaims, bodyHash, importDeviceKey, isDeviceJwk, parseProof, verifyProof } from "@mehen/protocol/proof"

export const ORIGIN = "https://vault.example"
export const TENANT = "tn_acme0000test"
export const DEVICE = "dev_device0001"
export const WORKLOAD = "wl_workload0001"

export type SignedBy = "device" | "workload" | "enrolling"

export type Seen = {
  method: string
  path: string
  search: string
  url: string
  headers: Headers
  claims: ProofClaims
  signedBy: SignedBy
  body: Uint8Array<ArrayBuffer>
  json: unknown
}

export type Handler = (seen: Seen) => Response | Promise<Response>

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } })
}

export function refuse(code: ErrorCode, message: string, extra: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify({ error: code, message, ...extra }), { status: HTTP_STATUS_FOR_ERROR[code], headers: { "content-type": "application/json; charset=utf-8", [ERROR_HEADER]: "1" } })
}

export function upstream(status: number, body: Uint8Array<ArrayBuffer> | string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { ...headers, [UPSTREAM_HEADER]: "1", [ITEM_HEADER]: "openai (alex@example.com)" } })
}

export class FakeVault {
  readonly devices = new Map<string, DeviceJwk>()
  readonly workloads = new Map<string, { device: string; jwk: DeviceJwk }>()
  readonly enrolments = new Map<string, DeviceJwk>()
  readonly seen: Seen[] = []
  private readonly routes = new Map<string, Handler>()
  private readonly nonces = new Set<string>()

  on(route: string, handler: Handler): this {
    this.routes.set(route, handler)
    return this
  }

  get last(): Seen {
    const seen = this.seen.at(-1)
    if (!seen) throw new Error("the fake vault has seen no request")
    return seen
  }

  readonly fetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url)
    if (url.origin !== ORIGIN) throw new TypeError(`the fake vault is ${ORIGIN}, not ${url.origin}`)
    const body = new Uint8Array(await request.arrayBuffer())
    const header = request.headers.get(PROOF_HEADER)
    if (!header) return refuse("unauthenticated", "Missing Mehen-Proof.")
    if (!request.headers.get("user-agent")?.startsWith("mehen-client/")) return refuse("bad_request", "The fake vault expects the client's user agent.")
    let proof: ReturnType<typeof parseProof>
    try {
      proof = parseProof(header)
    } catch {
      return refuse("proof_invalid", "The Mehen-Proof header is malformed.")
    }
    const { claims } = proof
    const signer = this.signerKey(claims, request.method, url.pathname, body)
    if ("refusal" in signer) return signer.refusal
    const checked = await verifyProof(proof, await importDeviceKey(signer.jwk), { method: request.method, url: request.url, bodyHash: await bodyHash(body) })
    if (!checked.ok) return refuse("proof_invalid", `The proof does not verify (${checked.reason}).`)
    const nonce = `${claims.wkl ?? claims.dev}:${claims.jti}`
    if (this.nonces.has(nonce)) return refuse("proof_invalid", "This proof was already used.")
    this.nonces.add(nonce)
    const text = new TextDecoder().decode(body)
    const seen: Seen = { method: request.method, path: url.pathname, search: url.search, url: request.url, headers: request.headers, claims, signedBy: signer.by, body, json: text.length > 0 ? JSON.parse(text) : undefined }
    this.seen.push(seen)
    const handler = this.routes.get(`${request.method} ${url.pathname}`)
    return handler ? handler(seen) : refuse("not_found", "No such route.")
  }

  private signerKey(claims: ProofClaims, method: string, path: string, body: Uint8Array<ArrayBuffer>): { jwk: DeviceJwk; by: SignedBy } | { refusal: Response } {
    if (claims.ten === "enrol") {
      if (claims.dev === "new") {
        if (method !== "POST" || path !== "/v1/enrol") return { refusal: refuse("proof_invalid", "Only the start is signed as dev new.") }
        const jwk: unknown = (JSON.parse(new TextDecoder().decode(body)) as { jwk?: unknown }).jwk
        return isDeviceJwk(jwk) ? { jwk, by: "enrolling" } : { refusal: refuse("bad_request", "The key must be a P-256 public JWK.") }
      }
      const jwk = this.enrolments.get(claims.dev)
      return jwk ? { jwk, by: "enrolling" } : { refusal: refuse("not_found", "No such enrolment.") }
    }
    if (claims.ten !== TENANT) return { refusal: refuse("proof_invalid", "This proof names another tenant.") }
    if (claims.wkl !== undefined) {
      const workload = this.workloads.get(claims.wkl)
      if (!workload || workload.device !== claims.dev) return { refusal: refuse("proof_invalid", "No such workload for this device.") }
      return { jwk: workload.jwk, by: "workload" }
    }
    const jwk = this.devices.get(claims.dev)
    return jwk ? { jwk, by: "device" } : { refusal: refuse("unauthenticated", "Unknown device.") }
  }
}
