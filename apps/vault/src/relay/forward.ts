// The Worker half of the relay: the DO has authorised the request and
// handed back the final URL, headers (credentials injected) and the values
// to scrub. This sends it upstream without following redirects, strips
// headers that could carry state across origins, caps the response, and
// streams the body through the redactor so an echoed secret never reaches
// the agent. The redactor can only read what the Worker decodes, so the
// request asks for gzip or br only (the runtime decodes both) and any other
// content coding in the response is refused. The upstream's reason phrase
// is dropped: it is free text the redactor never sees as a header.

import { ITEM_HEADER, MANDATE_HEADER, POSTURE_HEADER, RULE_HEADER, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { type RedactionSecret, StreamRedactor, buildNeedles, isReadMethod, redactText } from "@mehen/protocol"
import { VaultError } from "../http.ts"
import { upstreamFetch } from "./upstream.ts"

// What relay.authorise returns. Holds plaintext credentials: it lives only
// for this request and is never logged.
export type RelayMaterial = {
  method: string
  url: string
  headers: [string, string][]
  scrub: RedactionSecret[]
  // "gmail-alex (alex@example.com)", one per credential used.
  label: string
  items: string[]
  // The rul_ ids that allowed this request without asking (RULE_HEADER).
  rules?: string[]
  // The posture levels that allowed it without asking (POSTURE_HEADER).
  postures?: ("routine" | "trust")[]
  // The mdt_ id of the mandate that let it through without asking (MANDATE_HEADER).
  mandate?: string
  workspaceAudit?: {item:{id:string;slug:string;home:import("@mehen/protocol").CredentialHome};device:string;owner:import("@mehen/protocol").ShareSubject;session:string|null;run:string|null;workload?:{id:string;label:string}}[]
}

export const MAX_RELAY_RESPONSE_BYTES = 32 * 1024 * 1024

// RFC 9110 hop-by-hop headers, plus those that would let an upstream set
// or read state through the vault's origin.
const HOP_BY_HOP = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]
const RESPONSE_DROP = [...HOP_BY_HOP, "set-cookie", "set-cookie2", "content-length", "content-encoding"]

export const RELAY_ACCEPT_ENCODING = "gzip, br"
// Sent only when the agent sent no User-Agent, since some upstreams (GitHub)
// refuse a request without one. It is added here, after authorisation, so
// it is no part of the approved headers, the approval page or the audit.
const RELAY_USER_AGENT = "mehen-relay"
const DECODED_CODINGS = ["identity", "gzip", "br"]

export function connectionTokens(value: string | null): string[] {
  return (value ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t !== "")
}

// Bytes to a string of one char per byte and back, so redaction works on
// any body (text or binary) without changing a single byte it does not
// replace. Secrets are ASCII in practice; non-ASCII ones are also matched
// as their UTF-8 bytes (see scrubSecrets).
export function bytesToBinary(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return out
}

export function binaryToBytes(text: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

function scrubSecrets(secrets: RedactionSecret[]): RedactionSecret[] {
  const out: RedactionSecret[] = []
  for (const s of secrets) {
    out.push(s)
    if (/[\u0080-\uffff]/.test(s.value)) out.push({ label: s.label, value: bytesToBinary(new TextEncoder().encode(s.value)) })
  }
  return out
}

function headerSafe(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, (c) => encodeURIComponent(c))
}

export type ForwardOptions = {
  // Called once, after the body has been streamed, with the items whose
  // value was found and scrubbed in the response.
  onEcho?: (items: string[]) => void
}

export async function forwardRelay(material: RelayMaterial, body: Uint8Array<ArrayBuffer> | null, options: ForwardOptions = {}): Promise<Response> {
  const host = new URL(material.url).host
  const requestHeaders = new Headers(material.headers)
  requestHeaders.set("accept-encoding", RELAY_ACCEPT_ENCODING)
  if (!requestHeaders.has("user-agent")) requestHeaders.set("user-agent", RELAY_USER_AGENT)
  let response: Response
  try {
    response = await upstreamFetch(new Request(material.url, { method: material.method, headers: requestHeaders, body, redirect: "manual" }))
  } catch {
    if (isReadMethod(material.method)) throw new VaultError("upstream_failed", `Could not reach ${host}. Nothing was changed by the vault; retry later.`, { retryAfter: 5 })
    // A write may have been sent before the connection failed.
    throw new VaultError("upstream_failed", `Could not get an answer from ${host}. The request may have reached it: check whether it took effect before sending it again.`)
  }
  const coding = response.headers.get("content-encoding")?.trim().toLowerCase() ?? ""
  if (coding !== "" && !DECODED_CODINGS.includes(coding)) {
    await response.body?.cancel()
    throw new VaultError("upstream_failed", `${host} answered with a body in a compression the vault cannot check for leaked credentials, so it was not passed on. The request itself was sent; check its effect before retrying.`)
  }
  const declared = Number(response.headers.get("content-length") ?? "0")
  if (declared > MAX_RELAY_RESPONSE_BYTES) {
    await response.body?.cancel()
    if (isReadMethod(material.method)) throw new VaultError("too_large", `The response from ${host} is larger than the relay allows (${MAX_RELAY_RESPONSE_BYTES} bytes). Ask for less, for example with a range or a page size.`)
    // The write was sent and answered: only its answer is withheld.
    throw new VaultError("too_large", `The response from ${host} is larger than the relay allows (${MAX_RELAY_RESPONSE_BYTES} bytes), so it was not passed on. The request was sent and may have taken effect: check whether it did before sending it again.`)
  }

  const needles = buildNeedles(scrubSecrets(material.scrub))
  const markers = material.items.map((slug) => ({ slug, marker: `[redacted:${slug}]` }))
  const echoed = new Set<string>()
  const noteEchoes = (text: string) => {
    for (const m of markers) if (text.includes(m.marker)) echoed.add(m.slug)
  }

  const headers = new Headers()
  const dropped = new Set([...RESPONSE_DROP, ...connectionTokens(response.headers.get("connection"))])
  for (const [name, value] of response.headers) {
    const lower = name.toLowerCase()
    if (dropped.has(lower) || lower.startsWith("mehen-")) continue
    const clean = redactText(value, needles)
    noteEchoes(clean)
    headers.append(name, clean)
  }
  headers.set(ITEM_HEADER, headerSafe(material.label))
  if (material.rules?.length) headers.set(RULE_HEADER, material.rules.join(", "))
  if (material.postures?.length) headers.set(POSTURE_HEADER, material.postures.join(", "))
  if (material.mandate !== undefined) headers.set(MANDATE_HEADER, material.mandate)
  headers.set(UPSTREAM_HEADER, "1")

  const upstreamBody = response.body
  if (material.method === "HEAD" || response.status === 204 || response.status === 304 || upstreamBody === null) {
    await response.body?.cancel()
    if (echoed.size > 0) options.onEcho?.([...echoed])
    return new Response(null, { status: response.status, headers })
  }

  const redactor = new StreamRedactor(needles)
  let seen = 0
  const scrubbed = upstreamBody.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.length
        if (seen > MAX_RELAY_RESPONSE_BYTES) {
          controller.error(new Error("relay response too large"))
          return
        }
        const out = redactor.push(bytesToBinary(chunk))
        noteEchoes(out)
        if (out.length > 0) controller.enqueue(binaryToBytes(out))
      },
      flush(controller) {
        const rest = redactor.end()
        noteEchoes(rest)
        if (rest.length > 0) controller.enqueue(binaryToBytes(rest))
        if (echoed.size > 0) options.onEcho?.([...echoed])
      },
    }),
  )
  return new Response(scrubbed, { status: response.status, headers })
}
