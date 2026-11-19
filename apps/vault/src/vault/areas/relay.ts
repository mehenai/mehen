// The relay's decision, inside the DO (R2, R7, R9, R10). Every
// check runs before anything is decrypted: the item and its status, the
// device scope, host fences (in both modes), the canonical destination
// against the binding, method override, hosts that need an exact binding,
// placeholder surfaces in run mode, protected items (R4), then the policy
// (deny, approve, allow). Only then are the secrets opened and injected, on
// the item's own surface and nowhere else. The Worker does the upstream
// fetch with what this returns.

import { gunzipSync, inflateSync } from "node:zlib"
import { type ApprovalSubject, MAX_RELAY_BODY_CHARS, RelayRequest, type RelayRequestInput } from "@mehen/protocol/api"
import {
  type Destination,
  PLACEHOLDER_CORE,
  type RedactionSecret,
  base64UrlDecode,
  bindingCutWords,
  bodyHash,
  checkBinding,
  evaluatePolicy,
  hostMatches,
  isLeaseOnly,
  leaseOnlyDelivery,
  leaseOnlyWords,
  isReservedHeader,
  parseDestination,
  placeholderCore,
} from "@mehen/protocol"
import { policyBodyDeclaresUnreadCharset, policyMethodOverrideBodyField, policyMethodOverrideParameter } from "@mehen/protocol/policy-safety"
import { exactApprovalNext, policy, preparePolicy } from "./policy.ts"
import { type Mode, deviceModeAllowed } from "@mehen/protocol/kinds"
import { VaultError } from "../../http.ts"
import { RELAY_ACCEPT_ENCODING, connectionTokens, type RelayMaterial } from "../../relay/forward.ts"
import { MAX_APPROVAL_BODY_BYTES, MAX_APPROVAL_HEADER_BYTES, presentRequest } from "../../relay/presentation.ts"
import { relayServices } from "../../relay/services.ts"
import { type Area, type DevicePrincipal, type VaultContext, actorOf } from "../core.ts"
import type { ItemRecord, RunPlaceholder,  } from "../services.ts"
import { digestOf } from "./approvals.ts"
import { deviceCovers, devicePolicyState } from "./devices.ts"
import { items } from "./items.ts"
import { oauth } from "./oauth.ts"
import { workspaceRelayOps } from "./relay-workspace.ts"
import { projects } from "./projects.ts"
import { runs } from "./runs.ts"

const RELAY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
const METHOD_OVERRIDE_HEADERS = ["x-http-method-override", "x-http-method", "x-method-override"]
// Headers some upstreams route on in place of the request's own path.
const URL_REWRITE_HEADERS = ["x-original-url", "x-rewrite-url"]
// Headers proxies set and frameworks trust to rebuild the path (Spring,
// ASP.NET and Werkzeug read a prefix; Traefik, nginx and Kong a path or URI)
// or the host (every framework that trusts proxies; Forwarded's host=; IIS,
// ARR and Azure Application Gateway's X-Original-Host, which ASP.NET Core
// can be told to read).
// The client address and scheme ones (x-forwarded-for, -proto, -port) move
// neither, so they are forwarded as sent.
const PATH_ROUTING_HEADERS = ["x-forwarded-prefix", "x-forwarded-path", "x-forwarded-uri", "x-forwarded-url", "x-original-uri"]
const HOST_ROUTING_HEADERS = ["x-forwarded-host", "x-forwarded-server", "x-original-host", "forwarded"]
const STRIPPED_REQUEST_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "cookie",
]
// Request content codings the vault undoes to read a body for a
// method-override field: gzip, and deflate as HTTP means it (zlib-wrapped).
const READ_REQUEST_CODINGS: Record<string, typeof gunzipSync> = { gzip: gunzipSync, "x-gzip": gunzipSync, deflate: inflateSync }
// A decoded body may be as large as the largest body as sent and no larger,
// every coding's output counted, so a small compressed body cannot make the
// vault hold, inflate or parse more than an uncompressed one.
const MAX_DECODED_BODY_BYTES = (MAX_RELAY_BODY_CHARS / 4) * 3
// No client stacks more codings than this on a request body.
const MAX_REQUEST_CODINGS = 3
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

// What an approval asks for when the request asks for nothing else, so the
// digest is the same on every retry and the grant lookup matches.
export const DEFAULT_APPROVAL_CONSTRAINTS = { uses: 1, ttlSeconds: 600 } as const

// A header's value as the upstream receives it: every copy, in order, joined
// the way Headers joins them; null when the request does not carry it.
function requestHeader(headers: [string, string][], name: string): string | null {
  const values = headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v.trim())
  return values.length === 0 ? null : values.join(", ")
}

type DecodedBody = { forms: Uint8Array[] } | { unread: string } | { stacked: number } | { tooLarge: true }

// One coding undone, or null when data follows the end of the stream, which
// node:zlib otherwise drops without a word. With info set it also returns
// its engine, whose bytesWritten is the input it consumed.
function decodedWhole(decode: typeof gunzipSync, input: Uint8Array, maxOutputLength: number): Uint8Array | null {
  // workerd stops at the cap: with info set it inflates 16 KiB at a time and throws once past maxOutputLength (https://github.com/cloudflare/workerd/blob/v1.20261023.1/src/node/internal/internal_zlib_base.ts#L294-L304).
  const { buffer, engine } = decode(input, { info: true, maxOutputLength }) as unknown as { buffer: Uint8Array; engine: { bytesWritten: number } }
  return engine.bytesWritten === input.length ? buffer : null
}

// Whether a gzip step's output is all its last member's: the input's last 4
// bytes are that member's ISIZE, its length mod 2^32 (RFC 1952). node:zlib
// joins concatenated members into one output, but an upstream that stops
// after the first member reads another body.
function gzipOutputIsLastMember(input: Uint8Array, output: Uint8Array): boolean {
  return new DataView(input.buffer, input.byteOffset + input.length - 4, 4).getUint32(0, true) === output.length >>> 0
}

// Every form of the body an upstream may read: as sent, and after each step
// of undoing the request's Content-Encoding, the last coding first, since an
// upstream may undo none, some or all of them (and a gzip header's name and
// comment survive only in the forms before that step). unread names a
// coding the vault cannot undo, whose data is not valid in it, or whose gzip
// output is not all its last member's. node:zlib's maxOutputLength stops
// inflating at the cap; workerd's DecompressionStream inflates each write
// whole into its own buffer before anything is read, so it cannot.
export function decodedRequestBody(body: Uint8Array, contentEncoding: string | null, maxDecodedBytes = MAX_DECODED_BODY_BYTES): DecodedBody {
  const codings = (contentEncoding ?? "").split(",").map((c) => c.trim().toLowerCase()).filter((c) => c !== "" && c !== "identity")
  if (codings.length > MAX_REQUEST_CODINGS) return { stacked: codings.length }
  const forms: Uint8Array[] = [body]
  let decoded: Uint8Array = body
  let budget = maxDecodedBytes
  for (const coding of codings.reverse()) {
    const decode = READ_REQUEST_CODINGS[coding]
    if (decode === undefined) return { unread: coding }
    let whole: Uint8Array | null
    try {
      whole = decodedWhole(decode, decoded, Math.max(1, budget))
    } catch (error) {
      return error instanceof RangeError ? { tooLarge: true } : { unread: coding }
    }
    if (whole === null || (decode === gunzipSync && !gzipOutputIsLastMember(decoded, whole))) return { unread: coding }
    decoded = whole
    if (decoded.length > budget) return { tooLarge: true }
    budget -= decoded.length
    forms.push(decoded)
  }
  return { forms }
}

// The forwarded headers as one block on the wire, "name: value\r\n" each.
function headerBlockBytes(headers: [string, string][]): number {
  const encoder = new TextEncoder()
  return headers.reduce((total, [name, value]) => total + encoder.encode(`${name}: ${value}\r\n`).length, 0)
}

// A request that needs a human must be one a human can read on the card:
// uncompressed, and short enough to check, headers and body.
function assertApprovable(slug: string, contentEncoding: string | null, body: Uint8Array | null, headers: [string, string][]): void {
  if (contentEncoding !== null && contentEncoding.toLowerCase() !== "identity") {
    throw new VaultError("mode_refused", `This request to "${slug}" needs a human's approval, and its body is compressed (content-encoding: ${contentEncoding}), so the approval card could not show it. Send it uncompressed, without a content-encoding header.`, {
      next: { say: "The vault refused a compressed request that needs approval; send it again uncompressed." },
    })
  }
  if (body !== null && body.length > MAX_APPROVAL_BODY_BYTES) {
    throw new VaultError(
      "mode_refused",
      `This request to "${slug}" needs a human's approval, and its body is ${body.length} bytes, more than the ${MAX_APPROVAL_BODY_BYTES} bytes an approval card can show in full. Send a smaller request, for example the content in parts, or without large attachments.`,
      { next: { say: `The vault refused to ask for approval of a body over ${MAX_APPROVAL_BODY_BYTES / 1024} KiB, because a human could not check all of it.` } },
    )
  }
  const headerBytes = headerBlockBytes(headers)
  if (headerBytes > MAX_APPROVAL_HEADER_BYTES) {
    throw new VaultError(
      "mode_refused",
      `This request to "${slug}" needs a human's approval, and its headers come to ${headerBytes} bytes, more than the ${MAX_APPROVAL_HEADER_BYTES} bytes an approval card shows in full. Send it with fewer or shorter headers.`,
      { next: { say: `The vault refused to ask for approval of headers over ${MAX_APPROVAL_HEADER_BYTES / 1024} KiB, because a human could not check all of them.` } },
    )
  }
}

function refuse(code: "binding_refused" | "surface_refused" | "policy_denied" | "mode_refused" | "forbidden", message: string, say: string): never {
  throw new VaultError(code, message, { next: { say } })
}

// Hosts that are only reachable when a human bound them exactly: IP
// literals, loopback names, our own origin and *.workers.dev. A wildcard
// binding never opens them.
export function needsExactBinding(host: string, vaultOrigin: string): boolean {
  if (host.startsWith("[") || IPV4.test(host)) return true
  if (host === "localhost" || host.endsWith(".localhost")) return true
  if (host === "workers.dev" || host.endsWith(".workers.dev")) return true
  const own = new URL(vaultOrigin).hostname.toLowerCase()
  return host === own || host.endsWith(`.${own}`)
}

export type Checked = { item: ItemRecord; mode: Mode }
export type RelayAuthorisationHooks = {
  visible(slug: string, mode: Mode): ItemRecord
  reauth(item:ItemRecord): never
  prepare(checked: Checked[], request: RelayRequestInput): void
  // held: the request as it will be forwarded, and why it is held: the
  // item's policy said approve, or the item is protected.
  approve(item: ItemRecord, subject: ApprovalSubject, presentation: import("../services.ts").ApprovalPresentation, held: import("./policy-rules-workspace.ts").HeldRequest & { policyApprove: boolean; protectedUse: boolean }): boolean
  secrets?(item: ItemRecord): Promise<{secrets:Record<string,string>;item:ItemRecord}>
  assertCurrent(): void
  consume(): void
  // Plan mode (a bundle): stop after the approval loop, before any secret is
  // opened, so nothing is sent, consumed or recorded as a use.
  plan?: boolean
}

async function loadUsableItem(ctx: VaultContext, principal: DevicePrincipal, slug: string, mode: Mode, hooks?: RelayAuthorisationHooks): Promise<ItemRecord> {
  const item = hooks ? hooks.visible(slug, mode) : items.getItem(ctx, slug)
  if (!item) {
    throw new VaultError("not_found", `No credential called "${slug}".`, {
      next: { command: "mehen ls", say: `There is no credential called "${slug}"; list what exists with \`mehen ls\`, or ask for it with \`mehen request\`.` },
    })
  }
  if (item.status === "needs_reauth") {
    if(hooks)hooks.reauth(item)
    // The OAuth service throws needs_reauth with a fresh reconnect link
    // without decrypting anything.
    if (item.kind === "oauth-connection") await oauth.accessToken(ctx, item)
    throw new VaultError("needs_reauth", `"${slug}" needs to be set up again by a human.`, {
      next: { url: `${ctx.env.VAULT_ORIGIN}/items/${slug}`, say: `The credential "${slug}" is no longer valid; a human must replace it in the vault.` },
    })
  }
  if (item.status === "disabled") {
    refuse("forbidden", `"${slug}" is disabled.`, `The credential "${slug}" is disabled in the vault; a human must enable it.`)
  }
  if (!deviceModeAllowed(item.ceiling, mode)) {
    refuse("mode_refused", `"${slug}" may not be used in ${mode} mode: its exposure ceiling is ${item.ceiling}.`, `The vault does not allow "${slug}" in ${mode} mode; only a human can change its ceiling.`)
  }
  if (!deviceCovers(principal, item, mode)) {
    refuse("forbidden", `This machine's scope does not cover "${slug}" in ${mode} mode.`, `This machine is not allowed to use "${slug}"; a human can widen its scope in the vault.`)
  }
  if (item.injection === null) {
    refuse("forbidden", `"${slug}" (${item.kind}) is never sent by the relay.`, `"${slug}" cannot be used through the relay.`)
  }
  return item
}

function checkDestination(ctx: VaultContext, principal: DevicePrincipal, item: ItemRecord, dest: Destination): void {
  const hosts = item.binding.hosts.map((h) => h.toLowerCase())
  const audit = (reason: string) =>
    ctx.audit({ actor: actorOf(principal), action: "relay.refuse", target: item.slug, detail: { host: dest.host, method: dest.method, reason } })
  if (needsExactBinding(dest.host, ctx.env.VAULT_ORIGIN) && !hosts.includes(dest.host)) {
    audit("host-needs-exact-binding")
    refuse("binding_refused", `${dest.host} is never reachable through the relay unless "${item.slug}" is bound to exactly that host.`, `The vault refused to send "${item.slug}" to ${dest.host}.`)
  }
  const check = checkBinding(item.binding, dest)
  if (!check.ok) {
    audit(`binding-${check.reason}`)
    refuse(
      "binding_refused",
      isLeaseOnly(item.binding)
        ? `"${item.slug}" may not go to ${dest.method} ${dest.scheme}://${dest.host}:${dest.port}${dest.path}. ${leaseOnlyWords(leaseOnlyDelivery(item.kind, item.ceiling))}`
        : `"${item.slug}" may not go to ${dest.method} ${dest.scheme}://${dest.host}:${dest.port}${dest.path} (the ${check.reason}${check.cutAt ? `, ${bindingCutWords(check.cutAt)},` : ""} is outside its binding: ${item.binding.hosts.join(", ")}).`,
      `The vault refused to send "${item.slug}" there. Its destinations are set by a human in the vault, never by a request.`,
    )
  }
}

// ---------------------------------------------------------------- run mode: where placeholders were seen

type Sighting = { core: string; where: string }

function sightingsIn(text: string, where: string, out: Sighting[]): void {
  for (const match of text.matchAll(PLACEHOLDER_CORE)) out.push({ core: match[0], where })
}

function basicCredentials(value: string): string | null {
  const match = /^\s*basic\s+([A-Za-z0-9+/=_-]+)\s*$/i.exec(value)
  if (!match) return null
  try {
    return atob((match[1] as string).replaceAll("-", "+").replaceAll("_", "/"))
  } catch {
    return null
  }
}

function findSightings(url: URL, headers: [string, string][], body: Uint8Array | null): Sighting[] {
  const out: Sighting[] = []
  sightingsIn(`${url.protocol}//${url.host}${url.pathname}${url.hash}`, "url", out)
  for (const [key, value] of url.searchParams) {
    sightingsIn(key, "query-name", out)
    sightingsIn(value, `query:${key}`, out)
  }
  for (const [name, value] of headers) {
    const lower = name.toLowerCase()
    sightingsIn(name, "header-name", out)
    sightingsIn(value, `header:${lower}`, out)
    if (lower === "authorization") {
      const decoded = basicCredentials(value)
      if (decoded !== null) sightingsIn(decoded, "basic", out)
    }
  }
  if (body !== null && body.length > 0) {
    let text = ""
    for (let i = 0; i < body.length; i += 0x8000) text += String.fromCharCode(...body.subarray(i, i + 0x8000))
    sightingsIn(text, "body", out)
  }
  return out
}

function declaredSurface(item: ItemRecord): string | null {
  const injection = item.injection
  if (injection === null) return null
  switch (injection.in) {
    case "header":
      return `header:${injection.name.toLowerCase()}`
    case "query":
      return `query:${injection.name}`
    case "basic":
      return "basic"
    case "headers":
      return null
  }
}

// Host fences are enforced here, whatever sent the
// request: the local relay's check is only an early refusal, and mehen fetch
// --run or vault_fetch with a run never pass through it.
function assertNotFenced(ctx: VaultContext, principal: DevicePrincipal, run: string, dest: Destination, slugs: string[]): void {
  const fences = runs.fencesFor(ctx, principal, run)
  const matched = fences?.fencedHosts.filter((pattern) => hostMatches(pattern, dest.host)) ?? []
  if (fences === null || matched.length === 0) return
  ctx.audit({
    actor: actorOf(principal),
    action: "relay.tripwire",
    target: slugs[0] ?? null,
    detail: { run, host: dest.host, method: dest.method, items: slugs, fences: matched, reason: "fenced-host" },
  })
  throw new VaultError("environment_refused", `${dest.host} is fenced to another environment of this project, and this run is env=${fences.env}. Nothing was sent, and this was recorded.`, {
    next: { say: `The vault refused to reach ${dest.host} from a ${fences.env} run. Run with the environment that host belongs to (mehen run --env <env>), or ask a human to change the fence in the vault.` },
  })
}

// Item mode has no run, so no environment of its own: the item may not
// reach a host fenced to any environment it backs no variable in. A dev
// item named directly is held off prod's hosts as a dev run's placeholder is.
function assertItemNotFenced(ctx: VaultContext, principal: DevicePrincipal, slug: string, dest: Destination): void {
  const matched = projects.fencesAgainstItem(ctx, slug).filter((pattern) => hostMatches(pattern, dest.host))
  if (matched.length === 0) return
  ctx.audit({
    actor: actorOf(principal),
    action: "relay.tripwire",
    target: slug,
    detail: { host: dest.host, method: dest.method, items: [slug], fences: matched, reason: "fenced-host" },
  })
  throw new VaultError("environment_refused", `${dest.host} is fenced to an environment that "${slug}" does not belong to. Nothing was sent, and this was recorded.`, {
    next: { say: `The vault refused to send "${slug}" to ${dest.host}, which belongs to another environment. Run with that environment (mehen run --env <env>) so its own credentials are used, or ask a human to change the fence in the vault.` },
  })
}

async function authoriseItem(ctx: VaultContext, principal: DevicePrincipal, slug: string, dest: Destination, hooks?: RelayAuthorisationHooks): Promise<Checked> {
  const item = await loadUsableItem(ctx, principal, slug, "relay", hooks)
  assertItemNotFenced(ctx, principal, item.slug, dest)
  return { item, mode: "relay" }
}

async function authoriseRun(ctx: VaultContext, principal: DevicePrincipal, run: string, dest: Destination, url: URL, headers: [string, string][], body: Uint8Array | null, hooks?: RelayAuthorisationHooks): Promise<Checked[]> {
  const placeholders = relayServices.placeholdersFor(ctx, principal, run)
  const byCore = new Map<string, RunPlaceholder>()
  for (const p of placeholders) {
    const core = placeholderCore(p.placeholder)
    if (core !== null) byCore.set(core, p)
  }
  const sightings = findSightings(url, headers, body)
  const seen = [...new Set(sightings.flatMap((s) => byCore.get(s.core)?.item ?? []))].sort()
  if (hooks) for (const slug of seen) hooks.visible(slug, "placeholder")
  assertNotFenced(ctx, principal, run, dest, seen)
  const misplaced: { slug: string | null; where: string }[] = []
  const used = new Map<string, ItemRecord>()
  for (const s of sightings) {
    const p = byCore.get(s.core)
    const item = p ? hooks ? hooks.visible(p.item, "placeholder") : items.getItem(ctx, p.item) : null
    if (!p || !item) {
      misplaced.push({ slug: null, where: s.where })
      continue
    }
    const surface = declaredSurface(item)
    const hostBound = !isLeaseOnly(item.binding) && !isLeaseOnly({ hosts: p.hosts }) && p.hosts.some((h) => hostMatches(h, dest.host)) && item.binding.hosts.some((h) => hostMatches(h, dest.host))
    if (surface === null || s.where !== surface || !hostBound) {
      misplaced.push({ slug: item.slug, where: s.where })
      continue
    }
    used.set(item.slug, item)
  }
  if (misplaced.length > 0) {
    const slugs = [...new Set(misplaced.map((m) => m.slug ?? "unknown"))]
    ctx.audit({
      actor: actorOf(principal),
      action: "relay.tripwire",
      target: slugs[0] ?? null,
      detail: { run, host: dest.host, method: dest.method, items: slugs, where: [...new Set(misplaced.map((m) => m.where))] },
    })
    const first = misplaced[0] as { slug: string | null; where: string }
    const what = first.slug ? `A placeholder for "${first.slug}"` : "An unknown placeholder"
    refuse(
      "surface_refused",
      `${what} appeared in the request ${describeWhere(first.where)} to ${dest.host}, which is not where it may go. Nothing was sent, and this was recorded.`,
      "The vault refused a request that carried a credential placeholder outside its declared place. Placeholders are only swapped in the item's own header or query parameter, on its bound hosts.",
    )
  }
  if (used.size === 0) {
    throw new VaultError("bad_request", "This request carries no placeholder of the run on a declared surface, so the vault relay has nothing to do with it.", {
      next: { say: "Base-URL delivery is not available yet. Use the run's placeholder key on its declared surface instead." },
    })
  }
  const checked: Checked[] = []
  for (const slug of [...used.keys()].sort()) checked.push({ item: await loadUsableItem(ctx, principal, slug, "placeholder", hooks), mode: "placeholder" })
  return checked
}

function describeWhere(where: string): string {
  if (where === "body") return "body"
  if (where === "url") return "address"
  if (where === "basic") return "Basic credentials"
  if (where.startsWith("query")) return `query string (${where.slice(where.indexOf(":") + 1) || "a parameter name"})`
  if (where.startsWith("header:")) return `header ${where.slice(7)}`
  return "headers"
}

// ---------------------------------------------------------------- injection

function fieldValue(item: ItemRecord, secrets: Record<string, string>, field: string): string {
  const value = secrets[field] ?? item.publicFields[field]
  if (value === undefined || value === "") {
    throw new VaultError("internal", `"${item.slug}" has no "${field}" to inject; replace it in the vault.`, {
      next: { say: `The credential "${item.slug}" is incomplete; a human must fix it in the vault.` },
    })
  }
  if (/[\r\n\0]/.test(value)) throw new VaultError("internal", `"${item.slug}" holds a value that cannot be sent in a request.`)
  return value
}

export function inject(item: ItemRecord, secrets: Record<string, string>, headers: Headers, url: URL): RedactionSecret[] {
  const injection = item.injection
  const scrub: RedactionSecret[] = []
  const label = item.slug
  const secretOf = (field: string) => {
    const value = fieldValue(item, secrets, field)
    if (field in secrets) scrub.push({ label, value })
    return value
  }
  if (injection === null) return scrub
  switch (injection.in) {
    case "header": {
      if (isReservedHeader(injection.name)) {
        refuse(
          "mode_refused",
          `"${item.slug}" injects its secret as ${injection.name}, a framing, routing, cookie, proxy or method-override header the relay never sets. Nothing was sent.`,
          `The vault refused to use "${item.slug}": it injects into ${injection.name}, which the relay never sets. A human must change how it is sent, in the vault.`,
        )
      }
      const value = injection.format.replace(/\{([a-z][a-z0-9_]*)\}/g, (_m, field: string) => secretOf(field))
      headers.set(injection.name, value)
      break
    }
    case "query":
      url.searchParams.set(injection.name, secretOf(injection.field))
      break
    case "basic": {
      const pair = `${fieldValue(item, secrets, injection.username)}:${secretOf(injection.password)}`
      let bin = ""
      for (const b of new TextEncoder().encode(pair)) bin += String.fromCharCode(b)
      const encoded = btoa(bin)
      scrub.push({ label, value: encoded })
      headers.set("authorization", `Basic ${encoded}`)
      break
    }
    case "headers": {
      let map: unknown
      try {
        map = JSON.parse(secretOf(injection.field))
      } catch {
        throw new VaultError("internal", `"${item.slug}" does not hold a valid header map; replace it in the vault.`)
      }
      if (typeof map !== "object" || map === null || Array.isArray(map)) throw new VaultError("internal", `"${item.slug}" does not hold a valid header map.`)
      for (const [name, value] of Object.entries(map as Record<string, unknown>)) {
        if (typeof value !== "string" || !HEADER_NAME.test(name) || /[\r\n\0]/.test(value)) throw new VaultError("internal", `"${item.slug}" holds an invalid header.`)
        if (isReservedHeader(name)) {
          refuse(
            "mode_refused",
            `"${item.slug}" holds a header map that names ${name}, a framing, routing, cookie, proxy or method-override header the relay never sets. Nothing was sent.`,
            `The vault refused to use "${item.slug}": its stored headers include ${name}, which the relay never sets. A human must replace it in the vault without that header.`,
          )
        }
        scrub.push({ label, value })
        headers.set(name, value)
      }
      break
    }
  }
  return scrub
}

// The headers an item's injection sets, replacing any copy the agent sent.
// A header map's names are inside its secret, which is not opened before
// the approval, so none are left out for it: its card shows every copy.
function injectedHeaderNames(item: ItemRecord): string[] {
  const injection = item.injection
  if (injection?.in === "header") return [injection.name.toLowerCase()]
  if (injection?.in === "basic") return ["authorization"]
  return []
}

async function secretsFor(ctx: VaultContext, item: ItemRecord): Promise<Record<string, string>> {
  if (item.kind === "oauth-connection") return { access_token: await oauth.accessToken(ctx, item) }
  return items.openSecrets(ctx, item)
}

// ---------------------------------------------------------------- the op

export function parseRelayRequest(input: unknown): RelayRequestInput {
  if (typeof input === "object" && input !== null && ["policyMode", "env", "environment"].some((field) => field in input)) throw new VaultError("bad_request", "A relay request cannot select a policy mode or claim an environment.", { next: { say: "Remove policyMode, env and environment from the relay request body." } })
  const parsed = RelayRequest.safeParse(input)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    throw new VaultError("bad_request", `Invalid relay request: ${issue ? `${issue.path.join(".") || "body"} ${issue.message}` : "bad shape"}.`)
  }
  return parsed.data
}

function destinationOf(method: string, url: string): Destination {
  const result = parseDestination(method, url)
  if (result.ok) {
    if (result.destination.scheme === "https" || result.destination.scheme === "http") return result.destination
    refuse("binding_refused", "The relay speaks HTTP and HTTPS only.", "The vault relay cannot carry WebSocket connections.")
  }
  switch (result.error) {
    case "invalid-url":
      throw new VaultError("bad_request", "That is not a valid URL.")
    case "userinfo":
      refuse("binding_refused", "URLs with a username or password in them are refused.", "Remove the user:password@ part of the URL; the vault adds credentials itself.")
    case "unsupported-scheme":
      refuse("binding_refused", "Only http and https URLs can be relayed.", "The vault relay only carries HTTP(S) requests.")
    case "ambiguous-path":
      refuse(
        "binding_refused",
        "The path holds an encoded slash, backslash or dot, a dot segment or an empty segment, which upstreams read differently. Send the plain path.",
        "The vault refused an ambiguous path; send it without encoded slashes, dots, backslashes, '..' or '//'.",
      )
  }
}

// An item behind a protected environment's variable (R4): only a device
// allowed protected environments may use it, through an approval in item
// mode, or inside its own approved protected run.
function assertProtectedAllowed(ctx: VaultContext, principal: DevicePrincipal, slugs: string[], run: string | null): void {
  const named = slugs.map((s) => `"${s}"`).join(", ")
  if (principal.scope.maxEnvironment !== "protected") {
    ctx.audit({ actor: actorOf(principal), action: "relay.refuse", target: slugs[0] ?? null, detail: { items: slugs, reason: "protected-item", ...(run ? { run } : {}) } })
    throw new VaultError("environment_refused", `${named} ${slugs.length === 1 ? "backs" : "back"} a protected environment, and this device is not allowed protected environments.`, {
      next: { url: `${ctx.env.VAULT_ORIGIN}/devices`, say: `${named} belongs to a protected environment; this machine may not use it unless a human widens its scope in the vault.` },
    })
  }
  if (run !== null && !runs.isApprovedProtectedRun(ctx, principal, run)) {
    ctx.audit({ actor: actorOf(principal), action: "relay.refuse", target: slugs[0] ?? null, detail: { items: slugs, reason: "protected-item", run } })
    throw new VaultError("environment_refused", `${named} ${slugs.length === 1 ? "backs" : "back"} a protected environment, and this run is not an approved run in a protected environment.`, {
      next: { say: `${named} belongs to a protected environment; start the run with --env and the protected environment's name, so a human can approve it.` },
    })
  }
}

function assertRelayCurrent(ctx: VaultContext, principal: DevicePrincipal, checked: Checked[], req: RelayRequestInput, dest: Destination, protectedBefore: Set<string>, hooks?: RelayAuthorisationHooks): void {
  const state = devicePolicyState(ctx, principal.device)
  if (!state?.active) throw new VaultError("forbidden", "This device is no longer active.", { next: exactApprovalNext })
  const currentPrincipal = { ...principal, scope: state.scope }
  for (const { item, mode } of checked) {
    const current = items.getItem(ctx, item.slug)
    if (!current || current.id !== item.id || hooks !== undefined && (current.version !== item.version || current.configRev !== item.configRev) || (current.status !== "active" && !(hooks && current.status === "refresh_retrying")) || !deviceModeAllowed(current.ceiling, mode) || !deviceCovers(currentPrincipal, current, mode)) throw new VaultError("forbidden", "The credential or device scope changed before authorisation.", { next: exactApprovalNext })
    checkDestination(ctx, currentPrincipal, current, dest)
    if (req.item) assertItemNotFenced(ctx, currentPrincipal, current.slug, dest)
  }
  if (req.run) {
    const live = relayServices.placeholdersFor(ctx, currentPrincipal, req.run)
    if (!checked.every(({ item }) => live.some((placeholder) => placeholder.item === item.slug))) throw new VaultError("not_found", "The run ended before authorisation.", { next: exactApprovalNext })
    assertNotFenced(ctx, currentPrincipal, req.run, dest, checked.map(({ item }) => item.slug))
  }
  const protectedNow = new Set(checked.filter(({ item }) => projects.isProtectedItem(ctx, item.slug)).map(({ item }) => item.slug))
  if (protectedNow.size !== protectedBefore.size || [...protectedNow].some((slug) => !protectedBefore.has(slug))) throw new VaultError("conflict", "Environment protection changed before authorisation.", { next: exactApprovalNext })
  if (protectedNow.size && !hooks) assertProtectedAllowed(ctx, currentPrincipal, [...protectedNow], req.run ?? null)
}

export async function authoriseRelay(ctx: VaultContext, principal: DevicePrincipal, input: unknown, hooks?: RelayAuthorisationHooks): Promise<RelayMaterial> {
  const req = parseRelayRequest(input)
  if (req.session !== undefined && req.session !== principal.session) throw new VaultError("forbidden", "The body session must equal the signed proof session.", { next: { say: "Remove session from the relay body or match the signed proof session." } })
  if ((req.item === undefined) === (req.run === undefined)) {
    throw new VaultError("bad_request", "Name exactly one of item (a credential to inject) or run (whose placeholders to swap).")
  }
  const method = req.method.toUpperCase()
  if (!RELAY_METHODS.includes(method)) throw new VaultError("bad_request", `The relay does not carry ${method} requests.`)
  const dest = destinationOf(method, req.url)
  const url = new URL(req.url)
  url.hash = ""
  // Forward the path the policy was checked against, not the one as sent.
  url.pathname = dest.path

  let body: Uint8Array<ArrayBuffer> | null = null
  if (req.body !== undefined && req.body !== "") {
    try {
      body = base64UrlDecode(req.body)
    } catch {
      throw new VaultError("bad_request", "The relay body must be base64url.")
    }
  }
  if (body !== null && (method === "GET" || method === "HEAD")) throw new VaultError("bad_request", `${method} requests cannot carry a body.`)

  for (const [name] of req.headers) {
    if (!HEADER_NAME.test(name)) throw new VaultError("bad_request", `"${name}" is not a valid header name.`)
    // CGI and FastCGI read X_Original_URL as X-Original-URL.
    const spelled = name.toLowerCase().replaceAll("_", "-")
    if (METHOD_OVERRIDE_HEADERS.includes(spelled)) {
      refuse("forbidden", `Method-override headers (${name}) are refused: the policy checks the method you send, so send the real one.`, "The vault refused a method-override header; send the real HTTP method instead.")
    }
    if (URL_REWRITE_HEADERS.includes(spelled)) {
      refuse("forbidden", `URL-rewrite headers (${name}) are refused: the binding and policy check the path you send, so send the real one.`, "The vault refused a URL-rewrite header; send the real path instead.")
    }
    if (spelled === "content-encoding" && name.toLowerCase() !== "content-encoding") {
      refuse("forbidden", `A ${name} header is refused: an upstream may read it as Content-Encoding, and the vault reads the body by the Content-Encoding you send, so send that.`, "The vault refused a misspelt Content-Encoding header; send Content-Encoding instead.")
    }
    if (PATH_ROUTING_HEADERS.includes(spelled)) {
      refuse("forbidden", `Routing headers (${name}) are refused: an upstream may act on the path they name, and the binding and policy check the path you send, so send the real one.`, "The vault refused a routing header; send the real path instead.")
    }
    if (HOST_ROUTING_HEADERS.includes(spelled)) {
      refuse("forbidden", `Routing headers (${name}) are refused: an upstream may act on the host they name, and the binding checks the host you send, so send the real one.`, "The vault refused a routing header; send the real host instead.")
    }
  }
  const overrideParameter = policyMethodOverrideParameter(dest.search)
  if (overrideParameter !== null) {
    refuse("forbidden", "Method-override parameters are refused: send the real method instead.", "The vault refused a method-override parameter; send the real HTTP method instead.")
  }
  const contentType = requestHeader(req.headers, "content-type")
  let forms: Uint8Array[] = []
  if (body !== null) {
    const decoded = decodedRequestBody(body, requestHeader(req.headers, "content-encoding"))
    if ("unread" in decoded) {
      refuse("forbidden", `A body in content-encoding ${JSON.stringify(decoded.unread.slice(0, 40))} that the vault cannot decompress is refused: it reads every body for a method-override field, so send it uncompressed, or as gzip or deflate.`, "The vault refused a compressed body it cannot read; send it uncompressed instead.")
    }
    if ("stacked" in decoded) {
      refuse("forbidden", `A body in ${decoded.stacked} stacked content codings is refused: the vault undoes no more than ${MAX_REQUEST_CODINGS}, so send it uncompressed or in one coding.`, "The vault refused a body in more stacked content codings than it undoes; send it uncompressed instead.")
    }
    if ("tooLarge" in decoded) {
      throw new VaultError("too_large", `A compressed body that decompresses to more than ${MAX_DECODED_BODY_BYTES} bytes is refused: the vault reads every body for a method-override field.`, { next: { say: "The vault refused a compressed body that decompresses to more than it reads; send less in one request." } })
    }
    forms = decoded.forms
  }
  for (const form of forms) {
    if (policyBodyDeclaresUnreadCharset(form, contentType)) {
      refuse("forbidden", "A body whose type declares a charset other than UTF-8, ASCII, UTF-16, ISO-8859 or windows-125x, or an empty or unknown one, or whose multipart field name (name*) declares any charset but UTF-8, ASCII, ISO-8859 or windows-125x, is refused: the vault cannot read it for a method-override field, so send it as UTF-8.", "The vault refused a body in a charset it cannot read; send it as UTF-8 instead.")
    }
    const overrideField = policyMethodOverrideBodyField(form, contentType)
    if (overrideField !== null) {
      refuse("forbidden", `The body's ${overrideField} field is refused: an upstream may read it as the method, and the policy checks the method you send, so send the real one.`, "The vault refused a method-override field in the body; send the real HTTP method instead.")
    }
  }

  const checked: Checked[] =
    req.item !== undefined ? [await authoriseItem(ctx, principal, req.item, dest, hooks)] : await authoriseRun(ctx, principal, req.run as string, dest, url, req.headers, body, hooks)

  for (const { item } of checked) checkDestination(ctx, principal, item, dest)

  const protectedSlugs = new Set(checked.filter(({ item }) => projects.isProtectedItem(ctx, item.slug)).map(({ item }) => item.slug))
  hooks?.prepare(checked, req)
  if (protectedSlugs.size > 0 && !hooks) assertProtectedAllowed(ctx, principal, [...protectedSlugs].sort(), req.run ?? null)

  const headers = new Headers()
  const stripped = new Set([...STRIPPED_REQUEST_HEADERS, ...connectionTokens(req.headers.find(([n]) => n.toLowerCase() === "connection")?.[1] ?? null)])
  try {
    for (const [name, value] of req.headers) {
      const lower = name.toLowerCase()
      if (stripped.has(lower) || lower.startsWith("mehen-") || lower.startsWith("cf-")) continue
      headers.append(name, value)
    }
  } catch {
    throw new VaultError("bad_request", "A header value is not valid.")
  }
  // The relay asks only for compressions it can scan for leaked values. It
  // is set here, not only in forwardRelay, so the approved list is the sent one.
  headers.set("accept-encoding", RELAY_ACCEPT_ENCODING)
  // What a human approves: every header forwarded from the agent, as it
  // will be sent, apart from those the injection overwrites.
  const injected = new Set(checked.flatMap(({ item }) => injectedHeaderNames(item)))
  const forwarded = [...headers].filter(([name]) => !injected.has(name)).sort(([an, av], [bn, bv]) => (an < bn ? -1 : an > bn ? 1 : av < bv ? -1 : av > bv ? 1 : 0))

  const bodySha256 = await bodyHash(body)
  const contentEncoding = requestHeader(req.headers, "content-encoding")
  // Still asked here, as when it chose whether a window could widen: a run
  // that stopped standing since authoriseRun refuses at this point.
  if (req.run !== undefined) runs.isApprovedProtectedRun(ctx, principal, req.run)
  const decisions = checked.map(({ item, mode }) => {
    const permit = preparePolicy(ctx, principal, item, dest, body, contentType, contentEncoding)
    permit.request.mode = mode
    permit.request.run = req.run ?? null
    return { item, permit }
  })
  for (const { item, permit } of decisions) {
    if (permit.decision === "deny") {
      ctx.audit({ actor: actorOf(principal), action: "relay.deny", target: item.slug, detail: { host: dest.host, method: dest.method } })
      const why = [...evaluatePolicy(item.policy, dest, body).matched.map((rule) => rule.note).filter((note): note is string => !!note), ...permit.reasons]
      refuse(
        "policy_denied",
        `"${item.slug}" may not be used for ${dest.method} ${dest.path}${why.length > 0 ? ` (${why.join(", ")})` : ""}.`,
        `The vault's policy for "${item.slug}" forbids this request. Only a human can change that policy, in the vault.`,
      )
    }
  }
  const refusals: VaultError[] = []
  for (const { item, permit } of decisions) {
    // A protected item in item mode always needs an approval; inside an
    // approved protected run the run's approval already covers it.
    const protectedUse = req.item !== undefined && protectedSlugs.has(item.slug)
    if (permit.decision === "approve" || protectedUse) {
      assertApprovable(item.slug, contentEncoding, body, forwarded)
      const subject: ApprovalSubject = {
        item: item.slug,
        method: dest.method,
        url: url.href,
        contentType,
        contentEncoding,
        headersSha256: digestOf(forwarded),
        bodySha256,
        constraints: { ...DEFAULT_APPROVAL_CONSTRAINTS },
      }
      const presentation = await presentRequest(item, dest, url, body, contentType, forwarded)
      if (hooks?.approve(item, subject, presentation, { destination: dest, url: url.href, body, contentType, contentEncoding, policyApprove: permit.decision === "approve", protectedUse })) continue
      try {
        await relayServices.reviewRequest(ctx, principal, subject, presentation)
      } catch (error) {
        if (!(error instanceof VaultError) || error.code !== "approval_required") throw error
        refusals.push(error)
      }
    }
  }

  if (refusals.length) throw refusals[0]
  if (hooks?.plan) return { method, url: url.href, headers: [], scrub: [], label: checked.map(({ item }) => item.slug).join(", "), items: checked.map(({ item }) => item.slug) }
  const requestDigest = digestOf({ method, url: url.href, bodySha256, headers: forwarded })
  const scrub: RedactionSecret[] = []
  if (!hooks) {
    // Bare-engine helper path. Workspace calls always provide their hooks.
    ctx.storage.transactionSync(() => {
      assertRelayCurrent(ctx, principal, checked, req, dest, protectedSlugs)
      policy.assertCurrent(ctx, decisions.map(({ permit }) => permit))
      policy.recordUse(ctx, decisions.map(({ permit }) => permit), requestDigest)
    })
    for (const { item } of checked) scrub.push(...inject(item, await secretsFor(ctx, item), headers, url))
  } else {
    for (const entry of checked) {
      if (!hooks.secrets) throw new VaultError("internal", "Workspace secret reader is not registered.")
      const opened = await hooks.secrets(entry.item)
      entry.item = opened.item
      scrub.push(...inject(entry.item, opened.secrets, headers, url))
    }
    // No await after this point. The baseline is the value actually opened,
    // including this request's own maintenance refresh, never an unrelated edit.
    ctx.storage.transactionSync(() => {
      hooks.assertCurrent()
      assertRelayCurrent(ctx, principal, checked, req, dest, protectedSlugs, hooks)
      policy.assertCurrent(ctx, decisions.map(({ permit }) => permit))
      policy.recordUse(ctx, decisions.map(({ permit }) => permit), requestDigest)
      hooks.consume()
    })
  }

  return {
    method,
    url: url.href,
    headers: [...headers],
    scrub,
    label: checked.map(({ item }) => (item.account ? `${item.slug} (${item.account})` : item.slug)).join(", "),
    items: checked.map(({ item }) => item.slug),
  }
}

export const relayArea: Area = {
  name: "relay",
  migrations: [],
  get workspaceOps(){return workspaceRelayOps},
}
