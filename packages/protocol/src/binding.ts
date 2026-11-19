// Destination binding: the rule that a credential only ever goes where it
// was meant to. Every use of a secret, by the vault's relay, the local
// relay or a helper, is checked here first, with the same code.
//
// Deliberately strict and boring:
//   - https only unless the binding says otherwise;
//   - hosts are exact names or "*.suffix" (any depth below, never the apex);
//   - no userinfo, no IP literals unless listed exactly, default ports only
//     unless listed;
//   - paths are canonicalised (RFC 3986 6.2.2), and a path holding an
//     encoded slash, backslash or dot, a control character, a malformed or
//     double escape, a dot segment or an empty segment is refused outright
//     rather than guessed at;
//   - matching fails closed both ways: permissive patterns (binding paths,
//     allow rules) match the canonical path exactly, while restrictive ones
//     (deny and approve rules) match every loose form an upstream router
//     might read the path as (see looseForms), so an encoding, case or
//     suffix trick can narrow what is allowed but never dodge what is
//     denied;
//   - policy rules combine as deny over approve over allow, never "first
//     match wins", so adding a rule cannot silently open something up;
//   - a rule may also name a body matcher (body-match.ts). A deny or approve
//     rule's matcher matches whatever it cannot read; an allow rule may
//     carry only a matcher from ALLOW_BODY_MATCHERS, which matches only what
//     it can prove harmless.

import type { Injection } from "./api.ts"
import { ALLOW_BODY_MATCHERS, type BodyMatcher, bodyMatches } from "./body-match.ts"
import { type ItemKind, KINDS, type Mode, deviceModeAllowed, modeAllowed } from "./kinds.ts"

export type Scheme = "https" | "http" | "wss" | "ws"

export type Binding = {
  hosts: string[]
  schemes?: Scheme[]
  ports?: number[]
  paths?: string[]
  methods?: string[]
}

export type RuleAction = "allow" | "approve" | "deny"

export type PolicyRule = {
  action: RuleAction
  methods?: string[]
  paths?: string[]
  // The rule applies only when the body matches (see ruleMatches).
  body?: BodyMatcher
  note?: string
}

export type Policy = {
  default: RuleAction
  rules: PolicyRule[]
}

export type Destination = {
  scheme: Scheme
  host: string
  port: number
  // Canonical: unreserved escapes decoded, every other escape upper-case hex.
  path: string
  method: string
  // The query string as sent: "?a=b", or "" for none. Body matchers read it.
  search: string
}

export type DestinationError =
  | "invalid-url"
  | "userinfo"
  | "unsupported-scheme"
  | "ambiguous-path"

const DEFAULT_PORT: Record<Scheme, number> = { https: 443, http: 80, wss: 443, ws: 80 }

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const HOST_PATTERN = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$/

export function parseDestination(method: string, url: string): { ok: true; destination: Destination } | { ok: false; error: DestinationError } {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return { ok: false, error: "invalid-url" }
  }
  if (parsed.username !== "" || parsed.password !== "") return { ok: false, error: "userinfo" }
  const scheme = parsed.protocol.replace(/:$/, "")
  if (scheme !== "https" && scheme !== "http" && scheme !== "wss" && scheme !== "ws") {
    return { ok: false, error: "unsupported-scheme" }
  }
  // The parser resolves "%2e%2e" segments and turns "\" into "/" before
  // pathname is read, so check the URL as written (up to the query, with the
  // tabs and newlines the parser drops removed) as well as the parsed path.
  // Dot segments and empty segments are refused rather than resolved: an
  // upstream may read "/v1//admin" or "/v1/../admin" differently from us.
  // A single trailing slash is fine.
  const asWritten = url.replace(/[\t\n\r]/g, "").split(/[?#]/, 1)[0] ?? ""
  const writtenPath = asWritten.replace(/^[a-z]+:\/\/[^/]*/i, "")
  const path = canonicalPath(parsed.pathname || "/")
  if (/%2f|%5c|%2e/i.test(asWritten) || asWritten.includes("\\") || hasOddSegment(writtenPath) || path === null || hasOddSegment(path)) {
    return { ok: false, error: "ambiguous-path" }
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "")
  const port = parsed.port === "" ? DEFAULT_PORT[scheme] : Number(parsed.port)
  return { ok: true, destination: { scheme, host, port, path, method: method.toUpperCase(), search: parsed.search } }
}

const HEX_PAIR = /^[0-9A-Fa-f]{2}$/
const UNRESERVED = /^[A-Za-z0-9._~-]$/

function hasOddSegment(path: string): boolean {
  return /(^|\/)\.{1,2}(\/|$)/.test(path) || path.includes("//")
}

// RFC 3986 6.2.2: decode escapes of unreserved characters and upper-case the
// hex of the rest. Null when the path holds something no two readers agree
// on: an encoded slash, backslash or dot, a raw backslash, a control character,
// a malformed escape, or an escaped "%" that starts another escape ("%2573",
// or "%25%37%33", which decodes to "%2573"), which an upstream that decodes
// twice would read as "s".
function canonicalPath(raw: string): string | null {
  let out = ""
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charAt(i)
    const code = c.charCodeAt(0)
    if (code <= 0x1f || code === 0x7f || c === "\\") return null
    if (c !== "%") {
      out += c
      continue
    }
    const hex = raw.slice(i + 1, i + 3)
    if (!HEX_PAIR.test(hex)) return null
    const byte = Number.parseInt(hex, 16)
    if (byte <= 0x1f || byte === 0x7f || byte === 0x2f || byte === 0x5c || byte === 0x2e) return null
    if (byte === 0x25 && HEX_PAIR.test(raw.slice(i + 3, i + 5))) return null
    const decoded = String.fromCharCode(byte)
    out += UNRESERVED.test(decoded) ? decoded : `%${hex.toUpperCase()}`
    i += 2
  }
  return /%25[0-9A-Fa-f]{2}/.test(out) ? null : out
}

function decodeEscapes(path: string): string {
  return path.replace(/(%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 3)
    for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16)
    return new TextDecoder().decode(bytes)
  })
}

// Decoded until nothing changes (runs as UTF-8, invalid sequences becoming
// U+FFFD) and case-folded, so "%73", "S", "\u017F" (long s) and "\u212A"
// (Kelvin) all read as their ASCII letter.
function loosePath(path: string): string {
  let out = path
  for (let next = decodeEscapes(out); next !== out; next = decodeEscapes(out)) out = next
  return out.split("/").map((segment) => segment.normalize("NFKC").replace(/[\s\u00a0]+$/u, "")).join("/").toUpperCase().toLowerCase()
}

// Every form a restrictive rule is matched against. Each strips something
// an upstream router may ignore, so matching them all only ever narrows:
//   - the loose path itself, and the loose path cut at its first decoded
//     "?" or "#" (an upstream that decodes and splits again reads
//     "/keys%3Fx" as "/keys"), and for each of those:
//   - every segment cut at ";" (matrix parameters: "/keys;x=1");
//   - the last segment cut at its first "." (a format suffix: "/keys.json");
//   - the last segment after its last "." (a qualified action name:
//     "microsoft.graph.send", "graph.sendMail").
function looseForms(path: string): string[] {
  const loose = loosePath(path)
  const forms = new Set<string>()
  for (const whole of new Set([loose, loose.split(/[?#]/, 1)[0] ?? ""])) {
    const cut = whole
      .split("/")
      .map((s) => s.split(";", 1)[0] ?? "")
      .join("/")
      .replace(/\/+$/, "")
    const slash = cut.lastIndexOf("/")
    const head = cut.slice(0, slash + 1)
    const last = cut.slice(slash + 1)
    forms.add(whole).add(cut)
    if (last.includes(".")) {
      forms.add(head + last.slice(0, last.indexOf(".")))
      forms.add(head + last.slice(last.lastIndexOf(".") + 1))
    }
  }
  return [...forms]
}

export function validHostPattern(pattern: string): boolean {
  const p = pattern.toLowerCase()
  if (p.startsWith("[")) return /^\[[0-9a-f:.]+\]$/.test(p)
  if (IPV4.test(p)) return true
  if (!HOST_PATTERN.test(p) || p.length > 253) return false
  // A wildcard must keep at least two labels: "*.com" would bind a TLD.
  if (p.startsWith("*.")) return p.slice(2).includes(".")
  return true
}

export function hostMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase()
  const h = host.toLowerCase()
  if (p.startsWith("*.")) {
    const suffix = p.slice(1)
    return h.endsWith(suffix) && h.length > suffix.length
  }
  return p === h
}

// Path globs: "*" is one segment, "**" any number including none, anything
// else literal. "/v1/**" matches "/v1" and everything below it.
export function pathMatches(pattern: string, path: string): boolean {
  return pathMatchWork(pattern, path).matched
}

// pathMatches with its steps: one per pattern segment and path position,
// filled from the end, so a device's path costs pattern segments times path
// segments whatever "**" the pattern holds, never a search over every split.
export function pathMatchWork(pattern: string, path: string): { matched: boolean; steps: number } {
  const pat = pattern.split("/").filter((s, i) => i === 0 || s !== "")
  const segs = path.split("/").filter((s, i) => i === 0 || s !== "")
  let steps = 0
  // after[si]: whether pat from the segment after this one matches segs from si.
  let after = Array.from({ length: segs.length + 1 }, (_, si) => si === segs.length)
  for (let pi = pat.length - 1; pi >= 0; pi--) {
    const p = pat[pi]
    const here = new Array<boolean>(segs.length + 1)
    for (let si = segs.length; si >= 0; si--) {
      steps++
      if (p === "**") here[si] = after[si] === true || (si < segs.length && here[si + 1] === true)
      else here[si] = si < segs.length && (p === "*" || p === segs[si]) && after[si + 1] === true
    }
    after = here
  }
  return { matched: after[0] === true, steps }
}

function methodListed(methods: string[] | undefined, method: string): boolean {
  return methods === undefined || methods.length === 0 || methods.some((m) => m.toUpperCase() === method || m === "*")
}

// The canonical path cut at its first encoded "?" or "#", which an upstream
// that decodes and splits again reads as the end of the path; null when it
// has neither.
function pathCut(path: string): { path: string; at: "?" | "#" } | null {
  const found = /%3F|%23/i.exec(path)
  return found === null ? null : { path: path.slice(0, found.index), at: found[0].toUpperCase() === "%3F" ? "?" : "#" }
}

// Permissive: the canonical path, exactly and case-sensitively, and the path
// cut (pathCut). Both must be listed, so the cut only ever narrows.
function pathListed(paths: string[] | undefined, path: string): boolean {
  if (paths === undefined || paths.length === 0) return true
  const cut = pathCut(path)
  return paths.some((p) => pathMatches(p, path)) && (cut === null || paths.some((p) => pathMatches(p, cut.path)))
}

// Restrictive: every loose form of the path against loose patterns, so
// "%73end", "MessageRules", "keys;x=1" and "microsoft.graph.send" still hit
// the rules written for "send", "messageRules", "keys" and "send".
function pathListedLoosely(paths: string[] | undefined, path: string): boolean {
  if (paths === undefined || paths.length === 0) return true
  const forms = looseForms(path)
  return paths.some((p) => {
    const pattern = loosePath(p)
    return forms.some((f) => pathMatches(pattern, f))
  })
}

function ruleMatches(rule: PolicyRule, dest: Destination, body: Uint8Array | null): boolean {
  if (!methodListed(rule.methods, dest.method)) return false
  if (rule.action === "allow") {
    if (!pathListed(rule.paths, dest.path)) return false
    // An allow rule's matcher must prove the body harmless; any other
    // matcher could only widen, so the rule never matches.
    return rule.body === undefined || (ALLOW_BODY_MATCHERS.includes(rule.body) && bodyMatches(rule.body, body, dest.search))
  }
  if (!pathListedLoosely(rule.paths, dest.path)) return false
  // An allow-only matcher on a restrictive rule is ignored, so the rule
  // applies to every body.
  return rule.body === undefined || ALLOW_BODY_MATCHERS.includes(rule.body) || bodyMatches(rule.body, body, dest.search)
}

// The one host of a lease-only credential: a custom credential stored with
// no binding and no injection, which only `mehen run` delivers, as a lease,
// into a process. It keeps the rule that every item has a binding while
// naming nowhere: checkBinding refuses every destination for it, whatever
// DNS says, and BindingSchema refuses any other host under mehen.invalid,
// and this one beside any other host.
export const LEASE_ONLY_HOST = "lease-only.mehen.invalid"

export function leaseOnlyBinding(): Binding {
  return { hosts: [LEASE_ONLY_HOST] }
}

export function isLeaseOnly(binding: { hosts: readonly string[] }): boolean {
  return binding.hosts.length === 1 && binding.hosts[0] === LEASE_ONLY_HOST
}

function inReservedNamespace(host: string): boolean {
  const h = host.toLowerCase()
  return h === "mehen.invalid" || h.endsWith(".mehen.invalid")
}

// Whether these hosts use the reserved namespace in any way but the lone
// LEASE_ONLY_HOST: beside another host, as a wildcard, or another name.
export function misusesLeaseOnlyHost(hosts: readonly string[]): boolean {
  return hosts.some(inReservedNamespace) && !isLeaseOnly({ hosts })
}

// Without a template, the injection a kind gets when nobody says otherwise.
export const NATURAL_INJECTION: Record<ItemKind, Injection | null> = {
  "api-key": { in: "header", name: "Authorization", format: "Bearer {key}" },
  "bearer-token": { in: "header", name: "Authorization", format: "Bearer {token}" },
  "basic-auth": { in: "basic", username: "username", password: "password" },
  "custom-headers": { in: "headers", field: "headers" },
  "oauth-client": null,
  "oauth-connection": { in: "header", name: "Authorization", format: "Bearer {access_token}" },
  "google-service-account": null,
  "github-app": null,
  "hmac-key": null,
  "ssh-key": null,
  "password-login": null,
  totp: null,
  "database-url": null,
  "smtp-imap": null,
  "cloud-access-key": null,
  file: null,
  note: null,
  generic: null,
}

// Whether a custom credential of this kind, proposed with no hosts, may be
// stored lease-only. A kind the relay puts into requests would sit there
// unusable, so it needs the hosts it goes to instead. The vault and adopt's
// plan check both ask this, so a plan never sends what the vault refuses.
export function leaseOnlyAllowed(kind: ItemKind): boolean {
  return NATURAL_INJECTION[kind] === null
}

export function leaseOnlyRefusal(kind: ItemKind): string {
  return `${/^[aeiou]/.test(kind) ? "An" : "A"} ${kind} credential is sent to a service: name the hosts it may go to with --host.`
}

// What a lease-only credential's ceiling lets happen to it: mehen run
// leases it into a process; or it is stored only until a human sets its
// ceiling to lease; or, for a kind that can never be leased, stored only.
export type LeaseOnlyDelivery = "run" | "stored-until-lease" | "stored"

export function leaseOnlyDelivery(kind: ItemKind, ceiling: Mode): LeaseOnlyDelivery {
  if (deviceModeAllowed(ceiling, "lease")) return "run"
  return modeAllowed(KINDS[kind].maxCeiling, "lease") ? "stored-until-lease" : "stored"
}

// Said wherever a lease-only credential's hosts would be shown, by the web
// app and the CLI alike, so the reserved host never is. Null: a page that
// does not know the ceiling.
export function leaseOnlyWords(delivery: LeaseOnlyDelivery | null): string {
  if (delivery === null) return "No host: never sent to a service."
  if (delivery === "run") return "No host: only delivered into a process with mehen run."
  if (delivery === "stored-until-lease") return "No host: stored only; a human can allow mehen run by setting its ceiling to lease."
  return "No host: stored only."
}

// cutAt: the path as sent is listed, but not the path cut at that encoded
// character (pathCut).
export type BindingCheck = { ok: true } | { ok: false; reason: "scheme" | "host" | "port" | "path" | "method"; cutAt?: "?" | "#" }

// Why a path with a cutAt refusal is outside, for a refusal message.
export function bindingCutWords(at: "?" | "#"): string {
  return `read up to its encoded ${at} (${at === "?" ? "%3F" : "%23"}) as an upstream that decodes it again may end it`
}

export function checkBinding(binding: Binding, dest: Destination): BindingCheck {
  if (binding.hosts.some(inReservedNamespace)) return { ok: false, reason: "host" }
  const schemes = binding.schemes ?? ["https", "wss"]
  if (!schemes.includes(dest.scheme)) return { ok: false, reason: "scheme" }
  if (!binding.hosts.some((h) => hostMatches(h, dest.host))) return { ok: false, reason: "host" }
  const ports = binding.ports ?? [DEFAULT_PORT[dest.scheme]]
  if (!ports.includes(dest.port)) return { ok: false, reason: "port" }
  if (!pathListed(binding.paths, dest.path)) {
    const cut = pathCut(dest.path)
    return cut !== null && (binding.paths ?? []).some((p) => pathMatches(p, dest.path)) ? { ok: false, reason: "path", cutAt: cut.at } : { ok: false, reason: "path" }
  }
  if (!methodListed(binding.methods, dest.method)) return { ok: false, reason: "method" }
  return { ok: true }
}

export type PolicyDecision = { action: RuleAction; matched: PolicyRule[] }

// `body` is the request body as it will be sent; null for none. A missing
// body matches a deny or approve rule's matcher and never an allow rule's.
export function evaluatePolicy(policy: Policy, dest: Destination, body: Uint8Array | null = null): PolicyDecision {
  const matched = policy.rules.filter((r) => ruleMatches(r, dest, body))
  if (matched.some((r) => r.action === "deny")) return { action: "deny", matched: matched.filter((r) => r.action === "deny") }
  if (matched.some((r) => r.action === "approve")) return { action: "approve", matched: matched.filter((r) => r.action === "approve") }
  if (matched.some((r) => r.action === "allow")) return { action: "allow", matched: matched.filter((r) => r.action === "allow") }
  return { action: policy.default, matched: [] }
}

export const READ_METHODS = ["GET", "HEAD", "OPTIONS"]

export function isReadMethod(method: string): boolean {
  return READ_METHODS.includes(method.toUpperCase())
}

// The policy of an item stored without a template, whose binding an agent
// proposed: it fails closed. Every request waits for a human's approval,
// except reads when the human ticked them on the intake page. A human
// widens it later from the item page, with a passkey.
export function customItemPolicy(allowReads: boolean): Policy {
  return {
    default: "approve",
    rules: allowReads ? [{ action: "allow", methods: [...READ_METHODS], note: "reads, allowed when the credential was added" }] : [],
  }
}
