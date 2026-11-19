import { z } from "zod"
import { checkBinding, evaluatePolicy, parseDestination, pathMatches, type Binding, type Destination, type Policy, type PolicyRule, type RuleAction } from "./binding.ts"
import { bodyMatches, parseFormDataStrictly, parseJsonStrictly, type FormDataPart } from "./body-match.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import {
  CATALOGUE_SEGMENTS, catalogueFloorKeys, cataloguePathMatches, foldedKey, POLICY_CATALOGUES, policyCatalogueFor, policyCatalogueNamed,
  type CatalogueBody, type CatalogueEntry, type CatalogueReader, type CatalogueReaderId, type CatalogueReaderVerdict, type PolicyCatalogue, type PolicyFloorReason,
} from "./policy-catalogue.ts"
import { connectionPolicy, OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"
import { isPolicyHost, isPolicyPath, PolicyRouteScopeSchema, policyPathSubset, policyScopeWithinBinding, resolvePolicyMode, type PolicyFloorView, type PolicyMode, type PolicyRouteScope } from "./policy-mode.ts"

export const GENERIC_POLICY_FLOOR_WORDS = ["hook", "webhook", "token", "key", "secret", "invite", "member", "collaborator", "oauth", "authoriz", "credential", "destination", "subscription", "integration", "sso", "saml", "role", "permission", "share", "export"] as const
export type PolicyEffect = "read" | "routine" | "destructive" | "unknown"
export type PolicyFloorEntry = Omit<PolicyFloorView, "ruleDigest">
export type PolicySafetyProfile = { id: string; version: number; hosts: string[]; reads: PolicyRule[]; floor: PolicyFloorEntry[]; widenable: CatalogueEntry[] }
export type PolicySafetyInput = { destination: Destination; body?: Uint8Array | null; contentType?: string | null; contentEncoding?: string | null }
export type PolicyClassification = { effect: PolicyEffect; routeId: string | null; additionalPermission: boolean }
export type PolicyFloorDecision = { action: RuleAction; reasons: string[] }
export type PolicyEligibility = { eligible: boolean; basis: PolicyRouteScope["basis"]; reason: string | null }

const WIDENING_ONLY_REASONS = new Set(["safety.body", "safety.body-opaque", "safety.batch", "safety.json-rpc", "safety.graphql-proof", "safety.content-encoding", "safety.destination-shape", "safety.method-override"])
const WRITES = ["POST", "PUT", "PATCH", "DELETE"]
const GITHUB_ENTRIES = policyCatalogueNamed("github")?.entries ?? []
const STRIPE_ENTRIES = policyCatalogueNamed("stripe")?.entries ?? []

function matcherOf(rule: PolicyRule): PolicyRule {
  return { action: rule.action, ...(rule.methods ? { methods: [...rule.methods] } : {}), ...(rule.paths ? { paths: [...rule.paths] } : {}), ...(rule.body ? { body: rule.body } : {}) }
}

// The words floorReason looks for in a template rule's paths, by the reason
// they give, in the order it checks them.
export const POLICY_FLOOR_REASON_WORDS = {
  credential: ["token", "key", "secret", "password", "credential", "connection_uri", "/env/"],
  persistence: ["hook", "runner", "forwarding", "settings", "watch", "subscription", "drain", "destination", "integration", "saml", "sso", "jwks", "messagerules", "inboxrules", "applications", "serviceprincipal"],
  sharing: ["member", "invite", "collaborator", "permission", "/acl", "share", "createlink", "transfer", "/access", "/iam", "publish"],
  money: ["billing", "budget", "credit", "payout", "refund", "topup", "payment", "charge", "invoice", "treasury", "issuing"],
  send: ["send", "email", "message", "reply", "transactional", "broadcast", "enrollment", "incident", "status-report"],
} as const satisfies Record<string, readonly string[]>

export type PolicyFloorWordReason = keyof typeof POLICY_FLOOR_REASON_WORDS

// The words of POLICY_FLOOR_REASON_WORDS that name an act rather than a
// thing, which an API may do on a GET (Telegram's GET /bot{token}/sendMessage).
export const POLICY_FLOOR_VERB_WORDS = ["send", "reply", "broadcast", "publish", "transfer", "refund", "payout", "topup"] as const satisfies readonly (typeof POLICY_FLOOR_REASON_WORDS)[PolicyFloorWordReason][number][]

// The floor reasons the words in a path give, percent escapes decoded and
// case folded; only POLICY_FLOOR_VERB_WORDS when verbsOnly. Each segment is
// split at everything but letters and digits; a word counts when one part or
// the whole segment without those holds it. A word written with a leading
// "/" counts only at the start of one ("/acl"), and one with a trailing "/"
// only as all of one ("/env/").
export function policyPathFloorReasons(path: string, verbsOnly = false): PolicyFloorWordReason[] {
  const segments = (decodedText(path) ?? path).normalize("NFKC").toLowerCase().split("/").map((segment) => {
    const parts = segment.split(/[^a-z0-9]+/).filter((p) => p !== "")
    return [...parts, parts.join("")]
  })
  const holds = (word: string): boolean => {
    const bare = word.replace(/[^a-z0-9]/g, "")
    return segments.some((texts) => texts.some((t) => (word.endsWith("/") ? t === bare : word.startsWith("/") ? t.startsWith(bare) : t.includes(bare))))
  }
  const counted = (word: string): boolean => !verbsOnly || (POLICY_FLOOR_VERB_WORDS as readonly string[]).includes(word)
  return (Object.keys(POLICY_FLOOR_REASON_WORDS) as PolicyFloorWordReason[]).filter((reason) => POLICY_FLOOR_REASON_WORDS[reason].some((word) => counted(word) && holds(word)))
}

function floorReason(rule: PolicyRule): PolicyFloorView["reason"] {
  const paths = (rule.paths ?? []).join(" ").toLowerCase()
  const names = (reason: keyof typeof POLICY_FLOOR_REASON_WORDS): boolean => POLICY_FLOOR_REASON_WORDS[reason].some((word) => paths.includes(word))
  if (rule.body) return "opaque"
  if (names("credential")) return "credential"
  if (names("persistence")) return "persistence"
  if (names("sharing")) return "sharing"
  if (names("money")) return "money"
  if (rule.methods?.every((m) => m === "DELETE")) return "destructive"
  if (names("send")) return "send"
  return "opaque"
}

function profile(id: string, hosts: string[], policy: Policy): PolicySafetyProfile {
  const floor = policy.rules.filter((r) => r.action !== "allow").flatMap((rule, i) => hosts.map((host) => ({
    id: `${id}.floor-${i + 1}`, host, action: rule.action as "deny" | "approve", reason: floorReason(rule), rule: matcherOf(rule),
  })))
  return {
    id, version: 1, hosts: [...hosts], floor,
    reads: policy.rules.filter((r) => r.action === "allow" && (r.body === "graphql-query" || r.methods?.every((m) => m === "GET" || m === "HEAD"))).map(matcherOf),
    widenable: id === "github-pat" || id === "github-oauth" ? GITHUB_ENTRIES : id === "stripe" ? STRIPE_ENTRIES : [],
  }
}

export const POLICY_SAFETY_PROFILES: readonly PolicySafetyProfile[] = [
  ...Object.values(TEMPLATES).map((t) => profile(t.id, t.binding.hosts, t.policy)),
  ...Object.values(OAUTH_PROVIDERS).map((p) => profile(p.id, p.upstream.binding.hosts, connectionPolicy(p))),
]
const stripe = POLICY_SAFETY_PROFILES.find((p) => p.id === "stripe")
if (stripe) {
  for (const name of ["charges", "payment_intents", "setup_intents", "invoices", "invoiceitems", "credit_notes", "refunds", "payouts", "transfers", "topups", "treasury", "issuing", "customers"]) {
    stripe.floor.push({ id: `stripe.${name}`, host: "api.stripe.com", action: "approve", reason: name === "customers" ? "sharing" : "money", rule: { action: "approve", methods: WRITES, paths: [`/v1/${name}/**`] } })
  }
}
export const POLICY_FLOOR: readonly PolicyFloorEntry[] = POLICY_SAFETY_PROFILES.flatMap((p) => p.floor)
// Changes to classifier or unreviewed-route semantics must bump this domain,
// even when the template matcher data stays unchanged.
export const POLICY_SAFETY_VERSION = "mehen-policy-safety/v6"

export function policySafetyDigest(): Promise<string> {
  return sha256B64(canonicalJson({ domain: POLICY_SAFETY_VERSION, profiles: POLICY_SAFETY_PROFILES, generic: GENERIC_POLICY_FLOOR_WORDS, catalogues: POLICY_CATALOGUES }))
}
export function policyFloorDigest(entry: PolicyFloorEntry): Promise<string> {
  return sha256B64(canonicalJson({ host: entry.host, action: entry.action, reason: entry.reason, rule: entry.rule }))
}
export async function policyFloorViews(host: string): Promise<PolicyFloorView[]> {
  return Promise.all(POLICY_FLOOR.filter((f) => f.host === host).map(async (f) => ({ ...f, ruleDigest: await policyFloorDigest(f) })))
}

function decodedText(text: string): string | null {
  let out = text.replaceAll("+", " ")
  for (let i = 0; i <= 8; i++) {
    if (/[\p{Cc}\p{Cf}]/u.test(out.replace(/[\u00ad\u200c\u200d]/g, ""))) return null
    if (!/%[0-9a-f]{2}/i.test(out)) return i === 0 && out.includes("%") ? null : out
    if (i === 8) return null
    try { out = decodeURIComponent(out) } catch { return null }
  }
  return null
}

function looseText(text: string): string | null {
  const decoded = decodedText(text)
  if (decoded === null) return null
  const folded = decoded.normalize("NFKC").toUpperCase().toLowerCase()
  // Non-ASCII letters may stand in for a floor word, so widening cannot match around them.
  if (/[\p{L}\p{M}\p{N}]/u.test(folded.replace(/[\x00-\x7f]/g, ""))) return null
  return folded.replace(/[^a-z0-9]/g, "")
}

function queryValues(search: string): string[] | null {
  if (search === "") return []
  if (!search.startsWith("?") || search.includes("#")) return null
  return search.slice(1).split(/[&;]/).flatMap((part) => {
    const equals = part.indexOf("=")
    return equals < 0 ? [part] : [part.slice(0, equals), part.slice(equals + 1)]
  })
}

// Request fields an upstream may read as the method in place of the one sent.
const METHOD_OVERRIDE_FIELDS = ["_method", "_httpmethod", "x-http-method-override"]

// A run of percent escapes as text; bytes that are not UTF-8 become U+FFFD.
function percentDecoded(run: string): string {
  return new TextDecoder().decode(Uint8Array.from(run.slice(1).split("%"), (hex) => Number.parseInt(hex, 16)))
}

// A field name as an upstream registers it, so every spelling that reaches
// _method reads as _method. Decoded ("+" as a space, then percent escapes,
// up to eight rounds, a malformed one kept as it is), NFKC and lower case;
// cut at the first control character (PHP ends a name at a NUL, so
// "_method%00" is _method, and a cut at any other only refuses more); leading
// "[" and "]" dropped and cut at the next one (Rack 2 reads "[_method]",
// "]_method" and "_method]" as _method, and both read "_method[x]" as a
// _method array); then leading spaces dropped and "." and " " read as "_"
// (PHP reads ".method" and " _method" as _method).
function registeredFieldName(name: string): string {
  let decoded = name.replaceAll("+", " ")
  for (let i = 0; i < 8 && /%[0-9a-f]{2}/i.test(decoded); i++) decoded = decoded.replace(/(?:%[0-9a-f]{2})+/gi, percentDecoded)
  const named = (decoded.normalize("NFKC").toLowerCase().split(/\p{Cc}/u, 1)[0] ?? "").replace(/^[[\]]+/, "")
  return (named.split(/[[\]]/, 1)[0] ?? "").trimStart().replace(/[ .]/g, "_")
}

// The override field a name is, read as an upstream registers it; null when
// none.
function methodOverrideField(name: string): string | null {
  const folded = registeredFieldName(name)
  return METHOD_OVERRIDE_FIELDS.includes(folded) ? folded : null
}

function formOverrideField(form: string): string | null {
  for (const part of form.split(/[&;]/)) {
    const field = methodOverrideField(part.split("=", 1)[0] ?? "")
    if (field !== null) return field
  }
  return null
}

export function policyMethodOverrideParameter(search: string): string | null {
  return formOverrideField(search.slice(1))
}

function jsonOverrideField(text: string): string | null {
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { return null }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null
  for (const key of Object.keys(parsed)) {
    const field = methodOverrideField(key)
    if (field !== null) return field
  }
  return null
}

// Parsers disagree on a multipart body (which of two names or boundaries
// counts, what a filename is, which multipart types are forms), so it is not
// parsed: any name parameter anywhere in it that starts with an override
// field counts, whatever part, header or file it sits in. Quotes of either
// kind (PHP accepts '), brackets and spaces before the value are skipped, and
// an RFC 5987 name* value (busboy decodes "utf-8''%5Fmethod") is read both
// from its start and after its charset'lang' prefix.
const MULTIPART_NAME = /name\*?\s*=["'\s[\]]*((?:[!#$%&+^_`{}~0-9a-z-]*'[0-9a-z-]*')?)/gi
// How much of a name is read: the longest override field with every
// character percent-encoded, and a little slack.
const MULTIPART_NAME_WINDOW = 3 * Math.max(...METHOD_OVERRIDE_FIELDS.map((f) => f.length)) + 8
const SPACES = /\s*/y

function multipartNameFieldAt(text: string, start: number): string | null {
  SPACES.lastIndex = start
  SPACES.test(text)
  const name = registeredFieldName(text.slice(SPACES.lastIndex, SPACES.lastIndex + MULTIPART_NAME_WINDOW))
  return METHOD_OVERRIDE_FIELDS.find((f) => name.startsWith(f)) ?? null
}

function multipartOverrideField(text: string): string | null {
  for (const match of text.matchAll(MULTIPART_NAME)) {
    const end = match.index + match[0].length
    const field = multipartNameFieldAt(text, end - (match[1] ?? "").length) ?? multipartNameFieldAt(text, end)
    if (field !== null) return field
  }
  return null
}

// The method-override field a body names, read whatever type it declares,
// since upstreams pick the parser from the Content-Type in ways that differ
// (Rack and PHP cut it at a comma, Laravel reads any type holding "/json"):
// a URL-encoded form field, a key of a top-level JSON object, or, when the
// type mentions multipart, a name parameter anywhere in the body. Null when
// it names none.
export function policyMethodOverrideBodyField(body: Uint8Array | null, contentType: string | null): string | null {
  if (body === null || body.length === 0) return null
  const type = (contentType ?? "").toLowerCase()
  for (const text of bodyTexts(body, type)) {
    const field = formOverrideField(text) ?? jsonOverrideField(text) ?? (type.includes("multipart/") ? multipartOverrideField(text) : null)
    if (field !== null) return field
  }
  return null
}

// Every charset parameter in a type, named as iconv-lite (and so
// body-parser, which reads JSON in any utf- charset) names it: lower case
// with everything but letters and digits dropped, so utf-1-6le is utf16le.
function declaredCharsets(contentType: string | null): string[] {
  return [...(contentType ?? "").matchAll(/charset\s*=\s*("(?:[^"\\]|\\.)*"?|[^;,]*)/gi)].map((m) => (m[1] ?? "").toLowerCase().replace(/[^0-9a-z]/g, ""))
}

// The charsets, named as declaredCharsets names them, in which the scan
// above reads a field name as the upstream does: UTF-8, ASCII, the UTF-16
// that bodyTexts decodes, and single-byte charsets whose ASCII bytes mean
// ASCII.
const READ_CHARSETS = new Set([
  "utf8", "unicode11utf8", "usascii", "ascii", "utf16", "utf16le", "utf16be",
  ...Array.from({ length: 16 }, (_, i) => `iso8859${i + 1}`).filter((c) => c !== "iso885912"),
  ...Array.from({ length: 10 }, (_, i) => `latin${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => [`windows${1250 + i}`, `cp${1250 + i}`]).flat(),
])

// The body as UTF-8 and, when the type names UTF-16 or the body starts with
// a UTF-16 byte order mark, as UTF-16 too: in the byte order the mark or the
// type says, or in both when neither says.
function bodyTexts(body: Uint8Array, type: string): string[] {
  const texts = [new TextDecoder().decode(body)]
  const charsets = declaredCharsets(type)
  const orders = new Set<"utf-16le" | "utf-16be">()
  if (body[0] === 0xff && body[1] === 0xfe) orders.add("utf-16le")
  if (body[0] === 0xfe && body[1] === 0xff) orders.add("utf-16be")
  if (charsets.includes("utf16le")) orders.add("utf-16le")
  if (charsets.includes("utf16be")) orders.add("utf-16be")
  if (orders.size === 0 && charsets.includes("utf16")) orders.add("utf-16le").add("utf-16be")
  for (const order of orders) texts.push(new TextDecoder(order).decode(body))
  return texts
}

// The charsets of READ_CHARSETS in which the scan reads an RFC 5987 name*
// as the upstream does: it reads the percent escapes as UTF-8, so only those
// whose ASCII bytes mean ASCII, not UTF-16.
const NAME_READ_CHARSETS = new Set([...READ_CHARSETS].filter((c) => !c.startsWith("utf16")))

// A charset name is short. The run is read at most one character past this,
// so each name* costs a bounded read whatever follows it rather than a scan
// to the next "'" (quadratic over a body of name*= alone), and a run that
// reaches it is unread.
const NAME_CHARSET_MAX = 64
const MULTIPART_NAME_CHARSET = new RegExp(`name\\*\\s*=["\\s]*([^'";\\s]{0,${NAME_CHARSET_MAX + 1}})(')?`, "gi")

// The charset of every RFC 5987 name* (or filename*) in a multipart body,
// everything before its first "'", empty included, named as declaredCharsets
// names them; null for one longer than NAME_CHARSET_MAX.
function multipartNameCharsets(text: string): (string | null)[] {
  const charsets: (string | null)[] = []
  for (const match of text.matchAll(MULTIPART_NAME_CHARSET)) {
    const run = match[1] ?? ""
    if (run.length > NAME_CHARSET_MAX) charsets.push(null)
    else if (match[2] !== undefined) charsets.push(run.toLowerCase().replace(/[^0-9a-z]/g, ""))
  }
  return charsets
}

// Whether a body's type declares any charset outside READ_CHARSETS (UTF-7,
// UTF-32, UCS-2, x-utf-16le and the rest), or, when the type mentions
// multipart, a name* in it declares one outside NAME_READ_CHARSETS: an
// upstream may decode either in a way the checks above cannot follow.
export function policyBodyDeclaresUnreadCharset(body: Uint8Array | null, contentType: string | null): boolean {
  if (body === null || body.length === 0) return false
  if (declaredCharsets(contentType).some((c) => !READ_CHARSETS.has(c))) return true
  const type = (contentType ?? "").toLowerCase()
  return type.includes("multipart/") && bodyTexts(body, type).some((text) => multipartNameCharsets(text).some((c) => c === null || !NAME_READ_CHARSETS.has(c)))
}

function queryParts(search: string): string[] | null {
  const parts = queryValues(search)?.map(looseText) ?? null
  return parts === null || parts.some((p) => p === null) ? null : parts as string[]
}

function destinationRefusal(d: Destination): string | null {
  if (!isPolicyHost(d.host) || !/^[A-Z]+$/.test(d.method) || !Number.isSafeInteger(d.port) || d.port < 1 || d.port > 65535) return "safety.destination"
  const parsed = parseDestination(d.method, `${d.scheme}://${d.host}:${d.port}${d.path}${d.search}`)
  if (!parsed.ok || parsed.destination.path !== d.path || parsed.destination.search !== d.search || parsed.destination.host !== d.host) return "safety.destination"
  const parts = queryValues(d.search)
  const decoded = [decodedText(d.path), ...(parts?.map(decodedText) ?? [null])]
  if (decoded.some((part) => part === null)) return "safety.encoding"
  if (!isPolicyPath(d.path) || queryParts(d.search) === null || decoded.some((part) => /[\u00ad\u200c\u200d]/.test(part ?? ""))) return "safety.destination-shape"
  return null
}

// The media type alone, lower-cased: whatever spacing or parameters follow it.
function mediaType(contentType: string | null | undefined): string {
  return (contentType ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? ""
}

// An unreviewed window widens only bodies whose shape is known: none, or one strict JSON object
// that is no RPC call, batch or unproved GraphQL. Every other body (forms, whose decoded values
// could carry any of those, multipart, HTTP messages, text, JSON sequences, anything this cannot
// read) asks instead.
function bodyRefusal(input: PolicySafetyInput): string | null {
  const media = mediaType(input.contentType)
  if (/^(multipart|message)\//.test(media) || media === "application/http" || media === "application/json-seq") return "safety.batch"
  if (input.contentEncoding !== undefined && input.contentEncoding !== null && input.contentEncoding !== "identity") return "safety.content-encoding"
  const body = input.body ?? null
  if (body === null) return null
  if (body.length === 0 || body.length > 64 * 1024) return "safety.body"
  let text: string
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body) } catch { return "safety.body" }
  if (text.includes("\u001e") || /^[A-Za-z]+ \S+ HTTP\/\d/m.test(text)) return "safety.batch"
  const isJson = media.endsWith("json") || media.endsWith("+json") || /^[\s]*[\[{]/.test(text)
  if (isJson) {
    const parsed = parseJsonStrictly(text)
    if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) return "safety.body"
    if (Array.isArray(parsed.value)) return "safety.batch"
    const object = parsed.value as Record<string, unknown>
    if (Object.keys(object).some((key) => METHOD_OVERRIDE_FIELDS.includes(key.toLowerCase()))) return "safety.method-override"
    if ("jsonrpc" in object || "method" in object) return "safety.json-rpc"
    if (["batch", "requests", "operations"].some((key) => Array.isArray(object[key]))) return "safety.batch"
    if (graphqlShaped(object, input.destination.path) && !bodyMatches("graphql-query", body, input.destination.search)) return "safety.graphql-proof"
    return null
  }
  return media === "application/graphql" ? "safety.graphql-proof" : "safety.body-opaque"
}

// A JSON object is a GraphQL request when it holds a key only GraphQL uses,
// variables as an object (so a persisted query under any name, Relay's doc_id
// or a queryId or hash, is one), a persisted query's id with its variables,
// or an id or variables sent to a path that names GraphQL. Anywhere else an
// id or a list of variables is the API's own field, as Cloudflare's gateway
// create names the gateway's id and GitLab's pipeline lists its variables.
function graphqlShaped(object: Record<string, unknown>, path: string): boolean {
  if (["query", "operationName", "extensions", "documentId", "doc_id"].some((key) => key in object)) return true
  if (("variables" in object && !Array.isArray(object["variables"])) || ("id" in object && "variables" in object)) return true
  return ("id" in object || "variables" in object) && graphqlPath(path)
}

// Whether a path segment names GraphQL (graphql or gql, in any case or
// encoding), or is one looseText cannot read.
function graphqlPath(path: string): boolean {
  return path.split("/").some((segment) => {
    const text = looseText(segment)
    return text === null || text.includes("graphql") || text.includes("gql")
  })
}

const issueBody = z.strictObject({ title: z.string().optional(), body: z.string().optional(), state: z.enum(["open", "closed"]).optional() }).refine((v) => Object.keys(v).length > 0)
const commentBody = z.strictObject({ body: z.string() })

// A body the safety checks read as one strict JSON object, and that value.
function strictJsonBody(input: PolicySafetyInput): { value: unknown } | null {
  if (bodyRefusal(input) !== null || !input.body) return null
  let text: string
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input.body) } catch { return null }
  const parsed = parseJsonStrictly(text)
  return parsed.ok ? { value: parsed.value } : null
}

// The one value of a JSON object's key, read as Go's encoding/json would
// find it (any key that folds to it); null when none or several fold to it.
function foldedField(object: Record<string, unknown>, key: string): { value: unknown } | null {
  const found = Object.keys(object).filter((k) => foldedKey(k) === foldedKey(key))
  return found.length === 1 ? { value: object[found[0] as string] } : null
}

const ROUTINE_DNS_TYPES = new Set(["A", "AAAA", "CNAME"])
// A routine record name: ASCII letters, digits, "*", "@", "." and "-" only,
// so punycode (xn--) passes and no "_" label, invisible character IDNA would
// delete, or zone-file escape (\095 for "_") can hide a mail or proof name.
const ROUTINE_DNS_NAME = /^[A-Za-z0-9*@.-]+$/

// A DNS record body is routine only as one strict JSON object naming its type
// and name once each: an A, AAAA or CNAME record whose name ROUTINE_DNS_NAME
// takes. Anything else (mail, domain proof, delegation, or a type or name it
// cannot read) is persistence. A PATCH that leaves out the type or name is
// floor too, since the record it changes may be any type. A reader of some
// of the routine types (own) leaves the others to another entry's reader
// (no-match), and only the reader that owns the rest (rest) floors a body
// that is none of them.
function dnsRecordVerdict(input: PolicySafetyInput, own: ReadonlySet<string>, rest: boolean): CatalogueReaderVerdict {
  const other: CatalogueReaderVerdict = rest ? { floor: "persistence" } : "no-match"
  const read = strictJsonBody(input)
  if (read === null || typeof read.value !== "object" || read.value === null || Array.isArray(read.value)) return other
  const record = read.value as Record<string, unknown>
  const type = foldedField(record, "type")
  const name = foldedField(record, "name")
  if (typeof type?.value !== "string" || !ROUTINE_DNS_TYPES.has(foldedKey(type.value))) return other
  if (!own.has(foldedKey(type.value))) return "no-match"
  if (typeof name?.value !== "string" || !ROUTINE_DNS_NAME.test(name.value)) return { floor: "persistence" }
  return "match"
}

const UPLOAD_JSON_MAX = 64 * 1024
const FLOOR_ORDER: readonly PolicyFloorReason[] = ["credential", "send", "money", "sharing", "destructive", "persistence", "opaque"]

// The parts of an upload body read as parseFormDataStrictly reads them, no
// two of whose names fold alike (foldedKey); null for a coded body, one the
// override or name-charset scans flag anywhere in it, or one it cannot read.
function uploadParts(input: PolicySafetyInput): FormDataPart[] | null {
  const body = input.body ?? null
  const type = input.contentType ?? null
  const coded = input.contentEncoding !== undefined && input.contentEncoding !== null && input.contentEncoding !== "identity"
  if (body === null || coded || policyMethodOverrideBodyField(body, type) !== null || policyBodyDeclaresUnreadCharset(body, type)) return null
  const form = parseFormDataStrictly(body, input.contentType ?? null)
  if (!form.ok) return null
  const names = form.parts.map((p) => foldedKey(p.name))
  return new Set(names).size === names.length ? form.parts : null
}

// The one part whose name folds to this one, as one strict JSON object of
// at most 64 KiB in UTF-8 with no byte order mark, sent untyped or as JSON
// under exactly that name; null when there is none, or it is anything else.
function uploadJsonPart(parts: FormDataPart[], name: string): Record<string, unknown> | null {
  const part = parts.find((p) => foldedKey(p.name) === foldedKey(name))
  if (part === undefined || part.name !== name || (part.contentType !== null && part.contentType !== "application/json") || part.body.length > UPLOAD_JSON_MAX) return null
  let text: string
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(part.body) } catch { return null }
  if (text.startsWith("\ufeff")) return null
  const parsed = parseJsonStrictly(text)
  return parsed.ok && typeof parsed.value === "object" && parsed.value !== null && !Array.isArray(parsed.value) ? parsed.value as Record<string, unknown> : null
}

const SECRET_BINDING_TYPES = new Set(["secret_text", "secret_key", "secrets_store_secret"].map(foldedKey))
const WORKER_FLOOR_KEYS = new Map<string, PolicyFloorReason>(Object.entries({
  logpush: "persistence", tail_consumers: "persistence", streaming_tail_consumers: "persistence",
  deleted_classes: "destructive", transferred_classes: "destructive", transferred_to: "destructive", transfer_from: "destructive",
} satisfies Record<string, PolicyFloorReason>).map(([key, reason]) => [foldedKey(key), reason]))

// Every binding type the scripts reference lists under metadata.bindings
// (https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/),
// folded, and the floor a binding of it gives (null: none). A binding is
// floor-free only if it gives the uploaded code no read, write or delete of
// data or resources that existed before the upload, and no route to another
// script, network or party: a secret is credential, email send, and reach
// into another script, a network or existing data sharing, since the code
// can send that data anywhere.
const WORKER_BINDING_FLOORS = new Map<string, PolicyFloorReason | null>(Object.entries({
  ai: null, analytics_engine: null, assets: null, browser: null, data_blob: null, json: null, plain_text: null, ratelimit: null, text_blob: null,
  version_metadata: null, wasm_module: null, worker_loader: null, media: null, workflow: null, durable_object_namespace: null,
  secret_text: "credential", secret_key: "credential", secrets_store_secret: "credential", inherit: "credential", hyperdrive: "credential", mtls_certificate: "credential",
  send_email: "send",
  service: "sharing", dispatch_namespace: "sharing", vpc_service: "sharing", vpc_network: "sharing", d1: "sharing", r2_bucket: "sharing", kv_namespace: "sharing",
  vectorize: "sharing", queue: "sharing", pipelines: "sharing", ai_search: "sharing", ai_search_namespace: "sharing", k2: "sharing", artifacts: "sharing",
  messaging: "sharing", images: "sharing", flagship: "sharing",
} satisfies Record<string, PolicyFloorReason | null>).map(([type, reason]) => [foldedKey(type), reason]))
// Keys by which a Durable Object or Workflow binding names a script other
// than the one uploaded, or a namespace that already exists, which makes it
// sharing.
const OTHER_SCRIPT_KEYS = new Set(["script_name", "dispatch_namespace", "environment", "namespace_id"].map(foldedKey))

// The floor one entry of a bindings array gives: credential for one it
// cannot read (not an object, or not exactly one string type) or of a type
// the reference does not list; otherwise its type's (WORKER_BINDING_FLOORS),
// or sharing for a Durable Object or Workflow naming another script or an
// existing namespace.
function workerBindingFloor(binding: unknown): PolicyFloorReason | null {
  if (typeof binding !== "object" || binding === null || Array.isArray(binding)) return "credential"
  const type = foldedField(binding as Record<string, unknown>, "type")
  if (typeof type?.value !== "string") return "credential"
  const folded = foldedKey(type.value)
  const reason = WORKER_BINDING_FLOORS.get(folded)
  if (reason === undefined) return "credential"
  const reachesOut = (folded === foldedKey("durable_object_namespace") || folded === foldedKey("workflow")) && Object.keys(binding).some((k) => OTHER_SCRIPT_KEYS.has(foldedKey(k)))
  return reachesOut ? "sharing" : reason
}

// What a Worker's metadata makes floor, every key at every depth read folded
// as Cloudflare's API may match it (foldedKey), walked without recursion:
// each binding in any bindings array (workerBindingFloor), and a bindings
// value that is not an array (credential); any keep_bindings but an empty
// array (credential), since a kept binding is one the body cannot show; a
// "type" anywhere naming a secret (credential) or email (send); logpush or
// tail consumers, or logs or traces sent to any destination but
// Cloudflare's own (persistence); a Durable Object class deleted or
// transferred, by a migration or an export's state (destructive).
function workerMetadataFloor(metadata: Record<string, unknown>): PolicyFloorReason[] {
  const found = new Set<PolicyFloorReason>()
  const pending: unknown[] = [metadata]
  while (pending.length > 0) {
    const value = pending.pop()
    if (Array.isArray(value)) for (const inner of value) pending.push(inner)
    else if (typeof value === "object" && value !== null) {
      for (const [key, inner] of Object.entries(value)) {
        const folded = foldedKey(key)
        const text = typeof inner === "string" ? foldedKey(inner) : null
        const reason = WORKER_FLOOR_KEYS.get(folded)
        if (reason !== undefined) found.add(reason)
        if (folded === "BINDINGS") {
          if (!Array.isArray(inner)) found.add("credential")
          else for (const binding of inner) { const floor = workerBindingFloor(binding); if (floor !== null) found.add(floor) }
        }
        if (folded === "KEEP_BINDINGS" && !(Array.isArray(inner) && inner.length === 0)) found.add("credential")
        if (folded === "TYPE" && text !== null && SECRET_BINDING_TYPES.has(text)) found.add("credential")
        if (folded === "TYPE" && text === "SEND_EMAIL") found.add("send")
        if (folded === "STATE" && (text === "DELETED" || text === "TRANSFERRED")) found.add("destructive")
        if (folded === "DESTINATIONS" && !(Array.isArray(inner) && inner.every((d) => typeof d === "string" && foldedKey(d) === "CLOUDFLARE"))) found.add("persistence")
        pending.push(inner)
      }
    }
  }
  return FLOOR_ORDER.filter((r) => found.has(r))
}

const WORKER_MODULE_TYPES = ["application/javascript+module", "text/javascript+module", "application/javascript", "text/javascript"]
const WORKER_PART_TYPES = new Set([...WORKER_MODULE_TYPES, "application/wasm", "application/source-map", "text/plain", "application/octet-stream"])

// A Worker upload (multipart, as uploadParts reads it): exactly one
// "metadata" part (uploadJsonPart), whose floor (workerMetadataFloor) wins;
// every other part a module, wasm, source map, text or bytes, by its type.
function workerUploadVerdict(input: PolicySafetyInput): CatalogueReaderVerdict {
  const parts = uploadParts(input)
  const metadata = parts === null ? null : uploadJsonPart(parts, "metadata")
  if (parts === null || metadata === null) return "no-match"
  const floor = workerMetadataFloor(metadata)[0]
  if (floor !== undefined) return { floor }
  return parts.every((p) => p.name === "metadata" || (p.contentType !== null && WORKER_PART_TYPES.has(p.contentType))) ? "match" : "no-match"
}

// A body sent as JSON (the type's media type ends in json) and read as one
// strict JSON array of objects, in UTF-8 with no byte order mark, no
// content coding and at most 64 KiB, each object's keys all among these and
// each value of the type named; null for anything else. Two keys that fold
// alike cannot both be among the names, so none is read two ways.
type ArrayFieldType = "string" | "number" | "boolean" | "any"
function strictJsonArray(input: PolicySafetyInput, fields: Record<string, ArrayFieldType>, required: readonly string[]): Record<string, unknown>[] | null {
  const body = input.body ?? null
  const coded = input.contentEncoding !== undefined && input.contentEncoding !== null && input.contentEncoding !== "identity"
  if (body === null || coded || body.length === 0 || body.length > UPLOAD_JSON_MAX || !mediaType(input.contentType).endsWith("json")) return null
  let text: string
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body) } catch { return null }
  const parsed = text.startsWith("\ufeff") ? { ok: false as const } : parseJsonStrictly(text)
  if (!parsed.ok || !Array.isArray(parsed.value) || parsed.value.length === 0) return null
  const items = parsed.value as unknown[]
  const fits = (item: unknown): item is Record<string, unknown> => typeof item === "object" && item !== null && !Array.isArray(item)
    && required.every((key) => Object.hasOwn(item, key))
    && Object.entries(item).every(([key, value]) => Object.hasOwn(fields, key) && (fields[key] === "any" || typeof value === fields[key]))
  return items.every(fits) ? items : null
}

// A KV bulk write: an array of { key, value } with the optional fields
// Cloudflare documents (expiration, expiration_ttl, metadata, base64).
function kvBulkVerdict(input: PolicySafetyInput): CatalogueReaderVerdict {
  return strictJsonArray(input, { key: "string", value: "string", expiration: "number", expiration_ttl: "number", base64: "boolean", metadata: "any" }, ["key", "value"]) === null ? "no-match" : "match"
}

// A Worker's cron triggers: an array of { cron }.
function cronTriggersVerdict(input: PolicySafetyInput): CatalogueReaderVerdict {
  return strictJsonArray(input, { cron: "string" }, ["cron"]) === null ? "no-match" : "match"
}

// A queue consumer to add, as the queues reference documents it: a pull
// consumer is one strict JSON object, or none, whose type folds to
// http_pull and with no key at any depth folding to script_name. Any other
// body the JSON check reads is a Worker consumer (pull: false), which
// points the queue's messages at a script.
function queueConsumerVerdict(input: PolicySafetyInput, pull: boolean): CatalogueReaderVerdict {
  if (input.body === null || input.body === undefined) return bodyRefusal(input) === null && !pull ? "match" : "no-match"
  const read = strictJsonBody(input)
  if (read === null || typeof read.value !== "object" || read.value === null || Array.isArray(read.value)) return "no-match"
  const type = foldedField(read.value as Record<string, unknown>, "type")
  let names = false
  const pending: unknown[] = [read.value]
  while (pending.length > 0 && !names) {
    const value = pending.pop()
    if (Array.isArray(value)) for (const inner of value) pending.push(inner)
    else if (typeof value === "object" && value !== null) for (const [key, inner] of Object.entries(value)) { names ||= foldedKey(key) === "SCRIPT_NAME"; pending.push(inner) }
  }
  const isPull = typeof type?.value === "string" && foldedKey(type.value) === "HTTP_PULL" && !names
  return isPull === pull ? "match" : "no-match"
}

// An Analytics Engine SQL query, which Cloudflare takes as the raw body
// whatever its type: sent untyped, as text/plain or as a URL-encoded form (as
// curl --data sends it), text the body check reads as plain text rather than
// JSON, a batch or GraphQL, naming no override field, and one statement,
// nothing but space after any semicolon.
const ANALYTICS_ENGINE_SQL_TYPES = new Set(["", "text/plain", "application/x-www-form-urlencoded"])
function analyticsEngineSqlVerdict(input: PolicySafetyInput): CatalogueReaderVerdict {
  const body = input.body ?? null
  if (!ANALYTICS_ENGINE_SQL_TYPES.has(mediaType(input.contentType)) || body === null || bodyRefusal(input) !== "safety.body-opaque" || policyMethodOverrideBodyField(body, input.contentType ?? null) !== null) return "no-match"
  return /;\s*\S/.test(new TextDecoder().decode(body)) ? "no-match" : "match"
}

// An issue's fields, a title required to open one; a comment's body alone.
const CATALOGUE_READERS: Record<CatalogueReaderId, CatalogueReader> = {
  "github.issue": (input) => {
    const read = strictJsonBody(input)
    const opens = input.destination.method === "POST"
    return read !== null && issueBody.safeParse(read.value).success && (!opens || typeof (read.value as Record<string, unknown>)["title"] === "string") ? "match" : "no-match"
  },
  "github.comment": (input) => {
    const read = strictJsonBody(input)
    return read !== null && commentBody.safeParse(read.value).success ? "match" : "no-match"
  },
  "cloudflare.dns-record": (input) => dnsRecordVerdict(input, ROUTINE_DNS_TYPES, true),
  "cloudflare.dns-address-record": (input) => dnsRecordVerdict(input, new Set(["A", "AAAA"]), true),
  "cloudflare.dns-cname-record": (input) => dnsRecordVerdict(input, new Set(["CNAME"]), false),
  "cloudflare.worker-upload": workerUploadVerdict,
  "cloudflare.kv-bulk": kvBulkVerdict,
  "cloudflare.queue-pull-consumer": (input) => queueConsumerVerdict(input, true),
  "cloudflare.queue-worker-consumer": (input) => queueConsumerVerdict(input, false),
  "cloudflare.cron-triggers": cronTriggersVerdict,
  "cloudflare.analytics-engine-sql": analyticsEngineSqlVerdict,
}

// A body whose type declares a charset the checks do not read matches no
// entry: an upstream may decode it into fields the checks never saw.
function catalogueBodyVerdict(input: PolicySafetyInput, body: CatalogueBody): CatalogueReaderVerdict {
  if (body === "none") return (input.body === null || input.body === undefined) && bodyRefusal(input) === null ? "match" : "no-match"
  const raw = input.body ?? null
  const unreadCharset = policyBodyDeclaresUnreadCharset(raw, input.contentType ?? null)
  if (body === "json") return bodyRefusal(input) === null && !unreadCharset ? "match" : "no-match"
  if (body === "data") {
    const coded = input.contentEncoding !== undefined && input.contentEncoding !== null && input.contentEncoding !== "identity"
    return coded || policyMethodOverrideBodyField(raw, input.contentType ?? null) !== null || unreadCharset ? "no-match" : "match"
  }
  const verdict = CATALOGUE_READERS[body.reader](input)
  return verdict === "match" && unreadCharset ? "no-match" : verdict
}

// Whether a request meets a catalogue path as a floor: case folded, and also
// as a template floor does (binding.ts's restrictive rules), every loose form
// of the path (escapes decoded, a trailing slash, matrix parameters or a
// format suffix dropped) against the path with each typed segment as "*".
function catalogueFloorMeets(methods: readonly string[], path: string, d: Destination): boolean {
  if (!methods.includes(d.method)) return false
  if (cataloguePathMatches(path, d.path, true)) return true
  const pattern = path.split("/").map((s) => (s in CATALOGUE_SEGMENTS ? "*" : s)).join("/")
  return evaluatePolicy({ default: "allow", rules: [{ action: "approve", methods: [...methods], paths: [pattern] }] }, d, null).action === "approve"
}

// floor: each catalogue floor the request meets, then each floor key and
// reader floor verdict of an entry whose method and path it meets as a
// floor does (catalogueFloorMeets), whatever its query string, by reason id
// (catalogueFloorReason reads them back). entry: the entry it is, a
// destructive one before a routine one, only when no floor holds and the
// destination is readable; an entry matches its typed path exactly, takes
// no query string, and one with floor keys only a body catalogueFloorKeys
// can read.
export type PolicyCatalogueVerdict = { floor: { id: string; reason: PolicyFloorReason }[]; entry: CatalogueEntry | null }

export function policyCatalogueVerdict(input: PolicySafetyInput, catalogue: PolicyCatalogue | null = policyCatalogueFor(input.destination.host)): PolicyCatalogueVerdict {
  const d = input.destination
  if (catalogue === null || !catalogue.hosts.includes(d.host)) return { floor: [], entry: null }
  const floor = new Map<string, PolicyFloorReason>()
  for (const f of catalogue.floor) if (catalogueFloorMeets(f.methods, f.path, d)) floor.set(f.id, f.reason)
  const entries: CatalogueEntry[] = []
  const readable = destinationRefusal(d) === null && d.search === ""
  for (const entry of catalogue.entries) {
    if (!catalogueFloorMeets(entry.methods, entry.path, d)) continue
    const keys = catalogueFloorKeys(entry.floorKeys, input.body)
    for (const reason of keys.reasons) floor.set(`${entry.id}:${reason}`, reason)
    const verdict = catalogueBodyVerdict(input, entry.body)
    if (verdict !== "match" && verdict !== "no-match") floor.set(`${entry.id}:${verdict.floor}`, verdict.floor)
    else if (verdict === "match" && readable && keys.readable && cataloguePathMatches(entry.path, d.path)) entries.push(entry)
  }
  const floors = [...floor].map(([id, reason]) => ({ id, reason }))
  return { floor: floors, entry: floors.length > 0 ? null : entries.find((e) => e.effect === "destructive") ?? entries[0] ?? null }
}

export function classifyPolicyRequest(input: PolicySafetyInput): PolicyClassification {
  const unknown: PolicyClassification = { effect: "unknown", routeId: null, additionalPermission: false }
  if (destinationRefusal(input.destination) !== null) return unknown
  const { entry } = policyCatalogueVerdict(input)
  if (entry) return { effect: entry.effect, routeId: entry.id, additionalPermission: entry.additionalPermission }
  if (bodyRefusal(input)) return unknown
  const profiles = POLICY_SAFETY_PROFILES.filter((p) => p.hosts.includes(input.destination.host))
  if (profiles.some((p) => evaluatePolicy({ default: "deny", rules: p.reads }, input.destination, input.body ?? null).action === "allow")) return { effect: "read", routeId: null, additionalPermission: false }
  return unknown
}

// The template floors (POLICY_FLOOR), then the catalogue's floors, floor
// keys and reader verdicts (policyCatalogueVerdict), each a mandatory
// reason. A request that is a catalogue entry has had its body read by that
// entry, and skips the body check and the generic words.
export function evaluatePolicyFloor(input: PolicySafetyInput, catalogue: PolicyCatalogue | null = policyCatalogueFor(input.destination.host)): PolicyFloorDecision {
  const floors = POLICY_FLOOR.filter((f) => f.host === input.destination.host)
  const matched = floors.filter((f) => evaluatePolicy({ default: "allow", rules: [f.rule] }, input.destination, input.body ?? null).action !== "allow")
  const denies = matched.filter((f) => f.action === "deny")
  if (denies.length) return { action: "deny", reasons: denies.map((f) => f.id) }
  const reasons = matched.map((f) => f.id)
  const verdict = policyCatalogueVerdict(input, catalogue)
  reasons.push(...verdict.floor.map((f) => f.id))
  const destinationReason = destinationRefusal(input.destination)
  if (destinationReason) reasons.push(destinationReason)
  if (verdict.entry === null) {
    const refusal = bodyRefusal(input)
    if (refusal) reasons.push(refusal)
    const texts = [looseText(input.destination.path), ...(queryParts(input.destination.search) ?? [null])]
    for (const word of GENERIC_POLICY_FLOOR_WORDS) if (texts.some((t) => t?.includes(word))) reasons.push(`generic.${word}`)
  }
  return { action: reasons.length ? "approve" : "allow", reasons }
}

function reviewedScope(scope: PolicyRouteScope): boolean {
  if (scope.host === "api.github.com") {
    const parts = scope.path.split("/")
    return parts[1] === "repos" && /^[A-Za-z0-9][A-Za-z0-9-]*$/.test(parts[2] ?? "") && (parts[3] === "*" || /^[A-Za-z0-9_.-]+$/.test(parts[3] ?? "")) && parts[4] === "issues" && policyPathSubset(scope.path, `/repos/${parts[2]}/${parts[3]}/issues/**`) && GITHUB_ENTRIES.some((e) => cataloguePathMatches(e.path, scope.anchorPath)) && scope.methods.every((m) => GITHUB_ENTRIES.some((e) => e.methods.includes(m)))
  }
  return scope.host === "api.stripe.com" && ["products", "prices"].some((name) => policyPathSubset(scope.path, `/v1/${name}/**`)) && scope.methods.every((m) => m === "POST")
}

export function policyScopeEligibility(scope: PolicyRouteScope, binding: Binding): PolicyEligibility {
  const refused = (reason: string): PolicyEligibility => ({ eligible: false, basis: scope.basis, reason })
  if (!PolicyRouteScopeSchema.safeParse(scope).success || !policyScopeWithinBinding(scope, binding)) return refused("scope.binding-or-pin")
  const reviewed = reviewedScope(scope)
  if ((scope.basis === "reviewed") !== reviewed) return refused("scope.basis")
  if (scope.host === "api.github.com" && !reviewed) return refused("scope.github-namespace")
  if (scope.basis === "unreviewed" && scope.path.split("/").some((s) => s.toLowerCase() === "graphql")) return refused("scope.graphql")
  return { eligible: true, basis: scope.basis, reason: null }
}

export function policyWideningEligibility(input: PolicySafetyInput, scope: PolicyRouteScope, binding: Binding): PolicyEligibility {
  const refused = (reason: string): PolicyEligibility => ({ eligible: false, basis: scope.basis, reason })
  const eligibility = policyScopeEligibility(scope, binding)
  if (!eligibility.eligible) return eligibility
  const d = input.destination
  const destinationReason = destinationRefusal(d)
  if (destinationReason) return refused(destinationReason)
  if (!checkBinding(binding, d).ok || d.host !== scope.host || !scope.methods.some((m) => m === d.method) || !pathMatches(scope.path, d.path)) return refused("scope.destination")
  if (evaluatePolicyFloor(input).action !== "allow") return refused("scope.floor")
  const classified = classifyPolicyRequest(input)
  if (scope.host === "api.stripe.com") return refused("scope.stripe-base-only")
  if (scope.basis === "reviewed") return classified.additionalPermission ? eligibility : refused("scope.not-widenable")
  if (d.path.split("/").some((s) => s.toLowerCase() === "graphql")) return refused("scope.graphql")
  const queryNames = d.search.slice(1).split(/[&;]/).map((p) => looseText(p.split("=", 1)[0] ?? ""))
  if (queryNames.some((k) => k !== null && ["query", "operationname", "extensions", "documentid"].includes(k))) return refused("scope.graphql-proof")
  return bodyRefusal(input) === null ? eligibility : refused("scope.body")
}

export function resolvePolicyRequest(input: PolicySafetyInput & { policy: Policy; binding: Binding; policyMode: PolicyMode; scope: PolicyRouteScope | null }): PolicyFloorDecision {
  const floor = evaluatePolicyFloor(input)
  const base = evaluatePolicy(input.policy, input.destination, input.body ?? null)
  if (floor.action === "deny" || base.action === "deny") return { action: "deny", reasons: floor.reasons }
  if (!checkBinding(input.binding, input.destination).ok) return { action: "deny", reasons: ["scope.binding"] }
  // Base-allowed traffic keeps its existing body and route semantics. Only
  // known-host floors and unreadable destinations hold it in standard mode.
  const mandatory = floor.reasons.some((reason) => !reason.startsWith("generic.") && !WIDENING_ONLY_REASONS.has(reason))
  if (floor.action === "approve" && (base.action !== "allow" || mandatory)) return floor
  const eligible = input.scope !== null && policyWideningEligibility(input, input.scope, input.binding).eligible
  const classification = classifyPolicyRequest(input)
  const effect = input.scope?.basis === "unreviewed" ? input.destination.method === "DELETE" ? "destructive" : input.destination.method === "GET" || input.destination.method === "HEAD" ? "read" : "routine" : classification.effect
  return { action: resolvePolicyMode(base, input.policyMode, effect, eligible), reasons: [] }
}
