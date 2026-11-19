// What a human sees on an approval card for a relayed request (R6): the
// whole request, as the upstream will read it. A Gmail send that carries
// the whole message is summarised (every header, the recipients counted
// and checked against the account's domain, each text and HTML part, the
// attachments), and the whole decoded message is always the card's last
// section, so the summary can never hide anything. When any part of the
// message cannot be read without guessing, the card says so in red and
// shows no parts, only the headers and the whole message. Anything else is
// shown as method, host, path and the body, pretty-printed when its
// content type is JSON or a form. Every header forwarded from the agent is
// listed too. Built from the agent's request before any secret is
// injected. Every string here is rendered as text, never as HTML, with
// control characters spelled out and characters that hide or reorder text
// marked where they sit, and every one of them is checked for both.

import { type Destination, base64UrlDecode, parseJsonStrictly, pathMatches, sha256 } from "@mehen/protocol"
import type { ApprovalEmail } from "@mehen/protocol/api"
import type { ApprovalPresentation, ItemRecord } from "../vault/services.ts"
import { spellCardText, textWarnings } from "./spelling.ts"

// The largest body a human is asked to approve; anything longer is refused
// (relay.ts), because nobody can check it on a card.
export const MAX_APPROVAL_BODY_BYTES = 64 * 1024

// The same for the headers forwarded from the agent, as one block on the wire.
export const MAX_APPROVAL_HEADER_BYTES = 16 * 1024

// Multiparts nested deeper than this are unreadable: real mail rarely goes
// past three, and parsers stop at different depths.
const MAX_MIME_DEPTH = 5

// An attachment this small that decodes as UTF-8 is shown inline.
const INLINE_ATTACHMENT_BYTES = 64 * 1024

export const UNREADABLE_WARNING =
  "The vault could not read every part of this message, so it shows no parts, only the headers and the whole message at the bottom. Read the whole message before approving, or deny it."

const lenient = new TextDecoder("utf-8")

function strictUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)
  } catch {
    return null
  }
}

function decodeCharset(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(charset.trim().toLowerCase() || "utf-8").decode(bytes)
  } catch {
    return lenient.decode(bytes)
  }
}

// Base64 or base64url with optional padding, and line breaks only where a
// MIME body allows them. Null for anything else, so a stray character can
// never make data disappear from the card.
function strictBase64(text: string, lineBreaks: boolean): Uint8Array | null {
  const compact = lineBreaks ? text.replace(/[ \t\r\n]/g, "") : text
  const match = /^([A-Za-z0-9+/_-]*)(={0,2})$/.exec(compact)
  if (!match) return null
  const data = match[1] as string
  const padding = (match[2] as string).length
  if (padding > 0 && (data.length + padding) % 4 !== 0) return null
  try {
    return base64UrlDecode(data.replaceAll("+", "-").replaceAll("/", "_"))
  } catch {
    return null
  }
}

function quotedPrintableBytes(text: string, header: boolean): Uint8Array {
  const source = header ? text.replaceAll("_", " ") : text.replace(/=\r?\n/g, "")
  const out: number[] = []
  const encoder = new TextEncoder()
  for (let i = 0; i < source.length; i++) {
    const c = source[i] as string
    const hex = source.slice(i + 1, i + 3)
    if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(hex)) {
      out.push(Number.parseInt(hex, 16))
      i += 2
    } else {
      for (const b of encoder.encode(c)) out.push(b)
    }
  }
  return new Uint8Array(out)
}

// RFC 2047 encoded words: =?utf-8?B?...?= and =?utf-8?Q?...?=. A word that
// does not decode cleanly is left exactly as written.
function decodeWords(value: string): string {
  return value
    .replace(/\?=\s+=\?/g, "?==?")
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (whole, charset: string, enc: string, text: string) => {
      const bytes = enc.toUpperCase() === "B" ? strictBase64(text, false) : quotedPrintableBytes(text, true)
      return bytes === null ? whole : decodeCharset(bytes, charset)
    })
}

type Header = { name: string; value: string }
type Part = { headers: Header[]; body: string }

// A header block up to the first empty line, then the body. A line that is
// neither a header nor a continuation is a problem, never skipped, and so
// is a line of only spaces, which parsers read either as the end of the
// headers or as a continuation.
function parsePart(text: string, where: string, problems: string[]): Part {
  const lines = text.split(/\r?\n/)
  const end = lines.indexOf("")
  const headers: Header[] = []
  for (const line of end < 0 ? lines : lines.slice(0, end)) {
    if (/^[ \t]+$/.test(line)) {
      problems.push(`${where} has a header line of only spaces.`)
      continue
    }
    if (/^[ \t]/.test(line)) {
      const last = headers.at(-1)
      if (last === undefined) problems.push(`${where} starts with a folded header line.`)
      else last.value = `${last.value} ${line.trim()}`
      continue
    }
    const match = /^([!-9;-~]+):(.*)$/.exec(line)
    if (match === null) {
      problems.push(`${where} has a line that is not a header: ${JSON.stringify(line.slice(0, 80))}.`)
      continue
    }
    headers.push({ name: match[1] as string, value: (match[2] as string).trim() })
  }
  return { headers, body: end < 0 ? "" : lines.slice(end + 1).join("\n") }
}

function headerValues(part: Part, name: string): string[] {
  return part.headers.filter((h) => h.name.toLowerCase() === name).map((h) => h.value)
}

// A header that may appear once; a second copy is a problem, because
// parsers disagree on which one counts.
function singleHeader(part: Part, name: string, where: string, problems: string[]): string | null {
  const values = headerValues(part, name)
  if (values.length > 1) problems.push(`${where} has ${values.length} ${name} headers.`)
  return values[0] ?? null
}

type Parameterised = { value: string; params: Map<string, string> }

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+/
const BARE_VALUE = /^[^\s;"()<>,\\]+/

// "type/subtype; a=b; c="d"" (or a disposition, "attachment; filename=x"),
// read strictly: a comment, a repeated parameter or stray text is a
// problem, because mail parsers disagree on them. Returns why on failure.
function parseParameterised(header: string, withSubtype: boolean): Parameterised | string {
  let pos = 0
  const skip = () => {
    while (header[pos] === " " || header[pos] === "\t") pos++
  }
  const take = (pattern: RegExp): string | null => {
    const match = pattern.exec(header.slice(pos))
    if (match === null) return null
    pos += match[0].length
    return match[0]
  }
  skip()
  let value = take(TOKEN)
  if (value === null) return "has no type"
  if (withSubtype) {
    if (header[pos] !== "/") return "has no subtype"
    pos++
    const sub = take(TOKEN)
    if (sub === null) return "has no subtype"
    value = `${value}/${sub}`
  }
  const params = new Map<string, string>()
  for (;;) {
    skip()
    if (pos >= header.length) break
    if (header[pos] !== ";") return `has text the vault cannot read: ${JSON.stringify(header.slice(pos, pos + 40))}`
    pos++
    skip()
    if (pos >= header.length) break
    const name = take(TOKEN)?.toLowerCase()
    if (name === undefined) return `has text the vault cannot read: ${JSON.stringify(header.slice(pos, pos + 40))}`
    skip()
    if (header[pos] !== "=") return `has a "${name}" parameter without a value`
    pos++
    skip()
    let param = ""
    if (header[pos] === '"') {
      pos++
      for (;;) {
        if (pos >= header.length) return `has an unfinished quoted "${name}"`
        const c = header[pos++] as string
        if (c === '"') break
        if (c === "\\") {
          if (pos >= header.length) return `has an unfinished quoted "${name}"`
          param += header[pos++] as string
        } else {
          param += c
        }
      }
    } else {
      const bare = take(BARE_VALUE)
      if (bare === null) return `has a "${name}" parameter without a value`
      param = bare
    }
    if (params.has(name)) return `has the "${name}" parameter twice`
    params.set(name, param)
  }
  for (const name of params.keys()) {
    if (name.includes("*") && name !== "name*" && name !== "filename*") return `has a "${name}" parameter split or encoded in a way the vault does not read`
  }
  return { value: value.toLowerCase(), params }
}

// RFC 2231 "filename*=utf-8''r%C3%A9sum%C3%A9.pdf", else the plain parameter.
function fileName(params: Map<string, string>, name: string): string | null {
  const extended = params.get(`${name}*`)
  if (extended !== undefined) {
    const quote = extended.indexOf("''")
    const encoded = quote >= 0 ? extended.slice(quote + 2) : extended
    try {
      return decodeURIComponent(encoded)
    } catch {
      return encoded
    }
  }
  const plain = params.get(name)
  return plain === undefined ? null : decodeWords(plain)
}

// RFC 2046: 1 to 70 characters from a fixed set, not ending in a space.
const BOUNDARY = /^[0-9A-Za-z'()+_,\-./:=? ]{0,69}[0-9A-Za-z'()+_,\-./:=?]$/

type Split = { preamble: string; parts: string[]; epilogue: string }

// RFC 2046 delimiters are whole lines, ^--B(--)?[ \t]*$, after a line
// break (the break belongs to the delimiter). Boundary text anywhere else
// in a line is content. A line that starts like a delimiter but is not one,
// a delimiter after the end marker, or a missing end marker is a problem,
// because parsers split such bodies differently.
function splitMultipart(body: string, boundary: string, where: string, problems: string[]): Split | null {
  const delimiter = `--${boundary}`
  const preamble: string[] = []
  const epilogue: string[] = []
  const parts: string[][] = []
  let current = preamble
  let state: "preamble" | "parts" | "closed" = "preamble"
  for (const line of body.split(/\r?\n/)) {
    const bare = line.replace(/[ \t]+$/, "")
    if (bare === delimiter || bare === `${delimiter}--`) {
      if (state === "closed") {
        problems.push(`${where} has a boundary line after its end marker.`)
        return null
      }
      if (bare === delimiter) {
        current = []
        parts.push(current)
        state = "parts"
      } else {
        current = epilogue
        state = "closed"
      }
      continue
    }
    if (line.startsWith(delimiter)) {
      problems.push(`${where} has a line that starts like its boundary but is not one: ${JSON.stringify(line.slice(0, 80))}.`)
      return null
    }
    current.push(line)
  }
  if (state !== "closed") {
    problems.push(`${where} has no end marker (a line "--${boundary}--").`)
    return null
  }
  if (parts.length === 0) {
    problems.push(`${where} is a multipart with no parts.`)
    return null
  }
  return { preamble: preamble.join("\n"), parts: parts.map((p) => p.join("\n")), epilogue: epilogue.join("\n") }
}

type Section = ApprovalEmail["sections"][number]
type FoundAttachment = { name: string; type: string; bytes: Uint8Array; charset: string | null }
type MailContent = { sections: Section[]; attachments: FoundAttachment[]; problems: string[] }

const TRANSFER_ENCODINGS = new Set(["7bit", "8bit", "binary", "base64", "quoted-printable"])

function partLabel(where: string): string {
  return where === "The message" ? "" : `, ${where.toLowerCase()}`
}

function collectContent(part: Part, where: string, depth: number, out: MailContent): void {
  const problems = out.problems
  const typeHeader = singleHeader(part, "content-type", where, problems)
  const encodingHeader = singleHeader(part, "content-transfer-encoding", where, problems)
  const dispositionHeader = singleHeader(part, "content-disposition", where, problems)
  let type: Parameterised = { value: "text/plain", params: new Map() }
  if (typeHeader !== null) {
    const parsed = parseParameterised(typeHeader, true)
    if (typeof parsed === "string") {
      problems.push(`${where}'s Content-Type ${parsed}.`)
      return
    }
    type = parsed
  }
  const encoding = (encodingHeader ?? "7bit").trim().toLowerCase()
  if (!TRANSFER_ENCODINGS.has(encoding)) {
    problems.push(`${where} has a transfer encoding the vault does not read: ${JSON.stringify(encodingHeader)}.`)
    return
  }

  if (type.value.startsWith("multipart/")) {
    const boundary = type.params.get("boundary")
    if (depth >= MAX_MIME_DEPTH) problems.push(`${where} nests multiparts more than ${MAX_MIME_DEPTH} deep.`)
    else if (encoding === "base64" || encoding === "quoted-printable") problems.push(`${where} is a multipart with a ${encoding} encoding.`)
    else if (boundary === undefined) problems.push(`${where} is a multipart without a boundary.`)
    else if (!BOUNDARY.test(boundary)) problems.push(`${where} has a boundary that is not allowed: ${JSON.stringify(boundary)}.`)
    else {
      const split = splitMultipart(part.body, boundary, where, problems)
      if (split === null) return
      if (split.preamble.trim() !== "") {
        out.sections.push({ heading: `Text before the first part${partLabel(where)}`, note: "Most mail apps hide this, but it is sent.", text: split.preamble })
      }
      split.parts.forEach((text, i) => {
        const child = where === "The message" ? `Part ${i + 1}` : `${where}.${i + 1}`
        collectContent(parsePart(text, child, problems), child, depth + 1, out)
      })
      if (split.epilogue.trim() !== "") {
        out.sections.push({ heading: `Text after the last part${partLabel(where)}`, note: "Most mail apps hide this, but it is sent.", text: split.epilogue })
      }
    }
    return
  }

  let disposition: Parameterised = { value: "inline", params: new Map() }
  if (dispositionHeader !== null) {
    const parsed = parseParameterised(dispositionHeader, false)
    if (typeof parsed === "string") {
      problems.push(`${where}'s Content-Disposition ${parsed}.`)
      return
    }
    disposition = parsed
  }
  let bytes: Uint8Array
  if (encoding === "base64") {
    const decoded = strictBase64(part.body, true)
    if (decoded === null) {
      problems.push(`${where} is not valid base64.`)
      return
    }
    bytes = decoded
  } else if (encoding === "quoted-printable") {
    bytes = quotedPrintableBytes(part.body, false)
  } else {
    bytes = new TextEncoder().encode(part.body)
  }
  const name = fileName(disposition.params, "filename") ?? fileName(type.params, "name")
  const charset = type.params.get("charset") ?? null
  const inlineText = (type.value === "text/plain" || type.value === "text/html") && name === null && disposition.value === "inline"
  if (!inlineText) {
    out.attachments.push({ name: name ?? "(no name)", type: type.value, bytes, charset })
    return
  }
  const text = decodeCharset(bytes, charset ?? "utf-8")
  const label = partLabel(where)
  if (type.value === "text/plain") {
    out.sections.push({ heading: `Text${label}`, note: null, text })
    return
  }
  out.sections.push({
    heading: `HTML${label}, as text`,
    note: "Most mail apps show the HTML version. Tags removed, link and image addresses spelled out.",
    text: htmlToText(text),
  })
  out.sections.push({ heading: `HTML${label}, source`, note: "Shown as text, never rendered: comments, scripts, styles and attributes included.", text })
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " }

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]+);/gi, (whole, ref: string) => {
    if (ref.startsWith("#")) {
      const code = ref[1] === "x" || ref[1] === "X" ? Number.parseInt(ref.slice(2), 16) : Number.parseInt(ref.slice(1), 10)
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole
    }
    return ENTITIES[ref.toLowerCase()] ?? whole
  })
}

function attribute(tag: string, name: string): string | null {
  const match = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag)
  return match ? decodeEntities(match[1] ?? match[2] ?? match[3] ?? "") : null
}

// An HTML body as plain text: comments, scripts and styles dropped, tags
// removed, links and images spelled out with their addresses (a link's
// text can say anything, and an image address can carry data out),
// entities decoded. The result is only ever shown as text, and the card
// shows the HTML source beside it, so nothing dropped here is hidden.
export function htmlToText(source: string): string {
  return decodeEntities(
    source
      .replace(/<!--[\s\S]*?(?:-->|$)/g, "")
      .replace(/<(script|style)\b[\s\S]*?(?:<\/\1\s*>|$)/gi, "")
      .replace(/<a\b[^>]*>/gi, (tag) => {
        const href = attribute(tag, "href")
        return href === null ? "" : `[link to ${href}] `
      })
      .replace(/<img\b[^>]*>/gi, (tag) => `[image ${attribute(tag, "src") ?? "without an address"}]`)
      .replace(/<\/?(br|p|div|tr|li|ul|ol|table|blockquote|h[1-6])\b[^>]*>/gi, "\n")
      .replace(/<[^>]*(>|$)/g, ""),
  )
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} bytes`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

// An address list split at top-level commas: quoted strings, angle
// brackets and comments respected, group names ("team: a@x, b@y;") and
// comments dropped. Null when the quoting does not balance.
function splitAddresses(value: string): string[] | null {
  const out: string[] = []
  let current = ""
  let quoted = false
  let angle = 0
  let comment = 0
  for (let i = 0; i < value.length; i++) {
    const c = value[i] as string
    if ((quoted || comment > 0) && c === "\\") {
      if (quoted) current += c + (value[i + 1] ?? "")
      i++
      continue
    }
    if (quoted) {
      current += c
      if (c === '"') quoted = false
      continue
    }
    if (comment > 0) {
      if (c === "(") comment++
      else if (c === ")") comment--
      continue
    }
    if (c === "(") comment++
    else if (c === '"') {
      quoted = true
      current += c
    } else if (c === "<") {
      angle++
      current += c
    } else if (c === ">") {
      angle--
      current += c
    } else if (angle === 0 && (c === "," || c === ";")) {
      out.push(current)
      current = ""
    } else if (angle === 0 && c === ":") {
      current = ""
    } else {
      current += c
    }
  }
  if (quoted || angle !== 0 || comment !== 0) return null
  out.push(current)
  return out.map((a) => a.trim()).filter((a) => a !== "")
}

const ADDRESS = /^[^\s@<>()",;:\\]+@([^\s@<>()",;:\\]+)$/

function domainOf(address: string): string | null {
  const match = ADDRESS.exec(address)
  return match ? (match[1] as string).toLowerCase().replace(/\.$/, "") : null
}

const RECIPIENT_HEADERS: Record<string, string> = { to: "To", cc: "Cc", bcc: "Bcc" }
const HIGHLIGHTED_HEADERS = new Set(["to", "cc", "bcc", "reply-to", "from"])
// Headers a message may carry once; mail apps disagree on which copy wins.
const ONCE_HEADERS = ["from", "sender", "reply-to", "to", "cc", "bcc", "subject", "date", "message-id", "in-reply-to", "references", "mime-version"]

function recipientsOf(top: Part, accountDomain: string | null, problems: string[]): ApprovalEmail["recipients"] {
  const recipients: ApprovalEmail["recipients"] = []
  for (const h of top.headers) {
    const label = RECIPIENT_HEADERS[h.name.toLowerCase()]
    if (label === undefined) continue
    const entries = splitAddresses(h.value)
    if (entries === null) {
      problems.push(`The ${label} header cannot be read as a list of addresses.`)
      recipients.push({ header: label, address: decodeWords(h.value), external: true })
      continue
    }
    for (const entry of entries) {
      const angles = entry.replace(/"(?:[^"\\]|\\.)*"/g, "").split("<").length - 1
      const address = angles === 1 ? (/<([^<>]*)>\s*$/.exec(entry)?.[1]?.trim() ?? "") : entry
      const domain = angles > 1 ? null : domainOf(address)
      if (domain === null) problems.push(`The ${label} header has a recipient the vault cannot read: ${JSON.stringify(entry.slice(0, 80))}.`)
      recipients.push({ header: label, address: domain === null ? decodeWords(entry) : address, external: accountDomain === null || domain !== accountDomain })
    }
  }
  return recipients
}

async function hex(bytes: Uint8Array): Promise<string> {
  return [...(await sha256(new Uint8Array(bytes)))].map((b) => b.toString(16).padStart(2, "0")).join("")
}

async function presentAttachment(a: FoundAttachment): Promise<ApprovalEmail["attachments"][number]> {
  const declaredText = a.type.startsWith("text/") || a.type === "application/json" || a.type === "application/xml"
  const text = declaredText ? decodeCharset(a.bytes, a.charset ?? "utf-8") : a.bytes.length < INLINE_ATTACHMENT_BYTES ? strictUtf8(a.bytes) : null
  return { name: a.name, type: a.type, bytes: a.bytes.length, text, sha256: text === null ? await hex(a.bytes) : null }
}

type EmailRequest = {
  // Problems found before the message was parsed (its encoding in the request).
  problems: string[]
  // The request's other fields, pretty-printed, when it has any; the whole
  // request as sent when formatting would change a number in it.
  otherFields: { text: string; note: string } | null
}

async function emailPresentation(bytes: Uint8Array, account: string | null, request: EmailRequest): Promise<ApprovalPresentation> {
  const problems = [...request.problems]
  const strict = strictUtf8(bytes)
  if (strict === null) problems.push("The message has bytes that are not UTF-8; they show as \uFFFD.")
  const source = strict ?? lenient.decode(bytes)
  if (/\r(?!\n)/.test(source)) problems.push("The message has a carriage return that does not end a line.")

  const top = parsePart(source, "The message", problems)
  for (const name of ONCE_HEADERS) {
    const count = headerValues(top, name).length
    if (count > 1) problems.push(`The message has ${count} ${name} headers.`)
  }
  const domain = account?.includes("@") ? (account.split("@").pop() as string).toLowerCase() : null
  const recipients = recipientsOf(top, domain, problems)
  const content: MailContent = { sections: [], attachments: [], problems }
  collectContent(top, "The message", 0, content)

  const readable = problems.length === 0
  const sections = readable ? content.sections : []
  if (request.otherFields !== null) sections.push({ heading: "Other fields in the request", ...request.otherFields })
  const attachments = readable ? await Promise.all(content.attachments.map(presentAttachment)) : []

  const warnings = readable ? [] : [UNREADABLE_WARNING, ...new Set(problems)]
  const details: ApprovalPresentation["details"] = []
  if (account !== null) details.push({ label: "From account", value: account })
  for (const a of attachments) details.push({ label: "Attachment", value: `${a.name} (${a.type}, ${formatBytes(a.bytes)})` })
  const email: ApprovalEmail = {
    recipients,
    accountDomain: domain,
    headers: top.headers.map((h) => ({ name: h.name, value: decodeWords(h.value), highlight: HIGHLIGHTED_HEADERS.has(h.name.toLowerCase()) })),
    sections,
    attachments,
  }
  return { title: "Send an email", details, body: source, warnings, email }
}

export function describeEmail(message: string, account: string | null): Promise<ApprovalPresentation> {
  return emailPresentation(new TextEncoder().encode(message), account, { problems: [], otherFields: null })
}

const GMAIL_SEND = "/gmail/v1/users/*/messages/send"
const GMAIL_UPLOAD_SEND = "/upload/gmail/v1/users/*/messages/send"

// A Gmail messages.send as an email, when the request carries the whole
// message: {"raw": ...} in JSON, or the RFC 822 bytes of a media upload or
// of a resumable upload's PUT. Anything else is shown as a request.
async function gmailSend(item: ItemRecord, dest: Destination, url: URL, body: Uint8Array | null, contentType: string | null): Promise<ApprovalPresentation | null> {
  if (item.provider !== "google-gmail" || body === null) return null
  const path = dest.path.toLowerCase()
  if (pathMatches(GMAIL_UPLOAD_SEND, path)) {
    const uploadType = url.searchParams.get("uploadType")
    const whole = (dest.method === "POST" && uploadType === "media") || (dest.method === "PUT" && uploadType === "resumable")
    return whole ? emailPresentation(body, item.account, { problems: [], otherFields: null }) : null
  }
  if (dest.method !== "POST" || !pathMatches(GMAIL_SEND, path)) return null
  const text = lenient.decode(body)
  const parsed = parseJsonStrictly(text)
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) return null
  const { raw, ...rest } = parsed.value as Record<string, unknown>
  if (typeof raw !== "string") return null
  const otherFields =
    Object.keys(rest).length === 0
      ? null
      : numbersFormatAsSent(text)
        ? { text: JSON.stringify(rest, null, 2), note: "Sent to Gmail with the message." }
        : { text, note: "Sent to Gmail with the message. One has a number that formatting would change, so the whole request is shown exactly as sent." }
  const bytes = strictBase64(raw, false)
  if (bytes === null) {
    const plain = presentGeneric(item, dest, url, body, contentType)
    return { ...plain, warnings: ["This is an email, but its raw field is not clean base64url, so the vault cannot show the message. Deny it."] }
  }
  return emailPresentation(bytes, item.account, { problems: [], otherFields })
}

function mediaType(contentType: string | null): string {
  return (contentType?.split(";")[0] ?? "").trim().toLowerCase()
}

function formKey(key: string): string {
  return /^[A-Za-z0-9_.\-[\]]+$/.test(key) ? key : JSON.stringify(key)
}

// Every number in valid JSON text formats back to the very token sent. A
// string token is matched whole, so digits inside one are never read as a
// number. One that does not (an integer above 2^53, or one spelled 1.0, -0
// or 1E3) would show a number other than the one sent.
function numbersFormatAsSent(text: string): boolean {
  for (const [token] of text.matchAll(/"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g)) {
    if (!token.startsWith('"') && JSON.stringify(Number(token)) !== token) return false
  }
  return true
}

// The body as the upstream will read it, by its declared content type.
// JSON is pretty-printed from what was parsed; JSON with a repeated key is
// shown as sent, since parsers disagree on which copy wins, and so is JSON
// with a number formatting would change. A form is one field per line with
// each value quoted, so a value holding a line break cannot pass for
// another field.
export function presentBody(body: Uint8Array | null, contentType: string | null): { text: string | null; note: string | null } {
  if (body === null || body.length === 0) return { text: null, note: null }
  const text = strictUtf8(body)
  if (text === null) return { text: `(${formatBytes(body.length)} of binary data, which cannot be shown)`, note: "Binary data the vault cannot show" }
  const type = mediaType(contentType)
  if (type === "application/json" || type.endsWith("+json")) {
    const parsed = parseJsonStrictly(text)
    if (parsed.ok && !numbersFormatAsSent(text)) return { text, note: "JSON with a number that formatting would change, so it is shown exactly as sent" }
    if (parsed.ok) return { text: JSON.stringify(parsed.value, null, 2), note: null }
    return { text, note: "Not valid JSON, or JSON with a repeated key, so it is shown exactly as sent" }
  }
  if (type === "application/x-www-form-urlencoded") {
    const lines = [...new URLSearchParams(text)].map(([k, v]) => `${formKey(k)} = ${JSON.stringify(v)}`)
    return { text: lines.length > 0 ? lines.join("\n") : text, note: null }
  }
  return { text, note: null }
}

function presentGeneric(item: ItemRecord, dest: Destination, url: URL, body: Uint8Array | null, contentType: string | null): ApprovalPresentation {
  const details: ApprovalPresentation["details"] = [{ label: "Credential", value: item.account ? `${item.slug} (${item.account})` : item.slug }]
  details.push({ label: "Request", value: `${dest.method} ${dest.host}${dest.path}` })
  if (url.search !== "") details.push({ label: "Query", value: url.search.slice(1) })
  const shown = presentBody(body, contentType)
  if (shown.note !== null) details.push({ label: "Body", value: shown.note })
  return { title: `${dest.method} ${dest.host}${dest.path}`, details, body: shown.text }
}

// The spelling of hidden and control characters lives in spelling.ts (pure,
// shared with the browser bundle) and is re-exported here.
export {
  CONTROL_WARNING,
  type CardTextSegment,
  DECEPTIVE_MARKER,
  DECEPTIVE_WARNING,
  escapeDeceptiveJson,
  spellCardSegments,
  spellCardText,
  spellControls,
  spellDeceptive,
  textWarnings,
} from "./spelling.ts"

// Every string the card renders, passed through `f`: one list, so the
// checks below and the spelling-out cannot miss a part the page shows. The
// approval page uses it too, on the stored view, so a card that was not
// built here (a protected run's) is checked and spelled the same way.
export function mapCardText(card: ApprovalPresentation, f: (text: string) => string): ApprovalPresentation {
  const email = card.email
  return {
    ...card,
    title: f(card.title),
    details: card.details.map((d) => ({ label: f(d.label), value: f(d.value) })),
    body: card.body === null ? null : f(card.body),
    ...(card.warnings !== undefined ? { warnings: card.warnings.map(f) } : {}),
    ...(card.headers !== undefined ? { headers: card.headers.map(([name, value]): [string, string] => [f(name), f(value)]) } : {}),
    ...(email !== undefined
      ? {
          email: {
            recipients: email.recipients.map((r) => ({ ...r, header: f(r.header), address: f(r.address) })),
            accountDomain: email.accountDomain === null ? null : f(email.accountDomain),
            headers: email.headers.map((h) => ({ ...h, name: f(h.name), value: f(h.value) })),
            sections: email.sections.map((s) => ({ heading: f(s.heading), note: s.note === null ? null : f(s.note), text: f(s.text) })),
            attachments: email.attachments.map((a) => ({ ...a, name: f(a.name), type: f(a.type), text: a.text === null ? null : f(a.text) })),
          },
        }
      : {}),
  }
}

// `headers` are the ones forwarded from the agent, as relay.ts binds them.
export async function presentRequest(
  item: ItemRecord,
  dest: Destination,
  url: URL,
  body: Uint8Array | null,
  contentType: string | null,
  headers: [string, string][],
): Promise<ApprovalPresentation> {
  const shown = (await gmailSend(item, dest, url, body, contentType)) ?? presentGeneric(item, dest, url, body, contentType)
  const card: ApprovalPresentation = { ...shown, headers }
  const texts: string[] = [url.href]
  mapCardText(card, (text) => {
    texts.push(text)
    return text
  })
  const added = textWarnings(texts)
  if (added.length === 0) return card
  // The forwarded headers stay as sent: the page's boot payload carries them
  // and the browser recomputes headersSha256 over them before Approve
  // appears. The page spells them when it shows them (spellCardText).
  const spelled = mapCardText(card, spellCardText)
  return { ...spelled, headers, warnings: [...added, ...(spelled.warnings ?? [])] }
}
