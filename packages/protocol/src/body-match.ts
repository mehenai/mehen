// Policy rules that look at a request's body and query string, not only its
// method and path. Templates stay data: a rule names a matcher and this
// module decides. Every matcher fails closed, in the direction of its rule:
//   - "graphql-mutation" goes on deny and approve rules and matches anything
//     it cannot prove is a plain query, so the rule still applies;
//   - "graphql-query" is the only matcher an allow rule may carry, and it
//     matches only a request it can prove is a single plain query;
//   - the JSON field matchers ("json-remote-mcp", "json-webhook",
//     "json-public-url") go on
//     deny and approve rules and match a body that is not one strict JSON
//     object, or that names a field the matcher lists (JSON_FIELD_MATCHERS),
//     so an allow on the same route applies only to bodies proved not to.
// See ruleMatches in binding.ts for how a rule uses them.
// graphqlMutationRootFields, at the end, is the stricter proof a standing
// rule (policy-rules.ts) needs: the root fields of exactly one mutation and
// the real names of every field below them.
//
// No dependencies, so the browser bundle and the CLI can use it.

export const BODY_MATCHERS = ["graphql-mutation", "graphql-query", "json-remote-mcp", "json-webhook", "json-public-url"] as const

export type BodyMatcher = (typeof BODY_MATCHERS)[number]

// The matchers an allow rule may carry.
export const ALLOW_BODY_MATCHERS: readonly BodyMatcher[] = ["graphql-query"]

// `search` is the URL's query string as sent ("?a=b", or "" for none). A
// GraphQL server may read the operation from the URL instead of the body
// (or let the URL override it), so any query string on a GraphQL request
// counts as a possible mutation and never as a plain query.
export function bodyMatches(matcher: BodyMatcher, body: Uint8Array | null, search: string): boolean {
  switch (matcher) {
    case "graphql-mutation":
      return search !== "" || graphqlMayMutate(body)
    case "graphql-query":
      return search === "" && graphqlIsQuery(body)
    case "json-remote-mcp":
    case "json-webhook":
    case "json-public-url":
      return jsonNamesField(matcher, body)
  }
}

// The fields each JSON field matcher looks for, in a body already read as
// one JSON object. Keys compare without regard to case, since some JSON
// decoders (Go's encoding/json among them) match a key to a field that way.
type JsonFieldMatcher = Extract<BodyMatcher, `json-${string}`>
type JsonObject = Record<string, unknown>
const JSON_FIELD_DEPTH = 64

const keyIs = (key: string, name: string): boolean => key.toLowerCase() === name

// An object anywhere in the value, at most JSON_FIELD_DEPTH deep, for which
// the test holds; anything deeper counts as holding it.
function someObject(value: unknown, test: (object: JsonObject) => boolean, depth = 0): boolean {
  if (depth > JSON_FIELD_DEPTH) return true
  if (Array.isArray(value)) return value.some((v) => someObject(v, test, depth + 1))
  if (typeof value !== "object" || value === null) return false
  const object = value as JsonObject
  return test(object) || Object.values(object).some((v) => someObject(v, test, depth + 1))
}

const JSON_FIELD_MATCHERS: Record<JsonFieldMatcher, (body: JsonObject) => boolean> = {
  // A remote MCP server the provider would call itself, with whatever the
  // request hands it: any object, at any depth (a batch nests whole
  // requests), whose "type" is "mcp" or that has a "server_url".
  "json-remote-mcp": (body) =>
    someObject(body, (object) => Object.entries(object).some(([key, value]) => (keyIs(key, "type") && typeof value === "string" && value.toLowerCase() === "mcp") || keyIs(key, "server_url"))),
  // A URL the provider would send the result to: a top-level "webhook".
  "json-webhook": (body) => Object.keys(body).some((key) => keyIs(key, "webhook")),
  // Storage options that publish the output at a permanent unauthenticated
  // URL: at any depth (a batch nests whole requests), a "storage_options"
  // that is not an object, or whose "public_url" is anything but false.
  "json-public-url": (body) =>
    someObject(body, (object) =>
      Object.entries(object).some(([key, value]) => {
        if (!keyIs(key, "storage_options")) return false
        if (typeof value !== "object" || value === null || Array.isArray(value)) return true
        return Object.entries(value as JsonObject).some(([k, v]) => keyIs(k, "public_url") && v !== false)
      }),
    ),
}

// True unless the body is one strict JSON object (UTF-8, no byte order
// mark, no repeated key) that names none of the matcher's fields.
function jsonNamesField(matcher: JsonFieldMatcher, body: Uint8Array | null): boolean {
  if (body === null || body.length === 0) return true
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body)
  } catch {
    return true
  }
  const parsed = parseJsonStrictly(text)
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) return true
  return JSON_FIELD_MATCHERS[matcher](parsed.value as JsonObject)
}

// JSON.parse, but a document with a repeated key in any object is refused:
// parsers disagree on which copy wins, so what one shows another may not run.
export function parseJsonStrictly(text: string): { ok: true; value: unknown } | { ok: false } {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return { ok: false }
  }
  return hasRepeatedKey(text) ? { ok: false } : { ok: true, value }
}

// Only called on text JSON.parse accepted, so a plain scan is exact.
function hasRepeatedKey(text: string): boolean {
  const objects: (Set<string> | null)[] = []
  let i = 0
  while (i < text.length) {
    const c = text.charAt(i)
    if (c === '"') {
      const end = jsonStringEnd(text, i)
      const raw = text.slice(i, end)
      i = end
      let j = i
      while (j < text.length && " \t\n\r".includes(text.charAt(j))) j++
      const keys = objects[objects.length - 1]
      if (text.charAt(j) === ":" && keys) {
        const key = JSON.parse(raw) as string
        if (keys.has(key)) return true
        keys.add(key)
      }
      continue
    }
    if (c === "{") objects.push(new Set())
    else if (c === "[") objects.push(null)
    else if (c === "}" || c === "]") objects.pop()
    i++
  }
  return false
}

function jsonStringEnd(text: string, start: number): number {
  let i = start + 1
  while (i < text.length) {
    const c = text.charAt(i)
    if (c === "\\") i += 2
    else if (c === '"') return i + 1
    else i++
  }
  return text.length
}

// True unless the body is a GraphQL-over-HTTP JSON request whose query
// document, read in full, holds no mutation or subscription. An empty or
// non-UTF-8 body, invalid JSON, a repeated key, a batch (an array), or a
// missing or unreadable query all count as a mutation.
export function graphqlMayMutate(body: Uint8Array | null): boolean {
  const request = graphqlRequestOf(body)
  if (request === null) return true
  const query = request.query
  if (typeof query !== "string") return true
  return graphqlDocumentMayMutate(query)
}

// True only for a GraphQL-over-HTTP JSON request that holds nothing but
// "query", and optionally "variables" (an object or null) and
// "operationName" (a string or null), whose document is exactly one plain
// query operation. Persisted-query keys ("extensions", "id", "documentId")
// or any other key, and everything graphqlMayMutate flags, are not a query.
export function graphqlIsQuery(body: Uint8Array | null): boolean {
  const request = graphqlRequestOf(body)
  if (request === null) return false
  for (const key of Object.keys(request)) if (key !== "query" && key !== "variables" && key !== "operationName") return false
  const { query, variables, operationName } = request
  if (typeof query !== "string") return false
  if (variables !== undefined && variables !== null && (typeof variables !== "object" || Array.isArray(variables))) return false
  if (operationName !== undefined && operationName !== null && typeof operationName !== "string") return false
  return graphqlDocumentIsQuery(query)
}

// The JSON object of a GraphQL-over-HTTP request; null for an empty or
// non-UTF-8 body, a byte order mark, invalid JSON, a repeated key or
// anything but one object (a batch is an array).
function graphqlRequestOf(body: Uint8Array | null): Record<string, unknown> | null {
  if (body === null || body.length === 0) return null
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body)
  } catch {
    return null
  }
  const parsed = parseJsonStrictly(text)
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) return null
  return parsed.value as Record<string, unknown>
}

const NAME_START = /[_A-Za-z]/
const NAME_CONTINUE = /[_0-9A-Za-z]/

// A small GraphQL lexer (October 2021 spec, section 2.1): skips ignored
// tokens, comments and strings, tracks nesting, and reports any top-level
// name "mutation" or "subscription". An operation or fragment that happens
// to be named that way counts too, which only ever asks for an approval.
// Unbalanced brackets, an unterminated string, or no definition at all
// count as a mutation.
export function graphqlDocumentMayMutate(doc: string): boolean {
  let depth = 0
  let definitions = 0
  let i = 0
  while (i < doc.length) {
    const c = doc.charAt(i)
    if (isIgnored(c)) {
      i++
      continue
    }
    if (c === "#") {
      while (i < doc.length && doc.charAt(i) !== "\n" && doc.charAt(i) !== "\r") i++
      continue
    }
    if (c === '"') {
      const end = doc.startsWith('"""', i) ? blockStringEnd(doc, i + 3) : stringEnd(doc, i + 1)
      if (end < 0) return true
      i = end
      continue
    }
    if (c === "{" || c === "(" || c === "[") {
      if (depth === 0 && c === "{") definitions++
      depth++
      i++
      continue
    }
    if (c === "}" || c === ")" || c === "]") {
      depth--
      if (depth < 0) return true
      i++
      continue
    }
    if (NAME_START.test(c)) {
      let j = i + 1
      while (j < doc.length && NAME_CONTINUE.test(doc.charAt(j))) j++
      const name = doc.slice(i, j)
      if (depth === 0 && (name === "mutation" || name === "subscription")) return true
      i = j
      continue
    }
    i++
  }
  return depth !== 0 || definitions === 0
}

function isIgnored(c: string): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r" || c === "," || c === "\uFEFF"
}

const CLOSER: Record<string, string> = { "}": "{", ")": "(", "]": "[" }

// Stricter than graphqlDocumentMayMutate, which it runs first: the document
// must be exactly one query operation ("{ ... }" or "query Name($v: T) {
// ... }") plus any number of fragment definitions, with matching brackets.
// At the top level only names, a variable list after "query", and selection
// sets may appear: a string, a number, a directive or any other punctuation
// there is doubtful, so the document is not a query.
export function graphqlDocumentIsQuery(doc: string): boolean {
  if (graphqlDocumentMayMutate(doc)) return false
  const open: string[] = []
  let operations = 0
  // At the top level, between definitions; otherwise inside a definition's
  // header (after "query" or "fragment", before its selection set).
  let betweenDefinitions = true
  let i = 0
  while (i < doc.length) {
    const c = doc.charAt(i)
    if (isIgnored(c)) {
      i++
      continue
    }
    if (c === "#") {
      while (i < doc.length && doc.charAt(i) !== "\n" && doc.charAt(i) !== "\r") i++
      continue
    }
    const top = open.length === 0
    if (c === '"') {
      if (top) return false
      const end = doc.startsWith('"""', i) ? blockStringEnd(doc, i + 3) : stringEnd(doc, i + 1)
      if (end < 0) return false
      i = end
      continue
    }
    if (c === "{" || c === "(" || c === "[") {
      if (top) {
        if (c === "[") return false
        if (c === "(" && betweenDefinitions) return false
        if (c === "{" && betweenDefinitions) operations++
        if (c === "{") betweenDefinitions = false
      }
      open.push(c)
      i++
      continue
    }
    if (c === "}" || c === ")" || c === "]") {
      if (open.pop() !== CLOSER[c]) return false
      if (open.length === 0 && c === "}") betweenDefinitions = true
      i++
      continue
    }
    if (NAME_START.test(c)) {
      let j = i + 1
      while (j < doc.length && NAME_CONTINUE.test(doc.charAt(j))) j++
      if (top && betweenDefinitions) {
        const keyword = doc.slice(i, j)
        if (keyword === "query") operations++
        else if (keyword !== "fragment") return false
        betweenDefinitions = false
      }
      i = j
      continue
    }
    if (top) return false
    i++
  }
  return open.length === 0 && betweenDefinitions && operations === 1
}

// The index after the closing quote, or -1 when the string never ends on
// its line.
function stringEnd(doc: string, from: number): number {
  let i = from
  while (i < doc.length) {
    const c = doc.charAt(i)
    if (c === "\n" || c === "\r") return -1
    if (c === "\\") i += 2
    else if (c === '"') return i + 1
    else i++
  }
  return -1
}

function blockStringEnd(doc: string, from: number): number {
  let i = from
  while (i < doc.length) {
    if (doc.startsWith('\\"""', i)) i += 4
    else if (doc.startsWith('"""', i)) return i + 3
    else i++
  }
  return -1
}

// Why graphqlMutationRootFields refused a body: "body" for anything but one
// JSON object of query, variables and operationName; "batch" for an array;
// "parse" for any doubt the parser has about the document.
export type GraphqlMutationRefusal = "body" | "batch" | "query" | "subscription" | "fragment" | "alias" | "argument" | "directive" | "operations" | "operation-name" | "repeated-field" | "parse"
export type GraphqlMutationProof = { ok: true; fields: string[]; nestedFields: string[]; operationName: string | null } | { ok: false; reason: GraphqlMutationRefusal }

// The root fields of a GraphQL-over-HTTP JSON request that is exactly one
// mutation operation, in document order, the real name (never the alias) of
// every field below them, in document order, and the operation's name. A
// standing rule names those fields, so anything that could make a server run
// a field the list does not show is refused: a second operation or any
// fragment (named or inline, at any depth), an alias or a directive at the
// root (on the operation, a variable or a root field), an argument or a
// directive below the root field (an API that nests its mutations, as in
// "project { delete(id: 1) }", would run one the list does not name), a
// query or subscription, a batch, persisted-query keys, an operationName
// that is not the operation's own, a root field named twice, and anything
// the tokeniser or parser cannot read. The root fields' arguments and the
// variables are free.
export function graphqlMutationRootFields(body: Uint8Array | null): GraphqlMutationProof {
  const refused = (reason: GraphqlMutationRefusal): GraphqlMutationProof => ({ ok: false, reason })
  if (body === null || body.length === 0) return refused("body")
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body)
  } catch {
    return refused("body")
  }
  const parsed = parseJsonStrictly(text)
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) return refused("body")
  if (Array.isArray(parsed.value)) return refused("batch")
  const request = parsed.value as Record<string, unknown>
  for (const key of Object.keys(request)) if (key !== "query" && key !== "variables" && key !== "operationName") return refused("body")
  const { query, variables, operationName } = request
  if (typeof query !== "string") return refused("body")
  if (variables !== undefined && variables !== null && (typeof variables !== "object" || Array.isArray(variables))) return refused("body")
  if (operationName !== undefined && operationName !== null && typeof operationName !== "string") return refused("body")
  const tokens = graphqlTokens(query)
  if (tokens === null) return refused("parse")
  const operation = parseMutationOperation(tokens)
  if (!operation.ok) return operation
  if (typeof operationName === "string" && operationName !== operation.operationName) return refused("operation-name")
  return operation
}

type GraphqlToken = { kind: "punctuator" | "name"; value: string } | { kind: "value"; value: "int" | "float" | "string" }

// Selections and values nest no deeper than this; deeper is doubt.
const GRAPHQL_MAX_DEPTH = 64

// The lexical tokens of a document (October 2021 spec, section 2.1), with
// ignored tokens and comments dropped; null for any character, escape or
// number the spec does not allow, and for "&" and "|", which only type
// definitions use. Stricter than the spec where servers may disagree on
// where a comment or line ends: a comment holds only tab and printable
// ASCII, and a byte order mark is refused outside strings (as U+2028 and
// U+2029 are, being non-ASCII).
function graphqlTokens(doc: string): GraphqlToken[] | null {
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(doc)) return null
  const tokens: GraphqlToken[] = []
  let i = 0
  while (i < doc.length) {
    const c = doc.charAt(i)
    if (c === "\uFEFF") {
      return null
    } else if (isIgnored(c)) {
      i++
    } else if (c === "#") {
      while (i < doc.length && doc.charAt(i) !== "\n" && doc.charAt(i) !== "\r") {
        if (!/[\t\x20-\x7e]/.test(doc.charAt(i))) return null
        i++
      }
    } else if ("!$():=@[]{}".includes(c)) {
      tokens.push({ kind: "punctuator", value: c })
      i++
    } else if (c === ".") {
      if (!doc.startsWith("...", i)) return null
      tokens.push({ kind: "punctuator", value: "..." })
      i += 3
    } else if (NAME_START.test(c)) {
      let j = i + 1
      while (j < doc.length && NAME_CONTINUE.test(doc.charAt(j))) j++
      tokens.push({ kind: "name", value: doc.slice(i, j) })
      i = j
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      const number = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(doc.slice(i))
      if (number === null) return null
      const end = i + number[0].length
      const next = doc.charAt(end)
      if (next === "." || NAME_START.test(next) || (next >= "0" && next <= "9")) return null
      tokens.push({ kind: "value", value: number[1] !== undefined || number[2] !== undefined ? "float" : "int" })
      i = end
    } else if (c === '"') {
      const end = doc.startsWith('"""', i) ? blockStringEnd(doc, i + 3) : strictStringEnd(doc, i + 1)
      if (end < 0) return null
      tokens.push({ kind: "value", value: "string" })
      i = end
    } else {
      return null
    }
  }
  return tokens
}

// As stringEnd, but an escape the spec does not define is unreadable too.
function strictStringEnd(doc: string, from: number): number {
  let i = from
  while (i < doc.length) {
    const c = doc.charAt(i)
    if (c === "\n" || c === "\r") return -1
    if (c === '"') return i + 1
    if (c !== "\\") {
      i++
      continue
    }
    const escape = /^\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}|u\{[0-9A-Fa-f]{1,6}\})/.exec(doc.slice(i, i + 10))
    if (escape === null) return -1
    i += escape[0].length
  }
  return -1
}

type MutationParse = { ok: true; fields: string[]; nestedFields: string[]; operationName: string | null } | { ok: false; reason: GraphqlMutationRefusal }

// mutation Name? VariableDefinitions? SelectionSet, and nothing after it.
function parseMutationOperation(tokens: GraphqlToken[]): MutationParse {
  const refused = (reason: GraphqlMutationRefusal): MutationParse => ({ ok: false, reason })
  let i = 0
  const at = (kind: GraphqlToken["kind"], value?: string): boolean => {
    const token = tokens[i]
    return token !== undefined && token.kind === kind && (value === undefined || token.value === value)
  }
  const first = tokens[0]
  if (first === undefined) return refused("parse")
  if (first.kind === "punctuator" && first.value === "{") return refused("query")
  if (first.kind !== "name") return refused("parse")
  if (first.value === "query") return refused("query")
  if (first.value === "subscription") return refused("subscription")
  if (first.value === "fragment") return refused("fragment")
  if (first.value !== "mutation") return refused("parse")
  i = 1
  let operationName: string | null = null
  if (at("name")) operationName = tokens[i++]?.value ?? null

  // Anything that refuses below this point; "parse" when the shape is wrong.
  let refusal: GraphqlMutationRefusal | null = null
  const fail = (reason: GraphqlMutationRefusal): false => {
    refusal ??= reason
    return false
  }
  const expect = (value: string): boolean => (at("punctuator", value) ? (i++, true) : fail("parse"))
  const name = (): boolean => (at("name") ? (i++, true) : fail("parse"))
  const fieldName = (): string | null => {
    const token = tokens[i]
    return name() && token !== undefined ? token.value : null
  }

  const value = (depth: number, constant: boolean): boolean => {
    if (depth > GRAPHQL_MAX_DEPTH) return fail("parse")
    if (at("punctuator", "$")) return !constant ? (i++, name()) : fail("parse")
    if (at("value") || at("name")) return (i++, true)
    if (at("punctuator", "[")) {
      i++
      while (!at("punctuator", "]")) if (!value(depth + 1, constant)) return false
      return expect("]")
    }
    if (at("punctuator", "{")) {
      i++
      while (!at("punctuator", "}")) if (!name() || !expect(":") || !value(depth + 1, constant)) return false
      return expect("}")
    }
    return fail("parse")
  }
  const args = (depth: number): boolean => {
    if (!at("punctuator", "(")) return true
    i++
    if (at("punctuator", ")")) return fail("parse")
    while (!at("punctuator", ")")) if (!name() || !expect(":") || !value(depth, false)) return false
    return expect(")")
  }
  const type = (depth: number): boolean => {
    if (depth > GRAPHQL_MAX_DEPTH) return fail("parse")
    if (at("punctuator", "[")) {
      i++
      if (!type(depth + 1) || !expect("]")) return false
    } else if (!name()) {
      return false
    }
    if (at("punctuator", "!")) i++
    return true
  }
  // A nested selection set: aliases are fine below the root; arguments,
  // directives and fragments are not.
  const nestedFields: string[] = []
  const selectionSet = (depth: number): boolean => {
    if (depth > GRAPHQL_MAX_DEPTH) return fail("parse")
    if (!expect("{")) return false
    if (at("punctuator", "}")) return fail("parse")
    while (!at("punctuator", "}")) {
      if (at("punctuator", "...")) return fail("fragment")
      let field = fieldName()
      if (field !== null && at("punctuator", ":")) {
        i++
        field = fieldName()
      }
      if (field === null) return false
      nestedFields.push(field)
      if (at("punctuator", "(")) return fail("argument")
      if (at("punctuator", "@")) return fail("directive")
      if (at("punctuator", "{") && !selectionSet(depth + 1)) return false
    }
    return expect("}")
  }

  if (at("punctuator", "(")) {
    i++
    if (at("punctuator", ")")) return refused("parse")
    while (!at("punctuator", ")")) {
      if (!expect("$") || !name() || !expect(":") || !type(1)) return refused(refusal ?? "parse")
      if (at("punctuator", "=")) {
        i++
        if (!value(1, true)) return refused(refusal ?? "parse")
      }
      if (at("punctuator", "@")) return refused("directive")
    }
    i++
  }
  if (at("punctuator", "@")) return refused("directive")
  if (!at("punctuator", "{")) return refused("parse")
  i++
  if (at("punctuator", "}")) return refused("parse")
  const fields: string[] = []
  while (!at("punctuator", "}")) {
    if (at("punctuator", "...")) return refused("fragment")
    const field = tokens[i]
    if (field === undefined || field.kind !== "name") return refused("parse")
    i++
    if (at("punctuator", ":")) return refused("alias")
    if (!args(1)) return refused(refusal ?? "parse")
    if (at("punctuator", "@")) return refused("directive")
    if (at("punctuator", "{") && !selectionSet(1)) return refused(refusal ?? "parse")
    if (fields.includes(field.value)) return refused("repeated-field")
    fields.push(field.value)
  }
  i++
  const rest = tokens[i]
  if (rest !== undefined) return refused(rest.kind === "name" && rest.value === "fragment" ? "fragment" : "operations")
  return { ok: true, fields, nestedFields, operationName }
}

// One part of a multipart/form-data body: its name, its filename if it has
// one, its media type (lower case, no parameters) if it declares one, and
// its bytes.
export type FormDataPart = { name: string; filename: string | null; contentType: string | null; body: Uint8Array }

const FORM_BOUNDARY = /^[0-9A-Za-z'()+_\-./:=?]{1,70}$/
const HEADER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
// A quoted value with no escapes and no control characters, or a token,
// with only spaces and tabs as white space (RFC 9110's OWS), so no
// non-breaking space, vertical tab or form feed that \s or trim() would
// take reads as a separator.
const PARAMETER = /^[ \t]*;[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)=("[\x20\x21\x23-\x5b\x5d-\x7e]*"|[!#$%&'*+.^_`|~0-9A-Za-z-]+)/
const OWS = /^[ \t]*$/
// Spaces and tabs off both ends, by index rather than a regular expression,
// whose trailing run would cost quadratic time on a long line of spaces.
function trimOws(text: string): string {
  let start = 0
  let end = text.length
  while (start < end && (text[start] === " " || text[start] === "\t")) start++
  while (end > start && (text[end - 1] === " " || text[end - 1] === "\t")) end--
  return text.slice(start, end)
}

// The parameters after a header's first value, lower-cased names to values
// with their quotes taken off; null for anything this does not read exactly:
// a repeated name, an extended name ("name*", RFC 2231 or 5987), an escape
// in a quoted value, or anything left over.
function headerParameters(rest: string): Map<string, string> | null {
  const parameters = new Map<string, string>()
  let left = rest
  while (!OWS.test(left)) {
    const match = PARAMETER.exec(left)
    if (match === null) return null
    const name = (match[1] ?? "").toLowerCase()
    const raw = match[2] ?? ""
    if (name.includes("*") || parameters.has(name)) return null
    parameters.set(name, raw.startsWith('"') ? raw.slice(1, -1) : raw)
    left = left.slice(match[0].length)
  }
  return parameters
}

// The first occurrence of needle in haystack at or after from, or -1, by
// Knuth, Morris and Pratt: linear in the bytes searched whatever they hold,
// so no body can make a search compare the whole needle at every byte.
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  const fallback = new Int32Array(needle.length)
  for (let i = 1, k = 0; i < needle.length; i++) {
    while (k > 0 && needle[i] !== needle[k]) k = fallback[k - 1] as number
    if (needle[i] === needle[k]) k++
    fallback[i] = k
  }
  for (let i = from, k = 0; i < haystack.length; i++) {
    while (k > 0 && haystack[i] !== needle[k]) k = fallback[k - 1] as number
    if (haystack[i] === needle[k]) k++
    if (k === needle.length) return i - needle.length + 1
  }
  return -1
}

const CRLF = (body: Uint8Array, at: number): boolean => body[at] === 0x0d && body[at + 1] === 0x0a

// A part's name or filename: the characters Cloudflare documents for a
// module name at most, with no leading or trailing dot or slash and no "..",
// so no parser that splits on ";", "=" or ",", trims spaces or resolves a
// path could read it as another.
const FORM_PART_NAME = /^[A-Za-z0-9_@+-](?:[A-Za-z0-9._/@+-]*[A-Za-z0-9_@+-])?$/
const formPartName = (name: string): boolean => FORM_PART_NAME.test(name) && !name.includes("..")

// One part's headers and bytes, or null. Only Content-Disposition (form-data,
// with a name and optionally a filename, each as formPartName allows) and
// Content-Type (with at most charset=utf-8), each at most once, in printable
// ASCII with no folding.
function formDataPart(part: Uint8Array): FormDataPart | null {
  const end = indexOfBytes(part, new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]), 0)
  if (end < 0) return null
  const head = part.subarray(0, end)
  if (head.some((b) => (b < 0x20 && b !== 0x0d && b !== 0x0a) || b > 0x7e)) return null
  const headers = new Map<string, string>()
  for (const line of new TextDecoder().decode(head).split("\r\n")) {
    if (/[\r\n]/.test(line)) return null
    const colon = line.indexOf(":")
    const name = line.slice(0, Math.max(colon, 0)).toLowerCase()
    if (colon <= 0 || !HEADER_TOKEN.test(name) || !["content-disposition", "content-type"].includes(name) || headers.has(name)) return null
    headers.set(name, trimOws(line.slice(colon + 1)))
  }
  const disposition = headers.get("content-disposition")
  if (disposition === undefined) return null
  const semicolon = disposition.indexOf(";")
  if (semicolon < 0 || trimOws(disposition.slice(0, semicolon)).toLowerCase() !== "form-data") return null
  const parameters = headerParameters(disposition.slice(semicolon))
  const name = parameters?.get("name")
  if (parameters === null || name === undefined || !formPartName(name) || [...parameters.keys()].some((k) => k !== "name" && k !== "filename")) return null
  const filename = parameters.get("filename") ?? null
  if (filename !== null && !formPartName(filename)) return null
  let contentType: string | null = null
  const declared = headers.get("content-type")
  if (declared !== undefined) {
    const cut = declared.indexOf(";")
    const media = trimOws(cut < 0 ? declared : declared.slice(0, cut)).toLowerCase()
    const rest = headerParameters(cut < 0 ? "" : declared.slice(cut))
    if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(media) || rest === null || [...rest].some(([k, v]) => k !== "charset" || v.toLowerCase() !== "utf-8")) return null
    contentType = media
  }
  return { name, filename, contentType, body: part.subarray(end + 4) }
}

export const FORM_DATA_PARTS_MAX = 1000
// What a parse looked at, for tests: each delimiter it checked.
export type FormDataScan = { delimiters: number }

// A multipart/form-data body read so that no two parsers could split it
// differently, or { ok: false }. The type is exactly multipart/form-data
// with one boundary and nothing else (no comma, no extended or repeated
// parameter). The body starts with the first delimiter and ends with the
// closing one (and at most one line break): no preamble, no epilogue. Every
// occurrence of "--" and the boundary is a delimiter, after a CRLF and
// followed by a CRLF or, last, by "--"; none sits inside a part or after a
// bare line feed. Each part is read by formDataPart, at most
// FORM_DATA_PARTS_MAX of them. Each delimiter is checked as it is found, and
// the first bad one ends the parse, so no body costs more than one linear
// pass or holds more than the parts it has.
export function parseFormDataStrictly(body: Uint8Array, contentType: string | null, scan?: FormDataScan): { ok: true; parts: FormDataPart[] } | { ok: false } {
  const refused = { ok: false } as const
  if (contentType === null || contentType.includes(",")) return refused
  const semicolon = contentType.indexOf(";")
  if (semicolon < 0 || trimOws(contentType.slice(0, semicolon)).toLowerCase() !== "multipart/form-data") return refused
  const parameters = headerParameters(contentType.slice(semicolon))
  const boundary = parameters?.get("boundary")
  if (parameters === null || parameters.size !== 1 || boundary === undefined || !FORM_BOUNDARY.test(boundary)) return refused
  const delimiter = new TextEncoder().encode(`--${boundary}`)
  if (body.length < delimiter.length || delimiter.some((b, i) => body[i] !== b)) return refused
  const parts: FormDataPart[] = []
  for (let at = 0; ;) {
    if (scan !== undefined) scan.delimiters++
    const after = at + delimiter.length
    if (body[after] === 0x2d && body[after + 1] === 0x2d) {
      const ends = after + 2 === body.length || (after + 4 === body.length && CRLF(body, after + 2))
      return ends && parts.length > 0 ? { ok: true, parts } : refused
    }
    if (!CRLF(body, after) || parts.length === FORM_DATA_PARTS_MAX) return refused
    const next = indexOfBytes(body, delimiter, after + 2)
    if (next < after + 4 || !CRLF(body, next - 2)) return refused
    const part = formDataPart(body.subarray(after + 2, next - 2))
    if (part === null) return refused
    parts.push(part)
    at = next
  }
}
