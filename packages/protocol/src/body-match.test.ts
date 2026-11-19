import { describe, expect, it } from "bun:test"
import { bodyMatches, graphqlDocumentIsQuery, graphqlDocumentMayMutate, graphqlIsQuery, graphqlMayMutate, graphqlMutationRootFields, parseFormDataStrictly, parseJsonStrictly, type GraphqlMutationRefusal } from "./body-match.ts"

const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const text = (value: string) => new TextEncoder().encode(value)

describe("graphqlDocumentMayMutate", () => {
  it("passes plain queries, named, anonymous or with fragments", () => {
    for (const doc of [
      "{ viewer { login } }",
      "query { viewer { login } }",
      "query Me($n: Int = 3) { viewer { repositories(first: $n) { nodes { name } } } }",
      "query A { ...F } fragment F on Query { viewer { login } }",
      'query { search(query: "mutation { deleteRef }", type: REPOSITORY, first: 1) { repositoryCount } }',
      'query { a(text: """block mutation { x } \\""" still inside""") }',
      "# mutation { deleteRef(input: {}) }\nquery { viewer { login } }",
      "query($input: X = {mutation: 1}) { viewer { login } }",
    ]) {
      expect(graphqlDocumentMayMutate(doc), doc).toBe(false)
    }
  })

  it("flags any mutation or subscription, wherever it sits in the document", () => {
    for (const doc of [
      "mutation { deleteRef(input: {refId: \"x\"}) { clientMutationId } }",
      "mutation DeleteIt { deleteIssue(input: {issueId: \"x\"}) { clientMutationId } }",
      "query A { viewer { login } } mutation B { addStar(input: {starrableId: \"x\"}) { clientMutationId } }",
      "{ viewer { login } }\nmutation{deleteRef(input:{refId:\"x\"}){clientMutationId}}",
      "subscription { x }",
      ",,mutation\t{ x }",
    ]) {
      expect(graphqlDocumentMayMutate(doc), doc).toBe(true)
    }
  })

  it("fails closed on what it cannot read", () => {
    for (const doc of ["", "   # only a comment", "{ viewer { login }", "{ viewer } }", 'query { a(t: "unterminated) }', 'query { a(t: "line\nbreak") }', 'query { a(t: """never ends) }']) {
      expect(graphqlDocumentMayMutate(doc), JSON.stringify(doc)).toBe(true)
    }
  })
})

describe("graphqlMayMutate", () => {
  it("passes a JSON GraphQL query, with variables that mention mutations", () => {
    expect(graphqlMayMutate(json({ query: "query($q: String!) { search(query: $q, type: ISSUE, first: 5) { issueCount } }", variables: { q: "mutation" } }))).toBe(false)
    expect(graphqlMayMutate(json({ query: "{ viewer { login } }", operationName: null }))).toBe(false)
  })

  it("flags a mutation", () => {
    expect(graphqlMayMutate(json({ query: "mutation { deleteRef(input: {refId: \"r\"}) { clientMutationId } }" }))).toBe(true)
  })

  it("fails closed on a body that is not exactly one readable GraphQL JSON request", () => {
    const cases: [string, Uint8Array | null][] = [
      ["no body", null],
      ["empty body", new Uint8Array()],
      ["not JSON", text("query { viewer { login } }")],
      ["not UTF-8", new Uint8Array([0x7b, 0xff, 0x7d])],
      ["a byte order mark", text('\uFEFF{"query":"{ viewer { login } }"}')],
      ["a batch", json([{ query: "{ viewer { login } }" }])],
      ["no query", json({ variables: {} })],
      ["a query that is not a string", json({ query: { mutation: true } })],
      ["a repeated query key", text('{"query":"{ viewer { login } }","query":"mutation { deleteRef(input:{refId:\\"r\\"}) { clientMutationId } }"}')],
      ["a repeated key spelled with an escape", text('{"query":"mutation { x }","\\u0071uery":"{ viewer { login } }"}')],
    ]
    for (const [what, body] of cases) expect(graphqlMayMutate(body), what).toBe(true)
  })

  it("accepts only a strict single-query envelope: a multiplexed _json batch, any other key or several operations count as a mutation", () => {
    const query = "{ currentUser { username } }"
    const cases: [string, Uint8Array][] = [
      ["a _json batch beside a harmless query", json({ query, _json: [{ query: "mutation { createIssue(input: {}) { errors } }" }] })],
      ["an empty _json batch", json({ query, _json: [] })],
      ["persisted-query extensions", json({ query, extensions: { persistedQuery: { sha256Hash: "x" } } })],
      ["any other key", json({ query, mehen: 1 })],
      ["two query operations", json({ query: "query A { a } query B { b }" })],
      ["variables that are not an object", json({ query, variables: [1] })],
    ]
    for (const [what, body] of cases) expect(graphqlMayMutate(body), what).toBe(true)
    expect(graphqlMayMutate(json({ query, variables: {}, operationName: null }))).toBe(false)
  })

  it("is what bodyMatches runs for graphql-mutation, which also flags any query string", () => {
    expect(bodyMatches("graphql-mutation", json({ query: "{ viewer { login } }" }), "")).toBe(false)
    expect(bodyMatches("graphql-mutation", null, "")).toBe(true)
    for (const search of ["?query=mutation%7Bx%7D", "?operationName=X", "?variables=%7B%7D", "?extensions=x", "?id=1", "?documentId=1", "?x=1"]) {
      expect(bodyMatches("graphql-mutation", json({ query: "{ viewer { login } }" }), search), search).toBe(true)
    }
  })
})

describe("graphqlDocumentIsQuery", () => {
  it("passes exactly one plain query operation, with fragments", () => {
    for (const doc of [
      "{ viewer { login } }",
      "query { viewer { login } }",
      "query Me($n: Int = 3) { viewer { repositories(first: $n) { nodes { name } } } }",
      "query A { ...F } fragment F on Query { viewer { login } }",
      "fragment F on Query { viewer { login } } { ...F }",
      'query { search(query: "mutation { deleteRef }", type: REPOSITORY, first: 1) { repositoryCount } }',
      "# mutation { x }\nquery { viewer { login } }",
      "query($input: X = {mutation: 1}) { viewer { login } }",
    ]) {
      expect(graphqlDocumentIsQuery(doc), doc).toBe(true)
    }
  })

  it("refuses anything else, and anything it is not sure of", () => {
    for (const doc of [
      "",
      "mutation { deleteRef(input: {refId: \"x\"}) { clientMutationId } }",
      "subscription { x }",
      "query A { a } query B { b }",
      "{ a } { b }",
      "fragment F on Query { viewer { login } }",
      "query",
      "query A",
      "query @live { viewer { login } }",
      '"description" query { a }',
      "($v: Int) { a }",
      "[ a ]",
      "query { a ]",
      "query { a ) }",
      "{ viewer { login }",
      "{ viewer } }",
      "schema { query: Q }",
      "type Q { a: Int }",
      "extend type Q { b: Int }",
      "1 { a }",
      "query { a } $",
      'query { a(t: "unterminated) }',
    ]) {
      expect(graphqlDocumentIsQuery(doc), JSON.stringify(doc)).toBe(false)
    }
  })
})

describe("graphqlIsQuery", () => {
  it("passes a JSON request holding only a query, variables and operation name", () => {
    expect(graphqlIsQuery(json({ query: "{ viewer { login } }" }))).toBe(true)
    expect(graphqlIsQuery(json({ query: "query Q($q: String!) { search(query: $q, type: ISSUE, first: 5) { issueCount } }", variables: { q: "mutation" }, operationName: "Q" }))).toBe(true)
    expect(graphqlIsQuery(json({ query: "{ viewer { login } }", variables: null, operationName: null }))).toBe(true)
  })

  it("refuses persisted queries, other keys and anything graphqlMayMutate flags", () => {
    const cases: [string, Uint8Array | null][] = [
      ["no body", null],
      ["empty body", new Uint8Array()],
      ["not JSON", text("{ viewer { login } }")],
      ["not UTF-8", new Uint8Array([0x7b, 0xff, 0x7d])],
      ["a byte order mark", text('\uFEFF{"query":"{ viewer { login } }"}')],
      ["a batch", json([{ query: "{ viewer { login } }" }])],
      ["a mutation", json({ query: "mutation { x }" })],
      ["extensions", json({ query: "{ viewer { login } }", extensions: { persistedQuery: { sha256Hash: "x" } } })],
      ["a persisted id", json({ id: "abc" })],
      ["a document id", json({ query: "{ viewer { login } }", documentId: "abc" })],
      ["another key", json({ query: "{ viewer { login } }", mutation: "x" })],
      ["variables as a string", json({ query: "{ viewer { login } }", variables: "{}" })],
      ["variables as an array", json({ query: "{ viewer { login } }", variables: [] })],
      ["operationName not a string", json({ query: "{ viewer { login } }", operationName: 1 })],
      ["a repeated key", text('{"query":"{ viewer { login } }","query":"mutation { x }"}')],
      ["two operations", json({ query: "query A { a } query B { b }", operationName: "A" })],
    ]
    for (const [what, body] of cases) expect(graphqlIsQuery(body), what).toBe(false)
  })

  it("is what bodyMatches runs for graphql-query, which refuses any query string", () => {
    const query = json({ query: "{ viewer { login } }" })
    expect(bodyMatches("graphql-query", query, "")).toBe(true)
    for (const search of ["?query=mutation%7Bx%7D", "?operationName=X", "?variables=%7B%7D", "?extensions=x", "?id=1", "?documentId=1", "?x=1"]) {
      expect(bodyMatches("graphql-query", query, search), search).toBe(false)
    }
  })
})

describe("parseJsonStrictly", () => {
  it("parses JSON and refuses a repeated key at any depth", () => {
    expect(parseJsonStrictly('{"a":1,"b":[{"a":2},{"a":3}]}')).toEqual({ ok: true, value: { a: 1, b: [{ a: 2 }, { a: 3 }] } })
    expect(parseJsonStrictly('{"a":"\\"a\\":","b":1}')).toEqual({ ok: true, value: { a: '"a":', b: 1 } })
    expect(parseJsonStrictly('{"a":1,"a":2}').ok).toBe(false)
    expect(parseJsonStrictly('{"x":{"to":"a","to":"b"}}').ok).toBe(false)
    expect(parseJsonStrictly("{not json}").ok).toBe(false)
  })
})

describe("graphqlMutationRootFields", () => {
  const proof = (query: string, rest: Record<string, unknown> = {}) => graphqlMutationRootFields(json({ query, ...rest }))

  it("names the root fields of one mutation, and its name", () => {
    expect(proof("mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id } } }", { variables: { input: { issueId: "x", body: "hi" } }, operationName: "CommentCreate" }))
      .toEqual({ ok: true, fields: ["commentCreate"], nestedFields: ["success", "comment", "id"], operationName: "CommentCreate" })
    expect(proof("mutation { a(x: 1) { id } b { id } }")).toEqual({ ok: true, fields: ["a", "b"], nestedFields: ["id", "id"], operationName: null })
    expect(proof("mutation { commentCreate(input: {issueId: \"x\", body: \"hi\"}) { success } }", { variables: null, operationName: null })).toMatchObject({ ok: true, fields: ["commentCreate"] })
  })

  it("names every field below the root by its real name, never its alias", () => {
    expect(proof("mutation { project(id: 1) { delete } }")).toMatchObject({ ok: true, fields: ["project"], nestedFields: ["delete"] })
    expect(proof("mutation { commentCreate(input: {}) { ok: success comment { body: userRemove { id } } } }")).toMatchObject({ ok: true, nestedFields: ["success", "comment", "userRemove", "id"] })
  })

  it("reads comments, block strings, escaped strings, commas and variables in arguments", () => {
    for (const query of [
      "# issueDelete(id: 1)\nmutation { commentCreate(input: {body: \"x\"}) { success } } # trailing",
      'mutation { commentCreate(input: {body: """a } issueDelete { id } \\""" still inside"""}) { success } }',
      'mutation { commentCreate(input: {body: "quote \\" brace } \\\\ slash \\/ \\u00e9 \\u{1F600} tab \\t"}) { success } }',
      ",,mutation ,Name, ( $input : CommentCreateInput! , $n: [Int!]! = [1, 2] , ) , { , commentCreate ( input : $input , ) { success , } , } ,",
      "mutation($input: CommentCreateInput!, $id: String) { commentCreate(input: {issueId: $id, nested: {list: [$input, -1.5e3, true, null, ENUM]}}) { comment { id author: user { name } } } }",
      'mutation { commentCreate(input: {issueId: "ISS-1", body: "hi"}) { success comment { id } } }',
      "mutation { commentCreate(input: {}) { success } } #\ta comment with a tab ~\n",
      'mutation { commentCreate(input: {body: "line\u2028separator \u2029 \uFEFF caf\u00e9"}) { success } }',
      'mutation { commentCreate(input: {body: """block \u2028 \uFEFF"""}) { success } }',
    ]) {
      expect(proof(query), query).toMatchObject({ ok: true, fields: ["commentCreate"] })
    }
  })

  it("refuses each shape a rule cannot pin down, one case each", () => {
    const cases: [string, Uint8Array | null, GraphqlMutationRefusal][] = [
      ["two operations", json({ query: "mutation A { commentCreate { success } } mutation B { issueDelete { success } }" }), "operations"],
      ["a mutation and a query", json({ query: "mutation A { commentCreate { success } } query B { viewer { id } }", operationName: "A" }), "operations"],
      ["a named fragment", json({ query: "mutation { ...F } fragment F on Mutation { issueDelete { success } }" }), "fragment"],
      ["a fragment spread below the root", json({ query: "mutation { commentCreate { ...F } } fragment F on X { id }" }), "fragment"],
      ["a fragment definition after the operation", json({ query: "mutation { commentCreate { success } } fragment F on X { id }" }), "fragment"],
      ["an inline fragment at the root", json({ query: "mutation { ... on Mutation { issueDelete { success } } }" }), "fragment"],
      ["an inline fragment below the root", json({ query: "mutation { commentCreate { ... on Payload { success } } }" }), "fragment"],
      ["an alias on a root field", json({ query: "mutation { commentCreate: issueDelete(id: 1) { success } }" }), "alias"],
      ["a directive on the operation", json({ query: "mutation @x { commentCreate { success } }" }), "directive"],
      ["a directive on a variable", json({ query: "mutation($a: Int @x) { commentCreate { success } }" }), "directive"],
      ["a directive on a root field", json({ query: "mutation { commentCreate @skip(if: false) { success } }" }), "directive"],
      ["an argument below the root", json({ query: "mutation { project { delete(id: 1) } }" }), "argument"],
      ["an argument deeper below the root", json({ query: "mutation { commentCreate(input: {}) { comment { user(id: 1) { id } } } }" }), "argument"],
      ["an argument on an aliased field below the root", json({ query: "mutation { project { p: delete(id: 1) } }" }), "argument"],
      ["a directive below the root", json({ query: "mutation { commentCreate(input: {}) { success @include(if: true) } }" }), "directive"],
      ["a directive without arguments below the root", json({ query: "mutation { project { delete @x } }" }), "directive"],
      ["a subscription", json({ query: "subscription { commentCreated { id } }" }), "subscription"],
      ["a batch", json([{ query: "mutation { commentCreate { success } }" }]), "batch"],
      ["anonymous shorthand", json({ query: "{ viewer { id } }" }), "query"],
      ["a named query", json({ query: "query Q { viewer { id } }" }), "query"],
      ["an operationName that is not the operation's", json({ query: "mutation A { commentCreate { success } }", operationName: "B" }), "operation-name"],
      ["an operationName for an anonymous operation", json({ query: "mutation { commentCreate { success } }", operationName: "A" }), "operation-name"],
      ["a root field named twice", json({ query: "mutation { commentCreate(a: 1) { success } commentCreate(a: 2) { success } }" }), "repeated-field"],
      ["persisted-query keys", json({ query: "mutation { commentCreate { success } }", extensions: { persistedQuery: { sha256Hash: "x" } } }), "body"],
      ["a repeated key", text('{"query":"mutation { commentCreate { success } }","query":"mutation { issueDelete { success } }"}'), "body"],
      ["no body", null, "body"],
      ["not JSON", text("mutation { commentCreate { success } }"), "body"],
      ["variables as an array", json({ query: "mutation { commentCreate { success } }", variables: [] }), "body"],
      ["an unknown token", json({ query: "mutation { commentCreate(a: 1 & 2) { success } }" }), "parse"],
      ["a lone dot", json({ query: "mutation { commentCreate(a: .5) { success } }" }), "parse"],
      ["a number running into a name", json({ query: "mutation { commentCreate(a: 12abc) { success } }" }), "parse"],
      ["an unknown escape", json({ query: 'mutation { commentCreate(a: "\\x41") { success } }' }), "parse"],
      ["an unterminated string", json({ query: 'mutation { commentCreate(a: "open) { success } }' }), "parse"],
      ["an unterminated block string", json({ query: 'mutation { commentCreate(a: """open) { success } }' }), "parse"],
      ["a control character", json({ query: "mutation { commentCreate\u0007 { success } }" }), "parse"],
      ["a non-ASCII name", json({ query: "mutation { c\u043emmentCreate { success } }" }), "parse"],
      ["a line separator in a comment", json({ query: "mutation { commentCreate { success } # \u2028 issueDelete { success }\n }" }), "parse"],
      ["a paragraph separator in a comment", json({ query: "mutation { commentCreate { success } # \u2029 issueDelete { success }\n }" }), "parse"],
      ["a non-ASCII letter in a comment", json({ query: "mutation { commentCreate { success } } # caf\u00e9" }), "parse"],
      ["a DEL in a comment", json({ query: "mutation { commentCreate { success } } # \u007f" }), "parse"],
      ["a line separator between tokens", json({ query: "mutation { commentCreate { success }\u2028 }" }), "parse"],
      ["a paragraph separator between tokens", json({ query: "mutation {\u2029commentCreate { success } }" }), "parse"],
      ["a byte order mark before the document", json({ query: "\uFEFFmutation { commentCreate { success } }" }), "parse"],
      ["a byte order mark between tokens", json({ query: "mutation { commentCreate\uFEFF{ success } }" }), "parse"],
      ["a NUL between tokens", json({ query: "mutation { commentCreate\u0000{ success } }" }), "parse"],
      ["a NUL in a comment", json({ query: "mutation { commentCreate { success } } # \u0000" }), "parse"],
      ["unbalanced braces", json({ query: "mutation { commentCreate { success }" }), "parse"],
      ["an empty selection", json({ query: "mutation { }" }), "parse"],
      ["empty arguments", json({ query: "mutation { commentCreate() { success } }" }), "parse"],
      ["a variable in a default value", json({ query: "mutation($a: Int = $b) { commentCreate { success } }" }), "parse"],
      ["no document", json({ query: "# just a comment" }), "parse"],
      ["nesting past the limit", json({ query: `mutation { commentCreate(a: ${"[".repeat(70)}${"]".repeat(70)}) { success } }` }), "parse"],
    ]
    for (const [what, body, reason] of cases) expect(graphqlMutationRootFields(body), what).toEqual({ ok: false, reason })
  })
})

describe("parseFormDataStrictly", () => {
  const TYPE = "multipart/form-data; boundary=b0undary"
  const form = (...parts: string[]) => text(`${parts.map((p) => `--b0undary\r\n${p}\r\n`).join("")}--b0undary--\r\n`)
  const metadata = 'Content-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n{"main_module":"index.js"}'
  const module = 'Content-Disposition: form-data; name="index.js"; filename="index.js"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}'

  it("reads each part's name, filename, type and bytes", () => {
    const parsed = parseFormDataStrictly(form(metadata, module), TYPE)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.parts.map((p) => [p.name, p.filename, p.contentType, new TextDecoder().decode(p.body)])).toEqual([
      ["metadata", null, "application/json", '{"main_module":"index.js"}'],
      ["index.js", "index.js", "application/javascript+module", "export default {}"],
    ])
  })

  it("takes the boundary quoted, a part with no type, binary bytes, and no closing line break", () => {
    expect(parseFormDataStrictly(form(metadata), 'multipart/form-data; boundary="b0undary"').ok).toBe(true)
    expect(parseFormDataStrictly(form('Content-Disposition: form-data; name=branch\r\n\r\nmain'), TYPE)).toMatchObject({ ok: true, parts: [{ name: "branch", filename: null, contentType: null }] })
    const wasm = new Uint8Array([...text('--b0undary\r\nContent-Disposition: form-data; name="m.wasm"\r\nContent-Type: application/wasm\r\n\r\n'), 0x00, 0x61, 0x73, 0x6d, 0xff, 0x0d, ...text("\r\n--b0undary--")])
    expect(parseFormDataStrictly(wasm, TYPE)).toMatchObject({ ok: true, parts: [{ name: "m.wasm", body: new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0xff, 0x0d]) }] })
  })

  it.each([
    ["another media type", form(metadata), "multipart/mixed; boundary=b0undary"],
    ["no boundary", form(metadata), "multipart/form-data"],
    ["two boundaries", form(metadata), "multipart/form-data; boundary=b0undary; boundary=b0undary"],
    ["an extended boundary", form(metadata), "multipart/form-data; boundary*=b0undary"],
    ["another parameter", form(metadata), "multipart/form-data; boundary=b0undary; charset=utf-8"],
    ["a comma in the type", form(metadata), "multipart/form-data; boundary=b0undary, text/plain"],
    ["a boundary over 70 characters", text(`--${"b".repeat(71)}\r\n${metadata}\r\n--${"b".repeat(71)}--`), `multipart/form-data; boundary=${"b".repeat(71)}`],
    ["a preamble", text(`preamble\r\n--b0undary\r\n${metadata}\r\n--b0undary--`), TYPE],
    ["an epilogue", text(`--b0undary\r\n${metadata}\r\n--b0undary--\r\nepilogue`), TYPE],
    ["no closing delimiter", text(`--b0undary\r\n${metadata}\r\n`), TYPE],
    ["a delimiter after a bare line feed", text(`--b0undary\r\n${metadata}\n--b0undary\r\n${module}\r\n--b0undary--`), TYPE],
    ["the boundary inside a part", form(`${metadata}--b0undary`), TYPE],
    ["a longer boundary that starts with this one inside a part", form(`${metadata}\r\n--b0undaryX`), TYPE],
    ["a part with no blank line after its headers", form('Content-Disposition: form-data; name="a"'), TYPE],
    ["a part with no Content-Disposition", form("Content-Type: text/plain\r\n\r\nx"), TYPE],
    ["two Content-Disposition headers", form('Content-Disposition: form-data; name="a"\r\nContent-Disposition: form-data; name="b"\r\n\r\nx'), TYPE],
    ["two Content-Type headers", form('Content-Disposition: form-data; name="a"\r\nContent-Type: text/plain\r\nContent-Type: application/wasm\r\n\r\nx'), TYPE],
    ["another header", form('Content-Disposition: form-data; name="a"\r\nContent-Transfer-Encoding: base64\r\n\r\neA=='), TYPE],
    ["a folded header", form('Content-Disposition: form-data;\r\n name="a"\r\n\r\nx'), TYPE],
    ["another disposition", form('Content-Disposition: attachment; name="a"\r\n\r\nx'), TYPE],
    ["no name", form('Content-Disposition: form-data; filename="a"\r\n\r\nx'), TYPE],
    ["an extended name", form("Content-Disposition: form-data; name*=utf-8''a\r\n\r\nx"), TYPE],
    ["an extended filename", form("Content-Disposition: form-data; name=\"a\"; filename*=utf-8''a.js\r\n\r\nx"), TYPE],
    ["a repeated name parameter", form('Content-Disposition: form-data; name="a"; name="b"\r\n\r\nx'), TYPE],
    ["another disposition parameter", form('Content-Disposition: form-data; name="a"; size=1\r\n\r\nx'), TYPE],
    ["an escape in a quoted name", form('Content-Disposition: form-data; name="a\\"b"\r\n\r\nx'), TYPE],
    ["a percent sign in a name", form('Content-Disposition: form-data; name="%5Fmethod"\r\n\r\nx'), TYPE],
    ["an empty name", form('Content-Disposition: form-data; name=""\r\n\r\nx'), TYPE],
    ["a part type with a parameter other than charset=utf-8", form('Content-Disposition: form-data; name="a"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\nx'), TYPE],
    ["a control character in a header", form('Content-Disposition: form-data; name="a\u0000"\r\n\r\nx'), TYPE],
  ])("refuses %s", (_label, body, contentType) => {
    expect(parseFormDataStrictly(body, contentType).ok).toBe(false)
  })

  it("takes names and filenames in letters, digits and . _ / @ + -, a path among them", () => {
    const parsed = parseFormDataStrictly(form('Content-Disposition: form-data; name="chunks/a-1_b.js"; filename="@scope/pkg+x.mjs"\r\n\r\nx'), TYPE)
    expect(parsed).toMatchObject({ ok: true, parts: [{ name: "chunks/a-1_b.js", filename: "@scope/pkg+x.mjs" }] })
  })

  it.each([
    ["a name holding ; and =", 'name="metadata; x=1"'],
    ["a name with a leading space", 'name=" metadata"'],
    ["a name with a trailing space", 'name="metadata "'],
    ["a filename with a space", 'name="index.js"; filename="my index.js"'],
    ["a filename climbing a directory", 'name="x.js"; filename="../x.js"'],
    ["a name climbing a directory", 'name="../x.js"'],
    ["a name with .. inside", 'name="a/../b.js"'],
    ["a name with a leading dot", 'name=".env"'],
    ["a name with a trailing dot", 'name="index."'],
    ["a name with a leading slash", 'name="/index.js"'],
    ["a filename with a trailing slash", 'name="a"; filename="dir/"'],
    ["a name with a comma", 'name="a,b"'],
    ["a name with a single quote", "name=\"a'b\""],
    ["a name with a backslash", 'name="a\\b"'],
    ["a name with a tab", 'name="a\tb"'],
    ["an empty filename", 'name="a"; filename=""'],
  ])("refuses %s", (_label, parameters) => {
    expect(parseFormDataStrictly(form(`Content-Disposition: form-data; ${parameters}\r\n\r\nx`), TYPE).ok).toBe(false)
  })

  it("refuses a delimiter followed by anything but a line break or the closing dashes", () => {
    expect(parseFormDataStrictly(text(`--b0undary\r\n${metadata}\r\n--b0undaryX\r\n${module}\r\n--b0undary--`), TYPE).ok).toBe(false)
    expect(parseFormDataStrictly(text(`--b0undary\r\n${metadata}\r\n--b0undary--\r\n--b0undary--`), TYPE).ok).toBe(false)
  })

  // 10 MiB: a body of dashes under a dash boundary, and one that makes a
  // naive search compare the whole delimiter at every byte.
  const MIB10 = 10 * 1024 * 1024
  it("refuses 10 MiB of dashes under a dash boundary at the first delimiter, in well under 2 s", () => {
    const scan = { delimiters: 0 }
    const started = performance.now()
    expect(parseFormDataStrictly(new Uint8Array(MIB10).fill(0x2d), "multipart/form-data; boundary=-", scan).ok).toBe(false)
    expect(performance.now() - started).toBeLessThan(2000)
    expect(scan.delimiters).toBe(1)
  })

  it("searches 10 MiB for a delimiter that almost matches everywhere in well under 2 s", () => {
    const boundary = `${"-".repeat(69)}x`
    const head = text(`--${boundary}\r\nContent-Disposition: form-data; name="a"\r\n\r\n`)
    const body = new Uint8Array(MIB10).fill(0x2d)
    body.set(head)
    const scan = { delimiters: 0 }
    const started = performance.now()
    expect(parseFormDataStrictly(body, `multipart/form-data; boundary=${boundary}`, scan).ok).toBe(false)
    expect(performance.now() - started).toBeLessThan(2000)
    expect(scan.delimiters).toBe(1)
  })

  it("reads at most 1,000 parts, and refuses the 1,001st at its delimiter", () => {
    const many = (n: number) => form(...Array.from({ length: n }, (_, i) => `Content-Disposition: form-data; name="p${i}"\r\n\r\nx`))
    expect(parseFormDataStrictly(many(1000), TYPE)).toMatchObject({ ok: true, parts: { length: 1000 } })
    const scan = { delimiters: 0 }
    expect(parseFormDataStrictly(many(1001), TYPE, scan).ok).toBe(false)
    expect(scan.delimiters).toBe(1001)
  })

  it("reads only spaces and tabs as white space in the type, refusing a non-breaking space, a vertical tab or a form feed", () => {
    expect(parseFormDataStrictly(form(metadata), "multipart/form-data;\t boundary=b0undary ").ok).toBe(true)
    for (const type of ["multipart/form-data;\u00a0boundary=b0undary", "multipart/form-data; boundary=b0undary\u00a0", "\u00a0multipart/form-data; boundary=b0undary", "multipart/form-data\u00a0; boundary=b0undary", "multipart/form-data;\vboundary=b0undary", "multipart/form-data;\fboundary=b0undary", "multipart/form-data; boundary=b0undary\u2028"]) {
      expect(parseFormDataStrictly(form(metadata), type).ok, JSON.stringify(type)).toBe(false)
    }
  })

  it("refuses an empty body and a null type", () => {
    expect(parseFormDataStrictly(new Uint8Array(), TYPE).ok).toBe(false)
    expect(parseFormDataStrictly(form(metadata), null).ok).toBe(false)
  })
})
