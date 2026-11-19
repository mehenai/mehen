import { describe, expect, test } from "bun:test"
import { denyDestinationFixtures, destinationShapeFixtures, standardDestinationFixtures } from "../test/policy-safety-fixtures.ts"
import { evaluatePolicy, parseDestination, type Binding, type Destination, type Policy } from "./binding.ts"
import { canonicalJson } from "./canonical-json.ts"
import { connectionPolicy, OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"
import { RULE_DEFAULT_DURATION, type PolicyRouteScope } from "./policy-mode.ts"
import { ruleTermsFrom } from "./policy-rules.ts"
import {
  classifyPolicyRequest, evaluatePolicyFloor, GENERIC_POLICY_FLOOR_WORDS, POLICY_FLOOR, POLICY_SAFETY_PROFILES,
  policyBodyDeclaresUnreadCharset, policyFloorDigest, policyFloorViews, policyMethodOverrideBodyField, policyMethodOverrideParameter, policySafetyDigest, policyScopeEligibility, policyWideningEligibility, POLICY_SAFETY_VERSION,
  resolvePolicyRequest, type PolicySafetyInput,
} from "./policy-safety.ts"

const binding: Binding = { hosts: ["custom.example"], paths: ["/api/**"] }
const scope: PolicyRouteScope = { host: "custom.example", methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], path: "/api/projects/123/**", anchorPath: "/api/projects/123/task", basis: "unreviewed" }
const base: Policy = { default: "approve", rules: [] }
const json = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value))
function destination(path: string, method = "POST", host = "custom.example"): Destination {
  const parsed = parseDestination(method, `https://${host}${path}`)
  if (!parsed.ok) throw new Error("Invalid test destination")
  return parsed.destination
}
const inputOf = (path = "/api/projects/123/task", method = "POST"): PolicySafetyInput => ({ destination: destination(path, method) })
function action(input: PolicySafetyInput, selectedScope = scope, selectedBinding = binding, policy = base, policyMode: "standard" | "relaxed" | "yolo" = "yolo") {
  return resolvePolicyRequest({ ...input, policy, scope: selectedScope, binding: selectedBinding, policyMode }).action
}
function refusal(input: PolicySafetyInput): void {
  expect(policyWideningEligibility(input, scope, binding).eligible).toBe(false)
  expect(action(input)).not.toBe("allow")
}
const githubBinding: Binding = { hosts: ["api.github.com"] }
const githubScope: PolicyRouteScope = { host: "api.github.com", methods: ["POST", "PATCH", "DELETE"], path: "/repos/alex/*/issues/**", anchorPath: "/repos/alex/vault/issues/comments/42", basis: "reviewed" }
const github = (path: string, method = "POST", body: Uint8Array | null = json({ body: "A comment" })): PolicySafetyInput => ({ destination: destination(path, method, "api.github.com"), body, contentType: "application/json" })

function matcher(rule: Policy["rules"][number]) {
  const { note: _note, ...rest } = rule
  return rest
}

describe("code-owned known-host floors", () => {
  const policies = [
    ...Object.values(TEMPLATES).map((t) => ({ id: t.id, hosts: t.binding.hosts, policy: t.policy })),
    ...Object.values(OAUTH_PROVIDERS).map((p) => ({ id: p.id, hosts: p.upstream.binding.hosts, policy: connectionPolicy(p) })),
  ]
  for (const source of policies) {
    for (const [i, rule] of source.policy.rules.entries()) {
      if (rule.action === "allow") continue
      test(`refusal/template-parity ${source.id} rule ${i}`, () => {
        for (const host of source.hosts) expect(POLICY_FLOOR.some((f) => f.host === host && canonicalJson(f.rule) === canonicalJson(matcher(rule)))).toBe(true)
      })
    }
  }
  test.each(["/repos/alex/vault/hooks", "/repos/alex/vault/HoOkS", "/repos/alex/vault/%68ooks", "/repos/alex/vault/hooks.json"])("refusal/known-deny %s", (path) => {
    const input = github(path, "POST", null)
    expect(action(input, githubScope, githubBinding, { default: "allow", rules: [] })).toBe("deny")
  })
  test.each([
    ["api.linear.app", "/graphql", "POST", json({ query: "mutation { issueCreate { id } }" })],
    ["slack.com", "/api/chat.postMessage", "GET", null],
    ["slack.com", "/api/chat.scheduleMessage", "POST", json({ text: "hello" })],
  ] as const)("refusal/known-approve %s %s", (host, path, method, body) => expect(evaluatePolicyFloor({ destination: destination(path, method, host), body }).action).toBe("approve"))
  test("deny outranks an overlapping approve floor", () => expect(evaluatePolicyFloor(github("/repos/alex/vault/hooks")).action).toBe("deny"))
  test("floor digests cover matcher, host, action and reason, never notes", async () => {
    const floor = POLICY_FLOOR[0]!
    const digest = await policyFloorDigest(floor)
    expect(digest).toMatch(/^[A-Za-z0-9_-]{43}$/)
    for (const patch of [{ host: "other.example" }, { action: "approve" as const }, { reason: "money" as const }, { rule: { action: "deny" as const, paths: ["/other"] } }]) {
      expect(await policyFloorDigest({ ...floor, ...patch })).not.toBe(digest)
    }
    expect(await policySafetyDigest()).toBe(await policySafetyDigest())
    expect((await policyFloorViews(floor.host)).every((f) => f.ruleDigest.length === 43)).toBe(true)
    expect(POLICY_SAFETY_PROFILES.every((p) => p.version === 1 && p.floor.every((f) => f.rule.note === undefined))).toBe(true)
  })
})

describe("generic unreviewed floor", () => {
  for (const word of GENERIC_POLICY_FLOOR_WORDS) {
    for (const place of ["path", "query-name", "query-value"] as const) {
      for (const variant of ["literal", "encoded", "case", "suffix", "punctuation"] as const) {
        test(`refusal/generic ${word} ${place} ${variant}`, () => {
          const value = variant === "encoded" ? `%${word.charCodeAt(0).toString(16)}${word.slice(1)}` : variant === "case" ? word.toUpperCase() : variant === "suffix" ? `create${word}s.json` : variant === "punctuation" ? word.split("").join("-") : word
          const path = place === "path" ? `/api/projects/123/${value}` : place === "query-name" ? `/api/projects/123/task?${value}=yes` : `/api/projects/123/task?op=${value}`
          const input = inputOf(path)
          expect(evaluatePolicyFloor(input).reasons).toContain(`generic.${word}`)
          refusal(input)
          expect(action(input, scope, binding, { default: "allow", rules: [] })).toBe("allow")
        })
      }
    }
  }
  test("refusal/query-value-createWebhook", () => {
    const input = { destination: destination("/api/do?op=createWebhook") }
    expect(evaluatePolicyFloor(input).action).toBe("approve")
  })
  test("refusal/query-double-encoding", () => refusal(inputOf("/api/projects/123/task?op=%2577ebhook")))
  test("refusal/query-encoded-separators", () => refusal(inputOf("/api/projects/123/task?op=create%2FWebhook")))
  test("refusal/query-unicode-fold", () => refusal(inputOf("/api/projects/123/task?op=%E2%84%AAey")))
  test("refusal/query-value-cyrillic-lookalike", () => refusal(inputOf("/api/projects/123/task?op=createT%D0%BEken")))
  test("refusal/query-name-cyrillic-lookalike", () => refusal(inputOf("/api/projects/123/task?t%D0%BEken=1")))
  test("refusal/query-value-greek-lookalike", () => refusal(inputOf("/api/projects/123/task?op=webh%CE%BFok")))
  test("refusal/query-value-raw-lookalike", () => refusal(inputOf("/api/projects/123/task?op=s%D0%B5cret")))
})

describe("unreviewed RPC and malformed safety input", () => {
  const unsafeBodies: [string, Uint8Array, string | null][] = [
    ["json-rpc", json({ jsonrpc: "2.0", method: "listProjects", params: {} }), "application/json"],
    ["rpc-without-version", json({ method: "deleteProject" }), "application/json"],
    ["batch", json([{ task: "list" }]), "application/json"],
    ["rpc-batch", json([{ jsonrpc: "2.0", method: "read" }]), "application/json"],
    ["wrapped-batch", json({ requests: [{ method: "read" }] }), "application/json"],
    ["multipart-batch", new TextEncoder().encode("--batch\r\nrequest\r\n--batch--"), "multipart/mixed; boundary=batch"],
    ["json-sequence", new TextEncoder().encode('\u001e{"task":"read"}\n\u001e{"task":"write"}'), "application/json-seq"],
    ["json-sequence-without-type", new TextEncoder().encode('\u001e{"task":"read"}\n\u001e{"task":"write"}'), null],
    ["json-sequence-as-text", new TextEncoder().encode('\u001e{"task":"read"}\n\u001e{"task":"write"}'), "text/plain"],
    ["multipart-without-type", new TextEncoder().encode("--batch\r\nContent-Type: application/http\r\n\r\nPOST /v1/tokens\r\n--batch--"), null],
    ["multipart-after-bom", new TextEncoder().encode("\uFEFF--batch\r\nContent-Type: application/http\r\n\r\nPOST /v1/tokens\r\n--batch--"), "text/plain"],
    ["multipart-after-blank-lines", new TextEncoder().encode(" \r\n--batch\r\nContent-Type: application/http\r\n\r\nPOST /v1/tokens\r\n--batch--"), null],
    ["http-message-type", new TextEncoder().encode("POST /v1/tokens HTTP/1.1\r\nHost: api.example.com\r\n\r\n"), "application/http"],
    ["http-message-media", new TextEncoder().encode("anything"), "message/http"],
    ["http-request-line-untyped", new TextEncoder().encode("note\nPOST /v1/tokens HTTP/1.1\nHost: api.example.com\n"), null],
    ["http-part-header", new TextEncoder().encode("part one\nContent-Type: application/http\n\nhello"), "text/plain"],
    ["multipart-batch-type", new TextEncoder().encode("x"), "multipart/batch; boundary=b"],
    ["graphql-mutation", json({ query: "mutation { deleteProject { id } }" }), "application/json"],
    ["graphql-subscription", json({ query: "subscription { projects { id } }" }), "application/json"],
    ["graphql-multi-query", json({ query: "{ projects { id } } { projects { id } }" }), "application/json"],
    ["graphql-persisted", json({ query: "{ projects { id } }", extensions: { persistedQuery: { hash: "abc" } } }), "application/json"],
    ["graphql-persisted-id", json({ id: "persisted-document", variables: { project: "123" } }), "application/json"],
    ["graphql-document-id", json({ documentId: "persisted-document" }), "application/json"],
    ["graphql-unproved", json({ query: "query { projects ( }" }), "application/json"],
    ["graphql-raw", new TextEncoder().encode("query { projects { id } }"), "application/graphql"],
    ["duplicate-key", new TextEncoder().encode('{"query":"{ projects { id } }","query":"mutation { delete { id } }"}'), "application/json"],
    ["nested-duplicate", new TextEncoder().encode('{"query":"{ projects { id } }","variables":{"id":1,"id":2}}'), "application/json"],
    ["malformed-json", new TextEncoder().encode('{"task":'), "application/json"],
    ["non-object-json", json("opaque"), "application/json"],
    ["empty-body", new Uint8Array(), "application/json"],
    ["invalid-utf8", new Uint8Array([0xff]), "application/json"],
    ["bom", new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), "application/json"],
    ["oversized-body", new TextEncoder().encode("x".repeat(65537)), "text/plain"],
    ["multipart-spaced-type-with-preamble", new TextEncoder().encode('preamble\r\n--batch\r\nContent-Type: application/json\r\n\r\n[{"jsonrpc":"2.0","method":"deleteProject"}]\r\n--batch--\r\n'), "multipart/mixed ; boundary=batch"],
    ["http-spaced-type", new TextEncoder().encode("anything"), "application/http ; msgtype=request"],
    ["multipart-form-data", new TextEncoder().encode("--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n--b--"), "multipart/form-data; boundary=b"],
    ["lowercase-request-line", new TextEncoder().encode("note\npost /v1/tokens HTTP/1.1\n"), "text/plain"],
    ["plain-text-opaque", new TextEncoder().encode("make me an admin"), "text/plain"],
    ["untyped-text-opaque", new TextEncoder().encode("op=create&what=token"), null],
    ["multi-line-form", new TextEncoder().encode("a=1\nb=2"), "application/x-www-form-urlencoded"],
    ["form-encoded-graphql", new TextEncoder().encode("%71uery=%6dutation%20%7Bdelete%7Bid%7D%7D"), "application/x-www-form-urlencoded"],
    ["form-encoded-request-line", new TextEncoder().encode("payload=note%0Apost%20/v1/tokens%20HTTP/1.1"), "application/x-www-form-urlencoded"],
    ["form-encoded-rpc-batch", new TextEncoder().encode("payload=%5B%7B%22jsonrpc%22%3A%222.0%22%2C%22method%22%3A%22deleteProject%22%7D%5D"), "application/x-www-form-urlencoded"],
    ["plain-form", new TextEncoder().encode("name=Build+check&state=open"), "application/x-www-form-urlencoded; charset=utf-8"],
  ]
  test.each(unsafeBodies)("refusal/body %s", (_label, body, contentType) => refusal({ ...inputOf(), body, contentType }))
  test("one strict JSON object stays widenable, vendor JSON types included", () => {
    const vendor = { ...inputOf(), body: json({ data: { type: "projects", attributes: { name: "x" } } }), contentType: "application/vnd.api+json" }
    expect(policyWideningEligibility(vendor, scope, binding).eligible).toBe(true)
    const object = { ...inputOf(), body: json({ name: "Build check" }), contentType: "application/json ; charset=utf-8" }
    expect(policyWideningEligibility(object, scope, binding).eligible).toBe(true)
  })
  test.each(["graphql", "GrApHqL", "%67raphql"])("refusal/graphql-segment %s", (segment) => refusal({ destination: destination(`/api/projects/123/${segment}`), body: json({ query: "{ projects { id } }" }) }))
  test("refusal/graphql-scope-pin", () => expect(policyScopeEligibility({ ...scope, path: "/api/projects/123/graphql", anchorPath: "/api/projects/123/graphql" }, binding).eligible).toBe(false))
  test("refusal/graphql-url-override", () => refusal({ destination: destination("/api/projects/123/task?query=mutation%20%7Bdelete%7Bid%7D%7D"), body: json({ query: "{ projects { id } }" }) }))
  test.each(["query", "%2571uery", "QuErY"])("refusal/graphql-url-without-body %s", (name) => refusal(inputOf(`/api/projects/123/task?${name}=%7Bprojects%7Bid%7D%7D`)))
  test.each(["gzip", "br", "IDENTITY", ""])("refusal/content-encoding %s", (contentEncoding) => refusal({ ...inputOf(), body: json({ task: "list" }), contentEncoding }))
  test.each(["/api/projects/123/task?op=%XX", "/api/projects/123/task?op=%ff", "/api/projects/123/task?op=%00", "/api/projects/123/task?op=%E2%80%AE"])("refusal/query-malformed %s", (path) => refusal(inputOf(path)))
  test.each(["/api/projects/123/%2Ftask", "/api/projects/123/%2574ask", "/api/projects/123/../task", "/api/projects/123/task;x=1", "/api/projects/123/task\u202E"])("refusal/destination-malformed %s", (path) => refusal({ destination: { ...destination("/api/projects/123/task"), path } }))
  test("proved query at another endpoint still needs the ordinary scope", () => {
    const input = { ...inputOf(), body: json({ query: "query { projects { id } }" }), contentType: "application/json", contentEncoding: "identity" }
    expect(action(input)).toBe("allow")
    expect(action({ ...input, destination: destination("/api/projects/other/task") })).toBe("approve")
  })
})

describe("a JSON id or a list of variables is GraphQL only with another GraphQL key or on a GraphQL path", () => {
  const reasons = (path: string, body: unknown, host = "custom.example") => evaluatePolicyFloor({ destination: destination(path, "POST", host), body: json(body), contentType: "application/json" }).reasons
  const gateways = "/client/v4/accounts/0123456789abcdef0123456789abcdef/ai-gateway/gateways"
  const gateway = { id: "contoso", collect_logs: false, cache_ttl: 0, cache_invalidate_on_update: false, rate_limiting_interval: 0, rate_limiting_limit: 0, rate_limiting_technique: "fixed" }

  test("Cloudflare's AI Gateway create, naming its own id, is the gateway entry with no floor", () => {
    const input: PolicySafetyInput = { destination: destination(gateways, "POST", "api.cloudflare.com"), body: json(gateway), contentType: "application/json" }
    expect(evaluatePolicyFloor(input)).toEqual({ action: "allow", reasons: [] })
    expect(classifyPolicyRequest(input)).toEqual({ effect: "routine", routeId: "cloudflare.gateway-create", additionalPermission: false })
  })
  test("a GitLab-style variables list on a pipeline is ordinary JSON", () => {
    const input = { ...inputOf("/api/v4/projects/1/pipeline"), body: json({ ref: "main", variables: [{ key: "STAGE", value: "test" }] }), contentType: "application/json" }
    expect(evaluatePolicyFloor(input).reasons).toEqual([])
    expect(policyWideningEligibility(input, { ...scope, path: "/api/v4/projects/1/**", anchorPath: "/api/v4/projects/1/pipeline" }, binding).eligible).toBe(true)
  })
  test.each([
    ["an id with variables", { id: "persisted-document", variables: { project: "123" } }],
    ["a query", { query: "mutation { deleteProject { id } }" }],
    ["a document id", { documentId: "persisted-document" }],
    ["a persisted query extension", { extensions: { persistedQuery: { version: 1, sha256Hash: "abc" } } }],
    ["an operation name", { operationName: "DeleteProject" }],
  ])("refusal/%s anywhere still needs the GraphQL proof", (_, body) => {
    expect(reasons("/api/projects/123/task", body)).toContain("safety.graphql-proof")
    expect(reasons(gateways, { ...gateway, ...body }, "api.cloudflare.com")).toContain("safety.graphql-proof")
  })
  test.each([
    ["a Relay document id with variables", { doc_id: "1234567890", variables: { project: "123" } }],
    ["a Relay document id alone", { doc_id: "1234567890" }],
    ["a query id with variables", { queryId: "DeleteProject", variables: {} }],
    ["a hash with variables", { hash: "abc", variables: {} }],
    ["variables as an object alone", { variables: {} }],
    ["a hash with variables sent as a string", { hash: "abc", variables: "{\"project\":\"123\"}" }],
    ["variables as null", { variables: null }],
  ])("refusal/%s on /api and / needs the GraphQL proof", (_, body) => {
    expect(reasons("/api", body)).toContain("safety.graphql-proof")
    expect(reasons("/", body)).toContain("safety.graphql-proof")
  })
  test.each(["/graphql", "/api/GraphQL", "/api/%67raphql", "/v1/gql", "/api/GQL/v2", "/api/my-graphql-endpoint"])("refusal/an id or variables alone on %s still needs the GraphQL proof", (path) => {
    expect(reasons(path, { id: "persisted-document" })).toContain("safety.graphql-proof")
    expect(reasons(path, { variables: { project: "123" } })).toContain("safety.graphql-proof")
  })
  test.each([
    ["batch", [{ id: "a" }], "safety.batch"],
    ["method override", { id: "a", _method: "DELETE" }, "safety.method-override"],
    ["JSON-RPC", { jsonrpc: "2.0", id: 1, method: "deleteProject" }, "safety.json-rpc"],
  ])("refusal/a %s with an id is refused as before", (_, body, reason) => expect(reasons("/api/projects/123/task", body)).toContain(reason))
})

describe("catalogue and pinned scopes", () => {
  test.each(["GET", "HEAD", "POST", "PUT", "PATCH"])("unreviewed relaxed capability %s", (method) => expect(action(inputOf(undefined, method), scope, binding, base, "relaxed")).toBe("allow"))
  test("unreviewed DELETE is YOLO only", () => {
    expect(action(inputOf(undefined, "DELETE"))).toBe("allow")
    expect(action(inputOf(undefined, "DELETE"), scope, binding, base, "relaxed")).toBe("approve")
  })
  test.each(["OPTIONS", "CONNECT", "TRACE", "CUSTOM"])("refusal/unreviewed-method %s", (method) => refusal(inputOf(undefined, method)))
  test.each([
    ["/api/projects/other/task", "custom.example"], ["/api/projects/123/task", "other.example"], ["/outside/task", "custom.example"],
  ])("refusal/outside-scope %s %s", (path, host) => refusal({ destination: destination(path, "POST", host) }))
  test.each(["GET", "HEAD"])("refusal/outside-scope read %s", (method) => refusal(inputOf("/api/projects/other/task", method)))
  test("refusal/fake-reviewed-basis", () => expect(policyScopeEligibility({ ...scope, basis: "reviewed" }, binding).eligible).toBe(false))
  test("refusal/catalogue-new-host", () => expect(policyScopeEligibility({ ...githubScope, host: "github.enterprise.example" }, { hosts: ["github.enterprise.example"] }).eligible).toBe(false))
  test.each([
    ["/repos/alex/vault/issues", "POST", json({ title: "Issue", body: "Details" })],
    ["/repos/alex/vault/issues/12", "PATCH", json({ state: "closed" })],
    ["/repos/alex/vault/issues/12/comments", "POST", json({ body: "Comment" })],
    ["/repos/alex/vault/issues/comments/42", "PATCH", json({ body: "Edited comment" })],
  ] as const)("reviewed routine %s", (path, method, body) => {
    const input = github(path, method, body)
    expect(classifyPolicyRequest(input).effect).toBe("routine")
    expect(action(input, githubScope, githubBinding, base, "relaxed")).toBe("allow")
    expect(action(input, githubScope, githubBinding, base, "yolo")).toBe("allow")
  })
  test("reviewed-only YOLO difference is comment deletion", () => {
    const input = github("/repos/alex/vault/issues/comments/42", "DELETE", null)
    expect(action(input, githubScope, githubBinding, base, "relaxed")).toBe("approve")
    expect(action(input, githubScope, githubBinding, base, "yolo")).toBe("allow")
    expect(POLICY_SAFETY_PROFILES.flatMap((p) => p.widenable).filter((e) => e.effect === "destructive").every((e) => e.id === "github.comment-delete")).toBe(true)
  })
  test.each([
    ["/repos/foreign/vault/issues/12/comments", "POST"], ["/repos/alex/vault/pulls", "POST"],
    ["/repositories/123/issues/12/comments", "POST"], ["/repos/alex/vault/issues/comments/not-numeric", "PATCH"],
  ])("refusal/github-namespace %s", (path, method) => expect(action(github(path, method), githubScope, githubBinding)).toBe("approve"))
  test("refusal/github-anchor-grammar", () => expect(policyScopeEligibility({ ...githubScope, anchorPath: "/repos/alex/vault/issues/comments/not-numeric" }, githubBinding).eligible).toBe(false))
  test.each(["/repositories/123/issues/**", "/repos/*/vault/issues/**", "/repos/alex/*/**"])("refusal/github-unreviewed-namespace %s", (path) => {
    const anchorPath = path.replaceAll("**", "12/comments").replaceAll("*", "foreign")
    expect(policyScopeEligibility({ ...githubScope, path, anchorPath, basis: "unreviewed" }, githubBinding).eligible).toBe(false)
  })
  test.each([
    json({ body: "Comment", owner: "foreign" }), json({ body: "Comment", repo: "foreign" }), json({ body: "Comment", url: "https://foreign.example" }),
  ])("refusal/github-body-override %j", (body) => expect(action(github("/repos/alex/vault/issues/12/comments", "POST", body), githubScope, githubBinding)).toBe("approve"))
  test("refusal/github-query-override", () => expect(action(github("/repos/alex/vault/issues/12/comments?repo=foreign"), githubScope, githubBinding)).toBe("approve"))
  test("refusal/explicit-base-approve", () => expect(action(inputOf(), scope, binding, { default: "approve", rules: [{ action: "approve", paths: ["/api/projects/**"] }] })).toBe("approve"))
  test("refusal/base-deny", () => expect(action(inputOf(), scope, binding, { default: "deny", rules: [] })).toBe("deny"))
  test("refusal/explicit-base-deny", () => expect(action(inputOf(), scope, binding, { default: "allow", rules: [{ action: "deny" }] })).toBe("deny"))
  test("notes never classify a write as a read", () => expect(classifyPolicyRequest(inputOf()).effect).toBe("unknown"))
})

describe("Stripe is base-only", () => {
  const stripeBinding: Binding = { hosts: ["api.stripe.com"] }
  const stripeScope: PolicyRouteScope = { host: "api.stripe.com", methods: ["POST"], path: "/v1/products/**", anchorPath: "/v1/products", basis: "reviewed" }
  for (const name of ["charges", "payment_intents", "setup_intents", "invoices", "invoiceitems", "credit_notes", "refunds", "payouts", "transfers", "topups", "treasury", "issuing", "customers"]) {
    for (const suffix of ["", "/record"]) {
      test(`refusal/stripe-floor ${name}${suffix}`, () => expect(evaluatePolicyFloor({ destination: destination(`/v1/${name}${suffix}`, "PATCH", "api.stripe.com") }).action).toBe("approve"))
    }
  }
  test.each(["products", "prices"])("refusal/stripe-no-permission %s", (name) => {
    const input = { destination: destination(`/v1/${name}`, "POST", "api.stripe.com"), body: json({ name: "Catalogue item" }) }
    const selectedScope = { ...stripeScope, path: `/v1/${name}/**`, anchorPath: `/v1/${name}` }
    expect(evaluatePolicy(TEMPLATES["stripe"]!.policy, input.destination).action).toBe("allow")
    expect(classifyPolicyRequest(input).additionalPermission).toBe(false)
    expect(action(input, selectedScope, stripeBinding, base, "relaxed")).toBe("approve")
    expect(action(input, selectedScope, stripeBinding, base, "yolo")).toBe("approve")
    expect(action(input, selectedScope, stripeBinding, TEMPLATES["stripe"]!.policy)).toBe("allow")
  })
  test("refusal/stripe-unreviewed", () => {
    const selectedScope: PolicyRouteScope = { ...stripeScope, basis: "unreviewed", path: "/v1/**" }
    expect(action({ destination: destination("/v1/products", "POST", "api.stripe.com") }, selectedScope, stripeBinding)).toBe("approve")
  })
})


describe("standard-mode body compatibility and widening-only floors", () => {
  const cases: [string, PolicySafetyInput][] = [
    ["65 KiB JSON", { ...inputOf(), body: json({ text: "a".repeat(65 * 1024) }), contentType: "application/json" }],
    ["gzip", { ...inputOf(), body: json({ title: "task" }), contentEncoding: "gzip" }],
    ["form", { ...inputOf(), body: new TextEncoder().encode("title=task"), contentType: "application/x-www-form-urlencoded" }],
    ["text", { ...inputOf(), body: new TextEncoder().encode("task"), contentType: "text/plain" }],
    ["multipart", { ...inputOf(), body: new TextEncoder().encode("--boundary"), contentType: "multipart/form-data" }],
    ["generic word", inputOf("/api/projects/123/count_tokens")],
  ]
  for (const [name, input] of cases) {
    test(`base allow remains allow for ${name}, even with a live window`, () => {
      for (const mode of ["standard", "relaxed", "yolo"] as const) expect(action(input, scope, binding, { default: "allow", rules: [] }, mode)).toBe("allow")
    })
    test(`refusal/widening-only ${name} never bypasses default approval`, () => {
      for (const mode of ["relaxed", "yolo"] as const) expect(action(input, scope, binding, base, mode)).toBe("approve")
    })
  }
  test("Anthropic base-allowed count_tokens remains usable", () => expect(action({ destination: destination("/v1/messages/count_tokens", "POST", "api.anthropic.com") }, { ...scope, host: "api.anthropic.com" }, { hosts: ["api.anthropic.com"] }, { default: "allow", rules: [] }, "standard")).toBe("allow"))
  test("known-host deny is mandatory in standard mode", () => expect(action(github("/repos/alex/vault/hooks", "POST", null), githubScope, githubBinding, { default: "allow", rules: [] }, "standard")).toBe("deny"))
  test("known-host approve is mandatory in standard mode", () => expect(action({ destination: destination("/v1/refunds", "POST", "api.stripe.com") }, { ...scope, host: "api.stripe.com" }, { hosts: ["api.stripe.com"] }, { default: "allow", rules: [] }, "standard")).toBe("approve"))
})

describe("review destination precedence and compatibility", () => {
  test("classification changes invalidate earlier safety guards", () => expect(POLICY_SAFETY_VERSION).toBe("mehen-policy-safety/v6"))
  test.each(standardDestinationFixtures)("standard destination $name stays base-allowed", ({ host, route }) => {
    const input = { destination: destination(route, "GET", host) }
    expect(policyMethodOverrideParameter(input.destination.search)).toBeNull()
    expect(resolvePolicyRequest({ ...input, policy: { default: "allow", rules: [] }, binding: { hosts: [host] }, policyMode: "standard", scope: null }).action).toBe("allow")
  })
  test.each(["_method", "_httpmethod", "%5Fmethod", "a=1;_method", "a=1;_httpmethod", "%255Fmethod", "%25255Fhttpmethod", "%EF%BC%BFmethod", "_MeThOd"])("refusal/exact decoded override %s", (name) => {
    expect(policyMethodOverrideParameter(`?${name}=DELETE`)).not.toBeNull()
  })
  test.each([
    ["a Content-Type with a comma, which Rack and PHP cut at", "note=x&_method=DELETE", "application/x-www-form-urlencoded, text/plain"],
    ["two Content-Type headers joined", "note=x&_method=DELETE", "text/plain, application/x-www-form-urlencoded"],
    ["a text type, which nothing declares as a form", "note=x&_method=DELETE", "text/plain"],
    ["a JSON body declared as text with /json in a parameter, which Laravel reads as JSON", '{"_method":"DELETE"}', "text/plain; x=/json"],
    ["a JSON body declared as a form", '{"_method":"DELETE"}', "application/x-www-form-urlencoded"],
    ["a duplicate multipart name, where parsers keep the last", '--a\r\nContent-Disposition: form-data; name="note"; name="_method"\r\n\r\nDELETE\r\n--a--\r\n', "multipart/form-data; boundary=a"],
    ["a fake multipart filename inside a quoted value", '--a\r\nContent-Disposition: form-data; name="_method"; x="; filename=a"\r\n\r\nDELETE\r\n--a--\r\n', "multipart/form-data; boundary=a"],
    ["a duplicate multipart boundary, where Rack splits on the last", '--b\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--b--\r\n', "multipart/form-data; boundary=a; boundary=b"],
    ["multipart/mixed, which Rack also reads as a form", '--a\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--a--\r\n', "multipart/mixed; boundary=a"],
    ["multipart/related", '--a\r\nContent-Disposition: form-data; name=_METHOD\r\n\r\nDELETE\r\n--a--\r\n', "multipart/related; boundary=a"],
    ["a multipart file named after the field", '--a\r\nContent-Disposition: form-data; name="_httpmethod"; filename="m.txt"\r\n\r\nDELETE\r\n--a--\r\n', "multipart/form-data; boundary=a"],
    ["multipart behind a Content-Type with a comma", '--a\r\nContent-Disposition: form-data; name*="_method"\r\n\r\nDELETE\r\n--a--\r\n', "text/plain, multipart/form-data; boundary=a"],
  ])("refusal/body method override in %s", (_, body, contentType) => {
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(body), contentType)).not.toBeNull()
  })
  test.each([".method", "%2Emethod", "+_method", "%20.httpmethod"])("refusal/override %s as PHP reads it, leading spaces dropped and . and space read as _", (name) => {
    expect(policyMethodOverrideParameter(`?${name}=DELETE`)).not.toBeNull()
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(`note=x&${name}=DELETE`), "application/x-www-form-urlencoded")).not.toBeNull()
  })
  test.each(["_method%00", "[_method]", "]_method", "_method]", "_method[x]", "_method%00%01", "_method%00%FF", "%5B_method%5D"])("refusal/override %s as PHP and Rack read it, cut at a NUL or other control and with its brackets dropped", (name) => {
    const sent = name.replaceAll("%00", "\0")
    const multipart = `--a\r\nContent-Disposition: form-data; name="${sent}"\r\n\r\nDELETE\r\n--a--\r\n`
    expect(policyMethodOverrideParameter(`?${name}=DELETE`)).toBe("_method")
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(`note=x&${name}=DELETE`), "application/x-www-form-urlencoded")).toBe("_method")
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(JSON.stringify({ [sent]: "DELETE" })), "application/json")).toBe("_method")
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(multipart), "multipart/form-data; boundary=a")).toBe("_method")
  })
  test.each([
    ["single quotes, which PHP accepts", "name='_method'"],
    ["a value that also reads as an RFC 5987 prefix", "name='_method''"],
    ["26 spaces, which PHP drops", `name="${" ".repeat(26)}_method"`],
    ["a run of spaces and tabs", `name= \t "${" ".repeat(200)}x-http-method-override"`],
    ["an RFC 5987 name, which busboy decodes", "name*=utf-8''%5Fmethod"],
    ["an RFC 5987 name with a language, quoted", "name*=\"UTF-8'en-gb'%5F%6D%65%74%68%6F%64\""],
    ["an RFC 5987 name with every character encoded", `name*=utf-8''${[..."x-http-method-override"].map((c) => `%${c.charCodeAt(0).toString(16)}`).join("")}`],
  ])("refusal/multipart override named with %s", (_, parameter) => {
    const body = `--a\r\nContent-Disposition: form-data; ${parameter}\r\n\r\nDELETE\r\n--a--\r\n`
    expect(policyMethodOverrideBodyField(new TextEncoder().encode(body), "multipart/form-data; boundary=a")).not.toBeNull()
  })
  test("refusal/a UTF-16 body is read in the byte order its mark or type says, and in both when neither says", () => {
    const utf16 = (text: string, order: "le" | "be", mark: boolean) => {
      const units = [...(mark ? [0xfeff] : []), ...[...text].map((c) => c.charCodeAt(0))]
      return new Uint8Array(units.flatMap((u) => (order === "le" ? [u & 0xff, u >> 8] : [u >> 8, u & 0xff])))
    }
    const json = '{"_method":"DELETE"}'
    for (const order of ["le", "be"] as const) {
      expect(policyMethodOverrideBodyField(utf16(json, order, false), `application/json; charset=utf-16${order}`), order).toBe("_method")
      expect(policyMethodOverrideBodyField(utf16(json, order, false), "application/json; charset=UTF-16"), order).toBe("_method")
      expect(policyMethodOverrideBodyField(utf16(json, order, true), "application/json"), order).toBe("_method")
      expect(policyMethodOverrideBodyField(utf16(json, order, false), "application/json"), order).toBeNull()
      expect(policyMethodOverrideBodyField(utf16('{"payment_method":"card"}', order, true), `application/json; charset=utf-16${order}`), order).toBeNull()
    }
    expect(policyMethodOverrideBodyField(utf16(json, "le", false), "application/json; charset=utf-1-6le")).toBe("_method")
    expect(policyBodyDeclaresUnreadCharset(utf16(json, "le", false), "application/json; charset=utf-1-6le")).toBe(false)
  })
  test("refusal/a body in a utf- charset other than UTF-8 or UTF-16, spelled as iconv-lite reads it, is refused", () => {
    const body = (text: string) => new TextEncoder().encode(text)
    for (const type of ["application/json; charset=utf-7", "application/json; charset=utf-3-2", 'application/json; charset="UTF-32"', "application/json; charset=utf--32le", "text/plain, application/json; charset=UTF-7-IMAP"]) {
      expect(policyBodyDeclaresUnreadCharset(body('{"+AF8-method":"DELETE"}'), type), type).toBe(true)
    }
    for (const type of ["application/json; charset=utf-8", "application/json; charset=UTF8", "application/json; charset=utf-16le", "application/x-www-form-urlencoded; charset=latin1", "application/json"]) {
      expect(policyBodyDeclaresUnreadCharset(body('{"note":"x"}'), type), type).toBe(false)
      expect(policyMethodOverrideBodyField(body('{"note":"x"}'), type), type).toBeNull()
    }
    expect(policyBodyDeclaresUnreadCharset(null, "application/json; charset=utf-7")).toBe(false)
  })
  test("refusal/a body in any charset outside those the scan reads faithfully is refused", () => {
    const body = new TextEncoder().encode('{"note":"x"}')
    for (const charset of ["x-utf-16le", "ucs-2", "UCS2", "unicode", "csUnicode", "iso-10646-ucs-2", "cp1200", "utf-32", "UTF-32LE", "utf-7", "unicode-1-1-utf-7", "csunicode11utf7", "shift_jis", "ebcdic-cp-us", "binary", "x-unknown", ""]) {
      expect(policyBodyDeclaresUnreadCharset(body, `application/json; charset=${charset}`), charset).toBe(true)
    }
    for (const charset of ["utf-8", "UTF-8", "unicode-1-1-utf-8", "us-ascii", "ascii", "iso-8859-1", "ISO-8859-15", "iso-8859-16", "latin1", "windows-1252", "windows-1250", "cp1252", "utf-16le", "utf-16be", "utf-16"]) {
      expect(policyBodyDeclaresUnreadCharset(body, `application/json; charset=${charset}`), charset).toBe(false)
    }
  })
  test("refusal/a multipart name* in a charset whose escapes the scan does not read as UTF-8 does is refused", () => {
    const multipart = (parameter: string) => new TextEncoder().encode(`--a\r\nContent-Disposition: form-data; ${parameter}\r\n\r\nDELETE\r\n--a--\r\n`)
    const type = "multipart/form-data; boundary=a"
    const utf16le = [..."_method"].map((c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}%00`).join("")
    const utf16be = [..."_method"].map((c) => `%00%${c.charCodeAt(0).toString(16).toUpperCase()}`).join("")
    for (const parameter of [
      `name*=utf-16le''${utf16le}`, `name*=UTF-16BE''${utf16be}`, `name*="utf-16'en'${utf16le}"`, `name*=utf-32''%00%00%00%5F`, "name*=utf-7''+AF8-method",
      "name*=shift_jis''%5Fmethod", "name*=x-unknown''%5Fmethod", "name*=''%5Fmethod", `name="note"; filename*=ucs-2''${utf16le}`,
      `name*='utf-16le''${utf16le}`, `name*=[utf-16le''${utf16le}`,
    ]) {
      expect(policyBodyDeclaresUnreadCharset(multipart(parameter), type), parameter).toBe(true)
      expect(policyBodyDeclaresUnreadCharset(multipart(parameter), "text/plain, multipart/mixed; boundary=a"), parameter).toBe(true)
    }
    for (const parameter of ["name*=utf-8''%5Fmethod", "name*=\"UTF-8'en-gb'%5F%6D%65%74%68%6F%64\"", "name*=iso-8859-1''note", "name*=us-ascii''note", "name*=note", `name="utf-16le''${utf16le}"`]) {
      expect(policyBodyDeclaresUnreadCharset(multipart(parameter), type), parameter).toBe(false)
    }
    expect(policyMethodOverrideBodyField(multipart("name*=utf-8''%5Fmethod"), type)).toBe("_method")
    expect(policyBodyDeclaresUnreadCharset(multipart(`name*=utf-16le''${utf16le}`), "application/octet-stream")).toBe(false)
  })
  test("refusal/a multipart name* charset is read no further than 64 characters, and one that reaches 65 is refused", () => {
    const type = "multipart/form-data; boundary=a"
    const multipart = (parameter: string) => new TextEncoder().encode(`--a\r\nContent-Disposition: form-data; ${parameter}\r\n\r\nDELETE\r\n--a--\r\n`)
    // Both read as utf8 once spelled as iconv-lite reads it; only the length differs.
    const read64 = `utf${"-".repeat(60)}8`
    const read65 = `utf${"-".repeat(61)}8`
    expect(read64.length).toBe(64)
    expect(read65.length).toBe(65)
    expect(policyBodyDeclaresUnreadCharset(multipart(`name*=${read64}''%5Fnote`), type)).toBe(false)
    expect(policyBodyDeclaresUnreadCharset(multipart(`name*=${read65}''%5Fnote`), type)).toBe(true)
    // A run of name*= with nothing to end a charset reaches the bound at the first one.
    const unended = new TextEncoder().encode("name*=".repeat(2_000))
    expect(policyBodyDeclaresUnreadCharset(unended, type)).toBe(true)
  })
  test("refusal/a plain ASCII method override in a form declared as ISO-8859-1 is found", () => {
    const form = new TextEncoder().encode("note=x&_method=DELETE")
    expect(policyBodyDeclaresUnreadCharset(form, "application/x-www-form-urlencoded; charset=iso-8859-1")).toBe(false)
    expect(policyMethodOverrideBodyField(form, "application/x-www-form-urlencoded; charset=iso-8859-1")).toBe("_method")
  })
  test("a field whose name only ends in an override field is not one", () => {
    for (const name of ["payment_method", "payment_method[x]", "[payment]_method", "x[_method]", "%FF_method"]) {
      const multipart = `--a\r\nContent-Disposition: form-data; name="${name}"\r\n\r\nDELETE\r\n--a--\r\n`
      expect({ name, query: policyMethodOverrideParameter(`?${name}=DELETE`) }).toEqual({ name, query: null })
      expect({ name, form: policyMethodOverrideBodyField(new TextEncoder().encode(`note=x&${name}=DELETE`), "application/x-www-form-urlencoded") }).toEqual({ name, form: null })
      expect({ name, json: policyMethodOverrideBodyField(new TextEncoder().encode(JSON.stringify({ [name]: "DELETE" })), "application/json") }).toEqual({ name, json: null })
      expect({ name, multipart: policyMethodOverrideBodyField(new TextEncoder().encode(multipart), "multipart/form-data; boundary=a") }).toEqual({ name, multipart: null })
    }
  })
  test("refusal/multipart override named as PHP reads it", () => {
    expect(policyMethodOverrideBodyField(new TextEncoder().encode('--a\r\nContent-Disposition: form-data; name=" .method"\r\n\r\nDELETE\r\n--a--\r\n'), "multipart/form-data; boundary=a")).toBe("_method")
  })
  test("a body names no override field when it carries one only as a value or below the top level", () => {
    const field = (body: string, contentType: string | null) => policyMethodOverrideBodyField(new TextEncoder().encode(body), contentType)
    expect(field("note=_method&method=DELETE", "application/x-www-form-urlencoded")).toBeNull()
    expect(field(JSON.stringify({ data: { _method: "DELETE" } }), "text/plain")).toBeNull()
    expect(field('--a\r\nContent-Disposition: form-data; name="note"\r\n\r\nname=method\r\n--a--\r\n', "multipart/form-data; boundary=a")).toBeNull()
    expect(field('name="_method"', "text/plain")).toBeNull()
  })
  test("refusal/double-encoded paths stay ambiguous while query values decode repeatedly", () => {
    expect(parseDestination("GET", "https://custom.example/api/projects/123/%2541").ok).toBe(false)
    const input = inputOf("/api/projects/123/task?q=%2541")
    expect(action(input, scope, binding, { default: "allow", rules: [] }, "standard")).toBe("allow")
    const hidden = inputOf("/api/projects/123/task?op=%2577ebhook")
    expect(evaluatePolicyFloor(hidden).reasons).toContain("generic.webhook")
    refusal(hidden)
  })
  test("percent decoding allows eight rounds, never nine", () => {
    const eight = `%${"25".repeat(7)}41`
    const input = inputOf(`/api/projects/123/task?q=${eight}`)
    expect(evaluatePolicyFloor(input).reasons).not.toContain("safety.encoding")
    expect(action(input, scope, binding, { default: "allow", rules: [] }, "standard")).toBe("allow")
    expect(evaluatePolicyFloor(inputOf(`/api/projects/123/task?q=%25${eight.slice(1)}`)).reasons).toContain("safety.encoding")
  })
  test.each(denyDestinationFixtures)("refusal/deny-before-destination $name", ({ method, host, route }) => {
    const input = { destination: destination(route, method, host) }
    expect(evaluatePolicyFloor(input).action).toBe("deny")
    for (const mode of ["standard", "relaxed", "yolo"] as const) expect(action(input, scope, { hosts: [host] }, { default: "allow", rules: [] }, mode)).toBe("deny")
  })
  test.each(destinationShapeFixtures)("destination-shape $name preserves base allow but refuses widening", ({ host, route, prefix }) => {
    const input = { destination: destination(route, "GET", host) }
    const selectedBinding = { hosts: [host] }
    const selectedScope = { ...scope, host, path: `${prefix}/**`, anchorPath: `${prefix}/tasks` }
    expect(evaluatePolicyFloor(input).reasons).toContain("safety.destination-shape")
    for (const mode of ["standard", "relaxed", "yolo"] as const) expect(action(input, selectedScope, selectedBinding, { default: "allow", rules: [] }, mode)).toBe("allow")
    expect(policyWideningEligibility(input, selectedScope, selectedBinding)).toMatchObject({ eligible: false, reason: "safety.destination-shape" })
    expect(action(input, selectedScope, selectedBinding)).toBe("approve")
  })
  test.each(["%", "%2", "%XX", "%25%XX", "%ff", "%00", ...[0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200b, 0x2060, 0xfeff].map((point) => encodeURIComponent(String.fromCodePoint(point))), "%25252525252525252541"])("refusal/unreadable query %s is mandatory", (value) => {
    const input = inputOf(`/api/projects/123/task?q=${value}`)
    expect(evaluatePolicyFloor(input).reasons).toContain("safety.encoding")
    expect(action(input, scope, binding, { default: "allow", rules: [] }, "standard")).toBe("approve")
  })
  test.each(["%2Ftask", "%5Ctask", "%2Etask", "../task", "task//child", "%2574ask", "task\u202E"])("refusal/unreadable path %s is mandatory", (segment) => {
    const input = { destination: { ...destination("/api/projects/123/task"), path: `/api/projects/123/${segment}` } }
    expect(evaluatePolicyFloor(input).reasons.some((reason) => ["safety.destination", "safety.encoding"].includes(reason))).toBe(true)
    expect(action(input, scope, binding, { default: "allow", rules: [] }, "standard")).toBe("approve")
  })
  test.each(["_method", "_httpmethod", "X-HTTP-Method-Override"])("refusal/JSON method override %s is widening-only", (key) => {
    const input = { ...inputOf(), contentType: "application/json", body: json({ [key]: "DELETE" }) }
    expect(evaluatePolicyFloor(input).reasons).toContain("safety.method-override")
    refusal(input)
    expect(action(input, scope, binding, { default: "allow", rules: [] }, "standard")).toBe("allow")
  })
})

// The floor reasons a standing rule reads (policy-rules.ts): Linear's
// commentCreate is held only by an opaque GraphQL floor and the GraphQL body
// check, which a root-field proof lifts; a GitHub issue comment by nothing
// but the template's default. The window machinery still refuses Linear.
describe("standing-rule anchors", () => {
  const linear = TEMPLATES["linear"]!
  const githubTemplate = TEMPLATES["github-pat"]!
  const linearInput = { destination: destination("/graphql", "POST", "api.linear.app"), body: json({ query: "mutation { commentCreate(input: {issueId: \"x\", body: \"y\"}) { success } }" }), contentType: "application/json" }
  const githubInput = github("/repos/alex/vault/issues/42/comments")

  test("Linear commentCreate: an opaque GraphQL floor and the GraphQL body check, and no widening window", () => {
    expect(evaluatePolicyFloor(linearInput)).toEqual({ action: "approve", reasons: ["linear.floor-1", "safety.graphql-proof"] })
    expect(POLICY_FLOOR.find((f) => f.id === "linear.floor-1")).toMatchObject({ action: "approve", reason: "opaque", rule: { body: "graphql-mutation" } })
    const linearScope: PolicyRouteScope = { host: "api.linear.app", methods: ["POST"], path: "/graphql", anchorPath: "/graphql", basis: "unreviewed" }
    expect(policyScopeEligibility(linearScope, linear.binding as Binding).eligible).toBe(false)
    const made = ruleTermsFrom({ ...linearInput, item: "linear-work", itemId: "itm_linear01", asker: { device: "dev_x", workload: null }, contentEncoding: null, policy: linear.policy as Policy, binding: linear.binding as Binding, secretPrefixes: ["lin_api_"] }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })
    expect(made).toMatchObject({ ok: true, terms: { graphql: { fields: ["commentCreate"], nestedFields: ["success"] } } })
  })

  test("GitHub issue comment: no floor, held only by the template default", () => {
    expect(evaluatePolicyFloor(githubInput)).toEqual({ action: "allow", reasons: [] })
    expect(evaluatePolicy(githubTemplate.policy as Policy, githubInput.destination, githubInput.body ?? null)).toEqual({ action: "approve", matched: [] })
    const made = ruleTermsFrom({ ...githubInput, body: githubInput.body ?? null, contentType: "application/json", item: "github-work", itemId: "itm_github01", asker: { device: "dev_x", workload: null }, contentEncoding: null, policy: githubTemplate.policy as Policy, binding: githubTemplate.binding as Binding, secretPrefixes: ["github_pat_"] }, { path: "/repos/alex/vault/issues/*/comments", ttlSeconds: RULE_DEFAULT_DURATION })
    expect(made).toMatchObject({ ok: true, terms: { path: "/repos/alex/vault/issues/*/comments", graphql: null } })
  })
})

describe("Cloudflare uploads, once refused whole as safety.batch, read through their readers", () => {
  const worker = "/client/v4/accounts/0123456789abcdef0123456789abcdef/workers/scripts/my-worker"
  const upload = (body: string, contentType = "multipart/form-data; boundary=a"): PolicySafetyInput => ({ destination: destination(worker, "PUT", "api.cloudflare.com"), body: new TextEncoder().encode(body), contentType, contentEncoding: null })
  const metadata = '--a\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n{"main_module":"index.js"}\r\n'
  const module = '--a\r\nContent-Disposition: form-data; name="index.js"; filename="index.js"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}\r\n'

  test("a Worker upload the reader reads is the destructive entry, with no floor", () => {
    const input = upload(`${metadata}${module}--a--\r\n`)
    expect(evaluatePolicyFloor(input)).toEqual({ action: "allow", reasons: [] })
    expect(classifyPolicyRequest(input)).toEqual({ effect: "destructive", routeId: "cloudflare.worker-upload", additionalPermission: false })
  })

  test.each([
    ["a duplicate multipart name, where parsers keep the last", `--a\r\nContent-Disposition: form-data; name="metadata"; name="_method"\r\n\r\nDELETE\r\n${module}--a--\r\n`],
    ["a fake filename inside a quoted value", `${metadata}--a\r\nContent-Disposition: form-data; name="index.js"; x="; filename=a"\r\nContent-Type: application/javascript+module\r\n\r\nx\r\n--a--\r\n`],
    ["a multipart override field", `${metadata}${module}--a\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--a--\r\n`],
    ["an override named in a module's code", `${metadata}--a\r\nContent-Disposition: form-data; name="index.js"; filename="index.js"\r\nContent-Type: application/javascript+module\r\n\r\nform.append("x", 1); // name="_method"\r\n--a--\r\n`],
    ["a name* in a charset the scan does not read", `${metadata}--a\r\nContent-Disposition: form-data; name*=utf-7''index.js\r\nContent-Type: application/javascript+module\r\n\r\nx\r\n--a--\r\n`],
    ["a second metadata part", `${metadata}${metadata}${module}--a--\r\n`],
    ["no closing delimiter", `${metadata}${module}`],
  ])("refusal/%s is not the entry and still asks", (_, body) => {
    const input = upload(body)
    expect(classifyPolicyRequest(input).routeId).toBeNull()
    expect(evaluatePolicyFloor(input).action).toBe("approve")
  })

  // The slowest body the reader reads whole: 10 MiB in 1,000 well-formed
  // parts, which the floor and the classification each parse.
  test("10 MiB in 1,000 well-formed Worker upload parts is read, the floor and the classification together in well under 2 s", () => {
    const filler = "x".repeat(Math.floor((10 * 1024 * 1024) / 1000) - 120)
    const modules = Array.from({ length: 999 }, (_, i) => `--b\r\nContent-Disposition: form-data; name="m${i}.js"; filename="m${i}.js"\r\nContent-Type: application/javascript+module\r\n\r\n// ${filler}\r\n`)
    const metadata = `--b\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n{"main_module":"m0.js","compatibility_date":"2026-11-01"}\r\n`
    const body = new TextEncoder().encode(`${metadata}${modules.join("")}--b--\r\n`)
    expect(body.length).toBeGreaterThan(9.9 * 1024 * 1024)
    const input: PolicySafetyInput = { destination: destination(worker, "PUT", "api.cloudflare.com"), body, contentType: "multipart/form-data; boundary=b", contentEncoding: null }
    const started = performance.now()
    expect(evaluatePolicyFloor(input).action).toBe("allow")
    expect(classifyPolicyRequest(input).routeId).toBe("cloudflare.worker-upload")
    expect(performance.now() - started).toBeLessThan(2000)
  })

  test("10 MiB of dashes under a dash boundary asks, the floor and the classification together in well under 2 s", () => {
    for (const [body, contentType] of [
      [new Uint8Array(10 * 1024 * 1024).fill(0x2d), "multipart/form-data; boundary=-"],
      [(() => { const b = new Uint8Array(10 * 1024 * 1024).fill(0x2d); b.set(new TextEncoder().encode(`--${"-".repeat(69)}x\r\n`)); return b })(), `multipart/form-data; boundary=${"-".repeat(69)}x`],
    ] as const) {
      const input: PolicySafetyInput = { destination: destination(worker, "PUT", "api.cloudflare.com"), body, contentType, contentEncoding: null }
      const started = performance.now()
      expect(evaluatePolicyFloor(input).action).toBe("approve")
      expect(classifyPolicyRequest(input).routeId).toBeNull()
      expect(performance.now() - started).toBeLessThan(2000)
    }
  })

  test.each([
    ["a duplicate boundary", "multipart/form-data; boundary=b; boundary=a"],
    ["multipart/mixed", "multipart/mixed; boundary=a"],
    ["a type behind a comma", "text/plain, multipart/form-data; boundary=a"],
  ])("refusal/%s in the type is not the entry and asks as safety.batch", (_, contentType) => {
    const input = upload(`${metadata}${module}--a--\r\n`, contentType)
    expect(classifyPolicyRequest(input).routeId).toBeNull()
    expect(evaluatePolicyFloor(input).action).toBe("approve")
  })
})
