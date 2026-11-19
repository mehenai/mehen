import { describe, expect, test } from "bun:test"
import { parseDestination, type Binding, type Destination, type Policy } from "./binding.ts"
import { graphqlMutationRootFields } from "./body-match.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { POLICY_CATALOGUES, type PolicyCatalogue } from "./policy-catalogue.ts"
import { PolicyRememberSchema, policyRulePathChoices, PolicyRuleTermsSchema, PostureSchema, RULE_DEFAULT_DURATION, RULE_DURATIONS, type PolicyAreaGrantTerms, type PolicyAreaRefusal, type PolicyRuleRefusal, type PolicyRuleTerms } from "./policy-mode.ts"
import { areaGrantCovers, areaGrantEntry, areaGrantTermsFrom, itemPostureDigest, policyFloorRefusal, policyRuleTermsDigest, policyRuleTermsDigestMatches, postureCatalogueFor, postureCovers, ruleCovers, ruleTermsFrom, type PolicyRuleAnchor } from "./policy-rules.ts"
import { evaluatePolicyFloor, GENERIC_POLICY_FLOOR_WORDS, POLICY_FLOOR } from "./policy-safety.ts"
import { connectionPolicy, OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"

const json = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value))
function destination(method: string, url: string): Destination {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error("Invalid test destination")
  return parsed.destination
}
function template(id: string): { policy: Policy; binding: Binding } {
  const t = TEMPLATES[id]
  if (!t) throw new Error(`No template ${id}`)
  return { policy: t.policy as Policy, binding: t.binding as Binding }
}
function provider(id: string): { policy: Policy; binding: Binding } {
  const p = OAUTH_PROVIDERS[id]
  if (!p) throw new Error(`No provider ${id}`)
  return { policy: connectionPolicy(p) as Policy, binding: p.upstream.binding as Binding }
}
const asker = { device: "dev_alexmbp", workload: null }

// Linear: a commentCreate mutation on POST https://api.linear.app/graphql.
const linear = template("linear")
const comment = (query: string, rest: Record<string, unknown> = {}) => json({ query, ...rest })
const COMMENT_CREATE = "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id } } }"
const linearRequest = (body: Uint8Array | null, overrides: Partial<PolicyRuleAnchor> = {}): PolicyRuleAnchor => ({
  item: "linear-work", itemId: "itm_linear01", asker, destination: destination("POST", "https://api.linear.app/graphql"), body, contentType: "application/json", contentEncoding: null, policy: linear.policy,
  binding: linear.binding, secretPrefixes: ["lin_api_"], ...overrides,
})
const linearAnchor = linearRequest(comment(COMMENT_CREATE, { variables: { input: { issueId: "ISS-1", body: "First" } }, operationName: "CommentCreate" }))

// GitHub: a comment on issue 42, with the issue number as the pattern's "*".
const github = template("github-pat")
const githubRequest = (method: string, path: string, body: Uint8Array | null = json({ body: "A comment" }), overrides: Partial<PolicyRuleAnchor> = {}): PolicyRuleAnchor => ({
  item: "github-work", itemId: "itm_github01", asker, destination: destination(method, `https://api.github.com${path}`), body, contentType: body === null ? null : "application/json", contentEncoding: null, policy: github.policy,
  binding: github.binding, secretPrefixes: ["github_pat_"], ...overrides,
})
const githubAnchor = githubRequest("POST", "/repos/alex/vault/issues/42/comments")
const GITHUB_PATTERN = "/repos/alex/vault/issues/*/comments"

// A key with no template: everything asks.
const custom = (method: string, path: string, body: Uint8Array | null, secretPrefixes: string[] = []): PolicyRuleAnchor => ({
  item: "tasks-key", itemId: "itm_tasks001", asker, destination: destination(method, `https://api.example.com${path}`), body, contentType: body === null ? null : "application/json", contentEncoding: null,
  policy: { default: "approve", rules: [] }, binding: { hosts: ["api.example.com"] }, secretPrefixes,
})

// Vercel on its template policy.
const vercelRequest = (method: string, path: string, body: Uint8Array): PolicyRuleAnchor => ({
  ...template("vercel"), item: "vercel-work", itemId: "itm_vercel01", asker, destination: destination(method, `https://api.vercel.com${path}`), body, contentType: "application/json", contentEncoding: null, secretPrefixes: [],
})

// Microsoft Graph and Google Calendar connections on their default policies.
const graphRequest = (method: string, path: string): PolicyRuleAnchor => ({
  ...provider("microsoft-graph"), item: "graph-work", itemId: "itm_graph001", asker, destination: destination(method, `https://graph.microsoft.com${path}`), body: json({ subject: "x" }), contentType: "application/json", contentEncoding: null, secretPrefixes: [],
})
const calendarRequest = (method: string, path: string, body: Uint8Array | null = json({ summary: "x" })): PolicyRuleAnchor => ({
  ...provider("google-calendar"), item: "calendar-work", itemId: "itm_calendar1", asker, destination: destination(method, `https://www.googleapis.com${path}`), body, contentType: body === null ? null : "application/json", contentEncoding: null, secretPrefixes: [],
})

function termsOf(anchor: PolicyRuleAnchor, path = anchor.destination.path, ttlSeconds: number = RULE_DEFAULT_DURATION): PolicyRuleTerms {
  const made = ruleTermsFrom(anchor, { path, ttlSeconds })
  if (!made.ok) throw new Error(`Refused: ${made.reason}`)
  return made.terms
}

describe("Linear commentCreate anchor", () => {
  const terms = termsOf(linearAnchor)

  test("is allowed, as the mutation's root fields and the fields below them on the literal path", () => {
    expect(terms).toEqual({
      item: "linear-work", itemId: "itm_linear01", asker, method: "POST", host: "api.linear.app", path: "/graphql", anchorPath: "/graphql",
      queryNames: [], graphql: { fields: ["commentCreate"], nestedFields: ["comment", "id", "success"] }, ttlSeconds: 604_800,
    })
    expect(policyRulePathChoices("/graphql")).toEqual(["/graphql"])
  })

  test("covers a second commentCreate with different variables", () => {
    expect(ruleCovers(terms, linearRequest(comment(COMMENT_CREATE, { variables: { input: { issueId: "ISS-2", body: "Second" } }, operationName: "CommentCreate" })))).toBe(true)
    expect(ruleCovers(terms, linearRequest(comment('mutation { commentCreate(input: {issueId: "ISS-3", body: "Third"}) { success comment { id } } }')))).toBe(true)
  })

  test.each([
    ["issueDelete", comment('mutation { issueDelete(id: "ISS-1") { success } }')],
    ["commentCreate plus issueDelete", comment('mutation { commentCreate(input: {issueId: "x", body: "y"}) { success } issueDelete(id: "ISS-1") { success } }')],
    ["an aliased commentCreate", comment('mutation { commentCreate: issueDelete(id: "ISS-1") { success } }')],
    ["a fragment", comment("mutation { ...F } fragment F on Mutation { commentCreate(input: {}) { success } }")],
    ["a query", comment("query { viewer { id } }")],
    ["two operations", comment("mutation A { commentCreate(input: {}) { success } } mutation B { issueDelete(id: \"x\") { success } }", { operationName: "A" })],
    ["a batch", json([{ query: COMMENT_CREATE }])],
    ["a commentCreate selecting fewer fields", comment('mutation { commentCreate(input: {issueId: "x", body: "y"}) { success } }')],
  ])("does not cover %s", (_, body) => {
    expect(ruleCovers(terms, linearRequest(body))).toBe(false)
  })

  test("does not cover another asker, item, method, path, port or a query string", () => {
    const body = comment(COMMENT_CREATE, { variables: { input: {} } })
    expect(ruleCovers(terms, linearRequest(body))).toBe(true)
    expect(ruleCovers(terms, linearRequest(body, { asker: { device: "dev_alexmbp", workload: "wl_task12345" } }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { asker: { device: "dev_other", workload: null } }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { item: "linear-other" }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { itemId: "itm_linear02" }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { destination: destination("PUT", "https://api.linear.app/graphql") }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { destination: destination("POST", "https://api.linear.app/graphql?x=1") }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { destination: destination("POST", "https://api.linear.app/graphql/") }))).toBe(false)
    expect(ruleCovers(terms, linearRequest(body, { destination: destination("POST", "https://api.linear.app:8443/graphql") }))).toBe(false)
  })

  test.each([
    ["issueDelete", "rule.destructive"],
    ["webhookCreate", "rule.persistence"],
    ["organizationInviteCreate", "rule.sharing"],
    ["apiKeyCreate", "rule.credential"],
    ["deployKeyCreate", "rule.credential"],
    ["teamMembershipCreate", "rule.sharing"],
    ["emailSend", "rule.send"],
    ["project_archive", "rule.destructive"],
    ["oauth2ClientCreate", "rule.generic"],
    ["connectionUriUpdate", "rule.credential"],
    ["connectionURIs", "rule.credential"],
    ["createLINKs", "rule.sharing"],
    ["create_2LINKs", "rule.sharing"],
    ["userPromoteAdmin", "rule.credential"],
    ["userSuspend", "rule.destructive"],
    ["refForceUpdate", "rule.destructive"],
    ["issueSubscribe", "rule.persistence"],
    ["createSponsorship", "rule.money"],
    ["publish", "rule.sharing"],
    ["publishPost", "rule.sharing"],
  ] as [string, PolicyRuleRefusal][])("a %s root field asks every time, as an anchor and as a covered request", (field, reason) => {
    const body = comment(`mutation { ${field}(input: {}) { success } }`)
    expect(ruleTermsFrom({ ...linearAnchor, body }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason })
    expect(ruleCovers({ ...terms, graphql: { fields: [field], nestedFields: ["success"] } }, linearRequest(body))).toBe(false)
  })

  test.each([
    ["project(id: 1) { delete }", "rule.destructive"],
    ["project(id: 1) { settings { webhookCreate } }", "rule.persistence"],
    ["commentCreate(input: {}) { success ok: issueDelete { id } }", "rule.destructive"],
    ["workspace(id: 1) { publish }", "rule.sharing"],
  ] as [string, PolicyRuleRefusal][])("a field below the root such as mutation { %s } asks every time, as an anchor and as a covered request", (selection, reason) => {
    const body = comment(`mutation { ${selection} }`)
    const root = selection.split("(", 1)[0] ?? ""
    expect(ruleTermsFrom({ ...linearAnchor, body }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason })
    expect(ruleCovers({ ...terms, graphql: graphqlTermsOf(body) }, linearRequest(body))).toBe(false)
  })

  test("a commentCreate that selects the comment's id and body may be a rule, and covers the same shape with other input values", () => {
    const anchorBody = comment('mutation { commentCreate(input: {issueId: "ISS-1", body: "Hi"}) { success comment { id body } } }')
    const bodyTerms = termsOf({ ...linearAnchor, body: anchorBody })
    expect(bodyTerms.graphql).toEqual({ fields: ["commentCreate"], nestedFields: ["body", "comment", "id", "success"] })
    expect(ruleCovers(bodyTerms, linearRequest(comment('mutation { commentCreate(input: {issueId: "ISS-9", body: "Another"}) { success comment { id body } } }')))).toBe(true)
    expect(ruleCovers(bodyTerms, linearRequest(comment('mutation { commentCreate(input: {issueId: "ISS-9", body: "Another"}) { success comment { body id } } }')))).toBe(true)
  })

  test("a commentCreate rule does not cover the same mutation selecting an extra field below the root", () => {
    const bodyTerms = termsOf({ ...linearAnchor, body: comment('mutation { commentCreate(input: {issueId: "ISS-1", body: "Hi"}) { success comment { id body } } }') })
    expect(ruleCovers(bodyTerms, linearRequest(comment('mutation { commentCreate(input: {issueId: "ISS-1", body: "Hi"}) { success comment { id body url } } }')))).toBe(false)
    expect(ruleCovers(bodyTerms, linearRequest(comment('mutation { commentCreate(input: {issueId: "ISS-1", body: "Hi"}) { success comment { id body issue { id } } } }')))).toBe(false)
  })

  test("a rule for one nested action does not cover another under the same root field", () => {
    const renameTerms = termsOf({ ...linearAnchor, body: comment("mutation { workspace(id: 1) { rename } }") })
    expect(renameTerms.graphql).toEqual({ fields: ["workspace"], nestedFields: ["rename"] })
    expect(ruleCovers(renameTerms, linearRequest(comment("mutation { workspace(id: 2) { rename } }")))).toBe(true)
    for (const action of ["disable", "close", "lock", "merge", "cancel", "publish", "unpublish", "deactivate"]) {
      expect(ruleCovers(renameTerms, linearRequest(comment(`mutation { workspace(id: 2) { ${action} } }`))), action).toBe(false)
    }
  })

  test("a mutation naming more than 64 distinct fields below the root is refused, as an anchor and as a covered request", () => {
    const selecting = (count: number) => comment(`mutation { commentCreate(input: {}) { ${Array.from({ length: count }, (_, i) => `f${String.fromCharCode(97 + Math.floor(i / 26))}${String.fromCharCode(97 + (i % 26))}`).join(" ")} } }`)
    expect(ruleTermsFrom({ ...linearAnchor, body: selecting(64) }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true })
    expect(ruleTermsFrom({ ...linearAnchor, body: selecting(65) }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.graphql" })
    const graphql = graphqlTermsOf(selecting(64))
    expect(ruleCovers({ ...terms, graphql }, linearRequest(selecting(64)))).toBe(true)
    expect(ruleCovers({ ...terms, graphql }, linearRequest(selecting(65)))).toBe(false)
  })

  test("a field named at several depths is pinned once", () => {
    expect(termsOf({ ...linearAnchor, body: comment("mutation { commentCreate(input: {}) { success comment { id issue { id } } } }") }).graphql).toEqual({ fields: ["commentCreate"], nestedFields: ["comment", "id", "issue", "success"] })
  })

  test.each(["commentCreate", "issueCreate", "issueUpdate"])("a %s root field may be a rule", (field) => {
    const body = comment(`mutation { ${field}(input: {}) { success } }`)
    expect(ruleTermsFrom({ ...linearAnchor, body }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true, terms: { graphql: { fields: [field], nestedFields: ["success"] } } })
  })

  test.each([
    ["a form", "application/x-www-form-urlencoded"],
    ["text/plain", "text/plain"],
    ["no content type", null],
    ["another parameter", "application/json; foo=bar"],
    ["a second charset", "application/json; charset=utf-8; charset=latin1"],
    ["another charset", "application/json; charset=utf-16"],
    ["a JSON suffix type", "application/graphql+json"],
  ])("a GraphQL body sent as %s is refused, as an anchor and as a covered request", (_, contentType) => {
    expect(ruleTermsFrom({ ...linearAnchor, contentType }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.graphql" })
    expect(ruleCovers(terms, linearRequest(linearAnchor.body, { contentType }))).toBe(false)
  })

  test.each(["application/json", "Application/JSON", "application/json; charset=utf-8", "application/json;charset=UTF-8"])("a GraphQL body sent as %s may be a rule", (contentType) => {
    expect(ruleTermsFrom({ ...linearAnchor, contentType }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true })
    expect(ruleCovers(terms, linearRequest(linearAnchor.body, { contentType }))).toBe(true)
  })

  test("a GraphQL anchor whose proof fails is refused", () => {
    expect(ruleTermsFrom({ ...linearAnchor, body: comment('mutation { a: commentCreate(input: {}) { success } }') }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.graphql" })
    expect(ruleTermsFrom({ ...linearAnchor, destination: destination("POST", "https://api.linear.app/graphql?operationName=X") }, { path: "/graphql", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.graphql" })
  })
})

describe("GitHub issue comment anchor", () => {
  test("offers the exact path and the issue number as *", () => {
    expect(policyRulePathChoices("/repos/alex/vault/issues/42/comments")).toEqual(["/repos/alex/vault/issues/42/comments", GITHUB_PATTERN])
  })

  test("is allowed with the id-segment pattern and covers another issue's comment", () => {
    const terms = termsOf(githubAnchor, GITHUB_PATTERN, 2_592_000)
    expect(terms).toMatchObject({ method: "POST", host: "api.github.com", path: GITHUB_PATTERN, anchorPath: "/repos/alex/vault/issues/42/comments", queryNames: [], graphql: null, ttlSeconds: 2_592_000 })
    expect(ruleCovers(terms, githubRequest("POST", "/repos/alex/vault/issues/43/comments", json({ body: "Another" })))).toBe(true)
    for (const request of [
      githubRequest("POST", "/repos/alex/vault/issues/token/comments"),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments/"),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments/1"),
      githubRequest("POST", "/repos/alex/other/issues/43/comments"),
      githubRequest("PATCH", "/repos/alex/vault/issues/43/comments"),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments?per_page=1"),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments", json([{ body: "batch" }])),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments", json({ query: "mutation { deleteRef { id } }" })),
      githubRequest("POST", "/repos/alex/vault/issues/43/comments", json({ _method: "DELETE", body: "x" })),
    ]) {
      expect(ruleCovers(terms, request), `${request.destination.method} ${request.destination.path}${request.destination.search}`).toBe(false)
    }
  })

  test("the exact path covers only that issue", () => {
    const terms = termsOf(githubAnchor)
    expect(ruleCovers(terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments"))).toBe(true)
    expect(ruleCovers(terms, githubRequest("POST", "/repos/alex/vault/issues/43/comments"))).toBe(false)
  })

  test("a path or duration the vault did not offer is refused", () => {
    expect(ruleTermsFrom(githubAnchor, { path: "/repos/alex/*/issues/42/comments", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.path" })
    expect(ruleTermsFrom(githubAnchor, { path: "/repos/alex/vault/issues/**", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.path" })
    expect(ruleTermsFrom(githubAnchor, { path: GITHUB_PATTERN, ttlSeconds: 3600 })).toEqual({ ok: false, reason: "rule.duration" })
  })
})

// The GraphQL terms a body would pin if its proof holds, without the floor checks.
function graphqlTermsOf(body: Uint8Array | null): PolicyRuleTerms["graphql"] {
  const proof = graphqlMutationRootFields(body)
  return proof.ok ? { fields: [...proof.fields].sort(), nestedFields: [...new Set(proof.nestedFields)].sort() } : null
}

// Anchors ruleTermsFrom refuses, whatever path and duration are chosen.
const REFUSED_ANCHORS: [string, PolicyRuleAnchor, PolicyRuleRefusal][] = [
  ["a DELETE", githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null), "rule.destructive"],
  ["a Stripe money route", { ...template("stripe"), item: "stripe-test", itemId: "itm_stripe01", asker, destination: destination("POST", "https://api.stripe.com/v1/charges"), body: json({ amount: 100 }), contentType: "application/json", contentEncoding: null, secretPrefixes: ["sk_test_"] }, "rule.money"],
  ["a /token path", custom("POST", "/v1/token", json({ name: "ci" })), "rule.generic"],
  ["a batch body", custom("POST", "/v1/tasks", json([{ task: "a" }, { task: "b" }])), "rule.body"],
  ["an sk_live_ key", custom("POST", "/v1/tasks", json({ task: "a" }), ["sk_live_"]), "rule.live-key"],
  ["an rk_live_ key", custom("POST", "/v1/tasks", json({ task: "a" }), ["rk_live_"]), "rule.live-key"],
  ["a GitHub webhook (deny)", githubRequest("POST", "/repos/alex/vault/hooks", json({ name: "web" })), "rule.deny"],
  ["a GraphQL query parameter", custom("POST", "/v1/tasks?query=x", json({ task: "a" })), "rule.query"],
  ["a repeated query parameter", custom("POST", "/v1/tasks?a=1&a=2", json({ task: "a" })), "rule.query"],
  ["a method override in the query", custom("POST", "/v1/tasks?_method=DELETE", json({ task: "a" })), "rule.query"],
  ["plain HTTP", { ...custom("POST", "/v1/tasks", json({ task: "a" })), destination: destination("POST", "http://api.example.com/v1/tasks") }, "rule.destination"],
  ["a GitHub comment whose secret is now a live key", githubRequest("POST", "/repos/alex/vault/issues/42/comments", undefined, { secretPrefixes: ["sk_live_"] }), "rule.live-key"],
  ["a path outside the binding", { ...custom("POST", "/v1/tasks", json({ task: "a" })), binding: { hosts: ["api.example.com"], paths: ["/v2/**"] } }, "rule.binding"],
  ["a Linear issueDelete", linearRequest(comment('mutation { issueDelete(id: "ISS-1") { success } }')), "rule.destructive"],
  ["a Linear commentCreate sent as a form", linearRequest(linearAnchor.body, { contentType: "application/x-www-form-urlencoded" }), "rule.graphql"],
  ["a host outside the binding", { ...custom("POST", "/v1/tasks", json({ task: "a" })), binding: { hosts: ["other.example.com"] } }, "rule.binding"],
  ["an item rule that asks", { ...custom("POST", "/v1/tasks", json({ task: "a" })), policy: { default: "allow", rules: [{ action: "approve", methods: ["POST"], paths: ["/v1/tasks"] }] } }, "rule.item-rule"],
  ["a JSON body sent as a form to a custom /api", { ...custom("POST", "/api", json({ a: "&query=mutation%7BdeleteEverything%7D&" })), contentType: "application/x-www-form-urlencoded" }, "rule.body"],
  ["a JSON body sent as text to a custom /api", { ...custom("POST", "/api", json({ a: "x" })), contentType: "text/plain" }, "rule.body"],
  ["a custom POST /v1/messages/send", custom("POST", "/v1/messages/send", json({ to: "a" })), "rule.send"],
  ["a custom POST /v2/email", custom("POST", "/v2/email", json({ to: "a" })), "rule.send"],
  ["a custom POST /v1/Messages", custom("POST", "/v1/Messages", json({ to: "a" })), "rule.send"],
  ["a custom POST /v1/%73end", custom("POST", "/v1/%73end", json({ to: "a" })), "rule.send"],
  ["a custom POST /payments", custom("POST", "/payments", json({ amount: 1 })), "rule.money"],
  ["a custom POST /charges", custom("POST", "/charges", json({ amount: 1 })), "rule.money"],
  ["a custom PUT /settings/forwarding", custom("PUT", "/settings/forwarding", json({ to: "a" })), "rule.persistence"],
  ["a custom POST /posts/1/publish", custom("POST", "/posts/1/publish", json({ at: "now" })), "rule.sharing"],
  ["a custom PATCH /v1/transfer-ownership", custom("PATCH", "/v1/transfer-ownership", json({ to: "a" })), "rule.sharing"],
  ["a custom POST /v1/connection_uri", custom("POST", "/v1/connection_uri", json({ a: "b" })), "rule.credential"],
  ["a custom GET /bot123456:TEST/sendMessage", custom("GET", "/bot123456:TEST/sendMessage?chat_id=1&text=hi", null), "rule.send"],
  ["a custom HEAD /v1/posts/1/publish", custom("HEAD", "/v1/posts/1/publish", null), "rule.sharing"],
  ["a custom GET /v1/orders/7/refund", custom("GET", "/v1/orders/7/refund", null), "rule.money"],
  ["a Microsoft Graph event", graphRequest("POST", "/v1.0/me/events"), "rule.send"],
  ["a Microsoft Graph event in another calendar", graphRequest("POST", "/v1.0/me/calendars/C1/events"), "rule.send"],
  ["a Microsoft Graph event of another user", graphRequest("POST", "/beta/users/U1/events"), "rule.send"],
  ["a Microsoft Graph event update", graphRequest("PATCH", "/v1.0/me/events/E1"), "rule.send"],
  ["a Microsoft Graph event update by a key in parentheses", graphRequest("PATCH", "/v1.0/me/events('E1')"), "rule.send"],
  ["a Microsoft Graph event answer by a key in parentheses", graphRequest("POST", "/v1.0/me/events('E1')/accept"), "rule.send"],
  ["a Microsoft Graph event answer spelt in capitals", graphRequest("POST", "/v1.0/me/Events/E1/accept"), "rule.send"],
  ["a Google Calendar event insert", calendarRequest("POST", "/calendar/v3/calendars/primary/events"), "rule.send"],
  ["a Google Calendar event patch", calendarRequest("PATCH", "/calendar/v3/calendars/primary/events/E1"), "rule.send"],
  ["a Google Calendar event update", calendarRequest("PUT", "/calendar/v3/calendars/primary/events/E1"), "rule.send"],
  ["a Google Calendar event move", calendarRequest("POST", "/calendar/v3/calendars/primary/events/E1/move?destination=C2", null), "rule.send"],
  ["a Google Calendar event import", calendarRequest("POST", "/calendar/v3/calendars/primary/events/import", json({ iCalUID: "x" })), "rule.send"],
  ["a GitHub repository change", githubRequest("PATCH", "/repos/alex/vault", json({ private: false })), "rule.sharing"],
  ["a GitHub repository change by id", githubRequest("PATCH", "/repositories/123", json({ private: false })), "rule.sharing"],
  ["a GitHub organisation's settings", githubRequest("PATCH", "/orgs/acme", json({ description: "Audit" })), "rule.sharing"],
  ["a GitHub organisation's settings by id", githubRequest("PATCH", "/organizations/123", json({ description: "Audit" })), "rule.sharing"],
  ["a GitHub organisation's settings over OAuth", { ...githubRequest("PATCH", "/orgs/acme", json({ description: "Audit" })), ...provider("github-oauth"), secretPrefixes: [] }, "rule.sharing"],
  ["a GitHub team creation", githubRequest("POST", "/orgs/acme/teams", json({ name: "audit" })), "rule.sharing"],
  ["a GitHub team creation by organisation id", githubRequest("POST", "/organizations/123/teams", json({ name: "audit" })), "rule.sharing"],
  ["a GitHub team's settings", githubRequest("PATCH", "/orgs/acme/teams/audit", json({ privacy: "closed" })), "rule.sharing"],
  ["a GitHub team repository grant", githubRequest("PUT", "/orgs/acme/teams/audit/repos/acme/app", json({ permission: "push" })), "rule.sharing"],
  ["a GitHub team project grant", githubRequest("PUT", "/orgs/acme/teams/audit/projects/7", json({ permission: "write" })), "rule.sharing"],
  ["a GitHub team repository grant by ids", githubRequest("PUT", "/organizations/123/team/456/repos/acme/app", json({ permission: "push" })), "rule.sharing"],
  ["a legacy GitHub team repository grant", githubRequest("PUT", "/teams/456/repos/acme/app", json({ permission: "push" })), "rule.sharing"],
  ["a legacy GitHub team's settings", githubRequest("PATCH", "/teams/456", json({ privacy: "closed" })), "rule.sharing"],
  ["a GitHub security manager team", githubRequest("PUT", "/orgs/acme/security-managers/teams/audit", json({})), "rule.sharing"],
  ["a GitHub organisation block", githubRequest("PUT", "/orgs/acme/blocks/octocat", json({})), "rule.sharing"],
  ["a GitHub organisation ruleset", githubRequest("POST", "/orgs/acme/rulesets", json({ name: "main" })), "rule.sharing"],
  ["a GitHub repository ruleset", githubRequest("PUT", "/repos/acme/app/rulesets/7", json({ name: "main" })), "rule.sharing"],
  ["a GitHub branch protection", githubRequest("PUT", "/repos/acme/app/branches/main/protection", json({ enforce_admins: false })), "rule.sharing"],
  ["a GitHub branch push restriction", githubRequest("POST", "/repos/acme/app/branches/main/protection/restrictions/users", json({ users: ["someone"] })), "rule.sharing"],
  ["a GitHub branch protection on a branch with a slash", githubRequest("PUT", "/repos/acme/app/branches/release/v1/protection", json({ enforce_admins: false })), "rule.sharing"],
  ["a GitHub branch protection on a branch with a slash by id", githubRequest("PUT", "/repositories/123/branches/release/v1/protection", json({ enforce_admins: false })), "rule.sharing"],
  ["a GitHub environment's settings", githubRequest("PUT", "/repos/acme/app/environments/production", json({ reviewers: [] })), "rule.sharing"],
  ["a GitHub environment's settings by id", githubRequest("PUT", "/repositories/123/environments/production", json({ reviewers: [] })), "rule.sharing"],
  ["a GitHub environment protection rule", githubRequest("POST", "/repos/acme/app/environments/production/deployment_protection_rules", json({ integration_id: 5 })), "rule.sharing"],
  ["a GitHub environment deployment branch policy", githubRequest("POST", "/repos/acme/app/environments/production/deployment-branch-policies", json({ name: "release/*" })), "rule.sharing"],
  ["a GitHub environment deployment branch policy change", githubRequest("PUT", "/repos/acme/app/environments/production/deployment-branch-policies/9", json({ name: "*" })), "rule.sharing"],
  ["a GitHub fork", githubRequest("POST", "/repos/acme/app/forks", json({ organization: "elsewhere" })), "rule.sharing"],
  ["a GitHub fork by id", githubRequest("POST", "/repositories/123/forks", json({ organization: "elsewhere" })), "rule.sharing"],
  ["a GitHub repository from a template", githubRequest("POST", "/repos/acme/app/generate", json({ owner: "elsewhere", name: "copy" })), "rule.sharing"],
  ["a GitHub Pages site", githubRequest("POST", "/repos/acme/app/pages", json({ source: { branch: "main" } })), "rule.sharing"],
  ["a GitHub Pages site change", githubRequest("PUT", "/repos/acme/app/pages", json({ public: true })), "rule.sharing"],
  ["a Vercel project's settings", vercelRequest("PATCH", "/v9/projects/my-app", json({ framework: "nextjs" })), "rule.sharing"],
  ["a Vercel project's settings without a version", vercelRequest("PATCH", "/projects/my-app", json({ framework: "nextjs" })), "rule.sharing"],
  ["a Vercel protection bypass", vercelRequest("PATCH", "/v1/projects/my-app/protection-bypass", json({ generate: {} })), "rule.sharing"],
  ["a Vercel team's settings", vercelRequest("PATCH", "/v2/teams/team_1", json({ name: "Acme" })), "rule.sharing"],
]

// The terms a refused anchor would have had at its own path, so ruleCovers
// can be asked whether they cover it.
function termsLike(anchor: PolicyRuleAnchor, path = anchor.destination.path): PolicyRuleTerms {
  const d = anchor.destination
  const graphql = d.path === "/graphql" ? graphqlTermsOf(anchor.body) : null
  const queryNames = d.search === "" ? [] : [...new Set(d.search.slice(1).split("&").map((part) => part.split("=")[0] ?? ""))].sort()
  return { item: anchor.item, itemId: anchor.itemId, asker: anchor.asker, method: d.method as PolicyRuleTerms["method"], host: d.host, path, anchorPath: d.path, queryNames, graphql, ttlSeconds: RULE_DEFAULT_DURATION }
}

describe("held requests that ask every time", () => {
  const choice = (anchor: PolicyRuleAnchor) => ({ path: anchor.destination.path, ttlSeconds: RULE_DEFAULT_DURATION })
  test.each(REFUSED_ANCHORS)("%s is refused", (_, anchor, reason) => {
    expect(ruleTermsFrom(anchor, choice(anchor))).toEqual({ ok: false, reason })
  })

  test.each(REFUSED_ANCHORS)("%s is not covered by terms that name it", (_, anchor) => {
    const terms = termsLike(anchor)
    expect(PolicyRuleTermsSchema.safeParse(terms).success).toBe(anchor.destination.method !== "DELETE")
    expect(ruleCovers(terms, anchor)).toBe(false)
  })

  test("an event write and a GitHub repository change are refused as rules only: no floor holds them, so the item's own policy decides", () => {
    for (const anchor of [graphRequest("POST", "/v1.0/me/events"), graphRequest("PATCH", "/v1.0/me/events('E1')"), calendarRequest("PATCH", "/calendar/v3/calendars/primary/events/E1"), githubRequest("PATCH", "/repos/alex/vault", json({ private: false }))]) {
      expect(evaluatePolicyFloor({ destination: anchor.destination, body: anchor.body, contentType: anchor.contentType, contentEncoding: null }), anchor.destination.path).toEqual({ action: "allow", reasons: [] })
    }
  })

  test("an organisation's or a Vercel project's settings are not covered with a later body that changes who has access", () => {
    const org = githubRequest("PATCH", "/orgs/acme", json({ description: "Audit" }))
    expect(ruleCovers(termsLike(org), { ...org, body: json({ default_repository_permission: "admin" }) })).toBe(false)
    const project = vercelRequest("PATCH", "/v9/projects/my-app", json({ framework: "nextjs" }))
    expect(ruleCovers(termsLike(project), { ...project, body: json({ publicSource: true }) })).toBe(false)
  })

  test("an ordinary write beside the access-changing ones may still be a rule", () => {
    for (const anchor of [
      githubAnchor, linearAnchor, custom("POST", "/tasks", json({ task: "a" })),
      githubRequest("PATCH", "/repos/alex/vault/issues/42", json({ title: "Renamed" })), githubRequest("POST", "/repos/alex/vault/pulls", json({ title: "Fix", head: "fix", base: "main" })),
      githubRequest("POST", "/repos/alex/vault/pulls/1/reviews", json({ event: "COMMENT", body: "Looks right." })),
      vercelRequest("POST", "/v13/deployments", json({ name: "my-app" })),
    ]) {
      const terms = termsOf(anchor)
      expect(ruleCovers(terms, anchor), anchor.destination.path).toBe(true)
    }
  })

  test("the same key-less request without a live prefix may be a rule", () => {
    const anchor = custom("POST", "/v1/tasks/7?view=full", json({ task: "a" }), ["sk_test_"])
    const terms = termsOf(anchor, "/v1/tasks/*")
    expect(terms).toMatchObject({ path: "/v1/tasks/*", queryNames: ["view"], graphql: null })
    expect(ruleCovers(terms, { ...anchor, destination: destination("POST", "https://api.example.com/v1/tasks/8?view=short") })).toBe(true)
    expect(ruleCovers(terms, { ...anchor, destination: destination("POST", "https://api.example.com/v1/tasks/8") })).toBe(false)
    expect(ruleCovers(terms, { ...anchor, destination: destination("POST", "https://api.example.com/v1/tasks/8?view=short&x=1") })).toBe(false)
    expect(ruleCovers(terms, { ...anchor, destination: destination("POST", "https://api.example.com/v1/tasks/8?view=token") })).toBe(false)
    expect(ruleCovers(terms, { ...anchor, destination: destination("DELETE", "https://api.example.com/v1/tasks/8?view=short") })).toBe(false)
  })

  test("a custom POST /tasks and a custom GET /v1/messages may be rules: a read is refused only for a word that does something", () => {
    expect(ruleTermsFrom(custom("POST", "/tasks", json({ task: "a" })), { path: "/tasks", ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true })
    for (const path of ["/v1/messages", "/v1/emails", "/v1/payments", "/v1/settings"]) {
      const read = custom("GET", path, null)
      const terms = termsOf(read)
      expect(terms).toMatchObject({ method: "GET", path })
      expect(ruleCovers(terms, read)).toBe(true)
    }
  })

  test.each([
    ["/v1/env/prod", "rule.credential"],
    ["/v1/acls", "rule.sharing"],
    ["/v1/status-report", "rule.send"],
  ] as [string, PolicyRuleRefusal][])("a custom write to %s is refused by a word the floor marks at a segment's start or as all of it", (path, reason) => {
    expect(ruleTermsFrom(custom("POST", path, json({ a: "b" })), { path, ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason })
  })

  test.each(["/v1/environments", "/v1/oracle"])("a custom write to %s may be a rule: the floor's word is not at a segment's start or all of it", (path) => {
    expect(ruleTermsFrom(custom("POST", path, json({ a: "b" })), { path, ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true })
  })

  test("a GitHub issue comment on a repository whose name holds a floor word may be a rule, as a catalogue route", () => {
    const anchor = githubRequest("POST", "/repos/alex/payments-email/issues/42/comments")
    expect(ruleCovers(termsOf(anchor, "/repos/alex/payments-email/issues/*/comments"), githubRequest("POST", "/repos/alex/payments-email/issues/43/comments"))).toBe(true)
  })

  test("a rule on a custom path does not cover a write whose path names a send", () => {
    const terms = termsOf(custom("POST", "/v1/items/7", json({ a: "b" })), "/v1/items/*")
    expect(ruleCovers(terms, custom("POST", "/v1/items/8", json({ a: "b" })))).toBe(true)
    expect(ruleCovers({ ...terms, path: "/v1/send/*", anchorPath: "/v1/send/7" }, custom("POST", "/v1/send/8", json({ a: "b" })))).toBe(false)
  })

  test("a rule from a JSON anchor on a custom /api does not cover the same bytes sent as a form", () => {
    const anchor = custom("POST", "/api", json({ query: "query { viewer { id } }" }))
    const terms = termsOf(anchor)
    expect(terms).toMatchObject({ path: "/api", queryNames: [], graphql: null })
    const later = custom("POST", "/api", json({ a: "&query=mutation%7BdeleteEverything%7D&" }))
    expect(ruleCovers(terms, later)).toBe(true)
    for (const contentType of ["application/x-www-form-urlencoded", "text/plain", "application/json; foo=bar", null]) {
      expect(ruleCovers(terms, { ...later, contentType }), String(contentType)).toBe(false)
    }
  })

  test.each([
    ["a Relay document id with variables", { doc_id: "1234567890", variables: { project: "123" } }],
    ["a query id with variables", { queryId: "DeleteProject", variables: {} }],
    ["a hash with variables", { hash: "abc", variables: {} }],
  ])("%s on a custom /api is no rule, and a plain JSON rule there does not cover it", (_, body) => {
    const persisted = custom("POST", "/api", json(body))
    expect(ruleTermsFrom(persisted, { path: "/api", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.graphql" })
    const terms = termsOf(custom("POST", "/api", json({ task: "a" })))
    expect(terms.graphql).toBeNull()
    expect(ruleCovers(terms, persisted)).toBe(false)
  })

  test("a pattern whose * is the first segment the binding leaves open is refused", () => {
    const anchor = custom("POST", "/7", json({ task: "a" }))
    expect(policyRulePathChoices("/7")).toEqual(["/7", "/*"])
    expect(ruleTermsFrom(anchor, { path: "/*", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.binding" })
    expect(ruleTermsFrom(anchor, { path: "/7", ttlSeconds: RULE_DEFAULT_DURATION })).toMatchObject({ ok: true })
    expect(PolicyRuleTermsSchema.safeParse(termsLike(anchor, "/*")).success).toBe(true)
    expect(ruleCovers(termsLike(anchor, "/*"), custom("POST", "/8", json({ task: "a" })))).toBe(false)
  })
})

// The live hard floors the widening window was tested against, now that a
// standing rule is the only way to widen: a generic floor word anywhere in
// the path or the query, however it is spelt, and a body the safety checks
// refuse.
const percentEncoded = (word: string, hex: (digits: string) => string) => word.split("").map((c) => `%${hex(c.charCodeAt(0).toString(16))}`).join("")
const FLOOR_WORD_SPELLINGS: [string, (word: string) => string][] = [
  ["plain", (word) => word],
  ["in upper case", (word) => word.toUpperCase()],
  ["percent-encoded with lower-case escapes", (word) => percentEncoded(word, (digits) => digits)],
  ["percent-encoded with upper-case escapes", (word) => percentEncoded(word, (digits) => digits.toUpperCase())],
  ["hyphenated", (word) => word.split("").join("-")],
]
const FLOOR_WORD_PLACES: [string, (spelt: string) => string][] = [
  ["the path", (spelt) => `/v1/${spelt}Suffix`],
  ["a query name", (spelt) => `/v1/tasks?${spelt}=value`],
  ["a query value", (spelt) => `/v1/tasks?op=create${spelt}`],
]

describe("the live hard floors refuse a rule", () => {
  const choice = (anchor: PolicyRuleAnchor) => ({ path: anchor.destination.path, ttlSeconds: RULE_DEFAULT_DURATION })
  const cases = GENERIC_POLICY_FLOOR_WORDS.flatMap((word) => FLOOR_WORD_SPELLINGS.flatMap(([spelling, spell]) => FLOOR_WORD_PLACES.map(([place, at]): [string, string, string, string] => [word, spelling, place, at(spell(word))])))

  test.each(cases)("the generic word %s, %s, in %s", (_word, _spelling, _place, path) => {
    const anchor = custom("POST", path, json({ task: "a" }))
    expect(ruleTermsFrom(anchor, choice(anchor))).toEqual({ ok: false, reason: "rule.generic" })
  })

  test.each(FLOOR_WORD_PLACES)("a word the floor does not hold in %s may be a rule", (_place, at) => {
    const anchor = custom("POST", at("comment"), json({ task: "a" }))
    expect(ruleTermsFrom(anchor, choice(anchor))).toMatchObject({ ok: true })
  })

  test.each([
    ["a JSON-RPC call", '{"jsonrpc":"2.0","method":"do"}', "application/json"],
    ["a duplicate key", '{"title":"one","title":"two"}', "application/json"],
    ["malformed JSON", '{"title":', "application/json"],
    ["a JSON text sequence", '\u001e{"title":"a"}\n', "application/json-seq"],
    ["a multipart form", "--boundary\r\nopaque", "multipart/form-data; boundary=boundary"],
    ["plain text", "change something", "text/plain"],
  ])("a body holding %s", (_, body, contentType) => {
    const anchor = { ...custom("POST", "/v1/tasks", new TextEncoder().encode(body)), contentType }
    expect(ruleTermsFrom(anchor, choice(anchor))).toEqual({ ok: false, reason: "rule.body" })
  })
})

// The one floor test standing rules, task grants and postures share: every
// refusal ruleShape gives except those about the rule itself (a live key,
// the binding, the query string it pins, a body not sent as exactly JSON).
describe("policyFloorRefusal", () => {
  const NOT_FLOOR = new Set([
    "an sk_live_ key", "an rk_live_ key", "a GitHub comment whose secret is now a live key", "a path outside the binding", "a host outside the binding",
    "a GraphQL query parameter", "a repeated query parameter", "a method override in the query", "a JSON body sent as a form to a custom /api", "a JSON body sent as text to a custom /api",
  ])

  test.each(REFUSED_ANCHORS)("%s", (label, anchor, reason) => {
    expect(policyFloorRefusal(anchor)).toBe(NOT_FLOOR.has(label) ? null : reason)
  })

  test("every refusal that is not the floor's is one a rule makes of itself", () => {
    const reasons = new Set(REFUSED_ANCHORS.filter(([label]) => NOT_FLOOR.has(label)).map(([, , reason]) => reason))
    expect([...reasons].sort()).toEqual(["rule.binding", "rule.body", "rule.live-key", "rule.query"])
  })

  test.each([
    ["a GraphQL field naming a floor word", linearRequest(comment('mutation { webhookCreate(input: {}) { success } }')), "rule.persistence"],
    ["a GraphQL field below the root naming a floor word", linearRequest(comment("mutation { project(id: 1) { delete } }")), "rule.destructive"],
    ["a GraphQL mutation sent as a form", linearRequest(linearAnchor.body, { contentType: "application/x-www-form-urlencoded" }), "rule.graphql"],
    ["a GraphQL mutation with a query string", linearRequest(linearAnchor.body, { destination: destination("POST", "https://api.linear.app/graphql?x=1") }), "rule.graphql"],
    ["an OPTIONS request", custom("OPTIONS", "/v1/tasks", null), "rule.method"],
  ] as [string, PolicyRuleAnchor, PolicyRuleRefusal][])("%s", (_, request, reason) => {
    expect(policyFloorRefusal(request)).toBe(reason)
  })

  test("a request a rule may cover passes it, and so does a JSON body a rule refuses only for its content type", () => {
    for (const anchor of [
      githubAnchor, linearAnchor, custom("POST", "/tasks", json({ task: "a" })), custom("GET", "/v1/messages", null),
      githubRequest("POST", "/repos/alex/payments-email/issues/42/comments"), vercelRequest("POST", "/v13/deployments", json({ name: "my-app" })),
    ]) {
      expect(policyFloorRefusal(anchor), anchor.destination.path).toBeNull()
    }
    const typed = { ...custom("POST", "/v1/tasks", json({ task: "a" })), contentType: "application/json; foo=bar" }
    expect(policyFloorRefusal(typed)).toBeNull()
    expect(ruleTermsFrom(typed, { path: "/v1/tasks", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.body" })
  })
})

// A Slack item keeps the policy it was stored with; the floor is the
// template's as it is now, so splitting the template's rules changes what an
// item stored before the split gives as well.
describe("Slack's chat floor after the template split", () => {
  const STORED_BEFORE_SPLIT: Policy = {
    default: "approve",
    rules: [{ action: "approve", paths: ["/api/chat.postMessage", "/api/chat.postEphemeral", "/api/chat.scheduleMessage", "/api/chat.meMessage", "/api/chat.update", "/api/chat.delete", "/api/conversations.invite"], note: "posts, shares or invites as the bot" }],
  }
  const slackRequest = (method: string, policy: Policy): PolicyRuleAnchor => ({
    item: "slack-bot", itemId: "itm_slack001", asker, destination: destination("POST", `https://slack.com/api/${method}`), body: json({ channel: "C1", text: "hi" }), contentType: "application/json", contentEncoding: null,
    policy, binding: template("slack-bot").binding, secretPrefixes: ["xoxb-"],
  })

  test.each([
    ["chat.postMessage", "rule.send"], ["chat.postEphemeral", "rule.send"], ["chat.scheduleMessage", "rule.send"], ["chat.meMessage", "rule.send"], ["chat.update", "rule.send"],
    ["chat.delete", "rule.opaque"], ["conversations.invite", "rule.sharing"],
  ] as [string, PolicyRuleRefusal][])("%s gives %s on the template's policy and on an item stored before the split", (method, reason) => {
    expect(policyFloorRefusal(slackRequest(method, template("slack-bot").policy))).toBe(reason)
    expect(policyFloorRefusal(slackRequest(method, STORED_BEFORE_SPLIT))).toBe(reason)
  })

  // Floor ids are positional, so the delete and invite rules come after the
  // chat rule, Slack's last: no id that stood before the split moves.
  test("keeps every floor id that stood before the split and adds the new rules after them", () => {
    expect(POLICY_FLOOR.filter((entry) => entry.host === "slack.com").map((entry) => [entry.id, entry.reason])).toEqual([
      ["slack-bot.floor-1", "sharing"], ["slack-bot.floor-2", "send"], ["slack-bot.floor-3", "opaque"], ["slack-bot.floor-4", "sharing"],
    ])
  })
})

describe("rule terms", () => {
  const terms = termsOf(githubAnchor, GITHUB_PATTERN)

  test("the schema takes only terms the vault could have built", () => {
    expect(PolicyRuleTermsSchema.parse(terms)).toEqual(terms)
    expect(PolicyRuleTermsSchema.safeParse({ ...terms, graphql: { fields: ["commentCreate"], nestedFields: [] } }).success).toBe(true)
    expect(PolicyRuleTermsSchema.safeParse({ ...terms, graphql: { fields: ["commentCreate"], nestedFields: Array.from({ length: 64 }, (_, i) => `f${String(i).padStart(2, "0")}`) } }).success).toBe(true)
    for (const patch of [
      { path: "/repos/alex/vault/issues/**" },
      { path: "/repos/*/vault/issues/42/comments" },
      { path: "/repos/alex/vault/issues/*/*" },
      { method: "DELETE" },
      { ttlSeconds: 3600 },
      { queryNames: ["b", "a"] },
      { queryNames: ["a", "a"] },
      { graphql: { fields: [], nestedFields: [] } },
      { graphql: { fields: ["commentCreate"], nestedFields: [] }, queryNames: ["a"] },
      { graphql: { fields: ["commentCreate"] } },
      { graphql: { fields: ["commentCreate"], nestedFields: ["success", "comment"] } },
      { graphql: { fields: ["commentCreate"], nestedFields: ["id", "id"] } },
      { graphql: { fields: ["commentCreate"], nestedFields: ["not-a-name"] } },
      { graphql: { fields: ["commentCreate"], nestedFields: Array.from({ length: 65 }, (_, i) => `f${String(i).padStart(2, "0")}`) } },
      { asker: { device: "dev_alexmbp", workload: "task-1" } },
      { asker: { device: "dev_alexmbp" } },
      { host: "API.github.com" },
      { itemId: "github-work" },
      { itemId: undefined },
      { extra: true },
    ]) {
      expect(PolicyRuleTermsSchema.safeParse({ ...terms, ...patch }).success, JSON.stringify(patch)).toBe(false)
    }
  })

  test("ruleCovers refuses terms the schema refuses", () => {
    expect(ruleCovers({ ...terms, path: "/repos/alex/vault/issues/**" }, githubRequest("POST", "/repos/alex/vault/issues/42/comments"))).toBe(false)
  })

  test("a remembered digest matches only the terms it was made from", async () => {
    const digest = await policyRuleTermsDigest(terms)
    expect(PolicyRememberSchema.safeParse({ kind: "rule", path: terms.path, ttlSeconds: terms.ttlSeconds, termsDigest: digest }).success).toBe(true)
    expect(await policyRuleTermsDigestMatches(terms, digest)).toBe(true)
    expect(await policyRuleTermsDigestMatches({ ...terms, path: terms.anchorPath }, digest)).toBe(false)
    expect(await policyRuleTermsDigestMatches({ ...terms, ttlSeconds: RULE_DURATIONS[2] }, digest)).toBe(false)
    expect(await policyRuleTermsDigestMatches(terms, await policyRuleTermsDigest({ ...terms, graphql: { fields: ["issueDelete"], nestedFields: [] }, queryNames: [] }))).toBe(false)
    expect(await policyRuleTermsDigestMatches(terms, "")).toBe(false)
  })

  test("the digest is canonical JSON under the rule domain and changes with every term", async () => {
    const digest = await policyRuleTermsDigest(terms)
    expect(digest).toBe(await sha256B64(canonicalJson({ domain: "mehen-policy-rule/v1", terms })))
    expect(await policyRuleTermsDigest({ ...terms })).toBe(digest)
    for (const patch of [{ item: "github-other" }, { itemId: "itm_github02" }, { asker: { device: "dev_alexmbp", workload: "wl_task12345" } }, { path: terms.anchorPath }, { queryNames: ["a"] }, { ttlSeconds: RULE_DURATIONS[0] }, { graphql: { fields: ["x"], nestedFields: [] } }, { graphql: { fields: ["x"], nestedFields: ["y"] } }] as Partial<PolicyRuleTerms>[]) {
      expect(await policyRuleTermsDigest({ ...terms, ...patch })).not.toBe(digest)
    }
  })
})

describe("areaGrantCovers", () => {
  const terms: PolicyAreaGrantTerms = { kind: "area", item: "github-work", itemId: "itm_github01", asker, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50 }
  const exampleCatalogue: PolicyCatalogue = {
    template: "example", version: 2, hosts: ["api.example.com"], floor: [],
    areas: [{ id: "tasks", name: "Tasks", words: "Makes tasks" }, { id: "lists", name: "Lists", words: "Makes lists" }],
    entries: [
      { id: "example.task-create", area: "tasks", effect: "routine", methods: ["POST"], path: "/v1/tasks", body: "json", words: "Makes a task", since: 1, additionalPermission: false },
      { id: "example.list-create", area: "lists", effect: "routine", methods: ["POST"], path: "/v1/lists", body: "json", words: "Makes a list", since: 2, additionalPermission: false },
    ],
  }
  const exampleTerms: PolicyAreaGrantTerms = { ...terms, item: "tasks-key", itemId: "itm_tasks001", host: "api.example.com", catalogue: "example", areas: ["lists", "tasks"] }

  test("covers a routine entry in one of its areas, for the same key and credential, on the binding", () => {
    expect(areaGrantCovers(terms, githubAnchor)).toBe(true)
    expect(areaGrantCovers(terms, githubRequest("POST", "/repos/alex/other/issues", json({ title: "A bug" })))).toBe(true)
    expect(areaGrantCovers(terms, githubRequest("PATCH", "/repos/alex/vault/issues/comments/7", json({ body: "Edited" })))).toBe(true)
  })

  test.each([
    ["another credential", { ...terms, itemId: "itm_github02" }, githubAnchor],
    ["another slug", { ...terms, item: "github-other" }, githubAnchor],
    ["another machine", terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments", json({ body: "x" }), { asker: { device: "dev_other", workload: null } })],
    ["a workload's key", terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments", json({ body: "x" }), { asker: { device: "dev_alexmbp", workload: "wl_task12345" } })],
    ["another host", { ...terms, host: "api.stripe.com" }, githubAnchor],
    ["an area the catalogue lacks", { ...terms, areas: ["issues", "pulls"] }, githubAnchor],
    ["a catalogue that does not exist", { ...terms, catalogue: "gitlab" }, githubAnchor],
    ["a catalogue for another host", { ...terms, catalogue: "stripe" }, githubAnchor],
    ["a catalogue version newer than the catalogue", { ...terms, catalogueVersion: 2 }, githubAnchor],
    ["terms that do not parse", { ...terms, maxUses: 201 }, githubAnchor],
    ["a destructive entry", terms, githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null)],
    ["a read", terms, githubRequest("GET", "/repos/alex/vault/issues", null)],
    ["a route no catalogue reviewed", terms, githubRequest("POST", "/repos/alex/vault/labels", json({ name: "bug" }))],
    ["a body its reader refuses", terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments", json({ body: "x", owner: "someone" }))],
    ["a query string", terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments?x=1")],
    ["a body sent as a form", terms, { ...githubAnchor, contentType: "application/x-www-form-urlencoded" }],
    ["a credential whose secret is now a live key", terms, githubRequest("POST", "/repos/alex/vault/issues/42/comments", undefined, { secretPrefixes: ["sk_live_"] })],
    ["a host outside the binding", terms, { ...githubAnchor, binding: { hosts: ["uploads.github.com"] } }],
  ] as [string, PolicyAreaGrantTerms, PolicyRuleAnchor][])("not %s", (_, grant, request) => {
    expect(areaGrantCovers(grant, request)).toBe(false)
  })

  test("not an item's own approve rule, which always asks", () => {
    const policy: Policy = { default: "allow", rules: [{ action: "approve", methods: ["POST"], paths: ["/repos/*/*/issues/*/comments"] }] }
    expect(policyFloorRefusal({ ...githubAnchor, policy })).toBe("rule.item-rule")
    expect(areaGrantCovers(terms, { ...githubAnchor, policy })).toBe(false)
  })

  test("an entry the catalogue added after the grant's version is not covered until someone signs again", () => {
    const list = custom("POST", "/v1/lists", json({ name: "a" }))
    const task = custom("POST", "/v1/tasks", json({ task: "a" }))
    expect(areaGrantCovers(exampleTerms, task, exampleCatalogue)).toBe(true)
    expect(areaGrantCovers(exampleTerms, list, exampleCatalogue)).toBe(false)
    expect(areaGrantCovers({ ...exampleTerms, catalogueVersion: 2 }, list, exampleCatalogue)).toBe(true)
    expect(areaGrantCovers({ ...exampleTerms, catalogueVersion: 2, areas: ["tasks"] }, list, exampleCatalogue)).toBe(false)
    expect(areaGrantCovers(exampleTerms, { ...task, contentType: "text/plain" }, exampleCatalogue)).toBe(false)
  })
})

// The four standing rules production holds on a Cloudflare token, made
// before the Cloudflare catalogue. ruleCovers re-runs the rule's shape and
// the floor at every use, so the catalogue decides which still cover.
describe("standing rules on a Cloudflare token made before its catalogue", () => {
  const cloudflare = template("cloudflare-api-token")
  const ACCOUNT = "/client/v4/accounts/0123456789abcdef0123456789abcdef"
  const ZONE = "/client/v4/zones/fedcba9876543210fedcba9876543210"
  const request = (path: string, body: unknown): PolicyRuleAnchor => ({
    ...cloudflare, item: "cloudflare-work", itemId: "itm_cloudflare1", asker, destination: destination("POST", `https://api.cloudflare.com${path}`), body: json(body), contentType: "application/json", contentEncoding: null, secretPrefixes: [],
  })
  const d1 = request(`${ACCOUNT}/d1/database`, { name: "app" })
  const telemetry = request(`${ACCOUNT}/workers/observability/telemetry/query`, { queryId: "errors", timeframe: { from: 1, to: 2 }, view: "events" })
  const aRecord = request(`${ZONE}/dns_records`, { type: "A", name: "www", content: "192.0.2.1", proxied: true })
  const widget = request(`${ACCOUNT}/challenges/widgets`, { domains: ["example.com"], mode: "managed", name: "login" })
  // What ruleTermsFrom made for the widget rule before the catalogue made
  // widget creation floor: the same terms as any POST on the host, at its path.
  const widgetTerms: PolicyRuleTerms = { ...termsOf(d1), path: widget.destination.path, anchorPath: widget.destination.path }

  test("D1 database create and the telemetry query still cover", () => {
    expect(ruleCovers(termsOf(d1), d1)).toBe(true)
    expect(ruleCovers(termsOf(d1), request(`${ACCOUNT}/d1/database`, { name: "app-2", primary_location_hint: "weur" }))).toBe(true)
    expect(ruleCovers(termsOf(telemetry), telemetry)).toBe(true)
  })

  test("DNS record create covers an A or AAAA record and not a CNAME, a TXT record or a _ label", () => {
    const terms = termsOf(aRecord)
    expect(ruleCovers(terms, aRecord)).toBe(true)
    expect(ruleCovers(terms, request(`${ZONE}/dns_records`, { type: "AAAA", name: "www", content: "2001:db8::1", proxied: true }))).toBe(true)
    expect(ruleCovers(terms, request(`${ZONE}/dns_records`, { type: "CNAME", name: "app", content: "x.pages.dev" }))).toBe(false)
    expect(policyFloorRefusal(request(`${ZONE}/dns_records`, { type: "CNAME", name: "app", content: "x.pages.dev" }))).toBe("rule.destructive")
    expect(ruleCovers(terms, request(`${ZONE}/dns_records`, { type: "TXT", name: "@", content: "v=spf1 -all" }))).toBe(false)
    expect(ruleCovers(terms, request(`${ZONE}/dns_records`, { type: "CNAME", name: "_acme-challenge", content: "x" }))).toBe(false)
    expect(policyFloorRefusal(request(`${ZONE}/dns_records`, { type: "TXT", name: "@", content: "x" }))).not.toBeNull()
  })

  test("Turnstile widget create no longer covers: creation is floor, its answer holding the widget's secret", () => {
    expect(PolicyRuleTermsSchema.safeParse(widgetTerms).success).toBe(true)
    expect(ruleCovers(widgetTerms, widget)).toBe(false)
    expect(policyFloorRefusal(widget)).not.toBeNull()
    expect(ruleTermsFrom(widget, { path: widget.destination.path, ttlSeconds: RULE_DEFAULT_DURATION }).ok).toBe(false)
  })

  const QUEUE = `${ACCOUNT}/queues/00112233445566778899aabbccddeeff`
  const sent = (method: string, path: string, body: Uint8Array, contentType = "application/json"): PolicyRuleAnchor => ({ ...request(path, null), destination: destination(method, `https://api.cloudflare.com${path}`), body, contentType })
  const upload = new TextEncoder().encode([
    "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"main_module\":\"index.js\"}\r\n",
    "--b\r\nContent-Disposition: form-data; name=\"index.js\"; filename=\"index.js\"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}\r\n--b--\r\n",
  ].join(""))

  test.each([
    ["a queue consumer update", sent("PUT", `${QUEUE}/consumers/ffeeddccbbaa99887766554433221100`, json({ script_name: "my-worker", type: "worker" }))],
    ["a queue consumer create naming script_name", sent("POST", `${QUEUE}/consumers`, json({ script_name: "my-worker", type: "worker" }))],
    ["a Workflow deploy", sent("PUT", `${ACCOUNT}/workflows/nightly`, json({ class_name: "Nightly", script_name: "my-worker" }))],
    ["a full Worker upload", sent("PUT", `${ACCOUNT}/workers/scripts/my-worker`, upload, "multipart/form-data; boundary=b")],
  ])("%s is destructive: no rule is made from it, and a stored rule on its exact path no longer covers it", (_, destructive) => {
    const d = destructive.destination
    const stored: PolicyRuleTerms = { ...termsOf(d1), method: d.method as PolicyRuleTerms["method"], path: d.path, anchorPath: d.path }
    expect(PolicyRuleTermsSchema.safeParse(stored).success).toBe(true)
    expect(policyFloorRefusal(destructive)).toBe("rule.destructive")
    expect(ruleTermsFrom(destructive, { path: d.path, ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.destructive" })
    expect(ruleCovers(stored, destructive)).toBe(false)
  })

  test("a pull consumer create naming no script_name still covers", () => {
    const pull = request(`${QUEUE}/consumers`, { type: "http_pull", settings: { batch_size: 10, visibility_timeout_ms: 6000 } })
    expect(policyFloorRefusal(pull)).toBeNull()
    expect(ruleCovers(termsOf(pull), pull)).toBe(true)
  })
})

describe("areaGrantEntry", () => {
  const terms: PolicyAreaGrantTerms = { kind: "area", item: "github-work", itemId: "itm_github01", asker, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50 }

  test("names the catalogue entry a covered request is, for the grant's receipt", () => {
    expect(areaGrantEntry(terms, githubAnchor)?.id).toBe("github.comment-create")
    expect(areaGrantEntry(terms, githubRequest("POST", "/repos/alex/vault/issues", json({ title: "A bug" })))?.id).toBe("github.issue-create")
    expect(areaGrantEntry(terms, githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null))).toBeNull()
  })

  test("never covers a request with a query string, a method override among them", () => {
    for (const query of ["?_method=DELETE", "?x=1"]) expect(areaGrantEntry(terms, githubRequest("POST", `/repos/alex/vault/issues/42/comments${query}`)), query).toBeNull()
  })
})

describe("areaGrantTermsFrom", () => {
  const uploads: PolicyCatalogue = {
    template: "example", version: 1, hosts: ["api.example.com"], floor: [],
    areas: [{ id: "tasks", name: "Tasks", words: "Makes tasks" }, { id: "uploads", name: "Uploads", words: "Uploads files" }],
    entries: [
      { id: "example.task-create", area: "tasks", effect: "routine", methods: ["POST"], path: "/v1/tasks", body: "json", words: "Makes a task", since: 1, additionalPermission: false },
      { id: "example.upload", area: "uploads", effect: "routine", methods: ["POST"], path: "/v1/uploads", body: "data", words: "Uploads a file", since: 1, additionalPermission: false },
    ],
  }

  test("offers the request's own area for 1 hour and 50 requests, at the catalogue's current version", () => {
    expect(areaGrantTermsFrom(githubAnchor, null)).toEqual({ ok: true, requestArea: "issues", terms: { kind: "area", item: "github-work", itemId: "itm_github01", asker, host: "api.github.com", catalogue: "github", catalogueVersion: 1, areas: ["issues"], ttlSeconds: 3600, maxUses: 50 } })
  })

  test("takes the person's areas sorted, any duration offered and up to 200 requests", () => {
    const built = areaGrantTermsFrom(custom("POST", "/v1/tasks", json({ title: "a" })), { areas: ["uploads", "tasks"], ttlSeconds: 14_400, maxUses: 200 }, uploads)
    expect(built).toMatchObject({ ok: true, requestArea: "tasks", terms: { areas: ["tasks", "uploads"], ttlSeconds: 14_400, maxUses: 200, catalogue: "example" } })
  })

  test("builds a grant from bytes an upload stores, which no shape rule takes", () => {
    const upload = { ...custom("POST", "/v1/uploads", new TextEncoder().encode("file bytes")), contentType: "application/octet-stream" }
    // The floor reads stored bytes as the entry's only once the catalogue is one the vault serves.
    expect(areaGrantTermsFrom(upload, null, uploads)).toEqual({ ok: false, reason: "area.not-routine" })
    const served = POLICY_CATALOGUES as PolicyCatalogue[]
    served.push(uploads)
    try {
      expect(ruleTermsFrom(upload, { path: "/v1/uploads", ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.body" })
      expect(areaGrantTermsFrom(upload, null)).toMatchObject({ ok: true, requestArea: "uploads" })
    } finally { served.splice(served.indexOf(uploads), 1) }
  })

  test.each([
    ["area.unreviewed", custom("POST", "/v1/tasks", json({ title: "a" })), null, null],
    ["area.not-routine", githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null), null, undefined],
    ["area.not-routine", githubRequest("POST", "/repos/alex/vault/labels", json({ name: "bug" })), null, undefined],
    ["area.not-routine", githubRequest("POST", "/repos/alex/vault/issues/42/comments?_method=DELETE"), null, undefined],
    ["area.live-key", githubRequest("POST", "/repos/alex/vault/issues/42/comments", undefined, { secretPrefixes: ["sk_live_"] }), null, undefined],
    ["area.terms", { ...githubAnchor, binding: { hosts: ["uploads.github.com"] } }, null, undefined],
    ["area.unknown", githubAnchor, { areas: ["pulls"], ttlSeconds: 3600, maxUses: 50 }, undefined],
    ["area.unknown", githubAnchor, { areas: [], ttlSeconds: 3600, maxUses: 50 }, undefined],
    ["area.duration", githubAnchor, { areas: ["issues"], ttlSeconds: 600, maxUses: 50 }, undefined],
    ["area.uses", githubAnchor, { areas: ["issues"], ttlSeconds: 3600, maxUses: 201 }, undefined],
    ["area.uses", githubAnchor, { areas: ["issues"], ttlSeconds: 3600, maxUses: 0 }, undefined],
    ["area.uses", githubAnchor, { areas: ["issues"], ttlSeconds: 3600, maxUses: 1.5 }, undefined],
  ] as [PolicyAreaRefusal, PolicyRuleAnchor, { areas: string[]; ttlSeconds: number; maxUses: number } | null, PolicyCatalogue | null | undefined][])("refuses %s", (reason, anchor, choice, catalogue) => {
    expect(catalogue === undefined ? areaGrantTermsFrom(anchor, choice) : areaGrantTermsFrom(anchor, choice, catalogue)).toEqual({ ok: false, reason })
  })
})

// Postures (policy-mode.ts PostureSchema, policy-rules.ts postureCovers): what
// a level lets through on the catalogue a person signed, before the vault
// decides which machines it reaches.
describe("postures", () => {
  const issue = json({ title: "Flaky test", body: "It fails on Tuesdays." })
  const signed = { template: "github", version: 1 }
  const opens = githubRequest("POST", "/repos/alex/vault/issues", issue)
  const unreviewed = githubRequest("POST", "/repos/alex/vault/labels", json({ name: "flaky" }))

  test("routine lets a routine entry through, and trust a route nobody reviewed in a rule's shape as well", () => {
    expect(postureCovers("routine", signed, opens)).toEqual({ entry: "github.issue-create" })
    expect(postureCovers("trust", signed, opens)).toEqual({ entry: "github.issue-create" })
    expect(postureCovers("routine", signed, unreviewed)).toBeNull()
    expect(postureCovers("trust", signed, unreviewed)).toEqual({ entry: "unreviewed" })
    expect(postureCovers("ask", signed, opens)).toBeNull()
  })

  test("never the floor, a query string, a body not sent as JSON, a request outside the binding or a live key", () => {
    expect(policyFloorRefusal(githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null))).not.toBeNull()
    for (const level of ["routine", "trust"] as const) {
      expect(postureCovers(level, signed, githubRequest("DELETE", "/repos/alex/vault/issues/comments/7", null))).toBeNull()
      expect(postureCovers(level, signed, githubRequest("POST", "/repos/alex/vault/issues/42/comments?_method=DELETE"))).toBeNull()
      expect(postureCovers(level, signed, { ...opens, contentType: "text/plain" })).toBeNull()
      expect(postureCovers(level, signed, githubRequest("POST", "/repos/alex/vault/hooks", json({ name: "web", config: { url: "https://example.com" } })))).toBeNull()
      expect(postureCovers(level, signed, { ...opens, binding: { hosts: ["api.example.com"] } })).toBeNull()
      expect(postureCovers(level, signed, { ...opens, secretPrefixes: ["sk_live_"] })).toBeNull()
    }
  })

  test("never covers an entry the catalogue marks destructive, at any level, even one the floor test lets by", () => {
    const catalogue = postureCatalogueFor({ hosts: ["api.github.com"] })!
    const marked: PolicyCatalogue = { ...catalogue, entries: catalogue.entries.map((e) => e.id === "github.issue-create" ? { ...e, effect: "destructive" as const } : e) }
    expect(policyFloorRefusal(opens)).toBeNull()
    for (const level of ["routine", "trust"] as const) expect(postureCovers(level, signed, opens, marked)).toBeNull()
    expect(postureCovers("trust", signed, opens, catalogue)).toEqual({ entry: "github.issue-create" })
  })

  test("covers an entry only up to the catalogue version signed, and nothing on another catalogue", () => {
    const catalogue = postureCatalogueFor({ hosts: ["api.github.com"] })!
    const grown: PolicyCatalogue = { ...catalogue, version: 2, entries: catalogue.entries.map((e) => e.id === "github.issue-create" ? { ...e, since: 2 } : e) }
    expect(postureCovers("routine", signed, opens, grown)).toBeNull()
    expect(postureCovers("routine", { template: "github", version: 2 }, opens, grown)).toEqual({ entry: "github.issue-create" })
    expect(postureCovers("routine", { template: "github", version: 2 }, opens, catalogue)).toBeNull()
    expect(postureCovers("routine", { template: "stripe", version: 1 }, opens)).toBeNull()
  })

  test("reads a credential's catalogue from every host of its binding, or none", () => {
    expect(postureCatalogueFor({ hosts: ["api.github.com"] })?.template).toBe("github")
    expect(postureCatalogueFor({ hosts: ["api.github.com", "api.stripe.com"] })).toBeNull()
    expect(postureCatalogueFor({ hosts: ["*.github.com"] })).toBeNull()
    expect(postureCatalogueFor({ hosts: [] })).toBeNull()
  })

  test("names machines sorted and each once, and none for ask", () => {
    expect(PostureSchema.safeParse({ level: "routine", machines: ["dev_a", "dev_b"] }).success).toBe(true)
    expect(PostureSchema.safeParse({ level: "routine", machines: ["dev_b", "dev_a"] }).success).toBe(false)
    expect(PostureSchema.safeParse({ level: "routine", machines: ["dev_a", "dev_a"] }).success).toBe(false)
    expect(PostureSchema.safeParse({ level: "trust", machines: [] }).success).toBe(false)
    expect(PostureSchema.safeParse({ level: "ask", machines: ["dev_a"] }).success).toBe(false)
    expect(PostureSchema.safeParse({ level: "ask", machines: null }).success).toBe(true)
  })

  test("the digest a passkey signs binds the item, the level, the machines, the catalogue and the revision replaced", async () => {
    const terms = { item: "itm_github01", level: "routine" as const, machines: ["dev_a"], catalogue: "github", catalogueVersion: 1, before: 0 }
    const digest = await itemPostureDigest(terms)
    expect(digest).toBe(await sha256B64(canonicalJson({ domain: "mehen-item-posture/v1", item: "itm_github01", level: "routine", machines: ["dev_a"], catalogue: "github", catalogueVersion: 1, before: 0 })))
    for (const change of [{ item: "itm_other" }, { level: "trust" as const }, { machines: null }, { catalogue: "stripe" }, { catalogueVersion: 2 }, { before: 1 }])
      expect(await itemPostureDigest({ ...terms, ...change })).not.toBe(digest)
  })
})

// Analytics Engine takes its SQL as the raw body, which no shape rule
// takes, so a task grant or posture covers it through the one text reader
// they accept (CATALOGUE_COVERED_TEXT_READERS), and every other reader's
// entry only when sent as JSON, as before.
describe("Analytics Engine SQL under a task grant and a posture", () => {
  const cloudflare = template("cloudflare-api-token")
  const ACCOUNT = "/client/v4/accounts/0123456789abcdef0123456789abcdef"
  const SQL = `${ACCOUNT}/analytics_engine/sql`
  const sent = (path: string, body: string | Uint8Array, contentType: string | null, method = "POST"): PolicyRuleAnchor => ({
    ...cloudflare, item: "cloudflare-work", itemId: "itm_cloudflare1", asker, destination: destination(method, `https://api.cloudflare.com${path}`),
    body: typeof body === "string" ? new TextEncoder().encode(body) : body, contentType, contentEncoding: null, secretPrefixes: [],
  })
  const grant: PolicyAreaGrantTerms = { kind: "area", item: "cloudflare-work", itemId: "itm_cloudflare1", asker, host: "api.cloudflare.com", catalogue: "cloudflare-api-token", catalogueVersion: 2, areas: ["workers"], ttlSeconds: 3600, maxUses: 50 }
  const signed = { template: "cloudflare-api-token", version: 2 }
  // The four measured asks, SQL from a file whose content type the
  // measurement did not see, each sent untyped, as fetch sends a string and
  // as curl --data sends a file.
  const measured = [
    "SELECT blob1 AS route, count() AS hits FROM contoso_events WHERE timestamp > NOW() - INTERVAL '1' DAY GROUP BY route ORDER BY hits DESC",
    "SELECT double1 AS ms, blob2 AS status FROM contoso_requests ORDER BY timestamp DESC LIMIT 100",
    "SELECT\n  blob3 AS country,\n  sum(_sample_interval) AS visits\nFROM contoso_events\nGROUP BY country;\n",
    "SHOW TABLES",
  ].flatMap((sql) => [null, "text/plain;charset=UTF-8", "application/x-www-form-urlencoded"].map((contentType) => sent(SQL, sql, contentType)))

  test.each(measured.map((m, i) => [i, m.contentType, m] as const))("measured ask %i, typed %s, is covered by a routine posture and a task grant on workers", (_, _type, request) => {
    expect(policyFloorRefusal(request)).toBeNull()
    expect(areaGrantEntry(grant, request)?.id).toBe("cloudflare.analytics-engine-sql")
    expect(postureCovers("routine", signed, request)).toEqual({ entry: "cloudflare.analytics-engine-sql" })
    expect(postureCovers("trust", signed, request)).toEqual({ entry: "cloudflare.analytics-engine-sql" })
    expect(areaGrantTermsFrom(request, null)).toMatchObject({ ok: true, requestArea: "workers", terms: { catalogueVersion: 2, areas: ["workers"] } })
    expect(ruleTermsFrom(request, { path: SQL, ttlSeconds: RULE_DEFAULT_DURATION })).toEqual({ ok: false, reason: "rule.body" })
  })

  test("a grant or posture signed before the entry arrived does not cover it until someone signs again", () => {
    const [request] = measured
    expect(areaGrantCovers({ ...grant, catalogueVersion: 1 }, request!)).toBe(false)
    expect(postureCovers("routine", { ...signed, version: 1 }, request!)).toBeNull()
  })

  test.each([
    ["a JSON body", json({ query: "SELECT 1" }), "application/json"],
    ["an untyped JSON body", json({ sql: "SELECT 1" }), null],
    ["SQL as another text type", "SELECT 1", "text/csv"],
    ["SQL in a multipart form", "--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nSELECT 1\r\n--b--\r\n", "multipart/form-data; boundary=b"],
    ["two statements", "SELECT 1; SELECT 2", null],
    ["two statements sent as a form", "SELECT 1; SELECT 2", "application/x-www-form-urlencoded"],
    ["a comment after a semicolon", "SELECT 1; -- note", "text/plain"],
  ] as const)("refusal/%s on the SQL path is not covered", (_, body, contentType) => {
    const request = sent(SQL, body, contentType)
    expect(areaGrantCovers(grant, request)).toBe(false)
    expect(postureCovers("routine", signed, request)).toBeNull()
  })

  test("refusal/SQL text to any other path is not covered", () => {
    for (const path of [`${ACCOUNT}/workers/observability/telemetry/query`, `${ACCOUNT}/analytics_engine/sql/extra`, `${ACCOUNT}/kv/namespaces`]) {
      for (const level of ["routine", "trust"] as const) expect(postureCovers(level, signed, sent(path, "SELECT 1", null)), path).toBeNull()
      expect(areaGrantCovers(grant, sent(path, "SELECT 1", "text/plain")), path).toBe(false)
    }
  })

  test("another reader's entry keeps its coverage: a Worker version upload, not JSON, is still not covered", () => {
    const upload = sent(`${ACCOUNT}/workers/scripts/my-worker/versions`, [
      "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"main_module\":\"index.js\"}\r\n",
      "--b\r\nContent-Disposition: form-data; name=\"index.js\"; filename=\"index.js\"\r\nContent-Type: application/javascript+module\r\n\r\nexport default {}\r\n--b--\r\n",
    ].join(""), "multipart/form-data; boundary=b")
    expect(policyFloorRefusal(upload)).toBeNull()
    expect(areaGrantCovers(grant, upload)).toBe(false)
    expect(postureCovers("routine", signed, upload)).toBeNull()
    expect(areaGrantTermsFrom(upload, null)).toEqual({ ok: false, reason: "area.not-routine" })
  })
})
