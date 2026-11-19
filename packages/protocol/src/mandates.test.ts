import { describe, expect, test } from "bun:test"
import { parseDestination, type Binding, type Policy } from "./binding.ts"
import { MANDATE_CAP_DEFAULTS, MandateProposedTermsSchema, MandateTermsSchema, mandateCapsFit, parseMandateReceiptsCursor, mandateReceiptsCursor, type MandateClass, type MandateSchedule, type MandateTerms } from "./mandate-terms.ts"
import { mandateClassesOf, mandateCovers, mandateDigest, mandateHostNamed, mandateRequestFacts, mandateScheduleOpen } from "./mandates.ts"
import { POLICY_RULE_METHODS } from "./policy-mode.ts"
import { policyFloorRefusal, type PolicyRuleAnchor } from "./policy-rules.ts"
import { TEMPLATES } from "./templates.ts"

const encoded = (value: unknown): Uint8Array => new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value))

// A held request on a template's policy and binding, or on a credential
// with no template (everything asks), as the relay holds it.
function held(template: string | null, method: string, url: string, body: unknown = null, overrides: Partial<PolicyRuleAnchor> = {}): PolicyRuleAnchor {
  const t = template === null ? null : TEMPLATES[template]
  if (template !== null && !t) throw new Error(`No template ${template}`)
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`Invalid test destination ${url}`)
  return {
    item: "work-key", itemId: "itm_work0001", asker: { device: "dev_alexmbp", workload: null }, destination: parsed.destination,
    body: body === null ? null : encoded(body), contentType: body === null ? null : "application/json", contentEncoding: null,
    policy: (t?.policy ?? { default: "approve", rules: [] }) as Policy, binding: (t?.binding ?? { hosts: [new URL(url).hostname] }) as Binding, secretPrefixes: [], ...overrides,
  }
}
const classesOf = (request: PolicyRuleAnchor) => mandateClassesOf(mandateRequestFacts(request), request.destination.method)

describe("mandateRequestFacts and mandateClassesOf on real routes", () => {
  test.each([
    ["a GitHub issue comment", held("github-pat", "POST", "https://api.github.com/repos/alex/vault/issues/42/comments", { body: "Looks right." }), ["change"]],
    ["Slack chat.postMessage, after the split", held("slack-bot", "POST", "https://slack.com/api/chat.postMessage", { channel: "C1", text: "hi" }), ["change", "send"]],
    ["DELETE /repos/x/y", held("github-pat", "DELETE", "https://api.github.com/repos/x/y"), ["delete"]],
    ["a custom DELETE", held(null, "DELETE", "https://api.example.com/v1/tasks/7"), ["delete"]],
    ["a plain GET", held(null, "GET", "https://api.example.com/v1/tasks"), ["read"]],
    ["Telegram GET /bot.../sendMessage", held(null, "GET", "https://api.telegram.org/bot123456:TEST/sendMessage?chat_id=1&text=hi"), ["send"]],
    ["a proven Linear commentCreate", held("linear", "POST", "https://api.linear.app/graphql", { query: "mutation { commentCreate(input: {}) { success } }" }), ["change"]],
    ["a custom POST", held(null, "POST", "https://api.example.com/v1/tasks", { task: "a" }), ["change"]],
    ["two GraphQL mutations without aliases", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { commentCreate(input: {}) { success } issueUpdate(input: {}) { success } }" }), ["change"]],
  ] as [string, PolicyRuleAnchor, MandateClass[]][])("%s gives its classes", (_, request, classes) => {
    expect(classesOf(request)).toEqual(classes)
  })

  test.each([
    ["Slack conversations.invite", held("slack-bot", "POST", "https://slack.com/api/conversations.invite", { channel: "C1", users: "U1" }), "sharing"],
    ["Slack chat.delete, its own opaque rule", held("slack-bot", "POST", "https://slack.com/api/chat.delete", { channel: "C1", ts: "1" }), "unreadable"],
    ["OPTIONS", held(null, "OPTIONS", "https://api.example.com/v1/tasks"), "method"],
    ["TRACE", held(null, "TRACE", "https://api.example.com/v1/tasks"), "method"],
    ["a DELETE of a token", held(null, "DELETE", "https://api.example.com/v1/tokens/7"), "generic"],
    ["a DELETE of a credential path", held(null, "DELETE", "https://api.example.com/v1/connection_uri/7"), "credential"],
    ["a DELETE of forwarding", held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"), "persistence"],
    ["a DELETE of a member", held(null, "DELETE", "https://api.example.com/v1/teams/7/members/3"), "generic"],
    ["a DELETE of an access-control entry", held(null, "DELETE", "https://api.example.com/v1/acl/7"), "sharing"],
    ["a DELETE with an opaque body", held(null, "DELETE", "https://api.example.com/v1/tasks/7", "remove it", { contentType: "text/plain" }), "unreadable"],
    ["a DELETE the item's policy denies", held(null, "DELETE", "https://api.example.com/v1/tasks/7", null, { policy: { default: "approve", rules: [{ action: "deny", methods: ["DELETE"] }] } }), "deny"],
    ["Stripe POST /v1/refunds", held("stripe", "POST", "https://api.stripe.com/v1/refunds", { charge: "ch_1" }, { secretPrefixes: ["sk_test_"] }), "money"],
    ["any sk_live_ key", held(null, "POST", "https://api.example.com/v1/tasks", { task: "a" }, { secretPrefixes: ["sk_live_"] }), "live-key"],
    ["GitHub POST /repos/x/y/hooks", held("github-pat", "POST", "https://api.github.com/repos/x/y/hooks", { name: "web" }), "deny"],
    ["a custom /rpc body naming createApiKey as JSON-RPC", held(null, "POST", "https://api.example.com/rpc", { jsonrpc: "2.0", method: "createApiKey" }), "unreadable"],
    ["a custom /rpc body naming createApiKey as its method", held(null, "POST", "https://api.example.com/rpc", { method: "createApiKey", params: {} }), "unreadable"],
    ["a GraphQL query selecting apiKeys", held(null, "POST", "https://api.example.com/graphql", { query: "query { apiKeys { id secret } }" }), "unreadable"],
    ["aliased GraphQL mutations", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { a: commentCreate(input: {}) { success } b: commentCreate(input: {}) { success } }" }), "unreadable"],
    ["aliased GraphQL fields", held(null, "POST", "https://api.example.com/graphql", { query: "query { a: viewer { id } b: viewer { name } }" }), "unreadable"],
    ["a GraphQL fragment", held(null, "POST", "https://api.example.com/graphql", { query: "mutation { commentCreate(input: {}) { ...F } } fragment F on X { id }" }), "unreadable"],
    ["a persisted GraphQL query", held(null, "POST", "https://api.example.com/graphql", { extensions: { persistedQuery: { version: 1, sha256Hash: "abc" } } }), "unreadable"],
    ["a GraphQL batch", held(null, "POST", "https://api.example.com/graphql", [{ query: "mutation { commentCreate(input: {}) { success } }" }]), "unreadable"],
    ["a JSON batch", held(null, "POST", "https://api.example.com/v1/tasks", [{ task: "a" }, { task: "b" }]), "unreadable"],
    ["a proven GraphQL mutation naming a webhook", held("linear", "POST", "https://api.linear.app/graphql", { query: "mutation { webhookCreate(input: {}) { success } }" }), "persistence"],
    ["a proven GraphQL mutation sent with a query string", held("linear", "POST", "https://api.linear.app/graphql?x=1", { query: "mutation { commentCreate(input: {}) { success } }" }), "unreadable"],
    ["a form body", held(null, "POST", "https://api.example.com/v1/tasks", "task=a", { contentType: "application/x-www-form-urlencoded" }), "unreadable"],
    ["a repeated query name", held(null, "GET", "https://api.example.com/v1/tasks?a=1&a=2"), "unreadable"],
    ["plain HTTP", held(null, "GET", "http://api.example.com/v1/tasks"), "destination"],
    ["another port", held(null, "GET", "https://api.example.com:8443/v1/tasks"), "destination"],
  ] as [string, PolicyRuleAnchor, string][])("%s is never", (_, request, fact) => {
    expect(mandateRequestFacts(request).has(fact as never)).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  test("a DELETE is destructive and still read for everything else it does", () => {
    expect([...mandateRequestFacts(held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"))].sort()).toEqual(["destructive", "persistence"])
  })

  test("an item rule that asks makes a read a change", () => {
    const request = held(null, "GET", "https://api.example.com/v1/tasks", null, { policy: { default: "allow", rules: [{ action: "approve", methods: ["GET"], paths: ["/v1/tasks"] }] } })
    expect(classesOf(request)).toEqual(["change"])
  })

  test("a result that is not never always has a class", () => {
    for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]) {
      const classes = mandateClassesOf(new Set(), method)
      expect(classes === "never" || classes.length > 0, method).toBe(true)
    }
    expect(mandateClassesOf(new Set(), "OPTIONS")).toBe("never")
  })
})

// Analytics Engine takes its SQL as the raw body, which the collector reads
// as a task grant or posture does (the entry's reader proved it), and the
// AI Gateway create names its own id, which is no GraphQL.
describe("Cloudflare's Analytics Engine SQL and AI Gateway create", () => {
  const A = "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef"
  const sql = (url: string, body: unknown, contentType: string | null) => held("cloudflare-api-token", "POST", url, body, { contentType })

  test.each([null, "text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded"])("SQL on the SQL path, typed %s, is a change", (contentType) => {
    const request = sql(`${A}/analytics_engine/sql`, "SELECT blob1, count() AS n FROM contoso_events GROUP BY blob1", contentType)
    expect([...mandateRequestFacts(request)]).toEqual([])
    expect(classesOf(request)).toEqual(["change"])
  })

  test.each([
    ["SQL text to the telemetry query", sql(`${A}/workers/observability/telemetry/query`, "SELECT 1", "text/plain"), "unreadable"],
    ["SQL text below the SQL path", sql(`${A}/analytics_engine/sql/extra`, "SELECT 1", null), "unreadable"],
    ["SQL text to a custom host", held(null, "POST", "https://api.example.com/analytics_engine/sql", "SELECT 1", { contentType: "text/plain" }), "unreadable"],
    ["two statements on the SQL path", sql(`${A}/analytics_engine/sql`, "SELECT 1; SELECT 2", null), "unreadable"],
    ["an untyped JSON body on the SQL path", sql(`${A}/analytics_engine/sql`, { sql: "SELECT 1" }, null), "unreadable"],
    ["a JSON query the GraphQL check cannot prove on the SQL path", sql(`${A}/analytics_engine/sql`, { query: "SELECT 1" }, "application/json"), "unreadable"],
  ] as [string, PolicyRuleAnchor, string][])("%s is never, as before", (_, request, fact) => {
    expect(mandateRequestFacts(request).has(fact as never)).toBe(true)
    expect(classesOf(request)).toBe("never")
  })

  test("another JSON body on the SQL path is a change, as before", () => {
    expect(classesOf(sql(`${A}/analytics_engine/sql`, { sql: "SELECT 1" }, "application/json"))).toEqual(["change"])
  })

  test("the AI Gateway create, naming its own id, is a change", () => {
    const request = held("cloudflare-api-token", "POST", `${A}/ai-gateway/gateways`, { id: "contoso", collect_logs: false, cache_ttl: 0, cache_invalidate_on_update: false, rate_limiting_interval: 0, rate_limiting_limit: 0, rate_limiting_technique: "fixed" })
    expect([...mandateRequestFacts(request)]).toEqual([])
    expect(classesOf(request)).toEqual(["change"])
  })
})

// The standing rules' floor test is not the collector: its early return on
// a DELETE and its methods stay as they were.
describe("the floor test the standing rules share is unchanged", () => {
  test("a DELETE still refuses as destructive and a method no rule takes as rule.method", () => {
    expect(policyFloorRefusal(held(null, "DELETE", "https://api.example.com/v1/settings/forwarding"))).toBe("rule.destructive")
    expect(policyFloorRefusal(held(null, "OPTIONS", "https://api.example.com/v1/tasks"))).toBe("rule.method")
    expect(POLICY_RULE_METHODS).toEqual(["GET", "HEAD", "POST", "PUT", "PATCH"])
  })

  test("a request the collector reads as a change still passes it", () => {
    expect(policyFloorRefusal(held("github-pat", "POST", "https://api.github.com/repos/alex/vault/issues/42/comments", { body: "x" }))).toBeNull()
    expect(policyFloorRefusal(held(null, "GET", "https://api.telegram.org/bot123456:TEST/sendMessage?chat_id=1&text=hi"))).toBe("rule.send")
  })
})

describe("mandateHostNamed", () => {
  test("only a host the binding names exactly, never one a wildcard admits", () => {
    const binding: Binding = { hosts: ["api.example.com", "*.example.com"] }
    expect(mandateHostNamed(binding, "api.example.com")).toBe(true)
    expect(mandateHostNamed(binding, "attacker.example.com")).toBe(false)
    expect(mandateHostNamed({ hosts: ["*.example.com"] }, "api.example.com")).toBe(false)
  })
})

const at = (iso: string): number => Date.parse(iso)
const terms = (overrides: Partial<MandateTerms> = {}): MandateTerms => ({
  device: "dev_alexmbp", items: "all", classes: ["change", "delete", "read", "send"], caps: { ...MANDATE_CAP_DEFAULTS }, ttlDays: 30, schedule: null, note: "Sam's own work", ...overrides,
})
const active = { state: "active" as const, expiresAt: at("2026-12-08T12:00:00Z") }

describe("mandateCovers", () => {
  const now = at("2026-11-08T12:00:00Z")

  test("an active, unexpired mandate covers the classes it ticks, and no other", () => {
    expect(mandateCovers(terms(), active, ["change", "send"], now)).toBe(true)
    expect(mandateCovers(terms({ classes: ["change", "read"], caps: { ...MANDATE_CAP_DEFAULTS, send: 0, delete: 0 } }), active, ["change", "send"], now)).toBe(false)
    expect(mandateCovers(terms(), active, [], now)).toBe(false)
  })

  test.each(["paused", "tripped", "stopped", "expired"] as const)("a %s mandate covers nothing", (state) => {
    expect(mandateCovers(terms(), { ...active, state }, ["read"], now)).toBe(false)
  })

  test("a mandate covers nothing from its expiry on", () => {
    expect(mandateCovers(terms(), active, ["read"], active.expiresAt - 1)).toBe(true)
    expect(mandateCovers(terms(), active, ["read"], active.expiresAt)).toBe(false)
  })

  test("outside its schedule, nothing", () => {
    const schedule: MandateSchedule = { tz: "Europe/London", windows: [{ days: [1, 2, 3, 4, 5], from: "09:00", to: "17:00" }] }
    expect(mandateCovers(terms({ schedule }), active, ["read"], at("2026-11-09T10:00:00Z"))).toBe(true)
    expect(mandateCovers(terms({ schedule }), active, ["read"], at("2026-11-08T10:00:00Z"))).toBe(false)
  })
})

describe("mandateScheduleOpen", () => {
  test("no schedule is always", () => {
    expect(mandateScheduleOpen(null, at("2026-11-08T03:00:00Z"))).toBe(true)
  })

  test("a window starts inclusive and ends exclusive", () => {
    const schedule: MandateSchedule = { tz: "UTC", windows: [{ days: [1], from: "09:00", to: "17:00" }] }
    expect(mandateScheduleOpen(schedule, at("2026-11-09T08:59:59Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T09:00:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T16:59:59Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-09T17:00:00Z"))).toBe(false)
  })

  test("a window crossing midnight counts on the day it started", () => {
    // Friday 6 November 2026, 22:00, to Saturday 02:00.
    const schedule: MandateSchedule = { tz: "UTC", windows: [{ days: [5], from: "22:00", to: "02:00" }] }
    expect(mandateScheduleOpen(schedule, at("2026-11-06T22:00:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T01:59:00Z"))).toBe(true)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T02:00:00Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-07T22:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(schedule, at("2026-11-06T01:00:00Z"))).toBe(false)
    expect(mandateScheduleOpen({ tz: "UTC", windows: [{ days: [6], from: "22:00", to: "02:00" }] }, at("2026-11-08T01:00:00Z"))).toBe(true)
  })

  test("the same moment reads as each zone's own wall clock", () => {
    const window = { days: [1], from: "09:00", to: "17:00" }
    const moment = at("2026-11-09T15:00:00Z")
    expect(mandateScheduleOpen({ tz: "Europe/London", windows: [window] }, moment)).toBe(true)
    expect(mandateScheduleOpen({ tz: "America/New_York", windows: [window] }, moment)).toBe(true)
    expect(mandateScheduleOpen({ tz: "Asia/Tokyo", windows: [window] }, moment)).toBe(false)
    expect(mandateScheduleOpen({ tz: "America/New_York", windows: [window] }, at("2026-11-09T13:59:00Z"))).toBe(false)
  })

  test("in Europe/Paris, a local time the spring change skips never occurs", () => {
    // Sunday 29 March 2026: 02:00 CET becomes 03:00 CEST at 01:00 UTC.
    const skipped: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "02:00", to: "03:00" }] }
    for (const iso of ["2026-03-29T00:30:00Z", "2026-03-29T00:59:59Z", "2026-03-29T01:00:00Z", "2026-03-29T01:30:00Z"]) expect(mandateScheduleOpen(skipped, at(iso)), iso).toBe(false)
    const straddling: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "01:30", to: "03:30" }] }
    expect(mandateScheduleOpen(straddling, at("2026-03-29T00:45:00Z"))).toBe(true)
    expect(mandateScheduleOpen(straddling, at("2026-03-29T01:15:00Z"))).toBe(true)
    expect(mandateScheduleOpen(straddling, at("2026-03-29T01:30:00Z"))).toBe(false)
  })

  test("in Europe/Paris, an hour the autumn change repeats is inside or outside both times", () => {
    // Sunday 25 October 2026: 03:00 CEST becomes 02:00 CET at 01:00 UTC, so
    // 02:30 local is both 00:30 and 01:30 UTC.
    const inside: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "02:00", to: "03:00" }] }
    expect(mandateScheduleOpen(inside, at("2026-10-25T00:30:00Z"))).toBe(true)
    expect(mandateScheduleOpen(inside, at("2026-10-25T01:30:00Z"))).toBe(true)
    const outside: MandateSchedule = { tz: "Europe/Paris", windows: [{ days: [0], from: "03:00", to: "04:00" }] }
    expect(mandateScheduleOpen(outside, at("2026-10-25T00:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(outside, at("2026-10-25T01:30:00Z"))).toBe(false)
    expect(mandateScheduleOpen(outside, at("2026-10-25T02:00:00Z"))).toBe(true)
  })
})

describe("mandate terms", () => {
  test("take only what a person could sign", () => {
    expect(MandateTermsSchema.safeParse(terms()).success).toBe(true)
    expect(MandateTermsSchema.safeParse(terms({ items: ["itm_b0000001", "itm_a0000001"] })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ classes: ["change", "send"] })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ caps: { ...MANDATE_CAP_DEFAULTS, send: 501 } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ classes: ["read"], caps: MANDATE_CAP_DEFAULTS })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ ttlDays: 60 as 30 })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ note: "" })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "Mars/Olympus", windows: [{ days: [1], from: "09:00", to: "17:00" }] } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "UTC", windows: [{ days: [1], from: "09:00", to: "09:00" }] } })).success).toBe(false)
    expect(MandateTermsSchema.safeParse(terms({ schedule: { tz: "UTC", windows: [{ days: [1], from: "24:00", to: "09:00" }] } })).success).toBe(false)
  })

  test("a ticked class's cap is between 1 and its most, an unticked one's 0", () => {
    expect(mandateCapsFit(["read"], { read: 1, change: 0, send: 0, delete: 0 })).toBe(true)
    expect(mandateCapsFit(["read"], { read: 0, change: 0, send: 0, delete: 0 })).toBe(false)
    expect(mandateCapsFit(["delete", "read"], { read: 50_000, change: 0, send: 0, delete: 200 })).toBe(true)
  })

  test("a machine proposes terms without a device, naming credentials by slug", () => {
    const { device: _device, ...rest } = terms()
    expect(MandateProposedTermsSchema.safeParse({ ...rest, items: ["github-work", "slack-bot"] }).success).toBe(true)
    expect(MandateProposedTermsSchema.safeParse({ ...rest, device: "dev_alexmbp" }).success).toBe(false)
  })

  test("the digest binds the terms, the workspace and the signer", async () => {
    const base = { terms: terms(), workspace: "tn_Ex7mR4pLq9WzTnVc2Hdyk", signer: "mem_alex" }
    const digest = await mandateDigest(base)
    expect(digest).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(await mandateDigest(base)).toBe(digest)
    for (const changed of [{ ...base, terms: terms({ ttlDays: 7 }) }, { ...base, workspace: "tn_Nw4dQ2m8xPLsJyKb3Rtvz" }, { ...base, signer: "mem_kim" }]) expect(await mandateDigest(changed)).not.toBe(digest)
  })

  test("a receipts cursor reads back as the time and id it was made from", () => {
    expect(parseMandateReceiptsCursor(mandateReceiptsCursor(1_762_000_000_000, "mdu_abc123"))).toEqual({ at: 1_762_000_000_000, id: "mdu_abc123" })
    expect(parseMandateReceiptsCursor("1.mdt_abc")).toBeNull()
  })
})
