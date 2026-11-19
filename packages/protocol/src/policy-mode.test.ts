import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import {
  isPolicyHost, isPolicyNarrowing, isPolicyPath, PolicyChangeSchema, PolicyDecideSchema, PolicyDeviceIdSchema,
  PolicyGrantIdSchema, PolicyPreviewRequestSchema, PolicyProposeSchema, PolicyRememberSchema, PolicyReviewIdSchema,
  PolicyProposalIdSchema, PolicyProposalStatusSchema, PolicyRevisionSchema, PolicyRouteScopeSchema, PolicyWindowIdSchema,
  policyExpiresAt, policyLifetime, policyPathSubset, policyScopeWithinBinding, resolvePolicyMode,
  type PolicyChange, type PolicyRouteScope,
} from "./policy-mode.ts"

const scope: PolicyRouteScope = { host: "custom.example", methods: ["GET", "POST", "PATCH"], path: "/api/projects/*/**", anchorPath: "/api/projects/12345/issues", basis: "unreviewed" }
const change: PolicyChange = { kind: "mode", target: { kind: "item", item: "custom-key" }, selector: { device: "dev_laptop", session: "task.1" }, policyMode: "relaxed", scope, ttlSeconds: 3600, notAfter: null }
const preview = { change, reason: "Work on the selected project" }
const proof = { nonce: "nonce", assertion: {} }
const now = Date.parse("2026-10-26T10:00:00Z")
const changedScope = (patch: Partial<PolicyRouteScope>): PolicyChange => ({ ...change, scope: { ...scope, ...patch } })

function refused(input: unknown): void { expect(PolicyChangeSchema.safeParse(input).success).toBe(false) }

describe("policy-mode contracts", () => {
  test("strict schemas preserve raw terms and canonicalise method order", () => {
    const input = { ...change, scope: { ...scope, methods: ["PATCH", "GET", "POST"] } }
    expect(PolicyChangeSchema.parse(input)).toEqual(change)
    expect(PolicyPreviewRequestSchema.parse({ ...preview, reason: "  raw reason  " }).reason).toBe("  raw reason  ")
    expect(PolicyProposeSchema.parse({ ...preview, baseDigest: "a".repeat(43), slotRevision: 0, fresh: true }).fresh).toBe(true)
    expect(PolicyDecideSchema.parse({ decision: "deny", effectiveChange: null, stepUp: proof }).effectiveChange).toBeNull()
    expect(PolicyDecideSchema.parse({ decision: "deny", effectiveChange: null, stepUp: { nonce: "nonce", grace: true } }).stepUp).toEqual({ nonce: "nonce", grace: true })
    expect(PolicyRememberSchema.parse({ kind: "exact", selector: change.selector }).kind).toBe("exact")
    expect(PolicyRememberSchema.parse({ kind: "route", selector: change.selector, policyMode: "relaxed", scope, parent: "pov_parent" }).kind).toBe("route")
  })

  for (const field of ["rules", "body", "controls", "maximum", "run", "environment", "devices", "items", "floorLifts"]) {
    test(`refusal/unknown-change ${field}`, () => refused({ ...change, [field]: [] }))
  }
  test.each([
    { ...change, target: { ...change.target, extra: true } },
    { ...change, selector: { ...change.selector, run: "run_x" } },
    { ...change, scope: { ...scope, body: "graphql-query" } },
  ])("refusal/unknown-nested %j", (input) => refused(input))
  test.each(["tenant", "device", "environment", "items", "run"])("refusal/broad-target %s", (kind) => refused({ ...change, target: { kind, item: "custom-key" } }))
  test("refusal/target-list", () => refused({ ...change, target: [{ kind: "item", item: "custom-key" }] }))
  test.each(["standard", "strict", "YOLO", "off"])("refusal/mode %s", (policyMode) => refused({ ...change, policyMode }))
  test("refusal/basis", () => refused(changedScope({ basis: "catalogue" as "reviewed" })))
  test.each([[], ["get"], ["OPTIONS"], ["CONNECT"], ["TRACE"], ["RUN"], ["*"], ["GET", "GET"], ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "EXTRA"]].map((methods) => [methods]))("refusal/method %j", (methods) => refused({ ...change, scope: { ...scope, methods } }))
  test("refusal/relaxed-delete", () => refused(changedScope({ methods: ["DELETE"] })))
  test.each([0, -1, 59, 1.5, Infinity, Number.MAX_SAFE_INTEGER])("refusal/ttl-basic %s", (ttlSeconds) => refused({ ...change, ttlSeconds }))
  test.each([
    ["mode", "reviewed", "relaxed", 86401], ["allow", "reviewed", "relaxed", 28801],
    ["mode", "unreviewed", "relaxed", 28801], ["allow", "unreviewed", "relaxed", 28801],
    ["mode", "reviewed", "yolo", 7201], ["allow", "reviewed", "yolo", 7201],
    ["mode", "unreviewed", "yolo", 7201], ["allow", "unreviewed", "yolo", 7201],
  ])("refusal/ttl-cap %s %s %s %s", (kind, basis, policyMode, ttlSeconds) => refused({ ...change, kind, policyMode, ttlSeconds, scope: { ...scope, basis } }))
  test.each(["tomorrow", "2026-10-26T12:00:00", "2026-02-30T10:00:00Z", "", "2026-10-26"])("refusal/deadline %s", (notAfter) => refused({ ...change, notAfter }))
  test.each(["", "bad session", "\u202E", "x".repeat(121)])("refusal/session %j", (session) => refused({ ...change, selector: { ...change.selector, session } }))
  test.each(["a", "Bad-slug", "bad--slug", "bad-", "has/slash"])("refusal/slug %s", (item) => refused({ ...change, target: { kind: "item", item } }))
  test.each(["", "a".repeat(501), "   "])("refusal/reason %j", (reason) => expect(PolicyPreviewRequestSchema.safeParse({ ...preview, reason }).success).toBe(false))
  test("refusal/request-limit", () => expect(PolicyDecideSchema.safeParse({ decision: "approve", effectiveChange: change, stepUp: { nonce: "nonce", assertion: { padding: "x".repeat(32768) } } }).success).toBe(false))
  test.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity])("refusal/revision %s", (revision) => expect(PolicyRevisionSchema.safeParse(revision).success).toBe(false))
  test.each([PolicyDeviceIdSchema, PolicyProposalIdSchema, PolicyWindowIdSchema, PolicyGrantIdSchema, PolicyReviewIdSchema])("refusal/id %j", (schema) => {
    expect(schema.safeParse("other_bad/id").success).toBe(false)
  })
  test.each([
    { decision: "deny", effectiveChange: change, stepUp: proof },
    { decision: "approve", effectiveChange: null, stepUp: proof },
    { decision: "deny", effectiveChange: null, stepUp: { ...proof, extra: true } },
    { decision: "deny", effectiveChange: null, stepUp: { nonce: "nonce" } },
    { decision: "deny", effectiveChange: null, stepUp: { ...proof, grace: true } },
    { decision: "deny", effectiveChange: null, stepUp: { nonce: "nonce", grace: false } },
    { decision: "deny", effectiveChange: null, stepUp: proof, remember: { kind: "exact", selector: change.selector } },
  ])("refusal/decision %j", (input) => expect(PolicyDecideSchema.safeParse(input).success).toBe(false))
  test.each([
    { kind: "exact", selector: change.selector, uses: 20 },
    { kind: "route", selector: change.selector, policyMode: "relaxed", scope, parent: "gnt_not-a-window" },
    { kind: "route", selector: change.selector, policyMode: "relaxed", scope: { ...scope, methods: ["DELETE"] }, parent: null },
    { kind: "route", selector: { ...change.selector, environment: "prod" }, policyMode: "relaxed", scope, parent: null },
  ])("refusal/remember %j", (input) => expect(PolicyRememberSchema.safeParse(input).success).toBe(false))
  test("refusal/outer-unknown", () => {
    expect(PolicyPreviewRequestSchema.safeParse({ ...preview, extra: true }).success).toBe(false)
    expect(PolicyProposeSchema.safeParse({ ...preview, baseDigest: "a".repeat(43), slotRevision: 0, extra: true }).success).toBe(false)
  })
  test("refusal/digest", () => expect(PolicyProposeSchema.safeParse({ ...preview, baseDigest: "not-a-digest", slotRevision: 0 }).success).toBe(false))
  test("api imports stay type-only", () => {
    const source = readFileSync(new URL("./policy-mode.ts", import.meta.url), "utf8")
    expect(source.split("\n").filter((line) => line.includes('from "./api.ts"'))).toEqual(['import type { NextStep, PolicyInput, RequestedBy, StepUpProof } from "./api.ts"'])
  })
})

describe("strict policy proposal status", () => {
  const status = { proposal: "pol_proposal", item: "custom-key", status: "pending", bindingCode: "ABCD", summary: "Review this change", expiresAt: "2026-10-26T11:00:00Z", outcome: null }
  const outcome = { change, override: "pov_window", grant: null, effectiveUntil: "2026-10-26T12:00:00Z", active: true, endedReason: null }
  test.each(["pending", "approved", "denied", "expired", "cancelled", "stale"])("status retains item slug for terminal next steps: %s", (state) => {
    expect(PolicyProposalStatusSchema.parse({ ...status, status: state }).item).toBe("custom-key")
  })
  test("status validates the actual approved outcome", () => {
    expect(PolicyProposalStatusSchema.parse({ ...status, status: "approved", outcome }).outcome?.change).toEqual(change)
  })
  test("refusal/status-missing-item", () => {
    const { item: _item, ...missing } = status
    expect(PolicyProposalStatusSchema.safeParse(missing).success).toBe(false)
  })
  test.each(["", "Bad-slug", "bad--slug", "bad-", "has/slash"])("refusal/status-bad-item %s", (item) => {
    expect(PolicyProposalStatusSchema.safeParse({ ...status, item }).success).toBe(false)
  })
  test.each(["proposal", "status", "bindingCode", "summary", "expiresAt", "outcome"])("refusal/status-missing-field %s", (field) => {
    const missing: Record<string, unknown> = { ...status }
    delete missing[field]
    expect(PolicyProposalStatusSchema.safeParse(missing).success).toBe(false)
  })
  test.each(["change", "override", "grant", "effectiveUntil", "active", "endedReason"])("refusal/status-missing-outcome-field %s", (field) => {
    const missing: Record<string, unknown> = { ...outcome }
    delete missing[field]
    expect(PolicyProposalStatusSchema.safeParse({ ...status, status: "approved", outcome: missing }).success).toBe(false)
  })
  test("refusal/status-unknown-field", () => expect(PolicyProposalStatusSchema.safeParse({ ...status, next: { command: "mehen policy show other-key" } }).success).toBe(false))
  test("refusal/status-unknown-outcome-field", () => expect(PolicyProposalStatusSchema.safeParse({ ...status, status: "approved", outcome: { ...outcome, extra: true } }).success).toBe(false))
  test("refusal/status-unknown-change-field", () => expect(PolicyProposalStatusSchema.safeParse({ ...status, status: "approved", outcome: { ...outcome, change: { ...change, controls: {} } } }).success).toBe(false))
  test("refusal/status-unknown-state", () => expect(PolicyProposalStatusSchema.safeParse({ ...status, status: "completed" }).success).toBe(false))
  test("refusal/status-unknown-ending", () => expect(PolicyProposalStatusSchema.safeParse({ ...status, status: "approved", outcome: { ...outcome, endedReason: "pending" } }).success).toBe(false))
})

describe("policy path pins", () => {
  test.each(["https://example.com", "user@example.com", "*.example.com", "example.com:443", "EXAMPLE.com", "example.com.", "256.1.2.3", "01.2.3.4", "bad_.example", "x".repeat(254)])("refusal/host %s", (host) => expect(isPolicyHost(host)).toBe(false))
  test.each(["example.com", "127.0.0.1", "[::1]"])("canonical host %s", (host) => expect(isPolicyHost(host)).toBe(true))
  test.each(["api/projects", "/api//projects", "/api/../projects", "/api/./projects", "/api/%2Fprojects", "/api/%73ecret", "/api\\projects", "/api/projects;x=1", "/api/projects?q=1", "/api/projects#fragment", "/api/\u202Eprojects", "/api/\u0000projects", "/api/foo*", "/api/**/projects", `/${"x".repeat(256)}`])("refusal/path %s", (path) => expect(isPolicyPath(path, true)).toBe(false))
  test("refusal/anchor-wildcard", () => expect(PolicyRouteScopeSchema.safeParse({ ...scope, anchorPath: "/api/projects/*/issues" }).success).toBe(false))
  test("refusal/anchor-outside", () => expect(PolicyRouteScopeSchema.safeParse({ ...scope, anchorPath: "/api/elsewhere" }).success).toBe(false))
  test.each([
    ["/api/**", "/api/**"], ["/api/*/**", "/api/**"], ["/**", "/**"],
    ["/api/projects/**", "/api/projects/**"],
  ])("refusal/binding-pin %s within %s", (path, boundary) => expect(policyScopeWithinBinding({ ...scope, path }, { hosts: [scope.host], paths: [boundary] })).toBe(false))
  test("refusal/deepest-boundary", () => expect(policyScopeWithinBinding(scope, { hosts: [scope.host], paths: ["/api/**", "/api/projects/**"] })).toBe(false))
  test.each([["/api/**", "/api/projects/**"], ["/api/*/**", "/api/projects/**"], ["/api/**", "/api/*"], ["/api/*", "/api/projects"], ["/api/projects/**", "/api/**/issues"]])("refusal/subset %s within %s", (child, parent) => expect(policyPathSubset(child, parent)).toBe(false))
  test("refusal/binding-host", () => expect(policyScopeWithinBinding(scope, { hosts: ["other.example"] })).toBe(false))
  test("refusal/binding-method", () => expect(policyScopeWithinBinding(scope, { hosts: [scope.host], methods: ["GET"] })).toBe(false))
  test("refusal/binding-path", () => expect(policyScopeWithinBinding(scope, { hosts: [scope.host], paths: ["/other/**"] })).toBe(false))
  test("pinned constructive subsets", () => {
    expect(policyScopeWithinBinding(scope, { hosts: [scope.host], paths: ["/api/**"] })).toBe(true)
    expect(policyScopeWithinBinding({ ...scope, path: "/projects/**", anchorPath: "/projects/123" }, { hosts: [scope.host] })).toBe(true)
    expect(policyPathSubset("/api/projects/*", "/api/**")).toBe(true)
    expect(policyPathSubset("/api/projects/123", "/api/*/*")).toBe(true)
  })
})

describe("pure policy narrowing and resolution", () => {
  test("anchor literals, fewer methods, shorter TTL and YOLO to relaxed narrow", () => {
    const requested: PolicyChange = { ...change, policyMode: "yolo" }
    expect(isPolicyNarrowing(requested, { ...change, ttlSeconds: 60, scope: { ...scope, methods: ["GET"], path: "/api/projects/12345/**" } })).toBe(true)
    expect(isPolicyNarrowing(change, change)).toBe(true)
  })
  const narrowingRefusals: [string, PolicyChange][] = [
    ["kind", { ...change, kind: "allow" }], ["item", { ...change, target: { kind: "item", item: "other-key" } }],
    ["device", { ...change, selector: { ...change.selector, device: "dev_other" } }],
    ["session-null", { ...change, selector: { ...change.selector, session: null } }],
    ["session-other", { ...change, selector: { ...change.selector, session: "other" } }],
    ["host", changedScope({ host: "other.example" })], ["basis", changedScope({ basis: "reviewed" })],
    ["anchor", changedScope({ anchorPath: "/api/projects/foreign/issues" })], ["mode", { ...change, policyMode: "yolo" }],
    ["ttl", { ...change, ttlSeconds: 3601 }], ["methods", changedScope({ methods: ["GET", "PUT"] })],
    ["path-broader", changedScope({ path: "/api/**" })],
    ["path-unanchored", changedScope({ path: "/api/projects/foreign/**", anchorPath: scope.anchorPath })],
  ]
  test.each(narrowingRefusals)("refusal/narrow-%s", (_label, effective) => expect(isPolicyNarrowing(change, effective)).toBe(false))
  test("refusal/narrow-deadline-remove", () => expect(isPolicyNarrowing({ ...change, notAfter: "2026-10-26T11:00:00Z" }, change)).toBe(false))
  test("refusal/narrow-deadline-later", () => expect(isPolicyNarrowing({ ...change, notAfter: "2026-10-26T11:00:00Z" }, { ...change, notAfter: "2026-10-26T12:00:00Z" })).toBe(false))
  test.each(["2026-10-26T10:00:00Z", "2026-10-26T09:59:59Z", "2026-10-26T10:00:59Z"])("refusal/expiry %s", (notAfter) => expect(policyExpiresAt({ ...change, notAfter }, now)).toBeNull())
  test("refusal/parent-expiry", () => expect(policyExpiresAt(change, now, "2026-10-26T10:00:00Z")).toBeNull())
  test("TTL begins at approval and intersects absolute and parent caps", () => {
    expect(policyExpiresAt(change, now)).toBe("2026-10-26T11:00:00.000Z")
    expect(policyExpiresAt({ ...change, notAfter: "2026-10-26T12:30:00+02:00" }, now, "2026-10-26T10:45:00Z")).toBe("2026-10-26T10:30:00.000Z")
    expect(policyLifetime("relaxed", "reviewed", "mode").maximumSeconds).toBe(86400)
    expect(policyLifetime("relaxed", "reviewed", "allow").maximumSeconds).toBe(28800)
  })
  test.each([
    ["deny", [], "yolo", "routine", true, "deny"], ["approve", [{ action: "approve" }], "yolo", "routine", true, "approve"],
    ["approve", [], "standard", "routine", true, "approve"], ["approve", [], "yolo", "unknown", true, "approve"],
    ["approve", [], "yolo", "routine", false, "approve"], ["approve", [], "relaxed", "destructive", true, "approve"],
  ] as const)("refusal/resolve %s %j %s %s %s", (action, matched, mode, effect, eligible, expected) => expect(resolvePolicyMode({ action, matched: [...matched] }, mode, effect, eligible)).toBe(expected))
  test("default approval alone can be skipped", () => expect(resolvePolicyMode({ action: "approve", matched: [] }, "relaxed", "routine", true)).toBe("allow"))
})
