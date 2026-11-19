import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { OAUTH_PROVIDERS, TEMPLATES, connectionPolicy } from "@mehen/protocol/templates"
import { MockVault, item, vaultError } from "../testing/mock-vault.ts"
import { policyCatalogueNamed } from "@mehen/protocol/policy-catalogue"
import { grantView, ruleView } from "../testing/policy-rules-fixtures.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { checkLines, checkRequest, mayCoverText } from "./check.ts"
import { plainText, styler, terminalText } from "../tty.ts"
import { clockText } from "../ask.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

const gmail = OAUTH_PROVIDERS["google-gmail"] as NonNullable<(typeof OAUTH_PROVIDERS)[string]>
const gmailItem = item("gmail-alex", {
  kind: "oauth-connection",
  provider: "google-gmail",
  account: "alex@example.com",
  accountVerified: true,
  hosts: ["gmail.googleapis.com"],
  binding: gmail.upstream.binding,
  policy: connectionPolicy(gmail),
})

beforeAll(() => {
  vault = new MockVault()
  vault.items.push(gmailItem)
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

function relayCalls(): number {
  return vault.seen.filter((s) => s.path === "/v1/relay").length
}

describe("mehen check", () => {
  test("a send needs approval: exit 3, the approve rule's note quoted, advisory, and no relay request", async () => {
    const relays = relayCalls()
    const result = await runJv(["check", "gmail-alex", "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"], env)
    expect(result.code).toBe(EXIT.approval)
    expect(result.stdout.split("\n")[0]).toBe('needs approval: "sends email as you" (approve rule; policy default approve)')
    expect(result.stdout).toContain("The base policy asks for approval. The real request may have a different result.")
    expect(result.stdout).toContain("Advisory:")
    expect(result.stderr).toBe("")
    expect(relayCalls()).toBe(relays)
    expect(vault.seen.filter((s) => s.method === "GET").slice(-2)).toMatchObject([{ path: "/v1/items/gmail-alex" }, { path: "/v1/policy/rules", search: "?item=gmail-alex&include=grants" }])
  })

  test("a read is allowed: exit 0, still advisory", async () => {
    const result = await runJv(["check", "gmail-alex", "GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout.split("\n")[0]).toBe('allowed: "reads" (allow rule)')
    expect(result.stdout).toContain("Advisory: local base policy only. Live windows, floors, protection and grants are not included; this cannot predict permission to send. The real fetch enforces current authority.")
  })

  test("sending a stored draft is refused: exit 5 with the deny rule's note", async () => {
    const result = await runJv(["check", "gmail-alex", "POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(result.stdout.split("\n")[0]).toBe('refused: "sending a saved draft by id cannot show you what is sent; send the whole message with messages/send and raw instead" (deny rule)')
  })

  test("a host outside the binding is refused: exit 5, binding_refused, and nothing is sent to the relay", async () => {
    const relays = relayCalls()
    const result = await runJv(["check", "openai-personal", "GET", "https://api.evil.test/v1/models"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(result.stdout.split("\n")[0]).toBe("outside the binding: host api.evil.test is not api.openai.com")
    expect(relayCalls()).toBe(relays)
    const asJson = json(await runJv(["check", "openai-personal", "GET", "https://api.evil.test/v1/models", "--json"], env))
    expect(asJson).toEqual({ item: "openai-personal", method: "GET", url: "https://api.evil.test/v1/models", decision: "binding_refused", matched: [], reason: "host api.evil.test is not api.openai.com", bodyUnknown: false, advisory: true, scope: "base-policy-only" })
    expect(relayCalls()).toBe(relays)
  })

  test("--json carries the decision, the matched rules and advisory: true, with the same exit codes", async () => {
    const approve = await runJv(["check", "gmail-alex", "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", "--json"], env)
    expect(approve.code).toBe(EXIT.approval)
    expect(json(approve)).toMatchObject({ item: "gmail-alex", method: "POST", decision: "approve", matched: [{ action: "approve", note: "sends email as you" }], advisory: true })
    const allow = await runJv(["check", "gmail-alex", "GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels", "--json"], env)
    expect(allow.code).toBe(EXIT.ok)
    expect(json(allow)).toMatchObject({ decision: "allow", matched: [{ action: "allow", note: "reads" }] })
    const deny = await runJv(["check", "gmail-alex", "POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send", "--json"], env)
    expect(deny.code).toBe(EXIT.refused)
    expect(json(deny)).toMatchObject({ decision: "deny" })
  })

  test("a body matcher without a body fails closed and says so; with the body, the allow rule can match", async () => {
    const linear = TEMPLATES.linear as NonNullable<(typeof TEMPLATES)[string]>
    vault.items.push(item("linear-key", { provider: "linear", hosts: ["api.linear.app"], binding: linear.binding, policy: linear.policy }))
    try {
      const noBody = await runJv(["check", "linear-key", "POST", "https://api.linear.app/graphql"], env)
      expect(noBody.code).toBe(EXIT.approval)
      expect(noBody.stdout).toContain("No body was given (-d), so rules that read the body were taken to match")
      expect(json(await runJv(["check", "linear-key", "POST", "https://api.linear.app/graphql", "--json"], env))).toMatchObject({ decision: "approve", bodyUnknown: true })
      const query = await runJv(["check", "linear-key", "POST", "https://api.linear.app/graphql", "-H", "Content-Type: application/json", "-d", '{"query":"{ viewer { id } }"}'], env)
      expect(query.code).toBe(EXIT.ok)
      expect(query.stdout.split("\n")[0]).toBe('allowed: "read-only GraphQL queries" (allow rule)')
      const mutation = await runJv(["check", "linear-key", "POST", "https://api.linear.app/graphql", "-d", '{"query":"mutation { issueCreate(input: {}) { success } }"}', "--json"], env)
      expect(mutation.code).toBe(EXIT.approval)
      expect(json(mutation)).toMatchObject({ decision: "approve", bodyUnknown: false })
    } finally {
      vault.items.pop()
    }
  })

  test("a missing item, a bad slug, a bad URL or a malformed header are the usual errors and nothing is relayed", async () => {
    const relays = relayCalls()
    expect((await runJv(["check", "nope-item", "GET", "https://api.openai.com/v1/models", "--json"], env)).code).toBe(EXIT.error)
    expect((await runJv(["check", "Bad_Slug", "GET", "https://api.openai.com/v1/models"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["check", "openai-personal", "GET", "not a url"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["check", "openai-personal", "GET", "https://api.openai.com/", "-H", "no colon"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["check", "openai-personal", "GET"], env)).code).toBe(EXIT.usage)
    expect(relayCalls()).toBe(relays)
  })

  test("an item whose rule notes and hosts carry hidden characters and escapes prints them spelled out", async () => {
    vault.items.push(
      item("hostile-key", {
        hosts: ["api.hostile.test"],
        binding: { hosts: ["api.hostile.test"] },
        policy: { default: "approve", rules: [{ action: "deny", methods: ["POST"], paths: ["/send"], note: "sends\u001b[2K\u001b[32m allowed\u202e" }] },
      }),
    )
    try {
      const result = await runJv(["check", "hostile-key", "POST", "https://api.hostile.test/send"], env)
      expect(result.code).toBe(EXIT.refused)
      expect(result.stdout).not.toContain("\u001b")
      expect(result.stdout).not.toContain("\u202e")
      expect(result.stdout.split("\n")[0]).toBe('refused: "sends\\u001B[2K\\u001B[32m allowed[RLO U+202E]" (deny rule)')
      const outside = await runJv(["check", "hostile-key", "GET", "https://api.evil.test/x"], env)
      expect(outside.stdout.split("\n")[0]).toBe("outside the binding: host api.evil.test is not api.hostile.test")
    } finally {
      vault.items.pop()
    }
  })

  test("on a TTY the verdict word is coloured and a hostile rule note cannot steer the terminal", () => {
    const result = checkRequest({
      item: "x",
      method: "POST",
      url: "https://h.example/send",
      binding: { hosts: ["h.example"] },
      policy: { default: "approve", rules: [{ action: "approve", paths: ["/send"], note: "sends\u001b[2K\u202e" }] },
      body: null,
    })
    const lines = checkLines(result, "approve", styler(true)).map(terminalText)
    expect(lines[0]).toStartWith("\u001b[33mneeds approval\u001b[0m: ")
    expect(lines[0]).toContain('"sends\\u001B[2K[RLO U+202E]"')
    expect((lines[0] ?? "").match(/\u001b\[[0-9;]*m/g)).toEqual(["\u001b[33m", "\u001b[0m"])
    expect(plainText(checkLines(result, "approve", styler(false))[0] ?? "")).toStartWith("needs approval: ")
  })
})

test("a lease-only credential is outside the binding with no host, never the reserved host", () => {
  const result = checkRequest({ item: "jwt-secret", method: "GET", url: "https://api.example.com/", binding: { hosts: [LEASE_ONLY_HOST] }, policy: { default: "allow", rules: [] }, body: null })
  expect(result).toMatchObject({ decision: "binding_refused", reason: "no host: the vault never sends this credential to a service" })
  expect(plainText(checkLines(result, "allow", styler(false))[0] ?? "")).toBe("outside the binding: no host: the vault never sends this credential to a service")
})

test("a path with an encoded ? or # meets the rules cut there too, and a path no rule covers is checked as before", () => {
  const check = (policy: Parameters<typeof checkRequest>[0]["policy"], method: string, path: string) =>
    checkRequest({ item: "key", method, url: `https://api.example.com${path}`, binding: { hosts: ["api.example.com"] }, policy, body: null }).decision
  const deny = { default: "allow" as const, rules: [{ action: "deny" as const, paths: ["/v1/keys/**"] }] }
  expect(check(deny, "GET", "/v1/keys%3Fx")).toBe("deny")
  expect(check(deny, "GET", "/v1/keys%23x")).toBe("deny")
  expect(check(deny, "GET", "/repos/o/r/git/refs/heads/fix%23123")).toBe("allow")
  const allow = { default: "approve" as const, rules: [{ action: "allow" as const, methods: ["POST"], paths: ["/v1/*/send"] }, { action: "allow" as const, paths: ["/repos/*/*/git/refs/**"] }] }
  expect(check(allow, "POST", "/v1/x/send")).toBe("allow")
  expect(check(allow, "POST", "/v1/delete%3F/send")).toBe("approve")
  expect(check(allow, "GET", "/repos/o/r/git/refs/heads/fix%23123")).toBe("allow")
  expect(check(allow, "GET", "/storage/kv/values/user%231")).toBe("approve")
})

test("a path outside the binding only once cut at an encoded ? or # names it", () => {
  const binding = { hosts: ["gitlab.example"], paths: ["/api/v4/projects/*/repository/files/*/raw"] }
  const check = (path: string) => checkRequest({ item: "gitlab", method: "GET", url: `https://gitlab.example${path}`, binding, policy: { default: "allow", rules: [] }, body: null })
  expect(check("/api/v4/projects/1/repository/files/what%3F.md/raw")).toMatchObject({
    decision: "binding_refused",
    reason: "path /api/v4/projects/1/repository/files/what%3F.md/raw, read up to its encoded ? (%3F) as an upstream that decodes it again may end it, is not under /api/v4/projects/*/repository/files/*/raw",
  })
  expect(check("/api/v4/projects/1/issues")).toMatchObject({ decision: "binding_refused", reason: "path /api/v4/projects/1/issues is not under /api/v4/projects/*/repository/files/*/raw" })
})

test("refusal/local check never claims to predict live server permission in human output or JSON", async () => {
  const result = await runJv(["check", "openai-personal", "GET", "https://api.openai.com/v1/models"], env)
  expect(result.stdout).toContain("Live windows, floors, protection and grants are not included; this cannot predict permission to send")
  expect(result.stdout).toContain("mehen policy show openai-personal")
  expect(checkRequest({ item: "key", method: "GET", url: "https://api.example.com/", binding: { hosts: ["api.example.com"] }, policy: { default: "allow", rules: [] }, body: null })).toMatchObject({ advisory: true, scope: "base-policy-only" })
})

describe("mehen check --plan", () => {
  const send = { item: "gmail-alex", method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send" }
  const read = { item: "gmail-alex", method: "GET", url: "https://gmail.googleapis.com/gmail/v1/users/me/labels" }
  const draft = { item: "gmail-alex", method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send" }
  async function plan(requests: unknown[]): Promise<string> {
    const path = join(dir.path, "plan.json")
    await writeFile(path, JSON.stringify({ version: 1, requests }))
    return path
  }

  test("checks every request: the counts, the requests that share a shape, and the worst outcome's exit code, sending nothing", async () => {
    const relays = relayCalls()
    const asks = await runJv(["check", "--plan", await plan([read, send, { ...send, url: `${send.url}?x=1` }]), "--json"], env)
    expect(asks.code).toBe(EXIT.approval)
    const body = json(asks) as { results: { index: number; decision: string }[]; counts: unknown; sameShape: number[][]; advisory: boolean }
    expect(body.results.map((r) => [r.index, r.decision])).toEqual([[0, "allow"], [1, "approve"], [2, "approve"]])
    expect(body).toMatchObject({ counts: { allow: 1, approve: 2, refuse: 0 }, sameShape: [[1, 2]], advisory: true, scope: "base-policy-only" })
    expect((await runJv(["check", "--plan", await plan([read])], env)).code).toBe(EXIT.ok)
    const refused = await runJv(["check", "--plan", await plan([read, send, draft])], env)
    expect(refused.code).toBe(EXIT.refused)
    const lines = refused.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe('request 1 (GET https://gmail.googleapis.com/gmail/v1/users/me/labels): allowed: "reads" (allow rule)')
    expect(refused.stdout).toContain("1 would go through, 1 would ask and 1 would be refused, by the base policies.")
    expect(refused.stdout).not.toContain("go to the same place")
    expect(lines.at(-1)).toContain("Advisory: local base policy only.")
    const shared = await runJv(["check", "--plan", await plan([send, read, send])], env)
    expect(shared.stdout).toContain("Requests 1, 3 go to the same place (item, method, host and path); a bundle keeps every one, so check you meant each.")
    expect(relayCalls()).toBe(relays)
    expect(vault.seen.filter((s) => s.path === "/v1/approvals/bundles")).toEqual([])
  })

  test("--plan takes no item, method, URL, -H or -d, and a bad plan is a usage error", async () => {
    const path = await plan([read])
    for (const extra of [["gmail-alex", "GET", "https://gmail.googleapis.com/"], ["-d", "x"], ["-H", "A: b"]]) {
      expect((await runJv(["check", "--plan", path, ...extra, "--json"], env)).code).toBe(EXIT.usage)
    }
    expect((await runJv(["check", "--json"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["check", "--plan", await plan([]), "--json"], env)).code).toBe(EXIT.usage)
  })
})

// A task grant of this key, or the credential's posture for this machine,
// may let a held request through (the vault's order: grant, then posture).
// mehen check only hints at it: the vault decides at send time, from the
// credential's protection, the request's mode and the grant's state then, so
// the decision, the exit code and the scope stay the base policy's.
describe("mehen check with task grants and how careful a credential is", () => {
  const version = policyCatalogueNamed("github")!.version
  const github = (extra: Parameters<typeof item>[1] = {}) => item("github-work", { hosts: ["api.github.com"], binding: { hosts: ["api.github.com"] }, policy: { default: "approve", rules: [] }, ...extra })
  const routine = { level: "routine", coversThisKey: true, catalogue: { template: "github", version } } as const
  const comment = ["check", "github-work", "POST", "https://api.github.com/repos/northwind/platform/issues/1/comments", "-d", '{"body":"x"}', "-H", "Content-Type: application/json"]
  const endsAt = new Date(Date.now() + 3_600_000).toISOString()
  const grant = (extra: Parameters<typeof grantView>[0] = {}) => grantView({ id: "rul_grant", catalogueVersion: version, endsAt, uses: 3, maxUses: 50, ...extra })
  const held = "needs approval: no rule matched; policy default approve"
  // Every run of this block: the word the vault alone may say is never printed.
  async function check(args: string[], runEnv = env): Promise<JvResult> {
    const result = await runJv(args, runEnv)
    expect(result.stdout).not.toContain("covered")
    return result
  }
  beforeEach(() => {
    vault.items.splice(1)
    vault.overrides.clear()
  })

  test("a live task grant on the request's area may cover it: still exit 3, one may-cover line, and --json keeps the base decision and scope with mayCover", async () => {
    vault.items.push(github())
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([ruleView(), grant()]))
    const human = await check(comment, { ...env, TZ: "Etc/UTC" })
    expect(human.code).toBe(EXIT.approval)
    expect(human.stdout.split("\n").slice(0, 2)).toEqual([held, `  A task grant on issues may cover this (rul_grant, 3 of 50 uses, ends ${clockText(endsAt, { timeZone: "Etc/UTC" })}); the vault decides when it is sent.`])
    expect(human.stdout).toContain("The base policy asks for approval.")
    const result = await check([...comment, "--json"])
    expect(result.code).toBe(EXIT.approval)
    expect(json(result)).toMatchObject({ decision: "approve", scope: "base-policy-only", mayCover: { kind: "grant", id: "rul_grant", areas: ["issues"], endsAt, uses: 3, maxUses: 50 } })
    expect(mayCoverText({ kind: "grant", id: "rul_grant", areas: ["dns", "workers"], endsAt, uses: 0, maxUses: 20 }, { timeZone: "Etc/UTC" })).toBe(`A task grant on dns, workers may cover this (rul_grant, 0 of 20 uses, ends ${clockText(endsAt, { timeZone: "Etc/UTC" })}); the vault decides when it is sent.`)
  })

  test("a posture that lets this machine's routine building through, or trusts it, may cover it: still exit 3, with mayCover", async () => {
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([]))
    vault.items.push(github({ posture: routine }))
    const human = await check(comment)
    expect(human.code).toBe(EXIT.approval)
    expect(human.stdout.split("\n").slice(0, 2)).toEqual([held, "  This credential's posture lets routine building through and may cover this; the vault decides when it is sent."])
    const result = await check([...comment, "--json"])
    expect(result.code).toBe(EXIT.approval)
    expect(json(result)).toMatchObject({ decision: "approve", scope: "base-policy-only", mayCover: { kind: "posture", level: "routine" } })
    vault.items.splice(1, 1, github({ posture: { ...routine, level: "trust" } }))
    const trust = await check(comment)
    expect(trust.code).toBe(EXIT.approval)
    expect(trust.stdout.split("\n")[1]).toBe("  This credential trusts this machine and may cover this; the vault decides when it is sent.")
  })

  test("no mayCover for a spent, ended or project grant, a posture that does not cover this key, or a request the floor holds", async () => {
    vault.items.push(github())
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([grant({ id: "rul_spent", uses: 50 }), grant({ id: "rul_ended", status: "ended", endedReason: "revoked" }), grant({ id: "rul_past", endsAt: new Date(Date.now() - 1000).toISOString() }), grant({ id: "rul_project", context: { project: "prj_a", environment: "dev" } }), grant({ id: "rul_pulls", areas: ["pulls"] })]))
    const grants = await check([...comment, "--json"])
    expect(grants.code).toBe(EXIT.approval)
    expect(json(grants)).toMatchObject({ decision: "approve", scope: "base-policy-only" })
    expect(json(grants)).not.toHaveProperty("mayCover")
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([]))
    for (const posture of [{ ...routine, coversThisKey: false }, { level: "ask", coversThisKey: false, catalogue: { template: "github", version } }] as const) {
      vault.items.splice(1, 1, github({ posture }))
      const asks = await check([...comment, "--json"])
      expect(asks.code).toBe(EXIT.approval)
      expect(json(asks)).not.toHaveProperty("mayCover")
    }
    // Deleting a comment is floor: no grant or posture may cover it.
    vault.items.splice(1, 1, github({ posture: routine }))
    vault.overrides.set("GET /v1/policy/rules", () => Response.json([grant()]))
    const floor = await check(["check", "github-work", "DELETE", "https://api.github.com/repos/northwind/platform/issues/comments/5", "--json"])
    expect(floor.code).toBe(EXIT.approval)
    expect(json(floor)).not.toHaveProperty("mayCover")
    // A body without a JSON content type, or a live key, is never covered either.
    expect(json(await check(comment.slice(0, -2).concat("--json")))).not.toHaveProperty("mayCover")
    vault.items.splice(1, 1, github({ posture: routine, secretFields: [{ name: "key", set: true, length: 40, prefix: "sk_live_", fingerprint: "f" }] }))
    expect(json(await check([...comment, "--json"]))).not.toHaveProperty("mayCover")
    const plain = await check(comment)
    expect(plain.stdout.split("\n")[1]).toBe("  The base policy asks for approval. The real request may have a different result.")
  })

  test("stays base-policy-only with no hint against an older vault with no posture and no grant list", async () => {
    vault.items.push(github())
    vault.overrides.set("GET /v1/policy/rules", () => vaultError("forbidden", "Policy widening is not available yet."))
    const old = await check([...comment, "--json"])
    expect(old.code).toBe(EXIT.approval)
    expect(json(old)).toMatchObject({ decision: "approve", scope: "base-policy-only" })
    expect(json(old)).not.toHaveProperty("mayCover")
    expect((await check(comment)).stdout).toContain("Advisory: local base policy only.")
  })
})
