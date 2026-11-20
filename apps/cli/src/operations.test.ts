import { describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { CliError, exitCodeFor } from "./errors.ts"
import { clockDown, connectCommandText, durationText, fetchContext, missingClientError, parseDurationSeconds, relayRequest, requestCommandText, resolveHome, settle, shellWord, waitTarget, showItem, waitFor, isWaitKind } from "./operations.ts"
import { OAUTH_PROVIDERS } from "@mehen/protocol/templates"

const parse = (text: string) => parseDurationSeconds(text, { max: 86_400, flag: "--timeout", help: "mehen wait --help" })

describe("durations", () => {
  test("seconds, s, m and h; 0 checks once", () => {
    expect(parse("0")).toBe(0)
    expect(parse("90")).toBe(90)
    expect(parse("30s")).toBe(30)
    expect(parse("10m")).toBe(600)
    expect(parse("2h")).toBe(7200)
    expect(parse(" 5 m ")).toBe(300)
  })

  test("soon, a negative, a fraction, a unit alone or over the maximum is a usage error naming the flag", () => {
    for (const bad of ["soon", "-5", "1.5m", "m", "", "10 minutes", "1d", "25h"]) {
      let error: unknown
      try {
        parse(bad)
      } catch (e) {
        error = e
      }
      expect(error).toBeInstanceOf(CliError)
      expect((error as CliError).code).toBe("usage")
      expect((error as CliError).message).toBe("--timeout takes a number of seconds, or a duration such as 30s, 10m or 2h, up to 24 h; 0 checks once.")
    }
  })

  test("durationText and clockDown use the same units the flags take", () => {
    expect(durationText(0)).toBe("0 s")
    expect(durationText(45)).toBe("45 s")
    expect(durationText(600)).toBe("10 min")
    expect(durationText(2880)).toBe("48 min")
    expect(durationText(7200)).toBe("2 h")
    expect(durationText(5400)).toBe("1 h 30 min")
    expect(durationText(86_400)).toBe("24 h")
    expect(clockDown(57 * 60_000 + 40_000)).toBe("57:40")
    expect(clockDown(9 * 60_000 + 12_000)).toBe("9:12")
    expect(clockDown(24 * 3_600_000 - 20_000)).toBe("23:59:40")
    expect(clockDown(500)).toBe("0:01")
    expect(clockDown(-5)).toBe("0:00")
  })
})

describe("recorded commands", () => {
  test("shellWord leaves safe words bare and single-quotes the rest", () => {
    expect(shellWord("openai-new")).toBe("openai-new")
    expect(shellWord("a@b.c:1,2/3.4%+=")).toBe("a@b.c:1,2/3.4%+=")
    expect(shellWord("summarise the inbox")).toBe("'summarise the inbox'")
    expect(shellWord("Alex's $HOME `x` \"q\" \\ !")).toBe(`'Alex'\\''s $HOME \`x\` "q" \\ !'`)
    expect(shellWord("")).toBe("''")
  })

  test("requestCommandText and connectCommandText rebuild the command that was run", () => {
    expect(requestCommandText({ kind: "api-key", name: "acme-key", provider: null, reason: "call Acme", tags: ["ai", "work"], hosts: ["api.acme.test"], paths: ["/v2/**"], injection: { in: "header", name: "X-Api-Key", format: "{key}" }, session: "pi-1", home: { home: "private" } })).toBe(
      "mehen request api-key --name acme-key --reason 'call Acme' --tag ai --tag work --host api.acme.test --path '/v2/**' --header X-Api-Key --format '{key}' --home private",
    )
    expect(connectCommandText({ provider: "google-gmail", client: null, name: "gmail-alex", scopes: ["gmail.modify", "gmail.labels"], expect: "alex@example.com", reason: "triage", session: null, requestClient: true, clientTags: ["mail"], home: { home: "project", project: "prj_1" } })).toBe(
      "mehen connect google-gmail --name gmail-alex --scopes gmail.modify,gmail.labels --expect alex@example.com --reason triage --client-tag mail --request-client --home project --project prj_1",
    )
  })

  test("resolveHome: private unless said; project needs an explicit id or the bound checkout's project, never guessed (design 7.1, 15.7)", () => {
    const help = "mehen request --help"
    expect(resolveHome({ home: null, project: null, manifestProject: null, help })).toEqual({ home: "private" })
    expect(resolveHome({ home: "workspace", project: null, manifestProject: "prj_manifest", help })).toEqual({ home: "workspace" })
    expect(resolveHome({ home: "project", project: "prj_explicit", manifestProject: "prj_manifest", help })).toEqual({ home: "project", project: "prj_explicit" })
    expect(resolveHome({ home: "project", project: null, manifestProject: "prj_manifest", help })).toEqual({ home: "project", project: "prj_manifest" })
    for (const bad of [{ home: "project", project: null, manifestProject: null }, { home: "private", project: "prj_x", manifestProject: null }, { home: "team", project: null, manifestProject: null }, { home: "project", project: "not-an-id", manifestProject: null }, { home: "project", project: null, manifestProject: "legacy" }]) {
      expect(() => resolveHome({ ...bad, help })).toThrow(CliError)
    }
    expect(fetchContext(null, null, help)).toBeNull()
    expect(fetchContext("prj_1", "prod", help)).toEqual({ project: "prj_1", environment: "prod" })
    expect(() => fetchContext("prj_1", null, help)).toThrow(CliError)
    expect(() => fetchContext(null, "prod", help)).toThrow(CliError)
    expect(() => fetchContext("x", "prod", help)).toThrow(CliError)
    expect(relayRequest({ item: "openai", run: null, method: "get", url: "https://api.openai.com/v1/models", headers: [], body: null, approval: null, session: null, context: { project: "prj_1", environment: "prod" } })).toMatchObject({ context: { project: "prj_1", environment: "prod" }, method: "GET" })
    expect(relayRequest({ item: "openai", run: null, method: "get", url: "https://api.openai.com/v1/models", headers: [], body: null, approval: null, session: null })).not.toHaveProperty("context")
  })
})

describe("client_missing", () => {
  test("exits 4 and carries the vault_request arguments and the redirect URI derived from the vault URL", () => {
    const error = missingClientError({ provider: OAUTH_PROVIDERS["google-gmail"] as (typeof OAUTH_PROVIDERS)[string], name: "gmail-alex", expect: "alex@example.com", reason: "read and draft replies", vaultUrl: "https://app.mehen.dev", home: { home: "private" } })
    expect(error.code).toBe("client_missing")
    expect(exitCodeFor(error.code)).toBe(EXIT.human)
    expect(error.extras.request).toEqual({ kind: "oauth-client", name: "google-oauth-client", provider: "google-oauth-client", reason: "connect Gmail as alex@example.com: read and draft replies" })
    expect(error.extras.setup).toEqual({ redirectUri: "https://app.mehen.dev/oauth/callback", docsUrl: "https://console.cloud.google.com/apis/credentials" })
    expect(error.next?.command).toBe("mehen request oauth-client --name google-oauth-client --provider google-oauth-client --reason 'connect Gmail as alex@example.com: read and draft replies' --home private")
    expect(error.next?.url).toBeUndefined()
  })
})

describe("settle", () => {
  test("recognises every wait prefix and nothing else", () => {
    expect(waitTarget("int_1").kind).toBe("intake")
    expect(waitTarget("apr_1").kind).toBe("approval")
    expect(waitTarget("con_1").kind).toBe("connect")
    expect(waitTarget("enr_1")).toEqual({ kind: "enrol", path: "/v1/enrol/enr_1", label: "Enrolment" })
    expect(waitTarget("adp_1")).toEqual({ kind: "adoption", path: "/v1/adoptions/adp_1", label: "Adoption" })
    for (const bad of ["xyz_1", "int_", "int_1/../x", "int_1?wait=1", `int_${"a".repeat(61)}`, "INT_1"]) expect(() => waitTarget(bad)).toThrow()
  })

  test("the ledger's command is the next step once a link is gone; the generic one without it", () => {
    const ledger = { reissueCommand: "mehen request api-key --name k --provider openai --reason r", replacedBy: "int_new" }
    const thrown = (fn: () => unknown): CliError => {
      try {
        fn()
      } catch (e) {
        return e as CliError
      }
      throw new Error("did not throw")
    }
    expect(thrown(() => settle("intake", "int_1", { status: "expired" }, ledger)).next?.command).toBe(ledger.reissueCommand)
    expect(thrown(() => settle("intake", "int_1", { status: "expired" })).next?.command).toBe("mehen request <kind> --name <slug> --reason <why>")
    expect(thrown(() => settle("intake", "int_1", { status: "cancelled", superseded: true }, ledger)).next?.command).toBe("mehen wait int_new")
    expect(thrown(() => settle("connect", "con_1", { status: "failed" }, { ...ledger, reissueCommand: "mehen connect google-gmail --name g --reason r" })).next?.command).toBe("mehen connect google-gmail --name g --reason r")
    expect(thrown(() => settle("enrol", "enr_1", { status: "expired" })).next?.command).toBe("mehen enrol --workspace <slug>")
    expect(thrown(() => settle("approval", "apr_1", { status: "denied", summary: "Send" })).code).toBe("denied")
    expect(thrown(() => settle("enrol", "enr_1", { status: "rejected" })).code).toBe("rejected")
    expect(thrown(() => settle("intake", "int_1", { status: "weird" })).code).toBe("internal")
    expect(settle("intake", "int_1", { status: "open" })).toBeNull()
    expect(settle("approval", "apr_1", { status: "pending" })).toBeNull()
    expect(settle("connect", "con_1", { status: "open" })).toBeNull()
    expect(settle("enrol", "enr_1", { status: "pending" })).toBeNull()
    expect(settle("adoption", "adp_1", { status: "open" })).toBeNull()
    expect(settle("adoption", "adp_1", { status: "approved", adoption: "adp_1", expiresAt: "x", machines: [], created: [] })?.kind).toBe("adoption")
    expect(thrown(() => settle("adoption", "adp_1", { status: "expired" })).next?.command).toBe("mehen adopt submit")
    expect(thrown(() => settle("adoption", "adp_1", { status: "cancelled" })).code).toBe("cancelled")
    expect(settle("enrol", "enr_1", { status: "active", tenant: "t", device: "d", scope: {} })?.kind).toBe("enrol")
  })
})

describe("policy and guarded approval settlement", () => {
  const route = { host: "api.example.com", methods: ["GET"], path: "/v1/**", anchorPath: "/v1/data", basis: "unreviewed" }
  const outcome = { change: { kind: "mode", policyMode: "relaxed", ttlSeconds: 60, scope: route }, override: "pov_narrowed", grant: null, effectiveUntil: "later", active: false, endedReason: "revoked" }
  const proposal = { proposal: "pol_x", item: "example-key", status: "approved", bindingCode: "CODE", summary: "Narrowed route", expiresAt: "later", outcome }
  const grant = { id: "gnt_x", uses: null, expiresAt: "later", kind: "route", scope: { selector: { device: "dev_x", session: null }, route }, parent: "pov_x" }
  const failure = (kind: "policy" | "approval", value: unknown): CliError => {
    try { settle(kind, kind === "policy" ? "pol_x" : "apr_x", value) } catch (error) {
      if (error instanceof CliError) return error
      throw error
    }
    throw new Error("expected terminal refusal")
  }

  test("pol_ resolves the policy status endpoint and preserves the actual narrowed outcome", async () => {
    expect(waitTarget("pol_x")).toEqual({ kind: "policy", path: "/v1/policy/proposals/pol_x", label: "Policy proposal" })
    expect(isWaitKind("policy")).toBe(true)
    const paths: string[] = []
    const api = { async relay(): Promise<Response> { throw new Error("unexpected relay") }, async request<T>(_method: string, path: string): Promise<T> { paths.push(path); return proposal as T } }
    expect(await waitFor(api, "pol_x", { timeoutMs: 0, intervalMs: 0 })).toMatchObject({ kind: "policy", status: proposal })
    expect(paths).toEqual(["/v1/policy/proposals/pol_x"])
    expect(settle("policy", "pol_x", { ...proposal, status: "pending", outcome: null })).toBeNull()
  })

  test("policy terminal refusals retain status/outcome and use local exits with no automatic reproposal", () => {
    for (const [status, code, exit] of [["denied", "denied", 5], ["expired", "expired", 1], ["cancelled", "cancelled", 1], ["stale", "stale", 5]] as const) {
      const error = failure("policy", { ...proposal, status })
      expect(error.code).toBe(code)
      expect(exitCodeFor(error.code)).toBe(exit)
      expect(error.extras).toMatchObject({ kind: "policy", status, outcome })
      expect(error.next?.command ?? "").not.toContain("propose")
      if (status === "stale" || status === "expired") expect(error.next?.command).toBe("mehen policy show example-key")
    }
    expect(failure("policy", { status: "stale" }).next?.command).toBe("mehen pending")
    expect(failure("policy", { status: "expired", item: "bad;cmd" }).next?.command).toBe("mehen pending")
    expect(failure("policy", { status: "unknown" }).code).toBe("internal")
  })

  test("revoked approvals retain grant metadata and say stopped, never human-denied", () => {
    const error = failure("approval", { approval: "apr_x", status: "revoked", grant })
    expect(error.code).toBe("denied")
    expect(exitCodeFor(error.code)).toBe(5)
    expect(error.extras).toMatchObject({ kind: "approval", status: "revoked", grant })
    expect(error.next?.say).toContain("stopped")
    expect(error.next?.say).not.toContain("denied")
    expect(error.next?.command).toBeUndefined()
    const approved = { approval: "apr_x", status: "approved", grant }
    expect(settle("approval", "apr_x", approved)).toMatchObject({ kind: "approval", status: approved })
  })

  test("stale approvals refuse with local stale and safe item-specific next", () => {
    const error = failure("approval", { approval: "apr_x", status: "stale", item: "example-key", grant })
    expect(error.code).toBe("stale")
    expect(exitCodeFor(error.code)).toBe(5)
    expect(error.extras).toMatchObject({ status: "stale", grant })
    expect(error.next?.command).toBe("mehen policy show example-key")
    expect(failure("approval", { status: "stale" }).next?.command).toBe("mehen pending")
    expect(failure("approval", { status: "stale", item: "x;rm" }).next?.command).toBe("mehen pending")
  })

  test("pol_ wait grammar refuses separators, controls and other prefixes", () => {
    for (const id of ["pol_", "pol_x/next", "pol_x?wait=1", "pol_x#fragment", "pol_%2f", "pol_x\n", `pol_${"x".repeat(61)}`, "imp_x"]) expect(() => waitTarget(id)).toThrow(CliError)
  })
})

test("showItem copies policyFloor only when the vault sent it", async () => {
  const { item } = await import("./testing/mock-vault.ts")
  const base = item("example-key")
  let description = base
  const api = { async relay(): Promise<Response> { throw new Error("unexpected relay") }, async request<T>(): Promise<T> { return description as T } }
  expect(await showItem(api, "example-key")).not.toHaveProperty("policyFloor")
  description = { ...base, policyFloor: [] }
  expect(await showItem(api, "example-key")).toHaveProperty("policyFloor", [])
})

test("showItem (pickDescription) copies pushes field by field only when the vault sent them, never who asked", async () => {
  const { item } = await import("./testing/mock-vault.ts")
  const base = item("openai-prod")
  const record = { push: "psh_1", destination: "github:acme/app/OPENAI_API_KEY", words: "GitHub acme/app, Actions secret OPENAI_API_KEY", field: "key", version: 1, current: true, via: null, state: "failed" as const, outcome: null, providerStatus: 403, at: "2026-10-24T09:15:00.000Z" }
  let description: unknown = base
  const api = { async relay(): Promise<Response> { throw new Error("unexpected relay") }, async request<T>(): Promise<T> { return description as T } }
  expect(await showItem(api, "openai-prod")).not.toHaveProperty("pushes")
  description = { ...base, pushes: [{ ...record, message: "what GitHub said" }, { ...record, push: "psh_2", by: "Alex" }] }
  // The vault never sends a machine who asked; a by that comes anyway is dropped.
  expect((await showItem(api, "openai-prod")).pushes).toEqual([record, { ...record, push: "psh_2" }])
  description = { ...base, pushes: [] }
  expect(await showItem(api, "openai-prod")).toHaveProperty("pushes", [])
})

test("showItem (pickDescription) copies a connection's scopes, expiry and renewal field by field, never a token", async () => {
  const { item } = await import("./testing/mock-vault.ts")
  const base = item("gmail-alex")
  const connection = { scopes: ["https://www.googleapis.com/auth/gmail.modify"], expiresAt: "2026-11-09T10:00:00.000Z", refreshing: false }
  let description: unknown = base
  const api = { async relay(): Promise<Response> { throw new Error("unexpected relay") }, async request<T>(): Promise<T> { return description as T } }
  expect(await showItem(api, "gmail-alex")).not.toHaveProperty("connection")
  description = { ...base, connection: { ...connection, accessToken: "ya29.never" } }
  expect((await showItem(api, "gmail-alex")).connection).toEqual(connection)
  description = { ...base, home: { kind: "project", project: "prj_1", extra: true }, connection: { ...connection, client: "google-client" } }
  expect(await showItem(api, "gmail-alex")).toMatchObject({ home: { kind: "project", project: "prj_1" }, connection: { ...connection, client: "google-client" } })
  expect((await showItem(api, "gmail-alex")).home).not.toHaveProperty("extra")
})

// A rotation or reconnect must ask for the home the credential has (the
// default is private), and a reconnect for its OAuth client.
test("credentialRejectedHint names a workspace or project credential's home, and a connection's client", async () => {
  const { credentialRejectedHint } = await import("./operations.ts")
  const revoked = { status: 401, headers: {} }
  const workspaceConnection = { slug: "gmail-team", kind: "oauth-connection" as const, provider: "google-gmail", home: { kind: "workspace" as const }, connection: { scopes: [], expiresAt: null, refreshing: false, client: "google-client" } }
  expect(credentialRejectedHint(revoked, workspaceConnection)).toBe("The service rejected gmail-team's sign-in. If it was revoked, ask a human to reconnect it: mehen connect google-gmail --client google-client --name gmail-team --reason '<why>' --home workspace.")
  // A reader who may not see the client: mehen connect without --client
  // would use the provider's default client, not the connection's own, so
  // the hint sends the human to the credential's page instead.
  const unnamed = { ...workspaceConnection, connection: { scopes: [], expiresAt: null, refreshing: false } }
  const narrow = { status: 403, headers: { "www-authenticate": 'Bearer error="insufficient_scope", scope="gmail.send"' } }
  expect(credentialRejectedHint(revoked, unnamed)).toBe("The service rejected gmail-team's sign-in. If it was revoked, ask a human to reconnect it from its page in the vault.")
  expect(credentialRejectedHint(narrow, unnamed)).toBe("The service said gmail-team lacks a scope it needs. Ask a human to reconnect it with more from its page in the vault; mehen show gmail-team lists the scopes it holds.")
  for (const head of [revoked, narrow]) expect(credentialRejectedHint(head, unnamed)).not.toContain("mehen connect")
  const projectKey = { slug: "openai-evals", kind: "api-key" as const, provider: "openai", home: { kind: "project" as const, project: "prj_3kQ9vXyZ7" } }
  expect(credentialRejectedHint(revoked, projectKey)).toBe("The service rejected openai-evals. If its value was revoked or expired, ask a human to replace it: mehen request api-key --name openai-evals --provider openai --reason '<why>' --home project --project prj_3kQ9vXyZ7.")
  expect(credentialRejectedHint(revoked, { ...projectKey, home: { kind: "member", member: "mem_1" } })).toMatch(/--reason '<why>' --home private\.$/)
})

// Only the platform reconnects a managed workspace's connection, or one
// made with a custom provider (mehen connect cannot name one): the hint
// says so and names no command the agent cannot run.
test("credentialRejectedHint leaves a managed or custom-provider connection to the platform, with no mehen connect", async () => {
  const { credentialRejectedHint } = await import("./operations.ts")
  const revoked = { status: 401, headers: {} }, narrow = { status: 403, headers: { "www-authenticate": 'Bearer error="insufficient_scope", scope="gmail.send"' } }
  const managed = { slug: "gmail-team", kind: "oauth-connection" as const, provider: "google-gmail", home: { kind: "workspace" as const }, connection: { scopes: [], expiresAt: null, refreshing: false, reconnect: "platform" as const } }
  const custom = { ...managed, slug: "acme", provider: null, connection: { scopes: [], expiresAt: null, refreshing: false } }
  expect(credentialRejectedHint(revoked, managed)).toBe("The service rejected gmail-team's sign-in. The platform reconnects this account.")
  expect(credentialRejectedHint(narrow, managed)).toBe("The service said gmail-team lacks a scope it needs. The platform reconnects this account; mehen show gmail-team lists the scopes it holds.")
  expect(credentialRejectedHint(revoked, custom)).toBe("The service rejected acme's sign-in. The platform reconnects this account.")
  for (const head of [revoked, narrow]) for (const item of [managed, custom]) expect(credentialRejectedHint(head, item)).not.toContain("mehen connect")
})

// RFC 6750: only a Bearer challenge whose error parameter is exactly
// insufficient_scope, its parameters read with quoted strings.
test("insufficientScope reads the Bearer challenge's error and scope parameters, nothing else", async () => {
  const { insufficientScope } = await import("./operations.ts")
  const of = (challenge: string, status = 403) => insufficientScope({ status, headers: { "www-authenticate": challenge } })
  expect(of('Bearer error="insufficient_scope", scope="gmail.send gmail.modify"')).toEqual(["gmail.send", "gmail.modify"])
  expect(of("Bearer error=insufficient_scope")).toEqual([])
  expect(of('Bearer realm="a, b=\\"c\\"", error="insufficient_scope", scope="x"')).toEqual(["x"])
  expect(of('Basic realm="api", Bearer error="insufficient_scope", scope="y"')).toEqual(["y"])
  // Whole challenges: a token68 (with its padding) before Bearer, and every Bearer challenge.
  expect(of('Negotiate YIIF==, Bearer error="insufficient_scope", scope="gmail.send"')).toEqual(["gmail.send"])
  expect(of("Negotiate oRswGaADCgEAoxIEEAEAAABDh+CIwTbjqQAAAAA=, Bearer error=insufficient_scope, scope=a")).toEqual(["a"])
  expect(of('Bearer realm="a", error="invalid_token", Bearer error="insufficient_scope", scope="z"')).toEqual(["z"])
  expect(of('Bearer error="invalid_token", Negotiate YIIF==')).toBeNull()
  expect(of('Negotiate a/b+c==, Bearer error="insufficient_scope", scope="w"')).toEqual(["w"])
  expect(of('Bearer error="insufficient_scope", scope="x", Negotiate YIIF==')).toEqual(["x"])
  // The phrase only inside a description, a suffixed value, another scheme or another status: none.
  expect(of('Bearer error="invalid_token", error_description="insufficient_scope for this call"')).toBeNull()
  expect(of('Bearer error="insufficient_scope_extra"')).toBeNull()
  expect(of('Bearer error="insufficient_scopes"')).toBeNull()
  expect(of('Basic error="insufficient_scope"')).toBeNull()
  expect(of('Bearer error="insufficient_scope"', 401)).toBeNull()
})

test("policy operations export the real producer implementations", async () => {
  const operations = await import("./operations.ts")
  const policy = await import("./policy-operations.ts")
  for (const name of ["showPolicy", "previewPolicy", "proposePolicy", "cancelPolicy", "stopPolicy", "convenienceProposal"] as const) expect(operations[name]).toBe(policy[name])
})

test("a truncated answer keeps its bytes and its truncation when the source refuses to be cancelled", async () => {
  const { readLimited } = await import("./operations.ts")
  let pulls = 0
  const source = new ReadableStream<Uint8Array>({
    pull(c) { pulls++; c.enqueue(new Uint8Array(8).fill(pulls)) },
    cancel() { throw new Error("cannot cancel") },
  })
  const read = await readLimited(new Response(source), 12, "POST")
  expect([read.truncated, read.bytes.length]).toEqual([true, 12])
})
