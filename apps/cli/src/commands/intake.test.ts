import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { hostname } from "node:os"
import { EXIT } from "@mehen/protocol/api"
import { readLedger } from "../ledger.ts"
import { MOCK_EXPIRES_AT, MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, WORKSPACE_SCOPE, item, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
const scope = () => vault.ledgerScope()
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  vault.lastDevice = null
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  vault.items.length = 2
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

async function enrolled(): Promise<string> {
  return vault.enrolSoftware(dir.path)
}

function lastBody(): Record<string, unknown> {
  return JSON.parse(vault.seen.at(-1)?.body ?? "{}") as Record<string, unknown>
}

const REQUEST = ["request", "api-key", "--name", "openai-new", "--provider", "openai", "--reason", "summarise mail"]

// A vault that reuses an open intake per slug unless `fresh`, as V-4 does.
function reusingIntakes(): void {
  const open = new Map<string, string>()
  let n = 0
  vault.overrides.set("POST /v1/intakes", (_request, seen) => {
    const body = JSON.parse(seen.body) as { slug: string; fresh?: boolean }
    let id = open.get(body.slug)
    if (!id || body.fresh) {
      n += 1
      id = `int_reuse${n}`
      open.set(body.slug, id)
    }
    return Response.json({ intake: id, url: `${vault.url}/w/mock-space/i/${id}`, expiresAt: MOCK_EXPIRES_AT })
  })
}

describe("mehen request --home (design 7.1, 15.5)", () => {
  test("private is the explicit default; workspace and project are sent as given; project needs an id or the checkout's manifest; nothing is guessed", async () => {
    await enrolled()
    expect((await runJv([...REQUEST, "--home", "workspace", "--json"], env)).code).toBe(EXIT.ok)
    expect(lastBody()).toMatchObject({ home: "workspace" })
    expect(lastBody()).not.toHaveProperty("project")
    expect((await runJv([...REQUEST, "--home", "project", "--project", "prj_3kQ9vXyZ7", "--json"], env)).code).toBe(EXIT.ok)
    expect(lastBody()).toMatchObject({ home: "project", project: "prj_3kQ9vXyZ7" })
    const [entry] = (await readLedger(vault.slotDir(dir.path), scope())).slice(-1)
    expect(entry?.command).toEndWith("--home project --project prj_3kQ9vXyZ7")
    const before = vault.seen.length
    for (const args of [["--home", "project"], ["--home", "team"], ["--project", "prj_x"], ["--home", "project", "--project", "nope"]]) {
      const refused = await runJv([...REQUEST, ...args, "--json"], env)
      expect(refused.code).toBe(EXIT.usage)
      expect(json(refused)).toMatchObject({ error: "usage" })
    }
    expect(vault.seen.length).toBe(before)
    // In a checkout whose mehen.toml names the project, project home takes it.
    const repo = await tempDir()
    try {
      await Bun.write(`${repo.path}/mehen.toml`, 'project = "prj_fromToml"\n')
      expect((await runJv([...REQUEST, "--home", "project", "--json"], env, undefined, repo.path)).code).toBe(EXIT.ok)
      expect(lastBody()).toMatchObject({ home: "project", project: "prj_fromToml" })
    } finally {
      await repo.remove()
    }
  })
})

describe("a machine accepted without private credentials", () => {
  const SAY = 'Ask again in a project you can edit with --home project --project <prj_id>, or with --home workspace if the person is a workspace owner or admin; otherwise ask the human to open this machine\'s page under Machines in the web app and allow it to use their private credentials, then ask again.'
  const privateRefused = (code: "not_found" | "forbidden") => () => vaultError(code, code === "not_found" ? "Not found." : "Private credentials are off for this machine.")

  test("a default (private) request the vault refuses, as not_found or forbidden, is explained as forbidden (exit 5) with the --home to use", async () => {
    await enrolled()
    for (const code of ["not_found", "forbidden"] as const) {
      vault.overrides.set("POST /v1/intakes", privateRefused(code))
      const result = await runJv([...REQUEST, "--json"], env)
      expect(result.code).toBe(EXIT.refused)
      expect(json(result)).toEqual({
        error: "forbidden",
        message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home, which is where an ask goes when no home is given.",
        next: { command: "mehen request api-key --name openai-new --provider openai --reason 'summarise mail' --home project --project '<prj_id>'", say: SAY },
      })
    }
    // Given explicitly, --home private is not described as the default.
    for (const code of ["not_found", "forbidden"] as const) {
      vault.overrides.set("POST /v1/intakes", privateRefused(code))
      const explicit = await runJv([...REQUEST, "--home", "private", "--json"], env)
      expect(explicit.code).toBe(EXIT.refused)
      expect(json(explicit)).toMatchObject({ error: "forbidden", message: "This machine was accepted without private credentials, so it cannot ask for a credential in its owner's private home.", next: { say: SAY } })
    }
    // Human output: the message, then the step.
    const human = await runJv(REQUEST, env)
    expect(human.stderr).toContain("mehen: This machine was accepted without private credentials")
    expect(human.stderr).toContain(`next: ${SAY}`)
  })

  test("a refusal of another home, or of a machine that has private credentials, stays the vault's own", async () => {
    await enrolled()
    vault.overrides.set("POST /v1/intakes", privateRefused("not_found"))
    const project = await runJv([...REQUEST, "--home", "project", "--project", "prj_3kQ9vXyZ7", "--json"], env)
    expect(json(project)).toMatchObject({ error: "not_found", message: "Not found." })
    vault.overrides.set("GET /v1/me", (_request, seen) => Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { ...WORKSPACE_SCOPE, privateCredentials: true }, frozen: false, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER, displayRev: 1 }))
    const allowed = await runJv([...REQUEST, "--json"], env)
    expect(json(allowed)).toMatchObject({ error: "not_found", message: "Not found." })
  })

  test("mehen connect is explained the same way", async () => {
    await enrolled()
    vault.overrides.set("POST /v1/connect", privateRefused("not_found"))
    const result = await runJv(["connect", "google-gmail", "--client", "google-client", "--name", "gmail-alex", "--reason", "triage", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(json(result)).toMatchObject({ error: "forbidden", next: { command: "mehen connect google-gmail --client google-client --name gmail-alex --reason triage --home project --project '<prj_id>'", say: SAY } })
  })
})

describe("mehen request", () => {
  test("creates an intake, prints the ask block and records it in the ledger with the exact re-request", async () => {
    await enrolled()
    const result = await runJv([...REQUEST, "--tag", "ai", "--json"], { ...env, MEHEN_SESSION: "claude-1" })
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { intake: string; url: string; kind: string; name: string; provider: string; ask: Record<string, unknown>; next: Record<string, unknown> }
    expect(out.intake).toStartWith("int_")
    expect(out).toMatchObject({ kind: "api-key", name: "openai-new", provider: "openai", url: `${vault.url}/w/mock-space/i/${out.intake}` })
    expect(out.ask).toMatchObject({
      kind: "intake",
      id: out.intake,
      url: out.url,
      title: "Add a credential",
      what: "Add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise mail",
      check: { label: "asked by", value: expect.stringContaining("session claude-1") },
      expiresAt: MOCK_EXPIRES_AT,
      account: null,
      requestedBy: { session: "claude-1" },
      wait: `mehen wait ${out.intake} --timeout 60 --json`,
    })
    expect(out.next).toMatchObject({ url: out.url, command: `mehen wait ${out.intake} --timeout 60 --json` })
    expect(out.next.say).toContain("it goes into the vault, never to the agent")
    expect(lastBody()).toEqual({ kind: "api-key", slug: "openai-new", provider: "openai", reason: "summarise mail", tags: ["ai"], session: "claude-1", home: "private" })
    expect(vault.seen.at(-1)?.claims.sid).toBe("claude-1")

    const ledger = await readLedger(vault.slotDir(dir.path), scope())
    expect(ledger).toHaveLength(1)
    expect(ledger[0]).toMatchObject({ slug: "openai-new", command: "mehen request api-key --name openai-new --provider openai --reason 'summarise mail' --tag ai --home private", ask: { id: out.intake } })

    const human = await runJv(REQUEST, env)
    const lines = human.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: add a credential")
    expect(lines[1]).toMatch(new RegExp(`^  open:    ${vault.url.replaceAll(".", "\\.")}/w/mock-space/i/int_\\w+$`))
    expect(lines[2]).toBe("  what:    Add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise mail")
    expect(lines[3]).toStartWith("  check:   the page says it was asked by ")
    expect(lines[4]).toMatch(/^  expires: /)
    expect(lines[5]).toMatch(/^  then:    mehen wait int_\w+ --timeout 60 --json   \(or add --wait to this command\)$/)
    expect(human.stderr).toBe("")
  })

  test("asked by is the machine's name in the workspace when the slot records it, else the short host name, for request and connect", async () => {
    await vault.enrolSoftware(dir.path, { config: { name: "tom-laptop" } })
    const requested = json(await runJv([...REQUEST, "--json"], env)) as { ask: { check: unknown; requestedBy: unknown } }
    expect(requested.ask).toMatchObject({ check: { label: "asked by", value: "tom-laptop" }, requestedBy: { device: "tom-laptop", session: null } })
    expect((await runJv(REQUEST, env)).stdout).toContain("  check:   the page says it was asked by tom-laptop\n")
    const connected = json(await runJv(["connect", "google-gmail", "--client", "google-client", "--name", "gmail-alex", "--reason", "triage", "--json"], env)) as { ask: { requestedBy: unknown } }
    expect(connected.ask).toMatchObject({ requestedBy: { device: "tom-laptop" } })
    await dir.remove()
    dir = await tempDir()
    env = { ...env, MEHEN_CONFIG_DIR: dir.path }
    await enrolled()
    const host = (hostname().split(".")[0] ?? "machine").slice(0, 64) || "machine"
    expect(json(await runJv([...REQUEST, "--json"], env))).toMatchObject({ ask: { check: { label: "asked by", value: host } } })
  })

  test("an oauth-client intake names the redirect URI derived from the vault URL in its what line", async () => {
    await enrolled()
    const out = json(await runJv(["request", "oauth-client", "--name", "google-oauth-client", "--provider", "google-oauth-client", "--reason", "connect Gmail", "--json"], env)) as { ask: { what: string } }
    expect(out.ask.what).toBe(`Add google-oauth-client (Google OAuth client, redirect URI ${vault.url}/oauth/callback) so the agent can connect Gmail`)
  })

  test("a link off the vault from the intake answer stays refused: never printed, never in the ask, rebuilt from the id with a warning", async () => {
    await enrolled()
    vault.linkOrigin = "https://evil.example"
    try {
      const human = await runJv(REQUEST, env)
      expect(human.code).toBe(EXIT.ok)
      expect(human.stdout).not.toContain("evil.example")
      expect(human.stdout).toMatch(new RegExp(`  open:    ${vault.url.replaceAll(".", "\\.")}/w/mock-space/i/int_\\w+`))
      expect(human.stderr).toContain(`mehen: warning: The vault returned a link that is not on ${vault.url}`)
      const asJson = await runJv([...REQUEST, "--json"], env)
      expect(asJson.code).toBe(EXIT.ok)
      expect(asJson.stdout).not.toContain("evil.example")
      const out = json(asJson) as { intake: string; url: string; ask: { url: string }; next: { url?: string; say: string }; warning?: string }
      expect(out.url).toBe(`${vault.url}/w/mock-space/i/${out.intake}`)
      expect(out.ask.url).toBe(out.url)
      expect(out.next.url).toBe(out.url)
      expect(out.next.say).toStartWith("The vault returned a link that is not on")
      expect(out.warning).toContain("not on")
      const ledger = await readLedger(vault.slotDir(dir.path), scope())
      for (const entry of ledger) expect(entry.ask.url).toStartWith(vault.url)
    } finally {
      vault.linkOrigin = null
    }
  })

  test("an intake id the vault returns that mehen does not know never reaches a wait command, human text, the link or the ledger", async () => {
    await enrolled()
    vault.overrides.set("POST /v1/intakes", () => Response.json({ intake: "int_1/../../admin", url: `${vault.url}/w/mock-space/i/int_1`, expiresAt: MOCK_EXPIRES_AT }))
    const human = await runJv(REQUEST, env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).not.toContain("mehen wait")
    expect(human.stdout).not.toContain("../")
    expect(human.stdout).not.toContain(`${vault.url}/w/mock-space/i/`)
    expect(human.stdout).toContain("run `mehen pending` to find it")
    expect(human.stderr).toContain("mehen: warning:")
    const asJson = await runJv([...REQUEST, "--json"], env)
    const out = json(asJson) as { url: string | null; ask?: unknown; next: { command?: string; url?: string } }
    expect(out.url).toBeNull()
    expect(out.ask).toBeUndefined()
    expect(out.next.command).toBeUndefined()
    expect(out.next.url).toBeUndefined()
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
    // A link whose route id is not the id the answer names is a bad link: rebuilt from the id.
    vault.overrides.set("POST /v1/intakes", () => Response.json({ intake: "int_7", url: `${vault.url}/w/mock-space/i/int_other`, expiresAt: MOCK_EXPIRES_AT }))
    const mismatch = json(await runJv([...REQUEST, "--json"], env)) as { url: string; next: { command?: string }; warning?: string }
    expect(mismatch.url).toBe(`${vault.url}/w/mock-space/i/int_7`)
    expect(mismatch.next.command).toBe("mehen wait int_7 --timeout 60 --json")
    expect(mismatch.warning).toContain("not on")
  })

  test("an unknown kind, a missing reason or a bad --timeout is a usage error", async () => {
    await enrolled()
    expect((await runJv(["request", "password", "--name", "x-item", "--reason", "r"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["request", "api-key", "--name", "x-item"], env)).code).toBe(EXIT.usage)
    const soon = await runJv([...REQUEST, "--wait", "--timeout", "soon"], env)
    expect(soon.code).toBe(EXIT.usage)
    expect(soon.stderr).toContain("--timeout takes a number of seconds, or a duration such as 30s, 10m or 2h")
  })

  test("without a template, proposes the binding with --host and --path and the injection with --header and --format", async () => {
    await enrolled()
    const result = await runJv(
      ["request", "api-key", "--name", "acme-key", "--reason", "call Acme", "--host", "api.acme.test", "--host", "eu.acme.test", "--path", "/v2/**", "--header", "X-Api-Key", "--format", "{key}", "--json"],
      env,
    )
    expect(result.code).toBe(EXIT.ok)
    expect(lastBody()).toEqual({
      kind: "api-key",
      slug: "acme-key",
      reason: "call Acme",
      binding: { hosts: ["api.acme.test", "eu.acme.test"], paths: ["/v2/**"] },
      injection: { in: "header", name: "X-Api-Key", format: "{key}" },
      home: "private",
    })
    expect((json(result) as { ask: { what: string } }).ask.what).toBe("Add acme-key (api-key, goes to api.acme.test, eu.acme.test) so the agent can call Acme")
    const [entry] = await readLedger(vault.slotDir(dir.path), scope())
    expect(entry?.command).toBe("mehen request api-key --name acme-key --reason 'call Acme' --host api.acme.test --host eu.acme.test --path '/v2/**' --header X-Api-Key --format '{key}' --home private")
  })

  test("a half-given injection or paths without hosts is a usage error and sends nothing", async () => {
    await enrolled()
    const before = vault.seen.length
    for (const extra of [["--host", "api.acme.test", "--header", "X-Api-Key"], ["--host", "api.acme.test", "--format", "{key}"], ["--path", "/v2/**"]]) {
      const result = await runJv(["request", "api-key", "--name", "acme-key", "--reason", "r", ...extra, "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result).error).toBe("usage")
    }
    expect(vault.seen.length).toBe(before)
  })

  test("a repeat of an open request gets the same link back from the vault, keeps the first ledger entry and says so; --new sends fresh and gets a new one", async () => {
    await enrolled()
    reusingIntakes()
    const first = json(await runJv([...REQUEST, "--json"], env)) as { intake: string; url: string; expiresAt: string }
    const [recorded] = await readLedger(vault.slotDir(dir.path), scope())
    expect(lastBody().fresh).toBeUndefined()

    const again = await runJv(REQUEST, env)
    expect(again.code).toBe(EXIT.ok)
    expect(again.stdout).toContain(`  open:    ${first.url}`)
    expect(again.stderr).toBe("mehen: already asked under a minute ago; same link\n")
    expect(lastBody().fresh).toBeUndefined()
    const ledger = await readLedger(vault.slotDir(dir.path), scope())
    expect(ledger).toHaveLength(1)
    expect(ledger[0]?.createdAt).toBe(recorded?.createdAt as string)
    expect(ledger[0]?.ask.expiresAt).toBe(first.expiresAt)

    const fresh = await runJv([...REQUEST, "--new", "--json"], env)
    expect(fresh.code).toBe(EXIT.ok)
    expect(lastBody().fresh).toBe(true)
    const out = json(fresh) as { intake: string }
    expect(out.intake).not.toBe(first.intake)
    expect(fresh.stderr).toBe("")
    expect((await readLedger(vault.slotDir(dir.path), scope())).map((e) => e.ask.id)).toEqual([first.intake, out.intake])
  })

  test("--wait prints the ask and then waits for the intake in the same process", async () => {
    await enrolled()
    vault.overrides.set("POST /v1/intakes", () => Response.json({ intake: "int_w1", url: `${vault.url}/w/mock-space/i/int_w1`, expiresAt: MOCK_EXPIRES_AT }))
    vault.sequences.set("intake:int_w1", [{ intake: "int_w1", status: "open" }, { intake: "int_w1", status: "completed", item: item("openai-new") }])
    const human = await runJv([...REQUEST, "--wait", "--timeout", "10s"], env)
    expect(human.code).toBe(EXIT.ok)
    const lines = human.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: add a credential")
    expect(lines[5]).toBe("  then:    mehen keeps waiting (Ctrl-C is safe: mehen wait int_w1 --timeout 60 --json resumes)")
    expect(lines[6]).toBe("Added openai-new (OpenAI API key, goes to api.openai.com).")
    expect(lines[7]).toBe("  then:    mehen fetch openai-new GET https://api.openai.com/...")
    expect(human.stderr).toBe("")
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])

    vault.sequences.set("intake:int_w1", [{ intake: "int_w1", status: "completed", item: item("openai-new") }])
    const asJson = await runJv([...REQUEST, "--wait", "--json"], env)
    const [created, settled] = jsonLines(asJson.stdout) as Record<string, unknown>[]
    expect(created).toMatchObject({ intake: "int_w1", ask: { id: "int_w1" } })
    expect(settled).toMatchObject({ id: "int_w1", kind: "intake", status: "completed", item: { slug: "openai-new" } })
  })
})

const CONNECT = ["connect", "google-gmail", "--name", "gmail-alex", "--expect", "alex@example.com", "--reason", "triage"]

function googleClient(slug: string, account: string | null = null) {
  return item(slug, { kind: "oauth-client", provider: "google-oauth-client", account, hosts: ["oauth2.googleapis.com"] })
}

// A vault that chains a client intake to the connect when asked and no
// client exists, as V-4 does.
function chainingConnects(): void {
  vault.overrides.set("POST /v1/connect", (_request, seen) => {
    const body = JSON.parse(seen.body) as { client?: string; requestClient?: boolean }
    const base = { connect: "con_chain", url: `${vault.url}/w/mock-space/c/con_chain`, expiresAt: MOCK_EXPIRES_AT }
    if (body.requestClient && !body.client && !vault.items.some((i) => i.kind === "oauth-client")) {
      return Response.json({ ...base, intake: { intake: "int_client", url: `${vault.url}/w/mock-space/i/int_client`, expiresAt: MOCK_EXPIRES_AT } })
    }
    return Response.json(base)
  })
}

describe("mehen connect", () => {
  test("creates a connect link with --client and prints the ask block with the account check", async () => {
    await enrolled()
    const result = await runJv(["connect", "google-gmail", "--client", "google-client", "--name", "gmail-alex", "--scopes", "gmail.modify,gmail.labels", "--expect", "alex@example.com", "--reason", "triage", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { connect: string; url: string; client: string; ask: Record<string, unknown>; next: Record<string, unknown> }
    expect(out.connect).toStartWith("con_")
    expect(out).toMatchObject({ client: "google-client", name: "gmail-alex", provider: "google-gmail", account: "alex@example.com", url: `${vault.url}/w/mock-space/c/${out.connect}` })
    expect(out.ask).toMatchObject({ kind: "connect", id: out.connect, title: "Connect an account", what: "Connect gmail-alex to Gmail as alex@example.com so the agent can triage", check: { label: "account", value: "alex@example.com" }, account: "alex@example.com", wait: `mehen wait ${out.connect} --timeout 60 --json` })
    expect(out.next).toMatchObject({ url: out.url, command: `mehen wait ${out.connect} --timeout 60 --json` })
    expect(lastBody()).toEqual({ provider: "google-gmail", client: "google-client", slug: "gmail-alex", scopes: ["gmail.modify", "gmail.labels"], expect: "alex@example.com", reason: "triage", home: "private" })
    // No listing was needed: the client was named.
    expect(vault.seen.at(-2)?.path).not.toBe("/v1/items")

    const human = await runJv(["connect", "google-gmail", "--client", "google-client", "--name", "gmail-alex", "--expect", "alex@example.com", "--reason", "triage"], env)
    const lines = human.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: connect an account")
    expect(lines[1]).toMatch(/^  open:    .*\/c\/con_\w+$/)
    expect(lines[2]).toBe("  what:    Connect gmail-alex to Gmail as alex@example.com so the agent can triage")
    expect(lines[3]).toBe("  check:   the page shows account alex@example.com; sign in as that account")
    expect(lines[5]).toMatch(/^  then:    mehen wait con_\w+ --timeout 60 --json   \(or add --wait to this command\)$/)
    const entries = await readLedger(vault.slotDir(dir.path), scope())
    expect(entries.map((e) => e.command)).toEqual([
      "mehen connect google-gmail --client google-client --name gmail-alex --scopes gmail.modify,gmail.labels --expect alex@example.com --reason triage --home private",
      "mehen connect google-gmail --client google-client --name gmail-alex --expect alex@example.com --reason triage --home private",
    ])
  })

  test("a link off the vault from the connect answer stays refused: rebuilt from the id with a warning", async () => {
    await enrolled()
    vault.items.push(googleClient("google-oauth-client"))
    vault.linkOrigin = "https://evil.example"
    try {
      const human = await runJv(CONNECT, env)
      expect(human.code).toBe(EXIT.ok)
      expect(human.stdout).not.toContain("evil.example")
      expect(human.stderr).toContain(`mehen: warning: The vault returned a link that is not on ${vault.url}`)
      const asJson = await runJv([...CONNECT, "--json"], env)
      expect(asJson.stdout).not.toContain("evil.example")
      const out = json(asJson) as { connect: string; url: string; ask: { url: string }; next: { url?: string } }
      expect(out.url).toBe(`${vault.url}/w/mock-space/c/${out.connect}`)
      expect(out.ask.url).toBe(out.url)
      expect(out.next.url).toBe(out.url)
    } finally {
      vault.linkOrigin = null
    }
  })

  test("without --client, the one OAuth client made from the provider's client template is picked and named on stderr", async () => {
    await enrolled()
    vault.items.push(googleClient("google-oauth-work", "work@example.com"), item("github-app", { kind: "oauth-client", provider: "github-oauth-app" }))
    const before = vault.seen.length
    const human = await runJv(CONNECT, env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stderr).toBe("mehen: using OAuth client google-oauth-work\n")
    const calls = vault.seen.slice(before)
    expect(`${calls[0]?.path}${calls[0]?.search}`).toBe("/v1/items?kind=oauth-client&provider=google-oauth-client")
    expect(calls[1]?.path).toBe("/v1/connect")
    expect(lastBody()).toMatchObject({ client: "google-oauth-work", slug: "gmail-alex" })
    const asJson = await runJv([...CONNECT, "--json"], env)
    expect(asJson.stderr).toBe("")
    expect(json(asJson).client).toBe("google-oauth-work")
  })

  test("with several matching clients, exits with usage and lists them as choices", async () => {
    await enrolled()
    vault.items.push(googleClient("google-oauth-client"), googleClient("google-oauth-work", "work@example.com"))
    const before = vault.seen.length
    const human = await runJv(CONNECT, env)
    expect(human.code).toBe(EXIT.usage)
    expect(human.stderr).toContain("mehen: Several Gmail OAuth clients exist (google-oauth-client, google-oauth-work); name one with --client.")
    const asJson = await runJv([...CONNECT, "--json"], env)
    expect(asJson.code).toBe(EXIT.usage)
    expect(json(asJson)).toMatchObject({ error: "usage", choices: [{ slug: "google-oauth-client", account: null }, { slug: "google-oauth-work", account: "work@example.com" }] })
    expect(vault.seen.slice(before).every((call) => call.path !== "/v1/connect")).toBe(true)
  })

  test("with no client at all, client_missing (exit 4) carries the exact vault_request arguments and the redirect URI from the vault URL", async () => {
    await enrolled()
    const before = vault.seen.length
    const asJson = await runJv([...CONNECT, "--json"], env)
    expect(asJson.code).toBe(EXIT.human)
    const out = json(asJson) as { error: string; message: string; next: { command: string; say: string; url?: string }; request: Record<string, string>; setup: Record<string, string> }
    expect(out.error).toBe("client_missing")
    expect(out.message).toBe("No Google OAuth client is in the vault yet; a Gmail connection needs one (template google-oauth-client).")
    expect(out.request).toEqual({ kind: "oauth-client", name: "google-oauth-client", provider: "google-oauth-client", reason: "connect Gmail as alex@example.com: triage" })
    expect(out.setup).toEqual({ redirectUri: `${vault.url}/oauth/callback`, docsUrl: "https://console.cloud.google.com/apis/credentials" })
    expect(out.next.command).toBe("mehen request oauth-client --name google-oauth-client --provider google-oauth-client --reason 'connect Gmail as alex@example.com: triage' --home private")
    expect(out.next.url).toBeUndefined()
    expect(vault.seen.slice(before).every((call) => call.path !== "/v1/connect")).toBe(true)

    // The request object is what mehen request (and so vault_request) sends.
    const made = await runJv(["request", out.request.kind as string, "--name", out.request.name as string, "--provider", out.request.provider as string, "--reason", out.request.reason as string, "--json"], env)
    expect(made.code).toBe(EXIT.ok)
    expect(lastBody()).toEqual({ kind: "oauth-client", slug: "google-oauth-client", provider: "google-oauth-client", reason: "connect Gmail as alex@example.com: triage", home: "private" })

    const human = await runJv(CONNECT, env)
    expect(human.code).toBe(EXIT.human)
    const lines = human.stderr.trimEnd().split("\n")
    expect(lines[0]).toBe("mehen: No Google OAuth client is in the vault yet; a Gmail connection needs one (template google-oauth-client).")
    expect(lines[1]).toStartWith("next: Ask the human for a Google OAuth client first")
    expect(lines[2]).toBe("  run:  mehen request oauth-client --name google-oauth-client --provider google-oauth-client --reason 'connect Gmail as alex@example.com: triage' --home private")
    expect(lines[3]).toBe("  or:   mehen connect google-gmail --name gmail-alex --expect alex@example.com --reason triage --request-client --home private   (asks for the client, waits for it, then continues)")
    expect(lines[4]).toBe(`  the human will need: a Google OAuth client (web application) with redirect URI ${vault.url}/oauth/callback`)
    expect(lines[5]).toBe("  docs: https://console.cloud.google.com/apis/credentials")
    expect(human.stdout).toBe("")
  })

  test("--request-client asks the vault for the chained connect, waits for the client intake, then prints the connect ask, in that order", async () => {
    await enrolled()
    chainingConnects()
    vault.sequences.set("intake:int_client", [{ intake: "int_client", status: "open" }, { intake: "int_client", status: "completed", item: googleClient("google-oauth-client") }])
    vault.sequences.set("connect:con_chain", [{ connect: "con_chain", status: "open" }, { connect: "con_chain", status: "completed", item: item("gmail-alex", { kind: "oauth-connection", provider: "google-gmail", account: "alex@example.com", hosts: ["gmail.googleapis.com"] }), account: "alex@example.com", grantedScopes: ["https://www.googleapis.com/auth/gmail.modify"] }])
    const before = vault.seen.length
    const result = await runJv([...CONNECT, "--request-client", "--client-tag", "mail", "--wait", "--json"], { ...env, MEHEN_SESSION: "pi-1" })
    expect(result.code).toBe(EXIT.ok)
    const seen = vault.seen.slice(before).map((c) => `${c.method} ${c.path}${c.search}`)
    expect(seen).toEqual([
      "GET /v1/items?kind=oauth-client&provider=google-oauth-client",
      "POST /v1/connect",
      "GET /v1/intakes/int_client",
      "GET /v1/intakes/int_client?wait=1",
      "GET /v1/connect/con_chain",
      "GET /v1/connect/con_chain?wait=1",
    ])
    expect(JSON.parse(vault.seen[before + 1]?.body ?? "{}")).toEqual({ provider: "google-gmail", slug: "gmail-alex", expect: "alex@example.com", reason: "triage", session: "pi-1", requestClient: true, clientTags: ["mail"], home: "private" })
    const steps = jsonLines(result.stdout) as Record<string, unknown>[]
    expect(steps.map((s) => s.step)).toEqual(["client", "client", "connect", "connect"])
    expect(steps[0]).toMatchObject({ intake: "int_client", url: `${vault.url}/w/mock-space/i/int_client`, ask: { kind: "intake", id: "int_client", what: `Add google-oauth-client (Google OAuth client, redirect URI ${vault.url}/oauth/callback) so the agent can connect Gmail as alex@example.com: triage` }, next: { command: "mehen wait int_client --timeout 60 --json" } })
    expect(steps[1]).toMatchObject({ id: "int_client", kind: "intake", status: "completed", item: { slug: "google-oauth-client" } })
    expect(steps[2]).toMatchObject({ connect: "con_chain", url: `${vault.url}/w/mock-space/c/con_chain`, client: "google-oauth-client", ask: { kind: "connect", id: "con_chain" } })
    expect(steps[3]).toMatchObject({ id: "con_chain", kind: "connect", status: "completed", account: "alex@example.com" })
    expect(await readLedger(vault.slotDir(dir.path), scope())).toEqual([])
  })

  test("--request-client in human output prints the client ask, waits, then the connect ask", async () => {
    await enrolled()
    chainingConnects()
    vault.sequences.set("intake:int_client", [{ intake: "int_client", status: "completed", item: googleClient("google-oauth-client") }])
    const result = await runJv([...CONNECT, "--request-client"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: add a credential")
    expect(lines[1]).toBe(`  open:    ${vault.url}/w/mock-space/i/int_client`)
    expect(lines[4]).toEndWith("; the connection link follows once the client is saved")
    expect(lines[5]).toBe("  then:    mehen keeps waiting (Ctrl-C is safe: mehen wait int_client --timeout 60 --json resumes)")
    expect(lines[6]).toBe("Added google-oauth-client (Google OAuth client, goes to oauth2.googleapis.com).")
    expect(lines[7]).toBe('  then:    mehen connect google-gmail --client google-oauth-client --name <slug> --reason "<why>"')
    expect(lines[8]).toBe("Human needed: connect an account")
    expect(lines[9]).toBe(`  open:    ${vault.url}/w/mock-space/c/con_chain`)
    expect(lines.at(-1)).toBe("  then:    mehen wait con_chain --timeout 60 --json   (or add --wait to this command)")
    expect(result.stderr).toBe("")
  })

  test("--request-client with a client already in the vault is an ordinary connect that picks it", async () => {
    await enrolled()
    chainingConnects()
    vault.items.push(googleClient("google-oauth-client"))
    const result = await runJv([...CONNECT, "--request-client", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(lastBody()).toEqual({ provider: "google-gmail", client: "google-oauth-client", slug: "gmail-alex", expect: "alex@example.com", reason: "triage", home: "private" })
    expect(json(result)).toMatchObject({ connect: "con_chain", client: "google-oauth-client" })
    expect(json(result).step).toBeUndefined()
  })

  test("--new sends fresh; a missing name or reason, or an unknown provider, is a usage error", async () => {
    await enrolled()
    vault.items.push(googleClient("google-oauth-client"))
    expect((await runJv([...CONNECT, "--new", "--json"], env)).code).toBe(EXIT.ok)
    expect(lastBody().fresh).toBe(true)
    expect((await runJv(["connect", "google-gmail", "--name", "gmail-alex"], env)).code).toBe(EXIT.usage)
    expect((await runJv(["connect", "google-gmail", "--reason", "r"], env)).code).toBe(EXIT.usage)
    const unknown = await runJv(["connect", "gmail", "--name", "gmail-alex", "--reason", "r"], env)
    expect(unknown.code).toBe(EXIT.usage)
    expect(unknown.stderr).toContain('Unknown OAuth provider "gmail". Known: google-gmail')
  })
})

test("policy outcome lines report the actual ended window without suggesting a reproposal", async () => {
  const { outcomeLines } = await import("./intake.ts")
  const { plainStyler, plainText } = await import("../tty.ts")
  const result: import("../operations.ts").WaitResult = {
    kind: "policy",
    status: {
      proposal: "pol_narrowed", item: "example-key", status: "approved", bindingCode: "CODE", summary: "Narrowed", expiresAt: "later",
      outcome: { change: { kind: "mode", target: { kind: "item", item: "example-key" }, selector: { device: "dev_x", session: null }, policyMode: "relaxed", scope: { host: "api.example.com", methods: ["GET"], path: "/v1/**", anchorPath: "/v1/data", basis: "unreviewed" }, ttlSeconds: 60, notAfter: null }, override: "pov_actual", grant: null, effectiveUntil: "later", active: false, endedReason: "revoked" },
    },
  }
  const text = outcomeLines(result, plainStyler()).map(plainText).join("\n")
  expect(text).toContain("has ended (revoked); it was granted until later")
  expect(text).toContain("mehen policy show example-key")
  expect(text).not.toContain("propose")
})
