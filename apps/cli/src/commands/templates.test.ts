import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, TEMPLATES, TEMPLATE_CATEGORIES, connectionPolicy } from "@mehen/protocol/templates"
import { MockVault } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { CliError } from "../errors.ts"
import { goesTo, policySummaryLines, redirectUri, templateSummary, templatesJson } from "./templates.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

describe("mehen templates", () => {
  test("lists every template and OAuth provider id, before enrolment and without touching the vault", async () => {
    const before = vault.seen.length
    const result = await runJv(["templates"], env)
    expect(result.code).toBe(EXIT.ok)
    for (const id of Object.keys(TEMPLATES)) expect(result.stdout).toMatch(new RegExp(`^${id} `, "m"))
    for (const id of Object.keys(OAUTH_PROVIDERS)) expect(result.stdout).toMatch(new RegExp(`^${id} `, "m"))
    expect(result.stdout).toContain("CREDENTIAL TEMPLATES")
    expect(result.stdout).toContain("OAUTH PROVIDERS")
    expect(result.stdout).toContain(`redirect URI ${vault.url}/oauth/callback`)
    expect(vault.seen.length).toBe(before)
  })

  test("lists each template and provider under its category's title, in the categories' order", async () => {
    const result = await runJv(["templates"], env)
    const lines = result.stdout.split("\n")
    const titles = TEMPLATE_CATEGORIES.map((c) => `${c.title}:`)
    const sectionOf = (id: string, from: number): string | undefined => {
      const at = lines.findIndex((l, i) => i >= from && l.startsWith(`${id} `))
      return lines.slice(0, at).reverse().find((l) => titles.includes(l))
    }
    const providersAt = lines.findIndex((l) => l.startsWith("OAUTH PROVIDERS"))
    for (const t of Object.values(TEMPLATES)) expect({ id: t.id, section: sectionOf(t.id, 0) }).toEqual({ id: t.id, section: `${TEMPLATE_CATEGORIES.find((c) => c.id === t.category)?.title}:` })
    for (const p of Object.values(OAUTH_PROVIDERS)) expect({ id: p.id, section: sectionOf(p.id, providersAt) }).toEqual({ id: p.id, section: `${TEMPLATE_CATEGORIES.find((c) => c.id === p.category)?.title}:` })
    const order = lines.slice(0, providersAt).filter((l) => titles.includes(l))
    expect(order).toEqual(titles.filter((t) => order.includes(t)))
    expect(order).toContain("AI models:")
    expect(order).toContain("OAuth clients:")
  })

  test("--json carries every id with its category and policy summary, the categories in order, and the redirect URI", async () => {
    const result = await runJv(["templates", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as {
      categories: { id: string; title: string }[]
      templates: { id: string; category: string; defaultEnvVar: string | null; policySummary: unknown }[]
      oauthProviders: { id: string; category: string; policy: unknown }[]
      redirectUri: string
    }
    expect(out.categories).toEqual([...TEMPLATE_CATEGORIES])
    expect(out.templates.map((t) => t.id)).toEqual(Object.keys(TEMPLATES))
    expect(out.templates.map((t) => t.category)).toEqual(Object.values(TEMPLATES).map((t) => t.category))
    expect(out.oauthProviders.map((p) => p.id)).toEqual(Object.keys(OAUTH_PROVIDERS))
    expect(out.oauthProviders.find((p) => p.id === "google-gmail")?.category).toBe("mail")
    expect(out.templates[0]?.policySummary).toEqual(templateSummary(TEMPLATES.openai?.policy as never))
    expect(out.templates.map((t) => t.defaultEnvVar)).toEqual(Object.values(TEMPLATES).map((t) => t.defaultEnvVar ?? null))
    expect(out.templates.find((t) => t.id === "openai")?.defaultEnvVar).toBe("OPENAI_API_KEY")
    expect(out.templates.find((t) => t.id === "google-oauth-client")?.defaultEnvVar).toBeNull()
    expect(out.redirectUri).toBe(`${vault.url}/oauth/callback`)
  })

  test("the redirect URI follows MEHEN_VAULT_URL, then the enrolled vault, then the default", async () => {
    expect(await redirectUri({ MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: "https://vault.example" })).toBe("https://vault.example/oauth/callback")
    expect(await redirectUri({ MEHEN_CONFIG_DIR: dir.path })).toBe("https://app.mehen.dev/oauth/callback")
    await vault.enrolSoftware(dir.path)
    expect(await redirectUri({ MEHEN_CONFIG_DIR: dir.path })).toBe(`${vault.url}/oauth/callback`)
  })

  test("google-gmail groups its rules into the three lines, from the trusted notes", async () => {
    const result = await runJv(["templates", "google-gmail"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("google-gmail: Gmail (OAuth provider; client template google-oauth-client)")
    expect(result.stdout).toContain(`  redirect URI:      ${vault.url}/oauth/callback`)
    expect(result.stdout).toContain("  default scopes:    gmail.modify")
    expect(result.stdout).toContain("  allowed scopes:    gmail.readonly, gmail.metadata, gmail.labels, gmail.compose, gmail.send, gmail.modify, gmail.insert")
    expect(result.stdout).toContain("  goes to:           gmail.googleapis.com /gmail/v1/**, /upload/gmail/v1/**")
    expect(result.stdout).toContain("  without a human:   reads; creates a draft; changes labels")
    expect(result.stdout).toContain("  needs approval:    sends email as you; puts a message with any sender into the mailbox; permanent deletes; anything else")
    expect(result.stdout).toContain("  refused:           forwarding sends every message elsewhere; delegates give someone else the mailbox; filters can forward or hide mail;")
    const lines = policySummaryLines(templateSummary(connectionPolicy(OAUTH_PROVIDERS["google-gmail"] as never)))
    expect(lines.allowed).toBe("reads; creates a draft; changes labels")
    expect(lines.approve).toEndWith("; anything else")
  })

  test("openai: reads and model calls, anything else needs approval, the admin API is refused", async () => {
    const result = await runJv(["templates", "openai"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("openai: OpenAI API key (api-key template)")
    expect(result.stdout).toContain("  category:          AI models")
    expect(result.stdout).toContain("  without a human:   reads; model calls and the data they use")
    expect(result.stdout).toContain("  needs approval:    anything else")
    expect(result.stdout).toContain("  refused:           admin API")
    expect(result.stdout).toContain("  injection:         Authorization: Bearer {key}")
    expect(result.stdout).toContain("  env variable:      OPENAI_API_KEY")
    expect(result.stdout).not.toContain("redirect URI")
    const asJson = json(await runJv(["templates", "openai", "--json"], env))
    expect(asJson).toMatchObject({ type: "template", id: "openai", kind: "api-key", defaultEnvVar: "OPENAI_API_KEY", policySummary: { allowed: ["reads", "model calls and the data they use"], approve: [], deny: ["admin API"], rest: "approve" } })
  })

  test("an OAuth client template shows the redirect URI and an allow-everything policy reads as anything", async () => {
    const result = await runJv(["templates", "google-oauth-client"], env)
    expect(result.stdout).toContain(`  redirect URI:      ${vault.url}/oauth/callback`)
    expect(result.stdout).toContain("  goes to:           oauth2.googleapis.com (token only)")
    expect(result.stdout).toContain("  without a human:   anything")
    expect(result.stdout).toContain("  needs approval:    nothing")
    expect(json(await runJv(["templates", "google-oauth-client", "--json"], env)).redirectUri).toBe(`${vault.url}/oauth/callback`)
  })

  test("goes to names hosts, methods and paths", () => {
    expect(goesTo(TEMPLATES.linear as never)).toBe("api.linear.app POST /graphql")
    expect(goesTo(TEMPLATES["cloudflare-api-token"] as never)).toBe("api.cloudflare.com /client/v4/**")
    expect(goesTo(TEMPLATES["microsoft-oauth-client"] as never)).toBe("login.microsoftonline.com (token only)")
  })

  test("an unknown id exits 1 and points back at the list", async () => {
    const result = await runJv(["templates", "openia", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "not_found", next: { command: "mehen templates" } })
  })

  test("an unknown id that starts several ids, or is one of their words, names them", async () => {
    const github = await runJv(["templates", "github", "--json"], env)
    expect(github.code).toBe(EXIT.error)
    expect(json(github)).toEqual({ error: "not_found", message: 'No template or OAuth provider is called "github".', next: { say: "Did you mean github-pat, github-oauth-client or github-oauth?" } })
    const gmail = await runJv(["templates", "gmail", "--json"], env)
    expect(json(gmail).next).toEqual({ command: "mehen templates google-gmail --json", say: "Did you mean google-gmail?" })
    const human = await runJv(["templates", "gmail"], env)
    expect(human.code).toBe(EXIT.error)
    expect(human.stderr).toContain("Did you mean google-gmail?")
  })

  test("vault_templates gets the same ids for a near miss, with no mehen command", () => {
    const nextFor = (id: string) => {
      try {
        templatesJson("https://vault.example/oauth/callback", id)
      } catch (error) {
        if (error instanceof CliError) return { code: error.code, next: error.next }
      }
      throw new Error(`templatesJson did not refuse ${id}`)
    }
    expect(nextFor("github")).toEqual({ code: "not_found", next: { say: "Did you mean github-pat, github-oauth-client or github-oauth?" } })
    expect(nextFor("gmail")).toEqual({ code: "not_found", next: { say: "Did you mean google-gmail?" } })
  })

  test("the whole templates listing and every detail page leave the process with no escape or hidden character", async () => {
    const list = await runJv(["templates"], env)
    expect(list.stdout).not.toMatch(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/)
    for (const id of [...Object.keys(TEMPLATES), ...Object.keys(OAUTH_PROVIDERS)]) {
      const detail = await runJv(["templates", id], env)
      expect(detail.code).toBe(EXIT.ok)
      expect(detail.stdout).not.toMatch(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/)
    }
    // One process per template, in turn: on a busy runner that passes the default 5 s.
  }, 30_000)

  test("hidden characters in a rule note are spelled out before they reach the terminal", () => {
    const lines = policySummaryLines({ allowed: ["re\u200bads"], approve: ["send\u202e"], deny: [], rest: "deny" })
    expect(lines.allowed).toBe("re[ZWSP U+200B]ads")
    expect(lines.approve).toBe("send[RLO U+202E]")
    expect(lines.deny).toBe("anything else")
    expect(policySummaryLines({ allowed: [], approve: [], deny: [], rest: "deny" })).toEqual({ allowed: "nothing", approve: "nothing", deny: "anything" })
  })
})
