import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { ERROR_HEADER, EXIT } from "@mehen/protocol/api"
import { readLedger } from "../ledger.ts"
import { MOCK_EXPIRES_AT, MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, jsonLines, runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, MEHEN_POLL_INTERVAL_MS: "0", TZ: "UTC" }
  vault.overrides.clear()
  vault.sequences.clear()
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

const SUMMARY = "Put openai-prod into GitHub acme/app, Actions secret OPENAI_API_KEY, using github-pat-ci"
const APPROVAL_LINK = () => `${vault.url}/w/mock-space/a/apr_p1`

// POST /v1/push as the vault answers a new push: approval_required with the
// ask (apps/vault/src/vault/areas/pushes.ts push.ask). Records each body.
function askingForApproval(): Record<string, unknown>[] {
  const bodies: Record<string, unknown>[] = []
  vault.overrides.set("POST /v1/push", (_request, seen) => {
    bodies.push(JSON.parse(seen.body) as Record<string, unknown>)
    return vaultError("approval_required", "This push needs a human's approval.", { approval: "apr_p1", bindingCode: "K7Q2MX", expiresAt: MOCK_EXPIRES_AT, next: { url: APPROVAL_LINK(), command: "mehen wait apr_p1", say: "Send this link to Alex." } })
  })
  return bodies
}

function refusing(code: Parameters<typeof vaultError>[0], message: string, extra: Record<string, unknown> = {}, status = 400): void {
  vault.overrides.set("POST /v1/push", () => Response.json({ error: code, message, ...extra }, { status, headers: { [ERROR_HEADER]: "1" } }))
}

const pushStatus = (push: Record<string, unknown>) => ({ approval: "apr_p1", status: "used", bindingCode: "K7Q2MX", summary: SUMMARY, expiresAt: MOCK_EXPIRES_AT, push: { destination: "github:acme/app/OPENAI_API_KEY", field: "key", version: 3, ...push } })

describe("mehen push: destinations", () => {
  const forms: [string, Record<string, unknown>, string, string][] = [
    ["github:Acme/App/openai_api_key", { provider: "github", owner: "acme", repo: "app", store: "actions", environment: null, name: "OPENAI_API_KEY" }, "github:acme/app/OPENAI_API_KEY", "GitHub acme/app, Actions secret OPENAI_API_KEY"],
    ["github:acme/app/env/Production/OPENAI_API_KEY", { provider: "github", owner: "acme", repo: "app", store: "environment", environment: "production", name: "OPENAI_API_KEY" }, "github:acme/app/env/production/OPENAI_API_KEY", "GitHub acme/app, environment production, Actions secret OPENAI_API_KEY"],
    ["github:acme/app/dependabot/NPM_TOKEN", { provider: "github", owner: "acme", repo: "app", store: "dependabot", environment: null, name: "NPM_TOKEN" }, "github:acme/app/dependabot/NPM_TOKEN", "GitHub acme/app, Dependabot secret NPM_TOKEN"],
    ["vercel:Shop@Acme/production/STRIPE_SECRET_KEY", { provider: "vercel", project: "shop", team: "acme", target: "production", name: "STRIPE_SECRET_KEY" }, "vercel:shop@acme/production/STRIPE_SECRET_KEY", "Vercel shop in team acme, production variable STRIPE_SECRET_KEY"],
    ["vercel:prj_AbC123/preview/stripe_key", { provider: "vercel", project: "prj_AbC123", team: null, target: "preview", name: "stripe_key" }, "vercel:prj_AbC123/preview/stripe_key", "Vercel prj_AbC123, preview variable stripe_key"],
    ["cloudflare:0123456789ABCDEF0123456789abcdef/Mailer/RESEND_API_KEY", { provider: "cloudflare", account: "0123456789abcdef0123456789abcdef", script: "mailer", name: "RESEND_API_KEY" }, "cloudflare:0123456789abcdef0123456789abcdef/mailer/RESEND_API_KEY", "Cloudflare Worker mailer in account 0123456789abcdef0123456789abcdef, secret RESEND_API_KEY"],
  ]
  for (const [text, to, canonical, words] of forms) {
    test(`${text} is sent as its canonical JSON and printed as ${canonical} before sending`, async () => {
      const bodies = askingForApproval()
      const result = await runJv(["push", "openai-prod", "--to", text], env)
      expect(result.code).toBe(EXIT.approval)
      expect(bodies).toEqual([{ item: "openai-prod", to }])
      expect(result.stderr.split("\n")[0]).toBe(`mehen: pushing openai-prod to ${canonical} (${words})`)
      if (text !== canonical) expect(result.stderr).not.toContain(text)
    })
  }

  test("the field, --with and --reason go with it; the canonical form goes to stderr with --json too", async () => {
    const bodies = askingForApproval()
    const result = await runJv(["push", "openai-prod#key", "--to", "github:acme/app/OPENAI_API_KEY", "--with", "github-pat-ci", "--reason", "the evals workflow calls OpenAI", "--json"], env)
    expect(result.code).toBe(EXIT.approval)
    expect(bodies).toEqual([{ item: "openai-prod", field: "key", to: { provider: "github", owner: "acme", repo: "app", store: "actions", environment: null, name: "OPENAI_API_KEY" }, with: "github-pat-ci", reason: "the evals workflow calls OpenAI" }])
    expect(result.stderr).toBe("mehen: pushing openai-prod#key to github:acme/app/OPENAI_API_KEY (GitHub acme/app, Actions secret OPENAI_API_KEY)\n")
  })

  test("a destination the grammar refuses is a usage error and nothing is sent", async () => {
    const bodies = askingForApproval()
    const before = vault.seen.length
    for (const to of ["github:acme/app/GITHUB_TOKEN", "github:acme/app/OPENAI_KEY\u212a", "github:acme/app", "vercel:shop/staging/KEY", "cloudflare:abc/mailer/KEY", "gitlab:acme/app/KEY", "github:acme/../KEY"]) {
      const result = await runJv(["push", "openai-prod", "--to", to, "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "usage", next: { command: "mehen push --help" } })
      expect(String(json(result).message)).toContain("is not a push destination")
    }
    const misuses: [string[], string][] = [
      [["openai-prod"], "Say where it goes with --to <destination>."],
      [["openai-prod", "--to", "github:acme/app/A", "--to", "github:acme/app/B"], "Give one --to per push; run mehen push again for another destination."],
      [["openai-prod#", "--to", "github:acme/app/A"], "Name the field after #, or leave # out to push the credential's main field."],
      [["Not_A_Slug", "--to", "github:acme/app/A"], '"Not_A_Slug" is not a valid item name'],
      [["openai-prod", "--to", "github:acme/app/A", "--with", "x"], '"x" is not a valid credential to push with'],
      [["openai-prod", "--to", "github:acme/app/A", "--timeout", "soon"], "--timeout takes a number of seconds"],
    ]
    for (const [argv, message] of misuses) {
      const result = await runJv(["push", ...argv], env)
      expect(result.code).toBe(EXIT.usage)
      expect(result.stderr).toStartWith(`mehen: ${message}`)
    }
    expect(bodies).toEqual([])
    expect(vault.seen.length).toBe(before)
  })

  test("fly: parses and goes to the vault, whose bad_request is shown as is and exits 2", async () => {
    refusing("bad_request", "Pushing to Fly is not available yet.")
    const result = await runJv(["push", "openai-prod", "--to", "fly:my-app/OPENAI_API_KEY"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(result.stderr.split("\n").slice(0, 2)).toEqual(["mehen: pushing openai-prod to fly:my-app/OPENAI_API_KEY (Fly app my-app, secret OPENAI_API_KEY)", "mehen: Pushing to Fly is not available yet."])
  })
})

describe("mehen push: asking a human", () => {
  test("without --wait it exits 3 with the ask, as mehen fetch does, and records nothing in the ledger", async () => {
    askingForApproval()
    const human = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY"], env)
    expect(human.code).toBe(EXIT.approval)
    expect(human.stdout).toBe("")
    expect(human.stderr).toContain("mehen: This push needs a human's approval.\nnext: Send this link to Alex.\n")
    expect(human.stderr).toContain(APPROVAL_LINK())
    expect(human.stderr).toContain("  then:    mehen wait apr_p1 --timeout 60 --json")
    const asJson = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--json"], env)
    expect(asJson.code).toBe(EXIT.approval)
    expect(json(asJson)).toMatchObject({ error: "approval_required", approval: "apr_p1", bindingCode: "K7Q2MX", next: { url: APPROVAL_LINK(), command: "mehen wait apr_p1" }, ask: { kind: "approval", id: "apr_p1", url: APPROVAL_LINK(), check: { label: "code", value: "K7Q2MX" } } })
    expect(await readLedger(vault.slotDir(dir.path), vault.ledgerScope())).toEqual([])
  })

  test("--wait prints the ask, waits until the push is done and says where it went, exit 0", async () => {
    askingForApproval()
    vault.sequences.set("approval:apr_p1", [{ ...pushStatus({ state: "pending" }), status: "pending" }, pushStatus({ state: "sending" }), pushStatus({ state: "done", outcome: "replaced" })])
    const human = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--wait", "--timeout", "10s"], env)
    expect(human.code).toBe(EXIT.ok)
    const lines = human.stdout.trimEnd().split("\n")
    expect(lines[0]).toBe("Human needed: approve a request")
    expect(human.stdout).toContain(APPROVAL_LINK())
    expect(lines.at(-2)).toBe("  then:    mehen keeps waiting (Ctrl-C is safe: mehen wait apr_p1 --timeout 60 --json resumes)")
    expect(lines.at(-1)).toBe(`Pushed: ${SUMMARY}: replaced (version 3).`)
    expect(human.stderr).toBe("mehen: pushing openai-prod to github:acme/app/OPENAI_API_KEY (GitHub acme/app, Actions secret OPENAI_API_KEY)\n")
  })

  test("--wait --json prints the ask line, then the outcome line, as mehen request --wait --json does", async () => {
    askingForApproval()
    vault.sequences.set("approval:apr_p1", [pushStatus({ state: "done", outcome: "created" })])
    const result = await runJv(["push", "openai-prod#key", "--to", "github:acme/app/OPENAI_API_KEY", "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = jsonLines(result.stdout) as Record<string, unknown>[]
    expect(lines).toHaveLength(2)
    expect(lines[0]).toEqual({ approval: "apr_p1", url: APPROVAL_LINK(), expiresAt: MOCK_EXPIRES_AT, item: "openai-prod", field: "key", destination: "github:acme/app/OPENAI_API_KEY", bindingCode: "K7Q2MX", ask: expect.objectContaining({ kind: "approval", id: "apr_p1", url: APPROVAL_LINK() }), next: { url: APPROVAL_LINK(), command: "mehen wait apr_p1", say: "Send this link to Alex." } })
    expect(lines[1]).toMatchObject({ id: "apr_p1", kind: "approval", status: "used", push: { state: "done", outcome: "created" } })
  })

  test("--wait on a push the provider refuses exits 5 provider_refused with its providerStatus", async () => {
    askingForApproval()
    vault.sequences.set("approval:apr_p1", [pushStatus({ state: "failed", providerStatus: 403 })])
    const result = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--wait", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    const lines = jsonLines(result.stdout) as Record<string, unknown>[]
    expect(lines.at(-1)).toMatchObject({ error: "provider_refused", providerStatus: 403, message: `GitHub refused the push (403): ${SUMMARY}.` })
  })

  test("the same push done in the last ten minutes answers its result, exit 0, and sends nothing again", async () => {
    const result = { push: "psh_1", item: "openai-prod", field: "key", version: 3, destination: "github:acme/app/OPENAI_API_KEY", via: "github-pat-ci", outcome: "replaced", at: "2026-11-06T09:15:00.000Z" }
    vault.overrides.set("POST /v1/push", () => Response.json({ ...result, internal: "never shown" }))
    const human = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--wait"], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toBe("Already put openai-prod into GitHub acme/app, Actions secret OPENAI_API_KEY: replaced at 2026-11-06 09:15.\n")
    const asJson = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--json"], env)
    expect(asJson.code).toBe(EXIT.ok)
    expect(json(asJson)).toEqual(result)
  })
})

describe("mehen push: refusals", () => {
  test("a credential not allowed to leave prints the vault's words and its page's link, exit 5", async () => {
    const page = `${vault.url}/w/mock-space/items/openai-prod`
    refusing("mode_refused", "openai-prod may not be put into other services' secret stores. Allow it on its page.", { next: { url: page, say: "A person allows openai-prod to be put into other services' secret stores on its page." } }, 403)
    const human = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY"], env)
    expect(human.code).toBe(EXIT.refused)
    expect(human.stderr).toContain("mehen: openai-prod may not be put into other services' secret stores. Allow it on its page.\nnext: A person allows openai-prod to be put into other services' secret stores on its page.\n")
    expect(human.stderr).toContain(`  open: ${page}`)
    const asJson = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--json"], env)
    expect(json(asJson)).toMatchObject({ error: "mode_refused", next: { url: page } })
  })

  test("a provider's refusal before anyone is asked exits 5 provider_refused with providerStatus", async () => {
    refusing("provider_refused", "GitHub says acme/app does not exist, or github-pat-ci cannot see it.", { providerStatus: 404 }, 502)
    const result = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(json(result)).toMatchObject({ error: "provider_refused", providerStatus: 404, message: "GitHub says acme/app does not exist, or github-pat-ci cannot see it." })
  })

  test("several credentials could carry it: ambiguous with the choices, exit 2", async () => {
    refusing("ambiguous", "Several GitHub credentials could push this; name one with --with.", { choices: [{ slug: "github-pat-ci", account: "example-bot" }, { slug: "github-pat-me", account: null }] })
    const result = await runJv(["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--json"], env)
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "ambiguous", choices: [{ slug: "github-pat-ci" }, { slug: "github-pat-me" }] })
  })
})
