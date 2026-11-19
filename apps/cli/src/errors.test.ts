import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { ERROR_CODES, EXIT, EXIT_FOR_ERROR, LOCAL_ERROR_CODES } from "@mehen/protocol/api"
import { type CliError, DEFAULT_NEXT, LOCAL_EXIT, exitCodeFor, toCliError } from "./errors.ts"
import { readApiError } from "./http-client.ts"
import { mandateCapped } from "./mandate-operations.ts"
import { MockVault, vaultError } from "./testing/mock-vault.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"
import { type VaultApi, VaultApiError } from "./vault-api.ts"

describe("every error names a next step", () => {
  test("every vault error code has a default next with a sentence, and commands only from mehen", () => {
    for (const code of ERROR_CODES) {
      const next = DEFAULT_NEXT[code]
      expect(next.say.length).toBeGreaterThan(10)
      expect(next.url).toBeUndefined()
      if (next.command !== undefined) expect(next.command).toMatch(/^mehen [a-z]+( --help)?$/)
    }
  })

  test("a vault refusal without next gets the default for its code; one with next keeps the vault's", () => {
    const bare = toCliError(new VaultApiError(403, { error: "policy_denied", message: "Policy denies DELETE here." }))
    expect(bare.next).toEqual(DEFAULT_NEXT.policy_denied)
    const own = { command: "mehen ls", say: "There is no credential called x." }
    expect(toCliError(new VaultApiError(404, { error: "not_found", message: "No x.", next: own })).next).toEqual(own)
  })

  test("a capped mandate stays off an approval's error unless the caps are said in words, as mehen fetch and vault_fetch do", async () => {
    const held = new VaultApiError(403, { error: "approval_required", message: "This request needs a human's approval.", approval: "apr_1", mandate: { id: "mdt_live", capped: ["send"] } })
    const plain = toCliError(held)
    expect(plain.extras).toEqual({ approval: "apr_1" })
    const api: VaultApi = { request: async () => { throw new Error("unreadable") }, relay: async () => { throw new Error("unexpected relay") } }
    const said = (await mandateCapped(api, held)) as CliError
    expect(said.message).toBe("This request needs a human's approval. This machine's mandate has used today's sends.")
    expect(said.extras).toEqual({ approval: "apr_1", mandate: { id: "mdt_live", capped: ["send"] } })
  })

  test("an outdated CLI refusal exits 1 and says to run mehen update; the vault's own next wins", () => {
    expect(exitCodeFor("cli_outdated")).toBe(EXIT.error)
    expect(DEFAULT_NEXT.cli_outdated).toEqual({ command: "mehen update", say: "This machine's mehen is older than the vault supports; update it, then run the command again." })
    expect(toCliError(new VaultApiError(426, { error: "cli_outdated", message: "Too old." })).next).toEqual(DEFAULT_NEXT.cli_outdated)
    const own = { command: "mehen update --json", say: "Update mehen on this machine, then run the command again." }
    expect(toCliError(new VaultApiError(426, { error: "cli_outdated", message: "Too old.", next: own })).next).toEqual(own)
  })

  test("an unexpected failure inside mehen says to run mehen doctor", () => {
    expect(toCliError(new TypeError("boom")).next).toMatchObject({ command: "mehen doctor" })
  })

  test("exit codes follow the one table, local codes included", () => {
    for (const code of ERROR_CODES) expect(exitCodeFor(code)).toBe(EXIT_FOR_ERROR[code])
    for (const [code, exit] of Object.entries(LOCAL_EXIT)) expect(exitCodeFor(code as keyof typeof LOCAL_EXIT)).toBe(exit)
    expect(exitCodeFor("network")).toBe(EXIT.transient)
  })

  test("mehen fill's own codes exit as the design says, and none is a vault code", () => {
    const fill = { cdp_unreachable: EXIT.transient, page_changed: EXIT.transient, cdp_refused: EXIT.usage, target_ambiguous: EXIT.usage, field_ambiguous: EXIT.usage, field_not_found: EXIT.error, not_submitted: EXIT.error, field_kind_mismatch: EXIT.refused, field_hidden: EXIT.refused, frame_origin_mismatch: EXIT.refused }
    for (const [code, exit] of Object.entries(fill)) {
      expect({ code, exit: exitCodeFor(code as keyof typeof LOCAL_EXIT) }).toEqual({ code, exit })
      expect(ERROR_CODES).not.toContain(code)
    }
    expect(ERROR_CODES).toContain("origin_mismatch")
  })

  test("the frozen workspace selection codes are local, exit 2 and never a vault code", () => {
    expect(LOCAL_ERROR_CODES).toEqual(["pin_outdated", "workspace_unbound", "workspace_mismatch", "workspace_unknown", "context_ambiguous", "workspace_not_allowed", "config_dir_retired"])
    for (const code of LOCAL_ERROR_CODES) {
      expect(exitCodeFor(code)).toBe(EXIT.usage)
      expect(ERROR_CODES).not.toContain(code)
      expect(Object.hasOwn(DEFAULT_NEXT, code)).toBe(false)
    }
  })

  test("provider_refused keeps the provider's HTTP status as providerStatus, exits 5 and is the only code that carries it", async () => {
    expect(exitCodeFor("provider_refused")).toBe(EXIT.refused)
    const refused = await readApiError(Response.json({ error: "provider_refused", message: "github-pat-ci may not write secrets in acme/app.", providerStatus: 403 }, { status: 502 }))
    expect(refused.body.providerStatus).toBe(403)
    const error = toCliError(refused)
    expect(error.extras.providerStatus).toBe(403)
    expect(error.next).toEqual(DEFAULT_NEXT.provider_refused)
    for (const providerStatus of ["403", 4.5, 99, 600]) expect((await readApiError(Response.json({ error: "provider_refused", message: "x", providerStatus }, { status: 502 }))).body).not.toHaveProperty("providerStatus")
    expect((await readApiError(Response.json({ error: "upstream_failed", message: "x", providerStatus: 403 }, { status: 502 }))).body).not.toHaveProperty("providerStatus")
  })

  test("a vault that sends a local code is read as internal, never as a local refusal", async () => {
    for (const code of LOCAL_ERROR_CODES) {
      const read = await readApiError(Response.json({ error: code, message: "spoofed" }, { status: 400 }))
      expect(read.body.error).toBe("internal")
      expect(toCliError(read).code).toBe("internal")
    }
  })
})

describe("through mehen", () => {
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
    vault.overrides.clear()
    await vault.enrolSoftware(dir.path)
  })
  afterEach(async () => dir.remove())

  test("a refusal the vault sent without next prints the default next, in --json and for a human, with the table's exit code", async () => {
    vault.overrides.set("GET /v1/items/openai-personal", () => vaultError("forbidden", "This device's scope does not cover that item."))
    const json = await runJv(["show", "openai-personal", "--json"], env)
    expect(json.code).toBe(EXIT.refused)
    expect(JSON.parse(json.stdout)).toEqual({ error: "forbidden", message: "This device's scope does not cover that item.", next: DEFAULT_NEXT.forbidden })
    const human = await runJv(["show", "openai-personal"], env)
    expect(human.stderr).toContain(`next: ${DEFAULT_NEXT.forbidden.say}`)
    expect(human.stderr).toContain("  run:  mehen status")
  })
})

test("policy settlement codes are local with unchanged terminal exits", () => {
  expect(exitCodeFor("stale")).toBe(5)
  expect(exitCodeFor("superseded")).toBe(5)
  expect(exitCodeFor("denied")).toBe(5)
  expect(exitCodeFor("expired")).toBe(1)
  expect(exitCodeFor("cancelled")).toBe(1)
  expect(ERROR_CODES).not.toContain("stale")
  expect(ERROR_CODES).not.toContain("superseded")
  expect(ERROR_CODES).not.toContain("revoked")
})
