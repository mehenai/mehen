import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync } from "node:fs"
import { rm } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { type AskUrl, approvalAsk, askUrl } from "../ask.ts"
import { readConfig } from "../config.ts"
import { pendingSlotPath } from "../home.ts"
import { addLedgerEntry } from "../ledger.ts"
import { activeLockPath, withSlotLocks } from "../slot-lock.ts"
import { mandateOpenProposal, mandateView } from "../testing/mandate-fixtures.ts"
import { MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { revokeSlot, status, statusCommand } from "./device.ts"

const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }

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
  vault.sequences.clear()
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
  vault.meFingerprint = true
  vault.workspace = { ...MOCK_WORKSPACE }
  vault.owner = { ...MOCK_OWNER }
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

async function enrolled(): Promise<string> {
  return vault.enrolSoftware(dir.path)
}

describe("identity", () => {
  test("not enrolled: exit 6 and next says mehen enrol", async () => {
    const result = await runJv(["ls", "--json"], env)
    expect(result.code).toBe(EXIT.identity)
    expect(json(result)).toMatchObject({ error: "unauthenticated", next: { command: "mehen enrol --workspace <slug> --json" } })
  })

  // Plain status spans the allowed set and exits 0: a
  // failing check is reported in its entry, never deleted. With
  // --workspace it is one slot's status, with the exit codes as before.
  test("status before enrolment names the default vault and respects MEHEN_VAULT_URL; --workspace with nothing enrolled is workspace_unknown", async () => {
    const defaults = await runJv(["status", "--json"], { ...env, MEHEN_VAULT_URL: "" })
    expect(defaults.code).toBe(EXIT.ok)
    expect(json(defaults)).toMatchObject({ home: dir.path, allowed: null, workspaces: [], selected: null, next: { command: "mehen enrol --workspace <slug> --json" } })
    expect((await runJv(["status"], { ...env, MEHEN_VAULT_URL: "" })).stdout).toContain("This machine is not enrolled with the vault at https://app.mehen.dev yet.")
    expect((await runJv(["status"], env)).stdout).toContain(`This machine is not enrolled with the vault at ${vault.url} yet.`)
    const named = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(named.code).toBe(EXIT.usage)
    expect(json(named)).toMatchObject({ error: "workspace_unknown", next: { command: "mehen enrol --workspace mock-space" } })
    // The help says the same exit code the command gives.
    expect(statusCommand.notes?.join("\n")).toContain("a workspace this machine is not enrolled in is exit 2 (workspace_unknown)")
  })

  test("a revoked device exits 6 with --workspace; plain status reports it in the entry's check and deletes nothing", async () => {
    const device = await enrolled()
    const record = vault.devices.get(device)
    if (record) record.revoked = true
    const result = await runJv(["status", "--workspace", "mock-space"], env)
    expect(result.code).toBe(EXIT.identity)
    expect(result.stderr).toContain("revoked")
    const all = await runJv(["status", "--json"], env)
    expect(all.code).toBe(EXIT.ok)
    expect(json(all)).toMatchObject({ workspaces: [{ state: "active", slot: vault.slotDir(dir.path), device, check: { ok: false, error: "device_revoked" } }] })
    expect(existsSync(join(vault.slotDir(dir.path), "config.json"))).toBe(true)
    expect(existsSync(join(vault.slotDir(dir.path), "device-key.json"))).toBe(true)
  })

  test("a group-readable device key is refused before any request", async () => {
    await enrolled()
    await Bun.$`chmod 644 ${join(vault.slotDir(dir.path), "device-key.json")}`
    const before = vault.seen.length
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(result.code).toBe(EXIT.identity)
    expect(json(result)).toMatchObject({ error: "key_insecure" })
    const all = await runJv(["status", "--json"], env)
    expect(json(all)).toMatchObject({ workspaces: [{ state: "corrupt", reason: "key_insecure", slot: vault.slotDir(dir.path) }] })
    expect(vault.seen.length).toBe(before)
  })

  test("an unreachable vault exits 7 with --workspace, and is the entry's network check otherwise", async () => {
    await vault.enrolSoftware(dir.path, { config: { vault: "http://127.0.0.1:1" } })
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], { ...env, MEHEN_VAULT_URL: "http://127.0.0.1:1" })
    expect(result.code).toBe(EXIT.transient)
    expect(json(result)).toMatchObject({ error: "network" })
    const all = await runJv(["status", "--json"], { ...env, MEHEN_VAULT_URL: "http://127.0.0.1:1" })
    expect(all.code).toBe(EXIT.ok)
    expect(json(all)).toMatchObject({ workspaces: [{ state: "active", check: { ok: false, error: "network" } }] })
  })

  test("MEHEN_VAULT_URL naming another origin than the enrolment refuses before any signature (workspace_mismatch, exit 2)", async () => {
    await enrolled()
    const before = vault.seen.length
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], { ...env, MEHEN_VAULT_URL: "https://other.example" })
    expect(result.code).toBe(EXIT.usage)
    expect(json(result)).toMatchObject({ error: "workspace_mismatch", message: `MEHEN_VAULT_URL is https://other.example, but this context is enrolled with ${vault.url}.` })
    const all = await runJv(["status", "--json"], { ...env, MEHEN_VAULT_URL: "https://other.example" })
    expect(all.code).toBe(EXIT.ok)
    expect(json(all)).toMatchObject({ workspaces: [{ state: "active", check: { ok: false, error: "workspace_mismatch" } }] })
    expect(vault.seen.length).toBe(before)
    // Unset, the enrolled origin is used as before.
    expect((await runJv(["status", "--json", "--workspace", "mock-space"], { MEHEN_CONFIG_DIR: dir.path })).code).toBe(EXIT.ok)
  })

  test("a key scope naming another origin or workspace refuses before any signature", async () => {
    await enrolled()
    const scopePath = join(vault.slotDir(dir.path), "device-key.scope.json")
    for (const scope of [{ vault: "https://other.example", tenant: MOCK_TENANT }, { vault: vault.url, tenant: "tn_other000000001" }]) {
      await Bun.write(scopePath, `${JSON.stringify(scope)}\n`)
      const before = vault.seen.length
      const result = await runJv(["status", "--json", "--workspace", "mock-space"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "workspace_mismatch" })
      expect(json(await runJv(["status", "--json"], env))).toMatchObject({ workspaces: [{ state: "corrupt", reason: "scope_mismatch" }] })
      expect(vault.seen.length).toBe(before)
    }
  })

  test("an invalid MEHEN_SESSION is a usage error, spanning or not", async () => {
    await enrolled()
    expect((await runJv(["status"], { ...env, MEHEN_SESSION: "has spaces" })).code).toBe(EXIT.usage)
    expect((await runJv(["status", "--workspace", "mock-space"], { ...env, MEHEN_SESSION: "has spaces" })).code).toBe(EXIT.usage)
  })
})

describe("mehen status and mehen whoami", () => {
  const fingerprint = "ZLSQ 8ZY0 FNHK WLS5"

  test("prints the fingerprint stored at enrolment, the session label and the pending count", async () => {
    const device = await vault.enrolSoftware(dir.path, { fingerprint })
    await addLedgerEntry(vault.slotDir(dir.path), { vaultUrl: vault.url, workspace: MOCK_TENANT, device, workspaceSlug: "mock-space" }, {
      ask: approvalAsk({ id: "apr_1", url: (askUrl(`${vault.url}/w/mock-space/a/apr_1`, vault.askVault()) as { url: AskUrl }).url, summary: "Send", bindingCode: "K7Q2MX", expiresAt: new Date(Date.now() + 60_000).toISOString(), requestedBy: { device: "d", session: null } }),
    })
    const result = await runJv(["status"], { ...env, MEHEN_SESSION: "pi-4f2a" })
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.trimEnd().split("\n")
    expect(lines[0]).toMatch(/^test-machine \(dev_mock\d+, software key\) in Mock Space \(mock-space\) at http:\/\/127\.0\.0\.1:\d+, owned by Test Owner$/)
    expect(lines[1]).toBe(`  workspace id:    ${MOCK_TENANT}`)
    expect(lines[2]).toBe(`  slot:            ${vault.slotDir(dir.path)}`)
    expect(lines[3]).toBe(`  key fingerprint: ${fingerprint}`)
    expect(lines[4]).toBe("  session:         pi-4f2a (MEHEN_SESSION)")
    expect(lines[5]).toBe("  items:           all")
    expect(lines[6]).toBe("  projects:        all")
    expect(lines[7]).toBe("  environments:    unprotected")
    expect(lines[8]).toBe("  modes:           relay, placeholder")
    expect(lines[9]).toBe("  private:         no (ask with --home project or workspace)")
    expect(lines[10]).toBe("  pending:         1 ask waiting for a human (mehen pending)")
    expect(result.stdout).not.toMatch(/\u001b\[/)
  })

  test("status carries this machine's live mandate and its waiting proposals, best effort: any refusal leaves both out and never fails status", async () => {
    await enrolled()
    const live = mandateView({ classes: ["change", "read", "send"], caps: { read: 5000, change: 200, send: 50, delete: 0 }, today: { read: 9, change: 3, send: 1, delete: 0 }, expiresAt: "2030-02-06T12:00:00.000Z" })
    vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [live, mandateView({ id: "mdt_old", state: "expired" })], proposals: [mandateOpenProposal(vault.url)] }))
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(json(result)).toMatchObject({ mandate: { id: "mdt_live", state: "active", classes: ["change", "read", "send"], today: live.today, caps: live.caps, expiresAt: live.expiresAt }, mandateProposals: 1 })
    expect(Object.keys(json(result).mandate as object).sort()).toEqual(["caps", "classes", "expiresAt", "id", "state", "today"])
    const lines = (await runJv(["status"], { ...env, TZ: "Etc/UTC" })).stdout.split("\n")
    expect(lines).toContain("  mandate:         mdt_live: active, change 3/200, send 1/50, ends 6 Feb")
    expect(lines).toContain("  proposals:       1 proposal waiting for its signer (mehen mandate ls)")
    vault.overrides.set("GET /v1/mandates", () => Response.json({ mandates: [mandateView({ state: "stopped", endedReason: "stopped" })], proposals: [] }))
    const none = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(json(none)).toMatchObject({ mandate: null, mandateProposals: 0 })
    expect((await runJv(["status"], env)).stdout).toContain("  mandate:         none\n")
    for (const answer of [() => vaultError("not_found", "No such route."), () => vaultError("forbidden", "Only a machine can do that."), () => new Response("not json", { status: 200 })]) {
      vault.overrides.set("GET /v1/mandates", answer)
      const refused = await runJv(["status", "--json", "--workspace", "mock-space"], env)
      expect(refused.code).toBe(EXIT.ok)
      expect(json(refused)).not.toHaveProperty("mandate")
      expect(json(refused)).not.toHaveProperty("mandateProposals")
      expect((await runJv(["status"], env)).stdout).not.toContain("mandate:")
    }
  })

  test("status gives up on a mandate read slower than 2 seconds, leaves both fields out and still answers", async () => {
    await enrolled()
    vault.overrides.set("GET /v1/mandates", () => new Promise((resolve) => setTimeout(() => resolve(Response.json({ mandates: [mandateView()], proposals: [] })), 6000)))
    const started = Date.now()
    const slow = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(slow.code).toBe(EXIT.ok)
    expect(Date.now() - started).toBeLessThan(5000)
    expect(json(slow)).toMatchObject({ device: expect.any(String) })
    expect(json(slow)).not.toHaveProperty("mandate")
    expect(json(slow)).not.toHaveProperty("mandateProposals")
  }, 15000)

  test("the private line says yes when the machine may use its owner's private credentials, and is left out when the vault does not say", async () => {
    await enrolled()
    const me = (scope: Record<string, unknown>) => (_request: Request, seen: { claims: { dev: string } }) =>
      Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], ...scope }, frozen: false, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER })
    vault.overrides.set("GET /v1/me", me({ privateCredentials: true }))
    const ticked = (await runJv(["status"], env)).stdout.split("\n")
    expect(ticked[ticked.indexOf("  modes:           relay") + 1]).toBe("  private:         yes")
    vault.overrides.set("GET /v1/me", me({}))
    expect((await runJv(["status"], env)).stdout).not.toContain("  private:")
  })

  // A 0.3.18 machine may be given fill (ladder F1): its status reads the
  // six modes, as a member's machine page lists them, and revokes nothing.
  test("a machine given fill shows it among its modes, plain and --json", async () => {
    await enrolled()
    const modes = ["relay", "sign", "mint", "placeholder", "fill", "lease"]
    vault.overrides.set("GET /v1/me", (_request, seen) => Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes, privateCredentials: false }, frozen: false, workspace: MOCK_WORKSPACE, owner: MOCK_OWNER }))
    const plain = await runJv(["status", "--workspace", "mock-space"], env)
    expect(plain.code).toBe(EXIT.ok)
    expect(plain.stdout).toContain(`  modes:           ${modes.join(", ")}`)
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(result.code).toBe(EXIT.ok)
    expect((json(result).scope as { modes: string[] }).modes).toEqual(modes)
    expect(vault.seen.filter((c) => c.path === "/v1/devices/self/revoke")).toEqual([])
  })

  test("--workspace --json is one slot's status: fingerprint, session and pending, with the slot", async () => {
    const device = await vault.enrolSoftware(dir.path, { fingerprint })
    const result = await runJv(["status", "--json", "--workspace", "mock-space"], { ...env, MEHEN_SESSION: "pi-4f2a" })
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({
      vault: vault.url,
      tenant: MOCK_TENANT,
      workspace: MOCK_WORKSPACE,
      owner: MOCK_OWNER,
      slot: vault.slotDir(dir.path),
      device,
      name: "test-machine",
      backend: "software",
      fingerprint,
      fingerprintFrom: "enrolment",
      session: "pi-4f2a",
      frozen: false,
      scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "placeholder"], privateCredentials: false },
      pending: 0,
      policyState: null,
    })
  })

  // Status only observes. It shows the slug, name and owner the
  // vault authenticates and writes nothing; the recorded ones stay, and a
  // label whose id is not this slot's is never shown. (The MCP server's
  // vault_status keeps the refresh its latch needs.)
  test("status shows the authenticated slug, name and owner and writes nothing; the recorded ones stay; the id never changes from a label", async () => {
    await vault.enrolSoftware(dir.path, { config: { workspaceSlug: "old-slug", workspaceName: "Old Name" } })
    const recorded = await Bun.file(join(vault.slotDir(dir.path), "config.json")).text()
    vault.workspace = { id: MOCK_TENANT, slug: "renamed", name: "Renamed Space" }
    vault.owner = { kind: "team", team: "team_ci", name: "ci" }
    const result = await runJv(["status", "--json", "--workspace", MOCK_TENANT], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ workspace: { id: MOCK_TENANT, slug: "renamed", name: "Renamed Space" }, owner: { kind: "team", team: "team_ci", name: "ci" } })
    expect((await runJv(["status"], env)).stdout).toContain("in Renamed Space (renamed) at")
    expect((await runJv(["status"], env)).stdout).toContain(", owned by ci (team)")
    expect(await Bun.file(join(vault.slotDir(dir.path), "config.json")).text()).toBe(recorded)
    // The selector still answers to the recorded slug.
    expect((await runJv(["status", "--json", "--workspace", "old-slug"], env)).code).toBe(EXIT.ok)
    // A workspace ref whose id is not this context's is never shown.
    vault.overrides.set("GET /v1/me", (_request, seen) => Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false }, frozen: false, workspace: { id: "tn_other000000001", slug: "hijack", name: "Hijack" } }))
    expect(json(await runJv(["status", "--json", "--workspace", MOCK_TENANT], env))).toMatchObject({ tenant: MOCK_TENANT, workspace: { id: MOCK_TENANT, slug: "old-slug", name: "Old Name" } })
    expect(await Bun.file(join(vault.slotDir(dir.path), "config.json")).text()).toBe(recorded)
  })

  test("vault_status's refresh records the machine's name as the vault now has it; mehen status writes nothing", async () => {
    await vault.enrolSoftware(dir.path, { config: { name: "old-name" } })
    const slot = vault.slotDir(dir.path)
    await runJv(["status", "--json"], env)
    expect(await readConfig(slot)).toMatchObject({ name: "old-name" })
    await status({ ...env, MEHEN_WORKSPACE: MOCK_TENANT })
    expect(await readConfig(slot)).toMatchObject({ name: "test-machine" })
  })

  test("a config written before mehen recorded the fingerprint gets it from the vault (the enclave key on sam-mac-mini)", async () => {
    const device = await enrolled()
    const jwk = vault.devices.get(device)?.jwk
    if (!jwk) throw new Error("mock device missing")
    const expected = fingerprintOf(await jwkThumbprint(jwk))
    const result = await runJv(["status", "--json", "--workspace", MOCK_TENANT], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ fingerprint: expected, fingerprintFrom: "vault" })
    expect((await runJv(["status"], env)).stdout).toContain(`  key fingerprint: ${expected} (as the vault holds it; this enrolment did not record it)`)
  })

  test("the fingerprint computed at enrolment wins over the vault's, and a malformed one from the vault is ignored", async () => {
    await vault.enrolSoftware(dir.path, { fingerprint })
    expect(json(await runJv(["status", "--json", "--workspace", MOCK_TENANT], env))).toMatchObject({ fingerprint, fingerprintFrom: "enrolment" })
    await rm(join(vault.slotDir(dir.path), "config.json"))
    await vault.enrolSoftware(dir.path)
    vault.overrides.set("GET /v1/me", (_request, seen) =>
      Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] }, frozen: false, fingerprint: "\u001b[31mnot one" }),
    )
    try {
      expect(json(await runJv(["status", "--json", "--workspace", MOCK_TENANT], env))).toMatchObject({ fingerprint: null, fingerprintFrom: null })
    } finally {
      vault.overrides.clear()
    }
  })

  test("neither the vault nor the config knows the fingerprint: it says so instead of guessing, and no session reads as none", async () => {
    await enrolled()
    vault.meFingerprint = false
    try {
      const result = await runJv(["status"], env)
      expect(result.stdout).toContain("  key fingerprint: unknown (the vault did not say")
      expect(result.stdout).toContain("  session:         none")
      expect(result.stdout).toContain("  pending:         nothing waiting for a human")
      expect(json(await runJv(["status", "--json", "--workspace", MOCK_TENANT], env))).toMatchObject({ fingerprint: null, fingerprintFrom: null, session: null, pending: 0 })
    } finally {
      vault.meFingerprint = true
    }
  })

  test("whoami is the same command under another name", async () => {
    await vault.enrolSoftware(dir.path, { fingerprint })
    const status = await runJv(["status", "--json"], env)
    const whoami = await runJv(["whoami", "--json"], env)
    expect(whoami.code).toBe(EXIT.ok)
    expect(json(whoami)).toEqual(json(status))
    const help = await runJv(["whoami", "--help"], env)
    expect(help.stdout).toContain("usage: mehen whoami")
    expect(help.stdout).toContain("same as mehen status")
    expect((await runJv(["--help"], env)).stdout).toMatch(/^ {2}whoami\s+same as mehen status$/m)
  })

  test("hidden characters and escape sequences in what the vault or the config says are spelled out, in every status field", async () => {
    await vault.enrolSoftware(dir.path, { fingerprint: "ZLSQ\u200b 8ZY0\u001b[2K FNHK WLS5" })
    vault.overrides.set("GET /v1/me", () =>
      Response.json({
        tenant: "ten_\u202emock",
        device: "dev_\u001b[31mred",
        name: "test\u001b]0;title\u0007machine\uFFFE[31m",
        scope: { tags: ["ai\u200b"], projects: ["prj\u001b[A"], maxEnvironment: "unprotected\u2066", modes: ["relay\u001b[2J"] },
        frozen: false,
      }),
    )
    try {
      const result = await runJv(["status"], env)
      expect(result.code).toBe(EXIT.ok)
      expect(result.stdout).not.toContain("\u001b")
      expect(result.stdout).not.toMatch(/[\u200b\u202e\u2066]/)
      expect(result.stdout).toContain("test\\u001B]0;title\\u0007machine[NONCHAR U+FFFE][31m (dev_\\u001B[31mred, software key) in Mock Space (mock-space) at")
      expect(result.stdout).toContain("workspace id:    ten_[RLO U+202E]mock")
      expect(result.stdout).not.toContain("\uFFFE")
      expect(result.stdout).toContain("key fingerprint: ZLSQ[ZWSP U+200B] 8ZY0\\u001B[2K FNHK WLS5")
      expect(result.stdout).toContain("items:           tagged ai[ZWSP U+200B]")
      expect(result.stdout).toContain("projects:        prj\\u001B[A")
      expect(result.stdout).toContain("environments:    unprotected[LRI U+2066]")
      expect(result.stdout).toContain("modes:           relay\\u001B[2J")
    } finally {
      vault.overrides.clear()
    }
  })

  test("a frozen workspace is still spelled out in words", async () => {
    await enrolled()
    vault.frozen = true
    try {
      const result = await runJv(["status"], env)
      expect(result.stdout).toContain("The workspace is FROZEN: every use is refused until a human unfreezes it in the vault.")
    } finally {
      vault.frozen = false
    }
  })
})

// The shape of a JSON value: every key, the type of every leaf, the first
// element of every array; equal shapes mean a consumer reading one reads
// the other.
function shapeOf(value: unknown): unknown {
  if (value === null) return "null"
  if (Array.isArray(value)) return value.length ? [shapeOf(value[0])] : []
  if (typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, shapeOf(v)]))
  return typeof value
}

describe("mehen status across the allowed set", () => {
  const fingerprint = "ZLSQ 8ZY0 FNHK WLS5"

  test("an active and a pending slot: StatusAll in the shape of the shared fixture, status-all.json, that a managed harness reads", async () => {
    const env2 = { ...env, MEHEN_SESSION: "pi-4f2a", MEHEN_WORKSPACES: "mock-space,personal" }
    const device = await vault.enrolSoftware(dir.path, { fingerprint })
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env2)
    expect(enrol.code).toBe(EXIT.ok)
    const enrolment = (json(enrol) as { enrolment: string }).enrolment
    const result = await runJv(["status", "--json"], env2)
    expect(result.code).toBe(EXIT.ok)
    const all = json(result) as { workspaces: { state: string }[] }
    expect(all).toMatchObject({
      home: dir.path,
      allowed: ["mock-space", "personal"],
      selected: vault.slotDir(dir.path),
      next: null,
      workspaces: [
        { state: "active", slot: vault.slotDir(dir.path), origin: vault.url, workspace: MOCK_WORKSPACE, device, check: { ok: true, status: { device, slot: vault.slotDir(dir.path), session: "pi-4f2a" } } },
        { state: "pending", slot: pendingSlotPath(dir.path, vault.url, "personal"), origin: vault.url, intent: { workspace: "personal", team: null }, enrolment, legacy: false, claimed: false, ask: { kind: "enrol", id: enrolment, intent: { workspace: "personal", team: null }, context: { origin: vault.url, workspace: null, device: null } } },
      ],
      cli: { installed: null, previous: null, highestSeen: null, holdBelow: null, pending: null, check: null, vault: {}, lastUpdate: null },
    })
    const fixture = JSON.parse(await Bun.file(join(import.meta.dir, "..", "mcp", "fixtures", "status-all.json")).text()) as { workspaces: { state: string }[]; cli: Record<string, unknown> }
    expect(fixture.workspaces.map((w) => w.state)).toEqual(["active", "pending"])
    // Each entry on its own: shapeOf looks at an array's first
    // element only, so the pending entry is compared by itself.
    expect(all.workspaces.map(shapeOf)).toEqual(fixture.workspaces.map(shapeOf))
    const PENDING_KEYS = ["ask", "backend", "claimed", "enrolment", "expiresAt", "fingerprint", "hardExpiresAt", "intent", "legacy", "origin", "renewals", "slot", "startedAt", "state"]
    const ASK_KEYS = ["account", "check", "claimed", "context", "expiresAt", "id", "intent", "kind", "requestedBy", "title", "url", "wait", "what"]
    for (const entries of [all.workspaces, fixture.workspaces]) {
      const pendingEntry = entries[1] as unknown as { ask: Record<string, unknown> }
      expect(Object.keys(pendingEntry).sort()).toEqual(PENDING_KEYS)
      expect(Object.keys(pendingEntry.ask).sort()).toEqual(ASK_KEYS)
    }
    // A fixture whose pending entry lost or changed a required field fails the comparison.
    const fixturePending = fixture.workspaces[1] as unknown as Record<string, unknown>
    const { intent: _dropped, ...withoutIntent } = fixturePending
    expect(shapeOf(withoutIntent)).not.toEqual(shapeOf(all.workspaces[1]))
    expect(shapeOf({ ...fixturePending, renewals: "0" })).not.toEqual(shapeOf(all.workspaces[1]))
    expect(Object.keys(all).sort()).toEqual(Object.keys(fixture).sort())
    // cli against its contract, values and not only keys, in both.
    for (const cli of [(all as unknown as { cli: Record<string, unknown> }).cli, fixture.cli]) {
      expect(Object.keys(cli).sort()).toEqual(["autoUpdate", "build", "check", "commit", "highestSeen", "holdBelow", "installed", "lastUpdate", "mcpHandover", "path", "pending", "previous", "vault", "version"])
      expect(typeof cli.version).toBe("string")
      expect(cli.commit === null || typeof cli.commit === "string").toBe(true)
      expect([null, "release", "dev"]).toContain(cli.build as string | null)
      expect(typeof cli.path).toBe("string")
      expect(["on", "off", "ci", "dev", "read-only"]).toContain(cli.autoUpdate as string)
      expect(cli.mcpHandover).toMatchObject({ handover: expect.stringMatching(/^(on|off)$/) })
      expect(cli).toMatchObject({ installed: null, previous: null, highestSeen: null, holdBelow: null, pending: null, check: null, vault: {}, lastUpdate: null })
    }
    // The human form: one block per entry, then the CLI.
    const human = await runJv(["status"], env2)
    expect(human.stdout).toContain(`personal at ${vault.url}: enrolment ${enrolment} waiting for approval`)
    expect(human.stdout).toContain(`  then:            mehen wait ${enrolment}`)
    expect(human.stdout).toMatch(/\ncli: mehen \d+\.\d+\.\d+/)
  })

  test("a pending slot alone says to wait; a corrupt slot and an absent ceiling entry are listed with their next steps; nothing is signed for them", async () => {
    const env2 = { ...env, MEHEN_WORKSPACES: "personal,client" }
    const enrol = await runJv(["enrol", "--workspace", "personal", "--json"], env2)
    const enrolment = (json(enrol) as { enrolment: string }).enrolment
    const corrupt = vault.slotDir(dir.path, "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    const before = vault.seen.length
    const result = await runJv(["status", "--json"], env2)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({
      allowed: ["personal", "client"],
      selected: null,
      next: { command: `mehen wait ${enrolment}` },
      workspaces: [
        { state: "pending", enrolment },
        { state: "corrupt", slot: corrupt, reason: "not_a_slot", next: { command: `mehen workspace forget --slot ${corrupt}` } },
        { state: "absent", entry: "client", next: { command: "mehen enrol --workspace client" } },
      ],
    })
    expect(vault.seen.length).toBe(before)
  })
})

// Every path under `root` with its type, mode, size, modification time and,
// for a file, its bytes' hash: what "status and doctor write nothing" means.
async function tree(root: string): Promise<Record<string, string>> {
  const { lstat, readdir } = await import("node:fs/promises")
  const { createHash } = await import("node:crypto")
  const out: Record<string, string> = {}
  const walk = async (path: string): Promise<void> => {
    const info = await lstat(path)
    const hash = info.isFile() ? createHash("sha256").update(await Bun.file(path).bytes()).digest("hex") : ""
    out[path] = `${info.isDirectory() ? "d" : info.isFile() ? "f" : "o"}:${(info.mode & 0o7777).toString(8)}:${info.size}:${info.mtimeMs}:${hash}`
    if (info.isDirectory()) for (const name of await readdir(path)) await walk(join(path, name))
  }
  await walk(root)
  return out
}

// Status, status --workspace, whoami and doctor only observe.
describe("status and doctor write nothing", () => {
  const observers = (named: string): string[][] => [["status", "--json"], ["status"], ["status", "--json", "--workspace", named], ["whoami", "--json"], ["doctor", "--json"], ["doctor"]]

  test("a renamed workspace: no config rewrite, no lock file or directory, nothing else", async () => {
    await vault.enrolSoftware(dir.path)
    // A layout-2 root, as any migrated machine has.
    await Bun.write(join(dir.path, "mehen.json"), JSON.stringify({ layout: 2, migratedAt: "2026-10-28T12:00:00.000Z", from: null }))
    await Bun.$`chmod 600 ${join(dir.path, "mehen.json")}`
    vault.workspace = { id: MOCK_TENANT, slug: "renamed", name: "Renamed Space" }
    const before = await tree(dir.path)
    for (const args of observers(MOCK_TENANT)) {
      const result = await runJv(args, env)
      expect(result.code, args.join(" ")).toBe(EXIT.ok)
      expect(await tree(dir.path), args.join(" ")).toEqual(before)
    }
    expect(existsSync(join(dir.path, "locks"))).toBe(false)
  }, 30_000)

  test("a legacy layout and an unfinished journal: status refuses with the command that migrates, doctor reports; nothing moves", async () => {
    const { writeConfig } = await import("../config.ts")
    await writeConfig(dir.path, { vault: vault.url, tenant: MOCK_TENANT, device: "dev_legacy0000001", backend: "software" })
    const legacy = await tree(dir.path)
    for (const args of observers(MOCK_TENANT)) {
      const result = await runJv(args, env)
      if (args[0] === "doctor") expect(result.stdout, args.join(" ")).toContain("not migrated yet")
      else {
        expect(result.code, args.join(" ")).toBe(EXIT.error)
        if (args.includes("--json")) expect(json(result), args.join(" ")).toMatchObject({ error: "failed", next: { command: "mehen workspace list" } })
      }
      expect(await tree(dir.path), args.join(" ")).toEqual(legacy)
    }
    // A journal the next command resumes: refused and reported the same way.
    await Bun.write(join(dir.path, "migration.json"), JSON.stringify({ v: 1, from: "contexts-v1", startedAt: "2026-10-28T12:00:00.000Z", pid: 1, steps: [{ id: 0, kind: "delete", source: join(dir.path, "default-context"), state: "planned" }] }))
    await Bun.$`chmod 600 ${join(dir.path, "migration.json")}`
    const journal = await tree(dir.path)
    for (const args of observers(MOCK_TENANT)) {
      const result = await runJv(args, env)
      if (args[0] === "doctor") expect(result.stdout, args.join(" ")).toContain("unfinished")
      else expect(result.code, args.join(" ")).toBe(EXIT.error)
      expect(await tree(dir.path), args.join(" ")).toEqual(journal)
    }
  }, 30_000)

  test("an enclave slot whose helper is absent, stale or not executable: refused with a repair step; no bin/ made, nothing extracted, chmodded or removed", async () => {
    await vault.enrolSoftware(dir.path)
    await Bun.write(join(dir.path, "mehen.json"), JSON.stringify({ layout: 2, migratedAt: "2026-10-28T12:00:00.000Z", from: null }))
    await Bun.$`chmod 600 ${join(dir.path, "mehen.json")}`
    const slot = vault.slotDir(dir.path)
    const config = await readConfig(slot)
    const { writeConfig } = await import("../config.ts")
    await writeConfig(slot, { ...config!, backend: "secure-enclave" })
    for (const [name, text] of [["device-key.se", "blob"], ["device-key.se.pub.json", JSON.stringify({ kty: "EC", crv: "P-256", x: "x".repeat(43), y: "y".repeat(43) })], ["device-key.se.scope.json", JSON.stringify({ vault: vault.url, tenant: MOCK_TENANT })]] as const) {
      await Bun.write(join(slot, name), text)
      await Bun.$`chmod 600 ${join(slot, name)}`
    }
    const absent = await tree(dir.path)
    for (const args of observers(MOCK_TENANT)) {
      await runJv(args, env)
      expect(await tree(dir.path), args.join(" ")).toEqual(absent)
    }
    expect(existsSync(join(dir.path, "bin"))).toBe(false)
    // A stale extracted helper and a helper that is not executable stay exactly as they are.
    mkdirSync(join(dir.path, "bin"), { mode: 0o700 })
    await Bun.write(join(dir.path, "bin", "mehen-se-0000000000000000"), "#!/bin/sh\nexit 0\n")
    await Bun.$`chmod 755 ${join(dir.path, "bin", "mehen-se-0000000000000000")}`
    await Bun.write(join(dir.path, "bin", "not-executable"), "#!/bin/sh\nexit 0\n")
    await Bun.$`chmod 600 ${join(dir.path, "bin", "not-executable")}`
    const stale = await tree(dir.path)
    for (const extra of [{}, { MEHEN_SE_PATH: join(dir.path, "bin", "not-executable") }] as Record<string, string>[]) {
      for (const args of observers(MOCK_TENANT)) {
        const result = await runJv(args, { ...env, ...extra })
        if (args[0] === "status" && args.includes("--workspace")) expect(json(result), args.join(" ")).toMatchObject({ error: "not_available" })
        expect(await tree(dir.path), args.join(" ")).toEqual(stale)
      }
    }
  }, 30_000)
})

describe("panic buttons", () => {
  test("revoke revokes the device and forgets it locally", async () => {
    const device = await enrolled()
    const result = await runJv(["revoke", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({ revoked: device, alreadyRevoked: false, workspace: MOCK_WORKSPACE, slot: vault.slotDir(dir.path) })
    expect(vault.devices.get(device)?.revoked).toBe(true)
    expect(existsSync(join(vault.slotDir(dir.path), "config.json"))).toBe(false)
    expect(existsSync(join(vault.slotDir(dir.path), "device-key.json"))).toBe(false)
    expect(existsSync(vault.slotDir(dir.path))).toBe(false)
  })

  // Enrol said "revoke first" and revoke said "enrol again".
  // A definitive device_revoked from the signed revoke retires the slot,
  // and enrol then starts afresh; the other workspace's slot is untouched.
  test("a device the vault already revoked is retired by revoke, and enrol works again: no deadlock", async () => {
    const other = await vault.enrolSoftware(dir.path, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const device = await enrolled()
    const record = vault.devices.get(device)
    if (record) record.revoked = true
    const status = await runJv(["status", "--json", "--workspace", "mock-space"], env)
    expect(status.code).toBe(EXIT.identity)
    expect(json(status)).toMatchObject({ error: "device_revoked" })
    const result = await runJv(["revoke", "--json", "--workspace", "mock-space"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual({ revoked: null, alreadyRevoked: true, workspace: MOCK_WORKSPACE, slot: vault.slotDir(dir.path), note: `The vault had already revoked ${device}; its key, config and ledger were removed from this machine.` })
    expect(existsSync(vault.slotDir(dir.path))).toBe(false)
    // The second workspace's slot and device are as they were.
    expect(await readConfig(vault.slotDir(dir.path, SECOND.id))).toMatchObject({ tenant: SECOND.id, device: other })
    expect(vault.devices.get(other)?.revoked).toBe(false)
    // Enrol now starts a new attempt instead of refusing.
    const enrol = await runJv(["enrol", "--workspace", "mock-space", "--json"], env)
    expect(enrol.code).toBe(EXIT.ok)
    expect(json(enrol)).toMatchObject({ status: "pending" })
  })

  // Every answer but success or device_revoked leaves the slot and names the way to retire it by hand.
  test("revoke leaves the slot on unauthenticated, proof_invalid, a 5xx and a network failure, and names workspace forget", async () => {
    const answers: [string, () => Response][] = [
      ["unauthenticated", () => vaultError("unauthenticated", "Unknown device.")],
      ["proof_invalid", () => vaultError("proof_invalid", "The proof does not match the request.")],
      ["internal", () => Response.json({ error: "internal", message: "Something broke." }, { status: 500, headers: { "Mehen-Error": "1" } })],
    ]
    const device = await enrolled()
    const slot = vault.slotDir(dir.path)
    for (const [code, answer] of answers) {
      vault.overrides.set("POST /v1/devices/self/revoke", answer)
      const result = await runJv(["revoke", "--json"], env)
      expect(result.code).not.toBe(EXIT.ok)
      expect(json(result)).toMatchObject({ error: code, next: { say: expect.stringContaining(`mehen workspace forget --slot ${slot}`) } })
      expect(await readConfig(slot)).toMatchObject({ device })
      expect(existsSync(join(slot, "device-key.json"))).toBe(true)
    }
    vault.overrides.clear()
    await rm(slot, { recursive: true })
    await vault.enrolSoftware(dir.path, { config: { vault: "http://127.0.0.1:1" } })
    const offline = vault.slotDir(dir.path, MOCK_TENANT, "http://127.0.0.1:1")
    const network = await runJv(["revoke", "--json"], { ...env, MEHEN_VAULT_URL: "http://127.0.0.1:1" })
    expect(network.code).toBe(EXIT.transient)
    expect(json(network)).toMatchObject({ error: "network", next: { say: expect.stringContaining(`mehen workspace forget --slot ${offline}`) } })
    expect(existsSync(join(offline, "config.json"))).toBe(true)
  })

  // The revoke and the removal happen under the slot's lock
  // and only while it still holds the device the session opened; a slot
  // replaced meanwhile is never revoked or removed.
  test("revoke of a slot another process replaced meanwhile sends nothing and leaves the newer device", async () => {
    const a = await enrolled()
    const slot = vault.slotDir(dir.path)
    let release = () => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let locked = () => {}
    const holding = new Promise<void>((resolve) => {
      locked = resolve
    })
    const holder = withSlotLocks([activeLockPath(dir.path, vault.url, MOCK_TENANT)], async () => {
      locked()
      await held
    })
    await holding
    const pending = revokeSlot(env).then(
      () => null,
      (error: unknown) => error,
    )
    // The revoke has opened its session on A and waits for the lock; B lands.
    await Bun.sleep(400)
    await rm(slot, { recursive: true })
    const b = await enrolled()
    release()
    await holder
    expect(await pending).toMatchObject({ code: "failed", message: expect.stringContaining("another mehen process replaced it meanwhile") })
    expect(vault.revoked).not.toContain(a)
    expect(vault.revoked).not.toContain(b)
    expect(await readConfig(slot)).toMatchObject({ device: b })
  })

  test("freeze freezes the tenant", async () => {
    await enrolled()
    vault.frozen = false
    const result = await runJv(["freeze", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(vault.frozen).toBe(true)
    vault.frozen = false
  })
})

test("refusal/status shows unavailable rather than no active access on an unsupported vault", async () => {
  await enrolled()
  const result = await runJv(["status"], env)
  expect(result.stdout).toContain("  policy windows:  unavailable from this vault\n")
  expect(result.stdout).not.toContain("No active policy windows")
})
