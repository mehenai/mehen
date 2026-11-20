// mehen workspace: slots listed without the
// network (pending, corrupt and absent ceiling entries included), the
// selection explained, a slot forgotten locally, no default, and a checkout
// bound only to the one enrolled workspace that holds its project.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs"
import { readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { defaultConfigDir, readConfig, writeConfig } from "../config.ts"
import { pendingSlotPath } from "../home.ts"
import { addLedgerEntry } from "../ledger.ts"
import { activeLockPath, pendingLockPath, withSlotLocks } from "../slot-lock.ts"
import { writeEnrolmentRecord } from "../enrolment-record.ts"
import { askUrl, enrolAsk } from "../ask.ts"
import { MOCK_OWNER, MOCK_TENANT, MOCK_WORKSPACE, MockVault, WORKSPACE_SCOPE, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { createDeviceKey } from "../device-key.ts"
import { openContext } from "../session.ts"
import { mutateSlot, publicKeyOnDisk } from "./activate.ts"
import { status } from "./device.ts"
import { bindManifestText } from "./workspace.ts"

let vault: MockVault
let home: { path: string; remove(): Promise<void> }
let env: Record<string, string>
const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  home = await tempDir()
  env = { HOME: home.path, MEHEN_CONFIG_DIR: "" }
  vault.overrides.clear()
  vault.workspace = { ...MOCK_WORKSPACE }
})
afterEach(() => home.remove())

const root = () => defaultConfigDir(env)
const base = () => vault.slotDir(root())
const second = () => vault.slotDir(root(), SECOND.id)
function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}
async function twoContexts(): Promise<{ a: string; b: string }> {
  const a = await vault.enrolSoftware(root())
  const b = await vault.enrolSoftware(root(), { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
  return { a, b }
}

// A pending enrolment for `slug` in its pending slot, as today's enrol leaves it.
async function pendingEnrolment(slug: string, id: string): Promise<string> {
  const dir = pendingSlotPath(root(), vault.url, slug)
  const url = askUrl(`${vault.url}/w/${slug}/e/ABCD2345`, { vaultUrl: vault.url, workspaceSlug: slug })!.url
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }
  await addLedgerEntry(dir, { vaultUrl: vault.url, workspace: null, device: null }, { ask: enrolAsk({ id, url, name: "n", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }), enrol: { code: "ABCD2345", name: "n", backend: "software", jwk, workspace: slug, team: null } })
  return dir
}

// Runs `mehen <args>` while this process holds `lock`, lets the child reach
// the lock, applies `change` (another process's write), then releases it.
async function whileForgetWaits(args: string[], runEnv: Record<string, string>, lock: string, change: () => Promise<void>): Promise<JvResult> {
  let release = () => {}
  const held = new Promise<void>((resolve) => {
    release = resolve
  })
  let locked = () => {}
  const holding = new Promise<void>((resolve) => {
    locked = resolve
  })
  const holder = withSlotLocks([lock], async () => {
    locked()
    await held
  })
  await holding
  const running = runJv(args, runEnv)
  await Bun.sleep(1500)
  await change()
  release()
  await holder
  return running
}

describe("list and show", () => {
  test("list names every slot from disk alone, pending, corrupt and absent ceiling entries included; --check asks each vault", async () => {
    const before = vault.seen.length
    const empty = await runJv(["workspace", "list"], env)
    expect(empty.code).toBe(EXIT.ok)
    expect(empty.stdout).toContain("No workspace is enrolled on this machine.")
    await twoContexts()
    const result = await runJv(["workspace", "list", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const listed = json(result) as { home: string; allowed: unknown; workspaces: { state: string; slot: string; workspace: { id: string; slug: string } }[] }
    expect(listed.home).toBe(root())
    expect(listed.allowed).toBeNull()
    expect(listed.workspaces.map((c) => [c.state, c.slot, c.workspace.id, c.workspace.slug])).toEqual([["active", base(), MOCK_TENANT, "mock-space"], ["active", second(), SECOND.id, SECOND.slug]])
    expect(vault.seen.length).toBe(before)
    const human = await runJv(["workspace", "list"], env)
    expect(human.stdout).toContain(`Mock Space (mock-space, ${MOCK_TENANT}) at ${vault.url}`)
    const checked = await runJv(["workspace", "list", "--check", "--json"], env)
    const checks = (json(checked) as { workspaces: { check: { ok: boolean; status?: { slot: string } } }[] }).workspaces.map((c) => [c.check.ok, c.check.status?.slot])
    expect(checks).toEqual([[true, base()], [true, second()]])
    expect(vault.seen.length).toBeGreaterThan(before)
    // A pending slot, a corrupt one and a ceiling entry not enrolled yet.
    const pending = await pendingEnrolment("client", "enr_listed00001")
    const corrupt = join(root(), "workspaces", "stray.example", "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    writeFileSync(join(corrupt, "config.json"), "{ nope", { mode: 0o600 })
    const all = json(await runJv(["workspace", "list", "--json"], { ...env, MEHEN_WORKSPACES: "mock-space,client,absent-space" })) as { allowed: string[]; workspaces: Record<string, unknown>[] }
    expect(all.allowed).toEqual(["mock-space", "client", "absent-space"])
    expect(all.workspaces.map((w) => w.state)).toEqual(["active", "pending", "corrupt", "absent"])
    expect(all.workspaces[1]).toMatchObject({ slot: pending, enrolment: "enr_listed00001", intent: { workspace: "client", team: null }, legacy: true, claimed: false, ask: { kind: "enrol", id: "enr_listed00001" } })
    expect(all.workspaces[2]).toMatchObject({ slot: corrupt, reason: "config_invalid", next: { command: `mehen workspace forget --slot ${corrupt}` } })
    expect(all.workspaces[3]).toMatchObject({ entry: "absent-space", next: { command: "mehen enrol --workspace absent-space" } })
  })

  // Threat model, one terminal boundary: a line break in a workspace or
  // owner name the vault recorded is a character of that name, spelled out,
  // never a row of its own in list, show or bind.
  test("a renamed workspace's line break stays inside its row in list, show, bind and enrol", async () => {
    const injected = "Acme\n  next: verify-enrolment"
    await vault.enrolSoftware(root(), { config: { owner: { kind: "member", member: "mem_owner1", name: "Owner\nnext: trust-me" } } })
    vault.workspace = { ...MOCK_WORKSPACE, name: injected }
    vault.overrides.set("GET /v1/projects/prj_app", () => Response.json({ id: "prj_app", slug: "app", remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }], vars: [] }))
    expect((await runJv(["workspace", "list", "--check", "--json"], env)).code).toBe(EXIT.ok)
    expect((await readConfig(base()))?.workspaceName).toBe(injected)
    const repo = await tempDir()
    try {
      await writeFile(join(repo.path, "mehen.toml"), 'project = "prj_app"\n')
      for (const args of [["workspace", "list"], ["workspace", "show"], ["workspace", "bind"], ["enrol", "--workspace", "mock-space"]]) {
        const result = await runJv(args, { ...env, MEHEN_VAULT_URL: vault.url }, undefined, repo.path)
        expect(result.code, args.join(" ")).toBe(EXIT.ok)
        expect(result.stdout, args.join(" ")).toContain("Acme\\u000A  next: verify-enrolment")
        expect(result.stdout, args.join(" ")).not.toMatch(/^\s*next: (verify-enrolment|trust-me)/m)
      }
      expect((await runJv(["workspace", "list"], env)).stdout).toContain("owned by Owner\\u000Anext: trust-me")
    } finally {
      await repo.remove()
    }
  })

  // The command line's one refresh of a renamed workspace.
  describe("list --check records a rename", () => {
    // Every path under the root with its type, mode, size, mtime and bytes.
    async function tree(dir: string): Promise<Record<string, string>> {
      const { lstatSync } = await import("node:fs")
      const out: Record<string, string> = {}
      const walk = (path: string): void => {
        const info = lstatSync(path)
        out[path] = `${info.isDirectory() ? "d" : "f"}:${(info.mode & 0o7777).toString(8)}:${info.size}:${info.mtimeMs}:${info.isFile() ? readFileSync(path, "hex") : ""}`
        if (info.isDirectory()) for (const name of readdirSync(path)) walk(join(path, name))
      }
      walk(dir)
      return out
    }

    test("the new slug and name are written, nothing else; plain list and status write nothing", async () => {
      await vault.enrolSoftware(root())
      expect((await runJv(["workspace", "list", "--json"], env)).code).toBe(EXIT.ok)
      const recorded = await readConfig(base())
      if (!recorded) throw new Error("the enrolled slot has a config")
      vault.workspace = { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" }
      vault.owner = { kind: "member", member: "mem_other1", name: "Someone Else" }
      try {
        const before = await tree(root())
        for (const args of [["workspace", "list", "--json"], ["workspace", "list"], ["status", "--json"], ["status", "--json", "--workspace", MOCK_TENANT]]) {
          expect((await runJv(args, env)).code, args.join(" ")).toBe(EXIT.ok)
          expect(await tree(root()), args.join(" ")).toEqual(before)
        }
        const checked = json(await runJv(["workspace", "list", "--check", "--json"], env)) as { workspaces: { check: { ok: boolean; status: { workspace: unknown } } }[] }
        expect(checked.workspaces[0]?.check).toMatchObject({ ok: true, status: { workspace: { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" } } })
        expect(await readConfig(base())).toEqual({ ...recorded, name: "test-machine", workspaceSlug: "renamed-space", workspaceName: "Renamed Space" })
        // The renamed slug now selects the slot.
        expect(json(await runJv(["workspace", "show", "--json", "--workspace", "renamed-space"], env))).toMatchObject({ slot: base(), reason: "workspace" })
      } finally {
        vault.owner = { ...MOCK_OWNER }
      }
    })

    // The slot changes while the signed GET /v1/me is outstanding
    // (after the vault verified the proof, before it answers with the
    // original workspace's rename). The refresh must find, under the slot
    // lock, the key it signed with and the identity it opened; otherwise it
    // writes nothing, and a changed identity is workspace_mismatch.
    const late: { name: string; change: (slot: string) => Promise<void>; refused: boolean }[] = [
      { name: "a replacement key", change: async (slot) => void (await createDeviceKey(slot, "software", {}, { vault: vault.url, tenant: MOCK_TENANT })), refused: false },
      { name: "a removed key", change: (slot) => rm(join(slot, "device-key.json")), refused: false },
      { name: "a replacement origin in the config", change: async (slot) => void (await replaceConfig(slot, { vault: "https://other.example" })), refused: true },
      { name: "a replacement workspace in the config", change: async (slot) => void (await replaceConfig(slot, { tenant: "tn_other00000001" })), refused: true },
    ]
    // Another process's locked rewrite of the slot's config.
    async function replaceConfig(slot: string, patch: { vault?: string; tenant?: string }): Promise<void> {
      const current = await readConfig(slot)
      if (!current) throw new Error("the slot has a config")
      expect(await mutateSlot(slot, { device: current.device, jwk: await publicKeyOnDisk(slot, current.backend) }, (c) => ({ ...c, ...patch }))).toBe("applied")
    }
    for (const scenario of late) {
      test(`a late answer after ${scenario.name} writes nothing${scenario.refused ? " and is workspace_mismatch" : ""}`, async () => {
        await vault.enrolSoftware(root())
        const config = await readConfig(base())
        if (!config) throw new Error("the enrolled slot has a config")
        const session = await openContext(env, { dir: base(), config, reason: "workspace" }, { observe: true })
        let changed: Record<string, string> | null = null
        vault.overrides.set("GET /v1/me", async (_request, seen) => {
          await scenario.change(base())
          changed = await tree(base())
          return Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: WORKSPACE_SCOPE, frozen: false, workspace: { id: MOCK_TENANT, slug: "stale-rename", name: "Stale Rename" }, owner: MOCK_OWNER })
        })
        const outcome = await status(env, session, { persist: false, refreshNames: true }).then(() => null, (error: unknown) => error)
        if (scenario.refused) expect(outcome).toMatchObject({ code: "workspace_mismatch" })
        else expect(outcome).toBeNull()
        expect(changed).not.toBeNull()
        expect(await tree(base())).toEqual(changed as unknown as Record<string, string>)
        expect((await readConfig(base()))?.workspaceSlug).not.toBe("stale-rename")
      })
    }

    test("vault_status's own display refresh compares the signing key too: a late answer after a replacement key writes nothing", async () => {
      await vault.enrolSoftware(root())
      const config = await readConfig(base())
      if (!config) throw new Error("the enrolled slot has a config")
      const session = await openContext(env, { dir: base(), config, reason: "workspace" })
      let changed: Record<string, string> | null = null
      vault.overrides.set("GET /v1/me", async (_request, seen) => {
        await createDeviceKey(base(), "software", {}, { vault: vault.url, tenant: MOCK_TENANT })
        changed = await tree(base())
        return Response.json({ tenant: MOCK_TENANT, device: seen.claims.dev, name: "test-machine", scope: WORKSPACE_SCOPE, frozen: false, workspace: { id: MOCK_TENANT, slug: "stale-rename", name: "Stale Rename" }, owner: MOCK_OWNER })
      })
      await status(env, session)
      expect(await tree(base())).toEqual(changed as unknown as Record<string, string>)
    })

    test("a held slot lock holds the refresh: nothing is written until it is released", async () => {
      await vault.enrolSoftware(root())
      const config = await readConfig(base())
      if (!config) throw new Error("the enrolled slot has a config")
      const session = await openContext(env, { dir: base(), config, reason: "workspace" }, { observe: true })
      vault.workspace = { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" }
      let refreshed: Promise<unknown> | null = null
      await withSlotLocks([activeLockPath(root(), vault.url, MOCK_TENANT)], async () => {
        refreshed = status(env, session, { persist: false, refreshNames: true })
        await Bun.sleep(400)
        expect((await readConfig(base()))?.workspaceSlug).toBe("mock-space")
      })
      await refreshed
      expect((await readConfig(base()))?.workspaceSlug).toBe("renamed-space")
    })

    test("an answer for another workspace, or a session at another origin, is workspace_mismatch and leaves the slot byte-identical", async () => {
      const device = await vault.enrolSoftware(root())
      expect((await runJv(["workspace", "list", "--json"], env)).code).toBe(EXIT.ok)
      vault.workspace = { id: MOCK_TENANT, slug: "renamed-space", name: "Renamed Space" }
      const before = await tree(root())
      const other = { id: "tn_other00000001", slug: "renamed-space", name: "Renamed Space" }
      for (const answer of [{ tenant: MOCK_TENANT, workspace: other }, { tenant: other.id, workspace: other }, { tenant: other.id, workspace: MOCK_WORKSPACE }]) {
        vault.overrides.set("GET /v1/me", () => Response.json({ ...answer, device, name: "test-machine", scope: WORKSPACE_SCOPE, frozen: false, owner: MOCK_OWNER }))
        const checked = json(await runJv(["workspace", "list", "--check", "--json"], env)) as { workspaces: { check: { ok: boolean; error?: string } }[] }
        expect(checked.workspaces[0]?.check, JSON.stringify(answer)).toMatchObject({ ok: false, error: "workspace_mismatch" })
        expect(await tree(root()), JSON.stringify(answer)).toEqual(before)
      }
      vault.overrides.clear()
      const elsewhere = json(await runJv(["workspace", "list", "--check", "--json"], { ...env, MEHEN_VAULT_URL: "https://elsewhere.example" })) as { workspaces: { check: { ok: boolean; error?: string } }[] }
      expect(elsewhere.workspaces[0]?.check).toMatchObject({ ok: false, error: "workspace_mismatch" })
      expect(await tree(root())).toEqual(before)
    })
  })

  test("show says which slot the directory selects and why; with two and nothing selecting one it refuses", async () => {
    const none = await runJv(["workspace", "show"], env)
    expect(none.code).toBe(EXIT.ok)
    expect(none.stdout).toBe("No workspace is selected: this machine is not enrolled in one yet. Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page.\n")
    await vault.enrolSoftware(root())
    const only = await runJv(["workspace", "show", "--json"], env)
    expect(json(only)).toEqual({ slot: base(), reason: "only", workspace: MOCK_WORKSPACE, origin: vault.url, device: expect.any(String), manifest: null })
    await vault.enrolSoftware(root(), { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const plain = await runJv(["workspace", "show", "--json"], env)
    expect(plain.code).toBe(EXIT.usage)
    expect(json(plain)).toMatchObject({ error: "context_ambiguous", next: { say: expect.stringContaining("items[].workspace.slug in `mehen ls --json`") } })
    expect(String(json(plain).message)).not.toContain(root())
    expect(json(plain).next).not.toHaveProperty("command")
    const selected = await runJv(["workspace", "show", "--json", "--workspace", SECOND.slug], env)
    expect(json(selected)).toMatchObject({ slot: second(), reason: "workspace" })
    const repo = await tempDir()
    try {
      await writeFile(join(repo.path, "mehen.toml"), `project = "prj_1"\nworkspace = "${SECOND.id}"\n`)
      const fromManifest = await runJv(["workspace", "show", "--json"], env, undefined, repo.path)
      expect(json(fromManifest)).toMatchObject({ slot: second(), reason: "manifest", manifest: { workspace: SECOND.id } })
      const human = await runJv(["workspace", "show"], env, undefined, repo.path)
      expect(human.stdout).toContain("because the checkout's mehen.toml names its workspace")
      await writeFile(join(repo.path, "mehen.toml"), 'project = "prj_1"\n')
      const unbound = await runJv(["workspace", "show", "--json"], env, undefined, repo.path)
      expect(unbound.code).toBe(EXIT.usage)
      expect(json(unbound)).toMatchObject({ error: "workspace_unbound", next: { command: "mehen workspace bind" } })
    } finally {
      await repo.remove()
    }
  })

  test("help, an unknown verb, and the removed default verb", async () => {
    expect((await runJv(["workspace", "--help"], env)).stdout).toContain("usage: mehen workspace list")
    expect((await runJv(["help", "workspace"], env)).stdout).toContain("mehen workspace bind")
    expect((await runJv(["--help"], env)).stdout).toMatch(/^ {2}workspace\s+list, show, forget or bind/m)
    expect((await runJv(["workspace", "frobnicate", "--json"], env)).code).toBe(EXIT.usage)
    // No verb is a usage error: the help goes to stderr, as mehen alone does, and stdout stays empty.
    const bare = await runJv(["workspace"], env)
    expect(bare.code).toBe(EXIT.usage)
    expect(bare.stdout).toBe("")
    expect(bare.stderr).toContain("usage: mehen workspace list")
    await twoContexts()
    const gone = await runJv(["workspace", "default", SECOND.slug, "--json"], env)
    expect(gone.code).toBe(EXIT.usage)
    expect(json(gone)).toMatchObject({ error: "usage" })
    expect(existsSync(join(root(), "default-context"))).toBe(false)
  })
})

describe("forget", () => {
  test("forgets one slot locally by slug, id or --slot, sending nothing; the note says the device stays until an owner revokes it", async () => {
    const { a } = await twoContexts()
    const before = vault.seen.length
    const result = await runJv(["workspace", "forget", "mock-space", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toMatchObject({ forgotten: true, slot: base(), state: "active", device: a, enrolment: null })
    expect(String(json(result).note)).toContain("stays on the workspace's Machines page until an owner revokes it")
    expect(existsSync(base())).toBe(false)
    expect(existsSync(second())).toBe(true)
    const bySlot = await runJv(["workspace", "forget", SECOND.id, "--slot", second(), "--json"], env)
    expect(json(bySlot)).toMatchObject({ forgotten: true, slot: second(), state: "active" })
    expect(vault.seen.length).toBe(before)
    // A pending enrolment is forgotten with its record; the note warns about the stale link.
    const pending = await pendingEnrolment("client", "enr_forget00001")
    const forgotPending = await runJv(["workspace", "forget", "client", "--json"], env)
    expect(json(forgotPending)).toMatchObject({ state: "pending", enrolment: "enr_forget00001", slot: pending })
    expect(String(json(forgotPending).note)).toContain("reject it instead")
    expect(existsSync(pending)).toBe(false)
  })

  test("refusals: neither selector nor --slot, a --slot outside the root, a link or a disagreeing pair is usage; a duplicate needs --slot; outside the ceiling is workspace_not_allowed; nothing is removed", async () => {
    await twoContexts()
    const neither = await runJv(["workspace", "forget", "--json"], env)
    expect(neither.code).toBe(EXIT.usage)
    for (const path of [home.path, join(root(), "workspaces"), "/etc"]) {
      const outside = await runJv(["workspace", "forget", "--slot", path, "--json"], env)
      expect(outside.code).toBe(EXIT.usage)
    }
    const linked = join(root(), "workspaces", "linked.example")
    symlinkSync(join(base(), ".."), linked)
    expect((await runJv(["workspace", "forget", "--slot", join(linked, MOCK_TENANT), "--json"], env)).code).toBe(EXIT.usage)
    const disagree = await runJv(["workspace", "forget", "mock-space", "--slot", second(), "--json"], env)
    expect(disagree.code).toBe(EXIT.usage)
    const outsideCeiling = await runJv(["workspace", "forget", "mock-space", "--json"], { ...env, MEHEN_WORKSPACES: SECOND.slug })
    expect(outsideCeiling.code).toBe(EXIT.usage)
    expect(json(outsideCeiling)).toMatchObject({ error: "workspace_not_allowed" })
    // The same workspace at two origins: the selector is ambiguous, --slot picks one.
    await vault.enrolSoftware(root(), { config: { vault: "https://other.example" } })
    const ambiguous = await runJv(["workspace", "forget", "mock-space", "--json"], env)
    expect(ambiguous.code).toBe(EXIT.usage)
    expect(json(ambiguous)).toMatchObject({ error: "context_ambiguous" })
    expect(existsSync(base())).toBe(true)
    expect(existsSync(second())).toBe(true)
    const corrupt = join(root(), "workspaces", "stray.example", "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    writeFileSync(join(corrupt, "config.json"), "{ nope", { mode: 0o600 })
    const forgotCorrupt = await runJv(["workspace", "forget", "--slot", corrupt, "--json"], env)
    expect(json(forgotCorrupt)).toMatchObject({ forgotten: true, state: "corrupt", device: null })
    expect(existsSync(corrupt)).toBe(false)
  })

  // Admission is decided again under the slot's lock. A slot whose
  // slug changed (same device and key) to one MEHEN_WORKSPACES does not
  // admit, while forget waited, is refused and kept whole.
  test("a slot that left the ceiling while forget waited for its lock is refused workspace_not_allowed and kept, by selector and by --slot", async () => {
    const device = await vault.enrolSoftware(root())
    const ceiling = { ...env, MEHEN_WORKSPACES: "mock-space" }
    for (const args of [["workspace", "forget", "mock-space", "--json"], ["workspace", "forget", "--slot", base(), "--json"]]) {
      await writeConfig(base(), { ...(await readConfig(base()))!, workspaceSlug: "mock-space" })
      const before = vault.seen.length
      const result = await whileForgetWaits(args, ceiling, activeLockPath(root(), vault.url, MOCK_TENANT), async () => {
        await writeConfig(base(), { ...(await readConfig(base()))!, workspaceSlug: "no-longer-admitted" })
      })
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "workspace_not_allowed" })
      expect(await readConfig(base())).toMatchObject({ device, workspaceSlug: "no-longer-admitted" })
      expect(existsSync(join(base(), "device-key.json"))).toBe(true)
      expect(existsSync(join(base(), "device-key.scope.json"))).toBe(true)
      expect(vault.seen.length).toBe(before)
    }
  })

  // The directory is compared by identity under the lock, not by
  // its classification. Every replacement or in-place change below leaves
  // the newer evidence untouched and reports failed.
  test("a corrupt slot replaced by another corrupt one, or changed in place, is not removed: failed, the newer directory intact", async () => {
    const corrupt = vault.slotDir(root(), "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    const replaced = await whileForgetWaits(["workspace", "forget", "--slot", corrupt, "--json"], env, activeLockPath(root(), vault.url, "tn_broken0000001"), async () => {
      await rm(corrupt, { recursive: true })
      mkdirSync(corrupt, { mode: 0o700 })
      writeFileSync(join(corrupt, "replacement-marker"), "B", { mode: 0o600 })
    })
    expect(replaced.code).toBe(EXIT.error)
    expect(json(replaced)).toMatchObject({ error: "failed" })
    expect(readFileSync(join(corrupt, "replacement-marker"), "utf8")).toBe("B")
    // In place: the same directory gains an attempt that is still being issued.
    const pendingDir = pendingSlotPath(root(), vault.url, "client")
    mkdirSync(pendingDir, { recursive: true, mode: 0o700 })
    const issuing = { v: 1 as const, state: "issuing" as const, id: null, code: null, url: null, origin: vault.url, intent: { workspace: "client", team: null }, name: "n", backend: "software" as const, jwk: { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }, session: null, startedAt: new Date().toISOString(), expiresAt: null, hardExpiresAt: null, renewals: 0, legacy: false, claimed: false }
    const changed = await whileForgetWaits(["workspace", "forget", "--slot", pendingDir, "--json"], env, pendingLockPath(root(), vault.url, "client"), async () => {
      await writeEnrolmentRecord(pendingDir, issuing)
    })
    expect(changed.code).toBe(EXIT.error)
    expect(json(changed)).toMatchObject({ error: "failed" })
    expect(existsSync(join(pendingDir, "enrolment.json"))).toBe(true)
  })

  test("a pending slot that became another attempt or an active slot while forget waited is not removed", async () => {
    const dir = await pendingEnrolment("client", "enr_forgetold001")
    const other = await whileForgetWaits(["workspace", "forget", "client", "--json"], env, pendingLockPath(root(), vault.url, "client"), async () => {
      await rm(dir, { recursive: true })
      await pendingEnrolment("client", "enr_forgetnew001")
    })
    expect(other.code).toBe(EXIT.error)
    expect(json(other)).toMatchObject({ error: "failed" })
    expect(readFileSync(join(dir, "ledger.json"), "utf8")).toContain("enr_forgetnew001")
    const active = await whileForgetWaits(["workspace", "forget", "client", "--json"], env, pendingLockPath(root(), vault.url, "client"), async () => {
      await rm(dir, { recursive: true })
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      await writeConfig(dir, { vault: vault.url, tenant: "tn_client00000001", device: "dev_client0000001", backend: "software" })
    })
    expect(active.code).toBe(EXIT.error)
    expect(json(active)).toMatchObject({ error: "failed" })
    expect(await readConfig(dir)).toMatchObject({ device: "dev_client0000001" })
  })

  // Forget goes through mutateSlot, so a slot another process
  // replaced while forget waited for its lock is left as the newer one.
  test("an active slot replaced while forget waited for its lock is not removed: failed, the newer device intact", async () => {
    await vault.enrolSoftware(root())
    let release = () => {}
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    let locked = () => {}
    const holding = new Promise<void>((resolve) => {
      locked = resolve
    })
    const holder = withSlotLocks([activeLockPath(root(), vault.url, MOCK_TENANT)], async () => {
      locked()
      await held
    })
    await holding
    const forgetting = runJv(["workspace", "forget", "mock-space", "--json"], env)
    await Bun.sleep(1500)
    await rm(base(), { recursive: true })
    const b = await vault.enrolSoftware(root())
    release()
    await holder
    const result = await forgetting
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "failed" })
    expect(await readConfig(base())).toMatchObject({ device: b })
  })
})

describe("bind", () => {
  const project = (id: string) => ({ id, slug: "app", remotes: [], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [] }], vars: [] })

  test("writes workspace and vault into mehen.toml for exactly the one enrolled workspace that holds the project; never an origin the repo or server suggests", async () => {
    await twoContexts()
    vault.overrides.set("GET /v1/projects/prj_app", (_request, seen) => (seen.claims.ten === SECOND.id ? Response.json(project("prj_app")) : vaultError("not_found", "No such project.")))
    const repo = await tempDir()
    try {
      const before = `# comment\nproject = "prj_app"\nvault = "https://evil.example"\ndefault_env = "dev"\n\n[vars]\nA = "vault"\n`
      await writeFile(join(repo.path, "mehen.toml"), before)
      // An unbound manifest under two slots: bind still works (it selects nothing), status would refuse.
      const result = await runJv(["workspace", "bind", "--json"], env, undefined, repo.path)
      expect(result.code).toBe(EXIT.ok)
      expect(json(result)).toMatchObject({ bound: true, changed: true, project: "prj_app", workspace: { id: SECOND.id, slug: SECOND.slug }, vault: vault.url, slot: second() })
      const after = await readFile(join(repo.path, "mehen.toml"), "utf8")
      expect(after).toBe(`# comment\nproject = "prj_app"\nworkspace = "${SECOND.id}"  # workspace Second Space (second-space); the id prefix is historical\nvault = "${vault.url}"\ndefault_env = "dev"\n\n[vars]\nA = "vault"\n`)
      expect(after).not.toContain("evil.example")
      // Now the checkout selects the second slot on its own.
      expect(json(await runJv(["status", "--json"], env, undefined, repo.path))).toMatchObject({ selected: second() })
      // Idempotent.
      expect(json(await runJv(["workspace", "bind", "--json"], env, undefined, repo.path))).toMatchObject({ bound: true, changed: false })
    } finally {
      await repo.remove()
    }
  })

  test("none or several workspaces holding the project refuse, and nothing is written", async () => {
    await twoContexts()
    const repo = await tempDir()
    try {
      const before = 'project = "prj_app"\n'
      await writeFile(join(repo.path, "mehen.toml"), before)
      vault.overrides.set("GET /v1/projects/prj_app", () => vaultError("not_found", "No such project."))
      const none = await runJv(["workspace", "bind", "--json"], env, undefined, repo.path)
      expect(none.code).toBe(EXIT.usage)
      expect(json(none)).toMatchObject({ error: "workspace_unknown" })
      vault.overrides.set("GET /v1/projects/prj_app", () => Response.json(project("prj_app")))
      const several = await runJv(["workspace", "bind", "--json"], env, undefined, repo.path)
      expect(several.code).toBe(EXIT.usage)
      expect(json(several)).toMatchObject({ error: "context_ambiguous" })
      // A server answering with another project id is not a match either.
      vault.overrides.set("GET /v1/projects/prj_app", () => Response.json(project("prj_other")))
      expect(json(await runJv(["workspace", "bind", "--json"], env, undefined, repo.path))).toMatchObject({ error: "workspace_unknown" })
      expect(await readFile(join(repo.path, "mehen.toml"), "utf8")).toBe(before)
      const nowhere = await runJv(["workspace", "bind", "--json"], env, undefined, home.path)
      expect(nowhere.code).toBe(EXIT.usage)
    } finally {
      await repo.remove()
    }
  })

  test("bindManifestText replaces or inserts the two keys before the first table and keeps every other byte", () => {
    const ws = { id: "tn_x", slug: "s", name: "Name\nwith newline" }
    expect(bindManifestText('project = "p"\n[vars]\nA = "vault"\n', ws, "https://v")).toBe('project = "p"\nworkspace = "tn_x"  # workspace Name with newline (s); the id prefix is historical\nvault = "https://v"\n[vars]\nA = "vault"\n')
    expect(bindManifestText('workspace = "old"\nproject = "p"\nvault="old"\n', { id: "tn_x", slug: null, name: null }, "https://v")).toBe('workspace = "tn_x"\nproject = "p"\nvault = "https://v"\n')
  })
})

// A path names a slot; it never authorises one outside the ceiling.
describe("forget --slot under a ceiling", () => {
  test("a path-only target outside MEHEN_WORKSPACES, or under an empty one, is refused and every file of it remains", async () => {
    await twoContexts()
    const files = () => readdirSync(second()).sort()
    const before = files()
    for (const ceiling of ["mock-space", ""]) {
      const refused = await runJv(["workspace", "forget", "--slot", second(), "--json"], { ...env, MEHEN_WORKSPACES: ceiling })
      expect(refused.code).toBe(EXIT.usage)
      expect(json(refused)).toMatchObject({ error: "workspace_not_allowed" })
      expect(files()).toEqual(before)
    }
    // A corrupt slot, whose workspace cannot be established, is refused under a ceiling too.
    const corrupt = join(root(), "workspaces", "stray.example", "tn_broken0000001")
    mkdirSync(corrupt, { recursive: true, mode: 0o700 })
    writeFileSync(join(corrupt, "config.json"), "{ nope", { mode: 0o600 })
    expect(json(await runJv(["workspace", "forget", "--slot", corrupt, "--json"], { ...env, MEHEN_WORKSPACES: "mock-space" }))).toMatchObject({ error: "workspace_not_allowed" })
    expect(existsSync(join(corrupt, "config.json"))).toBe(true)
    // Inside the ceiling the same path is forgotten.
    expect(json(await runJv(["workspace", "forget", "--slot", second(), "--json"], { ...env, MEHEN_WORKSPACES: SECOND.slug }))).toMatchObject({ forgotten: true, slot: second() })
  })
})
