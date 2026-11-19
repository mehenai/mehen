// Slot discovery, the published slot views and the managed-host rule 0
// under the slot layout. Temporary HOMEs
// only; the marker is read through the files seam.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type Config, DEFAULT_VAULT_URL, defaultConfigDir, writeConfig } from "./config.ts"
import { createDeviceKey, writeKeyScope } from "./device-key.ts"
import { writeEnrolmentRecord } from "./enrolment-record.ts"
import { CliError, type CliErrorCode, exitCodeFor } from "./errors.ts"
import { activeSlotPath, pendingSlotPath } from "./home.ts"
import { openSession } from "./session.ts"
import { type FoundSlot, assertManifestAgrees, assertVaultUrlAgrees, contextMatches, knownVault, listActive, listSlots, selectSlot, slotView, workspaceSelector } from "./slots.ts"
import { MockVault } from "./testing/mock-vault.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

const ORIGIN = "https://vault.example"
const WORK: Config = { vault: ORIGIN, tenant: "tn_work00000001", device: "dev_work00000001", backend: "software", workspaceSlug: "northwind", workspaceName: "Northwind" }

let home: { path: string; remove(): Promise<void> }
let env: Record<string, string | undefined>
const root = () => defaultConfigDir(env)

beforeEach(async () => {
  home = await tempDir()
  env = { HOME: home.path }
})
afterEach(() => home.remove())

async function failure(run: () => Promise<unknown>): Promise<CliError> {
  try {
    await run()
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a CliError")
}

async function view(dir: string): Promise<Awaited<ReturnType<typeof slotView>>> {
  const found = (await listSlots(root())).find((f) => f.dir === dir) as FoundSlot
  return slotView(found, "office")
}

describe("discovery and the published views", () => {
  test("an active slot with its key is active; without its key, with a loose key, or with a key for another workspace it is corrupt with that reason", async () => {
    const dir = activeSlotPath(root(), ORIGIN, WORK.tenant)
    await writeConfig(dir, WORK)
    expect(await view(dir)).toMatchObject({ state: "corrupt", reason: "key_missing", next: { command: `mehen workspace forget --slot ${dir}` } })
    await createDeviceKey(dir, "software", {}, { vault: ORIGIN, tenant: WORK.tenant })
    expect(await view(dir)).toMatchObject({ state: "active", slot: dir, origin: ORIGIN, workspace: { id: WORK.tenant, slug: "northwind", name: "Northwind" }, device: WORK.device, backend: "software", owner: null, fingerprint: null })
    await writeKeyScope(dir, "software", { vault: ORIGIN, tenant: "tn_other00000001" })
    expect(await view(dir)).toMatchObject({ state: "corrupt", reason: "scope_mismatch" })
    await writeKeyScope(dir, "software", { vault: ORIGIN, tenant: WORK.tenant })
    chmodSync(join(dir, "device-key.json"), 0o644)
    expect(await view(dir)).toMatchObject({ state: "corrupt", reason: "key_insecure" })
  })

  test("a slot whose config names another workspace than its directory, a duplicate device and an empty directory are corrupt; nothing throws", async () => {
    const misplaced = activeSlotPath(root(), ORIGIN, "tn_elsewhere0001")
    await writeConfig(misplaced, WORK)
    const duplicate = `${activeSlotPath(root(), ORIGIN, WORK.tenant)}.duplicate-dev_twin00000001`
    await writeConfig(duplicate, { ...WORK, device: "dev_twin00000001" })
    const empty = pendingSlotPath(root(), ORIGIN, "nothing")
    mkdirSync(empty, { recursive: true, mode: 0o700 })
    const found = await listSlots(root())
    expect(found.map((f) => [f.state, f.state === "corrupt" ? f.reason : null])).toEqual([
      ["corrupt", "scope_mismatch"],
      ["corrupt", "duplicate_device"],
      ["corrupt", "not_a_slot"],
    ])
  })

  test("a pending slot's record is shown with its ask, intent, lease fields and claim; a tampered link drops it to corrupt", async () => {
    const dir = pendingSlotPath(root(), ORIGIN, "example")
    const { jwk } = await createDeviceKey(dir, "software", {}, { vault: ORIGIN, tenant: null })
    const record = { v: 1 as const, state: "pending" as const, id: "enr_f1xtR3cP4y5KIRtrusg", code: "ABCD2345", url: `${ORIGIN}/w/example/e/ABCD2345`, origin: ORIGIN, intent: { workspace: "example", team: null }, name: "sam-mac-mini", backend: "software" as const, jwk, session: null, startedAt: "2026-10-28T12:00:00.000Z", expiresAt: "2026-10-28T12:15:00.000Z", hardExpiresAt: null, renewals: 0, legacy: true, claimed: false }
    await writeEnrolmentRecord(dir, record)
    expect(await view(dir)).toMatchObject({ state: "pending", slot: dir, origin: ORIGIN, intent: { workspace: "example", team: null }, enrolment: record.id, backend: "software", startedAt: record.startedAt, expiresAt: record.expiresAt, hardExpiresAt: null, renewals: 0, claimed: false, legacy: true, ask: { kind: "enrol", id: record.id, url: record.url, context: { origin: ORIGIN, workspace: null, device: null } } })
    writeFileSync(join(dir, "enrolment.json"), JSON.stringify({ ...record, url: "https://evil.example/w/example/e/ABCD2345" }), { mode: 0o600 })
    expect(await view(dir)).toMatchObject({ state: "corrupt", reason: "config_invalid" })
  })

  test("two roots never see each other's slots", async () => {
    const other = join(home.path, "other-root")
    await writeConfig(activeSlotPath(other, ORIGIN, WORK.tenant), WORK)
    expect(await listSlots(root())).toEqual([])
    expect(await selectSlot(env)).toMatchObject({ config: null, reason: "none" })
    expect(await selectSlot({ ...env, MEHEN_HOME: other })).toMatchObject({ config: { tenant: WORK.tenant }, reason: "only" })
  })
})

// Rule 0 is unchanged: the marker in the owner's home and the version-3 pin
// decide alone. These add the slot layout's cases to the kept ones below
// (moved from contexts.test.ts).
describe("managed hosts under the slot layout", () => {
  function managed(pinnedDir: (root: string) => string) {
    const owner = realpathSync(home.path)
    chmodSync(owner, 0o700)
    const mehen = join(owner, ".config", "mehen")
    mkdirSync(mehen, { recursive: true, mode: 0o700 })
    chmodSync(join(owner, ".config"), 0o755)
    writeFileSync(join(mehen, "managed-agents"), "", { mode: 0o600 })
    const pinned = pinnedDir(owner)
    mkdirSync(pinned, { recursive: true, mode: 0o700 })
    for (let dir = pinned; dir !== owner; dir = join(dir, "..")) chmodSync(dir, 0o700)
    const scope = { tags: ["work"], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false }
    const pin = { agentDir: join(owner, "agent"), configDir: pinned, origin: ORIGIN, tenant: WORK.tenant, device: WORK.device, scope }
    mkdirSync(pin.agentDir, { mode: 0o700 })
    writeFileSync(join(pinned, "contexts.json"), JSON.stringify({ version: 3, contexts: { work: pin } }), { mode: 0o600 })
    return { owner, pinned, files: { ownerRoot: owner }, env: { ...env, HOME: owner, MEHEN_CONFIG_DIR: pinned, MEHEN_MANAGED_CONTEXT: "work" } }
  }

  test("a pin whose configDir is a layout-2 slot path verifies and is selected", async () => {
    const f = managed((owner) => activeSlotPath(join(owner, "agent-root"), ORIGIN, WORK.tenant))
    await writeConfig(f.pinned, WORK)
    expect(await selectSlot(f.env, { files: f.files })).toMatchObject({ dir: f.pinned, reason: "managed", config: { tenant: WORK.tenant } })
  })

  test("with the marker, MEHEN_WORKSPACES unset, widened or replaced still selects only the pin, and a ceiling without the pin refuses", async () => {
    const f = managed((owner) => activeSlotPath(join(owner, "agent-root"), ORIGIN, WORK.tenant))
    await writeConfig(f.pinned, WORK)
    // Another slot under the same root is never reachable on a managed host.
    await writeConfig(activeSlotPath(join(f.owner, "agent-root"), ORIGIN, "tn_personal0001"), { ...WORK, tenant: "tn_personal0001", device: "dev_personal0001", workspaceSlug: "personal" })
    for (const ceiling of [undefined, "*", "northwind", "northwind,personal"]) {
      expect(await selectSlot({ ...f.env, MEHEN_WORKSPACES: ceiling }, { files: f.files })).toMatchObject({ dir: f.pinned, reason: "managed" })
    }
    for (const ceiling of ["personal", ""]) expect((await failure(() => selectSlot({ ...f.env, MEHEN_WORKSPACES: ceiling }, { files: f.files }))).code).toBe("workspace_not_allowed")
    // env -u of the launcher's variables, or a selector naming the other slot, refuses as before.
    const { MEHEN_CONFIG_DIR: _d, MEHEN_MANAGED_CONTEXT: _k, ...bare } = f.env
    expect((await failure(() => selectSlot(bare, { files: f.files }))).code).toBe("workspace_mismatch")
    expect((await failure(() => selectSlot({ ...f.env, MEHEN_WORKSPACE: "personal" }, { files: f.files }))).code).toBe("workspace_mismatch")
    // A changed HOME does not move the marker the files seam reads.
    expect((await failure(() => selectSlot({ ...bare, HOME: join(f.owner, "elsewhere") }, { files: f.files }))).code).toBe("workspace_mismatch")
  })
})

// One slot that cannot be decoded never hides a healthy sibling.
describe("corrupt siblings", () => {
  test("a config whose vault is not an origin, and a subtree that cannot be listed, are reported corrupt with their paths while the healthy slot is selected", async () => {
    const good = activeSlotPath(root(), ORIGIN, WORK.tenant)
    await writeConfig(good, WORK)
    const bad = join(root(), "workspaces", "broken.example", "tn_broken0000001")
    await writeConfig(bad, { ...WORK, vault: "not a URL", tenant: "tn_broken0000001" })
    const unreadable = join(root(), "pending", "locked.example")
    mkdirSync(unreadable, { recursive: true, mode: 0o700 })
    chmodSync(unreadable, 0o300)
    try {
      expect(await selectSlot({ ...env, MEHEN_WORKSPACE: "northwind" })).toMatchObject({ dir: good, reason: "workspace" })
      expect(await selectSlot(env)).toMatchObject({ dir: good, reason: "only" })
      const found = await listSlots(root())
      expect(found.find((f) => f.dir === bad)).toMatchObject({ state: "corrupt", reason: "config_invalid" })
      expect(found.find((f) => f.dir === unreadable)).toMatchObject({ state: "corrupt", reason: "not_a_slot", detail: expect.stringContaining("cannot be listed") })
      // A selector naming the corrupt slot is workspace_unknown with its path.
      const named = await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "tn_broken0000001" }))
      expect(named.code).toBe("workspace_unknown")
      expect(named.message).toContain(bad)
      expect(named.next?.command).toBe(`mehen workspace forget --slot ${bad}`)
    } finally {
      chmodSync(unreadable, 0o700)
    }
  })
})

// The selection refusal table, exact, through the selection the
// CLI and the MCP server share.
describe("selection refusal table", () => {
  const OTHER: Config = { ...WORK, tenant: "tn_other00000001", device: "dev_other00000001", workspaceSlug: "other", workspaceName: "Other" }
  const manifest = (workspace: string | null) => ({ path: "/repo/mehen.toml", project: "prj_1", workspace, vault: null })
  type Row = { name: string; slots: Config[]; env: Record<string, string>; manifest?: ReturnType<typeof manifest>; waitId?: string; code: CliErrorCode }
  const rows: Row[] = [
    { name: "empty A, no selector", slots: [WORK], env: { MEHEN_WORKSPACES: "" }, code: "workspace_not_allowed" },
    { name: "empty A, a wait id", slots: [WORK], env: { MEHEN_WORKSPACES: "" }, waitId: "apr_x", code: "workspace_not_allowed" },
    { name: "empty A, no slots at all", slots: [], env: { MEHEN_WORKSPACES: "" }, code: "workspace_not_allowed" },
    { name: "unbound manifest under several, before a selector", slots: [WORK, OTHER], env: { MEHEN_WORKSPACE: "northwind" }, manifest: manifest(null), code: "workspace_unbound" },
    { name: "selector outside A", slots: [WORK, OTHER], env: { MEHEN_WORKSPACES: "northwind", MEHEN_WORKSPACE: "other" }, code: "workspace_not_allowed" },
    { name: "selector inside A, manifest outside A", slots: [WORK, OTHER], env: { MEHEN_WORKSPACES: "northwind", MEHEN_WORKSPACE: "northwind" }, manifest: manifest(OTHER.tenant), code: "workspace_not_allowed" },
    { name: "selector and manifest inside A but different", slots: [WORK, OTHER], env: { MEHEN_WORKSPACE: "northwind" }, manifest: manifest(OTHER.tenant), code: "workspace_mismatch" },
    { name: "selector with no slot", slots: [WORK], env: { MEHEN_WORKSPACE: "client" }, code: "workspace_unknown" },
    { name: "manifest with no slot", slots: [WORK], env: {}, manifest: manifest("tn_unknown000001"), code: "workspace_unknown" },
    { name: "wait id nowhere, several slots", slots: [WORK, OTHER], env: {}, waitId: "apr_x", code: "not_found" },
    { name: "wait id nowhere, no slot", slots: [], env: {}, waitId: "apr_x", code: "not_found" },
    { name: "several slots, nothing selects", slots: [WORK, OTHER], env: {}, code: "context_ambiguous" },
  ]
  for (const row of rows) {
    test(row.name, async () => {
      for (const config of row.slots) await writeConfig(activeSlotPath(root(), config.vault, config.tenant), config)
      const refused = await failure(() => selectSlot({ ...env, ...row.env }, { manifest: row.manifest ?? null, ...(row.waitId ? { waitId: row.waitId } : {}) }))
      expect(refused.code).toBe(row.code)
    })
  }

  test("the MCP server and the command line refuse an empty A the same way, before anything is read or sent", async () => {
    await writeConfig(activeSlotPath(root(), ORIGIN, WORK.tenant), WORK)
    const { bindMcpContext } = await import("./mcp.ts")
    await expect(bindMcpContext({ ...env, MEHEN_WORKSPACES: "" }, home.path)).rejects.toMatchObject({ code: "workspace_not_allowed" })
    const freeze = await runJv(["freeze", "--json"], { HOME: home.path, MEHEN_WORKSPACES: "" })
    expect(freeze.code).toBe(2)
    expect(JSON.parse(freeze.stdout)).toMatchObject({ error: "workspace_not_allowed" })
    const mcp = await runJv(["mcp"], { HOME: home.path, MEHEN_WORKSPACES: "" }, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    expect(mcp.code).toBe(2)
    expect(mcp.stdout).toBe("")
  })
})

// Selection through slots.ts, moved here from contexts.test.ts when the
// legacy adapter was deleted (the cutover commit): discovery, precedence,
// the ceiling and their refusals (threat T1), every case before any key is
// read or signature made. The managed-host cases at the end are kept
// unchanged.

const OTHER_ORIGIN = "https://other.example"

function config(patch: Partial<Config> = {}): Config {
  return { vault: ORIGIN, tenant: "tn_personal0001", device: "dev_personal0001", backend: "software", workspaceSlug: "personal", workspaceName: "Personal", ...patch }
}

async function enrol(dir: string, value: Config): Promise<string> {
  await writeConfig(dir, value)
  return dir
}

// The slot a config belongs in under the default root.
function slot(value: Config): string {
  return activeSlotPath(defaultConfigDir(env), value.vault, value.tenant)
}

async function enrolSlot(value: Config): Promise<string> {
  return enrol(slot(value), value)
}

describe("discovery", () => {
  test("every owner-only slot under workspaces/ is an enrolment; a loose or linked directory, or anything at the root, is not", async () => {
    expect(await listActive(env)).toEqual([])
    const personal = await enrolSlot(config())
    const work = await enrolSlot(WORK)
    const found = await listActive(env)
    expect(found.map((c) => c.dir)).toEqual([personal, work])
    expect(found.map((c) => c.config.tenant)).toEqual(["tn_personal0001", "tn_work00000001"])
    // A world-readable or symlinked slot is not one, nor a legacy config at the root.
    const loose = await enrolSlot(config({ tenant: "tn_loose0000001", workspaceSlug: "loose" }))
    chmodSync(loose, 0o755)
    symlinkSync(work, join(work, "..", "tn_linked000001"))
    await enrol(defaultConfigDir(env), config({ tenant: "tn_root00000001" }))
    expect((await listActive(env)).map((c) => c.dir)).toEqual([personal, work])
  })

  test("a corrupt slot is reported and skipped, never selected and never thrown", async () => {
    const personal = await enrolSlot(config())
    const broken = slot(WORK)
    mkdirSync(broken, { recursive: true, mode: 0o700 })
    writeFileSync(join(broken, "config.json"), "{ nope", { mode: 0o600 })
    expect((await listActive(env)).map((c) => c.dir)).toEqual([personal])
    expect((await listSlots(defaultConfigDir(env))).find((f) => f.dir === broken)).toMatchObject({ state: "corrupt", reason: "config_invalid" })
    expect(await selectSlot(env)).toMatchObject({ dir: personal, reason: "only" })
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "tn_work00000001" }))).code).toBe("workspace_unknown")
  })

  test("a selector is a workspace id or a recorded slug, never a name", () => {
    const context = { dir: "/c", config: config() }
    expect(contextMatches(context, "tn_personal0001")).toBe(true)
    expect(contextMatches(context, "personal")).toBe(true)
    // The selector is normalised like a slug (protocol normaliseWorkspaceSlug); a name never matches.
    expect(contextMatches(context, " Personal ")).toBe(true)
    expect(contextMatches(context, "Personal Space")).toBe(false)
    expect(contextMatches(context, "tn_work00000001")).toBe(false)
    expect(contextMatches({ dir: "/c", config: config({ workspaceSlug: undefined, workspaceName: undefined }) }, "personal")).toBe(false)
    expect(workspaceSelector({})).toBeNull()
    expect(workspaceSelector({ MEHEN_WORKSPACE: " Northwind " })).toBe("northwind")
    expect(workspaceSelector({ MEHEN_WORKSPACE: "tn_work00000001" })).toBe("tn_work00000001")
    expect(() => workspaceSelector({ MEHEN_WORKSPACE: "not a slug" })).toThrow(CliError)
    expect(() => workspaceSelector({ MEHEN_WORKSPACE: "legacy-x" })).toThrow(CliError)
  })
})

describe("precedence", () => {
  test("MEHEN_CONFIG_DIR names the root, never a slot: a slot path refuses config_dir_retired; a disagreeing --workspace is unknown there", async () => {
    const elsewhere = join(home.path, "elsewhere")
    const work = await enrol(activeSlotPath(elsewhere, WORK.vault, WORK.tenant), WORK)
    expect(await selectSlot({ ...env, MEHEN_CONFIG_DIR: elsewhere })).toMatchObject({ dir: work, reason: "only", config: { tenant: "tn_work00000001" } })
    expect(await selectSlot({ ...env, MEHEN_CONFIG_DIR: elsewhere, MEHEN_WORKSPACE: "northwind" })).toMatchObject({ dir: work, reason: "workspace" })
    expect((await failure(() => selectSlot({ ...env, MEHEN_CONFIG_DIR: elsewhere, MEHEN_WORKSPACE: "personal" }))).code).toBe("workspace_unknown")
    const retired = await failure(() => selectSlot({ ...env, MEHEN_CONFIG_DIR: work }))
    expect(retired.code).toBe("config_dir_retired")
    expect(exitCodeFor(retired.code)).toBe(EXIT.usage)
    expect(retired.next?.say).toContain(`MEHEN_HOME=${elsewhere}`)
    // The default root is another root: it sees none of these.
    expect(await selectSlot(env)).toMatchObject({ dir: defaultConfigDir(env), config: null, reason: "none" })
  })

  test("--workspace / MEHEN_WORKSPACE picks exactly one slot by id or slug; none is workspace_unknown with the enrol command, several is context_ambiguous", async () => {
    await enrolSlot(config())
    const work = await enrolSlot(WORK)
    expect(await selectSlot({ ...env, MEHEN_WORKSPACE: "northwind" })).toMatchObject({ dir: work, reason: "workspace" })
    expect(await selectSlot({ ...env, MEHEN_WORKSPACE: "tn_work00000001" })).toMatchObject({ dir: work })
    const unknown = await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "client" }))
    expect(unknown.code).toBe("workspace_unknown")
    expect(unknown.next).toMatchObject({ command: "mehen enrol --workspace client" })
    expect(exitCodeFor(unknown.code)).toBe(EXIT.usage)
    // The same workspace id at another origin is a second slot: ambiguous by id.
    await enrolSlot({ ...WORK, vault: OTHER_ORIGIN })
    const ambiguous = await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "tn_work00000001" }))
    expect(ambiguous.code).toBe("context_ambiguous")
    expect(ambiguous.message).toContain(OTHER_ORIGIN)
    expect(ambiguous.next).toMatchObject({ command: "mehen workspace list" })
  })

  test("the cwd manifest's workspace (and vault) selects; a mismatch with the selector refuses; none enrolled is workspace_unknown", async () => {
    await enrolSlot(config())
    const work = await enrolSlot(WORK)
    const manifest = { path: "/repo/mehen.toml", project: "prj_1", workspace: "tn_work00000001", vault: null }
    expect(await selectSlot(env, { manifest })).toMatchObject({ dir: work, reason: "manifest" })
    expect(await selectSlot(env, { manifest: { ...manifest, vault: ORIGIN } })).toMatchObject({ dir: work })
    expect((await failure(() => selectSlot(env, { manifest: { ...manifest, vault: OTHER_ORIGIN } }))).code).toBe("workspace_unknown")
    expect((await failure(() => selectSlot(env, { manifest: { ...manifest, workspace: "tn_unknown000001" } }))).code).toBe("workspace_unknown")
    const conflict = await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "personal" }, { manifest }))
    expect(conflict.code).toBe("workspace_mismatch")
    expect(conflict.message).toContain("/repo/mehen.toml belongs to workspace tn_work00000001")
    // The manifest never adds a trusted origin: a vault it names that no slot uses is unknown, not adopted.
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "northwind" }, { manifest: { ...manifest, vault: OTHER_ORIGIN } }))).code).toBe("workspace_mismatch")
  })

  test("a manifest without a workspace keeps working under one slot and is workspace_unbound under several, before every shortcut", async () => {
    const personal = await enrolSlot(config())
    const unbound = { path: "/repo/mehen.toml", project: "prj_1", workspace: null, vault: null }
    expect(await selectSlot(env, { manifest: unbound })).toMatchObject({ dir: personal })
    await enrolSlot(WORK)
    const refused = await failure(() => selectSlot(env, { manifest: unbound }))
    expect(refused.code).toBe("workspace_unbound")
    expect(refused.next).toMatchObject({ command: "mehen workspace bind" })
    expect(exitCodeFor(refused.code)).toBe(EXIT.usage)
    // Not even an explicit selector excuses it: the checkout must be bound.
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "northwind" }, { manifest: unbound }))).code).toBe("workspace_unbound")
    expect(() => assertManifestAgrees({ dir: personal, config: config() }, unbound, 1)).not.toThrow()
  })

  test("there is no default: the only slot is selected; with several, nothing is guessed", async () => {
    const personal = await enrolSlot(config())
    expect(await selectSlot(env)).toMatchObject({ dir: personal, reason: "only" })
    await enrolSlot(WORK)
    const refused = await failure(() => selectSlot(env))
    expect(refused.code).toBe("context_ambiguous")
    expect(refused.next?.say).toContain("--workspace personal")
    expect(refused.next?.say).toContain("--workspace northwind")
    // A hand-written legacy default-context file selects nothing.
    writeFileSync(join(defaultConfigDir(env), "default-context"), JSON.stringify({ origin: ORIGIN, workspace: "tn_work00000001" }), { mode: 0o600 })
    expect((await failure(() => selectSlot(env))).code).toBe("context_ambiguous")
  })

  test("with nothing enrolled the root is selected unenrolled (or the only pending slot), and a selector is workspace_unknown", async () => {
    expect(await selectSlot(env)).toEqual({ dir: defaultConfigDir(env), config: null, reason: "none", known: 0 })
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACE: "personal" }))).code).toBe("workspace_unknown")
  })
})

describe("the ceiling (MEHEN_WORKSPACES only narrows)", () => {
  test("a selector, a manifest or an enrolment outside the ceiling refuses workspace_not_allowed; inside it selects as usual", async () => {
    await enrolSlot(config())
    const work = await enrolSlot(WORK)
    const narrowed = { ...env, MEHEN_WORKSPACES: "northwind" }
    expect(await selectSlot(narrowed)).toMatchObject({ dir: work, reason: "only" })
    for (const run of [() => selectSlot({ ...narrowed, MEHEN_WORKSPACE: "personal" }), () => selectSlot(narrowed, { manifest: { path: "/repo/mehen.toml", project: "p", workspace: "tn_personal0001", vault: null } })]) {
      const refused = await failure(run)
      expect(refused.code).toBe("workspace_not_allowed")
      expect(exitCodeFor(refused.code)).toBe(EXIT.usage)
      expect(refused.next?.say).toContain("This agent may use only northwind. Only the human can widen MEHEN_WORKSPACES, in the harness that sets it; nothing here can.")
    }
    // The enrolment outside the ceiling refuses the same way, before any key or request.
    const enrolled = await runJv(["enrol", "--workspace", "personal", "--name", "test-mac", "--backend", "software", "--json"], { ...narrowed, MEHEN_VAULT_URL: ORIGIN })
    expect(enrolled.code).toBe(EXIT.usage)
    expect(JSON.parse(enrolled.stdout)).toMatchObject({ error: "workspace_not_allowed", next: { say: expect.stringContaining("This agent may use only northwind. Only the human can widen MEHEN_WORKSPACES, in the harness that sets it; nothing here can.") } })
    expect(existsSync(pendingSlotPath(defaultConfigDir(env), ORIGIN, "personal"))).toBe(false)
    expect((await listActive(narrowed)).map((c) => c.dir)).toEqual([work])
    // Set and empty: nothing at all.
    expect(await listActive({ ...env, MEHEN_WORKSPACES: "" })).toEqual([])
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACES: "", MEHEN_WORKSPACE: "northwind" }))).code).toBe("workspace_not_allowed")
    // `*` is every slot; a bad spelling is usage.
    expect(await listActive({ ...env, MEHEN_WORKSPACES: "*" })).toHaveLength(2)
    expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACES: "not a slug" }))).code).toBe("usage")
  })

  test("a bare entry matching slots at two origins refuses context_ambiguous; an origin-prefixed one selects", async () => {
    const work = await enrolSlot(WORK)
    await enrolSlot({ ...WORK, vault: OTHER_ORIGIN })
    const refused = await failure(() => selectSlot({ ...env, MEHEN_WORKSPACES: "northwind" }))
    expect(refused.code).toBe("context_ambiguous")
    expect(refused.next?.say).toContain("vault.example/northwind")
    expect(await selectSlot({ ...env, MEHEN_WORKSPACES: "vault.example/northwind" })).toMatchObject({ dir: work, reason: "only" })
  })
})

// The ceiling admits an (origin, workspace) pair; an entry or a
// slot at one vault never authorises an enrolment at another.
describe("enrolment under an origin-qualified ceiling", () => {
  test("an absent origin-qualified entry, or a same-slug slot at another origin, refuses the enrolment before any key or request", async () => {
    const vault = new MockVault()
    try {
      const root = defaultConfigDir(env)
      const pending = pendingSlotPath(root, vault.url, "mock-space")
      for (const ceiling of ["vault.example/mock-space", "mock-space"]) {
        if (ceiling === "mock-space") await enrolSlot(config({ tenant: "tn_mockelsewhere1", workspaceSlug: "mock-space", workspaceName: "Mock" }))
        const result = await runJv(["enrol", "--workspace", "mock-space", "--name", "test-mac", "--backend", "software", "--json"], { HOME: home.path, MEHEN_VAULT_URL: vault.url, MEHEN_WORKSPACES: ceiling })
        expect(result.code).toBe(EXIT.usage)
        expect(JSON.parse(result.stdout)).toMatchObject({ error: "workspace_not_allowed", message: `Workspace mock-space at ${vault.url} is outside MEHEN_WORKSPACES.` })
        expect(vault.seen).toEqual([])
        expect(existsSync(pending)).toBe(false)
      }
    } finally {
      vault.stop()
    }
  })
})

describe("fail-closed selection", () => {
  // A present but invalid manifest refuses before selection
  // completes; absence keeps the only slot.
  test("a malformed manifest in the cwd refuses workspace_unbound through status, with no key read and nothing sent; absence keeps the only slot", async () => {
    const vault = new MockVault()
    const repo = await tempDir()
    try {
      await vault.enrolSoftware(join(home.path, ".config", "mehen"))
      const before = vault.seen.length
      for (const broken of [`project = "prj_1"\nworkspace = "tn_other000000001"\nvault = "${vault.url}/forbidden-path"\n`, 'project = "prj_1"\nworkspace = "tn_other000000001"\nvault = "https://user@vault.example"\n', 'project = "prj_1"\n[vars]\nA = ["x"]\n', "{ not toml", 'workspace = "tn_other000000001"\n']) {
        writeFileSync(join(repo.path, "mehen.toml"), broken)
        for (const args of [["status", "--json"], ["fetch", "openai-personal", "GET", "https://api.openai.com/v1/models", "--json"]]) {
          const result = await runJv(args, { HOME: home.path, MEHEN_CONFIG_DIR: "" }, undefined, repo.path)
          expect(result.code).toBe(EXIT.usage)
          expect(JSON.parse(result.stdout)).toMatchObject({ error: "workspace_unbound", next: { command: "mehen workspace bind" } })
        }
      }
      expect(vault.seen.length).toBe(before)
      const { unlinkSync } = await import("node:fs")
      unlinkSync(join(repo.path, "mehen.toml"))
      expect((await runJv(["status", "--json"], { HOME: home.path, MEHEN_CONFIG_DIR: "" }, undefined, repo.path)).code).toBe(EXIT.ok)
    } finally {
      vault.stop()
      await repo.remove()
    }
  })

  // The unbound-manifest rule applies on every path.
  test("an unbound manifest under two slots is refused with an explicit root and a selector, and accepted under one", async () => {
    const personal = await enrolSlot(config())
    const root = defaultConfigDir(env)
    const unbound = { path: "/repo/mehen.toml", project: "prj_1", workspace: null, vault: null }
    expect(await selectSlot({ ...env, MEHEN_CONFIG_DIR: root }, { manifest: unbound })).toMatchObject({ dir: personal, known: 1 })
    await enrolSlot(WORK)
    for (const selector of ["personal", "northwind"]) {
      const refused = await failure(() => selectSlot({ ...env, MEHEN_CONFIG_DIR: root, MEHEN_WORKSPACE: selector }, { manifest: unbound }))
      expect(refused.code).toBe("workspace_unbound")
      expect(refused.next).toMatchObject({ command: "mehen workspace bind" })
    }
    expect((await selectSlot({ ...env, MEHEN_WORKSPACE: "personal" }, { manifest: null })).known).toBe(2)
  })

  // Two enrolments of one workspace are never resolved to the first found.
  test("the same workspace at two origins is context_ambiguous without a selector, and a duplicate device slot is never selected", async () => {
    await enrolSlot(config())
    await enrolSlot(config({ vault: OTHER_ORIGIN, device: "dev_other00000001" }))
    const refused = await failure(() => selectSlot(env))
    expect(refused.code).toBe("context_ambiguous")
    expect(refused.message).toContain("dev_other00000001")
    const twin = join(slot(config()) + ".duplicate-dev_twin00000001")
    await enrol(twin, config({ device: "dev_twin00000001" }))
    expect((await listActive(env)).map((c) => c.config.device)).not.toContain("dev_twin00000001")
    expect((await listSlots(defaultConfigDir(env))).find((f) => f.dir === twin)).toMatchObject({ state: "corrupt", reason: "duplicate_device" })
  })

  // Mehen wait's one-slot-records-it stage, after the explicit rules.
  test("a wait id recorded in exactly one slot selects it; a pending slot counts; two hits or a foreign identity refuse; an explicit selector wins", async () => {
    const base = await enrolSlot(config())
    const work = await enrolSlot(WORK)
    const { addLedgerEntry } = await import("./ledger.ts")
    const { approvalAsk, enrolAsk, askUrl } = await import("./ask.ts")
    const scopeOf = (c: Config) => ({ vaultUrl: c.vault, workspace: c.tenant, device: c.device, workspaceSlug: c.workspaceSlug ?? null })
    const ask = (slug: string, id: string) => approvalAsk({ id, url: askUrl(`${ORIGIN}/w/${slug}/a/${id}`, { vaultUrl: ORIGIN, workspaceSlug: slug })!.url, summary: "s", bindingCode: null, expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } })
    await addLedgerEntry(work, scopeOf(WORK), { ask: ask("northwind", "apr_unique") })
    expect(await selectSlot(env, { waitId: "apr_unique" })).toMatchObject({ dir: work, reason: "ledger" })
    // An id nowhere, with two slots and no selector: not_found.
    expect((await failure(() => selectSlot(env, { waitId: "apr_nowhere" }))).code).toBe("not_found")
    // An explicit selector outranks the ledger stage.
    expect(await selectSlot({ ...env, MEHEN_WORKSPACE: "personal" }, { waitId: "apr_unique" })).toMatchObject({ dir: base, reason: "workspace" })
    // The same id in two slots is ambiguous before anything is signed.
    await addLedgerEntry(base, scopeOf(config()), { ask: ask("personal", "apr_unique") })
    expect((await failure(() => selectSlot(env, { waitId: "apr_unique" }))).code).toBe("context_ambiguous")
    // A pending slot (a ledger enrol entry, no config) is a hit for its enr_ id.
    const pending = pendingSlotPath(defaultConfigDir(env), ORIGIN, "client")
    mkdirSync(pending, { recursive: true, mode: 0o700 })
    const jwk = { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }
    const enrolment = enrolAsk({ id: "enr_pending00001", url: askUrl(`${ORIGIN}/w/client/e/ABCD2345`, { vaultUrl: ORIGIN, workspaceSlug: "client" })!.url, name: "n", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } })
    await addLedgerEntry(pending, { vaultUrl: ORIGIN, workspace: null, device: null }, { ask: enrolment, enrol: { code: "ABCD2345", name: "n", backend: "software", jwk, workspace: "client", team: null } })
    expect(await selectSlot({ ...env, MEHEN_VAULT_URL: ORIGIN }, { waitId: "enr_pending00001" })).toMatchObject({ dir: pending, config: null, reason: "ledger" })
    // An entry of the same id under another device's identity in a slot is not that slot's.
    const stray = await enrolSlot(config({ tenant: "tn_stray00000001", device: "dev_stray00000001", workspaceSlug: "stray", workspaceName: "Stray" }))
    await Bun.write(join(stray, "ledger.json"), JSON.stringify({ entries: [{ ask: ask("stray", "apr_foreign"), createdAt: new Date().toISOString(), origin: ORIGIN, workspace: "tn_stray00000001", device: "dev_other00000001", slug: null, command: null }] }))
    expect((await failure(() => selectSlot(env, { waitId: "apr_foreign" }))).code).toBe("not_found")
    expect(await selectSlot({ ...env, MEHEN_WORKSPACES: "stray" }, { waitId: "apr_foreign" })).toMatchObject({ dir: stray, reason: "only" })
  })
})

// The wait id rule: only slots inside A
// count; a miss asks the one active slot of A, or is not_found.
describe("a wait id with no local hit", () => {
  test("with several active slots in A it is not_found (exit 1) and nothing is signed; a slot outside A that records it is never polled", async () => {
    const vault = new MockVault()
    try {
      const root = defaultConfigDir(env)
      const a = await vault.enrolSoftware(root)
      const b = await vault.enrolSoftware(root, { config: { tenant: "tn_second00000001", workspaceSlug: "second", workspaceName: "Second" } })
      const several = await runJv(["wait", "apr_missing", "--timeout", "0", "--json"], { HOME: home.path, MEHEN_VAULT_URL: vault.url })
      expect(several.code).toBe(EXIT.error)
      expect(JSON.parse(several.stdout)).toMatchObject({ error: "not_found", next: { command: "mehen pending" } })
      expect(vault.seen).toEqual([])
      // The id is recorded only in the slot outside the ceiling: A's one slot is asked, never that one.
      const { addLedgerEntry } = await import("./ledger.ts")
      const { approvalAsk, askUrl } = await import("./ask.ts")
      const link = askUrl(`${vault.url}/w/second/a/apr_outside`, { vaultUrl: vault.url, workspaceSlug: "second" })!
      await addLedgerEntry(vault.slotDir(root, "tn_second00000001"), { vaultUrl: vault.url, workspace: "tn_second00000001", device: b, workspaceSlug: "second" }, { ask: approvalAsk({ id: "apr_outside", url: link.url, summary: "s", bindingCode: null, expiresAt: new Date(Date.now() + 600_000).toISOString(), requestedBy: { device: "d", session: null } }) })
      const narrowed = { HOME: home.path, MEHEN_VAULT_URL: vault.url, MEHEN_WORKSPACES: "mock-space" }
      expect(await selectSlot({ ...narrowed, HOME: home.path }, { waitId: "apr_outside" })).toMatchObject({ dir: vault.slotDir(root), reason: "only" })
      await runJv(["wait", "apr_outside", "--timeout", "0", "--json"], narrowed)
      expect(vault.seen.length).toBeGreaterThan(0)
      for (const call of vault.seen) expect(call.claims.dev).toBe(a)
      // With no active slot in A, a miss is not_found too.
      expect((await failure(() => selectSlot({ ...env, MEHEN_WORKSPACES: "absent-space" }, { waitId: "apr_outside" }))).code).toBe("not_found")
    } finally {
      vault.stop()
    }
  })
})

describe("active origin and key scope (design 15.6, 9.5)", () => {
  test("MEHEN_VAULT_URL naming another origin than the selected slot refuses; the same origin in another spelling is fine", async () => {
    await enrolSlot(config())
    expect(() => assertVaultUrlAgrees({ MEHEN_VAULT_URL: `${ORIGIN}/` }, config())).not.toThrow()
    expect(() => assertVaultUrlAgrees({}, config())).not.toThrow()
    expect(() => assertVaultUrlAgrees({ MEHEN_VAULT_URL: OTHER_ORIGIN }, config())).toThrow(CliError)
    const refused = await failure(() => selectSlot({ ...env, MEHEN_VAULT_URL: OTHER_ORIGIN }))
    expect(refused.code).toBe("workspace_mismatch")
    expect(refused.message).toBe(`MEHEN_VAULT_URL is ${OTHER_ORIGIN}, but this context is enrolled with ${ORIGIN}.`)
    // Non-canonical origins are usage errors before anything else.
    for (const url of [`${ORIGIN}/path`, "https://user@vault.example", `${ORIGIN}?x`, "http://vault.example"]) {
      expect((await failure(() => selectSlot({ ...env, MEHEN_VAULT_URL: url }))).code).toBe("usage")
    }
  })

  test("a key scope naming another origin or workspace refuses before the key is read", async () => {
    const dir = await enrolSlot(config())
    for (const scope of [{ vault: OTHER_ORIGIN, tenant: "tn_personal0001" }, { vault: ORIGIN, tenant: "tn_work00000001" }]) {
      await writeKeyScope(dir, "software", scope)
      const refused = await failure(() => openSession(env, { manifest: null }))
      expect(refused.code).toBe("workspace_mismatch")
      expect(refused.message).toContain("The device key in")
    }
    // A matching scope, or one from before the workspace was known, passes on to the key (which is absent here).
    for (const scope of [{ vault: ORIGIN, tenant: "tn_personal0001" }, { vault: ORIGIN, tenant: null }]) {
      await writeKeyScope(dir, "software", scope)
      expect((await failure(() => openSession(env, { manifest: null }))).code).toBe("unauthenticated")
    }
  })
})

// The error renderer's view of the vault (moved from config.test.ts's
// knownVaultUrl when the cutover deleted it): never throws.
describe("knownVault", () => {
  test("follows MEHEN_VAULT_URL, then the only slot's vault and slug, and is null when neither is usable", async () => {
    expect(await knownVault(env)).toEqual({ vaultUrl: DEFAULT_VAULT_URL, workspaceSlug: null })
    expect(await knownVault({ ...env, MEHEN_VAULT_URL: "https://vault.example/" })).toEqual({ vaultUrl: ORIGIN, workspaceSlug: null })
    await enrolSlot(WORK)
    expect(await knownVault(env)).toEqual({ vaultUrl: ORIGIN, workspaceSlug: "northwind" })
    expect(await knownVault({ ...env, MEHEN_VAULT_URL: "not a url" })).toBeNull()
    // A selection refusal (several slots, nothing deciding) still answers with the default.
    await enrolSlot(config())
    expect(await knownVault(env)).toEqual({ vaultUrl: DEFAULT_VAULT_URL, workspaceSlug: null })
  })
})

describe("the local vault mehen up set up", () => {
  function localVault(origin = "http://localhost:7787"): void {
    mkdirSync(root(), { recursive: true, mode: 0o700 })
    writeFileSync(join(root(), "local-vault.json"), JSON.stringify({ origin, data: join(home.path, "vault"), port: 7787, service: "process" }), { mode: 0o600 })
  }

  test("is the vault links are checked against until MEHEN_VAULT_URL or an enrolment names another", async () => {
    localVault()
    expect(await knownVault(env)).toEqual({ vaultUrl: "http://localhost:7787", workspaceSlug: null })
    expect(await knownVault({ ...env, MEHEN_VAULT_URL: "https://vault.example" })).toEqual({ vaultUrl: ORIGIN, workspaceSlug: null })
    await enrolSlot(WORK)
    expect(await knownVault(env)).toEqual({ vaultUrl: ORIGIN, workspaceSlug: "northwind" })
  })

  test("is the vault an unknown enrolment is said to be missing from", async () => {
    localVault()
    const refused = await failure(() => selectSlot(env, { waitId: "enr_unknown" }))
    expect(refused).toMatchObject({ code: "not_found", message: "No open enrolment enr_unknown is recorded on this machine for http://localhost:7787." })
    const overridden = await failure(() => selectSlot({ ...env, MEHEN_VAULT_URL: "https://vault.example" }, { waitId: "enr_unknown" }))
    expect(overridden.message).toBe(`No open enrolment enr_unknown is recorded on this machine for ${ORIGIN}.`)
  })
})

describe("managed hosts (WORKLOAD 2.2)", () => {
  // The marker and map live under an owner-only root; the test's root
  // stands in for the passwd home through the files seam.
  function managedFixture() {
    const root = realpathSync(home.path)
    chmodSync(root, 0o700)
    const mehen = join(root, ".config", "mehen")
    mkdirSync(mehen, { recursive: true, mode: 0o700 })
    chmodSync(join(root, ".config"), 0o755)
    writeFileSync(join(mehen, "managed-agents"), "", { mode: 0o600 })
    const pinned = join(root, "mehen-work")
    mkdirSync(pinned, { mode: 0o700 })
    const scope = { tags: ["work"], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false }
    const pin = { agentDir: join(root, "agent"), configDir: pinned, origin: ORIGIN, tenant: "tn_work00000001", device: "dev_work00000001", scope }
    mkdirSync(pin.agentDir, { mode: 0o700 })
    writeFileSync(join(pinned, "contexts.json"), JSON.stringify({ version: 3, contexts: { work: pin } }), { mode: 0o600 })
    return { root, pinned, pin, files: { ownerRoot: root } }
  }

  test("only the launcher's pinned MEHEN_CONFIG_DIR, verified against its own pin, is selected; every implicit rule refuses", async () => {
    const f = managedFixture()
    await writeConfig(f.pinned, WORK)
    const managed = { ...env, HOME: f.root, MEHEN_CONFIG_DIR: f.pinned, MEHEN_MANAGED_CONTEXT: "work" }
    expect(await selectSlot(managed, { files: f.files })).toMatchObject({ dir: f.pinned, reason: "managed", config: { tenant: "tn_work00000001" } })
    // Same workspace named explicitly is fine; another refuses.
    expect(await selectSlot({ ...managed, MEHEN_WORKSPACE: "tn_work00000001" }, { files: f.files })).toMatchObject({ dir: f.pinned })
    for (const broken of [{ MEHEN_CONFIG_DIR: undefined }, { MEHEN_CONFIG_DIR: "" }, { MEHEN_MANAGED_CONTEXT: undefined }, { MEHEN_MANAGED_CONTEXT: "personal" }, { MEHEN_WORKSPACE: "personal" }, { MEHEN_VAULT_URL: OTHER_ORIGIN }, { MEHEN_CONFIG_DIR: join(f.root, ".config", "mehen") }]) {
      const refused = await failure(() => selectSlot({ ...managed, ...broken }, { files: f.files }))
      expect(refused.code).toBe("workspace_mismatch")
    }
    // A default context, a manifest or discovery cannot pick another context on a managed host.
    await enrol(join(f.root, ".config", "mehen", "contexts", "personal"), config())
    const { MEHEN_CONFIG_DIR: _dir, MEHEN_MANAGED_CONTEXT: _key, ...implicit } = managed
    expect((await failure(() => selectSlot(implicit, { files: f.files }))).code).toBe("workspace_mismatch")
    expect((await failure(() => selectSlot(managed, { files: f.files, manifest: { path: "/repo/mehen.toml", project: "p", workspace: "tn_personal0001", vault: null } }))).code).toBe("workspace_mismatch")
  })

  test("a pinned directory whose enrolment is not the pin's identity refuses", async () => {
    const f = managedFixture()
    await writeConfig(f.pinned, { ...WORK, device: "dev_other00000001" })
    const managed = { ...env, HOME: f.root, MEHEN_CONFIG_DIR: f.pinned, MEHEN_MANAGED_CONTEXT: "work" }
    const refused = await failure(() => selectSlot(managed, { files: f.files }))
    expect(refused.code).toBe("workspace_mismatch")
    expect(refused.message).toContain("Vault pin verification failed")
  })
})
