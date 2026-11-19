// The home resolver and the managed-host marker
// read through it: every refusal happens before migration, key reads or
// network, in a temporary HOME so nothing of this user's own configuration
// is touched.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { CliError, exitCodeFor } from "./errors.ts"
import { activeSlotPath, assertSafeRoot, ensureSafeRoot, managedHost, originKey, pendingSlotPath, resolveHome } from "./home.ts"
import { pendingLockPath, withSlotLocks } from "./slot-lock.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

let home: { path: string; remove(): Promise<void> }

beforeEach(async () => {
  home = await tempDir()
})
afterEach(() => home.remove())

function refusal(run: () => unknown): CliError {
  try {
    run()
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a CliError")
}

describe("resolveHome", () => {
  test("MEHEN_HOME wins; MEHEN_CONFIG_DIR is an alias of the root; neither is ~/.config/mehen of HOME", () => {
    const root = join(home.path, "root")
    expect(resolveHome({ HOME: home.path, MEHEN_HOME: root })).toEqual({ root, source: "MEHEN_HOME" })
    expect(resolveHome({ HOME: home.path, MEHEN_CONFIG_DIR: root })).toEqual({ root, source: "MEHEN_CONFIG_DIR" })
    expect(resolveHome({ HOME: home.path, MEHEN_HOME: root, MEHEN_CONFIG_DIR: `${root}/` })).toEqual({ root, source: "MEHEN_HOME" })
    expect(resolveHome({ HOME: home.path })).toEqual({ root: join(home.path, ".config", "mehen"), source: "default" })
    // A changed HOME is another default root: organisation, not protection.
    expect(resolveHome({ HOME: join(home.path, "other") }).root).toBe(join(home.path, "other", ".config", "mehen"))
  })

  test("a relative or NUL-bearing MEHEN_HOME is usage; MEHEN_HOME and MEHEN_CONFIG_DIR that disagree are config_dir_retired", () => {
    for (const value of ["relative/root", `${home.path}/a\0b`]) expect(refusal(() => resolveHome({ HOME: home.path, MEHEN_HOME: value })).code).toBe("usage")
    const disagree = refusal(() => resolveHome({ HOME: home.path, MEHEN_HOME: join(home.path, "a"), MEHEN_CONFIG_DIR: join(home.path, "b") }))
    expect(disagree.code).toBe("config_dir_retired")
    expect(exitCodeFor(disagree.code)).toBe(EXIT.usage)
    expect(disagree.next?.say).toContain("Set MEHEN_HOME only")
  })

  test("MEHEN_CONFIG_DIR naming a slot, a pending slot, a legacy context or a directory with enrolment.json is config_dir_retired with the exact MEHEN_HOME", () => {
    const root = join(home.path, ".config", "mehen")
    const cases: [string, string][] = [
      [activeSlotPath(root, "https://app.mehen.dev", "tn_Nw4dQ2m8xPLsJyKb3Rtvz"), "MEHEN_WORKSPACES=tn_Nw4dQ2m8xPLsJyKb3Rtvz"],
      [pendingSlotPath(root, "https://app.mehen.dev", "example"), "MEHEN_WORKSPACES=example"],
      [join(root, "contexts", "example"), `MEHEN_HOME=${root}`],
    ]
    for (const [path, says] of cases) {
      const retired = refusal(() => resolveHome({ HOME: home.path, MEHEN_CONFIG_DIR: path }))
      expect(retired.code).toBe("config_dir_retired")
      expect(retired.next?.say).toContain(`MEHEN_HOME=${root}`)
      expect(retired.next?.say).toContain(says)
    }
    const holding = join(home.path, "holding")
    mkdirSync(holding, { mode: 0o700 })
    writeFileSync(join(holding, "enrolment.json"), "{}", { mode: 0o600 })
    expect(refusal(() => resolveHome({ HOME: home.path, MEHEN_CONFIG_DIR: holding })).code).toBe("config_dir_retired")
  })

  test("MEHEN_MANAGED_CONTEXT without the managed-host marker is workspace_mismatch", () => {
    const root = realpathSync(home.path)
    chmodSync(root, 0o700)
    const claimed = refusal(() => resolveHome({ HOME: root, MEHEN_MANAGED_CONTEXT: "work" }, { files: { ownerRoot: root } }))
    expect(claimed.code).toBe("workspace_mismatch")
    expect(claimed.message).toContain("no managed-host marker")
  })

  test("the slot paths of a root are keyed by origin: the host for https, host_port for another port, http_<host>_<port> for loopback", () => {
    expect(originKey("https://app.mehen.dev")).toBe("app.mehen.dev")
    expect(originKey("https://app.mehen.dev:443")).toBe("app.mehen.dev")
    expect(originKey("https://vault.example:8443")).toBe("vault.example_8443")
    expect(originKey("http://127.0.0.1:8787")).toBe("http_127.0.0.1_8787")
    expect(originKey("http://localhost")).toBe("http_localhost_80")
    expect(originKey("http://[::1]:8787")).toBe("http_--1_8787")
    expect(activeSlotPath("/r", "https://app.mehen.dev", "tn_x")).toBe("/r/workspaces/app.mehen.dev/tn_x")
    expect(pendingSlotPath("/r", "http://127.0.0.1:8787", "acme")).toBe("/r/pending/http_127.0.0.1_8787/acme")
  })
})

// The marker walk (agent-profiles.ts, unchanged) refuses a home below a
// directory others can write. That refusal used to surface as `internal`
// "Vault pin verification failed"; it is the named local refusal
// key_insecure (exit 6) with the unsafe path and a next step.
describe("the managed-host marker under an unsafe ancestor", () => {
  test("a world-writable ancestor of the home is key_insecure naming it, through the resolver and through mehen", async () => {
    const shared = join(realpathSync(home.path), "shared")
    mkdirSync(shared, { mode: 0o700 })
    chmodSync(shared, 0o777)
    const user = join(shared, "user")
    mkdirSync(user, { mode: 0o700 })
    try {
      const refused = refusal(() => managedHost({ ownerRoot: user }))
      expect(refused.code).toBe("key_insecure")
      expect(exitCodeFor(refused.code)).toBe(EXIT.identity)
      expect(refused.message).toContain(`${shared} is not a directory only this user`)
      expect(refused.next?.say).toContain("Put MEHEN_HOME (or HOME) under a directory only this user can write")
      expect(refusal(() => resolveHome({ HOME: user }, { files: { ownerRoot: user } })).code).toBe("key_insecure")
      // Through the command line: never `internal`, never the pin wording.
      for (const args of [["status", "--json"], ["workspace", "list", "--json"]]) {
        const result = await runJv(args, { HOME: user })
        expect(result.code).toBe(EXIT.identity)
        const body = JSON.parse(result.stdout) as { error: string; message: string; next: { say: string } }
        expect(body.error).toBe("key_insecure")
        expect(body.message).toContain(shared)
        expect(body.message).not.toContain("Vault pin verification failed")
        expect(body.next.say).toContain("not below a world-writable one such as /tmp")
      }
    } finally {
      chmodSync(shared, 0o700)
    }
  })

  test("a root-owned sticky ancestor (the system's /tmp) stays refused: the sticky allowance is the installer's only", () => {
    const user = mkdtempSync(join("/tmp", "mehen-sticky-"))
    try {
      chmodSync(user, 0o700)
      const refused = refusal(() => managedHost({ ownerRoot: user }))
      expect(refused.code).toBe("key_insecure")
      expect(refused.message).toContain(`${realpathSync("/tmp")} is not a directory only this user`)
    } finally {
      rmSync(user, { recursive: true, force: true })
    }
  })

  test("a safe home with no marker is not managed, and a marker with a loose mode is refused by name, not as internal", () => {
    const root = realpathSync(home.path)
    chmodSync(root, 0o700)
    expect(managedHost({ ownerRoot: root })).toBe(false)
    mkdirSync(join(root, ".config", "mehen"), { recursive: true, mode: 0o700 })
    chmodSync(join(root, ".config"), 0o755)
    writeFileSync(join(root, ".config", "mehen", "managed-agents"), "", { mode: 0o644 })
    const refused = refusal(() => managedHost({ ownerRoot: root }))
    expect(refused.code).toBe("key_insecure")
    expect(refused.message).toContain(join(root, ".config", "mehen", "managed-agents"))
  })
})

// G0 F-1: a machine with no config root yet. The first command that takes a
// lock creates the root 0700 (and a missing ~/.config with it) through the
// same ancestor rules the migration walk uses; looking creates nothing.
describe("the first command on a fresh HOME creates the config root", () => {
  const ORIGIN = "https://app.mehen.dev"
  const mode = (path: string) => lstatSync(path).mode & 0o777

  test("a HOME with nothing: the first lock creates ~/.config and the root private to this user", async () => {
    const user = realpathSync(home.path)
    const root = join(user, ".config", "mehen")
    assertSafeRoot(root)
    expect(existsSync(join(user, ".config"))).toBe(false)
    await withSlotLocks([pendingLockPath(root, ORIGIN, "acme")], async () => undefined)
    for (const dir of [join(user, ".config"), root, join(root, "locks")]) {
      expect(lstatSync(dir).isDirectory()).toBe(true)
      expect(lstatSync(dir).uid).toBe(process.getuid?.() ?? -1)
      expect(mode(dir)).toBe(0o700)
    }
  })

  test("a HOME with an empty ~/.config (the usual 0755): the root is created 0700 and ~/.config is left as it is", async () => {
    const user = realpathSync(home.path)
    mkdirSync(join(user, ".config"), { mode: 0o755 })
    chmodSync(join(user, ".config"), 0o755)
    const root = join(user, ".config", "mehen")
    await withSlotLocks([pendingLockPath(root, ORIGIN, "acme")], async () => undefined)
    expect(mode(root)).toBe(0o700)
    expect(mode(join(user, ".config"))).toBe(0o755)
  })

  test("a group-writable ~/.config is refused key_insecure naming it, and nothing is created under it", async () => {
    const user = realpathSync(home.path)
    mkdirSync(join(user, ".config"), { mode: 0o700 })
    chmodSync(join(user, ".config"), 0o775)
    const root = join(user, ".config", "mehen")
    try {
      const refused = refusal(() => ensureSafeRoot(root))
      expect(refused.code).toBe("key_insecure")
      expect(refused.message).toContain(`${join(user, ".config")} is writable by other users`)
      await expect(withSlotLocks([pendingLockPath(root, ORIGIN, "acme")], async () => undefined)).rejects.toMatchObject({ code: "key_insecure" })
      expect(existsSync(root)).toBe(false)
    } finally {
      chmodSync(join(user, ".config"), 0o700)
    }
  })

  test("a ~/.config that is a symbolic link is refused key_insecure naming it, and nothing is created at its target", async () => {
    const user = realpathSync(home.path)
    mkdirSync(join(user, "elsewhere"), { mode: 0o700 })
    symlinkSync(join(user, "elsewhere"), join(user, ".config"))
    const root = join(user, ".config", "mehen")
    const refused = refusal(() => ensureSafeRoot(root))
    expect(refused.code).toBe("key_insecure")
    expect(refused.message).toContain(`${join(user, ".config")} is a symbolic link`)
    await expect(withSlotLocks([pendingLockPath(root, ORIGIN, "acme")], async () => undefined)).rejects.toMatchObject({ code: "key_insecure" })
    expect(existsSync(join(user, "elsewhere", "mehen"))).toBe(false)
  })

  test("a root that cannot be created is the named refusal, never internal", () => {
    const user = realpathSync(home.path)
    mkdirSync(join(user, ".config"), { mode: 0o500 })
    try {
      const refused = refusal(() => ensureSafeRoot(join(user, ".config", "mehen")))
      expect(refused.code).toBe("key_insecure")
      expect(refused.message).toContain(`${join(user, ".config", "mehen")} cannot be created (EACCES)`)
    } finally {
      chmodSync(join(user, ".config"), 0o700)
    }
  })
})
