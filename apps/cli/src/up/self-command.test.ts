import { afterEach, beforeEach, expect, test } from "bun:test"
import { realpathSync } from "node:fs"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { brewPrefix } from "../testing/brew-prefix.ts"
import { selfCommand } from "./index.ts"
import { launchdPlist, systemdUnit } from "./service.ts"

let root: string
beforeEach(async () => {
  root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-up-brew-")))
})
afterEach(async () => rm(root, { recursive: true, force: true }))

// The vault's service outlives any one version: for a Homebrew keg it runs
// the opt/mehen link, which `brew upgrade` moves to the new keg, so the
// service keeps starting after the old keg is deleted.
test("the vault's service runs Homebrew's opt/mehen link for a keg, and the installed binary otherwise", async () => {
  const brew = await brewPrefix(root)
  const command = selfCommand({ MEHEN_SELF_EXECUTABLE: brew.bin })
  expect(command).toEqual([brew.opt])
  const plan = { kind: "launchd" as const, command: [...command, "serve", "--port", "7787", "--data", join(root, "vault")], dataDir: join(root, "vault"), home: root, logFile: join(root, "vault", "serve.log") }
  for (const unit of [launchdPlist(plan), systemdUnit({ ...plan, kind: "systemd" })]) {
    expect(unit).toContain(brew.opt)
    expect(unit).not.toContain("Cellar")
  }
  expect(selfCommand({ MEHEN_SELF_EXECUTABLE: join(root, "plain", "mehen") })).toEqual([join(root, "plain", "mehen")])
  expect(selfCommand({})).toEqual([process.execPath, Bun.main])
})
