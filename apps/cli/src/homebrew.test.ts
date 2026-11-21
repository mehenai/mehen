import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { realpathSync } from "node:fs"
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { homebrewInstall, launchPath } from "./homebrew.ts"
import { brewPrefix } from "./testing/brew-prefix.ts"

let root: string
beforeEach(async () => {
  root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-brew-")))
})
afterEach(async () => rm(root, { recursive: true, force: true }))

describe("homebrewInstall", () => {
  test("a keg, reached through any of brew's links, is Homebrew's; the stable path is opt/mehen", async () => {
    const brew = await brewPrefix(root)
    for (const path of [brew.keg, brew.bin, brew.opt]) {
      expect(homebrewInstall(path, {})).toEqual({ prefix: brew.prefix, version: "0.5.0", keg: join(brew.prefix, "Cellar", "mehen", "0.5.0"), stable: brew.opt })
      expect(launchPath(path, {})).toBe(brew.opt)
    }
  })

  test("without opt/mehen, or with opt/mehen on another version, the stable path is bin/mehen", async () => {
    const missing = await brewPrefix(join(root, "a"), "0.5.0", { opt: false })
    expect(homebrewInstall(missing.keg, {})?.stable).toBe(missing.bin)
    const other = await brewPrefix(join(root, "b"), "0.5.0", { opt: "0.4.9" })
    expect(homebrewInstall(other.keg, {})?.stable).toBe(other.bin)
  })

  test("a revision keg such as 0.5.0_1 is a version", async () => {
    const brew = await brewPrefix(root, "0.5.0_1")
    expect(homebrewInstall(brew.keg, {})).toMatchObject({ version: "0.5.0_1", stable: brew.opt })
  })

  test("anything else is not Homebrew's, whatever HOMEBREW_PREFIX says, and keeps its own path", async () => {
    const brew = await brewPrefix(root)
    const local = join(root, ".local", "bin", "mehen")
    await mkdir(join(root, ".local", "bin"), { recursive: true })
    await writeFile(local, "#!/bin/sh\n", { mode: 0o755 })
    const linked = join(root, "linked-mehen")
    await symlink(local, linked)
    for (const path of [local, linked]) {
      expect(homebrewInstall(path, { HOMEBREW_PREFIX: brew.prefix })).toBeNull()
      expect(launchPath(path, { HOMEBREW_PREFIX: brew.prefix })).toBe(path)
    }
    // Shaped like a keg but under no Cellar, and no HOMEBREW_CELLAR names it.
    const shaped = join(root, "kegs", "mehen", "0.5.0", "bin", "mehen")
    await mkdir(join(root, "kegs", "mehen", "0.5.0", "bin"), { recursive: true })
    await writeFile(shaped, "#!/bin/sh\n", { mode: 0o755 })
    expect(homebrewInstall(shaped, { HOMEBREW_PREFIX: brew.prefix })).toBeNull()
    // Another formula's keg, or another file in mehen's keg.
    for (const [path, dir] of [[join(root, "homebrew", "Cellar", "other", "1.0", "bin", "mehen"), join(root, "homebrew", "Cellar", "other", "1.0", "bin")], [join(root, "homebrew", "Cellar", "mehen", "0.5.0", "libexec", "mehen"), join(root, "homebrew", "Cellar", "mehen", "0.5.0", "libexec")]] as const) {
      await mkdir(dir, { recursive: true })
      await writeFile(path, "#!/bin/sh\n", { mode: 0o755 })
      expect(homebrewInstall(path, {})).toBeNull()
    }
  })

  test("a cellar outside the prefix counts only where HOMEBREW_PREFIX and HOMEBREW_CELLAR name it", async () => {
    const cellar = join(root, "kegs")
    const brew = await brewPrefix(root, "0.5.0", { cellar })
    expect(homebrewInstall(brew.keg, {})).toBeNull()
    expect(homebrewInstall(brew.keg, { HOMEBREW_PREFIX: brew.prefix, HOMEBREW_CELLAR: cellar })).toMatchObject({ prefix: brew.prefix, stable: brew.opt })
  })

  test("HOMEBREW_PREFIX picks the prefix whose opt/mehen is this keg", async () => {
    const brew = await brewPrefix(root)
    expect(homebrewInstall(brew.keg, { HOMEBREW_PREFIX: join(root, "elsewhere") })?.stable).toBe(brew.opt)
  })
})
