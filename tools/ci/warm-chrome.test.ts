import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { chromeInstallDir, readAhead } from "./warm-chrome.ts"

let root: string
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "mehen-warm-"))
})
afterEach(() => rm(root, { recursive: true, force: true }))

async function install(dir: string, binary: string): Promise<string> {
  await mkdir(dir, { recursive: true })
  await writeFile(join(dir, "icudtl.dat"), "icu")
  await writeFile(join(dir, binary), "\x7fELF")
  await chmod(join(dir, binary), 0o755)
  return join(dir, binary)
}

describe("chromeInstallDir", () => {
  test("Google Chrome: the symlinked name resolves to its own directory", async () => {
    const chrome = await install(join(root, "opt/google/chrome"), "google-chrome")
    await mkdir(join(root, "usr/bin"), { recursive: true })
    await symlink(chrome, join(root, "usr/bin/google-chrome"))
    expect(chromeInstallDir(join(root, "usr/bin/google-chrome"), [])).toBe(join(root, "opt/google/chrome"))
  })

  test("Debian's chromium: a wrapper script in /usr/bin points to /usr/lib/chromium, never /usr/bin itself", async () => {
    await mkdir(join(root, "usr/bin"), { recursive: true })
    await writeFile(join(root, "usr/bin/chromium"), "#!/bin/sh\nexec /usr/lib/chromium/chromium \"$@\"\n")
    await install(join(root, "usr/lib/chromium"), "chromium")
    expect(chromeInstallDir(join(root, "usr/bin/chromium"), [join(root, "usr/lib/chromium"), join(root, "usr/lib/chromium-browser")])).toBe(join(root, "usr/lib/chromium"))
  })

  test("an unknown layout is skipped, not read", async () => {
    await mkdir(join(root, "usr/bin"), { recursive: true })
    await writeFile(join(root, "usr/bin/chromium"), "#!/bin/sh\nexec snap run chromium\n")
    expect(chromeInstallDir(join(root, "usr/bin/chromium"), [join(root, "usr/lib/chromium")])).toBeNull()
    expect(chromeInstallDir(join(root, "missing"), [])).toBeNull()
  })
})

describe("readAhead", () => {
  test("reads every regular file under the directory once, following no link out of it", async () => {
    const dir = await install(join(root, "chrome"), "chrome").then(() => join(root, "chrome"))
    await mkdir(join(dir, "locales"))
    await writeFile(join(dir, "locales/en-GB.pak"), "x".repeat(3_000_000))
    await writeFile(join(root, "outside"), "y".repeat(10))
    await symlink(join(root, "outside"), join(dir, "link"))
    expect(readAhead(dir)).toEqual({ files: 3, bytes: 3_000_000 + 3 + 4 })
  })
})
