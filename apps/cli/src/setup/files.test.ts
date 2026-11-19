import { afterEach, beforeEach, expect, test } from "bun:test"
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { atomicText, safePath } from "./files.ts"
let home: string
beforeEach(async () => { home = await mkdtemp(join(tmpdir(), "mehen-files-")) })
afterEach(async () => { await rm(home, { recursive: true, force: true }) })
test("in-HOME links are safe, but out-of-HOME and lexical escapes are refused", async () => {
  await mkdir(join(home, "dotfiles"))
  await symlink(join(home, "dotfiles"), join(home, ".config"))
  await safePath(home, join(home, ".config/mehen/state.json"))
  await symlink(tmpdir(), join(home, "external"))
  await expect(safePath(home, join(home, "external/config.json"))).rejects.toThrow("outside HOME")
  await expect(safePath(home, join(home, "../escape"))).rejects.toThrow("within HOME")
})
test("atomic text keeps modes and refuses a changed file immediately before rename", async () => {
  const path = join(home, "config.json")
  await writeFile(path, "before"); await chmod(path, 0o664)
  await atomicText(home, path, "after", "before")
  expect((await lstat(path)).mode & 0o777).toBe(0o664)
  await expect(atomicText(home, path, "replacement", "after", async () => { await writeFile(path, "human") })).rejects.toThrow("changed while setup ran")
  expect(await readFile(path, "utf8")).toBe("human")
})
