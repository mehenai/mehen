import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { readFileSync, renameSync, writeFileSync } from "node:fs"
import { lstat } from "node:fs/promises"
import { join } from "node:path"
import { writeNewFile } from "./files.ts"
import { tempDir } from "../testing/run-mehen.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
beforeEach(async () => {
  dir = await tempDir()
})
afterEach(() => dir.remove())

describe("writeNewFile", () => {
  test("sets the mode and the mtime on the open file, after the bytes are written", async () => {
    const path = join(dir.path, "restored.env")
    await writeNewFile(path, new Uint8Array([65, 61, 49, 10]), { mode: 0o640, mtimeMs: 1_700_000_000_123.5 })
    const info = await lstat(path)
    expect(info.mode & 0o7777).toBe(0o640)
    expect(info.size).toBe(4)
    expect(Math.abs(info.mtimeMs - 1_700_000_000_123.5)).toBeLessThan(0.01)
  })

  test.skipIf(process.getuid?.() === 0)("a write that fails after the file is created leaves nothing behind", async () => {
    const path = join(dir.path, "partial.env")
    await expect(writeNewFile(path, new Uint8Array([1, 2, 3]), { owner: { uid: 0, gid: 0 } })).rejects.toThrow()
    expect(await lstat(path).catch(() => null)).toBeNull()
  })

  // Seen in review: a write that failed unlinked the path, deleting a file
  // another program had renamed over it since it was created.
  test.skipIf(process.getuid?.() === 0)("a write that fails after another program renames its own file over the path leaves that file as it is", async () => {
    const path = join(dir.path, "restored.env")
    let saved = false
    // Read once the file is created: an editor saves over it, then the chown to root fails.
    const attributes = {
      get owner() {
        if (!saved) {
          writeFileSync(`${path}.swp`, "SAVED=1\n")
          renameSync(`${path}.swp`, path)
          saved = true
        }
        return { uid: 0, gid: 0 }
      },
    }
    await expect(writeNewFile(path, new Uint8Array([1, 2, 3]), attributes)).rejects.toThrow(`something else is at ${path} now, left as it is`)
    expect(saved).toBe(true)
    expect(readFileSync(path, "utf8")).toBe("SAVED=1\n")
  })
})
