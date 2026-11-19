import { expect, test } from "bun:test"
import { readdir } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { embeddedHelperPath } from "./embedded-helper.ts"
import { runJv, tempDir } from "./testing/run-mehen.ts"

// The clean-checkout gate: tsc and every test pass without the generated
// module, which only scripts/build.ts writes, per target, and deletes.
test("a source checkout has no generated module, so there is no embedded helper", async () => {
  expect(await Bun.file(join(import.meta.dir, "generated", "embedded-helper.ts")).exists()).toBe(false)
  expect(await Bun.file(join(import.meta.dir, "generated", "embedded-helper.d.ts")).exists()).toBe(true)
  expect(await embeddedHelperPath()).toBeNull()
  expect(await embeddedHelperPath()).toBeNull()
})

test("version reports helper none from source, and --extract-helper refuses with usage, writing nothing", async () => {
  const version = await runJv(["version", "--json"], {})
  expect(JSON.parse(version.stdout)).toMatchObject({ build: null, helper: "none" })
  const dir = await tempDir()
  const refused = await runJv(["version", "--extract-helper", join(dir.path, "out"), "--json"], {})
  expect(refused.code).toBe(EXIT.usage)
  expect(JSON.parse(refused.stdout)).toMatchObject({ error: "usage" })
  expect(refused.stdout).toContain("no embedded Secure Enclave helper")
  expect(await readdir(dir.path)).toEqual([])
  expect((await runJv(["version", "--extract-helper", ""], {})).code).toBe(EXIT.usage)
  await dir.remove()
})
