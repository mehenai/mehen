// mehen serve from source, as a person runs it: it bundles the engine,
// listens, says where, and stops cleanly on SIGTERM.

import { afterAll, expect, test } from "bun:test"
import { mkdtempSync, rmSync, statSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"

const CLI = join(import.meta.dir, "../../cli/src/main.ts")
const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const root = mkdtempSync(join(base, "mehen-serve-"))
afterAll(() => rmSync(root, { recursive: true, force: true }))

function serve(...args: string[]) {
  return Bun.spawn(["bun", CLI, "serve", ...args], { env: { ...process.env, MEHEN_HOME: join(root, "home"), MEHEN_NO_AUTO_UPDATE: "1" }, stdout: "pipe", stderr: "pipe" })
}

async function firstLine(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader()
  let text = ""
  while (!text.includes("\n")) {
    const { value, done } = await reader.read()
    if (done) break
    text += new TextDecoder().decode(value)
  }
  reader.releaseLock()
  return text.split("\n")[0] ?? ""
}

test("listens, reports itself once and stops on SIGTERM", async () => {
  const proc = serve("--port", "0", "--data", join(root, "vault"), "--json")
  const started = JSON.parse(await firstLine(proc.stdout)) as { origin: string; data: string; bootstrap: boolean; dumpable: string; custody: string }
  expect(started).toMatchObject({ data: join(root, "vault"), bootstrap: true })
  expect(started.custody).toMatch(process.platform === "darwin" ? /^(secure-enclave|file)$/ : /^(keyring|file)$/)
  expect(started.origin).toMatch(/^http:\/\/localhost:\d+$/)
  expect(await (await fetch(`${started.origin}/healthz`)).json()).toEqual({ ok: true })
  for (const file of ["directory.sqlite", "instance", "serve.lock"]) expect({ file, mode: statSync(join(root, "vault", file)).mode & 0o777 }).toEqual({ file, mode: 0o600 })
  proc.kill("SIGTERM")
  expect(await proc.exited).toBe(0)
}, 60_000)

test("a second serve on the same data directory is refused with the first one's pid", async () => {
  const data = join(root, "shared")
  const first = serve("--port", "0", "--data", data, "--json")
  JSON.parse(await firstLine(first.stdout))
  const second = serve("--port", "0", "--data", data, "--json")
  expect(await second.exited).toBe(1)
  const refusal = JSON.parse(await new Response(second.stdout).text()) as { error: string; message: string }
  expect(refusal.error).toBe("conflict")
  expect(refusal.message).toContain(`pid ${first.pid}`)
  first.kill("SIGTERM")
  expect(await first.exited).toBe(0)
}, 60_000)

test("an origin that is not https is a usage error, before anything listens", async () => {
  const proc = serve("--origin", "http://vault.lan", "--data", join(root, "other"), "--json")
  expect(await proc.exited).toBe(2)
  expect(JSON.parse(await new Response(proc.stdout).text())).toMatchObject({ error: "usage" })
})
