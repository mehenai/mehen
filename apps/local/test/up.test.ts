// mehen up from nothing, as a person and their agent meet it: the vault
// starts, the sign-up link opens, the person makes a passkey and a
// workspace, the machine's enrolment opens, the person accepts it, and up
// says done. Run again, it finds everything in place. Then --remove stops it.

import { afterAll, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { Person } from "./person.ts"

const CLI = join(import.meta.dir, "../../cli/src/main.ts")
const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const root = mkdtempSync(join(base, "mehen-up-"))
const dataDir = join(root, "vault")
const home = join(root, "home")
const opened = join(root, "opened.txt")
const browser = join(root, "browser.sh")
writeFileSync(browser, `#!/bin/sh\nprintf '%s\\n' "$1" >> ${JSON.stringify(opened)}\n`)
chmodSync(browser, 0o700)

function freePort(): number {
  const server = Bun.serve({ port: 0, fetch: () => new Response() })
  const port = server.port ?? 0
  server.stop(true)
  return port
}
const port = freePort()
const env = { ...process.env, HOME: root, MEHEN_HOME: home, MEHEN_SERVICE: "process", MEHEN_BROWSER: browser, MEHEN_NO_AUTO_UPDATE: "1", MEHEN_SELF_EXECUTABLE: "" }

afterAll(async () => {
  await Bun.spawn(["bun", CLI, "up", "--remove", "--json"], { env, stdout: "ignore", stderr: "ignore" }).exited
  rmSync(root, { recursive: true, force: true })
})

type Line = { event: string; [key: string]: unknown }

async function* lines(stream: ReadableStream<Uint8Array>): AsyncGenerator<Line> {
  const decoder = new TextDecoder()
  let buffer = ""
  const reader = stream.getReader()
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buffer += decoder.decode(value, { stream: true })
    let at = buffer.indexOf("\n")
    while (at !== -1) {
      const line = buffer.slice(0, at).trim()
      buffer = buffer.slice(at + 1)
      if (line) yield JSON.parse(line) as Line
      at = buffer.indexOf("\n")
    }
  }
}

test("from nothing to an enrolled machine, with two touches in the browser", async () => {
  const up = Bun.spawn(["bun", CLI, "up", "--port", String(port), "--data", dataDir, "--timeout", "60", "--json"], { env, stdout: "pipe", stderr: "pipe" })
  const seen: Line[] = []
  const origin = `http://localhost:${port}`
  const person = new Person(origin)
  let workspace: Awaited<ReturnType<Person["createWorkspace"]>> | null = null
  for await (const line of lines(up.stdout)) {
    seen.push(line)
    const ask = line.ask as { kind?: string; id?: string; url?: string; opened?: boolean } | undefined
    if (line.event === "ask" && ask?.kind === "signup") {
      expect(ask.opened).toBe(true)
      // The link carries no code: the vault's start page redirects to it.
      expect(ask.url).toBe(`${origin}/local/v1/start`)
      const start = await fetch(ask.url!, { redirect: "manual" })
      expect(start.status).toBe(302)
      const location = start.headers.get("location") ?? ""
      expect(location).toStartWith("/signup#")
      await person.signUp(location.slice("/signup#".length))
      workspace = await person.createWorkspace("home", "Home")
    }
    if (line.event === "ask" && ask?.kind === "enrol") {
      expect(ask.opened).toBe(true)
      const code = new URL(ask.url!).pathname.split("/").at(-1)!
      const record = await Bun.file(join(home, "pending", `http_localhost_${port}`, "home", "enrolment.json")).json()
      await person.acceptMachine(dataDir, workspace!, code, ask.id!, record)
    }
  }
  const code = await up.exited
  expect({ code, stderr: code === 0 ? "" : await new Response(up.stderr).text() }).toEqual({ code: 0, stderr: "" })
  expect(seen.map((l) => l.event)).toEqual(["vault", "ask", "workspace", "ask", "machine", "agents", "done"])
  expect(seen[0]).toMatchObject({ event: "vault", origin, data: dataDir, service: "process", startsAtLogin: false, custody: expect.stringMatching(/^(secure-enclave|keyring|file)$/) })
  expect(seen[2]).toMatchObject({ event: "workspace", slug: "home", name: "Home" })
  expect(seen[4]).toMatchObject({ event: "machine", device: expect.stringMatching(/^dev_/) })
  expect(seen[5]).toMatchObject({ event: "agents", skipped: "source" })
  const links = (await Bun.file(opened).text()).trim().split("\n")
  expect(links).toHaveLength(2)
  expect(links[0]).toBe(`${origin}/local/v1/start`)
  expect(seen.map((l) => JSON.stringify(l)).join("\n")).not.toMatch(/signup#/)
  expect(links[1]).toStartWith(`${origin}/w/home/e/`)
}, 90_000)

test("run again with no flags, it finds the vault, the workspace and the machine in place and asks nothing", async () => {
  const again = Bun.spawn(["bun", CLI, "up", "--json"], { env, stdout: "pipe", stderr: "pipe" })
  const seen: Line[] = []
  for await (const line of lines(again.stdout)) seen.push(line)
  expect(await again.exited).toBe(0)
  expect(seen.map((l) => l.event)).toEqual(["vault", "workspace", "machine", "agents", "done"])
  expect(seen[0]).toMatchObject({ service: null, origin: `http://localhost:${port}`, data: dataDir, custody: expect.stringMatching(/^(secure-enclave|keyring|file)$/) })
}, 60_000)

test("a port of 0 is refused: the service and the agents need a fixed address", async () => {
  const up = Bun.spawn(["bun", CLI, "up", "--port", "0", "--data", join(root, "zero"), "--json"], { env, stdout: "pipe", stderr: "pipe" })
  expect(await up.exited).toBe(2)
})

test("--remove stops the vault and keeps its data", async () => {
  const removed = Bun.spawn(["bun", CLI, "up", "--remove", "--json"], { env, stdout: "pipe", stderr: "pipe" })
  const out = await new Response(removed.stdout).text()
  expect(await removed.exited).toBe(0)
  expect(JSON.parse(out)).toEqual({ event: "done", removed: true, service: "process", data: dataDir })
  await Bun.sleep(500)
  const answer = await fetch(`http://localhost:${port}/healthz`).then(() => "up", () => "down")
  expect(answer).toBe("down")
  expect(existsSync(join(dataDir, "directory.sqlite"))).toBe(true)
}, 30_000)

test("refuses a vault on the port that is not the one in its data directory", async () => {
  const impostor = Bun.serve({ port: 0, fetch: () => Response.json({ origin: "x", instance: "not-yours", accounts: true, bootstrap: false, workspaces: [{ slug: "home", name: "Home" }] }) })
  try {
    const up = Bun.spawn(["bun", CLI, "up", "--port", String(impostor.port), "--data", join(root, "other"), "--json"], { env, stdout: "pipe", stderr: "pipe" })
    const out = await new Response(up.stdout).text()
    expect(await up.exited).not.toBe(0)
    expect(JSON.parse(out.trim().split("\n").at(-1)!)).toMatchObject({ error: "conflict" })
  } finally {
    impostor.stop(true)
  }
}, 30_000)

test("--remove never signals a process that is not this vault's serve", async () => {
  const other = join(root, "stale")
  const sleeper = Bun.spawn(["sleep", "30"])
  const home2 = join(root, "home2")
  rmSync(home2, { recursive: true, force: true })
  try {
    await Bun.write(join(other, "serve.pid"), String(sleeper.pid))
    await Bun.write(join(home2, "local-vault.json"), JSON.stringify({ origin: "http://localhost:1", data: other, port: 1, service: "process" }))
    chmodSync(home2, 0o700)
    const removed = Bun.spawn(["bun", CLI, "up", "--remove", "--json"], { env: { ...env, MEHEN_HOME: home2 }, stdout: "pipe", stderr: "pipe" })
    expect(await removed.exited).toBe(0)
    expect(sleeper.killed).toBe(false)
    expect(sleeper.exitCode).toBeNull()
  } finally {
    sleeper.kill()
  }
}, 30_000)
