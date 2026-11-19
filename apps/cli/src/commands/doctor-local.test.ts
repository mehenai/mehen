import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, readdir, stat, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { doctorAll, localVaultCheck } from "./doctor.ts"
import { tempDir } from "../testing/run-mehen.ts"

const ORIGIN = "http://localhost:7787"
let root: { path: string; remove(): Promise<void> }
let data: string
const asked: string[] = []

beforeEach(async () => {
  root = await tempDir()
  data = join(root.path, "vault")
  await mkdir(data, { mode: 0o700 })
  await writeFile(join(data, "instance"), "tok_local\n", { mode: 0o600 })
  asked.length = 0
})
afterEach(() => root.remove())

async function record(fields: Record<string, unknown> = { origin: ORIGIN, data: "" }): Promise<void> {
  await writeFile(join(root.path, "local-vault.json"), JSON.stringify({ port: 7787, service: "launchd", ...fields, ...(fields.data === "" ? { data } : {}) }), { mode: 0o600 })
}

function answering(state: Record<string, unknown> | null) {
  return async (request: Request): Promise<Response> => {
    asked.push(request.url)
    if (state === null) throw new TypeError("connection refused")
    return Response.json(state)
  }
}

describe("doctor's local vault check", () => {
  test("no local-vault.json, no check and nothing asked", async () => {
    expect(await localVaultCheck(root.path, answering({}))).toBeNull()
    expect(asked).toEqual([])
  })

  test("each custody is reported with what it means; a file is a warning that says what keeps the key better", async () => {
    await record()
    const enclave = await localVaultCheck(root.path, answering({ instance: "tok_local", custody: "secure-enclave" }))
    expect(enclave).toMatchObject({ check: "local_vault", status: "ok" })
    expect(String(enclave?.detail)).toContain("sealed by this Mac's Secure Enclave")
    expect(String(enclave?.detail)).toContain("a program running as you can still have the enclave open it")
    const keyring = await localVaultCheck(root.path, answering({ instance: "tok_local", custody: "keyring" }))
    expect(keyring).toMatchObject({ status: "ok" })
    expect(String(keyring?.detail)).toContain("in your login keyring")
    const file = await localVaultCheck(root.path, answering({ instance: "tok_local", custody: "file" }))
    expect(file).toMatchObject({ status: "warn" })
    expect(String(file?.detail)).toContain("keys.json, a file only you can read")
    expect(String(file?.detail)).toContain("A Mac with the Secure Enclave helper (a released mehen), a Linux desktop with a login keyring and secret-tool, or a vault on another machine keeps it better.")
    expect(file?.next).toBeUndefined()
    expect(asked).toEqual([`${ORIGIN}/local/v1/state`, `${ORIGIN}/local/v1/state`, `${ORIGIN}/local/v1/state`])
  })

  test("a vault that does not answer, an impostor, an older vault, and an origin off loopback", async () => {
    await record()
    expect(await localVaultCheck(root.path, answering(null))).toMatchObject({ status: "warn", detail: expect.stringContaining("did not answer"), next: { command: "mehen up" } })
    expect(await localVaultCheck(root.path, answering({ instance: "someone-else", custody: "secure-enclave" }))).toMatchObject({ status: "warn", detail: expect.stringContaining("is not the vault in") })
    expect(await localVaultCheck(root.path, answering({ instance: "tok_local" }))).toMatchObject({ status: "skipped", detail: expect.stringContaining("does not say what keeps its key") })
    asked.length = 0
    await record({ origin: "http://vault.example.com", data })
    expect(await localVaultCheck(root.path, answering({}))).toMatchObject({ status: "skipped", detail: expect.stringContaining("not this machine's loopback") })
    expect(asked).toEqual([])
  })

  test("mehen doctor carries it among the machine's checks, never as a stray, and writes nothing", async () => {
    const config = join(root.path, "config")
    await mkdir(config, { mode: 0o700 })
    await writeFile(join(config, "local-vault.json"), JSON.stringify({ origin: ORIGIN, data, port: 7787, service: "launchd" }), { mode: 0o600 })
    const before = (await readdir(config)).sort()
    const mtime = (await stat(join(config, "local-vault.json"))).mtimeMs
    const env = { MEHEN_CONFIG_DIR: config, MEHEN_VAULT_URL: "http://127.0.0.1:1", MEHEN_SESSION: "pi-4f2a", HOME: root.path, PATH: "/usr/bin:/bin" }
    const fetcher = async (request: Request): Promise<Response> => (request.url.startsWith(ORIGIN) ? Response.json({ instance: "tok_local", custody: "file" }) : new Response(null, { status: 503 }))
    const report = await doctorAll(env, { fetch: fetcher })
    expect(report.machine.find((c) => c.check === "local_vault")).toMatchObject({ status: "warn", detail: expect.stringContaining("keeps its key in keys.json") })
    expect(report.machine.find((c) => c.check === "migration")).toMatchObject({ status: "ok" })
    expect(report.strays).toEqual([])
    expect((await readdir(config)).sort()).toEqual(before)
    expect((await stat(join(config, "local-vault.json"))).mtimeMs).toBe(mtime)
  })
})
