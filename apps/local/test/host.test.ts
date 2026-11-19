import { afterEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, utimesSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { addressFor, canonicalLocalOrigin, defaultDataDir, LocalConfigError, parsePort, resolveConfig } from "../src/config.ts"
import { hardenProcess } from "../src/harden.ts"
import { BOOTSTRAP_FILE, INSTANCE_FILE, LOCK_FILE, startLocalVault, type LocalVault } from "../src/host.ts"
import { LocalBucket } from "../src/r2.ts"
import { LocalRateLimit } from "../src/rate-limit.ts"

// keys.json, whatever this machine offers: these tests are not about custody.
const FILE_ONLY = { custody: { platform: process.platform, env: {}, helper: null } }
const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const made: string[] = []
const started: LocalVault[] = []
function scratch(): string {
  const dir = mkdtempSync(join(base, "mehen-local-unit-"))
  made.push(dir)
  return dir
}
afterEach(async () => {
  for (const vault of started.splice(0)) await vault.stop()
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe("config", () => {
  test("data directories follow each platform's convention", () => {
    expect(defaultDataDir({ HOME: "/Users/a" }, "darwin")).toBe("/Users/a/Library/Application Support/Mehen/vault")
    expect(defaultDataDir({ HOME: "/home/a" }, "linux")).toBe("/home/a/.local/share/mehen/vault")
    expect(defaultDataDir({ HOME: "/home/a", XDG_DATA_HOME: "/data" }, "linux")).toBe("/data/mehen/vault")
  })

  test("a port is an integer from 0 to 65535", () => {
    expect(parsePort(undefined)).toBe(7787)
    expect(parsePort("0")).toBe(0)
    expect(() => parsePort("80a")).toThrow(LocalConfigError)
    expect(() => parsePort("70000")).toThrow(LocalConfigError)
  })

  test("an origin must be bare https", () => {
    expect(canonicalLocalOrigin("https://mehen.example.ts.net/")).toBe("https://mehen.example.ts.net")
    expect(() => canonicalLocalOrigin("http://mehen.lan")).toThrow(/secure context/)
    expect(() => canonicalLocalOrigin("https://mehen.lan/vault")).toThrow(/bare origin/)
    expect(() => canonicalLocalOrigin("https://u:p@mehen.lan")).toThrow(/bare origin/)
  })

  test("without an origin the vault answers loopback names only", () => {
    const address = addressFor({ dataDir: "/x", port: 7787, hostname: "127.0.0.1", origin: null }, 7787)
    expect(address).toEqual({ origin: "http://localhost:7787", rpId: "localhost", hosts: new Set(["localhost:7787", "127.0.0.1:7787"]), loopback: true })
    expect(() => addressFor({ dataDir: "/x", port: 7787, hostname: "0.0.0.0", origin: null }, 7787)).toThrow(/needs --origin/)
  })

  test("port 80 answers the Host a browser sends for it, with no port", () => {
    expect(addressFor({ dataDir: "/x", port: 80, hostname: "127.0.0.1", origin: null }, 80).hosts).toEqual(new Set(["localhost", "127.0.0.1"]))
  })

  test("with an origin it answers that name, as its RP ID", () => {
    const address = addressFor(resolveConfig({ origin: "https://mehen.example.ts.net", dataDir: "/x" }, {}), 7787)
    expect(address).toEqual({ origin: "https://mehen.example.ts.net", rpId: "mehen.example.ts.net", hosts: new Set(["mehen.example.ts.net"]), loopback: false })
  })
})

describe("rate limits", () => {
  test("a fixed window per key", async () => {
    let now = 0
    const limiter = new LocalRateLimit(2, 60, () => now)
    expect((await limiter.limit({ key: "a" })).success).toBe(true)
    expect((await limiter.limit({ key: "a" })).success).toBe(true)
    expect((await limiter.limit({ key: "a" })).success).toBe(false)
    expect((await limiter.limit({ key: "b" })).success).toBe(true)
    now = 60_000
    expect((await limiter.limit({ key: "a" })).success).toBe(true)
  })
})

describe("backups", () => {
  test("an object is written once, never overwritten, and kept private", async () => {
    const bucket = new LocalBucket(join(scratch(), "backups"))
    await bucket.put("ws/tn_a/2026-11-18.bin", new Uint8Array([1, 2, 3]))
    const object = await bucket.get("ws/tn_a/2026-11-18.bin")
    expect(object?.size).toBe(3)
    expect(new Uint8Array(await object!.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]))
    await expect(bucket.put("ws/tn_a/2026-11-18.bin", new Uint8Array([9]))).rejects.toThrow(/never overwritten/)
    expect(await bucket.get("ws/tn_a/2026-11-19.bin")).toBeNull()
  })

  test("a key cannot leave the backup folder", async () => {
    const bucket = new LocalBucket(join(scratch(), "backups"))
    await expect(bucket.get("../keys.json")).rejects.toThrow(/outside/)
    await expect(bucket.put("ws/../../keys.json", new Uint8Array([1]))).rejects.toThrow(/outside/)
  })

  test("dailies go after 35 days, monthlies after a year", async () => {
    const dir = join(scratch(), "backups")
    const bucket = new LocalBucket(dir)
    await bucket.put("ws/tn_a/2026-10-01.bin", new Uint8Array([1]))
    await bucket.put("monthly/ws/tn_a/2026-10.bin", new Uint8Array([1]))
    const forty = (Date.now() - 40 * 86_400_000) / 1000
    utimesSync(join(dir, "ws/tn_a/2026-10-01.bin"), forty, forty)
    utimesSync(join(dir, "monthly/ws/tn_a/2026-10.bin"), forty, forty)
    expect(bucket.prune()).toBe(1)
    expect(await bucket.get("monthly/ws/tn_a/2026-10.bin")).not.toBeNull()
  })
})

describe("the host", () => {
  test("refuses a data directory other users can open, before binding", async () => {
    const dir = join(scratch(), "open")
    mkdirSync(dir, { mode: 0o755 })
    chmodSync(dir, 0o755)
    await expect(startLocalVault({ dataDir: dir, port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)).rejects.toThrow(/open to other users/)
  })

  test("refuses a data directory below a world-writable folder", async () => {
    const open = join(scratch(), "shared")
    mkdirSync(open)
    chmodSync(open, 0o777)
    await expect(startLocalVault({ dataDir: join(open, "vault"), port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)).rejects.toThrow(/writable by other users/)
  })

  test("keeps its files private and the bootstrap code in a 0600 file", async () => {
    const dataDir = join(scratch(), "vault")
    const vault = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)
    started.push(vault)
    expect(statSync(dataDir).mode & 0o777).toBe(0o700)
    expect(statSync(join(dataDir, "keys.json")).mode & 0o777).toBe(0o600)
    expect(statSync(join(dataDir, BOOTSTRAP_FILE)).mode & 0o777).toBe(0o600)
    expect((await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()).length).toBeGreaterThanOrEqual(32)
  })

  test("with an origin it refuses loopback names and hides its state", async () => {
    const vault = await startLocalVault({ dataDir: join(scratch(), "vault"), port: 0, hostname: "127.0.0.1", origin: "https://mehen.example.ts.net" }, FILE_ONLY)
    started.push(vault)
    const at = `http://127.0.0.1:${vault.port}`
    expect((await fetch(`${at}/healthz`)).status).toBe(421)
    expect((await fetch(`${at}/healthz`, { headers: { host: "mehen.example.ts.net" } })).status).toBe(200)
    expect((await fetch(`${at}/local/v1/state`, { headers: { host: "mehen.example.ts.net" } })).status).toBe(404)
    expect(await (await fetch(`${at}/v1/seal-key`, { headers: { host: "mehen.example.ts.net" } })).json()).toHaveProperty("jwk")
  })

  test("sends a page asked for at 127.0.0.1 to localhost, where its passkeys are", async () => {
    const vault = await startLocalVault({ dataDir: join(scratch(), "vault"), port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)
    started.push(vault)
    const page = await fetch(`http://127.0.0.1:${vault.port}/signin?next=%2F`, { headers: { accept: "text/html" }, redirect: "manual" })
    expect(page.status).toBe(308)
    expect(page.headers.get("location")).toBe(`${vault.origin}/signin?next=%2F`)
    expect((await fetch(`http://127.0.0.1:${vault.port}/healthz`)).status).toBe(200)
  })

  test("one server per data directory: a second is refused and the first keeps its identity", async () => {
    const dataDir = join(scratch(), "vault")
    const first = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })
    started.push(first)
    const identity = await Bun.file(join(dataDir, INSTANCE_FILE)).text()
    await expect(startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })).rejects.toThrow(/(already using|already serving) the vault/)
    expect(await Bun.file(join(dataDir, INSTANCE_FILE)).text()).toBe(identity)
    expect(first.state().instance).toBe(identity)
  })

  test("a server that cannot take its port leaves no lock and no identity behind", async () => {
    const dataDir = join(scratch(), "vault")
    const blocker = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response() })
    try {
      await expect(startLocalVault({ dataDir, port: blocker.port ?? 0, hostname: "127.0.0.1", origin: null })).rejects.toThrow()
      expect(existsSync(join(dataDir, LOCK_FILE))).toBe(false)
      expect(existsSync(join(dataDir, INSTANCE_FILE))).toBe(false)
    } finally {
      blocker.stop(true)
    }
  })

  test("a restart before anyone signs up keeps the sign-up code a browser may have open", async () => {
    const dataDir = join(scratch(), "vault")
    const first = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })
    const code = await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()
    await first.stop()
    const second = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })
    started.push(second)
    expect(await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()).toBe(code)
  })

  test("the start page sends the browser to sign-up with the code in the fragment, on loopback only", async () => {
    const dataDir = join(scratch(), "vault")
    const vault = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })
    started.push(vault)
    const code = (await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()).trim()
    const start = await fetch(`${vault.origin}/local/v1/start`, { redirect: "manual" })
    expect(start.status).toBe(302)
    expect(start.headers.get("location")).toBe(`/signup#${code}`)
    expect(start.headers.get("cache-control")).toBe("no-store")
  })

  test("a client cannot pick its own address to slip the rate limits", async () => {
    const vault = await startLocalVault({ dataDir: join(scratch(), "vault"), port: 0, hostname: "127.0.0.1", origin: null })
    started.push(vault)
    const statuses: number[] = []
    for (let i = 0; i < 22; i++) {
      const response = await fetch(`${vault.origin}/api/auth/signin/options`, { method: "POST", headers: { origin: vault.origin, "sec-fetch-site": "same-origin", "content-type": "application/json", "cf-connecting-ip": `10.0.0.${i}` }, body: "{}" })
      statuses.push(response.status)
    }
    expect(statuses.slice(0, 20).every((s) => s !== 429)).toBe(true)
    expect(statuses.at(-1)).toBe(429)
  })

  test("answers its state on loopback, to GET only", async () => {
    const vault = await startLocalVault({ dataDir: join(scratch(), "vault"), port: 0, hostname: "127.0.0.1", origin: null }, FILE_ONLY)
    started.push(vault)
    expect(await (await fetch(`${vault.origin}/local/v1/state`)).json()).toMatchObject({ origin: vault.origin, accounts: false, bootstrap: true, workspaces: [] })
    expect((await fetch(`${vault.origin}/local/v1/state`, { method: "POST" })).status).toBe(404)
  })
})

test.if(process.platform === "linux")("on Linux the process stops being dumpable", () => {
  expect(hardenProcess()).toEqual({ dumpable: "off", detail: null })
})
