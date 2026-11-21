import { afterEach, beforeAll, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, utimes, writeFile } from "node:fs/promises"
import * as fsPromises from "node:fs/promises"
import { realpathSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { base64UrlEncode } from "@mehen/protocol/bytes"
import { type ReleaseKey, manifestSigningBytes } from "@mehen/protocol/release-manifest"
import { type InstallState, OWNERLESS_GRACE_MS, freshInstallState, installation, readInstallState, recordVaultAdvice, withInstallLock, writeInstallState } from "./install-state.ts"
import { sha256, type ReleaseManifest } from "./release-client.ts"
import { type UpdateOptions, type UpdateStep, healInForeground, preDispatchHeal, scheduleBackgroundUpdate, update } from "./update.ts"
import { VERSION } from "./version.ts"
import { CliError } from "./errors.ts"

// A test release key, trusted through MEHEN_RELEASE_KEYS over the loopback
// fixture base; never a real release key.
let releaseKey: ReleaseKey
let releaseSigner: CryptoKey
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  releaseKey = { id: "rk-test-update", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" }
  releaseSigner = pair.privateKey
})
async function signed(value: ReleaseManifest) {
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, releaseSigner, manifestSigningBytes(value))
  return { ...value, signatures: [{ keyId: releaseKey.id, alg: "ES256", signature: base64UrlEncode(signature) }] }
}

// A release binary stand-in: a shell script that answers the smoke test
// (`version --json`) and the skills refresh (`setup --json`) as a release
// build would.
function release(version: string, options: { commit?: string; helper?: "none" | "embedded"; skills?: string; mark?: string; slowSkills?: boolean } = {}): Uint8Array<ArrayBuffer> {
  const info = JSON.stringify({ version, commit: options.commit ?? "a53a3de", build: "release", helper: options.helper ?? "none" })
  const skills = options.skills ?? JSON.stringify({ agents: [], skills: [{ path: "/skills/mehen/SKILL.md", status: "updated" }] })
  return new TextEncoder().encode(`#!/bin/sh\n# ${options.mark ?? version}\nif [ "$1 $2" = "version --json" ]; then printf '%s\\n' '${info}'; exit 0; fi\nif [ "$1 $2" = "setup --json" ]; then [ "$MEHEN_SETUP_SKILLS_ONLY" = 1 ] && [ "$MEHEN_UPDATE_CHILD" = 1 ] || exit 3; ${options.slowSkills ? "sleep 3; " : ""}printf '%s\\n' '${skills}'; exit 0; fi\nexit 2\n`)
}

let root: string
let binary: string
let server: ReturnType<typeof Bun.serve>
let manifest: ReleaseManifest
let bad = ""
let requests: string[]
let raw: Uint8Array<ArrayBuffer>
let gz: Uint8Array
let servedGz: Uint8Array
let offline = false
let manifestDelay = 0
const old = release("1.0.0", { commit: "0ld0000", mark: "old" })

function setRelease(bytes: Uint8Array<ArrayBuffer>, version = "1.2.3", commit = "a53a3de") {
  raw = bytes
  gz = Bun.gzipSync(raw)
  servedGz = gz
  manifest = { version, commit, builtAt: "2026-10-27T13:00:00Z", files: ["mehen-linux-x64", "mehen-linux-arm64", "mehen-darwin-arm64", "mehen-darwin-x64", "mehen-se"].map((name) => ({ name, os: name.includes("linux") ? "linux" : "darwin", arch: "arm64", url: `https://mehen.dev/dl/v${version}/${name}.gz`, sha256: sha256(raw), size: raw.length, gzSha256: sha256(gz), gzSize: gz.length })) }
}

beforeEach(async () => {
  root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-update-")))
  await chmod(root, 0o700)
  binary = join(root, "mehen")
  await writeFile(binary, old, { mode: 0o755 })
  bad = ""
  requests = []
  offline = false
  manifestDelay = 0
  setRelease(release("1.2.3"))
  server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
    const path = new URL(req.url).pathname
    requests.push(path)
    if (offline) return new Response("offline", { status: 503 })
    if (manifestDelay && path.endsWith(".json")) await Bun.sleep(manifestDelay)
    if (bad === "blocked" && path.endsWith(".gz")) return new Response("blocked", { status: 403 })
    if (path.endsWith("latest.json") || path.endsWith("manifest.json")) return Response.json(await signed(manifest))
    return new Response(new Uint8Array(bad === "truncated" ? servedGz.slice(0, 5) : servedGz))
  } })
})
afterEach(async () => {
  server.stop(true)
  await rm(root, { recursive: true, force: true })
})
const env = () => ({ HOME: root, MEHEN_HOME: join(root, "config"), MEHEN_DL_BASE: `http://127.0.0.1:${server.port}/dl`, MEHEN_RELEASE_KEYS: JSON.stringify([releaseKey]) })
const run = (options: Partial<UpdateOptions> = {}) => update({ env: env(), install: installation(binary), by: "manual", current: "1.0.0", commit: "0ld0000", build: "release", platform: "linux", arch: "x64", ...options })
const state = async () => (await readInstallState(installation(binary))) as InstallState
const bytes = async (path = binary) => new Uint8Array(await readFile(path))
const staging = async () => (await readdir(root)).filter((n) => n.startsWith(".mehen-update."))

describe("checking and installing", () => {
  test("check reports only and leaves every file untouched", async () => {
    expect(await run({ check: true })).toMatchObject({ current: "1.0.0", latest: "1.2.3", available: true, path: binary, installed: null, pending: null })
    expect(await bytes()).toEqual(old)
    expect(await readdir(root)).toEqual(["mehen"])
    expect(requests).toEqual(["/dl/latest.json"])
  })

  test("first install with no state: verified, smoke-tested, one rename, receipt, previous kept with its record, skills reported verbatim", async () => {
    const report = await run()
    expect(report).toMatchObject({ result: "updated", updated: true, from: "1.0.0", to: "1.2.3", skills: [{ path: "/skills/mehen/SKILL.md", status: "updated" }] })
    expect(await bytes()).toEqual(raw)
    expect(await readFile(join(root, ".mehen.sha256"), "utf8")).toBe(`${sha256(raw)}\n`)
    expect(await bytes(join(root, ".mehen.previous"))).toEqual(old)
    const previous = JSON.parse(await readFile(join(root, ".mehen.previous.json"), "utf8"))
    expect(previous).toMatchObject({ version: "1.0.0", sha256: sha256(old), by: "install", keyId: null, manifest: null })
    const s = await state()
    expect(s.pending).toBeNull()
    expect(s.installed).toMatchObject({ version: "1.2.3", commit: "a53a3de", sha256: sha256(raw), size: raw.length, by: "manual", keyId: releaseKey.id })
    expect(s.installed?.manifest?.version).toBe("1.2.3")
    expect(s.previous).toMatchObject({ version: "1.0.0", sha256: sha256(old) })
    expect(s.highestSeen).toBe("1.2.3")
    expect(s.check).toMatchObject({ latest: "1.2.3", error: null })
    expect(s.lastUpdate).toMatchObject({ from: "1.0.0", to: "1.2.3", result: "ok", reason: null })
    expect((await lstat(join(root, ".mehen.update.json"))).mode & 0o777).toBe(0o600)
    expect(await staging()).toEqual([])
    expect(await readdir(root)).not.toContain(".mehen.update.lock")
    // The same release again is current: nothing downloaded, nothing changed.
    requests = []
    expect(await run({ current: "1.2.3" })).toMatchObject({ result: "current", updated: false, available: false })
    expect(requests).toEqual(["/dl/latest.json"])
  })

  test("a failed skill is reported, not called refreshed: the binary update stands and lastUpdate says ok_skills_failed", async () => {
    setRelease(release("1.2.3", { skills: JSON.stringify({ skills: [{ path: "/a", status: "unchanged" }, { path: "/b", status: "failed", reason: "EACCES" }, { path: "/c", status: "external", reason: "symlinked" }] }) }))
    const report = await run()
    expect(report.result).toBe("updated")
    expect(report.skills).toEqual([{ path: "/a", status: "unchanged" }, { path: "/b", status: "failed", reason: "EACCES" }, { path: "/c", status: "external", reason: "symlinked" }])
    expect((await state()).lastUpdate).toMatchObject({ result: "ok_skills_failed", reason: "1 skill could not be refreshed" })
    expect(await bytes()).toEqual(raw)
  })

  for (const failure of ["gz", "raw", "truncated"]) test(`${failure} mismatch leaves the old binary and helper untouched`, async () => {
    await writeFile(join(root, "mehen-se"), "old helper")
    if (failure === "gz") manifest.files[0]!.gzSha256 = "0".repeat(64)
    if (failure === "raw") manifest.files[0]!.sha256 = "0".repeat(64)
    bad = failure
    await expect(run()).rejects.toThrow(/checksum|size/)
    expect(await bytes()).toEqual(old)
    expect(await readFile(join(root, "mehen-se"), "utf8")).toBe("old helper")
    expect(await staging()).toEqual([])
    expect(await readdir(root)).not.toContain(".mehen.previous")
  })

  test("a staged binary that fails its smoke test, or answers for another release or platform, changes nothing", async () => {
    for (const fixture of [new TextEncoder().encode("#!/bin/sh\nexit 1\n"), release("1.2.4"), release("1.2.3", { helper: "embedded" })]) {
      setRelease(fixture)
      await expect(run()).rejects.toThrow(/smoke test|does not match/)
      expect(await bytes()).toEqual(old)
      expect(await staging()).toEqual([])
      expect((await state()).pending).toBeNull()
    }
  })

  // Update rollout design gap 5: a failed download or smoke test left
  // doctor reporting ok.
  test("a failed update is recorded in lastUpdate with a short reason code, and the next success or a release no newer clears it", async () => {
    setRelease(new TextEncoder().encode("#!/bin/sh\necho /private/detail >&2\nexit 1\n"))
    await expect(run()).rejects.toThrow(/smoke test/)
    expect((await state()).lastUpdate).toEqual({ at: expect.any(String), from: "1.0.0", to: "1.2.3", result: "failed", reason: "smoke_failed", skills: [] })
    expect(await bytes()).toEqual(old)
    manifest.files[0]!.sha256 = "0".repeat(64)
    await expect(run()).rejects.toThrow(/checksum/)
    expect((await state()).lastUpdate).toMatchObject({ result: "failed", reason: "verify_failed" })
    setRelease(release("1.2.3"))
    expect(await run()).toMatchObject({ result: "updated" })
    expect((await state()).lastUpdate).toMatchObject({ result: "ok", reason: null })
    const s = await state()
    s.lastUpdate = { at: "2026-10-28T00:00:00Z", from: "1.2.3", to: "1.2.4", result: "failed", reason: "smoke_failed", skills: [] }
    await writeInstallState(installation(binary), s)
    expect(await run({ current: "1.2.3" })).toMatchObject({ result: "current" })
    expect((await state()).lastUpdate).toBeNull()
  })

  test("macOS installs one file; the 0.2.0 helper is retired only when it and its receipt agree, a foreign one stays", async () => {
    setRelease(release("1.2.3", { helper: "embedded" }))
    await writeFile(join(root, "mehen-se"), "foreign helper")
    await writeFile(join(root, ".mehen-se.sha256"), `${"0".repeat(64)}\n`)
    expect(await run({ platform: "darwin", arch: "arm64" })).toMatchObject({ result: "updated" })
    expect(await readFile(join(root, "mehen-se"), "utf8")).toBe("foreign helper")
    expect(requests.filter((p) => p.endsWith(".gz"))).toEqual(["/dl/v1.2.3/mehen-darwin-arm64.gz"])
    await writeFile(join(root, ".mehen-se.sha256"), `${sha256(new TextEncoder().encode("foreign helper"))}\n`)
    setRelease(release("1.2.4", { helper: "embedded" }), "1.2.4")
    expect(await run({ current: "1.2.3", platform: "darwin", arch: "arm64" })).toMatchObject({ result: "updated", to: "1.2.4" })
    expect(await readdir(root)).not.toContain("mehen-se")
    expect(await readdir(root)).not.toContain(".mehen-se.sha256")
  })

  test("a musl build fetches the musl binary, refuses a release without one, and the glibc build never takes it", async () => {
    for (const name of ["mehen-linux-x64-musl", "mehen-linux-arm64-musl"]) manifest.files.push({ ...manifest.files[0]!, name, url: `https://mehen.dev/dl/v1.2.3/${name}.gz` })
    expect(await run({ libc: "musl" })).toMatchObject({ result: "updated", to: "1.2.3" })
    expect(requests.filter((p) => p.endsWith(".gz"))).toEqual(["/dl/v1.2.3/mehen-linux-x64-musl.gz"])
    setRelease(release("1.2.4"), "1.2.4")
    await expect(run({ current: "1.2.3", libc: "musl", arch: "arm64" })).rejects.toThrow("no mehen-linux-arm64-musl")
    requests = []
    expect(await run({ current: "1.2.3", libc: "glibc" })).toMatchObject({ result: "updated", to: "1.2.4" })
    expect(requests.filter((p) => p.endsWith(".gz"))).toEqual(["/dl/v1.2.4/mehen-linux-x64.gz"])
  })

  test("musl applies to Linux only: a darwin update with libc musl still fetches the darwin binary", async () => {
    setRelease(release("1.2.3", { helper: "embedded" }))
    expect(await run({ platform: "darwin", arch: "arm64", libc: "musl" })).toMatchObject({ result: "updated" })
    expect(requests.filter((p) => p.endsWith(".gz"))).toEqual(["/dl/v1.2.3/mehen-darwin-arm64.gz"])
  })
})

describe("trust and anti-rollback", () => {
  test("without the test key only the compiled set is trusted, so another key's manifest, or an unsigned one, is refused and changes nothing", async () => {
    const { MEHEN_RELEASE_KEYS: _keys, ...untrusted } = env()
    await expect(run({ env: untrusted })).rejects.toThrow("signed by a key this build does not trust")
    await expect(run({ env: untrusted, check: true })).rejects.toThrow("signed by a key this build does not trust")
    const unsigned = async () => Response.json(manifest)
    await expect(run({ fetch: unsigned })).rejects.toThrow("not signed")
    expect(await bytes()).toEqual(old)
    expect((await readdir(root)).filter((n) => n !== ".mehen.update.json" && n !== ".mehen.sha256")).toEqual(["mehen"])
  })

  test("a release build against the public base ignores MEHEN_RELEASE_KEYS: a manifest signed by the test key is refused", async () => {
    const fetched: string[] = []
    const publicFetch = async (url: string) => { fetched.push(url); return Response.json(await signed(manifest)) }
    await expect(run({ env: { ...env(), MEHEN_DL_BASE: "https://mehen.dev/dl" }, fetch: publicFetch })).rejects.toThrow("signed by a key this build does not trust")
    expect(fetched).toEqual(["https://mehen.dev/dl/latest.json"])
    expect(requests).toEqual([])
    expect(await bytes()).toEqual(old)
  })

  // An invalid signature naming trusted A, then a
  // valid one by trusted B. The record names B, the key that verified, in an
  // update and in a rollback.
  test("the installed record names the key whose signature verified, not the first trusted id a signature names", async () => {
    const make = async (id: string) => {
      const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
      const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
      return { key: { id, alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y! }, presence: "none", created: "2026-10-28T12:00:00.000Z" } as ReleaseKey, signer: pair.privateKey }
    }
    const a = await make("trusted-a")
    const b = await make("trusted-b")
    const forger = await make("forger")
    const twoKey = async (value: ReleaseManifest) => {
      const bytesToSign = manifestSigningBytes(value)
      const bad = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, forger.signer, bytesToSign))
      const good = base64UrlEncode(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, b.signer, bytesToSign))
      return { ...value, signatures: [{ keyId: "trusted-a", alg: "ES256", signature: bad }, { keyId: "trusted-b", alg: "ES256", signature: good }] }
    }
    const fetcher = async (url: string, init?: RequestInit) => (url.endsWith(".json") ? Response.json(await twoKey(manifest)) : fetch(url, init))
    const keys = { ...env(), MEHEN_RELEASE_KEYS: JSON.stringify([a.key, b.key]) }
    expect(await run({ env: keys, fetch: fetcher })).toMatchObject({ result: "updated", to: "1.2.3" })
    expect((await state()).installed?.keyId).toBe("trusted-b")
    setRelease(release("1.3.0"), "1.3.0")
    expect(await run({ env: keys, fetch: fetcher, current: "1.2.3" })).toMatchObject({ result: "updated", to: "1.3.0" })
    expect((await state()).installed?.keyId).toBe("trusted-b")
    expect(await run({ env: keys, current: "1.3.0", rollback: true })).toMatchObject({ result: "rolled_back", to: "1.2.3" })
    expect((await state()).installed).toMatchObject({ version: "1.2.3", keyId: "trusted-b", by: "rollback" })
  })

  test("a signature by another key is refused", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const forged = async () => {
      const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, manifestSigningBytes(manifest))
      return Response.json({ ...manifest, signatures: [{ keyId: releaseKey.id, alg: "ES256", signature: base64UrlEncode(signature) }] })
    }
    await expect(run({ fetch: forged })).rejects.toThrow("does not verify")
    expect(await bytes()).toEqual(old)
  })

  test("downgrade is refused unless forced; a forced downgrade holds later releases below what it replaced", async () => {
    await expect(run({ current: "2.0.0" })).rejects.toThrow("downgrade")
    expect(await bytes()).toEqual(old)
    // A refusal is no failed update.
    expect((await state()).lastUpdate).toBeNull()
    expect(await run({ current: "2.0.0", force: true })).toMatchObject({ result: "updated", available: false })
    expect((await state()).holdBelow).toBe("2.0.0")
    // The background updater does not go back up past the hold to the same release.
    expect(await run({ current: "1.2.3", by: "auto" })).toMatchObject({ result: "current" })
  })

  // A record matching the bytes on disk says 1.0.0
  // with no highestSeen, the process runs 2.0.0, and a valid signed 1.2.3 is
  // offered. It is below the running version: never installed without --force.
  test("an ordinary update never goes below the running version, whatever the matching record on disk says", async () => {
    const install = installation(binary)
    const seeded = freshInstallState()
    seeded.installed = { version: "1.0.0", commit: "0ld0000", sha256: sha256(old), size: old.length, at: "2026-10-28T00:00:00Z", by: "install", keyId: null, manifestSha256: null, manifest: null }
    await writeInstallState(install, seeded)
    for (const by of ["auto", "heal"] as const) {
      expect(await run({ current: "2.0.0", by })).toMatchObject({ result: "current", updated: false })
      expect(await bytes()).toEqual(old)
    }
    await expect(run({ current: "2.0.0", by: "manual" })).rejects.toThrow("Refusing to downgrade mehen from 2.0.0 to 1.2.3")
    expect(await run({ current: "1.2.3", by: "auto" })).toMatchObject({ result: "current" })
    expect(await bytes()).toEqual(old)
    expect((await state()).installed?.version).toBe("1.0.0")
    // The explicit exception stays: --force installs the signed release.
    expect(await run({ current: "2.0.0", by: "manual", force: true })).toMatchObject({ result: "updated", to: "1.2.3" })
    expect((await state()).holdBelow).toBe("2.0.0")
  })

  test("a signed manifest below the highest release this machine saw is held, not installed", async () => {
    expect(await run({ check: false, current: "1.0.0" })).toMatchObject({ result: "updated", to: "1.2.3" })
    // Back on an older binary (a hand copy) a replayed older signed manifest is still above it.
    await writeFile(binary, old, { mode: 0o755 })
    setRelease(release("1.1.0"), "1.1.0")
    expect(await run()).toMatchObject({ result: "held", latest: "1.1.0" })
    expect(await bytes()).toEqual(old)
  })

  test("--version installs that signed release; a manifest naming another version is refused", async () => {
    setRelease(release("1.2.3"))
    expect(await run({ version: "1.2.3" })).toMatchObject({ result: "updated", to: "1.2.3" })
    expect(requests).toContain("/dl/v1.2.3/manifest.json")
    await expect(run({ version: "9.9.9" })).rejects.toThrow("names 1.2.3")
    await expect(run({ version: "1.0;rm" })).rejects.toThrow("--version")
  })

  test("unsupported platform, missing target, symlink target and a read-only directory are refused", async () => {
    await expect(run({ platform: "win32" })).rejects.toThrow("macOS and Linux")
    await expect(run({ arch: "riscv64" })).rejects.toThrow("arm64 and x64")
    manifest.files = []
    await expect(run()).rejects.toThrow("no mehen-linux-x64")
    await rm(binary)
    await symlink(join(root, "other"), binary)
    await expect(run()).rejects.toThrow("symlink")
    await rm(binary)
    await writeFile(binary, old, { mode: 0o755 })
    await chmod(root, 0o500)
    try {
      await expect(run()).rejects.toThrow("not writable")
    } finally {
      await chmod(root, 0o700)
    }
  })

  test("symlinked or non-file install receipts are refused before replacement", async () => {
    await symlink(binary, join(root, ".mehen.sha256"))
    await expect(run()).rejects.toThrow("receipt")
    expect(await bytes()).toEqual(old)
    await rm(join(root, ".mehen.sha256"))
    await mkdir(join(root, ".mehen.sha256"))
    await expect(run()).rejects.toThrow("receipt")
  })
})

describe("the lock", () => {
  test("a live holder is never stolen, however old: the update reports locked and changes nothing", async () => {
    const sleeper = Bun.spawn(["sleep", "30"])
    try {
      await mkdir(join(root, ".mehen.update.lock"), { mode: 0o700 })
      await writeFile(join(root, ".mehen.update.lock/owner.json"), JSON.stringify({ pid: sleeper.pid, boot: "", at: "2020-01-01T00:00:00.000Z", by: "manual" }))
      const report = await run({ wait: false })
      expect(report).toMatchObject({ result: "locked", updated: false, holder: { pid: sleeper.pid, live: true } })
      expect(await bytes()).toEqual(old)
      expect(requests).toEqual([])
    } finally {
      sleeper.kill()
    }
  })

  // An updater killed between mkdir and its owner write left an empty lock
  // that stopped every later update on that installation.
  test("a lock with no owner is locked for the grace period, then the background update takes it over and updates", async () => {
    const lock = join(root, ".mehen.update.lock")
    await mkdir(lock, { mode: 0o700 })
    expect(await run({ by: "auto", wait: false })).toMatchObject({ result: "locked", updated: false, holder: { pid: 0, live: true } })
    expect(await bytes()).toEqual(old)
    expect(requests).toEqual([])
    const past = new Date(Date.now() - OWNERLESS_GRACE_MS - 60_000)
    await utimes(lock, past, past)
    expect(await run({ by: "auto", wait: false })).toMatchObject({ result: "updated", to: "1.2.3" })
    expect(await bytes()).toEqual(raw)
    expect(JSON.parse(await readFile(join(root, ".mehen.update.log"), "utf8"))).toMatchObject({ event: "lock", result: "reclaimed", reason: "ownerless" })
    expect(await readdir(root)).not.toContain(".mehen.update.lock")
  })

  test("a holder whose pid is gone is stale and reaped", async () => {
    const gone = Bun.spawn(["true"])
    await gone.exited
    await mkdir(join(root, ".mehen.update.lock"), { mode: 0o700 })
    await writeFile(join(root, ".mehen.update.lock/owner.json"), JSON.stringify({ pid: gone.pid, boot: "", at: new Date().toISOString(), by: "auto" }))
    expect(await run({ wait: false })).toMatchObject({ result: "updated" })
  })

  test("advice is a zero-wait write under the lock: skipped while the updater holds it, recorded after the journal and after the final record with nothing lost", async () => {
    const install = installation(binary)
    let during: InstallState | null = null
    await run({
      onStep: async (step) => {
        if (step !== "journal") return
        await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: null })
        during = await readInstallState(install)
      },
    })
    expect(during!.pending?.target.version).toBe("1.2.3")
    expect(during!.vault).toEqual({})
    await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.3.0", recommended: "1.2.3" })
    const after = await state()
    expect(after.vault["https://app.mehen.dev"]).toMatchObject({ minimum: "0.3.0", recommended: "1.2.3" })
    expect(after.installed?.version).toBe("1.2.3")
    expect(after.highestSeen).toBe("1.2.3")
    expect(after.pending).toBeNull()
  })
})

// A kill (SIGKILL, so no cleanup runs) after every step leaves exactly the
// old bytes or the new ones, and a state that describes them; the next run
// finishes or undoes the journal, offline included.
describe("kill after every step", () => {
  const steps: UpdateStep[] = ["locked", "recovered", "fetched", "staged", "smoked", "previous", "journal", "renamed", "record", "receipt", "retire-helper", "skills", "done"]
  const afterRename = new Set<UpdateStep>(["renamed", "record", "receipt", "retire-helper", "skills", "done"])
  for (const killAt of steps) test(`killed at ${killAt}`, async () => {
    const child = Bun.spawn([process.execPath, join(import.meta.dir, "testing/update-child.ts"), JSON.stringify({ binary, killAt, env: env(), current: "1.0.0" })], { stdout: "pipe", stderr: "pipe" })
    await child.exited
    expect(child.signalCode).toBe("SIGKILL")
    const disk = await bytes()
    const s = await readInstallState(installation(binary))
    if (afterRename.has(killAt)) {
      expect(disk).toEqual(raw)
      // The new bytes are described by the journal's target or by the record.
      expect(s?.pending?.target.sha256 === sha256(raw) || (s?.pending === null && s?.installed?.sha256 === sha256(raw))).toBe(true)
    } else {
      expect(disk).toEqual(old)
      if (s?.pending) expect(s.pending.previousSha256).toBe(sha256(old))
      if (s?.installed) expect(s.installed.sha256).toBe(sha256(old))
    }
    // Recovery offline: the dead holder's lock is reaped, the journal is
    // finished (after the rename) or undone (before it), whatever the network.
    offline = true
    const refused = await run({ by: "auto", wait: false }).then(() => null, (error: unknown) => error)
    // G0 F-4: the offline refusal keeps its code and says what recovery did first.
    expect(refused).toBeInstanceOf(CliError)
    const { code, message: said } = refused as CliError
    expect(code).toBe("network")
    expect(said).toEndWith("Release download failed (HTTP 503).")
    // After the skills step the update was complete: nothing was interrupted.
    if (afterRename.has(killAt) && killAt !== "skills" && killAt !== "done") expect(said).toStartWith("The interrupted update to 1.2.3 was finished first: mehen 1.2.3 is installed. ")
    else if (killAt === "journal") expect(said).toStartWith("The interrupted update to 1.2.3 was undone first: mehen 1.0.0 stays installed. ")
    else if (killAt === "staged" || killAt === "smoked" || killAt === "previous") expect(said).toStartWith("An interrupted update was cleaned up first (its staged download removed): mehen 1.0.0 is installed. ")
    else expect(said).toBe("Release download failed (HTTP 503).")
    const recovered = await state()
    expect(recovered.pending).toBeNull()
    expect(await staging()).toEqual([])
    if (afterRename.has(killAt)) {
      expect(await bytes()).toEqual(raw)
      expect(recovered.installed).toMatchObject({ version: "1.2.3", sha256: sha256(raw), keyId: releaseKey.id, by: "auto" })
      expect(await readFile(join(root, ".mehen.sha256"), "utf8")).toBe(`${sha256(raw)}\n`)
      expect(recovered.lastUpdate).toMatchObject({ to: "1.2.3", result: "ok" })
    } else {
      expect(await bytes()).toEqual(old)
      expect(recovered.installed).toMatchObject({ version: "1.0.0", sha256: sha256(old), by: "install" })
      // Back online the update completes from the start.
      offline = false
      expect(await run({ by: "auto", wait: false })).toMatchObject({ result: "updated", to: "1.2.3" })
      expect(await bytes()).toEqual(raw)
    }
  }, 20_000)

  test("kill before the rename, then recovery aborts: the journal and staging go, the old binary stays", async () => {
    const child = Bun.spawn([process.execPath, join(import.meta.dir, "testing/update-child.ts"), JSON.stringify({ binary, killAt: "journal", env: env(), current: "1.0.0" })], { stdout: "pipe", stderr: "pipe" })
    await child.exited
    expect((await state()).pending?.target.sha256).toBe(sha256(raw))
    expect((await staging()).length).toBe(1)
    offline = true
    await expect(run({ by: "auto" })).rejects.toThrow()
    expect((await state()).pending).toBeNull()
    expect(await staging()).toEqual([])
    expect(await bytes()).toEqual(old)
  })

  test("an unknown binary under a journal is refused: the journal stays, nothing is recorded over it", async () => {
    const child = Bun.spawn([process.execPath, join(import.meta.dir, "testing/update-child.ts"), JSON.stringify({ binary, killAt: "journal", env: env(), current: "1.0.0" })], { stdout: "pipe", stderr: "pipe" })
    await child.exited
    await writeFile(binary, "a hand copy", { mode: 0o755 })
    await expect(run()).rejects.toThrow("neither the previous nor the pending release")
    // The advice is for the human; it never sends an agent to the installer.
    const refusal = (await run().catch((e: CliError) => e)) as CliError
    expect(refusal).toMatchObject({ next: { command: "mehen doctor --json", say: expect.stringContaining("an agent must not rerun the installer or add --force") } })
    expect(JSON.stringify(refusal.next)).not.toMatch(/reinstall/i)
    const s = await state()
    expect(s.pending?.target.sha256).toBe(sha256(raw))
    expect(s.installed?.sha256).toBe(sha256(old))
    expect(s.lastUpdate).toMatchObject({ result: "failed", reason: "the binary on disk is neither the previous nor the pending release" })
  })
})

describe("reconcile and rollback", () => {
  test("a hand copy over a recorded release is recorded as by install with no key, and its receipt rewritten", async () => {
    await run()
    await writeFile(binary, old, { mode: 0o755 })
    expect(await run({ check: false, current: "1.0.0", fetch: async () => new Response("down", { status: 503 }) }).catch((e: Error) => e.message)).toContain("HTTP 503")
    const s = await state()
    expect(s.installed).toMatchObject({ version: "1.0.0", sha256: sha256(old), by: "install", keyId: null, manifest: null })
    expect(await readFile(join(root, ".mehen.sha256"), "utf8")).toBe(`${sha256(old)}\n`)
    expect(s.check?.error).toContain("HTTP 503")
  })

  test("rollback is verified against the retained signed manifest, swaps by one rename, holds below the release it left", async () => {
    setRelease(release("1.2.3"))
    await run()
    const first = raw
    setRelease(release("1.3.0"), "1.3.0")
    expect(await run({ current: "1.2.3" })).toMatchObject({ result: "updated", to: "1.3.0" })
    const report = await run({ current: "1.3.0", rollback: true })
    expect(report).toMatchObject({ result: "rolled_back", from: "1.3.0", to: "1.2.3" })
    expect(await bytes()).toEqual(first)
    const s = await state()
    expect(s.installed).toMatchObject({ version: "1.2.3", by: "rollback", sha256: sha256(first), keyId: releaseKey.id })
    expect(s.holdBelow).toBe("1.3.0")
    // The release rolled back from is now the previous pair, still signed.
    expect(JSON.parse(await readFile(join(root, ".mehen.previous.json"), "utf8"))).toMatchObject({ version: "1.3.0", keyId: releaseKey.id })
    expect(await run({ current: "1.2.3", by: "auto" })).toMatchObject({ result: "held" })
  })

  test("rollback refuses a previous without signed metadata, a tampered previous and a forged retained manifest", async () => {
    await run()
    // The previous is the never-verified 1.0.0 (by install).
    await expect(run({ current: "1.2.3", rollback: true })).rejects.toThrow("previous binary cannot be verified")
    const refusal = (await run({ current: "1.2.3", rollback: true }).catch((e: CliError) => e)) as CliError
    expect(refusal).toMatchObject({ next: { command: "mehen update --force --version <v> --json", say: expect.stringContaining("an agent must not rerun the installer or add --force") } })
    expect(`${refusal.message} ${JSON.stringify(refusal.next)}`).not.toMatch(/reinstall/i)
    setRelease(release("1.3.0"), "1.3.0")
    await run({ current: "1.2.3" })
    await writeFile(join(root, ".mehen.previous"), "tampered")
    await expect(run({ current: "1.3.0", rollback: true })).rejects.toThrow("previous binary cannot be verified")
    const meta = JSON.parse(await readFile(join(root, ".mehen.previous.json"), "utf8"))
    meta.manifest.files[0].sha256 = sha256(new TextEncoder().encode("tampered"))
    meta.sha256 = meta.manifest.files[0].sha256
    meta.size = 8
    await writeFile(join(root, ".mehen.previous.json"), JSON.stringify(meta))
    await expect(run({ current: "1.3.0", rollback: true })).rejects.toThrow("previous binary cannot be verified")
    expect(await bytes()).toEqual(raw)
  })

  test("two homes that share one binary share one installation and one lock", async () => {
    const a = join(root, "a")
    const b = join(root, "b")
    await mkdir(a)
    await mkdir(b)
    await symlink(binary, join(a, "mehen"))
    await symlink(binary, join(b, "mehen"))
    expect(installation(join(a, "mehen")).files.lock).toBe(installation(join(b, "mehen")).files.lock)
    const held = await withInstallLock(installation(join(a, "mehen")), "manual", async () => run({ install: installation(join(b, "mehen")), wait: false }))
    expect(held.ok && held.value.result).toBe("locked")
  })
})

// Scheduling: after a command, a detached
// `update --background` with MEHEN_UPDATE_CHILD=1 when a check is due, for
// a release installation with auto-update on, never otherwise.
describe("scheduling the background updater", () => {
  const recorder = new TextEncoder().encode(`#!/bin/sh\nprintf '%s|%s\\n' "$*" "$MEHEN_UPDATE_CHILD" >> "$HOME/spawned"\n`)
  const installed = (extra: Record<string, string> = {}) => ({ ...env(), MEHEN_SELF_EXECUTABLE: binary, CI: "", ...extra })
  async function spawned(): Promise<string> {
    for (let i = 0; i < 100; i++) {
      const text = await readFile(join(root, "spawned"), "utf8").catch(() => "")
      if (text) return text
      await Bun.sleep(20)
    }
    return ""
  }
  beforeEach(async () => {
    await writeFile(binary, recorder, { mode: 0o755 })
  })

  test("a fresh installation is due: one detached child, update --background with MEHEN_UPDATE_CHILD=1, its output to the 0600 log", async () => {
    expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("spawned")
    expect(await spawned()).toBe("update --background|1\n")
    expect((await lstat(join(root, ".mehen.update.log"))).mode & 0o777).toBe(0o600)
  })

  test("a lock with no owner holds the updater back for the grace period, and no longer after it", async () => {
    const lock = installation(binary).files.lock
    await mkdir(lock, { mode: 0o700 })
    expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("skipped")
    const past = new Date(Date.now() - OWNERLESS_GRACE_MS - 60_000)
    await utimes(lock, past, past)
    expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("spawned")
    expect(await spawned()).toBe("update --background|1\n")
  })

  test("never for the excluded commands, an updater child, a re-executed heal, skills-only setup, a source run, CI, MEHEN_NO_AUTO_UPDATE, settings, or a read-only directory", async () => {
    for (const command of [undefined, "update", "version", "--version", "help", "--help", "guide", "mcp"]) expect(await scheduleBackgroundUpdate(installed(), command)).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed({ MEHEN_SETUP_SKILLS_ONLY: "1" }), "setup")).toBe("skipped")
    for (const extra of [{ MEHEN_UPDATE_CHILD: "1" }, { MEHEN_UPDATE_RETRIED: "1" }, { CI: "true" }, { MEHEN_NO_AUTO_UPDATE: "1" }] as Record<string, string>[]) expect(await scheduleBackgroundUpdate(installed(extra), "status")).toBe("skipped")
    const { MEHEN_SELF_EXECUTABLE: _self, ...source } = installed()
    expect(await scheduleBackgroundUpdate(source, "status")).toBe("skipped")
    await mkdir(join(root, "config"), { mode: 0o700 })
    await writeFile(join(root, "config/settings.json"), '{"autoUpdate": false}')
    expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("skipped")
    await rm(join(root, "config/settings.json"))
    await chmod(root, 0o500)
    try {
      expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("skipped")
    } finally {
      await chmod(root, 0o700)
    }
    expect(await spawned()).toBe("")
  })

  // A malformed journal is the human's to repair (doctor names it); an
  // updater child would only refuse to read it again.
  test("a malformed journal launches no updater: not from a command, not after a cli_outdated, not from an idle mcp server", async () => {
    const install = installation(binary)
    await writeFile(install.files.state, JSON.stringify({ ...freshInstallState(), pending: { target: "nonsense" } }))
    const idleMcp = { executable: async () => binary, env: { HOME: root }, isIdle: () => true }
    expect(await scheduleBackgroundUpdate(installed(), "status")).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { outdated: true })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "mcp", { idleMcp })).toBe("skipped")
  })

  // The urgent cases are due at once, even a minute after a
  // check: a journal left by a kill, fresh vault advice, a cli_outdated.
  test("vault advice above this version is urgent until a check after it finds nothing newer or fails, then waits for the schedule or for higher advice; below a vault's minimum a failed check is retried at once", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-10-28T12:00:00.000Z")
    const state = freshInstallState()
    state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
    state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: VERSION, error: null, highestAnswered: "99.0.0" }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 3_600_001 })).toBe("spawned")
    state.check.latest = "99.0.0"
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
    state.check.latest = VERSION
    state.check.error = "offline"
    state.check.nextAt = new Date(now - 60_000 + 15 * 60_000).toISOString()
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now - 60_000 + 15 * 60_000 })).toBe("spawned")
    state.vault["https://app.mehen.dev"] = { minimum: "99.0.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
  })

  // After a rollback every run is held below the version rolled back from,
  // and a failing manifest fetch answers nothing: neither may launch an
  // updater every idle minute while the advice stays above the installation.
  describe("an idle mcp server whose last check was held or failed", () => {
    const now = Date.parse("2026-10-28T12:00:00.000Z")
    const idleMcp = { executable: async () => binary, env: { HOME: root }, isIdle: () => true }
    const ticks = async () => {
      const results: string[] = []
      for (let minute = 0; minute < 3; minute++) results.push(await scheduleBackgroundUpdate(installed(), "mcp", { now: now + minute * 60_000, idleMcp }))
      return results
    }
    const advised = () => {
      const state = freshInstallState()
      state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
      return state
    }

    test("held at or below holdBelow: nothing until the next check; a release above the hold or advice above what the check answered still spawns", async () => {
      const install = installation(binary)
      const state = advised()
      state.holdBelow = "99.0.0"
      state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: "99.0.0", error: null, highestAnswered: "99.0.0" }
      await writeInstallState(install, state)
      expect(await ticks()).toEqual(["skipped", "skipped", "skipped"])
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now: now + 3_600_000, idleMcp })).toBe("spawned")
      state.check.latest = "99.0.1"
      await writeInstallState(install, state)
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("spawned")
      state.check.latest = "99.0.0"
      state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.1", seenAt: new Date(now - 30_000).toISOString() }
      await writeInstallState(install, state)
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("spawned")
    })

    test("a manifest that went back below a release seen before: nothing until the next check", async () => {
      const install = installation(binary)
      const state = advised()
      state.highestSeen = "99.0.1"
      state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: "99.0.0", error: null, highestAnswered: "99.0.0" }
      await writeInstallState(install, state)
      expect(await ticks()).toEqual(["skipped", "skipped", "skipped"])
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now: now + 3_600_000, idleMcp })).toBe("spawned")
    })

    test("an install of the checked release that failed: an idle server waits for the next check, a command run by hand for the retry interval, and below a vault's minimum it retries at once", async () => {
      const install = installation(binary)
      const state = advised()
      state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: "99.0.0", error: null, highestAnswered: "99.0.0" }
      state.lastUpdate = { at: new Date(now - 30_000).toISOString(), from: VERSION, to: "99.0.0", result: "failed", reason: "smoke test failed", skills: [] }
      await writeInstallState(install, state)
      expect(await ticks()).toEqual(["skipped", "skipped", "skipped"])
      expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
      expect(await scheduleBackgroundUpdate(installed(), "status", { now: now - 30_000 + 15 * 60_000 - 1 })).toBe("skipped")
      expect(await scheduleBackgroundUpdate(installed(), "status", { now: now - 30_000 + 15 * 60_000 })).toBe("spawned")
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now: now - 30_000 + 15 * 60_000, idleMcp })).toBe("skipped")
      state.vault["https://app.mehen.dev"] = { minimum: "99.0.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
      await writeInstallState(install, state)
      expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
      state.vault = advised().vault
      state.lastUpdate = { ...state.lastUpdate, to: "98.0.0" }
      await writeInstallState(install, state)
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("spawned")
    })

    test("a failed fetch: nothing until its retry is due; advice above what it answered still spawns", async () => {
      const install = installation(binary)
      const state = advised()
      state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 15 * 60_000).toISOString(), base: "x", latest: null, error: "fetch failed", highestAnswered: "99.0.0" }
      await writeInstallState(install, state)
      expect(await ticks()).toEqual(["skipped", "skipped", "skipped"])
      expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now: now + 15 * 60_000, idleMcp })).toBe("spawned")
      state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.1", seenAt: new Date(now - 30_000).toISOString() }
      await writeInstallState(install, state)
      expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("spawned")
    })
  })

  // The 0.3.7 idle loop: a long-lived mehen mcp started on an older version
  // stayed behind the vault's advice forever although the installation
  // already met it, and launched an updater every minute that found it current.
  test("an idle mcp server whose installation already meets the vault's advice schedules nothing before the next check; one whose installation does not still does", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-10-28T12:00:00.000Z")
    const record = (version: string) => ({ version, commit: "abc", sha256: "a".repeat(64), size: 1, at: new Date(now - 120_000).toISOString(), by: "auto" as const, keyId: "rk", manifestSha256: null, manifest: null })
    const idleMcp = { executable: async () => binary, env: { HOME: root }, isIdle: () => true }
    const state = freshInstallState()
    state.installed = record("99.0.0")
    state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
    state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: "99.0.0", error: null, highestAnswered: "99.0.0" }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("skipped")
    state.installed = record(VERSION)
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp })).toBe("spawned")
  })

  // The record is not checked against the bytes: a hand copy of an older
  // binary keeps a newer record, and only the updater's own hash check
  // finds that, so every other command still runs it at once.
  test("any command but the idle mcp server judges the vault's advice against the running version, not the recorded installed one", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-10-28T12:00:00.000Z")
    const state = freshInstallState()
    state.installed = { version: "99.0.0", commit: "abc", sha256: "a".repeat(64), size: 1, at: new Date(now - 120_000).toISOString(), by: "auto", keyId: "rk", manifestSha256: null, manifest: null }
    state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now - 120_000).toISOString() }
    state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: "99.0.0", error: null, highestAnswered: "99.0.0" }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "mcp", { now, idleMcp: { executable: async () => binary, env: { HOME: root }, isIdle: () => true } })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
  })

  test("due by the schedule, or at once for a pending journal, vault advice above this version or a cli_outdated, a minute after the last check; never past a live holder", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-10-28T12:00:00.000Z")
    const state = freshInstallState()
    state.check = { at: new Date(now - 60_000).toISOString(), nextAt: new Date(now + 3_600_000).toISOString(), base: "x", latest: VERSION, error: null, highestAnswered: null }
    state.lastUpdate = { at: new Date(now - 60_000).toISOString(), from: "0.2.0", to: VERSION, result: "ok", reason: null, skills: [] }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now, outdated: true })).toBe("spawned")
    state.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now).toISOString() }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
    state.vault["https://app.mehen.dev"] = { minimum: "99.0.0", recommended: null, seenAt: new Date(now).toISOString() }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
    state.vault = {}
    state.pending = { target: { version: "9.9.9", commit: "abc", sha256: "a".repeat(64), size: 1, at: new Date(now).toISOString(), by: "auto", keyId: "rk", manifestSha256: null, manifest: null }, previousSha256: "b".repeat(64), steps: ["record"], since: new Date(now - 30_000).toISOString() }
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
    state.pending = null
    await writeInstallState(install, state)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("skipped")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 3_600_001 })).toBe("spawned")
    const sleeper = Bun.spawn(["sleep", "30"])
    try {
      await mkdir(install.files.lock, { mode: 0o700 })
      await writeFile(join(install.files.lock, "owner.json"), JSON.stringify({ pid: sleeper.pid, boot: "", at: new Date(now).toISOString(), by: "auto" }))
      expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 3_600_001 })).toBe("skipped")
    } finally {
      sleeper.kill()
    }
  })

  // Update rollout design gap 11: advice above the running version makes
  // the next command check at once; a check that finds nothing newer than
  // the running version must answer it, or every command would launch the
  // updater again.
  test("an urgent check whose latest is not above the running version answers the advice: no command spawns again before the hourly schedule", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-11-03T12:00:00.000Z")
    const advice = { minimum: "0.2.0", recommended: "99.0.0" }
    // The advice as recordVaultAdvice would write it, on this test's clock.
    const advised = freshInstallState()
    advised.vault["https://app.mehen.dev"] = { ...advice, seenAt: new Date(now - 60_000).toISOString() }
    await writeInstallState(install, advised)
    expect(await scheduleBackgroundUpdate(installed(), "status", { now })).toBe("spawned")
    setRelease(release(VERSION), VERSION)
    expect(await run({ by: "auto", current: VERSION, now: () => now + 1_000 })).toMatchObject({ result: "current" })
    for (const minutes of [1, 2, 15, 30, 59]) {
      await recordVaultAdvice(install, "https://app.mehen.dev", advice)
      expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + minutes * 60_000 }), `${minutes} min`).toBe("skipped")
    }
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 66 * 60_000 })).toBe("spawned")
  })

  // A highest answered that no version compares with made all advice look
  // answered, so no advice was urgent on that machine again.
  test("a check records the highest advice it can compare, whatever an earlier check or a vault left that it cannot, so higher advice is still urgent", async () => {
    const install = installation(binary)
    const now = Date.parse("2026-11-03T12:00:00.000Z")
    const advised = freshInstallState()
    advised.check = { at: new Date(now - 7_200_000).toISOString(), nextAt: new Date(now - 3_600_000).toISOString(), base: "x", latest: VERSION, error: null, highestAnswered: "garbage" }
    advised.vault["https://broken.example"] = { minimum: "garbage", recommended: null, seenAt: new Date(now - 60_000).toISOString() }
    advised.vault["https://app.mehen.dev"] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(now - 60_000).toISOString() }
    await writeInstallState(install, advised)
    setRelease(release(VERSION), VERSION)
    expect(await run({ by: "auto", current: VERSION, now: () => now })).toMatchObject({ result: "current" })
    expect((await state()).check?.highestAnswered).toBe("99.0.0")
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 60_000 })).toBe("skipped")
    await recordVaultAdvice(install, "https://app.mehen.dev", { minimum: "0.2.0", recommended: "99.0.1" })
    expect(await scheduleBackgroundUpdate(installed(), "status", { now: now + 60_000 })).toBe("spawned")
  })

  // The vault recommends the published release, so every machine below it
  // holds that advice: one that cannot install the release must not launch
  // an updater, and download it again, on every command.
  describe("a machine that cannot install the release the vault recommends", () => {
    const start = Date.parse("2026-11-03T12:00:00.000Z")
    const origin = "https://app.mehen.dev"

    // An hour of a command and an idle `mehen mcp` tick every minute, each
    // after a vault call that recorded the advice it was given (as
    // recordVaultAdvice does, on this test's clock); every spawn runs the
    // updater as its child would. The minutes that spawned.
    async function spawnMinutes(recommended: (minute: number) => string = () => "99.0.0"): Promise<number[]> {
      const install = installation(binary)
      const idleMcp = { executable: async () => binary, env: { HOME: root }, isIdle: () => true }
      await writeInstallState(install, freshInstallState())
      const minutes: number[] = []
      for (let minute = 0; minute < 60; minute++) {
        const now = start + minute * 60_000
        for (const command of ["status", "mcp"]) {
          const state = await readInstallState(install)
          if (state && state.vault[origin]?.recommended !== recommended(minute)) {
            state.vault[origin] = { minimum: "0.2.0", recommended: recommended(minute), seenAt: new Date(now).toISOString() }
            await writeInstallState(install, state)
          }
          if ((await scheduleBackgroundUpdate(installed(), command, { now, idleMcp })) !== "spawned") continue
          minutes.push(minute)
          await run({ by: "auto", current: VERSION, now: () => now }).catch(() => {})
        }
      }
      return minutes
    }

    test("a release with no smoke-test pass on this platform: one updater per retry interval", async () => {
      setRelease(new TextEncoder().encode("#!/bin/sh\nexit 1\n"), "99.0.0")
      expect(await spawnMinutes()).toEqual([0, 15, 30, 45])
      expect((await state()).lastUpdate).toMatchObject({ to: "99.0.0", result: "failed", reason: "smoke_failed" })
    })

    test("a release with no binary for this platform: one updater per retry interval", async () => {
      setRelease(release("99.0.0"), "99.0.0")
      manifest.files = manifest.files.filter((file) => file.name !== "mehen-linux-x64")
      expect(await spawnMinutes()).toEqual([0, 15, 30, 45])
      expect((await state()).lastUpdate).toMatchObject({ to: "99.0.0", result: "failed", reason: "no_binary_for_platform" })
    })

    test("downloads blocked while the vault answers: one updater per retry interval", async () => {
      setRelease(release("99.0.0"), "99.0.0")
      bad = "blocked"
      expect(await spawnMinutes()).toEqual([0, 15, 30, 45])
      expect((await state()).lastUpdate).toMatchObject({ to: "99.0.0", result: "failed" })
    })

    test("no release check gets through while the vault answers: one updater per retry interval", async () => {
      offline = true
      expect(await spawnMinutes()).toEqual([0, 15, 30, 45])
      expect((await state()).check).toMatchObject({ error: expect.any(String) })
    })

    // A cold vault isolate recommends its floor until its first read of the
    // published release, a warm one the release: the advice alternates, and
    // advice already answered must not count as new each time it returns.
    test("advice that alternates between the floor and the release, with an install that fails: one updater per retry interval", async () => {
      setRelease(new TextEncoder().encode("#!/bin/sh\nexit 1\n"), "99.0.0")
      // At minute 15 the advice is the floor, so the retry waits for the next
      // advice of the release.
      expect(await spawnMinutes((minute) => (minute % 2 === 0 ? "99.0.0" : "0.2.0"))).toEqual([0, 16, 32, 48])
      expect((await state()).lastUpdate).toMatchObject({ to: "99.0.0", result: "failed", reason: "smoke_failed" })
    })

    test("advice above what a check answered is new: it launches the updater at once", async () => {
      setRelease(new TextEncoder().encode("#!/bin/sh\nexit 1\n"), "99.0.0")
      expect(await spawnMinutes((minute) => (minute < 20 ? "99.0.0" : "99.0.1"))).toEqual([0, 15, 20, 35, 50])
    })

    // The rename can fail after the journal is written (an immutable binary,
    // a binary owned by someone else in a sticky directory, a bind mount);
    // here the staged file is gone when it runs.
    test("a rename that fails after the journal: the old binary stays, install_failed is recorded and nothing spawns within the retry interval", async () => {
      const install = installation(binary)
      const before = await bytes()
      setRelease(release("99.0.0"), "99.0.0")
      const advised = freshInstallState()
      advised.vault[origin] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(start).toISOString() }
      await writeInstallState(install, advised)
      const failRename = async (step: UpdateStep) => {
        if (step === "journal") for (const name of await staging()) await rm(join(root, name, "mehen"))
      }
      await expect(run({ by: "auto", current: VERSION, now: () => start, onStep: failRename })).rejects.toThrow(/ENOENT/)
      expect(await bytes()).toEqual(before)
      const s = await state()
      expect(s.pending).toBeNull()
      expect(s.lastUpdate).toMatchObject({ from: VERSION, to: "99.0.0", result: "failed", reason: "install_failed" })
      const idleMcp = { executable: async () => binary, env: { HOME: root }, isIdle: () => true }
      for (const minute of [1, 14]) {
        expect(await scheduleBackgroundUpdate(installed(), "status", { now: start + minute * 60_000 }), `${minute} min`).toBe("skipped")
        expect(await scheduleBackgroundUpdate(installed(), "mcp", { now: start + minute * 60_000, idleMcp }), `${minute} min, idle`).toBe("skipped")
      }
      expect(await scheduleBackgroundUpdate(installed(), "status", { now: start + 15 * 60_000 })).toBe("spawned")
    })

    // Between the check and the download: a recorded installed version this
    // build cannot compare, or no room for the staging directory.
    describe("a failure after the check and before the download", () => {
      const failsThenBacksOff = async (expected: RegExp) => {
        setRelease(release("99.0.0"), "99.0.0")
        await expect(run({ by: "auto", current: VERSION, now: () => start })).rejects.toThrow(expected)
        expect((await state()).lastUpdate).toMatchObject({ to: "99.0.0", result: "failed", reason: "install_failed" })
        for (const minute of [1, 14]) expect(await scheduleBackgroundUpdate(installed(), "status", { now: start + minute * 60_000 }), `${minute} min`).toBe("skipped")
        expect(await scheduleBackgroundUpdate(installed(), "status", { now: start + 15 * 60_000 })).toBe("spawned")
      }
      const advised = () => {
        const state = freshInstallState()
        state.vault[origin] = { minimum: "0.2.0", recommended: "99.0.0", seenAt: new Date(start).toISOString() }
        return state
      }

      test("an installed record whose version does not compare: install_failed, then the retry interval", async () => {
        const disk = await bytes()
        const state = advised()
        state.installed = { version: "garbage", commit: "abc", sha256: sha256(disk), size: disk.length, at: new Date(start - 60_000).toISOString(), by: "auto", keyId: "rk", manifestSha256: null, manifest: null }
        await writeInstallState(installation(binary), state)
        await failsThenBacksOff(/Invalid release version/)
      })

      test("a staging directory that cannot be made: install_failed, then the retry interval", async () => {
        await writeInstallState(installation(binary), advised())
        const realMkdtemp = fsPromises.mkdtemp
        const full = spyOn(fsPromises, "mkdtemp").mockImplementation((async (prefix: string) => {
          if (prefix.startsWith(join(root, ".mehen-update."))) throw Object.assign(new Error("ENOSPC: no space left on device, mkdtemp"), { code: "ENOSPC" })
          return realMkdtemp(prefix)
        }) as typeof fsPromises.mkdtemp)
        try {
          await failsThenBacksOff(/ENOSPC/)
        } finally {
          full.mockRestore()
        }
      })
    })
  })
})

// Update rollout design: a release reaches a machine at its next check, so
// checks are hourly with five minutes of spread, and a failed one is retried
// in fifteen minutes.
describe("the check schedule", () => {
  const at = Date.parse("2026-11-03T12:00:00.000Z")
  const due = async () => Date.parse((await state()).check!.nextAt) - at

  test("a check that fetched the manifest is next due an hour later, plus at most five minutes", async () => {
    for (let i = 0; i < 20; i++) {
      expect(await run({ current: "1.2.3", now: () => at })).toMatchObject({ result: "current" })
      const wait = await due()
      expect(wait).toBeGreaterThanOrEqual(3_600_000)
      expect(wait).toBeLessThan(3_600_000 + 5 * 60_000)
    }
  })

  test("a check that could not fetch it is retried fifteen minutes later", async () => {
    offline = true
    await expect(run({ now: () => at })).rejects.toThrow()
    expect((await state()).check).toMatchObject({ error: expect.any(String) })
    expect(await due()).toBe(15 * 60_000)
  })
})

describe("the foreground heal", () => {
  const helper = process.platform === "darwin" ? "embedded" : "none"
  const log = () => readFile(join(root, ".mehen.update.log"), "utf8").catch(() => "")

  // A deadline before the rename returns with the
  // old binary and no work left running; nothing is installed afterwards.
  test("a deadline before the rename stops the updater: the old binary stays and nothing happens after the heal returns", async () => {
    const installedEnv = { ...env(), MEHEN_SELF_EXECUTABLE: binary, CI: "" }
    setRelease(release("9.9.9", { helper }), "9.9.9")
    manifestDelay = 400
    const started = Date.now()
    expect(await healInForeground(installedEnv, { budgetMs: 50 })).toBeNull()
    expect(Date.now() - started).toBeLessThan(350)
    await Bun.sleep(600)
    expect(await bytes()).toEqual(old)
    expect(await staging()).toEqual([])
    expect(await readdir(root)).not.toContain(".mehen.update.lock")
    expect((await state())?.pending ?? null).toBeNull()
    expect(await log()).toContain('"result":"stopped"')
    expect(await log()).not.toContain('"result":"updated"')
  })

  test("a deadline after the rename leaves the new bytes and a recoverable journal, kills the skills child, and nothing continues; the next run finishes it", async () => {
    const installedEnv = { ...env(), MEHEN_SELF_EXECUTABLE: binary, CI: "" }
    setRelease(release("9.9.9", { helper, slowSkills: true }), "9.9.9")
    const started = Date.now()
    expect(await healInForeground(installedEnv, { budgetMs: 1200 })).toBeNull()
    expect(Date.now() - started).toBeLessThan(2500)
    expect(await bytes()).toEqual(raw)
    const left = await state()
    expect(left.pending?.target.version).toBe("9.9.9")
    expect(left.pending?.steps).toEqual(["skills"])
    expect(await readdir(root)).not.toContain(".mehen.update.lock")
    await Bun.sleep(500)
    expect(await state()).toEqual(left)
    offline = true
    await run({ current: VERSION, by: "auto", refreshSkills: async () => [] }).catch(() => {})
    expect((await state()).pending).toBeNull()
    expect((await state()).installed).toMatchObject({ version: "9.9.9", by: "heal" })
  })
  test("updates by heal and reports the newer version on disk; preDispatchHeal does nothing without a recorded minimum above this version", async () => {
    const installedEnv = { ...env(), MEHEN_SELF_EXECUTABLE: binary, CI: "" }
    requests = []
    await preDispatchHeal(installedEnv, ["status"])
    expect(requests).toEqual([])
    setRelease(release("9.9.9", { helper }), "9.9.9")
    expect(await healInForeground(installedEnv)).toEqual({ from: VERSION, to: "9.9.9" })
    expect(await bytes()).toEqual(raw)
    expect((await state()).installed).toMatchObject({ version: "9.9.9", by: "heal" })
    // Nothing newer: no heal to report.
    expect(await healInForeground(installedEnv)).toEqual({ from: VERSION, to: "9.9.9" })
    expect(await healInForeground({ ...installedEnv, MEHEN_NO_AUTO_UPDATE: "1" })).toBeNull()
  })
})
