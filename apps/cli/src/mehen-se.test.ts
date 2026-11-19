import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto"
import { chmod, copyFile, lstat, mkdir, mkdtemp, readdir, rm, stat, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createProof, importDeviceKey, parseProof, verifyProof, bodyHash } from "@mehen/protocol/proof"
import { ENCLAVE_KEY_FILE, ENCLAVE_KEY_SCOPE_FILE, ENCLAVE_PUBLIC_KEY_FILE, chooseBackend, createDeviceKey, loadDeviceKey, loadOrCreateDeviceKey } from "./device-key.ts"
import { CliError } from "./errors.ts"
import { derToRaw, ensureHelper, extractHelper, extractedHelperName, findHelper, helperAvailable, helperOverride, readyHelper } from "./mehen-se.ts"

describe("derToRaw", () => {
  test("converts a real DER ECDSA signature to r||s that WebCrypto verifies", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
    const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey
    const verifyKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    const data = new TextEncoder().encode("mehen proof")
    for (let i = 0; i < 20; i++) {
      const der = new Uint8Array(sign("sha256", data, { key: createPrivateKey(privateKey.export({ format: "pem", type: "pkcs8" })), dsaEncoding: "der" }))
      const raw = derToRaw(der)
      expect(raw).toHaveLength(64)
      expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifyKey, raw, data)).toBe(true)
    }
  })

  test("left-pads short integers and strips the sign byte", () => {
    const r = new Uint8Array(33).fill(0xff)
    r[0] = 0
    const der = new Uint8Array([0x30, 2 + 33 + 3, 0x02, 33, ...r, 0x02, 1, 7])
    const raw = derToRaw(der)
    expect([...raw.subarray(0, 32)]).toEqual(new Array(32).fill(0xff))
    expect([...raw.subarray(32, 63)]).toEqual(new Array(31).fill(0))
    expect(raw[63]).toBe(7)
  })

  test("refuses anything that is not a DER signature", () => {
    expect(() => derToRaw(new Uint8Array([1, 2, 3]))).toThrow(CliError)
    expect(() => derToRaw(new Uint8Array([0x30, 6, 0x02, 1, 5, 0x02, 1, 7, 0]))).toThrow(CliError)
  })
})

describe("helperOverride", () => {
  test("MEHEN_SE_PATH is taken from source and development builds, and ignored by a release build", () => {
    const env = { MEHEN_SE_PATH: "/somewhere/mehen-se" }
    expect(helperOverride(env, { compiled: false, kind: null })).toBe("/somewhere/mehen-se")
    expect(helperOverride(env, { compiled: true, kind: "dev" })).toBe("/somewhere/mehen-se")
    expect(helperOverride(env, { compiled: true, kind: "release" })).toBeNull()
    expect(helperOverride(env, { compiled: true, kind: null })).toBeNull()
    expect(helperOverride({}, { compiled: false, kind: null })).toBeNull()
  })

  test("this run from source takes it", () => {
    expect(helperOverride({ MEHEN_SE_PATH: "/somewhere/mehen-se" })).toBe("/somewhere/mehen-se")
  })
})

describe("findHelper", () => {
  test("MEHEN_SE_PATH must be executable, and nothing else is tried when it is set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mehen-se-find-"))
    const fake = join(dir, "mehen-se")
    await Bun.write(fake, "#!/bin/sh\nexit 0\n")
    expect(findHelper({ MEHEN_SE_PATH: fake }, dir)).toBeNull()
    await chmod(fake, 0o755)
    expect(findHelper({ MEHEN_SE_PATH: fake }, dir)).toBe(fake)
    await rm(dir, { recursive: true, force: true })
  })

  test("the 0.2.0 discovery is retired: a helper at <home>/bin/mehen-se or beside the binary is never run", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mehen-se-find-"))
    await Bun.write(join(dir, "bin", "mehen-se"), "#!/bin/sh\nexit 0\n")
    await chmod(join(dir, "bin", "mehen-se"), 0o755)
    expect(findHelper({}, dir)).toBeNull()
    expect(await ensureHelper({}, dir)).toBeNull()
    expect(await chooseBackend(null, { MEHEN_HOME: dir })).toBe("software")
    const refused = (await chooseBackend("secure-enclave", { MEHEN_HOME: dir }).catch((e: unknown) => e)) as CliError
    expect(refused.code).toBe("not_available")
    await rm(dir, { recursive: true, force: true })
  })
})

// A stand-in for mehen-se that needs no Secure Enclave: its "blob" is a
// private JWK, and it signs with WebCrypto exactly as the helper's protocol
// says (base64url r||s on stdout). Test keys only.
const FAKE_HELPER = `#!${process.execPath}
const [command, ...rest] = process.argv.slice(2)
const flag = (name) => { const i = rest.indexOf(name); return i === -1 ? null : rest[i + 1] }
if (command === "available") process.exit(0)
if (command === "sign") {
  const key = await crypto.subtle.importKey("jwk", JSON.parse(await Bun.file(flag("--key")).text()), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
  const data = new Uint8Array(await Bun.stdin.arrayBuffer())
  console.log(Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)).toString("base64url"))
  process.exit(0)
}
process.exit(2)
`

async function writeExecutable(path: string, text: string): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true })
  await writeFile(path, text)
  await chmod(path, 0o755)
}

describe("extracting the embedded helper", () => {
  test("extracts to <home>/bin/mehen-se-<hash16>, 0755 in a 0700 directory, and reuses it", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    const source = join(home, "embedded-source")
    await writeFile(source, "helper bytes v1")
    const name = extractedHelperName(new TextEncoder().encode("helper bytes v1"))
    expect(name).toMatch(/^mehen-se-[0-9a-f]{16}$/)
    const path = await extractHelper(source, home)
    expect(path).toBe(join(home, "bin", name))
    expect(await Bun.file(path).text()).toBe("helper bytes v1")
    expect((await stat(path)).mode & 0o777).toBe(0o755)
    expect((await stat(join(home, "bin"))).mode & 0o777).toBe(0o700)
    const first = await stat(path)
    expect(await extractHelper(source, home)).toBe(path)
    expect((await stat(path)).ino).toBe(first.ino)
    expect(findHelper({}, home)).toBe(path)
    // The right bytes that lost their executable bit are made executable again, in place.
    await chmod(path, 0o600)
    expect(findHelper({}, home)).not.toBe(path)
    expect(await extractHelper(source, home)).toBe(path)
    expect((await stat(path)).mode & 0o777).toBe(0o755)
    expect((await stat(path)).ino).toBe(first.ino)
    expect(findHelper({}, home)).toBe(path)
    await rm(home, { recursive: true, force: true })
  })

  test("a new helper replaces a changed file, and only plain stale helpers of this user are removed", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    const source = join(home, "embedded-source")
    await writeFile(source, "helper bytes v1")
    const old = await extractHelper(source, home)
    await writeFile(join(home, "bin", "mehen-se-ffffffffffffffff"), "an older helper")
    await symlink("/bin/sh", join(home, "bin", "mehen-se-eeeeeeeeeeeeeeee"))
    await writeFile(join(home, "bin", "mehen-se"), "a hand-placed helper")
    await writeFile(source, "helper bytes v2")
    const current = await extractHelper(source, home)
    expect(current).not.toBe(old)
    expect((await readdir(join(home, "bin"))).sort()).toEqual(["mehen-se", "mehen-se-eeeeeeeeeeeeeeee", current.split("/").at(-1)!].sort())
    expect((await lstat(join(home, "bin", "mehen-se-eeeeeeeeeeeeeeee"))).isSymbolicLink()).toBe(true)
    // A damaged file under the right name is rewritten, not trusted.
    await writeFile(current, "tampered")
    await extractHelper(source, home)
    expect(await Bun.file(current).text()).toBe("helper bytes v2")
    await rm(home, { recursive: true, force: true })
  })

  test("two extractors end with one correct file", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    const source = join(home, "embedded-source")
    await writeFile(source, "x".repeat(200_000))
    const paths = await Promise.all(Array.from({ length: 6 }, () => extractHelper(source, home)))
    expect(new Set(paths).size).toBe(1)
    expect(await readdir(join(home, "bin"))).toEqual([paths[0]!.split("/").at(-1)!])
    expect(await Bun.file(paths[0]!).text()).toBe("x".repeat(200_000))
    await rm(home, { recursive: true, force: true })
  })

  test("a linked <home>/bin is refused", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    await mkdir(join(home, "elsewhere"))
    await symlink(join(home, "elsewhere"), join(home, "bin"))
    await writeFile(join(home, "embedded-source"), "helper")
    const error = (await extractHelper(join(home, "embedded-source"), home).catch((e: unknown) => e)) as CliError
    expect(error.code).toBe("key_insecure")
    expect(await readdir(join(home, "elsewhere"))).toEqual([])
    await rm(home, { recursive: true, force: true })
  })

  test("the extracted helper is found and a legacy <home>/bin/mehen-se beside it is not; MEHEN_SE_PATH beats both", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    await writeExecutable(join(home, "bin", "mehen-se"), "#!/bin/sh\nexit 0\n")
    await writeFile(join(home, "embedded-source"), "#!/bin/sh\nexit 0\n# embedded\n")
    const extracted = await extractHelper(join(home, "embedded-source"), home)
    expect(findHelper({}, home)).toBe(extracted)
    await writeExecutable(join(home, "override"), "#!/bin/sh\nexit 0\n")
    expect(findHelper({ MEHEN_SE_PATH: join(home, "override") }, home)).toBe(join(home, "override"))
    expect(await ensureHelper({ MEHEN_SE_PATH: join(home, "override") }, home)).toBe(join(home, "override"))
    await rm(home, { recursive: true, force: true })
  })

  test("without an embedded helper, ensureHelper extracts nothing and finds nothing but MEHEN_SE_PATH", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    expect(await ensureHelper({}, home)).toBeNull()
    expect(await readdir(home)).toEqual([])
    await writeExecutable(join(home, "bin", "mehen-se"), "#!/bin/sh\nexit 0\n")
    expect(await ensureHelper({}, home)).toBeNull()
    expect(await ensureHelper({ MEHEN_SE_PATH: join(home, "bin", "mehen-se") }, home)).toBe(join(home, "bin", "mehen-se"))
    await rm(home, { recursive: true, force: true })
  })
})

// After the U1 handover: device-key.ts runs the helper
// ensureHelper finds under the resolved config root, never one in a slot.
// A slot enrolled on the Secure Enclave keeps working without MEHEN_SE_PATH
// once the helper is extracted into <root>/bin: its key is reused, never
// replaced, and signs proofs the vault verifies.
describe("an existing enclave-backed slot without MEHEN_SE_PATH", () => {
  test("finds the extracted helper under the root, reuses its key and signs proofs the vault verifies; a helper inside the slot is never run", async () => {
    const root = await mkdtemp(join(tmpdir(), "mehen-se-root-"))
    await chmod(root, 0o700)
    const dir = join(root, "workspaces", "vault.example", "tn_existing0001")
    await mkdir(dir, { recursive: true, mode: 0o700 })
    // A planted helper in the slot that would refuse to sign: never chosen.
    await writeExecutable(join(dir, "bin", "mehen-se"), "#!/bin/sh\nexit 3\n")
    await writeFile(join(root, "embedded-source"), FAKE_HELPER)
    const extracted = await extractHelper(join(root, "embedded-source"), root)
    expect(extracted).toStartWith(join(root, "bin", "mehen-se-"))
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string }
    const publicJwk = { kty: "EC" as const, crv: "P-256" as const, x: jwk.x, y: jwk.y }
    await writeFile(join(dir, ENCLAVE_KEY_FILE), JSON.stringify(privateKey.export({ format: "jwk" })), { mode: 0o600 })
    await writeFile(join(dir, ENCLAVE_PUBLIC_KEY_FILE), `${JSON.stringify(publicJwk)}\n`, { mode: 0o600 })
    await writeFile(join(dir, ENCLAVE_KEY_SCOPE_FILE), `${JSON.stringify({ vault: "https://vault.example", tenant: "tn_existing0001" })}\n`, { mode: 0o600 })
    const env = { MEHEN_HOME: root }
    expect(findHelper(env, root)).toBe(extracted)
    expect(findHelper(env, dir)).toBeNull()
    const reused = await loadOrCreateDeviceKey(dir, "secure-enclave", env, "https://vault.example")
    expect(reused.created).toBe(false)
    expect(reused.jwk).toEqual(publicJwk)
    const key = await loadDeviceKey(dir, "secure-enclave", env)
    expect(key.backend).toBe("secure-enclave")
    const url = "https://vault.example/v1/me"
    const token = await createProof(key.signer("dev_existing"), { method: "GET", url, body: "" }, { tenant: "tn_existing0001" })
    const parsed = parseProof(token)
    expect(await verifyProof(parsed, await importDeviceKey(publicJwk), { method: "GET", url, bodyHash: await bodyHash("") })).toEqual({ ok: true, claims: parsed.claims })
    if (process.platform === "darwin" && process.arch === "arm64") expect(await chooseBackend(null, env)).toBe("secure-enclave")
    await rm(root, { recursive: true, force: true })
  })
})

// The Secure Enclave backend needs Apple silicon and a Swift toolchain to
// build native/mehen-se; elsewhere these tests are skipped with the reason.
const appleSilicon = process.platform === "darwin" && process.arch === "arm64"
const swiftc = appleSilicon ? Bun.which("swiftc") : null
const skipReason = !appleSilicon ? "not macOS on Apple silicon" : !swiftc ? "no swiftc to build mehen-se" : null
if (skipReason) console.error(`mehen-se.test.ts: skipping Secure Enclave tests: ${skipReason}`)

describe.skipIf(skipReason !== null)("Secure Enclave backend (mehen-se)", () => {
  let work = ""
  let helper = ""
  let usable = false

  beforeAll(async () => {
    work = await mkdtemp(join(tmpdir(), "mehen-se-build-"))
    const native = join(import.meta.dir, "..", "native", "mehen-se")
    await copyFile(join(native, "mehen-se.swift"), join(work, "mehen-se.swift"))
    await copyFile(join(native, "build.sh"), join(work, "build.sh"))
    const build = Bun.spawn(["bash", join(work, "build.sh"), "--native"], { stdout: "pipe", stderr: "pipe", timeout: 240_000 })
    const [code, err] = await Promise.all([build.exited, new Response(build.stderr).text()])
    if (code !== 0) throw new Error(`mehen-se build failed: ${err}`)
    helper = join(work, "build", "mehen-se")
    usable = await helperAvailable(helper)
    if (!usable) console.error("mehen-se.test.ts: mehen-se built but the Secure Enclave is not available; enclave assertions skipped")
  }, 300_000)

  afterAll(async () => {
    if (work) await rm(work, { recursive: true, force: true })
  })

  test("is chosen by default on Apple silicon when the helper works", async () => {
    if (!usable) return
    expect(await chooseBackend(null, { MEHEN_SE_PATH: helper })).toBe("secure-enclave")
    expect(await chooseBackend("software", { MEHEN_SE_PATH: helper })).toBe("software")
  })

  test("--backend secure-enclave without a helper is refused with a next step", async () => {
    const error = (await chooseBackend("secure-enclave", { MEHEN_SE_PATH: join(work, "missing") }).catch((e: unknown) => e)) as CliError
    expect(error.code).toBe("not_available")
    expect(error.next?.command).toContain("--backend software")
  })

  test("creates a 0600 blob and signs proofs the vault verifies", async () => {
    if (!usable) return
    const dir = await mkdtemp(join(work, "cfg-"))
    const env = { MEHEN_SE_PATH: helper }
    const { jwk } = await createDeviceKey(dir, "secure-enclave", env)
    expect((await stat(join(dir, ENCLAVE_KEY_FILE))).mode & 0o777).toBe(0o600)
    const key = await loadDeviceKey(dir, "secure-enclave", env)
    const url = "https://vault.example/v1/items"
    const token = await createProof(key.signer("dev_se"), { method: "POST", url, body: '{"a":1}' }, { tenant: "ten_se" })
    const parsed = parseProof(token)
    const publicKey = await importDeviceKey(jwk)
    expect(await verifyProof(parsed, publicKey, { method: "POST", url, bodyHash: await bodyHash('{"a":1}') })).toEqual({ ok: true, claims: parsed.claims })
    const tampered = await verifyProof(parsed, publicKey, { method: "POST", url, bodyHash: await bodyHash('{"a":2}') })
    expect(tampered).toEqual({ ok: false, reason: "body" })
  })

  test("refuses a group-readable blob", async () => {
    if (!usable) return
    const dir = await mkdtemp(join(work, "cfg-"))
    await createDeviceKey(dir, "secure-enclave", { MEHEN_SE_PATH: helper })
    await chmod(join(dir, ENCLAVE_KEY_FILE), 0o640)
    const error = (await loadDeviceKey(dir, "secure-enclave", { MEHEN_SE_PATH: helper }).catch((e: unknown) => e)) as CliError
    expect(error.code).toBe("key_insecure")
  })
})

// What status and doctor use. The helper is taken only as it
// already is; nothing is created, extracted, chmodded or retired.
describe("readyHelper, the observing lookup", () => {
  async function listing(home: string): Promise<string[]> {
    const out: string[] = []
    for (const name of await readdir(home, { recursive: true })) {
      const info = await lstat(join(home, String(name)))
      out.push(`${String(name)}:${(info.mode & 0o7777).toString(8)}:${info.size}:${info.mtimeMs}`)
    }
    return out.sort()
  }

  test("absent, stale or not executable is null and leaves every file as it was; the exact extracted bytes, executable, are found", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    try {
      const source = join(home, "embedded-source")
      await writeFile(source, "helper bytes v2")
      // Absent: no bin/ is made.
      expect(await readyHelper({}, home, source)).toBeNull()
      expect(await readdir(home)).toEqual(["embedded-source"])
      // Stale: another release's extracted helper is neither used nor removed.
      await mkdir(join(home, "bin"), { mode: 0o700 })
      await writeFile(join(home, "bin", "mehen-se-0000000000000000"), "old helper", { mode: 0o755 })
      let before = await listing(home)
      expect(await readyHelper({}, home, source)).toBeNull()
      expect(await listing(home)).toEqual(before)
      // The right bytes without the executable bit: null, and no chmod.
      const target = join(home, "bin", extractedHelperName(new TextEncoder().encode("helper bytes v2")))
      await writeFile(target, "helper bytes v2", { mode: 0o600 })
      before = await listing(home)
      expect(await readyHelper({}, home, source)).toBeNull()
      expect(await listing(home)).toEqual(before)
      // Changed bytes under the right name: null.
      await chmod(target, 0o755)
      await writeFile(target, "helper bytes v3")
      expect(await readyHelper({}, home, source)).toBeNull()
      // The exact bytes, executable: found, with nothing changed.
      await writeFile(target, "helper bytes v2")
      before = await listing(home)
      expect(await readyHelper({}, home, source)).toBe(target)
      expect(await listing(home)).toEqual(before)
      // A non-executable MEHEN_SE_PATH is null, executable it is the only candidate.
      expect(await readyHelper({ MEHEN_SE_PATH: source }, home, source)).toBeNull()
      expect(await readyHelper({ MEHEN_SE_PATH: target }, home, null)).toBe(target)
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })

  test("an observing enclave key load makes nothing on disk and names the command that prepares the helper", async () => {
    const home = await mkdtemp(join(tmpdir(), "mehen-se-home-"))
    try {
      const slot = join(home, "workspaces", "app.mehen.dev", "tn_observe00000001")
      await mkdir(slot, { recursive: true, mode: 0o700 })
      await writeFile(join(slot, ENCLAVE_KEY_FILE), "blob", { mode: 0o600 })
      const error = (await loadDeviceKey(slot, "secure-enclave", { MEHEN_HOME: home }, { observe: true }).catch((e: unknown) => e)) as CliError
      expect(error).toBeInstanceOf(CliError)
      expect(error.code).toBe("not_available")
      expect(error.next?.command).toBe("mehen ls")
      expect(await readdir(home)).toEqual(["workspaces"])
    } finally {
      await rm(home, { recursive: true, force: true })
    }
  })
})
