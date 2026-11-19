import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmod, mkdir, readFile, rename, rm, stat, symlink } from "node:fs/promises"
import { userInfo } from "node:os"
import { join } from "node:path"
import { base64UrlEncode, randomBytes } from "@mehen/protocol/bytes"
import { type DeviceJwk, bodyHash, createProof, importDeviceKey, parseProof, verifyProof } from "@mehen/protocol/proof"
import { assertPrivateFile, ensureConfigDir } from "./config.ts"
import { ENCLAVE_KEY_FILE, ENCLAVE_KEY_SCOPE_FILE, ENCLAVE_PUBLIC_KEY_FILE, SOFTWARE_KEY_FILE, SOFTWARE_KEY_SCOPE_FILE, chooseBackend, createDeviceKey, loadDeviceKey, loadOrCreateDeviceKey, publicJwk, readKeyScope, removeDeviceKey, writeKeyScope } from "./device-key.ts"
import { ENCLAVE_BLOCKED_SAY } from "./mehen-se.ts"
import { CliError } from "./errors.ts"
import { fakeHelper } from "./testing/fake-mehen-se.ts"
import { tempDir } from "./testing/run-mehen.ts"

const VAULT = "https://vault.example"
const OTHER_VAULT = "https://other.example"

let dir: { path: string; remove(): Promise<void> }

beforeEach(async () => {
  dir = await tempDir()
})
afterEach(async () => dir.remove())

async function signsFor(key: Awaited<ReturnType<typeof loadOrCreateDeviceKey>>["key"], jwk: DeviceJwk): Promise<boolean> {
  const url = "https://vault.example/v1/enrol"
  const token = await createProof(key.signer("new"), { method: "POST", url, body: "{}" }, { tenant: "enrol" })
  const check = await verifyProof(parseProof(token), await importDeviceKey(jwk), { method: "POST", url, bodyHash: await bodyHash("{}") })
  return check.ok
}

describe("loadOrCreateDeviceKey, software", () => {
  test("creates a key when there is none, then reuses it: same public JWK, created only the first time", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(first.created).toBe(true)
    const second = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(second.created).toBe(false)
    expect(second.jwk).toEqual(first.jwk)
    expect(await signsFor(second.key, first.jwk)).toBe(true)
    expect((await stat(join(dir.path, SOFTWARE_KEY_FILE))).mode & 0o777).toBe(0o600)
  })

  test("publicJwk carries x and y only", async () => {
    const { jwk } = await createDeviceKey(dir.path, "software", {})
    const file = JSON.parse(await readFile(join(dir.path, SOFTWARE_KEY_FILE), "utf8")) as { kty: "EC"; crv: "P-256"; x: string; y: string; d: string }
    expect(file.d).toBeString()
    expect(publicJwk(file)).toEqual(jwk)
    expect(Object.keys(publicJwk(file)).sort()).toEqual(["crv", "kty", "x", "y"])
  })

  test("a key file other users can read is not reused: a fresh 0600 key replaces it", async () => {
    const first = await createDeviceKey(dir.path, "software", {})
    await chmod(join(dir.path, SOFTWARE_KEY_FILE), 0o644)
    const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(loaded.created).toBe(true)
    expect(loaded.jwk).not.toEqual(first.jwk)
    expect((await stat(join(dir.path, SOFTWARE_KEY_FILE))).mode & 0o777).toBe(0o600)
  })

  test("a key file that is not a P-256 private JWK is replaced", async () => {
    await Bun.write(join(dir.path, SOFTWARE_KEY_FILE), '{"kty":"EC","crv":"P-256","x":"short"}')
    await chmod(join(dir.path, SOFTWARE_KEY_FILE), 0o600)
    const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(loaded.created).toBe(true)
    expect(await signsFor(loaded.key, loaded.jwk)).toBe(true)
  })

  test("removeDeviceKey leaves nothing to reuse: key and scope file gone", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    await removeDeviceKey(dir.path, "software")
    await expect(stat(join(dir.path, SOFTWARE_KEY_SCOPE_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    const next = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(next.created).toBe(true)
    expect(next.jwk).not.toEqual(first.jwk)
  })

  test("a symbolic link in place of the key file is not followed: a fresh key replaces the link, the target is untouched", async () => {
    const elsewhere = await tempDir()
    try {
      const planted = await createDeviceKey(elsewhere.path, "software", {})
      const target = join(elsewhere.path, SOFTWARE_KEY_FILE)
      const before = await readFile(target, "utf8")
      await ensureConfigDir(dir.path)
      await symlink(target, join(dir.path, SOFTWARE_KEY_FILE))
      await expect(assertPrivateFile(join(dir.path, SOFTWARE_KEY_FILE))).rejects.toMatchObject({ code: "key_insecure", message: expect.stringContaining("symbolic link") })
      const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
      expect(loaded.created).toBe(true)
      expect(loaded.jwk).not.toEqual(planted.jwk)
      expect((await stat(join(dir.path, SOFTWARE_KEY_FILE))).isSymbolicLink()).toBe(false)
      expect(await readFile(target, "utf8")).toBe(before)
    } finally {
      await elsewhere.remove()
    }
  })

  test("a key file owned by another user is refused by the private-file check", async () => {
    await createDeviceKey(dir.path, "software", {})
    const path = join(dir.path, SOFTWARE_KEY_FILE)
    await expect(assertPrivateFile(path)).resolves.toBeUndefined()
    const error = (await assertPrivateFile(path, { owner: userInfo().uid + 1 }).catch((e: unknown) => e)) as CliError
    expect(error).toBeInstanceOf(CliError)
    expect(error.code).toBe("key_insecure")
    expect(error.message).toContain("owned by another user")
  })

  test("a directory in place of the key file is refused", async () => {
    await ensureConfigDir(dir.path)
    await mkdir(join(dir.path, SOFTWARE_KEY_FILE))
    const error = (await assertPrivateFile(join(dir.path, SOFTWARE_KEY_FILE)).catch((e: unknown) => e)) as CliError
    expect(error.code).toBe("key_insecure")
    expect(error.message).toContain("not a regular file")
  })

  test("a config directory owned by another user is refused before any key is read or written", async () => {
    await ensureConfigDir(dir.path)
    const error = (await ensureConfigDir(dir.path, { owner: userInfo().uid + 1 }).catch((e: unknown) => e)) as CliError
    expect(error).toBeInstanceOf(CliError)
    expect(error.code).toBe("key_insecure")
    expect(error.message).toContain("owned by another user")
  })

  test("correctly shaped but invalid curve material is not reusable: a fresh key, no abort", async () => {
    const coordinate = () => base64UrlEncode(randomBytes(32))
    const bogus = { kty: "EC", crv: "P-256", x: coordinate(), y: coordinate(), d: coordinate() }
    await ensureConfigDir(dir.path)
    await Bun.write(join(dir.path, SOFTWARE_KEY_FILE), JSON.stringify(bogus))
    await chmod(join(dir.path, SOFTWARE_KEY_FILE), 0o600)
    const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(loaded.created).toBe(true)
    expect(loaded.jwk.x).not.toBe(bogus.x)
    expect(await signsFor(loaded.key, loaded.jwk)).toBe(true)
  })

  test("a private scalar that does not match the public point is not reusable", async () => {
    const a = await createDeviceKey(dir.path, "software", {})
    const fileA = JSON.parse(await readFile(join(dir.path, SOFTWARE_KEY_FILE), "utf8")) as { d: string }
    const other = await tempDir()
    try {
      await createDeviceKey(other.path, "software", {})
      const fileB = JSON.parse(await readFile(join(other.path, SOFTWARE_KEY_FILE), "utf8")) as { x: string; y: string }
      await Bun.write(join(dir.path, SOFTWARE_KEY_FILE), JSON.stringify({ kty: "EC", crv: "P-256", x: fileB.x, y: fileB.y, d: fileA.d }))
      await chmod(join(dir.path, SOFTWARE_KEY_FILE), 0o600)
      const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
      expect(loaded.created).toBe(true)
      expect(loaded.jwk).not.toEqual(a.jwk)
      expect(loaded.jwk).not.toEqual({ kty: "EC", crv: "P-256", x: fileB.x, y: fileB.y })
    } finally {
      await other.remove()
    }
  })
})

describe("key scope", () => {
  test("a new key records the vault it was made for, with no tenant yet", async () => {
    await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(await readKeyScope(dir.path, "software")).toEqual({ vault: VAULT, tenant: null })
    expect((await stat(join(dir.path, SOFTWARE_KEY_SCOPE_FILE))).mode & 0o777).toBe(0o600)
  })

  test("a key made for another vault is refused with key_scope and nothing on disk changes", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    const before = await readFile(join(dir.path, SOFTWARE_KEY_FILE), "utf8")
    const error = (await loadOrCreateDeviceKey(dir.path, "software", {}, OTHER_VAULT).catch((e: unknown) => e)) as CliError
    expect(error).toBeInstanceOf(CliError)
    expect(error.code).toBe("key_scope")
    expect(error.message).toBe(`The software device key in ${dir.path} was made for ${VAULT}, not ${OTHER_VAULT}.`)
    expect(error.next?.command).toBe("mehen enrol --workspace <slug> --fresh-key")
    expect(error.next?.say).toContain(VAULT)
    expect(await readFile(join(dir.path, SOFTWARE_KEY_FILE), "utf8")).toBe(before)
    expect(await readKeyScope(dir.path, "software")).toEqual({ vault: VAULT, tenant: null })
    const same = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(same.created).toBe(false)
    expect(same.jwk).toEqual(first.jwk)
  })

  test("createDeviceKey with a scope replaces the key and the scope together", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    const fresh = await createDeviceKey(dir.path, "software", {}, { vault: OTHER_VAULT, tenant: null })
    expect(fresh.jwk).not.toEqual(first.jwk)
    expect(await readKeyScope(dir.path, "software")).toEqual({ vault: OTHER_VAULT, tenant: null })
    expect((await loadOrCreateDeviceKey(dir.path, "software", {}, OTHER_VAULT)).jwk).toEqual(fresh.jwk)
  })

  test("a key with no scope file (from before scopes) is adopted for the vault at hand and the scope written", async () => {
    const first = await createDeviceKey(dir.path, "software", {})
    expect(await readKeyScope(dir.path, "software")).toBeNull()
    const loaded = await loadOrCreateDeviceKey(dir.path, "software", {}, VAULT)
    expect(loaded.created).toBe(false)
    expect(loaded.jwk).toEqual(first.jwk)
    expect(await readKeyScope(dir.path, "software")).toEqual({ vault: VAULT, tenant: null })
  })

  test("a scope file that is a link or malformed reads as none", async () => {
    await createDeviceKey(dir.path, "software", {})
    await Bun.write(join(dir.path, SOFTWARE_KEY_SCOPE_FILE), "{")
    expect(await readKeyScope(dir.path, "software")).toBeNull()
    await rename(join(dir.path, SOFTWARE_KEY_SCOPE_FILE), join(dir.path, "elsewhere.json"))
    await symlink(join(dir.path, "elsewhere.json"), join(dir.path, SOFTWARE_KEY_SCOPE_FILE))
    expect(await readKeyScope(dir.path, "software")).toBeNull()
  })

  test("the tenant is recorded once written and the enclave backend has its own scope file", async () => {
    const env = { MEHEN_SE_PATH: await fakeHelper(dir.path) }
    await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(await readKeyScope(dir.path, "secure-enclave")).toEqual({ vault: VAULT, tenant: null })
    await writeKeyScope(dir.path, "secure-enclave", { vault: VAULT, tenant: "ten_1" })
    expect(await readKeyScope(dir.path, "secure-enclave")).toEqual({ vault: VAULT, tenant: "ten_1" })
    expect((await stat(join(dir.path, ENCLAVE_KEY_SCOPE_FILE))).mode & 0o777).toBe(0o600)
    await expect(loadOrCreateDeviceKey(dir.path, "secure-enclave", env, OTHER_VAULT)).rejects.toMatchObject({ code: "key_scope" })
    await removeDeviceKey(dir.path, "secure-enclave")
    await expect(stat(join(dir.path, ENCLAVE_KEY_SCOPE_FILE))).rejects.toMatchObject({ code: "ENOENT" })
  })
})

describe("loadOrCreateDeviceKey, secure-enclave (fake mehen-se)", () => {
  let env: Record<string, string>
  beforeEach(async () => {
    env = { MEHEN_SE_PATH: await fakeHelper(dir.path) }
  })

  test("create writes the blob and a 0600 sidecar with the public JWK only, and reuse proves the sidecar against the blob", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(first.created).toBe(true)
    const sidecar = JSON.parse(await readFile(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), "utf8")) as Record<string, unknown>
    expect(sidecar).toEqual(first.jwk)
    expect(Object.keys(sidecar).sort()).toEqual(["crv", "kty", "x", "y"])
    expect((await stat(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE))).mode & 0o777).toBe(0o600)
    const second = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(second.created).toBe(false)
    expect(second.jwk).toEqual(first.jwk)
    expect(await signsFor(second.key, first.jwk)).toBe(true)
  })

  test("a sidecar the blob cannot sign for is refused: a fresh key, never the foreign JWK", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    const other = await crypto.subtle.exportKey("jwk", (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])).publicKey)
    const foreign: DeviceJwk = { kty: "EC", crv: "P-256", x: other.x as string, y: other.y as string }
    await Bun.write(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), JSON.stringify(foreign))
    const loaded = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(loaded.created).toBe(true)
    expect(loaded.jwk).not.toEqual(foreign)
    expect(loaded.jwk).not.toEqual(first.jwk)
    expect(await signsFor(loaded.key, loaded.jwk)).toBe(true)
    expect(JSON.parse(await readFile(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), "utf8"))).toEqual(loaded.jwk)
  })

  test("a sidecar with a private scalar, a malformed one, or none at all: a fresh key", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    await Bun.write(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), JSON.stringify({ ...first.jwk, d: "AAAA" }))
    expect((await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)).created).toBe(true)
    await Bun.write(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), "not json")
    expect((await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)).created).toBe(true)
    await rm(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE))
    expect((await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)).created).toBe(true)
  })

  test("a blob the helper cannot sign with means a fresh key", async () => {
    await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    await Bun.write(join(dir.path, ENCLAVE_KEY_FILE), "corrupt")
    await chmod(join(dir.path, ENCLAVE_KEY_FILE), 0o600)
    const loaded = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(loaded.created).toBe(true)
    expect(await signsFor(loaded.key, loaded.jwk)).toBe(true)
  })

  test("a symbolic link in place of the sidecar or the blob is not followed: a fresh key", async () => {
    const first = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    await rename(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE), join(dir.path, "pub-elsewhere.json"))
    await symlink(join(dir.path, "pub-elsewhere.json"), join(dir.path, ENCLAVE_PUBLIC_KEY_FILE))
    const second = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(second.created).toBe(true)
    expect(second.jwk).not.toEqual(first.jwk)
    expect((await stat(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE))).isSymbolicLink()).toBe(false)
    await rename(join(dir.path, ENCLAVE_KEY_FILE), join(dir.path, "blob-elsewhere"))
    await symlink(join(dir.path, "blob-elsewhere"), join(dir.path, ENCLAVE_KEY_FILE))
    const third = await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    expect(third.created).toBe(true)
    expect(third.jwk).not.toEqual(second.jwk)
  })

  test("removeDeviceKey removes the blob and the sidecar", async () => {
    await loadOrCreateDeviceKey(dir.path, "secure-enclave", env, VAULT)
    await removeDeviceKey(dir.path, "secure-enclave")
    await expect(stat(join(dir.path, ENCLAVE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    await expect(stat(join(dir.path, ENCLAVE_PUBLIC_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
  })
})

// The enclave helper is ensureHelper's
// under the resolved config root (MEHEN_HOME), never a mehen-se found in
// the key's own directory or a slot's bin/.
// Under Codex's macOS sandbox the release helper's `available` exits 1 and
// create and sign print "mehen-se: Secure Enclave is not available".
describe("a helper that cannot reach the Secure Enclave", () => {
  const appleSilicon = { platform: "darwin" as const, arch: "arm64" }

  test("auto mode refuses rather than fall back to a software key; no helper at all is still software", async () => {
    const blocked = { MEHEN_SE_PATH: await fakeHelper(dir.path, { unreachable: true }) }
    const refusal = await chooseBackend(null, blocked, appleSilicon).catch((error: unknown) => error)
    expect(refusal).toBeInstanceOf(CliError)
    expect(refusal).toMatchObject({ code: "not_available", next: { say: ENCLAVE_BLOCKED_SAY } })
    expect((refusal as CliError).next?.command).toBeUndefined()
    expect(await chooseBackend(null, { MEHEN_SE_PATH: join(dir.path, "absent") }, appleSilicon)).toBe("software")
    expect(await chooseBackend("software", blocked, appleSilicon)).toBe("software")
    await expect(chooseBackend("secure-enclave", blocked, appleSilicon)).rejects.toMatchObject({ code: "not_available" })
    await mkdir(join(dir.path, "ok"))
    expect(await chooseBackend(null, { MEHEN_SE_PATH: await fakeHelper(join(dir.path, "ok")) }, appleSilicon)).toBe("secure-enclave")
    expect(await chooseBackend(null, blocked, { platform: "linux", arch: "x64" })).toBe("software")
  })

  test("signing with an enrolled enclave key says to run outside the sandbox or use the MCP tools, never to enrol again", async () => {
    await mkdir(join(dir.path, "ok"))
    await loadOrCreateDeviceKey(dir.path, "secure-enclave", { MEHEN_SE_PATH: await fakeHelper(join(dir.path, "ok")) }, VAULT)
    const key = await loadDeviceKey(dir.path, "secure-enclave", { MEHEN_SE_PATH: await fakeHelper(dir.path, { unreachable: true }) })
    const failure = await key.signer("dev_1").sign(randomBytes(32)).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: "helper_failed", message: "The Secure Enclave helper could not sign: mehen-se: Secure Enclave is not available" })
    expect((failure as CliError).next).toEqual({ say: "This process cannot reach the Secure Enclave, usually because a sandbox (such as Codex's) blocks it; the key itself is fine, so do not enrol again. Run this command outside the sandbox (ask the human to approve it), or use the mehen MCP tools instead." })
  })
})

describe("the enclave helper comes from the resolved root", () => {
  test("a helper planted in the key's directory is never run: without MEHEN_SE_PATH or an extracted helper the enclave backend is not available", async () => {
    const slot = join(dir.path, "workspaces", "vault.example", "tn_planted0001")
    await mkdir(join(slot, "bin"), { recursive: true, mode: 0o700 })
    await fakeHelper(join(slot, "bin"))
    const env = { MEHEN_HOME: dir.path }
    const refused = (await loadOrCreateDeviceKey(slot, "secure-enclave", env, VAULT).catch((e: unknown) => e)) as CliError
    expect(refused).toBeInstanceOf(CliError)
    expect(refused.code).toBe("not_available")
    expect(refused.next?.command).toBe("mehen enrol --workspace <slug> --backend software")
    await expect(stat(join(slot, ENCLAVE_KEY_FILE))).rejects.toMatchObject({ code: "ENOENT" })
    // MEHEN_SE_PATH is the only override, and then nothing else is tried.
    const created = await loadOrCreateDeviceKey(slot, "secure-enclave", { ...env, MEHEN_SE_PATH: await fakeHelper(dir.path) }, VAULT)
    expect(created.created).toBe(true)
  })
})
