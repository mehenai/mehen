import { afterEach, describe, expect, test } from "bun:test"
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join, relative } from "node:path"
import { ENCLAVE_KEY_FILE, KEYRING_MARKER, KEYS_FILE, SEALED_FILE, type CustodyHost, loadSecrets, storedData } from "../src/custody.ts"
import { DISK, type Disk } from "../src/durable.ts"
import { startLocalVault, type LocalVault } from "../src/host.ts"
import { fakeEnclaveHelper, fakeSecretTool, keyringItems, keyringSecrets } from "./fakes.ts"

const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const made: string[] = []
const started: LocalVault[] = []
function scratch(): string {
  const dir = mkdtempSync(join(base, "mehen-custody-"))
  made.push(dir)
  return dir
}
function vaultDir(root: string, name = "vault"): string {
  const dir = join(root, name)
  mkdirSync(dir, { mode: 0o700 })
  return dir
}
afterEach(async () => {
  for (const vault of started.splice(0)) await vault.stop()
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const OLD = { ROOT_KEYS: JSON.stringify({ "1": "b2xkLXJvb3Qta2V5LW5vdC1yZWFs" }), SEAL_PRIVATE_JWK: JSON.stringify({ kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" }) }
const FILE_ONLY: CustodyHost = { platform: process.platform, env: {}, helper: null }
const mode = (path: string) => statSync(path).mode & 0o777
const config = (dataDir: string) => ({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })

async function linuxHost(root: string, extra: Record<string, string> = {}): Promise<{ host: CustodyHost; store: string; secrets: (dataDir: string) => string[] }> {
  const bin = join(root, "bin")
  const store = join(root, "store")
  mkdirSync(bin)
  mkdirSync(store)
  await fakeSecretTool(bin)
  const host: CustodyHost = { platform: "linux", env: { PATH: bin, DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus", FAKE_SECRET_TOOL_DIR: store, ...extra }, helper: null }
  return { host, store, secrets: (dataDir) => keyringSecrets(store, { service: "mehen-local", "vault-id": vaultIdOf(dataDir) }) }
}

function vaultIdOf(dataDir: string): string {
  return (JSON.parse(readFileSync(join(dataDir, KEYRING_MARKER), "utf8")) as { vaultId: string }).vaultId
}

async function macHost(root: string, extra: Record<string, string> = {}): Promise<CustodyHost> {
  const bin = join(root, "bin")
  mkdirSync(bin, { recursive: true })
  return { platform: "darwin", env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? root, ...extra }, helper: await fakeEnclaveHelper(bin) }
}

describe("the keyring on Linux", () => {
  test("new keys go into one item found by the vault's id, never onto a command line, and come back on the next start", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const { host, store, secrets } = await linuxHost(root)
    const first = await loadSecrets(dataDir, host)
    expect(first.custody).toBe("keyring")
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(mode(join(dataDir, KEYRING_MARKER))).toBe(0o600)
    const id = vaultIdOf(dataDir)
    expect(id).toMatch(/^[A-Za-z0-9_-]{24}$/)
    expect(keyringItems(store)).toEqual([{ attributes: { service: "mehen-local", "vault-id": id, vault: dataDir }, secret: JSON.stringify(first.secrets) }])
    expect(secrets(dataDir).map((s) => JSON.parse(s))).toEqual([first.secrets])
    const args = readFileSync(join(store, "args.log"), "utf8")
    expect(args).toContain(`store --label=Mehen local vault (${dataDir}) service mehen-local vault-id ${id} vault ${dataDir}`)
    expect(args).not.toContain(JSON.parse(first.secrets.ROOT_KEYS)["1"])
    expect(await loadSecrets(dataDir, host)).toEqual(first)
  })

  test("a moved data directory still opens, by the id keys.keyring records", async () => {
    const root = scratch()
    const { host, store } = await linuxHost(root)
    const before = vaultDir(root, "before")
    const first = await loadSecrets(before, host)
    const after = join(root, "after")
    renameSync(before, after)
    expect(await loadSecrets(after, host)).toEqual(first)
    expect(keyringItems(store)).toHaveLength(1)
  })

  test("two vaults keep two items, each opened by its own vault", async () => {
    const root = scratch()
    const { host, store } = await linuxHost(root)
    const one = vaultDir(root, "one")
    const two = vaultDir(root, "two")
    const first = await loadSecrets(one, host)
    const second = await loadSecrets(two, host)
    expect(first.secrets).not.toEqual(second.secrets)
    expect(vaultIdOf(one)).not.toBe(vaultIdOf(two))
    expect(keyringItems(store)).toHaveLength(2)
    expect(await loadSecrets(one, host)).toEqual(first)
    expect(await loadSecrets(two, host)).toEqual(second)
  })

  test("a keys.json from before is moved in, checked, then removed", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    const { host, secrets } = await linuxHost(root)
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "keyring" })
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(secrets(dataDir).map((s) => JSON.parse(s))).toEqual([OLD])
  })

  test("a move that stopped after keys.keyring and before the item carries on from keys.json", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const { host, store, secrets } = await linuxHost(root)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    writeFileSync(join(dataDir, KEYRING_MARKER), JSON.stringify({ service: "mehen-local", vaultId: "abcdefghijklmnopqrstuvwx" }), { mode: 0o600 })
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "keyring" })
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(vaultIdOf(dataDir)).toBe("abcdefghijklmnopqrstuvwx")
    expect(secrets(dataDir).map((s) => JSON.parse(s))).toEqual([OLD])
    expect(keyringItems(store)).toHaveLength(1)
  })

  test("without a session bus or secret-tool it keeps keys.json", async () => {
    const root = scratch()
    const { host } = await linuxHost(root)
    const noBus = vaultDir(root)
    expect((await loadSecrets(noBus, { ...host, env: { PATH: host.env.PATH } })).custody).toBe("file")
    expect(mode(join(noBus, KEYS_FILE))).toBe(0o600)
    const noTool = vaultDir(root, "other")
    expect((await loadSecrets(noTool, { ...host, env: { ...host.env, PATH: join(root, "nowhere") } })).custody).toBe("file")
  })

  test("a keyring that refuses the item, or cannot be asked, leaves the keys in keys.json", async () => {
    const root = scratch()
    const refusing = vaultDir(root)
    writeFileSync(join(refusing, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    const { host, store } = await linuxHost(root, { FAKE_SECRET_TOOL_STORE: "fail" })
    expect(await loadSecrets(refusing, host)).toEqual({ secrets: OLD, custody: "file" })
    expect(JSON.parse(readFileSync(join(refusing, KEYS_FILE), "utf8"))).toEqual(OLD)
    expect(existsSync(join(refusing, KEYRING_MARKER))).toBe(false)
    const broken = vaultDir(root, "broken")
    expect((await loadSecrets(broken, { ...host, env: { ...host.env, FAKE_SECRET_TOOL_STORE: "", FAKE_SECRET_TOOL_LOOKUP: "fail" } })).custody).toBe("file")
    expect(keyringItems(store)).toEqual([])
  })

  test("keys kept in the keyring are never replaced when the keyring is out of reach or the item is gone", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const { host, store } = await linuxHost(root)
    await loadSecrets(dataDir, host)
    await expect(loadSecrets(dataDir, { ...host, env: { PATH: host.env.PATH } })).rejects.toThrow(/in the login keyring.*never makes new keys/)
    for (const name of readdirSync(store).filter((n) => n.startsWith("item-"))) rmSync(join(store, name))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/no item with the id keys.keyring names/)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(keyringItems(store)).toEqual([])
  })

  test("with keys.keyring removed, the item stays as it was and no new keys are made", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const { host, store } = await linuxHost(root)
    await loadSecrets(dataDir, host)
    const before = keyringItems(store)
    rmSync(join(dataDir, KEYRING_MARKER))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/keys.keyring is missing, so the vault will not make new keys beside them/)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/keys.keyring is missing/)
    expect(keyringItems(store)).toEqual(before)
    expect(existsSync(join(dataDir, KEYRING_MARKER))).toBe(false)
  })

  test("refuses a keys.keyring other users can read, or one that names no id", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const { host } = await linuxHost(root)
    await loadSecrets(dataDir, host)
    chmodSync(join(dataDir, KEYRING_MARKER), 0o644)
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/not a private file/)
    writeFileSync(join(dataDir, KEYRING_MARKER), JSON.stringify({ service: "mehen-local", vault: dataDir }), { mode: 0o600 })
    chmodSync(join(dataDir, KEYRING_MARKER), 0o600)
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/does not name this vault's keyring item/)
  })
})

describe("the Secure Enclave on a Mac (a stand-in helper)", () => {
  test("new keys are sealed, with the blob and envelope 0600 and no keys.json", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const host = await macHost(root)
    const first = await loadSecrets(dataDir, host)
    expect(first.custody).toBe("secure-enclave")
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(mode(join(dataDir, SEALED_FILE))).toBe(0o600)
    expect(mode(join(dataDir, ENCLAVE_KEY_FILE))).toBe(0o600)
    expect(readFileSync(join(dataDir, SEALED_FILE), "utf8")).not.toContain(JSON.parse(first.secrets.ROOT_KEYS)["1"])
    expect(await loadSecrets(dataDir, host)).toEqual(first)
  })

  test("a keys.json from before is sealed, checked, then removed", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    const host = await macHost(root)
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "secure-enclave" })
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "secure-enclave" })
  })

  test("the move is durable before keys.json goes: sealed and synced, read back, then removed and synced", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    const log = join(root, "helper.log")
    const steps: string[] = []
    let seen = 0
    const drain = () => {
      const lines = existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean) : []
      for (const line of lines.slice(seen)) steps.push(`helper ${line}`)
      seen = lines.length
    }
    const name = (path: string) => relative(dataDir, path).replace(/\.[0-9a-f-]{36}\.tmp$/, ".tmp") || "."
    const disk: Disk = {
      write(path, text) {
        drain()
        steps.push(`write ${name(path)}`)
        DISK.write(path, text)
      },
      rename(from, to) {
        drain()
        steps.push(`rename ${name(from)} ${name(to)}`)
        DISK.rename(from, to)
      },
      remove(path) {
        drain()
        steps.push(`remove ${name(path)}`)
        DISK.remove(path)
      },
      syncDir(dir) {
        drain()
        steps.push(`sync ${name(dir)}`)
        DISK.syncDir(dir)
      },
    }
    const host = { ...(await macHost(root, { FAKE_ENCLAVE_LOG: log })), disk }
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "secure-enclave" })
    drain()
    expect(steps).toEqual([
      "helper available",
      "helper wrap",
      "write keys.sealed.json.tmp",
      "rename keys.sealed.json.tmp keys.sealed.json",
      "sync .",
      "helper unwrap",
      "remove keys.json",
      "sync .",
    ])
  })

  test("a start that stopped mid-move finishes it, and refuses two different sets of keys", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const host = await macHost(root)
    const { secrets } = await loadSecrets(dataDir, host)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(secrets), { mode: 0o600 })
    expect((await loadSecrets(dataDir, host)).secrets).toEqual(secrets)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/different keys in keys.json/)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(true)
  })

  test("without a working enclave it keeps keys.json", async () => {
    const root = scratch()
    const host = await macHost(root, { FAKE_ENCLAVE: "off" })
    const off = vaultDir(root)
    expect((await loadSecrets(off, host)).custody).toBe("file")
    expect(existsSync(join(off, SEALED_FILE))).toBe(false)
    const none = vaultDir(root, "none")
    expect((await loadSecrets(none, { ...host, helper: null })).custody).toBe("file")
  })

  test("sealed keys are never replaced when the helper is gone, changed or given another key", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const host = await macHost(root)
    await loadSecrets(dataDir, host)
    await expect(loadSecrets(dataDir, { ...host, helper: null })).rejects.toThrow(/sealed by this Mac's Secure Enclave.*never makes new keys/)
    const sealed = join(dataDir, SEALED_FILE)
    const envelope = JSON.parse(readFileSync(sealed, "utf8")) as { ct: string }
    const flipped = { ...envelope, ct: `${envelope.ct[0] === "A" ? "B" : "A"}${envelope.ct.slice(1)}` }
    writeFileSync(sealed, JSON.stringify(flipped))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/does not open with this key/)
    writeFileSync(sealed, JSON.stringify(envelope))
    writeFileSync(join(dataDir, ENCLAVE_KEY_FILE), crypto.getRandomValues(new Uint8Array(32)), { mode: 0o600 })
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/does not open with this key/)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
  })

  test("with keys.sealed.json removed, the enclave key stays and no new keys are made", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const host = await macHost(root)
    await loadSecrets(dataDir, host)
    const blob = readFileSync(join(dataDir, ENCLAVE_KEY_FILE))
    rmSync(join(dataDir, SEALED_FILE))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/not new \(an enclave key \(se-root.key\) with no keys.sealed.json beside it\)/)
    expect(readFileSync(join(dataDir, ENCLAVE_KEY_FILE))).toEqual(blob)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(existsSync(join(dataDir, SEALED_FILE))).toBe(false)
  })

  test("refuses a key blob or an envelope other users can read", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    const host = await macHost(root)
    await loadSecrets(dataDir, host)
    chmodSync(join(dataDir, ENCLAVE_KEY_FILE), 0o644)
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/se-root.key: it is not a private file/)
    chmodSync(join(dataDir, ENCLAVE_KEY_FILE), 0o600)
    chmodSync(join(dataDir, SEALED_FILE), 0o640)
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/keys.sealed.json: it is not a private file/)
  })
})

describe("a vault that is not new never gets new keys", () => {
  test("stored data is an account or an object file, not the empty database and folders the host makes", () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    mkdirSync(join(dataDir, "objects", "WorkspaceVault"), { recursive: true })
    writeFileSync(join(dataDir, "directory.sqlite"), "")
    expect(storedData(dataDir, false)).toEqual([])
    expect(storedData(dataDir, true)).toEqual(["an account in directory.sqlite"])
    writeFileSync(join(dataDir, "objects", "WorkspaceVault", "abc.sqlite"), "")
    expect(storedData(dataDir, false)).toEqual(["stored objects in objects/WorkspaceVault"])
  })

  test("keys.json removed from a vault with data is refused, in every custody", async () => {
    const root = scratch()
    const data = ["an account in directory.sqlite"]
    const hosts: [string, CustodyHost][] = [["file", FILE_ONLY], ["enclave", await macHost(scratch())], ["keyring", (await linuxHost(scratch())).host]]
    for (const [name, host] of hosts) {
      const dataDir = vaultDir(root, name)
      await expect(loadSecrets(dataDir, host, data)).rejects.toThrow(/not new \(an account in directory.sqlite\)/)
      expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
      expect(existsSync(join(dataDir, SEALED_FILE))).toBe(false)
      expect(existsSync(join(dataDir, KEYRING_MARKER))).toBe(false)
    }
  })

  test("the host refuses to start a vault with stored objects and no keys", async () => {
    const root = scratch()
    const dataDir = join(root, "vault")
    const vault = await startLocalVault(config(dataDir), { custody: FILE_ONLY })
    await vault.stop()
    writeFileSync(join(dataDir, "objects", "WorkspaceVault", "0123.sqlite"), "")
    rmSync(join(dataDir, KEYS_FILE))
    await expect(startLocalVault(config(dataDir), { custody: FILE_ONLY })).rejects.toThrow(/not new \(stored objects in objects\/WorkspaceVault\)/)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
  })
})

describe("the host reports its custody", () => {
  test("in its state and at /local/v1/state", async () => {
    const root = scratch()
    const vault = await startLocalVault(config(join(root, "vault")), { custody: await macHost(root) })
    started.push(vault)
    expect(vault.state().custody).toBe("secure-enclave")
    expect(await (await fetch(`${vault.origin}/local/v1/state`)).json()).toMatchObject({ custody: "secure-enclave" })
  })
})

// The real helper, on a Mac that has built it (apps/cli/native/mehen-se/build.sh)
// or points MEHEN_SE_PATH at one, with a Secure Enclave this process can reach.
const BUILT = join(import.meta.dir, "../../cli/native/mehen-se/build/mehen-se")
const realHelper = process.platform !== "darwin" ? null : process.env.MEHEN_SE_PATH ?? (existsSync(BUILT) ? BUILT : null)
const enclaveReady = realHelper !== null && (await Bun.spawn([realHelper, "available"], { stdout: "ignore", stderr: "ignore" }).exited) === 0
if (process.platform === "darwin" && !enclaveReady) console.error("custody.test.ts: no built mehen-se or no reachable Secure Enclave; the real round trip is skipped")
const onThisMac = process.platform === "darwin" && enclaveReady

async function helper(args: string[], input: Uint8Array): Promise<{ code: number; out: Uint8Array; err: string }> {
  const proc = Bun.spawn([realHelper ?? "mehen-se", ...args], { stdin: input, stdout: "pipe", stderr: "pipe" })
  const [out, err, code] = await Promise.all([new Response(proc.stdout).arrayBuffer(), new Response(proc.stderr).text(), proc.exited])
  return { code, out: new Uint8Array(out), err }
}

describe("the Secure Enclave on this Mac (the real helper)", () => {
  test.if(onThisMac)("seals keys.json to the enclave, opens it again, and refuses a changed envelope or another key", async () => {
    const root = scratch()
    const dataDir = vaultDir(root)
    writeFileSync(join(dataDir, KEYS_FILE), JSON.stringify(OLD), { mode: 0o600 })
    const host: CustodyHost = { platform: "darwin", env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? root }, helper: realHelper }
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "secure-enclave" })
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
    expect(mode(join(dataDir, ENCLAVE_KEY_FILE))).toBe(0o600)
    expect(mode(join(dataDir, SEALED_FILE))).toBe(0o600)
    expect(readFileSync(join(dataDir, SEALED_FILE), "utf8")).not.toContain("b2xkLXJvb3Qta2V5")
    expect(await loadSecrets(dataDir, host)).toEqual({ secrets: OLD, custody: "secure-enclave" })
    const sealed = join(dataDir, SEALED_FILE)
    const envelope = JSON.parse(readFileSync(sealed, "utf8")) as { tag: string }
    writeFileSync(sealed, JSON.stringify({ ...envelope, tag: `${envelope.tag[0] === "A" ? "B" : "A"}${envelope.tag.slice(1)}` }))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/does not open with this key/)
    writeFileSync(sealed, JSON.stringify(envelope))
    const other = vaultDir(root, "other")
    await loadSecrets(other, host)
    copyFileSync(join(other, ENCLAVE_KEY_FILE), join(dataDir, ENCLAVE_KEY_FILE))
    await expect(loadSecrets(dataDir, host)).rejects.toThrow(/does not open with this key/)
    expect(existsSync(join(dataDir, KEYS_FILE))).toBe(false)
  }, 30_000)

  test.if(onThisMac)("the largest secret wrap takes comes back whole, and the largest envelope unwrap reads opens; one byte more is refused", async () => {
    const key = join(scratch(), "k")
    const largest = crypto.getRandomValues(new Uint8Array(64 * 1024))
    const wrapped = await helper(["wrap", "--key", key, "--create-if-missing"], largest)
    expect(wrapped.code).toBe(0)
    const opened = await helper(["unwrap", "--key", key], wrapped.out)
    expect({ code: opened.code, same: Buffer.from(opened.out).equals(Buffer.from(largest)) }).toEqual({ code: 0, same: true })
    const tooBig = await helper(["wrap", "--key", key], new Uint8Array(64 * 1024 + 1))
    expect({ code: tooBig.code, err: tooBig.err.trim(), out: tooBig.out.length }).toEqual({ code: 1, err: "mehen-se: secret on stdin is over 65536 bytes", out: 0 })

    const text = new TextDecoder().decode(wrapped.out).trim()
    const padded = new TextEncoder().encode(text.padEnd(128 * 1024, " "))
    const fullEnvelope = await helper(["unwrap", "--key", key], padded)
    expect({ code: fullEnvelope.code, same: Buffer.from(fullEnvelope.out).equals(Buffer.from(largest)) }).toEqual({ code: 0, same: true })
    const overEnvelope = await helper(["unwrap", "--key", key], new TextEncoder().encode(text.padEnd(128 * 1024 + 1, " ")))
    expect({ code: overEnvelope.code, err: overEnvelope.err.trim(), out: overEnvelope.out.length }).toEqual({ code: 1, err: "mehen-se: envelope on stdin is over 131072 bytes", out: 0 })
  }, 30_000)

  test.if(onThisMac)("refuses malformed envelopes, naming what is wrong and printing nothing", async () => {
    const key = join(scratch(), "k")
    const wrapped = await helper(["wrap", "--key", key, "--create-if-missing"], new TextEncoder().encode("secret"))
    const good = JSON.parse(new TextDecoder().decode(wrapped.out)) as Record<string, unknown>
    const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url")
    const offCurve = new Uint8Array(65).fill(1)
    offCurve[0] = 4
    const cases: [string, string, RegExp][] = [
      ["not JSON", "{", /not valid JSON of the expected shape/],
      ["a missing field", JSON.stringify({ ...good, tag: undefined }), /not valid JSON of the expected shape/],
      ["version 2", JSON.stringify({ ...good, v: 2 }), /unsupported envelope version 2/],
      ["an 11-byte nonce", JSON.stringify({ ...good, nonce: b64(new Uint8Array(11)) }), /expected sizes/],
      ["a 15-byte tag", JSON.stringify({ ...good, tag: b64(new Uint8Array(15)) }), /expected sizes/],
      ["padded base64", JSON.stringify({ ...good, nonce: `${b64(new Uint8Array(12))}=` }), /expected sizes/],
      ["characters outside base64url", JSON.stringify({ ...good, ct: "not*base64" }), /expected sizes/],
      ["a point off the curve", JSON.stringify({ ...good, epk: b64(offCurve) }), /not a P-256 point/],
      ["a short ephemeral key", JSON.stringify({ ...good, epk: b64(new Uint8Array(33)) }), /not a P-256 point/],
    ]
    for (const [what, envelope, refusal] of cases) {
      const result = await helper(["unwrap", "--key", key], new TextEncoder().encode(envelope))
      expect({ what, code: result.code, out: result.out.length, refused: refusal.test(result.err) }).toEqual({ what, code: 1, out: 0, refused: true })
    }
  }, 30_000)
})
