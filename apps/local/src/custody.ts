// Where the local vault keeps its root key map and seal key, which decrypt
// everything it holds. Best first:
//
//   secure-enclave  a Mac with the mehen-se helper: the keys sealed to a
//                   Secure Enclave key-agreement key (keys.sealed.json, and
//                   the enclave's wrapped key blob in se-root.key)
//   keyring         Linux with secret-tool and a session bus: one item in the
//                   Secret Service, found by the vault's own id (service
//                   mehen-local, vault-id <id>), which keys.keyring in the
//                   data directory records, so the directory can move
//   file            keys.json, 0600
//
// The keys are opened once at start and held in memory. A keys.json from an
// earlier start is moved into the better custody, checked by reading it
// back, then removed. New keys are made only for a vault that is new: one
// with no enclave key, no keyring item and no data. Anything else without
// its keys refuses to start, since new keys could never open what is there.

import { chmodSync, existsSync, lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
import { userInfo } from "node:os"
import { join } from "node:path"
import { CliError } from "../../cli/src/errors.ts"
import { DISK, type Disk, removeDurably, replaceDurably } from "./durable.ts"

export type Custody = "secure-enclave" | "keyring" | "file"
export type VaultSecrets = { ROOT_KEYS: string; SEAL_PRIVATE_JWK: string }

// What the choice depends on, given rather than read so a test can stand
// in for a platform: the helper is the path `mehen serve` resolved, or null.
// disk is how key files are written durably (a test records the order).
export type CustodyHost = { platform: NodeJS.Platform; env: Record<string, string | undefined>; helper: string | null; disk?: Disk }

export const KEYS_FILE = "keys.json"
export const SEALED_FILE = "keys.sealed.json"
export const ENCLAVE_KEY_FILE = "se-root.key"
export const KEYRING_MARKER = "keys.keyring"
export const KEYRING_SERVICE = "mehen-local"

const TOOL_TIMEOUT_MS = 15_000

// read answers null when the custody holds no keys for this vault.
type Custodian = {
  custody: Exclude<Custody, "file">
  read(): Promise<string | null>
  write(text: string): Promise<void>
  discard(): Promise<void>
  // An item made for a vault at this path with no file here saying so
  // (the keyring's), or null.
  found(): Promise<string | null>
}

// What keys.keyring holds: the id the vault's keyring item is found by.
type KeyringMarker = { service: typeof KEYRING_SERVICE; vaultId: string }

const VAULT_ID = /^[A-Za-z0-9_-]{16,64}$/

export function writePrivate(path: string, text: string): void {
  writeFileSync(path, text, { mode: 0o600 })
  chmodSync(path, 0o600)
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url")
}

async function freshSecrets(): Promise<VaultSecrets> {
  const root = crypto.getRandomValues(new Uint8Array(32))
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
  return { ROOT_KEYS: JSON.stringify({ "1": b64url(root) }), SEAL_PRIVATE_JWK: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }) }
}

function parseSecrets(text: string, where: string): VaultSecrets {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    value = null
  }
  if (typeof value === "object" && value !== null) {
    const { ROOT_KEYS, SEAL_PRIVATE_JWK } = value as Record<string, unknown>
    if (typeof ROOT_KEYS === "string" && typeof SEAL_PRIVATE_JWK === "string") return { ROOT_KEYS, SEAL_PRIVATE_JWK }
  }
  throw new CliError("failed", `The vault's keys in ${where} are not in the expected shape, so the vault will not start.`, {
    say: "Restore the data directory from a backup; do not delete the keys, since nothing else can open the vault.",
  })
}

function same(a: VaultSecrets, b: VaultSecrets): boolean {
  return a.ROOT_KEYS === b.ROOT_KEYS && a.SEAL_PRIVATE_JWK === b.SEAL_PRIVATE_JWK
}

class ToolError extends Error {
  constructor(
    message: string,
    readonly exitCode: number | null,
    readonly stderr: string,
  ) {
    super(message)
  }
}

// Runs a helper or secret-tool with the secret on stdin, never in its
// arguments, and returns its stdout. A failure carries the first line of
// its stderr, which never holds the secret.
async function runTool(command: string, args: string[], stdin: string | null, env: Record<string, string | undefined>): Promise<string> {
  const proc = Bun.spawn([command, ...args], {
    stdin: stdin === null ? "ignore" : new TextEncoder().encode(stdin),
    stdout: "pipe",
    stderr: "pipe",
    env: Object.fromEntries(Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
    timeout: TOOL_TIMEOUT_MS,
  })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  await proc.exited
  if (proc.signalCode || proc.exitCode !== 0) {
    const detail = stderr.trim().split("\n")[0] || (proc.signalCode ? `killed by ${proc.signalCode}` : `exit ${proc.exitCode}`)
    throw new ToolError(`${command.split("/").at(-1)} ${args[0]}: ${detail}`, proc.signalCode ? null : proc.exitCode, stderr)
  }
  return stdout
}

function assertPrivateFile(path: string): void {
  const info = lstatSync(path, { throwIfNoEntry: false })
  if (!info) return
  if (!info.isFile() || info.uid !== userInfo().uid || (info.mode & 0o077) !== 0) {
    throw new CliError("key_insecure", `Refusing to use ${path}: it is not a private file of this user.`, { say: `Check who changed ${path}; it should be a plain file with mode 0600.` })
  }
}

function enclaveCustodian(dataDir: string, helper: string, env: Record<string, string | undefined>, disk: Disk): Custodian {
  const sealed = join(dataDir, SEALED_FILE)
  const blob = join(dataDir, ENCLAVE_KEY_FILE)
  return {
    custody: "secure-enclave",
    async read() {
      assertPrivateFile(blob)
      assertPrivateFile(sealed)
      return runTool(helper, ["unwrap", "--key", blob], readFileSync(sealed, "utf8"), env)
    },
    // mehen-se syncs a new blob and its directory before it prints the
    // envelope; the envelope then lands by temporary file and rename.
    async write(text) {
      assertPrivateFile(blob)
      const envelope = await runTool(helper, ["wrap", "--key", blob, "--create-if-missing"], text, env)
      assertPrivateFile(blob)
      replaceDurably(disk, sealed, envelope)
    },
    async discard() {
      removeDurably(disk, sealed)
    },
    async found() {
      return null
    },
  }
}

// The item is stored with the vault's id and the path it was made at; it is
// read by the id alone, so a moved data directory still finds it, and the
// path is how a start with keys.keyring missing learns there is one. The
// marker is written before the item, so an item's id is always on disk.
function keyringCustodian(dataDir: string, tool: string, env: Record<string, string | undefined>, disk: Disk, vaultId: string): Custodian {
  const byId = ["service", KEYRING_SERVICE, "vault-id", vaultId]
  const byPath = ["service", KEYRING_SERVICE, "vault", dataDir]
  const marker = join(dataDir, KEYRING_MARKER)
  const lookup = async (attributes: string[]): Promise<string | null> => {
    try {
      const text = await runTool(tool, ["lookup", ...attributes], null, env)
      return text.trim() === "" ? null : text
    } catch (error) {
      // secret-tool lookup exits 1 with nothing on stderr when there is no item.
      if (error instanceof ToolError && error.exitCode === 1 && error.stderr.trim() === "") return null
      throw error
    }
  }
  return {
    custody: "keyring",
    read: () => lookup(byId),
    async write(text) {
      replaceDurably(disk, marker, `${JSON.stringify({ service: KEYRING_SERVICE, vaultId } satisfies KeyringMarker)}\n`)
      await runTool(tool, ["store", `--label=Mehen local vault (${dataDir})`, ...byId, "vault", dataDir], text, env)
    },
    async discard() {
      removeDurably(disk, marker)
      await runTool(tool, ["clear", ...byId], null, env).catch(() => undefined)
    },
    found: () => lookup(byPath),
  }
}

function readMarker(dataDir: string): KeyringMarker {
  const path = join(dataDir, KEYRING_MARKER)
  let value: unknown
  try {
    value = JSON.parse(readFileSync(path, "utf8"))
  } catch {
    value = null
  }
  const { service, vaultId } = (typeof value === "object" && value !== null ? value : {}) as Record<string, unknown>
  if (service === KEYRING_SERVICE && typeof vaultId === "string" && VAULT_ID.test(vaultId)) return { service, vaultId }
  throw new CliError("failed", `${path} does not name this vault's keyring item, so the vault will not start.`, {
    say: `Restore ${KEYRING_MARKER} from a backup of the data directory; \`secret-tool search service ${KEYRING_SERVICE}\` lists the vault ids the keyring holds.`,
  })
}

async function helperWorks(helper: string, env: Record<string, string | undefined>): Promise<boolean> {
  try {
    await runTool(helper, ["available"], null, env)
    return true
  } catch {
    return false
  }
}

// The best custody this host offers, or null for keys.json.
async function chooseCustodian(dataDir: string, host: CustodyHost, disk: Disk, vaultId: string | null): Promise<Custodian | null> {
  if (host.platform === "darwin" && host.helper !== null && (await helperWorks(host.helper, host.env))) return enclaveCustodian(dataDir, host.helper, host.env, disk)
  if (host.platform === "linux" && host.env.DBUS_SESSION_BUS_ADDRESS) {
    const tool = Bun.which("secret-tool", { PATH: host.env.PATH ?? "" })
    if (tool) return keyringCustodian(dataDir, tool, host.env, disk, vaultId ?? b64url(crypto.getRandomValues(new Uint8Array(18))))
  }
  return null
}

// Which custody already holds this vault's keys, by the files that say so.
function heldBy(dataDir: string): Exclude<Custody, "file"> | null {
  const sealedPath = join(dataDir, SEALED_FILE)
  const markerPath = join(dataDir, KEYRING_MARKER)
  assertPrivateFile(sealedPath)
  assertPrivateFile(markerPath)
  const sealed = existsSync(sealedPath)
  const keyring = existsSync(markerPath)
  if (sealed && keyring) {
    throw new CliError("failed", `The vault in ${dataDir} says its keys are both sealed by the Secure Enclave and in the keyring, so it will not guess which.`, {
      say: `Remove whichever of ${SEALED_FILE} and ${KEYRING_MARKER} is stale, then start the vault again.`,
    })
  }
  return sealed ? "secure-enclave" : keyring ? "keyring" : null
}

// What in the data directory shows the vault has held something, whatever
// its keys: an account in the directory database, or a stored object. The
// host makes directory.sqlite and the object folders before the keys are
// read, so only their contents count.
export function storedData(dataDir: string, hasAccount: boolean): string[] {
  const found: string[] = []
  if (hasAccount) found.push("an account in directory.sqlite")
  const objects = join(dataDir, "objects")
  if (existsSync(objects)) {
    for (const kind of readdirSync(objects).sort()) {
      const dir = join(objects, kind)
      if (lstatSync(dir).isDirectory() && readdirSync(dir).some((name) => name.endsWith(".sqlite"))) found.push(`stored objects in objects/${kind}`)
    }
  }
  return found
}

const CUSTODY_WORDS: Record<Exclude<Custody, "file">, string> = { "secure-enclave": "sealed by this Mac's Secure Enclave", keyring: "in the login keyring" }

function unreachable(held: Exclude<Custody, "file">, dataDir: string, detail: string): CliError {
  const say =
    held === "secure-enclave"
      ? "Start it with a mehen that carries the mehen-se helper (a released build, or MEHEN_SE_PATH in a development build), on the Mac that sealed the keys, outside any sandbox that blocks the Secure Enclave."
      : "Start it in a session with the login keyring unlocked and DBUS_SESSION_BUS_ADDRESS set, with secret-tool (libsecret) installed."
  return new CliError("not_available", `The vault's keys are ${CUSTODY_WORDS[held]} (${dataDir}), and ${detail}, so the vault will not start. It never makes new keys in their place.`, { say })
}

function markerLine(): string {
  return JSON.stringify({ service: KEYRING_SERVICE, vaultId: "<vault-id>" })
}

const FIND_ID = `\`secret-tool search service ${KEYRING_SERVICE}\` shows each item's attribute.vault-id`

function orphanedKeyring(dataDir: string): CliError {
  return new CliError("failed", `The login keyring holds keys made for a vault in ${dataDir}, but ${KEYRING_MARKER} is missing, so the vault will not make new keys beside them.`, {
    say: `Restore ${KEYRING_MARKER} from a backup, or recreate it: a file of mode 0600 in ${dataDir} holding ${markerLine()} with the item's id (${FIND_ID}). If that item belongs to a vault that has moved away, and this one is new, remove it from here with \`secret-tool clear service ${KEYRING_SERVICE} vault ${dataDir}\` only once you are sure.`,
  })
}

function notNew(dataDir: string, reasons: string[]): CliError {
  return new CliError("failed", `The vault in ${dataDir} has no keys to open it with, but it is not new (${reasons.join("; ")}), so it will not make new keys: they could never open what is already there.`, {
    say: `Restore the missing key file from a backup of ${dataDir}: ${SEALED_FILE} (with ${ENCLAVE_KEY_FILE}, on the Mac that made it), ${KEYRING_MARKER} (${markerLine()}, when the keys are in the login keyring; ${FIND_ID}) or ${KEYS_FILE}. Remove ${ENCLAVE_KEY_FILE} only if this vault never held anything.`,
  })
}

async function keep(custodian: Custodian, secrets: VaultSecrets): Promise<boolean> {
  let reason: string
  try {
    await custodian.write(JSON.stringify(secrets))
    const back = await custodian.read()
    if (back !== null && same(parseSecrets(back, CUSTODY_WORDS[custodian.custody]), secrets)) return true
    reason = "the keys read back were not the keys written"
  } catch (error) {
    reason = error instanceof Error ? error.message : String(error)
  }
  await custodian.discard().catch(() => undefined)
  console.error(JSON.stringify({ at: "local.custody", custody: custodian.custody, fallback: "file", reason }))
  return false
}

// data is what storedData found: the vault's own evidence that it is not new.
export async function loadSecrets(dataDir: string, host: CustodyHost, data: string[] = []): Promise<{ secrets: VaultSecrets; custody: Custody }> {
  const disk = host.disk ?? DISK
  const keysPath = join(dataDir, KEYS_FILE)
  const held = heldBy(dataDir)
  let custodian = await chooseCustodian(dataDir, host, disk, held === "keyring" ? readMarker(dataDir).vaultId : null)

  if (held !== null) {
    if (custodian?.custody !== held) throw unreachable(held, dataDir, held === "secure-enclave" ? "the helper is missing or cannot reach the enclave here" : "the keyring cannot be reached here")
    let text: string | null
    try {
      text = await custodian.read()
    } catch (error) {
      throw unreachable(held, dataDir, `they could not be opened (${error instanceof Error ? error.message : String(error)})`)
    }
    if (text === null) {
      // keys.keyring is written before the item: a move that stopped
      // between the two still has keys.json, and carries on from it.
      if (!existsSync(keysPath)) throw unreachable(held, dataDir, "the keyring has no item with the id keys.keyring names")
      const existing = parseSecrets(readFileSync(keysPath, "utf8"), keysPath)
      if (!(await keep(custodian, existing))) return { secrets: existing, custody: "file" }
      removeDurably(disk, keysPath)
      return { secrets: existing, custody: held }
    }
    const secrets = parseSecrets(text, CUSTODY_WORDS[held])
    // A start that stopped between moving the keys and removing keys.json.
    if (existsSync(keysPath)) {
      if (!same(parseSecrets(readFileSync(keysPath, "utf8"), keysPath), secrets)) {
        throw new CliError("failed", `The vault in ${dataDir} has keys ${CUSTODY_WORDS[held]} and different keys in ${KEYS_FILE}, so it will not guess which are its own.`, {
          say: `Move ${keysPath} aside if the vault starts and opens with it gone; keep it until then.`,
        })
      }
      removeDurably(disk, keysPath)
    }
    return { secrets, custody: held }
  }

  const existing = existsSync(keysPath) ? parseSecrets(readFileSync(keysPath, "utf8"), keysPath) : null

  // An item made at this path with no marker: keys.keyring was removed, or
  // belongs to a vault moved away from here. Nothing is stored beside it; a
  // keyring that cannot say whether it holds one is not used at all.
  let found: string | null = null
  if (custodian) {
    try {
      found = await custodian.found()
    } catch (error) {
      console.error(JSON.stringify({ at: "local.custody", custody: custodian.custody, fallback: "file", reason: error instanceof Error ? error.message : String(error) }))
      custodian = null
    }
  }
  if (found !== null) throw orphanedKeyring(dataDir)

  if (existing === null) {
    const reasons = [...(existsSync(join(dataDir, ENCLAVE_KEY_FILE)) ? [`an enclave key (${ENCLAVE_KEY_FILE}) with no ${SEALED_FILE} beside it`] : []), ...data]
    if (reasons.length > 0) throw notNew(dataDir, reasons)
  }

  const secrets = existing ?? (await freshSecrets())
  if (custodian && (await keep(custodian, secrets))) {
    if (existing) removeDurably(disk, keysPath)
    return { secrets, custody: custodian.custody }
  }
  if (!existing) replaceDurably(disk, keysPath, JSON.stringify(secrets))
  return { secrets, custody: "file" }
}
