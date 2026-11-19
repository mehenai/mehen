// This machine's device key, behind protocol's ProofSigner. Two backends:
// secure-enclave (a non-exportable key through mehen-se) and software (a P-256
// private JWK in a 0600 file).
//
// The key is the machine's identity, so an enrolment that lapses keeps it
// (UX-MEHEN-TOOLS 2.3): loadOrCreateDeviceKey reuses the key on disk and only
// makes one when there is none it can vouch for. An enclave key cannot be
// asked for its public half, so the public JWK is kept beside the blob and
// proved against it with a signed challenge before it is ever reused.

import { readFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { type DeviceJwk, type ProofSigner, importDeviceKey, isDeviceJwk, webCryptoSigner } from "@mehen/protocol"
import { randomBytes } from "@mehen/protocol/bytes"
import { type Backend, type Env, assertPrivateFile, ensureConfigDir, writePrivateFile } from "./config.ts"
import { CliError } from "./errors.ts"
import { resolveHome } from "./home.ts"
import { ENCLAVE_BLOCKED_SAY, enclaveCreate, enclaveSign, ensureHelper, helperAvailable, helperOverride, readyHelper } from "./mehen-se.ts"

export type DeviceKey = {
  backend: Backend
  // The signer for a device id: "new" while enrolling, the enrolment id
  // while pending, the device id once active.
  signer(deviceId: string): ProofSigner
}

export const SOFTWARE_KEY_FILE = "device-key.json"
export const ENCLAVE_KEY_FILE = "device-key.se"
// The enclave key's public JWK, which mehen-se cannot print again after create.
// Public data; trusted only once the blob has signed a challenge it verifies.
export const ENCLAVE_PUBLIC_KEY_FILE = "device-key.se.pub.json"
// What a key is for: the vault it was made to enrol with, and the tenant
// once it is active. A key is reused only for its own vault.
export const SOFTWARE_KEY_SCOPE_FILE = "device-key.scope.json"
export const ENCLAVE_KEY_SCOPE_FILE = "device-key.se.scope.json"

export function keyPath(dir: string, backend: Backend): string {
  return join(dir, backend === "software" ? SOFTWARE_KEY_FILE : ENCLAVE_KEY_FILE)
}

export function enclavePublicKeyPath(dir: string): string {
  return join(dir, ENCLAVE_PUBLIC_KEY_FILE)
}

export function keyScopePath(dir: string, backend: Backend): string {
  return join(dir, backend === "software" ? SOFTWARE_KEY_SCOPE_FILE : ENCLAVE_KEY_SCOPE_FILE)
}

export type KeyScope = { vault: string; tenant: string | null }

function isKeyScope(value: unknown): value is KeyScope {
  if (typeof value !== "object" || value === null) return false
  const s = value as Record<string, unknown>
  return typeof s.vault === "string" && (s.tenant === null || typeof s.tenant === "string")
}

// The scope recorded beside the key, or null when there is none mehen can read
// (missing, a link, not this user's, malformed): a key from before scopes
// were recorded, which the caller adopts for the vault at hand.
export async function readKeyScope(dir: string, backend: Backend): Promise<KeyScope | null> {
  const path = keyScopePath(dir, backend)
  try {
    await assertPrivateFile(path)
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"))
    return isKeyScope(parsed) ? { vault: parsed.vault, tenant: parsed.tenant } : null
  } catch {
    return null
  }
}

export async function writeKeyScope(dir: string, backend: Backend, scope: KeyScope): Promise<void> {
  await writePrivateFile(keyScopePath(dir, backend), `${JSON.stringify({ vault: scope.vault, tenant: scope.tenant })}\n`)
}

function missingHelper(): CliError {
  return new CliError("not_available", "The Secure Enclave helper mehen-se was not found or the Secure Enclave is not usable on this machine.", {
    command: "mehen enrol --workspace <slug> --backend software",
    say: "A release build of mehen carries its helper; this one does not. Point MEHEN_SE_PATH at mehen-se, update mehen, or enrol with --backend software.",
  })
}

// The helper this process runs: MEHEN_SE_PATH when set,
// outside a release build, and nothing else; otherwise the embedded helper,
// extracted into the resolved config root's bin/ (never a slot's), or null.
async function helperFor(env: Env): Promise<string | null> {
  return ensureHelper(env, helperOverride(env) ? "" : resolveHome(env).root)
}

async function requireHelper(env: Env): Promise<string> {
  const helper = await helperFor(env)
  if (!helper) throw missingHelper()
  return helper
}

// A helper that is here but cannot reach the enclave: a sandbox (Codex's
// seatbelt) blocks it, so a key made now would silently be on disk.
function enclaveBlocked(): CliError {
  return new CliError("not_available", "The Secure Enclave helper is here, but this process cannot reach the Secure Enclave, so no key was made.", { say: ENCLAVE_BLOCKED_SAY })
}

// The Secure Enclave on Apple silicon when the helper works; software where
// there is no helper (a development build) or no enclave. A helper that is
// present but cannot reach the enclave refuses rather than fall back.
export async function chooseBackend(requested: Backend | null, env: Env, host: { platform: NodeJS.Platform; arch: string } = process): Promise<Backend> {
  if (requested === "software") return "software"
  if (requested === "secure-enclave") {
    const helper = await requireHelper(env)
    if (!(await helperAvailable(helper))) throw missingHelper()
    return "secure-enclave"
  }
  if (host.platform !== "darwin" || host.arch !== "arm64") return "software"
  const helper = await helperFor(env)
  if (!helper) return "software"
  if (!(await helperAvailable(helper))) throw enclaveBlocked()
  return "secure-enclave"
}

type SoftwareKeyFile = DeviceJwk & { d: string }

function isSoftwareKeyFile(value: unknown): value is SoftwareKeyFile {
  if (typeof value !== "object" || value === null) return false
  const k = value as Record<string, unknown>
  const coordinate = (v: unknown) => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v)
  return k.kty === "EC" && k.crv === "P-256" && coordinate(k.x) && coordinate(k.y) && coordinate(k.d)
}

// The public half of a software key file: what goes to the vault and the
// ledger, never the private scalar.
export function publicJwk(file: SoftwareKeyFile): DeviceJwk {
  return { kty: "EC", crv: "P-256", x: file.x, y: file.y }
}

function softwareKey(privateKey: CryptoKey): DeviceKey {
  return { backend: "software", signer: (deviceId) => webCryptoSigner(deviceId, privateKey) }
}

function enclaveKey(helper: string, blobPath: string): DeviceKey {
  return {
    backend: "secure-enclave",
    signer: (deviceId) => ({ deviceId, sign: (data) => enclaveSign(helper, blobPath, data) }),
  }
}

async function importSoftwareKey(file: SoftwareKeyFile): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: file.x, y: file.y, d: file.d, ext: false },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  )
}

// Creates a fresh key, replacing any earlier one of that backend together
// with its sidecar and scope file; the new scope is written when given.
export async function createDeviceKey(dir: string, backend: Backend, env: Env, scope?: KeyScope): Promise<{ key: DeviceKey; jwk: DeviceJwk }> {
  await ensureConfigDir(dir)
  const path = keyPath(dir, backend)
  await rm(keyScopePath(dir, backend), { force: true })
  const made = await createKeyFiles(dir, backend, env, path)
  if (scope) await writeKeyScope(dir, backend, scope)
  return made
}

async function createKeyFiles(dir: string, backend: Backend, env: Env, path: string): Promise<{ key: DeviceKey; jwk: DeviceJwk }> {
  if (backend === "software") {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    const exported = await crypto.subtle.exportKey("jwk", pair.privateKey)
    const file = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y, d: exported.d }
    if (!isSoftwareKeyFile(file)) throw new CliError("internal", "WebCrypto produced an unexpected P-256 key.")
    await writePrivateFile(path, `${JSON.stringify(file)}\n`)
    return { key: softwareKey(await importSoftwareKey(file)), jwk: publicJwk(file) }
  }
  const helper = await requireHelper(env)
  await rm(path, { force: true })
  await rm(enclavePublicKeyPath(dir), { force: true })
  const jwk = await enclaveCreate(helper, path)
  await writePrivateFile(enclavePublicKeyPath(dir), `${JSON.stringify(jwk)}\n`)
  return { key: enclaveKey(helper, path), jwk }
}

export type LoadedDeviceKey = { key: DeviceKey; jwk: DeviceJwk; created: boolean }

// A key proves it is usable by signing a random challenge that its public
// half verifies. False for anything that throws or does not verify.
async function signsForItself(key: DeviceKey, jwk: DeviceJwk): Promise<boolean> {
  const challenge = randomBytes(32)
  try {
    const signature = await key.signer("new").sign(challenge)
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importDeviceKey(jwk), signature, challenge)
  } catch {
    return false
  }
}

// The key file as a usable software key, or null when there is none to
// reuse: a missing file, a link or a file another user owns or others can
// read (a key that may have been planted or copied must not become the
// identity), one that is not a P-256 private JWK, or one whose material
// WebCrypto cannot import or that does not sign for its own public half.
// Nothing here throws: a bad key means a fresh key, never an abort.
async function reusableSoftwareKey(path: string): Promise<{ key: DeviceKey; jwk: DeviceJwk } | null> {
  let file: SoftwareKeyFile
  try {
    await assertPrivateFile(path)
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"))
    if (!isSoftwareKeyFile(parsed)) return null
    file = parsed
  } catch {
    return null
  }
  let key: DeviceKey
  try {
    key = softwareKey(await importSoftwareKey(file))
  } catch {
    return null
  }
  const jwk = publicJwk(file)
  return (await signsForItself(key, jwk)) ? { key, jwk } : null
}

// The enclave blob's public JWK from the file beside it, accepted only after
// the blob has signed a random challenge that the JWK verifies, so mehen never
// posts a public key the enclave cannot sign for. Both files must pass
// assertPrivateFile (plain, owned, 0600). Anything short of that (no blob,
// no sidecar, a link, a malformed one, a helper failure, a mismatch) is no
// key to reuse.
async function reusableEnclaveKey(helper: string, blobPath: string, publicPath: string): Promise<{ key: DeviceKey; jwk: DeviceJwk } | null> {
  let parsed: unknown
  try {
    await assertPrivateFile(blobPath)
    await assertPrivateFile(publicPath)
    parsed = JSON.parse(await readFile(publicPath, "utf8"))
  } catch {
    return null
  }
  if (!isDeviceJwk(parsed) || "d" in parsed) return null
  const jwk: DeviceJwk = { kty: "EC", crv: "P-256", x: parsed.x, y: parsed.y }
  const key = enclaveKey(helper, blobPath)
  return (await signsForItself(key, jwk)) ? { key, jwk } : null
}

// The key on disk was made for another vault. Nothing is overwritten: the
// human picks --fresh-key or the other vault.
export function keyScopeError(dir: string, backend: Backend, scope: KeyScope, vault: string): CliError {
  return new CliError("key_scope", `The ${backend} device key in ${dir} was made for ${scope.vault}, not ${vault}.`, {
    command: "mehen enrol --workspace <slug> --fresh-key",
    say: `Run \`mehen enrol --workspace <slug> --fresh-key\` to replace it with a new key for ${vault} (a new fingerprint), or set MEHEN_VAULT_URL back to ${scope.vault}.`,
  })
}

// The key of this backend already on disk, when it can be vouched for and
// was made for `vault`; otherwise a fresh one (`created`) scoped to it. A
// key with no scope file is from before scopes were recorded and is adopted
// for this vault. A key made for another vault is refused (key_scope), not
// replaced. A revoked machine has no key file (removeDeviceKey), so a
// revoked key is never picked up here.
export async function loadOrCreateDeviceKey(dir: string, backend: Backend, env: Env, vault: string): Promise<LoadedDeviceKey> {
  await ensureConfigDir(dir)
  const path = keyPath(dir, backend)
  const found = backend === "software" ? await reusableSoftwareKey(path) : await reusableEnclaveKey(await requireHelper(env), path, enclavePublicKeyPath(dir))
  if (found) {
    const scope = await readKeyScope(dir, backend)
    if (scope && scope.vault !== vault) throw keyScopeError(dir, backend, scope, vault)
    if (!scope) await writeKeyScope(dir, backend, { vault, tenant: null })
    return { ...found, created: false }
  }
  return { ...(await createDeviceKey(dir, backend, env, { vault, tenant: null })), created: true }
}

// `observe`: for a command that only observes (status, doctor).
// The Secure Enclave helper is taken only as it already is on disk
// (readyHelper): nothing is extracted, made executable or retired, and an
// absent or stale helper is the not_available refusal with its repair step.
export type KeyLoadOptions = { observe?: boolean }

function helperNotPrepared(): CliError {
  return new CliError("not_available", "The Secure Enclave helper is not prepared on this machine yet, and mehen status and doctor only read.", {
    command: "mehen ls",
    say: "Run a command that signs, such as `mehen ls`: it prepares the helper in the config root's bin/, then run this again.",
  })
}

async function observedHelper(env: Env): Promise<string> {
  const helper = await readyHelper(env, helperOverride(env) ? "" : resolveHome(env).root)
  if (!helper) throw helperOverride(env) ? missingHelper() : helperNotPrepared()
  return helper
}

export async function loadDeviceKey(dir: string, backend: Backend, env: Env, options: KeyLoadOptions = {}): Promise<DeviceKey> {
  return (await loadSigningKey(dir, backend, env, options)).key
}

// The enclave key's public sidecar as it stands now; null when it is not a
// plain private public JWK.
async function enclavePublicJwk(dir: string): Promise<DeviceJwk | null> {
  try {
    const path = enclavePublicKeyPath(dir)
    await assertPrivateFile(path)
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"))
    return isDeviceJwk(parsed) && !("d" in parsed) ? { kty: "EC", crv: "P-256", x: parsed.x, y: parsed.y } : null
  } catch {
    return null
  }
}

// The key a session signs with and its public half as loaded: for a software
// key derived from the very file loaded, for an enclave key its sidecar read
// at load. A write that follows an answer compares the slot against this,
// never against what is on disk by then. Null when the
// public half cannot be known, which permits no such write.
export async function loadSigningKey(dir: string, backend: Backend, env: Env, options: KeyLoadOptions = {}): Promise<{ key: DeviceKey; jwk: DeviceJwk | null }> {
  const path = keyPath(dir, backend)
  try {
    await assertPrivateFile(path)
  } catch (error) {
    if ((error as { code?: string }).code !== "ENOENT") throw error
    throw new CliError("unauthenticated", `The device key ${path} is missing, so this machine cannot prove who it is.`, {
      command: "mehen enrol --workspace <slug>",
      say: "Enrol this machine again with `mehen enrol --workspace <slug>` and accept it in the browser.",
    })
  }
  if (backend === "secure-enclave") {
    const key = enclaveKey(options.observe ? await observedHelper(env) : await requireHelper(env), path)
    return { key, jwk: await enclavePublicJwk(dir) }
  }
  let parsed: unknown = null
  try {
    parsed = JSON.parse(await Bun.file(path).text())
  } catch {
    parsed = null
  }
  if (!isSoftwareKeyFile(parsed)) {
    throw new CliError("unauthenticated", `The device key ${path} is not a P-256 private JWK.`, {
      command: "mehen enrol --workspace <slug>",
      say: "Enrol this machine again with `mehen enrol --workspace <slug>`.",
    })
  }
  return { key: softwareKey(await importSoftwareKey(parsed)), jwk: publicJwk(parsed) }
}

export async function removeDeviceKey(dir: string, backend: Backend): Promise<void> {
  await rm(keyPath(dir, backend), { force: true })
  await rm(keyScopePath(dir, backend), { force: true })
  if (backend === "secure-enclave") await rm(enclavePublicKeyPath(dir), { force: true })
}
