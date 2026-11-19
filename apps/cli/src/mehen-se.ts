// The Secure Enclave helper (native/mehen-se). The key never
// leaves the enclave; on disk is an enclave-wrapped blob, useless elsewhere.
//
//   mehen-se create --out <path>   prints the public JWK, writes the blob 0600
//   mehen-se sign --key <path> --no-interaction   stdin bytes, prints base64url signature
//   mehen-se available             exit 0 when the Secure Enclave can be used

import { createHash } from "node:crypto"
import { accessSync, constants } from "node:fs"
import { chmod, lstat, mkdir, readdir, rename, rm, writeFile } from "node:fs/promises"
import { userInfo } from "node:os"
import { dirname, join } from "node:path"
import { type Bytes, base64UrlDecode, isDeviceJwk, type DeviceJwk } from "@mehen/protocol"
import { randomId } from "@mehen/protocol/bytes"
import { CliError } from "./errors.ts"
import type { Env } from "./config.ts"
import { embeddedHelperPath } from "./embedded-helper.ts"
import { BUILD_KIND, type BuildKind, isCompiledBinary } from "./version.ts"

const HELPER_TIMEOUT_MS = 15_000

function executable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

// The file name of an extracted helper: mehen-se-<first 16 hex of its sha256>,
// so a new helper never overwrites one a running mehen may still use.
const EXTRACTED_HELPER = /^mehen-se-[0-9a-f]{16}$/

export function extractedHelperName(bytes: Uint8Array): string {
  return `mehen-se-${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}`
}

// The name ensureHelper extracted or found in this process; findHelper is
// synchronous and cannot read the embedded helper itself.
let extractedName: string | null = null

// MEHEN_SE_PATH points a source run or a development build at a helper. A
// release build ignores it and runs only the helper it carries, since that
// helper is handed every signature and the local vault's keys.
export type HelperBuild = { compiled: boolean; kind: BuildKind }

export function helperOverride(env: Env, build: HelperBuild = { compiled: isCompiledBinary(), kind: BUILD_KIND }): string | null {
  if (!env.MEHEN_SE_PATH) return null
  return !build.compiled || build.kind === "dev" ? env.MEHEN_SE_PATH : null
}

// helperOverride when set (and nothing else), else <home>/bin/mehen-se-<hash16>
// once ensureHelper has extracted the embedded helper there in this
// process, else null. `home` is the resolved config root (device-key.ts
// passes resolveHome(env).root). The discovery 0.2.0 used (a helper next to
// the binary, or <dir>/bin/mehen-se) is retired: a release binary carries
// its helper, and a development build is pointed at one with MEHEN_SE_PATH.
export function findHelper(env: Env, home: string): string | null {
  const override = helperOverride(env)
  if (override) return executable(override) ? override : null
  const candidate = extractedName ? join(home, "bin", extractedName) : null
  return candidate && executable(candidate) ? candidate : null
}

// Writes a helper file by temp file and rename, 0755, so a reader sees the
// old file or the whole new one and two writers end with one correct file.
export async function writeHelperFile(bytes: Uint8Array, target: string): Promise<void> {
  const temp = join(dirname(target), `.${randomId("helper", 6)}.tmp`)
  try {
    await writeFile(temp, bytes, { mode: 0o755, flag: "wx" })
    await chmod(temp, 0o755)
    await rename(temp, target)
  } finally {
    await rm(temp, { force: true })
  }
}

// <home>/bin: created 0700; a link, a file or another user's directory is
// refused, since mehen runs what it finds there.
async function helperDir(home: string): Promise<string> {
  const dir = join(home, "bin")
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const info = await lstat(dir)
  if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== userInfo().uid) {
    throw new CliError("key_insecure", `Refusing to put the Secure Enclave helper in ${dir}: it is not a directory this user owns.`, { say: `Move ${dir} aside and run the command again.` })
  }
  if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700)
  return dir
}

async function sameBytes(path: string, bytes: Uint8Array): Promise<boolean> {
  try {
    const info = await lstat(path)
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== userInfo().uid || info.size !== bytes.length) return false
    return Buffer.from(await Bun.file(path).bytes()).equals(Buffer.from(bytes))
  } catch {
    return false
  }
}

// Extracts a helper into <home>/bin/mehen-se-<hash16> unless that file is
// already there with these bytes, then removes other extracted helpers that
// are plain files of this user (never a link or someone else's file).
export async function extractHelper(source: string, home: string): Promise<string> {
  const bytes = await Bun.file(source).bytes()
  const name = extractedHelperName(bytes)
  const dir = await helperDir(home)
  const target = join(dir, name)
  if (await sameBytes(target, bytes)) {
    // The right bytes in a plain file of this user: put back a lost executable bit.
    if (((await lstat(target)).mode & 0o777) !== 0o755) await chmod(target, 0o755)
  } else {
    await writeHelperFile(bytes, target)
    for (const entry of await readdir(dir)) {
      if (entry === name || !EXTRACTED_HELPER.test(entry)) continue
      const info = await lstat(join(dir, entry)).catch(() => null)
      if (info?.isFile() && !info.isSymbolicLink() && info.uid === userInfo().uid) await rm(join(dir, entry), { force: true })
    }
  }
  extractedName = name
  return target
}

// The helper to run: the embedded one, extracted into <home>/bin when this
// build carries one, then findHelper. helperOverride, when set, is the only
// candidate and nothing is extracted.
export async function ensureHelper(env: Env, home: string): Promise<string | null> {
  if (!helperOverride(env)) {
    const embedded = await embeddedHelperPath()
    if (embedded) await extractHelper(embedded, home)
  }
  return findHelper(env, home)
}

// The helper as it already is on disk, for a command that only observes
// (status, doctor): helperOverride when set and executable; else
// <home>/bin/mehen-se-<hash16> of the embedded helper when that is a plain
// file of this user, in a directory of this user, with exactly the embedded
// bytes and executable; else null. Nothing is created, extracted, chmodded
// or removed. `source` stands in for the embedded helper (tests).
export async function readyHelper(env: Env, home: string, source?: string | null): Promise<string | null> {
  const override = helperOverride(env)
  if (override) return executable(override) ? override : null
  const embedded = source === undefined ? await embeddedHelperPath() : source
  if (!embedded) return null
  const bytes = await Bun.file(embedded).bytes()
  const dir = join(home, "bin")
  try {
    const info = await lstat(dir)
    if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== userInfo().uid) return null
  } catch {
    return null
  }
  const target = join(dir, extractedHelperName(bytes))
  return (await sameBytes(target, bytes)) && executable(target) ? target : null
}

type HelperResult = { exitCode: number | null; stdout: string; stderr: string }

async function runHelper(helper: string, args: string[], stdin?: Bytes): Promise<HelperResult> {
  const proc = Bun.spawn([helper, ...args], {
    stdin: stdin ?? "ignore",
    stdout: "pipe",
    stderr: "pipe",
    timeout: HELPER_TIMEOUT_MS,
  })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  await proc.exited
  // A signal (a CryptoKit trap on a corrupt blob, or our timeout) is a failure.
  return { exitCode: proc.signalCode ? null : proc.exitCode, stdout, stderr }
}

// What the helper prints when this process cannot reach the enclave, as
// under Codex's macOS sandbox, where `available` also fails.
const ENCLAVE_UNREACHABLE = "Secure Enclave is not available"
export const ENCLAVE_BLOCKED_SAY = "This process cannot reach the Secure Enclave, usually because a sandbox (such as Codex's) blocks it. Run this command outside the sandbox (ask the human to approve it), or enrol with --backend software only if the human chooses a key stored on disk."

function helperFailure(action: string, result: HelperResult): CliError {
  const detail = result.stderr.trim().split("\n")[0] || (result.exitCode === null ? "killed by a signal or timed out" : `exit ${result.exitCode}`)
  // The key is fine; only this process cannot use it.
  if (detail.includes(ENCLAVE_UNREACHABLE)) {
    return new CliError("helper_failed", `The Secure Enclave helper could not ${action}: ${detail}`, {
      say: "This process cannot reach the Secure Enclave, usually because a sandbox (such as Codex's) blocks it; the key itself is fine, so do not enrol again. Run this command outside the sandbox (ask the human to approve it), or use the mehen MCP tools instead.",
    })
  }
  return new CliError("helper_failed", `The Secure Enclave helper could not ${action}: ${detail}`, {
    command: "mehen enrol --workspace <slug> --backend software",
    say: "The Secure Enclave key is unusable here; enrol this machine again, with --backend software if the enclave keeps failing.",
  })
}

export async function helperAvailable(helper: string): Promise<boolean> {
  try {
    return (await runHelper(helper, ["available"])).exitCode === 0
  } catch {
    return false
  }
}

function parseJwk(text: string): DeviceJwk | null {
  try {
    const value: unknown = JSON.parse(text)
    return isDeviceJwk(value) ? { kty: "EC", crv: "P-256", x: value.x, y: value.y } : null
  } catch {
    return null
  }
}

export async function enclaveCreate(helper: string, blobPath: string): Promise<DeviceJwk> {
  const result = await runHelper(helper, ["create", "--out", blobPath])
  if (result.exitCode !== 0) throw helperFailure("create a key", result)
  const jwk = parseJwk(result.stdout.trim())
  if (!jwk) throw helperFailure("create a key", { ...result, stderr: "unexpected output" })
  return jwk
}

export async function enclaveSign(helper: string, blobPath: string, data: Bytes): Promise<Bytes> {
  const result = await runHelper(helper, ["sign", "--key", blobPath, "--no-interaction"], data)
  if (result.exitCode !== 0) throw helperFailure("sign", result)
  let signature: Bytes
  try {
    signature = base64UrlDecode(result.stdout.trim())
  } catch {
    throw helperFailure("sign", { ...result, stderr: "the signature is not base64url" })
  }
  if (signature.length === 64) return signature
  return derToRaw(signature)
}

function derInteger(bytes: Bytes, offset: number): { value: Bytes; end: number } {
  if (bytes[offset] !== 0x02) throw new Error("expected an INTEGER")
  const length = bytes[offset + 1] ?? 0
  const start = offset + 2
  const end = start + length
  if (length === 0 || length > 33 || end > bytes.length) throw new Error("bad INTEGER length")
  let value = bytes.subarray(start, end)
  while (value.length > 32 && value[0] === 0) value = value.subarray(1)
  if (value.length > 32) throw new Error("INTEGER too large for P-256")
  return { value, end }
}

// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } to the 64-byte
// r||s the vault accepts. A P-256 signature is under 128 bytes, so the
// lengths are always single-byte.
export function derToRaw(der: Bytes): Bytes {
  try {
    if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("expected a SEQUENCE")
    const r = derInteger(der, 2)
    const s = derInteger(der, r.end)
    if (s.end !== der.length) throw new Error("trailing bytes")
    const raw = new Uint8Array(64)
    raw.set(r.value, 32 - r.value.length)
    raw.set(s.value, 64 - s.value.length)
    return raw
  } catch (error) {
    throw new CliError("helper_failed", `The Secure Enclave helper returned a signature that is neither r||s nor DER: ${(error as Error).message}`)
  }
}
