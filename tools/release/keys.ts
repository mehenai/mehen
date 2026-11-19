// Release keys: P-256 keys in the release Mac's Secure Enclave, made by the
// mehen-se helper the repository ships, that sign release manifests.
//
//   bun tools/release/keys.ts create --id rk-release-2026 [--user-presence]
//
// writes ~/.config/mehen-release/<id>.se (the enclave-wrapped blob, useless
// on any other machine) and <id>.json, the ReleaseKey sidecar
// { id, alg, jwk, presence, created }, in a 0700 directory, and prints the
// ReleaseKey literal to add to RELEASE_KEYS in packages/protocol/src/release-keys.ts
// in its own reviewed commit. `--user-presence` makes the enclave ask for
// Touch ID or the password on every signature; `presence` records which,
// and the release tool refuses to sign when the sidecar and RELEASE_KEYS
// disagree. An existing key is never replaced: a new key gets a new id.
//
// The helper is MEHEN_SE_PATH, else apps/cli/dist/mehen-se from a build,
// else apps/cli/native/mehen-se/build/mehen-se from its build.sh.

import { type Stats, accessSync, constants } from "node:fs"
import { chmod, lstat, mkdir, open, readFile } from "node:fs/promises"
import { homedir, userInfo } from "node:os"
import { join, resolve } from "node:path"
import { isDeviceJwk } from "../../packages/protocol/src/proof.ts"
import { type ReleaseKey, type ReleaseKeyPresence, isReleaseKey } from "../../packages/protocol/src/release-manifest.ts"

export class ReleaseKeyError extends Error {}

const CLI_DIR = resolve(import.meta.dir, "..", "..", "apps", "cli")
// A file name on the release Mac and a key id in every manifest.
export const RELEASE_KEY_ID = /^[a-z0-9][a-z0-9-]{0,47}$/

export function releaseKeyDir(env: Record<string, string | undefined>): string {
  return join(env.HOME || homedir(), ".config", "mehen-release")
}

export function releaseHelper(env: Record<string, string | undefined>): string {
  const candidates = env.MEHEN_SE_PATH ? [env.MEHEN_SE_PATH] : [join(CLI_DIR, "dist", "mehen-se"), join(CLI_DIR, "native", "mehen-se", "build", "mehen-se")]
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK)
      return candidate
    } catch {
      // try the next one
    }
  }
  throw new ReleaseKeyError(`No mehen-se helper at ${candidates.join(" or ")}. Build it first (apps/cli/native/mehen-se/build.sh) or point MEHEN_SE_PATH at it.`)
}

async function lstatOrNull(path: string): Promise<Stats | null> {
  return lstat(path).catch((error: unknown) => {
    if ((error as { code?: string }).code === "ENOENT") return null
    throw error
  })
}

// The key directory as it must be: a real directory this user owns that
// nobody else can enter. Created 0700; an existing one is tightened.
async function ensureKeyDir(dir: string): Promise<void> {
  if (!(await lstatOrNull(dir))) await mkdir(dir, { recursive: true, mode: 0o700 })
  const info = await lstat(dir)
  if (info.isSymbolicLink() || !info.isDirectory()) throw new ReleaseKeyError(`${dir} must be a directory, not a link or a file.`)
  if (info.uid !== userInfo().uid) throw new ReleaseKeyError(`${dir} is owned by another user (uid ${info.uid}).`)
  if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700)
}

async function assertPrivate(path: string, what: string): Promise<void> {
  const info = await lstatOrNull(path)
  if (!info) throw new ReleaseKeyError(`No ${what} at ${path}.`)
  if (info.isSymbolicLink() || !info.isFile()) throw new ReleaseKeyError(`The ${what} ${path} must be a plain file, not a link.`)
  if (info.uid !== userInfo().uid) throw new ReleaseKeyError(`The ${what} ${path} is owned by another user (uid ${info.uid}).`)
  if ((info.mode & 0o077) !== 0) throw new ReleaseKeyError(`The ${what} ${path} is readable by other users; chmod 600 it.`)
}

export type CreateReleaseKeyInput = { id: string; presence: ReleaseKeyPresence; dir: string; helper: string; now?: Date }

export async function createReleaseKey(input: CreateReleaseKeyInput): Promise<ReleaseKey> {
  if (!RELEASE_KEY_ID.test(input.id)) throw new ReleaseKeyError(`${JSON.stringify(input.id)} is not a key id like rk-release-2026 (lower case letters, digits and dashes).`)
  await ensureKeyDir(input.dir)
  const blob = join(input.dir, `${input.id}.se`)
  const sidecar = join(input.dir, `${input.id}.json`)
  for (const path of [blob, sidecar]) {
    if (await lstatOrNull(path)) throw new ReleaseKeyError(`${path} already exists. A release key is never replaced; make a new key with a new id.`)
  }
  const proc = Bun.spawn([input.helper, "create", "--out", blob, ...(input.presence === "required" ? ["--user-presence"] : [])], { stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 60_000 })
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  if (code !== 0) throw new ReleaseKeyError(`mehen-se create failed: ${stderr.trim().split("\n")[0] || `exit ${code}`}`)
  let jwk: unknown
  try {
    jwk = JSON.parse(stdout.trim())
  } catch {
    jwk = null
  }
  if (!isDeviceJwk(jwk)) throw new ReleaseKeyError("mehen-se create printed something other than a P-256 public JWK.")
  await chmod(blob, 0o600)
  await assertPrivate(blob, "key blob")
  const key: ReleaseKey = { id: input.id, alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, presence: input.presence, created: (input.now ?? new Date()).toISOString() }
  const handle = await open(sidecar, "wx", 0o600)
  try {
    await handle.writeFile(`${JSON.stringify(key, null, 2)}\n`, "utf8")
  } finally {
    await handle.close()
  }
  return key
}

// The key a release is signed with: its sidecar, checked, and the blob the
// helper signs with. Neither may be a link, another user's, or readable by
// anyone else.
export async function readSigningKey(dir: string, id: string): Promise<{ key: ReleaseKey; blob: string }> {
  if (!RELEASE_KEY_ID.test(id)) throw new ReleaseKeyError(`${JSON.stringify(id)} is not a release key id.`)
  const info = await lstatOrNull(dir)
  if (!info) throw new ReleaseKeyError(`No release key directory at ${dir}; make the key with bun tools/release/keys.ts create --id ${id}.`)
  if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== userInfo().uid || (info.mode & 0o077) !== 0) throw new ReleaseKeyError(`${dir} must be a 0700 directory this user owns.`)
  const sidecar = join(dir, `${id}.json`)
  const blob = join(dir, `${id}.se`)
  await assertPrivate(sidecar, "key sidecar")
  await assertPrivate(blob, "key blob")
  let key: unknown
  try {
    key = JSON.parse(await readFile(sidecar, "utf8"))
  } catch {
    key = null
  }
  if (!isReleaseKey(key) || key.id !== id) throw new ReleaseKeyError(`${sidecar} is not the ReleaseKey sidecar of ${id}.`)
  return { key, blob }
}

export type KeysArgs = { command: "create"; id: string; presence: ReleaseKeyPresence }

export function parseKeysArgs(argv: string[]): KeysArgs {
  const usage = "Usage: bun tools/release/keys.ts create --id <key id> [--user-presence]"
  if (argv[0] !== "create") throw new ReleaseKeyError(usage)
  let id: string | null = null
  let presence: ReleaseKeyPresence = "none"
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--id") {
      const value = argv[++i]
      if (!value) throw new ReleaseKeyError("--id needs a value")
      id = value
    } else if (arg === "--user-presence") presence = "required"
    else throw new ReleaseKeyError(`unknown argument ${arg}. ${usage}`)
  }
  if (!id) throw new ReleaseKeyError(`--id is required. ${usage}`)
  return { command: "create", id, presence }
}

if (import.meta.main) {
  try {
    const args = parseKeysArgs(process.argv.slice(2))
    const key = await createReleaseKey({ id: args.id, presence: args.presence, dir: releaseKeyDir(process.env), helper: releaseHelper(process.env) })
    process.stdout.write(`${JSON.stringify(key, null, 2)}\n`)
    console.error(`keys: made ${key.id} (presence ${key.presence}) in ${releaseKeyDir(process.env)}. Add the literal above to RELEASE_KEYS in packages/protocol/src/release-keys.ts in its own reviewed commit.`)
  } catch (error) {
    console.error(`keys: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
