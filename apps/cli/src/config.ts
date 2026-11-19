// Local state: a workspace slot under the root (MEHEN_HOME, default
// ~/.config/mehen; home.ts) holds config.json and the device key, both 0600.
// Nothing else about the vault is kept on disk.

import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises"
import { homedir, userInfo } from "node:os"
import { join } from "node:path"
import { randomId } from "@mehen/protocol/bytes"
import { type OwnerRef, OwnerRefSchema, type WorkspaceRef, WorkspaceSlugSchema } from "@mehen/protocol/workspace"
import { CliError, usageError } from "./errors.ts"
import { defaultVault } from "./local-vault.ts"

export const DEFAULT_VAULT_URL = "https://app.mehen.dev"

export type Backend = "secure-enclave" | "software"
export const BACKENDS: readonly Backend[] = ["secure-enclave", "software"]

// `tenant` is the workspace id (the tn_ prefix is historical, design 1.2);
// `name` (this machine's name in the workspace, as the vault's pages show
// it), `workspaceSlug`, `workspaceName` and `owner` are display fields
// refreshed from authenticated status, never a selector of authority.
export type Config = {
  vault: string
  tenant: string
  device: string
  backend: Backend
  // The device key's fingerprint as the Machines page shows it, recorded at
  // enrolment so mehen status can print it without the key helper. Public.
  fingerprint?: string
  name?: string
  workspaceSlug?: string
  workspaceName?: string
  owner?: OwnerRef
}

export type Env = Record<string, string | undefined>

export const DEFAULT_CONTEXT_FILE = "default-context"

export function homeDir(env: Env): string {
  return env.HOME || homedir()
}

// ~/.config/mehen: the default root (MEHEN_HOME when unset; home.ts).
export function defaultConfigDir(env: Env): string {
  return join(homeDir(env), ".config", "mehen")
}

// The workspace a config records, as a WorkspaceRef when the display fields
// are recorded; null for a config from before they were.
export function configWorkspace(config: Config): WorkspaceRef | null {
  return config.workspaceSlug && config.workspaceName ? { id: config.tenant, slug: config.workspaceSlug, name: config.workspaceName } : null
}

// "Northwind (northwind)" or, before the display fields are recorded, the id.
export function workspaceLabel(config: Pick<Config, "tenant" | "workspaceSlug" | "workspaceName">): string {
  return config.workspaceSlug && config.workspaceName ? `${config.workspaceName} (${config.workspaceSlug})` : config.tenant
}

export function configPath(dir: string): string {
  return join(dir, "config.json")
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"])

// A vault origin as mehen accepts it (design 6.5): canonical https origin
// with no userinfo, path, query or fragment; plain http only for a vault on
// this machine. Throws usage for anything else.
export function canonicalOrigin(raw: string): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw usageError(`The vault URL ${JSON.stringify(raw)} is not a URL. Set MEHEN_VAULT_URL to something like ${DEFAULT_VAULT_URL}.`)
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw usageError(`The vault URL ${raw} must use https (plain http is allowed for 127.0.0.1 and localhost only).`)
  }
  if (url.search || url.hash) throw usageError(`The vault URL ${raw} must not carry a query or fragment.`)
  if (url.username || url.password) throw usageError(`The vault URL ${raw} must not carry a user name or password.`)
  if (url.pathname !== "/") throw usageError(`The vault URL ${raw} must be an origin with no path.`)
  return url.origin
}

// MEHEN_VAULT_URL wins, then the enrolled vault, then the local vault
// `mehen up` set up, then Mehen Cloud. Once a context is selected, a
// MEHEN_VAULT_URL naming another origin is refused instead (session.ts);
// here it only picks the vault to enrol with.
export function resolveVaultUrl(env: Env, config: Config | null): string {
  return canonicalOrigin(env.MEHEN_VAULT_URL || config?.vault || defaultVault(env).url)
}

export function isMachineName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 64
}

export function isConfig(value: unknown): value is Config {
  if (typeof value !== "object" || value === null) return false
  const c = value as Record<string, unknown>
  return (
    typeof c.vault === "string" &&
    typeof c.tenant === "string" &&
    typeof c.device === "string" &&
    typeof c.backend === "string" &&
    (BACKENDS as readonly string[]).includes(c.backend) &&
    (c.fingerprint === undefined || typeof c.fingerprint === "string") &&
    (c.name === undefined || isMachineName(c.name)) &&
    (c.workspaceSlug === undefined || WorkspaceSlugSchema.safeParse(c.workspaceSlug).success) &&
    (c.workspaceName === undefined || (typeof c.workspaceName === "string" && c.workspaceName.length > 0 && c.workspaceName.length <= 64)) &&
    (c.owner === undefined || OwnerRefSchema.safeParse(c.owner).success)
  )
}

export async function readConfig(dir: string): Promise<Config | null> {
  let text: string
  try {
    text = await readFile(configPath(dir), "utf8")
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") return null
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    parsed = null
  }
  if (!isConfig(parsed)) {
    throw new CliError("internal", `${configPath(dir)} is not a valid mehen config.`, {
      command: "mehen enrol --workspace <slug>",
      say: `Move ${configPath(dir)} aside and enrol this machine again with \`mehen enrol --workspace <slug>\`.`,
    })
  }
  return parsed
}

export async function writeConfig(dir: string, config: Config): Promise<void> {
  await writePrivateFile(configPath(dir), `${JSON.stringify(config, null, 2)}\n`)
}

export async function removeConfig(dir: string): Promise<void> {
  await rm(configPath(dir), { force: true })
}

// The user whose files mehen trusts: the one running it. Tests pass another
// uid to prove a file or directory owned by someone else is refused.
export type OwnerOptions = { owner?: number }

function expectedOwner(options: OwnerOptions): number {
  return options.owner ?? userInfo().uid
}

// The config directory, created 0700. An existing directory is looked at
// without following links: a symbolic link is refused (a link planted there
// would send the key and the ledger elsewhere), one another user owns is
// refused (they could plant a key in it), and one this user owns is
// tightened to 0700 when its mode lets anyone else in.
export async function ensureConfigDir(dir: string, options: OwnerOptions = {}): Promise<void> {
  let info: Awaited<ReturnType<typeof lstat>>
  try {
    info = await lstat(dir)
  } catch (error) {
    if ((error as { code?: string }).code !== "ENOENT") throw error
    await mkdir(dir, { recursive: true, mode: 0o700 })
    info = await lstat(dir)
  }
  if (info.isSymbolicLink()) {
    throw new CliError("key_insecure", `Refusing to use ${dir}: it is a symbolic link, so the device key and ledger would be written somewhere else.`, {
      say: `Remove the link at ${dir} (or point MEHEN_HOME at a real directory) and run the command again.`,
    })
  }
  if (!info.isDirectory()) {
    throw new CliError("key_insecure", `Refusing to use ${dir}: it is not a directory.`, { say: `Move ${dir} aside or point MEHEN_HOME at a directory.` })
  }
  if (info.uid !== expectedOwner(options)) {
    throw new CliError("key_insecure", `Refusing to use ${dir}: it is owned by another user (uid ${info.uid}), who could put a device key there.`, {
      say: `Point MEHEN_HOME at a directory you own, or take ownership of ${dir} and run the command again.`,
    })
  }
  if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700)
}

// Writes a 0600 file atomically: a fresh temp file created with O_EXCL and
// mode 0600 whatever the umask, then renamed over the target.
export async function writePrivateFile(path: string, content: string): Promise<void> {
  await ensureConfigDir(join(path, ".."))
  const temp = `${path}.${randomId("tmp", 6)}`
  const handle = await open(temp, "wx", 0o600)
  try {
    await handle.chmod(0o600)
    await handle.writeFile(content, "utf8")
    await handle.sync()
  } finally {
    await handle.close()
  }
  await rename(temp, path)
  await chmod(path, 0o600)
}

// Refuses key-bearing state that is not a plain file this user owns and
// nobody else can read or write: looked at without following links, so a
// symbolic link, a directory, a device or a file owned by another user is
// refused before its mode is even considered. A missing file throws the
// ENOENT error itself, so callers can tell "no key" from "a bad key".
export async function assertPrivateFile(path: string, options: OwnerOptions = {}): Promise<void> {
  const info = await lstat(path)
  if (info.isSymbolicLink()) {
    throw new CliError("key_insecure", `Refusing to use ${path}: it is a symbolic link, so the device key would be read from somewhere else.`, {
      say: `Remove the link at ${path} and enrol this machine again with \`mehen enrol\`.`,
    })
  }
  if (!info.isFile()) {
    throw new CliError("key_insecure", `Refusing to use ${path}: it is not a regular file.`, { say: `Move ${path} aside and enrol this machine again with \`mehen enrol\`.` })
  }
  if (info.uid !== expectedOwner(options)) {
    throw new CliError("key_insecure", `Refusing to use ${path}: it is owned by another user (uid ${info.uid}), so it is not this machine's key.`, {
      say: `Remove ${path} (or take ownership of it) and enrol this machine again with \`mehen enrol\`.`,
    })
  }
  if ((info.mode & 0o077) !== 0) {
    const mode = (info.mode & 0o777).toString(8).padStart(3, "0")
    throw new CliError("key_insecure", `Refusing to use ${path}: its mode is ${mode}, so other users on this machine can read it.`, {
      command: `chmod 600 ${path}`,
      say: `Restrict the device key with \`chmod 600 ${path}\`; if someone else may have copied it, revoke this device and enrol again.`,
    })
  }
}
