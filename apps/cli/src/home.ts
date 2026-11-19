// The config root: one directory per identity,
// MEHEN_HOME, default ~/.config/mehen, holding a slot per (origin,
// workspace). Every command, `mehen mcp`, setup and doctor get the root
// from resolveHome; it refuses before migration, key reads or network.
//
//   MEHEN_HOME        the root; absolute, no NUL, else usage
//   MEHEN_CONFIG_DIR  an alias of the root for one release; naming a slot,
//                     a pending slot, a legacy context or a directory with
//                     enrolment.json, or disagreeing with MEHEN_HOME, is
//                     config_dir_retired. On a managed host it is the
//                     launcher's pinned slot directory, never the alias.
//
// The managed-host marker (agent-profiles.ts, unchanged) is read through
// managedHost, which turns the marker walk's plain refusal into the named
// local refusal key_insecure with the unsafe path, never `internal`.

import { lstatSync, mkdirSync, realpathSync, statSync } from "node:fs"
import { userInfo } from "node:os"
import { join, resolve, sep } from "node:path"
import { type VaultFileOptions, defaultOwnerRoot, readManagedVaultMarker } from "./agent-profiles.ts"
import { type Env, canonicalOrigin, homeDir } from "./config.ts"
import { CliError, usageError } from "./errors.ts"

export type HomeResolution = { root: string; source: "MEHEN_HOME" | "MEHEN_CONFIG_DIR" | "default" | "managed" }

export const ROOT_MARKER_FILE = "mehen.json"
export const MIGRATION_JOURNAL_FILE = "migration.json"
export const WORKSPACES_DIR = "workspaces"
export const PENDING_DIR = "pending"
export const LOCKS_DIR = "locks"
export const ENROLMENT_RECORD_FILE = "enrolment.json"

// The directory name of an origin under workspaces/, pending/ and locks/:
// the host for https on 443, host_port for another port, and
// http_<host>_<port> for a loopback vault on plain http.
export function originKey(origin: string): string {
  const url = new URL(canonicalOrigin(origin))
  const host = url.hostname.replace(/^\[|\]$/g, "").replaceAll(":", "-")
  if (url.protocol === "http:") return `http_${host}_${url.port || "80"}`
  return url.port ? `${host}_${url.port}` : host
}

// A path component mehen writes under the root: a workspace id, a slug, a
// device, a context name. Never empty, never `.` or `..`, never a separator.
export const SAFE_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/

function unsafeDirectory(path: string, why: string): CliError {
  return new CliError("key_insecure", `Refusing to use ${path}: ${why}, so what mehen keeps there could be moved or replaced by someone else.`, {
    say: `Move ${path} aside (mehen makes it a private directory of this user), then run the command again.`,
  })
}

// Every existing directory from below `root` down to `path` is a real
// directory (not a link) this user owns and nobody else can open. A missing
// component ends the walk: what is below it does not exist yet. Read-only.
export function assertPrivateDirs(root: string, path: string): void {
  if (path !== root && !path.startsWith(root + sep)) throw unsafeDirectory(path, `it is outside the config root ${root}`)
  const uid = process.getuid?.() ?? -1
  let current = root
  for (const component of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, component)
    let info: ReturnType<typeof lstatSync> | undefined
    try {
      info = lstatSync(current, { throwIfNoEntry: false })
    } catch (error) {
      throw unsafeDirectory(current, `it cannot be examined (${(error as { code?: string }).code ?? "error"})`)
    }
    if (!info) return
    if (info.isSymbolicLink()) throw unsafeDirectory(current, "it is a symbolic link")
    if (!info.isDirectory()) throw unsafeDirectory(current, "it is not a directory")
    if (info.uid !== uid) throw unsafeDirectory(current, `it is owned by another user (uid ${info.uid})`)
    if ((info.mode & 0o077) !== 0) throw unsafeDirectory(current, "other users can open it")
  }
}

// Creates `path` and its missing parents below `root`, each 0700, one
// component at a time and checked after it is made: never a recursive
// mkdir through components nobody looked at.
export function mkdirPrivate(root: string, path: string): void {
  assertPrivateDirs(root, path)
  let current = root
  for (const component of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, component)
    try {
      mkdirSync(current, { mode: 0o700 })
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") throw unsafeDirectory(current, `it cannot be created (${(error as { code?: string }).code ?? "error"})`)
    }
  }
  assertPrivateDirs(root, path)
}

// ---- the root and its ancestors ------------------------------------------

// The root must be a real directory this user owns; every ancestor a real
// directory owned by this user or root and closed to group and world
// writes. A root-owned link (macOS's /var and /tmp) is followed; any other
// link refuses. World-writable ancestors stay refused, sticky or not
// (the sticky allowance is the installer's only).
// Read-only: a missing component ends the walk.
export function assertSafeRoot(root: string): void {
  walkRoot(root, false)
}

// The same walk for the first command that writes under the root: each
// missing component, ~/.config and the root itself included, is created
// 0700 one at a time and checked by the same rules once it exists, so the
// root is never made under an ancestor nobody looked at.
export function ensureSafeRoot(root: string): void {
  walkRoot(root, true)
}

// The same walk and rules for another directory mehen writes private files
// to (a backup restore's staging directory), refused in its caller's words.
export function ensureSafeDirectory(dir: string, refuse: (path: string, why: string) => CliError): void {
  walkRoot(dir, true, refuse)
}

function walkRoot(
  root: string,
  create: boolean,
  refuse = (path: string, why: string) =>
    new CliError("key_insecure", `Refusing to use ${root}: ${path} ${why}, so the device keys under it could be moved or replaced by someone else.`, {
      say: "Put MEHEN_HOME (or HOME) under a directory only this user can write, not below a world-writable one such as /tmp, then run the command again.",
    }),
): void {
  const uid = userInfo().uid
  // An inaccessible or impossible component (EACCES, ENOTDIR, a loop) is
  // the same named refusal, never an internal error.
  const examine = (path: string, follow: boolean) => {
    try {
      return (follow ? statSync : lstatSync)(path, { throwIfNoEntry: false })
    } catch (error) {
      throw refuse(path, `cannot be examined (${(error as { code?: string }).code ?? "error"})`)
    }
  }
  const made = (path: string) => {
    try {
      mkdirSync(path, { mode: 0o700 })
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") throw refuse(path, `cannot be created (${(error as { code?: string }).code ?? "error"})`)
    }
    return examine(path, false)
  }
  const parts = root.split(sep).filter(Boolean)
  let current: string = sep
  for (let i = 0; i <= parts.length; i++) {
    if (i > 0) current = join(current, parts[i - 1] as string)
    let info = examine(current, false)
    if (!info && create) info = made(current)
    if (!info) return
    const isRoot = i === parts.length
    if (info.isSymbolicLink()) {
      if (isRoot || info.uid !== 0) throw refuse(current, isRoot ? "is a symbolic link" : info.uid === uid ? "is a symbolic link (only links root owns, such as /var on macOS, are followed)" : "is a symbolic link another user controls")
      info = examine(current, true)
      if (!info) return
    }
    if (!info.isDirectory()) throw refuse(current, "is not a directory")
    if (isRoot) {
      // The root is this user's and nobody else's.
      if (info.uid !== uid) throw refuse(current, `is owned by another user (uid ${info.uid})`)
      if ((info.mode & 0o077) !== 0) throw refuse(current, `is open to other users (mode ${(info.mode & 0o777).toString(8)}); \`chmod 700 ${current}\` closes it`)
      if ((info.mode & 0o700) !== 0o700) throw refuse(current, `is not readable, writable and searchable by this user (mode ${(info.mode & 0o777).toString(8)})`)
      continue
    }
    if (info.uid !== uid && info.uid !== 0) throw refuse(current, `is owned by another user (uid ${info.uid})`)
    if ((info.mode & 0o022) !== 0) throw refuse(current, "is writable by other users")
  }
}

export function workspacesDir(root: string): string {
  return join(root, WORKSPACES_DIR)
}

export function pendingDir(root: string): string {
  return join(root, PENDING_DIR)
}

export function activeSlotPath(root: string, origin: string, tenant: string): string {
  return join(root, WORKSPACES_DIR, originKey(origin), tenant)
}

export function pendingSlotPath(root: string, origin: string, slug: string): string {
  return join(root, PENDING_DIR, originKey(origin), slug)
}

// Why the marker walk refused: the first component on the path from / to
// the marker's directory that is not a real directory owned by this user or
// root and closed to group and world writes, or the marker file itself.
// The walk mirrors agent-profiles.ts so the refusal can name the path; it
// never decides anything on its own.
function unsafeMarkerPath(files: VaultFileOptions): string | null {
  let ownerRoot: string
  try {
    ownerRoot = files.ownerRoot === undefined ? defaultOwnerRoot() : realpathSync(files.ownerRoot)
  } catch {
    return files.ownerRoot ?? null
  }
  const uid = process.getuid?.() ?? -1
  const stat = files.lstat ?? lstatSync
  const target = join(ownerRoot, ".config", "mehen")
  let current: string = sep
  for (const component of ["", ...target.split(sep).filter(Boolean)]) {
    current = component === "" ? sep : join(current, component)
    let info: ReturnType<typeof stat>
    try {
      info = stat(current)
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") return null
      return current
    }
    const insideHome = current === ownerRoot || current.startsWith(ownerRoot + sep)
    const ownerOk = info.uid === uid || (!insideHome && info.uid === 0)
    if (info.isSymbolicLink() || !info.isDirectory() || !ownerOk || (info.mode & 0o022) !== 0) return current
  }
  return join(target, "managed-agents")
}

// Is this a managed host? The marker under the owner's home, read by the
// unchanged agent-profiles.ts walk. Any refusal of that walk (an unsafe
// ancestor such as Linux's world-writable /tmp, a link, a marker with the
// wrong mode) is fail-closed and named: key_insecure, exit 6.
export function managedHost(files: VaultFileOptions = {}): boolean {
  try {
    return readManagedVaultMarker(undefined, files)
  } catch (error) {
    if (error instanceof CliError) throw error
    const path = unsafeMarkerPath(files)
    const where = path ? ` ${path} is not a directory only this user (or root, above the home) can write, so the managed-host marker under it cannot be trusted` : " the managed-host marker could not be verified"
    throw new CliError("key_insecure", `Refusing to run: whether this host is managed cannot be verified;${where}.`, {
      say: "Put MEHEN_HOME (or HOME) under a directory only this user can write, not below a world-writable one such as /tmp; if this host is managed, ask its owner to check the marker.",
    })
  }
}

function retired(message: string, say: string): CliError {
  return new CliError("config_dir_retired", message, { say })
}

function absolute(name: string, value: string): string {
  if (value.includes("\0") || !value.startsWith("/")) throw usageError(`${name} must be an absolute path.`)
  return resolve(value)
}

// <root>/workspaces/<o>/<t>, <root>/pending/<o>/<s> or <root>/contexts/<c>:
// the root above a slot path, or null for a path of another shape.
export function rootAboveSlot(path: string): { root: string; kind: "workspaces" | "pending" | "contexts"; parts: string[] } | null {
  const parts = path.split(sep).filter(Boolean)
  const at = (n: number) => parts[parts.length - n]
  if (parts.length >= 3 && (at(3) === WORKSPACES_DIR || at(3) === PENDING_DIR)) {
    return { root: sep + parts.slice(0, -3).join(sep), kind: at(3) as "workspaces" | "pending", parts: parts.slice(-2) }
  }
  if (parts.length >= 2 && at(2) === "contexts") return { root: sep + parts.slice(0, -2).join(sep), kind: "contexts", parts: parts.slice(-1) }
  return null
}

function holdsEnrolmentRecord(dir: string): boolean {
  try {
    lstatSync(join(dir, ENROLMENT_RECORD_FILE))
    return true
  } catch {
    return false
  }
}

function configDirRetired(path: string): CliError | null {
  const above = rootAboveSlot(path)
  if (above) {
    const entry = above.kind === "workspaces" ? `MEHEN_WORKSPACES=${above.parts[1]}` : above.kind === "pending" ? `MEHEN_WORKSPACES=${above.parts[1]}` : null
    return retired(`MEHEN_CONFIG_DIR ${path} names a ${above.kind === "pending" ? "pending slot" : above.kind === "workspaces" ? "workspace slot" : "legacy context"}, not a config root.`, `Set MEHEN_HOME=${above.root} instead${entry ? ` and ${entry} to keep to that workspace` : ""}; MEHEN_CONFIG_DIR is only an alias of the root now.`)
  }
  if (holdsEnrolmentRecord(path)) return retired(`MEHEN_CONFIG_DIR ${path} holds an enrolment record, so it is a slot, not a config root.`, "Set MEHEN_HOME to the root above it; MEHEN_CONFIG_DIR is only an alias of the root now.")
  return null
}

export type HomeOptions = { files?: VaultFileOptions }

// The root for this process. Throws config_dir_retired, usage,
// workspace_mismatch or key_insecure (the marker) before anything is read.
export function resolveHome(env: Env, options: HomeOptions = {}): HomeResolution {
  const home = env.MEHEN_HOME ? absolute("MEHEN_HOME", env.MEHEN_HOME) : null
  const alias = env.MEHEN_CONFIG_DIR ? absolute("MEHEN_CONFIG_DIR", env.MEHEN_CONFIG_DIR) : null
  const managed = managedHost(options.files ?? {})
  if (!managed && env.MEHEN_MANAGED_CONTEXT) {
    throw new CliError("workspace_mismatch", "The launcher claims a managed context (MEHEN_MANAGED_CONTEXT), but this host has no managed-host marker.", {
      say: "Unset MEHEN_MANAGED_CONTEXT, or ask the owner to provision this host as managed.",
    })
  }
  if (managed && alias) {
    // The pinned slot directory: its root is three levels up in layout 2;
    // a legacy pin's directory is its own (unmigrated) root.
    const above = rootAboveSlot(alias)
    const root = above && above.kind === "workspaces" ? above.root : alias
    if (home !== null && home !== root) throw retired(`MEHEN_HOME ${home} is not the root of the pinned slot ${alias}.`, "On a managed host the launcher's pin decides; unset MEHEN_HOME or set it to the pinned slot's root.")
    return { root, source: "managed" }
  }
  if (alias !== null) {
    if (home !== null && home !== alias) throw retired(`MEHEN_HOME (${home}) and MEHEN_CONFIG_DIR (${alias}) disagree.`, `Set MEHEN_HOME only; unset MEHEN_CONFIG_DIR.`)
    const refusal = configDirRetired(alias)
    if (refusal) throw refusal
    return home !== null ? { root: home, source: "MEHEN_HOME" } : { root: alias, source: "MEHEN_CONFIG_DIR" }
  }
  if (home !== null) return { root: home, source: "MEHEN_HOME" }
  return { root: join(homeDir(env), ".config", "mehen"), source: "default" }
}
