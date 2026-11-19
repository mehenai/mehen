// The file rules every `mehen backup` command keeps. Reads look with lstat
// first, refuse links and anything but a regular file, open with
// O_NOFOLLOW and check the opened file is the one examined, and stop at a
// size cap. Writes create a new file with O_EXCL and O_NOFOLLOW, so an
// existing file or a planted link is never written through. Every refusal
// names the path, never anything read from it.

import { constants, lstatSync, readFileSync, realpathSync } from "node:fs"
import { lstat, open, unlink } from "node:fs/promises"
import { userInfo } from "node:os"
import { basename, dirname, join, resolve, sep } from "node:path"
import type { Stats } from "node:fs"
import { CliError } from "../errors.ts"

export function backupFailure(message: string, say: string, command?: string): CliError {
  return new CliError("failed", message, { say, ...(command ? { command } : {}) })
}

export type ReadFile = { bytes: Uint8Array; info: Stats }

export type ReadRules = {
  maxBytes: number
  // Refuse a file another user owns (sources); archives and sidecars copied
  // between machines may carry another owner.
  ownOnly: boolean
  // What to do about a file over maxBytes; by default, take it out of the plan.
  tooLarge?: string
}

function code(error: unknown): string | undefined {
  return (error as { code?: string }).code
}

// null when nothing is at the path.
export async function readRegularFile(path: string, rules: ReadRules): Promise<ReadFile | null> {
  let info: Stats
  try {
    info = await lstat(path)
  } catch (error) {
    if (code(error) === "ENOENT") return null
    throw backupFailure(`Cannot examine ${path} (${code(error) ?? "error"}).`, `Check that ${path} is readable by this user, then run the command again.`)
  }
  if (info.isSymbolicLink()) throw backupFailure(`Refusing ${path}: it is a symbolic link.`, `Name the file the link points to instead of ${path}.`)
  if (!info.isFile()) throw backupFailure(`Refusing ${path}: it is not a regular file.`, `Name a regular file instead of ${path}.`)
  if (rules.ownOnly && info.uid !== userInfo().uid) throw backupFailure(`Refusing ${path}: it is owned by another user (uid ${info.uid}).`, `Only this user's own files are read; take ${path} out of the plan or run as its owner.`)
  if (info.size > rules.maxBytes) throw backupFailure(`Refusing ${path}: it is larger than ${rules.maxBytes} bytes.`, rules.tooLarge ?? `Take ${path} out of the plan; mehen reads files up to ${rules.maxBytes} bytes.`)
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch((error: unknown) => {
    throw backupFailure(`Cannot open ${path} (${code(error) ?? "error"}).`, `Check that ${path} is readable by this user, then run the command again.`)
  })
  try {
    const opened = await handle.stat()
    if (opened.dev !== info.dev || opened.ino !== info.ino) throw backupFailure(`Refusing ${path}: it changed while it was opened.`, "Run the command again once nothing is changing the file.")
    const bytes = new Uint8Array(await handle.readFile())
    if (bytes.length > rules.maxBytes) throw backupFailure(`Refusing ${path}: it grew past ${rules.maxBytes} bytes while it was read.`, "Run the command again once nothing is changing the file.")
    return { bytes, info: opened }
  } finally {
    await handle.close()
  }
}

export type NewFileAttributes = { mode?: number; mtimeMs?: number; owner?: { uid: number; gid: number } }

// A new file at `path`, flushed to disk. Never replaces anything: an
// existing file or link refuses. Owner, mode and mtime are set on the open
// file, never by path, so a link swapped in after it is created is never
// followed: the owner first (a chown may clear setuid and setgid), the mode
// (default 0600, whatever the umask) after the bytes, the mtime last. A
// write that fails part way removes the file, so no partial copy is left,
// but only while the path is still the file it created: one another
// program renamed over it meanwhile is left as it is.
export async function writeNewFile(path: string, bytes: Uint8Array, attributes: NewFileAttributes = {}): Promise<void> {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600).catch((error: unknown) => {
    if (code(error) === "EEXIST") throw backupFailure(`Refusing to write ${path}: something is already there.`, `Move ${path} aside or choose another path; mehen never overwrites it.`)
    throw backupFailure(`Cannot create ${path} (${code(error) ?? "error"}).`, `Check that ${dirname(path)} exists and this user can write it.`)
  })
  let made: Stats | null = null
  try {
    made = await handle.stat()
    if (attributes.owner) await handle.chown(attributes.owner.uid, attributes.owner.gid)
    await handle.writeFile(bytes)
    await handle.chmod(attributes.mode ?? 0o600)
    if (attributes.mtimeMs !== undefined) await handle.utimes(attributes.mtimeMs / 1000, attributes.mtimeMs / 1000)
    await handle.sync()
  } catch (error) {
    await handle.close().catch(() => undefined)
    const why = code(error) ?? "error"
    const at = await lstat(path).catch(() => null)
    if (at !== null && (made === null || at.dev !== made.dev || at.ino !== made.ino)) throw backupFailure(`Cannot write ${path} (${why}); something else is at ${path} now, left as it is.`, `Check what is at ${path} and the space and permissions there, then run the command again.`)
    if (at !== null) await unlink(path).catch(() => undefined)
    throw backupFailure(`Cannot write ${path} (${why}); nothing was left there.`, `Check the space and permissions where ${path} goes, then run the command again.`)
  }
  await handle.close()
}

// The real path `path` would have: the realpath of its deepest existing
// ancestor, with the missing components after it.
export function realTarget(path: string): string {
  const absolute = resolve(path)
  const missing: string[] = []
  let current = absolute
  for (;;) {
    try {
      return join(realpathSync(current), ...missing.reverse())
    } catch (error) {
      if (code(error) !== "ENOENT" && code(error) !== "ENOTDIR") throw backupFailure(`Cannot resolve ${absolute} (${code(error) ?? "error"}).`, `Check that ${absolute} is a path this user can reach.`)
      const parent = dirname(current)
      if (parent === current) return absolute
      missing.push(basename(current))
      current = parent
    }
  }
}

export function insideDir(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir.endsWith(sep) ? dir : dir + sep)
}

// The git work tree holding `path` (a directory with `.git` at or above
// it), or null. Only what exists is examined, without running git.
export function gitWorkTreeAbove(path: string): string | null {
  let current = realTarget(path)
  for (;;) {
    let found = false
    try {
      found = lstatSync(join(current, ".git"), { throwIfNoEntry: false }) !== undefined
    } catch {
      found = false
    }
    if (found) return current
    const parent = dirname(current)
    if (parent === current) return null
    current = parent
  }
}

const groups = new Map<number, string | null>()

// The group's name from /etc/group, or null when it is not listed there
// (a directory-service group on macOS, say).
export function groupName(gid: number): string | null {
  if (!groups.has(gid)) {
    let found: string | null = null
    try {
      for (const line of readFileSync("/etc/group", "utf8").split("\n")) {
        const [name, , id] = line.split(":")
        if (name && !name.startsWith("#") && Number(id) === gid) {
          found = name
          break
        }
      }
    } catch {
      found = null
    }
    groups.set(gid, found)
  }
  return groups.get(gid) ?? null
}

// A standard-base64 string `base64 -d` reads.
export function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64")
}

export function fromBase64(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64"))
}
