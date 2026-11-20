// The approval replay cache: a request the vault held for a human is saved
// under MEHEN_HOME/pending-requests/<apr_id>.json, so that once the human
// approves it mehen can send the identical request again (mehen fetch
// --resume, mehen wait --execute, vault_fetch with approval alone,
// vault_wait with execute) and the agent never rebuilds it. Each file is
// 0600 in a 0700 folder, holds the request as the agent sent it (references
// and placeholders, never a credential value) and lasts an hour. It is
// claimed right before it is sent, after every local check, and removed
// once it may have reached the vault, so an approval is replayed once.
// Nothing in it is logged.

import { constants } from "node:fs"
import { lstat, open, opendir, rename, unlink, utimes, writeFile } from "node:fs/promises"
import { hostname } from "node:os"
import { dirname, join } from "node:path"
import { RelayRequest, type RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlDecode, fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { readRegularFile, writeNewFile } from "./backup/files.ts"
import type { Env } from "./config.ts"
import { CliError, usageError } from "./errors.ts"
import { REPLAY_DIR, assertPrivateDirs, ensureSafeRoot, mkdirPrivate, resolveHome } from "./home.ts"
import { RelayOutcomeUnknownError, VaultApiError, VaultNetworkError, retrySafeMethod } from "./vault-api.ts"

export { REPLAY_DIR }

// The file operations that move or remove a saved request, a marker or a
// lock, so a test can make one fail as a full disk or a busy file would.
export const replayFs = { rename, unlink, writeNewFile }

export const REPLAY_TTL_SECONDS = 3600
// The vault's own limit on a body a human approves (an approval card shows
// all of it); a larger one is never held, and never saved.
export const MAX_REPLAY_BODY_BYTES = 64 * 1024
const FILE_MAX_BYTES = 1024 * 1024
const APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/

// Who saved a request: it is sent again only from the same enrolment.
export type ReplayOwner = { vault: string; workspace: string; device: string }

const SavedSchema = z.strictObject({
  version: z.literal(1),
  approval: z.string().regex(APPROVAL_ID),
  createdAt: z.iso.datetime(),
  vault: z.string(),
  workspace: z.string(),
  device: z.string(),
  request: RelayRequest.strict(),
})
export type SavedRequest = z.infer<typeof SavedSchema>

// How long a contender waits for an approval's lock before it fails
// closed: holders only rename and write small files. A lock is never
// broken by age, so a crashed holder's lock stays until a person removes it.
const LOCK_WAIT_MS = 2_000
// The sweep runs at most once a minute and looks at most at this many
// entries, so one save never walks a folder of any size.
export const SWEEP_BUDGET = 256
const SWEEP_EVERY_MS = 60_000
const SWEPT_FILE = ".swept"
const SWEEP_LEASE = ".sweep.lock"
// A marker or a lock is a short line; anything larger is not mehen's.
const SMALL_FILE_MAX_BYTES = 512
const TOKEN = /^[0-9]+\.[0-9]+\.[a-z0-9]+$/

// What a held answer says about its replay: saved until expiresAt, or why not.
export type ReplayNote = { saved: true; expiresAt: string } | { saved: false; reason: string }

export function replayDir(env: Env): string {
  return join(resolveHome(env).root, REPLAY_DIR)
}

export function savedRequestPath(env: Env, approval: string): string {
  return join(replayDir(env), `${approval}.json`)
}

// Per approval, beside its saved request: a lock save, claim and restore
// take with an exclusive create, and a marker a claim leaves, naming that
// claim, for the rest of the hour. The vault reuses one pending approval
// for identical asks, so a duplicate request's save can land after the
// first was claimed; with the marker there it saves nothing, and a resume
// finds nothing to send twice.
const lockPath = (env: Env, approval: string) => join(replayDir(env), `${approval}.lock`)
const markerPath = (env: Env, approval: string) => join(replayDir(env), `${approval}.spent`)

const LockSchema = z.strictObject({ token: z.string().min(1).max(128), pid: z.number().int(), host: z.string().max(255) })
type LockOwner = z.infer<typeof LockSchema>

function newToken(): string {
  return `${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`
}

// A marker or lock file, read as any file mehen keeps there: a regular
// file this user owns, nobody else can open, small. Null only when it does
// not exist; anything else refuses.
async function readSmallFile(path: string, approval: string): Promise<string | null> {
  const refuse = (why: string) => new CliError("failed", `Refusing ${path}: ${why}, so mehen cannot tell whether the request for ${approval} was sent.`, { say: `Remove ${path} only if no other mehen is saving or sending that request, then run the command again.` })
  let read: Awaited<ReturnType<typeof readRegularFile>>
  try {
    read = await readRegularFile(path, { maxBytes: SMALL_FILE_MAX_BYTES, ownOnly: true, tooLarge: `Remove ${path}; mehen never writes one that large.` })
  } catch (error) {
    throw refuse(error instanceof CliError ? error.message.replace(/^Refusing [^:]*: /, "").replace(/\.$/, "") : "it cannot be read")
  }
  if (read === null) return null
  if ((read.info.mode & 0o077) !== 0) throw refuse("other users can read or write it")
  return fromUtf8(new Uint8Array(read.bytes)).trim()
}

async function markerOf(env: Env, approval: string): Promise<string | null> {
  const path = markerPath(env, approval)
  const token = await readSmallFile(path, approval)
  if (token !== null && !TOKEN.test(token)) throw new CliError("failed", `Refusing ${path}: it does not hold a claim mehen wrote, so mehen cannot tell whether the request for ${approval} was sent.`, { say: `Remove ${path} only if no other mehen is saving or sending that request, then run the command again.` })
  return token
}

async function lockOwner(path: string, approval: string): Promise<LockOwner | null> {
  const text = await readSmallFile(path, approval)
  if (text === null) return null
  try {
    const parsed = LockSchema.safeParse(JSON.parse(text))
    if (parsed.success) return parsed.data
  } catch {
    // Not JSON: not a lock mehen wrote.
  }
  throw new CliError("failed", `Refusing ${path}: it is not a lock mehen wrote.`, { say: `Remove ${path} only if no other mehen is saving or sending the request for ${approval}, then run the command again.` })
}

function lockedError(path: string, approval: string, holder: LockOwner | null, aside: string | null): CliError {
  const by = holder ? ` (pid ${holder.pid} on ${holder.host})` : ""
  if (aside !== null) {
    const saved = join(dirname(path), `${approval}.json`)
    const marker = join(dirname(path), `${approval}.spent`)
    return new CliError("replay_locked", `The request for ${approval} was not sent, but mehen could not put its saved copy back from ${aside}: ${path} is held${by}.`, {
      say: `Wait for the other mehen to finish; if no other mehen is running, delete ${path}, rename ${aside} to ${saved} and delete ${marker}, then run the command again.`,
    })
  }
  return new CliError("replay_locked", `${path} is held${by}, so another mehen is saving or sending the request for ${approval}; nothing was changed.`, { say: `Wait for the other mehen to finish and run this again; if no other mehen is running, delete ${path} and run it again.` })
}

// A lock at `path`, taken now or not at all: an exclusive create with a
// token written in it. Null when another holds it. The release removes it
// only while it still holds this token.
async function acquireLock(path: string, approval: string): Promise<(() => Promise<void>) | null> {
  const mine: LockOwner = { token: newToken(), pid: process.pid, host: hostname() }
  try {
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    try {
      await handle.writeFile(`${JSON.stringify(mine)}\n`)
      await handle.sync()
    } finally {
      await handle.close()
    }
  } catch (error) {
    if ((error as { code?: string }).code === "EEXIST") return null
    throw error
  }
  return async () => {
    const holder = await lockOwner(path, approval).catch(() => null)
    if (holder?.token === mine.token) await replayFs.unlink(path).catch(() => undefined)
  }
}

// The approval's lock; a contender waits about two seconds, then is
// replay_locked. `aside` is the claimed copy a restore is putting back,
// named in the refusal so it is never lost.
export async function withApprovalLock<T>(env: Env, approval: string, work: () => Promise<T>, aside: string | null = null): Promise<T> {
  const path = lockPath(env, approval)
  const deadline = Date.now() + LOCK_WAIT_MS
  let release = await acquireLock(path, approval)
  while (release === null) {
    if (Date.now() >= deadline) throw lockedError(path, approval, await lockOwner(path, approval).catch(() => null), aside)
    await Bun.sleep(20)
    release = await acquireLock(path, approval)
  }
  try {
    return await work()
  } finally {
    await release()
  }
}

// Test seams: before a save takes the approval's lock; when a sweep's scan
// starts; and after the sweep's first look at an entry it would remove.
export type SaveSeams = { beforeLock?: () => Promise<void>; onSweep?: () => Promise<void>; afterSweepStat?: (path: string) => Promise<void> }

function rebuild(message: string): CliError {
  return new CliError("replay_missing", message, { say: "Build the request again and send it byte for byte from this machine, with the approval id (mehen fetch --approval, or vault_fetch's approval with the full request)." })
}

function checkedId(approval: string): string {
  if (!APPROVAL_ID.test(approval)) throw usageError(`${JSON.stringify(approval)} is not an approval id (apr_...).`, "mehen fetch --help")
  return approval
}

// The request as it was held, saved for an hour. A body over the approval
// limit is not saved; neither is anything when the folder cannot be
// written: the held answer stays the vault's, with the reason beside it.
export async function saveHeldRequest(env: Env, owner: ReplayOwner, approval: string, request: RelayRequestInput, now = new Date(), seams: SaveSeams = {}): Promise<ReplayNote> {
  if (!APPROVAL_ID.test(approval)) return { saved: false, reason: "the vault's approval id is not one mehen can save under" }
  const body = request.body === undefined ? 0 : base64UrlDecode(request.body).length
  if (body > MAX_REPLAY_BODY_BYTES) return { saved: false, reason: `its body is over ${MAX_REPLAY_BODY_BYTES / 1024} KiB` }
  const { approval: _approval, replaces: _replaces, ...held } = request
  const saved: SavedRequest = { version: 1, approval, createdAt: now.toISOString(), ...owner, request: held }
  try {
    const { root } = resolveHome(env)
    ensureSafeRoot(root)
    const dir = replayDir(env)
    mkdirPrivate(root, dir)
    await sweep(env, dir, now, seams).catch(() => undefined)
    await seams.beforeLock?.()
    const sent = await withApprovalLock(env, approval, async () => {
      if ((await markerOf(env, approval)) !== null) return true
      const path = savedRequestPath(env, approval)
      const temp = `${path}.${process.pid}.${Date.now()}.tmp`
      await replayFs.writeNewFile(temp, utf8(`${JSON.stringify(saved)}\n`), { mode: 0o600 })
      await replayFs.rename(temp, path)
      return false
    })
    if (sent) return { saved: false, reason: "this approval's request was already sent again from this machine, or is being sent, so it is not saved again" }
  } catch (error) {
    if (error instanceof CliError && error.code === "replay_locked") return { saved: false, reason: "locked" }
    return { saved: false, reason: `mehen could not save it (${error instanceof Error ? error.message : String(error)})` }
  }
  return { saved: true, expiresAt: new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000).toISOString() }
}

// What is past its hour (saved requests, markers, claimed files set aside,
// temp files) goes when a request is saved: at most once a minute, by the
// mtime of .swept, under a lease only one sweep holds (taken without
// waiting: a save that finds it held skips), and at most SWEEP_BUDGET
// entries looked at, read one by one. Each removal is decided again under
// its approval's lock, taken without waiting, so a file saved again since
// the first look is kept. Only this user's regular files go, never a lock.
async function sweep(env: Env, dir: string, now: Date, seams: SaveSeams): Promise<void> {
  const swept = join(dir, SWEPT_FILE)
  const due = async () => {
    const last = await lstat(swept).catch(() => null)
    return last === null || (last.isFile() && now.getTime() - last.mtimeMs >= SWEEP_EVERY_MS)
  }
  if (!(await due())) return
  const lease = await acquireLock(join(dir, SWEEP_LEASE), "the sweep").catch(() => null)
  if (lease === null) return
  try {
    if (!(await due())) return
    await writeFile(swept, "", { mode: 0o600, flag: "wx" }).catch(() => undefined)
    await utimes(swept, now, now).catch(() => undefined)
    await seams.onSweep?.()
    const cutoff = now.getTime() - REPLAY_TTL_SECONDS * 1000
    const uid = process.getuid?.() ?? -1
    const stale = async (path: string) => {
      const info = await lstat(path).catch(() => null)
      return info !== null && info.isFile() && info.uid === uid && info.mtimeMs < cutoff
    }
    const entries = await opendir(dir)
    let examined = 0
    try {
      for await (const entry of entries) {
        if (++examined > SWEEP_BUDGET) break
        const approval = /^(apr_[A-Za-z0-9_-]{1,60})\./.exec(entry.name)?.[1]
        if (approval === undefined || entry.name.endsWith(".lock")) continue
        const path = join(dir, entry.name)
        if (!(await stale(path))) continue
        await seams.afterSweepStat?.(path)
        const release = await acquireLock(lockPath(env, approval), approval).catch(() => null)
        if (release === null) continue
        try {
          if (await stale(path)) await replayFs.unlink(path).catch(() => undefined)
        } finally {
          await release()
        }
      }
    } finally {
      await entries.close().catch(() => undefined)
    }
  } finally {
    await lease()
  }
}

// The saved request for an approval, checked: a private regular file this
// user owns, a request mehen saved, within its hour. An expired one is
// removed. It is not claimed here.
export async function readSavedRequest(env: Env, approval: string, now = new Date()): Promise<SavedRequest> {
  checkedId(approval)
  const { root } = resolveHome(env)
  const dir = replayDir(env)
  const path = savedRequestPath(env, approval)
  assertPrivateDirs(root, dir)
  const read = await readRegularFile(path, { maxBytes: FILE_MAX_BYTES, ownOnly: true, tooLarge: `Remove ${path}; mehen never saves a request that large.` })
  if (read === null) throw rebuild(`No saved request for ${approval} on this machine: it was sent again already, it expired, or it was made elsewhere.`)
  if ((read.info.mode & 0o077) !== 0) {
    throw new CliError("failed", `Refusing ${path}: other users can read or write it, so the request in it may not be the one this machine saved.`, { say: `Remove ${path} and build the request again.` })
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(fromUtf8(new Uint8Array(read.bytes)))
  } catch {
    parsed = null
  }
  const saved = SavedSchema.safeParse(parsed)
  if (!saved.success || saved.data.approval !== approval) throw rebuild(`${path} is not a request mehen saved for ${approval}.`)
  if (now.getTime() - Date.parse(saved.data.createdAt) > REPLAY_TTL_SECONDS * 1000) {
    await replayFs.unlink(path).catch(() => undefined)
    throw rebuild(`The saved request for ${approval} expired: mehen keeps one for an hour.`)
  }
  return saved.data
}

// The saved request is this enrolment's: checked before anything is
// claimed, so a refusal changes nothing on disk.
export function assertSavedBy(saved: SavedRequest, owner: ReplayOwner): void {
  if (saved.vault !== owner.vault || saved.workspace !== owner.workspace || saved.device !== owner.device) {
    throw rebuild(`The saved request for ${saved.approval} was made by another machine or workspace; mehen sends it again only from the one that made it.`)
  }
}

// A claimed request: its file moved aside and the approval marked, under
// the approval's lock, so no other call can claim or save it. `spent`
// removes the file once the request may have reached the vault, keeping
// the marker for the hour; `unsent` puts it back when it certainly did
// not. Every failure along the way leaves the request at its path, or
// names where it is.
export type ClaimedRequest = { request: RelayRequestInput; spent(): Promise<void>; unsent(): Promise<void> }

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error))

// Claims a saved request for sending, right before it is sent: from the
// enrolment that saved it, and only once. The request comes back with its
// approval.
export async function claimSavedRequest(env: Env, saved: SavedRequest, owner: ReplayOwner): Promise<ClaimedRequest> {
  assertSavedBy(saved, owner)
  const approval = saved.approval
  const path = savedRequestPath(env, approval)
  const marker = markerPath(env, approval)
  const token = newToken()
  const aside = `${path}.claimed.${token}`
  await withApprovalLock(env, approval, async () => {
    if ((await markerOf(env, approval)) !== null) throw rebuild(`The saved request for ${approval} was sent again already, or is being sent.`)
    try {
      await replayFs.rename(path, aside)
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") throw rebuild(`The saved request for ${approval} was sent again already.`)
      throw new CliError("failed", `mehen could not set the saved request for ${approval} aside to send it (${errorText(error)}); nothing was sent, and it is still at ${path}.`, { say: "Fix what the message names, then run the command again." })
    }
    try {
      await replayFs.writeNewFile(marker, utf8(token), { mode: 0o600 })
    } catch (error) {
      try {
        await replayFs.rename(aside, path)
      } catch (back) {
        throw new CliError("failed", `mehen could not mark the request for ${approval} as being sent (${errorText(error)}), nor put it back (${errorText(back)}); nothing was sent, and the saved request is at ${aside}.`, {
          say: `Rename ${aside} to ${path}, then run the command again.`,
        })
      }
      throw new CliError("failed", `mehen could not mark the request for ${approval} as being sent (${errorText(error)}); nothing was sent, and the saved request is back at ${path}.`, { say: "Fix what the message names (free some space, say), then run the command again." })
    }
  })
  return {
    request: { ...saved.request, approval },
    spent: () => replayFs.unlink(aside).then(() => undefined, () => undefined),
    unsent: () =>
      withApprovalLock(
        env,
        approval,
        async () => {
          let mine: boolean
          let newer: boolean
          try {
            mine = (await markerOf(env, approval)) === token
            newer = await lstat(path).then(() => true, (error: unknown) => (error as { code?: string }).code !== "ENOENT")
          } catch (error) {
            throw new CliError("failed", `The request for ${approval} was not sent, but mehen could not check whether to put its saved copy back (${errorText(error)}); it is at ${aside}.`, { say: `Rename ${aside} to ${path} and delete ${marker} once the message's problem is fixed, then run the command again.` })
          }
          // Proven stale: another claim owns the approval, or a newer copy is saved.
          if (!mine || newer) {
            await replayFs.unlink(aside).catch(() => undefined)
            return
          }
          try {
            await replayFs.rename(aside, path)
          } catch (error) {
            // Swept as past its hour while it was being sent: expired either way.
            if ((error as { code?: string }).code === "ENOENT") throw rebuild(`The request for ${approval} was not sent, and its saved copy expired meanwhile: mehen keeps one for an hour.`)
            throw new CliError("failed", `The request for ${approval} was not sent, but mehen could not put its saved copy back (${errorText(error)}); it is at ${aside}.`, { say: `Rename ${aside} to ${path} and delete ${marker}, then run the command again.` })
          }
          try {
            await replayFs.unlink(marker)
          } catch (error) {
            throw new CliError("failed", `The request for ${approval} was not sent and is back at ${path}, but mehen could not remove ${marker} (${errorText(error)}), so a resume would take it for sent.`, { say: `Delete ${marker}, then run the command again.` })
          }
        },
        aside,
      ),
  }
}

// Whether a failed send certainly never reached the vault: anything thrown
// before the connection (signing, say), or, for a write, a connection that
// was refused (HttpVaultApi reports any other failure of a write as
// RelayOutcomeUnknownError). A read's network error may have come after it
// was sent, and a cancelled call may have gone too.
export function neverSent(error: unknown, request: Pick<RelayRequestInput, "method">, signal: AbortSignal): boolean {
  if (signal.aborted || error instanceof VaultApiError || error instanceof RelayOutcomeUnknownError) return false
  if (error instanceof VaultNetworkError) return !retrySafeMethod(request.method)
  return true
}
