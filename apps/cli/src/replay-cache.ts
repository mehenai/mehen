// The approval replay cache: a request the vault held for a human is saved
// under MEHEN_HOME/pending-requests/<apr_id>.json, so that once the human
// approves it mehen can send the identical request again (mehen fetch
// --resume, mehen wait --execute, vault_fetch with approval alone,
// vault_wait with execute) and the agent never rebuilds it. Each file is
// 0600 in a 0700 folder, holds the request as the agent sent it (references
// and placeholders, never a credential value) and lasts an hour. Nothing
// in it is logged.
//
// The single-use gate is a marker, <apr_id>.spent, created exclusively
// right before the request is sent: whoever creates it sends, and nobody
// else can. The request file never moves, and nothing but the sweep ever
// deletes it. A send that certainly never left this machine removes its own
// marker, so a corrected call can claim the request again; any other
// outcome keeps the approval spent.

import { constants } from "node:fs"
import { lstat, open, opendir, rename, unlink, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { RelayRequest, type RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlDecode, fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { readRegularFile, writeNewFile } from "./backup/files.ts"
import type { Env } from "./config.ts"
import { CliError, usageError } from "./errors.ts"
import { REPLAY_DIR, assertPrivateDirs, ensureSafeRoot, mkdirPrivate, resolveHome } from "./home.ts"
import { RelayOutcomeUnknownError, VaultApiError, VaultNetworkError, retrySafeMethod } from "./vault-api.ts"

export { REPLAY_DIR }

export const REPLAY_TTL_SECONDS = 3600
// The vault's own limit on a body a human approves (an approval card shows
// all of it); a larger one is never held, and never saved.
export const MAX_REPLAY_BODY_BYTES = 64 * 1024
const FILE_MAX_BYTES = 1024 * 1024
const APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/
// A marker holds one short token mehen wrote.
const MARKER_MAX_BYTES = 512
const TOKEN = /^[0-9]+\.[0-9]+\.[a-z0-9]+$/
// The sweep is best effort: about once a minute (by the mtime of .swept;
// two saves at once may both sweep, which is harmless) and at most this
// many entries looked at, read one by one.
export const SWEEP_BUDGET = 256
const SWEEP_EVERY_MS = 60_000
const SWEPT_FILE = ".swept"

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

// What a held answer says about its replay: saved until expiresAt, or why
// not ("spent" when the approval's request was sent again already).
export type ReplayNote = { saved: true; expiresAt: string } | { saved: false; reason: string }

// An exclusive, never-followed create of a marker holding `token`. It
// throws the system error, EEXIST when anything is already at the path.
async function createMarker(path: string, token: string): Promise<void> {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await handle.writeFile(token)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

// The file operations of the cache, so a test can make one fail as a full
// disk or a failing device would.
export const replayFs = { rename, unlink, writeNewFile, createMarker, readRequest: readRegularFile }

export function replayDir(env: Env): string {
  return join(resolveHome(env).root, REPLAY_DIR)
}

export function savedRequestPath(env: Env, approval: string): string {
  return join(replayDir(env), `${approval}.json`)
}

function markerPath(env: Env, approval: string): string {
  return join(replayDir(env), `${approval}.spent`)
}

function rebuild(message: string): CliError {
  return new CliError("replay_missing", message, { say: "Build the request again and send it byte for byte from this machine, with the approval id (mehen fetch --approval, or vault_fetch's approval with the full request)." })
}

function checkedId(approval: string): string {
  if (!APPROVAL_ID.test(approval)) throw usageError(`${JSON.stringify(approval)} is not an approval id (apr_...).`, "mehen fetch --help")
  return approval
}

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error))
const codeOf = (error: unknown) => (error as { code?: string } | null)?.code

function newToken(): string {
  return `${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`
}

// Whether anything at all is at the marker's path: a link, a FIFO or a
// file mehen did not write counts too, so the gate never opens by mistake.
async function marked(env: Env, approval: string): Promise<boolean> {
  return lstat(markerPath(env, approval)).then(
    () => true,
    (error: unknown) => codeOf(error) !== "ENOENT",
  )
}

// The request as it was held, saved for an hour. A spent approval's is
// never saved again: the vault reuses one pending approval for identical
// asks, so a duplicate request can be held after the first was sent.
// Concurrent saves of one approval write the same request; the last rename
// wins. A body over the approval limit is not saved; neither is anything
// when the folder cannot be written: the held answer stays the vault's,
// with the reason beside it.
export async function saveHeldRequest(env: Env, owner: ReplayOwner, approval: string, request: RelayRequestInput, now = new Date()): Promise<ReplayNote> {
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
    await sweep(dir, now).catch(() => undefined)
    if (await marked(env, approval)) return { saved: false, reason: "spent" }
    const path = savedRequestPath(env, approval)
    const temp = `${path}.${newToken()}.tmp`
    await replayFs.writeNewFile(temp, utf8(`${JSON.stringify(saved)}\n`), { mode: 0o600 })
    await replayFs.rename(temp, path)
  } catch (error) {
    return { saved: false, reason: `mehen could not save it (${errorText(error)})` }
  }
  return { saved: true, expiresAt: new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000).toISOString() }
}

// Requests, markers and temp files past their hour go when a request is
// saved, and nothing else ever deletes them. A same-id save after an hour
// does not happen in the normal flow, since the vault's approvals expire
// at an hour too, so removing a marker then reopens nothing. Only this
// user's regular files are removed.
async function sweep(dir: string, now: Date): Promise<void> {
  const swept = join(dir, SWEPT_FILE)
  const last = await lstat(swept).catch(() => null)
  if (last !== null && (!last.isFile() || now.getTime() - last.mtimeMs < SWEEP_EVERY_MS)) return
  if (last === null) await writeFile(swept, "", { mode: 0o600, flag: "wx" }).catch(() => undefined)
  await utimes(swept, now, now).catch(() => undefined)
  const cutoff = now.getTime() - REPLAY_TTL_SECONDS * 1000
  const uid = process.getuid?.() ?? -1
  const entries = await opendir(dir)
  let examined = 0
  try {
    for await (const entry of entries) {
      if (++examined > SWEEP_BUDGET) break
      if (!entry.name.startsWith("apr_")) continue
      const path = join(dir, entry.name)
      const info = await lstat(path).catch(() => null)
      if (info !== null && info.isFile() && info.uid === uid && info.mtimeMs < cutoff) await replayFs.unlink(path).catch(() => undefined)
    }
  } finally {
    await entries.close().catch(() => undefined)
  }
}

// The saved request for an approval, checked: a private regular file this
// user owns, a request mehen saved, within its hour. An expired one is
// replay_missing and left for the sweep. Reading claims nothing.
export async function readSavedRequest(env: Env, approval: string, now = new Date()): Promise<SavedRequest> {
  checkedId(approval)
  const { root } = resolveHome(env)
  const dir = replayDir(env)
  const path = savedRequestPath(env, approval)
  assertPrivateDirs(root, dir)
  const read = await replayFs.readRequest(path, { maxBytes: FILE_MAX_BYTES, ownOnly: true, tooLarge: `Remove ${path}; mehen never saves a request that large.` })
  if (read === null) throw rebuild(`No saved request for ${approval} on this machine: it expired, it was never saved, or it was made elsewhere.`)
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
  if (now.getTime() - Date.parse(saved.data.createdAt) > REPLAY_TTL_SECONDS * 1000) throw rebuild(`The saved request for ${approval} expired: mehen keeps one for an hour.`)
  return saved.data
}

// The saved request is this enrolment's: checked before anything is
// claimed, so a refusal changes nothing on disk.
export function assertSavedBy(saved: SavedRequest, owner: ReplayOwner): void {
  if (saved.vault !== owner.vault || saved.workspace !== owner.workspace || saved.device !== owner.device) {
    throw rebuild(`The saved request for ${saved.approval} was made by another machine or workspace; mehen sends it again only from the one that made it.`)
  }
}

// A claimed request. `spent` keeps the approval spent (the request may have
// reached the vault); `unsent` frees it when the request certainly never
// left this machine, so a corrected call can claim it again.
export type ClaimedRequest = { request: RelayRequestInput; spent(): Promise<void>; unsent(): Promise<void> }

// Removes the marker only while it holds `token`. A marker that cannot be
// read as this token is left as it is.
async function releaseMarker(path: string, token: string): Promise<void> {
  const read = await readRegularFile(path, { maxBytes: MARKER_MAX_BYTES, ownOnly: true }).catch(() => null)
  if (read === null || (read.info.mode & 0o077) !== 0) return
  const text = fromUtf8(new Uint8Array(read.bytes)).trim()
  if (!TOKEN.test(text) || text !== token) return
  await replayFs.unlink(path)
}

// Claims a saved request for sending, right before it is sent: from the
// enrolment that saved it, and once. The marker is created first, then the
// request is read again under it; a read that fails releases the marker.
export async function claimSavedRequest(env: Env, saved: SavedRequest, owner: ReplayOwner, now = new Date()): Promise<ClaimedRequest> {
  assertSavedBy(saved, owner)
  const approval = saved.approval
  const marker = markerPath(env, approval)
  const token = newToken()
  try {
    await replayFs.createMarker(marker, token)
  } catch (error) {
    if (codeOf(error) === "EEXIST") throw rebuild(`The saved request for ${approval} was sent again already, or is being sent.`)
    throw new CliError("failed", `mehen could not mark the request for ${approval} as being sent (${errorText(error)}); nothing was sent, and the saved request is as it was.`, { say: "Fix what the message names (free some space, say), then run the command again." })
  }
  let current: SavedRequest
  try {
    current = await readSavedRequest(env, approval, now)
    assertSavedBy(current, owner)
  } catch (error) {
    try {
      await releaseMarker(marker, token)
    } catch (release) {
      throw new CliError("failed", `mehen could not read the saved request for ${approval} (${errorText(error)}), nor remove its marker ${marker} (${errorText(release)}); nothing was sent.`, {
        say: `Once the saved request can be read, delete ${marker} and run the command again; or build the request again.`,
      })
    }
    if (error instanceof CliError) throw error
    throw new CliError("failed", `mehen could not read the saved request for ${approval} (${errorText(error)}); nothing was sent.`, { say: "Fix what the message names, then run the command again." })
  }
  return {
    request: { ...current.request, approval },
    spent: async () => undefined,
    unsent: async () => {
      try {
        await releaseMarker(marker, token)
      } catch (error) {
        throw new CliError("failed", `The request for ${approval} was not sent, but mehen could not remove its marker ${marker} (${errorText(error)}), so a resume would take it for sent.`, {
          say: `Deleting ${marker} lets the request be sent again; then run the command again.`,
        })
      }
    },
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
