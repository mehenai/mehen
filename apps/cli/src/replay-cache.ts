// The approval replay cache: a request the vault held for a human is saved
// under MEHEN_HOME/pending-requests/<apr_id>.json, so that once the human
// approves it mehen can send the identical request again (mehen fetch
// --resume, mehen wait --execute, vault_fetch with approval alone,
// vault_wait with execute) and the agent never rebuilds it. Each file is
// 0600 in a 0700 folder, holds the request as the agent sent it (references
// and placeholders, never a credential value) and lasts an hour; a claim
// removes it, so an approval is replayed once. Nothing in it is logged.

import { readdir, rename, unlink } from "node:fs/promises"
import { join } from "node:path"
import { RelayRequest, type RelayRequestInput } from "@mehen/protocol/api"
import { base64UrlDecode, fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { readRegularFile, writeNewFile } from "./backup/files.ts"
import type { Env } from "./config.ts"
import { CliError, usageError } from "./errors.ts"
import { REPLAY_DIR, assertPrivateDirs, ensureSafeRoot, mkdirPrivate, resolveHome } from "./home.ts"

export { REPLAY_DIR }

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

// What a held answer says about its replay: saved until expiresAt, or why not.
export type ReplayNote = { saved: true; expiresAt: string } | { saved: false; reason: string }

export function replayDir(env: Env): string {
  return join(resolveHome(env).root, REPLAY_DIR)
}

export function savedRequestPath(env: Env, approval: string): string {
  return join(replayDir(env), `${approval}.json`)
}

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
    await sweep(dir, now)
    const path = savedRequestPath(env, approval)
    const temp = `${path}.${process.pid}.${now.getTime()}.tmp`
    await writeNewFile(temp, utf8(`${JSON.stringify(saved)}\n`), { mode: 0o600 })
    await rename(temp, path)
  } catch (error) {
    return { saved: false, reason: `mehen could not save it (${error instanceof Error ? error.message : String(error)})` }
  }
  return { saved: true, expiresAt: new Date(now.getTime() + REPLAY_TTL_SECONDS * 1000).toISOString() }
}

// Entries past their hour, and temp files left by a save that stopped,
// go whenever a request is saved. A file that cannot be examined stays.
async function sweep(dir: string, now: Date): Promise<void> {
  const cutoff = now.getTime() - REPLAY_TTL_SECONDS * 1000
  for (const name of await readdir(dir).catch(() => [])) {
    if (!name.startsWith("apr_")) continue
    const path = join(dir, name)
    const read = await readRegularFile(path, { maxBytes: FILE_MAX_BYTES, ownOnly: true }).catch(() => null)
    if (read !== null && read.info.mtimeMs < cutoff) await unlink(path).catch(() => undefined)
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
    await unlink(path).catch(() => undefined)
    throw rebuild(`The saved request for ${approval} expired: mehen keeps one for an hour.`)
  }
  return saved.data
}

// Claims a saved request for sending: from the enrolment that saved it,
// and only once, since the claim removes the file before anything is sent.
// The request comes back with its approval.
export async function claimSavedRequest(env: Env, saved: SavedRequest, owner: ReplayOwner): Promise<RelayRequestInput> {
  if (saved.vault !== owner.vault || saved.workspace !== owner.workspace || saved.device !== owner.device) {
    throw rebuild(`The saved request for ${saved.approval} was made by another machine or workspace; mehen sends it again only from the one that made it.`)
  }
  try {
    await unlink(savedRequestPath(env, saved.approval))
  } catch {
    throw rebuild(`The saved request for ${saved.approval} was sent again already.`)
  }
  return { ...saved.request, approval: saved.approval }
}
