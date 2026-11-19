// The transparent handover, for a server whose
// handover is on (mcpHandoverDecision: on by default with automatic
// updates on, off with `"mcpHandover": false`).
//
// With a verified replacement on disk the old image waits for a quiet
// point (one read owner, no outstanding read, no partial line, no call in
// flight, every stdout write handed to the kernel), has the new image
// accept the resume payload (`<new> mcp --accept-resume`, payload on
// stdin), re-reads the executable's identity, then execve's it: same pid,
// same pipes, and every unread byte still in the kernel. The new image
// takes the latch table over (a changed slot becomes a tombstone, a
// refused one stays refused) and reads the pipe where the old one stopped.

import { closeSync, fstatSync, openSync, read, readSync, realpathSync, statSync } from "node:fs"
import { z } from "zod"
import type { SignedManifest } from "@mehen/protocol/release-manifest"
import type { Env } from "../config.ts"
import { toCliError } from "../errors.ts"
import { mcpHandoverNow } from "../install-state.ts"
import { enterRootMigrates } from "../migration.ts"
import { sha256 } from "../release-client.ts"
import { VERSION } from "../version.ts"
import { latchState, restoreLatchState, startServer } from "./binding.ts"
import type { McpLatchState, McpServer } from "./shared.ts"
import type { PrivateExecutables, VerifiedReplacement } from "./self-watch.ts"

// `apps`: the host negotiated MCP Apps; absent in a payload from before the cards.
export type McpResumePayload = { v: 1; protocolVersion: string; clientInfo: { name: string; version: string }; apps?: boolean; initialized: true; startedAt: string; toolsHash: string; latch: McpLatchState; manifest: SignedManifest }

export const RESUME_ENV = "MEHEN_MCP_RESUME"
export const RESUME_MAX_BYTES = 64 * 1024
export const RESUME_MAX_SLOTS = 64
const RESUME_MAX_STRING = 1024
// At most this long per attempt for the quiet point.
export const BARRIER_MS = 5_000
const ACCEPT_TIMEOUT_MS = 10_000
// How much of the acceptance check's stderr the old image reads for its reason.
export const ACCEPT_STDERR_MAX_BYTES = 2048

const text = z.string().max(RESUME_MAX_STRING)
const LatchedSchema = z.strictObject({ vault: text, tenant: text, device: text })
const ResumeSchema = z.strictObject({
  v: z.literal(1),
  protocolVersion: text,
  clientInfo: z.object({ name: text, version: text }),
  apps: z.boolean().optional(),
  initialized: z.literal(true),
  startedAt: text,
  toolsHash: text,
  latch: z.strictObject({
    v: z.literal(1),
    home: text,
    allowed: z.array(z.strictObject({ entry: text, origin: text.nullable(), workspace: text.nullable() })).max(RESUME_MAX_SLOTS).nullable(),
    pin: z.strictObject({ text, vault: text, tenant: text }).nullable(),
    manifest: z.strictObject({ path: text, workspace: text.nullable(), vault: text.nullable() }).nullable(),
    slots: z.record(text, z.union([z.strictObject({ latched: LatchedSchema }), z.strictObject({ refused: z.strictObject({ reason: text, since: text }) })])).refine((slots) => Object.keys(slots).length <= RESUME_MAX_SLOTS, "too many slots"),
    // Checked field by field by restoreLatchState.
    seen: z.record(text, z.strictObject({ dir: text, config: z.record(text, z.unknown()) })).refine((seen) => Object.keys(seen).length <= RESUME_MAX_SLOTS, "too many slots").optional(),
  }),
  manifest: z.looseObject({ version: text, files: z.array(z.unknown()), signatures: z.array(z.unknown()) }),
})

// The payload as one line, or a refusal when it is over its bounds.
export function encodeResume(payload: McpResumePayload): string {
  const line = JSON.stringify(payload)
  if (new TextEncoder().encode(line).length > RESUME_MAX_BYTES) throw new Error(`the resume payload is over ${RESUME_MAX_BYTES} bytes`)
  if (Object.keys(payload.latch.slots).length > RESUME_MAX_SLOTS) throw new Error(`the resume payload has over ${RESUME_MAX_SLOTS} slots`)
  return line
}

export function parseResume(line: string): McpResumePayload {
  if (new TextEncoder().encode(line).length > RESUME_MAX_BYTES) throw new Error(`the resume payload is over ${RESUME_MAX_BYTES} bytes`)
  let value: unknown
  try {
    value = JSON.parse(line)
  } catch {
    throw new Error("the resume payload is not JSON")
  }
  const parsed = ResumeSchema.safeParse(value)
  if (!parsed.success) throw new Error("the resume payload is not one this build accepts")
  return parsed.data as McpResumePayload
}

// The acceptance check's stdin, read to at most RESUME_MAX_BYTES + 1
// bytes: enough for parseResume to refuse a payload over its bound
// without reading the rest.
export async function readResumeLine(stdin: ReadableStream<Uint8Array>): Promise<string> {
  const kept = new Uint8Array(RESUME_MAX_BYTES + 1)
  let size = 0
  const reader = stdin.getReader()
  try {
    while (size < kept.length) {
      const { done, value } = await reader.read()
      if (done) break
      const take = Math.min(value.length, kept.length - size)
      kept.set(value.subarray(0, take), size)
      size += take
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
  return new TextDecoder().decode(kept.subarray(0, size))
}

// The payload from the environment, removed from it before anything is
// spawned: from process.env and from the env this server uses.
export function takeResume(env: Env): { env: Env; payload: string | null } {
  const payload = env[RESUME_ENV] ?? process.env[RESUME_ENV] ?? null
  delete process.env[RESUME_ENV]
  const { [RESUME_ENV]: _taken, ...rest } = env
  return { env: rest, payload }
}

// Takes a previous image's latch table over: the payload's root and
// resolved admitted set must be this server's own, every latched slot is
// checked against the disk now, every refused slot stays refused.
export async function resumeInto(server: McpServer, line: string): Promise<McpResumePayload> {
  const payload = parseResume(line)
  await restoreLatchState(server, payload.latch)
  return payload
}

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error))

// Why this image would not take the payload over, or null when it would.
// An image whose own handover is off refuses, so turning the setting off
// stops the next switch; the install directory is the old image's to
// judge, since this runs from a private copy. A reason names no path and
// carries nothing of the payload: the old image logs it.
export async function acceptanceRefusal(env: Env, cwd: string, line: string): Promise<string | null> {
  const own = await mcpHandoverNow(env, { installDir: false })
  if (own.handover === "off") return `the new image does not take handovers: ${own.reason}`
  let payload: McpResumePayload
  try {
    payload = parseResume(line.trim())
  } catch (error) {
    return messageOf(error)
  }
  // The payload names the release the old image verified: this one.
  if (payload.manifest.version !== VERSION) return `the payload was built for another release than this image, ${VERSION}`
  let server: McpServer
  try {
    if (await enterRootMigrates(env)) return "this image would migrate the root before serving"
    server = await startServer(env, cwd)
  } catch (error) {
    return `the new image would not start a server here (${toCliError(error).code})`
  }
  try {
    await restoreLatchState(server, payload.latch)
  } catch (error) {
    return messageOf(error)
  }
  return null
}

// `mehen mcp --accept-resume`: exit 0 when this image would take the
// payload on stdin over, 1 with the reason on stderr when it would not.
export async function acceptResume(env: Env, cwd: string, line: string): Promise<number> {
  const reason = await acceptanceRefusal(env, cwd, line).catch(() => "the new image could not check the payload")
  if (reason === null) return 0
  process.stderr.write(`${JSON.stringify({ msg: "mcp resume refused", reason })}\n`)
  return 1
}

// The reason the acceptance check gave: its `reason` field alone, from at
// most ACCEPT_STDERR_MAX_BYTES of its stderr; the rest is read and dropped,
// so the check never blocks on a full pipe.
async function refusalReason(stderr: ReadableStream<Uint8Array>): Promise<string | null> {
  const kept = new Uint8Array(ACCEPT_STDERR_MAX_BYTES)
  let size = 0
  const reader = stderr.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    const take = Math.min(value.length, kept.length - size)
    kept.set(value.subarray(0, take), size)
    size += take
  }
  for (const text of new TextDecoder().decode(kept.subarray(0, size)).split("\n")) {
    try {
      const value = JSON.parse(text) as { msg?: unknown; reason?: unknown }
      if (value.msg === "mcp resume refused" && typeof value.reason === "string") return value.reason
    } catch {
      // Not the check's line.
    }
  }
  return null
}

// One read owner for fd 0: one `fs.read` at a time into a byte buffer split
// at 0x0A, each line decoded on its own, so "the buffer is empty" means no
// byte of the host's is held in this process.
export class StdinLines {
  private buffer = new Uint8Array(0)
  private readonly chunk = new Uint8Array(64 * 1024)
  private ended = false

  constructor(private readonly fd = 0) {}

  // True when a partial line is held.
  partial(): boolean {
    return this.buffer.length > 0
  }

  // The next complete lines, or null at end of input (the last partial
  // line, if any, is returned first).
  async next(): Promise<string[] | null> {
    if (this.ended) return null
    const n = await this.readOnce()
    if (n === 0) {
      this.ended = true
      const last = this.buffer
      this.buffer = new Uint8Array(0)
      return last.length ? [new TextDecoder().decode(last)] : []
    }
    const joined = new Uint8Array(this.buffer.length + n)
    joined.set(this.buffer)
    joined.set(this.chunk.subarray(0, n), this.buffer.length)
    const lines: string[] = []
    let start = 0
    for (let i = 0; i < joined.length; i++) {
      if (joined[i] !== 0x0a) continue
      lines.push(new TextDecoder().decode(joined.subarray(start, i)))
      start = i + 1
    }
    this.buffer = joined.slice(start)
    return lines
  }

  // One read; a non-blocking descriptor with nothing to read waits briefly
  // and reads again, so there is still only ever one read.
  private async readOnce(): Promise<number> {
    for (;;) {
      try {
        return await new Promise<number>((resolve, reject) => read(this.fd, this.chunk, 0, this.chunk.length, null, (error, bytes) => (error ? reject(error) : resolve(bytes))))
      } catch (error) {
        if ((error as { code?: string }).code !== "EAGAIN") throw error
        await Bun.sleep(10)
      }
    }
  }
}

// Waits up to `ms` for `ready`; false when it did not hold in time.
export async function quietWithin(ready: () => boolean, ms = BARRIER_MS): Promise<boolean> {
  const deadline = Date.now() + ms
  while (!ready()) {
    if (Date.now() >= deadline) return false
    await Bun.sleep(10)
  }
  return true
}

export type HandoverContext = {
  env: Env
  server: McpServer
  replacement: VerifiedReplacement
  binary: string
  // Where the acceptance check's private copy is made (the self-watch's own).
  executables: PrivateExecutables
  args: string[]
  handshake: { protocolVersion: string; clientInfo: { name: string; version: string }; apps?: boolean }
  startedAt: string
  toolsHash: string
}

export type PreparedExec = { file: string; argv: string[]; env: Record<string, string> }

function plainEnv(env: Env): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(env)) if (value !== undefined && key !== RESUME_ENV) out[key] = value
  return out
}

const CHANGED = "the executable changed after it was verified"

// The bytes at `binary`, when they are the verified ones, read and hashed
// through one descriptor: the path resolves to itself, the descriptor's
// file is the one the self-watch verified (device, inode and mtime, since
// a freed inode number is soon reused on Linux), its bytes
// hash to the record and, as the last step, the path still names that
// file with its size and mtime unchanged (a write in place keeps the
// inode). Throws when anything changed since the verification (a second
// update, a rollback). `hashed` is a test seam between the hash and that
// last look.
function verifiedBytes(binary: string, replacement: VerifiedReplacement, hashed?: () => void): Uint8Array {
  let fd: number
  try {
    if (realpathSync(binary) !== binary) throw new Error(CHANGED)
    fd = openSync(binary, "r")
  } catch {
    throw new Error(CHANGED)
  }
  try {
    const held = fstatSync(fd)
    const { record, identity } = replacement
    if (!held.isFile() || held.size !== record.size || held.dev !== identity.dev || held.ino !== identity.ino || held.mtimeMs !== identity.mtimeMs) throw new Error(CHANGED)
    const bytes = new Uint8Array(held.size)
    let at = 0
    while (at < bytes.length) {
      const n = readSync(fd, bytes, at, bytes.length - at, at)
      if (n === 0) break
      at += n
    }
    if (at !== bytes.length || sha256(bytes) !== record.sha256) throw new Error(CHANGED)
    hashed?.()
    const named = statSync(binary, { throwIfNoEntry: false })
    if (named === undefined || named.dev !== held.dev || named.ino !== held.ino || named.size !== held.size || named.mtimeMs !== held.mtimeMs) throw new Error(CHANGED)
    return bytes
  } finally {
    closeSync(fd)
  }
}

// The last look before execve: synchronous, and the caller runs nothing
// but execve after it. execve resolves the path again, so a rename landing
// between the last stat and that lookup would still run another file:
// that window cannot be closed while execve takes a path.
export function assertStillVerified(binary: string, replacement: VerifiedReplacement, hashed?: () => void): void {
  verifiedBytes(binary, replacement, hashed)
}

// Builds the payload and has the new image accept it. The image is read
// once and checked against the verified record (realpath, identity, size,
// hash) before anything runs, and the acceptance runs only a private copy of
// those bytes, never the path. Throws with the reason when
// there is no switch; the caller still runs assertStillVerified just
// before the exec.
export async function prepareHandover(context: HandoverContext): Promise<PreparedExec> {
  const { replacement, binary } = context
  const manifest = replacement.record.manifest
  if (manifest === null) throw new Error("the replacement has no signed manifest")
  const payload: McpResumePayload = { v: 1, protocolVersion: context.handshake.protocolVersion, clientInfo: context.handshake.clientInfo, ...(context.handshake.apps ? { apps: true } : {}), initialized: true, startedAt: context.startedAt, toolsHash: context.toolsHash, latch: latchState(context.server), manifest }
  const line = encodeResume(payload)
  const childEnv = plainEnv(context.env)
  const copy = await context.executables.create(verifiedBytes(binary, replacement))
  let accepted: number
  let reason: string | null
  try {
    const proc = Bun.spawn([copy, "mcp", "--accept-resume"], { env: childEnv, stdin: new TextEncoder().encode(`${line}\n`), stdout: "ignore", stderr: "pipe", timeout: ACCEPT_TIMEOUT_MS })
    ;[accepted, reason] = await Promise.all([proc.exited, refusalReason(proc.stderr)])
  } finally {
    await context.executables.remove(copy)
  }
  if (accepted !== 0) throw new Error(`the new image refused the resume payload (exit ${accepted})${reason === null ? "" : `: ${reason}`}`)
  return { file: binary, argv: [binary, "mcp", ...context.args], env: { ...childEnv, [RESUME_ENV]: line } }
}
