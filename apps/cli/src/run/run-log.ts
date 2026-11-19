// The local run log, <MEHEN_HOME root>/runs.jsonl: one line per finished
// `mehen run`, so `mehen adopt retire` can tell that a program has been
// getting its values from Mehen. A line says when the run started and
// ended, how it exited, the folder of the mehen.toml it used, its project,
// its environment and whether it was a service run. Never the command
// line, a value or any other name. A run its parent stopped with SIGINT or
// SIGTERM records the signal, as passed on.
//
// The file is 0600 in the private root. It is opened with O_NOFOLLOW, so a
// link planted at its path is refused, never written through. Over 1 MiB,
// it keeps its newest half.

import { constants } from "node:fs"
import { open, rename, rm } from "node:fs/promises"
import { constants as osConstants } from "node:os"
import { join } from "node:path"
import { randomId } from "@mehen/protocol/bytes"
import { z } from "zod"

export const RUN_LOG_FILE = "runs.jsonl"
export const RUN_LOG_MAX_BYTES = 1024 * 1024

export const RunLogEntrySchema = z.strictObject({
  at: z.iso.datetime(),
  endedAt: z.iso.datetime(),
  // The child's exit code or the signal that ended it; mehen run's own
  // code when the child never started.
  exit: z.union([z.number().int(), z.string().regex(/^SIG[A-Z0-9]{1,16}$/)]),
  // The folder holding the mehen.toml the run used.
  root: z.string().min(1).max(4096),
  project: z.string().min(1).max(128),
  env: z.string().min(1).max(64),
  service: z.boolean(),
  // A SIGINT or SIGTERM mehen run received from outside while the child
  // ran, from its parent, a service manager or the terminal, and passed on.
  signal: z.enum(["SIGINT", "SIGTERM"]).optional(),
  forwarded: z.literal(true).optional(),
})
export type RunLogEntry = z.infer<typeof RunLogEntrySchema>

// A run counts as clean when its child exited 0, or ended on a SIGINT or
// SIGTERM passed on from outside, by that signal or the 128 plus its number
// a shell exits with: a dev server stopped with Ctrl-C, a service its
// manager stopped. A crash, or any other exit, does not.
export function cleanRun(entry: RunLogEntry): boolean {
  if (entry.exit === 0) return true
  if (entry.forwarded !== true || entry.signal === undefined) return false
  return entry.exit === entry.signal || entry.exit === 128 + osConstants.signals[entry.signal]
}

export function runLogPath(root: string): string {
  return join(root, RUN_LOG_FILE)
}

function notRegular(path: string): Error {
  return new Error(`${path} is not a regular file`)
}

export async function appendRunLog(path: string, entry: RunLogEntry): Promise<void> {
  const line = `${JSON.stringify(RunLogEntrySchema.parse(entry))}\n`
  const handle = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
  let size: number
  try {
    const info = await handle.stat()
    if (!info.isFile()) throw notRegular(path)
    if ((info.mode & 0o077) !== 0) await handle.chmod(0o600)
    await handle.write(line)
    size = (await handle.stat()).size
  } finally {
    await handle.close()
  }
  if (size > RUN_LOG_MAX_BYTES) await keepNewestHalf(path)
}

async function readLog(path: string): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    if (!(await handle.stat()).isFile()) throw notRegular(path)
    return await handle.readFile()
  } finally {
    await handle.close()
  }
}

// The newest half of the file, from the first whole line in it, written to
// a fresh file beside it and renamed over it.
async function keepNewestHalf(path: string): Promise<void> {
  const bytes = await readLog(path)
  const tail = bytes.subarray(bytes.length - RUN_LOG_MAX_BYTES / 2)
  const kept = tail.subarray(tail.indexOf(0x0a) + 1)
  const temp = `${path}.${randomId("tmp", 6)}`
  const handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await handle.writeFile(kept)
    await handle.sync()
  } finally {
    await handle.close()
  }
  try {
    await rename(temp, path)
  } catch (error) {
    await rm(temp, { force: true })
    throw error
  }
}

// Every line that reads as an entry; none when there is no log yet.
export async function readRunLog(path: string): Promise<RunLogEntry[]> {
  let bytes: Buffer
  try {
    bytes = await readLog(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return []
    throw error
  }
  const entries: RunLogEntry[] = []
  for (const line of bytes.toString("utf8").split("\n")) {
    if (line === "") continue
    let raw: unknown
    try {
      raw = JSON.parse(line)
    } catch {
      continue
    }
    const parsed = RunLogEntrySchema.safeParse(raw)
    if (parsed.success) entries.push(parsed.data)
  }
  return entries
}
