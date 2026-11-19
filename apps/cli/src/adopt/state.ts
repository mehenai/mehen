// The files adopt keeps on this machine, under <root>/adopt/<host>/: the
// scan, the plan and the local state (the batch, the projects submit
// created, and verify's results). None holds a value: every write goes
// through the output guard, and each file is 0600 in a 0700 folder.

import { constants } from "node:fs"
import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises"
import { hostname } from "node:os"
import { dirname, join } from "node:path"
import type { AdoptionStatus } from "@mehen/protocol/adopt"
import { z } from "zod"
import type { Env } from "../config.ts"
import { CliError } from "../errors.ts"
import { resolveHome } from "../home.ts"
import type { OutputGuard } from "./output-guard.ts"

export function machineName(): string {
  return (hostname().split(".")[0] ?? "machine").slice(0, 64) || "machine"
}

export function adoptDir(env: Env): string {
  return join(resolveHome(env).root, "adopt", machineName())
}

export const SCAN_FILE = "scan.json"
export const PLAN_FILE = "plan.json"
export const STATE_FILE = "state.json"

const MAX_STATE_BYTES = 16 * 1024 * 1024

// Written to a fresh file beside the target, then renamed over it, so a
// symlink planted at the path is replaced, never followed.
export async function writePrivateFile(path: string, text: string, guard: OutputGuard): Promise<void> {
  guard.assertClean(text)
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`
  const handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await handle.writeFile(text)
  } finally {
    await handle.close()
  }
  try {
    await chmod(temp, 0o600)
    await rename(temp, path)
  } catch (error) {
    await rm(temp, { force: true })
    throw error
  }
}

export async function readPrivateJson(path: string, what: string): Promise<unknown> {
  let info: Awaited<ReturnType<typeof lstat>>
  try {
    info = await lstat(path)
  } catch {
    throw new CliError("not_found", `There is no ${what} at ${path}.`, { command: what === "scan" ? "mehen adopt scan" : "mehen adopt plan", say: `Run the ${what === "scan" ? "scan" : "plan"} first, or give its path.` })
  }
  if (!info.isFile() || info.size > MAX_STATE_BYTES) throw new CliError("bad_request", `${path} is not a ${what} file mehen can read.`)
  try {
    return JSON.parse(await readFile(path, "utf8")) as unknown
  } catch {
    throw new CliError("bad_request", `${path} is not valid JSON.`, { say: `Fix the ${what} file, or make it again.` })
  }
}

const VerifyResult = z.strictObject({
  slug: z.string(),
  check: z.enum(["ok", "failed", "none", "refused"]),
  status: z.number().int().nullable(),
  at: z.string(),
})
export type VerifyResult = z.infer<typeof VerifyResult>

const AdoptState = z.strictObject({
  version: z.literal(1),
  // The batches this machine uploaded into, newest last. `refs`: plan ref
  // to the ref its row has in the batch; absent for a batch from before
  // machines had refs of their own, whose rows have the plan's refs.
  // `submit`: when the submit that last uploaded into it started, the same
  // for every batch one submit filled. `sources`: plan ref to the source
  // keys (scan.ts sourceKey) of the item uploaded under it, never a value;
  // absent for a batch from before submit kept them. `appliedAt`: when
  // `adopt apply` first applied all of it once approved, which `adopt
  // retire` counts runs from. `bound`: until then, the source keys of the
  // variables `adopt apply` set, or found already set, to an item the batch
  // stored from them; absent for a batch from before apply kept them.
  adoptions: z.array(z.strictObject({ adoption: z.string(), url: z.string(), expiresAt: z.string(), workspace: z.string(), joined: z.boolean(), refs: z.record(z.string(), z.string()).optional(), sources: z.record(z.string(), z.array(z.string())).optional(), submit: z.string().optional(), appliedAt: z.iso.datetime().optional(), bound: z.array(z.string()).optional() })),
  // Project slug to prj_ id, for the projects submit created.
  projects: z.record(z.string(), z.string()),
  // Per plan ref, the last live check `adopt verify` made.
  verify: z.record(z.string(), VerifyResult),
})
export type AdoptState = z.infer<typeof AdoptState>

export async function readState(dir: string): Promise<AdoptState> {
  const path = join(dir, STATE_FILE)
  try {
    await lstat(path)
  } catch {
    return { version: 1, adoptions: [], projects: {}, verify: {} }
  }
  const parsed = AdoptState.safeParse(await readPrivateJson(path, "state"))
  if (!parsed.success) throw new CliError("bad_request", `${path} is not an adopt state file mehen can read.`, { say: "Move it aside; mehen adopt submit writes a fresh one." })
  return parsed.data
}

export async function writeState(dir: string, state: AdoptState, guard: OutputGuard): Promise<void> {
  await writePrivateFile(join(dir, STATE_FILE), `${JSON.stringify(state, null, 2)}\n`, guard)
}

// A batch's rows by the refs this machine's plan gives them; another
// machine's rows keep the batch's refs.
export async function statusByPlanRefs(env: Env, status: AdoptionStatus): Promise<AdoptionStatus> {
  const refs = (await readState(adoptDir(env))).adoptions.find((a) => a.adoption === status.adoption)?.refs
  if (!refs) return status
  const planRefOf = new Map(Object.entries(refs).map(([planRef, ref]) => [ref, planRef]))
  const rename = <T extends { ref: string }>(rows: T[]) => rows.map((r) => ({ ...r, ref: planRefOf.get(r.ref) ?? r.ref }))
  return { ...status, ...(status.created ? { created: rename(status.created) } : {}), ...(status.mapped ? { mapped: rename(status.mapped) } : {}), ...(status.replaced ? { replaced: rename(status.replaced) } : {}), ...(status.refused ? { refused: rename(status.refused) } : {}), ...(status.staged ? { staged: rename(status.staged) } : {}) }
}
