import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { lstat, readFile, rm, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { requireSnapshot } from "./guard.ts"
import { takeSnapshot } from "./snapshot.ts"
import { type BackupFixture, backupFixture, planFor, writePlan } from "../testing/backup-fixtures.ts"
import { CliError } from "../errors.ts"

let f: BackupFixture
beforeEach(async () => {
  f = await backupFixture()
})
afterEach(() => f.remove())

// Every source last changed well before the snapshot, so a later touch is
// unambiguously newer.
async function ageSources(): Promise<void> {
  const past = new Date(Date.now() - 60_000)
  for (const path of [f.envFile, f.secretsFile, f.manifest, f.unit, f.serviceEnv]) await utimes(path, past, past)
}

const snap = () => takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env })
const guard = (snapshot?: string) => requireSnapshot({ planPath: f.planPath, env: f.env, ...(snapshot ? { snapshot } : {}) })

async function refusal(): Promise<CliError> {
  try {
    await guard()
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

describe("requireSnapshot, the gate before adopt submit", () => {
  test("refuses when no snapshot is recorded, naming the command that takes one", async () => {
    const error = await refusal()
    expect(error.code).toBe("failed")
    expect(error.message).toContain("No passed snapshot")
    expect(error.next?.command).toBe(`mehen backup snapshot --plan ${f.planPath} --to <dir outside your repos> --recipient <age1...>`)
  })

  test("passes with the newest passed snapshot that holds every path the plan names", async () => {
    await ageSources()
    await snap()
    const newest = await snap()
    expect(await guard()).toEqual({ id: newest.id, path: newest.archive })
  })

  test("refuses when a source changed after the snapshot", async () => {
    await ageSources()
    await snap()
    await writeFile(f.secretsFile, "OPENAI_API_KEY=rotated\n")
    await utimes(f.secretsFile, new Date(Date.now() + 5_000), new Date(Date.now() + 5_000))
    const error = await refusal()
    expect(error.message).toContain(`${f.secretsFile} changed after snapshot`)
  })

  test("refuses when a source changed after the snapshot even with its old mtime put back (touch -r, cp -p)", async () => {
    await ageSources()
    await snap()
    const before = await lstat(f.secretsFile)
    await Bun.sleep(5)
    await writeFile(f.secretsFile, "OPENAI_API_KEY=rotated\n")
    await utimes(f.secretsFile, before.atime, before.mtime)
    expect((await lstat(f.secretsFile)).mtimeMs).toBe(before.mtimeMs)
    expect((await refusal()).message).toContain(`${f.secretsFile} changed after snapshot`)
  })

  test("refuses when the plan names a file no snapshot holds: a new source, or a mehen.toml made since", async () => {
    await ageSources()
    await snap()
    const extra = join(f.root, "config", "extra.env")
    await writeFile(extra, "X=1\n", { mode: 0o600 })
    await writePlan(f.planPath, { ...planFor(f), sources: { ...(planFor(f).sources as object), s0new: { path: extra } } })
    expect((await refusal()).message).toContain(`The plan names ${extra}, which snapshot`)

    await writePlan(f.planPath, planFor(f))
    await rm(f.manifest)
    await snap()
    expect(await guard()).toMatchObject({ id: expect.stringMatching(/^snp_/) })
    await writeFile(f.manifest, 'project = "billing-api"\n')
    expect((await refusal()).message).toContain(`The plan names ${f.manifest}`)
  })

  test("--snapshot names one: an unknown id refuses, the right one passes", async () => {
    await ageSources()
    const taken = await snap()
    await expect(guard("snp_unknown")).rejects.toThrow("No passed snapshot snp_unknown")
    expect(await guard(taken.id)).toEqual({ id: taken.id, path: taken.archive })
  })

  test("the archive must still be there and pass check; a missing one passes only when --snapshot names it", async () => {
    await ageSources()
    const taken = await snap()
    const bytes = await readFile(taken.archive)
    await rm(taken.archive)
    expect((await refusal()).message).toContain(`The archive of snapshot ${taken.id}, ${taken.archive}, is not there`)
    expect(await guard(taken.id)).toEqual({ id: taken.id, path: taken.archive })

    bytes[bytes.length - 1] = (bytes[bytes.length - 1] as number) ^ 1
    await writeFile(taken.archive, bytes)
    expect((await refusal()).message).toContain(`${taken.archive} is damaged`)
    await expect(guard(taken.id)).rejects.toThrow(`${taken.archive} is damaged`)
  })

  test("a snapshot that failed its self-check is never recorded, so it never passes the gate", async () => {
    await ageSources()
    await takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env, beforeSelfCheck: () => writeFile(f.envFile, "changed\n") }).catch(() => null)
    expect((await refusal()).message).toContain("No passed snapshot")
  })
})
