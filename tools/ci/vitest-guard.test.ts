import { describe, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { FakeVitestMode } from "./fake-vitest.ts"
import { parseGuardArgs, readProgress, runPassed, type VitestProgress } from "./vitest-guard.ts"

const GUARD = join(import.meta.dir, "vitest-guard.ts")
const FAKE = join(import.meta.dir, "fake-vitest.ts")

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true } catch { return false }
}

// The guard with a one second grace and a two second idle limit, over the fake vitest.
async function guarded(mode: FakeVitestMode): Promise<{ code: number; output: string; workerdAlive: boolean; seconds: number }> {
  const dir = mkdtempSync(join(tmpdir(), "vitest-guard-test-"))
  const pidFile = join(dir, "workerd.pid")
  const started = Date.now()
  try {
    const run = Bun.spawn(["bun", GUARD, "--grace", "1", "--idle", "2", "--", "bun", FAKE, mode, pidFile], { stdout: "pipe", stderr: "pipe" })
    const [code, stdout, stderr] = await Promise.all([run.exited, new Response(run.stdout).text(), new Response(run.stderr).text()])
    const workerd = Number(readFileSync(pidFile, "utf8"))
    await Bun.sleep(100)
    return { code, output: stdout + stderr, workerdAlive: alive(workerd), seconds: (Date.now() - started) / 1000 }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe("vitest-guard over a command that exits by itself", () => {
  test("passes its exit code through: 0 for a pass, 1 for a failure, and 1 even when the record says every file passed", async () => {
    const [pass, fail, exitsOne] = await Promise.all([guarded("passes-and-exits"), guarded("fails-and-exits"), guarded("passes-but-exits-1")])
    expect(pass).toMatchObject({ code: 0, workerdAlive: false })
    expect(fail).toMatchObject({ code: 1, workerdAlive: false })
    expect(exitsOne).toMatchObject({ code: 1, workerdAlive: false })
    for (const run of [pass, fail, exitsOne]) expect(run.output).not.toContain("vitest-guard:")
  }, 20_000)
})

describe("vitest-guard over a command that does not exit", () => {
  test("kills a run whose every file passed once the grace is up, its children too, and exits 0 saying so", async () => {
    const run = await guarded("passes-and-hangs")
    expect(run).toMatchObject({ code: 0, workerdAlive: false })
    expect(run.output).toContain("::warning::vitest-guard: vitest did not exit 1 s after its last file finished, all 2 files passed; killed it")
    expect(run.seconds).toBeLessThan(10)
  }, 20_000)

  test("kills a run that printed its summary and then hung, and exits 0", async () => {
    const run = await guarded("ends-then-hangs")
    expect(run).toMatchObject({ code: 0, workerdAlive: false })
    expect(run.output).toContain("all 2 files passed; killed it")
  }, 20_000)

  test("exits 1 for a finished run with a failed file or an unhandled error", async () => {
    const [failed, errored] = await Promise.all([guarded("fails-and-hangs"), guarded("errors-and-hangs")])
    expect(failed).toMatchObject({ code: 1, workerdAlive: false })
    expect(failed.output).toContain("::error::vitest-guard: vitest did not exit 1 s after its last file finished, 2 of 2 files finished, 1 failed (test/b.test.ts); killed it")
    expect(errored).toMatchObject({ code: 1, workerdAlive: false })
    expect(errored.output).toContain("2 of 2 files finished, 1 unhandled errors; killed it")
  }, 20_000)

  test("exits 1 when no test finishes within the idle limit, midway or before any result", async () => {
    const [midway, before] = await Promise.all([guarded("stops-midway"), guarded("hangs-before-any-result")])
    expect(midway).toMatchObject({ code: 1, workerdAlive: false })
    expect(midway.output).toContain("::error::vitest-guard: no test finished for 2 s, 1 of 2 files finished; killed it")
    expect(before).toMatchObject({ code: 1, workerdAlive: false })
    expect(before.output).toContain("::error::vitest-guard: no test finished for 2 s, nothing was recorded at $VITEST_PROGRESS_FILE")
  }, 20_000)
})

describe("the guard's rules", () => {
  const record: VitestProgress = { files: 3, finished: 3, failed: [], tests: 9, errors: 0, end: null }
  test("a pass needs every file finished, none failed, no unhandled error and no other ending", () => {
    expect(runPassed(record)).toBe(true)
    expect(runPassed({ ...record, end: "passed" })).toBe(true)
    for (const change of [{ finished: 2 }, { failed: ["test/a.test.ts"] }, { errors: 1 }, { end: "failed" as const }, { end: "interrupted" as const }, { files: 0, finished: 0 }]) {
      expect(runPassed({ ...record, ...change }), JSON.stringify(change)).toBe(false)
    }
  })

  test("reads only a well-formed record", () => {
    expect(readProgress(JSON.stringify(record))).toEqual(record)
    for (const text of ["", "{", "null", "[]", JSON.stringify({ ...record, files: "3" }), JSON.stringify({ ...record, failed: [1] }), JSON.stringify({ ...record, end: "done" }), JSON.stringify({ ...record, errors: -1 })]) {
      expect(readProgress(text), text).toBeNull()
    }
  })

  test("takes the grace, the idle limit and a command after -- or after the last option", () => {
    expect(parseGuardArgs(["--", "bun", "run", "test"])).toEqual({ graceSeconds: 60, idleSeconds: 300, command: ["bun", "run", "test"] })
    expect(parseGuardArgs(["bun", "run", "test", "--idle", "1"])).toEqual({ graceSeconds: 60, idleSeconds: 300, command: ["bun", "run", "test", "--idle", "1"] })
    expect(parseGuardArgs(["--grace", "5", "bun", "--", "x"])).toEqual({ graceSeconds: 5, idleSeconds: 300, command: ["bun", "--", "x"] })
    expect(parseGuardArgs(["--grace", "5", "--idle", "30", "--", "vitest", "--grace", "x"])).toEqual({ graceSeconds: 5, idleSeconds: 30, command: ["vitest", "--grace", "x"] })
    for (const argv of [[], ["--"], ["--grace", "5"], ["--grace", "0", "--", "bun"], ["--idle", "x", "--", "bun"], ["--wait", "5", "--", "bun"]]) expect(() => parseGuardArgs(argv), argv.join(" ")).toThrow("Usage:")
  })
})
