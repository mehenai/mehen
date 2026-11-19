// A stand-in for vitest in vitest-guard.test.ts: it records a run at
// $VITEST_PROGRESS_FILE as apps/vault/scripts/vitest-progress.ts would, then
// exits or hangs. A child it starts stands for workerd, its pid written to
// the path in the second argument, so the test can see the kill reach it.
import { spawn } from "node:child_process"
import { writeFileSync } from "node:fs"
import type { VitestProgress } from "./vitest-guard.ts"

export type FakeVitestMode = "passes-and-exits" | "fails-and-exits" | "passes-but-exits-1" | "passes-and-hangs" | "fails-and-hangs" | "errors-and-hangs" | "stops-midway" | "hangs-before-any-result" | "ends-then-hangs"

const passed: VitestProgress = { files: 2, finished: 2, failed: [], tests: 5, errors: 0, end: null }
const records: Record<FakeVitestMode, VitestProgress | null> = {
  "passes-and-exits": { ...passed, end: "passed" },
  "fails-and-exits": { ...passed, failed: ["test/b.test.ts"], end: "failed" },
  "passes-but-exits-1": { ...passed, end: "passed" },
  "passes-and-hangs": passed,
  "fails-and-hangs": { ...passed, failed: ["test/b.test.ts"] },
  "errors-and-hangs": { ...passed, errors: 1 },
  "stops-midway": { ...passed, finished: 1, tests: 2 },
  "hangs-before-any-result": null,
  "ends-then-hangs": { ...passed, end: "passed" },
}
const exits: Partial<Record<FakeVitestMode, number>> = { "passes-and-exits": 0, "fails-and-exits": 1, "passes-but-exits-1": 1 }

const mode = Bun.argv[2] as FakeVitestMode
const pidFile = Bun.argv[3]
if (!(mode in records) || !pidFile) throw new Error("Usage: bun tools/ci/fake-vitest.ts <mode> <pid file>")
const workerd = spawn("sleep", ["600"], { stdio: "ignore" })
writeFileSync(pidFile, String(workerd.pid))
const record = records[mode]
if (record) writeFileSync(process.env.VITEST_PROGRESS_FILE!, JSON.stringify(record))
const code = exits[mode]
if (code !== undefined) {
  workerd.kill()
  process.exit(code)
}
setInterval(() => {}, 60_000)
