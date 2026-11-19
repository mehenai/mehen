// A vitest reporter for tools/ci/vitest-guard.ts: it keeps a record of the
// run as JSON at $VITEST_PROGRESS_FILE, so the guard can tell a run whose
// every file has finished from one still running even when vitest never
// reaches its summary. Without that variable it writes nothing. The record's
// shape is VitestProgress in tools/ci/vitest-guard.ts.
import { renameSync, writeFileSync } from "node:fs"
import type { Reporter, TestModule, TestRunEndReason, TestSpecification, Vitest } from "vitest/node"

type VitestProgress = { files: number; finished: number; failed: string[]; tests: number; errors: number; end: TestRunEndReason | null }

export default class VitestProgressReporter implements Reporter {
  private readonly path = process.env.VITEST_PROGRESS_FILE
  private vitest: Vitest | undefined
  private progress: VitestProgress = { files: 0, finished: 0, failed: [], tests: 0, errors: 0, end: null }
  private written = ""

  onInit(vitest: Vitest): void {
    this.vitest = vitest
    // An unhandled error reaches vitest's state with no reporter event.
    if (this.path) setInterval(() => this.write(), 1000).unref()
  }

  onTestRunStart(specifications: ReadonlyArray<TestSpecification>): void {
    this.progress = { files: specifications.length, finished: 0, failed: [], tests: 0, errors: 0, end: null }
    this.write()
  }

  onTestCaseResult(): void {
    this.progress.tests++
    this.write()
  }

  onTestModuleEnd(testModule: TestModule): void {
    this.progress.finished++
    if (testModule.state() === "failed") this.progress.failed.push(testModule.relativeModuleId)
    this.write()
  }

  onTestRunEnd(_testModules: unknown, _unhandledErrors: unknown, reason: TestRunEndReason): void {
    this.progress.end = reason
    this.write()
  }

  private write(): void {
    if (!this.path) return
    this.progress.errors = this.vitest?.state.getUnhandledErrors().length ?? 0
    const text = JSON.stringify(this.progress)
    if (text === this.written) return
    writeFileSync(`${this.path}.part`, text)
    renameSync(`${this.path}.part`, this.path)
    this.written = text
  }
}
