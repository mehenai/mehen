// Runs a vitest command and ends it when vitest does not. Twice in CI the
// vault step printed every file as passed and then never exited, until the
// job's 40 minute limit (cloudflare/workers-sdk#15498). The command's
// reporter, apps/vault/scripts/vitest-progress.ts, keeps a record of the run
// at $VITEST_PROGRESS_FILE, which the guard sets. The guard kills the
// command's whole process group when every file has finished and the
// command is still running --grace seconds later, or when no test has
// finished for --idle seconds; then it exits 0 only if every file passed
// with no unhandled error, and 1 otherwise. A command that exits by itself
// exits with its own code: the guard never turns a failure into a pass.
//
//   bun tools/ci/vitest-guard.ts [--grace 60] [--idle 300] [--] <command...>
//
// Bun drops a `--` that comes straight after the script, so the command
// starts at the first argument that is not one of the guard's options.
import { spawn } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

export type VitestProgress = { files: number; finished: number; failed: string[]; tests: number; errors: number; end: "passed" | "failed" | "interrupted" | null }

export type GuardOptions = { graceSeconds: number; idleSeconds: number; command: string[] }

const USAGE = "Usage: bun tools/ci/vitest-guard.ts [--grace <seconds>] [--idle <seconds>] [--] <command...>"
const POLL_MS = 250
const TERM_WAIT_MS = 5_000

export function parseGuardArgs(argv: string[]): GuardOptions {
  const options: GuardOptions = { graceSeconds: 60, idleSeconds: 300, command: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--") { options.command = argv.slice(i + 1); break }
    if (!arg?.startsWith("--")) { options.command = argv.slice(i); break }
    const seconds = Number(argv[i + 1])
    if ((arg !== "--grace" && arg !== "--idle") || !(seconds > 0)) throw new Error(USAGE)
    if (arg === "--grace") options.graceSeconds = seconds
    else options.idleSeconds = seconds
    i++
  }
  if (options.command.length === 0) throw new Error(USAGE)
  return options
}

export function readProgress(text: string): VitestProgress | null {
  let value: unknown
  try { value = JSON.parse(text) } catch { return null }
  if (typeof value !== "object" || value === null) return null
  const p = value as Record<string, unknown>
  const count = (n: unknown) => typeof n === "number" && Number.isInteger(n) && n >= 0
  if (!count(p.files) || !count(p.finished) || !count(p.tests) || !count(p.errors)) return null
  if (!Array.isArray(p.failed) || !p.failed.every((f) => typeof f === "string")) return null
  if (p.end !== null && p.end !== "passed" && p.end !== "failed" && p.end !== "interrupted") return null
  return p as VitestProgress
}

export function runFinished(p: VitestProgress): boolean {
  return p.end !== null || (p.files > 0 && p.finished >= p.files)
}

export function runPassed(p: VitestProgress): boolean {
  return p.files > 0 && p.finished === p.files && p.failed.length === 0 && p.errors === 0 && (p.end === null || p.end === "passed")
}

function outcome(p: VitestProgress): string {
  if (runPassed(p)) return `all ${p.files} files passed`
  const parts = [`${p.finished} of ${p.files} files finished`]
  if (p.failed.length > 0) parts.push(`${p.failed.length} failed (${p.failed.join(", ")})`)
  if (p.errors > 0) parts.push(`${p.errors} unhandled errors`)
  if (p.end !== null && p.end !== "passed") parts.push(`the run ended ${p.end}`)
  return parts.join(", ")
}

function signalGroup(pid: number, signal: NodeJS.Signals): void {
  try { process.kill(-pid, signal) } catch { /* the group has already gone */ }
}

export async function guard(options: GuardOptions): Promise<number> {
  const dir = mkdtempSync(join(tmpdir(), "vitest-guard-"))
  const progressFile = join(dir, "progress.json")
  const [command, ...args] = options.command as [string, ...string[]]
  // Its own process group, so a kill reaches workerd and every other child.
  const child = spawn(command, args, { stdio: "inherit", detached: true, env: { ...process.env, VITEST_PROGRESS_FILE: progressFile } })
  const exited = new Promise<number>((resolve) => {
    child.once("error", (error) => { console.error(`vitest-guard: could not run ${command}: ${error.message}`); resolve(1) })
    child.once("exit", (code, signal) => resolve(code ?? (signal ? 1 : 0)))
  })
  let running = true
  void exited.then(() => { running = false })
  const forward = (signal: NodeJS.Signals) => { signalGroup(child.pid!, signal); process.exit(128 + (signal === "SIGINT" ? 2 : 15)) }
  process.once("SIGINT", forward)
  process.once("SIGTERM", forward)

  const kill = async (line: string, code: number): Promise<number> => {
    signalGroup(child.pid!, "SIGTERM")
    await Promise.race([exited, Bun.sleep(TERM_WAIT_MS)])
    signalGroup(child.pid!, "SIGKILL")
    console.log(`${code === 0 ? "::warning::" : "::error::"}vitest-guard: ${line}; killed it`)
    return code
  }

  try {
    let seen = "", progress: VitestProgress | null = null
    let changedAt = Date.now(), finishedAt: number | null = null
    while (running) {
      await Promise.race([exited, Bun.sleep(POLL_MS)])
      if (!running) break
      let text = ""
      try { text = readFileSync(progressFile, "utf8") } catch { /* nothing recorded yet */ }
      if (text !== seen) {
        seen = text
        changedAt = Date.now()
        progress = readProgress(text) ?? progress
      }
      if (progress && finishedAt === null && runFinished(progress)) finishedAt = Date.now()
      if (progress && finishedAt !== null && Date.now() - finishedAt >= options.graceSeconds * 1000) {
        return await kill(`vitest did not exit ${options.graceSeconds} s after its last file finished, ${outcome(progress)}`, runPassed(progress) ? 0 : 1)
      }
      if (finishedAt === null && Date.now() - changedAt >= options.idleSeconds * 1000) {
        const recorded = progress ? outcome(progress) : `nothing was recorded at $VITEST_PROGRESS_FILE (does the command pass --reporter=./scripts/vitest-progress.ts?)`
        return await kill(`no test finished for ${options.idleSeconds} s, ${recorded}`, 1)
      }
    }
    return await exited
  } finally {
    process.off("SIGINT", forward)
    process.off("SIGTERM", forward)
    rmSync(dir, { recursive: true, force: true })
  }
}

if (import.meta.main) {
  let options: GuardOptions
  try { options = parseGuardArgs(Bun.argv.slice(2)) } catch (error) { console.error((error as Error).message); process.exit(2) }
  process.exit(await guard(options))
}
