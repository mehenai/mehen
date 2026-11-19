// Runs `bun src/main.ts` as a real child process, so tests see the exit
// code, stdout bytes and stderr exactly as an agent would. MAIN is the
// test entry that wraps it (main-under-test.ts: the passwd home is the
// child's HOME unless MEHEN_TEST_PASSWD_HOME names another).

import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

export const MAIN = join(import.meta.dir, "main-under-test.ts")

export type JvResult = { code: number; stdout: string; stderr: string; stdoutBytes: Uint8Array }

// HOME is a fresh empty directory unless the test names one: context
// discovery under ~/.config/mehen must never read this user's own
// enrolments from a test.
export async function runJv(args: string[], env: Record<string, string>, stdin?: string | Uint8Array, cwd?: string): Promise<JvResult> {
  const home = env.HOME === undefined ? await tempDir() : null
  const proc = Bun.spawn([process.execPath, MAIN, ...args], {
    ...(cwd ? { cwd } : {}),
    env: { PATH: process.env.PATH ?? "", HOME: home?.path ?? "", MEHEN_POLL_INTERVAL_MS: "20", ...env },
    stdin: stdin === undefined ? "ignore" : typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin,
    stdout: "pipe",
    stderr: "pipe",
    timeout: 20_000,
  })
  const [stdoutBytes, stderr] = await Promise.all([new Response(proc.stdout).bytes(), new Response(proc.stderr).text()])
  const code = await proc.exited
  if (home) await home.remove()
  return { code, stdout: new TextDecoder().decode(stdoutBytes), stderr, stdoutBytes }
}

export async function tempDir(): Promise<{ path: string; remove(): Promise<void> }> {
  const path = await mkdtemp(join(tmpdir(), "mehen-test-"))
  return { path, remove: () => rm(path, { recursive: true, force: true }) }
}

export function jsonLines(text: string): unknown[] {
  return text
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as unknown)
}
