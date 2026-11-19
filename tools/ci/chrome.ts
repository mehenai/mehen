// Headless Chrome started for a script or a test, the one way every caller
// starts it: the UI gallery and interaction gate (apps/vault/scripts) and
// the CLI's real-Chrome tests (apps/cli/src/testing/chrome.ts).
//
// Why the wait is long: on a fresh GitHub-hosted runner the first read of
// each block of the disk is slow (7 to 23 s to read Chrome's 452 MB, at 20
// to 60 MB/s), so the first Chrome start of a job took 0.6 to 25 s, while a
// start after Chrome's files had been read took 0.3 s and every later start
// 0.1 to 0.2 s (mehenai/mehen#9's probe). CI reads Chrome's files ahead in
// the background (.github/workflows/ci.yml); this wait covers a runner
// where that has not finished.
//
// Chrome writes <profile>/DevToolsActivePort (the port, a line break, the
// browser's WebSocket path) once its DevTools server listens, and the file
// can be seen before both lines are in it, so it is read until it parses.
// Each start gets a profile of its own: a Chrome given a profile another
// Chrome still holds hands over to that one and exits. A Chrome that exits
// first, or never listens, is reported with what it printed.

import { type ChildProcess, spawn } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

export const CHROME_START_MS = 90_000
const POLL_MS = 50
const OUTPUT_LINES = 20

// For a browser a script or a test owns: nothing first-run, nothing fetched
// in the background, no proxy from the environment between it and pages on
// loopback, and a password store that never asks the desktop's keyring.
export const CHROME_FLAGS = ["--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", "--no-proxy-server", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--password-store=basic", "--use-mock-keychain"]

export type StartedChrome = { process: ChildProcess; endpoint: string; profile: string; close: () => Promise<void> }

// The two lines of DevToolsActivePort, or null while it is absent or partial.
export function devToolsEndpoint(text: string | null): string | null {
  if (text === null) return null
  const [port, path] = text.split("\n")
  if (port === undefined || path === undefined || !/^[1-9][0-9]{0,4}$/.test(port) || !/^\/devtools\/browser\/[A-Za-z0-9-]+$/.test(path)) return null
  return `ws://127.0.0.1:${port}${path}`
}

function exited(child: ChildProcess): Promise<void> {
  return child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : new Promise((resolve) => child.once("exit", () => resolve()))
}

async function stop(child: ChildProcess): Promise<void> {
  // No pid: it never started, so there is nothing to stop or wait for.
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return
  child.kill("SIGTERM")
  const gone = await Promise.race([exited(child).then(() => true), new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 5_000))])
  if (!gone) {
    child.kill("SIGKILL")
    await exited(child)
  }
}

export type StartOptions = { flags?: readonly string[]; timeoutMs?: number; profilePrefix?: string }

export async function startChrome(binary: string, options: StartOptions = {}): Promise<StartedChrome> {
  const timeoutMs = options.timeoutMs ?? CHROME_START_MS
  const profile = await mkdtemp(join(tmpdir(), options.profilePrefix ?? "mehen-chrome-"))
  // Chrome will not start its sandbox as root, which a CI container may be.
  const sandbox = process.getuid?.() === 0 ? ["--no-sandbox"] : []
  const child = spawn(binary, [...CHROME_FLAGS, `--user-data-dir=${profile}`, ...sandbox, ...(options.flags ?? []), "about:blank"], { stdio: ["ignore", "ignore", "pipe"] })
  const output: string[] = []
  let spawnError: Error | null = null
  child.on("error", (error) => {
    spawnError = error
  })
  child.stderr?.setEncoding("utf8")
  child.stderr?.on("data", (chunk: string) => {
    output.push(...chunk.split("\n"))
    if (output.length > OUTPUT_LINES * 4) output.splice(0, output.length - OUTPUT_LINES)
  })
  const printed = () => output.filter((line) => line.trim() !== "").slice(-OUTPUT_LINES).join("\n") || "(nothing)"
  const close = async () => {
    await stop(child)
    await rm(profile, { recursive: true, force: true })
  }
  const started = Date.now()
  for (;;) {
    const endpoint = devToolsEndpoint(await readFile(join(profile, "DevToolsActivePort"), "utf8").catch(() => null))
    if (endpoint !== null) return { process: child, endpoint, profile, close }
    const elapsed = Date.now() - started
    if (spawnError !== null || child.exitCode !== null || child.signalCode !== null) {
      await close()
      const how = spawnError !== null ? `could not be started (${(spawnError as Error).message})` : `exited ${child.exitCode !== null ? `with code ${child.exitCode}` : `on ${child.signalCode}`} after ${elapsed} ms`
      throw new Error(`Chrome (${binary}) ${how}, before its DevTools server listened. It printed:\n${printed()}`)
    }
    if (elapsed >= timeoutMs) {
      await close()
      throw new Error(`Chrome (${binary}) was still starting after ${timeoutMs} ms: no DevToolsActivePort in ${profile}. A first start on a fresh machine reads Chrome from disk, which a CI runner can make slow; this is far past that. It printed:\n${printed()}`)
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS))
  }
}
