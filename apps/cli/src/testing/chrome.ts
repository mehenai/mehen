// A headless Chrome for the tests that drive a real one, started so that a
// slow start on a busy CI runner waits as long as it needs to and a start
// that cannot succeed says why at once.
//
// Chrome writes <profile>/DevToolsActivePort (the port, a line break, the
// browser's WebSocket path) once its DevTools server listens. The file can
// be seen before both lines are in it, so it is read until it parses, not
// merely until it exists. A Chrome that exits first is reported with its
// exit code and the end of what it printed, instead of a missing file.

import { readFile } from "node:fs/promises"
import { join } from "node:path"
import type { Subprocess } from "bun"

// A first start with a new profile on a shared CI runner, with the other
// test files running beside it, has taken over 10 seconds.
export const CHROME_START_MS = 45_000
const POLL_MS = 50
const OUTPUT_LINES = 20

export type StartedChrome = { process: Subprocess<"ignore", "ignore", "pipe">; endpoint: string }

// The two lines of DevToolsActivePort, or null while it is absent or partial.
export function devToolsEndpoint(text: string | null): string | null {
  if (text === null) return null
  const [port, path] = text.split("\n")
  if (port === undefined || path === undefined || !/^[1-9][0-9]{0,4}$/.test(port) || !/^\/devtools\/browser\/[A-Za-z0-9-]+$/.test(path)) return null
  return `ws://127.0.0.1:${port}${path}`
}

// Flags for a browser the tests own: no first-run work, nothing fetched in
// the background, no proxy from the environment between it and the
// loopback test sites, and a password store that never asks the desktop's
// keyring (which on a runner with no session bus can stall the start).
export const TEST_CHROME_FLAGS = ["--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", "--no-proxy-server", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--password-store=basic", "--use-mock-keychain"]

export async function startChrome(binary: string, profile: string, flags: readonly string[], timeoutMs = CHROME_START_MS): Promise<StartedChrome> {
  const proc = Bun.spawn([binary, ...TEST_CHROME_FLAGS, `--user-data-dir=${profile}`, ...flags, "about:blank"], { stdin: "ignore", stdout: "ignore", stderr: "pipe" })
  const output: string[] = []
  void (async () => {
    const decoder = new TextDecoder()
    const reader = proc.stderr.getReader()
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return
      output.push(...decoder.decode(value, { stream: true }).split("\n"))
      if (output.length > OUTPUT_LINES * 4) output.splice(0, output.length - OUTPUT_LINES)
    }
  })().catch(() => undefined)
  const tail = () => output.filter(Boolean).slice(-OUTPUT_LINES).join("\n") || "(nothing)"
  const deadline = Date.now() + timeoutMs
  const started = Date.now()
  for (;;) {
    const endpoint = devToolsEndpoint(await readFile(join(profile, "DevToolsActivePort"), "utf8").catch(() => null))
    if (endpoint !== null) return { process: proc, endpoint }
    if (proc.exitCode !== null || proc.signalCode !== null) {
      throw new Error(`Chrome (${binary}) exited ${proc.exitCode !== null ? `with code ${proc.exitCode}` : `on ${proc.signalCode}`} after ${Date.now() - started} ms, before its DevTools server listened. It printed:\n${tail()}`)
    }
    if (Date.now() >= deadline) {
      proc.kill()
      throw new Error(`Chrome (${binary}) was still starting after ${timeoutMs} ms: no DevToolsActivePort in ${profile}. It printed:\n${tail()}`)
    }
    await Bun.sleep(POLL_MS)
  }
}
