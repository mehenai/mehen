import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmod, mkdtemp, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { CHROME_FLAGS, devToolsEndpoint, startChrome } from "./chrome.ts"

let dir: string
let before: string[] = []
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "mehen-chrome-start-"))
  before = await all()
})
afterEach(() => rm(dir, { recursive: true, force: true }))

// A stand-in for Chrome: a script that finds its profile in the arguments.
async function fake(body: string): Promise<string> {
  const path = join(dir, "chrome")
  await writeFile(path, `#!/bin/sh\nfor a in "$@"; do case "$a" in --user-data-dir=*) profile=\${a#--user-data-dir=} ;; esac; done\n${body}\n`)
  await chmod(path, 0o755)
  return path
}
const all = async () => (await readdir(tmpdir())).filter((n) => n.startsWith("mehen-chrome-test-"))
// The profiles this test made and left.
const profiles = async () => (await all()).filter((n) => !before.includes(n))

describe("devToolsEndpoint", () => {
  test("only both lines, a port and the browser's path, make an endpoint", () => {
    const uuid = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
    expect(devToolsEndpoint(`9222\n/devtools/browser/${uuid}`)).toBe(`ws://127.0.0.1:9222/devtools/browser/${uuid}`)
    expect(devToolsEndpoint(`9222\n/devtools/browser/${uuid}\n`)).toBe(`ws://127.0.0.1:9222/devtools/browser/${uuid}`)
    // Every cut of the path short of the whole id is partial, never an endpoint.
    for (let cut = 0; cut < uuid.length; cut++) expect(devToolsEndpoint(`9222\n/devtools/browser/${uuid.slice(0, cut)}`)).toBeNull()
    for (const partial of [null, "", "9222", "9222\n", "9222\n/devtools/br", `0\n/devtools/browser/${uuid}`, `abc\n/devtools/browser/${uuid}`, `9222\n/devtools/page/${uuid}`, "9222\n/devtools/browser/0b1c-2d3e"]) expect(devToolsEndpoint(partial)).toBeNull()
  })
})

describe("startChrome", () => {
  test("waits through a slow start and a file written in two steps, then close stops it and removes its profile", async () => {
    const chrome = await fake('sleep 1; printf 9222 > "$profile/DevToolsActivePort"; sleep 0.4; printf "9222\\n/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\\n" > "$profile/DevToolsActivePort"; exec sleep 30')
    const started = await startChrome(chrome, { flags: ["--extra"], profilePrefix: "mehen-chrome-test-" })
    expect(started.endpoint).toBe("ws://127.0.0.1:9222/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d")
    expect(await profiles()).toHaveLength(1)
    await started.close()
    expect(started.process.exitCode !== null || started.process.signalCode !== null).toBe(true)
    expect(await profiles()).toEqual([])
  })

  test("a browser path written in two pieces is waited for, never used cut short", async () => {
    const chrome = await fake('printf "9222\\n/devtools/browser/0b1c2d3e-4f50" > "$profile/DevToolsActivePort"; sleep 0.5; printf "9222\\n/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d" > "$profile/DevToolsActivePort"; exec sleep 30')
    const started = await startChrome(chrome, { profilePrefix: "mehen-chrome-test-" })
    expect(started.endpoint).toBe("ws://127.0.0.1:9222/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d")
    await started.close()
  })

  test("closing leaves no timer behind: a script that starts and closes Chrome exits at once", async () => {
    const chrome = await fake('printf "9222\\n/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d" > "$profile/DevToolsActivePort"; exec sleep 30')
    const script = join(dir, "run.ts")
    await writeFile(script, `import { startChrome, within } from ${JSON.stringify(join(import.meta.dir, "chrome.ts"))}\nconst c = await startChrome(${JSON.stringify(chrome)}, { profilePrefix: "mehen-chrome-test-" })\nawait c.close()\nawait within(Promise.resolve(1), 5_000)\n`)
    const begun = Date.now()
    const proc = Bun.spawn([process.execPath, script], { stdout: "ignore", stderr: "inherit" })
    expect(await proc.exited).toBe(0)
    expect(Date.now() - begun).toBeLessThan(3_000)
  })

  test("within gives the value, or null once the time is up", async () => {
    const { within } = await import("./chrome.ts")
    expect(await within(Promise.resolve(7), 1_000)).toBe(7)
    expect(await within(new Promise<number>(() => undefined), 50)).toBeNull()
  })

  test("every start gets a profile of its own", async () => {
    const chrome = await fake('printf "9222\\n/devtools/browser/0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d" > "$profile/DevToolsActivePort"; exec sleep 30')
    const [a, b] = await Promise.all([startChrome(chrome, { profilePrefix: "mehen-chrome-test-" }), startChrome(chrome, { profilePrefix: "mehen-chrome-test-" })])
    expect(a.profile).not.toBe(b.profile)
    await Promise.all([a.close(), b.close()])
  })

  test("a Chrome that exits first is reported at once, with its code and what it printed, and leaves no profile", async () => {
    const chrome = await fake('echo "Failed to move to new namespace: PID namespaces supported" >&2; exit 133')
    const begun = Date.now()
    const error = await startChrome(chrome, { profilePrefix: "mehen-chrome-test-" }).then(() => null, (e: unknown) => e as Error)
    expect(Date.now() - begun).toBeLessThan(5_000)
    expect(error?.message).toMatch(/exited with code 133 after \d+ ms, before its DevTools server listened/)
    expect(error?.message).toContain("Failed to move to new namespace")
    expect(await profiles()).toEqual([])
  })

  test("one that never listens is stopped at the deadline, says what it printed, and leaves nothing running", async () => {
    const chrome = await fake('echo "starting" >&2; exec sleep 30')
    const error = await startChrome(chrome, { timeoutMs: 600, profilePrefix: "mehen-chrome-test-" }).then(() => null, (e: unknown) => e as Error)
    expect(error?.message).toContain("was still starting after 600 ms: no DevToolsActivePort")
    expect(error?.message).toContain("It printed:\nstarting")
    expect(await profiles()).toEqual([])
  })

  test("a binary that is not there says so", async () => {
    const error = await startChrome(join(dir, "missing"), { profilePrefix: "mehen-chrome-test-" }).then(() => null, (e: unknown) => e as Error)
    expect(error?.message).toMatch(/could not be started|exited/)
  })

  test("waits long enough for a first start on a fresh runner, and never takes a proxy or the desktop keyring", async () => {
    const { CHROME_START_MS } = await import("./chrome.ts")
    expect(CHROME_START_MS).toBeGreaterThanOrEqual(60_000)
    expect(CHROME_FLAGS).toContain("--no-proxy-server")
    expect(CHROME_FLAGS).toContain("--password-store=basic")
  })
})
