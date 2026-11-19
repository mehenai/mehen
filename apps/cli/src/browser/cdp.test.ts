import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import { createServer, type Server } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { CliError } from "../errors.ts"
import { FakeCdp } from "../testing/fake-cdp.ts"
import { CdpCallError, CdpConnection, attachPage, cdpEndpoint, choosePage } from "./cdp.ts"

let fake: FakeCdp
let dir: string
beforeAll(() => {
  fake = new FakeCdp()
})
afterAll(() => fake.stop())
beforeEach(async () => {
  fake.calls.length = 0
  fake.handlers.clear()
  fake.versionAnswer = null
  dir = await mkdtemp(join(tmpdir(), "mehen-cdp-"))
})
afterEach(async () => rm(dir, { recursive: true, force: true }))

async function refusal(promise: Promise<unknown>): Promise<CliError> {
  const error = await promise.then(() => null, (e: unknown) => e)
  expect(error).toBeInstanceOf(CliError)
  return error as CliError
}

// A port nothing listens on: bound once, then closed.
async function closedPort(): Promise<number> {
  const server = createServer()
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const port = (server.address() as { port: number }).port
  await new Promise<void>((resolve) => server.close(() => resolve()))
  return port
}

describe("the endpoint forms mehen fill accepts", () => {
  test("a loopback browser-level ws:// URL, as given", async () => {
    for (const host of ["127.0.0.1", "[::1]", "localhost"]) {
      const url = `ws://${host}:9222/devtools/browser/0b1c-2d3e`
      expect(await cdpEndpoint({ cdp: url })).toBe(url)
    }
  })

  test("http://127.0.0.1:<port>, through the browser's /json/version", async () => {
    expect(await cdpEndpoint({ cdp: fake.httpUrl })).toBe(fake.wsUrl)
    expect(await cdpEndpoint({ cdp: `${fake.httpUrl}/` })).toBe(fake.wsUrl)
  })

  test("a profile directory, through the port and path in its DevToolsActivePort", async () => {
    await writeFile(join(dir, "DevToolsActivePort"), "9333\n/devtools/browser/abc-123\n")
    expect(await cdpEndpoint({ userDataDir: dir })).toBe("ws://127.0.0.1:9333/devtools/browser/abc-123")
  })

  test("wss:// to a remote host, for a cloud browser, as given", async () => {
    const url = "wss://connect.browser.example/?apiKey=k_secret"
    expect(await cdpEndpoint({ cdp: url })).toBe(url)
  })
})

describe("the endpoint forms mehen fill refuses with cdp_refused", () => {
  test("plain ws:// to another host", async () => {
    for (const host of ["192.168.1.20", "example.com", "127.0.0.2", "[::2]"]) {
      expect((await refusal(cdpEndpoint({ cdp: `ws://${host}:9222/devtools/browser/x` }))).code).toBe("cdp_refused")
    }
  })

  test("a page's endpoint, on loopback or remote", async () => {
    for (const cdp of ["ws://127.0.0.1:9222/devtools/page/ABCD", "wss://connect.browser.example/devtools/page/ABCD?apiKey=k_secret"]) {
      const error = await refusal(cdpEndpoint({ cdp }))
      expect(error.code).toBe("cdp_refused")
      expect(error.message).toContain("/devtools/page/")
      expect(error.message).not.toContain("k_secret")
    }
  })

  test("anything that is not one of the accepted forms", async () => {
    for (const cdp of ["not a url", "https://127.0.0.1:9222", "http://localhost:9222", "http://[::1]:9222", "http://127.0.0.1", "http://127.0.0.1:9222/json", "http://127.0.0.1:9222/?x=1", "ws://127.0.0.1/devtools/browser/x", "ws://127.0.0.1:9222/devtools/browser/x?y=1", "ws://127.0.0.1:9222/", "ws://user:pw@127.0.0.1:9222/devtools/browser/x", "file:///tmp/x"]) {
      expect({ cdp, code: (await refusal(cdpEndpoint({ cdp }))).code }).toEqual({ cdp, code: "cdp_refused" })
    }
  })

  test("a /json/version answer is held to the same rules as a URL given directly", async () => {
    for (const ws of ["ws://192.168.1.20:9222/devtools/browser/x", "ws://127.0.0.1:9222/devtools/page/x", "wss://remote.example/devtools/browser/x"]) {
      fake.versionAnswer = () => Response.json({ webSocketDebuggerUrl: ws })
      expect({ ws, code: (await refusal(cdpEndpoint({ cdp: fake.httpUrl }))).code }).toEqual({ ws, code: "cdp_refused" })
    }
  })
})

describe("an endpoint that cannot be reached is cdp_unreachable", () => {
  test("no browser on the http port, or an answer that is not Chrome's", async () => {
    expect((await refusal(cdpEndpoint({ cdp: `http://127.0.0.1:${await closedPort()}` }))).code).toBe("cdp_unreachable")
    fake.versionAnswer = () => Response.json({ Browser: "something" })
    expect((await refusal(cdpEndpoint({ cdp: fake.httpUrl }))).code).toBe("cdp_unreachable")
  })

  test("a profile without DevToolsActivePort, or with one that names no endpoint", async () => {
    expect((await refusal(cdpEndpoint({ userDataDir: dir }))).code).toBe("cdp_unreachable")
    for (const text of ["", "0\n/devtools/browser/x\n", "70000\n/devtools/browser/x\n", "9222\n/devtools/page/x\n", "9222\n"]) {
      await writeFile(join(dir, "DevToolsActivePort"), text)
      expect({ text, code: (await refusal(cdpEndpoint({ userDataDir: dir }))).code }).toEqual({ text, code: "cdp_unreachable" })
    }
  })

  test("a DevToolsActivePort that is a symbolic link, a FIFO or larger than 256 bytes is not read", async () => {
    const file = join(dir, "DevToolsActivePort")
    const elsewhere = join(dir, "elsewhere")
    await writeFile(elsewhere, "9333\n/devtools/browser/abc-123\n")
    await symlink(elsewhere, file)
    const linked = await refusal(cdpEndpoint({ userDataDir: dir }))
    expect({ code: linked.code, message: linked.message }).toEqual({ code: "cdp_unreachable", message: expect.stringContaining("symbolic link") })
    await rm(file)
    await writeFile(file, `9333\n/devtools/browser/abc-123\n${" ".repeat(300)}`)
    const large = await refusal(cdpEndpoint({ userDataDir: dir }))
    expect({ code: large.code, message: large.message }).toEqual({ code: "cdp_unreachable", message: expect.stringContaining("256 bytes") })
    await rm(file)
    if (Bun.which("mkfifo") && Bun.spawnSync(["mkfifo", file]).exitCode === 0) {
      const started = Date.now()
      const fifo = await refusal(cdpEndpoint({ userDataDir: dir }))
      expect({ code: fifo.code, message: fifo.message }).toEqual({ code: "cdp_unreachable", message: expect.stringContaining("not a regular file") })
      expect(Date.now() - started).toBeLessThan(2000)
    }
  })

  test("a closed port, and a listener that never finishes the WebSocket handshake, within the timeout", async () => {
    expect((await refusal(CdpConnection.open(`ws://127.0.0.1:${await closedPort()}/devtools/browser/x`, 2000))).code).toBe("cdp_unreachable")
    const silent: Server = createServer(() => {})
    await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve))
    try {
      const started = Date.now()
      const error = await refusal(CdpConnection.open(`ws://127.0.0.1:${(silent.address() as { port: number }).port}/devtools/browser/x`, 300))
      expect(error.code).toBe("cdp_unreachable")
      expect(Date.now() - started).toBeLessThan(2000)
    } finally {
      silent.close()
    }
  })

  test("a call the browser never answers, and every call open when the connection drops", async () => {
    const connection = await CdpConnection.open(fake.wsUrl)
    try {
      fake.on("Page.neverAnswers", () => "silent")
      const late = await refusal(connection.send("Page.neverAnswers", {}, { timeoutMs: 200 }))
      expect(late.code).toBe("cdp_unreachable")
      expect(late.message).toContain("Page.neverAnswers")
      const open = connection.send("Page.neverAnswers")
      await Bun.sleep(50)
      fake.dropConnection()
      expect((await refusal(open)).code).toBe("cdp_unreachable")
      expect((await refusal(connection.send("Target.getTargets"))).code).toBe("cdp_unreachable")
    } finally {
      connection.close()
    }
  })
})

describe("one connection, flattened sessions", () => {
  test("a call names its session, an event carries the session it came from, and a refusal is the browser's", async () => {
    const connection = await CdpConnection.open(fake.wsUrl)
    try {
      fake.on("Target.attachToTarget", (call) => ({ sessionId: `S-${String(call.params.targetId)}` }))
      fake.on("Runtime.evaluate", () => ({ error: "Cannot find context with specified id" }))
      expect(await attachPage(connection, "T1")).toBe("S-T1")
      expect(fake.calls.at(-1)).toMatchObject({ method: "Target.attachToTarget", params: { targetId: "T1", flatten: true }, sessionId: null })
      const events: unknown[] = []
      connection.onEvent((event) => events.push(event))
      fake.emit("Page.frameNavigated", { frame: { id: "F" } }, "S-T1")
      const error = await connection.send("Runtime.evaluate", { expression: "1" }, { sessionId: "S-T1" }).catch((e: unknown) => e)
      expect(error).toBeInstanceOf(CdpCallError)
      expect(fake.calls.at(-1)?.sessionId).toBe("S-T1")
      expect(events).toEqual([{ method: "Page.frameNavigated", params: { frame: { id: "F" } }, sessionId: "S-T1" }])
    } finally {
      connection.close()
    }
  })
})

describe("which page", () => {
  const targets = (...pages: string[]) => () => ({ targetInfos: [{ targetId: "SW", type: "service_worker", url: "chrome-extension://x/sw.js" }, ...pages.map((id) => ({ targetId: id, type: "page", url: `https://${id.toLowerCase()}.example/` })), { targetId: "IF", type: "iframe", url: "https://frame.example/" }] })

  test("the browser's only page when no --target is given", async () => {
    const connection = await CdpConnection.open(fake.wsUrl)
    try {
      fake.on("Target.getTargets", targets("P1"))
      expect(await choosePage(connection, null)).toEqual({ targetId: "P1", url: "https://p1.example/" })
    } finally {
      connection.close()
    }
  })

  test("several pages, or none, without --target is target_ambiguous; --target picks one page and nothing else", async () => {
    const connection = await CdpConnection.open(fake.wsUrl)
    try {
      fake.on("Target.getTargets", targets("P1", "P2"))
      expect((await refusal(choosePage(connection, null))).code).toBe("target_ambiguous")
      expect(await choosePage(connection, "P2")).toEqual({ targetId: "P2", url: "https://p2.example/" })
      for (const target of ["P3", "IF", "SW"]) expect((await refusal(choosePage(connection, target))).code).toBe("target_ambiguous")
      fake.on("Target.getTargets", targets())
      expect((await refusal(choosePage(connection, null))).code).toBe("target_ambiguous")
    } finally {
      connection.close()
    }
  })
})
