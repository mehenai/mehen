// Server-Timing (server-timing.ts) through worker.fetch: the web pages and
// GET /api/needs-you carry one entry per phase, under fixed names with a
// duration and nothing else; the API, the agents' /v1, the health check, the
// OAuth and Google sign-in callbacks and redirects never carry it.
// Durations are counted on a fake clock, never timed.
import { describe, expect, it } from "vitest"
import { TIMING_PHASES, timed, withServerTiming } from "../../src/server-timing.ts"
import { journey } from "./workspace-journey.ts"

const ENTRY = new RegExp(`^(${TIMING_PHASES.join("|")});dur=\\d+(\\.\\d)?$`)
function phases(response: Response): string[] {
  const header = response.headers.get("server-timing")
  if (header === null) return []
  const entries = header.split(", ")
  for (const entry of entries) expect(entry).toMatch(ENTRY)
  return entries.map((entry) => entry.split(";")[0]!)
}

describe("Server-Timing", () => {
  it("names each phase a page and the account inbox spent time in, and nothing on the API or /v1", async () => {
    const f = await journey()
    await f.recoverySetup(f.alex)
    const work = await f.createWorkspace(f.alex, "northwind", "Northwind")
    const machine = await f.machine(f.alex, work)
    const page = await f.request("/w/northwind/", f.alex, undefined, { accept: "text/html" })
    expect(page.status).toBe(200)
    expect(phases(page)).toEqual(["session", "d1", "inbox", "workspace", "render", "total"])
    const credentials = await f.request("/w/northwind/credentials", f.alex, undefined, { accept: "text/html" })
    expect(phases(credentials)).toEqual(["session", "d1", "workspace", "render", "total"])
    const needsYou = await f.request("/api/needs-you", f.alex)
    expect(needsYou.status).toBe(200)
    expect(phases(needsYou)).toEqual(["session", "d1", "inbox", "workspace", "total"])
    const unchanged = await f.request("/api/needs-you", f.alex, undefined, { "if-none-match": needsYou.headers.get("etag")! })
    expect(unchanged.status).toBe(304)
    expect(phases(unchanged)).toEqual(["session", "d1", "inbox", "workspace", "total"])
    const signedOut = await f.request("/signin", undefined, undefined, { accept: "text/html" })
    expect(signedOut.status).toBe(200)
    expect(phases(signedOut)).toContain("total")
    for (const response of [await f.request("/api/w/northwind/items", f.alex), await f.request("/api/account", f.alex), await f.deviceCall(machine, "/v1/me")]) {
      expect(response.status).toBe(200)
      expect(response.headers.has("server-timing")).toBe(false)
    }
  }, 60_000)

  it("leaves it off the health check, the OAuth and Google sign-in callbacks and a page route's redirect", async () => {
    const f = await journey()
    await f.recoverySetup(f.alex)
    await f.createWorkspace(f.alex, "northwind", "Northwind")
    const html = { accept: "text/html" }
    const healthz = await f.request("/healthz")
    expect(healthz.status).toBe(200)
    const callback = await f.request("/oauth/callback?state=not-a-state&code=x", undefined, undefined, html)
    expect(callback.status).toBeGreaterThanOrEqual(400)
    expect(callback.headers.get("content-type")).toMatch(/^text\/html/)
    const oidc = await f.request("/auth/oidc/verify", undefined, undefined, html)
    expect(oidc.headers.get("content-type")).toMatch(/^text\/html/)
    const redirect = await f.request("/", f.alex, undefined, html)
    expect(redirect.status).toBe(302)
    const signedOut = await f.request("/w/northwind/", undefined, undefined, html)
    expect(signedOut.status).toBe(302)
    for (const response of [healthz, callback, oidc, redirect, signedOut]) expect(response.headers.has("server-timing")).toBe(false)
    const page = await f.request("/w/northwind/", f.alex, undefined, html)
    expect(page.headers.get("content-type")).toMatch(/^text\/html/)
    expect(phases(page)).toContain("total")
  }, 60_000)

  it("counts a phase once while calls in it overlap, and adds up the times it was open", async () => {
    const ticks = [0, 10, 50, 60, 70, 100]
    const clock = () => ticks.shift()!
    let release: () => void = () => {}
    const held = new Promise<void>((resolve) => { release = resolve })
    const response = await withServerTiming(async () => {
      // total opens at 0; two overlapping workspace calls hold it 10 to 50.
      const first = timed("workspace", () => held)
      const second = timed("workspace", async () => {})
      await second
      release()
      await first
      // d1 is open 60 to 70; total closes at 100.
      await timed("d1", async () => {})
      return new Response("ok", { headers: { "content-type": "text/plain" } })
    }, () => true, clock)
    expect(response.headers.get("server-timing")).toBe("d1;dur=10, workspace;dur=40, total;dur=100")
    expect(response.headers.get("content-type")).toBe("text/plain")
    expect(await response.text()).toBe("ok")
  })
})
