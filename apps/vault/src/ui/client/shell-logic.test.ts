// The workspace tab's client rules: full-identity cache keys, dropped late
// responses, and a stale cross-workspace tab refusing every call with
// nothing sent. Runs inside workerd with a counting fetch in place of the
// network.

import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { STALE_TAB_STATUS, VaultFailure, api, setCallGuard, workspaceApi, workspaceRead } from "./api.ts"
import { type PaletteScope, buildEntries, filterEntries, workspacePaletteAsks } from "./palette-logic.ts"
import { SHELL_CHANNEL, ShellState, WORKSPACE_HEADER, parseShellMessage, readShellIdentity, staleRefusal, workspaceWords, type ShellIdentity } from "./shell-logic.ts"
import { type ShellChannel, type ShellHost, initShell } from "./shell.ts"
import { workspaceGoPlaces } from "./shortcut-keys.ts"

const ORIGIN = "https://app.mehen.dev"
const PERSONAL: ShellIdentity = { origin: ORIGIN, account: "acc_alex", workspace: { id: "tn_Alpha123456", slug: "alex", name: "Personal" }, pages: ["home"], reads: [] }
const WORK: ShellIdentity = { ...PERSONAL, workspace: { id: "tn_Beta1234567", slug: "northwind", name: "Personal" } }

type Sent = { url: string; headers: Record<string, string> }
let sent: Sent[] = []
let reply: () => Promise<Response> = async () => Response.json({ ok: true })
const realFetch = globalThis.fetch

beforeEach(() => {
  sent = []
  reply = async () => Response.json({ ok: true })
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push({ url: String(input), headers: Object.fromEntries(new Headers(init?.headers).entries()) })
    return reply()
  }) as typeof fetch
})

afterEach(() => {
  globalThis.fetch = realFetch
  setCallGuard(null)
})

async function refusal(promise: Promise<unknown>): Promise<VaultFailure> {
  try {
    await promise
  } catch (error) {
    if (error instanceof VaultFailure) return error
    throw error
  }
  throw new Error("expected a refusal")
}

describe("the boot identity", () => {
  it("reads only a complete shell for this page's own origin", () => {
    const boot = { origin: ORIGIN, account: "acc_alex", workspace: { id: "tn_Alpha123456", slug: "alex", name: "Personal" }, pages: ["home"], reads: [] }
    expect(readShellIdentity(boot, ORIGIN)).toEqual(PERSONAL)
    expect(readShellIdentity(boot, "https://evil.test")).toBeNull()
    expect(readShellIdentity({ ...boot, workspace: { slug: "alex", name: "Personal" } }, ORIGIN)).toBeNull()
    expect(readShellIdentity({ ...boot, account: "" }, ORIGIN)).toBeNull()
    expect(readShellIdentity(undefined, ORIGIN)).toBeNull()
  })

  it("keys caches by origin, account, workspace id and path, never by name", () => {
    const a = new ShellState(PERSONAL)
    const b = new ShellState(WORK)
    const otherOrigin = new ShellState({ ...PERSONAL, origin: "https://vault.example" })
    const otherAccount = new ShellState({ ...PERSONAL, account: "acc_tom" })
    const keys = [a, b, otherOrigin, otherAccount].map((s) => s.cacheKey("/items"))
    expect(new Set(keys).size).toBe(4)
    expect(a.cacheKey("/items")).not.toEqual(a.cacheKey("/devices"))
    expect(a.cacheKey("/items")).toBe(JSON.stringify([ORIGIN, "acc_alex", "tn_Alpha123456", "/items"]))
  })
})

describe("workspace calls", () => {
  it("go to the prefixed path with the workspace id in the header", async () => {
    const shell = new ShellState(PERSONAL)
    await workspaceApi(shell, "/items")
    await workspaceApi(shell, "/items", { slug: "x" })
    expect(sent).toEqual([
      { url: "/api/w/alex/items", headers: { accept: "application/json", [WORKSPACE_HEADER.toLowerCase()]: "tn_Alpha123456" } },
      { url: "/api/w/alex/items", headers: { accept: "application/json", "content-type": "application/json", [WORKSPACE_HEADER.toLowerCase()]: "tn_Alpha123456" } },
    ])
  })

  it("drop a response that lands after the tab moved on, and never cache it", async () => {
    const shell = new ShellState(PERSONAL)
    let release: (r: Response) => void = () => {}
    reply = () => new Promise<Response>((resolve) => { release = resolve })
    const read = workspaceRead(shell, "/items")
    await Promise.resolve()
    shell.clear()
    release(Response.json({ items: ["stale"] }))
    const failure = await refusal(read)
    expect(failure.status).toBe(STALE_TAB_STATUS)
    expect(shell.cached("/items")).toBeUndefined()
    reply = async () => Response.json({ items: ["fresh"] })
    expect(await workspaceRead(shell, "/items")).toEqual({ items: ["fresh"] })
    expect(shell.cached("/items")).toEqual({ items: ["fresh"] })
    // Kept for the page view: the second read sends nothing.
    const before = sent.length
    await workspaceRead(shell, "/items")
    expect(sent.length).toBe(before)
  })

  it("refuse with nothing sent once another tab signs out, and say which workspace this tab shows", async () => {
    const shell = new ShellState(PERSONAL)
    setCallGuard((path) => (path === "/api/auth/signout" ? null : shell.refusal()))
    expect(shell.receive(parseShellMessage({ kind: "signed-out", origin: ORIGIN }))).toBe(true)
    const failure = await refusal(workspaceApi(shell, "/items", { change: true }))
    expect(failure.body).toEqual(staleRefusal(PERSONAL, "signed-out"))
    expect(failure.body.message).toContain("Personal (alex) at https://app.mehen.dev")
    // Account-level calls from this tab are refused too; sign-out is not.
    expect((await refusal(api("/api/stepup", { action: {} }))).status).toBe(STALE_TAB_STATUS)
    expect(sent).toEqual([])
    await api("/api/auth/signout", {})
    expect(sent.map((s) => s.url)).toEqual(["/api/auth/signout"])
  })

  it("refuse once another account signs in to the browser, and ignore the same account and other origins", async () => {
    const shell = new ShellState(PERSONAL)
    expect(shell.receive(parseShellMessage({ kind: "account", origin: ORIGIN, account: "acc_alex" }))).toBe(false)
    expect(shell.receive(parseShellMessage({ kind: "account", origin: "https://other.test", account: "acc_tom" }))).toBe(false)
    expect(shell.receive(parseShellMessage({ kind: "signed-out", origin: "https://other.test" }))).toBe(false)
    expect(shell.receive(parseShellMessage({ kind: "bogus" }))).toBe(false)
    expect(shell.stale).toBeNull()
    expect(shell.receive(parseShellMessage({ kind: "account", origin: ORIGIN, account: "acc_tom" }))).toBe(true)
    expect(shell.stale).toBe("account-changed")
    expect((await refusal(workspaceApi(shell, "/items"))).body.error).toBe("conflict")
    expect(sent).toEqual([])
  })

  it("use one channel name for every tab", () => {
    expect(SHELL_CHANNEL).toBe("mehen-shell")
  })
})

describe("the palette and shortcuts on a workspace page", () => {
  const scope = (pages: string[]): PaletteScope => ({ kind: "workspace", slug: "alex", name: "Personal", pages, reads: [] })
  const sources = {
    pending: [{ kind: "approval" as const, id: "apr_1", title: "Send mail", item: null, requestedBy: null, expiresAt: null }],
    items: [{ slug: "gmail", kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "relay", hosts: [], status: "active", updatedAt: "2026-10-27T10:00:00Z", lastUsedAt: null, policy: {} }],
    devices: null,
    projects: null,
  } as unknown as Parameters<typeof buildEntries>[0]

  it("link only under /w/<slug> and only to served pages; the docs stay the account's", () => {
    const home = buildEntries(sources, 0, scope(["home"]))
    expect(home.map((e) => e.href)).toEqual(["/docs"])
    const more = buildEntries(sources, 0, scope(["home", "credentials", "asks", "machines"]))
    expect(more.map((e) => e.href)).toEqual(["/w/alex/a/apr_1", "/w/alex/items/gmail", "/w/alex/credentials", "/w/alex/devices", "/docs"])
  })

  it("list a workspace's /pending asks from their detail views, and leave its stop views to Needs you", () => {
    const workspace = { id: "tn_Alpha123456", slug: "alex", name: "Personal" }
    const owner = { kind: "member" as const, member: "mem_1", name: "Alex" }
    const detail = { kind: "approval" as const, id: "apr_1", title: "Send mail", url: `${ORIGIN}/w/alex/a/apr_1`, item: "gmail", requestedBy: { device: "dev_1", deviceName: "office", session: null }, expiresAt: "2026-10-27T10:05:00Z", bindingCode: "ABCD" }
    const pending = [
      { workspace, owner, view: "detail" as const, detail },
      { workspace, owner, view: "stop" as const, stop: { view: "stop", id: "apr_2" } },
    ] as unknown as Parameters<typeof workspacePaletteAsks>[0]
    const asks = workspacePaletteAsks(pending)
    expect(asks).toEqual([detail])
    const entries = buildEntries({ pending: asks, items: null, devices: null, projects: null }, 0, scope(["home", "asks"]))
    expect(filterEntries(entries, "send").map((m) => [m.entry.title, m.entry.href, m.entry.action])).toEqual([["Send mail", "/w/alex/a/apr_1", "Decide"]])
  })

  it("open an adoption batch at its review page, with its count", () => {
    const detail = { kind: "adoption" as const, id: "adp_1", title: "Adopt credentials from office", url: `${ORIGIN}/w/alex/b/adp_1`, item: null, requestedBy: { device: "dev_1", deviceName: "office", session: null }, expiresAt: "2026-10-28T10:00:00Z", items: 212 }
    const entries = buildEntries({ pending: [detail], items: null, devices: null, projects: null }, 0, scope(["home", "asks"]))
    expect(entries.filter((e) => e.group === "needs").map((e) => [e.href, e.action, e.sub])).toEqual([["/w/alex/b/adp_1", "Review", "An agent on office · 212 credentials"]])
  })

  it("name each workspace page as its rail does, and reach People and Connect an agent", () => {
    const actions = buildEntries({ pending: null, items: null, devices: null, projects: null }, 0, scope(["home", "people", "connect-agent", "audit"])).filter((e) => e.group === "actions")
    expect(actions.map((e) => [e.title, e.href])).toEqual([["People", "/w/alex/people"], ["Connect an agent", "/w/alex/connect-agent"], ["Activity", "/w/alex/audit"], ["Docs", "/docs"]])
  })

  it("open a machine's own page in a workspace, and the list on the legacy vault", () => {
    const devices = [{ device: "dev_1", name: "office", backend: "secure-enclave", host: null, scope: {}, createdAt: "2026-10-27T10:00:00Z", lastSeenAt: null, revoked: false, fingerprintWords: [] }] as unknown as Parameters<typeof buildEntries>[0]["devices"]
    const href = (at?: PaletteScope) => buildEntries({ pending: null, items: null, devices, projects: null }, 0, at).filter((e) => e.group === "machines").map((e) => e.href)
    expect(href(scope(["home", "machines"]))).toEqual(["/w/alex/devices/dev_1"])
    expect(href()).toEqual(["/devices"])
  })

  it("leave the legacy palette as it was", () => {
    expect(buildEntries(sources, 0).map((e) => e.href)).toEqual(["/a/apr_1", "/items/gmail", "/credentials", "/devices", "/projects", "/connect", "/settings", "/audit", "/docs"])
  })

  it("go only to the workspace's served pages", () => {
    expect(workspaceGoPlaces("alex", ["home"])).toEqual({ h: "/w/alex/" })
    expect(workspaceGoPlaces("alex", ["home", "credentials"])).toEqual({ h: "/w/alex/", c: "/w/alex/credentials" })
  })
})

// ---------------------------------------------------------------- the browser wiring

const BOOT = { page: "workspace-home", shell: { origin: ORIGIN, account: "acc_alex", workspace: { id: "tn_Alpha123456", slug: "alex", name: "Personal" }, pages: ["home"], reads: ["/items"] } }

type FakeHost = ShellHost & { hide(persisted: boolean): void; show(persisted: boolean): void; screen: string; reloads: number; refusals: string[]; posted: unknown[]; deliver(data: unknown): void }

function fakeHost(): FakeHost {
  const hides: ((p: boolean) => void)[] = []
  const shows: ((p: boolean) => void)[] = []
  const listeners: ((event: { data: unknown }) => void)[] = []
  const host: FakeHost = {
    origin: ORIGIN,
    screen: "account A's private screen",
    reloads: 0,
    refusals: [],
    posted: [],
    channel: (): ShellChannel => ({ postMessage: (m) => host.posted.push(m), addEventListener: (_t, l) => listeners.push(l), close: () => {} }),
    onPageHide: (l) => hides.push(l),
    onPageShow: (l) => shows.push(l),
    clearScreen: () => { host.screen = "" },
    showRefusal: (e) => host.refusals.push(e.body.message),
    reload: () => { host.reloads++ },
    hide: (p) => { for (const l of hides) l(p) },
    show: (p) => { for (const l of shows) l(p) },
    deliver: (data) => { for (const l of listeners) l({ data }) },
  }
  return host
}

describe("the shell's browser wiring", () => {
  it("drops account A's cache and screen on the way into the back-forward cache, and reloads on the way back with nothing sent as account B", async () => {
    const host = fakeHost()
    const shell = initShell(BOOT, host)
    if (shell === null) throw new Error("no shell")
    expect(host.posted).toEqual([{ kind: "account", origin: ORIGIN, account: "acc_alex" }])
    reply = async () => Response.json({ privateMetadata: "account A" })
    await workspaceRead(shell, "/items")
    expect(shell.cached("/items")).toEqual({ privateMetadata: "account A" })
    // A reply still in flight when the page goes away.
    let release: (r: Response) => void = () => {}
    reply = () => new Promise<Response>((resolve) => { release = resolve })
    const late = workspaceApi(shell, "/devices")
    await Promise.resolve()
    host.hide(true)
    expect(shell.cached("/items")).toBeUndefined()
    expect(host.screen).toBe("")
    release(Response.json({ devices: ["account A"] }))
    expect((await refusal(late)).status).toBe(STALE_TAB_STATUS)
    // Meanwhile account B signs in with a membership in the same workspace;
    // the cookie is B's from here on, the boot still A's.
    const before = sent.length
    host.show(true)
    expect(host.reloads).toBe(1)
    expect((await refusal(workspaceApi(shell, "/items", { name: "x" }))).body).toEqual(staleRefusal(shell.identity, "restored"))
    expect((await refusal(api("/api/stepup", { action: {} }))).status).toBe(STALE_TAB_STATUS)
    expect((await refusal(workspaceRead(shell, "/items"))).status).toBe(STALE_TAB_STATUS)
    expect(sent.length).toBe(before)
  })

  it("sends nothing while a restored page waits for its reload, even with no pagehide first", async () => {
    const host = fakeHost()
    const shell = initShell(BOOT, host)
    if (shell === null) throw new Error("no shell")
    host.show(true)
    expect(host.screen).toBe("")
    expect(host.reloads).toBe(1)
    await refusal(workspaceApi(shell, "/items", { change: true }))
    expect(sent).toEqual([])
  })

  it("leaves an ordinary first load alone", () => {
    const host = fakeHost()
    const shell = initShell(BOOT, host)
    host.show(false)
    expect(host.reloads).toBe(0)
    expect(shell?.stale).toBeNull()
    expect(host.screen).not.toBe("")
  })

  it("shows the refusal when another tab signs out", () => {
    const host = fakeHost()
    initShell(BOOT, host)
    host.deliver({ kind: "signed-out", origin: ORIGIN })
    expect(host.refusals).toHaveLength(1)
    expect(host.refusals[0]).toContain("Personal (alex) at https://app.mehen.dev")
  })

  it("is wired to the real pagehide and pageshow events by default", () => {
    const listeners = new Map<string, (event: { persisted: boolean }) => void>()
    let reloads = 0
    const body = { cleared: false, replaceChildren: () => { body.cleared = true }, classList: { add: () => {} } }
    const fakes: Record<string, unknown> = {
      window: { addEventListener: (type: string, l: (event: { persisted: boolean }) => void) => listeners.set(type, l) },
      location: { origin: ORIGIN, reload: () => { reloads++ } },
      document: { title: "Home · Personal (alex) · Mehen", body, createElement: () => ({ textContent: "" }) },
    }
    const saved = Object.keys(fakes).map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)] as const)
    for (const [k, v] of Object.entries(fakes)) Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true })
    try {
      const shell = initShell(BOOT)
      expect([...listeners.keys()].sort()).toEqual(["pagehide", "pageshow"])
      listeners.get("pagehide")?.({ persisted: true })
      expect(shell?.stale).toBe("restored")
      expect(body.cleared).toBe(true)
      expect((fakes.document as { title: string }).title).toBe("Mehen")
      listeners.get("pageshow")?.({ persisted: true })
      expect(reloads).toBe(1)
    } finally {
      for (const [k, d] of saved) {
        if (d) Object.defineProperty(globalThis, k, d)
        else delete (globalThis as Record<string, unknown>)[k]
      }
    }
  })
})

describe("hostile workspace names in client messages", () => {
  const hostile: ShellIdentity = { ...PERSONAL, workspace: { id: "tn_Alpha123456", slug: "alex", name: "Northwind\u202e\" <b>x</b>\u0007" } }

  it("spell direction overrides and controls as markers, keeping slug and origin", () => {
    const words = workspaceWords(hostile)
    expect(words).not.toMatch(/[\u202e\u0007]/)
    expect(words).toContain("[RLO U+202E]")
    expect(words).toContain("(alex) at https://app.mehen.dev")
    for (const reason of ["signed-out", "account-changed", "restored"] as const) {
      const message = staleRefusal(hostile, reason).message
      expect(message, reason).not.toMatch(/[\u202a-\u202e\u2066-\u2069\u0000-\u001f]/)
      expect(message, reason).toContain("[RLO U+202E]")
    }
  })
})
