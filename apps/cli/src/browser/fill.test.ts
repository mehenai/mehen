// mehen fill's flow against a fake DevTools endpoint: which origin it asks
// for, what it refuses before asking, and how it opens the vault's answer.
// The checks inside a real page are page-check.chrome.test.ts's.

import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { type FillRequest, fillSealContext } from "@mehen/protocol/fill"
import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { CliError } from "../errors.ts"
import { errorJson } from "../output.ts"
import { type CdpCall, type CdpHandler, FakeCdp } from "../testing/fake-cdp.ts"
import type { VaultApi, VaultRequestOptions } from "../vault-api.ts"
import { type FillOptions, fill, pagePath } from "./fill.ts"
import { BEFORE_ENTER, CHECK_FIELD, CLEAR_FIELD, RESOLVE_FIELD } from "./page-check.ts"

const VALUE = "s3ntinel-Value-7Q"
const WORKSPACE = "tn_FillTest12345"
const ITEM = "itm_filltest"
const LOGIN = "https://login.example.com"

type Frame = { id: string; parentId?: string; url: string; securityOrigin: string; field?: boolean }

let fake: FakeCdp
// The page as the fake browser reports it.
let top: string
let frames: Frame[]
let verdicts: { check: Record<string, unknown>; typed: Record<string, unknown> | "drop"; beforeEnter: Record<string, unknown> }
let typedValues: unknown[]
// Runs once the value is typed, to change the page the browser reports.
let afterTyping: (() => void) | null

beforeAll(() => {
  fake = new FakeCdp()
})
afterAll(() => fake.stop())

const argsOf = (call: CdpCall) => (call.params.arguments as { value: unknown }[]).map((arg) => arg.value)

beforeEach(() => {
  fake.calls.length = 0
  fake.handlers.clear()
  top = `${LOGIN}/session`
  frames = [{ id: "F1", url: `${LOGIN}/session?return_to=x`, securityOrigin: LOGIN, field: true }]
  verdicts = { check: { code: "ok" }, typed: { code: "typed" }, beforeEnter: { code: "ok" } }
  typedValues = []
  afterTyping = null
  fake
    .on("Target.getTargets", () => ({ targetInfos: [{ targetId: "T1", type: "page", url: top }] }))
    .on("Target.attachToTarget", () => ({ sessionId: "S1" }))
    .on("Target.getTargetInfo", () => ({ targetInfo: { targetId: "T1", type: "page", url: top } }))
    .on("Page.getFrameTree", () => {
      const node = (frame: Frame): Record<string, unknown> => ({ frame: { id: frame.id, ...(frame.parentId ? { parentId: frame.parentId } : {}), url: frame.url, securityOrigin: frame.securityOrigin }, childFrames: frames.filter((f) => f.parentId === frame.id).map(node) })
      return { frameTree: node(frames.find((frame) => !frame.parentId) as Frame) }
    })
    .on("Page.createIsolatedWorld", (call) => ({ executionContextId: Number(String(call.params.frameId).slice(1)) }))
    .on("Runtime.callFunctionOn", (call) => {
      const fn = call.params.functionDeclaration
      if (fn === RESOLVE_FIELD) {
        const frame = frames.find((f) => f.id === `F${call.params.executionContextId}`)
        return frame?.field ? { result: { type: "object", subtype: "node", objectId: `field-in-${frame.id}` } } : { result: { type: "string", value: "none" } }
      }
      if (fn === CHECK_FIELD) {
        const value = argsOf(call)[4]
        if (typeof value !== "string") return { result: { type: "object", value: verdicts.check } }
        typedValues.push(value)
        afterTyping?.()
        if (verdicts.typed === "drop") {
          fake.dropConnection()
          return "silent"
        }
        return { result: { type: "object", value: verdicts.typed } }
      }
      if (fn === BEFORE_ENTER) return { result: { type: "object", value: verdicts.beforeEnter } }
      if (fn === CLEAR_FIELD) return { result: { type: "boolean", value: true } }
      return { result: { type: "boolean", value: true } }
    })
})

type Answer = { item?: string; field?: string; origin?: string; input?: string; sealItem?: string; sealJti?: string; validUntil?: string }

// The vault's side: seals VALUE to the request's key under the context the
// CLI must build, unless a test bends one part of the answer or the seal.
function vaultOf(asked: FillRequest[], answer: (n: number) => Answer = () => ({})): VaultApi {
  return {
    async request<T>(_method: string, _path: string, body?: unknown, options?: VaultRequestOptions): Promise<T> {
      const request = body as FillRequest
      asked.push(request)
      const n = asked.length
      const jti = `jti_${n}`
      options?.onProof?.(jti)
      const bent = answer(n)
      const box = await seal(await importSealPublicKey(request.recipient), VALUE, fillSealContext({ workspace: WORKSPACE, item: bent.sealItem ?? ITEM, field: request.field, origin: request.origin, jti: bent.sealJti ?? jti }))
      return {
        box,
        item: bent.item ?? ITEM,
        field: bent.field ?? request.field,
        input: bent.input ?? (request.field === "totp" ? "one-time-code" : "password"),
        label: "the password for alex@example.com",
        origin: bent.origin ?? request.origin,
        by: { free: true },
        ...(bent.validUntil ? { validUntil: bent.validUntil } : {}),
      } as T
    },
    relay: async () => new Response(),
  }
}

function options(extra: Partial<FillOptions> = {}): FillOptions {
  return { item: "github-alex", field: "password", selector: "#pw", submit: false, source: { cdp: fake.wsUrl }, target: null, context: null, approval: null, help: "mehen fill --help", ...extra }
}

async function refusal(promise: Promise<unknown>): Promise<CliError> {
  const error = await promise.then(() => null, (e: unknown) => e)
  if (!(error instanceof CliError)) throw new Error(`expected a refusal, got ${error instanceof Error ? error.stack : JSON.stringify(error)}`)
  expect(JSON.stringify({ message: error.message, next: error.next, extras: error.extras })).not.toContain(VALUE)
  expect(Bun.inspect(error)).not.toContain(VALUE)
  expect(Bun.inspect(error.cause ?? null)).not.toContain(VALUE)
  expect(JSON.stringify(errorJson(error))).not.toContain(VALUE)
  return error
}

const depsOf = (api: VaultApi, extra: Record<string, unknown> = {}) => ({ vault: async () => ({ api, workspace: WORKSPACE }), ...extra })

describe("mehen fill's origin, before the vault is asked", () => {
  test("asks for the field frame's own origin and the page's path without its query", async () => {
    const asked: FillRequest[] = []
    const result = await fill(options({ context: { project: "prj_1", environment: "dev" }, approval: "apr_1" }), depsOf(vaultOf(asked)))
    expect(result).toEqual({ typed: true, label: "the password for alex@example.com", origin: LOGIN, page: "/session", submitted: false, navigatedTo: null, cleared: false })
    expect(JSON.stringify(result)).not.toContain(VALUE)
    expect(asked).toHaveLength(1)
    expect(asked[0]).toMatchObject({ item: "github-alex", field: "password", origin: LOGIN, page: "/session", context: { project: "prj_1", environment: "dev" }, approval: "apr_1" })
    expect(typedValues).toEqual([VALUE])
  })

  test("accepts a frame nested in frames of its own origin", async () => {
    frames = [
      { id: "F1", url: `${LOGIN}/`, securityOrigin: LOGIN },
      { id: "F2", parentId: "F1", url: `${LOGIN}/inner/form`, securityOrigin: LOGIN, field: true },
    ]
    const asked: FillRequest[] = []
    expect(await fill(options(), depsOf(vaultOf(asked)))).toMatchObject({ origin: LOGIN, page: "/inner/form" })
    const check = fake.calls.find((call) => call.params.functionDeclaration === CHECK_FIELD) as CdpCall
    expect(argsOf(check).slice(0, 4)).toEqual(["#pw", LOGIN, [LOGIN], "password"])
  })

  test("refuses a frame inside a parent of another origin", async () => {
    frames = [
      { id: "F1", url: "https://news.example.org/", securityOrigin: "https://news.example.org" },
      { id: "F2", parentId: "F1", url: `${LOGIN}/inner`, securityOrigin: LOGIN, field: true },
    ]
    top = "https://news.example.org/"
    const asked: FillRequest[] = []
    expect((await refusal(fill(options(), depsOf(vaultOf(asked))))).code).toBe("frame_origin_mismatch")
    expect(asked).toEqual([])
  })

  test("refuses a field of the page's own origin inside a frame of another origin, though the top-level address and the frame's own check agree", async () => {
    frames = [
      { id: "F1", url: `${LOGIN}/`, securityOrigin: LOGIN },
      { id: "F2", parentId: "F1", url: "https://other.example/embed", securityOrigin: "https://other.example" },
      { id: "F3", parentId: "F2", url: `${LOGIN}/inner`, securityOrigin: LOGIN, field: true },
    ]
    const asked: FillRequest[] = []
    const error = await refusal(fill(options(), depsOf(vaultOf(asked))))
    expect(error.code).toBe("frame_origin_mismatch")
    expect(error.message).toContain("inside a page of another origin")
    expect(asked).toEqual([])
  })

  test("refuses a frame the browser lists with a null ancestor", async () => {
    frames = [
      { id: "F1", url: `${LOGIN}/`, securityOrigin: "null" },
      { id: "F2", parentId: "F1", url: `${LOGIN}/inner`, securityOrigin: LOGIN, field: true },
    ]
    const asked: FillRequest[] = []
    expect((await refusal(fill(options(), depsOf(vaultOf(asked))))).code).toBe("frame_origin_mismatch")
    expect(asked).toEqual([])
  })

  test("refuses when the page's top-level address differs from the field's origin", async () => {
    top = "https://evil.example.net/login"
    const asked: FillRequest[] = []
    expect((await refusal(fill(options(), depsOf(vaultOf(asked))))).code).toBe("frame_origin_mismatch")
    expect(asked).toEqual([])
  })

  test("refuses when the frame's own check finds the browser and the page disagree", async () => {
    verdicts.check = { code: "frame_origin_mismatch", reason: "the browser and the page disagree about the frame's ancestors" }
    const asked: FillRequest[] = []
    const error = await refusal(fill(options(), depsOf(vaultOf(asked))))
    expect(error.code).toBe("frame_origin_mismatch")
    expect(error.message).toContain("disagree")
    expect(asked).toEqual([])
  })

  test("refuses a page that is not https or has an IP address for a host", async () => {
    for (const origin of ["http://login.example.com", "https://127.0.0.1:8443", "https://[::1]"]) {
      frames = [{ id: "F1", url: `${origin}/`, securityOrigin: origin, field: true }]
      top = `${origin}/`
      const asked: FillRequest[] = []
      expect({ origin, code: (await refusal(fill(options(), depsOf(vaultOf(asked))))).code }).toEqual({ origin, code: "origin_mismatch" })
      expect(asked).toEqual([])
    }
  })

  test("refuses a field the check turns down, before asking", async () => {
    verdicts.check = { code: "field_kind_mismatch", reason: "it is an input of type text" }
    const asked: FillRequest[] = []
    expect((await refusal(fill(options(), depsOf(vaultOf(asked))))).code).toBe("field_kind_mismatch")
    expect(asked).toEqual([])
  })

  test("refuses a field no frame has, and one two frames have", async () => {
    frames = [{ id: "F1", url: `${LOGIN}/`, securityOrigin: LOGIN }]
    expect((await refusal(fill(options(), depsOf(vaultOf([]))))).code).toBe("field_not_found")
    frames = [
      { id: "F1", url: `${LOGIN}/`, securityOrigin: LOGIN, field: true },
      { id: "F2", parentId: "F1", url: `${LOGIN}/inner`, securityOrigin: LOGIN, field: true },
    ]
    expect((await refusal(fill(options(), depsOf(vaultOf([]))))).code).toBe("field_ambiguous")
  })

  test("refuses a field no credential has, or an item name that is not one, without the browser", async () => {
    let opened = false
    const deps = { vault: async () => ((opened = true), { api: vaultOf([]), workspace: WORKSPACE }) }
    expect((await refusal(fill(options({ field: "pin" }), deps))).code).toBe("usage")
    expect((await refusal(fill(options({ item: "Not A Slug" }), deps))).code).toBe("usage")
    expect((await refusal(fill(options({ selector: "#a >>> " }), deps))).code).toBe("usage")
    expect((await refusal(fill(options({ approval: "pol_123" }), deps))).code).toBe("usage")
    expect(opened).toBe(false)
    expect(fake.calls).toEqual([])
  })
})

describe("opening the vault's answer", () => {
  const typedNothing = () => expect(typedValues).toEqual([])

  test("an answer for another field, origin or kind of field is dropped and nothing is typed", async () => {
    for (const bent of [{ field: "username" }, { origin: "https://other.example.com" }, { input: "secret" }]) {
      const error = await refusal(fill(options(), depsOf(vaultOf([], () => bent))))
      expect({ bent, code: error.code }).toEqual({ bent, code: "internal" })
    }
    typedNothing()
  })

  test("a box sealed for another item, or under another proof, does not open and nothing is typed", async () => {
    for (const bent of [{ item: "itm_another" }, { sealItem: "itm_another" }, { sealJti: "jti_other" }]) {
      const error = await refusal(fill(options(), depsOf(vaultOf([], () => bent))))
      expect({ bent, code: error.code }).toEqual({ bent, code: "internal" })
    }
    typedNothing()
  })

  test("an answer that is not a fill answer is dropped", async () => {
    const api: VaultApi = { request: async <T>() => ({ box: "x" }) as T, relay: async () => new Response() }
    expect((await refusal(fill(options(), depsOf(api)))).code).toBe("internal")
    typedNothing()
  })

  test("a field that changed between the check and the typing, with the value in hand, is page_changed and the value is in no part of the error", async () => {
    verdicts.typed = { code: "page_changed", reason: "the selector no longer names the same field" }
    const error = await refusal(fill(options(), depsOf(vaultOf([]))))
    expect(error.code).toBe("page_changed")
    expect(typedValues).toEqual([VALUE])
  })

  test("a browser that drops the connection while it holds the value is cdp_unreachable and the value is in no part of the error", async () => {
    verdicts.typed = "drop"
    const error = await refusal(fill(options(), depsOf(vaultOf([]))))
    expect(error.code).toBe("cdp_unreachable")
    expect(typedValues).toEqual([VALUE])
  })

  test("a one-time code about to expire is fetched again and opened under the new request's proof", async () => {
    let clock = Date.parse("2026-11-06T10:00:00Z")
    const asked: FillRequest[] = []
    const slept: number[] = []
    const api = vaultOf(asked, (n) => (n === 1 ? { validUntil: new Date(clock + 1_000).toISOString() } : { validUntil: new Date(clock + 30_000).toISOString() }))
    const deps = depsOf(api, { now: () => clock, sleep: async (ms: number) => void (slept.push(ms), (clock += ms)) })
    await fill(options({ field: "totp" }), deps)
    expect(asked).toHaveLength(2)
    expect(slept).toEqual([1_250])
    expect(typedValues).toEqual([VALUE])
  })
})

describe("--submit", () => {
  test("presses a trusted Enter after checking the page again, and reports where it went", async () => {
    fake.on("Input.dispatchKeyEvent", (call, self) => {
      if (call.params.type === "keyUp") setTimeout(() => self.emit("Page.frameNavigated", { frame: { id: "F1", url: `${LOGIN}/home?token=abc` } }, "S1"), 10)
      return {}
    })
    const result = await fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 2_000 }))
    expect(result).toMatchObject({ submitted: true, navigatedTo: `${LOGIN}/home`, cleared: false })
    const order = fake.calls.map((call) => (call.method === "Runtime.callFunctionOn" ? String(call.params.functionDeclaration) : call.method))
    expect(order.indexOf(BEFORE_ENTER)).toBeLessThan(order.indexOf("Input.dispatchKeyEvent"))
    expect(order.indexOf(BEFORE_ENTER)).toBeGreaterThan(order.lastIndexOf(CHECK_FIELD))
  })

  test("a page that changed before the Enter is page_changed: the field is emptied and Enter is never pressed", async () => {
    verdicts.beforeEnter = { code: "frame_origin_mismatch", reason: "the field's frame is now another origin" }
    const error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 2_000 })))
    expect(error.code).toBe("page_changed")
    expect(error.extras.cleared).toBe(true)
    expect(fake.methods()).not.toContain("Input.dispatchKeyEvent")
    expect(fake.calls.some((call) => call.params.functionDeclaration === CLEAR_FIELD)).toBe(true)
  })

  test("the browser's frame tree and page address are read again before the Enter: a change of origin since the typing is page_changed, emptied, with no Enter", async () => {
    const changes: Record<string, () => void> = {
      "an ancestor of another origin": () => {
        frames = [
          { id: "F0", url: "https://other.example/", securityOrigin: "https://other.example" },
          { id: "F1", parentId: "F0", url: `${LOGIN}/session`, securityOrigin: LOGIN, field: true },
        ]
      },
      "the field's frame on another origin": () => {
        frames = [{ id: "F1", url: "https://other.example/session", securityOrigin: "https://other.example", field: true }]
      },
      "the page's address on another origin": () => {
        top = "https://other.example/session"
      },
    }
    for (const [change, apply] of Object.entries(changes)) {
      fake.calls.length = 0
      frames = [{ id: "F1", url: `${LOGIN}/session`, securityOrigin: LOGIN, field: true }]
      top = `${LOGIN}/session`
      afterTyping = apply
      const error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 })))
      expect({ change, code: error.code, cleared: error.extras.cleared, entered: fake.methods().includes("Input.dispatchKeyEvent") }).toEqual({ change, code: "page_changed", cleared: true, entered: false })
    }
  })

  test("a page that does not go anywhere is not_submitted, with the field emptied", async () => {
    const error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 })))
    expect(error.code).toBe("not_submitted")
    expect(error.extras.cleared).toBe(true)
  })

  test("a navigation only requested after the Enter, which may still be cancelled, is not_submitted with the field emptied", async () => {
    fake.on("Input.dispatchKeyEvent", (call, self) => {
      if (call.params.type === "keyDown") self.emit("Page.frameRequestedNavigation", { frameId: "F1", reason: "formSubmissionGet", url: `${LOGIN}/done`, disposition: "currentTab" }, "S1")
      return {}
    })
    const error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 })))
    expect(error.code).toBe("not_submitted")
    expect(error.extras.cleared).toBe(true)
    expect(fake.calls.some((call) => call.params.functionDeclaration === CLEAR_FIELD)).toBe(true)
  })

  test("a change of address before the Enter, during Page.enable or the last check, does not count as the form going", async () => {
    const moved = (self: FakeCdp) => self.emit("Page.navigatedWithinDocument", { frameId: "F1", url: `${LOGIN}/session#step-2` }, "S1")
    const checks = fake.handlers.get("Runtime.callFunctionOn") as CdpHandler
    fake.on("Page.enable", (_call, self) => {
      moved(self)
      return {}
    })
    let error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 })))
    expect({ during: "Page.enable", code: error.code, cleared: error.extras.cleared }).toEqual({ during: "Page.enable", code: "not_submitted", cleared: true })
    fake.handlers.delete("Page.enable")
    fake.on("Runtime.callFunctionOn", (call, self) => {
      if (call.params.functionDeclaration === BEFORE_ENTER) moved(self)
      return checks(call, self)
    })
    error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 })))
    expect({ during: "BEFORE_ENTER", code: error.code, cleared: error.extras.cleared }).toEqual({ during: "BEFORE_ENTER", code: "not_submitted", cleared: true })
  })

  test("a browser that refuses a call or drops the connection after the typing gives page_changed before the Enter and not_submitted after it, with cleared as it is", async () => {
    const cases: { name: string; method: string; answer: CdpHandler; code: "page_changed" | "not_submitted"; cleared: boolean }[] = [
      { name: "Page.enable refused", method: "Page.enable", answer: () => ({ error: "Page domain is not available" }), code: "page_changed", cleared: true },
      { name: "the connection dropped in Page.enable", method: "Page.enable", answer: (_call, self) => (self.dropConnection(), "silent"), code: "page_changed", cleared: false },
      { name: "the Enter refused", method: "Input.dispatchKeyEvent", answer: () => ({ error: "Input domain is not available" }), code: "not_submitted", cleared: true },
      {
        name: "the connection dropped during the wait",
        method: "Input.dispatchKeyEvent",
        answer: (call, self) => {
          if (call.params.type === "keyUp") setTimeout(() => self.dropConnection(), 50)
          return {}
        },
        code: "not_submitted",
        cleared: false,
      },
    ]
    for (const { name, method, answer, code, cleared } of cases) {
      fake.handlers.delete("Page.enable")
      fake.handlers.delete("Input.dispatchKeyEvent")
      fake.on(method, answer)
      const error = await refusal(fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 1_000 })))
      expect({ name, code: error.code, cleared: error.extras.cleared }).toEqual({ name, code, cleared })
    }
  })

  test("a navigation of the page after the Enter is submitted: true", async () => {
    fake.on("Input.dispatchKeyEvent", (call, self) => {
      if (call.params.type === "keyDown") self.emit("Page.frameNavigated", { frame: { id: "F1", url: `${LOGIN}/home` } }, "S1")
      return {}
    })
    expect(await fill(options({ submit: true }), depsOf(vaultOf([]), { submitWaitMs: 300 }))).toMatchObject({ submitted: true, navigatedTo: `${LOGIN}/home`, cleared: false })
  })
})

test("pagePath keeps the path only, escaped to the request's characters and length", () => {
  expect(pagePath("https://a.example/login?next=/x#frag")).toBe("/login")
  expect(pagePath("https://a.example")).toBe("/")
  expect(pagePath("https://a.example/a b/<c>")).toBe("/a%20b/%3Cc%3E")
  expect(pagePath(`https://a.example/${"x".repeat(600)}`)).toHaveLength(512)
  expect(pagePath("not a url")).toBe("/")
})
