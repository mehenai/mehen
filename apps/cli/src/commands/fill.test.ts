// mehen fill and vault_fill end to end: the real binary, a fake browser
// (testing/fake-cdp.ts) and the mock vault, which seals the value under the
// jti of the proof the CLI actually sent.

import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { type FillRequest, fillSealContext } from "@mehen/protocol/fill"
import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { CHECK_FIELD, RESOLVE_FIELD } from "../browser/page-check.ts"
import { FakeCdp } from "../testing/fake-cdp.ts"
import { MOCK_TENANT, MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { cdpSource, fillSummary, fillTarget } from "./fill.ts"

const VALUE = "s3ntinel-Value-7Q"
const LOGIN = "https://login.example.com"
const ITEM_ID = "itm_mockfill"

let vault: MockVault
let browser: FakeCdp
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>
let typed: unknown[]

beforeAll(() => {
  vault = new MockVault()
  browser = new FakeCdp()
})
afterAll(() => {
  vault.stop()
  browser.stop()
})
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  browser.calls.length = 0
  typed = []
  browser
    .on("Target.getTargets", () => ({ targetInfos: [{ targetId: "T1", type: "page", url: `${LOGIN}/session` }] }))
    .on("Target.attachToTarget", () => ({ sessionId: "S1" }))
    .on("Target.getTargetInfo", () => ({ targetInfo: { targetId: "T1", type: "page", url: `${LOGIN}/session` } }))
    .on("Page.getFrameTree", () => ({ frameTree: { frame: { id: "F1", url: `${LOGIN}/session`, securityOrigin: LOGIN } } }))
    .on("Page.createIsolatedWorld", () => ({ executionContextId: 1 }))
    .on("Runtime.callFunctionOn", (call) => {
      if (call.params.functionDeclaration === RESOLVE_FIELD) return { result: { type: "object", subtype: "node", objectId: "field" } }
      if (call.params.functionDeclaration === CHECK_FIELD) {
        const value = (call.params.arguments as { value: unknown }[])[4]?.value
        if (typeof value !== "string") return { result: { type: "object", value: { code: "ok" } } }
        typed.push(value)
        return { result: { type: "object", value: { code: "typed" } } }
      }
      return { result: { type: "boolean", value: true } }
    })
})
afterEach(async () => dir.remove())

// The vault's answer, sealed as F2's vault seals it: to the request's key,
// under this workspace, the item's id and the proof's jti.
function vaultFills(): FillRequest[] {
  const asked: FillRequest[] = []
  vault.overrides.set("POST /v1/fill", async (_request, seen) => {
    const body = JSON.parse(seen.body) as FillRequest
    asked.push(body)
    const box = await seal(await importSealPublicKey(body.recipient), VALUE, fillSealContext({ workspace: MOCK_TENANT, item: ITEM_ID, field: body.field, origin: body.origin, jti: seen.claims.jti }))
    return Response.json({ box, item: ITEM_ID, field: body.field, input: "password", label: "the password for alex@example.com", origin: body.origin, by: { free: true } })
  })
  return asked
}

function noValue(result: JvResult): void {
  expect(result.stdout).not.toContain(VALUE)
  expect(result.stderr).not.toContain(VALUE)
}

describe("mehen fill", () => {
  test("types the value the vault sealed to this fill's own key and proof, and prints only what went where", async () => {
    await vault.enrolSoftware(dir.path)
    const asked = vaultFills()
    const human = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--project", "prj_3kQ9vXyZ7", "--env", "prod"], env)
    expect(human.stderr).toBe("")
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).toBe(`mehen: typed the password for alex@example.com into ${LOGIN}/session\n`)
    noValue(human)
    expect(typed).toEqual([VALUE])
    expect(asked[0]).toMatchObject({ item: "github-alex", field: "password", origin: LOGIN, page: "/session", context: { project: "prj_3kQ9vXyZ7", environment: "prod" } })
    const json = await runJv(["fill", "github-alex#password", "--cdp", browser.httpUrl, "--selector", "#pw", "--json"], env)
    expect(json.code).toBe(EXIT.ok)
    expect(JSON.parse(json.stdout)).toEqual({ typed: true, label: "the password for alex@example.com", origin: LOGIN, page: "/session", submitted: false, navigatedTo: null, cleared: false })
    noValue(json)
  })

  test("an approval answer exits 3 with the link and the ask, as mehen fetch does, and types nothing", async () => {
    await vault.enrolSoftware(dir.path)
    const link = `${vault.url}/w/mock-space/a/apr_1`
    vault.overrides.set("POST /v1/fill", () => vaultError("approval_required", "Alex must approve typing into https://login.example.com.", { next: { url: link, command: "mehen wait apr_1", say: "Ask the human." }, approval: "apr_1", bindingCode: "K7Q2" }))
    const result = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--json"], env)
    expect(result.code).toBe(EXIT.approval)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "approval_required", approval: "apr_1", ask: { kind: "approval", id: "apr_1", url: link } })
    const human = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw"], env)
    expect(human.code).toBe(EXIT.approval)
    expect(human.stderr).toContain(link)
    expect(typed).toEqual([])
  })

  test("a refusal in the page exits with its own code before the vault is asked", async () => {
    await vault.enrolSoftware(dir.path)
    const asked = vaultFills()
    browser.on("Page.getFrameTree", () => ({ frameTree: { frame: { id: "F1", url: "http://login.example.com/", securityOrigin: "http://login.example.com" } } }))
    const result = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "origin_mismatch" })
    expect(asked).toEqual([])
  })

  test("a field that changed under the typing is page_changed, and the value is in neither stream", async () => {
    await vault.enrolSoftware(dir.path)
    vaultFills()
    browser.on("Runtime.callFunctionOn", (call) => {
      if (call.params.functionDeclaration === RESOLVE_FIELD) return { result: { type: "object", subtype: "node", objectId: "field" } }
      const value = (call.params.arguments as { value: unknown }[] | undefined)?.[4]?.value
      if (typeof value === "string") typed.push(value)
      return { result: { type: "object", value: typeof value === "string" ? { code: "page_changed", reason: "the field is no longer in the page" } : { code: "ok" } } }
    })
    for (const json of [true, false]) {
      const result = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", ...(json ? ["--json"] : [])], env)
      expect(result.code).toBe(EXIT.transient)
      if (json) expect(JSON.parse(result.stdout)).toMatchObject({ error: "page_changed" })
      else expect(result.stderr).toContain("The page changed under mehen")
      noValue(result)
    }
    expect(typed).toEqual([VALUE, VALUE])
  })

  test("--submit on a page that does not go anywhere is not_submitted, with the field emptied, and the value is in neither stream", async () => {
    await vault.enrolSoftware(dir.path)
    vaultFills()
    const result = await runJv(["fill", "github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--submit", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(JSON.parse(result.stdout)).toMatchObject({ error: "not_submitted", cleared: true })
    noValue(result)
    expect(typed).toEqual([VALUE])
  }, 20_000)

  test("argument mistakes are usage errors that touch neither the browser nor the vault", async () => {
    await vault.enrolSoftware(dir.path)
    const before = vault.seen.length
    for (const args of [
      ["github-alex", "--cdp", browser.wsUrl, "--selector", "#pw"],
      ["github-alex#password", "--selector", "#pw"],
      ["github-alex#password", "--cdp", browser.wsUrl, "--user-data-dir", dir.path, "--selector", "#pw"],
      ["github-alex#password", "--cdp", browser.wsUrl],
      ["github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--approval", "nope"],
      ["github-alex#password", "--cdp", browser.wsUrl, "--selector", "#pw", "--project", "prj_3kQ9vXyZ7"],
    ]) {
      const result = await runJv(["fill", ...args, "--json"], env)
      expect({ args, code: result.code, error: JSON.parse(result.stdout).error }).toEqual({ args, code: EXIT.usage, error: "usage" })
    }
    expect(vault.seen.length).toBe(before)
    expect(browser.calls).toEqual([])
  })
})

describe("vault_fill", () => {
  const callFill = (args: Record<string, unknown>) => runJv(["mcp", "--toolsets", "all"], env, `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vault_fill", arguments: args } })}\n`)
  const reply = (result: JvResult) => (JSON.parse(result.stdout.trim().split("\n").at(-1) as string) as { result: { structuredContent: Record<string, unknown>; isError?: boolean } }).result

  test("returns what was typed where, never the value", async () => {
    await vault.enrolSoftware(dir.path)
    vaultFills()
    const result = await callFill({ item: "github-alex", field: "password", cdp: browser.wsUrl, selector: "#pw" })
    expect(reply(result).structuredContent).toEqual({ typed: true, label: "the password for alex@example.com", origin: LOGIN, page: "/session", submitted: false, navigatedTo: null, cleared: false })
    noValue(result)
    expect(typed).toEqual([VALUE])
  })

  test("an approval answer is an error carrying the ask", async () => {
    await vault.enrolSoftware(dir.path)
    const link = `${vault.url}/w/mock-space/a/apr_1`
    vault.overrides.set("POST /v1/fill", () => vaultError("approval_required", "Alex must approve.", { next: { url: link, command: "mehen wait apr_1", say: "Ask the human." }, approval: "apr_1", bindingCode: "K7Q2" }))
    const answer = reply(await callFill({ item: "github-alex", field: "password", cdp: browser.wsUrl, selector: "#pw" }))
    expect(answer.isError).toBe(true)
    expect(answer.structuredContent).toMatchObject({ error: "approval_required", ask: { kind: "approval", id: "apr_1", url: link } })
  })
})

test("fillTarget, cdpSource and fillSummary", () => {
  expect(fillTarget("github-alex#totp", "h")).toEqual({ item: "github-alex", field: "totp" })
  for (const bad of ["github-alex", "#password", "github-alex#", "a#b#c"]) expect(() => fillTarget(bad, "h")).toThrow("<item>#<field>")
  expect(cdpSource("ws://127.0.0.1:1/devtools/browser/x", null, "h")).toEqual({ cdp: "ws://127.0.0.1:1/devtools/browser/x" })
  expect(cdpSource(null, "/tmp/p", "h")).toEqual({ userDataDir: "/tmp/p" })
  expect(() => cdpSource(null, null, "h")).toThrow("one of them")
  const result = { typed: true as const, label: "the password for alex@example.com", origin: LOGIN, page: "/login", submitted: true, navigatedTo: `${LOGIN}/home`, cleared: false }
  expect(fillSummary(result)).toBe(`mehen: typed the password for alex@example.com into ${LOGIN}/login and submitted it; the page went to ${LOGIN}/home`)
})
