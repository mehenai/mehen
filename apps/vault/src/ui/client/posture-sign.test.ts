// Save with passkey on the How careful card (posture-sign.ts), driven with
// a fake fetch and a fake passkey: the posture each choice stores, what
// counts as nothing to save, and one signed item.posture whose digest the
// page computed itself; a vault action with any other digest is refused
// before the step-up starts.

import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { VaultFailure } from "./api.ts"
import { type PostureShown, chosenPosture, itemPostureAction, postureUnchanged, savePosture } from "./posture-sign.ts"
import { ShellState } from "./shell-logic.ts"
import { CHANGED_SINCE_SHOWN } from "./workspace-logic.ts"
import type { Passkey } from "./workspace-sign.ts"

const WORKSPACE = { id: "tn_work", slug: "northwind", name: "Northwind" }
const API = "/api/w/northwind/items/cloudflare-prod"
const STEPUP = { nonce: "n", options: { challenge: "c", allowCredentials: [] } }

type Call = { path: string; body: unknown }
// Answers by path; records every call the page sends.
function vault(answers: Record<string, unknown>): { calls: Call[]; paths: () => string[] } {
  const calls: Call[] = []
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const path = String(input)
    calls.push({ path, body: init?.body === undefined ? undefined : JSON.parse(String(init.body)) })
    const answer = answers[path]
    if (answer === undefined) return new Response(JSON.stringify({ error: "not_found", message: "No such route." }), { status: 404 })
    return new Response(JSON.stringify(answer), { status: 200, headers: { "content-type": "application/json" } })
  })
  return { calls, paths: () => calls.map((c) => c.path) }
}
const shell = () => new ShellState({ origin: "https://vault.test", account: "acc_alex", workspace: WORKSPACE, pages: [], reads: [] })

let passkey: Mock<Passkey>
beforeEach(() => {
  passkey = vi.fn<Passkey>(async () => ({ signed: true }))
})
afterEach(() => vi.restoreAllMocks())

// The gallery's Cloudflare token trusting alex-mbp only, at revision 2.
const TRUST: PostureShown = { item: "itm_cloudflareprod", slug: "cloudflare-prod", rev: 2, level: "trust", machines: ["dev_alexmbp0001"], catalogue: { template: "cloudflare-api-token", version: 1 }, grown: false }

describe("the posture a choice stores", () => {
  it("stores ask for Ask and Custom, with no machines, and sorts the machines ticked", () => {
    expect(chosenPosture("custom", ["dev_tomlaptop01"])).toEqual({ level: "ask", machines: null })
    expect(chosenPosture("ask", null)).toEqual({ level: "ask", machines: null })
    expect(chosenPosture("routine", null)).toEqual({ level: "routine", machines: null })
    expect(chosenPosture("trust", ["dev_tomlaptop01", "dev_alexmbp0001", "dev_tomlaptop01"])).toEqual({ level: "trust", machines: ["dev_alexmbp0001", "dev_tomlaptop01"] })
    expect(chosenPosture("trust", [])).toBeNull()
  })

  it("has nothing to save for the stored level and machines, and something once the catalogue grew", () => {
    expect(postureUnchanged(TRUST, { level: "trust", machines: ["dev_alexmbp0001"] })).toBe(true)
    expect(postureUnchanged(TRUST, { level: "trust", machines: null })).toBe(false)
    expect(postureUnchanged(TRUST, { level: "ask", machines: null })).toBe(false)
    expect(postureUnchanged({ ...TRUST, grown: true }, { level: "trust", machines: ["dev_alexmbp0001"] })).toBe(false)
    const ask: PostureShown = { ...TRUST, level: "ask", machines: null, rev: 0 }
    expect(postureUnchanged(ask, chosenPosture("custom", null)!)).toBe(true)
  })

  it("digests the posture, the current catalogue and the revision shown, as itemPostureDigest does", async () => {
    expect(await itemPostureAction(TRUST, { level: "ask", machines: null })).toEqual({ type: "item.posture", item: "itm_cloudflareprod", digest: "QWCzTyrbHwDFShXFQ8NTeHe2MObH2GWMsYlSfAPq4-Q", level: "ask" })
    const ask: PostureShown = { ...TRUST, level: "ask", machines: null, rev: 0 }
    expect((await itemPostureAction(ask, { level: "routine", machines: ["dev_alexmbp0001", "dev_tomlaptop01"] })).digest).toBe("jN6k944RLJYg9noHTW8W4RdJiMlno-9zTQdzKhukg-Q")
  })
})

describe("savePosture", () => {
  it("Trust to Custom signs one item.posture at level ask", async () => {
    const action = { type: "item.posture", item: TRUST.item, digest: "QWCzTyrbHwDFShXFQ8NTeHe2MObH2GWMsYlSfAPq4-Q", level: "ask" }
    const v = vault({ [`${API}/action`]: action, "/api/w/northwind": WORKSPACE, "/api/w/northwind/stepup/start": STEPUP, [`${API}/posture`]: { level: "ask" } })
    await savePosture(shell(), TRUST, chosenPosture("custom", null)!, passkey)
    const terms = { posture: { level: "ask", machines: null }, rev: 2 }
    expect(v.calls).toEqual([
      { path: `${API}/action`, body: { action: "posture", ...terms } },
      { path: "/api/w/northwind", body: undefined },
      { path: "/api/w/northwind/stepup/start", body: { action } },
      { path: `${API}/posture`, body: { ...terms, stepUp: { nonce: "n", assertion: { signed: true } } } },
    ])
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("refuses a vault action with another digest before the step-up starts", async () => {
    const v = vault({ [`${API}/action`]: { type: "item.posture", item: TRUST.item, digest: "other", level: "ask" } })
    const refused = await savePosture(shell(), TRUST, { level: "ask", machines: null }, passkey).catch((e: unknown) => (e instanceof VaultFailure ? e.body : e))
    expect(refused).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.paths()).toEqual([`${API}/action`])
    expect(passkey).not.toHaveBeenCalled()
  })
})
