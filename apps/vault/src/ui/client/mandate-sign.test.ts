// The mandate pages' flows (mandate-sign.ts), driven with a fake fetch and
// a fake passkey: the terms each form choice builds and what it refuses
// in plain words, one signed mandate.sign whose digest the page computed
// itself, refused before the step-up for any other, a resume that asks the
// vault whether it needs a passkey, and pause and stop with the revision
// shown and no passkey.

import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { MANDATE_CAP_DEFAULTS, type MandateTerms } from "@mehen/protocol/mandate-terms"
import { mandateDigest } from "@mehen/protocol/mandates"
import { MANDATE_BAD_CAPS, MANDATE_BAD_SCHEDULE, MANDATE_NO_NOTE, MANDATE_NOTHING_TICKED } from "../wording.ts"
import { VaultFailure } from "./api.ts"
import { type MandateFormChoice, changeMandate, mandateSignAction, mandateTermsOf, pauseMandates, resumeMandate, resumeNeedsPasskey, signMandate } from "./mandate-sign.ts"
import { ShellState } from "./shell-logic.ts"
import { CHANGED_SINCE_SHOWN } from "./workspace-logic.ts"
import type { Passkey } from "./workspace-sign.ts"

const WORKSPACE = { id: "tn_work", slug: "northwind", name: "Northwind" }
const API = "/api/w/northwind"
const STEPUP = { nonce: "n", options: { challenge: "c", allowCredentials: [] } }
const DEVICE = "dev_alexmbp0001"
const SIGNER = "mem_alex0001"
const MANDATE = "mdt_alexmbp0000000001"

type Call = { path: string; body: unknown }
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
const refusal = (e: unknown) => (e instanceof VaultFailure ? e.body : e)

let passkey: Mock<Passkey>
beforeEach(() => {
  passkey = vi.fn<Passkey>(async () => ({ signed: true }))
})
afterEach(() => vi.restoreAllMocks())

const CHOICE: MandateFormChoice = { classes: ["send", "change"], caps: { ...MANDATE_CAP_DEFAULTS }, items: ["itm_slack0000000001", "itm_github000000001", "itm_slack0000000001"], ttlDays: 90, schedule: null, note: "Weekly chores" }

describe("the terms a form choice builds", () => {
  it("always includes read, sorts the classes and credentials, zeroes the caps of classes not ticked and trims the note", () => {
    expect(mandateTermsOf(DEVICE, { ...CHOICE, note: "  Weekly chores " })).toEqual({ terms: {
      device: DEVICE, items: ["itm_github000000001", "itm_slack0000000001"], classes: ["change", "read", "send"],
      caps: { read: 5000, change: 2000, send: 50, delete: 0 }, ttlDays: 90, schedule: null, note: "Weekly chores",
    } })
    expect(mandateTermsOf(DEVICE, { ...CHOICE, items: "all" })).toMatchObject({ terms: { items: "all" } })
  })

  it("sorts each window's days and keeps the zone", () => {
    const built = mandateTermsOf(DEVICE, { ...CHOICE, schedule: { tz: "Europe/London", windows: [{ days: [5, 1, 3], from: "22:00", to: "06:00" }] } })
    expect(built).toMatchObject({ terms: { schedule: { tz: "Europe/London", windows: [{ days: [1, 3, 5], from: "22:00", to: "06:00" }] } } })
  })

  it("refuses, in the page's words, nothing ticked, no note, a cap out of bounds and a schedule that cannot hold", () => {
    expect(mandateTermsOf(DEVICE, { ...CHOICE, items: [] })).toEqual({ refusal: MANDATE_NOTHING_TICKED })
    expect(mandateTermsOf(DEVICE, { ...CHOICE, note: "   " })).toEqual({ refusal: MANDATE_NO_NOTE })
    expect(mandateTermsOf(DEVICE, { ...CHOICE, caps: { ...CHOICE.caps, send: 501 } })).toEqual({ refusal: MANDATE_BAD_CAPS })
    expect(mandateTermsOf(DEVICE, { ...CHOICE, caps: { ...CHOICE.caps, send: 0 } })).toEqual({ refusal: MANDATE_BAD_CAPS })
    expect(mandateTermsOf(DEVICE, { ...CHOICE, caps: { ...CHOICE.caps, send: 2.5 } })).toEqual({ refusal: MANDATE_BAD_CAPS })
    // A class not ticked keeps no cap, whatever was typed for it.
    expect(mandateTermsOf(DEVICE, { ...CHOICE, caps: { ...CHOICE.caps, delete: 99_999 } })).toMatchObject({ terms: { caps: { delete: 0 } } })
    for (const schedule of [{ tz: "Mars/Olympus", windows: [{ days: [1], from: "09:00", to: "17:00" }] }, { tz: "Europe/London", windows: [{ days: [], from: "09:00", to: "17:00" }] }, { tz: "Europe/London", windows: [{ days: [1], from: "09:00", to: "09:00" }] }, { tz: "Europe/London", windows: [{ days: [1], from: "", to: "17:00" }] }]) {
      expect(mandateTermsOf(DEVICE, { ...CHOICE, schedule })).toEqual({ refusal: MANDATE_BAD_SCHEDULE })
    }
  })
})

const TERMS = (mandateTermsOf(DEVICE, CHOICE) as { terms: MandateTerms }).terms

describe("signMandate", () => {
  it("signs one mandate.sign over the digest the page computed, naming a proposal when it came from one", async () => {
    const action = await mandateSignAction(WORKSPACE.id, SIGNER, TERMS)
    expect(action).toEqual({ type: "mandate.sign", device: DEVICE, digest: await mandateDigest({ terms: TERMS, workspace: WORKSPACE.id, signer: SIGNER }) })
    const v = vault({ [`${API}/mandates/action`]: action, [API]: WORKSPACE, [`${API}/stepup/start`]: STEPUP, [`${API}/mandates`]: { mandate: { id: MANDATE } } })
    await signMandate(shell(), { signer: SIGNER, proposal: "mdp_proposal000000001" }, TERMS, passkey)
    expect(v.calls).toEqual([
      { path: `${API}/mandates/action`, body: { op: "sign", terms: TERMS, proposal: "mdp_proposal000000001" } },
      { path: API, body: undefined },
      { path: `${API}/stepup/start`, body: { action } },
      { path: `${API}/mandates`, body: { terms: TERMS, proposal: "mdp_proposal000000001", stepUp: { nonce: "n", assertion: { signed: true } } } },
    ])
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("refuses a vault action over other terms or for another signer before the step-up starts", async () => {
    const other = await mandateSignAction(WORKSPACE.id, "mem_kim00001", TERMS)
    const v = vault({ [`${API}/mandates/action`]: other })
    expect(await signMandate(shell(), { signer: SIGNER, proposal: null }, TERMS, passkey).catch(refusal)).toEqual(CHANGED_SINCE_SHOWN)
    expect(v.calls).toEqual([{ path: `${API}/mandates/action`, body: { op: "sign", terms: TERMS } }])
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("resumeMandate", () => {
  it("resumes at once with the revision shown when the vault needs no passkey", async () => {
    const v = vault({ [`${API}/mandates/action`]: { stepUp: null }, [`${API}/mandates/${MANDATE}/resume`]: { mandate: { id: MANDATE } } })
    await resumeMandate(shell(), MANDATE, 3, passkey)
    expect(v.calls).toEqual([
      { path: `${API}/mandates/action`, body: { op: "resume", id: MANDATE, rev: 3 } },
      { path: `${API}/mandates/${MANDATE}/resume`, body: { rev: 3 } },
    ])
    expect(passkey).not.toHaveBeenCalled()
  })

  it("runs the passkey for the vault's mandate.resume and sends it beside the revision", async () => {
    const action = { type: "mandate.resume", mandate: MANDATE, digest: "d", rev: 3, from: "tripped" }
    const v = vault({ [`${API}/mandates/action`]: action, [API]: WORKSPACE, [`${API}/stepup/start`]: STEPUP, [`${API}/mandates/${MANDATE}/resume`]: { mandate: { id: MANDATE } } })
    await resumeMandate(shell(), MANDATE, 3, passkey)
    expect(v.paths()).toEqual([`${API}/mandates/action`, API, `${API}/stepup/start`, `${API}/mandates/${MANDATE}/resume`])
    expect(v.calls[3]?.body).toEqual({ rev: 3, stepUp: { nonce: "n", assertion: { signed: true } } })
    expect(passkey).toHaveBeenCalledTimes(1)
  })

  it("sends nothing further for an action on another mandate or revision", async () => {
    for (const action of [{ type: "mandate.resume", mandate: "mdt_other000000000001", digest: "d", rev: 3, from: "paused" }, { type: "mandate.resume", mandate: MANDATE, digest: "d", rev: 4, from: "paused" }, { type: "mandate.sign", device: DEVICE, digest: "d" }]) {
      const v = vault({ [`${API}/mandates/action`]: action })
      expect(await resumeMandate(shell(), MANDATE, 3, passkey).catch(refusal)).toEqual(CHANGED_SINCE_SHOWN)
      expect(v.paths()).toEqual([`${API}/mandates/action`])
      vi.restoreAllMocks()
    }
    expect(passkey).not.toHaveBeenCalled()
  })
})

describe("resumeNeedsPasskey", () => {
  it("says no passkey only when the vault plans none for this mandate and revision, and a passkey when the plan fails", async () => {
    const v = vault({ [`${API}/mandates/action`]: { stepUp: null } })
    expect(await resumeNeedsPasskey(shell(), MANDATE, 3)).toBe(false)
    expect(v.calls).toEqual([{ path: `${API}/mandates/action`, body: { op: "resume", id: MANDATE, rev: 3 } }])
    vi.restoreAllMocks()
    vault({ [`${API}/mandates/action`]: { type: "mandate.resume", mandate: MANDATE, digest: "d", rev: 3, from: "lapsed" } })
    expect(await resumeNeedsPasskey(shell(), MANDATE, 3)).toBe(true)
    vi.restoreAllMocks()
    vault({})
    expect(await resumeNeedsPasskey(shell(), MANDATE, 3)).toBe(true)
  })
})

describe("changeMandate", () => {
  it("pauses and stops with the revision shown and no passkey", async () => {
    const v = vault({ [`${API}/mandates/${MANDATE}/pause`]: { mandate: { id: MANDATE } }, [`${API}/mandates/${MANDATE}/stop`]: { mandate: { id: MANDATE } } })
    await changeMandate(shell(), MANDATE, 2, "pause")
    await changeMandate(shell(), MANDATE, 3, "stop")
    expect(v.calls).toEqual([{ path: `${API}/mandates/${MANDATE}/pause`, body: { rev: 2 } }, { path: `${API}/mandates/${MANDATE}/stop`, body: { rev: 3 } }])
  })

  it("pauses all in turn at the revisions shown, counting each refusal and still pausing the rest", async () => {
    const other = "mdt_alexdesk000000001", gone = "mdt_alexold0000000001"
    const v = vault({ [`${API}/mandates/${MANDATE}/pause`]: { mandate: { id: MANDATE } }, [`${API}/mandates/${other}/pause`]: { mandate: { id: other } } })
    expect(await pauseMandates(shell(), `${MANDATE}:2 ${gone}:4 ${other}:7`)).toEqual({ total: 3, refused: 1 })
    expect(v.calls).toEqual([{ path: `${API}/mandates/${MANDATE}/pause`, body: { rev: 2 } }, { path: `${API}/mandates/${gone}/pause`, body: { rev: 4 } }, { path: `${API}/mandates/${other}/pause`, body: { rev: 7 } }])
    expect(await pauseMandates(shell(), "")).toEqual({ total: 0, refused: 0 })
  })
})
