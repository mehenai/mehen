// The pages' step-up helpers (step-up.ts) with a fake fetch: a start that
// answers grace yields { nonce, grace: true } without startAuthentication;
// one that answers options asks the passkey as before.
import { afterEach, describe, expect, it, vi } from "vitest"

const startAuthentication = vi.hoisted(() => vi.fn(async () => ({ signed: true })))
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication }))

import { accountStepUp, stepUpProof } from "./step-up.ts"

function answer(started: unknown): void {
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify(started), { status: 200, headers: { "content-type": "application/json" } }))
}
afterEach(() => { vi.restoreAllMocks(); startAuthentication.mockClear() })

describe("a step-up inside the session's passkey grace window", () => {
  it("sends grace and never calls startAuthentication", async () => {
    answer({ nonce: "g", grace: { until: "2026-11-08T17:30:00.000Z" } })
    expect(await accountStepUp({ type: "workspace.create", slug: "new", name: "New" })).toEqual({ nonce: "g", grace: true })
    expect(startAuthentication).not.toHaveBeenCalled()
  })
  it("outside it, asks the passkey with the options the vault sent", async () => {
    answer({ nonce: "n", options: { challenge: "c", allowCredentials: [] } })
    expect(await accountStepUp({ type: "workspace.create", slug: "new", name: "New" })).toEqual({ nonce: "n", assertion: { signed: true } })
    expect(startAuthentication).toHaveBeenCalledWith({ optionsJSON: { challenge: "c", allowCredentials: [] } })
  })
  it("a given passkey is only asked when there are options", async () => {
    const passkey = vi.fn(async () => "signed")
    expect(await stepUpProof({ nonce: "g", grace: { until: "x" } }, passkey)).toEqual({ nonce: "g", grace: true })
    expect(passkey).not.toHaveBeenCalled()
  })
})
