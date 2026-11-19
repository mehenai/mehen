// /signup's emailed code beside Google (ui/client/email-code.ts), run against
// the page the server renders (test/mini-dom.ts) with the API answered here.
import { afterEach, describe, expect, it, vi } from "vitest"
import { renderDocument } from "../src/ui/layout.ts"
import { workspaceSignupPage } from "../src/ui/pages/account-setup.ts"
import { EMAIL_CODE_FAILED_WORDS, EMAIL_CODE_GOOGLE_ONLY_WORDS } from "../src/ui/pages/email-code.ts"
import { INVITE_KEY, RESULT_KEY, initWorkspaceSignup } from "../src/ui/client/pages/account-setup.ts"
import { type MiniBrowser, type MiniElement, installPage, settle, submit } from "./mini-dom.ts"

vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => ({ id: "test-assertion" }),
  startRegistration: async () => ({ id: "test-registration" }),
}))

type Answer = { status: number; body: unknown }
const ok = (body: unknown = {}): Answer => ({ status: 200, body })
const PEEK = { workspace: { name: "Northwind", slug: "northwind" }, role: "member", bound: true, emailCode: "offered", expiresAt: "2026-11-04T18:00:00.000Z" }
type Answers = { peek?: Answer; start?: Answer; verify?: Answer; signup?: Answer }

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})
const $ = (selector: string): MiniElement => {
  const found = browser!.document.querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}
const bodyOf = (path: string) => browser!.calls.filter((c) => c.path === path).map((c) => c.body)
const paths = () => browser!.calls.map((c) => c.path)
const shown = () => ["signup-verify", "signup-passkey", "signup-recovery", "signup-join"].filter((r) => !$(`[data-region="${r}"]`).hidden)

async function load(answers: Answers = {}, storage = new Map<string, string>([[INVITE_KEY, "the-code"]])) {
  browser = installPage(renderDocument(workspaceSignupPage({ signedIn: false, recoveryReady: false })).value, (path) => {
    if (path === "/api/auth/invite/peek") return answers.peek ?? ok(PEEK)
    if (path === "/api/auth/email/start") return answers.start ?? ok({ sent: true, expiresAt: "2026-11-02T18:10:00.000Z" })
    if (path === "/api/auth/email/verify") return answers.verify ?? ok({ emailProof: "eml_1", email: "tom@northwind.example", expiresAt: "2026-11-02T18:20:00.000Z" })
    if (path === "/api/auth/signup/options") return answers.signup ?? ok({ options: { challenge: "c" } })
    if (path === "/api/auth/signup/verify") return ok({ account: "acc_new", onboarding: "join" })
    return { status: 404, body: { error: "not_found", message: "No such route." } }
  }, "https://vault.test/signup")
  ;(globalThis as Record<string, unknown>).sessionStorage = { getItem: (k: string) => storage.get(k) ?? null, setItem: (k: string, v: string) => void storage.set(k, String(v)), removeItem: (k: string) => void storage.delete(k) }
  initWorkspaceSignup({ page: "workspace-signup", signedIn: false, recoveryReady: false })
  await settle()
  return storage
}

describe("/signup: Email me a code beside Verify with Google", () => {
  it("offers both; the code is sent to the invitation, typed back, and the signup carries the proof", async () => {
    const storage = await load()
    expect(shown()).toEqual(["signup-verify"])
    expect($('[data-action="verify-google"]').hidden).toBe(false)
    expect($('[data-region="email-code"]').hidden).toBe(false)
    expect($('[data-region="email-code-google-only"]').hidden).toBe(true)
    expect($('[data-form="email-code"]').hidden).toBe(true)
    $('[data-action="email-code-send"]').click()
    await settle()
    expect(bodyOf("/api/auth/email/start")).toEqual([{ code: "the-code" }])
    expect($('[data-form="email-code"]').hidden).toBe(false)
    expect($('[data-region="email-code-start"]').hidden).toBe(true)
    ;($('[data-input="email-code"]') as MiniElement).value = "123 456"
    submit($('[data-form="email-code"]'))
    await settle()
    expect(bodyOf("/api/auth/email/verify")).toEqual([{ code: "the-code", emailCode: "123 456" }])
    expect(storage.get(RESULT_KEY)).toBe("eml_1")
    expect(shown()).toEqual(["signup-passkey"])
    expect($('[data-region="verified"]').hidden).toBe(false)
    expect($('[data-region="verified"]').textContent).toContain("tom@northwind.example")
    expect(paths()).not.toContain("/api/auth/oidc/google/result")
    ;($('[data-input="name"]') as MiniElement).value = "Tom"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(bodyOf("/api/auth/signup/options")).toEqual([{ invite: "the-code", name: "Tom", emailProof: "eml_1" }])
    expect(bodyOf("/api/auth/signup/verify")).toEqual([{ invite: "the-code", name: "Tom", emailProof: "eml_1", response: { id: "test-registration" } }])
    expect(shown()).toEqual(["signup-recovery"])
  })

  it("a wrong code says the vault's words and stays; Send a new code asks again", async () => {
    await load({ verify: { status: 400, body: { error: "bad_request", message: "That code is not right. Check the email and try again." } } })
    $('[data-action="email-code-send"]').click()
    await settle()
    ;($('[data-input="email-code"]') as MiniElement).value = "000000"
    submit($('[data-form="email-code"]'))
    await settle()
    expect($('[data-region="email-code-error"]').hidden).toBe(false)
    expect($('[data-region="email-code-error"]').textContent).toBe("That code is not right. Check the email and try again.")
    expect(shown()).toEqual(["signup-verify"])
    $('[data-action="email-code-resend"]').click()
    await settle()
    expect(bodyOf("/api/auth/email/start")).toHaveLength(2)
    expect($('[data-region="email-code-error"]').hidden).toBe(true)
  })

  it("a send the vault could not make says so and leaves Google to press", async () => {
    await load({ start: { status: 502, body: { error: "upstream_failed", message: EMAIL_CODE_FAILED_WORDS } } })
    $('[data-action="email-code-send"]').click()
    await settle()
    expect($('[data-region="email-code-failed"]').hidden).toBe(false)
    expect($('[data-region="email-code-failed"]').textContent).toBe(EMAIL_CODE_FAILED_WORDS)
    expect($('[data-form="email-code"]').hidden).toBe(true)
    expect($('[data-action="verify-google"]').hidden).toBe(false)
  })

  it("under the workspace's identity rule only Google, saying why; with no code on offer, Google alone", async () => {
    await load({ peek: ok({ ...PEEK, emailCode: "identity_rule" }) })
    expect($('[data-region="email-code"]').hidden).toBe(true)
    expect($('[data-region="email-code-google-only"]').hidden).toBe(false)
    expect($('[data-region="email-code-google-only"]').textContent).toBe(EMAIL_CODE_GOOGLE_ONLY_WORDS)
    browser!.restore()
    await load({ peek: ok({ ...PEEK, emailCode: "off" }) })
    expect($('[data-region="email-code"]').hidden).toBe(true)
    expect($('[data-region="email-code-google-only"]').hidden).toBe(true)
    expect($('[data-action="verify-google"]').hidden).toBe(false)
  })

  it("an emailed proof the vault no longer takes asks again, and is dropped", async () => {
    const storage = await load({ signup: { status: 403, body: { error: "identity_required", message: "The emailed code could not be checked. Send a new code from the page that asked for it." } } }, new Map([[INVITE_KEY, "the-code"], [RESULT_KEY, "eml_old"]]))
    expect(shown()).toEqual(["signup-passkey"])
    ;($('[data-input="name"]') as MiniElement).value = "Tom"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(bodyOf("/api/auth/signup/options")).toEqual([{ invite: "the-code", name: "Tom", emailProof: "eml_old" }])
    expect(shown()).toEqual(["signup-verify"])
    expect($('[data-region="verify-lapsed"]').hidden).toBe(false)
    expect($('[data-region="email-code"]').hidden).toBe(false)
    expect(storage.has(RESULT_KEY)).toBe(false)
  })
})
