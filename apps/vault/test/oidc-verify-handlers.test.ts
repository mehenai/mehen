// The browser handler of /auth/oidc/verify (ui/client/pages/oidc-verify.ts),
// run against the page the server renders (test/mini-dom.ts), with the API
// answered by the test and the passkey prompt stubbed.
import { afterEach, describe, expect, it, vi } from "vitest"
import { renderDocument } from "../src/ui/layout.ts"
import { oidcVerifyPage } from "../src/ui/pages/oidc-verify.ts"
import { INVITE_KEY } from "../src/ui/client/oidc-logic.ts"
import { initOidc } from "../src/ui/client/pages/oidc-verify.ts"
import { type MiniBrowser, installPage, settle } from "./mini-dom.ts"

vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: async () => ({ id: "test-assertion" }) }))

type Answer = { status: number; body: unknown }
const GOOGLE = "https://accounts.google.com/o/oauth2/v2/auth?state=s"
let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

// The tab's sessionStorage, as an earlier page in this tab left it.
function tab(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial))
  return { map, store: { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, String(v)), removeItem: (k: string) => void map.delete(k) } }
}

// Opens /auth/oidc/verify for `purpose` in this tab and presses Verify with Google.
async function verify(purpose: string, storage: ReturnType<typeof tab>, href = `https://vault.test/auth/oidc/verify?purpose=${purpose}`, start: Answer = { status: 200, body: { url: GOOGLE } }) {
  browser = installPage(renderDocument(oidcVerifyPage({ mode: "verify", enabled: true, purpose })).value, (path) => {
    if (path === "/api/auth/oidc/google/start") return start
    if (path === "/api/account/stepup/start") return { status: 200, body: { nonce: "n", options: { challenge: "c" } } }
    return { status: 404, body: { error: "not_found", message: "No such route." } }
  }, href)
  ;(globalThis as Record<string, unknown>).sessionStorage = storage.store
  initOidc({ page: "oidc", mode: "verify", enabled: true, purpose })
  browser.document.querySelector('[data-action="oidc-start"]')!.click()
  await settle()
  return browser.calls.filter((c) => c.path === "/api/auth/oidc/google/start").map((c) => c.body)
}

describe("/auth/oidc/verify's Google start", () => {
  it("a sign-in or link in a tab that followed an invitation earlier carries no invitation, and leaves /signup's code alone", async () => {
    for (const purpose of ["signin", "link"]) {
      const storage = tab({ [INVITE_KEY]: "earlier-code" })
      const [sent] = await verify(purpose, storage)
      expect(sent).not.toHaveProperty("invite")
      expect(sent).toMatchObject({ purpose, next: "/workspaces" })
      expect(browser!.assigned).toEqual([GOOGLE])
      expect(storage.map.get(INVITE_KEY)).toBe("earlier-code")
      browser!.restore()
    }
  })

  it("an invitation's own step carries its code, from the fragment and after a reload", async () => {
    const storage = tab()
    expect(await verify("invite", storage, "https://vault.test/auth/oidc/verify?purpose=invite#invite=the-code")).toEqual([{ purpose: "invite", invite: "the-code", next: "/workspaces" }])
    expect(storage.map.get(INVITE_KEY)).toBe("the-code")
    browser!.restore()
    expect(await verify("invite", storage)).toEqual([{ purpose: "invite", invite: "the-code", next: "/workspaces" }])
  })

  it("an invitation the vault no longer has active drops its saved code", async () => {
    const storage = tab({ [INVITE_KEY]: "dead-code" })
    expect(await verify("invite", storage, undefined, { status: 404, body: { error: "not_found", message: "No such invite.", reason: "invite_inactive" } })).toEqual([{ purpose: "invite", invite: "dead-code", next: "/workspaces" }])
    expect(storage.map.has(INVITE_KEY)).toBe(false)
    expect(browser!.assigned).toEqual([])
  })

  it("any other not_found, such as a membership the workspace does not have yet, keeps the saved code", async () => {
    const storage = tab({ [INVITE_KEY]: "live-code" })
    expect(await verify("invite", storage, undefined, { status: 404, body: { error: "not_found", message: "No such membership." } })).toEqual([{ purpose: "invite", invite: "live-code", next: "/workspaces" }])
    expect(storage.map.get(INVITE_KEY)).toBe("live-code")
    expect(browser!.assigned).toEqual([])
  })
})
