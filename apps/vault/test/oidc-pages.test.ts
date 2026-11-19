import { createExecutionContext } from "cloudflare:test"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import worker from "../src/index.ts"
import { describe, expect, it } from "vitest"
import { oidcVerifyPage } from "../src/ui/pages/oidc-verify.ts"
import { oidcGallery } from "../src/ui/oidc-gallery.ts"
import { clearOidcFragment, oidcFragment } from "../src/ui/client/oidc-logic.ts"
import { renderDocument } from "../src/ui/layout.ts"
import { GOOGLE_REFUSED_HEADING, GOOGLE_REFUSED_NEXT } from "../src/routes/oidc.ts"
describe("oidc pages and native fragment bootstrap", () => {
  it("refuses malformed purpose query parameters without a server error", async () => { const f = await createWorkspaceFixture(); const response = await worker.fetch(new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/verify?purpose=recover`),f.env,createExecutionContext()); expect(response.status).toBe(400); expect(await response.json()).toEqual({ error: "bad_request",message: "Unknown Google verification purpose." }) })
  it("hides every Google action when configuration is absent", () => { const page = renderDocument(oidcVerifyPage({ mode: "verify",enabled: false,purpose: "signin" })).toString(); expect(page).not.toContain('data-action="oidc-'); expect(page).toContain("Sign in with a passkey") })
  it("shows only the action for its purpose and never promises Google sign-in alone", () => { for (const purpose of ["signin","link","gate"]) { const page = renderDocument(oidcVerifyPage({ mode: "result",enabled: true,purpose })).toString(); expect(page).toContain("Your passkey still signs you in"); for (const other of ["signin","link","gate"]) expect(page.includes(`data-action="oidc-${other}"`)).toBe(other === purpose) } })
  it("renders no invitation section: an invitation's Google step runs on /signup", () => { for (const mode of ["verify","result"] as const) { const page = renderDocument(oidcVerifyPage({ mode,enabled: true,purpose: "invite" })).toString(); expect(page).not.toMatch(/data-action="oidc-(signup|join)"|data-region="oidc-join"|Accept the invitation|Create your passkey/) } })
  it("sends an invitation's result page, old links included, to /signup without reading a result", async () => { const f = await createWorkspaceFixture(); for (const query of ["purpose=invite","purpose=invite&result=oidr_x&next=%2Fworkspaces"]) { const response = await worker.fetch(new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/result?${query}`),f.env,createExecutionContext()); expect(response.status).toBe(303); expect(response.headers.get("location")).toBe("/signup") } })
  it("spells hostile names, and identifies duplicate workspace labels with slugs", () => { const identity = { email: "alex@northwind.example",subject: "123",name: '<b>Alex</b>\u202e\u0007' }, page = oidcVerifyPage({ mode: "result",enabled: true,purpose: "link",identity }).body.toString(); expect(page).not.toContain("<b>Alex</b>"); expect(page).not.toMatch(/[\u202e\u0007]/); for (const workspace of ["northwind","northwind-client"]) expect(oidcVerifyPage({ mode: "verify",enabled: true,purpose: "gate",workspace }).body.toString()).toContain(workspace) })
  it("clears the fragment before native bootstrap and accepts no session bearer field", () => { const calls: unknown[][] = [], host = { location: { hash: "#state=state&flow=flow",pathname: "/auth/oidc/google/app/start",search: "" },history: { replaceState(...values: unknown[]) { calls.push(values) } } }; expect(oidcFragment(clearOidcFragment(host))).toEqual({ state: "state",flow: "flow" }); expect(calls).toEqual([[null,"","/auth/oidc/google/app/start"]]); expect(oidcFragment("#token=app-bearer")).toBeNull() })
  it("a browser back from Google to a refusal gets a page saying what to do next; an API caller keeps the JSON", async () => {
    const f = await createWorkspaceFixture(), html = { accept: "text/html,application/xhtml+xml" }
    const page = await worker.fetch(new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?state=abc&code=xyz`,{ headers: html }),f.env,createExecutionContext())
    expect(page.status).toBe(403)
    expect(page.headers.get("content-type")).toContain("text/html")
    const text = await page.text()
    expect(text).toContain(GOOGLE_REFUSED_HEADING)
    expect(text).toContain(GOOGLE_REFUSED_NEXT)
    expect(text).not.toContain('"error"')
    const api = await worker.fetch(new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?state=abc&code=xyz`),f.env,createExecutionContext())
    expect(api.status).toBe(403)
    expect(await api.json()).toMatchObject({ error: "identity_required" })
    const signedOut = await worker.fetch(new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/verify?purpose=link`,{ headers: html }),f.env,createExecutionContext())
    expect(signedOut.status).toBe(401)
    expect(await signedOut.text()).toContain("/signin?next=%2Fauth%2Foidc%2Fverify%3Fpurpose%3Dlink")
  })
  it("plain-browser callback contains no code or identity and every state has a gallery entry", () => { const page = oidcVerifyPage({ mode: "app-callback",enabled: false }).body.toString(); expect(page).toContain("Return to your app"); expect(page).not.toContain("data-action"); const entries = oidcGallery(); expect(entries).toHaveLength(5); expect(new Set(entries.map(entry => entry.id)).size).toBe(5); expect(entries.map(entry => entry.id)).not.toContain("oidc-invite-new") })
})
