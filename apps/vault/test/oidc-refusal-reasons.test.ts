import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest"
import { callbackOidcFlow, finishOidcLink, oidcCookieToken, readOidcResult, startOidcFlow } from "../src/directory/oidc-flow.ts"
import { OIDC_GOOGLE_BLOCKED, OIDC_GOOGLE_CANCELLED, OIDC_GOOGLE_REFUSED, OIDC_NEWER_START, OIDC_OTHER_BROWSER, OIDC_REFUSAL, OIDC_TOO_LONG_OR_OTHER_BROWSER, setOidcFetchForTest } from "../src/directory/oidc.ts"
import { sha256Text } from "../src/directory/session.ts"
import type { AccountWebSession } from "../src/directory/account-session.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { fakeGoogle } from "./oidc-google.ts"
let f: Awaited<ReturnType<typeof createWorkspaceFixture>>, google: Awaited<ReturnType<typeof fakeGoogle>>, account: AccountWebSession
let network: ReturnType<typeof vi.spyOn<typeof globalThis, "fetch">>, warnings: MockInstance<typeof console.warn>
// Every state, code and flow cookie a test hands the callback: none may reach a log line.
let secrets: string[]
beforeEach(async () => {
  f = await createWorkspaceFixture(); f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  google = await fakeGoogle(); setOidcFetchForTest(google.fetcher); secrets = []
  network = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("No live network") })
  warnings = vi.spyOn(console, "warn").mockImplementation(() => undefined)
  account = { account: f.account, session: f.session, name: "Alex", securityEpoch: 0, restrictedUntil: null, transition: null }
})
afterEach(() => {
  expect(network).not.toHaveBeenCalled(); network.mockRestore(); setOidcFetchForTest(null)
  const logged = warnings.mock.calls.map(call => call.map(String).join(" ")).join("\n")
  for (const secret of ["alex@northwind.example", "google-alex", "Alex", "northwind.example", ...secrets]) expect(logged).not.toContain(secret)
  warnings.mockRestore()
})
function refusals(): unknown[] { return warnings.mock.calls.map(([line]) => String(line)).filter(line => line.includes('"at":"oidc.refused"')).map(line => JSON.parse(line) as unknown) }
async function refusedWith(work: Promise<unknown>, reason: string, purpose: string | null, extra: Record<string, unknown> = {}) {
  await expect(work).rejects.toMatchObject({ code: "identity_required" })
  expect(refusals().at(-1)).toEqual({ at: "oidc.refused", reason, purpose, provider: "google", ...extra })
}
function remember(start: { url: string; cookie: string }) { const state = new URL(start.url).searchParams.get("state")!; secrets.push(state, start.cookie.split(";")[0]!.split("=")[1]!); return state }
function callback(start: { url: string; cookie: string }, override: Record<string, unknown> = {}, cookie = start.cookie) { remember(start); const authorised = google.authorise(start.url, override); secrets.push(authorised.code); return new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, { headers: { cookie } }) }
function returned(start: { url: string; cookie: string }, query: Record<string, string>) { const state = remember(start); return new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?${new URLSearchParams({ state, ...query })}`, { headers: { cookie: start.cookie } }) }
async function linked() { const start = await startOidcFlow(f.env, { purpose: "link", account }), row = await callbackOidcFlow(f.env, callback(start)); return { row, cookie: oidcCookieToken(new Request(f.env.VAULT_ORIGIN, { headers: { cookie: start.cookie } }), "link") } }
describe("oidc refusal reasons: the callback says which check refused", () => {
  it("an unknown or missing state is state_unknown, with no purpose to name", async () => {
    const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start)
    await refusedWith(callbackOidcFlow(f.env, new Request(request.url.replace("state=", "state=wrong"), request)), "state_unknown", null)
    await refusedWith(callbackOidcFlow(f.env, new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?code=x`, request)), "state_unknown", null)
  })
  it("a callback without the flow cookie is cookie_missing", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, {}, "")), "cookie_missing", "signin") })
  it("a callback with another browser's flow cookie is cookie_mismatch", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, {}, `__Host-mehen_oidc=${"a".repeat(43)}`)), "cookie_mismatch", "signin") })
  it("a replayed callback is flow_consumed", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start); await callbackOidcFlow(f.env, request); await refusedWith(callbackOidcFlow(f.env, request), "flow_consumed", "signin") })
  it("a callback after ten minutes is flow_expired, though the browser has dropped the flow cookie by then", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, {}, ""), Date.now() + 600001), "flow_expired", "signin") })
  it("Google's own refusal is provider_error with its error from a closed list", async () => {
    for (const [error, logged] of [["access_denied", "access_denied"], ["admin_policy_enforced", "admin_policy_enforced"], ["org_internal", "org_internal"], ["alex@northwind.example", "other"]] as const) {
      const start = await startOidcFlow(f.env, { purpose: "signin" })
      await refusedWith(callbackOidcFlow(f.env, returned(start, { error })), "provider_error", "signin", { googleError: logged })
    }
    expect(google.calls).toEqual([])
  })
  it("a callback with no code and no error is code_missing", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, returned(start, {})), "code_missing", "signin") })
  it("signing out during Google's step is session_ended", async () => { const start = await startOidcFlow(f.env, { purpose: "link", account }); await f.env.DB.prepare("DELETE FROM web_sessions WHERE id=?").bind(account.session).run(); await refusedWith(callbackOidcFlow(f.env, callback(start)), "session_ended", "link") })
  it("a recovery during Google's step is epoch_changed", async () => { const start = await startOidcFlow(f.env, { purpose: "link", account }); await f.env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(f.account).run(); await refusedWith(callbackOidcFlow(f.env, callback(start)), "epoch_changed", "link") })
  it("an account under a recovery restriction is account_restricted", async () => { const start = await startOidcFlow(f.env, { purpose: "link", account }); await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(Date.now() + 86400000, f.account).run(); await refusedWith(callbackOidcFlow(f.env, callback(start)), "account_restricted", "link") })
  it("Google sign-in without its configuration is not_configured", async () => { delete f.env.GOOGLE_SIGNIN_CLIENT_SECRET; await refusedWith(startOidcFlow(f.env, { purpose: "signin" }), "not_configured", "signin") })
  it("an unreachable token endpoint is token_exchange_failed", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start); google.faults.unavailable = true; await refusedWith(callbackOidcFlow(f.env, request), "token_exchange_failed", "signin") })
  it("no usable Google signing key is jwks_unavailable", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); google.faults.jwks = { keys: [] }; await refusedWith(callbackOidcFlow(f.env, callback(start)), "jwks_unavailable", "signin") })
  it("a malformed ID token is id_token_invalid", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, { sub: "" })), "id_token_invalid", "signin") })
  it("an ID token for another client is audience_mismatch", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, { aud: "other-client" })), "audience_mismatch", "signin") })
  it("an ID token for another flow is nonce_mismatch", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, { nonce: "other-nonce" })), "nonce_mismatch", "signin") })
  it("an unverified Google email is email_unverified", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await refusedWith(callbackOidcFlow(f.env, callback(start, { email_verified: false })), "email_unverified", "signin") })
  it("a sign-in carrying a stale invitation, still active or not, completes without it", async () => {
    for (const [code, expiresAt] of [["active-invite-code", Date.now() + 86400000], ["lapsed-invite-code", Date.now() - 1]] as const) {
      secrets.push(code)
      await f.env.DB.prepare("INSERT INTO invite_codes(code_hash,kind,workspace,invite,email,expires_at) VALUES (?,'join',?,?,NULL,?)").bind(await sha256Text(code), f.workspaces.work, `inv_${code}`, expiresAt).run()
      const start = await startOidcFlow(f.env, { purpose: "signin", inviteHash: await sha256Text(code) })
      expect(await callbackOidcFlow(f.env, callback(start))).toMatchObject({ purpose: "signin", invite_hash: null })
    }
    expect(refusals()).toEqual([])
  })
})
describe("oidc refusal reasons: the person is told what they can do", () => {
  it("an expired or replayed sign-in says to start again and finish within the flow's ten minutes", async () => {
    const ended = "This sign-in link has expired or was already used. Start again from the page that sent you to Google and finish within 10 minutes without refreshing."
    const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start)
    await callbackOidcFlow(f.env, request)
    await expect(callbackOidcFlow(f.env, request)).rejects.toMatchObject({ code: "identity_required", message: ended })
    const expired = await startOidcFlow(f.env, { purpose: "signin" })
    await expect(callbackOidcFlow(f.env, callback(expired, {}, ""), Date.now() + 600001)).rejects.toMatchObject({ message: ended })
  })
  it("an expired app identity check says to finish within the app flow's five minutes", async () => {
    const start = await startOidcFlow(f.env, { purpose: "gate", workspace: f.workspaces.work, context: { member: null, rule: null, ruleRevision: 0, gateGeneration: 0, sequence: 1, startedAt: Date.now(), purpose: "session", subjectDigest: null }, app: { sessionHash: "app-session-hash", challenge: "app-challenge" } }), launch = new URLSearchParams(new URL(start.url).hash.slice(1)), state = launch.get("state")!, flow = launch.get("flow")!
    secrets.push(state, flow)
    const request = new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?${new URLSearchParams({ state, code: "google-code" })}`, { headers: { cookie: start.cookie } })
    await expect(callbackOidcFlow(f.env, request, Date.now() + 300001)).rejects.toMatchObject({ message: "This sign-in link has expired or was already used. Start again from the page that sent you to Google and finish within 5 minutes without refreshing." })
    expect(refusals().at(-1)).toEqual({ at: "oidc.refused", reason: "flow_expired", purpose: "gate", provider: "google" })
  })
  it("a missing flow cookie says to finish in the browser that started; another flow's cookie says this browser started a newer one", async () => {
    for (const [cookie, message] of [["", OIDC_OTHER_BROWSER], [`__Host-mehen_oidc=${"a".repeat(43)}`, OIDC_NEWER_START]] as const) { const start = await startOidcFlow(f.env, { purpose: "signin" }); await expect(callbackOidcFlow(f.env, callback(start, {}, cookie))).rejects.toMatchObject({ message }) }
    expect(OIDC_NEWER_START).toBe("This browser started another sign-in after this one; finish the most recent one, or start again here.")
  })
  it("Google's refusal says Google refused, that the person cancelled or Google refused, or that a Google admin or setting blocks it", async () => {
    expect(OIDC_GOOGLE_CANCELLED).toBe("You cancelled at Google, or Google refused the request. Start again when you are ready.")
    for (const [error, message] of [["access_denied", OIDC_GOOGLE_CANCELLED], ["admin_policy_enforced", OIDC_GOOGLE_BLOCKED], ["org_internal", OIDC_GOOGLE_BLOCKED], ["server_error", OIDC_GOOGLE_REFUSED]] as const) {
      const start = await startOidcFlow(f.env, { purpose: "signin" })
      await expect(callbackOidcFlow(f.env, returned(start, { error }))).rejects.toMatchObject({ message })
    }
  })
  it("a cause the person cannot act on keeps the general message", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); await expect(callbackOidcFlow(f.env, callback(start, { aud: "other-client" }))).rejects.toMatchObject({ message: OIDC_REFUSAL }) })
})
describe("oidc refusal reasons: using the result says which check refused", () => {
  it("a result used without its flow cookie is result_cookie_missing, and says the step took too long or ended in another browser", async () => {
    await refusedWith(Promise.resolve().then(() => oidcCookieToken(new Request(f.env.VAULT_ORIGIN), "link")), "result_cookie_missing", "link")
    expect(() => oidcCookieToken(new Request(f.env.VAULT_ORIGIN), "signin")).toThrow(OIDC_TOO_LONG_OR_OTHER_BROWSER)
    expect(OIDC_TOO_LONG_OR_OTHER_BROWSER).toBe("This Google step took too long or was finished in another browser. Start it again here.")
  })
  it("a result read with the wrong flow cookie is result_unavailable", async () => { const { row } = await linked(); await refusedWith(readOidcResult(f.env, row.id, "wrong", "link"), "result_unavailable", "link") })
  it("a result confirmed by another account is account_mismatch", async () => { const { row } = await linked(); await refusedWith(finishOidcLink(f.env, { ...account, account: "acc_member" }, row, { email: row.email, subject: row.subject }), "account_mismatch", "link") })
  it("a link confirming a different identity is confirmation_mismatch", async () => { const { row } = await linked(); await refusedWith(finishOidcLink(f.env, account, row, { email: "other@example.com", subject: row.subject }), "confirmation_mismatch", "link") })
})
