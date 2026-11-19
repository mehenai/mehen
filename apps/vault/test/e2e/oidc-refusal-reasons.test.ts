import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest"
import { OIDC_INVITE_INACTIVE, OIDC_NOT_LINKED_REFUSAL, OIDC_OTHER_BROWSER, setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { GOOGLE_REFUSED_HEADING } from "../../src/routes/oidc.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { oidcStartInvite } from "../../src/ui/client/oidc-logic.ts"
import { googleFlow, linkGoogle, oidcResultOf, setGoogleRule } from "./oidc-journey.ts"
import { body, workJourney } from "./workspace-journey.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>, warnings: MockInstance<typeof console.warn>
// Every invitation code, state, Google code and flow cookie a test uses: none may reach a log line.
let secrets: string[]
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher); secrets = []; warnings = vi.spyOn(console, "warn").mockImplementation(() => undefined) })
afterEach(() => {
  setOidcFetchForTest(null)
  const logged = warnings.mock.calls.map(call => call.map(String).join(" ")).join("\n")
  for (const secret of ["@northwind.example", "@example.com", "google-alex", "google-colleague", "northwind.example", ...secrets]) expect(logged).not.toContain(secret)
  warnings.mockRestore()
})
function refusals(): unknown[] { return warnings.mock.calls.map(([line]) => String(line)).filter(line => line.includes('"at":"oidc.refused"')).map(line => JSON.parse(line) as unknown) }
function lastRefusal(reason: string, purpose: string | null) { expect(refusals().at(-1)).toEqual({ at: "oidc.refused", reason, purpose, provider: "google" }) }
const terms = () => ({ role: "member" as const, email: "colleague@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString() })
// An invitation's Google step up to Google's answer; the callback is the caller's.
async function inviteStep(f: Awaited<ReturnType<typeof workJourney>>, code: string, claims: Record<string, unknown>) {
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  const started = await f.request("/api/auth/oidc/google/start", undefined, { purpose: "invite", invite: code }), cookie = started.headers.get("set-cookie")!.split(";")[0]!, { url } = await body<{ url: string }>(started), authorised = google.authorise(url, claims)
  secrets.push(code, cookie.split("=")[1]!, authorised.state, authorised.code)
  return (headers: Record<string, string> = { cookie }) => f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, undefined, undefined, headers)
}
describe("oidc refusal reasons through worker.fetch", () => {
  it("an invitation revoked or expired during Google's step is invite_inactive", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-colleague", email: "colleague@northwind.example" })
    await f.db.prepare("UPDATE invite_codes SET expires_at=? WHERE invite=?").bind(Date.now() - 1, invite.invite.id).run()
    expect((await finish()).status).toBe(403)
    lastRefusal("invite_inactive", "invite")
  })
  it("a Google account for another address than the invitation's is invite_email_mismatch", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-colleague", email: "forwarded@northwind.example" })
    expect((await finish()).status).toBe(403)
    lastRefusal("invite_email_mismatch", "invite")
  })
  it("an invitation whose terms changed during Google's step is invite_changed", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-colleague", email: "colleague@northwind.example" })
    await f.sql(f.work, "UPDATE invites SET digest='changed-terms' WHERE id=?", invite.invite.id)
    expect((await finish()).status).toBe(403)
    lastRefusal("invite_changed", "invite")
  })
  it("a Google account outside the workspace's identity rule is domain_rule", async () => {
    const f = await workJourney(); await linkGoogle(f, google); await setGoogleRule(f, google)
    const result = await googleFlow(f, google, f.alex, { purpose: "gate", workspace: f.work.slug }, { email: "alex@example.com", hd: "example.com" })
    secrets.push(result.id, result.cookie.split("=")[1]!)
    expect((await f.request("/api/auth/oidc/google/gate", f.alex, { result: result.id }, { cookie: `${f.alex.cookie}; ${result.cookie}` })).status).toBe(403)
    lastRefusal("domain_rule", "gate")
  })
  it("an older identity check finished after a newer one is gate_changed", async () => {
    const f = await workJourney(); await linkGoogle(f, google); await setGoogleRule(f, google)
    const older = await googleFlow(f, google, f.alex, { purpose: "gate", workspace: f.work.slug }), newer = await googleFlow(f, google, f.alex, { purpose: "gate", workspace: f.work.slug })
    expect((await f.request("/api/auth/oidc/google/gate", f.alex, { result: newer.id }, { cookie: `${f.alex.cookie}; ${newer.cookie}` })).status).toBe(200)
    expect((await f.request("/api/auth/oidc/google/gate", f.alex, { result: older.id }, { cookie: `${f.alex.cookie}; ${older.cookie}` })).status).toBe(403)
    lastRefusal("gate_changed", "gate")
  })
  it("a member no longer active in the workspace starting an identity check is member_inactive", async () => {
    const f = await workJourney(); f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
    await f.sql(f.work, "UPDATE members SET status='suspended' WHERE account=?", f.alex.account)
    expect((await f.request("/api/auth/oidc/google/start", f.alex, { purpose: "gate", workspace: f.work.slug })).status).toBe(403)
    lastRefusal("member_inactive", "gate")
  })
  it("a Google sign-in with no linked Mehen account is no_linked_identity", async () => {
    const f = await workJourney(), signin = await googleFlow(f, google, f.alex, { purpose: "signin" }, { sub: "google-stranger", email: "stranger@example.com" })
    secrets.push(signin.id, signin.cookie.split("=")[1]!, "google-stranger")
    expect((await f.request("/api/auth/oidc/google/result", undefined, { result: signin.id, purpose: "signin" }, { cookie: signin.cookie })).status).toBe(403)
    lastRefusal("no_linked_identity", "signin")
    expect((await f.request("/api/auth/signin/options", undefined, { oidcResult: signin.id }, { cookie: signin.cookie })).status).toBe(403)
    lastRefusal("no_linked_identity", "signin")
  })
  it("an invitation that is no longer active, used or expired, tells the invitee what to do", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-colleague", email: "colleague@northwind.example" })
    await f.db.prepare("UPDATE invite_codes SET expires_at=? WHERE invite=?").bind(Date.now() - 1, invite.invite.id).run()
    expect(await (await finish()).json()).toMatchObject({ error: "identity_required", message: OIDC_INVITE_INACTIVE })
    const again = await f.invite(f.alex, f.work, terms()), twice = await inviteStep(f, again.code, { sub: "google-colleague", email: "colleague@northwind.example" })
    expect((await twice()).status).toBe(303)
    expect(await (await twice()).json()).toMatchObject({ error: "identity_required", message: "This sign-in link has expired or was already used. Start again from the invitation and finish within 10 minutes without refreshing." })
  })
  it("a browser that lost the flow cookie gets a page saying to finish in the browser it started in", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-colleague", email: "colleague@northwind.example" })
    const page = await finish({ accept: "text/html" }), text = await page.text()
    expect(page.status).toBe(403)
    expect(text).toContain(GOOGLE_REFUSED_HEADING)
    expect(text).toContain(OIDC_OTHER_BROWSER)
    lastRefusal("cookie_missing", "invite")
  })
  it("a Google account not linked to any Mehen account says how to link it or use an invitation", async () => {
    const f = await workJourney(), signin = await googleFlow(f, google, f.alex, { purpose: "signin" }, { sub: "google-stranger", email: "stranger@example.com" })
    secrets.push(signin.id, signin.cookie.split("=")[1]!, "google-stranger")
    expect(OIDC_NOT_LINKED_REFUSAL).toBe("This Google account is not linked to a Mehen account yet. Sign in with your passkey and link Google from your account page, or use your invitation link.")
    for (const [path, input] of [["/api/auth/oidc/google/result", { result: signin.id, purpose: "signin" }], ["/api/auth/signin/options", { oidcResult: signin.id }]] as const) expect(await (await f.request(path, undefined, input, { cookie: signin.cookie })).json()).toEqual({ error: "identity_required", message: OIDC_NOT_LINKED_REFUSAL })
  })
  it("a Google sign-in in a tab that followed an invitation earlier is not refused; the invitation's own step still carries its code", async () => {
    const f = await workJourney(); await linkGoogle(f, google)
    const earlier = await f.invite(f.alex, f.work, { role: "guest", email: null, teams: [], shares: [{ project: f.project.id, level: "edit", protected: true, expiresAt: null }], expiresAt: new Date(Date.now() + 86400000).toISOString() })
    const saved = new Map<string, string>(), tab = { getItem: (k: string) => saved.get(k) ?? null, setItem: (k: string, v: string) => void saved.set(k, v) }
    secrets.push(earlier.code)
    expect(oidcStartInvite("invite", `#invite=${earlier.code}`, tab)).toBe(earlier.code)
    const invite = oidcStartInvite("signin", "", tab)
    const started = await f.request("/api/auth/oidc/google/start", undefined, { purpose: "signin", ...(invite ? { invite } : {}) }), cookie = started.headers.get("set-cookie")!.split(";")[0]!, authorised = google.authorise((await body<{ url: string }>(started)).url, {})
    secrets.push(cookie.split("=")[1]!, authorised.state, authorised.code)
    const callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, undefined, undefined, { cookie })
    expect(callback.status).toBe(303)
    const result = oidcResultOf(callback, f.env.VAULT_ORIGIN); secrets.push(result)
    expect((await f.request("/api/auth/signin/options", undefined, { oidcResult: result }, { cookie })).status).toBe(200)
    expect(refusals()).toEqual([])
    const carried = oidcStartInvite("invite", "", tab)
    expect(carried).toBe(earlier.code)
    expect((await f.request("/api/auth/oidc/google/start", undefined, { purpose: "invite", invite: carried })).status).toBe(200)
  })
  it("a Google result is still usable nine minutes after the callback in the browser that started it", async () => {
    const f = await workJourney(); await linkGoogle(f, google)
    // The browser keeps the flow cookie for its Max-Age from the response that set it.
    let jar: { value: string; until: number } | null = null
    const keep = (response: Response) => { const set = response.headers.get("set-cookie"); if (!set) return; expect(set).toMatch(/^__Host-mehen_oidc=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=\d+$/); jar = { value: set.split(";")[0]!, until: Date.now() + Number(set.match(/Max-Age=(\d+)/)![1]) * 1000 }; secrets.push(jar.value.split("=")[1]!) }
    const cookie = () => (jar && jar.until > Date.now() ? { cookie: jar.value } : {}) as Record<string, string>
    vi.useFakeTimers({ toFake: ["Date"] })
    try {
      const started = await f.request("/api/auth/oidc/google/start", undefined, { purpose: "signin" }); keep(started)
      vi.setSystemTime(Date.now() + 5 * 60000)
      const authorised = google.authorise((await body<{ url: string }>(started)).url, {}); secrets.push(authorised.state, authorised.code)
      const callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, undefined, undefined, cookie()); keep(callback)
      expect(callback.status).toBe(303)
      const result = oidcResultOf(callback, f.env.VAULT_ORIGIN); secrets.push(result)
      vi.setSystemTime(Date.now() + 9 * 60000)
      expect((await f.request("/api/auth/signin/options", undefined, { oidcResult: result }, cookie())).status).toBe(200)
      expect(refusals()).toEqual([])
    } finally { vi.useRealTimers() }
  })
  it("an invitation's Google step for an invitation no longer active is invite_inactive, and keeps its answer", async () => {
    const f = await workJourney(), invite = await f.invite(f.alex, f.work, terms()); f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"; secrets.push(invite.code)
    await f.db.prepare("UPDATE invite_codes SET expires_at=? WHERE invite=?").bind(Date.now() - 1, invite.invite.id).run()
    const started = await f.request("/api/auth/oidc/google/start", undefined, { purpose: "invite", invite: invite.code })
    expect(started.status).toBe(404)
    expect(await started.json()).toEqual({ error: "not_found", message: "No such invite.", reason: "invite_inactive" })
    lastRefusal("invite_inactive", "invite")
  })
  it("an invitation proved with a Google account linked to another Mehen account is already_linked_elsewhere, at signup and at join, and keeps its answer", async () => {
    const f = await workJourney(); await linkGoogle(f, google)
    const linkedElsewhere = { error: "identity_required", message: "This Google account is linked to another Mehen account. Sign in with that account to accept, or use a different Google account." }
    const invite = await f.invite(f.alex, f.work, terms()), finish = await inviteStep(f, invite.code, { sub: "google-alex", email: "colleague@northwind.example" }), callback = await finish(), cookie = callback.headers.get("set-cookie")!.split(";")[0]!, result = oidcResultOf(callback, f.env.VAULT_ORIGIN)
    secrets.push(result)
    const signup = await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague", oidcResult: result }, { cookie })
    expect(signup.status).toBe(403)
    expect(await signup.json()).toEqual(linkedElsewhere)
    lastRefusal("already_linked_elsewhere", "invite")
    const tom = await f.guest(f.alex, f.work, f.project.id, "Tom"), personal = await f.invite(f.alex, f.personal, { ...terms(), email: "tom@northwind.example" }), proof = await googleFlow(f, google, tom, { purpose: "invite", invite: personal.code }, { sub: "google-alex", email: "tom@northwind.example" })
    secrets.push(personal.code, proof.id, proof.cookie.split("=")[1]!)
    const joined = await f.request("/api/account/invites/join", tom, { code: personal.code, oidcResult: proof.id }, { cookie: `${tom.cookie}; ${proof.cookie}` })
    expect(joined.status).toBe(403)
    expect(await joined.json()).toEqual(linkedElsewhere)
    lastRefusal("already_linked_elsewhere", "invite")
  })
  it("an invitation's Google step started without the invitation is request_invalid", async () => {
    const f = await workJourney(); f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
    expect((await f.request("/api/auth/oidc/google/start", undefined, { purpose: "invite" })).status).toBe(403)
    lastRefusal("request_invalid", "invite")
  })
})
