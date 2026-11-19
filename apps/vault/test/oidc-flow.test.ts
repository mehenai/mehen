import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { bootstrapAppOidc, callbackOidcFlow, finishOidcLink, oidcCookieToken, oidcNext, readOidcResult, startOidcFlow } from "../src/directory/oidc-flow.ts"
import { sha256Text } from "../src/directory/session.ts"
import { setOidcFetchForTest } from "../src/directory/oidc.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { fakeGoogle } from "./oidc-google.ts"
import type { AccountWebSession } from "../src/directory/account-session.ts"
let f: Awaited<ReturnType<typeof createWorkspaceFixture>>, google: Awaited<ReturnType<typeof fakeGoogle>>, account: AccountWebSession
let network: ReturnType<typeof vi.spyOn<typeof globalThis, "fetch">>
beforeEach(async () => { f = await createWorkspaceFixture(); f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"; google = await fakeGoogle(); setOidcFetchForTest(google.fetcher); network = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("No live network") }); account = { account: f.account, session: f.session, name: "Alex", securityEpoch: 0, restrictedUntil: null, transition: null } })
afterEach(() => { expect(network).not.toHaveBeenCalled(); network.mockRestore(); setOidcFetchForTest(null) })
function callback(start: { url: string; cookie: string }, override: Record<string, unknown> = {}, cookie = start.cookie) { const authorised = google.authorise(start.url, override); return new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?${new URLSearchParams(authorised)}`, { headers: { cookie } }) }
async function result(purpose: "signin" | "link" = "link", override: Record<string, unknown> = {}) { const start = await startOidcFlow(f.env, { purpose, ...(purpose === "link" ? { account } : {}) }); const row = await callbackOidcFlow(f.env, callback(start, override)); return { start, row, cookie: oidcCookieToken(new Request(f.env.VAULT_ORIGIN, { headers: { cookie: start.cookie } }), purpose) } }
describe("oidc-flow purpose and browser bindings", () => {
  it("refuses external, scheme-relative and control-character next paths", () => { for (const value of ["https://attacker.test", "//attacker.test", "/\\attacker.test", "/\nattacker.test", "javascript:alert(1)"]) expect(oidcNext(value)).toBeNull(); expect(oidcNext("/w/northwind/?tab=people")).toBe("/w/northwind/?tab=people") })
  it("starts only pinned online scopes with PKCE, state, nonce and host cookie", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }), url = new URL(start.url); expect(url.searchParams.get("scope")).toBe("openid email profile"); expect(url.searchParams.get("prompt")).toBe("select_account"); expect(url.searchParams.get("code_challenge_method")).toBe("S256"); expect(url.searchParams.has("access_type")).toBe(false); expect(start.cookie).toMatch(/^__Host-mehen_oidc=.*; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=600$/) })
  it("refuses wrong cookie, state, expired and replayed callback before exchange", async () => {
    const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start)
    await expect(callbackOidcFlow(f.env, new Request(request, { headers: { cookie: "__Host-mehen_oidc=" + "a".repeat(43) } }))).rejects.toMatchObject({ code: "identity_required" })
    await expect(callbackOidcFlow(f.env, new Request(request.url.replace("state=", "state=wrong"), request))).rejects.toMatchObject({ code: "identity_required" })
    const row = await callbackOidcFlow(f.env, request)
    await expect(callbackOidcFlow(f.env, request)).rejects.toMatchObject({ code: "identity_required" })
    const expired = await startOidcFlow(f.env, { purpose: "signin" })
    await expect(callbackOidcFlow(f.env, callback(expired), Date.now() + 600001)).rejects.toMatchObject({ code: "identity_required" })
    expect(row.purpose).toBe("signin")
  })
  it("has one callback winner under concurrent consumption", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }), request = callback(start); const outcomes = await Promise.allSettled([callbackOidcFlow(f.env, request), callbackOidcFlow(f.env, request)]); expect(outcomes.filter(x => x.status === "fulfilled")).toHaveLength(1) })
  it("refuses result use by wrong browser or purpose and expires it in ten minutes", async () => { const { row, cookie } = await result(); for (const operation of [() => readOidcResult(f.env, row.id, "wrong", "link"), () => readOidcResult(f.env, row.id, cookie, "invite"), () => readOidcResult(f.env, row.id, cookie, "link", Date.now() + 600001)]) await expect(operation()).rejects.toMatchObject({ code: "identity_required" }) })
  it("never consumes credential-connection OAuth state as identity state", async () => {
    const state = "credential-connection-state"
    await f.env.DB.prepare("INSERT INTO oauth_states(state_hash,tenant,connect,membership,expires_at,account,initiating_session,security_epoch,intent) VALUES (?,?,?,?,?,?,?,0,'create')").bind(await sha256Text(state),f.workspaces.work,"cn_connection","mem_owner",Date.now()+600000,f.account,f.session).run()
    const start = await startOidcFlow(f.env,{ purpose: "signin" })
    await expect(callbackOidcFlow(f.env,new Request(`${f.env.VAULT_ORIGIN}/auth/oidc/google/callback?state=${state}&code=fake`,{ headers: { cookie: start.cookie } }))).rejects.toMatchObject({ code: "identity_required" })
    expect(await f.env.DB.prepare("SELECT connect FROM oauth_states").first()).toEqual({ connect: "cn_connection" })
    expect(google.calls).toEqual([])
  })
  it("Google identification creates no account, session, passkey or recovery authority", async () => { const before = await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first(); const { row } = await result("signin"); expect(row.account).toBeNull(); expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM web_sessions").first()).toEqual(before); expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first()).toEqual({ n: 0 }); expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM recovery_codes").first()).toEqual({ n: 0 }) })
  it("refuses callback after sign-out or recovery epoch change", async () => { const start = await startOidcFlow(f.env, { purpose: "link", account }); await f.env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(f.account).run(); await expect(callbackOidcFlow(f.env, callback(start))).rejects.toMatchObject({ code: "identity_required" }); expect(google.calls).toEqual([]) })
  it("confirms the actual identity and refuses switched account/session or recovery", async () => { const { row } = await result(); for (const current of [{ ...account, account: "acc_member" }, { ...account, session: "different" }, { ...account, securityEpoch: 1 }]) await expect(finishOidcLink(f.env, current, row, { email: row.email, subject: row.subject })).rejects.toMatchObject({ code: "identity_required" }); await expect(finishOidcLink(f.env, account, row, { email: "other@northwind.example", subject: row.subject })).rejects.toMatchObject({ code: "identity_required" }); expect(await f.env.DB.prepare("SELECT * FROM oidc_identities").all()).toMatchObject({ results: [] }) })
  it("canonical issuer spellings cannot occupy the same identity on two accounts", async () => {
    const { row } = await result(); await finishOidcLink(f.env, account, row, { email: row.email, subject: row.subject })
    const other = await result("link", { iss: "accounts.google.com" }); await finishOidcLink(f.env, account, other.row, { email: other.row.email, subject: other.row.subject })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM oidc_identities").first()).toEqual({ n: 1 })
    await expect(finishOidcLink(f.env, account, row, { email: row.email, subject: row.subject })).rejects.toMatchObject({ code: "conflict" })
  })
  it("permits several linked subjects on one account, never another account claiming an occupied subject", async () => {
    const first = await result(); await finishOidcLink(f.env,account,first.row,{ email: first.row.email,subject: first.row.subject })
    const second = await result("link",{ sub: "second-google-subject" }); await finishOidcLink(f.env,account,second.row,{ email: second.row.email,subject: second.row.subject })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(account.account).first()).toEqual({ n: 2 })
    const now = Date.now()
    await f.env.DB.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,client) VALUES ('other','ses_other','acc_member',?,?,?,'web','passkey','Test')").bind(now,now+600000,now).run()
    const other = { ...account,account: "acc_member",session: "ses_other" },started = await startOidcFlow(f.env,{ purpose: "link",account: other }),row = await callbackOidcFlow(f.env,callback(started))
    await expect(finishOidcLink(f.env,other,row,{ email: row.email,subject: row.subject })).rejects.toMatchObject({ code: "conflict" })
    expect(await f.env.DB.prepare("SELECT account FROM oidc_identities WHERE subject='google-alex'").first()).toEqual({ account: account.account })
    expect(await f.env.DB.prepare("SELECT state FROM oidc_results WHERE id=?").bind(row.id).first()).toEqual({ state: "unused" })
  })
  it("sign-out during consent or before explicit confirmation invalidates linking", async () => {
    const pending = await result(),next = await startOidcFlow(f.env,{ purpose: "link",account })
    await f.env.DB.prepare("DELETE FROM web_sessions WHERE id=?").bind(account.session).run()
    await expect(callbackOidcFlow(f.env,callback(next))).rejects.toMatchObject({ code: "identity_required" })
    await expect(finishOidcLink(f.env,account,pending.row,{ email: pending.row.email,subject: pending.row.subject })).rejects.toMatchObject({ code: "identity_required" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM oidc_identities").first()).toEqual({ n: 0 })
  })
  it("has one link consumer and never retains provider tokens", async () => { const { row } = await result(); const outcomes = await Promise.allSettled([finishOidcLink(f.env, account, row, { email: row.email, subject: row.subject }), finishOidcLink(f.env, account, row, { email: row.email, subject: row.subject })]); expect(outcomes.filter(x => x.status === "fulfilled")).toHaveLength(1); const stored = JSON.stringify(await f.env.DB.prepare("SELECT * FROM oidc_results").all()); expect(stored).not.toContain("test-never-retained"); expect(stored).not.toContain("id_token") })
  it("native bootstrap is app-purpose-only, single-use and expires after five minutes", async () => {
    await f.env.DB.prepare("UPDATE web_sessions SET kind='app' WHERE id=?").bind(account.session).run()
    const context = { member: "mem_owner",rule: { provider: "google" as const,domains: ["northwind.example"],roles: ["owner" as const] },ruleRevision: 1,gateGeneration: 1,sequence: 1,startedAt: Date.now(),purpose: "session" as const,subjectDigest: null }
    const started = await startOidcFlow(f.env,{ purpose: "gate",account,workspace: f.workspaces.work,context,app: { sessionHash: "app-hash",challenge: "a".repeat(43) } })
    const params = new URLSearchParams(new URL(started.url).hash.slice(1)),state = params.get("state")!,flow = params.get("flow")!
    expect(started.url).toMatch(/\/auth\/oidc\/google\/app\/start#state=/)
    const bootstrap = await bootstrapAppOidc(f.env,state,flow)
    expect(bootstrap.cookie).toBe(started.cookie)
    expect(new URL(bootstrap.url).origin).toBe("https://accounts.google.com")
    await expect(bootstrapAppOidc(f.env,state,flow)).rejects.toMatchObject({ code: "identity_required" })
    const expired = await startOidcFlow(f.env,{ purpose: "gate",account,workspace: f.workspaces.work,context,app: { sessionHash: "app-hash",challenge: "a".repeat(43) } }),expiryParams = new URLSearchParams(new URL(expired.url).hash.slice(1))
    await expect(bootstrapAppOidc(f.env,expiryParams.get("state")!,expiryParams.get("flow")!,Date.now()+300001)).rejects.toMatchObject({ code: "identity_required" })
    await f.env.DB.prepare("UPDATE web_sessions SET kind='web' WHERE id=?").bind(account.session).run()
    const browser = await startOidcFlow(f.env,{ purpose: "signin" }),url = new URL(browser.url),cookie = oidcCookieToken(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: browser.cookie } }),"signin")
    await expect(bootstrapAppOidc(f.env,url.searchParams.get("state")!,cookie)).rejects.toMatchObject({ code: "identity_required" })
  })
  it("fails closed when Google configuration or provider is unavailable", async () => { const start = await startOidcFlow(f.env, { purpose: "signin" }); google.faults.unavailable = true; await expect(callbackOidcFlow(f.env, callback(start))).rejects.toMatchObject({ code: "identity_required" }); delete f.env.GOOGLE_SIGNIN_CLIENT_SECRET; await expect(startOidcFlow(f.env, { purpose: "signin" })).rejects.toMatchObject({ code: "identity_required" }) })
})
