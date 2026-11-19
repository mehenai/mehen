import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { afterEach,beforeEach,describe,expect,it } from "vitest"
import { createExecutionContext } from "cloudflare:test"
import { accountSigninOptions,accountSigninVerify } from "../src/directory/workspace-accounts.ts"
import { currentAccountAppSession } from "../src/directory/workspace-app-session.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { endOwnAccountSession } from "../src/directory/workspace-account-admin.ts"
import { STEP_UP_GRACE_MS } from "@mehen/protocol"
import { startAccountStepUp,requireAppAccountStepUp,requireAccountStepUp,stepUpGraceId } from "../src/directory/workspace-stepup.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { setPasskeyCeremonies,simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { directoryCeremonies,successfulDirectoryClient } from "./directory-test-support.ts"
import { reserveAccountSecurity,retryAccountSecurity } from "../src/directory/account-security.ts"
import { mirrorAccountEvents } from "../src/directory/account-events.ts"
let f: WorkspaceTestFixture
const assertion = { id: "credential",rawId: "credential",type: "public-key",response: {} }
beforeEach(async () => {
  f = await createWorkspaceFixture(); setPasskeyCeremonies(directoryCeremonies)
  await insertAccountPasskey(f.env,f.account,{ credentialId: "credential",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now()-1000,"signup","pk_old").run()
})
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
async function signin(kind: "web" | "app" = "web") { const { flow } = await accountSigninOptions(f.env); return accountSigninVerify(f.env,{ flow,response: assertion },undefined,Date.now(),kind) }
describe("account web and native app sessions",() => {
  it("app bearer and browser cookies cannot substitute for each other",async () => {
    const app = await signin("app"),bearer = new Request(f.env.VAULT_ORIGIN,{ headers: { authorization: `Bearer ${app.session.token}` } }),cookie = new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${app.session.token}` } })
    expect((await currentAccountAppSession(bearer,f.env))?.account).toBe(f.account)
    expect(await currentAccountSession(bearer,f.env)).toBeNull()
    expect(await currentAccountSession(cookie,f.env)).toBeNull()
    expect(await currentAccountAppSession(cookie,f.env)).toBeNull()
    const web = await signin()
    expect(await currentAccountAppSession(new Request(f.env.VAULT_ORIGIN,{ headers: { authorization: `Bearer ${web.session.token}` } }),f.env)).toBeNull()
  })
  it("app challenge is bound to the app session and cannot be spent with its cookie",async () => {
    const app = await signin("app"),request = new Request(f.env.VAULT_ORIGIN,{ headers: { authorization: `Bearer ${app.session.token}` } }),account = await currentAccountAppSession(request,f.env)
    if (!account) throw new Error("Missing app session")
    const action = { type: "device.revoke" as const,device: "dev_test" },proof = { nonce: (await startAccountStepUp(f.env,account,f.workspaces.work,action)).nonce,assertion },rc = { request,env: f.env,url: new URL(request.url),params: {},ctx: createExecutionContext() }
    await expectDirectoryRefusal(requireAccountStepUp({ ...rc,request: new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${app.session.token}` } }) },account,f.workspaces.work,action,proof),{ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(await requireAppAccountStepUp(rc,account,f.workspaces.work,action,proof)).toEqual({ action,factor: "pk_old",confirmation: { kind: "passkey",provenAt: expect.any(Number) } })
    await expectDirectoryRefusal(requireAppAccountStepUp(rc,account,f.workspaces.work,action,proof),{ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
  })
  it("single sign-out with unavailable DOs leaves surviving sessions and new sign-in working",async () => {
    const one = await signin(),two = await signin(),request = new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${one.session.token}` } }),account = await currentAccountSession(request,f.env)
    if (!account) throw new Error("Missing session")
    await endOwnAccountSession(f.env,account,account.session)
    const c = successfulDirectoryClient(); c.revokeSession = async () => { throw new Error("unavailable") }
    await mirrorAccountEvents(f.env,c)
    expect(await currentAccountSession(request,f.env)).toBeNull()
    expect((await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${two.session.token}` } }),f.env))?.account).toBe(f.account)
    expect((await signin()).account).toBe(f.account)
    expect(await f.env.DB.prepare("SELECT security_epoch,security_transition FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_epoch: 0,security_transition: null })
  })
  it("a browser passkey sign-in opens the window for its own session; an app sign-in or one while cooling off opens none",async () => {
    f.env = { ...f.env,STEPUP_GRACE: "on" }
    const windows = () => f.env.DB.prepare("SELECT id,challenge,factor,context,expires_at-CAST(challenge AS INTEGER) AS lasts FROM challenges WHERE kind='stepup-grace'").all().then(r => r.results)
    await signin("app")
    expect(await windows()).toEqual([])
    const web = await signin()
    expect(await windows()).toEqual([{ id: await stepUpGraceId(web.session.id),challenge: expect.stringMatching(/^\d+$/),factor: "pk_old",context: web.session.id,lasts: STEP_UP_GRACE_MS }])
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(Date.now()+86400000,f.account).run()
    await signin()
    expect(await windows()).toHaveLength(1)
  })
  it("a browser passkey sign-in while a security change is pending opens no window, and one after it settles does",async () => {
    f.env = { ...f.env,STEPUP_GRACE: "on" }
    const windows = () => f.env.DB.prepare("SELECT context FROM challenges WHERE kind='stepup-grace'").all().then(r => r.results)
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "sessions.end" },revokedSessionIds: [],removedFactorIds: [] })
    expect(await f.env.DB.prepare("SELECT security_transition,restricted_until FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ security_transition: id,restricted_until: null })
    const pending = await signin()
    expect(pending.account).toBe(f.account)
    expect(await windows()).toEqual([])
    await retryAccountSecurity(f.env,id,successfulDirectoryClient())
    const settled = await signin()
    expect(await windows()).toEqual([{ context: settled.session.id }])
  })
  it("removed-factor signin refuses during pending while older-factor sessions survive cancel",async () => {
    const now = Date.now(),notice = "ntc_cancel"
    await insertAccountPasskey(f.env,f.account,{ credentialId: "recovered",publicKey: new Uint8Array([2]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now,"recovery","pk_recovered").run()
    await f.env.DB.batch([f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(now+86400000,f.account),f.env.DB.prepare("INSERT INTO account_notices(id,account,kind,at,restricted_until) VALUES (?,?,'recovery',?,?)").bind(notice,f.account,now-1,now+86400000)])
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "recovery.cancel",notice,factor: "pk_old" },revokedSessionIds: [],removedFactorIds: [] })
    const { flow } = await accountSigninOptions(f.env)
    await expectDirectoryRefusal(accountSigninVerify(f.env,{ flow,response: { ...assertion,id: "recovered",rawId: "recovered" } }),{ error: "unauthenticated",message: "We could not sign you in with that passkey." })
    const survivor = await signin()
    await retryAccountSecurity(f.env,id,successfulDirectoryClient())
    expect((await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: `__Host-mehen_session=${survivor.session.token}` } }),f.env))?.account).toBe(f.account)
    const lineage = await f.env.DB.prepare("SELECT lineage FROM web_sessions WHERE id=?").bind(survivor.session.id).first<{ lineage: string }>()
    expect(JSON.parse(lineage?.lineage ?? "null")).toEqual({ kind: "factor",factor: "pk_old" })
  })
})

it("native step-up refuses widening, remembered decisions and foreign workspaces without a challenge",async () => {
  const { accountAppRoutes } = await import("../src/routes/account-app.ts"),app = await signin("app"),route = accountAppRoutes.find(route => route.path === "/app/v1/stepup")!
  await f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES ('tn_Foreign12345','foreign','Foreign','active','acc_admin',?)").bind(Date.now()).run()
  const decision = { type: "approval.decide" as const,approval: "apr_fixture",digest: "digest",decision: "approve" as const,constraints: { uses: null,ttlSeconds: 60 } }
  for (const input of [
    { scope: f.workspaces.work,action: { type: "member.invite",terms: { role: "guest",email: null,teams: [],shares: [{ project: "prj_a",level: "use",protected: false,expiresAt: null }],expiresAt: new Date(Date.now()+600000).toISOString() } } },
    { scope: f.workspaces.work,action: { ...decision,remember: { kind: "exact",selector: { device: "dev_fixture",session: null } } } },
    { scope: "tn_Foreign12345",action: decision },
  ]) {
    const url = new URL(`${f.env.VAULT_ORIGIN}/app/v1/stepup`),request = new Request(url,{ method: "POST",headers: { authorization: `Bearer ${app.session.token}` },body: JSON.stringify(input) })
    await expectDirectoryRefusal(route.handler({ request,url,env: f.env,params: {},ctx: createExecutionContext() }),input.scope === "tn_Foreign12345" ? { error: "not_found",message: "No such workspace." } : { error: "forbidden",message: "The app can only confirm exact request decisions. Open the vault page for other changes." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM challenges").first()).toEqual({ n: 0 })
  }
})
