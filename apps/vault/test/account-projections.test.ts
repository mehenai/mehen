import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { beforeEach,describe,expect,it } from "vitest"
import { createExecutionContext } from "cloudflare:test"
import { z } from "zod"
import type { AccountSessionsRead,PasskeyView,RecoveryStatus } from "@mehen/protocol/api"
import { workspaceDirectoryPrefix } from "../src/routes/directory.ts"
import { accountSessionStatements,insertAccountPasskey } from "../src/directory/account-store.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { successfulDirectoryClient } from "./directory-test-support.ts"
import { accountSessions,removeAccountPasskey,renameAccountPasskey } from "../src/directory/workspace-account-admin.ts"
import { newSession } from "../src/directory/session.ts"
import { responseFor } from "../src/http.ts"
import { createWorkspaceFixture,type WorkspaceTestFixture } from "./workspace-fixtures.ts"

// These protocol contracts are TypeScript-only. Strict schemas pin their exact
// runtime projection without adding a second public protocol declaration.
const Passkey: z.ZodType<PasskeyView> = z.strictObject({ passkey: z.string(),name: z.string().nullable(),authenticator: z.string(),synced: z.boolean().nullable(),addedVia: z.enum(["signup","settings","recovery","reset","break-glass"]),createdAt: z.iso.datetime(),lastUsedAt: z.iso.datetime().nullable(),lastUsedClient: z.string().nullable(),lastUsedPlace: z.string().nullable(),current: z.boolean() })
const Sessions: z.ZodType<AccountSessionsRead> = z.strictObject({ sessions: z.array(z.strictObject({ session: z.string(),kind: z.enum(["web","app"]),method: z.enum(["signup","passkey","recovery","reset"]),client: z.string(),place: z.string().nullable(),passkeyName: z.string().nullable(),createdAt: z.iso.datetime(),lastSeenAt: z.iso.datetime(),current: z.boolean() })),mayEndOtherSessions: z.boolean() })
const Recovery: z.ZodType<RecoveryStatus> = z.strictObject({ active: z.strictObject({ generatedAt: z.iso.datetime(),total: z.number().int(),left: z.number().int() }).nullable() })
let f: WorkspaceTestFixture
beforeEach(async () => {
  f = await createWorkspaceFixture()
  await insertAccountPasskey(f.env,f.account,{ credentialId: "current-credential",publicKey: new Uint8Array([1]),counter: 0,transports: ["internal"],aaguid: null,deviceType: "multiDevice",backedUp: true },Date.now()-1000,"signup","pk_current").run()
  await insertAccountPasskey(f.env,"acc_guest",{ credentialId: "foreign-credential",publicKey: new Uint8Array([2]),counter: 0,transports: ["usb"],aaguid: null,deviceType: "singleDevice",backedUp: false },Date.now()-1000,"signup","pk_foreign").run()
  await f.env.DB.batch([f.env.DB.prepare("UPDATE web_sessions SET passkey='current-credential' WHERE id=?").bind(f.session),f.env.DB.prepare("UPDATE passkeys SET name='My passkey' WHERE handle='pk_current'")])
})
async function call(path: string,body?: unknown,headers: Record<string,string> = {}) {
  const url = new URL(`${f.env.VAULT_ORIGIN}${path}`),request = new Request(url,{ method: body === undefined ? "GET" : "POST",headers: { cookie: f.cookie,origin: f.env.VAULT_ORIGIN,"content-type": "application/json",...headers },...(body === undefined ? {} : { body: JSON.stringify(body) }) })
  try { const response = await workspaceDirectoryPrefix({ request,env: f.env,url,ctx: createExecutionContext(),params: {} }); if (!response) throw new Error("Missing account route"); return response } catch (error) { return responseFor(error) }
}
describe("frozen account projections",() => {
  it("parses exact passkey and session envelopes with current flags and no credential ids",async () => {
    const app = await newSession(),ceremony = await newSession()
    await f.env.DB.batch([
      ...accountSessionStatements(f.env,app,f.account,Date.now(),{ kind: "app",method: "passkey",passkey: "current-credential",client: "Native app",place: null }),
      ...accountSessionStatements(f.env,ceremony,f.account,Date.now(),{ kind: "recovery",method: "recovery",passkey: null,client: "Browser",place: null }),
    ])
    const passkeys = z.strictObject({ passkeys: z.array(Passkey) }).parse(await (await call("/api/account/passkeys")).json())
    expect(passkeys.passkeys).toHaveLength(1)
    expect(passkeys.passkeys[0]).toMatchObject({ passkey: "pk_current",name: "My passkey",authenticator: "Built into a device",synced: true,current: true })
    const sessions = Sessions.parse(await (await call("/api/account/sessions")).json())
    expect(sessions.sessions).toHaveLength(2)
    expect(sessions.mayEndOtherSessions).toBe(true)
    expect(sessions.sessions.find(session => session.session === f.session)).toMatchObject({ current: true,passkeyName: "My passkey" })
    expect(sessions.sessions.find(session => session.session === app.id)).toMatchObject({ current: false,kind: "app" })
    const json = JSON.stringify({ passkeys,sessions })
    for (const secret of ["current-credential","foreign-credential",app.token,app.tokenHash,ceremony.token,"public_key","counter"]) expect(json).not.toContain(secret)
  })
  it("does not list a virtually revoked session while its D1 row awaits commit",async () => {
    await insertAccountPasskey(f.env,f.account,{ credentialId: "retiring",publicKey: new Uint8Array([3]),counter: 0,transports: ["usb"],aaguid: null,deviceType: "singleDevice",backedUp: false },Date.now(),"settings","pk_retiring").run()
    const app = await newSession()
    await f.env.DB.batch(accountSessionStatements(f.env,app,f.account,Date.now(),{ kind: "app",method: "passkey",passkey: "retiring",client: "Native app",place: null }))
    const actor = await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: f.cookie } }),f.env)
    if (!actor) throw new Error("Missing fixture actor")
    const client = successfulDirectoryClient(); client.install = async () => { throw new Error("unavailable") }
    expect(await removeAccountPasskey(f.env,actor,"pk_retiring","pk_current",client)).toEqual({ pending: true })
    expect(await f.env.DB.prepare("SELECT id FROM web_sessions WHERE id=?").bind(app.id).first()).toEqual({ id: app.id })
    expect((await accountSessions(f.env,actor)).map(session => session.session)).toEqual([f.session])
  })
  it("renames only an own passkey without a step-up and returns its frozen view",async () => {
    const response = await call("/api/account/passkeys/pk_current/rename",{ name: "Security key" })
    expect(response.status).toBe(200)
    expect(z.strictObject({ passkey: Passkey }).parse(await response.json()).passkey).toMatchObject({ passkey: "pk_current",name: "Security key",current: true })
    const foreign = await call("/api/account/passkeys/pk_foreign/rename",{ name: "Stolen" })
    expect(foreign.status).toBe(404)
    expect(await foreign.json()).toEqual({ error: "not_found",message: "You have no passkey with that id." })
    expect(await f.env.DB.prepare("SELECT name FROM passkeys WHERE handle='pk_foreign'").first()).toEqual({ name: null })
  })
  it("a stale committed epoch refuses rename without changing its name or audit",async () => {
    const actor = await currentAccountSession(new Request(f.env.VAULT_ORIGIN,{ headers: { cookie: f.cookie } }),f.env)
    if (!actor) throw new Error("Missing fixture actor")
    await f.env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(f.account).run()
    await expectDirectoryRefusal(renameAccountPasskey(f.env,actor,"pk_current","Stale"),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT name FROM passkeys WHERE handle='pk_current'").first()).toEqual({ name: "My passkey" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 0 })
  })
  it("returns the existing recovery status shape without any recovery values",async () => {
    expect(Recovery.parse(await (await call("/api/account/recovery")).json())).toEqual({ active: null })
    const now = Date.now()
    await f.env.DB.batch(Array.from({ length: 10 },(_,i) => f.env.DB.prepare("INSERT INTO recovery_codes(code_hash,account,batch,position,status,created_at) VALUES (?,?,?,?,'active',?)").bind(`hash-${i}`,f.account,"rcb_test",i+1,now)))
    const response = Recovery.parse(await (await call("/api/account/recovery")).json())
    expect(response).toEqual({ active: { generatedAt: new Date(now).toISOString(),total: 10,left: 10 } })
    expect(JSON.stringify(response)).not.toContain("hash-")
  })
  it("keeps recovery codes off agent and foreign browser surfaces",async () => {
    const response = await call("/api/auth/recovery",{ code: "not-a-code" },{ "Mehen-Proof": "agent","sec-fetch-site": "same-origin","sec-fetch-mode": "cors" })
    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({ error: "forbidden",message: "Use a recovery code only on the vault's recovery page, not through an agent or another site." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM auth_attempts").first()).toEqual({ n: 0 })
  })
})
