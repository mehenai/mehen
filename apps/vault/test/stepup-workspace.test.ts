import { expectDirectoryRefusal } from "./directory-test-support.ts"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { createExecutionContext } from "cloudflare:test"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { reserveAccountSecurity } from "../src/directory/account-security.ts"
import { assertAccountStepUpAllowed, requireAccountStepUp, requireWorkspaceStepUp, startAccountStepUp, workspaceStepUpChallenge } from "../src/directory/workspace-stepup.ts"
import { PENDING_RESTRICTION_UNTIL } from "@mehen/protocol"
import { setPasskeyCeremonies, simpleWebAuthnCeremonies, type PasskeyCeremonies } from "../src/directory/webauthn.ts"
import { responseFor } from "../src/http.ts"
import type { RequestContext, WorkspaceRequest } from "../src/routes/context.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
import { ORIGIN } from "./helpers.ts"

const action: WorkspaceStepUpAction = { type: "device.revoke",device: "dev_test" }
const assertion = { id: "credential",rawId: "credential",type: "public-key",response: {} }
const ceremonies: PasskeyCeremonies = { ...simpleWebAuthnCeremonies,async verifyAuthentication(_response,expected) { return expected.challenge ? { counter: 1,backedUp: false } : null } }
let f: WorkspaceTestFixture
let rc: RequestContext
let ws: WorkspaceRequest
beforeEach(async () => {
  f = await createWorkspaceFixture()
  setPasskeyCeremonies(ceremonies)
  await insertAccountPasskey(f.env,f.account,{ credentialId: "credential",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },Date.now(),"signup","pk_test").run()
  rc = { request: new Request(`${ORIGIN}/api/w/alex`,{ headers: { cookie: f.cookie } }),env: f.env,ctx: createExecutionContext(),url: new URL(`${ORIGIN}/api/w/alex`),params: { ws: "alex" } }
  const account = await currentAccountSession(rc.request,rc.env)
  if (!account) throw new Error("Missing account")
  ws = { account,workspace: { id: f.workspaces.personal,slug: "alex",name: "Personal" },membership: f.personalMember }
})
afterEach(() => setPasskeyCeremonies(simpleWebAuthnCeremonies))
async function proof(a = action) { return { nonce: (await startAccountStepUp(f.env,ws.account,ws.workspace.id,a)).nonce,assertion } }
async function refused(run: () => Promise<unknown>) {
  const before = await f.env.DB.prepare("SELECT counter FROM passkeys WHERE handle='pk_test'").first()
  let error: unknown
  try { await run() } catch (e) { error = e }
  expect(error).toBeDefined()
  const response = responseFor(error)
  expect(response.status).toBe(403)
  expect(await response.json()).toEqual({ error: "forbidden",message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
  expect(await f.env.DB.prepare("SELECT counter FROM passkeys WHERE handle='pk_test'").first()).toEqual(before)
  expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 0 })
}
describe("stepup-workspace",() => {
  it("binds the v2 challenge to workspace and complete action",async () => {
    const one = await workspaceStepUpChallenge("nonce",f.workspaces.personal,action)
    expect(one).not.toBe(await workspaceStepUpChallenge("nonce",f.workspaces.work,action))
    expect(one).not.toBe(await workspaceStepUpChallenge("nonce",f.workspaces.personal,{ ...action,device: "dev_other" }))
    expect(await requireWorkspaceStepUp(rc,ws,action,await proof())).toEqual({ action,factor: "pk_test",confirmation: { kind: "passkey",provenAt: expect.any(Number) } })
  })
  it("refuses a foreign workspace without changing state",async () => { const p = await proof(); await refused(() => requireWorkspaceStepUp(rc,{ ...ws,workspace: { ...ws.workspace,id: f.workspaces.work } },action,p)) })
  it("refuses changed action and wrong kind without changing state",async () => {
    await refused(async () => requireWorkspaceStepUp(rc,ws,{ ...action,device: "dev_other" },await proof()))
    await refused(async () => requireWorkspaceStepUp(rc,ws,{ type: "workspace.unfreeze" },await proof()))
  })
  it("consumes once and refuses replay",async () => { const p = await proof(); await requireWorkspaceStepUp(rc,ws,action,p); await refused(() => requireWorkspaceStepUp(rc,ws,action,p)) })
  it("refuses missing proof, sign-out, epoch change and expired challenge",async () => {
    await refused(() => requireWorkspaceStepUp(rc,ws,action,undefined))
    const p = await proof()
    await f.env.DB.prepare("UPDATE challenges SET expires_at=0").run()
    await refused(() => requireWorkspaceStepUp(rc,ws,action,p))
    const q = await proof()
    await f.env.DB.prepare("UPDATE accounts SET security_epoch=1 WHERE id=?").bind(f.account).run()
    await refused(() => requireWorkspaceStepUp(rc,ws,action,q))
    await f.env.DB.prepare("DELETE FROM web_sessions").run()
    await refused(() => requireWorkspaceStepUp(rc,ws,action,q))
  })
  it("rechecks session and factor after async verification",async () => {
    const p = await proof()
    setPasskeyCeremonies({ ...ceremonies,async verifyAuthentication() { await f.env.DB.prepare("DELETE FROM passkeys WHERE handle='pk_test'").run(); return { counter: 1,backedUp: false } } })
    const before = await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()
    await expectDirectoryRefusal(requireWorkspaceStepUp(rc,ws,action,p),{ error: "conflict",message: "Account state changed. Try again." })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual(before)
  })
  it("pending excludes keep at start and verification while cancel remains available",async () => {
    const keep = { type: "recovery.resolve" as const,notice: "ntc_recovery",outcome: "keep" as const }
    const p = { nonce: (await startAccountStepUp(f.env,ws.account,"-",keep)).nonce,assertion }
    const id = await reserveAccountSecurity(f.env,f.account,{ effect: { kind: "factor.remove" },revokedSessionIds: [],removedFactorIds: ["pk_other"] })
    const expected = { error: "account_pending",message: "Account security changes are still pending.",transition: { id,reservedEpoch: 1,targets: 2,acknowledged: 0,state: "pending" },next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "Wait for the account security change to complete." } }
    for (const run of [() => startAccountStepUp(f.env,ws.account,"-",keep),() => requireAccountStepUp(rc,ws.account,"-",keep,p)]) {
      let error: unknown
      try { await run() } catch (e) { error = e }
      const response = responseFor(error)
      expect(response.status).toBe(403)
      expect(await response.json()).toEqual(expected)
    }
    expect(await f.env.DB.prepare("SELECT counter FROM passkeys WHERE handle='pk_test'").first()).toEqual({ counter: 0 })
    expect(await startAccountStepUp(f.env,ws.account,"-",{ ...keep,outcome: "cancel" })).toHaveProperty("nonce")
  })
  it("refuses account actions under a workspace scope",async () => { await expectDirectoryRefusal(startAccountStepUp(f.env,ws.account,ws.workspace.id,{ type: "recovery.generate" }),{ error: "bad_request",message: "That action does not belong to this scope." }) })
})

describe("a widening step-up while the account is cooling off", () => {
  const widen: WorkspaceStepUpAction = { type: "workspace.create",slug: "other",name: "Other" }
  const message = "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access."
  it("says when it ends and what to do meanwhile, with the account page", async () => {
    const until = Date.UTC(2026,9,31,15,45)
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(until,f.account).run()
    await expectDirectoryRefusal(assertAccountStepUpAllowed(f.env,f.account,widen,until - 60_000),{ error: "forbidden",message,next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "It ends 2026-10-31 15:45 UTC; until then, ask another owner or admin if this cannot wait." } })
    await assertAccountStepUpAllowed(f.env,f.account,action,until - 60_000)
  })
  it("a recovery still committing has no end date yet, and says so", async () => {
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(PENDING_RESTRICTION_UNTIL,f.account).run()
    await expectDirectoryRefusal(assertAccountStepUpAllowed(f.env,f.account,widen),{ error: "forbidden",message,next: { url: `${f.env.VAULT_ORIGIN}/account`,say: "It ends once your recovery completes; until then, ask another owner or admin if this cannot wait." } })
  })
})

describe("how careful a credential is, while the account is cooling off", () => {
  const posture = (level: "ask" | "routine" | "trust"): WorkspaceStepUpAction => ({ type: "item.posture",item: "itm_github01",digest: "d",level })
  it("may go back to ask, and never to routine or trust", async () => {
    const until = Date.now() + 3_600_000
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(until,f.account).run()
    await assertAccountStepUpAllowed(f.env,f.account,posture("ask"))
    for (const level of ["routine","trust"] as const)
      await expectDirectoryRefusal(assertAccountStepUpAllowed(f.env,f.account,posture(level)),{ error: "forbidden",message: "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access.",next: expect.anything() })
  })
})

import { projectFixture, inAccess } from "./projects-workspace-fixture.ts"
import { batchAsk, batchActionFor, decideBatch } from "./approvals-batch-support.ts"
import { VaultError } from "../src/http.ts"
// approval.decide_many: one passkey over the exact sorted list.
describe("a batch decision's step-up", () => {
  const entry = (approval: string, decision: "approve" | "deny") => ({ approval, digest: "A".repeat(43), decision, uses: 1, ttlSeconds: 600 })
  // Deny-only, so the personal workspace's own session gate (for widening) is not in play.
  const many: WorkspaceStepUpAction = { type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "deny")] }
  it("binds the exact list: a changed, dropped or added entry refuses, and a signed list cannot be replayed", async () => {
    const changed: WorkspaceStepUpAction[] = [
      { type: "approval.decide_many", entries: [entry("apr_a", "deny"), { ...entry("apr_b", "deny"), digest: "B".repeat(43) }] },
      { type: "approval.decide_many", entries: [entry("apr_a", "deny")] },
      { type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "deny"), entry("apr_c", "deny")] },
      { type: "approval.decide_many", entries: [entry("apr_a", "deny"), { ...entry("apr_b", "deny"), uses: 2 }] },
    ]
    for (const other of changed) await refused(async () => requireWorkspaceStepUp(rc,ws,other,await proof(many)))
    const p = await proof(many)
    expect(await requireWorkspaceStepUp(rc,ws,many,p)).toEqual({ action: many,factor: "pk_test",confirmation: { kind: "passkey",provenAt: expect.any(Number) } })
    await refused(() => requireWorkspaceStepUp(rc,ws,many,p))
  })
  it("while cooling off, starts a batch that only denies and refuses one that approves anything", async () => {
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(Date.now() + 86_400_000,f.account).run()
    const denies: WorkspaceStepUpAction = { type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "deny")] }
    expect(await startAccountStepUp(f.env,ws.account,ws.workspace.id,denies)).toHaveProperty("nonce")
    await expectDirectoryRefusal(startAccountStepUp(f.env,ws.account,ws.workspace.id,{ type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "approve")] }),{ error: "forbidden",message: "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access.",next: expect.anything() })
  })
  it("in the vault, decides nothing unless the passkey covered the list the vault rebuilds from storage", async () => {
    const vault = await projectFixture()
    await inAccess(vault.tenant, (ctx) => {
      const rows = [batchAsk(ctx, { body: "1" }), batchAsk(ctx, { body: "2" })]
      const entries = rows.map((r) => ({ id: r.id, decision: "approve" as const }))
      const signed = batchActionFor(ctx, "kim", entries)
      const before = ctx.sql.exec("SELECT id,status FROM approvals ORDER BY id").toArray()
      const attempts = [
        () => decideBatch(ctx, "kim", [entries[0]!], signed),
        () => decideBatch(ctx, "kim", [entries[0]!, { ...entries[1]!, decision: "deny" }], signed),
        () => decideBatch(ctx, "kim", entries, batchActionFor(ctx, "kim", [entries[0]!])),
      ]
      for (const attempt of attempts) {
        try { attempt(); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "This needs a passkey confirmation of the exact action." }) }
      }
      expect(ctx.sql.exec("SELECT id,status FROM approvals ORDER BY id").toArray()).toEqual(before)
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM audit WHERE action='approval.batch'").toArray()).toEqual([{ n: 0 }])
      expect(decideBatch(ctx, "kim", entries, signed)).toMatchObject({ approved: 2, denied: 0, skipped: 0 })
    })
  })
})
