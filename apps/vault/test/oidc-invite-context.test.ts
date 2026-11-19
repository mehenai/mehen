import { afterEach, beforeEach, describe, expect, it } from "vitest"
import type { InviteTerms, SessionIdentityCheck } from "@mehen/protocol"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, installTestIdentity, workspaceInvoke } from "./access-test-support.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { fixtureSql } from "./fixture-sql.ts"
const system = { kind: "system",reason: "OIDC invite test" } as const
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
const rule = { provider: "google",domains: ["northwind.example"],roles: ["owner"] } as const
function check(sequence = 1,generation = 0,revision = 1): SessionIdentityCheck { return { id: `chk_owner_${sequence}`,checkSequence: sequence,gateGeneration: generation,identityRuleRev: revision,succeededAt: new Date(Date.now()-1000).toISOString(),expiresAt: new Date(Date.now()+3600000).toISOString() } }
async function invitation(covered = false) {
  const f = await accessFixture(),terms: InviteTerms = { role: "guest",email: "new@northwind.example",teams: [],shares: [{ project: "prj_a",level: "use",protected: false,expiresAt: null }],expiresAt: new Date(Date.now()+3600000).toISOString() }
  const auth = { ...accountAuth("owner",{ type: "member.invite",terms }),sessionCheck: covered ? check() : null }
  if (covered) await inAccess(f.tenant,ctx => { setSetting(ctx,"identity_rule",rule); setSetting(ctx,"identity_rule_rev",1); installTestIdentity(ctx,auth) })
  expect(await workspaceInvoke(f.tenant,"access.invites.create",{ invite: "inv_oidc_context",codeHash: "oidc-hash",terms,reservation: { expiresAt: new Date(Date.now()+60000).toISOString() } },auth)).toMatchObject({ ok: true })
  return { ...f,terms,auth }
}
describe("OIDC invite identity context system seam", () => {
  it("returns a readonly authoritative snapshot and refuses non-system callers", async () => { const f = await invitation(),before = await accessSnapshot(f.tenant); expect(await workspaceInvoke(f.tenant,"access.invites.identity_context",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: true,value: { termsDigest: expect.any(String),role: "guest",identityRule: null,identityRuleRev: 0 } }); expect(await workspaceInvoke(f.tenant,"access.invites.identity_context",{ codeHash: "oidc-hash" },accountAuth())).toMatchObject({ ok: false,error: { status: 403 } }); expect(await accessSnapshot(f.tenant)).toBe(before) })
  it.each(["unknown","expired","revoked"] as const)("%s codes have the same not_found refusal", async kind => { const f = await invitation(); if (kind === "expired") await inAccess(f.tenant,ctx => ctx.sql.exec("UPDATE invites SET terms=json_set(terms,'$.expiresAt',?)",new Date(ctx.now()-1).toISOString())); if (kind === "revoked") expect(await workspaceInvoke(f.tenant,"access.invites.revoke",{ invite: "inv_oidc_context" },accountAuth())).toMatchObject({ ok: true }); const before = await accessSnapshot(f.tenant); expect(await workspaceInvoke(f.tenant,"access.invites.identity_context",{ codeHash: kind === "unknown" ? "unknown" : "oidc-hash" },system)).toEqual({ ok: false,error: { status: 404,vaultError: { error: "not_found",message: "No such invite." } } }); expect(await accessSnapshot(f.tenant)).toBe(before) })
})
describe("inviteCreatorEligible current evidence (ACCESS review F5)", () => {
  it("same-session and new-session re-gates keep earlier lookup, redemption and confirmation working", async () => {
    const f = await invitation(true),owner = { ...f.auth,sessionCheck: check(2) }
    await inAccess(f.tenant,ctx => installTestIdentity(ctx,owner))
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: true })
    const another = { ...owner,session: "ses_new_owner",sessionCheck: check(3) }
    await inAccess(f.tenant,ctx => installTestIdentity(ctx,another))
    expect(await workspaceInvoke(f.tenant,"access.session_revoke",{ account: "acc_owner",session: owner.session },system)).toMatchObject({ ok: true })
    expect(await workspaceInvoke(f.tenant,"access.invites.redeem",{ codeHash: "oidc-hash",member: "mem_new",account: "acc_new",name: "New",evidence: { recoverySetup: true,identity: { provider: "google",subject: "sub-new",email: f.terms.email,hd: "northwind.example" } } },system)).toMatchObject({ ok: true })
    const lookup = await workspaceInvoke(f.tenant,"access.invites.identity_context",{ codeHash: "oidc-hash" },system)
    if (!lookup.ok) throw new Error("Missing invite context")
    const termsDigest = (lookup.value as { termsDigest: string }).termsDigest
    expect(await workspaceInvoke(f.tenant,"access.members.confirm",{ member: "mem_new" },{ ...another,stepUp: { type: "member.confirm",member: "mem_new",termsDigest,identityRuleRevision: 1 } })).toMatchObject({ ok: true,value: { status: "active" } })
  })
  it("null invalidation and rule changes refuse until current re-verification; demotion never borrows evidence", async () => {
    const f = await invitation(true)
    expect(await workspaceInvoke(f.tenant,"access.identity.install",{ account: "acc_owner",member: "mem_owner",session: f.auth.session,securityEpoch: 0,sessionCheck: null,invalidation: "creator-unlink" },system)).toMatchObject({ ok: true })
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: false,error: { vaultError: { error: "forbidden" } } })
    await inAccess(f.tenant,ctx => installTestIdentity(ctx,{ ...f.auth,sessionCheck: check(2,1) }))
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: true })
    await inAccess(f.tenant,ctx => { setSetting(ctx,"identity_rule_rev",2); ctx.sql.exec("UPDATE members SET gate_generation=2 WHERE id='mem_owner'") })
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: false,error: { vaultError: { error: "forbidden" } } })
    await inAccess(f.tenant,ctx => installTestIdentity(ctx,{ ...f.auth,sessionCheck: check(3,2,2) }))
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: true })
    await inAccess(f.tenant,ctx => fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_owner'"))
    const before = await accessSnapshot(f.tenant)
    expect(await workspaceInvoke(f.tenant,"access.invites.lookup",{ codeHash: "oidc-hash" },system)).toMatchObject({ ok: false,error: { vaultError: { error: "forbidden" } } })
    expect(await accessSnapshot(f.tenant)).toBe(before)
  })
})
