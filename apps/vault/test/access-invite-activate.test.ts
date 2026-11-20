// An email-bound invitation whose signed terms say onJoin "activate" makes
// the member active when they redeem it with the invited email proved;
// owner invitations and open links always wait for an owner or admin.
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { canonicalJson, type InviteTerms } from "@mehen/protocol"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, workspaceInvoke } from "./access-test-support.ts"
import { noticesFor, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { noticeRows } from "../src/ui/pages/needs-you.ts"
import { fixtureSql } from "./fixture-sql.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

const later = () => new Date(Date.now() + 600_000).toISOString()
const memberTerms = (onJoin?: InviteTerms["onJoin"]): InviteTerms => ({ role: "member", email: "new@example.com", teams: ["tm_engineering"], shares: [{ project: "prj_a", level: "use", protected: false, expiresAt: null }], expiresAt: later(), ...(onJoin ? { onJoin } : {}) })
const openGuestTerms = (onJoin: InviteTerms["onJoin"]): InviteTerms => ({ role: "guest", email: null, teams: [], shares: [{ project: "prj_a", level: "use", protected: false, expiresAt: null }], expiresAt: later(), onJoin })

async function create(tenant: string, terms: InviteTerms, inviter = "admin", invite = "inv_activate") {
  return workspaceInvoke(tenant, "access.invites.create", { invite, codeHash: `hash-${invite}`, terms, reservation: { expiresAt: new Date(Date.now() + 60_000).toISOString() } }, accountAuth(inviter, { type: "member.invite", terms }))
}

const system = { kind: "system", reason: "test" } as const
function redeem(tenant: string, email: string | null, hd: string | null = null) {
  return workspaceInvoke(tenant, "access.invites.redeem", { member: "mem_new", account: "acc_new", name: "New", codeHash: "hash-inv_activate", evidence: { recoverySetup: true, identity: email === null ? null : { provider: "google", subject: "new-subject", email, hd } } }, system)
}
// Terms written straight into the workspace, as no inviter could sign them.
function forge(tenant: string, terms: InviteTerms, invite = "inv_activate") {
  return inAccess(tenant, (ctx) => { ctx.sql.exec("INSERT INTO invites(id,code_hash,terms,digest,creator,created_at,status) VALUES (?,?,?,'forged','mem_owner',?,'open')", invite, `hash-${invite}`, canonicalJson(terms), ctx.now()) })
}
const newMemberRow = (tenant: string) => inAccess(tenant, (ctx) => ctx.sql.exec<{ status: string }>("SELECT status FROM members WHERE id='mem_new'").toArray())
const notices = (tenant: string) => inAccess(tenant, (ctx) => ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY account").toArray().map((n) => ({ account: n.account, payload: JSON.parse(n.payload) as unknown })))
const events = (tenant: string) => inAccess(tenant, (ctx) => ctx.sql.exec<{ actor: string; action: string; target: string; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE target='mem_new' ORDER BY seq").toArray().map((e) => ({ ...e, detail: JSON.parse(e.detail) as unknown })))

describe("access.invites.create: onJoin", () => {
  it("refuses activate on an owner invitation or an open link, and keeps it on an email-bound member", async () => {
    const { tenant } = await accessFixture()
    const before = await accessSnapshot(tenant)
    const refused = { ok: false, error: { status: 400, vaultError: { error: "bad_request", message: "Owner invitations and open links always wait for confirmation." } } }
    expect(await create(tenant, { ...memberTerms("activate"), role: "owner", teams: [] }, "owner")).toEqual(refused)
    expect(await create(tenant, openGuestTerms("activate"))).toEqual(refused)
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await create(tenant, { ...memberTerms("confirm"), role: "owner", teams: [] }, "owner", "inv_owner")).toMatchObject({ ok: true, value: { invite: { terms: { role: "owner", onJoin: "confirm" } } } })
    expect(await create(tenant, openGuestTerms("confirm"), "admin", "inv_open")).toMatchObject({ ok: true, value: { invite: { terms: { email: null, onJoin: "confirm" } } } })
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true, value: { invite: { terms: { onJoin: "activate" } } } })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ id: string }>("SELECT id FROM invites ORDER BY id").toArray().map((r) => r.id)).toEqual(["inv_activate", "inv_open", "inv_owner"]))
  })
})

describe("access.invites.redeem: joining straight away", () => {
  it("makes the member active with the invitation's teams and shares when the proved email is the invited one, and logs the inviter's confirmation", async () => {
    const { tenant } = await accessFixture()
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true })
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "active" } })
    await inAccess(tenant, (ctx) => {
      expect(ctx.sql.exec("SELECT status FROM members WHERE id='mem_new'").toArray()).toEqual([{ status: "active" }])
      expect(ctx.sql.exec("SELECT team FROM team_members WHERE member='mem_new'").toArray()).toEqual([{ team: "tm_engineering" }])
      expect(ctx.sql.exec("SELECT project FROM project_shares WHERE subject_id='mem_new'").toArray()).toEqual([{ project: "prj_a" }])
      expect(ctx.sql.exec("SELECT status,used_by,member FROM invites WHERE id='inv_activate'").toArray()).toEqual([{ status: "active", used_by: "acc_new", member: "mem_new" }])
    })
    expect(await events(tenant)).toEqual([
      { actor: "member:mem_new", action: "member.join", target: "mem_new", detail: {} },
      { actor: "member:mem_admin", action: "member.confirm", target: "mem_new", detail: { reason: "invitation" } },
    ])
    // Only the inviter is told, and Needs you says who joined as what.
    expect(await notices(tenant)).toEqual([{ account: "acc_admin", payload: { kind: "member_joined", workspace: { id: tenant, slug: "work", name: "Work" }, member: "mem_new", name: "New", role: "member", by: "mem_admin", at: expect.any(String) } }])
    const shown = await inAccess(tenant, (ctx) => noticesFor(ctx, { kind: "member", account: "acc_admin", memberId: "mem_admin", session: "ses_admin", securityEpoch: 0, sessionCheck: null }))
    expect(shown.map((n) => n.url)).toEqual([`${env.VAULT_ORIGIN}/w/work/people`])
    expect(noticeRows(shown, env.VAULT_ORIGIN, false).toString()).toContain("New joined as member")
    // A retry of the same redemption answers as before and changes nothing.
    const after = await accessSnapshot(tenant)
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "active" } })
    expect(await accessSnapshot(tenant)).toBe(after)
  })

  it("lets the member in under a workspace identity rule covering members only with Google's matching hosted domain, and otherwise changes nothing", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 1) })
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true })
    const before = await accessSnapshot(tenant)
    for (const hd of ["other.com", null]) expect(await redeem(tenant, "new@example.com", hd), String(hd)).toEqual({ ok: false, error: { status: 403, vaultError: { error: "identity_required", message: "Check your workspace identity before joining." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await redeem(tenant, "new@example.com", "example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "active" } })
    expect(await newMemberRow(tenant)).toEqual([{ status: "active" }])
  })

  it("refuses a different or missing proof, as without onJoin, and lets nobody in", async () => {
    const { tenant } = await accessFixture()
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true })
    const before = await accessSnapshot(tenant)
    for (const email of ["other@example.com", "New@example.com", null]) expect(await redeem(tenant, email)).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "Prove the invited email before joining." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("keeps an open link and an owner invitation waiting even when their terms were forged to say activate", async () => {
    const cases: [InviteTerms, string | null][] = [[openGuestTerms("activate"), null], [openGuestTerms("activate"), "someone@example.com"], [{ ...memberTerms("activate"), role: "owner", teams: [] }, "new@example.com"]]
    for (const [terms, email] of cases) {
      const { tenant } = await accessFixture()
      await forge(tenant, terms)
      expect(await redeem(tenant, email), terms.role).toEqual({ ok: true, value: { member: "mem_new", state: "pending_confirmation" } })
      expect(await newMemberRow(tenant)).toEqual([{ status: "unconfirmed" }])
      expect((await events(tenant)).map((e) => e.action)).toEqual(["member.join"])
      expect(await notices(tenant)).toEqual([])
    }
  })

  it("keeps terms signed with confirm, and terms signed before onJoin existed, waiting for confirmation", async () => {
    for (const terms of [memberTerms("confirm"), memberTerms()]) {
      const { tenant } = await accessFixture()
      expect(await create(tenant, terms)).toMatchObject({ ok: true })
      expect(await redeem(tenant, "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "pending_confirmation" } })
      expect(await newMemberRow(tenant)).toEqual([{ status: "unconfirmed" }])
      expect((await events(tenant)).map((e) => e.action)).toEqual(["member.join"])
      expect(await notices(tenant)).toEqual([])
    }
  })

  it("answers active to a retry once an owner has confirmed a member who waited, and changes nothing", async () => {
    const { tenant } = await accessFixture()
    const created = await create(tenant, memberTerms("confirm"))
    if (!created.ok) throw new Error(JSON.stringify(created))
    const { digest: termsDigest } = (created.value as { invite: { digest: string } }).invite
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "pending_confirmation" } })
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, accountAuth("owner", { type: "member.confirm", member: "mem_new", termsDigest, identityRuleRevision: 0 }))).toMatchObject({ ok: true, value: { status: "active" } })
    const confirmed = await accessSnapshot(tenant)
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "active" } })
    expect(await accessSnapshot(tenant)).toBe(confirmed)
  })

  it("lets nobody in once the inviter may no longer invite that role", async () => {
    const { tenant } = await accessFixture()
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => { fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_admin'") })
    const before = await accessSnapshot(tenant)
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This invitation needs an eligible owner or admin to reissue it." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("lets nobody in once the terms have run out", async () => {
    const { tenant } = await accessFixture()
    expect(await create(tenant, memberTerms("activate"))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => { ctx.sql.exec("UPDATE invites SET terms=json_set(terms,'$.expiresAt',?)", new Date(ctx.now() - 1).toISOString()) })
    const before = await accessSnapshot(tenant)
    expect(await redeem(tenant, "new@example.com")).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such invite." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
})
