import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { newMember, noticesFor, registerOffboardingHook, WorkspaceInviteViewSchema, updateRestriction, installSecurity, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { noticeRows } from "../src/ui/pages/needs-you.ts"

import type { InviteTerms } from "@mehen/protocol"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("access owners", () => {
  it("refuses last-owner demotion, suspension, removal and leave without state change", async () => {
    const { tenant } = await accessFixture()
    for (const op of ["role", "suspend", "remove", "leave"] as const) {
      const input = { member: "mem_owner", ...(op === "role" ? { role: "member" } : {}) }
      const before = await accessSnapshot(tenant)
      const action = op === "role" ? { type: "member.role" as const, member: "mem_owner", before: "owner" as const, after: "member" as const } : { type: `member.${op}` as "member.suspend" | "member.remove" | "member.leave", member: "mem_owner" }
      expect(await workspaceInvoke(tenant, `access.members.${op}`, input, accountAuth("owner", action as import("@mehen/protocol").WorkspaceStepUpAction))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
  })
  it("allows only one of concurrent voluntary last-owner removals", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); newMember(ctx, "acc_second", "Second owner", "owner", "active", "mem_second") })
    const results = await Promise.all([
      workspaceInvoke(tenant, "access.members.role", { member: "mem_owner", role: "member" }, accountAuth("owner", { type: "member.role", member: "mem_owner", before: "owner", after: "member" })),
      workspaceInvoke(tenant, "access.members.role", { member: "mem_second", role: "member" }, accountAuth("second", { type: "member.role", member: "mem_second", before: "owner", after: "member" })),
    ])
    expect(results.filter((r) => r.ok)).toHaveLength(1)
    expect(results.filter((r) => !r.ok)).toHaveLength(1)
  })
  it("queues the removed co-owner and pre-change owners atomically", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); newMember(ctx, "acc_second", "Second owner", "owner", "active", "mem_second") })
    const before = await accessSnapshot(tenant)
    await inAccess(tenant, () => registerOffboardingHook("consent", () => { throw new Error("audit dependency fault") }))
    expect(await workspaceInvoke(tenant, "access.members.remove", { member: "mem_second" }, accountAuth("owner", { type: "member.remove", member: "mem_second" }))).toMatchObject({ ok: false, error: { vaultError: { error: "internal" } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant, () => registerFixtureLifecycleHooks())
    expect(await workspaceInvoke(tenant, "access.members.remove", { member: "mem_second" }, accountAuth("owner", { type: "member.remove", member: "mem_second" }))).toMatchObject({ ok: true })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ account: string }>("SELECT account FROM notice_outbox ORDER BY account").toArray().map((r) => r.account)).toEqual(["acc_owner", "acc_second"]))
  })
  it("tells every owner and the subject when a suspended owner is reinstated, and no owner when a member is", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); newMember(ctx, "acc_second", "Second owner", "owner", "active", "mem_second"); newMember(ctx, "acc_third", "Third owner", "owner", "active", "mem_third") })
    for (const member of ["mem_third", "mem_member"]) {
      for (const change of ["suspend", "reinstate"] as const) expect(await workspaceInvoke(tenant, `access.members.${change}`, { member }, accountAuth("owner", { type: `member.${change}`, member }))).toMatchObject({ ok: true, value: { status: change === "suspend" ? "suspended" : "active" } })
    }
    expect(await ownerChanges(tenant)).toEqual([
      ...["acc_owner", "acc_second", "acc_third"].map((account) => ({ account, member: "mem_third", change: "reinstated", by: "mem_owner" })),
      ...["acc_owner", "acc_second", "acc_third"].map((account) => ({ account, member: "mem_third", change: "suspended", by: "mem_owner" })),
    ])
    expect(await ownerCards(tenant, "acc_second", "mem_second")).toContain("Third owner was reinstated as an owner")
  })
  it("creates an exact invitation idempotently and refuses changed or expired reservations", async () => {
    const { tenant } = await accessFixture()
    const terms = { role: "member", email: "tom@example.com", teams: [], shares: [], expiresAt: new Date(Date.now() + 600_000).toISOString() } as const
    const input = { invite: "inv_reserved", codeHash: "hash", terms: { ...terms, teams: [], shares: [] }, reservation: { expiresAt: new Date(Date.now() + 60_000).toISOString() } }
    const auth = accountAuth("owner", { type: "member.invite", terms: input.terms })
    const first = await workspaceInvoke(tenant, "access.invites.create", input, auth)
    expect(first).toMatchObject({ ok: true, value: { invite: { id: "inv_reserved", boundEmail: "tom@example.com", inviter: { member: "mem_owner" } } } })
    expect(await workspaceInvoke(tenant, "access.invites.create", input, auth)).toEqual(first)
    const before = await accessSnapshot(tenant)
    const changedTerms = { ...input.terms, email: "different@example.com" }
    expect(await workspaceInvoke(tenant, "access.invites.create", { ...input, terms: changedTerms }, accountAuth("owner", { type: "member.invite", terms: changedTerms }))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This invitation reservation changed." } } })
    expect(await workspaceInvoke(tenant, "access.invites.create", { ...input, codeHash: "different" }, auth)).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This invitation reservation changed." } } })
    expect(await workspaceInvoke(tenant, "access.invites.create", { ...input, invite: "inv_expired", reservation: { expiresAt: new Date(Date.now() - 1).toISOString() } }, auth)).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This invitation reservation expired." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    const listed = await workspaceInvoke(tenant, "access.invites.list", {}, accountAuth("owner"))
    expect(JSON.stringify(listed)).not.toContain("codeHash")
    expect(JSON.stringify(listed)).not.toContain('"hash"')
  })

})

async function ownerChanges(tenant: string) {
  return inAccess(tenant, (ctx) => ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray()
    .map((row) => ({ account: row.account, payload: JSON.parse(row.payload) as import("@mehen/protocol").WorkspaceNoticePayload }))
    .flatMap(({ account, payload }) => payload.kind === "owner_changed" ? [{ account, member: payload.member, change: payload.change, by: payload.by }] : [])
    .sort((a, b) => `${a.change}:${a.account}`.localeCompare(`${b.change}:${b.account}`)))
}
// The Needs you cards an owner sees for the notices queued to them.
async function ownerCards(tenant: string, account: string, memberId: string) {
  const shown = await inAccess(tenant, (ctx) => noticesFor(ctx, { kind: "member", account, memberId, session: `ses_${memberId}`, securityEpoch: 0, sessionCheck: null }))
  return noticeRows(shown, "https://vault.test", false).toString()
}
async function pendingConfirmation(tenant: string, options: { inviter?: "owner" | "admin"; role?: InviteTerms["role"] } = {}) {
  const terms: InviteTerms = { role: options.role ?? "member", email: "new@example.com", teams: ["tm_engineering"], shares: [{ project: "prj_a", level: "use", protected: false, expiresAt: null }], expiresAt: new Date(Date.now() + 600_000).toISOString() }
  const input = { invite: "inv_confirmation", codeHash: "hash-confirmation", terms, reservation: { expiresAt: new Date(Date.now() + 60_000).toISOString() } }
  const created = await workspaceInvoke(tenant, "access.invites.create", input, accountAuth(options.inviter ?? "admin", { type: "member.invite", terms }))
  if (!created.ok) throw new Error(JSON.stringify(created))
  const invite = WorkspaceInviteViewSchema.parse((created.value as { invite: unknown }).invite)
  const redeemed = await workspaceInvoke(tenant, "access.invites.redeem", { member: "mem_new", account: "acc_new", name: "New", codeHash: input.codeHash, evidence: { recoverySetup: true, identity: { provider: "google", subject: "new-subject", email: terms.email, hd: null } } }, { kind: "system", reason: "test" })
  expect(redeemed).toEqual({ ok: true, value: { member: "mem_new", state: "pending_confirmation" } })
  return { invite, auth: accountAuth("owner", { type: "member.confirm", member: "mem_new", termsDigest: invite.digest, identityRuleRevision: 0 }) }
}
describe("confirmation", () => {
  it("only lets an owner activate owner terms", async () => {
    const { tenant } = await accessFixture()
    const { invite } = await pendingConfirmation(tenant, { inviter: "owner", role: "owner" })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, accountAuth("admin", { type: "member.confirm", member: "mem_new", termsDigest: invite.digest, identityRuleRevision: 0 }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it.each(["owner", "member"] as const)("confirming %s terms tells every owner and the subject only when it adds an owner", async (role) => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => newMember(ctx, "acc_second", "Second owner", "owner", "active", "mem_second"))
    const { auth } = await pendingConfirmation(tenant, { inviter: "owner", role })
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toMatchObject({ ok: true, value: { member: "mem_new", status: "active", role } })
    expect(await ownerChanges(tenant)).toEqual(role === "owner" ? ["acc_new", "acc_owner", "acc_second"].map((account) => ({ account, member: "mem_new", change: "added", by: "mem_owner" })) : [])
    if (role === "owner") expect(await ownerCards(tenant, "acc_second", "mem_second")).toContain("New was added as an owner")
  })
  it.each(["demoted", "removed", "restricted", "gated", "pending"] as const)("rechecks the %s inviter before activation", async (change) => {
    const { tenant } = await accessFixture()
    const { auth } = await pendingConfirmation(tenant)
    await inAccess(tenant, (ctx) => {
      if (change === "demoted") ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_admin'")
      if (change === "removed") ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_admin'")
      if (change === "restricted") updateRestriction(ctx, "acc_admin", 0, { reason: "recovery", until: ctx.now() + 86_400_000, notice: "ntc_recovery" })
      if (change === "gated") setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["admin"] })
      if (change === "pending") installSecurity(ctx, "acc_admin", 0, { transitionId: "ast_inviter", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null })
    })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This invitation needs an eligible owner or admin to reissue it." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("refuses missing terms objects, changed terms digests and a covered identity rule", async () => {
    for (const change of ["team", "digest", "identity"] as const) {
      const { tenant } = await accessFixture()
      const { auth } = await pendingConfirmation(tenant)
      await inAccess(tenant, (ctx) => {
        if (change === "team") ctx.sql.exec("DELETE FROM teams WHERE id='tm_engineering'")
        if (change === "identity") setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] })
      })
      if (change === "digest" && auth.stepUp?.type === "member.confirm") auth.stepUp.termsDigest = "different"
      const before = await accessSnapshot(tenant)
      const expected = change === "team" ? { status: 409, vaultError: { error: "conflict", message: "The invitation terms changed." } } : change === "identity" ? { status: 403, vaultError: { error: "identity_required", message: "Check the invited identity before confirmation." } } : { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } }
      expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toEqual({ ok: false, error: expected })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
  })
  it("grants teams and shares only atomically with confirmation, and refuses a second confirmation", async () => {
    const { tenant } = await accessFixture()
    const { auth } = await pendingConfirmation(tenant)
    let audit = (_event: import("../src/vault/core.ts").AuditEvent): void => undefined
    await inAccess(tenant, (ctx) => { audit = ctx.audit; ctx.audit = (event) => { if (event.action === "member.confirm") throw new Error("confirmation audit fault"); audit(event) } })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toEqual({ ok: false, error: { status: 500, vaultError: { error: "internal", message: "Something went wrong inside the vault." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant, (ctx) => { ctx.audit = audit })
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toMatchObject({ ok: true, value: { member: "mem_new", status: "active", role: "member", teams: ["tm_engineering"] } })
    await inAccess(tenant, (ctx) => {
      expect(ctx.sql.exec("SELECT * FROM team_members WHERE member='mem_new'").toArray()).toHaveLength(1)
      expect(ctx.sql.exec("SELECT * FROM project_shares WHERE subject_id='mem_new'").toArray()).toHaveLength(1)
    })
    const confirmed = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, auth)).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This membership cannot be confirmed." } } })
    expect(await accessSnapshot(tenant)).toBe(confirmed)
  })
  it("revokes invites only for authorised people", async () => {
    const { tenant } = await accessFixture()
    const { invite } = await pendingConfirmation(tenant)
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.invites.revoke", { invite: invite.id }, accountAuth("member"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.invites.revoke", { invite: invite.id }, accountAuth("owner"))).toEqual({ ok: true, value: {} })
  })
  it("a workspace with 100 members and 20 open invitations takes another invitation: no cap on either", async () => {
    const { tenant } = await accessFixture()
    const terms: InviteTerms = { role: "member", email: "another@example.com", teams: [], shares: [], expiresAt: new Date(Date.now() + 600_000).toISOString() }
    await inAccess(tenant, (ctx) => {
      const present = ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM members WHERE status!='removed'").one().n
      for (let n = present; n < 100; n++) newMember(ctx, `acc_many${n}`, `Person ${n}`, "member", "active", `mem_many${n}`)
      for (let n = 0; n < 20; n++) ctx.sql.exec("INSERT INTO invites(id,code_hash,terms,digest,creator,created_at,status) VALUES (?,?,?,'current','mem_owner',?,'open')", `inv_open${n}`, `open-hash-${n}`, JSON.stringify(terms), ctx.now())
      expect(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM members WHERE status!='removed'").one().n).toBe(100)
    })
    const input = { invite: "inv_another", codeHash: "another-hash", terms, reservation: { expiresAt: new Date(Date.now() + 60_000).toISOString() } }
    expect(await workspaceInvoke(tenant, "access.invites.create", input, accountAuth("owner", { type: "member.invite", terms }))).toMatchObject({ ok: true, value: { invite: { status: "open" } } })
    await inAccess(tenant, (ctx) => { expect(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM invites WHERE status='open'").one().n).toBe(21) })
  })
})

it("demotion to guest removes teams and caps every direct manage share immediately", async () => {
  const { tenant } = await accessFixture()
  await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); ctx.sql.exec("INSERT INTO team_members(team,member) VALUES ('tm_engineering','mem_kim')") })
  expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_kim", role: "guest" }, accountAuth("owner", { type: "member.role", member: "mem_kim", before: "member", after: "guest" }))).toMatchObject({ ok: true, value: { role: "guest", teams: [] } })
  await inAccess(tenant, (ctx) => {
    expect(ctx.sql.exec("SELECT * FROM team_members WHERE member='mem_kim'").toArray()).toEqual([])
    const share = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares WHERE id='shr_kim'").toArray()[0]!.value)
    expect(share).toMatchObject({ level: "edit", protected: true })
  })
})
