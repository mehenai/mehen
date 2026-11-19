import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import type { SessionIdentityCheck, WorkspaceStepUpAction } from "@mehen/protocol"
import { accessState, digest, memberRows, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"

const system = { kind: "system", reason: "verified OIDC test" } as const
const rule = { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] } as const
function check(sequence = 1, generation = 0, revision = 1): SessionIdentityCheck {
  return { id: `chk_${sequence}`, checkSequence: sequence, gateGeneration: generation, identityRuleRev: revision, succeededAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
}
function install(sessionCheck: SessionIdentityCheck | null = check(), account = "member") {
  return { account: `acc_${account}`, member: `mem_${account}`, session: `ses_${account}`, securityEpoch: 0, sessionCheck,...(sessionCheck === null ? { invalidation: "invalidation-one" } : {}) }
}
function operation(action: WorkspaceStepUpAction, revision = 1, generation = 0) {
  return { id: "opc_one", subjectDigest: digest(action), identityRuleRev: revision, gateGeneration: generation, succeededAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
}
async function fixture() {
  const f = await accessFixture()
  await inAccess(f.tenant, ctx => { setSetting(ctx, "identity_rule", rule); setSetting(ctx, "identity_rule_rev", 1); registerFixtureLifecycleHooks() })
  return f
}
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("access.identity.install", () => {
  it("is system-only, installs monotonic per-session checks and leaves older sessions admitted", async () => {
    const { tenant } = await fixture(), input = install()
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", input)).toMatchObject({ ok: false, error: { status: 403 } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true, value: { checkSequence: 1 } })
    const saved = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true })
    expect(await accessSnapshot(tenant)).toBe(saved)
    expect(await workspaceInvoke(tenant, "access.identity.install", { ...input, session: "ses_second", sessionCheck: check(2) }, system)).toMatchObject({ ok: true, value: { checkSequence: 2 } })
    const both = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true, value: { checkSequence: 2 } })
    expect(await accessSnapshot(tenant)).toBe(both)
    for (const [session, sessionCheck] of [[input.session, input.sessionCheck], ["ses_second", check(2)]] as const) {
      const installed = session === "ses_second" ? await inAccess(tenant, ctx => JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_identity_checks WHERE session=?", session).toArray()[0]!.value) as SessionIdentityCheck) : sessionCheck
      expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), session, sessionCheck: installed })).toMatchObject({ ok: true })
    }
    expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), session: "ses_foreign", sessionCheck: input.sessionCheck })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  })

  it.each(["stale-sequence", "same-sequence", "rule", "generation", "expired", "future", "epoch", "account", "revoked", "pending"] as const)("refuses %s with no mutation", async kind => {
    const { tenant } = await fixture(), input = install(check(2))
    expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true })
    const next = { ...input, sessionCheck: { ...check(3) } }
    if (kind === "stale-sequence") next.sessionCheck.checkSequence = 1
    if (kind === "same-sequence") next.sessionCheck.checkSequence = 2
    if (kind === "rule") next.sessionCheck.identityRuleRev = 0
    if (kind === "generation") next.sessionCheck.gateGeneration = 1
    if (kind === "expired") next.sessionCheck.expiresAt = new Date(Date.now() - 1).toISOString()
    if (kind === "future") next.sessionCheck.succeededAt = new Date(Date.now() + 60_000).toISOString()
    if (kind === "epoch") next.securityEpoch = 1
    if (kind === "account") next.account = "acc_other"
    if (kind === "revoked") await workspaceInvoke(tenant, "access.session_revoke", { account: input.account, session: input.session }, system)
    if (kind === "pending") await workspaceInvoke(tenant, "access.security.install", { account: input.account, committedEpoch: 0, pending: { transitionId: "trn_pending", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null } }, system)
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", next, system)).toMatchObject({ ok: false })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("invalidates all admissions with an idempotent null install", async () => {
    const { tenant } = await fixture(), first = install()
    expect(await workspaceInvoke(tenant, "access.identity.install", first, system)).toMatchObject({ ok: true })
    const invalidation = install(null)
    expect(await workspaceInvoke(tenant, "access.identity.install", invalidation, system)).toMatchObject({ ok: true, value: { gateGeneration: 1 } })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", invalidation, system)).toMatchObject({ ok: true, value: { gateGeneration: 1 } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), sessionCheck: first.sessionCheck })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
    expect(await workspaceInvoke(tenant, "access.identity.install", install(check(2)), system)).toMatchObject({ ok: false })
    expect(await workspaceInvoke(tenant, "access.identity.install", install(check(2, 1)), system)).toMatchObject({ ok: true })
  })

  it("activates a pending promotion only with its saved exact operation", async () => {
    const { tenant } = await fixture(), owner = install(check(), "owner")
    expect(await workspaceInvoke(tenant, "access.identity.install", owner, system)).toMatchObject({ ok: true })
    const action = { type: "member.role", member: "mem_member", before: "member", after: "admin" } as const
    expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_member", role: "admin" }, { ...accountAuth("owner", action), sessionCheck: owner.sessionCheck, operationCheck: operation(action) })).toMatchObject({ ok: true, value: { role: "member", pendingRole: "admin" } })
    const input = { ...install(check(1, 1)), pendingRole: "admin" as const }
    for (const operationCheck of [undefined, operation({ ...action, after: "owner" }, 1, 1)]) {
      const before = await accessSnapshot(tenant)
      expect(await workspaceInvoke(tenant, "access.identity.install", { ...input, operationCheck }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
    expect(await workspaceInvoke(tenant, "access.identity.install", { ...input, operationCheck: operation(action, 1, 1) }, system)).toMatchObject({ ok: true, value: { role: "admin", gateGeneration: 1 } })
    await inAccess(tenant, ctx => expect(memberRows(ctx).find(m => m.id === "mem_member")).toMatchObject({ role: "admin", pending_role: null, pending_action: null }))
  })
})

describe("access.identity_rule", () => {
  it("needs owner authority, the exact passkey action and proposed-rule identity evidence, then re-gates every session", async () => {
    const { tenant } = await accessFixture()
    const action: Extract<WorkspaceStepUpAction, { type: "workspace.identity_rule" }> = { type: "workspace.identity_rule", rule: { ...rule, domains: [...rule.domains], roles: [...rule.roles] } }
    for (const auth of [accountAuth("admin", action), accountAuth("owner"), accountAuth("owner", { type: "workspace.unfreeze" }), accountAuth("owner", action), { ...accountAuth("owner", action), operationCheck: operation(action, 1) }]) {
      const before = await accessSnapshot(tenant)
      expect(await workspaceInvoke(tenant, "access.identity_rule", { rule: action.rule }, auth)).toMatchObject({ ok: false })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
    expect(await workspaceInvoke(tenant, "access.identity_rule", { rule: action.rule }, { ...accountAuth("owner", action), operationCheck: operation(action, 0) })).toMatchObject({ ok: true, value: { identityRuleRev: 1 } })
    await inAccess(tenant, ctx => {
      const state = accessState(ctx)
      expect(state.members.every(m => m.standing.gateGeneration === 1 && m.standing.identityRuleRev === 1 && m.standing.checkSequence === 0)).toBe(true)
      expect(state.members.find(m => m.id === "mem_owner")?.standing.identityGate.admitted).toBe(false)
    })
    expect(await workspaceInvoke(tenant, "access.members.list", {}, accountAuth())).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  })
})

it("installs purpose-bound invite evidence without activation, then confirms only with current admitted people", async () => {
  const { tenant } = await fixture(), owner = install(check(), "owner")
  expect(await workspaceInvoke(tenant, "access.identity.install", owner, system)).toMatchObject({ ok: true })
  const terms = { role: "member" as const, email: "new@example.com", teams: [], shares: [], expiresAt: new Date(Date.now() + 600_000).toISOString() }
  const inviteAction = { type: "member.invite", terms } as const
  const creator = { ...accountAuth("owner", inviteAction), sessionCheck: owner.sessionCheck, operationCheck: operation(inviteAction) }
  expect(await workspaceInvoke(tenant, "access.invites.create", { invite: "inv_covered", codeHash: "covered-hash", terms, reservation: { expiresAt: terms.expiresAt } }, creator)).toMatchObject({ ok: true })
  expect(await workspaceInvoke(tenant, "access.invites.lookup", { codeHash: "covered-hash" }, system)).toMatchObject({ ok: true })
  expect(await workspaceInvoke(tenant, "access.invites.redeem", { member: "mem_new", account: "acc_new", name: "New", codeHash: "covered-hash", evidence: { recoverySetup: true, identity: { provider: "google", subject: "new-google", email: terms.email, hd: "example.com" } } }, system)).toMatchObject({ ok: true })
  const action = { type: "member.confirm", member: "mem_new", termsDigest: digest(terms), identityRuleRevision: 1 } as const
  const confirmer = { ...accountAuth("owner", action), sessionCheck: owner.sessionCheck, operationCheck: operation(action) }
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, confirmer)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
  const input = { ...install(check(), "new"), purpose: "invite" as const, operationCheck: operation(action) }
  for (const change of [{ purpose: "session" as const }, { operationCheck: operation({ ...action, termsDigest: "wrong" }) }]) {
    expect(await workspaceInvoke(tenant, "access.identity.install", { ...input, ...change }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  }
  expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true, value: { role: "member" } })
  await inAccess(tenant, ctx => expect(memberRows(ctx).find(m => m.id === "mem_new")?.status).toBe("unconfirmed"))
  expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("new"), sessionCheck: input.sessionCheck })).toMatchObject({ ok: false, error: { vaultError: { error: "owner_inactive" } } })
  const installed = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, { ...confirmer, sessionCheck: null })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(installed)
  await inAccess(tenant, ctx => setSetting(ctx, "identity_rule_rev", 2))
  expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, confirmer)).toMatchObject({ ok: false })
  await inAccess(tenant, ctx => setSetting(ctx, "identity_rule_rev", 1))
  expect(await workspaceInvoke(tenant, "access.members.confirm", { member: "mem_new" }, confirmer)).toMatchObject({ ok: true, value: { status: "active", role: "member" } })
  // The exact invite proof also admits that same session after activation.
  expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("new"), sessionCheck: input.sessionCheck })).toMatchObject({ ok: true })
})

it("an emailed code's evidence proves the invited email, never the identity rule: refused for a role under it, redeemed for one outside it", async () => {
  const { tenant } = await fixture(), owner = install(check(), "owner")
  expect(await workspaceInvoke(tenant, "access.identity.install", owner, system)).toMatchObject({ ok: true })
  const create = async (role: "member" | "guest", codeHash: string) => {
    const terms = role === "member" ? { role, email: "new@example.com", teams: [], shares: [], expiresAt: new Date(Date.now() + 600_000).toISOString() } : { role, email: "new@example.com", teams: [], shares: [{ project: "prj_a", level: "use" as const, protected: false, expiresAt: null }], expiresAt: new Date(Date.now() + 600_000).toISOString() }
    const action = { type: "member.invite", terms } as const
    expect(await workspaceInvoke(tenant, "access.invites.create", { invite: `inv_${role}`, codeHash, terms, reservation: { expiresAt: terms.expiresAt } }, { ...accountAuth("owner", action), sessionCheck: owner.sessionCheck, operationCheck: operation(action) })).toMatchObject({ ok: true })
  }
  const redeem = (codeHash: string, email: string) => workspaceInvoke(tenant, "access.invites.redeem", { member: "mem_new", account: "acc_new", name: "New", codeHash, evidence: { recoverySetup: true, identity: { provider: "email", email } } }, system)
  await create("member", "member-hash")
  const before = await accessSnapshot(tenant)
  expect(await redeem("member-hash", "new@example.com")).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
  await create("guest", "guest-hash")
  expect(await redeem("guest-hash", "other@example.com")).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden", message: "Prove the invited email before joining." } } })
  expect(await redeem("guest-hash", "new@example.com")).toEqual({ ok: true, value: { member: "mem_new", state: "pending_confirmation" } })
  // Google's evidence shape is unchanged, and the two never mix.
  expect(await workspaceInvoke(tenant, "access.invites.redeem", { member: "mem_new", account: "acc_new", name: "New", codeHash: "guest-hash", evidence: { recoverySetup: true, identity: { provider: "email", email: "new@example.com", hd: "example.com" } } }, system)).toMatchObject({ ok: false, error: { status: 400 } })
})

it.each([false, true])("aborts only an exact pending invite source and repeats the original result (expired=%s)", async expired => {
  const { tenant } = await accessFixture(), terms = { role: "member" as const, email: "new@example.com", teams: [], shares: [], expiresAt: new Date(Date.now() + 600_000).toISOString() }
  expect(await workspaceInvoke(tenant, "access.invites.create", { invite: "inv_abort", codeHash: "abort-hash", terms, reservation: { expiresAt: terms.expiresAt } }, accountAuth("owner", { type: "member.invite", terms }))).toMatchObject({ ok: true })
  const source = { member: "mem_new", account: "acc_new", codeHash: "abort-hash" }
  expect(await workspaceInvoke(tenant, "access.invites.redeem", { ...source, name: "New", evidence: { recoverySetup: true, identity: { provider: "google", subject: "new", email: terms.email, hd: null } } }, system)).toMatchObject({ ok: true })
  const before = await accessSnapshot(tenant)
  for (const patch of [{ account: "acc_wrong" }, { member: "mem_wrong" }, { codeHash: "wrong" }]) expect(await workspaceInvoke(tenant, "access.invites.abort", { ...source, ...patch }, system)).toEqual({ ok: true, value: { aborted: false } })
  expect(await accessSnapshot(tenant)).toBe(before)
  await inAccess(tenant, ctx => ctx.sql.exec("UPDATE members SET status='active' WHERE id='mem_new'"))
  const active = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.invites.abort", source, system)).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This membership is already active." } } })
  expect(await accessSnapshot(tenant)).toBe(active)
  await inAccess(tenant, ctx => {
    ctx.sql.exec("UPDATE members SET status='unconfirmed' WHERE id='mem_new'")
    if (expired) ctx.sql.exec("UPDATE invites SET terms=? WHERE id='inv_abort'", JSON.stringify({ ...terms, expiresAt: new Date(ctx.now() - 1).toISOString() }))
  })
  const expected = { ok: true, value: { aborted: true, state: expired ? "expired" : "open" } }
  expect(await workspaceInvoke(tenant, "access.invites.abort", source, system)).toEqual(expected)
  const aborted = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.invites.abort", source, system)).toEqual(expected)
  expect(await accessSnapshot(tenant)).toBe(aborted)
  await inAccess(tenant, ctx => {
    expect(memberRows(ctx).some(m => m.id === source.member)).toBe(false)
    expect(ctx.sql.exec("SELECT * FROM account_security WHERE account=?", source.account).toArray()).toHaveLength(1)
    expect(ctx.sql.exec("SELECT member,used_by,status FROM invites WHERE id='inv_abort'").toArray()).toEqual([{ member: null, used_by: null, status: expired ? "expired" : "open" }])
  })
})

it("returns authoritative identity context to the system even while ungated and security-pending", async () => {
  const { tenant } = await fixture()
  await inAccess(tenant, ctx => ctx.sql.exec("UPDATE members SET pending_role='admin',pending_since=?,pending_action=? WHERE id='mem_member'", ctx.now(),JSON.stringify({ type: "member.role", member: "mem_member", before: "member", after: "admin" })))
  await workspaceInvoke(tenant, "access.security.install", { account: "acc_member", committedEpoch: 0, pending: { transitionId: "trn_pending", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null } }, system)
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.identity.context", { account: "acc_member" }, system)).toEqual({ ok: true, value: { member: "mem_member", role: "member", pendingRole: "admin", pendingAction: { type: "member.role", member: "mem_member", before: "member", after: "admin" }, identityRule: rule, identityRuleRev: 1, gateGeneration: 0, checkSequence: 0, status: "active" } })
  expect(await workspaceInvoke(tenant, "access.identity.context", { account: "acc_absent" }, system)).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such membership." } } })
  expect(await workspaceInvoke(tenant, "access.identity.context", { account: "acc_member" })).toMatchObject({ ok: false, error: { status: 403 } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("uses fresh session evidence for ordinary widening without an exact-operation check", async () => {
  const { tenant } = await fixture(), input = install(check(), "owner")
  expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true })
  const action = { type: "workspace.update", name: "Renamed", slug: "work" } as const
  expect(await workspaceInvoke(tenant, "access.workspace_update", { name: "Renamed" }, { ...accountAuth("owner", action), sessionCheck: input.sessionCheck })).toMatchObject({ ok: true })
  const old = { ...check(2), succeededAt: new Date(Date.now() - 43_200_000).toISOString() }
  expect(await workspaceInvoke(tenant, "access.identity.install", { ...input, sessionCheck: old }, system)).toMatchObject({ ok: true })
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.workspace_update", { name: "Renamed" }, { ...accountAuth("owner", action), sessionCheck: old })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("requires exact operation evidence for every covered acceptance and admission kind", async () => {
  const { authorise, requireStepUp } = await import("../src/vault/areas/workspace-runtime.ts")
  const { tenant } = await fixture(), installed = install(check(), "owner")
  expect(await workspaceInvoke(tenant, "access.identity.install", installed, system)).toMatchObject({ ok: true })
  await inAccess(tenant, ctx => {
    const state = accessState(ctx), before = state.devices.find(d => d.id === "dev_owner")!.scope, after = { ...before, privateCredentials: true }
    const cases: { action: import("../src/vault/access.ts").AccessAction; target: import("../src/vault/access.ts").AccessTarget; expected: WorkspaceStepUpAction }[] = [
      { action: { type: "enrol.accept" }, target: { owningAccount: "acc_owner", acceptingAccount: "acc_owner" }, expected: { type: "enrol.accept", workspace: tenant, enrolment: "enr_exact", thumbprint: "key", account: "acc_owner", member: "mem_owner", scope: before, start: { at: new Date(ctx.now()).toISOString(), place: null, clientLabel: "Terminal" } } },
      { action: { type: "enrol.approve" }, target: { member: "mem_guest", project: "prj_a", after }, expected: { type: "enrol.approve", enrolment: "enr_exact", digest: "exact", owner: { kind: "member", member: "mem_guest", name: "guest" }, admissionRole: "owner" } },
      { action: { type: "device.rescope_admit" }, target: { device: "dev_guest", project: "prj_a", before, after, proposal: "rsp_exact" }, expected: { type: "device.rescope", device: "dev_guest", thumbprint: "key", before, after } },
      { action: { type: "device.rescope_accept", before, after }, target: { device: "dev_owner", owningAccount: "acc_owner" }, expected: { type: "device.rescope_accept", device: "dev_owner", thumbprint: "key", account: "acc_owner", before, after, admission: false } },
      { action: { type: "workspace.identity_rule" }, target: {}, expected: { type: "workspace.identity_rule", rule: { ...rule, domains: [...rule.domains], roles: [...rule.roles] } } },
    ]
    const snapshot = canonicalJson(ctx.sql.exec("SELECT * FROM tenant_state").toArray())
    for (const entry of cases) {
      const auth = { ...accountAuth("owner", entry.expected), sessionCheck: installed.sessionCheck }, invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      const decision = authorise(ctx, invocation, entry.action, entry.target)
      expect(() => requireStepUp(ctx, decision, entry.expected, invocation)).toThrow("exact operation")
      expect(() => requireStepUp(ctx, decision, entry.expected, { ...invocation, auth: { ...auth, operationCheck: operation(entry.expected) } })).not.toThrow()
    }
    expect(canonicalJson(ctx.sql.exec("SELECT * FROM tenant_state").toArray())).toBe(snapshot)
  })
})

it("F1: a later invalidation after a fresh same-session check bumps the generation and refuses that check", async () => {
  const { tenant } = await fixture(), first = install()
  expect(await workspaceInvoke(tenant, "access.identity.install", first, system)).toMatchObject({ ok: true })
  const invalidation = install(null)
  expect(await workspaceInvoke(tenant, "access.identity.install", invalidation, system)).toMatchObject({ ok: true, value: { gateGeneration: 1 } })
  const fresh = check(2, 1)
  expect(await workspaceInvoke(tenant, "access.identity.install", install(fresh), system)).toMatchObject({ ok: true })
  expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), sessionCheck: fresh })).toMatchObject({ ok: true })
  const second = { ...invalidation,invalidation: "invalidation-two" }
  expect(await workspaceInvoke(tenant, "access.identity.install", second, system)).toMatchObject({ ok: true, value: { gateGeneration: 2 } })
  await inAccess(tenant, ctx => expect(ctx.sql.exec("SELECT session FROM workspace_identity_checks WHERE member='mem_member'").toArray()).toEqual([]))
  expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), sessionCheck: fresh })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.identity.install", second, system)).toMatchObject({ ok: true, value: { gateGeneration: 2 } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("F8: compares the installed session evidence by canonical values rather than timestamp formatting", async () => {
  const { tenant } = await fixture(), evidence = check()
  evidence.succeededAt = evidence.succeededAt.replace("Z", "0Z")
  evidence.expiresAt = evidence.expiresAt.replace("Z", "0Z")
  expect(await workspaceInvoke(tenant, "access.identity.install", install(evidence), system)).toMatchObject({ ok: true })
  const projected = { ...evidence, succeededAt: new Date(evidence.succeededAt).toISOString(), expiresAt: new Date(evidence.expiresAt).toISOString() }
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), sessionCheck: projected })).toMatchObject({ ok: true })
  for (const patch of [{ id: "chk_foreign" }, { checkSequence: 0 }, { identityRuleRev: 0 }, { gateGeneration: 1 }, { succeededAt: new Date(Date.parse(projected.succeededAt) - 1).toISOString() }, { expiresAt: new Date(Date.parse(projected.expiresAt) + 1).toISOString() }]) expect(await workspaceInvoke(tenant, "access.members.list", {}, { ...accountAuth("member"), sessionCheck: { ...projected, ...patch } })).toMatchObject({ ok: false, error: { vaultError: { error: "identity_required" } } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it.each(["demoted", "removed", "suspended", "expired", "eligible"] as const)("F4: pending promotion activation rechecks its %s promoter and seven-day lifetime", async change => {
  const { INVITE_TTL_MS } = await import("@mehen/protocol")
  const { tenant } = await fixture(), owner = install(check(), "owner"), admin = install(check(), "admin")
  for (const input of [owner, admin]) expect(await workspaceInvoke(tenant, "access.identity.install", input, system)).toMatchObject({ ok: true })
  const action = { type: "member.role", member: "mem_member", before: "member", after: "admin" } as const
  expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_member", role: "admin" }, { ...accountAuth("admin", action), sessionCheck: admin.sessionCheck })).toMatchObject({ ok: true, value: { role: "member", pendingRole: "admin" } })
  await inAccess(tenant, ctx => expect(memberRows(ctx).find(m => m.id === "mem_member")?.pending_by).toBe("mem_admin"))
  if (change === "demoted") expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_admin", role: "member" }, { ...accountAuth("owner", { type: "member.role", member: "mem_admin", before: "admin", after: "member" }), sessionCheck: owner.sessionCheck })).toMatchObject({ ok: true })
  if (change === "removed" || change === "suspended") expect(await workspaceInvoke(tenant, change === "removed" ? "access.members.remove" : "access.members.suspend", { member: "mem_admin" }, { ...accountAuth("owner", { type: change === "removed" ? "member.remove" : "member.suspend", member: "mem_admin" }), sessionCheck: owner.sessionCheck })).toMatchObject({ ok: true })
  if (change === "expired") await inAccess(tenant, ctx => ctx.sql.exec("UPDATE members SET pending_since=? WHERE id='mem_member'", ctx.now() - INVITE_TTL_MS))
  const result = await workspaceInvoke(tenant, "access.identity.install", { ...install(check(1, 1)), pendingRole: "admin", operationCheck: operation(action, 1, 1) }, system)
  if (change === "eligible") expect(result).toMatchObject({ ok: true, value: { role: "admin" } })
  else expect(result).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This pending promotion is no longer available." } } })
  await inAccess(tenant, ctx => {
    expect(memberRows(ctx).find(m => m.id === "mem_member")).toMatchObject({ role: change === "eligible" ? "admin" : "member", pending_role: null, pending_action: null, pending_since: null, pending_by: null })
    const cancelled = ctx.sql.exec<{ action: string; target: string; detail: string }>("SELECT action,target,detail FROM audit WHERE action='member.promotion_cancelled'").toArray()
    if (change === "eligible") expect(cancelled).toEqual([])
    else {
      expect(cancelled).toHaveLength(1)
      expect(cancelled[0]?.target).toBe("mem_member")
      expect(JSON.parse(cancelled[0]!.detail)).toMatchObject({ role: "admin", reason: change === "expired" ? "expired" : "promoter_ineligible" })
      expect(ctx.sql.exec("SELECT * FROM workspace_identity_checks WHERE member='mem_member'").toArray()).toEqual([])
    }
  })
})

it("F4: a failed cancellation audit rolls the pending-promotion clear back", async () => {
  const { tenant } = await fixture(), owner = install(check(), "owner")
  expect(await workspaceInvoke(tenant, "access.identity.install", owner, system)).toMatchObject({ ok: true })
  const action = { type: "member.role", member: "mem_member", before: "member", after: "admin" } as const
  expect(await workspaceInvoke(tenant, "access.members.role", { member: "mem_member", role: "admin" }, { ...accountAuth("owner", action), sessionCheck: owner.sessionCheck })).toMatchObject({ ok: true })
  let original!: import("../src/vault/core.ts").VaultContext["audit"]
  await inAccess(tenant, ctx => { ctx.sql.exec("UPDATE members SET pending_since=0 WHERE id='mem_member'"); original = ctx.audit; ctx.audit = event => { if (event.action === "member.promotion_cancelled") throw new Error("injected cancellation audit failure"); original(event) } })
  try {
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.identity.install", { ...install(check(1, 1)), pendingRole: "admin", operationCheck: operation(action, 1, 1) }, system)).toMatchObject({ ok: false, error: { status: 500 } })
    expect(await accessSnapshot(tenant)).toBe(before)
  } finally { await inAccess(tenant, ctx => { ctx.audit = original }) }
})


it("R1/A2: distinct unlink event ids invalidate an in-flight gate even with no installed rows", async () => {
  const { tenant } = await fixture(),first = install(),a = { ...install(null),invalidation: "unlink-a" },b = { ...install(null),invalidation: "unlink-b" }
  expect(await workspaceInvoke(tenant,"access.identity.install",first,system)).toMatchObject({ ok: true })
  expect(await workspaceInvoke(tenant,"access.identity.install",a,system)).toMatchObject({ ok: true,value: { gateGeneration: 1 } })
  const inflight = install(check(2,1))
  expect(await workspaceInvoke(tenant,"access.identity.install",b,system)).toMatchObject({ ok: true,value: { gateGeneration: 2 } })
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.identity.install",inflight,system)).toMatchObject({ ok: false,error: { vaultError: { error: "identity_required" } } })
  for (const repeat of [a,b]) expect(await workspaceInvoke(tenant,"access.identity.install",repeat,system)).toMatchObject({ ok: true,value: { gateGeneration: 2 } })
  const { invalidation: _invalidation,...missingId } = a
  expect(await workspaceInvoke(tenant,"access.identity.install",missingId,system)).toMatchObject({ ok: false,error: { status: 400,vaultError: { error: "bad_request" } } })
  expect(await workspaceInvoke(tenant,"access.identity.install",{ ...b,session: "changed-session" },system)).toMatchObject({ ok: false,error: { status: 409 } })
  expect(await accessSnapshot(tenant)).toBe(before)
})

it("R2: expired promotions disappear from member, membership, standing and identity-context projections", async () => {
  const { INVITE_TTL_MS } = await import("@mehen/protocol")
  const { tenant } = await fixture(),owner = install(check(),"owner"),action = { type: "member.role",member: "mem_member",before: "member",after: "admin" } as const
  expect(await workspaceInvoke(tenant,"access.identity.install",owner,system)).toMatchObject({ ok: true })
  const auth = { ...accountAuth("owner",action),sessionCheck: owner.sessionCheck }
  expect(await workspaceInvoke(tenant,"access.members.role",{ member: "mem_member",role: "admin" },auth)).toMatchObject({ ok: true,value: { role: "member",pendingRole: "admin" } })
  await inAccess(tenant,ctx => ctx.sql.exec("UPDATE members SET pending_since=? WHERE id='mem_member'",ctx.now()-INVITE_TTL_MS))
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.members.list",{},auth)).toMatchObject({ ok: true,value: expect.arrayContaining([expect.objectContaining({ member: "mem_member",role: "member",pendingRole: null })]) })
  expect(await workspaceInvoke(tenant,"access.membership",{ account: "acc_member" },system)).toMatchObject({ ok: true,value: { role: "member",pendingRole: null } })
  expect(await workspaceInvoke(tenant,"access.identity.context",{ account: "acc_member" },system)).toMatchObject({ ok: true,value: { pendingRole: null,pendingAction: null } })
  await inAccess(tenant,ctx => expect(accessState(ctx).members.find(member => member.id === "mem_member")?.standing.pendingRole).toBeNull())
  expect(await accessSnapshot(tenant)).toBe(before)
})

it.each(["revoked", "deleting", "epoch"] as const)("an invalidation survives %s session liveness while admission still refuses", async mode => {
  const { tenant } = await fixture(),first = install()
  expect(await workspaceInvoke(tenant,"access.identity.install",first,system)).toMatchObject({ ok: true })
  if (mode === "revoked") expect(await workspaceInvoke(tenant,"access.session_revoke",{ account: first.account,session: first.session },system)).toMatchObject({ ok: true })
  if (mode === "epoch") expect(await workspaceInvoke(tenant,"access.security.commit",{ account: first.account,committedEpoch: 1 },system)).toMatchObject({ ok: true })
  if (mode === "deleting") await inAccess(tenant,ctx => ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.deleting',json('true')) WHERE account=?",first.account))
  expect(await workspaceInvoke(tenant,"access.identity.install",install(check(2)),system)).toMatchObject({ ok: false,error: { vaultError: { error: "unauthenticated" } } })
  const invalidation = { ...install(null),invalidation: `unlink-after-${mode}` }
  expect(await workspaceInvoke(tenant,"access.identity.install",invalidation,system)).toMatchObject({ ok: true,value: { gateGeneration: 1 } })
  await inAccess(tenant,ctx => expect(ctx.sql.exec("SELECT * FROM workspace_identity_checks WHERE member=?",first.member).toArray()).toEqual([]))
  const before = await accessSnapshot(tenant)
  expect(await workspaceInvoke(tenant,"access.identity.install",invalidation,system)).toMatchObject({ ok: true,value: { gateGeneration: 1 } })
  expect(await accessSnapshot(tenant)).toBe(before)
})
