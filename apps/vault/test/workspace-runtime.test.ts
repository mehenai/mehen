import { describe, expect, it } from "vitest"
import { accessState, authorise, drainOutbox, installSecurity, observeCommittedEpoch, nameMiss, principalOf, queueNotice, noticesFor, eligibilityState, retainedGateValid, revokeSession, recordExposure, registerOffboardingHook, registerAccessChangeHook, isolateAccessLifecycleForTests, registerExposureProvider, beforeOffboarding, runOffboardingHooks, accessChanged, registerOpenAskCounter, openAskCount, updateRestriction, registerAccessStateProvider, newMember, requireStepUp, security, setSetting, digest, setProjectShare } from "../src/vault/areas/workspace-runtime.ts"
import { installTestIdentity, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke, beginAccessSideEffectChecks, finishAccessSideEffectChecks } from "./access-test-support.ts"
import { freshTenant } from "./helpers.ts"
import { verifyAuditChain } from "../src/vault/audit.ts"
import type { AuditRow } from "../src/vault/audit.ts"
import { fixtureSql } from "./fixture-sql.ts"
const system = { kind: "system", reason: "test" } as const

describe("workspace runtime seam", () => {
  it("initialises only from the system, idempotently, with exact terms", async () => {
    const tenant = freshTenant()
    await inAccess(tenant, (ctx) => { })
    const input = { member: "mem_initial", workspace: tenant, slug: "work", name: "Work", owner: { account: "acc_owner", name: "Alex" } }
    expect(await workspaceInvoke(tenant, "access.init", input)).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    const first = await workspaceInvoke(tenant, "access.init", input, system)
    expect(first).toMatchObject({ ok: true, value: { member: expect.stringMatching(/^mem_/) } })
    expect(await workspaceInvoke(tenant, "access.init", input, system)).toEqual(first)
    expect(await workspaceInvoke(tenant, "access.init", { ...input, owner: { ...input.owner, account: "acc_foreign" } }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
    expect(await workspaceInvoke(tenant, "access.init", { ...input, name: "Changed" }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
  })
  it("reloads live authority and checks the exact verified action and factor handle", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const workspace = { id: tenant, slug: "work", name: "Work" }
      const expected = { type: "device.revoke", device: "dev_member" } as const
      const invocation = { workspace, auth: accountAuth("owner", expected) }
      const decision = authorise(ctx, invocation, { type: "device.revoke" }, { device: "dev_member" }, ctx.now())
      expect(() => requireStepUp(ctx, decision, expected, invocation)).not.toThrow()
      expect(() => requireStepUp(ctx, decision, { ...expected, device: "dev_guest" }, invocation)).toThrow("exact action")
      installSecurity(ctx, "acc_owner", 0, { transitionId: "ast_one", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: ["pk_fixture"], restriction: null })
      expect(() => requireStepUp(ctx, decision, expected, invocation)).toThrow("no longer authorised")
      expect(() => authorise(ctx, invocation, { type: "workspace.unfreeze" }, {}, ctx.now())).toThrow("no longer authorised")
    })
  })
  it("shares one atomic name bucket across account and member machines", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const principal = principalOf(ctx, accountAuth("member"))
      for (let n = 0; n < 20; n++) nameMiss.record(ctx, principal, 1_000)
      expect(nameMiss.check(ctx, principal, 1_000)).toEqual({ ok: false, retryAfter: 3600 })
      expect(nameMiss.check(ctx, { kind: "device", deviceId: "dev_member" }, 1_000)).toEqual({ ok: false, retryAfter: 3600 })
      expect(nameMiss.check(ctx, { kind: "device", deviceId: "dev_service" }, 1_000)).toEqual({ ok: true })
      expect(nameMiss.check(ctx, principal, 3_601_000)).toEqual({ ok: true })
    })
  })
  it("assembles credentials before references and performs share CAS without echo", async () => {
    const { tenant, state } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const calls: string[] = []
      registerAccessStateProvider("credentials", () => { calls.push("credentials"); return { credentials: state.credentials } })
      registerAccessStateProvider("projects", (_ctx, credentials) => { expect(credentials).toEqual(state.credentials); calls.push("projects"); return { projects: state.projects } })
      expect(accessState(ctx).projects).toEqual(state.projects)
      expect(calls).toEqual(["credentials", "projects"])
      const before = state.shares[0]!
      const after = { ...before, level: "use" as const }
      ctx.storage.transactionSync(() => setProjectShare(ctx, after, before))
      expect(accessState(ctx).accessRev).toBe(2)
      expect(() => ctx.storage.transactionSync(() => setProjectShare(ctx, before, before))).toThrow("The expected state changed.")
      expect(accessState(ctx).shares.find((s) => s.id === before.id)).toEqual(after)
    })
  })
  it("persists deduplicated notices and exposure in the caller transaction", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const payload = { kind: "machine_added", workspace: { id: tenant, slug: "work", name: "Work" }, device: "dev_member", name: "Laptop", owner: { kind: "member", member: "mem_member", name: "Sam" }, place: "Amsterdam", at: new Date().toISOString() } as const
      ctx.storage.transactionSync(() => { queueNotice(ctx, payload); queueNotice(ctx, payload); recordExposure(ctx, { item: "itm_workspace", version: 1, member: "mem_member", device: "dev_member", event: "evt_one", source: "leased", at: 1 }) })
      expect(drainOutbox(ctx, 50).events).toHaveLength(2)
      expect(drainOutbox(ctx, 50).events[0]?.url).toBe(`https://vault.test/w/work/devices/dev_member`)
      expect(() => ctx.storage.transactionSync(() => { queueNotice(ctx, { ...payload, device: "dev_other" }); throw new Error("rollback") })).toThrow("rollback")
      expect(drainOutbox(ctx, 50).events).toHaveLength(2)
      expect(ctx.sql.exec("SELECT * FROM exposures").toArray()).toHaveLength(1)
    })
    const drained = await workspaceInvoke(tenant, "access.outbox.drain", { limit: 50 }, system)
    expect(drained).toMatchObject({ ok: true, value: { events: expect.any(Array) } })
    await inAccess(tenant, (ctx) => { expect(security(ctx, "acc_member")?.installedEpoch).toBe(0) })
  })
  it("mirrors each account event once and silently ignores non-members", async () => {
    const { tenant } = await accessFixture()
    const event = { id: "evt_account", account: "acc_member", at: 42, action: "account.signin", detail: { client: "Browser", workspace: "foreign", secret: "forbidden" } }
    expect(await workspaceInvoke(tenant, "access.account_event", event, system)).toEqual({ ok: true, value: { mirrored: true } })
    expect(await workspaceInvoke(tenant, "access.account_event", event, system)).toEqual({ ok: true, value: { mirrored: true } })
    expect(await workspaceInvoke(tenant, "access.account_event", { ...event, id: "evt_foreign", account: "acc_foreign" }, system)).toEqual({ ok: true, value: { mirrored: true } })
    await inAccess(tenant, (ctx) => {
      const rows = ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray()
      expect(rows).toHaveLength(1)
      expect(rows[0]?.detail).not.toContain("foreign")
      expect(rows[0]?.detail).not.toContain("forbidden")
      expect(verifyAuditChain(rows)).toEqual({ ok: true })
    })
  })
  it("looks up masked invite terms and redeems once with exact email and recovery proof", async () => {
    const { tenant } = await accessFixture()
    const terms = { role: "member", email: "tom@example.com", teams: [], shares: [{ project: "prj_a", level: "use", protected: false, expiresAt: null }], expiresAt: new Date(Date.now() + 600_000).toISOString() }
    await inAccess(tenant, (ctx) => ctx.sql.exec("INSERT INTO invites(id,code_hash,terms,digest,creator,created_at,status) VALUES ('inv_test','hash',?,'digest','mem_owner',?,'open')", JSON.stringify(terms), ctx.now()))
    expect(await workspaceInvoke(tenant, "access.invites.lookup", { codeHash: "absent" }, system)).toEqual({ ok: false, error: { status: 404, vaultError: { error: "not_found", message: "No such invite." } } })
    expect(await workspaceInvoke(tenant, "access.invites.lookup", { codeHash: "hash" }, system)).toMatchObject({ ok: true, value: { boundEmail: "t***@example.com", shares: [{ project: { id: "prj_a", slug: "project-a" }, level: "use", protected: false }] } })
    const input = { member: "mem_reserved", codeHash: "hash", account: "acc_new", name: "Tom", evidence: { recoverySetup: true, identity: { provider: "google", subject: "sub", email: "wrong@example.com", hd: null } } }
    expect(await workspaceInvoke(tenant, "access.invites.redeem", input, system)).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    input.evidence.identity.email = "tom@example.com"
    const result = await workspaceInvoke(tenant, "access.invites.redeem", input, system)
    expect(result).toMatchObject({ ok: true, value: { state: "pending_confirmation" } })
    expect(await workspaceInvoke(tenant, "access.invites.redeem", input, system)).toEqual(result)
    expect(await workspaceInvoke(tenant, "access.invites.redeem", { ...input, account: "acc_foreign" }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
    expect(await workspaceInvoke(tenant, "access.membership", { account: "acc_new" }, system)).toMatchObject({ ok: true, value: { member: "mem_reserved", role: "member", pendingRole: null, status: "unconfirmed", teams: [] } })
    await inAccess(tenant, (ctx) => expect(accessState(ctx).members.find((m) => m.account === "acc_new")?.status).toBe("unconfirmed"))
  })
  it("registers pending enrolment terms without ever substituting admission for acceptance", async () => {
    const { tenant } = await accessFixture()
    const input = { enrolment: "enr_test", start: { at: new Date().toISOString(), place: "Amsterdam", clientLabel: "Terminal" }, thumbprint: "key", requestedOwner: { kind: "self" }, claimedAccount: null, scope: { tags: [], projects: [], modes: ["relay"], maxEnvironment: "unprotected" } }
    const result = await workspaceInvoke(tenant, "access.enrol.register", input, system)
    expect(result).toMatchObject({ ok: true, value: { state: "pending_owner_acceptance", start: input.start } })
    expect(await workspaceInvoke(tenant, "access.enrol.register", input, system)).toEqual(result)
    expect(await workspaceInvoke(tenant, "access.enrol.register", { ...input, start: { ...input.start, clientLabel: "Different" } }, system)).toMatchObject({ ok: false, error: { vaultError: { error: "conflict" } } })
  })

  it("sums the resource-owned open ask counters", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      registerOpenAskCounter("fixture-intake", (_ctx, device) => device === "dev_member" ? 9 : 0)
      registerOpenAskCounter("fixture-approval", (_ctx, _device, now) => now === 100 ? 11 : 0)
      expect(openAskCount(ctx, "dev_member", 100)).toBe(20)
      expect(openAskCount(ctx, "dev_service", 100)).toBe(11)
      registerOpenAskCounter("fixture-intake", () => 0); registerOpenAskCounter("fixture-approval", () => 0)
    })
  })
  it("never loosens a pending restriction or revives removed factors after commit", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      installSecurity(ctx, "acc_member", 0, { transitionId: "ast_cancel", reservedEpoch: 2, revokedSessionIds: ["ses_recovered"], removedFactorIds: ["pk_recovered"], restriction: { until: 100_000, reason: "recovery", notice: "ntc_recovery" } })
      expect(() => updateRestriction(ctx, "acc_member", 0, null)).toThrow("not committed")
      installSecurity(ctx, "acc_member", 2, null)
      expect(() => updateRestriction(ctx, "acc_member", 1, null)).toThrow("not committed")
      const current = updateRestriction(ctx, "acc_member", 2, null)
      expect(current.restriction).toBeNull()
      expect(current.revokedSessionIds).toEqual(["ses_recovered"])
      expect(current.removedFactorIds).toEqual(["pk_recovered"])
    })
  })

  it("checks rename authority, exact step-up and reservation expiry without mutation", async () => {
    const { tenant } = await accessFixture()
    const input = { name: "Renamed", reservation: { id: "res_one", expiresAt: new Date(Date.now() - 1000).toISOString() } }
    const action = { type: "workspace.update", name: "Renamed", slug: "work" } as const
    const before = await workspaceInvoke(tenant, "access.workspace_ref", {}, system)
    expect(await workspaceInvoke(tenant, "access.workspace_update", input, accountAuth("owner", action))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "This workspace name reservation expired." } } })
    input.reservation.expiresAt = new Date(Date.now() + 600_000).toISOString()
    expect(await workspaceInvoke(tenant, "access.workspace_update", input, accountAuth("admin", action))).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    expect(await workspaceInvoke(tenant, "access.workspace_update", input, accountAuth("owner", { type: "workspace.unfreeze" }))).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
    expect(await workspaceInvoke(tenant, "access.workspace_ref", {}, system)).toEqual(before)
    expect(await workspaceInvoke(tenant, "access.workspace_update", input, accountAuth("owner", action))).toEqual({ ok: true, value: { displayRev: 2 } })
    expect(await workspaceInvoke(tenant, "access.workspace_ref", {}, system)).toEqual({ ok: true, value: { workspace: { id: tenant, slug: "work", name: "Renamed" }, displayRev: 2, appliedReservations: ["res_one"] } })
  })

  it("requires current exact-operation identity evidence, never session admission alone", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }); setSetting(ctx, "identity_rule_rev", 3)
      const expected = { type: "enrol.accept", workspace: tenant, enrolment: "enr_one", thumbprint: "key", account: "acc_owner", member: "mem_owner", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false }, start: { at: new Date().toISOString(), place: null, clientLabel: "Terminal" } } as const
      const auth = accountAuth("owner", { ...expected, scope: { ...expected.scope, tags: [], projects: [], modes: ["relay"] } })
      auth.sessionCheck = { id: "chk_session", identityRuleRev: 3, gateGeneration: 0, checkSequence: 1, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      const canonical = auth.stepUp!
      const decision = authorise(ctx, invocation, { type: "enrol.accept" }, { owningAccount: "acc_owner", acceptingAccount: "acc_owner" }, ctx.now())
      expect(() => requireStepUp(ctx, decision, canonical, invocation)).toThrow("exact operation")
      const evidence = { id: "chk_operation", subjectDigest: digest(canonical), identityRuleRev: 3, gateGeneration: 0, succeededAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }
      for (const patch of [{ subjectDigest: "different" }, { identityRuleRev: 2 }, { gateGeneration: 1 }, { expiresAt: new Date(Date.now() - 1).toISOString() }]) {
        auth.operationCheck = { ...evidence, ...patch }
        expect(() => requireStepUp(ctx, decision, canonical, invocation)).toThrow("exact operation")
      }
      auth.operationCheck = evidence
      expect(() => requireStepUp(ctx, decision, canonical, invocation)).not.toThrow()
    })
  })

  it("requires complete lifecycle registrations and rolls failing hooks back", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const restore = isolateAccessLifecycleForTests()
      try {
      expect(() => beforeOffboarding(ctx, "mem_member")).toThrow("not registered")
      for (const name of ["credentials", "projects", "consent", "overrides"]) registerOffboardingHook(name, (c) => { c.sql.exec("INSERT OR REPLACE INTO tenant_state(key,value) VALUES (?,'true')", `hook-${name}`) })
      for (const name of ["projects", "consent", "overrides"]) registerAccessChangeHook(name, (c) => { c.sql.exec("INSERT OR REPLACE INTO tenant_state(key,value) VALUES (?,'true')", `change-${name}`) })
      registerExposureProvider(() => [{ item: "itm_workspace", version: 2, ceiling: "lease" }])
      const snapshot = beforeOffboarding(ctx, "mem_member")
      expect(snapshot.exposures.some((e) => e.item === "itm_workspace" && e.source === "reachable_lease")).toBe(true)
      registerOffboardingHook("consent", () => { throw new Error("consent fault") })
      expect(() => ctx.storage.transactionSync(() => runOffboardingHooks(ctx, snapshot))).toThrow("consent fault")
      expect(ctx.sql.exec("SELECT * FROM tenant_state WHERE key LIKE 'hook-%'").toArray()).toEqual([])
      registerOffboardingHook("consent", () => undefined)
      ctx.storage.transactionSync(() => accessChanged(ctx, "mem_member", "suspend"))
      expect(accessState(ctx).accessRev).toBe(2)
      } finally { restore() }
    })
  })

  it("single sign-out retains epoch/restriction and revokes exactly once", async () => {
    const { tenant } = await accessFixture()
    const input = { account: "acc_member", session: "ses_member" }
    expect(await workspaceInvoke(tenant, "access.session_revoke", input, system)).toEqual({ ok: true, value: { revoked: true } })
    expect(await workspaceInvoke(tenant, "access.session_revoke", input, system)).toEqual({ ok: true, value: { revoked: true } })
    await inAccess(tenant, (ctx) => {
      expect(() => principalOf(ctx, accountAuth("member"))).toThrow("no longer authorised")
      expect(security(ctx, "acc_member")).toMatchObject({ installedEpoch: 0, restriction: null, pending: null, revokedSessionIds: ["ses_member"] })
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='account.session_revoke'").toArray()).toHaveLength(1)
    })
  })

  it("returns only the owning account's permitted notices, never team or guest directory detail", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      queueNotice(ctx, { kind: "machine_added", workspace: { id: tenant, slug: "work", name: "Work" }, device: "dev_member", name: "Laptop", owner: { kind: "member", member: "mem_member", name: "Sam" }, place: null, at: new Date().toISOString() })
      expect(noticesFor(ctx, principalOf(ctx, accountAuth("owner")))).toHaveLength(1)
      expect(noticesFor(ctx, { kind: "device", deviceId: "dev_owner" })).toEqual([])
      expect(noticesFor(ctx, { kind: "device", deviceId: "dev_member" })).toEqual([])
      expect(noticesFor(ctx, { kind: "device", deviceId: "dev_service" })).toEqual([])
      expect(noticesFor(ctx, principalOf(ctx, accountAuth("guest")))).toEqual([])
    })
  })

  it("projects only the caller admission and validates retained gate evidence live", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "member"] }); setSetting(ctx, "identity_rule_rev", 4)
      const auth = accountAuth("owner")
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      const others = accessState(ctx).members.filter((m) => m.account !== auth.account)
      expect(eligibilityState(ctx, invocation).members.find((m) => m.account === auth.account)?.standing.identityGate.admitted).toBe(false)
      auth.sessionCheck = { id: "chk_one", identityRuleRev: 4, gateGeneration: 0, checkSequence: 1, succeededAt: new Date(ctx.now() - 1).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      expect(eligibilityState(ctx, invocation).members.find((m) => m.account === auth.account)?.standing.identityGate.admitted).toBe(true)
      expect(eligibilityState(ctx, invocation).members.filter((m) => m.account !== auth.account)).toEqual(others)
      expect(retainedGateValid(ctx, auth, ctx.now())).toBe(true)
      auth.sessionCheck.identityRuleRev = 3
      expect(retainedGateValid(ctx, auth, ctx.now())).toBe(false)
      expect(eligibilityState(ctx, invocation).members.find((m) => m.account === auth.account)?.standing.identityGate.admitted).toBe(false)
      auth.sessionCheck.identityRuleRev = 4; auth.sessionCheck.expiresAt = new Date(ctx.now() - 1).toISOString()
      expect(retainedGateValid(ctx, auth, ctx.now())).toBe(false)
      auth.sessionCheck.expiresAt = new Date(ctx.now() + 600_000).toISOString()
      revokeSession(ctx, auth.account, auth.session)
      expect(retainedGateValid(ctx, auth, ctx.now())).toBe(false)
    })
  })

  it("uses the caller's valid identity evidence for final approval authorisation", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 4)
      const auth = accountAuth("member")
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      const target = { credential: "itm_workspace", ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } }
      expect(() => authorise(ctx, invocation, { type: "approval.approve" }, target, ctx.now())).toThrow("not allowed")
      auth.sessionCheck = { id: "chk_one", identityRuleRev: 4, gateGeneration: 0, checkSequence: 1, succeededAt: new Date(ctx.now() - 1).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      expect(authorise(ctx, invocation, { type: "approval.approve" }, target, ctx.now())).toMatchObject({ allowed: true, stepUp: "approval.decide" })
      auth.sessionCheck.identityRuleRev = 3
      expect(() => authorise(ctx, invocation, { type: "approval.approve" }, target, ctx.now())).toThrow("not allowed")
    })
  })

  it("round-trips an open-ended pending restriction and lowers it only after commit", async () => {
    const { PENDING_RESTRICTION_UNTIL } = await import("@mehen/protocol")
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const restriction = { reason: "recovery" as const, until: PENDING_RESTRICTION_UNTIL, notice: "ntc_pending" }
      installSecurity(ctx, "acc_owner", 0, { transitionId: "ast_open", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction })
      expect(security(ctx, "acc_owner")?.restriction).toEqual(restriction)
      expect(() => updateRestriction(ctx, "acc_owner", 0, { ...restriction, until: ctx.now() + 86_400_000 })).toThrow("not committed")
      observeCommittedEpoch(ctx, "acc_owner", 1)
      const invocation = { auth: { ...accountAuth("owner"), securityEpoch: 1 }, workspace: { id: tenant, slug: "work", name: "Work" } }
      expect(() => authorise(ctx, invocation, { type: "workspace.unfreeze" }, {}, ctx.now())).toThrow("While the pending security transition finishes")
      const deadline = ctx.now() + 86_400_000
      expect(updateRestriction(ctx, "acc_owner", 1, { ...restriction, until: deadline }).restriction?.until).toBe(deadline)
    })
  })

  it("feeds access.init from the frozen real-directory fixture and seeds only through test support", async () => {
    const { createWorkspaceFixture } = await import("./workspace-fixtures.ts")
    const { seedAccessStateForTests } = await import("./access-test-support.ts")
    const fixture = await createWorkspaceFixture()
    const tenant = fixture.workspaces.work
    await inAccess(tenant, (ctx) => {

      registerAccessStateProvider("credentials", () => ({ credentials: fixture.state.credentials }))
      registerAccessStateProvider("projects", () => ({ projects: fixture.state.projects }))
    })
    const initialOwner = fixture.state.members.find((m) => m.account === fixture.account)!
    const input = { workspace: tenant, slug: "northwind", name: "Work", member: initialOwner.id, owner: { account: fixture.account, name: initialOwner.name } }
    expect(await workspaceInvoke(tenant, "access.init", input, system)).toEqual({ ok: true, value: { member: initialOwner.id } })
    await inAccess(tenant, (ctx) => seedAccessStateForTests(ctx, fixture.state))
    await fixture.env.DB.prepare("UPDATE memberships SET role_hint='guest' WHERE id=?").bind(initialOwner.id).run()
    expect(await workspaceInvoke(tenant, "access.membership", { account: fixture.account }, system)).toMatchObject({ ok: true, value: { role: "owner", member: initialOwner.id } })
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices).toEqual(fixture.state.devices))
  })

  it("passes nullable member and explicit team/device targets to lifecycle hooks", async () => {
    const { tenant } = await accessFixture()
    const calls: { member: string | null; reason: string; target: { team?: string; device?: string } }[] = []
    await inAccess(tenant, () => { registerFixtureLifecycleHooks(); registerAccessChangeHook("fixture-targets", (_ctx, member, reason, target) => { calls.push({ member, reason, target }) }) })
    const deletion = { team: "tm_engineering", change: "delete", name: null, slug: null } as const
    expect(await workspaceInvoke(tenant, "access.team.update", deletion, accountAuth("owner", { type: "team.update", ...deletion }))).toMatchObject({ ok: true })
    for (const device of ["dev_service", "dev_member"]) expect(await workspaceInvoke(tenant, "devices.revoke", { device }, accountAuth("owner", { type: "device.revoke", device }))).toMatchObject({ ok: true })
    expect(calls).toEqual([
      { member: null, reason: "team.delete", target: { team: "tm_engineering" } },
      { member: null, reason: "revoke", target: { team: "tm_service", device: "dev_service" } },
      { member: "mem_member", reason: "revoke", target: { device: "dev_member" } },
    ])
  })

  it("keeps account notices for humans and device notices confined to that exact device", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const workspace = { id: tenant, slug: "work", name: "Work" }
      queueNotice(ctx, { kind: "account_security", workspace, account: "acc_member", name: "Member", event: "recovery", client: "Browser", place: "Paris", restrictedUntil: null, at: new Date().toISOString() })
      queueNotice(ctx, { kind: "machine_added", workspace, device: "dev_member", name: "Laptop", owner: { kind: "member", member: "mem_member", name: "Member" }, place: null, at: new Date().toISOString() })
      expect(noticesFor(ctx, { kind: "device", deviceId: "dev_admin" })).toEqual([])
      expect(noticesFor(ctx, { kind: "device", deviceId: "dev_owner" })).toEqual([])
      expect(noticesFor(ctx, principalOf(ctx, accountAuth("admin"))).some((notice) => notice.payload.kind === "account_security")).toBe(true)
      queueNotice(ctx, { kind: "machine_added", workspace, device: "dev_admin", name: "Admin laptop", owner: { kind: "member", member: "mem_admin", name: "Admin" }, place: null, at: new Date().toISOString() })
      const own = noticesFor(ctx, { kind: "device", deviceId: "dev_admin" })
      expect(own).toHaveLength(1)
      expect(own[0]?.payload).toMatchObject({ kind: "machine_added", device: "dev_admin" })
    })
  })
  it("overlays admission on the live rejoined member only and defaults covered gates closed", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      fixtureSql(ctx).exec("UPDATE members SET status='removed' WHERE id='mem_member'")
      newMember(ctx, "acc_member", "Rejoined", "member", "active", "mem_rejoined")
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["member"] }); setSetting(ctx, "identity_rule_rev", 2)
      const auth = accountAuth("member")
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      expect(accessState(ctx).members.filter((m) => m.account === auth.account).every((m) => !m.standing.identityGate.admitted)).toBe(true)
      expect(() => authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now())).toThrow("not allowed")
      auth.sessionCheck = { id: "chk_rejoin", identityRuleRev: 2, gateGeneration: 0, checkSequence: 1, succeededAt: new Date(ctx.now()).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, auth)
      const state = eligibilityState(ctx, invocation)
      expect(state.members.find((m) => m.id === "mem_rejoined")?.standing.identityGate.admitted).toBe(true)
      expect(state.members.find((m) => m.id === "mem_member")?.standing.identityGate.admitted).toBe(false)
      expect(principalOf(ctx, auth)).toMatchObject({ memberId: "mem_rejoined" })
    })
  })
  it("requires a directory reservation to change the slug", async () => {
    const { tenant } = await accessFixture()
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.workspace_update", { slug: "renamed" }, accountAuth("owner", { type: "workspace.update", name: "Work", slug: "renamed" }))).toEqual({ ok: false, error: { status: 400, vaultError: { error: "bad_request", message: "Changing the workspace slug needs a reservation." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("refuses every system-only operation for both account and signed device callers", async () => {
    beginAccessSideEffectChecks()
    try {
      const { tenant } = await accessFixture()
      const { newDeviceKey, publicJwk } = await import("./devices.ts")
      const { createProof, webCryptoSigner, jwkThumbprint, bodyHash } = await import("@mehen/protocol")
      const keys = await newDeviceKey()
      const jwk = await publicJwk(keys)
      const thumbprint = await jwkThumbprint(jwk)
      await inAccess(tenant, (ctx) => ctx.sql.exec("UPDATE devices SET jwk=?,thumbprint=? WHERE id='dev_owner'", JSON.stringify(jwk), thumbprint))
      const url = "https://vault.test/v1/system-guard"
      const deviceAuth = { kind: "device" as const, method: "POST", url, bodyHash: await bodyHash(null), proof: await createProof(webCryptoSigner("dev_owner", keys.privateKey), { method: "POST", url }, { tenant }) }
      const before = await accessSnapshot(tenant)
      for (const op of ["access.init", "access.workspace_ref", "access.security.install", "access.security.commit", "access.security.restriction", "access.session_revoke", "access.account_event", "access.outbox.drain", "access.outbox.ack", "access.invites.lookup", "access.invites.redeem", "access.enrol.register", "access.enrol.mirrored", "access.enrol.discard", "access.enrol.reconcile", "access.membership"]) {
        for (const auth of [accountAuth("owner"), deviceAuth]) expect(await workspaceInvoke(tenant, op, {}, auth)).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
        expect(await accessSnapshot(tenant)).toBe(before)
      }
    } finally { finishAccessSideEffectChecks() }
  })

})
