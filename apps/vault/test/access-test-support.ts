import { expect, vi } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { canonicalJson } from "@mehen/protocol"
import type { AccountInvocationAuth, VaultContext, WorkspaceInvocation } from "../src/vault/core.ts"
import type { AccessState } from "../src/vault/access.ts"
import { installIdentity, memberRows, newMember, registerAccessStateProvider, registerOffboardingHook, registerAccessChangeHook, registerExposureProvider, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { workspaceAccessState } from "./workspace-fixtures.ts"
import { freshTenant } from "./helpers.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

// Test-only seed. No production operation imports or exposes this function.
export function seedAccessStateForTests(ctx: VaultContext, state: AccessState): void {
  withTrustedSchema(ctx, () => ctx.sql.exec("CREATE TABLE IF NOT EXISTS access_fixture_state(value TEXT NOT NULL)"))
  ctx.sql.exec("DELETE FROM access_fixture_state")
  ctx.sql.exec("INSERT INTO access_fixture_state VALUES (?)", canonicalJson(state))
  for (const name of ["projects", "credentials"] as const) registerAccessStateProvider(name, (c) => {
    const saved = c.sql.exec<{ value: string }>("SELECT value FROM access_fixture_state").toArray()[0]
    const fixture = JSON.parse(saved?.value ?? "{}") as AccessState
    return { [name]: fixture[name] }
  })
  fixtureSql(ctx).exec("DELETE FROM members")
  for (const m of state.members) { newMember(ctx, m.account, m.name, m.standing.effectiveRole, m.status); fixtureSql(ctx).exec("UPDATE members SET id=?,pending_role=? WHERE account=?", m.id, m.standing.pendingRole, m.account) }
  for (const t of state.teams) {
    fixtureSql(ctx).exec("INSERT INTO teams VALUES (?,?,?,?,?)", t.id, t.id.replaceAll("_", "-"), t.name, "mem_owner", ctx.now())
    for (const m of t.members) fixtureSql(ctx).exec("INSERT INTO team_members(team,member) VALUES (?,?)", t.id, m)
  }
  for (const s of state.shares) fixtureSql(ctx).exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", s.id, s.project, s.subject.kind, s.subject.kind === "member" ? s.subject.member : s.subject.team, canonicalJson(s))
  for (const d of state.devices) ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) VALUES (?,?,?,'{}',?,?,?,?,?)", d.id, d.id, "software", d.id, canonicalJson(d.scope), ctx.now(), d.owner.kind, d.owner.id)
  setSetting(ctx, "access_rev", state.accessRev)
}
export async function accessFixture(): Promise<{ tenant: string; state: AccessState }> {
  const tenant = freshTenant()
  const state = workspaceAccessState()
  await inAccess(tenant, (ctx) => { if (sideEffectChecks) secretOpenSpies.push(vi.spyOn(ctx, "openField").mockImplementation(async () => { throw new Error("Unexpected secret open in access test") })); setSetting(ctx, "workspace", { id: tenant, slug: "work", name: "Work" }); seedAccessStateForTests(ctx, state) })
  return { tenant, state }
}
export function inAccess<T>(tenant: string, fn: (ctx: VaultContext) => T | Promise<T>): Promise<T> { return runInDurableObject(env.TENANT_VAULT.getByName(tenant), (instance) => fn(instance.context)) }
export function accountAuth(role = "owner", action?: AccountInvocationAuth["stepUp"]): AccountInvocationAuth { return { kind: "account", account: `acc_${role}`, session: `ses_${role}`, securityEpoch: 0, sessionCheck: null, restrictedUntil: null, ...(action ? { stepUp: action, stepUpFactor: "pk_fixture" } : {}) } }
export function workspaceInvoke(tenant: string, op: string, input: unknown, auth: WorkspaceInvocation["auth"] = accountAuth()): Promise<import("../src/vault/core.ts").InvocationResult> { return env.TENANT_VAULT.getByName(tenant).invoke({ op, input, auth }) }
// The data, never the management guard's own tables, whose revision counts
// writes rather than holding state.
export async function accessSnapshot(tenant: string): Promise<string> { return inAccess(tenant, (ctx) => canonicalJson(ctx.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB '_mehen_*' ORDER BY name").toArray().map(({ name }) => ({ name, rows: ctx.sql.exec(`SELECT * FROM ${name}`).toArray() })))) }

export function registerFixtureLifecycleHooks(): void {
  // Explicit doubles for resources owned by the parallel lanes.
  for (const name of ["credentials", "projects", "consent", "overrides"]) registerOffboardingHook(name, () => undefined)
  for (const name of ["projects", "consent", "overrides"]) registerAccessChangeHook(name, () => undefined)
  registerExposureProvider(() => [])
}

let sideEffectChecks = false
const secretOpenSpies: ReturnType<typeof vi.spyOn>[] = []
let upstreamSpy: ReturnType<typeof vi.spyOn> | null = null
export function beginAccessSideEffectChecks(): void {
  sideEffectChecks = true; secretOpenSpies.length = 0
  upstreamSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("Unexpected upstream send in access test") })
}
export function finishAccessSideEffectChecks(): void {
  try { for (const spy of secretOpenSpies) expect(spy).not.toHaveBeenCalled(); if (upstreamSpy) expect(upstreamSpy).not.toHaveBeenCalled() } finally { sideEffectChecks = false; for (const spy of secretOpenSpies) spy.mockRestore(); upstreamSpy?.mockRestore() }
}
export function editAccessFixture(ctx: VaultContext, edit: (state: AccessState) => void): void {
  const state = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM access_fixture_state").toArray()[0]!.value) as AccessState
  edit(state)
  ctx.sql.exec("UPDATE access_fixture_state SET value=?", canonicalJson(state))
}

export function installTestIdentity(ctx: VaultContext, auth: AccountInvocationAuth): void {
  const member = memberRows(ctx).find(m => m.account === auth.account && m.status !== "removed")
  if (!member || !auth.sessionCheck) throw new Error("An identity fixture needs a live member and check")
  installIdentity(ctx, { account: auth.account, member: member.id, session: auth.session, securityEpoch: auth.securityEpoch, sessionCheck: auth.sessionCheck })
}
