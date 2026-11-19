// accessState across the invocations of one object (tenant-vault.ts
// invocationContext): built once and shared by every call through the
// object's own context, dropped by any write to the object's storage from
// any call, by a transaction that rolled back, or once an open invite
// lapses. eligibilityState leaves the shared state as it was.
import { describe, expect, it, vi } from "vitest"
import { INVITE_TTL_MS, canonicalJson } from "@mehen/protocol"
import { invocationContext } from "../src/vault/tenant-vault.ts"
import { accessState, authorise, eligibilityState, memberRows, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { accessFixture, accountAuth, inAccess, installTestIdentity, workspaceInvoke } from "./access-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { beforeManagementChange } from "../src/vault/areas/management-guard.ts"

const ACCESS_STATE_READ = "SELECT id,owner_kind,owner_id,scope,revoked_at FROM devices WHERE owner_kind IS NOT NULL"
function builds(ctx: VaultContext): () => number {
  const exec = vi.spyOn(ctx.sql, "exec")
  return () => exec.mock.calls.filter((call) => call[0] === ACCESS_STATE_READ).length
}
const name = (ctx: VaultContext, member: string) => accessState(ctx).members.find((m) => m.id === member)?.name

describe("accessState across the invocations of one object", () => {
  it("builds once and shares one frozen state with every call until the object is written", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const count = builds(base), call = invocationContext(base)
      const first = accessState(call)
      expect(accessState(call)).toBe(first)
      expect(accessState(Object.create(call) as VaultContext)).toBe(first)
      expect(count()).toBe(1)
      expect(Object.isFrozen(first.members[0]!.standing.identityGate)).toBe(true)
      expect(() => { (first.members as unknown[]).push(null) }).toThrow(TypeError)
      // Another call shares it; the object's own context outside any call builds afresh.
      expect(accessState(invocationContext(base))).toBe(first)
      expect(accessState(base)).not.toBe(accessState(base))
      expect(count()).toBe(3)
    })
  })
  it("keeps the memo with the context that counts the writes: a second context over the same storage builds its own", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const count = builds(base)
      const first = accessState(invocationContext(base))
      expect(accessState(invocationContext(base))).toBe(first)
      expect(count()).toBe(1)
      // Its own counter, on the same value as the first context's memo.
      const other = Object.create(base, { storageWrites: { value: base.storageWrites } }) as VaultContext
      const second = accessState(invocationContext(other))
      expect(second).not.toBe(first)
      expect(accessState(invocationContext(other))).toBe(second)
      expect(accessState(invocationContext(base))).toBe(first)
      expect(count()).toBe(2)
    })
  })
  it("a write by any call drops the state for every call, which then build it once between them", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const count = builds(base), calls = [invocationContext(base), invocationContext(base), invocationContext(base)]
      expect(calls.map((call) => name(call, "mem_kim"))).toEqual(["Kim", "Kim", "Kim"])
      expect(count()).toBe(1)
      fixtureSql(calls[1]!).exec("UPDATE members SET name='Kim B' WHERE id='mem_kim'")
      expect(calls.map((call) => name(call, "mem_kim"))).toEqual(["Kim B", "Kim B", "Kim B"])
      expect(count()).toBe(2)
      fixtureSql(base).exec("UPDATE members SET status='removed' WHERE id='mem_kim'")
      expect(calls.map((call) => accessState(call).members.find((m) => m.id === "mem_kim")?.status)).toEqual(["removed", "removed", "removed"])
      expect(count()).toBe(3)
    })
  })
  it("sees a write made in the same call, and one made by another call or an alarm meanwhile", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const call = invocationContext(base), other = invocationContext(base)
      expect(name(call, "mem_kim")).toBe("Kim")
      fixtureSql(call).exec("UPDATE members SET name='Kim A' WHERE id='mem_kim'")
      expect(name(call, "mem_kim")).toBe("Kim A")
      fixtureSql(other).exec("UPDATE members SET name='Kim B' WHERE id='mem_kim'")
      expect(name(call, "mem_kim")).toBe("Kim B")
      fixtureSql(base).exec("UPDATE members SET name='Kim C' WHERE id='mem_kim'")
      expect(name(call, "mem_kim")).toBe("Kim C")
      setSetting(base, "access_rev", 41)
      expect(accessState(call).accessRev).toBe(41)
    })
  })
  it("drops an open invite's pending role once it lapses, with no write between, for a later call than the one that built it", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const clock = { at: base.now() }
      fixtureSql(base).exec("UPDATE members SET pending_role='admin', pending_since=? WHERE id='mem_kim'", clock.at)
      const clocked = Object.assign(Object.create(base) as VaultContext, { now: () => clock.at })
      const count = builds(base)
      const pending = (call: VaultContext) => accessState(call).members.find((m) => m.id === "mem_kim")?.standing.pendingRole
      expect(pending(invocationContext(clocked))).toBe("admin")
      clock.at += INVITE_TTL_MS - 1
      expect(pending(invocationContext(clocked))).toBe("admin")
      expect(count()).toBe(1)
      clock.at += 1
      expect(pending(invocationContext(clocked))).toBeNull()
      expect(count()).toBe(2)
    })
  })
  it("does not keep what it read inside a transaction that rolled back", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      const call = invocationContext(base), other = invocationContext(base)
      expect(() => call.storage.transactionSync(() => {
        fixtureSql(call).exec("UPDATE members SET name='Rolled back' WHERE id='mem_kim'")
        expect(name(call, "mem_kim")).toBe("Rolled back")
        throw new Error("refused")
      })).toThrow("refused")
      expect(name(other, "mem_kim")).toBe("Kim")
      expect(name(call, "mem_kim")).toBe("Kim")
    })
  })
  it("eligibilityState decides the caller's gate on a copy, leaving the shared state unchanged", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (base) => {
      setSetting(base, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] })
      const owner = memberRows(base).find((m) => m.id === "mem_owner")!, now = base.now()
      const auth = { ...accountAuth("owner"), sessionCheck: { id: "chk_owner", identityRuleRev: 0, gateGeneration: owner.gate_generation, checkSequence: owner.check_sequence + 1, succeededAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() } }
      installTestIdentity(base, auth)
      const call = invocationContext(base)
      const shared = accessState(call), before = canonicalJson(shared)
      expect(shared.members.find((m) => m.id === "mem_owner")?.standing.identityGate).toEqual({ covered: true, admitted: false, checkedAt: null })
      const decided = eligibilityState(call, { workspace: { id: tenant, slug: "work", name: "Work" }, auth })
      expect(decided.members.find((m) => m.id === "mem_owner")?.standing.identityGate).toEqual({ covered: true, admitted: true, checkedAt: now - 1000 })
      expect(decided.members.find((m) => m.id === "mem_owner")).not.toBe(shared.members.find((m) => m.id === "mem_owner"))
      expect(decided.members.find((m) => m.id === "mem_kim")).toBe(shared.members.find((m) => m.id === "mem_kim"))
      expect(accessState(call)).toBe(shared)
      expect(canonicalJson(shared)).toBe(before)
    })
  })
  it("drops the state mid-call: a call that demotes or removes its own member and then authorises as them in the same transaction is refused", async () => {
    const CHANGES = { demote: { sql: "UPDATE members SET role='member' WHERE id='mem_admin'", refused: "forbidden" }, remove: { sql: "UPDATE members SET status='removed' WHERE id='mem_admin'", refused: "not_found" } }
    const { tenant } = await accessFixture()
    let allowedBefore = 0
    // A test-only op, dispatched by TenantVault.invoke like any other.
    workspacePendingOps["test.changeThenAuthorise"] = { auth: ["account"], handler(ctx, _principal, raw, invocation) {
      const change = CHANGES[(raw as { change: keyof typeof CHANGES }).change]
      return ctx.storage.transactionSync(() => {
        authorise(ctx, invocation, { type: "member.invite" }, {}, ctx.now())
        allowedBefore++
        beforeManagementChange(ctx)
        ctx.sql.exec(change.sql)
        authorise(ctx, invocation, { type: "member.invite" }, {}, ctx.now())
        return {}
      })
    } }
    try {
      for (const [n, change] of (Object.keys(CHANGES) as (keyof typeof CHANGES)[]).entries()) {
        const count = await inAccess(tenant, (base) => builds(base))
        const result = await workspaceInvoke(tenant, "test.changeThenAuthorise", { change }, accountAuth("admin"))
        expect(result).toMatchObject({ ok: false, error: { vaultError: { error: CHANGES[change].refused } } })
        expect(allowedBefore).toBe(n + 1)
        // Built once for the call's checks before the write, once after it.
        expect(count()).toBe(2)
        vi.restoreAllMocks()
        await inAccess(tenant, (base) => expect(memberRows(base).find((m) => m.id === "mem_admin")).toMatchObject({ role: "admin", status: "active" }))
      }
    } finally {
      delete workspacePendingOps["test.changeThenAuthorise"]
    }
  })
})
