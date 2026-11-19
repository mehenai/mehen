// A workspace object's two system calls for the operator console
// (access.operator_view and access.operator_freeze in vault/areas/access.ts):
// only the directory's system path reaches them, the view answers only what
// the console shows, and the freeze is the workspace's own, recorded in its
// own audit as the operator's account and lifted only by an owner.

import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, workspaceInvoke } from "./access-test-support.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

const SYSTEM = { kind: "system", reason: "operator console" } as const
const FORBIDDEN = { ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } }

describe("a workspace object's operator calls", () => {
  it("refuses both to every caller but the directory's system path, changing nothing", async () => {
    const { tenant } = await accessFixture()
    const before = await accessSnapshot(tenant)
    for (const op of ["access.operator_view", "access.operator_freeze"]) {
      const input = op === "access.operator_freeze" ? { operator: "acc_owner" } : {}
      for (const role of ["owner", "admin", "member", "guest"]) expect(await workspaceInvoke(tenant, op, input, accountAuth(role))).toEqual(FORBIDDEN)
      expect(await workspaceInvoke(tenant, op, input, { kind: "platform", platform: "plt_globex", key: "pk_x", subject: "user", request: "req_x" } as never)).toEqual(FORBIDDEN)
    }
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("answers its view with whether it is frozen, its owners by account and name, and how many are unconfirmed, nothing else", async () => {
    const { tenant } = await accessFixture()
    const view = await workspaceInvoke(tenant, "access.operator_view", {}, SYSTEM)
    expect(view).toEqual({ ok: true, value: { frozen: false, owners: [{ account: "acc_owner", name: "owner" }], unconfirmed: 0 } })
  })

  it("freezes as the operator's account in its own audit, tells its owners and admins, and only an owner unfreezes it", async () => {
    const { tenant } = await accessFixture()
    expect(await workspaceInvoke(tenant, "access.operator_freeze", { operator: "acc_kim" }, SYSTEM)).toEqual({ ok: true, value: { frozen: true, already: false, notify: ["acc_owner", "acc_admin"] } })
    // A second freeze changes nothing and records nothing.
    expect(await workspaceInvoke(tenant, "access.operator_freeze", { operator: "acc_guest" }, SYSTEM)).toEqual({ ok: true, value: { frozen: true, already: true, notify: ["acc_owner", "acc_admin"] } })
    const audit = await inAccess(tenant, (ctx) => ctx.sql.exec<{ actor: string; action: string; target: string }>("SELECT actor,action,target FROM audit WHERE action LIKE 'workspace.%'").toArray())
    expect(audit).toEqual([{ actor: "operator:acc_kim", action: "workspace.freeze", target: tenant }])
    expect(await workspaceInvoke(tenant, "access.operator_view", {}, SYSTEM)).toMatchObject({ ok: true, value: { frozen: true } })
    // The console has no unfreeze: the system path cannot reach it, and an owner lifts it with a passkey.
    expect(await workspaceInvoke(tenant, "access.unfreeze", {}, SYSTEM)).toEqual(FORBIDDEN)
    expect(await workspaceInvoke(tenant, "access.unfreeze", {}, accountAuth("admin", { type: "workspace.unfreeze" }))).toMatchObject({ ok: false, error: { status: 403 } })
    expect(await workspaceInvoke(tenant, "access.unfreeze", {}, accountAuth("owner", { type: "workspace.unfreeze" }))).toMatchObject({ ok: true })
    expect(await workspaceInvoke(tenant, "access.operator_view", {}, SYSTEM)).toMatchObject({ ok: true, value: { frozen: false } })
  })

  it("refuses an operator that is not an account id", async () => {
    const { tenant } = await accessFixture()
    const answer = await workspaceInvoke(tenant, "access.operator_freeze", { operator: "member:mem_owner" }, SYSTEM)
    expect(answer).toMatchObject({ ok: false, error: { status: 400 } })
    expect(await workspaceInvoke(tenant, "access.operator_view", {}, SYSTEM)).toMatchObject({ ok: true, value: { frozen: false } })
  })
})
