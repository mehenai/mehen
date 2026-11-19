import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { workspaceMemberOps } from "../src/vault/areas/workspace-members.ts"
import { workspaceDeviceOps } from "../src/vault/areas/workspace-devices.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { assertRunUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { approvedProjectRun, projectFixture, projectState, inAccess, projectSecurityRows, accountAuth } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { VaultError } from "../src/http.ts"

function lifecycleRows(ctx: import("../src/vault/core.ts").VaultContext): string {
  return canonicalJson([projectSecurityRows(ctx), ...["devices", "teams", "team_members"].map((table) => ctx.sql.exec(`SELECT * FROM ${table}`).toArray())])
}
describe("PROJECTS nullable access-change targets with real hooks", () => {
  for (const change of ["team.delete", "device.revoke"] as const) for (const auditFailure of [false, true]) {
    it(`${change} voids team-machine authority, audit rollback=${auditFailure}`, async () => {
      const f = await projectFixture()
      await inAccess(f.tenant, async (ctx) => {
        ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','manage','$.protected',json('true')) WHERE id='shr_service'")
        const own = await approvedProjectRun(ctx)
        const service = await approvedProjectRun(ctx, undefined, "dev_service")
        ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT 'dev_service2','Other service','software','{}','service2-key',scope,?,'team','tm_service' FROM devices WHERE id='dev_service'", ctx.now())
        const otherService = await approvedProjectRun(ctx, undefined, "dev_service2")
        let pending: string | undefined
        try { await workspaceRunOps["runs.create"]!.handler(ctx, service.principal, service.input, service.invocation) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; pending = error.extra.approval }
        expect(pending).toBeDefined()
        // Team deletion requires revoked machines. Model a stranded run from
        // before hooks were installed; deletion must still clear its authority.
        if (change === "team.delete") ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE owner_kind='team' AND owner_id='tm_service'", ctx.now())
        const before = lifecycleRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch"), originalAudit = ctx.audit.bind(ctx)
        const audit = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (auditFailure && event.action === change) throw new Error("lifecycle audit failed"); originalAudit(event) })
        const principal = accessMember(projectState(ctx), "owner"), workspace = { id: ctx.tenant, slug: "work", name: "Work" }
        const perform = () => change === "team.delete"
          ? workspaceMemberOps["access.team.update"]!.handler(ctx, principal, { team: "tm_service", change: "delete", name: null, slug: null }, { workspace, auth: accountAuth("owner", { type: "team.update", team: "tm_service", change: "delete", name: null, slug: null }) })
          : workspaceDeviceOps["devices.revoke"]!.handler(ctx, principal, { device: "dev_service" }, { workspace, auth: accountAuth("owner", { type: "device.revoke", device: "dev_service" }) })
        if (auditFailure) {
          expect(perform).toThrow("lifecycle audit failed")
          expect(lifecycleRows(ctx)).toBe(before)
        } else {
          perform()
          expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id=?", service.run).toArray()[0]!.ended_at).not.toBeNull()
          expect(workspaceApproval(ctx, pending!)!.status).toBe("denied")
          for (const table of ["protected_use_grants", "consent_lineage"]) expect(ctx.sql.exec<{ revoked_at: number | null }>(`SELECT revoked_at FROM ${table} WHERE ${table === "consent_lineage" ? "decision" : "approval"}=?`, service.approval).toArray()[0]!.revoked_at).not.toBeNull()
          expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM run_authorisations WHERE run=?", service.run).toArray()[0]!.revoked_at).not.toBeNull()
          expect(() => assertRunUse(ctx, projectState(ctx), service.run, { kind: "device" as const, deviceId: "dev_service" }, ctx.now())).toThrow("No live run")
          expect(() => assertRunUse(ctx, projectState(ctx), own.run, { kind: "device" as const, deviceId: "dev_kim" }, ctx.now())).not.toThrow()
          if (change === "device.revoke") expect(() => assertRunUse(ctx, projectState(ctx), otherService.run, { kind: "device" as const, deviceId: "dev_service2" }, ctx.now())).not.toThrow()
          else expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id=?", otherService.run).toArray()[0]!.ended_at).not.toBeNull()
        }
        audit.mockRestore()
        expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
      })
    })
  }
})

import { accessChanged, registerOffboardingHook, runOffboardingHooks } from "../src/vault/areas/workspace-runtime.ts"
describe("real PROJECTS member lifecycle hooks", () => {
  for (const change of ["offboard", "suspend"] as const) for (const rollback of [false, true]) it(`${change} revokes own and decided-for-others authority, rollback=${rollback}`, async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      // Only the external credential owner is doubled here. The PROJECTS and
      // consent hooks registered by the application modules remain real.
      registerOffboardingHook("credentials", () => undefined)
      const own = await approvedProjectRun(ctx), decided = await approvedProjectRun(ctx, undefined, "dev_member", "kim")
      let pending: string | undefined
      try { await workspaceRunOps["runs.create"]!.handler(ctx, own.principal, own.input, own.invocation) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; pending = error.extra.approval }
      expect(pending).toBeDefined()
      const before = lifecycleRows(ctx), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch"), originalAudit = ctx.audit.bind(ctx)
      const audit = vi.spyOn(ctx, "audit").mockImplementation((event) => { if (rollback && event.action === "fixture.lifecycle") throw new Error("lifecycle audit failed"); originalAudit(event) })
      const perform = () => ctx.storage.transactionSync(() => {
        if (change === "offboard") runOffboardingHooks(ctx, { removal: "rem_fixture", by: "mem_owner", member: "mem_kim", devices: ["dev_kim"], privateItems: [], exposures: [], accessRevision: projectState(ctx).accessRev })
        else accessChanged(ctx, "mem_kim", "suspend")
        ctx.audit({ actor: "member:mem_owner", action: "fixture.lifecycle", target: "mem_kim" })
      })
      if (rollback) {
        expect(perform).toThrow("lifecycle audit failed")
        expect(lifecycleRows(ctx)).toBe(before)
      } else {
        perform()
        expect(workspaceApproval(ctx, pending!)!.status).toBe("denied")
        expect(ctx.sql.exec<{ ended_at: number | null }>("SELECT ended_at FROM runs WHERE id=?", own.run).toArray()[0]!.ended_at).not.toBeNull()
        for (const active of [own, decided]) {
          for (const table of ["protected_use_grants", "consent_lineage"]) expect(ctx.sql.exec<{ revoked_at: number | null }>(`SELECT revoked_at FROM ${table} WHERE ${table === "consent_lineage" ? "decision" : "approval"}=?`, active.approval).toArray()[0]!.revoked_at).not.toBeNull()
          expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM run_authorisations WHERE run=?", active.run).toArray()[0]!.revoked_at).not.toBeNull()
          expect(() => assertRunUse(ctx, projectState(ctx), active.run, { kind: "device" as const, deviceId: active.principal.deviceId }, ctx.now())).toThrow()
        }
      }
      audit.mockRestore()
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})
