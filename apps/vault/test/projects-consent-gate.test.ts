import { installTestIdentity } from "./access-test-support.ts"
import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { prepareApprovedUse, assertApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { setSetting, revokeSession } from "../src/vault/areas/workspace-runtime.ts"
import { projectFixture, projectState, inAccess, accountAuth } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { VaultError } from "../src/http.ts"
describe("workspace retained deciding-session evidence", () => {
  it("requires a live covered check, records it, and refuses consent after deciding-session revocation", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!, workspace = { id: ctx.tenant, name: "Work", slug: "work" }
      const required = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace, presentation: { title: "Protected test", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, { item: "key-project", method: "POST", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }, null, ctx.now())
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner"] }); setSetting(ctx, "identity_rule_rev", 4)
      const row = workspaceApproval(ctx, required.approvalId)!, action = { type: "approval.decide" as const, approval: row.id, digest: row.digest, decision: "approve" as const, constraints: { uses: 1, ttlSeconds: 600 } }
      const auth = accountAuth("owner", action), principal = accessMember(projectState(ctx), "owner"), input = { id: row.id, decision: "approve" }
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch"), before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())
      for (const kind of ["missing", "old-rule"] as const) {
        auth.sessionCheck = kind === "missing" ? null : { id: "chk_old", identityRuleRev: 3, gateGeneration: 0, checkSequence: 1, succeededAt: new Date(ctx.now()).toISOString(), expiresAt: new Date(ctx.now()+60_000).toISOString() }
        try { workspaceApprovalOps["approvals.decide"]!.handler(ctx, principal, input, { auth, workspace }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "identity_required", message: "You are not allowed to do that." }) }
      }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
      auth.sessionCheck = { id: "chk_live", identityRuleRev: 4, gateGeneration: 0, checkSequence: 2, succeededAt: new Date(ctx.now()).toISOString(), expiresAt: new Date(ctx.now()+60_000).toISOString() }
      installTestIdentity(ctx, auth)
      const result = workspaceApprovalOps["approvals.decide"]!.handler(ctx, principal, input, { auth, workspace }) as import("@mehen/protocol").ApprovalViewProjection
      expect(result.view).toBe("detail")
      expect(() => assertApprovedUse(ctx, projectState(ctx), required.snapshot, row.id, ctx.now())).not.toThrow()
      const basis = JSON.parse(ctx.sql.exec<{ basis: string }>("SELECT basis FROM consent_lineage").toArray()[0]!.basis)
      expect(basis).toMatchObject({ account: "acc_owner", session: "ses_owner", securityEpoch: 0, sessionCheck: { id: "chk_live" } })
      revokeSession(ctx, "acc_owner", "ses_owner")
      expect(() => assertApprovedUse(ctx, projectState(ctx), required.snapshot, row.id, ctx.now())).toThrow("no longer has a current approval")
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})
