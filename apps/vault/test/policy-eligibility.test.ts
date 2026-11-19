import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { workspacePolicyOps } from "../src/vault/areas/policy-workspace.ts"
import { projectFixture, projectState, inAccess, accountAuth } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { VaultError } from "../src/http.ts"
describe("workspace policy eligibility while widening remains disabled", () => {
  it("answers a machine's state, status, cancel and grant revoke as preview and propose do", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      for (const op of ["policy.state", "policy.status", "policy.cancel", "policy.revoke-grant"]) {
        expect(workspacePolicyOps[op]?.auth, op).toContain("device")
        try { workspacePolicyOps[op]!.handler(ctx, { kind: "device", deviceId: "dev_member" }, { id: "pol_missing123" }, { auth: { kind: "device", proof: "", method: "GET", url: "", bodyHash: "" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON(), op).toEqual({ error: "forbidden", message: "Policy widening is not available yet.", next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } }) }
      }
    })
  })
  it("refuses preview, propose and approve with no state, open or send", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM policy_proposals").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      for (const op of ["policy.preview", "policy.propose", "policy.approve"]) {
        try { workspacePolicyOps[op]!.handler(ctx, accessMember(projectState(ctx), "owner"), {}, { auth: accountAuth(), workspace: { id: ctx.tenant, slug: "work", name: "Work" } }); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "forbidden", message: "Policy widening is not available yet.", next: { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." } }) }
      }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM policy_proposals").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("answers a window's status, deny and stop as no such object", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), workspace = { id: ctx.tenant, slug: "work", name: "Work" }
      const answers = [
        ["policy.status", { id: "pol_fixture123" }],
        ["policy.action", { id: "pol_fixture123", decision: "deny" }],
        ["policy.decide", { id: "pol_fixture123", decision: "deny" }],
        ["policy.stop", { id: "pov_fixture" }],
      ].map(([op, input]) => { try { workspacePolicyOps[op as string]!.handler(ctx, accessMember(state, "owner"), input, { auth: accountAuth(), workspace }); return null } catch (error) { return (error as VaultError).toJSON() } })
      expect(answers).toEqual(Array(4).fill({ error: "not_found", message: "No such object." }))
    })
  })
})
