import { describe, expect, it } from "vitest"
import { credentialPending } from "../src/vault/areas/credentials-pending.ts"
import { createWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { credentialsFixture, inAccess, memberPrincipal, memberInvocation } from "./credentials-test-support.ts"
describe("credential pending home projections", () => {
  it("omits a member's human-created private intake for admins but includes it for its owner", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, ctx => {
      const p = memberPrincipal(ctx, "member"), i = memberInvocation(ctx, "member")
      const request = createWorkspaceIntake(ctx, p, { slug: "private-pending", provider: "openai", home: "private" }, i)
      expect(credentialPending(ctx, memberPrincipal(ctx, "admin"), memberInvocation(ctx, "admin"))).toEqual([])
      expect(credentialPending(ctx, p, i)).toMatchObject([{ view: "detail", detail: { id: request.intake, item: "private-pending", kind: "intake" } }])
    })
  })
})
it("registers the real credential provider in workspace pending without exposing private human asks to admins", async () => {
  const { workspacePendingOps } = await import("../src/vault/areas/pending-workspace.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    const p = memberPrincipal(ctx, "member"), invocation = memberInvocation(ctx, "member")
    const request = createWorkspaceIntake(ctx, p, { slug: "registered-private", provider: "openai", home: "private" }, invocation)
    const own = await workspacePendingOps["pending.list"]!.handler(ctx, p, {}, invocation) as { pending: import("@mehen/protocol").WorkspacePendingAsk[] }
    expect(own.pending).toMatchObject([{ view: "detail", detail: { id: request.intake, item: "registered-private" } }])
    const admin = await workspacePendingOps["pending.list"]!.handler(ctx, memberPrincipal(ctx, "admin"), {}, memberInvocation(ctx, "admin")) as { pending: import("@mehen/protocol").WorkspacePendingAsk[] }
    expect(admin.pending).toEqual([])
  })
})
it("dates a person's credential asks for the inbox and leaves a machine's own copy as a 0.2.0 CLI decodes it", async () => {
  const { devicePrincipal } = await import("./credentials-test-support.ts")
  const f = await credentialsFixture()
  await inAccess(f.tenant, ctx => {
    const p = memberPrincipal(ctx, "owner"), i = memberInvocation(ctx, "owner")
    const request = createWorkspaceIntake(ctx, p, { slug: "dated-pending", provider: "openai", home: "workspace" }, i)
    const [row] = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM workspace_credential_requests WHERE id=?", request.intake).toArray()
    expect(credentialPending(ctx, p, i)).toMatchObject([{ view: "detail", detail: { id: request.intake, createdAt: new Date(row!.created_at).toISOString() } }])
    ctx.sql.exec("UPDATE workspace_credential_requests SET requester_member=NULL,requester_device='dev_member' WHERE id=?", request.intake)
    const machine = credentialPending(ctx, devicePrincipal("dev_member"), i)
    expect(machine).toMatchObject([{ view: "detail", detail: { id: request.intake } }])
    expect(machine[0]?.view === "detail" && "createdAt" in machine[0].detail).toBe(false)
  })
})
