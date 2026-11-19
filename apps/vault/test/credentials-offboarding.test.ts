import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import type { OffboardingSnapshot } from "../src/vault/services.ts"
import { verifyAuditChain, type AuditRow } from "../src/vault/audit.ts"
import { workspaceMemberOps } from "../src/vault/areas/workspace-members.ts"
import { beforeOffboarding } from "../src/vault/areas/workspace-runtime.ts"
import { checkedCredential, registerCredentialServices, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { workspaceApproval } from "../src/vault/areas/approvals-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { VaultError } from "../src/http.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
import { accessSnapshot } from "./access-test-support.ts"
import { projectFixture } from "./projects-workspace-fixture.ts"

const removalAction = { type: "member.remove", member: "mem_member" } as const

describe("real credential offboarding hooks", () => {
  it("snapshots current unused lease reach, deletes private values, cancels asks and flags only surviving shared values", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const privateItem = await seedCredential(ctx, "offboard-private", { kind: "member", member: "mem_member" })
      const shared = await seedCredential(ctx, "offboard-shared")
      const p = memberPrincipal(ctx, "member"), invocation = memberInvocation(ctx, "member")
      const request = createWorkspaceIntake(ctx, p, { provider: "openai", slug: "offboard-request", home: "private" }, invocation)
      expect(beforeOffboarding(ctx, "mem_member").exposures).toEqual(expect.arrayContaining([expect.objectContaining({ item: shared.id, source: "reachable_lease", version: shared.version })]))
      const projectHooks = await import("../src/vault/areas/projects-workspace.ts")
      const original = projectHooks.onCredentialRemoved
      const removed = vi.spyOn(projectHooks, "onCredentialRemoved").mockImplementation((context,item,reason,by) => {
        expect(checkedCredential(context,item.slug)?.id).toBe(item.id)
        return original(context,item,reason,by)
      })
      const beforeSeq = ctx.sql.exec<{seq:number}>("SELECT COALESCE(MAX(seq),0) AS seq FROM audit").toArray()[0]!.seq
      const open = vi.spyOn(ctx, "openField")
      expect(await workspaceMemberOps["access.members.remove"]!.handler(ctx, memberPrincipal(ctx), { member: "mem_member" }, memberInvocation(ctx, "owner", removalAction))).toEqual({ removed: true, member: "mem_member" })
      expect(open).not.toHaveBeenCalled()
      expect(removed).toHaveBeenCalledWith(expect.anything(),expect.objectContaining({id:privateItem.id}),"offboarded","mem_owner")
      removed.mockRestore()
      expect(ctx.sql.exec<{action:string}>("SELECT action FROM audit WHERE seq>? ORDER BY seq",beforeSeq).toArray()).toEqual([{action:"member.remove"}])
      expect(checkedCredential(ctx, privateItem.slug)).toBeNull()
      expect(ctx.sql.exec("SELECT * FROM item_secrets WHERE item=?", privateItem.id).toArray()).toEqual([])
      expect(checkedCredential(ctx, shared.slug)?.review?.reason).toBe("member left: member")
      expect(ctx.sql.exec<{ status: string }>("SELECT status FROM workspace_credential_requests WHERE id=?", request.intake).toArray()[0]?.status).toBe("cancelled")
      expect(ctx.sql.exec<{ revoked_at: number | null }>("SELECT revoked_at FROM devices WHERE id='dev_service'").toArray()[0]?.revoked_at).toBeNull()
      const snapshot = JSON.parse(ctx.sql.exec<{ snapshot: string }>("SELECT snapshot FROM removal_exposures").toArray()[0]!.snapshot) as OffboardingSnapshot
      expect(snapshot.by).toBe("mem_owner")
      expect(snapshot.privateItems).toContain(privateItem.id)
      expect(verifyAuditChain(ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray())).toEqual({ ok: true })
    })
  })

  it("rolls the real secrets, exposure snapshot, flags, requests and membership back on final audit failure", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "atomic-private", { kind: "member", member: "mem_member" })
      await seedCredential(ctx, "atomic-shared")
      createWorkspaceIntake(ctx, memberPrincipal(ctx, "member"), { provider: "openai", slug: "atomic-request", home: "private" }, memberInvocation(ctx, "member"))
    })
    const before = await accessSnapshot(f.tenant)
    await inAccess(f.tenant, async ctx => {
      const wrapped = { ...ctx, audit(event: Parameters<typeof ctx.audit>[0]) {
        if (event.action === "member.remove") throw new Error("final audit failed")
        ctx.audit(event)
      } }
      await expect(Promise.resolve().then(() => workspaceMemberOps["access.members.remove"]!.handler(wrapped, memberPrincipal(ctx), { member: "mem_member" }, memberInvocation(ctx, "owner", removalAction)))).rejects.toThrow("final audit failed")
    })
    expect(await accessSnapshot(f.tenant)).toBe(before)
  })

  it("deleting a real referenced credential clears variables and stales its pending approval before removing the item", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async ctx => {
      registerCredentialServices()
      const item = checkedCredential(ctx, "key-project")!
      let approval: string | undefined
      try {
        await authoriseWorkspaceRelay(ctx, devicePrincipal("dev_kim"), { item: item.slug, context: { project: "prj_a", environment: "prod" }, method: "GET", url: "https://api.example.com/test", headers: [] }, await deviceInvocation(ctx, "dev_kim"))
      } catch (error) {
        if (!(error instanceof VaultError) || error.code !== "approval_required") throw error
        approval = error.extra.approval
      }
      expect(approval).toBeTruthy()
      const open = vi.spyOn(ctx, "openField")
      const action = { type: "item.delete", item: item.id } as const
      await workspaceItemOps["items.delete"].handler(ctx, memberPrincipal(ctx), { slug: item.slug }, memberInvocation(ctx, "owner", action))
      expect(checkedCredential(ctx, item.slug)).toBeNull()
      expect(ctx.sql.exec<{ item: string | null; field: string | null }>("SELECT item,field FROM vars WHERE project='prj_a' AND env='prod'").toArray()[0]).toEqual({ item: null, field: null })
      expect(workspaceApproval(ctx, approval!)?.policy_status).toBe("stale")
      expect(open).not.toHaveBeenCalled()
      expect(canonicalJson(ctx.sql.exec("SELECT payload FROM notice_outbox").toArray())).toContain("reference_removed")
    })
  })
})

it("removes private credentials through TenantVault.invoke and records only member.remove", async () => {
  const { workspaceInvoke, accountAuth } = await import("./access-test-support.ts")
  const f = await credentialsFixture()
  const before = await inAccess(f.tenant, async ctx => {
    const item = await seedCredential(ctx, "dispatch-private-removal", { kind: "member", member: "mem_member" })
    const seq = ctx.sql.exec<{ seq: number }>("SELECT MAX(seq) AS seq FROM audit").toArray()[0]!.seq
    return { id: item.id, seq }
  })
  expect(await workspaceInvoke(f.tenant, "access.members.remove", { member: "mem_member" }, accountAuth("owner", removalAction))).toEqual({
    ok: true, value: { removed: true, member: "mem_member" },
  })
  await inAccess(f.tenant, ctx => {
    expect(checkedCredential(ctx, "dispatch-private-removal")).toBeNull()
    expect(ctx.sql.exec("SELECT * FROM item_secrets WHERE item=?", before.id).toArray()).toEqual([])
    expect(ctx.sql.exec<{ status: string }>("SELECT status FROM members WHERE id='mem_member'").toArray()[0]?.status).toBe("removed")
    expect(ctx.sql.exec<{ action: string }>("SELECT action FROM audit WHERE seq>? ORDER BY seq", before.seq).toArray()).toEqual([{ action: "member.remove" }])
    expect(verifyAuditChain(ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq").toArray())).toEqual({ ok: true })
  })
})
