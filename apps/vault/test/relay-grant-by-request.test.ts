import { afterEach, describe, expect, it } from "vitest"
import type { ApprovalSubject, WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { workspaceApproval, workspaceApprovalOps, workspaceApprovalStatus } from "../src/vault/areas/approvals-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"

afterEach(() => setUpstreamFetch(null))

const request = (url = "https://api.example.com/gateways") => ({ item: "grant-key", method: "GET", url, headers: [] as [string, string][] })

async function relay(ctx: VaultContext, input: ReturnType<typeof request> & { approval?: string }): Promise<{ sent: true } | { approval: string }> {
  try {
    await authoriseWorkspaceRelay(ctx, devicePrincipal(), input, await deviceInvocation(ctx))
    return { sent: true }
  } catch (error) {
    if (error instanceof VaultError && error.code === "approval_required") return { approval: error.extra.approval as string }
    throw error
  }
}

async function approve(ctx: VaultContext, id: string): Promise<void> {
  const row = workspaceApproval(ctx, id)
  if (!row) throw new Error("No such approval")
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }
  await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "member"), { id, decision: "approve" }, memberInvocation(ctx, "member", action))
}

const usesLeft = (ctx: VaultContext, id: string) => ctx.sql.exec<{ uses_left: number | null }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", id).toArray()[0]?.uses_left
const approvals = (ctx: VaultContext) => ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM approvals").toArray()[0]!.n
const status = (ctx: VaultContext, id: string) => workspaceApprovalStatus(ctx, workspaceApproval(ctx, id)!)

async function held(ctx: VaultContext): Promise<void> {
  await seedCredential(ctx, "grant-key")
  ctx.sql.exec("UPDATE items SET policy=? WHERE slug='grant-key'", JSON.stringify({ default: "approve", rules: [] }))
}

describe("a grant is found by the request itself", () => {
  it("spends the approved grant when the same request comes back without the approval id", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const asked = await relay(ctx, request())
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      await approve(ctx, asked.approval)
      const before = approvals(ctx)
      expect(await relay(ctx, request())).toEqual({ sent: true })
      expect(approvals(ctx)).toBe(before)
      expect(usesLeft(ctx, asked.approval)).toBe(0)
      expect(status(ctx, asked.approval)).toBe("used")
      const again = await relay(ctx, request())
      expect(again).toMatchObject({ approval: expect.any(String) })
      expect(again).not.toEqual({ approval: asked.approval })
    })
  })

  it("never spends it on a different request, nor while it is undecided", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const asked = await relay(ctx, request())
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      expect(await relay(ctx, request())).toEqual({ approval: asked.approval })
      await approve(ctx, asked.approval)
      const other = await relay(ctx, request("https://api.example.com/other"))
      expect(other).not.toEqual({ approval: asked.approval })
      expect("approval" in other).toBe(true)
      expect(usesLeft(ctx, asked.approval)).toBe(1)
    })
  })
})

describe("an approval's status after its hour", () => {
  it("reads used once spent and expired with approvedAt when given but unused", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const spent = await relay(ctx, request())
      const unused = await relay(ctx, request("https://api.example.com/unused"))
      if (!("approval" in spent) || !("approval" in unused)) throw new Error("Expected approval_required")
      await approve(ctx, spent.approval)
      await approve(ctx, unused.approval)
      expect(await relay(ctx, { ...request(), approval: spent.approval })).toEqual({ sent: true })
      ctx.sql.exec("UPDATE approvals SET expires_at=? WHERE id IN (?,?)", ctx.now() - 1, spent.approval, unused.approval)
      expect(status(ctx, spent.approval)).toBe("used")
      expect(status(ctx, unused.approval)).toBe("expired")
      const read = await workspaceApprovalOps["approvals.status"]!.handler(ctx, devicePrincipal(), { id: unused.approval }, await deviceInvocation(ctx))
      expect(read).toMatchObject({ status: "expired", approvedAt: expect.any(String) })
    })
  })
})
