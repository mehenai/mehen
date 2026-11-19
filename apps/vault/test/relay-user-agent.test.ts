import { afterEach, describe, expect, it } from "vitest"
import type { ApprovalSubject, WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { authoriseWorkspaceRelay, workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import type { ApprovalBundleCreated, ApprovalBundleStatus } from "@mehen/protocol/api"
import type { VaultContext } from "../src/vault/core.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"

afterEach(() => setUpstreamFetch(null))

const request = (headers: [string, string][]) => ({ item: "ua-key", method: "GET", url: "https://api.example.com/user", headers })

async function relay(ctx: VaultContext, input: ReturnType<typeof request> & { approval?: string }): Promise<string | null> {
  let sent: string | null = null
  setUpstreamFetch(async (upstream) => {
    sent = upstream.headers.get("user-agent")
    return new Response("ok")
  })
  const material = await authoriseWorkspaceRelay(ctx, devicePrincipal(), input, await deviceInvocation(ctx))
  expect(material.headers.some(([name]) => name.toLowerCase() === "user-agent")).toBe(input.headers.some(([name]) => name.toLowerCase() === "user-agent"))
  expect(await (await forwardRelay(material, null)).text()).toBe("ok")
  return sent
}

async function approvalFor(ctx: VaultContext, input: ReturnType<typeof request>): Promise<string> {
  try {
    await authoriseWorkspaceRelay(ctx, devicePrincipal(), input, await deviceInvocation(ctx))
  } catch (error) {
    if (error instanceof VaultError && error.code === "approval_required") return error.extra.approval as string
    throw error
  }
  throw new Error("Expected approval_required")
}

async function approve(ctx: VaultContext, id: string): Promise<void> {
  const row = workspaceApproval(ctx, id)
  if (!row) throw new Error("No such approval")
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }
  await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "member"), { id, decision: "approve" }, memberInvocation(ctx, "member", action))
}

describe("the relay's upstream User-Agent", () => {
  it("is mehen-relay when the agent sent none, and the agent's own when it sent one", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "ua-key")
      expect(await relay(ctx, request([]))).toBe("mehen-relay")
      expect(await relay(ctx, request([["User-Agent", "my-agent/1.0"]]))).toBe("my-agent/1.0")
    })
  })

  it("is added after the approval digest, so an approved request still matches and the human never sees it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "ua-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='ua-key'", JSON.stringify({ default: "approve", rules: [] }))
      const id = await approvalFor(ctx, request([]))
      expect(workspaceApproval(ctx, id)!.presentation).not.toContain("mehen-relay")
      await approve(ctx, id)
      expect(await relay(ctx, { ...request([]), approval: id })).toBe("mehen-relay")
      const allowed = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='relay.allow'").toArray()
      expect(allowed).toHaveLength(1)
      expect(allowed[0]!.detail).not.toContain("mehen-relay")
    })
  })

  it("is mehen-relay when the identical later request spends an ask its bundle planned, with or without the approval", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "ua-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='ua-key'", JSON.stringify({ default: "approve", rules: [] }))
      const op = async <T>(name: string, input: unknown) => await workspaceRelayOps[name]!.handler(ctx, devicePrincipal(), input, await deviceInvocation(ctx)) as T
      for (const named of [true, false]) {
        const planned = await op<ApprovalBundleCreated>("approvals.bundle", { requests: [request([])] })
        const id = planned.results[0]!.approval!
        expect(planned.results).toEqual([{ index: 0, outcome: "ask", approval: id, bindingCode: workspaceApproval(ctx, id)!.binding_code, mandateCover: { classes: ["read"], state: "none", mandate: null, url: null } }])
        await approve(ctx, id)
        expect(await op<ApprovalBundleStatus>("approvals.bundle_status", { id: planned.bundle })).toEqual({ bundle: planned.bundle, approvals: [{ id, status: "approved" }] })
        // A second plan of the same bytes finds the grant and asks nothing.
        expect((await op<ApprovalBundleCreated>("approvals.bundle", { requests: [request([])] })).results).toEqual([{ index: 0, outcome: "allowed", approval: id }])
        expect(await relay(ctx, named ? { ...request([]), approval: id } : request([]))).toBe("mehen-relay")
        expect(await op<ApprovalBundleStatus>("approvals.bundle_status", { id: planned.bundle })).toEqual({ bundle: planned.bundle, approvals: [{ id, status: "used" }] })
      }
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='relay.allow'").toArray()).toHaveLength(2)
    })
  })
})
