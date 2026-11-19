import { afterEach, beforeEach, expect, it } from "vitest"
import { PrivateEventSchema } from "@mehen/protocol"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks } from "./access-test-support.ts"
import { credentialsFixture, inAccess, memberInvocation, memberPrincipal, seedCredential, state } from "./credentials-test-support.ts"
import { credentialAudit } from "../src/vault/areas/items-workspace.ts"
import { requestWorkspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { createCredentialRequest, requestAudit } from "../src/vault/areas/intake-workspace.ts"
import { workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import { onCredentialRemoved } from "../src/vault/areas/projects-workspace.ts"
import { auditLease } from "../src/vault/areas/runs-workspace.ts"
import { verifyAuditChain, type AuditRow } from "../src/vault/audit.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

const writers = ["credential", "approval.request", "approval.deny", "intake.current", "intake.original", "relay.echo", "run.lease", "project.references.remove"] as const

it.each(writers)("F9: %s records the private home's member in the owner index, not the actor", async writer => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async ctx => {
    const item = await seedCredential(ctx, "owner-index-key", { kind: "member", member: "mem_member" })
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
    const live = state(ctx), principal = memberPrincipal(ctx), invocation = memberInvocation(ctx)
    const ask = { device: "dev_member", credential: item.id, credentials: [item.id], context: null }
    let action: string
    if (writer === "credential") {
      credentialAudit(ctx, principal, item, "item.delete", "allowed")
      action = "item.delete"
    } else if (writer === "approval.request" || writer === "approval.deny") {
      const subject = { item: item.slug, method: "GET", url: "https://api.example.com/", contentType: null, contentEncoding: null, headersSha256: "headers", bodySha256: "body", constraints: { uses: 1, ttlSeconds: 600 } }
      const row = requestWorkspaceApproval(ctx, live, ask, invocation.workspace, subject, { title: "Private ask", details: [], body: null }, {}, ctx.now(), { floor: [], shape: "test-shape", replaces: null })
      action = writer
      if (writer === "approval.deny") await workspaceApprovalOps["approvals.decide"]!.handler(ctx, principal, { id: row.id, decision: "deny" }, memberInvocation(ctx, "owner", { type: "approval.decide", approval: row.id, digest: row.digest, decision: "deny", constraints: subject.constraints }))
    } else if (writer === "intake.current" || writer === "intake.original") {
      const row = createCredentialRequest(ctx, memberPrincipal(ctx, "member"), { kind: "intake", slug: "owner-index-ask", home: { kind: "member", member: "mem_member" }, tags: [], payload: {}, target: null }, memberInvocation(ctx, "member"))
      // The immutable home must win even if a later current home names somebody else.
      const current = writer === "intake.original" ? { ...row, home: JSON.stringify({ kind: "member", member: "mem_owner" }) } : row
      requestAudit(ctx, principal, current, "intake.cancel", invocation)
      action = "intake.cancel"
    } else if (writer === "relay.echo") {
      await workspaceRelayOps["relay.echo"]!.handler(ctx, { kind: "system" }, { items: [item.slug], host: "api.example.com", workspaceAudit: [{ item: { id: item.id, slug: item.slug, home: item.home }, device: "dev_member", owner: { kind: "member", member: "mem_member" }, session: null, run: null }] }, { auth: { kind: "system" }, workspace: invocation.workspace })
      action = "relay.echo"
    } else if (writer === "run.lease") {
      // Unit-test the real writer, not an impossible private variable reference.
      auditLease(ctx, live, "dev_member", item, "run_owner_index")
      action = "run.lease"
    } else {
      onCredentialRemoved(ctx, item, "deleted", "mem_owner")
      action = "project.references.remove"
    }
    const event = ctx.sql.exec<AuditRow>("SELECT * FROM audit WHERE action=? ORDER BY seq DESC LIMIT 1", action).toArray()[0]!
    expect(event).toBeDefined()
    expect(ctx.sql.exec<{ member: string }>("SELECT member FROM audit_private_owners WHERE seq=?", event.seq).toArray()).toEqual([{ member: "mem_member" }])
    expect(PrivateEventSchema.safeParse(JSON.parse(event.detail)).success).toBe(true)
    expect(verifyAuditChain([event], event.prev)).toEqual({ ok: true })
  })
})
