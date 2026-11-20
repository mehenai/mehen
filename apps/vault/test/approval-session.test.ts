// The agent's session label on a held request: `mehen fetch` sends it with
// the relay request (MEHEN_SESSION), and the approval page and Needs you
// show it, as an intake's page does.
import { expect, it } from "vitest"
import { base64UrlEncode, utf8, type ApprovalViewProjection } from "@mehen/protocol"
import { workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import { VaultError } from "../src/http.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { OPEN_ISSUE, seedGithub } from "./postures-test-support.ts"

it("a held fetch's approval shows the agent's session on its page and in Needs you, and none when it gave none", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    await seedGithub(ctx)
    const held = async (session?: string, title = "Flaky test") => {
      // As mehen fetch sends it: the label in the body and in the signed proof.
      const error = await authoriseWorkspaceRelay(ctx, devicePrincipal("dev_owner"), { item: "github-work", ...OPEN_ISSUE, body: base64UrlEncode(utf8(JSON.stringify({ title }))), ...(session !== undefined ? { session } : {}) }, await deviceInvocation(ctx, "dev_owner", session)).then(() => null, (e: unknown) => { if (e instanceof VaultError) return e; throw e })
      expect(error?.code).toBe("approval_required")
      return error?.extra.approval as string
    }
    const view = async (id: string) => ((await workspaceApprovalOps["approvals.view"]!.handler(ctx, memberPrincipal(ctx), { id }, memberInvocation(ctx))) as ApprovalViewProjection)
    const labelled = await held("e2e")
    const page = await view(labelled)
    expect(page.view === "detail" ? page.approval.requestedBy : null).toMatchObject({ device: "dev_owner", session: "e2e" })
    const inbox = (await workspacePendingOps["pending.inbox"]!.handler(ctx, memberPrincipal(ctx), { enrolments: [] }, memberInvocation(ctx))) as { items: { ask?: { view: string; detail?: { id: string; requestedBy?: { session?: string | null } } } }[] }
    const row = inbox.items.find((r) => r.ask?.view === "detail" && r.ask.detail?.id === labelled)
    expect(row?.ask?.detail?.requestedBy?.session).toBe("e2e")
    const unlabelled = await held(undefined, "Another issue")
    expect(unlabelled).not.toBe(labelled)
    const plain = await view(unlabelled)
    expect(plain.view === "detail" ? plain.approval.requestedBy : null).toMatchObject({ device: "dev_owner", session: null })
  })
})
