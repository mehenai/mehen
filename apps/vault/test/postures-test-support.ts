// Postures in direct-area tests (areas/postures-workspace.ts): a GitHub key
// whose policy holds every write, a posture set as the page sets it (the
// action built, then signed), and a relay from one machine.
import { base64UrlEncode, type CredentialHome, type Posture, type WorkspaceItemPosture, type WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { prepareCredential, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { workspacePostureOps } from "../src/vault/areas/postures-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { credentialInput, deviceInvocation, devicePrincipal, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"

export async function seedGithub(ctx: VaultContext, slug = "github-work", home: CredentialHome = { kind: "workspace" }) {
  const creator = home.kind === "member" ? home.member.slice(4) : "owner"
  const input = { ...credentialInput(slug, home), binding: { hosts: ["api.github.com"] }, policy: { default: "approve" as const, rules: [] } }
  const prepared = await prepareCredential(ctx, input, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx, creator), "item.create"))
}

export async function postureAction(ctx: VaultContext, role: string, slug: string, posture: Posture, rev: number): Promise<WorkspaceStepUpAction> {
  return await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx, role), { slug, action: "posture", posture, rev }, memberInvocation(ctx, role)) as WorkspaceStepUpAction
}
// Sets the posture as a page does: the action built from the revision shown, then signed.
export async function setPosture(ctx: VaultContext, role: string, slug: string, posture: Posture, rev = 0): Promise<WorkspaceItemPosture | undefined> {
  const action = await postureAction(ctx, role, slug, posture, rev)
  return await workspacePostureOps["items.posture"].handler(ctx, memberPrincipal(ctx, role), { slug, posture, rev }, memberInvocation(ctx, role, action))
}

const enc = (value: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)) as Uint8Array<ArrayBuffer>)
// Opens an issue: a routine entry of the GitHub catalogue.
export const OPEN_ISSUE = { method: "POST", url: "https://api.github.com/repos/acme/app/issues", headers: [["content-type", "application/json"]] as [string, string][], body: enc({ title: "Flaky test", body: "It fails on Tuesdays." }) }
// Deletes a comment: a destructive entry, which the floor holds.
export const DELETE_COMMENT = { method: "DELETE", url: "https://api.github.com/repos/acme/app/issues/comments/7", headers: [] as [string, string][] }
// A write nobody reviewed, in a standing rule's shape.
export const UNREVIEWED = { method: "POST", url: "https://api.github.com/repos/acme/app/labels", headers: [["content-type", "application/json"]] as [string, string][], body: enc({ name: "flaky" }) }

export type Relayed = { material: Awaited<ReturnType<typeof authoriseWorkspaceRelay>> | null; error: VaultError | null }
export async function relayAs(ctx: VaultContext, device: string, request: Record<string, unknown>, slug = "github-work"): Promise<Relayed> {
  try { return { material: await authoriseWorkspaceRelay(ctx, devicePrincipal(device), { item: slug, ...request }, await deviceInvocation(ctx, device)), error: null } }
  catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
}
export const postureRow = (ctx: VaultContext, slug = "github-work") => ctx.sql.exec<{ level: string; machines: string | null; catalogue: string | null; catalogue_version: number | null; rev: number; set_by: string }>("SELECT p.level,p.machines,p.catalogue,p.catalogue_version,p.rev,p.set_by FROM item_postures p JOIN items i ON i.id=p.item_id WHERE i.slug=?", slug).toArray()[0] ?? null
