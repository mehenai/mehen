import {registerWorkspacePendingProvider} from "./pending-workspace.ts"
import { can, reach, type AccessPrincipal } from "../access.ts"
import type { WorkspacePendingAsk } from "@mehen/protocol"
import { rows, type VaultContext } from "../core.ts"
import type { WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { credentialAccessState, checkedCredential } from "./items-workspace.ts"
import { requestHome, type CredentialRequest } from "./intake-workspace.ts"
import { devicePolicyState } from "./devices.ts"
import { askingWorkload } from "./workloads.ts"

export function credentialPending(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext): WorkspacePendingAsk[] {
  const state = credentialAccessState(ctx, invocation), now = ctx.now(), result: WorkspacePendingAsk[] = []
  const guest = principal.kind === "member" && state.members.find(member => member.id === principal.memberId)?.standing.effectiveRole === "guest"
  for (const row of rows(ctx.sql.exec<CredentialRequest>("SELECT * FROM workspace_credential_requests WHERE status='open' AND expires_at>? ORDER BY created_at,id", now))) {
    if (guest && principal.kind === "member" && row.requester_member !== principal.memberId) continue
    // A device's own key lists its workloads' asks too; a workload only its own.
    if (principal.kind === "device" && (row.requester_device !== principal.deviceId || principal.workload !== undefined && row.requester_workload !== principal.workload))
      continue
    const home = requestHome(row), item = checkedCredential(ctx, row.slug)
    const original=JSON.parse(row.payload) as {originalHome?:import("@mehen/protocol").CredentialHome;tags?:string[]}
    const originalVisible=original.originalHome?.kind!=="member"||can(state,principal,{type:"item.read"},{destinationHome:original.originalHome,prospectiveSlug:row.slug,prospectiveTags:item?.tags??original.tags??[]},now).allowed
    const visible = originalVisible && (row.target_id ? can(state, principal, { type: "item.read" }, { credential: row.target_id }, now).allowed : can(state, principal, { type: "item.read" }, { destinationHome: home, prospectiveSlug: row.slug, prospectiveTags: original.tags ?? [] }, now).allowed)
    const device = state.devices.find(d => d.id === row.requester_device)
    const owner = device ? reach(state, device, now).owner : { kind: "member" as const, member: row.requester_member ?? "", name: state.members.find(m => m.id === row.requester_member)?.name ?? "" }
    if (!visible) {
      // Owners/admins may stop a private ask, but cannot read its payload.
      const member = principal.kind === "member" ? state.members.find(m => m.id === principal.memberId) : null
      if (!device || !member || !["owner", "admin"].includes(member.standing.effectiveRole) || home.kind !== "member")
        continue
      result.push({ workspace: invocation.workspace, owner, view: "stop", stop: { view: "stop", id: row.id, workspace: invocation.workspace, machine: { device: device.id, name: devicePolicyState(ctx, device.id)?.name ?? device.id, owner }, item: { slug: row.slug }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } } })
      continue
    }
    const payload = JSON.parse(row.payload) as {
      provider?: string
      kind?: import("@mehen/protocol").ItemKind
      expect?: string | null
    }
    // createdAt for people only: a 0.2.0 CLI decodes a machine's asks strictly.
    result.push({ workspace: invocation.workspace, owner, view: "detail", detail: { kind: row.kind === "connect" ? "connect" : "intake", id: row.id, title: row.kind === "connect" ? `Connect ${row.slug}` : `Add ${row.slug}`, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/${row.kind === "connect" ? "c" : "i"}/${row.id}`, expiresAt: new Date(row.expires_at).toISOString(), requestedBy: row.requester_device ? { device: row.requester_device, deviceName: devicePolicyState(ctx, row.requester_device)?.name ?? row.requester_device, session: null, ...(principal.kind === "member" ? askingWorkload(ctx, row.requester_workload) : {}) } : { member: row.requester_member ?? "", self: principal.kind === "member" && principal.memberId === row.requester_member }, item: item?.slug ?? row.slug, provider: payload.provider ?? null, ...(payload.kind ? { kindRequested: payload.kind } : {}), ...(payload.expect ? { account: payload.expect } : {}), ...(principal.kind === "member" ? { createdAt: new Date(row.created_at).toISOString() } : {}) } })
  }
  if (principal.kind === "device" || guest)
    return result
  for (const { slug } of rows(ctx.sql.exec<{
    slug: string
  }>("SELECT slug FROM items WHERE status='needs_reauth' OR review_reason IS NOT NULL"))) {
    const item = checkedCredential(ctx, slug)
    if (!item || !can(state, principal, { type: "credential.update" }, { credential: item.id }, now).allowed)
      continue
    const owner = { kind: "member" as const, member: principal.memberId, name: state.members.find(m => m.id === principal.memberId)?.name ?? "" }
    result.push({ workspace: invocation.workspace, owner, view: "detail", detail: { kind: item.status === "needs_reauth" ? "reconnect" : "review", id: item.slug, title: `${item.status === "needs_reauth" ? "Reconnect" : "Review"} ${item.slug}`, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/items/${item.slug}`, expiresAt: null, requestedBy: null, item: item.slug } })
  }
  return result
}

registerWorkspacePendingProvider("credentials",credentialPending)
