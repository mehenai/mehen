import type { OwnerRef, WorkspacePendingAsk, WorkspaceRef } from "@mehen/protocol"

export function pendingWorkspaceFixtures(origin: string, workspace: WorkspaceRef, device: string, owner: OwnerRef) {
  const own: WorkspacePendingAsk = { workspace, owner, view: "detail", detail: { kind: "intake", id: "int_workspace", title: "Add workspace-key", url: `${origin}/w/${workspace.slug}/i/int_workspace`, expiresAt: "2030-01-01T00:00:00.000Z", requestedBy: { device, deviceName: "workspace-machine", session: null }, item: "workspace-key", provider: "openai", kindRequested: "api-key" } }
  const foreign = { ...own, workspace: { ...workspace, id: "tn_foreign0000001" } }
  // The same workspace, asked for by another device: never this machine's to show.
  const otherDevice: WorkspacePendingAsk = { ...own, detail: { ...own.detail, id: "int_other", requestedBy: { device: "dev_other0000001", deviceName: "workspace-machine", session: null } } }
  const stop: WorkspacePendingAsk = { workspace, owner, view: "stop", stop: { view: "stop", id: "int_stopped", workspace, machine: { device, name: "workspace-machine", owner }, item: { slug: "hidden" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } } }
  const unknown = { ...own, detail: { ...own.detail, kind: "unknown" } }
  const machine = { id: "ntc_workspace", account: "acc_test", payload: { kind: "machine_added", workspace, device, name: "workspace-machine", owner, place: null, at: "2026-10-27T18:00:00.000Z" }, at: 1793124000000, url: `${origin}/w/${workspace.slug}/devices/${device}` }
  return { own, foreign, otherDevice, stop, unknown, machine, pending: [own, foreign, otherDevice, stop, unknown] }
}
