import type { WorkspaceNoticePayload } from "@mehen/protocol"

type Context = { origin: string; workspace: { id: string; slug: string; name: string } | null; device: string | null }
export type PendingFixturePort = {
  normaliseWorkspacePending(listed: readonly unknown[], context: Context): unknown[]
  workspaceMachineNotices(raw: unknown, context: Context): { notices: { id: string; account: string; at: number; url: string; payload: Extract<WorkspaceNoticePayload, { kind: "machine_added" }> }[]; refusedLinks: number }
}
