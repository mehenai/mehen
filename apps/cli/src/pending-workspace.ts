// Decode only the workspace projections a device may display. The calling
// identity comes from the enrolment, never from names or server-supplied links.
import { z } from "zod"
import { OwnerRefSchema, WorkspaceNoticePayloadSchema, WorkspaceRefSchema, type WorkspaceNoticePayload } from "@mehen/protocol"
import { KindSchema } from "@mehen/protocol/api"
import type { CallContext } from "./vault-api.ts"

const PendingDetail = z.strictObject({
  kind: z.enum(["intake", "connect", "approval", "policy", "adoption"]),
  id: z.string(), title: z.string(), url: z.string(), expiresAt: z.iso.datetime().nullable(),
  requestedBy: z.strictObject({ device: z.string(), deviceName: z.string(), session: z.string().nullable() }),
  item: z.string().nullable(), bindingCode: z.string().optional(), kindRequested: KindSchema.optional(),
  provider: z.string().nullable().optional(), account: z.string().nullable().optional(), items: z.number().int().nonnegative().optional(),
})
const PendingProjection = z.strictObject({ workspace: WorkspaceRefSchema, owner: OwnerRefSchema, view: z.literal("detail"), detail: PendingDetail })
const Notice = z.strictObject({ id: z.string().regex(/^ntc_[A-Za-z0-9_-]+$/), account: z.string(), payload: WorkspaceNoticePayloadSchema, at: z.number().int().nonnegative(), url: z.string() })
export type MachineAddedNotice = Omit<z.infer<typeof Notice>, "payload"> & { payload: Extract<WorkspaceNoticePayload, { kind: "machine_added" }> }

export function normaliseWorkspacePending(listed: readonly unknown[], context: CallContext): unknown[] {
  return listed.flatMap(value => {
    if (typeof value !== "object" || value === null || !("view" in value || "detail" in value || "stop" in value)) return [value]
    const projection = PendingProjection.safeParse(value)
    if (!projection.success || projection.data.workspace.id !== context.workspace?.id || projection.data.detail.requestedBy.device !== context.device) return []
    return [projection.data.detail]
  })
}

export function workspaceMachineNotices(raw: unknown, context: CallContext): { notices: MachineAddedNotice[]; refusedLinks: number } {
  const notices: MachineAddedNotice[] = []
  let refusedLinks = 0
  if (!Array.isArray(raw) || !context.workspace || !context.device) return { notices, refusedLinks }
  for (const value of raw) {
    const parsed = Notice.safeParse(value)
    if (!parsed.success) continue
    const { payload } = parsed.data
    if (payload.kind !== "machine_added" || payload.workspace.id !== context.workspace.id || payload.device !== context.device) continue
    const url = `${context.origin}/w/${context.workspace.slug}/devices/${context.device}`
    if (parsed.data.url !== url) refusedLinks++
    notices.push({ ...parsed.data, payload, url })
  }
  return { notices, refusedLinks }
}
