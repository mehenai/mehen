import { PENDING_RESTRICTION_UNTIL, AccountRestrictionSchema, WorkspaceNoticePayloadSchema, type WorkspaceNoticePayload } from "@mehen/protocol"
import { z } from "zod"
import { OutboxEventSchema,registerNoticeDelivery,type OutboxEvent } from "../vault/areas/workspace-runtime.ts"
import type { Env } from "../env.ts"
import { accountBatch, accountGuard } from "./account-store.ts"
import { directoryWorkspaceClient, type DirectoryWorkspaceClient, type WorkspaceOutboxClient } from "./workspace-client.ts"

const Targets = z.array(z.string())
type EventRow = { id: string; account: string; at: number; action: string; detail: string; targets: string; mirrored_to: string; attempts: number }
export async function mirrorAccountEvents(env: Env,client: DirectoryWorkspaceClient = directoryWorkspaceClient(env),now = Date.now(),eventId: string | null = null): Promise<void> {
  const events = await env.DB.prepare(`SELECT * FROM account_events e WHERE EXISTS (SELECT 1 FROM json_each(e.targets) target
    WHERE NOT EXISTS (SELECT 1 FROM json_each(e.mirrored_to) done WHERE done.value=target.value)) AND (e.next_retry_at IS NULL OR e.next_retry_at<=?) AND (? IS NULL OR e.id=?) ORDER BY COALESCE(next_retry_at,0),at,id LIMIT 100`).bind(now,eventId,eventId).all<EventRow>()
  for (const event of events.results) {
    const claimed = await env.DB.prepare("UPDATE account_events SET attempts=attempts+1,next_retry_at=? WHERE id=? AND attempts=? AND (next_retry_at IS NULL OR next_retry_at<=?)").bind(now+60000,event.id,event.attempts,now).run()
    if (claimed.meta.changes !== 1) continue
    const targets = Targets.parse(JSON.parse(event.targets)),done = Targets.parse(JSON.parse(event.mirrored_to))
    const detail = z.record(z.string(),z.unknown()).parse(JSON.parse(event.detail))
    for (const workspace of targets) {
      if (done.includes(workspace)) continue
      try {
        if (event.action === "account.signout") await client.revokeSession(workspace,{ account: event.account,session: z.string().parse(detail.session) })
        if (event.action === "account.security" || event.action === "account.recovery_keep") {
          const epoch = z.number().int().nonnegative().parse(detail.epoch)
          const current = await env.DB.prepare("SELECT security_epoch,restricted_until,restricted_reason FROM accounts WHERE id=?").bind(event.account).first<{ security_epoch: number; restricted_until: number | null; restricted_reason: string | null }>()
          if (current?.security_epoch === epoch) {
            const recorded = AccountRestrictionSchema.nullable().parse(detail.restriction)
            const restriction = current.restricted_until === null ? null : recorded
            if (restriction === null && current.restricted_until === null || restriction?.until === current.restricted_until && restriction?.reason === current.restricted_reason) await client.restriction(workspace,{ account: event.account,committedEpoch: epoch,restriction })
          }
        }
        await client.mirror(workspace,{ id: event.id,account: event.account,at: event.at,action: event.action,detail })
        await env.DB.prepare(`UPDATE account_events SET mirrored_to=json_insert(mirrored_to,'$[#]',?) WHERE id=?
          AND NOT EXISTS (SELECT 1 FROM json_each(mirrored_to) WHERE value=?)`).bind(workspace,event.id,workspace).run()
      } catch { console.error(JSON.stringify({ at: "account.event.mirror_pending",event: event.id,workspace })) }
    }
  }
}
export type WorkspaceNoticeDelivery = { id: string; workspace: string; recipients: string[]; payload: WorkspaceNoticePayload }
const Delivery = z.strictObject({ id: z.string().min(1),workspace: z.string(),recipients: z.array(z.string()).min(1),payload: WorkspaceNoticePayloadSchema })
// One unique source key per recipient, not per notice. Removed recipients are
// retained by the source DO snapshot; no D1 role hint can add a recipient.
export async function deliverWorkspaceNotice(env: Env,delivery: WorkspaceNoticeDelivery): Promise<void> {
  const notice = Delivery.parse(delivery)
  if (notice.workspace !== notice.payload.workspace.id) throw new Error("Notice workspace mismatch")
  const statements: D1PreparedStatement[] = []
  for (const account of new Set(notice.recipients)) {
    const source = JSON.stringify([notice.workspace,notice.id,account])
    statements.push(accountGuard(env,"EXISTS (SELECT 1 FROM accounts WHERE id=?)",[account]))
    statements.push(env.DB.prepare(`INSERT INTO account_notices(id,account,kind,source_workspace,source_notice,payload,at)
      VALUES (?,?,'workspace',?,?,?,?) ON CONFLICT(source_notice) DO NOTHING`)
      .bind(`ntc_${await crypto.subtle.digest("SHA-256",new TextEncoder().encode(source)).then(b => Array.from(new Uint8Array(b),v => v.toString(16).padStart(2,"0")).join(""))}`,account,notice.workspace,source,JSON.stringify(notice.payload),Date.parse(notice.payload.at)))
  }
  await accountBatch(env,statements)
}
export async function ownAccountEvents(env: Env,account: string,before = Date.now()+1): Promise<{ id: string; at: string; action: string; detail: Record<string,unknown> }[]> {
  const rows = await env.DB.prepare("SELECT id,at,action,detail FROM account_events WHERE account=? AND at<? ORDER BY at DESC,id DESC LIMIT 100").bind(account,before).all<{ id: string; at: number; action: string; detail: string }>()
  return rows.results.map(row => ({ id: row.id,at: new Date(row.at).toISOString(),action: row.action,detail: z.record(z.string(),z.unknown()).parse(JSON.parse(row.detail)) }))
}
export async function ownAccountNotices(env: Env,account: string): Promise<unknown[]> {
  const rows = await env.DB.prepare("SELECT id,kind,payload,at,client,place,restricted_until,resolved_at,outcome FROM account_notices WHERE account=? ORDER BY at DESC,id DESC LIMIT 100").bind(account).all<{ id: string; kind: string; payload: string; at: number; client: string | null; place: string | null; restricted_until: number | null; resolved_at: number | null; outcome: string | null }>()
  return rows.results.map(row => ({ notice: row.id,kind: row.kind,payload: JSON.parse(row.payload) as unknown,at: new Date(row.at).toISOString(),client: row.client,place: row.place,restrictedUntil: row.restricted_until === null || row.restricted_until >= PENDING_RESTRICTION_UNTIL ? null : new Date(row.restricted_until).toISOString(),resolvedAt: row.resolved_at === null ? null : new Date(row.resolved_at).toISOString(),outcome: row.outcome }))
}

export async function drainWorkspaceNotices(env: Env,client: WorkspaceOutboxClient = directoryWorkspaceClient(env),now = Date.now()): Promise<void> {
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM workspaces WHERE status!='deleted'").first<{ n: number }>()
  const offset = (Math.floor(now / 900000) % Math.max(1, Math.ceil((count?.n ?? 0) / 100))) * 100
  const workspaces = await env.DB.prepare("SELECT id FROM workspaces WHERE status!='deleted' ORDER BY id LIMIT 100 OFFSET ?").bind(offset).all<{ id: string }>()
  for (const workspace of workspaces.results) {
    try {
      const { events } = await client.drain(workspace.id,100)
      if (events.some(event => event.payload.workspace.id !== workspace.id)) throw new Error("Notice workspace mismatch")
      const written = await writeWorkspaceNotices(env,events)
      if (written.length) await client.ack(workspace.id,written)
    } catch { console.error(JSON.stringify({ at: "workspace.notice.pending",workspace: workspace.id })) }
  }
}

export async function writeWorkspaceNotices(env: Env,events: OutboxEvent[]): Promise<string[]> {
  const written: string[] = []
  for (const raw of events) {
    try {
      const event = OutboxEventSchema.parse(raw)
      // Nothing can be written for an account that no longer exists: counted
      // as written, so its source stops retrying it.
      const recipient = await env.DB.prepare("SELECT status FROM accounts WHERE id=?").bind(event.account).first<{ status: string }>()
      if (recipient === null || recipient.status === "deleted") {
        console.info(JSON.stringify({ at: "workspace.notice.recipient_gone",notice: event.id }))
        written.push(event.id)
        continue
      }
      await deliverWorkspaceNotice(env,{ id: event.id,workspace: event.payload.workspace.id,recipients: [event.account],payload: event.payload })
      written.push(event.id)
    } catch { console.error(JSON.stringify({ at: "workspace.notice.write_pending",notice: raw.id })) }
  }
  return written
}
registerNoticeDelivery(writeWorkspaceNotices)
