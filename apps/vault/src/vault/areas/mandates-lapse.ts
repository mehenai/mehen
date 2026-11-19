// Marks the live mandates a member signed, the one on a machine, or one
// mandate, lapsed (mandates-workspace.ts, lapsed_at), and tells its signer
// once per lapse (mandate_lapsed). Its own module, importing nothing from
// the areas that call it, so access.ts can call it for an identity rule
// change without an import cycle.
import type { MandateTerms } from "@mehen/protocol"
import type { VaultContext } from "../core.ts"
import { queueNotice, workspaceRef } from "./workspace-runtime.ts"

type LapsingRow = { id: string; device: string; signer_member: string; terms: string; expires_at: number; rev: number }

export function lapseMandates(ctx: VaultContext, of: { member: string } | { device: string } | { mandate: string }): void {
  const [column, id] = "member" in of ? ["signer_member", of.member] : "device" in of ? ["device", of.device] : ["id", of.mandate]
  const newly = ctx.sql.exec<LapsingRow>(`SELECT id,device,signer_member,terms,expires_at,rev FROM mandates WHERE ${column}=? AND state IN ('active','paused','tripped') AND lapsed_at IS NULL`, id).toArray()
  ctx.sql.exec(`UPDATE mandates SET lapsed_at=COALESCE(lapsed_at,?),rev=rev+1 WHERE ${column}=? AND state IN ('active','paused','tripped')`, ctx.now(), id)
  for (const row of newly) {
    const machine = ctx.sql.exec<{ name: string }>("SELECT name FROM devices WHERE id=?", row.device).toArray()[0]?.name ?? row.device
    const signer = ctx.sql.exec<{ name: string }>("SELECT name FROM members WHERE id=?", row.signer_member).toArray()[0]?.name ?? "someone who has left"
    const at = new Date(ctx.now()).toISOString()
    queueNotice(ctx, { kind: "mandate_lapsed", workspace: workspaceRef(ctx), mandate: row.id, device: row.device, machine, signer: { member: row.signer_member, name: signer }, classes: (JSON.parse(row.terms) as MandateTerms).classes, expiresAt: new Date(row.expires_at).toISOString(), at }, `${row.id}:lapsed:${row.rev}`)
  }
}
