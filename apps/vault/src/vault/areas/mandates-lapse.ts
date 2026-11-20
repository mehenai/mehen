// Marks the live mandates a member signed, or each member of a team
// signed, the one on a machine, or one mandate, lapsed (mandates-workspace.ts, lapsed_at), and tells its signer
// once per lapse (mandate_lapsed), with an audit row saying why. Its own module, importing only
// workspace-runtime.ts, so access.ts can call it for an identity rule change
// and workspace-runtime.ts for an identity invalidation, each at call time.
import type { MandateTerms } from "@mehen/protocol"
import type { VaultContext } from "../core.ts"
import { queueNotice, workspaceRef } from "./workspace-runtime.ts"

type LapsingRow = { id: string; device: string; signer_member: string; terms: string; expires_at: number; rev: number }
// What lapsed it, for the audit (mandate.lapse): a change to the signer's
// membership, role or account security, their identity check, the machine
// rescoped wider, or management of a credential's home taken away.
export type MandateLapseCause = "role" | "suspend" | "remove" | "leave" | "security" | "identity_rule" | "identity_invalidated" | "rescope" | "share" | "team" | "rehome"

export function lapseMandates(ctx: VaultContext, of: { member: string } | { team: string } | { device: string } | { mandate: string }, cause: MandateLapseCause): void {
  if ("team" in of) {
    for (const { member } of ctx.sql.exec<{ member: string }>("SELECT member FROM team_members WHERE team=?", of.team).toArray()) lapseMandates(ctx, { member }, cause)
    return
  }
  const [column, id] = "member" in of ? ["signer_member", of.member] : "device" in of ? ["device", of.device] : ["id", of.mandate]
  const newly = ctx.sql.exec<LapsingRow>(`SELECT id,device,signer_member,terms,expires_at,rev FROM mandates WHERE ${column}=? AND state IN ('active','paused','tripped') AND lapsed_at IS NULL`, id).toArray()
  // The revision stays: a machine reads it, and an active mandate's moving
  // alone would tell it its signer's standing changed.
  ctx.sql.exec(`UPDATE mandates SET lapsed_at=? WHERE ${column}=? AND state IN ('active','paused','tripped') AND lapsed_at IS NULL`, ctx.now(), id)
  for (const row of newly) {
    const machine = ctx.sql.exec<{ name: string }>("SELECT name FROM devices WHERE id=?", row.device).toArray()[0]?.name ?? row.device
    const signer = ctx.sql.exec<{ name: string }>("SELECT name FROM members WHERE id=?", row.signer_member).toArray()[0]?.name ?? "someone who has left"
    const at = new Date(ctx.now()).toISOString()
    ctx.audit({ actor: "system", action: "mandate.lapse", target: row.id, detail: { device: row.device, cause } })
    queueNotice(ctx, { kind: "mandate_lapsed", workspace: workspaceRef(ctx), mandate: row.id, device: row.device, machine, signer: { member: row.signer_member, name: signer }, classes: (JSON.parse(row.terms) as MandateTerms).classes, expiresAt: new Date(row.expires_at).toISOString(), at }, `${row.id}:lapsed:${row.rev}`)
  }
}
