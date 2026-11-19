import { InviteCreateSchema,type InviteEmailed,WorkspaceMemberViewSchema,WorkspaceStepUpActionSchema,WorkspaceRoleSchema } from "@mehen/protocol"
import { z } from "zod"
import { accountRecoveryReadySql } from "../directory/account-recovery-setup.ts"
import { accountRecoverySetupRequired } from "../directory/workspace-recovery.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { reserveInviteRouting,finaliseInviteRouting } from "../directory/workspace-invite-routing.ts"
import { EMAIL_INVITES_UNAVAILABLE,emailInviteLink,emailInvitesCompletable } from "../directory/invite-email.ts"
import { WorkspaceInviteViewSchema } from "../vault/areas/workspace-runtime.ts"
import { json,VaultError } from "../http.ts"
import type { Route } from "../router.ts"
import { workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import { StepUpProofSchema } from "@mehen/protocol/step-up-proof"
import { accountBody } from "./account.ts"
const Proof = z.strictObject({ stepUp: StepUpProofSchema.optional() })
async function requireConfirmationRecoverySetup(rc: import("./context.ts").RequestContext,ws: import("./context.ts").WorkspaceRequest,member: string): Promise<void> {
  const ready = await rc.env.DB.prepare(`SELECT ${accountRecoveryReadySql("a.id")} AS ready FROM accounts a JOIN memberships m ON m.account=a.id WHERE m.id=? AND m.workspace=? AND m.state='member' AND a.status='active' AND a.security_transition IS NULL`).bind(member,ws.workspace.id).first<{ ready: number }>()
  if (!ready || ready.ready !== 1) throw accountRecoverySetupRequired(rc.env)
}
// The invitation is made whatever happens here: a send that is limited,
// refused or broken answers so, and the inviter copies the link instead. A
// sent link is recorded in the workspace's log; nothing else is.
async function emailNewInvite(rc: import("./context.ts").RequestContext,ws: import("./context.ts").WorkspaceRequest,invite: z.infer<typeof WorkspaceInviteViewSchema>,to: string,url: string): Promise<InviteEmailed> {
  let emailed: InviteEmailed
  try {
    emailed = await emailInviteLink(rc.env,{ to,inviterAccount: ws.account.account,workspace: ws.workspace,inviter: invite.inviter.name,role: invite.terms.role,url,expiresAt: invite.expiresAt })
  } catch {
    console.error(JSON.stringify({ at: "invite.email.send",error: "internal" }))
    return "failed"
  }
  if (emailed === "sent") {
    try { await workspaceCall(rc,ws,"access.invites.emailed",{ invite: invite.id }) } catch { console.error(JSON.stringify({ at: "invite.email.audit",workspace: ws.workspace.id,invite: invite.id })) }
  }
  return emailed
}
export const workspacePeopleRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET",path: "/members",handler: async (rc,ws) => json(z.array(WorkspaceMemberViewSchema).parse(await workspaceCall(rc,ws,"access.members.list",{}))) },
  { method: "GET",path: "/invites",handler: async (rc,ws) => json(z.strictObject({ invites: z.array(WorkspaceInviteViewSchema) }).parse(await workspaceCall(rc,ws,"access.invites.list",{}))) },
  { method: "POST",path: "/invites",handler: async (rc,ws) => {
    const { terms,email,stepUp } = await accountBody(rc,Proof.extend(InviteCreateSchema.shape))
    if (email && terms.email === null) throw new VaultError("bad_request","An open link names no email address, so it cannot be emailed.")
    if (terms.email !== null && !emailInvitesCompletable(rc.env)) throw new VaultError("bad_request",EMAIL_INVITES_UNAVAILABLE)
    const evidence = await requireWorkspaceStepUp(rc,ws,{ type: "member.invite",terms },stepUp)
    const reservation = await reserveInviteRouting(rc.env,ws.workspace,ws.account,terms)
    let result: { invite: z.infer<typeof WorkspaceInviteViewSchema> }
    try {
      result = z.strictObject({ invite: WorkspaceInviteViewSchema }).parse(await workspaceCall(rc,ws,"access.invites.create",{ invite: reservation.id,codeHash: reservation.codeHash,terms,reservation: { expiresAt: new Date(reservation.expiresAt).toISOString() } },evidence))
      if (result.invite.id !== reservation.id) throw new Error("Invite id changed")
      await finaliseInviteRouting(rc.env,reservation,result.invite.expiresAt)
    } catch (error) {
      if (error instanceof VaultError && ["forbidden","not_found","account_pending","identity_required","bad_request"].includes(error.code)) await rc.env.DB.prepare("DELETE FROM invite_codes WHERE code_hash=? AND state='pending'").bind(reservation.codeHash).run()
      throw error
    }
    const url = `${rc.env.VAULT_ORIGIN}/signup#${reservation.code}`
    const emailed = email && terms.email !== null ? await emailNewInvite(rc,ws,result.invite,terms.email,url) : "not_requested"
    return json({ ...result,url,emailed },201)
  } },
  { method: "POST",path: "/invites/:id/revoke",handler: async (rc,ws) => { await accountBody(rc,z.strictObject({})); const invite = rc.params.id ?? ""; await workspaceCall(rc,ws,"access.invites.revoke",{ invite }); await rc.env.DB.prepare("DELETE FROM invite_codes WHERE workspace=? AND invite=?").bind(ws.workspace.id,invite).run(); return json({}) } },
  { method: "POST",path: "/members/:id/action",handler: async (rc,ws) => { const input = await accountBody(rc,z.strictObject({ change: z.enum(["confirm","role","suspend","reinstate","remove","leave"]),role: WorkspaceRoleSchema.optional() })); return json(z.strictObject({ action: WorkspaceStepUpActionSchema }).parse(await workspaceCall(rc,ws,"access.members.action",{ member: rc.params.id ?? "",...input }))) } },
  ...(["confirm","role","suspend","reinstate","remove"] as const).map((change): Route<WorkspaceHandler> => ({ method: "POST",path: `/members/:id/${change}`,handler: async (rc,ws) => {
    const input = change === "role" ? await accountBody(rc,Proof.extend({ role: WorkspaceRoleSchema })) : await accountBody(rc,Proof)
    const member = rc.params.id ?? "",role = "role" in input ? input.role : undefined
    const { action } = z.strictObject({ action: WorkspaceStepUpActionSchema }).parse(await workspaceCall(rc,ws,"access.members.action",{ member,change,...(role ? { role } : {}) }))
    if (action.type !== `member.${change}`) throw new Error("Member preparation returned the wrong action")
    if (change === "confirm") await requireConfirmationRecoverySetup(rc,ws,member)
    const evidence = await requireWorkspaceStepUp(rc,ws,action,input.stepUp)
    if (change === "confirm") await requireConfirmationRecoverySetup(rc,ws,member)
    const result = await workspaceCall(rc,ws,`access.members.${change}`,{ member,...(role ? { role } : {}) },evidence)
    if (change === "remove") {
      const removed = z.strictObject({ removed: z.literal(true),member: z.string() }).parse(result)
      await rc.env.DB.prepare("UPDATE memberships SET state='left',updated_at=? WHERE id=? AND workspace=?").bind(Date.now(),removed.member,ws.workspace.id).run()
      return json(removed)
    }
    return json(WorkspaceMemberViewSchema.parse(result))
  } })),
  { method: "POST",path: "/leave",handler: async (rc,ws) => {
    const { stepUp } = await accountBody(rc,Proof),action = { type: "member.leave" as const,member: ws.membership },evidence = await requireWorkspaceStepUp(rc,ws,action,stepUp)
    const result = z.strictObject({ removed: z.literal(true),member: z.string() }).parse(await workspaceCall(rc,ws,"access.members.leave",{ member: ws.membership },evidence))
    await rc.env.DB.prepare("UPDATE memberships SET state='left',updated_at=? WHERE id=? AND account=? AND workspace=?").bind(Date.now(),ws.membership,ws.account.account,ws.workspace.id).run()
    return json(result)
  } },
]
