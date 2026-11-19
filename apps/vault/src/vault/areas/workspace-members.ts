import { z } from "zod"
import { InviteTermsSchema, WorkspaceRoleSchema, canonicalJson, inviteMayActivate } from "@mehen/protocol"
import type { Area, VaultContext } from "../core.ts"
import { one } from "../core.ts"
import { VaultError } from "../../http.ts"
import { forgetCliVersions } from "./device-cli-versions.ts"
import { INVITE_TTL_MS } from "@mehen/protocol"
import { activateInvitedMember, pendingRoleOf, accessChanged, beforeManagementChange, inviteCreatorEligible, requireInviteIdentity, accessState, authorise, beforeOffboarding, bumpAccessRevision, digest, memberRows, queueNotice, requireStepUp, runOffboardingHooks, setSetting, setting, workspaceRef, WorkspaceInviteViewSchema } from "./workspace-runtime.ts"
import type { WorkspaceInvocationContext } from "./workspace-runtime.ts"
const ROLE_RANK = { owner: 3, admin: 2, member: 1, guest: 0 } as const
const MemberInput = z.strictObject({ member: z.string() })
function targetMember(ctx: VaultContext, id: string) {
  const member = memberRows(ctx).find((m) => m.id === id && m.status !== "removed")
  if (!member) throw new VaultError("not_found", "No such member.")
  return member
}
function actor(invocation: WorkspaceInvocationContext, member: string): string { return invocation.auth.kind === "account" ? `member:${member}` : "system" }
function ownerNotice(ctx: VaultContext, subject: ReturnType<typeof targetMember>, by: string, change: "added" | "promoted" | "reinstated" | "demoted" | "suspended" | "removed"): void {
  queueNotice(ctx, { kind: "owner_changed", workspace: workspaceRef(ctx), member: subject.id, name: subject.name, by, change, at: new Date(ctx.now()).toISOString() })
}
function memberView(ctx: VaultContext, id: string) {
  const m = targetMember(ctx, id)
  const state = accessState(ctx)
  return { member: m.id, name: m.name, role: m.role, pendingRole: pendingRoleOf(m,ctx.now()), status: m.status, teams: state.teams.filter((t) => t.members.includes(m.id)).map((t) => t.id), machines: state.devices.filter((d) => d.status === "active" && d.owner.kind === "member" && d.owner.id === m.id).length, joinedAt: new Date(m.joined_at).toISOString() }
}
function inviteView(ctx: VaultContext, id: string) {
  const row = one(ctx.sql.exec<{ id: string; terms: string; digest: string; status: string; creator: string; created_at: number }>("SELECT * FROM invites WHERE id=?", id))
  if (!row) throw new VaultError("not_found", "No such invite.")
  const terms = InviteTermsSchema.parse(JSON.parse(row.terms))
  return WorkspaceInviteViewSchema.parse({ id: row.id, terms, digest: row.digest, status: row.status === "open" && Date.parse(terms.expiresAt) <= ctx.now() ? "expired" : row.status, inviter: { member: row.creator, name: memberRows(ctx).find((m) => m.id === row.creator)?.name ?? "" }, boundEmail: terms.email, createdAt: new Date(row.created_at).toISOString(), expiresAt: terms.expiresAt })
}
function teamViews(ctx: VaultContext) {
  const state = accessState(ctx)
  return ctx.sql.exec<{ id: string; name: string; slug: string }>("SELECT id,name,slug FROM teams ORDER BY slug").toArray().map((t) => ({ ...t, members: state.teams.find((s) => s.id === t.id)?.members.map((id) => ({ member: id, name: state.members.find((m) => m.id === id)?.name ?? "", role: "member" as const })) ?? [], shares: state.shares.filter((s) => s.subject.kind === "team" && s.subject.team === t.id), machines: state.devices.filter((d) => d.status === "active" && d.owner.kind === "team" && d.owner.id === t.id).length }))
}
export const workspaceMemberOps: NonNullable<Area["workspaceOps"]> = {
  "access.teams.read": { auth: ["account"], handler(ctx, _p, _raw, invocation) { authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now()); return teamViews(ctx) } },
  "access.team.update": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ team: z.string().regex(/^tm_[A-Za-z0-9_-]{1,64}$/), change: z.enum(["create", "rename", "delete"]), name: z.string().min(1).max(64).nullable(), slug: z.string().regex(/^[a-z][a-z0-9-]{1,30}[a-z0-9]$/).nullable() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = authorise(ctx, invocation, { type: "team.update" }, { team: input.team }, ctx.now())
      requireStepUp(ctx, decision, { type: "team.update", ...input }, invocation)
      const state = accessState(ctx)
      const existing = state.teams.find((t) => t.id === input.team)
      if (input.change === "create" && existing) throw new VaultError("conflict", "name not available")
      if (input.change !== "create" && !existing) throw new VaultError("not_found", "No such available team.")
      if (input.slug && one(ctx.sql.exec("SELECT id FROM teams WHERE slug=? AND id!=?", input.slug, input.team))) throw new VaultError("conflict", "name not available")
      if (input.change !== "delete" && (!input.name || !input.slug)) throw new VaultError("bad_request", "A team needs a name and slug.")
      if (input.change === "delete" && state.devices.some((d) => d.status === "active" && d.owner.kind === "team" && d.owner.id === input.team)) throw new VaultError("conflict", "Revoke its machines first.")
      const by = decision.principal.kind === "member" ? decision.principal.memberId : "system"
      // A team made or renamed takes the guard too: its slug is unique, so a
      // REPLACE on it would delete another team.
      if (input.change === "create") { beforeManagementChange(ctx); ctx.sql.exec("INSERT INTO teams VALUES (?,?,?,?,?)", input.team, input.slug, input.name, by, ctx.now()) }
      else if (input.change === "rename") { beforeManagementChange(ctx); ctx.sql.exec("UPDATE teams SET name=?,slug=? WHERE id=?", input.name, input.slug, input.team) }
      else { accessChanged(ctx, null, "team.delete", { team: input.team }); ctx.sql.exec("DELETE FROM teams WHERE id=?", input.team); ctx.sql.exec("DELETE FROM team_members WHERE team=?", input.team); ctx.sql.exec("DELETE FROM project_shares WHERE subject_kind='team' AND subject_id=?", input.team) }
      bumpAccessRevision(ctx)
      ctx.audit({ actor: actor(invocation, by), action: `team.${input.change}`, target: input.team })
      return input.change === "delete" ? {} : teamViews(ctx).find((t) => t.id === input.team)
    })
  } },
  "access.team.members": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ team: z.string().regex(/^tm_[A-Za-z0-9_-]{1,64}$/), member: z.string(), change: z.enum(["add", "remove"]) }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = authorise(ctx, invocation, { type: "team.members" }, { team: input.team, member: input.member }, ctx.now())
      requireStepUp(ctx, decision, { type: "team.members", ...input }, invocation)
      const subject = targetMember(ctx, input.member)
      if (!accessState(ctx).teams.some((t) => t.id === input.team) || subject.status !== "active") throw new VaultError("not_found", "No such active team member.")
      if (input.change === "remove") { accessChanged(ctx, input.member, "team.remove", { team: input.team }); ctx.sql.exec("DELETE FROM team_members WHERE team=? AND member=?", input.team, input.member) }
      else { beforeManagementChange(ctx); ctx.sql.exec("INSERT OR IGNORE INTO team_members(team,member) VALUES (?,?)", input.team, input.member) }
      bumpAccessRevision(ctx)
      ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", action: `team.member_${input.change}`, target: input.team, detail: { member: input.member } })
      return teamViews(ctx).find((t) => t.id === input.team)
    })
  } },
  "access.members.action": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = MemberInput.extend({ change: z.enum(["confirm", "role", "suspend", "reinstate", "remove", "leave"]), role: WorkspaceRoleSchema.optional() }).parse(raw)
    if (["role", "suspend", "reinstate"].includes(input.change)) authorise(ctx, invocation, { type: `member.${input.change}` } as import("../access.ts").AccessAction, { member: input.member, role: input.role }, ctx.now())
    if (input.change === "confirm") authorise(ctx, invocation, { type: "member.invite" }, {}, ctx.now())
    if (input.change === "remove") authorise(ctx, invocation, { type: "member.remove" }, { member: input.member }, ctx.now())
    const subject = targetMember(ctx, input.member)
    if (input.change === "role" && !input.role) throw new VaultError("bad_request", "Choose the intended role.")
    authorise(ctx, invocation, { type: `member.${input.change}` } as import("../access.ts").AccessAction, { member: subject.id, role: input.role, ...(input.change === "confirm" ? { inviteTerms: InviteTermsSchema.parse(JSON.parse(one(ctx.sql.exec<{ terms: string }>("SELECT terms FROM invites WHERE member=?", subject.id))?.terms ?? "null")) } : {}) }, ctx.now())
    const invite = one(ctx.sql.exec<{ digest: string }>("SELECT digest FROM invites WHERE member=?", subject.id))
    const action = input.change === "role" ? { type: "member.role", member: subject.id, before: subject.role, after: input.role } : input.change === "confirm" ? { type: "member.confirm", member: subject.id, termsDigest: invite?.digest ?? "", identityRuleRevision: setting(ctx, "identity_rule_rev", 0) } : { type: `member.${input.change}`, member: subject.id }
    return { action }
  } },
  "access.invites.list": { auth: ["account"], handler(ctx, _p, _raw, invocation) { authorise(ctx, invocation, { type: "member.invite" }, {}, ctx.now()); return { invites: ctx.sql.exec<{ id: string }>("SELECT id FROM invites ORDER BY created_at,id").toArray().map((i) => inviteView(ctx, i.id)) } } },
  "access.members.list": { auth: ["account"], handler(ctx, _p, _raw, invocation) {
    authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now())
    const state = accessState(ctx)
    return memberRows(ctx).filter((m) => m.status !== "removed").map((m) => ({ member: m.id, name: m.name, role: m.role, pendingRole: pendingRoleOf(m,ctx.now()), status: m.status, teams: state.teams.filter((t) => t.members.includes(m.id)).map((t) => t.id), machines: state.devices.filter((d) => d.status === "active" && d.owner.kind === "member" && d.owner.id === m.id).length, joinedAt: new Date(m.joined_at).toISOString() }))
  } },
  "access.members.role": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = MemberInput.extend({ role: WorkspaceRoleSchema }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = authorise(ctx, invocation, { type: "member.role" }, { member: input.member, role: input.role }, ctx.now())
      const subject = targetMember(ctx, input.member)
      requireStepUp(ctx, decision, { type: "member.role", member: subject.id, before: subject.role, after: input.role }, invocation)
      const by = decision.principal.kind === "member" ? decision.principal.memberId : "system"
      const rule = setting<import("@mehen/protocol").IdentityRule>(ctx, "identity_rule", null)
      const pending = rule?.roles.includes(input.role) && ROLE_RANK[input.role] > ROLE_RANK[subject.role]
      if (subject.role === "owner" || input.role === "owner") ownerNotice(ctx, subject, by, input.role === "owner" ? "promoted" : "demoted")
      accessChanged(ctx, subject.id, "role", pending ? {} : { role: input.role })
      if (pending) ctx.sql.exec("UPDATE members SET pending_role=?,pending_since=?,pending_action=?,pending_by=?,gate_generation=gate_generation+1,revision=revision+1 WHERE id=?", input.role, ctx.now(), canonicalJson({ type: "member.role", member: subject.id, before: subject.role, after: input.role }), by, subject.id)
      else {
        ctx.sql.exec("UPDATE members SET role=?,pending_role=NULL,pending_since=NULL,pending_action=NULL,pending_by=NULL,revision=revision+1 WHERE id=?", input.role, subject.id)
        if (input.role === "guest") {
          ctx.sql.exec("DELETE FROM team_members WHERE member=?", subject.id)
          for (const share of accessState(ctx).shares.filter((s) => s.subject.kind === "member" && s.subject.member === subject.id && s.level === "manage")) ctx.sql.exec("UPDATE project_shares SET value=? WHERE id=?", canonicalJson({ ...share, level: "edit", protected: true }), share.id)
        }
      }
      ctx.audit({ actor: actor(invocation, by), action: "member.role", target: subject.id, detail: { before: subject.role, after: input.role, pending } })
      return memberView(ctx, subject.id)
    })
  } },
  ...Object.fromEntries((["suspend", "reinstate"] as const).map((change) => [`access.members.${change}`, { auth: ["account"] as ("account")[], handler(ctx: VaultContext, _p: import("./workspace-runtime.ts").WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext) {
    const input = MemberInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = authorise(ctx, invocation, { type: change === "suspend" ? "member.suspend" : "member.reinstate" }, { member: input.member }, ctx.now())
      const subject = targetMember(ctx, input.member)
      requireStepUp(ctx, decision, { type: change === "suspend" ? "member.suspend" : "member.reinstate", member: subject.id }, invocation)
      const by = decision.principal.kind === "member" ? decision.principal.memberId : "system"
      if (subject.role === "owner") ownerNotice(ctx, subject, by, change === "suspend" ? "suspended" : "reinstated")
      accessChanged(ctx, subject.id, change)
      ctx.sql.exec("UPDATE members SET status=?,revision=revision+1 WHERE id=?", change === "suspend" ? "suspended" : "active", subject.id)
      ctx.audit({ actor: actor(invocation, by), action: `member.${change}`, target: subject.id })
      return memberView(ctx, subject.id)
    })
  } }])),
  ...Object.fromEntries((["remove", "leave"] as const).map((change) => [`access.members.${change}`, { auth: ["account"] as ("account")[], handler(ctx: VaultContext, _p: import("./workspace-runtime.ts").WorkspaceRuntimePrincipal, raw: unknown, invocation: WorkspaceInvocationContext) {
    const input = MemberInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      if (change === "remove") authorise(ctx, invocation, { type: "member.remove" }, { member: input.member }, ctx.now())
      const subject = targetMember(ctx, input.member)
      const decision = authorise(ctx, invocation, { type: change === "remove" ? "member.remove" : "member.leave" }, { member: subject.id }, ctx.now())
      requireStepUp(ctx, decision, { type: change === "remove" ? "member.remove" : "member.leave", member: subject.id }, invocation)
      const snapshot = beforeOffboarding(ctx, subject.id)
      const by = decision.principal.kind === "member" ? decision.principal.memberId : "system"
      snapshot.by = by
      if (subject.role === "owner") ownerNotice(ctx, subject, by, "removed")
      ctx.sql.exec("INSERT INTO removal_exposures(removal,member,snapshot,at) VALUES (?,?,?,?)", snapshot.removal, subject.id, canonicalJson(snapshot), ctx.now())
      // Hooks see the pre-removal graph and must mutate their own resources.
      beforeManagementChange(ctx)
      runOffboardingHooks(ctx, snapshot)
      accessChanged(ctx, subject.id, change)
      ctx.sql.exec("UPDATE members SET status='removed',pending_role=NULL,pending_since=NULL,pending_action=NULL,pending_by=NULL,revision=revision+1 WHERE id=?", subject.id)
      ctx.sql.exec("DELETE FROM team_members WHERE member=?", subject.id)
      ctx.sql.exec("DELETE FROM project_shares WHERE subject_kind='member' AND subject_id=?", subject.id)
      ctx.sql.exec("UPDATE devices SET revoked_at=?,scope_rev=scope_rev+1 WHERE owner_kind='member' AND owner_id=? AND revoked_at IS NULL", ctx.now(), subject.id)
      ctx.sql.exec("UPDATE invites SET status='revoked' WHERE creator=? AND status IN ('open','pending_confirmation')", subject.id)
      for (const proposal of ctx.sql.exec<{ id: string; value: string }>("SELECT id,value FROM device_rescope_proposals").toArray()) { const value = JSON.parse(proposal.value) as import("@mehen/protocol").DeviceRescopeProposal; if (snapshot.devices.includes(value.device) && value.state === "open") ctx.sql.exec("UPDATE device_rescope_proposals SET value=? WHERE id=?", canonicalJson({ ...value, state: "void" }), proposal.id) }
      ctx.audit({ actor: actor(invocation, by), action: `member.${change}`, target: subject.id, detail: { devices: snapshot.devices.length, privateItems: snapshot.privateItems.length, exposedValues: new Set(snapshot.exposures.map((e) => `${e.item}:${e.version}`)).size } })
      forgetCliVersions(ctx, snapshot.devices)
      return { removed: true, member: subject.id }
    })
  } }])),
  "access.invites.create": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ invite: z.string().regex(/^inv_[A-Za-z0-9_-]{1,64}$/), codeHash: z.string().min(1), terms: InviteTermsSchema, reservation: z.strictObject({ expiresAt: z.iso.datetime() }) }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const decision = authorise(ctx, invocation, { type: "member.invite" }, { role: input.terms.role }, ctx.now())
      requireStepUp(ctx, decision, { type: "member.invite", terms: input.terms }, invocation)
      if (Date.parse(input.reservation.expiresAt) <= ctx.now()) throw new VaultError("conflict", "This invitation reservation expired.")
      const existing = one(ctx.sql.exec<{ code_hash: string; digest: string }>("SELECT code_hash,digest FROM invites WHERE id=?", input.invite))
      if (existing) { if (existing.code_hash !== input.codeHash || existing.digest !== digest(input.terms)) throw new VaultError("conflict", "This invitation reservation changed."); return { invite: inviteView(ctx, input.invite) } }
      const state = accessState(ctx)
      if (input.terms.teams.some((team) => !state.teams.some((t) => t.id === team)) || input.terms.shares.some((s) => !state.projects.some((p) => p.id === s.project))) throw new VaultError("not_found", "No such invitation subject.")
      if (Date.parse(input.terms.expiresAt) <= ctx.now() || Date.parse(input.terms.expiresAt) > ctx.now() + INVITE_TTL_MS) throw new VaultError("bad_request", "Invitations last at most seven days.")
      if (input.terms.onJoin === "activate" && !inviteMayActivate(input.terms)) throw new VaultError("bad_request", "Owner invitations and open links always wait for confirmation.")
      const id = input.invite
      const by = decision.principal.kind === "member" ? decision.principal.memberId : "system"
      ctx.sql.exec("INSERT INTO invites(id,code_hash,terms,digest,creator,created_at,status,creator_evidence) VALUES (?,?,?,?,?,?,'open',?)", id, input.codeHash, canonicalJson(input.terms), digest(input.terms), by, ctx.now(), invocation.auth.kind === "account" ? canonicalJson({ account: invocation.auth.account, session: invocation.auth.session, securityEpoch: invocation.auth.securityEpoch, sessionCheck: invocation.auth.sessionCheck }) : null)
      ctx.audit({ actor: actor(invocation, by), action: "member.invite", target: id, detail: { role: input.terms.role } })
      return { invite: inviteView(ctx, id) }
    })
  } },
  // Its maker's own email-bound invitation, its link just emailed to the
  // invited address (directory/invite-email.ts): the address, never the link.
  "access.invites.emailed": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ invite: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const row = one(ctx.sql.exec<{ creator: string; terms: string }>("SELECT creator,terms FROM invites WHERE id=?", input.invite))
      if (!row) throw new VaultError("not_found", "No such invite.")
      const terms = InviteTermsSchema.parse(JSON.parse(row.terms))
      const decision = authorise(ctx, invocation, { type: "member.invite" }, { role: terms.role }, ctx.now())
      const by = decision.principal.kind === "member" ? decision.principal.memberId : null
      if (terms.email === null || row.creator !== by) throw new VaultError("not_found", "No such invite.")
      ctx.audit({ actor: `member:${by}`, action: "invite.emailed", target: input.invite, detail: { email: terms.email } })
      return {}
    })
  } },
  "access.invites.revoke": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = z.strictObject({ invite: z.string() }).parse(raw)
    return ctx.storage.transactionSync(() => {
      const row = one(ctx.sql.exec<{ creator: string }>("SELECT creator FROM invites WHERE id=?", input.invite))
      if (!row) throw new VaultError("not_found", "No such invite.")
      const decision = authorise(ctx, invocation, { type: "invite.revoke" }, { creator: row.creator }, ctx.now())
      ctx.sql.exec("UPDATE invites SET status='revoked' WHERE id=?", input.invite)
      ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", action: "member.invite_revoked", target: input.invite })
      return {}
    })
  } },
  "access.members.confirm": { auth: ["account"], handler(ctx, _p, raw, invocation) {
    const input = MemberInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      authorise(ctx, invocation, { type: "member.invite" }, {}, ctx.now())
      const subject = targetMember(ctx, input.member)
      const invite = one(ctx.sql.exec<{ id: string; terms: string; digest: string; creator: string; creator_evidence: string | null; status: string }>("SELECT * FROM invites WHERE member=?", subject.id))
      if (subject.status !== "unconfirmed" || !invite || invite.status !== "pending_confirmation") throw new VaultError("conflict", "This membership cannot be confirmed.")
      const terms = InviteTermsSchema.parse(JSON.parse(invite.terms))
      const state = accessState(ctx)
      if (!inviteCreatorEligible(ctx, invite.creator, invite.creator_evidence, terms.role)) throw new VaultError("forbidden", "This invitation needs an eligible owner or admin to reissue it.")
      if (terms.teams.some((id) => !state.teams.some((t) => t.id === id)) || terms.shares.some((s) => !state.projects.some((p) => p.id === s.project)) || Date.parse(terms.expiresAt) <= ctx.now()) throw new VaultError("conflict", "The invitation terms changed.")
      const rule = setting<import("@mehen/protocol").IdentityRule>(ctx, "identity_rule", null)
      if (rule?.roles.includes(terms.role)) requireInviteIdentity(ctx, subject, invite.digest)
      const decision = authorise(ctx, invocation, { type: "member.confirm" }, { member: subject.id, inviteTerms: terms }, ctx.now())
      requireStepUp(ctx, decision, { type: "member.confirm", member: subject.id, termsDigest: invite.digest, identityRuleRevision: setting(ctx, "identity_rule_rev", 0) }, invocation)
      if (subject.role === "owner") ownerNotice(ctx, subject, decision.principal.kind === "member" ? decision.principal.memberId : "system", "added")
      activateInvitedMember(ctx, subject.id, invite.id, terms)
      bumpAccessRevision(ctx)
      ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", action: "member.confirm", target: subject.id })
      return memberView(ctx, subject.id)
    })
  } },
  "access.freeze": { auth: ["account", "device"], handler(ctx, _p, _raw, invocation) {
    return ctx.storage.transactionSync(() => { const decision = authorise(ctx, invocation, { type: "workspace.freeze" }, {}, ctx.now()); setSetting(ctx, "frozen", true); ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : decision.principal.kind === "device" ? `device:${decision.principal.deviceId}` : "system", action: "workspace.freeze", target: ctx.tenant }); return {} })
  } },
  "access.unfreeze": { auth: ["account"], handler(ctx, _p, _raw, invocation) {
    return ctx.storage.transactionSync(() => { const decision = authorise(ctx, invocation, { type: "workspace.unfreeze" }, {}, ctx.now()); requireStepUp(ctx, decision, { type: "workspace.unfreeze" }, invocation); setSetting(ctx, "frozen", false); ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", action: "workspace.unfreeze", target: ctx.tenant }); return {} })
  } },
}
