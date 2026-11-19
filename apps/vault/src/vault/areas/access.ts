// Workspace-local authority, security epochs and durable reverse notices.
import { z } from "zod"
import { PENDING_RESTRICTION_UNTIL, EnrolEvidenceSchema, OwnerRefSchema, EnrolStartContextSchema, EnrolOwnerIntentSchema, IdentityRuleSchema, InviteTermsSchema, WorkspaceDeviceScopeSchema, WorkspaceRefSchema, canonicalJson, inviteJoinsStraightAway } from "@mehen/protocol"
import type { Area, VaultContext } from "../core.ts"
import { one, randomId } from "../core.ts"
import { VaultError } from "../../http.ts"
import { lapseMandates } from "./mandates-lapse.ts"
import { activateInvitedMember, pendingRoleOf, accessState, authorise, bumpAccessRevision, digest, drainOutbox, installSecurity, memberRows, newMember, observeCommittedEpoch, OutboxDrainInput, OutboxDrainOutput, requireStepUp, SecurityCommitInput, SecurityInstallInput, SecurityOutput, SecurityRestrictionInput, updateRestriction, revokeSession, setSetting, setting, workspaceRef, queueNotice, EnrolRegisterInput, PendingEnrolSchema, readStoredEnrol, enrolRecord, deliverNoticeOutbox, IdentityInstallInput, installIdentity, requireOperationIdentity, inviteCreatorEligible } from "./workspace-runtime.ts"

export const ACCESS_MIGRATIONS = [
  `CREATE TABLE members(id TEXT PRIMARY KEY,account TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','admin','member','guest')),pending_role TEXT,pending_since INTEGER,status TEXT NOT NULL,gate_generation INTEGER NOT NULL DEFAULT 0,joined_at INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1,invite TEXT);
   CREATE UNIQUE INDEX members_live_account ON members(account) WHERE status!='removed';
   CREATE TABLE account_security(account TEXT PRIMARY KEY,state TEXT NOT NULL);
   CREATE TABLE teams(id TEXT PRIMARY KEY,slug TEXT NOT NULL UNIQUE,name TEXT NOT NULL,created_by TEXT NOT NULL,created_at INTEGER NOT NULL);
   CREATE TABLE team_members(team TEXT NOT NULL,member TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'member' CHECK(role='member'),PRIMARY KEY(team,member));
   CREATE TABLE project_shares(id TEXT PRIMARY KEY,project TEXT NOT NULL,subject_kind TEXT NOT NULL,subject_id TEXT NOT NULL,value TEXT NOT NULL,UNIQUE(project,subject_kind,subject_id));
   CREATE TABLE invites(id TEXT PRIMARY KEY,code_hash TEXT NOT NULL UNIQUE,terms TEXT NOT NULL,digest TEXT NOT NULL,creator TEXT NOT NULL,created_at INTEGER NOT NULL,status TEXT NOT NULL,used_by TEXT,member TEXT);
   CREATE TABLE notice_outbox(id TEXT PRIMARY KEY,account TEXT NOT NULL,payload TEXT NOT NULL,created_at INTEGER NOT NULL,next_retry_at INTEGER NOT NULL,acknowledged_at INTEGER);
   CREATE INDEX notice_outbox_due ON notice_outbox(acknowledged_at,next_retry_at);
   CREATE TABLE exposures(event TEXT NOT NULL,item TEXT NOT NULL,version INTEGER NOT NULL,member TEXT,device TEXT,source TEXT NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(event,item,version,source));
   CREATE INDEX exposures_member ON exposures(member,item,version);
   CREATE TABLE removal_exposures(removal TEXT PRIMARY KEY,member TEXT NOT NULL,snapshot TEXT NOT NULL,at INTEGER NOT NULL);
   CREATE TABLE name_miss_buckets(subject TEXT PRIMARY KEY,window_start INTEGER NOT NULL,count INTEGER NOT NULL);
   CREATE TABLE device_rescope_proposals(id TEXT PRIMARY KEY,device TEXT NOT NULL,value TEXT NOT NULL);
   CREATE INDEX device_rescope_device ON device_rescope_proposals(device);
   CREATE TABLE mirrored_account_events(id TEXT PRIMARY KEY);
   CREATE TABLE workspace_enrolments(id TEXT PRIMARY KEY,thumbprint TEXT NOT NULL,value TEXT NOT NULL);
   CREATE UNIQUE INDEX workspace_enrolments_key ON workspace_enrolments(thumbprint);`,
  `CREATE TABLE workspace_enrol_mirrors(enrolment TEXT PRIMARY KEY,device TEXT NOT NULL UNIQUE);`,
  `ALTER TABLE notice_outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;`,
  `ALTER TABLE members ADD COLUMN check_sequence INTEGER NOT NULL DEFAULT 0;
   ALTER TABLE members ADD COLUMN pending_action TEXT;
   CREATE TABLE workspace_identity_checks(member TEXT NOT NULL,session TEXT NOT NULL,security_epoch INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(member,session));`,
  `ALTER TABLE invites ADD COLUMN creator_evidence TEXT;
   ALTER TABLE workspace_identity_checks ADD COLUMN operation_check TEXT;
   ALTER TABLE workspace_identity_checks ADD COLUMN purpose TEXT NOT NULL DEFAULT 'session';`,
  `CREATE TABLE workspace_rescope_identity(proposal TEXT NOT NULL,account TEXT NOT NULL,rule_rev INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(proposal,account));`,
  `ALTER TABLE members ADD COLUMN pending_by TEXT;`,
  // One key, many attempts: a superseded attempt's copy stays as history,
  // its terms and evidence untouched, while the same key's next attempt
  // registers beside it. One live machine per key stays finishEnrol's rule.
  `DROP INDEX workspace_enrolments_key;
   CREATE INDEX workspace_enrolments_thumbprint ON workspace_enrolments(thumbprint);`,
]
export const AccessInitInput = z.strictObject({ member: z.string().regex(/^mem_[A-Za-z0-9_-]{1,64}$/), workspace: z.string(), slug: WorkspaceRefSchema.shape.slug, name: WorkspaceRefSchema.shape.name, owner: z.strictObject({ account: z.string(), name: z.string().min(1).max(64) }) })
export const AccessInitOutput = z.strictObject({ member: z.string() })
const IdInput = z.strictObject({ codeHash: z.string().min(1).max(256) })
export const InviteTermsViewSchema = z.strictObject({ id: z.string(), workspace: WorkspaceRefSchema, inviter: z.strictObject({ name: z.string() }), role: InviteTermsSchema.shape.role, teams: z.array(z.strictObject({ id: z.string(), name: z.string() })), shares: z.array(z.strictObject({ project: z.strictObject({ id: z.string(), slug: z.string() }), level: z.enum(["use", "edit", "manage"]), protected: z.boolean() })), guestExpiresAt: z.string().nullable(), boundEmail: z.string().nullable(), digest: z.string(), status: z.enum(["open", "pending_confirmation", "active", "revoked"]), expiresAt: z.string() })
// The invited email proved by Google (with its hosted domain) or by a code
// emailed to it (directory/email-proof.ts); either names it in `email`. Only
// Google's hosted domain can satisfy the workspace identity rule.
export const InviteIdentityEvidence = z.discriminatedUnion("provider", [
  z.strictObject({ provider: z.literal("google"), subject: z.string(), email: z.string(), hd: z.string().nullable() }),
  z.strictObject({ provider: z.literal("email"), email: z.string() }),
])
export const InviteRedeemInput = IdInput.extend({ member: z.string().regex(/^mem_[A-Za-z0-9_-]{1,64}$/), account: z.string(), name: z.string().min(1).max(64), evidence: z.strictObject({ recoverySetup: z.boolean(), identity: InviteIdentityEvidence.nullable() }) })
export const InviteRedeemOutput = z.strictObject({ member: z.string(), state: z.enum(["pending_confirmation", "active"]) })
type InviteRow = { id: string; code_hash: string; terms: string; digest: string; creator: string; creator_evidence: string | null; status: "open" | "pending_confirmation" | "active" | "revoked"; used_by: string | null; member: string | null }
function openInvite(ctx: VaultContext, hash: string): { row: InviteRow; terms: z.infer<typeof InviteTermsSchema> } {
  const row = one(ctx.sql.exec<InviteRow>("SELECT * FROM invites WHERE code_hash=?", hash))
  if (!row || row.status === "revoked") throw new VaultError("not_found", "No such invite.")
  const terms = InviteTermsSchema.parse(JSON.parse(row.terms))
  if (Date.parse(terms.expiresAt) <= ctx.now()) throw new VaultError("not_found", "No such invite.")
  const state = accessState(ctx)
  if (!inviteCreatorEligible(ctx, row.creator, row.creator_evidence, terms.role)) throw new VaultError("forbidden", "This invitation needs an eligible owner or admin to reissue it.")
  if (terms.teams.some((id) => !state.teams.some((t) => t.id === id)) || terms.shares.some((s) => !state.projects.some((p) => p.id === s.project))) throw new VaultError("conflict", "The invitation terms changed.")
  return { row, terms }
}
import { workspaceMemberOps } from "./workspace-members.ts"

export const OperatorWorkspaceViewSchema = z.strictObject({ frozen: z.boolean(), owners: z.array(z.strictObject({ account: z.string(), name: z.string() })), unconfirmed: z.number().int().nonnegative() })
export const OperatorFreezeAnswerSchema = z.strictObject({ frozen: z.literal(true), already: z.boolean(), notify: z.array(z.string()) })

export const accessArea: Area = {
  name: "access", migrations: ACCESS_MIGRATIONS,
  async alarm(ctx, key) { if (key === "notice-outbox") await deliverNoticeOutbox(ctx) },
  workspaceOps: {
    ...workspaceMemberOps,
    "access.identity.context": { auth: ["system"], handler(ctx, _p, raw) {
      const { account } = z.strictObject({ account: z.string().min(1) }).parse(raw)
      const member = memberRows(ctx).find(m => m.account === account && m.status !== "removed")
      if (!member) throw new VaultError("not_found", "No such membership.")
      return { member: member.id, role: member.role, pendingRole: pendingRoleOf(member,ctx.now()), pendingAction: pendingRoleOf(member,ctx.now()) !== null && member.pending_action ? JSON.parse(member.pending_action) as import("@mehen/protocol").WorkspaceStepUpAction : null, identityRule: setting<import("@mehen/protocol").IdentityRule>(ctx, "identity_rule", null), identityRuleRev: setting(ctx, "identity_rule_rev", 0), gateGeneration: member.gate_generation, checkSequence: member.check_sequence, status: member.status }
    } },
    "access.identity.install": { auth: ["system"], handler(ctx, _p, raw) {
      const input = IdentityInstallInput.parse(raw)
      const result = ctx.storage.transactionSync(() => installIdentity(ctx, input))
      if ("promotionRefused" in result) throw new VaultError("conflict", "This pending promotion is no longer available.")
      return result
    } },
    "access.identity_rule": { auth: ["account"], handler(ctx, _p, raw, invocation) {
      const input = z.strictObject({ rule: IdentityRuleSchema }).parse(raw)
      return ctx.storage.transactionSync(() => {
        const action = { type: "workspace.identity_rule", rule: input.rule } as const
        const decision = authorise(ctx, invocation, { type: "workspace.identity_rule" }, {}, ctx.now())
        requireStepUp(ctx, decision, action, invocation)
        if (invocation.auth.kind !== "account" || decision.principal.kind !== "member") throw new VaultError("forbidden", "Only an owner can change the identity rule.")
        requireOperationIdentity(ctx, decision.principal.memberId, action, invocation.auth.operationCheck)
        const revision = setting(ctx, "identity_rule_rev", 0) + 1
        const previous = setting<import("@mehen/protocol").IdentityRule>(ctx, "identity_rule", null)
        for (const m of memberRows(ctx)) if (previous?.roles.includes(m.role) || input.rule?.roles.includes(m.role)) lapseMandates(ctx, { member: m.id })
        setSetting(ctx, "identity_rule", input.rule)
        setSetting(ctx, "identity_rule_rev", revision)
        ctx.sql.exec("UPDATE members SET gate_generation=gate_generation+1,revision=revision+1")
        ctx.sql.exec("DELETE FROM workspace_identity_checks")
        bumpAccessRevision(ctx)
        ctx.audit({ actor: `member:${decision.principal.memberId}`, action: "workspace.identity_rule", target: ctx.tenant, detail: { rule: input.rule, identityRuleRev: revision } })
        return { identityRule: input.rule, identityRuleRev: revision }
      })
    } },
    // Who the signed-in caller is here, refused exactly as reading the asks
    // is (suspended, unconfirmed, identity-gated). The connect-code issuer
    // calls it before anything is written.
    "access.viewer": { auth: ["account"], handler(ctx, _p, _raw, invocation) {
      const decision = authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
      const member = decision.principal.kind === "member" ? accessState(ctx).members.find((m) => m.id === (decision.principal.kind === "member" ? decision.principal.memberId : "")) : undefined
      if (!member) throw new VaultError("forbidden", "Only people connect agents.")
      return z.strictObject({ member: z.string(), role: InviteTermsSchema.shape.role }).parse({ member: member.id, role: member.standing.effectiveRole })
    } },
    "access.workspace_ref": { auth: ["system"], handler(ctx) { return { workspace: workspaceRef(ctx), displayRev: setting(ctx, "display_rev", 1), appliedReservations: setting<string[]>(ctx, "applied_reservations", []) } } },
    // The operator console's (directory/operator-workspaces.ts), system
    // only: what its Workspaces view shows of this workspace and nothing
    // more inside it: whether it is frozen, its owners, and how many people
    // an owner or admin has still to confirm.
    "access.operator_view": { auth: ["system"], handler(ctx) {
      const members = accessState(ctx).members.filter((m) => m.status !== "removed")
      return OperatorWorkspaceViewSchema.parse({ frozen: setting(ctx, "frozen", false), owners: members.filter((m) => m.standing.effectiveRole === "owner").map((m) => ({ account: m.account, name: m.name })), unconfirmed: members.filter((m) => m.status === "unconfirmed").length })
    } },
    // An operator's brake (workspace.freeze in operator-proposal-kinds.ts),
    // system only: this workspace's own freeze, in its own audit chain as
    // the operator's account, and only an owner unfreezes it. Answers the
    // owners and admins to tell; freezing a frozen workspace changes nothing.
    "access.operator_freeze": { auth: ["system"], handler(ctx, _p, raw) {
      const input = z.strictObject({ operator: z.string().regex(/^acc_[A-Za-z0-9_-]{1,124}$/) }).parse(raw)
      return ctx.storage.transactionSync(() => {
        const already = setting(ctx, "frozen", false)
        if (!already) {
          setSetting(ctx, "frozen", true)
          ctx.audit({ actor: `operator:${input.operator}`, action: "workspace.freeze", target: ctx.tenant, detail: { by: "operator" } })
        }
        const notify = accessState(ctx).members.filter((m) => m.status !== "removed" && (m.standing.effectiveRole === "owner" || m.standing.effectiveRole === "admin")).map((m) => m.account)
        return OperatorFreezeAnswerSchema.parse({ frozen: true, already, notify })
      })
    } },
    "access.workspace_update": { auth: ["account"], handler(ctx, _p, raw, invocation) {
      const input = z.strictObject({ name: WorkspaceRefSchema.shape.name.optional(), slug: WorkspaceRefSchema.shape.slug.optional(), reservation: z.strictObject({ id: z.string(), expiresAt: z.iso.datetime() }).optional() }).parse(raw)
      return ctx.storage.transactionSync(() => {
        const before = workspaceRef(ctx)
        const after = { ...before, ...(input.name ? { name: input.name } : {}), ...(input.slug ? { slug: input.slug } : {}) }
        const decision = authorise(ctx, invocation, { type: "workspace.update" }, {}, ctx.now())
        requireStepUp(ctx, decision, { type: "workspace.update", name: after.name, slug: after.slug }, invocation)
        if (after.slug !== before.slug && !input.reservation) throw new VaultError("bad_request", "Changing the workspace slug needs a reservation.")
        if (input.reservation && Date.parse(input.reservation.expiresAt) <= ctx.now()) throw new VaultError("conflict", "This workspace name reservation expired.")
        const applied = setting<string[]>(ctx, "applied_reservations", [])
        if (input.reservation && applied.includes(input.reservation.id)) return { displayRev: setting(ctx, "display_rev", 1) }
        setSetting(ctx, "workspace", after)
        const displayRev = setting(ctx, "display_rev", 1) + 1
        setSetting(ctx, "display_rev", displayRev)
        if (input.reservation) setSetting(ctx, "applied_reservations", [...applied, input.reservation.id])
        ctx.audit({ actor: decision.principal.kind === "member" ? `member:${decision.principal.memberId}` : "system", action: "workspace.update", target: ctx.tenant, detail: { name: after.name, slug: after.slug } })
        return { displayRev }
      })
    } },
    "access.membership": { auth: ["system"], handler(ctx, _p, raw) {
      const input = z.strictObject({ account: z.string() }).parse(raw)
      const state = accessState(ctx)
      const member = state.members.find((m) => m.account === input.account && m.status !== "removed")
      if (!member) throw new VaultError("not_found", "No such membership.")
      return z.strictObject({ member: z.string(), role: InviteTermsSchema.shape.role, pendingRole: InviteTermsSchema.shape.role.nullable(), status: z.enum(["unconfirmed", "active", "suspended", "removed"]), teams: z.array(z.string()) }).parse({ member: member.id, role: member.standing.effectiveRole, pendingRole: member.standing.pendingRole, status: member.status, teams: state.teams.filter((t) => t.members.includes(member.id)).map((t) => t.id) })
    } },
    "access.account_event": { auth: ["system"], handler(ctx, _p, raw) {
      const input = z.strictObject({ id: z.string(), account: z.string(), at: z.number().int().nonnegative(), action: z.string().regex(/^account\.[a-z_]+$/), detail: z.record(z.string(), z.unknown()) }).parse(raw)
      return ctx.storage.transactionSync(() => {
        const member = one(ctx.sql.exec<{ id: string; account: string; name: string; status: string }>("SELECT id,account,name,status FROM members WHERE account=? ORDER BY joined_at DESC,rowid DESC LIMIT 1", input.account))
        if (!member || one(ctx.sql.exec<{ id: string }>("SELECT id FROM mirrored_account_events WHERE id=?", input.id))) return { mirrored: true }
        // Account mirrors never copy arbitrary workspace/resource detail.
        const detail: Record<string, unknown> = { event: input.id, account: input.account, at: input.at }
        for (const key of ["client", "place", "outcome", "restrictedUntil"] as const) { const value = input.detail[key]; if (typeof value === "string" || typeof value === "number" || value === null) detail[key] = value }
        ctx.sql.exec("INSERT INTO mirrored_account_events VALUES (?)", input.id)
        ctx.audit({ actor: `member:${member.id}`, action: input.action, target: member.id, detail })
        if (member.status === "active" && (input.action === "account.recovery" || input.action === "account.break_glass")) {
          const until = input.detail.restrictedUntil
          queueNotice(ctx, { kind: "account_security", workspace: workspaceRef(ctx), account: member.account, name: member.name, event: input.action === "account.recovery" ? "recovery" : "break-glass", at: new Date(input.at).toISOString(), client: typeof input.detail.client === "string" ? input.detail.client : null, place: typeof input.detail.place === "string" ? input.detail.place : null, restrictedUntil: typeof until === "number" && until < PENDING_RESTRICTION_UNTIL ? new Date(until).toISOString() : typeof until === "string" ? until : null }, input.id)
        }
        // An operator suspended the account: its owners and admins decide
        // whether its machines keep their scope here.
        if (member.status === "active" && input.action === "account.suspend") queueNotice(ctx, { kind: "account_suspended", workspace: workspaceRef(ctx), account: member.account, name: member.name, at: new Date(input.at).toISOString() }, input.id)
        return { mirrored: true }
      })
    } },
    "access.init": { auth: ["system"], handler(ctx, _principal, raw) {
      const input = AccessInitInput.parse(raw)
      return ctx.storage.transactionSync(() => {
        if (input.workspace !== ctx.tenant) throw new VaultError("not_found", "No such workspace.")
        const existing = setting<string | null>(ctx, "access_init_digest", null)
        if (existing) {
          if (existing !== digest(input)) throw new VaultError("conflict", "This workspace was initialised with different terms.")
          const owner = memberRows(ctx).find((m) => m.account === input.owner.account)
          if (!owner) throw new VaultError("conflict", "The initial owner no longer exists.")
          return AccessInitOutput.parse({ member: owner.id })
        }
        const member = newMember(ctx, input.owner.account, input.owner.name, "owner", "active", input.member)
        setSetting(ctx, "workspace", { id: input.workspace, slug: input.slug, name: input.name })
        setSetting(ctx, "access_init_digest", digest(input)); bumpAccessRevision(ctx)
        ctx.audit({ actor: `member:${member}`, action: "workspace.create", target: input.workspace })
        return AccessInitOutput.parse({ member })
      })
    } },
    "access.security.install": { auth: ["system"], handler(ctx, _p, raw) { const i = SecurityInstallInput.parse(raw); return ctx.storage.transactionSync(() => SecurityOutput.parse({ installedEpoch: installSecurity(ctx, i.account, i.committedEpoch, i.pending).installedEpoch })) } },
    "access.session_revoke": { auth: ["system"], handler(ctx, _p, raw) { const i = z.strictObject({ account: z.string(), session: z.string() }).parse(raw); return ctx.storage.transactionSync(() => { revokeSession(ctx, i.account, i.session); return { revoked: true } }) } },
    "access.security.restriction": { auth: ["system"], handler(ctx, _p, raw) { const i = SecurityRestrictionInput.parse(raw); return ctx.storage.transactionSync(() => SecurityOutput.parse({ installedEpoch: updateRestriction(ctx, i.account, i.committedEpoch, i.restriction).installedEpoch })) } },
    "access.security.commit": { auth: ["system"], handler(ctx, _p, raw) { const i = SecurityCommitInput.parse(raw); return ctx.storage.transactionSync(() => SecurityOutput.parse({ installedEpoch: observeCommittedEpoch(ctx, i.account, i.committedEpoch).installedEpoch })) } },
    "access.outbox.drain": { auth: ["system"], handler(ctx, _p, raw) { const i = OutboxDrainInput.parse(raw); return OutboxDrainOutput.parse(drainOutbox(ctx, i.limit)) } },
    "access.outbox.ack": { auth: ["system"], handler(ctx, _p, raw) { const i = z.strictObject({ ids: z.array(z.string()).max(100) }).parse(raw); return ctx.storage.transactionSync(() => { for (const id of i.ids) ctx.sql.exec("UPDATE notice_outbox SET acknowledged_at=? WHERE id=? AND acknowledged_at IS NULL", ctx.now(), id); return z.strictObject({}).parse({}) }) } },
    "access.invites.abort": { auth: ["system"], handler(ctx, _p, raw) {
      const input = z.strictObject({ codeHash: z.string().min(1), member: z.string().min(1), account: z.string().min(1) }).parse(raw)
      return ctx.storage.transactionSync(() => {
        const key = `invite_abort:${digest(input)}`
        const previous = setting<{ aborted: true; state: "open" | "expired" } | null>(ctx, key, null)
        if (previous) return previous
        const invite = one(ctx.sql.exec<InviteRow>("SELECT * FROM invites WHERE code_hash=? AND member=? AND used_by=?", input.codeHash, input.member, input.account))
        const member = memberRows(ctx).find(m => m.id === input.member && m.account === input.account)
        if (!invite || !member) return { aborted: false }
        if (member.status === "active") throw new VaultError("conflict", "This membership is already active.")
        if (member.status !== "unconfirmed" || invite.status !== "pending_confirmation" || !one(ctx.sql.exec("SELECT id FROM members WHERE id=? AND invite=?", member.id, invite.id))) return { aborted: false }
        const state = Date.parse(InviteTermsSchema.parse(JSON.parse(invite.terms)).expiresAt) > ctx.now() ? "open" as const : "expired" as const
        ctx.sql.exec("DELETE FROM workspace_identity_checks WHERE member=?", member.id)
        ctx.sql.exec("DELETE FROM members WHERE id=? AND account=? AND status='unconfirmed'", member.id, member.account)
        ctx.sql.exec("DELETE FROM tenant_state WHERE key=?", `identity_install:${member.id}`)
        ctx.sql.exec("UPDATE invites SET status=?,used_by=NULL,member=NULL WHERE id=?", state, invite.id)
        const result = { aborted: true as const, state }
        setSetting(ctx, key, result)
        bumpAccessRevision(ctx)
        ctx.audit({ actor: "system", action: "member.join_aborted", target: member.id })
        return result
      })
    } },
    "access.invites.identity_context": { auth: ["system"], handler(ctx, _p, raw) {
      const { row,terms } = openInvite(ctx,IdInput.parse(raw).codeHash)
      return { termsDigest: row.digest,role: terms.role,identityRule: setting<import("@mehen/protocol").IdentityRule>(ctx,"identity_rule",null),identityRuleRev: setting(ctx,"identity_rule_rev",0) }
    } },
    "access.invites.lookup": { auth: ["system"], handler(ctx, _p, raw) {
      const { row, terms } = openInvite(ctx, IdInput.parse(raw).codeHash)
      const state = accessState(ctx)
      return InviteTermsViewSchema.parse({ id: row.id, workspace: workspaceRef(ctx), inviter: { name: state.members.find((m) => m.id === row.creator)?.name ?? "" }, role: terms.role, teams: terms.teams.map((id) => ({ id, name: state.teams.find((t) => t.id === id)?.name ?? "" })), shares: terms.shares.map((s) => ({ project: { id: s.project, slug: state.projects.find((p) => p.id === s.project)?.slug ?? s.project }, level: s.level, protected: s.protected })), guestExpiresAt: terms.role === "guest" ? terms.expiresAt : null, boundEmail: terms.email ? `${terms.email[0]}***@${terms.email.split("@")[1]}` : null, digest: row.digest, status: row.status, expiresAt: terms.expiresAt })
    } },
    "access.invites.redeem": { auth: ["system"], handler(ctx, _p, raw) {
      const input = InviteRedeemInput.parse(raw)
      return ctx.storage.transactionSync(() => {
        const { row, terms } = openInvite(ctx, input.codeHash)
        if (!input.evidence.recoverySetup) throw new VaultError("forbidden", "Set up account recovery before joining.")
        const identity = input.evidence.identity
        if (terms.email !== null && (!identity || identity.email !== terms.email)) throw new VaultError("forbidden", "Prove the invited email before joining.")
        const rule = setting<z.infer<typeof IdentityRuleSchema>>(ctx, "identity_rule", null)
        if (rule?.roles.includes(terms.role) && (identity?.provider !== "google" || !identity.hd || !rule.domains.includes(identity.hd) || identity.email.split("@")[1] !== identity.hd)) throw new VaultError("identity_required", "Check your workspace identity before joining.")
        if (row.status === "pending_confirmation" && row.used_by === input.account && row.member === input.member) return InviteRedeemOutput.parse({ member: row.member, state: "pending_confirmation" })
        // A retry answers active whenever the member is active: after joining
        // straight away, and equally once an owner or admin has confirmed
        // them, so the directory then installs a still-valid proof as a
        // session check rather than an invite check.
        if (row.status === "active" && row.used_by === input.account && row.member === input.member && memberRows(ctx).some((m) => m.id === row.member && m.status === "active")) return InviteRedeemOutput.parse({ member: row.member, state: "active" })
        if (row.status !== "open" || memberRows(ctx).some((m) => m.account === input.account && m.status !== "removed")) throw new VaultError("conflict", "This invitation is no longer available.")
        // Straight in only when the inviter signed onJoin "activate" on an
        // email-bound invitation below owner and that email is proved here.
        // openInvite has re-checked the creator's eligibility and the expiry,
        // and the identity rule passed above.
        const activate = inviteJoinsStraightAway(terms) && identity !== null && identity.email === terms.email
        const member = newMember(ctx, input.account, input.name, terms.role, "unconfirmed", input.member)
        ctx.sql.exec("UPDATE members SET invite=? WHERE id=?", row.id, member)
        ctx.sql.exec("UPDATE invites SET status='pending_confirmation',used_by=?,member=? WHERE id=?", input.account, member, row.id)
        ctx.audit({ actor: `member:${member}`, action: "member.join", target: member })
        if (activate) {
          activateInvitedMember(ctx, member, row.id, terms)
          ctx.audit({ actor: `member:${row.creator}`, action: "member.confirm", target: member, detail: { reason: "invitation" } })
          queueNotice(ctx, { kind: "member_joined", workspace: workspaceRef(ctx), member, name: input.name, role: terms.role, by: row.creator, at: new Date(ctx.now()).toISOString() })
        }
        bumpAccessRevision(ctx)
        return InviteRedeemOutput.parse({ member, state: activate ? "active" : "pending_confirmation" })
      })
    } },
    "access.enrol.register": { auth: ["system"], handler(ctx, _p, raw) {
      const input = EnrolRegisterInput.parse(raw)
      return ctx.storage.transactionSync(() => {
        const existing = one(ctx.sql.exec<{ value: string }>("SELECT value FROM workspace_enrolments WHERE id=?", input.enrolment))
        const scope = { ...input.scope, privateCredentials: false }
        const value = PendingEnrolSchema.parse({ ...input, scope, workspace: workspaceRef(ctx), state: input.requestedOwner.kind === "team" ? "pending_admission" : "pending_owner_acceptance", digest: digest({ ...input, scope }) })
        if (existing) {
          // Normalised terms: a legacy record reads with its expiry as the
          // hard cap and no claim, so the 0008 backfill re-registers it
          // idempotently and any claim against it is a different term.
          const old = readStoredEnrol(existing.value)
          const registered = { enrolment: old.enrolment, start: old.start, thumbprint: old.thumbprint, requestedOwner: old.requestedOwner, detail: old.detail, claimedAccount: old.claimedAccount, scope: { ...old.scope, privateCredentials: false }, requested: old.requested ?? null }
          const repeated = { enrolment: input.enrolment, start: input.start, thumbprint: input.thumbprint, requestedOwner: input.requestedOwner, detail: input.detail, claimedAccount: input.claimedAccount, scope, requested: input.requested ?? null }
          if (digest(registered) !== digest(repeated)) throw new VaultError("conflict", "This enrolment has different terms.")
          return enrolRecord(old)
        }
        if (input.detail && Date.parse(input.detail.hardExpiresAt) <= ctx.now()) throw new VaultError("not_found", "No such enrolment.")
        ctx.sql.exec("INSERT INTO workspace_enrolments(id,thumbprint,value) VALUES (?,?,?)", input.enrolment, input.thumbprint, canonicalJson(value))
        return value
      })
    } },
  },
}
