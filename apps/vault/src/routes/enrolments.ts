import { EnrolEvidenceSchema,EnrolOwnerIntentSchema,WorkspaceEnrolViewSchema,type WorkspaceEnrolView,type WorkspaceStepUpAction } from "@mehen/protocol"
import { z } from "zod"
import { EnrolVisibilitySchema,PendingEnrolViewSchema,digest,type EnrolVisibility,type PendingEnrolView } from "../vault/areas/workspace-runtime.ts"
import { ENROLMENT_ID,checkWorkspaceTypedGroup,enrolCandidate,enrolRegistration,expiredReason,mirrorActiveEnrolment,workspaceEnrolmentByCode,workspaceEnrolmentById,type WorkspaceEnrolmentRow } from "../directory/workspace-enrolment.ts"
import { enrolmentFingerprint,enrolmentLease,normaliseCode,type EnrolmentLease } from "../directory/enrolment.ts"
import { issueConnectCode } from "../directory/connect-code.ts"
import { connectCodesOffered } from "../cli-version.ts"
import { directoryWorkspaceClient } from "../directory/workspace-client.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { StepUpAssertionProofSchema } from "@mehen/protocol/step-up-proof"
import { onThisMachine,placeOf } from "../directory/session.ts"
import { json,VaultError } from "../http.ts"
import type { Route } from "../router.ts"
import { workspaceCall,type RequestContext,type WorkspaceRequest } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"
import { accountBody } from "./account.ts"
const Team = z.object({ id: z.string(),name: z.string() })
async function teamName(rc: RequestContext,ws: WorkspaceRequest,team: string): Promise<string> {
  const list = z.array(Team).parse(await workspaceCall(rc,ws,"access.teams.read",{}))
  const found = list.find(value => value.id === team)
  if (!found) throw new VaultError("not_found","No such enrolment.")
  return found.name
}
const notFound = () => new VaultError("not_found","No such enrolment.")
// An opened enrolment. The :ref is a code (the code form: any active member
// of the workspace, as the agent's link always worked) or an enr_ id (the id
// form: only those the workspace's evaluator says may view it, everyone else
// gets the bytes of an unknown enrolment). The id form never carries a code.
type Opened = { ref: string; code: string | null; row: WorkspaceEnrolmentRow; lease: EnrolmentLease; visibility: EnrolVisibility | null }
async function visibilityFor(rc: RequestContext,ws: WorkspaceRequest,row: WorkspaceEnrolmentRow): Promise<EnrolVisibility> {
  return EnrolVisibilitySchema.parse(await workspaceCall(rc,ws,"access.enrol.visible",{ candidate: await enrolCandidate(rc.env,row) }))
}
async function opened(rc: RequestContext,ws: WorkspaceRequest): Promise<Opened> {
  const ref = rc.params.ref ?? "",code = normaliseCode(ref)
  const row = code ? (await workspaceEnrolmentByCode(rc.env,ws.workspace,code)).row : ENROLMENT_ID.test(ref) ? await workspaceEnrolmentById(rc.env,ws.workspace,ref) : null
  if (!row) throw notFound()
  const lease = enrolmentLease(row,Date.now())
  if (code) return { ref: code,code,row,lease,visibility: lease === "lapsed" ? await visibilityFor(rc,ws,row) : null }
  const visibility = await visibilityFor(rc,ws,row)
  if (!visibility.visible) throw notFound()
  return { ref,code: null,row,lease,visibility }
}
// The workspace's copy. A live attempt is registered on first open; a
// lapsed or terminal one never is, and is viewed from its copy if it has one.
async function registeredView(rc: RequestContext,ws: WorkspaceRequest,o: Opened): Promise<PendingEnrolView> {
  if (o.lease === "live" && o.row.tenant === null) {
    await directoryWorkspaceClient(rc.env).registerEnrol(ws.workspace.id,enrolRegistration(o.row))
    const reserved = await rc.env.DB.prepare("UPDATE enrolments SET tenant=? WHERE id=? AND status='pending' AND expires_at>? AND (tenant IS NULL OR tenant=?)").bind(ws.workspace.id,o.row.id,Date.now(),ws.workspace.id).run()
    if (reserved.meta.changes !== 1) {
      // The copy exists now: record where, so maintenance waits for its reconcile and retention.
      await rc.env.DB.prepare("UPDATE enrolments SET tenant=? WHERE id=? AND tenant IS NULL").bind(ws.workspace.id,o.row.id).run()
      throw new VaultError("conflict","This enrolment changed. Refresh its page.")
    }
  } else if (o.row.tenant === null) throw notFound()
  const value = PendingEnrolViewSchema.parse(await workspaceCall(rc,ws,"access.enrol.view",{ enrolment: o.row.id }))
  if (value.enrolment !== o.row.id || value.workspace.id !== ws.workspace.id || value.thumbprint !== o.row.thumbprint) throw notFound()
  return value
}
// A lapsed or terminal page reads its copy when there is one and is built
// from the D1 row alone when not. The directory's membership
// row survives suspension, so a row-only view is served only after the
// workspace admits this caller to read, exactly as a copy's view would.
async function settledView(rc: RequestContext,ws: WorkspaceRequest,o: Opened): Promise<PendingEnrolView | null> {
  if (o.row.tenant !== null) {
    try { return await registeredView(rc,ws,o) } catch (error) { if (!(error instanceof VaultError && (error.code === "not_found" || error.code === "conflict"))) throw error }
  }
  await workspaceCall(rc,ws,"access.viewer",{})
  return null
}
function untilWords(at: number): string { return `${new Date(at).toISOString().slice(0,16).replace("T"," ")} UTC` }
function lapsedRefusal(row: WorkspaceEnrolmentRow): VaultError {
  return new VaultError("conflict",`This link has lapsed. Ask the agent to continue; the same link comes back to life until ${untilWords(row.hard_expires_at ?? row.expires_at)}.`)
}
// Accept, admit and the planning call need a live lease. A settled attempt
// refuses as its copy does (an expired copy is not found, a rejected one a
// conflict), or as already decided.
async function actingView(rc: RequestContext,ws: WorkspaceRequest,o: Opened): Promise<PendingEnrolView> {
  if (o.lease === "lapsed") throw lapsedRefusal(o.row)
  const value = await registeredView(rc,ws,o)
  if (o.lease === "terminal") throw new VaultError("conflict","This enrolment was already decided or has expired.")
  return value
}
// What this caller may do now. The id form offers only what the visibility
// table allows; the code form what the workspace allows any member with the
// link; a lapsed lease only an owner's or admin's reject; a settled one nothing.
function actionsFor(o: Opened,value: PendingEnrolView | null,state: WorkspaceEnrolView["state"]): ("accept" | "admit" | "reject")[] {
  if (state === "active" || state === "rejected" || state === "expired" || o.lease === "terminal") return []
  if (o.lease === "lapsed") return o.visibility?.actions ?? []
  const actions = value?.actions ?? []
  return o.visibility ? actions.filter(action => o.visibility?.actions.includes(action)) : actions
}
function acceptRefusal(o: Opened,ws: WorkspaceRequest): VaultError {
  return o.row.claimed_account !== null && o.row.claimed_account !== ws.account.account ? new VaultError("forbidden","This machine was started for another account.") : new VaultError("forbidden","Only the owning account can accept this machine.")
}
// A superseded attempt names its successor only for the same key, intent,
// owner intent and claim, and only when the successor is itself visible to
// this caller; otherwise the page says only that the link ran out.
async function successorOf(rc: RequestContext,ws: WorkspaceRequest,row: WorkspaceEnrolmentRow): Promise<{ enrolment: string; expiresAt: string } | null> {
  const next = await rc.env.DB.prepare(`SELECT e.* FROM enrolments e JOIN workspaces w ON w.id=? WHERE e.thumbprint=? AND e.workspace_intent=? AND e.owner_intent=? AND e.claimed_account IS ? AND e.id!=?
    AND e.status='pending' AND e.discard_pending=0 AND e.expires_at>? AND e.hidden_group IS NOT NULL AND (e.tenant IS NULL OR e.tenant=w.id) ORDER BY e.created_at DESC LIMIT 1`)
    .bind(ws.workspace.id,row.thumbprint,row.workspace_intent,row.owner_intent,row.claimed_account,row.id,Date.now()).first<WorkspaceEnrolmentRow>()
  if (!next || !(await visibilityFor(rc,ws,next)).visible) return null
  return { enrolment: next.id,expiresAt: new Date(next.expires_at).toISOString() }
}
async function publicView(rc: RequestContext,ws: WorkspaceRequest,o: Opened,value: PendingEnrolView | null): Promise<WorkspaceEnrolView> {
  const { row } = o,planning = value?.planning ?? null
  const settled = row.status === "rejected" ? "rejected" as const : row.status === "active" ? "active" as const : "expired" as const
  const state = o.lease === "terminal" && (value === null || value.state === "pending_owner_acceptance" || value.state === "pending_admission") ? settled : value?.state ?? row.pending_state ?? "pending_owner_acceptance"
  const terminal = state === "active" || state === "rejected" || state === "expired"
  const owned = value?.requestedOwner ?? EnrolOwnerIntentSchema.parse(JSON.parse(row.owner_intent))
  const requestedOwner = owned.kind === "self" ? owned : { ...owned,name: await teamName(rc,ws,owned.team) }
  const registration = enrolRegistration(row)
  // The scope registration records before anyone ticks: what the machine asked for, no private credentials.
  const registered = { ...registration.scope,privateCredentials: false }
  const claimed = row.claimed_account === null ? null : { account: row.claimed_account,name: (await rc.env.DB.prepare("SELECT name FROM accounts WHERE id=?").bind(row.claimed_account).first<{ name: string }>())?.name ?? "" }
  const reason = state === "expired" ? expiredReason(row) : null
  return WorkspaceEnrolViewSchema.parse({
    workspace: ws.workspace,enrolment: row.id,ref: o.ref,...(o.code !== null ? { code: o.code } : {}),name: row.name,host: row.host,backend: row.backend,start: value?.start ?? registration.start,acceptorPlace: placeOf(rc.request),...(onThisMachine(rc.request,rc.env.VAULT_ORIGIN) ? { acceptorLocal: true as const } : {}),...(row.start_session !== null && row.start_session !== "" ? { startedByAgent: true as const } : {}),requestedOwner,owner: value?.owner ?? null,
    // Built from the row alone, the digest is the one registration would
    // have recorded: the same terms through the same function.
    scope: planning?.scope ?? value?.scope ?? registered,digest: planning?.digest ?? value?.digest ?? digest({ ...registration,scope: registered }),
    fingerprint: await enrolmentFingerprint(o.ref,row.thumbprint,row.hidden_group ?? undefined),state,actions: actionsFor(o,value,state),
    expiresAt: new Date(row.expires_at).toISOString(),hardExpiresAt: new Date(row.hard_expires_at ?? row.expires_at).toISOString(),lease: terminal ? "terminal" : o.lease,claimed,reason,
    successor: reason === "superseded" ? await successorOf(rc,ws,row) : null,
    ...(registration.requested ? { requested: registration.requested } : {}),
  })
}
async function mirror(rc: RequestContext,ws: WorkspaceRequest,row: WorkspaceEnrolmentRow,value: PendingEnrolView): Promise<void> {
  if (value.state === "active" && value.device && value.owner) {
    const client = directoryWorkspaceClient(rc.env),source = await client.reconcile(ws.workspace.id,row.id)
    if (source.state !== "active" || source.device !== value.device || !source.active) throw new VaultError("conflict","This enrolment changed. Refresh its page.")
    await mirrorActiveEnrolment(rc.env,row,ws.workspace,{ device: source.device,...source.active },client)
  } else if (value.state === "rejected") await rc.env.DB.prepare("UPDATE enrolments SET status='rejected',pending_state=NULL WHERE id=? AND status='pending'").bind(row.id).run()
  else if (value.state === "pending_admission" || value.state === "pending_owner_acceptance") {
    const acceptance = EnrolEvidenceSchema.nullable().safeParse(value.acceptance),admission = EnrolEvidenceSchema.nullable().safeParse(value.admission)
    if (!acceptance.success || !admission.success) throw new VaultError("conflict","This enrolment changed. Refresh its page.")
    await rc.env.DB.prepare("UPDATE enrolments SET tenant=?,pending_state=?,scope=?,resolved_owner=?,acceptance_digest=?,accepted_by_account=?,accepted_by_member=?,accepted_at=?,admission_digest=?,admitted_by_account=?,admitted_at=? WHERE id=? AND status='pending' AND expires_at>?")
      .bind(ws.workspace.id,value.state,JSON.stringify(value.scope),value.owner ? JSON.stringify(value.owner) : null,acceptance.data?.digest ?? null,acceptance.data?.account ?? null,acceptance.data?.member ?? null,acceptance.data ? Date.parse(acceptance.data.at) : null,admission.data?.digest ?? null,admission.data?.account ?? null,admission.data ? Date.parse(admission.data.at) : null,row.id,Date.now()).run()
  }
}
const Decision = z.strictObject({ group: z.string().max(32),stepUp: StepUpAssertionProofSchema.optional() })
// The exact enrol.accept a browser signs. It carries the full thumbprint,
// which would give the hidden group away, so it is returned only after the
// typed group matches, through the same counted check accept repeats.
function acceptAction(ws: WorkspaceRequest,row: WorkspaceEnrolmentRow,value: PendingEnrolView,privateCredentials: boolean): WorkspaceStepUpAction {
  if (privateCredentials && value.requested?.privateCredentials === false) throw new VaultError("forbidden","This machine asked not to use private credentials. Accept it without them.")
  return { type: "enrol.accept",workspace: ws.workspace.id,enrolment: row.id,thumbprint: row.thumbprint,account: ws.account.account,member: ws.membership,scope: { ...value.scope,privateCredentials },start: value.start }
}
export const workspaceEnrolRoutes: Route<WorkspaceHandler>[] = [
  // Minted on the Connect an agent page: shown once, stored hashed, bound to
  // this account in this workspace for a day.
  { method: "POST",path: "/connect-code",handler: async (rc,ws) => {
    if (!connectCodesOffered(rc.env)) throw new VaultError("not_found","This vault does not issue connect codes yet.")
    const limited = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `connect-code:${ws.account.account}` })
    if (!limited?.success) throw new VaultError("rate_limited","Too many connect codes. Try again shortly.",{ retryAfter: 60 })
    await workspaceCall(rc,ws,"access.viewer",{})
    return json(await issueConnectCode(rc.env,ws.account.account,ws.workspace.id),200,{ "cache-control": "no-store" })
  } },
  { method: "POST",path: "/enrolments/:ref/action",handler: async (rc,ws) => {
    const input = await accountBody(rc,z.strictObject({ kind: z.literal("accept"),group: z.string().max(32),privateCredentials: z.boolean() })),o = await opened(rc,ws),value = await actingView(rc,ws,o)
    if (!actionsFor(o,value,value.state).includes("accept")) throw acceptRefusal(o,ws)
    const typed = await checkWorkspaceTypedGroup(rc.env,o.code,o.row,input.group)
    if (!typed.ok) throw typed.refusal
    return json({ action: acceptAction(ws,o.row,value,input.privateCredentials) })
  } },
  { method: "GET",path: "/enrolments/:ref",handler: async (rc,ws) => {
    const o = await opened(rc,ws),value = o.lease === "live" ? await registeredView(rc,ws,o) : await settledView(rc,ws,o)
    if (value?.state === "active") await mirror(rc,ws,o.row,value)
    return json(await publicView(rc,ws,o,value))
  } },
  { method: "POST",path: "/enrolments/:ref/accept",handler: async (rc,ws) => {
    const input = await accountBody(rc,Decision.extend({ privateCredentials: z.boolean() })),o = await opened(rc,ws),value = await actingView(rc,ws,o)
    if (!actionsFor(o,value,value.state).includes("accept")) throw acceptRefusal(o,ws)
    const action = acceptAction(ws,o.row,value,input.privateCredentials)
    const evidence = await requireWorkspaceStepUp(rc,ws,action,input.stepUp)
    const typed = await checkWorkspaceTypedGroup(rc.env,o.code,o.row,input.group)
    if (!typed.ok) throw typed.refusal
    const result = PendingEnrolViewSchema.parse(await workspaceCall(rc,ws,"access.enrol.accept",{ enrolment: o.row.id,privateCredentials: input.privateCredentials },evidence))
    await mirror(rc,ws,o.row,result)
    return json(await publicView(rc,ws,o,result))
  } },
  { method: "POST",path: "/enrolments/:ref/admit",handler: async (rc,ws) => {
    const input = await accountBody(rc,Decision.extend({ project: z.string().optional() })),o = await opened(rc,ws),value = await actingView(rc,ws,o)
    const owner = value.owner ?? (value.requestedOwner.kind === "team" ? { kind: "team" as const,team: value.requestedOwner.team,name: await teamName(rc,ws,value.requestedOwner.team) } : null)
    if (!owner) throw new VaultError("conflict","The owning account must accept this machine first.")
    if (!actionsFor(o,value,value.state).includes("admit")) throw new VaultError("forbidden","This enrolment needs an eligible insider admission.")
    const signer = await directoryWorkspaceClient(rc.env).membership(ws.workspace.id,ws.account.account)
    const action: WorkspaceStepUpAction = { type: "enrol.approve",enrolment: o.row.id,digest: value.digest,owner,admissionRole: signer.role },evidence = await requireWorkspaceStepUp(rc,ws,action,input.stepUp)
    const typed = await checkWorkspaceTypedGroup(rc.env,o.code,o.row,input.group)
    if (!typed.ok) throw typed.refusal
    const result = PendingEnrolViewSchema.parse(await workspaceCall(rc,ws,"access.enrol.admit",{ enrolment: o.row.id,...(input.project ? { project: input.project } : {}) },evidence))
    await mirror(rc,ws,o.row,result)
    return json(await publicView(rc,ws,o,result))
  } },
  // Reject needs a pending attempt, live or lapsed. On a lapsed one only an
  // owner or admin may, and a never-registered row is settled in D1 alone.
  { method: "POST",path: "/enrolments/:ref/reject",handler: async (rc,ws) => {
    await accountBody(rc,z.strictObject({}))
    const o = await opened(rc,ws)
    if (o.visibility && o.lease !== "terminal" && !o.visibility.actions.includes("reject")) throw new VaultError("forbidden","Only an owner or admin can reject this machine now.")
    if (o.lease === "lapsed" && o.row.tenant === null) {
      const rejected = await rc.env.DB.prepare("UPDATE enrolments SET status='rejected',pending_state=NULL WHERE id=? AND status='pending' AND discard_pending=0 AND tenant IS NULL AND hard_expires_at>?").bind(o.row.id,Date.now()).run()
      if (rejected.meta.changes !== 1) throw new VaultError("conflict","This enrolment changed. Refresh its page.")
      console.log(JSON.stringify({ at: "enrol.rejected_lapsed",enrolment: o.row.id,workspace: ws.workspace.id,account: ws.account.account }))
      return json(await publicView(rc,ws,{ ...o,row: { ...o.row,status: "rejected",pending_state: null },lease: "terminal" },null))
    }
    if (o.row.tenant === null && o.lease === "terminal") throw notFound()
    if (o.lease === "live") await registeredView(rc,ws,o)
    const result = PendingEnrolViewSchema.parse(await workspaceCall(rc,ws,"access.enrol.reject",{ enrolment: o.row.id }))
    await mirror(rc,ws,o.row,result)
    return json(await publicView(rc,ws,o,result))
  } },
]
