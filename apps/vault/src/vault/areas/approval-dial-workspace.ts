// How often Mehen asks a person in this workspace: the approval dial, a
// workspace setting (approval_dial in tenant_state; none reads as writes).
// writes leaves the relay as it is. work lets a held request through as
// posture trust would (postures-workspace.ts trustWouldCover), asked by the
// relay after standing rules, task grants and postures and before mandates,
// reading each service's current reviewed catalogue, so moving the dial is
// the person's signed choice to trust those as they are updated. Where the
// relay would open a new ask, work refuses instead; an approval a person
// already gave is still used. Protected runs, fill and pushes still ask.
// Asking less needs a passkey (workspace.approvals); asking more does not.
// Owners and admins change it. Behind APPROVAL_DIAL (approvalDialOn); off,
// or in a managed workspace, it reads writes and cannot be changed.

import { ApprovalDialSchema, approvalDialAsksLess, DEFAULT_APPROVAL_DIAL, type ApprovalDial, type ApprovalDialRefusal, type WorkspaceApprovalsView } from "@mehen/protocol"
import { WorkspaceApprovalsChangeSchema } from "@mehen/protocol/workspace"
import { holdsLiveKey, policyFloorRefusal, postureCatalogueFor, type PostureCoverage } from "@mehen/protocol/policy-rules"
import type { Env } from "../../env.ts"
import { VaultError } from "../../http.ts"
import { can, type AccessPrincipal, type AccessState } from "../access.ts"
import type { VaultContext } from "../core.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { credentialAudit, type CheckedCredential } from "./items-workspace.ts"
import { parseOpInput } from "./items.ts"
import { anchorOf, ruleRefusalWords, type HeldRequest } from "./policy-rules-workspace.ts"
import { trustReaches, trustWouldCover } from "./postures-workspace.ts"
import { projects } from "./projects.ts"
import { workloadRow } from "./workloads.ts"
import { authorise, managedSetting, requireStepUp, setSetting, setting, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

const SETTING = "approval_dial"

export const APPROVAL_DIAL_NAMES: Readonly<Record<ApprovalDial, string>> = { writes: "Ask on writes", work: "Let it work" }

// Whether the dial is on in this workspace (its tn_ id), read as
// workspaceSwitchOn reads every switch.
export function approvalDialOn(env: Pick<Env, "APPROVAL_DIAL">, workspace: string): boolean {
  return workspaceSwitchOn(env.APPROVAL_DIAL, workspace)
}
const dialHere = (ctx: VaultContext): boolean => approvalDialOn(ctx.env, ctx.tenant) && managedSetting(ctx) === null

// The level the relay uses: the stored one where the dial is on, otherwise
// writes. A stored value it cannot read is writes too.
export function approvalDial(ctx: VaultContext): ApprovalDial {
  if (!dialHere(ctx)) return DEFAULT_APPROVAL_DIAL
  const parsed = ApprovalDialSchema.safeParse(setting<unknown>(ctx, SETTING, DEFAULT_APPROVAL_DIAL))
  return parsed.success ? parsed.data : DEFAULT_APPROVAL_DIAL
}

// The settings read's part: the level and which way this caller may move it
// now, each the evaluator's answer for the action the page would send.
// Absent where the dial cannot be changed.
export function approvalDialView(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, now: number): WorkspaceApprovalsView | undefined {
  if (!dialHere(ctx)) return undefined
  const level = approvalDial(ctx)
  const allowed = (type: "workspace.approvals_less" | "workspace.approvals_more") => can(state, principal, { type }, {}, now).allowed
  return { level, askLess: level !== "work" && !setting(ctx, "frozen", false) && allowed("workspace.approvals_less"), askMore: level !== "writes" && allowed("workspace.approvals_more") }
}

function dialChanged(): VaultError {
  return new VaultError("conflict", "How often this workspace asks changed; review and try again.")
}

// access.approvals: the level the page showed and the one chosen. Asking
// less is refused while frozen and needs the passkey over exactly
// workspace.approvals with both levels; asking more needs neither. Every
// change is audited with its before and after.
export function setApprovalDial(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): { level: ApprovalDial } {
  const { before, after } = parseOpInput(WorkspaceApprovalsChangeSchema, raw)
  if (!approvalDialOn(ctx.env, ctx.tenant)) throw new VaultError("forbidden", "How often this workspace asks cannot be changed here yet.")
  if (managedSetting(ctx) !== null) throw new VaultError("forbidden", "The platform decides what is asked in this workspace.")
  const less = approvalDialAsksLess(before, after)
  return ctx.storage.transactionSync(() => {
    const decision = authorise(ctx, invocation, { type: less ? "workspace.approvals_less" : "workspace.approvals_more" }, {}, ctx.now())
    if (approvalDial(ctx) !== before) throw dialChanged()
    if (before === after) return { level: before }
    if (less && setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
    if (less) requireStepUp(ctx, decision, { type: "workspace.approvals", before, after }, invocation)
    if (p.kind !== "member" || decision.principal.kind !== "member") throw new VaultError("forbidden", "Only a person can change how often this workspace asks.")
    setSetting(ctx, SETTING, after)
    ctx.audit({ actor: `member:${p.memberId}`, action: "workspace.approvals", target: ctx.tenant, detail: { before, after } })
    return { level: after }
  })
}

// ---------------------------------------------------------------- relay

export type DialUse = { coverage: PostureCoverage; held: HeldRequest }

// What Let it work lets through without asking, or null: only at work, and
// only what posture trust would.
export function coveringDial(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, held: HeldRequest): DialUse | null {
  if (approvalDial(ctx) !== "work") return null
  const coverage = trustWouldCover(ctx, principal, item, held)
  return coverage === null ? null : { coverage, held }
}
// Inside the relay's last transaction: still at work, and trust would still
// let the same request through.
export function assertDialCurrent(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, use: DialUse): void {
  if (approvalDial(ctx) !== "work" || trustWouldCover(ctx, principal, item, use.held)?.entry !== use.coverage.entry)
    throw new VaultError("conflict", "How often this workspace asks changed since this request was checked; send it again.")
}
// The use, as a posture's: the entry (or unreviewed), method and host, never a path.
export function recordDialUse(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, use: DialUse, run: string | null): void {
  const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
  credentialAudit(ctx, principal, item, "approvals.use", "work", { entry: use.coverage.entry, method: use.held.destination.method, host: use.held.destination.host, ...(workload ? { by: { workload: { id: workload.id, label: workload.label } } } : {}) }, run)
}

// Why Let it work refuses a held request rather than letting it through,
// for the words only; the decision is trustWouldCover's.
type OwnRefusal = Extract<ApprovalDialRefusal, "protected" | "machine" | "unreviewed" | "not-covered">
const OWN_WORDS: Readonly<Record<OwnRefusal, string>> = {
  protected: "This credential is used in a protected environment, which always needs a person.",
  machine: "Only a machine whose owner manages this credential may carry on without asking, and this machine's owner does not.",
  unreviewed: "Nobody has reviewed this service's routes, so this credential can only ask for every change.",
  "not-covered": "This request is not one a trusted machine may send without asking.",
}
const isOwn = (reason: ApprovalDialRefusal): reason is OwnRefusal => Object.hasOwn(OWN_WORDS, reason)
function refusalOf(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, held: HeldRequest & { protectedUse: boolean }): ApprovalDialRefusal {
  if (held.protectedUse || projects.isProtectedItem(ctx, item.slug)) return "protected"
  if (!trustReaches(ctx, principal, item)) return "machine"
  if (postureCatalogueFor(item.binding) === null) return "unreviewed"
  const anchor = anchorOf(ctx, item, { device: principal.deviceId, workload: principal.workload ?? null }, held)
  if (holdsLiveKey(anchor)) return "rule.live-key"
  return policyFloorRefusal(anchor) ?? (held.destination.search !== "" ? "rule.query" : "not-covered")
}

// What Let it work never covers, said in every refusal it gives.
export const APPROVAL_DIAL_NEVER_WORDS = "Let it work never covers protected environments, browser fill or pushes into other services, and refuses machines its trust does not reach, such as team machines and guests'."

// The refusal Let it work gives where the relay would open a new ask,
// recorded as a refusal of the credential's use.
export function dialRefusal(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, held: HeldRequest & { protectedUse: boolean }, workspaceSlug: string, run: string | null): VaultError {
  const reason = refusalOf(ctx, principal, item, held)
  const words = isOwn(reason) ? OWN_WORDS[reason] : ruleRefusalWords(reason)
  credentialAudit(ctx, principal, item, "approvals.refuse", "refused:forbidden", { reason, method: held.destination.method, host: held.destination.host }, run)
  return new VaultError("forbidden", `This request would need a person's approval, and this workspace is set to ${APPROVAL_DIAL_NAMES.work}, so the vault refuses it instead of asking. ${words} ${APPROVAL_DIAL_NEVER_WORDS}`, {
    dialRefused: reason,
    next: { url: `${ctx.env.VAULT_ORIGIN}/w/${workspaceSlug}/items/${item.slug}`, say: `Nothing is waiting on a person. To have a person decide requests like this one, an owner or admin sets the workspace back to ${APPROVAL_DIAL_NAMES.writes} in Settings.` },
  })
}
