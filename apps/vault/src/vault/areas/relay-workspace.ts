import { CredentialHomeSchema, ShareSubjectSchema, canonicalJson, parseProof, type ItemUseContext, type MandateCoverHint, type Mode } from "@mehen/protocol"
import { z } from "zod"
import { auditPrivateEvent } from "../audit.ts"
import { items } from "./items.ts"
import { VaultError } from "../../http.ts"
import type { RelayMaterial } from "../../relay/forward.ts"
import { principalDevice, type AccessAsk, type AccessPrincipal } from "../access.ts"
import { WORKLOAD_MAX_OPEN_ASKS, principalWorkload, workloadEnded, workloadRow } from "./workloads.ts"
import { one, randomId, type DevicePrincipal, type VaultContext } from "../core.ts"
import { ApprovalBundleCreate, type ApprovalBundleCreated, type ApprovalBundleOutcome, type ApprovalBundleStatus, type ApprovalStatus } from "@mehen/protocol/api"
import { waitForStorageWrite } from "../storage-waits.ts"
import { devicePolicyState } from "./devices.ts"
import { relayServices } from "../../relay/services.ts"
import { authoriseRelay,parseRelayRequest, type Checked } from "./relay.ts"
import { assertCredentialCurrent, credentialAudit, credentialOps, openCredentialSecrets, visibleCredential, type CheckedCredential } from "./items-workspace.ts"
import { workspaceTokenRead } from "./oauth-workspace.ts"
import { assertApprovedUse, consumeApprovedUse, prepareApprovedUse, assertRunUse, type ProtectedSnapshot } from "./projects-workspace.ts"
import { accessState, authorise, managedSetting, openAskCount, openWorkloadAskCount, setting, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { managedPolicyView } from "../managed-platform.ts"
import { MACHINE_MAX_OPEN_ASKS, batchesHere, deviceSeesAsk, machineAsksFull, replacingUnavailable, workspaceApproval, workspaceApprovalStatus, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import { askGroupExtra } from "./pending-workspace.ts"
import { assertAreaGrantCurrent, assertRuleCurrent, coveringAreaGrant, coveringRule, policyRulesOn, readsGrants, recordAreaGrantUse, recordRuleUse, storeRuleAnchor, type CoveringGrant, type HeldRequest } from "./policy-rules-workspace.ts"
import { bindingCode, digestOf, parseOpInput } from "./approvals.ts"
import { assertPostureCurrent, countPostureAsk, coveringPosture, recordPostureUse, type PostureUse } from "./postures-workspace.ts"
import { assertDialCurrent, coveringDial, dialRefusal, recordDialUse, approvalDial, type DialUse } from "./approval-dial-workspace.ts"
import { addMandatePlanned, assertMandateCurrent, coveringMandate, settleBeforeMandateUse, mandateCoverHint, newMandatePlanned, newMandateReservation, type MandatePlanned, recordMandateCappedAsk, recordMandateCoverAsk, recordMandateUse } from "./mandates-workspace.ts"
import type { PolicyFloorView } from "@mehen/protocol/policy-mode"
import { POLICY_FLOOR, classifyPolicyRequest, evaluatePolicyFloor, policyPathFloorReasons } from "@mehen/protocol/policy-safety"

// The floor reasons a held request touches, from its bytes: each floor entry
// that holds it, a word in its path, and a delete. Anything the floor holds
// without a named entry (a generic word, a body or destination it cannot
// read) is opaque.
export function heldRequestFloor(held: HeldRequest): PolicyFloorView["reason"][] {
  const input = { destination: held.destination, body: held.body, contentType: held.contentType, contentEncoding: held.contentEncoding }
  const reasons = new Set<PolicyFloorView["reason"]>(evaluatePolicyFloor(input).reasons.map((id) => POLICY_FLOOR.find((entry) => entry.id === id)?.reason ?? "opaque"))
  for (const reason of policyPathFloorReasons(held.destination.path)) reasons.add(reason)
  if (held.destination.method === "DELETE" || classifyPolicyRequest(input).effect === "destructive") reasons.add("destructive")
  return [...reasons].sort()
}
// What makes two asks the same place: the credential, method, host and
// path, never the query or the body.
export function heldRequestShape(credential: string, held: HeldRequest): string {
  return digestOf({ credential, method: held.destination.method, host: held.destination.host, path: held.destination.path })
}

export function authoriseWorkspaceRelay(ctx: VaultContext, principal: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<RelayMaterial> {
  return workspaceRelay(ctx, principal, input, invocation, null)
}

// One request of a bundle in plan mode: the bnd_ its held ask joins, what
// the approval loop found (the ask it recorded, or the approved grant a
// later identical request spends), and whether it reached a member-private
// credential, whose rows go to that member's private audit.
// cover: on an ask, whether a mandate could let it through (mandateCoverHint).
// planned: what the bundle's requests before this one would debit of the
// machine's mandate, this one's added once it is covered.
type RelayPlan = { bundle: string; asked: WorkspaceApprovalRow | null; cover: MandateCoverHint | null; granted: string | null; private: boolean; planned: MandatePlanned }

async function workspaceRelay(ctx: VaultContext, principal: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext, plan: RelayPlan | null): Promise<RelayMaterial> {
  if (principal.kind !== "device" || invocation.auth.kind !== "device")
    throw new VaultError("forbidden", "Only an enrolled device can use the relay.")
  const req=parseRelayRequest(input)
  if((req.item===undefined)===(req.run===undefined))throw new VaultError("bad_request","Name exactly one of item (a credential to inject) or run (whose placeholders to swap).")
  if (req.replaces !== undefined && !batchesHere(ctx)) throw replacingUnavailable()
  const state = accessState(ctx), device = principalDevice(state, principal, ctx.now()), policyDevice = devicePolicyState(ctx, principal.deviceId)
  const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
  if (principal.workload !== undefined && (!device || !workload)) throw workloadEnded()
  if (!device || !policyDevice?.active)
    throw new VaultError("not_found", "No such machine.")
  const claims = parseProof(invocation.auth.proof).claims
  const legacy: DevicePrincipal = { kind: "device", device: principal.deviceId, name: policyDevice.name, scope: device.scope, session: claims.sid ?? null, grant: claims.gnt ?? null, workload: workload ? principalWorkload(workload) : null }
  let context: ItemUseContext | null = req.context ?? null
  let runSnapshot: ProtectedSnapshot | null = null
  if(req.run){
    const run=assertRunUse(ctx,accessState(ctx),req.run,principal,ctx.now())
    const stored={project:run.project,environment:run.env}
    if(context&&canonicalJson(context)!==canonicalJson(stored))throw new VaultError("bad_request","A relay context cannot override the run's context.")
    context=stored
    runSnapshot=run.snapshot
  }
  const checked = new Map<string, CheckedCredential>()
  const approvals: {
    snapshot: ProtectedSnapshot
    approval: string
  }[] = []
  // The standing rules that let a held request through without asking.
  const ruled: string[] = []
  const granted: CoveringGrant[] = []
  // The postures that let a held request through without asking, by slug.
  const postured = new Map<string, { use: PostureUse; held: HeldRequest }>()
  // What Let it work let through without asking, by slug.
  const dialed = new Map<string, DialUse>()
  // What this machine's mandate covered in this request: one mandate, the
  // union of the classes it debits once, and each credential it covered.
  const reservation = newMandateReservation()
  const guarded: VaultContext = Object.assign(Object.create(ctx) as VaultContext, { audit(event: Parameters<VaultContext["audit"]>[0]) {
      const mentioned = [event.target, event.detail?.item, ...(Array.isArray(event.detail?.items) ? event.detail.items : [])].filter((id): id is string => typeof id === "string")
      const privateItems = [...checked.values()].filter(c => c.home.kind === "member" && mentioned.some(id => id === c.slug || id === c.id))
      if (!privateItems.length) {
        ctx.audit(event)
        return
      }
      for (const item of privateItems)
        credentialAudit(ctx, principal, item, event.action, event.action === "relay.deny" ? "refused:policy_denied" : event.action === "relay.tripwire" ? `refused:${event.detail?.reason === "fenced-host" ? "environment_refused" : "surface_refused"}` : event.action === "relay.refuse" ? `refused:${typeof event.detail?.reason === "string" && event.detail.reason.startsWith("binding-") ? "binding_refused" : "environment_refused"}` : "allowed", {}, req.run ?? null)
    } })
  let auditContext: RelayMaterial["workspaceAudit"]
  // A managed workspace has no Mehen page to send anyone to: its platform
  // decides held requests and reconnects accounts.
  const managed = managedSetting(ctx) !== null
  const material = await authoriseRelay(guarded, legacy, input, {
    visible(slug: string, mode: Mode) {
      if (mode !== "relay" && mode !== "placeholder" && mode !== "lease")
        throw new VaultError("mode_refused", "This relay mode is unavailable.")
      const item = managedPolicyView(ctx, visibleCredential(ctx, principal, slug, { context, mode }))
      checked.set(slug, item)
      if (plan && item.home.kind === "member") plan.private = true
      return item
    },
    reauth(item) { throw new VaultError("needs_reauth", `"${item.slug}" needs to be connected again.`, { next: managed ? { say: "The platform reconnects this account." } : { url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/items/${item.slug}`, say: "Reconnect this credential in the workspace." } }); },
    prepare(entries: Checked[]) {
      for (const { item, mode } of entries)
        authorise(ctx, invocation, { type: "item.use", context }, { credential: item.id, mode: mode === "reveal" ? "relay" : mode }, ctx.now())
    },
    approve(item, subject, presentation, held) {
      if (req.run && runSnapshot)
        return true
      const credential = checked.get(item.slug)
      if (!credential)
        throw new VaultError("not_found", "No such credential.")
      // Only a request the item's policy holds, never a protected one; a
      // run's placeholder only in an unprotected run (a protected one
      // returned above). coveringRule refuses a managed workspace. A shape
      // rule first, then a task grant, which counts the use as its entry,
      // then a posture only when no grant covered the request, so a request
      // a grant covers is never also a posture use, then the workspace's
      // approval dial at Let it work, a workspace-wide trust that is
      // standing like a posture, so what a credential's own posture covers
      // is recorded as that, and the machine's mandate last, so a request
      // anything standing covers is never also a mandate use. At Let it
      // work, an approved grant that matches is still used, and where a new
      // ask would be opened the request is refused instead.
      const ruleable = held.policyApprove && !held.protectedUse
      const dial = approvalDial(ctx)
      const mode = req.run ? "placeholder" as const : "relay" as const
      if (ruleable) {
        const rule = coveringRule(ctx, principal, credential, held, mode, context)
        if (rule !== null) {
          ruled.push(rule)
          return true
        }
        const grant = coveringAreaGrant(ctx, principal, credential, held, mode, context)
        if (grant !== null) {
          granted.push(grant)
          return true
        }
        const posture = coveringPosture(ctx, principal, credential, held)
        if (posture !== null) {
          postured.set(credential.slug, { use: posture, held })
          return true
        }
        const dialUse = coveringDial(ctx, principal, credential, held)
        if (dialUse !== null) {
          dialed.set(credential.slug, dialUse)
          return true
        }
        if (coveringMandate(ctx, principal, credential, held, reservation, { plan: plan !== null, shape: heldRequestShape(credential.id, held), ...(plan ? { planned: plan.planned } : {}) })) return true
      }
      // Only a cap kept the mandate from covering it: the ask says which.
      const capped = ruleable ? reservation.capped : null
      // A relay stops at its first held item, so a planned request asks once too.
      if (plan?.asked) return true
      // PROJECTS binds only its structural credential projection, not mutable
      // last-use metadata or fields irrelevant to the exact request subject.
      const projection = { id: credential.id, slug: credential.slug, home: credential.home, configRevision:credential.configRev }
      // A run's held request is asked as one by item, in the mode the run
      // uses the credential: a placeholder-only workload holds no relay mode.
      const batch = { floor: heldRequestFloor(held), shape: heldRequestShape(credential.id, held), replaces: req.replaces ?? null, ...(plan ? { bundle: plan.bundle } : {}) }
      const askedFrom = ctx.now()
      const noAsk = dial === "work" ? { noAsk: () => dialRefusal(ctx, principal, credential, held, invocation.workspace.slug, req.run ?? null) } : {}
      const approved = prepareApprovedUse(guarded, accessState(ctx), { principal, workspace: invocation.workspace, presentation, mode: req.run ? "placeholder" : "relay", batch, ...noAsk }, projection, context ? { project: context.project, env: context.environment } : null, subject, req.approval ?? null, ctx.now())
      if (approved.kind === "required") {
        // The binding code, expiry and wait command a machine shows beside the link, as a protected run's ask carries them.
        // No command for a workload: mehen wait signs with the device's key, which cannot see a workload's approval.
        const asked = workspaceApproval(ctx, approved.approvalId)
        if (!asked) throw new VaultError("not_found", "No such approval.")
        // The bytes a rule made from this approval is built from.
        if (ruleable && !managed && policyRulesOn(ctx.env, ctx.tenant)) storeRuleAnchor(ctx, principal, credential, asked.id, held)
        // Counted once per ask: a resend finds the pending one it opened.
        if (ruleable && asked.created_at >= askedFrom) countPostureAsk(ctx, principal, credential, held)
        // Only for the machine itself, never beside a cap's line.
        const cover = ruleable && !managed && !capped ? mandateCoverHint(ctx, principal, credential, held, invocation.workspace.slug) : null
        if (cover && asked.created_at >= askedFrom) recordMandateCoverAsk(ctx, asked.id, principal.deviceId, credential.id, cover)
        if (plan) {
          plan.asked = asked
          plan.cover = cover
          return true
        }
        if (capped && asked.created_at >= askedFrom) recordMandateCappedAsk(ctx, asked.id, capped)
        if (managed) throw new VaultError("approval_required", "This request needs approval.", { approval: approved.approvalId, bindingCode: asked.binding_code, expiresAt: new Date(asked.expires_at).toISOString(), deciders: [], next: { say: "The platform decides this request." } })
        throw new VaultError("approval_required", "This request needs a human's approval.", { approval: approved.approvalId, bindingCode: asked.binding_code, expiresAt: new Date(asked.expires_at).toISOString(), deciders: approved.deciders, next: { url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/a/${approved.approvalId}`, ...(principal.workload === undefined ? { command: `mehen wait ${approved.approvalId}` } : {}), say: approved.deciders.length ? `Send this link to ${approved.deciders.join(" or ")}.` : "Send this link to a manager of the project, or open Needs you in the workspace." }, ...askGroupExtra(ctx, principal, invocation, asked), ...(capped ? { mandate: capped } : {}), ...(cover ? { mandateCover: cover } : {}) })
      }
      approvals.push({ snapshot: approved.snapshot, approval: approved.approvalId })
      if (plan) plan.granted = approved.approvalId
      return true
    },
    async secrets(item) {
      const credential = checked.get(item.slug)
      if (!credential)
        throw new VaultError("not_found", "No such credential.")
      if (item.kind !== "oauth-connection") return { secrets: await openCredentialSecrets(ctx, credential), item: credential }
      const { accessToken, item: refreshed } = await workspaceTokenRead(ctx, credential)
      if (!refreshed || refreshed.id !== credential.id || refreshed.configRev !== credential.configRev || canonicalJson(refreshed.home) !== canonicalJson(credential.home))
        throw new VaultError("conflict", "The credential changed; review and try again.")
      checked.set(item.slug, refreshed)
      return { secrets: { access_token: accessToken }, item: refreshed }
    },
    settle() {
      settleBeforeMandateUse(ctx, reservation)
    },
    assertCurrent() {
      const current = accessState(ctx)
      for (const item of checked.values()) {
        visibleCredential(ctx, principal, item.slug, { context, mode: req.run ? "placeholder" : "relay" })
        assertCredentialCurrent(ctx, item)
        authorise(ctx, invocation, { type: "item.use", context }, { credential: item.id, mode: req.run ? "placeholder" : "relay" }, ctx.now())
      }
      for (const approval of approvals)
        assertApprovedUse(ctx, current, approval.snapshot, approval.approval, ctx.now())
      for (const rule of ruled)
        assertRuleCurrent(ctx, rule)
      for (const grant of granted)
        assertAreaGrantCurrent(ctx, grant.id)
      for (const [slug, { use }] of postured)
        assertPostureCurrent(ctx, principal, checked.get(slug) as CheckedCredential, use)
      for (const [slug, use] of dialed)
        assertDialCurrent(ctx, principal, checked.get(slug) as CheckedCredential, use)
      assertMandateCurrent(ctx, reservation, (slug) => checked.get(slug) as CheckedCredential)
      if(req.run){
        const live=assertRunUse(ctx,current,req.run,principal,ctx.now())
        if(canonicalJson(live.snapshot)!==canonicalJson(runSnapshot))throw new VaultError("forbidden","The run authorisation is no longer current.")
        relayServices.placeholdersFor(ctx,legacy,req.run)
      }
    },
    consume() {
      for (const approval of approvals)
        consumeApprovedUse(ctx, approval.snapshot, approval.approval)
      for (const rule of ruled)
        recordRuleUse(ctx, rule, req.run ?? null)
      for (const grant of granted)
        recordAreaGrantUse(ctx, grant, req.run ?? null)
      for (const [slug, { use, held }] of postured)
        recordPostureUse(ctx, principal, checked.get(slug) as CheckedCredential, use, held, req.run ?? null)
      for (const [slug, use] of dialed)
        recordDialUse(ctx, principal, checked.get(slug) as CheckedCredential, use, req.run ?? null)
      recordMandateUse(ctx, principal, reservation, req.run ?? null)
      for (const item of checked.values())
        ctx.sql.exec("UPDATE items SET last_used_at=? WHERE id=?", ctx.now(), item.id)
      auditContext = [...checked.values()].map(item => ({ item: { id: item.id, slug: item.slug, home: item.home }, device: device.id, owner: device.owner.kind === "member" ? { kind: "member", member: device.owner.id } : { kind: "team", team: device.owner.id }, session: null, run:req.run??null, ...(workload ? { workload: { id: workload.id, label: workload.label } } : {}) }))
    },
    ...(plan ? { plan: true } : {}),
  })
  // Mehen-Rule names a task grant as it names a rule, but only to a mehen
  // that reads grants: to an older one or one of unknown version a grant
  // does not exist, so the answer is as if nothing standing allowed it.
  if (plan && !plan.asked) addMandatePlanned(plan.planned, reservation)
  const allowedBy = [...ruled, ...(readsGrants(principal, invocation) ? granted.map((g) => g.id) : [])]
  const postures = [...new Set([...postured.values()].map(({ use }) => use.level))]
  return { ...material, workspaceAudit: auditContext, ...(allowedBy.length ? { rules: allowedBy } : {}), ...(postures.length ? { postures } : {}), ...(reservation.mandate !== null ? { mandate: reservation.mandate } : {}) }
}
const Echo = z.object({ items: z.array(z.string()).max(16), host: z.string().max(253), workspaceAudit: z.array(z.object({ item: z.object({ id: z.string(), slug: z.string(), home: CredentialHomeSchema }), device: z.string(), owner: ShareSubjectSchema, session: z.string().nullable(), run:z.string().nullable(), workload: z.object({ id: z.string().max(80), label: z.string().max(120) }).optional() })).max(16) })

function bundlesUnavailable(): VaultError {
  return new VaultError("forbidden", "Asking for several requests at once is not available yet.")
}

// approvals.bundle: an agent's plan of up to APPROVAL_BUNDLE_MAX requests,
// each run through the relay in plan mode. A held one becomes an ask in the
// bundle; one a policy, a standing rule or an approved grant already lets
// through is reported allowed; a refusal is that request's alone. The room
// for every request is checked before anything is created.
async function createApprovalBundle(ctx: VaultContext, principal: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<ApprovalBundleCreated> {
  if (principal.kind !== "device" || invocation.auth.kind !== "device") throw new VaultError("forbidden", "Only an enrolled device can ask for a bundle.")
  const input = parseOpInput(ApprovalBundleCreate, raw)
  if (!batchesHere(ctx)) throw bundlesUnavailable()
  authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
  if (setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
  const now = ctx.now(), count = input.requests.length
  const open = openAskCount(ctx, principal.deviceId, now)
  // Never a count of open asks: the machine's takes in asks a workload cannot
  // see, and a workload's own takes in asks it may no longer see.
  if (open + count > MACHINE_MAX_OPEN_ASKS) throw machineAsksFull(ctx, { device: principal.deviceId, ...(principal.workload !== undefined ? { workload: principal.workload } : {}) }, invocation.workspace.slug, `This machine's open asks and these ${count} requests would pass its 20. Settle some, or send fewer at once.`)
  if (principal.workload !== undefined && openWorkloadAskCount(ctx, principal.workload, now) + count > WORKLOAD_MAX_OPEN_ASKS) throw new VaultError("rate_limited", `This task's workload's open asks and these ${count} requests would pass its own limit of ${WORKLOAD_MAX_OPEN_ASKS}. Settle some, or send fewer at once.`)
  const bundle = randomId("bnd"), expiresAt = now + 3_600_000, code = bindingCode()
  ctx.sql.exec("INSERT INTO approval_bundles(id,device,workload,reason,created_at,expires_at,code) VALUES (?,?,?,?,?,?,?)", bundle, principal.deviceId, principal.workload ?? null, input.reason ?? null, now, expiresAt, code)
  const results: ApprovalBundleCreated["results"] = []
  // The workspace's row counts only the requests its audit already shows.
  const shown: ApprovalBundleCreated["results"] = []
  const planned = newMandatePlanned()
  for (const [index, request] of input.requests.entries()) {
    const plan: RelayPlan = { bundle, asked: null, cover: null, granted: null, private: false, planned }
    let result: ApprovalBundleCreated["results"][number]
    try {
      await workspaceRelay(ctx, principal, request, invocation, plan)
      result = plan.asked ? { index, outcome: "ask", approval: plan.asked.id, bindingCode: plan.asked.binding_code, ...(plan.cover ? { mandateCover: plan.cover } : {}) } : { index, outcome: "allowed", ...(plan.granted ? { approval: plan.granted } : {}) }
    } catch (error) {
      if (!(error instanceof VaultError)) throw error
      result = { index, outcome: "refused", error: { error: error.code, message: error.message, ...(error.extra.next ? { next: error.extra.next } : {}), ...(error.extra.dialRefused ? { dialRefused: error.extra.dialRefused } : {}) } }
    }
    results.push(result)
    if (!plan.private) shown.push(result)
  }
  const tally = (outcome: ApprovalBundleOutcome) => shown.filter((r) => r.outcome === outcome).length
  if (shown.length) ctx.audit({ actor: `device:${principal.deviceId}`, action: "approval.bundle", target: bundle, detail: { requests: shown.length, asked: tally("ask"), allowed: tally("allowed"), refused: tally("refused") } })
  return { bundle, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/g/${bundle}`, expiresAt: new Date(expiresAt).toISOString(), code, results }
}

// approvals.bundle_status: the bundle's asks, oldest first, read only by the
// device and workload that asked for it. An ask the machine can no longer
// see reads stale, as access changed.
async function approvalBundleStatus(ctx: VaultContext, principal: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<ApprovalBundleStatus> {
  if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
  const { id, wait } = parseOpInput(z.strictObject({ id: z.string().max(64), wait: z.boolean().default(false) }), raw)
  if (!batchesHere(ctx)) throw bundlesUnavailable()
  const read = () => {
    authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
    const row = one(ctx.sql.exec<{ device: string; workload: string | null; expires_at: number }>("SELECT device,workload,expires_at FROM approval_bundles WHERE id=?", id))
    if (!row || row.device !== principal.deviceId || row.workload !== (principal.workload ?? null)) throw new VaultError("not_found", "No such object.")
    const state = accessState(ctx)
    const statusOf = (approval: WorkspaceApprovalRow): ApprovalStatus["status"] => {
      if (!deviceSeesAsk(state, principal, JSON.parse(approval.ask) as AccessAsk, ctx.now())) return "stale"
      const status = workspaceApprovalStatus(ctx, approval)
      return status === "ended" ? "expired" : status
    }
    const approvals = ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE bundle=? AND ask IS NOT NULL AND device=? AND workload IS ? ORDER BY created_at,id", id, row.device, row.workload).toArray().map((approval) => ({ id: approval.id, status: statusOf(approval) }))
    return { expiresAt: row.expires_at, approvals }
  }
  let current = read()
  const deadline = ctx.now() + Math.min(25_000, Math.max(0, current.expiresAt - ctx.now()))
  while (wait && current.approvals.some((a) => a.status === "pending") && ctx.now() < deadline) {
    await waitForStorageWrite(ctx.storage, deadline - ctx.now())
    current = read()
  }
  return { bundle: id, approvals: current.approvals }
}

export const workspaceRelayOps: NonNullable<import("../core.ts").Area["workspaceOps"]> = {
  ...credentialOps({ "relay.authorise": { auth: ["device"], handler: authoriseWorkspaceRelay } }),
  ...credentialOps({ "approvals.bundle": { auth: ["device"], handler: createApprovalBundle }, "approvals.bundle_status": { auth: ["device"], handler: approvalBundleStatus } }),
  "relay.echo": { auth: ["system"], handler(ctx, _principal, input) {
      const event = Echo.parse(input)
      return ctx.storage.transactionSync(() => {
        for (const slug of event.items) {
          const captured = event.workspaceAudit.find(c => c.item.slug === slug)
          if (!captured)
            throw new VaultError("bad_request", "Missing relay audit context.")
          if (captured.item.home.kind === "member")
            auditPrivateEvent(ctx, { action: "relay.echo", at: ctx.now(), actor: { kind: "device", device: captured.device, owner: captured.owner, ...(captured.workload ? { workload: captured.workload } : {}) }, session: captured.session, item: captured.item.id, slug, outcome: "scrubbed", run: captured.run }, captured.item.home.member)
          else
            ctx.audit({ actor: `device:${captured.device}`, action: "relay.echo", target: slug, detail: { host: event.host, ...(captured.workload ? { by: { workload: captured.workload } } : {}) } })
          if (items.getItem(ctx, slug)?.id === captured.item.id)
            items.flagForReview(ctx, slug, captured.item.home.kind === "member" ? "The provider echoed this credential; the vault removed it." : `${event.host} echoed this credential; the vault removed it.`)
        }
        return { recorded: event.items.length }
      })
    } },
}
