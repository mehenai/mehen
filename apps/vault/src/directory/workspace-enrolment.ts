import { canonicalJson,EnrolRequestedScopeSchema,type EnrolRequestedScope } from "@mehen/protocol"
import { bodyHash,EnrolOwnerIntentSchema,fingerprintGroupIndex,fingerprintOf, importDeviceKey, isDeviceJwk, jwkThumbprint, OwnerRefSchema, parseProof, PROOF_MAX_SKEW_SECONDS, verifyProof, WorkspaceDeviceScopeSchema, EnrolEvidenceSchema, WorkspaceEnrolStartSchema, type EnrolExpiredReason, type EnrolRenewResponse, type WorkspaceEnrolStatus, type WorkspaceRef } from "@mehen/protocol"
import type { z } from "zod"
import { EnrolRegisterInput,EnrolReconcileOutputSchema,type InboxEnrolCandidate } from "../vault/areas/workspace-runtime.ts"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { proofRefusal,replayRefusal } from "../vault/areas/devices.ts"
import { randomId } from "../vault/core.ts"
import { refuseFillUntilShipped } from "../vault/fill-unavailable.ts"
import { scopeForCli } from "../vault/fill-old-cli.ts"
import { cliVersionOf } from "../cli-version.ts"
import { accountBatch,accountGuard } from "./account-store.ts"
import { ENROLMENT_MAX_LIFE_MS,ENROLMENT_RENEW_INTERVAL_MS,ENROLMENT_TTL_MS,GROUP_ATTEMPTS_ALLOWED,UNREACHED_ENROLMENT,enrolmentCode,enrolmentLease,normaliseCode,type EnrolmentRow } from "./enrolment.ts"
import { clientLabel,placeOf,sha256Text } from "./session.ts"
import { connectCodeClaim } from "./connect-code.ts"
export type WorkspaceEnrolmentRow = EnrolmentRow & { code_hash: string; workspace_intent: string; owner_intent: string; start_at: number; start_place: string | null; start_client_label: string; pending_state: "pending_owner_acceptance" | "pending_admission" | null; resolved_owner: string | null; accepted_by_account: string | null; discard_pending: number; discard_device: string | null; mirror_acknowledged: number; reconciled_at: number | null; hard_expires_at: number | null; renewed_at: number | null; renewals: number; expired_reason: Exclude<EnrolExpiredReason,"legacy"> | null; hidden_group: 0 | 1 | 2 | 3 | null; start_session: string | null; claimed_account: string | null; requested_scope: string | null }
async function pendingProof(env: Env,request: Request,body: Uint8Array<ArrayBuffer>,jwk: unknown,thumbprint: string,device: string,now: number): Promise<ReturnType<typeof parseProof>["claims"]> {
  if (!isDeviceJwk(jwk)) throw new VaultError("bad_request","The key must be a P-256 public JWK.")
  const header = request.headers.get("Mehen-Proof")
  if (!header) throw new VaultError("unauthenticated","Missing Mehen-Proof. Enrol with `mehen enrol`, which signs with the new key.")
  let proof: ReturnType<typeof parseProof>
  try { proof = parseProof(header) } catch { throw new VaultError("proof_invalid","The Mehen-Proof header is malformed.") }
  // Enrolment and its polls predate workloads: a key enrols only as itself.
  if (proof.claims.wkl !== undefined) throw new VaultError("unauthenticated","A workload cannot enrol or poll an enrolment. Sign with the enrolling machine's own key.")
  if (proof.claims.ten !== "enrol" || proof.claims.dev !== device) throw new VaultError("proof_invalid",`An enrolment proof must carry ten "enrol" and dev "${device}".`)
  const verified = await verifyProof(proof,await importDeviceKey(jwk),{ method: request.method,url: request.url,bodyHash: await bodyHash(body),now })
  if (!verified.ok) throw proofRefusal(verified.reason)
  const result = await env.DB.prepare("INSERT INTO enrol_nonces(id,expires_at) VALUES (?,?) ON CONFLICT DO NOTHING").bind(`${thumbprint}:${proof.claims.jti}`,(proof.claims.iat+PROOF_MAX_SKEW_SECONDS+1)*1000).run()
  if (result.meta.changes !== 1) throw replayRefusal()
  return proof.claims
}
// The scope an enrolment registers with: the usual one, narrowed by what the
// machine asked for. Tags and projects as given; modes the intersection with
// the usual modes, so never lease; workloads as given. A request can only
// narrow: whatever it names outside the usual scope is simply not there.
// Private credentials are the acceptor's tick, hidden when it asked for none.
export const USUAL_ENROL_MODES = ["relay","sign","mint","placeholder"] as const
export function requestedEnrolScope(requested: EnrolRequestedScope | undefined): z.infer<typeof EnrolRegisterInput>["scope"] {
  refuseFillUntilShipped(requested?.modes ?? [])
  const modes = USUAL_ENROL_MODES.filter((mode) => requested?.modes === undefined || requested.modes.includes(mode))
  if (modes.length === 0) throw new VaultError("bad_request","scope.modes: a machine can ask only for relay, sign, mint or placeholder.")
  return { tags: [...(requested?.tags ?? [])],projects: [...(requested?.projects ?? [])],modes,maxEnvironment: "unprotected",...(requested?.workloads ? { workloads: requested.workloads } : {}) }
}
export async function startWorkspaceEnrolment(env: Env,request: Request,raw: Uint8Array<ArrayBuffer>,input: z.infer<typeof WorkspaceEnrolStartSchema>,now = Date.now()) {
  if (!isDeviceJwk(input.jwk)) throw new VaultError("bad_request","The key must be a P-256 public JWK.")
  requestedEnrolScope(input.scope)
  const thumbprint = await jwkThumbprint(input.jwk)
  const claims = await pendingProof(env,request,raw,input.jwk,thumbprint,"new",now)
  // A connect code claims the attempt for one account, once and for ever. A
  // refused code inserts nothing.
  const claimedAccount = input.connect === undefined ? null : await connectCodeClaim(env,request,input.connect,input.workspace,now)
  const enrolment = randomId("enr"),expiresAt = now+ENROLMENT_TTL_MS,hardExpiresAt = now+ENROLMENT_MAX_LIFE_MS,code = enrolmentCode()
  // The hidden group is chosen once, from the code, so the code page, the id
  // page and the CLI's "the page hides the nth group" line always agree.
  const hiddenGroup = await fingerprintGroupIndex(code)
  await accountBatch(env,[
    env.DB.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='superseded' WHERE thumbprint=? AND status='pending'").bind(thumbprint),
    env.DB.prepare(`INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,host,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_place,start_client_label,pending_state,hard_expires_at,hidden_group,start_session,claimed_account,requested_scope)
      VALUES (?,?,?,?,?,?,?,'pending',?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(enrolment,await sha256Text(code),JSON.stringify(input.jwk),thumbprint,input.name,input.backend,input.host ?? null,now,expiresAt,input.workspace,JSON.stringify(input.owner),now,placeOf(request),clientLabel(request.headers.get("user-agent")),input.owner.kind === "team" ? "pending_admission" : "pending_owner_acceptance",hardExpiresAt,hiddenGroup,claims.sid?.slice(0,120) ?? null,claimedAccount,input.scope ? canonicalJson(input.scope) : null),
  ])
  // Never resolve the workspace or team for an unauthenticated starting key.
  return { enrolment,code,url: `${env.VAULT_ORIGIN}/w/${input.workspace}/e/${code}`,fingerprint: fingerprintOf(thumbprint),expiresAt: new Date(expiresAt).toISOString(),hardExpiresAt: new Date(hardExpiresAt).toISOString() }
}
// The fixed terms a D1 row registers into its workspace with: the same input
// whether the page registers it or a view is built from the row alone.
export function enrolRegistration(row: WorkspaceEnrolmentRow): z.infer<typeof EnrolRegisterInput> {
  const jwk: unknown = JSON.parse(row.jwk)
  if (!isDeviceJwk(jwk)) throw new Error("Invalid stored enrolment key")
  const requested = row.requested_scope === null ? undefined : EnrolRequestedScopeSchema.parse(JSON.parse(row.requested_scope))
  return EnrolRegisterInput.parse({ enrolment: row.id,thumbprint: row.thumbprint,start: { at: new Date(row.start_at).toISOString(),place: row.start_place,clientLabel: row.start_client_label },requestedOwner: EnrolOwnerIntentSchema.parse(JSON.parse(row.owner_intent)),scope: requestedEnrolScope(requested),...(requested ? { requested } : {}),claimedAccount: row.claimed_account,detail: { name: row.name,backend: row.backend,host: row.host,jwk,codeHash: row.code_hash,hardExpiresAt: new Date(row.hard_expires_at ?? row.expires_at).toISOString() } })
}
export async function workspaceEnrolmentByCode(env: Env,workspace: WorkspaceRef,input: string): Promise<{ code: string; row: WorkspaceEnrolmentRow }> {
  const code = normaliseCode(input),row = code ? await env.DB.prepare(`SELECT e.* FROM enrolments e JOIN workspaces w ON w.id=? WHERE e.code_hash=? AND w.status='active' AND
    (e.workspace_intent=w.slug OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=e.workspace_intent)) AND (e.tenant IS NULL OR e.tenant=w.id) AND e.discard_pending=0`).bind(workspace.id,await sha256Text(code)).first<WorkspaceEnrolmentRow>() : null
  if (!row || !code) throw new VaultError("not_found","No such enrolment.")
  return { code,row }
}
export const ENROLMENT_ID = /^enr_[A-Za-z0-9_-]{1,64}$/
// The id form: the same workspace predicate as the code form, at any status.
// A row from before 0008 has no persisted hidden group and no id page.
export async function workspaceEnrolmentById(env: Env,workspace: WorkspaceRef,id: string): Promise<WorkspaceEnrolmentRow> {
  const row = ENROLMENT_ID.test(id) ? await env.DB.prepare(`SELECT e.* FROM enrolments e JOIN workspaces w ON w.id=? WHERE e.id=? AND w.status='active' AND
    (e.workspace_intent=w.slug OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=e.workspace_intent)) AND (e.tenant IS NULL OR e.tenant=w.id) AND e.discard_pending=0 AND e.hidden_group IS NOT NULL`).bind(workspace.id,id).first<WorkspaceEnrolmentRow>() : null
  if (!row) throw new VaultError("not_found","No such enrolment.")
  return row
}
// What the workspace's own evaluator decides visibility from.
export async function enrolCandidate(env: Env,row: WorkspaceEnrolmentRow,now = Date.now()): Promise<InboxEnrolCandidate> {
  const claimed = row.claimed_account === null ? null : await env.DB.prepare("SELECT name FROM accounts WHERE id=?").bind(row.claimed_account).first<{ name: string }>()
  return enrolCandidateOf(row,claimed?.name ?? null,now)
}
// The same candidate from a row whose claimed account's name was read with it.
export function enrolCandidateOf(row: WorkspaceEnrolmentRow,claimedName: string | null,now: number): InboxEnrolCandidate {
  return { enrolment: row.id,thumbprint: row.thumbprint,name: row.name,host: row.host,backend: row.backend,start: { at: new Date(row.start_at).toISOString(),place: row.start_place,clientLabel: row.start_client_label },session: row.start_session,requestedOwner: EnrolOwnerIntentSchema.parse(JSON.parse(row.owner_intent)),claimedAccount: row.claimed_account,claimedName,status: row.status,pendingState: row.pending_state,lease: enrolmentLease(row,now),acceptedByAccount: row.accepted_by_account,expiresAt: new Date(row.expires_at).toISOString(),hardExpiresAt: new Date(row.hard_expires_at ?? row.expires_at).toISOString(),hiddenGroup: row.hidden_group }
}
// What a poll or renewal answers for an enr_ id with no row: maintenance
// prunes settled attempts, and ids are random, so the settled answer an
// expired attempt gets reveals nothing and lets its machine start afresh.
const PRUNED_ENROLMENT: WorkspaceEnrolStatus = { status: "expired",reason: "hard_cap" }
const prunedRenewRefusal = (enrolment: string) => {
  if (!ENROLMENT_ID.test(enrolment)) return new VaultError("not_found","No such enrolment.")
  return new VaultError("conflict","This enrolment can no longer be renewed.",{ enrolment: PRUNED_ENROLMENT })
}
export async function workspaceEnrolmentStatus(env: Env,request: Request,enrolment: string,now = Date.now()): Promise<WorkspaceEnrolStatus> {
  const row = await env.DB.prepare("SELECT * FROM enrolments WHERE id=? AND workspace_intent IS NOT NULL").bind(enrolment).first<WorkspaceEnrolmentRow>()
  if (!row) {
    if (ENROLMENT_ID.test(enrolment)) return PRUNED_ENROLMENT
    throw new VaultError("not_found","No such enrolment.")
  }
  await pendingProof(env,request,new Uint8Array(),JSON.parse(row.jwk) as unknown,row.thumbprint,row.id,now)
  // Reload after verification and nonce persistence, not the entry snapshot.
  const live = await env.DB.prepare("SELECT * FROM enrolments WHERE id=?").bind(enrolment).first<WorkspaceEnrolmentRow>()
  if (!live) return PRUNED_ENROLMENT
  const status = await enrolmentStatusOf(env,live,now)
  return status.status === "active" ? { ...status,scope: scopeForCli(status.scope,cliVersionOf(request.headers.get("user-agent"))) } : status
}
// Why a terminal attempt ended. NULL on a row expired before 0008 is legacy.
export function expiredReason(row: WorkspaceEnrolmentRow): EnrolExpiredReason {
  if (row.discard_pending) return "discarded"
  if (row.status === "expired") return row.expired_reason ?? "legacy"
  return "hard_cap"
}
// What a poll answers for this row now: a lapsed lease is still pending,
// with expiresAt in the past; only the terminal states settle.
async function enrolmentStatusOf(env: Env,live: WorkspaceEnrolmentRow,now: number): Promise<WorkspaceEnrolStatus> {
  if (live.status === "rejected") return { status: "rejected" }
  if (live.status !== "active" && enrolmentLease(live,now) === "terminal") return { status: "expired",reason: expiredReason(live) }
  if (live.status === "active" && live.tenant && live.device && live.scope && live.resolved_owner) {
    const workspace = await env.DB.prepare("SELECT id,slug,name FROM workspaces WHERE id=? AND status='active'").bind(live.tenant).first<WorkspaceRef>()
    if (!workspace) throw new VaultError("not_found","No such enrolment.")
    return { status: "active",tenant: live.tenant,workspace,device: live.device,scope: WorkspaceDeviceScopeSchema.parse(JSON.parse(live.scope)),owner: OwnerRefSchema.parse(JSON.parse(live.resolved_owner)) }
  }
  return { status: live.pending_state ?? "pending_owner_acceptance",expiresAt: new Date(live.expires_at).toISOString(),hardExpiresAt: new Date(live.hard_expires_at ?? live.expires_at).toISOString() }
}
// POST /v1/enrol/:id/renew: the same id, code and link, a fresh lease up to
// the hard cap. Proof exactly as the poll. Renewal never touches the typed
// group counter and never reaches the workspace's own copy of the terms.
export async function renewWorkspaceEnrolment(env: Env,request: Request,enrolment: string,now = Date.now()): Promise<EnrolRenewResponse> {
  const row = await env.DB.prepare("SELECT * FROM enrolments WHERE id=? AND workspace_intent IS NOT NULL").bind(enrolment).first<WorkspaceEnrolmentRow>()
  if (!row) throw prunedRenewRefusal(enrolment)
  await pendingProof(env,request,new Uint8Array(),JSON.parse(row.jwk) as unknown,row.thumbprint,row.id,now)
  const renewed = await env.DB.prepare(`UPDATE enrolments SET expires_at=MIN(?+?,hard_expires_at),renewed_at=?,renewals=renewals+1
    WHERE id=? AND status='pending' AND discard_pending=0 AND group_attempts<? AND hard_expires_at>?
      AND (renewed_at IS NULL OR renewed_at<=?) RETURNING expires_at,hard_expires_at`)
    .bind(now,ENROLMENT_TTL_MS,now,row.id,GROUP_ATTEMPTS_ALLOWED,now,now-ENROLMENT_RENEW_INTERVAL_MS).first<{ expires_at: number; hard_expires_at: number }>()
  if (renewed) return { enrolment: row.id,expiresAt: new Date(renewed.expires_at).toISOString(),hardExpiresAt: new Date(renewed.hard_expires_at).toISOString() }
  const live = await env.DB.prepare("SELECT * FROM enrolments WHERE id=?").bind(enrolment).first<WorkspaceEnrolmentRow>()
  if (!live) throw prunedRenewRefusal(enrolment)
  if (live.status === "pending" && enrolmentLease(live,now) !== "terminal") {
    throw new VaultError("conflict","This enrolment was renewed less than a minute ago; keep waiting.",{ retryAfter: Math.max(1,Math.ceil(((live.renewed_at ?? now)+ENROLMENT_RENEW_INTERVAL_MS-now)/1000)) })
  }
  // Settled: the same answer a poll gives, so the CLI needs no second poll.
  throw new VaultError("conflict","This enrolment can no longer be renewed.",{ enrolment: await enrolmentStatusOf(env,live,now) })
}
export type EnrolMirrorClient = {
  mirrored(workspace: string,enrolment: string,device: string): Promise<void>
  expire(workspace: string,enrolment: string): Promise<{ expired: boolean }>
  discard(workspace: string,enrolment: string,device: string): Promise<void>
  reconcile(workspace: string,enrolment: string): Promise<z.infer<typeof EnrolReconcileOutputSchema>>
}
export async function mirrorActiveEnrolment(env: Env,row: WorkspaceEnrolmentRow,workspace: WorkspaceRef,result: { device: string; scope: z.infer<typeof WorkspaceDeviceScopeSchema>; owner: z.infer<typeof OwnerRefSchema>; acceptance?: z.infer<typeof EnrolEvidenceSchema> | null; admission?: z.infer<typeof EnrolEvidenceSchema> | null },client: EnrolMirrorClient,now = Date.now()): Promise<void> {
  try {
    await accountBatch(env,[
      accountGuard(env,"EXISTS (SELECT 1 FROM enrolments WHERE id=? AND code_hash=? AND discard_pending=0 AND ((status='pending' AND expires_at>? AND group_attempts<=5) OR (status='active' AND tenant=? AND device=?)))",[row.id,row.code_hash,now,workspace.id,result.device]),
      env.DB.prepare("UPDATE enrolments SET status='active',pending_state=NULL,tenant=?,device=?,scope=?,resolved_owner=?,acceptance_digest=?,accepted_by_account=?,accepted_by_member=?,accepted_at=?,admission_digest=?,admitted_by_account=?,admitted_at=? WHERE id=?")
        .bind(workspace.id,result.device,JSON.stringify(result.scope),JSON.stringify(result.owner),result.acceptance?.digest ?? null,result.acceptance?.account ?? null,result.acceptance?.member ?? null,result.acceptance ? Date.parse(result.acceptance.at) : null,result.admission?.digest ?? null,result.admission?.account ?? null,result.admission ? Date.parse(result.admission.at) : null,row.id),
    ])
  } catch (error) {
    await env.DB.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='discarded',discard_pending=1,discard_device=?,tenant=? WHERE id=? AND status!='active'").bind(result.device,workspace.id,row.id).run()
    throw error
  }
  try { await client.mirrored(workspace.id,row.id,result.device); await env.DB.prepare("UPDATE enrolments SET mirror_acknowledged=1 WHERE id=? AND status='active' AND device=?").bind(row.id,result.device).run() } catch { console.error(JSON.stringify({ at: "enrol.mirror_ack.pending",enrolment: row.id })) }
}
// Each queue of the source reconcile reads this many rows at a time. The
// settled queue reads up to RECONCILE_SETTLED_BATCHES of them a run,
// stopping at a short one: at most 200 rows a run, 19,200 a day at one run
// every 15 minutes. The pending window takes one batch a run.
const RECONCILE_BATCH = 50
const RECONCILE_SETTLED_BATCHES = 4
// The cron's period: each run moves the pending window on by one batch.
const RECONCILE_WINDOW_MS = 900_000
export async function reconcileEnrolmentMirrors(env: Env,client: EnrolMirrorClient,now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare("SELECT id,tenant,device,status,discard_pending,discard_device FROM enrolments WHERE discard_pending=1 OR (status='active' AND mirror_acknowledged=0) ORDER BY created_at LIMIT 100").all<{ id: string; tenant: string | null; device: string | null; status: string; discard_pending: number; discard_device: string | null }>()
  for (const row of rows.results) {
    if (!row.tenant) continue
    try {
      if (row.discard_pending && row.discard_device) {
        await client.discard(row.tenant,row.id,row.discard_device)
        await env.DB.prepare("UPDATE enrolments SET discard_pending=0,reconciled_at=? WHERE id=? AND discard_device=? AND status!='active'").bind(now,row.id,row.discard_device).run()
      } else if (row.status === "active" && row.device) {
        await client.mirrored(row.tenant,row.id,row.device)
        await env.DB.prepare("UPDATE enrolments SET mirror_acknowledged=1 WHERE id=? AND status='active' AND device=?").bind(row.id,row.device).run()
      }
    } catch { console.error(JSON.stringify({ at: "enrol.cleanup.pending",enrolment: row.id })) }
  }
  // Two queues, so neither starves the other. Rows D1 has settled drain
  // oldest first: each one leaves the scan once its source is told. Pending
  // rows, live or lapsed, may have nothing to do until their hard cap, so
  // they are visited in a window that moves every 15 minutes: a later source
  // whose reply was lost is reached behind any number of earlier starts. An
  // attempt that never reached a workspace is left to the prune, which takes
  // it at its hard cap without its source being told.
  const unclaimedFrom = `FROM enrolments e JOIN workspaces w
    ON (e.tenant=w.id OR e.tenant IS NULL AND (e.workspace_intent=w.slug OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=e.workspace_intent)))
    WHERE e.mirror_acknowledged=0 AND e.discard_pending=0 AND e.reconciled_at IS NULL AND NOT (${UNREACHED_ENROLMENT})`
  // Settled batches move on past the last row read, so a row that fails
  // stays for the next run without being read twice in this one.
  let after: [number,string,string] = [-1,"",""]
  for (let batch = 0; batch < RECONCILE_SETTLED_BATCHES; batch++) {
    const settled = await env.DB.prepare(`SELECT e.*,w.id AS workspace_id,w.slug AS workspace_slug,w.name AS workspace_name ${unclaimedFrom} AND e.status IN ('expired','rejected') AND (e.created_at,e.id,w.id)>(?,?,?) ORDER BY e.created_at,e.id,w.id LIMIT ?`)
      .bind(...after,RECONCILE_BATCH).all<UnclaimedRow>()
    for (const row of settled.results) await reconcileSource(env,client,row,now)
    const last = settled.results.at(-1)
    if (!last || settled.results.length < RECONCILE_BATCH) break
    after = [last.created_at,last.id,last.workspace_id]
  }
  const waiting = await env.DB.prepare(`SELECT COUNT(*) AS n ${unclaimedFrom} AND e.status='pending'`).first<{ n: number }>()
  const offset = (Math.floor(now / RECONCILE_WINDOW_MS) % Math.max(1,Math.ceil((waiting?.n ?? 0) / RECONCILE_BATCH))) * RECONCILE_BATCH
  const pending = await env.DB.prepare(`SELECT e.*,w.id AS workspace_id,w.slug AS workspace_slug,w.name AS workspace_name ${unclaimedFrom} AND e.status='pending' ORDER BY e.created_at,e.id LIMIT ? OFFSET ?`).bind(RECONCILE_BATCH,offset).all<UnclaimedRow>()
  for (const row of pending.results) await reconcileSource(env,client,row,now)
}
type UnclaimedRow = WorkspaceEnrolmentRow & { created_at: number; workspace_id: string; workspace_slug: string; workspace_name: string }
// One row's source, asked and settled; a failure is logged and the row stays.
async function reconcileSource(env: Env,client: EnrolMirrorClient,row: UnclaimedRow,now: number): Promise<void> {
  try {
    let source: z.infer<typeof EnrolReconcileOutputSchema>
    try { source = EnrolReconcileOutputSchema.parse(await client.reconcile(row.workspace_id,row.id)) } catch (error) {
      if (!(error instanceof VaultError) || error.code !== 'not_found') throw error
      source = { device: null,mirrored: false,state: 'pending_owner_acceptance',active: null }
    }
    if (source.device && source.active && !source.mirrored) {
      if (row.status === 'pending' && row.expires_at>now) await mirrorActiveEnrolment(env,row,{ id: row.workspace_id,slug: row.workspace_slug,name: row.workspace_name },{ device: source.device,...source.active },client,now)
      else {
        const queued = await env.DB.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason=CASE WHEN status='pending' THEN 'discarded' ELSE expired_reason END,tenant=?,discard_pending=1,discard_device=? WHERE id=? AND status!='active'").bind(row.workspace_id,source.device,row.id).run()
        if (queued.meta.changes === 1) {
          await client.discard(row.workspace_id,row.id,source.device)
          await env.DB.prepare("UPDATE enrolments SET discard_pending=0,reconciled_at=? WHERE id=? AND status!='active' AND discard_device=?").bind(now,row.id,source.device).run()
        }
      }
    } else if (!source.device && ((row.hard_expires_at ?? row.expires_at)<=now || row.status !== 'pending' || source.state === 'rejected' || source.state === 'expired')) {
      // Only the hard cap ends an attempt here: a lapsed lease stays
      // pending and renewable. A row already settled in D1 keeps its state.
      if (source.state !== 'rejected' && !(await client.expire(row.workspace_id,row.id)).expired) throw new Error("The source enrolment is not expired.")
      const settled = source.state === 'rejected' ? 'rejected' : 'expired',reason = source.state === 'rejected' || source.state === 'expired' ? 'source' : 'hard_cap'
      await env.DB.prepare("UPDATE enrolments SET status=CASE WHEN status='pending' THEN ? ELSE status END,expired_reason=CASE WHEN status='pending' AND ?='expired' THEN ? ELSE expired_reason END,pending_state=NULL,reconciled_at=? WHERE id=? AND status!='active'").bind(settled,settled,reason,now,row.id).run()
    }
  } catch { console.error(JSON.stringify({ at: "enrol.source_reconcile.pending",enrolment: row.id })) }
}

// The hidden group is the one persisted at start; a row from before 0008
// has none and only its code form can name it.
export async function checkWorkspaceTypedGroup(env: Env,code: string | null,row: WorkspaceEnrolmentRow,typed: string,now = Date.now()): Promise<import("./enrolment.ts").TypedGroup> {
  const { normaliseFingerprintGroup,fingerprintGroups,timingSafeEqualText } = await import("@mehen/protocol")
  const index = row.hidden_group ?? (code === null ? null : await fingerprintGroupIndex(code))
  if (index === null) throw new VaultError("conflict","This enrolment was already decided or has expired.")
  const normalised = normaliseFingerprintGroup(typed),hidden = fingerprintGroups(fingerprintOf(row.thumbprint))[index]
  const matches = normalised !== undefined && timingSafeEqualText(normalised,hidden)
  // Only a wrong group spends one of the five attempts. A correct one is
  // checked again by the browser's planning call and by the acceptance it
  // plans, and must never use up the budget the last guess left.
  const taken = await env.DB.prepare(`UPDATE enrolments SET group_attempts=group_attempts+?,
    status=CASE WHEN ?=1 AND group_attempts+1>=5 THEN 'rejected' ELSE status END,
    pending_state=CASE WHEN ?=1 AND group_attempts+1>=5 THEN NULL ELSE pending_state END
    WHERE id=? AND status='pending' AND expires_at>? AND group_attempts<5 AND discard_pending=0 RETURNING group_attempts,status,thumbprint`)
    .bind(matches ? 0 : 1,matches ? 0 : 1,matches ? 0 : 1,row.id,now).first<{ group_attempts: number; status: string; thumbprint: string }>()
  if (!taken) throw new VaultError("conflict","This enrolment was already decided or has expired.")
  if (matches && timingSafeEqualText(taken.thumbprint,row.thumbprint)) return { ok: true }
  if (taken.status === "rejected") return { ok: false,refusal: new VaultError("conflict","The hidden group was wrong 5 times, so this enrolment is rejected. Start a fresh enrolment on the machine.") }
  return { ok: false,refusal: new VaultError("forbidden",`That is not the hidden group of this key. Type it from the terminal: ${5-taken.group_attempts} attempts left before this enrolment is rejected.`) }
}
