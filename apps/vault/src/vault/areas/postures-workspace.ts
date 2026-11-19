// How careful a credential is (its posture), on top of its policy, and the
// home's nudge toward it. A posture is a record of its own (item_postures;
// no row reads as ask): setting one never touches the policy or config_rev,
// so standing rules outlive it. The relay asks coveringPosture after the
// standing rules, and only for a request the policy holds; policy-rules.ts
// (protocol) decides what a level covers. Behind POLICY_POSTURES
// (posturesOn); a managed workspace has none.

import { PostureSchema, type ItemDescriptionPosture, type PostureCatalogue, type PostureEligibleMachine, type PostureLevel, type WorkspaceItemPosture } from "@mehen/protocol"
import { itemPostureDigest, postureCatalogueFor, postureCovers, type PostureCoverage } from "@mehen/protocol/policy-rules"
import { Slug } from "@mehen/protocol/api"
import { z } from "zod"
import type { Env } from "../../env.ts"
import { VaultError } from "../../http.ts"
import { can, type AccessPrincipal, type AccessState } from "../access.ts"
import { one, rows, type VaultContext } from "../core.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { devicePolicyState } from "./devices.ts"
import { checkedCredential, credentialAudit, visibleCredential, type CheckedCredential } from "./items-workspace.ts"
import { parseOpInput } from "./items.ts"
import { anchorOf, managesHome, type HeldRequest } from "./policy-rules-workspace.ts"
import { projects } from "./projects.ts"
import { readableDevices } from "./workspace-devices.ts"
import { workloadRow } from "./workloads.ts"
import { accessState, authorise, eligibilityState, type AccessAllowed, managedSetting, requireStepUp, setting, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

const DAY_MS = 86_400_000
// The nudge reads seven days of counts; the sweep keeps eight.
const NUDGE_DAYS = 7
const COUNT_KEEP_DAYS = 8
const NUDGE_QUIET_MS = 7 * DAY_MS
const NUDGE_MAX = 3
const NUDGE_MIN_ASKED = 10
const NUDGE_MIN_ROUTINE = 5

// Whether postures are on in this workspace (its tn_ id), read as
// workspaceSwitchOn reads every switch.
export function posturesOn(env: Pick<Env, "POLICY_POSTURES">, workspace: string): boolean {
  return workspaceSwitchOn(env.POLICY_POSTURES, workspace)
}
const posturesHere = (ctx: VaultContext): boolean => posturesOn(ctx.env, ctx.tenant) && managedSetting(ctx) === null
function posturesAvailable(ctx: VaultContext): void {
  if (!posturesOn(ctx.env, ctx.tenant)) throw new VaultError("forbidden", "How careful a credential is cannot be set here yet.")
  if (managedSetting(ctx) !== null) throw new VaultError("forbidden", "The platform decides how careful each credential is.")
}
function postureChanged(): VaultError {
  return new VaultError("conflict", "How careful this credential is changed; review and try again.")
}

type PostureRow = { item_id: string; level: PostureLevel; machines: string | null; catalogue: string | null; catalogue_version: number | null; rev: number; set_by: string; set_at: number }
const storedRow = (ctx: VaultContext, item: string) => one(ctx.sql.exec<PostureRow>("SELECT * FROM item_postures WHERE item_id=?", item))
const machinesOf = (row: PostureRow | null): string[] | null => (row?.machines ? (JSON.parse(row.machines) as string[]) : null)
const signedCatalogue = (row: PostureRow): PostureCatalogue | null => (row.catalogue !== null && row.catalogue_version !== null ? { template: row.catalogue, version: row.catalogue_version } : null)

// Puts the credential back to ask, as a rehome or a managed workspace does,
// with the rev moved on so a page that read the old posture is refused.
// The level or reason is each row's outcome, all a private row keeps.
function resetPosture(ctx: VaultContext, principal: AccessPrincipal | null, item: CheckedCredential, reason: "rehome" | "managed"): void {
  const row = storedRow(ctx, item.id)
  if (!row || row.level === "ask") return
  ctx.sql.exec("UPDATE item_postures SET level='ask',machines=NULL,catalogue=NULL,catalogue_version=NULL,rev=rev+1,set_by='system',set_at=? WHERE item_id=?", ctx.now(), item.id)
  const detail = { reason, before: row.level }
  if (principal !== null) credentialAudit(ctx, principal, item, "posture.reset", reason, detail)
  // The vault's own reset is a system row, as its other acts are; for a
  // private credential it keeps only the reason, as the owner's rows do.
  else ctx.audit({ actor: "system", action: "posture.reset", target: item.slug, detail: item.home.kind === "member" ? { item: item.id, outcome: reason } : { ...detail, item: item.id } })
}
// A rehomed credential starts again at ask: who may set it, and which
// machines trust reaches, follow the home.
export function resetPostureOnRehome(ctx: VaultContext, principal: AccessPrincipal, item: CheckedCredential): void {
  resetPosture(ctx, principal, item, "rehome")
}
// The posture as it stands: in a managed workspace, ask, put back on the
// first read that finds it set.
function currentRow(ctx: VaultContext, item: CheckedCredential): PostureRow | null {
  const row = storedRow(ctx, item.id)
  if (row && row.level !== "ask" && managedSetting(ctx) !== null) {
    resetPosture(ctx, null, item, "managed")
    return storedRow(ctx, item.id)
  }
  return row
}

// Whether a level reaches this machine, now: never a revoked one, a guest's
// or one outside the posture's machines; routine, a member's or a team's;
// trust, only a machine whose owner manages the credential's home.
function machineCovered(state: AccessState, device: string, level: PostureLevel, machines: string[] | null, item: CheckedCredential, now: number): boolean {
  if (level === "ask" || (machines !== null && !machines.includes(device))) return false
  const d = state.devices.find((x) => x.id === device && x.status === "active")
  if (!d) return false
  if (d.owner.kind === "team") return level === "routine" && state.teams.some((t) => t.id === d.owner.id)
  const owner = state.members.find((m) => m.id === d.owner.id && m.status === "active")
  if (!owner || owner.standing.effectiveRole === "guest") return false
  return level === "routine" || managesHome(state, owner.id, item.home, now)
}

// ---------------------------------------------------------------- reading

// What a machine may know: the level, whether it lets this key through, and
// the catalogue; never which other machines it covers.
export function machinePosture(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential): ItemDescriptionPosture | undefined {
  if (!posturesOn(ctx.env, ctx.tenant)) return undefined
  const row = currentRow(ctx, item)
  if (managedSetting(ctx) !== null) return undefined
  const level = row?.level ?? "ask"
  const catalogue = row && level !== "ask" ? signedCatalogue(row) : itemCatalogue(item)
  return { level, coversThisKey: machineCovered(accessState(ctx), principal.deviceId, level, machinesOf(row), item, ctx.now()), catalogue }
}
function itemCatalogue(item: CheckedCredential): PostureCatalogue | null {
  const catalogue = postureCatalogueFor(item.binding)
  return catalogue ? { template: catalogue.template, version: catalogue.version } : null
}
const mayAsk = (state: AccessState, principal: AccessPrincipal, item: CheckedCredential, now: number): boolean => can(state, principal, { type: "credential.posture", level: "ask" }, { credential: item.id }, now).allowed
const isGuest = (state: AccessState, principal: AccessPrincipal): boolean => principal.kind === "member" && state.members.find((m) => m.id === principal.memberId)?.standing.effectiveRole === "guest"
// Whether this person may set routine, as the action checks it.
const mayWiden = (state: AccessState, principal: AccessPrincipal, item: CheckedCredential, now: number): boolean => !isGuest(state, principal) && can(state, principal, { type: "credential.posture", level: "routine" }, { credential: item.id }, now).allowed

// What a person's page shows, only to someone who may set it.
export function personPosture(ctx: VaultContext, principal: AccessPrincipal, item: CheckedCredential, invocation: WorkspaceInvocationContext): WorkspaceItemPosture | undefined {
  if (!posturesOn(ctx.env, ctx.tenant)) return undefined
  const row = currentRow(ctx, item)
  const state = eligibilityState(ctx, invocation)
  if (managedSetting(ctx) !== null || !mayAsk(state, principal, item, ctx.now())) return undefined
  const current = postureCatalogueFor(item.binding)
  const level = row?.level ?? "ask"
  const signed = row && level !== "ask" ? signedCatalogue(row) : current ? { template: current.template, version: current.version } : null
  const machines = machinesOf(row)?.map((id) => ({ id, name: devicePolicyState(ctx, id)?.name ?? id })) ?? null
  const setter = row?.set_by.startsWith("member:") ? state.members.find((m) => m.id === row.set_by.slice("member:".length))?.name ?? null : null
  return {
    level, machines,
    catalogue: signed ? { ...signed, current: current?.template === signed.template ? current.version : signed.version } : null,
    setBy: setter, setAt: row ? new Date(row.set_at).toISOString() : null, rev: row?.rev ?? 0,
    eligible: eligibleMachines(ctx, item, invocation),
  }
}
// The machines the page may tick: those this person may read, each with the
// levels machineCovered would cover it at now, and none that no level covers.
function eligibleMachines(ctx: VaultContext, item: CheckedCredential, invocation: WorkspaceInvocationContext): PostureEligibleMachine[] {
  const state = accessState(ctx), now = ctx.now()
  return readableDevices(ctx, invocation).flatMap((d) => {
    const levels = (["routine", "trust"] as const).filter((level) => machineCovered(state, d.id, level, null, item, now))
    return levels.length > 0 ? [{ device: d.id, name: devicePolicyState(ctx, d.id)?.name ?? d.id, levels }] : []
  })
}

// ---------------------------------------------------------------- setting

// The posture a page asks for and the posture revision it showed.
export const PostureTerms = z.object({ posture: PostureSchema, rev: z.number().int().min(0) })
const PostureInput = PostureTerms.extend({ slug: Slug })

// The item.posture action a passkey signs, rebuilt from live state, for
// someone who may set it (asked first, so nobody else learns its revision):
// the page's revision must still be the stored one, a level other than ask
// needs a catalogue for the credential's hosts, and every machine named
// must still be in the workspace.
export async function postureAction(ctx: VaultContext, item: CheckedCredential, input: z.infer<typeof PostureTerms>, invocation: WorkspaceInvocationContext) {
  posturesAvailable(ctx)
  const { posture, rev } = input
  const decision = authorise(ctx, invocation, { type: "credential.posture", level: posture.level }, { credential: item.id }, ctx.now())
  refuseGuestWidening(ctx, decision, posture.level)
  if ((currentRow(ctx, item)?.rev ?? 0) !== rev) throw postureChanged()
  const catalogue = postureCatalogueFor(item.binding)
  if (posture.level !== "ask" && catalogue === null) throw new VaultError("bad_request", "Nobody has reviewed this service's routes, so this credential can only ask for every change.")
  const state = accessState(ctx)
  if (posture.machines?.some((id) => !state.devices.some((d) => d.id === id && d.status === "active"))) throw new VaultError("bad_request", "No such machine.")
  if (posture.level !== "ask" && setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
  const action = { type: "item.posture" as const, item: item.id, digest: await itemPostureDigest({ ...posture, item: item.id, catalogue: catalogue?.template ?? null, catalogueVersion: catalogue?.version ?? null, before: rev }), level: posture.level }
  return { action, decision, catalogue }
}

// A guest's machines are never covered, so a guest may only ask.
function refuseGuestWidening(ctx: VaultContext, decision: AccessAllowed, level: PostureLevel): void {
  if (level !== "ask" && isGuest(accessState(ctx), decision.principal)) throw new VaultError("forbidden", "Guests cannot let agents carry on without asking.")
}

async function setPosture(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<WorkspaceItemPosture | undefined> {
  const { slug, ...input } = parseOpInput(PostureInput, raw)
  const before = visibleCredential(ctx, p, slug, undefined, invocation)
  const built = await postureAction(ctx, before, input, invocation)
  return ctx.storage.transactionSync(() => {
    const live = checkedCredential(ctx, slug)
    if (!live || live.id !== before.id) throw postureChanged()
    const decision = authorise(ctx, invocation, { type: "credential.posture", level: input.posture.level }, { credential: live.id }, ctx.now())
    refuseGuestWidening(ctx, decision, input.posture.level)
    const liveCatalogue = postureCatalogueFor(live.binding)
    if (liveCatalogue?.template !== built.catalogue?.template || liveCatalogue?.version !== built.catalogue?.version) throw postureChanged()
    const row = currentRow(ctx, live)
    if ((row?.rev ?? 0) !== input.rev) throw postureChanged()
    if (input.posture.level !== "ask" && setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
    const signed = invocation.auth.kind === "account" ? invocation.auth.stepUp : undefined
    if (signed?.type === "item.posture" && signed.item === live.id && signed.digest !== built.action.digest) throw postureChanged()
    requireStepUp(ctx, decision, built.action, invocation)
    if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can set how careful a credential is.")
    const catalogue = input.posture.level === "ask" ? null : built.catalogue
    ctx.sql.exec(`INSERT INTO item_postures(item_id,level,machines,catalogue,catalogue_version,rev,set_by,set_at) VALUES (?,?,?,?,?,1,?,?)
      ON CONFLICT(item_id) DO UPDATE SET level=excluded.level,machines=excluded.machines,catalogue=excluded.catalogue,catalogue_version=excluded.catalogue_version,rev=item_postures.rev+1,set_by=excluded.set_by,set_at=excluded.set_at`,
    live.id, input.posture.level, input.posture.machines ? JSON.stringify(input.posture.machines) : null, catalogue?.template ?? null, catalogue?.version ?? null, `member:${p.memberId}`, ctx.now())
    credentialAudit(ctx, p, live, "posture.set", input.posture.level, { before: row?.level ?? "ask", after: input.posture.level, machines: input.posture.machines?.length ?? null }, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
    return personPosture(ctx, p, live, invocation)
  })
}

// ---------------------------------------------------------------- use

// The posture that lets a held request through without asking, or null.
// Only for a request the item's policy would hold, never a protected item
// (the caller never asks for a protected environment or run), in an
// unmanaged workspace with postures on.
export type PostureUse = { item: string; rev: number; level: Exclude<PostureLevel, "ask">; coverage: PostureCoverage }
export function coveringPosture(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, request: HeldRequest): PostureUse | null {
  if (!posturesHere(ctx) || projects.isProtectedItem(ctx, item.slug)) return null
  const row = currentRow(ctx, item)
  if (!row || row.level === "ask") return null
  const signed = signedCatalogue(row)
  if (signed === null || !machineCovered(accessState(ctx), principal.deviceId, row.level, machinesOf(row), item, ctx.now())) return null
  const coverage = postureCovers(row.level, signed, anchorOf(ctx, item, { device: principal.deviceId, workload: principal.workload ?? null }, request))
  return coverage === null ? null : { item: item.id, rev: row.rev, level: row.level, coverage }
}
// What posture trust would let through for this machine now, read against
// the credential's current catalogue and every machine trust reaches, with
// no posture stored: the approval dial's Let it work
// (approval-dial-workspace.ts). Never a protected item.
export function trustWouldCover(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, request: HeldRequest): PostureCoverage | null {
  if (projects.isProtectedItem(ctx, item.slug)) return null
  const catalogue = postureCatalogueFor(item.binding)
  if (catalogue === null || !trustReaches(ctx, principal, item)) return null
  return postureCovers("trust", { template: catalogue.template, version: catalogue.version }, anchorOf(ctx, item, { device: principal.deviceId, workload: principal.workload ?? null }, request), catalogue)
}
// Whether trust reaches this machine for this credential: an active
// machine of a member, not a guest, who manages the credential's home.
export function trustReaches(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential): boolean {
  return machineCovered(accessState(ctx), principal.deviceId, "trust", null, item, ctx.now())
}
// Inside the relay's last transaction: the posture is the one the hook read,
// and still reaches this machine.
export function assertPostureCurrent(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, use: PostureUse): void {
  const row = posturesHere(ctx) ? storedRow(ctx, item.id) : null
  if (!row || row.item_id !== use.item || row.rev !== use.rev || row.level !== use.level || !machineCovered(accessState(ctx), principal.deviceId, row.level, machinesOf(row), item, ctx.now()))
    throw new VaultError("conflict", "How careful this credential is changed since this request was checked; send it again.")
}
// The use, without the path: the entry (or unreviewed), method, host and level.
export function recordPostureUse(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, use: PostureUse, request: HeldRequest, run: string | null): void {
  const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
  credentialAudit(ctx, principal, item, "posture.use", use.level, { entry: use.coverage.entry, method: request.destination.method, host: request.destination.host, level: use.level, ...(workload ? { by: { workload: { id: workload.id, label: workload.label } } } : {}) }, run)
}

// ---------------------------------------------------------------- nudge

const dayOf = (ms: number): number => Math.floor(ms / DAY_MS)

// A held request the relay asked a person about: counted on its day, and
// as routine when routine on the credential's catalogue would have let it
// through. Never a value: counts only.
export function countPostureAsk(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, request: HeldRequest): void {
  if (!posturesHere(ctx)) return
  const catalogue = postureCatalogueFor(item.binding)
  const routine = catalogue !== null && postureCovers("routine", { template: catalogue.template, version: catalogue.version }, anchorOf(ctx, item, { device: principal.deviceId, workload: principal.workload ?? null }, request), catalogue) !== null
  ctx.sql.exec("INSERT INTO posture_ask_counts(item_id,day,asked,routine) VALUES (?,?,1,?) ON CONFLICT(item_id,day) DO UPDATE SET asked=asked+1,routine=routine+excluded.routine", item.id, dayOf(ctx.now()), routine ? 1 : 0)
  prunePostureCounts(ctx)
}
// A deny counts on its ask's day, where that day counted an ask.
export function countPostureDenied(ctx: VaultContext, item: string | null, askedAt: number): void {
  if (item !== null) ctx.sql.exec("UPDATE posture_ask_counts SET denied=denied+1 WHERE item_id=? AND day=?", item, dayOf(askedAt))
}
export function prunePostureCounts(ctx: VaultContext): void {
  ctx.sql.exec("DELETE FROM posture_ask_counts WHERE day<?", dayOf(ctx.now()) - COUNT_KEEP_DAYS)
  ctx.sql.exec("DELETE FROM posture_nudge_quiet WHERE until<=?", ctx.now())
}
// A deleted credential leaves no posture, count or quiet behind.
export function forgetPosture(ctx: VaultContext, item: string): void {
  ctx.sql.exec("DELETE FROM item_postures WHERE item_id=?", item)
  ctx.sql.exec("DELETE FROM posture_ask_counts WHERE item_id=?", item)
  ctx.sql.exec("DELETE FROM posture_nudge_quiet WHERE item_id=?", item)
}

export type PostureNudge = { slug: string; asked: number; routine: number }
// items.nudges: at most three credentials the viewer may set to routine,
// still at ask, with a catalogue, that over seven days asked at least ten
// times, none denied, at least five of them routine, and that the viewer
// has not quietened.
function postureNudges(ctx: VaultContext, p: AccessPrincipal, invocation: WorkspaceInvocationContext): { nudges: PostureNudge[] } {
  authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
  if (!posturesHere(ctx) || p.kind !== "member") return { nudges: [] }
  const now = ctx.now(), state = eligibilityState(ctx, invocation)
  const counted = rows(ctx.sql.exec<{ item_id: string; asked: number; routine: number }>(`SELECT item_id,SUM(asked) AS asked,SUM(routine) AS routine FROM posture_ask_counts WHERE day>? GROUP BY item_id
    HAVING SUM(asked)>=? AND SUM(denied)=0 AND SUM(routine)>=? ORDER BY SUM(asked) DESC,item_id`, dayOf(now) - NUDGE_DAYS, NUDGE_MIN_ASKED, NUDGE_MIN_ROUTINE))
  const nudges: PostureNudge[] = []
  for (const count of counted) {
    if (nudges.length === NUDGE_MAX) break
    const slug = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", count.item_id))?.slug
    const item = slug ? checkedCredential(ctx, slug) : null
    if (!item || (storedRow(ctx, item.id)?.level ?? "ask") !== "ask" || postureCatalogueFor(item.binding) === null || !mayWiden(state, p, item, now)) continue
    if (one(ctx.sql.exec("SELECT 1 FROM posture_nudge_quiet WHERE member=? AND item_id=? AND until>?", p.memberId, item.id, now))) continue
    nudges.push({ slug: item.slug, asked: count.asked, routine: count.routine })
  }
  return { nudges }
}
// "Not now": that credential's nudge stays away from this person for 7 days.
function quietNudge(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Record<string, never> {
  const { slug } = parseOpInput(z.strictObject({ slug: Slug }), raw)
  posturesAvailable(ctx)
  const item = visibleCredential(ctx, p, slug, undefined, invocation)
  authorise(ctx, invocation, { type: "credential.posture", level: "ask" }, { credential: item.id }, ctx.now())
  if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can quieten a nudge.")
  ctx.sql.exec("INSERT INTO posture_nudge_quiet(member,item_id,until) VALUES (?,?,?) ON CONFLICT(member,item_id) DO UPDATE SET until=excluded.until", p.memberId, item.id, ctx.now() + NUDGE_QUIET_MS)
  credentialAudit(ctx, p, item, "posture.nudge_quiet", "quiet", {}, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
  return {}
}

export const workspacePostureOps = {
  "items.posture": { auth: ["account"] as const, handler: setPosture },
  "items.nudges": { auth: ["account"] as const, handler: (ctx: VaultContext, p: AccessPrincipal, _input: unknown, invocation: WorkspaceInvocationContext) => postureNudges(ctx, p, invocation) },
  "items.nudge_quiet": { auth: ["account"] as const, handler: quietNudge },
}
