// Pushes (design push-providers 3): the vault puts one stored secret into
// another service's secret store once a human has approved it. The asking
// machine never holds the value: push.prepare checks the ask and hands the
// Worker only the via's preview reads, push.ask files the approval, and
// after a decision push.execute hands the value to the Worker alone, which
// writes it and reports to push.record.

import { z } from "zod"
import { KINDS, PUSH_VIA, canonicalJson, checkBinding, deviceModeAllowed, evaluatePolicy, formatPushDestination, parseDestination, pushDestinationWords, type WorkspaceRef, type WorkspaceStepUpAction, type PushDestination, type PushOutcome, type PushPreview, type PushProvider, type PushResult, type RedactionSecret } from "@mehen/protocol"
import { PushRequest, type ApprovalSubject, type PushRequestInput } from "@mehen/protocol/api"
import { VaultError } from "../../http.ts"
import { pushCalls, type PushCall, type PushVia } from "../../push/adapters.ts"
import { can, effectiveAccess, eligibility, fourEyesProjects, visibleHuman, type AccessAsk, type AccessCredential, type AccessPrincipal, type AccessState } from "../access.ts"
import { auditPrivateEvent } from "../audit.ts"
import { one, randomId, type Area, type VaultContext } from "../core.ts"
import type { ApprovalPresentation } from "../services.ts"
import { digestOf, parseOpInput } from "./approvals.ts"
import { consentCurrent, readConsent, requestWorkspaceApproval, workspaceApproval } from "./approvals-workspace.ts"
import { checkedCredential, missingCredential, openCredentialSecrets, visibleCredential, type CheckedCredential } from "./items-workspace.ts"
import { workspaceTokenRead } from "./oauth-workspace.ts"
import { approvedUseSnapshot, type ProtectedSnapshot } from "./projects-workspace.ts"
import { itemPushable, pushesManaged, pushesOn, pushesUnavailable, pushOffered } from "./push-allowance.ts"
import { PUSHES_MIGRATION, PUSH_CONSTRAINTS, PUSH_METHOD, PUSH_QUEUED_MS, PUSH_SENDING_MS, PUSH_SWEEP_KEY, PUSH_URL_PREFIX, insertQueuedPush, pushRow, schedulePushSweep, storedDestination, type PushPresentation, type PushRow, type PushSnapshotPart } from "./push-records.ts"
import { inject, needsExactBinding } from "./relay.ts"
import { accessState, authorise, managedSetting, recordExposure, requireStepUp, setting, type WorkspaceInvocationContext, type WorkspaceRuntimePrincipal } from "./workspace-runtime.ts"

type DevicePrincipal = Extract<AccessPrincipal, { kind: "device" }>

const PROVIDER_NAMES: Record<PushProvider, string> = { github: "GitHub", vercel: "Vercel", cloudflare: "Cloudflare", fly: "Fly" }
// A push the same machine asked for that finished in the last ten minutes
// answers again rather than asking again (design 2.3).
const DONE_REPEAT_MS = 600_000
const MAX_PUSH_VALUE_BYTES = 64 * 1024

const PushPreviewSchema: z.ZodType<PushPreview> = z.discriminatedUnion("provider", [
  z.strictObject({ provider: z.literal("github"), owner: z.string().max(100).nullable(), ownerType: z.string().max(40).nullable(), private: z.boolean().nullable(), fork: z.boolean().nullable(), parent: z.string().max(200).nullable(), exists: z.boolean().nullable(), updatedAt: z.string().max(40).nullable() }),
  z.strictObject({ provider: z.literal("vercel"), projectId: z.string().max(100).nullable(), projectName: z.string().max(100).nullable(), accountId: z.string().max(100).nullable(), repo: z.string().max(200).nullable(), exists: z.null(), updatedAt: z.null() }),
  z.strictObject({ provider: z.literal("cloudflare"), accountName: z.string().max(200).nullable(), exists: z.boolean().nullable(), updatedAt: z.null() }),
  z.strictObject({ provider: z.literal("fly"), organization: z.string().max(100).nullable(), exists: z.boolean().nullable(), updatedAt: z.null() }),
])
export const PushAskInput = z.strictObject({ ticket: z.string().max(64), preview: PushPreviewSchema.nullable() })
// Long enough for the preview reads (10 seconds each).
const PUSH_TICKET_MS = 60_000

// What push.prepare hands the Worker: the via's headers and only the
// preview reads its policy allows. Never the pushed value.
export type PushPrepared = { ticket: string; destination: PushDestination; via: PushVia; allowed: PushCall[] }
// What push.execute hands the Worker once the checks hold.
export type PushHandOut = { sent: true; push: string; destination: PushDestination; value: RedactionSecret; via: PushVia } | { sent: false; push: string; reason: string }

type CheckedPush = { item: CheckedCredential; field: string; via: CheckedCredential; destination: PushDestination; calls: PushCall[]; allowed: PushCall[] }

function frozen(ctx: VaultContext): void {
  if (setting(ctx, "frozen", false)) throw new VaultError("frozen", "This workspace is frozen.")
}

function credentialPage(ctx: VaultContext, workspace: WorkspaceRef, slug: string): string {
  return `${ctx.env.VAULT_ORIGIN}/w/${workspace.slug}/items/${slug}`
}

// Relay-level use of the credential by this machine (ruling U1), checked as
// a reveal, so a cooling-off owner's machine is refused.
function pushedItem(ctx: VaultContext, principal: DevicePrincipal, workspace: WorkspaceRef, request: PushRequestInput): { item: CheckedCredential; field: string } {
  const item = checkedCredential(ctx, request.item)
  if (!item) throw missingCredential(request.item)
  const decision = can(accessState(ctx), principal, { type: "item.use", context: null }, { credential: item.id, mode: "relay", push: true }, ctx.now())
  if (!decision.allowed) {
    if (decision.error === "not_found") throw missingCredential(request.item)
    throw new VaultError(decision.error, decision.message, decision.next ? { next: decision.next } : {})
  }
  if (item.status === "disabled") throw new VaultError("forbidden", `"${item.slug}" is disabled.`)
  if (!pushOffered(item.kind)) throw new VaultError("mode_refused", `${item.slug} (${KINDS[item.kind].label}) is never put into other services' secret stores.`)
  const field = request.field ?? KINDS[item.kind].primary
  if (field === null) throw new VaultError("bad_request", `Name the field of ${item.slug} to push, as ${item.slug}#<field>.`)
  const spec = KINDS[item.kind].fields.find((f) => f.name === field)
  if (!spec) throw new VaultError("bad_request", `${item.slug} has no field "${field}".`)
  if (!spec.secret) throw new VaultError("bad_request", `"${field}" of ${item.slug} is not a secret; only a secret field is pushed.`)
  if (!itemPushable(ctx, item.id)) throw new VaultError("mode_refused", `${item.slug} may not be put into other services' secret stores. Allow it on its page.`, { next: { url: credentialPage(ctx, workspace, item.slug), say: `A person allows ${item.slug} to be put into other services' secret stores on its page.` } })
  const stored = one(ctx.sql.exec<{ length: number }>("SELECT length FROM item_secrets WHERE item=? AND name=?", item.id, field))
  if (!stored) throw new VaultError("bad_request", `${item.slug} holds no "${field}".`)
  if (stored.length > MAX_PUSH_VALUE_BYTES) throw new VaultError("too_large", `"${field}" of ${item.slug} is over 64 KiB, more than a secret store takes.`)
  return { item, field }
}

function usableAtRelay(ctx: VaultContext, state: AccessState, principal: DevicePrincipal, credential: CheckedCredential): boolean {
  return can(state, principal, { type: "item.use", context: null }, { credential: credential.id, mode: "relay" }, ctx.now()).allowed
}

// The credential that carries the push: the one named, else the single one
// this machine may use at relay for that provider.
function chooseVia(ctx: VaultContext, principal: DevicePrincipal, request: PushRequestInput): CheckedCredential {
  const provider = request.to.provider, name = PROVIDER_NAMES[provider]
  if (request.with !== undefined) {
    const via = checkedCredential(ctx, request.with)
    if (!via || !usableAtRelay(ctx, accessState(ctx), principal, via)) throw missingCredential(request.with)
    if (!PUSH_VIA[provider].includes(via.provider ?? "")) throw new VaultError("bad_request", `${via.slug} cannot carry a push to ${name}: it is not a ${name} credential.`)
    return via
  }
  const state = accessState(ctx)
  const candidates = PUSH_VIA[provider].flatMap((template) => ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE provider=? ORDER BY slug", template).toArray())
    .map((row) => checkedCredential(ctx, row.slug)).filter((c): c is CheckedCredential => c !== null && usableAtRelay(ctx, state, principal, c))
  if (candidates.length === 0) throw new VaultError("not_found", `This machine may use no ${name} credential to push with.`, { next: { say: `Add a ${name} token or name one with --with.` } })
  if (candidates.length > 1) throw new VaultError("ambiguous", `This machine may use several ${name} credentials; name one with --with.`, { choices: candidates.map((c) => ({ slug: c.slug, account: c.account })) })
  return candidates[0]!
}

// The via may make every call the push needs: under its binding, never
// denied by its policy. The preview reads are made only where its policy
// allows them without a human.
function checkViaCalls(ctx: VaultContext, via: CheckedCredential, destination: PushDestination): { calls: PushCall[]; allowed: PushCall[] } {
  if (via.status === "needs_reauth") throw new VaultError("needs_reauth", `"${via.slug}" needs to be connected again.`)
  if (via.status === "disabled") throw new VaultError("forbidden", `"${via.slug}" is disabled.`)
  if (!deviceModeAllowed(via.ceiling, "relay")) throw new VaultError("mode_refused", `"${via.slug}" may not be used through the relay: its exposure ceiling is ${via.ceiling}.`)
  if (via.injection === null || via.injection.in === "query") throw new VaultError("forbidden", `"${via.slug}" cannot carry a push: it is not sent in a header.`)
  const { preview, write } = pushCalls(destination)
  const words = pushDestinationWords(destination)
  const hosts = via.binding.hosts.map((h) => h.toLowerCase())
  const allowed: PushCall[] = []
  for (const call of [...preview, ...write]) {
    const parsed = parseDestination(call.method, call.url)
    if (!parsed.ok) throw new VaultError("internal", "A push call is not a URL the vault can read.")
    const dest = parsed.destination
    if (needsExactBinding(dest.host, ctx.env.VAULT_ORIGIN) && !hosts.includes(dest.host) || !checkBinding(via.binding, dest).ok)
      throw new VaultError("binding_refused", `"${via.slug}" may not go to ${dest.method} ${dest.host}${dest.path}, which a push to ${words} needs.`, { next: { say: `The vault refused to send "${via.slug}" there. Its destinations are set by a human in the vault, never by a request.` } })
    const decision = evaluatePolicy(via.policy, dest)
    if (decision.action === "deny") {
      const why = decision.matched.map((rule) => rule.note).filter((note): note is string => !!note)
      throw new VaultError("policy_denied", `"${via.slug}" may not be used for ${dest.method} ${dest.path}${why.length > 0 ? ` (${why.join(", ")})` : ""}.`, { next: { say: `The vault's policy for "${via.slug}" forbids this push. Only a human can change that policy, in the vault.` } })
    }
    if (decision.action === "allow" && preview.includes(call)) allowed.push(call)
  }
  return { calls: [...preview, ...write], allowed }
}

// Every check of design 3.1 in its order, from current state, without
// opening anything. The dispatcher has already refused a machine that acts
// only through workloads.
function checkPush(ctx: VaultContext, principal: DevicePrincipal, workspace: WorkspaceRef, request: PushRequestInput): CheckedPush {
  frozen(ctx)
  if (!pushesOn(ctx.env, ctx.tenant)) throw pushesUnavailable()
  if (managedSetting(ctx) !== null) throw pushesManaged()
  // Fly's adapter is not yet run end to end against the vault.
  if (request.to.provider === "fly") throw new VaultError("bad_request", "Pushing to Fly is not available yet.")
  const { item, field } = pushedItem(ctx, principal, workspace, request)
  const via = chooseVia(ctx, principal, request)
  return { item, field, via, destination: request.to, ...checkViaCalls(ctx, via, request.to) }
}

// GitHub owner, Vercel team (or the account the preview read), Cloudflare
// account, Fly organisation.
function ownerKey(d: PushDestination, preview: PushPreview | null): string {
  switch (d.provider) {
    case "github": return d.owner
    case "vercel": return d.team ?? (preview?.provider === "vercel" ? preview.accountId : null) ?? `project:${d.project}`
    case "cloudflare": return d.account
    case "fly": return (preview?.provider === "fly" ? preview.organization : null) ?? `app:${d.app}`
  }
}

// Known when this workspace bound the repository to a project, or a push
// to the same owner was done before (design 3.1 point 5).
function newDestination(ctx: VaultContext, d: PushDestination, owner: string): boolean {
  if (d.provider === "github" && one(ctx.sql.exec("SELECT 1 FROM remotes WHERE remote=? LIMIT 1", `github.com/${d.owner}/${d.repo}`)) !== null) return false
  return one(ctx.sql.exec("SELECT 1 FROM pushes WHERE provider=? AND owner_key=? AND state='done' LIMIT 1", d.provider, owner)) === null
}

function pushSnapshotPart(checked: CheckedPush, owner: string): PushSnapshotPart {
  const { item, via } = checked
  return { item: { id: item.id, version: item.version, configRev: item.configRev }, via: { id: via.id, version: via.version, configRev: via.configRev }, field: checked.field, destination: formatPushDestination(checked.destination), ownerKey: owner }
}

// The asker's snapshot (approvedUseSnapshot) widened to both credentials:
// their references and four-eyes projects, and the push part.
function pushSnapshot(ctx: VaultContext, state: AccessState, principal: DevicePrincipal, item: CheckedCredential, part: PushSnapshotPart, now: number): { snapshot: ProtectedSnapshot; ask: AccessAsk } {
  const { snapshot, ask } = approvedUseSnapshot(ctx, state, principal, { id: item.id, slug: item.slug, home: item.home, configRevision: item.configRev }, null, now, "relay")
  if (!ask) throw new VaultError("bad_request", "This push needs an approval subject.")
  const own = part.via.id === part.item.id
  const pushAsk: AccessAsk = { ...ask, credentials: own ? [part.item.id] : [part.item.id, part.via.id], ...(own ? {} : { via: part.via.id }) }
  const ids = pushAsk.credentials
  const references = state.projects.flatMap((p) => p.environments.filter((e) => e.references.some((r) => ids.includes(r.item))).map((e) => ({ project: p.id, environment: e.name, revision: e.revision, protectionRevision: e.protectionRevision }))).sort((a, b) => `${a.project}/${a.environment}`.localeCompare(`${b.project}/${b.environment}`))
  return { snapshot: { ...snapshot, references, fourEyes: fourEyesProjects(state, pushAsk).sort(), push: part }, ask: pushAsk }
}

export function pushSubject(checked: CheckedPush): ApprovalSubject {
  const { item, via, field, destination } = checked
  return {
    item: item.slug,
    method: PUSH_METHOD,
    url: PUSH_URL_PREFIX + formatPushDestination(destination),
    contentType: null,
    contentEncoding: null,
    headersSha256: digestOf([]),
    bodySha256: digestOf({ item: item.id, field, version: item.version, configRev: item.configRev, via: { id: via.id, version: via.version, configRev: via.configRev }, destination }),
    constraints: { ...PUSH_CONSTRAINTS },
  }
}

function pushPresentation(checked: CheckedPush, preview: PushPreview | null, isNew: boolean, owner: string, reason: string | undefined): ApprovalPresentation {
  const { item, via, field, destination } = checked
  const words = pushDestinationWords(destination), name = PROVIDER_NAMES[destination.provider], using = via.account ? `${via.slug} (as ${via.account})` : via.slug
  const push: PushPresentation = { destination: formatPushDestination(destination), words, field, version: item.version, via: via.slug, preview, newDestination: isNew }
  const warnings = [`Mehen cannot take this back. Removing it later is done in ${name}.`]
  if (isNew) warnings.push(`This workspace has never pushed to ${owner}.`)
  if (preview?.provider === "github" && preview.fork === true) warnings.push(`Fork of ${preview.parent ?? "another repository"}: its owner, not this workspace, controls it.`)
  return {
    title: `Put ${item.slug} into ${words}, using ${via.slug}`,
    details: [{ label: "Where", value: words }, { label: "Value", value: `${item.slug}, field ${field}, version ${item.version}` }, { label: "Using", value: using }, ...(reason ? [{ label: "The agent says", value: reason }] : [])],
    body: null,
    warnings,
    push,
  }
}

function asDevice(principal: WorkspaceRuntimePrincipal): DevicePrincipal {
  if (principal.kind !== "device") throw new VaultError("forbidden", "Only an enrolled machine can ask for a push.")
  return principal
}

export function pushResult(ctx: VaultContext, row: PushRow): PushResult {
  const slug = (id: string) => one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", id))?.slug ?? id
  return { push: row.id, item: slug(row.item), field: row.field, version: row.item_version, destination: row.destination, via: slug(row.via), outcome: row.outcome ?? "set", at: new Date(row.finished_at ?? row.created_at).toISOString() }
}

// The opened via: its headers with the token injected, and what to scrub.
async function openVia(ctx: VaultContext, via: CheckedCredential): Promise<{ via: PushVia; item: CheckedCredential }> {
  let secrets: Record<string, string>, item = via
  if (via.kind === "oauth-connection") {
    const read = await workspaceTokenRead(ctx, via)
    secrets = { access_token: read.accessToken }
    item = read.item
  } else secrets = await openCredentialSecrets(ctx, via)
  const headers = new Headers()
  const scrub = inject(item, secrets, headers, new URL("https://push.invalid/"))
  return { via: { slug: via.slug, headers: [...headers], scrub }, item }
}

// ---------------------------------------------------------------- recording

function pushActor(ctx: VaultContext, row: PushRow): { actor: string; private: Parameters<typeof auditPrivateEvent>[1]["actor"] } {
  if (row.member !== null) return { actor: `member:${row.member}`, private: { kind: "member", member: row.member } }
  const device = accessState(ctx).devices.find((d) => d.id === row.device)
  const owner = device?.owner.kind === "team" ? { kind: "team" as const, team: device.owner.id } : { kind: "member" as const, member: device?.owner.id ?? "" }
  return { actor: `device:${row.device}`, private: { kind: "device", device: row.device ?? "", owner } }
}

// push.done, push.failed, push.not_sent, push.unknown: a private event for
// a member's own credential, else a workspace row naming no value and no
// private via.
function auditPush(ctx: VaultContext, row: PushRow, state: "done" | "failed" | "not_sent" | "unknown", extra: { outcome?: PushOutcome | null; providerStatus?: number | null; reason?: string }): void {
  const item = one(ctx.sql.exec<{ slug: string; home_kind: string; home_id: string | null }>("SELECT slug,home_kind,home_id FROM items WHERE id=?", row.item))
  const carrier = one(ctx.sql.exec<{ slug: string; home_kind: string }>("SELECT slug,home_kind FROM items WHERE id=?", row.via))
  const via = carrier && carrier.home_kind !== "member" ? carrier.slug : null
  const who = pushActor(ctx, row)
  const outcome = state === "done" ? extra.outcome ?? "set" : state === "failed" ? "refused:provider_refused" : state
  if (item?.home_kind === "member" && item.home_id !== null) {
    auditPrivateEvent(ctx, { action: `push.${state}`, at: ctx.now(), actor: who.private, session: null, item: row.item, slug: item.slug, outcome, run: null }, item.home_id)
    return
  }
  const result = state === "done" ? { outcome: extra.outcome ?? "set" } : extra.providerStatus != null ? { providerStatus: extra.providerStatus } : {}
  ctx.audit({ actor: who.actor, action: `push.${state}`, target: item?.slug ?? row.item, detail: { item: row.item, destination: row.destination, via, version: row.item_version, ...result, ...(extra.reason ? { reason: extra.reason } : {}), ...(row.approval ? { approval: row.approval } : {}) } })
}

// A value that may now be in the provider's store is exposed to whoever
// asked: the machine and its owner, or the person who pushed.
function recordPushed(ctx: VaultContext, row: PushRow): void {
  const device = row.device === null ? undefined : accessState(ctx).devices.find((d) => d.id === row.device)
  const member = row.member ?? (device?.owner.kind === "member" ? device.owner.id : null)
  recordExposure(ctx, { item: row.item, version: row.item_version, member, device: row.device, event: `push:${row.id}`, source: "pushed", at: ctx.now() })
}

function finish(ctx: VaultContext, row: PushRow, from: "queued" | "sending", state: "done" | "failed" | "not_sent" | "unknown", extra: { outcome?: PushOutcome | null; providerStatus?: number | null; reason?: string } = {}): boolean {
  const written = ctx.sql.exec("UPDATE pushes SET state=?,outcome=?,provider_status=?,finished_at=? WHERE id=? AND state=?", state, extra.outcome ?? null, extra.providerStatus ?? null, ctx.now(), row.id, from).rowsWritten
  if (!written) return false
  auditPush(ctx, row, state, extra)
  if (state === "done" || state === "unknown") recordPushed(ctx, row)
  schedulePushSweep(ctx)
  return true
}

// Why a queued push may no longer be sent, from current state, or null.
function sendRefusal(ctx: VaultContext, row: PushRow): string | null {
  const now = ctx.now()
  if (row.created_at + PUSH_QUEUED_MS <= now) return "It waited too long to be sent; nothing was sent."
  if (setting(ctx, "frozen", false)) return "The workspace was frozen before Mehen sent it; nothing was sent."
  if (!pushesOn(ctx.env, ctx.tenant) || managedSetting(ctx) !== null) return "Pushing was turned off before Mehen sent it; nothing was sent."
  const item = one(ctx.sql.exec<{ slug: string; version: number }>("SELECT slug,version FROM items WHERE id=?", row.item))
  const via = one(ctx.sql.exec<{ slug: string; version: number }>("SELECT slug,version FROM items WHERE id=?", row.via))
  if (!item || !via || item.version !== row.item_version || via.version !== row.via_version) return "The credential or the one carrying it changed before Mehen sent it; nothing was sent."
  if (!itemPushable(ctx, row.item)) return "Pushing this credential was turned off before Mehen sent it; nothing was sent."
  if (one(ctx.sql.exec("SELECT 1 FROM pushes WHERE provider=? AND destination=? AND state='sending' AND id<>?", row.provider, row.destination, row.id)) !== null) return "Another push to the same place was still being sent; nothing was sent."
  const state = accessState(ctx)
  if (row.member !== null) return memberPushRefusal(state, row.member, row.item, row.via, now)
  const approval = row.approval === null ? null : workspaceApproval(ctx, row.approval)
  if (!approval || approval.status !== "approved" || approval.lineage === null) return "Its approval is no longer current; nothing was sent."
  const principal: DevicePrincipal = { kind: "device", deviceId: approval.device, ...(approval.workload !== null ? { workload: approval.workload } : {}) }
  if (state.devices.find((d) => d.id === approval.device)?.status !== "active") return "The machine was revoked before Mehen sent it; nothing was sent."
  const stored = JSON.parse(approval.snapshot) as ProtectedSnapshot
  const part = stored.push
  const current = checkedCredential(ctx, item.slug), carrier = checkedCredential(ctx, via.slug)
  if (!part || !current || !carrier) return "Its approval is no longer current; nothing was sent."
  try {
    if (!can(state, principal, { type: "item.use", context: null }, { credential: current.id, mode: "relay", push: true }, now).allowed || !usableAtRelay(ctx, state, principal, carrier)) return "The machine may no longer use these credentials; nothing was sent."
    const fresh = pushSnapshot(ctx, state, principal, current, { ...part, item: { id: current.id, version: current.version, configRev: current.configRev }, via: { id: carrier.id, version: carrier.version, configRev: carrier.configRev } }, now)
    fresh.snapshot.requestDigest = stored.requestDigest
    if (canonicalJson(fresh.snapshot) !== canonicalJson(stored)) return "Access changed before Mehen sent it; nothing was sent."
    const consent = readConsent(ctx, approval.lineage)
    if (!consent || !consentCurrent(ctx, state, consent.lineage, consent.ask, now)) return "The approval stopped being current before Mehen sent it; nothing was sent."
  } catch (error) {
    if (error instanceof VaultError) return "Access changed before Mehen sent it; nothing was sent."
    throw error
  }
  return null
}

// What a person's push of a credential to where it went before (item.push,
// design 3.3) must still hold when it is sent, as credential.push and
// pushAgainPlan checked under their passkey: the person active, managing
// the credential (a private one only its owner, a shared one an admin or a
// manager of its project, never a guest), seeing the via (a private one only
// its owner's, a shared one never a guest's), and no four-eyes environment
// referencing either.
function memberPushRefusal(state: AccessState, member: string, item: string, via: string, now: number): string | null {
  const credential = state.credentials.find((c) => c.id === item), carrier = state.credentials.find((c) => c.id === via)
  const m = state.members.find((x) => x.id === member)
  if (!credential || !carrier || !m || m.status !== "active") return "Access changed before Mehen sent it; nothing was sent."
  if (fourEyesProjects(state, { device: "", credential: item, credentials: [item, via], context: null }).length > 0) return "Push this from a machine's ask, so a second person decides."
  const role = m.standing.effectiveRole
  const manages = (c: AccessCredential) => c.home.kind === "member" ? c.home.member === member : role !== "guest" && (c.home.kind === "workspace" ? role === "owner" || role === "admin" : effectiveAccess(state, { kind: "member", id: member }, c.home.project, now).level === "manage")
  const sees = (c: AccessCredential) => visibleHuman(state, m, c, now) && (c.home.kind === "member" ? c.home.member === member : role !== "guest")
  if (!manages(credential) || !sees(carrier)) return "You may no longer push this credential; nothing was sent."
  return null
}

// The sweep (design 3.2 point 6): a queued push over two minutes old was
// never sent; one sending for five minutes is no longer known.
export function sweepPushes(ctx: VaultContext): void {
  const now = ctx.now()
  ctx.storage.transactionSync(() => {
    for (const row of ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE state='queued' AND created_at<=?", now - PUSH_QUEUED_MS).toArray())
      finish(ctx, row, "queued", "not_sent", { reason: "It waited too long to be sent; nothing was sent." })
    for (const row of ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE state='sending' AND created_at<=?", now - PUSH_SENDING_MS).toArray())
      finish(ctx, row, "sending", "unknown", { reason: `Mehen could not confirm this push. Check ${PROVIDER_NAMES[storedDestination(row).provider]}.` })
    schedulePushSweep(ctx)
  })
}

// ---------------------------------------------------------------- a person's push again

const PushAgainInput = z.strictObject({ slug: z.string().max(200), records: z.array(z.string().max(64)).min(1).max(25) })
type MemberPrincipal = Extract<AccessPrincipal, { kind: "member" }>

// A person's push of a credential's current value to where it was put
// before (design 3.3): each record the latest done push to its place, all
// of one field, each via one the person sees and may still use there. The
// passkey signs the action this rebuilds from the records and the current
// versions; credential.push says who may.
function pushAgainPlan(ctx: VaultContext, principal: MemberPrincipal, invocation: WorkspaceInvocationContext, slug: string, records: string[]): { action: Extract<WorkspaceStepUpAction, { type: "item.push" }>; item: CheckedCredential; parts: PushSnapshotPart[] } {
  frozen(ctx)
  if (!pushesOn(ctx.env, ctx.tenant)) throw pushesUnavailable()
  if (managedSetting(ctx) !== null) throw pushesManaged()
  const item = visibleCredential(ctx, principal, slug, undefined, invocation)
  if (!pushOffered(item.kind)) throw new VaultError("mode_refused", `${item.slug} (${KINDS[item.kind].label}) is never put into other services' secret stores.`)
  if (!itemPushable(ctx, item.id)) throw new VaultError("mode_refused", `${item.slug} may not be put into other services' secret stores. Allow it on its page.`, { next: { url: credentialPage(ctx, invocation.workspace, item.slug), say: `Allow ${item.slug} to be put into other services' secret stores on its page first.` } })
  if (new Set(records).size !== records.length) throw new VaultError("bad_request", "A push is named more than once.")
  const state = accessState(ctx), m = state.members.find((x) => x.id === principal.memberId)
  const rows = records.map((id) => pushRow(ctx, id))
  const parts: PushSnapshotPart[] = []
  for (const row of rows) {
    if (!row || row.item !== item.id || row.state !== "done") throw new VaultError("not_found", `${item.slug} was not put there.`)
    const later = one(ctx.sql.exec("SELECT 1 FROM pushes WHERE item=? AND destination=? AND created_at>? LIMIT 1", item.id, row.destination, row.created_at))
    if (later) throw new VaultError("conflict", `${item.slug} was pushed to ${row.destination} again since; review and try again.`)
    if (row.field !== rows[0]!.field) throw new VaultError("bad_request", "Push one field at a time.")
    const destination = storedDestination(row)
    if (destination.provider === "fly") throw new VaultError("bad_request", "Pushing to Fly is not available yet.")
    const viaSlug = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", row.via))?.slug
    const via = viaSlug === undefined ? null : checkedCredential(ctx, viaSlug)
    const seen = via && m ? state.credentials.find((c) => c.id === via.id) : undefined
    if (!via || !seen || !m || !visibleHuman(state, m, seen, ctx.now()) || seen.home.kind === "member" && seen.home.member !== m.id || seen.home.kind !== "member" && m.standing.effectiveRole === "guest") throw new VaultError("not_found", `The credential that carried the push to ${pushDestinationWords(destination)} is gone, or you may not use it.`)
    // As a machine's push is judged over both credentials (fourEyesProjects of its ask).
    if (fourEyesProjects(state, { device: "", credential: item.id, credentials: [item.id, via.id], context: null }).length > 0) throw new VaultError("forbidden", "Push this from a machine's ask, so a second person decides.")
    checkViaCalls(ctx, via, destination)
    parts.push({ item: { id: item.id, version: item.version, configRev: item.configRev }, via: { id: via.id, version: via.version, configRev: via.configRev }, field: row.field, destination: row.destination, ownerKey: row.owner_key })
  }
  const field = parts[0]!.field
  const stored = one(ctx.sql.exec<{ length: number }>("SELECT length FROM item_secrets WHERE item=? AND name=?", item.id, field))
  if (!stored) throw new VaultError("bad_request", `${item.slug} holds no "${field}".`)
  if (stored.length > MAX_PUSH_VALUE_BYTES) throw new VaultError("too_large", `"${field}" of ${item.slug} is over 64 KiB, more than a secret store takes.`)
  parts.sort((a, b) => a.destination < b.destination ? -1 : a.destination > b.destination ? 1 : 0)
  return { action: { type: "item.push", item: item.id, field, version: item.version, pushes: parts.map((p) => ({ destination: p.destination, via: p.via.id, viaVersion: p.via.version })) }, item, parts }
}

function asMember(principal: WorkspaceRuntimePrincipal): MemberPrincipal {
  if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person pushes a credential again.")
  return principal
}

const ExecuteInput = z.union([z.strictObject({ push: z.string().max(64) }), z.strictObject({ approval: z.string().max(64) })])
const RecordInput = z.strictObject({ push: z.string().max(64), state: z.enum(["done", "failed", "unknown"]), outcome: z.enum(["created", "replaced", "set"]).nullable(), providerStatus: z.number().int().min(100).max(599).nullable() })

export const workspacePushOps: NonNullable<Area["workspaceOps"]> = {
  // Every check of design 3.1, then the via's opened headers and the
  // preview reads its policy allows, for the Worker to make.
  // The ticket names the machine, its request and the via that made the
  // preview for push.ask, which the Worker calls as the system: a device
  // proof is spent once.
  "push.prepare": { auth: ["device"], async handler(ctx, caller, raw, invocation): Promise<PushPrepared> {
    const principal = asDevice(caller)
    const request = parseOpInput(PushRequest, raw)
    const checked = checkPush(ctx, principal, invocation.workspace, request)
    const opened = await openVia(ctx, checked.via)
    const ticket = randomId("pst")
    ctx.sql.exec("DELETE FROM push_tickets WHERE expires_at<=?", ctx.now())
    ctx.sql.exec("INSERT INTO push_tickets(id,device,workload,request,via,workspace,expires_at) VALUES(?,?,?,?,?,?,?)", ticket, principal.deviceId, principal.workload ?? null, JSON.stringify({ ...request, with: checked.via.slug }), checked.via.id, JSON.stringify(invocation.workspace), ctx.now() + PUSH_TICKET_MS)
    return { ticket, destination: checked.destination, via: opened.via, allowed: checked.allowed }
  } },
  // Re-checks everything for the ticket's machine and files the ask, named
  // with the via that made the preview, as if the machine had named it; a
  // push this machine asked for that finished in the last ten minutes
  // answers again instead.
  "push.ask": { auth: ["system"], handler(ctx, _caller, raw) {
    const { ticket, preview } = parseOpInput(PushAskInput, raw)
    const held = one(ctx.sql.exec<{ device: string; workload: string | null; request: string; via: string; workspace: string }>("DELETE FROM push_tickets WHERE id=? AND expires_at>? RETURNING device,workload,request,via,workspace", ticket, ctx.now()))
    if (!held) throw new VaultError("conflict", "This push took too long to check; ask again.")
    const principal: DevicePrincipal = { kind: "device", deviceId: held.device, ...(held.workload !== null ? { workload: held.workload } : {}) }
    const request = PushRequest.parse(JSON.parse(held.request)), workspace = JSON.parse(held.workspace) as WorkspaceRef
    const asked = ctx.storage.transactionSync(() => {
      const checked = checkPush(ctx, principal, workspace, request)
      if (checked.via.id !== held.via) throw missingCredential(checked.via.slug)
      const owner = ownerKey(checked.destination, preview)
      const done = one(ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE device=? AND workload IS ? AND item=? AND field=? AND item_version=? AND destination=? AND via=? AND via_version=? AND state='done' AND finished_at>? ORDER BY finished_at DESC LIMIT 1", principal.deviceId, principal.workload ?? null, checked.item.id, checked.field, checked.item.version, formatPushDestination(checked.destination), checked.via.id, checked.via.version, ctx.now() - DONE_REPEAT_MS))
      if (done) return { done: pushResult(ctx, done) }
      const state = accessState(ctx)
      const part = pushSnapshotPart(checked, owner)
      const { snapshot, ask } = pushSnapshot(ctx, state, principal, checked.item, part, ctx.now())
      const subject = pushSubject(checked)
      const presentation = pushPresentation(checked, preview, newDestination(ctx, checked.destination, owner), owner, request.reason)
      snapshot.requestDigest = digestOf({ subject, presentation })
      const row = requestWorkspaceApproval(ctx, state, ask, workspace, subject, presentation, snapshot, ctx.now(), { floor: ["credential", "sharing"], shape: digestOf({ push: part.destination }), replaces: null })
      const device = state.devices.find((d) => d.id === ask.device)
      const guest = device?.owner.kind === "member" && state.members.some((m) => m.id === device.owner.id && m.standing.effectiveRole === "guest")
      const deciders = guest ? [] : state.members.filter((m) => eligibility(state, m.id, ask, ctx.now()).canApprove).map((m) => m.name)
      return { row, deciders }
    })
    if ("done" in asked) return asked.done
    const { row, deciders } = asked
    throw new VaultError("approval_required", "This push needs a human's approval.", { approval: row.id, bindingCode: row.binding_code, expiresAt: new Date(row.expires_at).toISOString(), deciders, next: { url: `${ctx.env.VAULT_ORIGIN}/w/${workspace.slug}/a/${row.id}`, ...(principal.workload === undefined ? { command: `mehen wait ${row.id}` } : {}), say: deciders.length ? `Send this link to ${deciders.join(" or ")}.` : "Send this link to a manager of the project, or open Needs you in the workspace." } })
  } },
  // A queued push, re-checked; with no await between the last check and the
  // hand-out, it becomes sending and its value goes to the Worker only.
  "push.execute": { auth: ["system"], async handler(ctx, _principal, raw): Promise<PushHandOut> {
    const input = ExecuteInput.parse(raw)
    const found = "push" in input ? pushRow(ctx, input.push) : one(ctx.sql.exec<PushRow>("SELECT * FROM pushes WHERE approval=? ORDER BY created_at DESC LIMIT 1", input.approval))
    if (!found || found.state !== "queued") throw new VaultError("conflict", "This push is not waiting to be sent.")
    const row = found
    const refuse = (reason: string): PushHandOut => {
      ctx.storage.transactionSync(() => finish(ctx, row, "queued", "not_sent", { reason }))
      return { sent: false, push: row.id, reason }
    }
    const before = sendRefusal(ctx, row)
    if (before !== null) return refuse(before)
    const item = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", row.item)), carrier = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=?", row.via))
    const credential = item && checkedCredential(ctx, item.slug), via = carrier && checkedCredential(ctx, carrier.slug)
    if (!credential || !via) return refuse("The credential or the one carrying it changed before Mehen sent it; nothing was sent.")
    let value: string, opened: Awaited<ReturnType<typeof openVia>>
    try {
      value = (await openCredentialSecrets(ctx, credential))[row.field] ?? ""
      opened = await openVia(ctx, via)
    } catch (error) {
      if (error instanceof VaultError) return refuse(error.code === "needs_reauth" ? `${via.slug} needs to be connected again; nothing was sent.` : "Mehen could not open the credentials; nothing was sent.")
      throw error
    }
    if (value === "" || new TextEncoder().encode(value).length > MAX_PUSH_VALUE_BYTES) return refuse(`${credential.slug} holds no value that fits a secret store; nothing was sent.`)
    return ctx.storage.transactionSync((): PushHandOut => {
      const reason = sendRefusal(ctx, row) ?? (opened.item.configRev !== via.configRev || checkedCredential(ctx, credential.slug)?.configRev !== credential.configRev ? "The credential or the one carrying it changed before Mehen sent it; nothing was sent." : null)
      if (reason !== null) {
        finish(ctx, row, "queued", "not_sent", { reason })
        return { sent: false, push: row.id, reason }
      }
      if (!ctx.sql.exec("UPDATE pushes SET state='sending' WHERE id=? AND state='queued'", row.id).rowsWritten) throw new VaultError("conflict", "This push is not waiting to be sent.")
      schedulePushSweep(ctx)
      return { sent: true, push: row.id, destination: storedDestination(row), value: { label: credential.slug, value }, via: opened.via }
    })
  } },
  // Planning only: the item.push action the page signs. Who may push is
  // checked first, so no one is asked for a passkey, or told about the
  // plan, for a push they may not make.
  "push.action": { auth: ["account"], handler(ctx, caller, raw, invocation) {
    const principal = asMember(caller)
    const { slug, records } = parseOpInput(PushAgainInput, raw)
    authorise(ctx, invocation, { type: "credential.push" }, { credential: visibleCredential(ctx, principal, slug, undefined, invocation).id })
    return pushAgainPlan(ctx, principal, invocation, slug, records).action
  } },
  // Queues one push per record under the person's passkey; the route sends
  // them through push.execute.
  "push.again": { auth: ["account"], handler(ctx, caller, raw, invocation) {
    const principal = asMember(caller)
    const { slug, records } = parseOpInput(PushAgainInput, raw)
    return ctx.storage.transactionSync(() => {
      const plan = pushAgainPlan(ctx, principal, invocation, slug, records)
      requireStepUp(ctx, authorise(ctx, invocation, { type: "credential.push" }, { credential: plan.item.id }), plan.action, invocation)
      return { pushes: plan.parts.map((part) => insertQueuedPush(ctx, part, { member: principal.memberId })) }
    })
  } },
  // What the Worker's write gave, for a push being sent; nothing else.
  "push.record": { auth: ["system"], handler(ctx, _principal, raw) {
    const input = RecordInput.parse(raw)
    return ctx.storage.transactionSync(() => {
      const row = pushRow(ctx, input.push)
      if (!row || !finish(ctx, row, "sending", input.state, { outcome: input.state === "done" ? input.outcome ?? "set" : null, providerStatus: input.providerStatus })) throw new VaultError("conflict", "This push is not being sent.")
      return { push: row.id, state: input.state }
    })
  } },
}

export const pushesArea: Area = {
  name: "pushes",
  migrations: [PUSHES_MIGRATION],
  workspaceOps: workspacePushOps,
  async alarm(ctx, key) {
    if (key === PUSH_SWEEP_KEY) sweepPushes(ctx)
  },
}
