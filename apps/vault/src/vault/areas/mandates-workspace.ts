// Mandates: a member signs once, with a passkey, that one
// of their own machines may send certain classes of held request with
// certain credentials without asking, until a date, within daily caps and,
// optionally, only in certain hours. The relay asks coveringMandate after
// the standing rules, task grants and postures, and only for a request the
// policy holds; mandates.ts (protocol) decides what a request is and whether
// the terms cover it. Behind MANDATES (mandatesOn); a managed workspace has
// none.

import { MANDATE_CLASSES, MANDATE_ENDING_NOTICE_MS, MANDATE_LIST_MAX, MANDATE_LIVE_STATES, MANDATE_PROPOSAL_TTL_MS, MANDATE_PROPOSALS_DAY_MAX, MANDATE_PROPOSALS_OPEN_MAX, MANDATE_RATE_LIMIT, MANDATE_RATE_WINDOW_MS, MANDATE_RECEIPT_KEEP_MS, MANDATE_USES_PAGE, MANDATE_ASKED_WINDOW_MS, MANDATE_PROPOSAL_CAP_DEFAULTS, MANDATE_PROPOSAL_DEFAULT_TTL_DAYS, MandateActionRequestSchema, MandateIdSchema, MandateProposalIdSchema, MandateProposeSchema, MandateRevSchema, MandateSignSchema, mandateReceiptsCursor, parseMandateReceiptsCursor, type MandateChanged, type MandateClass, type MandateCounts, type MandateList, type MandateOpenProposal, type MandateProposalCreated, type MandateProposalView, type MandateProposedTerms, type MandateReceiptsPage, type MandateReceiptView, type MandateState, type MandateTerms, type MandateView, type MandateActionAnswer, type MandateAsked, type MandateProposalRefusal, type MandateCandidates, type MandateCappedAsk, type MandateCoverAsk, type MandateCoverHint, type MandateCoverState, type SessionIdentityCheck, type WorkspaceRole, type WorkspaceStepUpAction } from "@mehen/protocol"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { mandateClassesOf, mandateCovers, mandateDigest, mandateHostNamed, mandateRequestFacts, mandateScheduleOpen } from "@mehen/protocol/mandates"
import { policyCatalogueVerdict } from "@mehen/protocol/policy-safety"
import { z } from "zod"
import type { Env } from "../../env.ts"
import { VaultError } from "../../http.ts"
import { can, eligibility, type AccessAsk, type AccessCredential, type AccessPrincipal, type AccessState } from "../access.ts"
import { one, randomId, rows, type Area, type VaultContext } from "../core.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { workspaceApproval } from "./approvals-workspace.ts"
import { devicePolicyState } from "./devices.ts"
import { lapseMandates } from "./mandates-lapse.ts"
import { credentialAudit, type CheckedCredential } from "./items-workspace.ts"
import { parseOpInput } from "./items.ts"
import { anchorOf, managesHome, type HeldRequest } from "./policy-rules-workspace.ts"
import { projects } from "./projects.ts"
import { readableDevices } from "./workspace-devices.ts"
import { accessState, authorise, capabilityState, eligibilityState, managedSetting, queueNotice, registerAccessChangeHook, registerSecurityChangeHook, requireStepUp, security, setting, workspaceRef, type AccessAllowed, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

const DAY_MS = 86_400_000
// Today's counts, and the sweep keeps eight days of them.
const COUNT_KEEP_DAYS = 8
// The workspace's list: live mandates and recent ended ones, newest first.
const WORKSPACE_LIST_MAX = 100
export const MANDATE_SWEEP_KEY = "mandate-sweep"

export const MANDATES_MIGRATION = `CREATE TABLE mandates (id TEXT PRIMARY KEY, device TEXT NOT NULL, signer_member TEXT NOT NULL, terms TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL, rev INTEGER NOT NULL, basis TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, stopped_at INTEGER, ended_reason TEXT, paused_by TEXT, ending_noticed_at INTEGER, lapsed_at INTEGER);
CREATE UNIQUE INDEX mandates_live ON mandates(device) WHERE state IN ('active','paused','tripped');
CREATE INDEX mandates_created ON mandates(created_at);
CREATE TABLE mandate_proposals (id TEXT PRIMARY KEY, device TEXT NOT NULL, terms TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, closed_at INTEGER, mandate_id TEXT);
CREATE INDEX mandate_proposals_device ON mandate_proposals(device, created_at);
CREATE TABLE mandate_counts (mandate_id TEXT NOT NULL, day INTEGER NOT NULL, cls TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (mandate_id, day, cls));
CREATE TABLE mandate_rate (mandate_id TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX mandate_rate_at ON mandate_rate(mandate_id, at);
CREATE TABLE mandate_uses (id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL, at INTEGER NOT NULL, item_id TEXT NOT NULL, item_private INTEGER NOT NULL, classes TEXT NOT NULL, method TEXT NOT NULL, host TEXT NOT NULL, entry TEXT NOT NULL, run TEXT, approval_shape TEXT);
CREATE INDEX mandate_uses_page ON mandate_uses(mandate_id, at, id);`
// An ask a mandate would have let through but for a cap, for the ask page.
export const MANDATE_CAPPED_ASKS_MIGRATION = "CREATE TABLE mandate_capped_asks (approval TEXT PRIMARY KEY, mandate_id TEXT NOT NULL, capped TEXT NOT NULL, at INTEGER NOT NULL);"
// An approval lasts an hour (APPROVAL_TTL_MS), so a capped ask's line is
// kept well past the ask's expiry or decision, and no longer.
const CAPPED_ASK_KEEP_MS = 2 * DAY_MS
// closed_by: the mandate signed for the machine since, which closed this
// open proposal of the same machine.
export const MANDATE_PROPOSALS_CLOSED_BY_MIGRATION = "ALTER TABLE mandate_proposals ADD COLUMN closed_by TEXT;"
// An ask a mandate could have let through (mandateCoverHint), kept as long
// as a capped ask's line, for the ask page to offer one.
export const MANDATE_COVER_ASKS_MIGRATION = "CREATE TABLE mandate_cover_asks (approval TEXT PRIMARY KEY, device TEXT NOT NULL, classes TEXT NOT NULL, at INTEGER NOT NULL);"
// The proposal each mandate in a list was signed from (mandateView), found
// without reading every proposal, which the sweep closes but never deletes.
export const MANDATE_PROPOSALS_MANDATE_MIGRATION = "CREATE INDEX mandate_proposals_mandate ON mandate_proposals(mandate_id);"
// The last time each machine asked for a credential in a class a mandate
// could cover (a held request with a mandateCover hint), so a proposal of
// its own names only what it asked for. Pruned after MANDATE_ASKED_WINDOW_MS.
// It starts from the held asks with a hint the vault still keeps
// (mandate_cover_asks, CAPPED_ASK_KEEP_MS); a machine's own mandate uses
// are read from mandate_uses directly, so they need no copy.
export const MANDATE_ASKED_MIGRATION = `CREATE TABLE mandate_asked (device TEXT NOT NULL, item_id TEXT NOT NULL, cls TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (device, item_id, cls));
INSERT INTO mandate_asked(device,item_id,cls,at) SELECT c.device, COALESCE(json_extract(a.ask,'$.credential'), (SELECT i.id FROM items i WHERE i.slug=a.item)) AS item_id, j.value, MAX(c.at) FROM mandate_cover_asks c JOIN approvals a ON a.id=c.approval, json_each(c.classes) j WHERE item_id IS NOT NULL GROUP BY c.device, item_id, j.value;`

// Whether mandates are on in this workspace (its tn_ id), read as
// workspaceSwitchOn reads every switch.
export function mandatesOn(env: Pick<Env, "MANDATES">, workspace: string): boolean {
  return workspaceSwitchOn(env.MANDATES, workspace)
}
const mandatesHere = (ctx: VaultContext): boolean => mandatesOn(ctx.env, ctx.tenant) && managedSetting(ctx) === null
const frozen = (ctx: VaultContext): boolean => setting(ctx, "frozen", false)
// With the switch off, every mandate op answers as if it did not exist.
function mandatesAvailable(ctx: VaultContext): void {
  if (!mandatesOn(ctx.env, ctx.tenant)) throw new VaultError("not_found", "No such route.")
  if (managedSetting(ctx) !== null) throw new VaultError("forbidden", "The platform decides what each machine may do without asking.")
}
function mandateChanged(): VaultError {
  return new VaultError("conflict", "This mandate changed; review and try again.")
}
const noSuchMandate = (): VaultError => new VaultError("not_found", "No such mandate.")

// What sign and resume store about the person who signed (5.3): enough to
// tell, at each use, that the same member in the same role, on the same
// account security and identity check, still stands. The session is kept
// for the record only: a mandate outlives the browser that signed it.
type SigningBasis = { sessionCheck: SessionIdentityCheck | null; session: string; account: string; securityEpoch: number; member: string; role: WorkspaceRole }
// paused_by: who paused a paused mandate, which decides whether its signer
// may resume it without a passkey; null in every other state.
type PausedBy = "signer" | "machine" | "admin"
// ending_noticed_at: when its signer was told it ends soon, once, or, for
// one no longer than the notice window, when it was signed.
// lapsed_at: when a change to the signer's access or the machine ended its
// cover, for good: undoing the change does not restore it, only the
// signer's passkey resume does.
type MandateRow = { id: string; device: string; signer_member: string; terms: string; digest: string; state: MandateState; rev: number; basis: string; created_at: number; expires_at: number; stopped_at: number | null; ended_reason: MandateView["endedReason"]; paused_by: PausedBy | null; ending_noticed_at: number | null; lapsed_at: number | null }
type ProposalRow = { id: string; device: string; terms: string; reason: string; created_at: number; expires_at: number; closed_at: number | null; mandate_id: string | null; closed_by: string | null }
type UseRow = { id: string; mandate_id: string; at: number; item_id: string; item_private: number; classes: string; method: string; host: string; entry: string; run: string | null }

const mandateRow = (ctx: VaultContext, id: string) => one(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE id=?", id))
// The machine's mandate that is active, paused or tripped, if any.
const liveRow = (ctx: VaultContext, device: string) => one(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE device=? AND state IN ('active','paused','tripped')", device))
const termsOf = (row: MandateRow): MandateTerms => JSON.parse(row.terms) as MandateTerms
const basisOf = (row: MandateRow): SigningBasis => JSON.parse(row.basis) as SigningBasis
// The state as read now: a live mandate past its end is expired before the
// sweep writes it.
const stateNow = (row: MandateRow, now: number): MandateState => (MANDATE_LIVE_STATES.includes(row.state) && now >= row.expires_at ? "expired" : row.state)
const dayOf = (ms: number): number => Math.floor(ms / DAY_MS)
const iso = (ms: number): string => new Date(ms).toISOString()

function todayCounts(ctx: VaultContext, mandate: string, now: number): MandateCounts {
  const counts: MandateCounts = { read: 0, change: 0, send: 0, delete: 0 }
  for (const row of rows(ctx.sql.exec<{ cls: MandateClass; n: number }>("SELECT cls,n FROM mandate_counts WHERE mandate_id=? AND day=?", mandate, dayOf(now)))) counts[row.cls] = row.n
  return counts
}
// Covered requests other than reads in (now - 60s, now].
const rateCount = (ctx: VaultContext, mandate: string, now: number): number => one(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM mandate_rate WHERE mandate_id=? AND at>?", mandate, now - MANDATE_RATE_WINDOW_MS))?.n ?? 0
const writesBeyondRead = (classes: Iterable<MandateClass>): boolean => [...classes].some((c) => c !== "read")
// The classes of the union that have no cap left today for one more request.
function cappedClasses(ctx: VaultContext, row: MandateRow, classes: Iterable<MandateClass>, now: number): MandateClass[] {
  const terms = termsOf(row), counts = todayCounts(ctx, row.id, now)
  return MANDATE_CLASSES.filter((c) => [...classes].includes(c) && counts[c] + 1 > terms.caps[c])
}

// ---------------------------------------------------------------- the signer

// Whether the account that signed is as it was (5.3): the same security
// epoch, nothing pending or being deleted, and, for a member under an
// identity gate, the rule and gate generation the signing session's check
// was made under. Never the session itself, so signing out, another browser
// or a session ending keeps the mandate; recovery, a passkey removed or any
// other security change moves the epoch and ends it.
function signerAccountCurrent(ctx: VaultContext, member: AccessState["members"][number], basis: SigningBasis): boolean {
  const sec = security(ctx, basis.account)
  if (!sec || sec.installedEpoch !== basis.securityEpoch || sec.deleting || sec.pending) return false
  if (!member.standing.identityGate.covered) return true
  const check = basis.sessionCheck
  return check !== null && check.identityRuleRev === member.standing.identityRuleRev && check.gateGeneration === member.standing.gateGeneration
}
// Whether the person who signed still stands behind the mandate now, for
// any credential: not lapsed, their account, their standing as a member in
// the role they signed in, and the machine still theirs.
function mandateSignerStands(ctx: VaultContext, state: AccessState, row: MandateRow, now: number): boolean {
  if (row.lapsed_at !== null) return false
  const basis = basisOf(row)
  const member = state.members.find((m) => m.id === basis.member && m.account === basis.account)
  if (!member || member.status !== "active" || member.standing.effectiveRole !== basis.role || member.standing.transitionPending || member.standing.restriction !== null && member.standing.restriction.until > now) return false
  if (!signerAccountCurrent(ctx, member, basis)) return false
  const device = state.devices.find((d) => d.id === row.device)
  return device !== undefined && device.status === "active" && device.owner.kind === "member" && device.owner.id === member.id
}
// And for this credential: management of its home worked out again, not
// pinned to how they had it then.
export function mandateSignerCurrent(ctx: VaultContext, state: AccessState, row: MandateRow, credential: Pick<CheckedCredential, "home">, now: number): boolean {
  return mandateSignerStands(ctx, state, row, now) && managesHome(state, basisOf(row).member, credential.home, now)
}
function signingBasis(state: AccessState, decision: AccessAllowed, invocation: WorkspaceInvocationContext): SigningBasis {
  const auth = invocation.auth
  if (auth.kind !== "account" || decision.principal.kind !== "member") throw new VaultError("forbidden", "Only a person can sign a mandate.")
  const memberId = decision.principal.memberId
  const member = state.members.find((m) => m.id === memberId)
  if (!member) throw new VaultError("not_found", "No such object.")
  return { sessionCheck: auth.sessionCheck, session: auth.session, account: auth.account, securityEpoch: auth.securityEpoch, member: member.id, role: member.standing.effectiveRole }
}

// ---------------------------------------------------------------- what a reader sees

// Whether this reader may see the credential now: for the machine, that it
// reaches it; for a person, that it is visible to them.
const seesCredential = (state: AccessState, reader: AccessPrincipal, credential: string, now: number): boolean => can(state, reader, { type: "item.read" }, { credential }, now).allowed
const readerState = (ctx: VaultContext, invocation: WorkspaceInvocationContext): AccessState => eligibilityState(ctx, invocation)
const memberName = (state: AccessState, member: string): string => state.members.find((m) => m.id === member)?.name ?? "someone who has left"
const deviceName = (ctx: VaultContext, device: string): string => devicePolicyState(ctx, device)?.name ?? device

// One projection for every reader (5.4), computed now from their access;
// whether the signer still stands behind it only for a person reading a
// live one, and whether they signed it only for a person.
function mandateView(ctx: VaultContext, state: AccessState, reader: AccessPrincipal, row: MandateRow): MandateView {
  const terms = termsOf(row), now = ctx.now(), current = stateNow(row, now)
  const listed = terms.items === "all" ? null : terms.items.flatMap((id) => {
    const credential = state.credentials.find((c) => c.id === id)
    return credential?.slug !== undefined && seesCredential(state, reader, id, now) ? [credential.slug] : []
  })
  return {
    id: row.id, device: { id: row.device, name: deviceName(ctx, row.device) }, signer: { name: memberName(state, row.signer_member), ...(reader.kind === "member" ? { self: reader.memberId === row.signer_member } : {}) },
    state: current, rev: row.rev, ...(reader.kind === "member" && MANDATE_LIVE_STATES.includes(current) ? { signerCurrent: mandateSignerStands(ctx, accessState(ctx), row, now) } : {}),
    items: listed ?? "all", hiddenItems: terms.items === "all" || listed === null ? 0 : terms.items.length - listed.length,
    classes: terms.classes, caps: terms.caps, today: todayCounts(ctx, row.id, now), ttlDays: terms.ttlDays, schedule: terms.schedule, note: terms.note,
    createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), endedReason: current === "expired" ? "expired" : row.ended_reason,
    proposal: one(ctx.sql.exec<{ id: string }>("SELECT id FROM mandate_proposals WHERE mandate_id=?", row.id))?.id ?? null,
  }
}
function receiptView(state: AccessState, reader: AccessPrincipal, row: UseRow, now: number): MandateReceiptView {
  const credential = state.credentials.find((c) => c.id === row.item_id)
  const seen = credential?.slug !== undefined && seesCredential(state, reader, row.item_id, now)
  return { id: row.id, at: iso(row.at), classes: JSON.parse(row.classes) as MandateClass[], method: row.method, credential: seen ? { slug: credential.slug as string, host: row.host, entry: row.entry, run: row.run } : null }
}
function receiptsPage(ctx: VaultContext, state: AccessState, reader: AccessPrincipal, mandate: string, before: string | undefined): MandateReceiptsPage {
  const cursor = before === undefined ? null : parseMandateReceiptsCursor(before)
  if (before !== undefined && cursor === null) throw new VaultError("bad_request", "That is not a page of receipts.")
  const found = cursor === null
    ? rows(ctx.sql.exec<UseRow>("SELECT * FROM mandate_uses WHERE mandate_id=? ORDER BY at DESC,id DESC LIMIT ?", mandate, MANDATE_USES_PAGE + 1))
    : rows(ctx.sql.exec<UseRow>("SELECT * FROM mandate_uses WHERE mandate_id=? AND (at<? OR (at=? AND id<?)) ORDER BY at DESC,id DESC LIMIT ?", mandate, cursor.at, cursor.at, cursor.id, MANDATE_USES_PAGE + 1))
  const page = found.slice(0, MANDATE_USES_PAGE), now = ctx.now()
  const last = page.at(-1)
  return { receipts: page.map((row) => receiptView(state, reader, row, now)), next: found.length > MANDATE_USES_PAGE && last ? mandateReceiptsCursor(last.at, last.id) : null }
}

// A person may read a mandate on a machine they may read.
function readableRow(ctx: VaultContext, invocation: WorkspaceInvocationContext, id: string): MandateRow {
  const row = MandateIdSchema.safeParse(id).success ? mandateRow(ctx, id) : null
  if (!row || !readableDevices(ctx, invocation).some((d) => d.id === row.device)) throw noSuchMandate()
  return row
}
// A machine reads only its own.
function ownRow(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, id: string): MandateRow {
  const row = MandateIdSchema.safeParse(id).success ? mandateRow(ctx, id) : null
  if (!row || row.device !== principal.deviceId) throw noSuchMandate()
  return row
}
function machineOnly(principal: AccessPrincipal): Extract<AccessPrincipal, { kind: "device" }> {
  if (principal.kind !== "device") throw new VaultError("forbidden", "Only a machine can do that.")
  if (principal.workload !== undefined) throw new VaultError("forbidden", "A workload has no mandate: its requests always ask in this version. Run the work as the machine itself, whose owner may sign it a mandate, or propose a task grant for this work with `mehen policy propose`.", { next: { command: "mehen policy propose --from <apr_id> --reason <why>", say: "A workload's requests always ask; run the work as the machine itself, or ask for a task grant for routine work." } })
  return principal
}

// ---------------------------------------------------------------- proposing

const ProposalInput = MandateProposeSchema
const proposalUrl = (ctx: VaultContext, invocation: WorkspaceInvocationContext, id: string): string => `${ctx.env.VAULT_ORIGIN}/w/${encodeURIComponent(invocation.workspace.slug)}/sign-mandate?proposal=${encodeURIComponent(id)}`
// A machine's proposals still open, newest first.
const openProposalRows = (ctx: VaultContext, device: string, now: number): ProposalRow[] => rows(ctx.sql.exec<ProposalRow>("SELECT * FROM mandate_proposals WHERE device=? AND closed_at IS NULL AND expires_at>? ORDER BY created_at DESC,id DESC", device, now))
// An open proposal as a list shows it: the slugs it names that this reader
// may see now, and how many others.
function openProposalView(ctx: VaultContext, state: AccessState, reader: AccessPrincipal, invocation: WorkspaceInvocationContext, row: ProposalRow): MandateOpenProposal {
  const terms = JSON.parse(row.terms) as MandateProposedTerms, now = ctx.now()
  const seen = terms.items === "all" ? null : terms.items.filter((slug) => {
    const credential = state.credentials.find((c) => c.slug === slug)
    return credential !== undefined && seesCredential(state, reader, credential.id, now)
  })
  return {
    id: row.id, url: proposalUrl(ctx, invocation, row.id), expiresAt: iso(row.expires_at), createdAt: iso(row.created_at), device: { id: row.device, name: deviceName(ctx, row.device) },
    classes: terms.classes, items: seen ?? "all", hiddenItems: terms.items === "all" || seen === null ? 0 : terms.items.length - seen.length, reason: row.reason,
  }
}
// What a machine asked for in the window: each held request a mandate could
// cover (mandate_asked) and each request its own mandates covered
// (mandate_uses), by credential id and class. Another machine's never count.
function askedBy(ctx: VaultContext, device: string, now: number): { items: Set<string>; classes: Set<MandateClass> } {
  const since = now - MANDATE_ASKED_WINDOW_MS
  const items = new Set<string>(), classes = new Set<MandateClass>()
  for (const row of rows(ctx.sql.exec<{ item_id: string; cls: string }>("SELECT item_id,cls FROM mandate_asked WHERE device=? AND at>?", device, since))) {
    items.add(row.item_id)
    classes.add(row.cls as MandateClass)
  }
  for (const row of rows(ctx.sql.exec<{ item_id: string; classes: string }>("SELECT u.item_id,u.classes FROM mandate_uses u JOIN mandates m ON m.id=u.mandate_id WHERE m.device=? AND u.at>?", device, since))) {
    items.add(row.item_id)
    for (const cls of JSON.parse(row.classes) as MandateClass[]) classes.add(cls)
  }
  classes.delete("read")
  return { items, classes }
}
const sortedSlugs = (state: AccessState, ids: Set<string>): string[] => state.credentials.flatMap((c) => (c.slug !== undefined && ids.has(c.id) ? [c.slug] : [])).sort()
function askedView(ctx: VaultContext, p: AccessPrincipal): MandateAsked {
  mandatesAvailable(ctx)
  const principal = machineOnly(p), asked = askedBy(ctx, principal.deviceId, ctx.now())
  return { items: sortedSlugs(accessState(ctx), asked.items), classes: MANDATE_CLASSES.filter((c) => asked.classes.has(c)) }
}
// A machine proposes only what it asked for: never every credential, no
// credential or class besides read it did not ask for or use lately, no
// longer than 30 days and no cap above the proposal defaults. The person who
// signs may still widen any of them on the sign page.
function refuseBroad(ctx: VaultContext, state: AccessState, device: string, terms: MandateProposedTerms, now: number): void {
  const asked = askedBy(ctx, device, now)
  const askedSlugs = sortedSlugs(state, asked.items)
  // The same proposal cut to what a machine may propose, for next.command.
  const named = terms.items === "all" ? [] : terms.items.filter((slug) => askedSlugs.includes(slug))
  const items = named.length ? named : askedSlugs
  const classes = MANDATE_CLASSES.filter((c) => terms.classes.includes(c) && (c === "read" || asked.classes.has(c)))
  const days = Math.min(terms.ttlDays, MANDATE_PROPOSAL_DEFAULT_TTL_DAYS)
  const caps = classes.map((c) => `${c}=${Math.min(terms.caps[c], MANDATE_PROPOSAL_CAP_DEFAULTS[c])}`).join(",")
  const retry = items.length > 0 ? `mehen mandate propose --items ${items.join(",")} --classes ${classes.join(",")} --days ${days} --caps ${caps} --note <why>` : null
  const askedWords = askedSlugs.length ? `It asked for ${askedSlugs.join(", ")} in the last 30 days` : "It asked for nothing a mandate could cover in the last 30 days"
  const refuse = (refusal: MandateProposalRefusal, message: string, say: string): never => { throw new VaultError("forbidden", `${message} ${askedWords}. A person can choose wider terms on the sign page.`, { next: { ...(retry ? { command: retry } : {}), say: retry ? say : "Ask for each request as usual; propose a mandate once more asks like them will follow." }, mandateRefused: refusal }) }
  if (terms.items === "all") refuse("items_all", "A machine cannot propose a mandate for every credential: drop items all and name the credentials it asked for.", "Propose again naming only the credentials this machine asked for; the person signing can add others.")
  const unasked = (terms.items as string[]).filter((slug) => !askedSlugs.includes(slug))
  if (unasked.length) refuse("item_unasked", `This machine has not asked for ${unasked.join(", ")}: drop ${unasked.length === 1 ? "it" : "them"} from the proposal.`, "Propose again without the credentials this machine did not ask for; the person signing can add them.")
  const extra = terms.classes.filter((c) => c !== "read" && !asked.classes.has(c))
  if (extra.length) refuse("class_unasked", `This machine has not asked to ${extra.join(" or ")}: drop ${extra.join(" and ")} from the proposal.`, "Propose again without the kinds this machine did not ask for; the person signing can add them.")
  if (terms.ttlDays > MANDATE_PROPOSAL_DEFAULT_TTL_DAYS) refuse("term_too_long", `A machine can propose a mandate for at most ${MANDATE_PROPOSAL_DEFAULT_TTL_DAYS} days: lower ${terms.ttlDays} days to ${MANDATE_PROPOSAL_DEFAULT_TTL_DAYS}.`, `Propose again for ${MANDATE_PROPOSAL_DEFAULT_TTL_DAYS} days or fewer; the person signing can make it longer.`)
  const high = terms.classes.filter((c) => terms.caps[c] > MANDATE_PROPOSAL_CAP_DEFAULTS[c])
  if (high.length) refuse("caps_too_high", `A machine can propose at most ${MANDATE_PROPOSAL_CAP_DEFAULTS.read} reads, ${MANDATE_PROPOSAL_CAP_DEFAULTS.change} changes, ${MANDATE_PROPOSAL_CAP_DEFAULTS.send} sends and ${MANDATE_PROPOSAL_CAP_DEFAULTS.delete} deletes a day: lower ${high.map((c) => `${c} from ${terms.caps[c]} to ${MANDATE_PROPOSAL_CAP_DEFAULTS[c]}`).join(", ")}.`, "Propose again with caps at or under those; the person signing can raise them.")
}
function propose(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): MandateProposalCreated {
  mandatesAvailable(ctx)
  const principal = machineOnly(p)
  // Nobody could sign it while the workspace is frozen.
  if (frozen(ctx)) throw new VaultError("frozen", "This workspace is frozen.")
  const input = parseOpInput(ProposalInput, raw)
  const now = ctx.now(), state = accessState(ctx)
  const device = state.devices.find((d) => d.id === principal.deviceId && d.status === "active")
  if (!device) throw new VaultError("not_found", "No such machine.")
  if (device.owner.kind !== "member") throw new VaultError("forbidden", "A team's machine cannot have a mandate yet: team machines get mandates signed by two people in a later version. For routine work now, propose a task grant with `mehen policy propose`.", { next: { command: "mehen policy propose --from <apr_id> --reason <why>", say: "A team's machine cannot carry on without asking yet; ask for a task grant for routine work instead." } })
  refuseBroad(ctx, state, device.id, input.terms, now)
  return ctx.storage.transactionSync(() => {
    const open = openProposalRows(ctx, device.id, now)
    // The same terms and reason as one still open: that one, nothing new.
    const same = open.find((row) => row.reason === input.reason && canonicalJson(JSON.parse(row.terms)) === canonicalJson(input.terms))
    if (same) return { id: same.id, url: proposalUrl(ctx, invocation, same.id), expiresAt: iso(same.expires_at), existing: true }
    const newest = open[0]
    if (open.length >= MANDATE_PROPOSALS_OPEN_MAX && newest) throw new VaultError("conflict", `This machine already has ${open.length} mandates waiting for a person, which \`mehen mandate ls\` lists; wait for one to be signed or to expire.`, { next: { url: proposalUrl(ctx, invocation, newest.id), say: `This machine already has ${open.length} mandates waiting for you; open the newest to review and sign it.` } })
    const today = one(ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM mandate_proposals WHERE device=? AND created_at>=?", device.id, dayOf(now) * DAY_MS))?.n ?? 0
    if (today >= MANDATE_PROPOSALS_DAY_MAX) throw new VaultError("rate_limited", `This machine has proposed ${MANDATE_PROPOSALS_DAY_MAX} mandates today; try again tomorrow.`)
    const id = randomId("mdp")
    const expiresAt = now + MANDATE_PROPOSAL_TTL_MS
    ctx.sql.exec("INSERT INTO mandate_proposals(id,device,terms,reason,created_at,expires_at) VALUES (?,?,?,?,?,?)", id, device.id, JSON.stringify(input.terms), input.reason, now, expiresAt)
    ctx.audit({ actor: `device:${device.id}`, action: "mandate.propose", target: id, detail: { device: device.id, classes: input.terms.classes, ttlDays: input.terms.ttlDays, items: input.terms.items === "all" ? "all" : input.terms.items.length } })
    scheduleMandateSweep(ctx)
    return { id, url: proposalUrl(ctx, invocation, id), expiresAt: iso(expiresAt) }
  })
}

// A proposal, for its machine's owner: the credentials it names by slug
// that they may see, as refs the sign page puts in the terms by id.
function proposalView(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): MandateProposalView {
  mandatesAvailable(ctx)
  const { id } = parseOpInput(z.strictObject({ id: z.string().max(80) }), raw)
  const row = MandateProposalIdSchema.safeParse(id).success ? one(ctx.sql.exec<ProposalRow>("SELECT * FROM mandate_proposals WHERE id=?", id)) : null
  const state = readerState(ctx, invocation), now = ctx.now()
  const device = row ? state.devices.find((d) => d.id === row.device) : undefined
  if (!row || p.kind !== "member" || device?.owner.kind !== "member" || device.owner.id !== p.memberId) throw new VaultError("not_found", "No such proposal.")
  const terms = JSON.parse(row.terms) as MandateProposedTerms
  const refs = terms.items === "all" ? null : terms.items.flatMap((slug) => {
    const credential = state.credentials.find((c) => c.slug === slug)
    return credential && seesCredential(state, p, credential.id, now) ? [{ id: credential.id, slug }] : []
  })
  return {
    id: row.id, device: { id: row.device, name: deviceName(ctx, row.device) },
    items: refs ?? "all", hiddenItems: terms.items === "all" || refs === null ? 0 : terms.items.length - refs.length,
    classes: terms.classes, caps: terms.caps, ttlDays: terms.ttlDays, schedule: terms.schedule, note: terms.note, reason: row.reason,
    state: row.mandate_id !== null ? "signed" : row.closed_at !== null || now >= row.expires_at ? "expired" : "open", mandate: row.mandate_id ?? row.closed_by,
    createdAt: iso(row.created_at), expiresAt: iso(row.expires_at),
  }
}

// ---------------------------------------------------------------- signing

// The member's own active machine, which only they may sign a mandate for.
const ownMachine = (state: AccessState, member: string, device: string) => state.devices.find((d) => d.id === device && d.status === "active" && d.owner.kind === "member" && d.owner.id === member) ?? null
// Why a signer may not name this credential for their machine, or null when
// they may: the machine reaches it now and they manage where it lives. The
// sign page offers only those with none (mandates.candidates).
function credentialUnsignable(state: AccessState, member: string, device: string, credential: AccessCredential, now: number): "unreachable" | "unmanaged" | null {
  if (!seesCredential(state, { kind: "device", deviceId: device }, credential.id, now)) return "unreachable"
  return managesHome(state, member, credential.home, now) ? null : "unmanaged"
}

// Everything a signature needs from live state, checked before the passkey
// and again inside the transaction: the machine is the signer's and active,
// each listed credential one the signer manages the home of and the machine
// reaches, and a named proposal this machine's, open and unexpired.
function checkSignable(ctx: VaultContext, invocation: WorkspaceInvocationContext, terms: MandateTerms, proposal: string | undefined): AccessAllowed {
  mandatesAvailable(ctx)
  if (frozen(ctx)) throw new VaultError("frozen", "This workspace is frozen.")
  const now = ctx.now()
  const decision = authorise(ctx, invocation, { type: "mandate.sign" }, { device: terms.device }, now)
  if (decision.principal.kind !== "member") throw new VaultError("forbidden", "Only a person can sign a mandate.")
  const memberId = decision.principal.memberId
  const state = accessState(ctx)
  const device = ownMachine(state, memberId, terms.device)
  if (!device) throw new VaultError("forbidden", "Only the machine's owner can sign its mandate.")
  if (terms.items !== "all") {
    for (const id of terms.items) {
      const credential = state.credentials.find((c) => c.id === id)
      const refusal = credential ? credentialUnsignable(state, memberId, device.id, credential, now) : "unreachable"
      if (refusal === "unreachable") throw new VaultError("bad_request", "One of these credentials is not one this machine can use.")
      if (refusal === "unmanaged") throw new VaultError("bad_request", `You do not manage where "${credential?.slug ?? id}" lives, so you cannot let a machine use it without asking.`)
    }
  }
  if (proposal !== undefined) {
    const row = one(ctx.sql.exec<ProposalRow>("SELECT * FROM mandate_proposals WHERE id=?", proposal))
    if (!row || row.device !== device.id) throw new VaultError("bad_request", "That proposal is not this machine's.")
    if (row.closed_at !== null || now >= row.expires_at) throw new VaultError("bad_request", "That proposal has expired or was already signed.")
  }
  return decision
}
async function signAction(ctx: VaultContext, invocation: WorkspaceInvocationContext, terms: MandateTerms, proposal: string | undefined): Promise<WorkspaceStepUpAction> {
  const decision = checkSignable(ctx, invocation, terms, proposal)
  const signer = decision.principal.kind === "member" ? decision.principal.memberId : ""
  return { type: "mandate.sign", device: terms.device, digest: await mandateDigest({ terms, workspace: ctx.tenant, signer }) }
}

async function sign(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<MandateChanged> {
  const { terms, proposal } = parseOpInput(MandateSignSchema, raw)
  const action = await signAction(ctx, invocation, terms, proposal)
  return ctx.storage.transactionSync(() => {
    const decision = checkSignable(ctx, invocation, terms, proposal)
    requireStepUp(ctx, decision, action, invocation)
    if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can sign a mandate.")
    const state = accessState(ctx), now = ctx.now()
    const basis = signingBasis(state, decision, invocation)
    // One live mandate a machine: the one before ends here.
    const before = liveRow(ctx, terms.device)
    if (before) endRow(ctx, before, now >= before.expires_at ? "expired" : "stopped", now >= before.expires_at ? "expired" : "replaced", `member:${p.memberId}`)
    const id = randomId("mdt")
    const expiresAt = now + terms.ttlDays * DAY_MS
    if (action.type !== "mandate.sign") throw new Error("unreachable")
    // One no longer than the notice window has no moment before its end to
    // be told of, and is never told.
    const noticed = expiresAt - now <= MANDATE_ENDING_NOTICE_MS ? now : null
    ctx.sql.exec("INSERT INTO mandates(id,device,signer_member,terms,digest,state,rev,basis,created_at,expires_at,ending_noticed_at) VALUES (?,?,?,?,?,'active',1,?,?,?,?)", id, terms.device, p.memberId, JSON.stringify(terms), action.digest, JSON.stringify(basis), now, expiresAt, noticed)
    if (proposal !== undefined) ctx.sql.exec("UPDATE mandate_proposals SET closed_at=?,mandate_id=? WHERE id=?", now, id, proposal)
    // What the machine asked for before is settled by this signature.
    ctx.sql.exec("UPDATE mandate_proposals SET closed_at=?,closed_by=? WHERE device=? AND closed_at IS NULL AND expires_at>?", now, id, terms.device, now)
    const row = mandateRow(ctx, id) as MandateRow
    ctx.audit({ actor: `member:${p.memberId}`, action: "mandate.sign", target: id, detail: { device: terms.device, classes: terms.classes, caps: terms.caps, ttlDays: terms.ttlDays, schedule: terms.schedule !== null, items: terms.items === "all" ? "all" : terms.items.length, proposal: proposal ?? null, replaced: before?.id ?? null } })
    notice(ctx, "mandate_signed", row, state)
    scheduleMandateSweep(ctx)
    return { mandate: mandateView(ctx, readerState(ctx, invocation), p, row) }
  })
}

// The credentials the sign page offers for the reader's own active
// machine: exactly those signing would accept, among those the reader may
// see now, by slug. Any machine they may not sign for (another's, a team's,
// their own revoked one, or any for a guest) is no such machine.
function candidates(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): MandateCandidates {
  mandatesAvailable(ctx)
  if (frozen(ctx)) throw new VaultError("frozen", "This workspace is frozen.")
  const { device } = parseOpInput(z.strictObject({ device: z.string().max(80) }), raw)
  const state = accessState(ctx), now = ctx.now()
  if (p.kind !== "member" || !can(state, p, { type: "mandate.sign" }, { device }, now).allowed || ownMachine(state, p.memberId, device) === null) throw new VaultError("not_found", "No such machine.")
  const reader = readerState(ctx, invocation)
  const items = state.credentials.flatMap((c) => c.slug !== undefined && credentialUnsignable(state, p.memberId, device, c, now) === null && seesCredential(reader, p, c.id, now) ? [{ id: c.id, slug: c.slug }] : [])
  return { items: items.sort((a, b) => (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0)) }
}

// ---------------------------------------------------------------- pause, resume, stop

// Ends a live mandate: stopped by a person or replaced by a new signature,
// or expired by the sweep.
function endRow(ctx: VaultContext, row: MandateRow, state: "stopped" | "expired", reason: NonNullable<MandateView["endedReason"]>, actor: string): void {
  ctx.sql.exec("UPDATE mandates SET state=?,rev=rev+1,stopped_at=?,ended_reason=?,paused_by=NULL WHERE id=?", state, ctx.now(), reason, row.id)
  ctx.audit({ actor, action: state === "expired" ? "mandate.expire" : "mandate.stop", target: row.id, detail: { device: row.device, reason } })
}
// Pausing a paused or tripped mandate changes nothing and succeeds whatever
// revision it names, since it only narrows, except that an owner's or
// admin's pause takes over one by the signer or the machine, so resuming it
// needs a passkey; a stopped or expired one cannot be paused. A workload
// that pulls the brake is named in the audit row beside its machine.
function pauseRow(ctx: VaultContext, row: MandateRow, rev: number, actor: string, by: PausedBy, workload?: string): void {
  const state = stateNow(row, ctx.now())
  if (state === "paused" && by === "admin" && row.paused_by !== "admin") {
    ctx.sql.exec("UPDATE mandates SET paused_by='admin',rev=rev+1 WHERE id=?", row.id)
    ctx.audit({ actor, action: "mandate.pause", target: row.id, detail: { device: row.device } })
    return
  }
  if (state === "paused" || state === "tripped") return
  if (row.rev !== rev || state === "stopped" || state === "expired") throw mandateChanged()
  ctx.sql.exec("UPDATE mandates SET state='paused',rev=rev+1,paused_by=? WHERE id=?", by, row.id)
  ctx.audit({ actor, action: "mandate.pause", target: row.id, detail: { device: row.device, ...(workload !== undefined ? { workload } : {}) } })
}

// The machine, or a workload on it: a pause only narrows, so either may
// pull the brake, and it counts as the machine's own.
function machinePause(ctx: VaultContext, p: AccessPrincipal, raw: unknown): MandateChanged {
  mandatesAvailable(ctx)
  if (p.kind !== "device") throw new VaultError("forbidden", "Only a machine can do that.")
  const principal = p
  const { id, rev } = parseOpInput(MandateRevSchema.extend({ id: z.string().max(80) }), raw)
  return ctx.storage.transactionSync(() => {
    pauseRow(ctx, ownRow(ctx, principal, id), rev, `device:${principal.deviceId}`, "machine", principal.workload)
    return { mandate: mandateView(ctx, accessState(ctx), principal, mandateRow(ctx, id) as MandateRow) }
  })
}

const PersonChange = MandateRevSchema.extend({ id: z.string().max(80) })
// The signer, or an owner or admin who may read the machine.
function personChange(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext, change: "pause" | "stop"): MandateChanged {
  mandatesAvailable(ctx)
  const { id, rev } = parseOpInput(PersonChange, raw)
  return ctx.storage.transactionSync(() => {
    const row = readableRow(ctx, invocation, id)
    authorise(ctx, invocation, { type: change === "pause" ? "mandate.pause" : "mandate.stop" }, { device: row.device, member: row.signer_member }, ctx.now())
    if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can do that.")
    const actor = `member:${p.memberId}`
    if (change === "pause") pauseRow(ctx, row, rev, actor, p.memberId === row.signer_member ? "signer" : "admin")
    else {
      const state = stateNow(row, ctx.now())
      if (row.rev !== rev || state === "stopped" || state === "expired") throw mandateChanged()
      endRow(ctx, row, "stopped", "stopped", actor)
    }
    return { mandate: mandateView(ctx, readerState(ctx, invocation), p, mandateRow(ctx, id) as MandateRow) }
  })
}

// The signer alone; never a stopped or expired one, nor an active one whose
// signer still stands behind it. A passkey over the mandate's digest and
// the revision resumed, unless the signer or the machine itself paused it
// and the signer still stands behind it: then action is null. The action
// says what it resumes from, as read here: a trip, a signer who no longer
// stands behind it, or else a pause, which alone may ride a passkey window.
function checkResumable(ctx: VaultContext, invocation: WorkspaceInvocationContext, id: string, rev: number): { decision: AccessAllowed; row: MandateRow; action: WorkspaceStepUpAction | null } {
  mandatesAvailable(ctx)
  if (frozen(ctx)) throw new VaultError("frozen", "This workspace is frozen.")
  const row = readableRow(ctx, invocation, id)
  const now = ctx.now()
  const decision = authorise(ctx, invocation, { type: "mandate.resume" }, { device: row.device, member: row.signer_member }, now)
  const state = stateNow(row, now)
  const stands = mandateSignerStands(ctx, accessState(ctx), row, now)
  if (row.rev !== rev || state === "stopped" || state === "expired" || state === "active" && stands) throw mandateChanged()
  const withoutPasskey = state === "paused" && (row.paused_by === "signer" || row.paused_by === "machine") && stands
  const from = state === "tripped" ? "tripped" : stands ? "paused" : "lapsed"
  return { decision, row, action: withoutPasskey ? null : { type: "mandate.resume", mandate: row.id, digest: row.digest, rev: row.rev, from } }
}
function resume(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): MandateChanged {
  const { id, rev } = parseOpInput(PersonChange, raw)
  return ctx.storage.transactionSync(() => {
    const { decision, row, action } = checkResumable(ctx, invocation, id, rev)
    if (action !== null) requireStepUp(ctx, decision, action, invocation)
    if (p.kind !== "member") throw new VaultError("forbidden", "Only a person can resume a mandate.")
    // A passkey records the signer as they are now and ends a lapse;
    // without one, the basis they signed on, which still stands, is kept.
    const basis = action === null ? row.basis : JSON.stringify(signingBasis(accessState(ctx), decision, invocation))
    ctx.sql.exec("UPDATE mandates SET state='active',rev=rev+1,basis=?,paused_by=NULL,lapsed_at=NULL WHERE id=?", basis, row.id)
    ctx.audit({ actor: `member:${p.memberId}`, action: "mandate.resume", target: row.id, detail: { device: row.device, from: action?.type === "mandate.resume" ? action.from : row.state, stepUp: action !== null } })
    return { mandate: mandateView(ctx, readerState(ctx, invocation), p, mandateRow(ctx, id) as MandateRow) }
  })
}

// What ends a mandate's cover for good: a role change, a suspension or
// a removal of its signer, and the machine revoked or rescoped wider. A
// reinstatement, a team change or a narrowing rescope does not.
const LAPSING_MEMBER_CHANGES = new Set(["role", "suspend", "remove", "leave"])
registerAccessChangeHook("mandates", (ctx, member, reason, target) => {
  if (target.device !== undefined) {
    if (reason === "revoke" || reason === "rescope" && target.narrowing !== true) lapseMandates(ctx, { device: target.device })
  } else if (member !== null && LAPSING_MEMBER_CHANGES.has(reason)) lapseMandates(ctx, { member })
})
// And a change to the signer's account here, an account recovery among
// them, that leaves it no longer the account they signed with.
registerSecurityChangeHook("mandates", (ctx, account) => {
  const state = accessState(ctx)
  for (const row of rows(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE state IN ('active','paused','tripped') AND lapsed_at IS NULL"))) {
    const basis = basisOf(row)
    if (basis.account !== account) continue
    const member = state.members.find((m) => m.id === basis.member && m.account === account)
    if (!member || !signerAccountCurrent(ctx, member, basis)) lapseMandates(ctx, { mandate: row.id })
  }
})

// The action the page signs for a signature or a resume, from live state,
// or { stepUp: null } for a resume that needs no passkey.
async function planAction(ctx: VaultContext, _p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<MandateActionAnswer> {
  const input = parseOpInput(MandateActionRequestSchema, raw)
  if (input.op === "sign") return await signAction(ctx, invocation, input.terms, input.proposal)
  return checkResumable(ctx, invocation, input.id, input.rev).action ?? { stepUp: null }
}

// ---------------------------------------------------------------- notices

// How many accounts it was queued for.
function notice(ctx: VaultContext, kind: "mandate_signed" | "mandate_tripped" | "mandate_ending", row: MandateRow, state: AccessState): number {
  const terms = termsOf(row)
  return queueNotice(ctx, { kind, workspace: workspaceRef(ctx), mandate: row.id, device: row.device, machine: deviceName(ctx, row.device), signer: { member: row.signer_member, name: memberName(state, row.signer_member) }, classes: terms.classes, expiresAt: iso(row.expires_at), at: iso(ctx.now()) }, `${row.id}:${row.rev}`)
}

// ---------------------------------------------------------------- use

// What the relay hook reserves for one relay request (5.1): the machine's
// mandate, its revision, the union of the classes of every credential it
// covered, each covered credential, and, when a cap alone kept one from
// being covered, which.
export type MandateCovered = { item: CheckedCredential; classes: MandateClass[]; method: string; host: string; entry: string; shape: string }
export type MandateReservation = { mandate: string | null; rev: number; classes: Set<MandateClass>; covered: Map<string, MandateCovered>; capped: { id: string; capped: MandateClass[] } | null }
export function newMandateReservation(): MandateReservation {
  return { mandate: null, rev: 0, classes: new Set(), covered: new Map(), capped: null }
}

// Whether this machine's mandate lets this held request through without
// asking, adding it to the reservation when it does. Only for a request the
// item's policy holds, never a protected one (the caller checks), from a
// machine with no workload, in an unmanaged, unfrozen workspace with
// mandates on. Plan mode never trips a mandate.
export function coveringMandate(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, credential: CheckedCredential, held: HeldRequest, reservation: MandateReservation, options: { plan: boolean; shape: string }): boolean {
  reservation.capped = null
  if (!mandatesHere(ctx) || frozen(ctx) || principal.workload !== undefined || projects.isProtectedItem(ctx, credential.slug)) return false
  const row = liveRow(ctx, principal.deviceId)
  const now = ctx.now()
  if (!row || stateNow(row, now) !== "active" || reservation.mandate !== null && reservation.mandate !== row.id) return false
  const terms = termsOf(row)
  if (terms.items !== "all" && !terms.items.includes(credential.id)) return false
  const anchor = anchorOf(ctx, credential, { device: principal.deviceId, workload: null }, held)
  const classes = mandateClassesOf(mandateRequestFacts(anchor), held.destination.method)
  if (classes === "never" || !mandateHostNamed(credential.binding, held.destination.host)) return false
  if (!mandateCovers(terms, { state: row.state, expiresAt: row.expires_at }, classes, now)) return false
  const state = accessState(ctx)
  if (!mandateSignerCurrent(ctx, state, row, credential, now)) return false
  const union = new Set([...reservation.classes, ...classes])
  if (writesBeyondRead(union) && rateCount(ctx, row.id, now) + 1 > MANDATE_RATE_LIMIT) {
    if (!options.plan) trip(ctx, row, state)
    return false
  }
  const capped = cappedClasses(ctx, row, union, now)
  if (capped.length > 0) {
    reservation.capped = { id: row.id, capped }
    return false
  }
  reservation.mandate = row.id
  reservation.rev = row.rev
  reservation.classes = union
  const input = { destination: held.destination, body: held.body, contentType: held.contentType, contentEncoding: held.contentEncoding }
  reservation.covered.set(credential.slug, { item: credential, classes, method: held.destination.method, host: held.destination.host, entry: policyCatalogueVerdict(input).entry?.id ?? "unreviewed", shape: options.shape })
  return true
}
// Whether the machine's owner could ever sign it a mandate: a member, not a
// guest, judged without what passes in time (an identity check, a
// cooling-off, a pending security transition), so none of those changes
// what the machine is told.
function ownerCouldSign(state: AccessState, device: string, now: number): boolean {
  const machine = state.devices.find((d) => d.id === device)
  const owner = machine?.owner.kind === "member" ? state.members.find((m) => m.id === machine.owner.id) : undefined
  if (!owner) return false
  const settled = capabilityState(state, owner.id)
  const judged = { ...settled, members: settled.members.map((m) => (m.id === owner.id ? { ...m, standing: { ...m.standing, restriction: null, transitionPending: false } } : m)) }
  return can(judged, { kind: "member", account: owner.account, memberId: owner.id, session: "mandate-cover", securityEpoch: 0, sessionCheck: null }, { type: "mandate.sign" }, { device }, now).allowed
}
// For a held request that asked, no cap having kept a mandate from it: a
// mandate could let requests like it through (the same checks as
// coveringMandate, but for the machine's mandate), and why this one asked.
// Null when none could: a workload, a machine whose owner could never sign
// one, a request a mandate never covers, a managed or frozen workspace or
// mandates off. A signer who no longer stands
// behind it reads not_covering before anything else could be said.
export function mandateCoverHint(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, credential: CheckedCredential, held: HeldRequest, workspaceSlug: string): MandateCoverHint | null {
  if (!mandatesHere(ctx) || frozen(ctx) || principal.workload !== undefined || projects.isProtectedItem(ctx, credential.slug)) return null
  const classes = mandateClassesOf(mandateRequestFacts(anchorOf(ctx, credential, { device: principal.deviceId, workload: null }, held)), held.destination.method)
  if (classes === "never" || !mandateHostNamed(credential.binding, held.destination.host)) return null
  const now = ctx.now()
  const hint = (state: MandateCoverState, mandate: string | null): MandateCoverHint => ({ classes, state, mandate, url: mandate === null ? null : `${ctx.env.VAULT_ORIGIN}/w/${encodeURIComponent(workspaceSlug)}/mandates/${encodeURIComponent(mandate)}` })
  const row = liveRow(ctx, principal.deviceId)
  const state = row ? stateNow(row, now) : null
  if (!row || state === "expired") {
    if (!ownerCouldSign(accessState(ctx), principal.deviceId, now)) return null
    const last = row ?? one(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE device=? ORDER BY created_at DESC,id DESC LIMIT 1", principal.deviceId))
    return last ? hint("ended", last.id) : hint("none", null)
  }
  if (!mandateSignerCurrent(ctx, accessState(ctx), row, credential, now)) return hint("not_covering", row.id)
  if (state === "paused" || state === "tripped") return hint(state, row.id)
  const terms = termsOf(row)
  if (terms.items !== "all" && !terms.items.includes(credential.id) || !classes.every((c) => terms.classes.includes(c))) return hint("unticked", row.id)
  if (!mandateScheduleOpen(terms.schedule, now)) return hint("outside_schedule", row.id)
  return hint("not_covering", row.id)
}

// Too many covered requests in a minute: the mandate stops covering anything
// until its signer resumes it. Written by the hook, never by the final
// transaction.
function trip(ctx: VaultContext, row: MandateRow, state: AccessState): void {
  ctx.storage.transactionSync(() => {
    const live = mandateRow(ctx, row.id)
    if (!live || live.rev !== row.rev || live.state !== "active") return
    ctx.sql.exec("UPDATE mandates SET state='tripped',rev=rev+1 WHERE id=?", row.id)
    ctx.audit({ actor: "system", action: "mandate.trip", target: row.id, detail: { device: row.device, limit: MANDATE_RATE_LIMIT, windowSeconds: MANDATE_RATE_WINDOW_MS / 1000 } })
    notice(ctx, "mandate_tripped", mandateRow(ctx, row.id) as MandateRow, state)
  })
}

// Inside the relay's last transaction: the mandate the hook read, unchanged
// and still covering, and still within its caps and rate counting what was
// let through since. Anything else asks the machine to send it again, and
// nothing is written here.
export function assertMandateCurrent(ctx: VaultContext, reservation: MandateReservation, live: (slug: string) => CheckedCredential): void {
  if (reservation.mandate === null) return
  const row = mandateRow(ctx, reservation.mandate), now = ctx.now()
  const changed = () => new VaultError("conflict", "This machine's mandate changed since this request was checked; send it again.")
  if (!row || row.rev !== reservation.rev || stateNow(row, now) !== "active" || !mandatesHere(ctx) || frozen(ctx) || !mandateScheduleOpen(termsOf(row).schedule, now)) throw changed()
  const state = accessState(ctx)
  for (const slug of reservation.covered.keys()) if (!mandateSignerCurrent(ctx, state, row, live(slug), now)) throw changed()
  if (cappedClasses(ctx, row, reservation.classes, now).length > 0) throw changed()
  if (writesBeyondRead(reservation.classes) && rateCount(ctx, row.id, now) + 1 > MANDATE_RATE_LIMIT) throw changed()
}

// The use (5.1): a receipt per covered credential, each class of the union
// counted once, the rate for a request beyond a read, and, for a credential
// that is not member-private, a mandate.use audit row without the path.
export function recordMandateUse(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, reservation: MandateReservation, run: string | null): void {
  if (reservation.mandate === null) return
  const now = ctx.now(), mandate = reservation.mandate
  for (const use of reservation.covered.values()) {
    const owned = use.item.home.kind === "member"
    ctx.sql.exec("INSERT INTO mandate_uses(id,mandate_id,at,item_id,item_private,classes,method,host,entry,run,approval_shape) VALUES (?,?,?,?,?,?,?,?,?,?,?)", randomId("mdu"), mandate, now, use.item.id, owned ? 1 : 0, JSON.stringify(use.classes), use.method, use.host, use.entry, run, use.shape)
    if (!owned) credentialAudit(ctx, principal, use.item, "mandate.use", use.classes.join(","), { mandate, classes: use.classes, method: use.method, host: use.host, entry: use.entry }, run)
  }
  const day = dayOf(now)
  for (const cls of reservation.classes) ctx.sql.exec("INSERT INTO mandate_counts(mandate_id,day,cls,n) VALUES (?,?,?,1) ON CONFLICT(mandate_id,day,cls) DO UPDATE SET n=n+1", mandate, day, cls)
  if (writesBeyondRead(reservation.classes)) {
    ctx.sql.exec("INSERT INTO mandate_rate(mandate_id,at) VALUES (?,?)", mandate, now)
    ctx.sql.exec("DELETE FROM mandate_rate WHERE mandate_id=? AND at<=?", mandate, now - MANDATE_RATE_WINDOW_MS)
  }
}

// The ask the relay opened, only a new one, that a mandate could have let
// through (mandateCoverHint). A sweep already set prunes its line in time;
// with none set, nothing else is due, and a day's sweep prunes it.
export function recordMandateCoverAsk(ctx: VaultContext, approval: string, device: string, item: string, cover: MandateCoverHint): void {
  ctx.sql.exec("INSERT OR IGNORE INTO mandate_cover_asks(approval,device,classes,at) VALUES (?,?,?,?)", approval, device, JSON.stringify(cover.classes), ctx.now())
  for (const cls of cover.classes) ctx.sql.exec("INSERT INTO mandate_asked(device,item_id,cls,at) VALUES (?,?,?,?) ON CONFLICT(device,item_id,cls) DO UPDATE SET at=excluded.at", device, item, cls, ctx.now())
  if (one(ctx.sql.exec("SELECT 1 FROM schedule WHERE area='mandates' AND key=?", MANDATE_SWEEP_KEY)) === null) ctx.schedule("mandates", MANDATE_SWEEP_KEY, ctx.now() + DAY_MS)
}
// The ask the relay opened, only a new one, for a request the machine's
// mandate would have let through but for these caps.
export function recordMandateCappedAsk(ctx: VaultContext, approval: string, capped: NonNullable<MandateReservation["capped"]>): void {
  ctx.sql.exec("INSERT OR IGNORE INTO mandate_capped_asks(approval,mandate_id,capped,at) VALUES (?,?,?,?)", approval, capped.id, JSON.stringify(capped.capped), ctx.now())
  scheduleMandateSweep(ctx)
}
// Which caps kept a mandate from letting this ask through, for a person who
// may read the machine; nothing about the request itself.
function cappedAsk(ctx: VaultContext, raw: unknown, invocation: WorkspaceInvocationContext): MandateCappedAsk {
  mandatesAvailable(ctx)
  const { approval } = parseOpInput(z.strictObject({ approval: z.string().max(80) }), raw)
  const asked = one(ctx.sql.exec<{ mandate_id: string; capped: string }>("SELECT mandate_id,capped FROM mandate_capped_asks WHERE approval=?", approval))
  const row = asked ? mandateRow(ctx, asked.mandate_id) : null
  if (!asked || !row || !readableDevices(ctx, invocation).some((d) => d.id === row.device)) throw new VaultError("not_found", "No such ask.")
  const caps = termsOf(row).caps
  return { mandate: row.id, capped: (JSON.parse(asked.capped) as MandateClass[]).map((cls) => ({ class: cls, cap: caps[cls] })) }
}

// That a mandate could let asks like this one through, for the person who
// may sign for its machine and may see the ask in full, as its page does;
// nothing about the request itself.
function coverAsk(ctx: VaultContext, p: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): MandateCoverAsk {
  mandatesAvailable(ctx)
  const { approval } = parseOpInput(z.strictObject({ approval: z.string().max(80) }), raw)
  const asked = one(ctx.sql.exec<{ device: string; classes: string }>("SELECT device,classes FROM mandate_cover_asks WHERE approval=?", approval))
  const state = accessState(ctx), now = ctx.now()
  const row = asked ? workspaceApproval(ctx, approval) : null
  if (!asked || !row || p.kind !== "member" || !can(state, p, { type: "mandate.sign" }, { device: asked.device }, now).allowed || ownMachine(state, p.memberId, asked.device) === null || !eligibility(readerState(ctx, invocation), p.memberId, JSON.parse(row.ask) as AccessAsk, now).canReadAskDetail) throw new VaultError("not_found", "No such ask.")
  const live = liveRow(ctx, asked.device)
  const liveState = live ? stateNow(live, now) : null
  const held = live && (liveState === "paused" || liveState === "tripped") ? { state: liveState, mandate: live.id } : { state: "sign" as const, mandate: null }
  return { device: { id: asked.device, name: deviceName(ctx, asked.device) }, classes: JSON.parse(asked.classes) as MandateClass[], ...held }
}

// ---------------------------------------------------------------- sweep

// Tells the signer of each live mandate ending within
// MANDATE_ENDING_NOTICE_MS, and not yet ended, that it ends soon, once: a
// signer who cannot be told now (suspended) is told at a later sweep, if
// they can be by then and it is still live.
function noticeEnding(ctx: VaultContext): void {
  const now = ctx.now()
  const due = rows(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE state IN ('active','paused','tripped') AND ending_noticed_at IS NULL AND expires_at>? AND expires_at<=?", now, now + MANDATE_ENDING_NOTICE_MS))
  if (due.length === 0) return
  const state = accessState(ctx)
  for (const row of due) if (notice(ctx, "mandate_ending", row, state) > 0) ctx.sql.exec("UPDATE mandates SET ending_noticed_at=? WHERE id=?", now, row.id)
}

// Tells signers of mandates ending soon, marks mandates past their end
// expired, closes expired proposals, and prunes old counts, rate rows and
// receipts and capped asks; then sets the next sweep.
export function sweepMandates(ctx: VaultContext): void {
  const now = ctx.now()
  ctx.storage.transactionSync(() => {
    noticeEnding(ctx)
    for (const row of rows(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE state IN ('active','paused','tripped') AND expires_at<=?", now))) endRow(ctx, row, "expired", "expired", "system")
    ctx.sql.exec("UPDATE mandate_proposals SET closed_at=? WHERE closed_at IS NULL AND expires_at<=?", now, now)
    ctx.sql.exec("DELETE FROM mandate_counts WHERE day<?", dayOf(now) - COUNT_KEEP_DAYS)
    ctx.sql.exec("DELETE FROM mandate_rate WHERE at<=?", now - MANDATE_RATE_WINDOW_MS)
    ctx.sql.exec("DELETE FROM mandate_uses WHERE at<?", now - MANDATE_RECEIPT_KEEP_MS)
    ctx.sql.exec("DELETE FROM mandate_capped_asks WHERE at<?", now - CAPPED_ASK_KEEP_MS)
    ctx.sql.exec("DELETE FROM mandate_cover_asks WHERE at<?", now - CAPPED_ASK_KEEP_MS)
    ctx.sql.exec("DELETE FROM mandate_asked WHERE at<=?", now - MANDATE_ASKED_WINDOW_MS)
  })
  scheduleMandateSweep(ctx)
}
// The next sweep: the soonest end of a live mandate or an open proposal, the
// moment yet to come a live mandate's signer is due to hear it ends soon, or
// a day from now while anything is left to prune or a signer is still to be
// told.
export function scheduleMandateSweep(ctx: VaultContext): void {
  const now = ctx.now()
  const due = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(due) AS due FROM (SELECT MIN(expires_at) AS due FROM mandates WHERE state IN ('active','paused','tripped') UNION ALL SELECT MIN(expires_at-?) FROM mandates WHERE state IN ('active','paused','tripped') AND ending_noticed_at IS NULL AND expires_at-?>? UNION ALL SELECT MIN(expires_at) FROM mandate_proposals WHERE closed_at IS NULL)", MANDATE_ENDING_NOTICE_MS, MANDATE_ENDING_NOTICE_MS, now))?.due ?? null
  const leftovers = one(ctx.sql.exec("SELECT 1 FROM mandate_uses UNION ALL SELECT 1 FROM mandate_counts UNION ALL SELECT 1 FROM mandate_rate UNION ALL SELECT 1 FROM mandate_capped_asks UNION ALL SELECT 1 FROM mandate_cover_asks LIMIT 1")) !== null || one(ctx.sql.exec("SELECT 1 FROM mandate_asked LIMIT 1")) !== null
  const next = due === null ? (leftovers ? now + DAY_MS : null) : Math.min(due, now + DAY_MS)
  if (next === null) ctx.unschedule("mandates", MANDATE_SWEEP_KEY)
  else ctx.schedule("mandates", MANDATE_SWEEP_KEY, Math.max(next, now + 1))
}

// ---------------------------------------------------------------- ops

const IdInput = z.strictObject({ id: z.string().max(80) })
const UsesInput = z.strictObject({ id: z.string().max(80), before: z.string().max(120).optional() })

function mine(ctx: VaultContext, p: AccessPrincipal, invocation: WorkspaceInvocationContext): MandateList {
  mandatesAvailable(ctx)
  const principal = machineOnly(p), state = accessState(ctx)
  return {
    mandates: rows(ctx.sql.exec<MandateRow>("SELECT * FROM mandates WHERE device=? ORDER BY created_at DESC,id DESC LIMIT ?", principal.deviceId, MANDATE_LIST_MAX)).map((row) => mandateView(ctx, state, principal, row)),
    proposals: openProposalRows(ctx, principal.deviceId, ctx.now()).map((row) => openProposalView(ctx, state, principal, invocation, row)),
  }
}
function list(ctx: VaultContext, p: AccessPrincipal, invocation: WorkspaceInvocationContext): MandateList {
  mandatesAvailable(ctx)
  const devices = new Set(readableDevices(ctx, invocation).map((d) => d.id))
  if (devices.size === 0) return { mandates: [], proposals: [] }
  const state = readerState(ctx, invocation)
  const found: MandateRow[] = []
  for (const row of ctx.sql.exec<MandateRow>("SELECT * FROM mandates ORDER BY created_at DESC,id DESC")) {
    if (!devices.has(row.device)) continue
    found.push(row)
    if (found.length >= WORKSPACE_LIST_MAX) break
  }
  // Open proposals of the machines this reader may sign for: their own.
  const access = accessState(ctx), now = ctx.now()
  const signable = p.kind === "member" ? [...devices].filter((device) => ownMachine(access, p.memberId, device) !== null && can(access, p, { type: "mandate.sign" }, { device }, now).allowed) : []
  const proposals = signable.flatMap((device) => openProposalRows(ctx, device, now)).sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? 1 : -1))
  return { mandates: found.map((row) => mandateView(ctx, state, p, row)), proposals: proposals.map((row) => openProposalView(ctx, state, p, invocation, row)) }
}

export const workspaceMandateOps: NonNullable<Area["workspaceOps"]> = {
  "mandates.propose": { auth: ["device"], handler: (ctx, p, raw, invocation) => propose(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.mine": { auth: ["device"], handler: (ctx, p, _raw, invocation) => mine(ctx, p as AccessPrincipal, invocation) },
  "mandates.mine_asked": { auth: ["device"], handler: (ctx, p) => askedView(ctx, p as AccessPrincipal) },
  "mandates.mine_one": { auth: ["device"], handler(ctx, p, raw) {
    mandatesAvailable(ctx)
    const principal = machineOnly(p as AccessPrincipal), { id } = parseOpInput(IdInput, raw)
    return mandateView(ctx, accessState(ctx), principal, ownRow(ctx, principal, id))
  } },
  "mandates.mine_uses": { auth: ["device"], handler(ctx, p, raw) {
    mandatesAvailable(ctx)
    const principal = machineOnly(p as AccessPrincipal), { id, before } = parseOpInput(UsesInput, raw)
    return receiptsPage(ctx, accessState(ctx), principal, ownRow(ctx, principal, id).id, before)
  } },
  "mandates.mine_pause": { auth: ["device"], handler: (ctx, p, raw) => machinePause(ctx, p as AccessPrincipal, raw) },
  "mandates.list": { auth: ["account"], handler: (ctx, p, _raw, invocation) => list(ctx, p as AccessPrincipal, invocation) },
  "mandates.show": { auth: ["account"], handler(ctx, p, raw, invocation) {
    mandatesAvailable(ctx)
    const { id } = parseOpInput(IdInput, raw)
    return mandateView(ctx, readerState(ctx, invocation), p as AccessPrincipal, readableRow(ctx, invocation, id))
  } },
  "mandates.uses": { auth: ["account"], handler(ctx, p, raw, invocation) {
    mandatesAvailable(ctx)
    const { id, before } = parseOpInput(UsesInput, raw)
    return receiptsPage(ctx, readerState(ctx, invocation), p as AccessPrincipal, readableRow(ctx, invocation, id).id, before)
  } },
  "mandates.proposal": { auth: ["account"], handler: (ctx, p, raw, invocation) => proposalView(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.candidates": { auth: ["account"], handler: (ctx, p, raw, invocation) => candidates(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.capped_ask": { auth: ["account"], handler: (ctx, _p, raw, invocation) => cappedAsk(ctx, raw, invocation) },
  "mandates.cover_ask": { auth: ["account"], handler: (ctx, p, raw, invocation) => coverAsk(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.action": { auth: ["account"], handler: (ctx, p, raw, invocation) => planAction(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.sign": { auth: ["account"], handler: (ctx, p, raw, invocation) => sign(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.resume": { auth: ["account"], handler: (ctx, p, raw, invocation) => resume(ctx, p as AccessPrincipal, raw, invocation) },
  "mandates.pause": { auth: ["account"], handler: (ctx, p, raw, invocation) => personChange(ctx, p as AccessPrincipal, raw, invocation, "pause") },
  "mandates.stop": { auth: ["account"], handler: (ctx, p, raw, invocation) => personChange(ctx, p as AccessPrincipal, raw, invocation, "stop") },
}

export const mandatesArea: Area = {
  name: "mandates",
  migrations: [MANDATES_MIGRATION, MANDATE_CAPPED_ASKS_MIGRATION, MANDATE_PROPOSALS_CLOSED_BY_MIGRATION, MANDATE_COVER_ASKS_MIGRATION, MANDATE_PROPOSALS_MANDATE_MIGRATION, MANDATE_ASKED_MIGRATION],
  workspaceOps: workspaceMandateOps,
  async alarm(ctx, key) {
    if (key === MANDATE_SWEEP_KEY) sweepMandates(ctx)
  },
}
