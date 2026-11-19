// Standing rules (rul_) in a workspace: a human approved one held request
// and chose to allow that request shape from now on, for one item and the
// key that asked. policy-rules.ts (protocol) builds the terms from a stored
// request and decides what they cover; this module stores rules, the
// consent behind them and their proposals, and ends them. Behind
// POLICY_RULES (policyRulesOn): unless it is on for this workspace, every
// op here refuses as the window ops do, no approval offers a rule and the
// relay never looks one up.

import { base64UrlDecode, canonicalJson, parseDestination, type Destination, type ItemUseContext, type OwnerRef, type PolicyStandingProposalViewProjection, type WorkspacePendingAsk } from "@mehen/protocol"
import type { RequestedBy } from "@mehen/protocol/api"
import {
  AREA_GRANT_DEFAULT_DURATION, AREA_GRANT_USES, POLICY_RULES_ENDED_LISTED, PolicyAreaProposalSchema, PolicyRuleDecisionSchema, PolicyRuleExtendSchema, PolicyRuleProposalSchema, RULE_DEFAULT_DURATION, policyRulePathChoices,
  type PolicyAreaEffective, type PolicyAreaGrantTerms, type PolicyAreaGrantView, type PolicyAreaOffer, type PolicyAreaProposalView, type PolicyAreaRefusal, type PolicyRememberArea,
  type PolicyRememberRule, type PolicyRuleExtended, type PolicyRuleOffer, type PolicyRulePreview, type PolicyRuleProposal, type PolicyRuleProposalCreated, type PolicyRuleProposalRef,
  type PolicyRuleProposalStatus, type PolicyRuleProposalView, type PolicyRuleRef, type PolicyRuleRefusal, type PolicyRuleStopped, type PolicyRuleTerms, type PolicyRuleView, type RuleDuration,
} from "@mehen/protocol/policy-mode"
import { policyCatalogueFor, policyCatalogueNamed } from "@mehen/protocol/policy-catalogue"
import { areaGrantEntry, areaGrantTermsFrom, policyAreaGrantTermsDigest, policyRuleExtendDigest, policyRuleTermsDigest, ruleCovers, ruleTermsFrom, type PolicyRuleAnchor } from "@mehen/protocol/policy-rules"
import { compareVersions } from "@mehen/protocol/version"
import { z } from "zod"
import { AREA_GRANT_CLI } from "../../cli-version.ts"
import type { Env } from "../../env.ts"
import { VaultError } from "../../http.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { can, effectiveAccess, eligibility, type AccessAsk, type AccessPrincipal, type AccessState } from "../access.ts"
import { auditPrivateEvent } from "../audit.ts"
import { one, randomId, type VaultContext } from "../core.ts"
import type { ConsentBasis, ConsentLineage, ItemRecord } from "../services.ts"
import { waitForStorageWrite } from "../storage-waits.ts"
import { bindingCode, digestOf, parseOpInput } from "./approvals.ts"
import { STANDING_CONSENT_PREFIX, readConsent, standingConsentCurrent, storeConsent, workspaceApproval, type WorkspaceApprovalRow } from "./approvals-workspace.ts"
import { devicePolicyState } from "./devices.ts"
import { items } from "./items.ts"
import { AREA_REFUSAL_WORDS } from "./policy-area-refusal-words.ts"
import { visibleCredential } from "./items-workspace.ts"
import { policyHelpNext } from "./policy.ts"
import { projects } from "./projects.ts"
import { approvedUseSnapshot, snapshotPrincipal, type CheckedCredential, type ProtectedSnapshot } from "./projects-workspace.ts"
import { askingWorkload, assertWorkloadAskRoom, workloadRow, workloadState } from "./workloads.ts"
import { prunePostureCounts } from "./postures-workspace.ts"
import { accessState, authorise, eligibilityState, managedSetting, openAskCount, requireStepUp, standingGateValid, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { isPushSubject } from "./push-records.ts"

export const WORKSPACE_POLICY_RULES_MIGRATION = `CREATE TABLE policy_rules (
  id TEXT PRIMARY KEY, item_id TEXT NOT NULL, slug TEXT NOT NULL,
  device TEXT NOT NULL, workload TEXT, terms TEXT NOT NULL, terms_digest TEXT NOT NULL,
  snapshot TEXT NOT NULL, source TEXT NOT NULL,
  lineage TEXT NOT NULL REFERENCES consent_lineage(id), co_lineage TEXT REFERENCES consent_lineage(id),
  uses INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ended_at INTEGER, ended_reason TEXT
);
CREATE INDEX policy_rules_live ON policy_rules(item_id, device, ended_at);
CREATE INDEX policy_rules_source ON policy_rules(source);
CREATE INDEX policy_rules_device ON policy_rules(device);
CREATE TABLE policy_rule_anchors (source TEXT PRIMARY KEY, item TEXT NOT NULL, method TEXT, url TEXT, content_type TEXT, content_encoding TEXT, body BLOB, refused TEXT, created_at INTEGER NOT NULL);
CREATE INDEX policy_rule_anchors_item ON policy_rule_anchors(item);
ALTER TABLE policy_proposals ADD COLUMN rule_terms TEXT;
ALTER TABLE policy_proposals ADD COLUMN stage TEXT;
CREATE INDEX policy_proposals_requester ON policy_proposals(requester);`
// The anchor sweep reads held requests by age.
export const WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION = "CREATE INDEX policy_rule_anchors_created ON policy_rule_anchors(created_at);"
// Task grants: standing rules of kind 'area' (NULL: a shape rule), with the
// most uses they allow and their receipt, the uses so far by catalogue
// entry ({entry id: count}).
export const WORKSPACE_POLICY_AREA_GRANTS_MIGRATION = `ALTER TABLE policy_rules ADD COLUMN kind TEXT;
ALTER TABLE policy_rules ADD COLUMN max_uses INTEGER;
ALTER TABLE policy_rules ADD COLUMN receipt TEXT;
CREATE INDEX policy_rules_kind ON policy_rules(item_id, device, kind, ended_at);`

// A rule proposal waits a day for its approver, and again for a co-signer.
const PROPOSAL_TTL_MS = 86_400_000
// A held request is kept two days for an approval to name it; a pending
// proposal and a live rule keep their own copies while they stand.
const ANCHOR_TTL_MS = 2 * 86_400_000

// Whether standing rules are on in this workspace (its tn_ id), read as
// workspaceSwitchOn reads every switch. Every reader of POLICY_RULES, in the
// workspace's object and in the Worker, asks here.
export function policyRulesOn(env: Pick<Env, "POLICY_RULES">, workspace: string): boolean {
  return workspaceSwitchOn(env.POLICY_RULES, workspace)
}
const rulesOnHere = (ctx: VaultContext): boolean => policyRulesOn(ctx.env, ctx.tenant)
export function rulesOff(): never {
  throw new VaultError("forbidden", "Policy widening is not available yet.", { next: policyHelpNext })
}
export function rulesAvailable(ctx: VaultContext): void {
  if (!rulesOnHere(ctx) || managedSetting(ctx) !== null) rulesOff()
}

const REFUSAL_WORDS: Record<PolicyRuleRefusal, string> = {
  "rule.live-key": "This credential holds a live key, so it asks every time.",
  "rule.destination": "Only HTTPS requests on the standard port can be allowed from now on.",
  "rule.method": "Only GET, HEAD, POST, PUT and PATCH requests can be allowed from now on.",
  "rule.destructive": "This request deletes or removes something, so it asks every time.",
  "rule.deny": "This credential's rules refuse this request.",
  "rule.credential": "This request changes credentials or access, so it asks every time.",
  "rule.persistence": "This request sets up something that keeps running, so it asks every time.",
  "rule.sharing": "This request shares or publishes something, so it asks every time.",
  "rule.money": "This request moves money, so it asks every time.",
  "rule.send": "This request sends a message, so it asks every time.",
  "rule.opaque": "The vault cannot read what this request does, so it asks every time.",
  "rule.item-rule": "This credential's own rules ask for this request every time.",
  "rule.generic": "This request's path names something sensitive, so it asks every time.",
  "rule.body": "This request's body cannot be pinned down, so it asks every time; send it as JSON.",
  "rule.graphql": "The vault cannot prove which GraphQL mutation this is, so it asks every time.",
  "rule.query": "This request's query string cannot be pinned down, so it asks every time.",
  "rule.binding": "That path is wider than this credential's binding allows.",
  "rule.path": "Pick one of the vault's path choices.",
  "rule.duration": "Pick 1, 7 or 30 days.",
  "rule.terms": "This request cannot become a rule.",
}
export function ruleRefusalWords(reason: PolicyRuleRefusal): string {
  return REFUSAL_WORDS[reason]
}
function refused(reason: PolicyRuleRefusal): VaultError {
  return new VaultError("forbidden", REFUSAL_WORDS[reason], { ruleRefused: reason })
}
export function areaRefused(reason: PolicyAreaRefusal): VaultError {
  return new VaultError("forbidden", AREA_REFUSAL_WORDS[reason], { areaRefused: reason })
}
// A task grant is a standing rule to a machine: a released mehen reads this
// conflict by its words (RULE_ENDED) and says to send once more.
const ruleEnded = () => new VaultError("conflict", "The rule that allowed this request has ended; send it again to ask for approval.")

// kind: "area" for a task grant, whose terms are PolicyAreaGrantTerms and
// which also has max_uses and a receipt; null for a shape rule.
type RuleRow = { id: string; item_id: string; slug: string; device: string; workload: string | null; terms: string; terms_digest: string; snapshot: string; source: string; lineage: string; co_lineage: string | null; uses: number; last_used_at: number | null; created_at: number; expires_at: number; ended_at: number | null; ended_reason: PolicyAreaGrantView["endedReason"]; kind: "area" | null; max_uses: number | null; receipt: string | null }
type ProposalRow = { id: string; requester: string; requested_by: string; device_name: string; item: string; slug: string; device: string; reason: string; code: string; status: PolicyRuleProposalStatus["status"]; created_at: number; expires_at: number; decided_by: string | null; outcome: string | null; ask: string; lineage: string | null; rule_terms: string; stage: PolicyRuleProposalStatus["stage"] }
// What a rule proposal holds besides its row: the terms as they stand (the
// owner's narrowing once they approved), the approval it came from, the
// rule a co-sign would extend, and the credential's config revision the
// owner approved under (null until they have). A task grant's co-sign
// proposal holds a grant's terms, and the held request's own area.
type ProposalTerms = { terms: PolicyRuleTerms | PolicyAreaGrantTerms; termsDigest: string; source: string | null; extends: string | null; configRevision: number | null; requestArea?: string }
type Asker = { device: string; workload: string | null }
const isAreaTerms = (terms: PolicyRuleTerms | PolicyAreaGrantTerms): terms is PolicyAreaGrantTerms => "kind" in terms && terms.kind === "area"
// A task grant's proposal, which a mehen before AREA_GRANT_CLI or of
// unknown version never reads (readsGrants).
const isAreaProposal = (row: ProposalRow): boolean => isAreaTerms((JSON.parse(row.rule_terms) as ProposalTerms).terms)

const iso = (ms: number) => new Date(ms).toISOString()
const askerOf = (principal: Extract<AccessPrincipal, { kind: "device" }>): Asker => ({ device: principal.deviceId, workload: principal.workload ?? null })
const ruleRow = (ctx: VaultContext, id: string) => one(ctx.sql.exec<RuleRow>("SELECT * FROM policy_rules WHERE id=?", id))
export function ruleProposalRow(ctx: VaultContext, id: string): ProposalRow | null {
  return one(ctx.sql.exec<ProposalRow>("SELECT * FROM policy_proposals WHERE id=? AND rule_terms IS NOT NULL", id))
}
function secretPrefixes(ctx: VaultContext, item: string): string[] {
  return ctx.sql.exec<{ prefix: string }>("SELECT prefix FROM item_secrets WHERE item=?", item).toArray().map((r) => r.prefix)
}
function ownerRef(state: AccessState, device: string): OwnerRef {
  const d = state.devices.find((x) => x.id === device)
  if (!d) throw new VaultError("not_found", "No such object.")
  return d.owner.kind === "member" ? { kind: "member", member: d.owner.id, name: state.members.find((m) => m.id === d.owner.id)?.name ?? "" } : { kind: "team", team: d.owner.id, name: state.teams.find((t) => t.id === d.owner.id)?.name ?? "" }
}

// ---------------------------------------------------------------- held requests

// What the relay held, as it would forward it, kept so a rule can be built
// from the bytes the human saw rather than from anything a caller sends later.
// headerNames: the forwarded headers' names, on a request the relay holds
// now, for a mandate (mandateHeadersNameOperation); absent on stored bytes.
export type HeldRequest = { destination: Destination; url: string; body: Uint8Array | null; contentType: string | null; contentEncoding: string | null; headerNames?: readonly string[] }

// The bytes are kept only when the request could become a rule at its own
// path, or start a task grant; for one that can do neither, only why it
// cannot become a rule, so the page can say so. Kept bytes never leave the
// vault: a machine learns only a refusal reason.
export function storeRuleAnchor(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: ItemRecord, source: string, request: HeldRequest): void {
  const anchor = anchorOf(ctx, item, askerOf(principal), request)
  const built = ruleTermsFrom(anchor, { path: request.destination.path, ttlSeconds: RULE_DEFAULT_DURATION })
  if (!built.ok && !areaGrantTermsFrom(anchor, null).ok) ctx.sql.exec("INSERT OR IGNORE INTO policy_rule_anchors(source,item,refused,created_at) VALUES (?,?,?,?)", source, item.id, built.reason, ctx.now())
  else ctx.sql.exec("INSERT OR IGNORE INTO policy_rule_anchors(source,item,method,url,content_type,content_encoding,body,created_at) VALUES (?,?,?,?,?,?,?,?)", source, item.id, request.destination.method, request.url, request.contentType, request.contentEncoding, request.body === null ? null : request.body.slice().buffer, ctx.now())
  sweepRuleAnchors(ctx)
}

export const RULE_ANCHOR_SWEEP_KEY = "rule-anchors"
// The policy alarm's sweep: every copy two days old goes, unless a live rule
// or a pending proposal still stands on it, and the alarm is set for the
// next one due (a live rule's or a pending proposal's no sooner than its
// deadline: nothing reads a rule's copy once its deadline passes). Every copy
// is written by storeRuleAnchor or copyRuleAnchor, and both sweep, as does
// an extension, which may bring a deadline sooner, so one is always set for
// the earliest bound a copy may outlive. It runs whatever
// POLICY_RULES says: with rules off here nothing writes a copy, and one
// written while they were on still goes at its bound.
export function sweepRuleAnchors(ctx: VaultContext): void {
  const now = ctx.now()
  ctx.sql.exec("DELETE FROM policy_rule_anchors WHERE created_at<=? AND source NOT IN (SELECT id FROM policy_rules WHERE ended_at IS NULL AND expires_at>?) AND source NOT IN (SELECT id FROM policy_proposals WHERE status='pending' AND expires_at>?)", now - ANCHOR_TTL_MS, now, now)
  prunePostureCounts(ctx)
  const due = one(ctx.sql.exec<{ due: number | null }>("SELECT MIN(MAX(a.created_at+?, COALESCE(p.expires_at, 0), COALESCE(r.expires_at, 0))) AS due FROM policy_rule_anchors a LEFT JOIN policy_proposals p ON p.id=a.source AND p.status='pending' LEFT JOIN policy_rules r ON r.id=a.source AND r.ended_at IS NULL AND r.expires_at>?", ANCHOR_TTL_MS, now))?.due ?? null
  if (due === null) ctx.unschedule("policy", RULE_ANCHOR_SWEEP_KEY)
  else ctx.schedule("policy", RULE_ANCHOR_SWEEP_KEY, Math.max(due, now + 1))
}
function copyRuleAnchor(ctx: VaultContext, from: string, to: string): void {
  ctx.sql.exec("INSERT INTO policy_rule_anchors(source,item,method,url,content_type,content_encoding,body,refused,created_at) SELECT ?,item,method,url,content_type,content_encoding,body,refused,? FROM policy_rule_anchors WHERE source=?", to, ctx.now(), from)
  sweepRuleAnchors(ctx)
}
// Why a held request can never become a rule, when that is all the vault kept.
function anchorRefusal(ctx: VaultContext, source: string): PolicyRuleRefusal | null {
  return one(ctx.sql.exec<{ refused: PolicyRuleRefusal }>("SELECT refused FROM policy_rule_anchors WHERE source=? AND refused IS NOT NULL", source))?.refused ?? null
}
function storedRequest(ctx: VaultContext, source: string): HeldRequest | null {
  const row = one(ctx.sql.exec<{ method: string; url: string; content_type: string | null; content_encoding: string | null; body: ArrayBuffer | null }>("SELECT method,url,content_type,content_encoding,body FROM policy_rule_anchors WHERE source=? AND refused IS NULL", source))
  if (!row) return null
  const parsed = parseDestination(row.method, row.url)
  return parsed.ok ? { destination: parsed.destination, url: row.url, body: row.body === null ? null : new Uint8Array(row.body), contentType: row.content_type, contentEncoding: row.content_encoding } : null
}
// The anchor ruleTermsFrom reads: the stored request with the item as it is
// now (its binding, policy and secret prefixes), for the key that asked.
export function anchorOf(ctx: VaultContext, item: ItemRecord, asker: Asker, request: HeldRequest): PolicyRuleAnchor {
  return { item: item.slug, itemId: item.id, asker, destination: request.destination, body: request.body, contentType: request.contentType, contentEncoding: request.contentEncoding, policy: item.policy, binding: item.binding, secretPrefixes: secretPrefixes(ctx, item.id) }
}
function approvalAnchor(ctx: VaultContext, row: WorkspaceApprovalRow): { anchor: PolicyRuleAnchor; item: ItemRecord } | null {
  const request = storedRequest(ctx, row.id)
  const item = items.getItem(ctx, row.item)
  const ask = JSON.parse(row.ask) as AccessAsk
  if (!request || !item || item.id !== ask.credential) return null
  return { anchor: anchorOf(ctx, item, { device: row.device, workload: row.workload }, request), item }
}

// ---------------------------------------------------------------- consent

// How a person may turn a rule on for this ask (policy.rule.approve: the
// machine's owner, or an approver of a team machine's ask, never a guest):
// "direct" with one passkey when they also manage the credential's home;
// "co-sign" when a manager of the home must also sign.
type RuleSigner = "direct" | "co-sign"
function ruleSigner(state: AccessState, principal: AccessPrincipal, ask: AccessAsk, now: number): RuleSigner | null {
  if (principal.kind !== "member" || !can(state, principal, { type: "policy.rule.approve" }, { ask }, now).allowed) return null
  return can(state, principal, { type: "policy.approve" }, { ask, ...(ask.credential ? { credential: ask.credential } : {}) }, now).allowed ? "direct" : "co-sign"
}

export function managesHome(state: AccessState, member: string, home: import("@mehen/protocol").CredentialHome, now: number): boolean {
  const role = state.members.find((m) => m.id === member)?.standing.effectiveRole
  return home.kind === "member" ? home.member === member : home.kind === "workspace" ? role === "owner" || role === "admin" : effectiveAccess(state, { kind: "member", id: member }, home.project, now).level === "manage"
}

// A co-signer's consent: a manager of the credential's home, who need not
// be an approver of the machine's asks, so its basis binds the home's
// access rather than the ask's eligibility.
function storeCoSignConsent(ctx: VaultContext, state: AccessState, decision: string, member: string, ask: AccessAsk, home: import("@mehen/protocol").CredentialHome, expiresAt: number, invocation: WorkspaceInvocationContext): ConsentLineage {
  if (invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only a person can record consent.")
  const auth = invocation.auth, now = ctx.now()
  const decider = state.members.find((m) => m.id === member)
  if (!decider) throw new VaultError("not_found", "No such object.")
  const sources = home.kind === "project" ? effectiveAccess(state, { kind: "member", id: member }, home.project, now).sources : []
  const expiries = sources.flatMap((s) => s.kind === "share" && s.share.expiresAt !== null ? [Date.parse(s.share.expiresAt)] : [])
  const basis: ConsentBasis = { sessionCheck: auth.sessionCheck, session: auth.session, account: auth.account, securityEpoch: auth.securityEpoch, member, role: decider.standing.effectiveRole, sources, accessRevision: state.accessRev, context: ask.context, referenceRevisions: [], fourEyesProjects: [], expiresAt: expiries.length ? Math.min(...expiries) : null }
  const lineage: ConsentLineage = { id: randomId("cns"), decision: `${STANDING_CONSENT_PREFIX}cosign:${decision}`, basis, createdAt: now, expiresAt: Math.min(expiresAt, basis.expiresAt ?? expiresAt), revokedAt: null }
  ctx.sql.exec("INSERT INTO consent_lineage(id,decision,member,ask,basis,created_at,expires_at) VALUES (?,?,?,?,?,?,?)", lineage.id, lineage.decision, member, JSON.stringify(ask), JSON.stringify(basis), lineage.createdAt, lineage.expiresAt)
  return lineage
}
function coSignCurrent(ctx: VaultContext, state: AccessState, lineage: ConsentLineage, home: import("@mehen/protocol").CredentialHome, now: number): boolean {
  const basis = lineage.basis
  if (lineage.revokedAt !== null || now >= lineage.expiresAt || basis.expiresAt !== null && now >= basis.expiresAt || !standingGateValid(ctx, basis)) return false
  const member = state.members.find((m) => m.id === basis.member && m.account === basis.account)
  if (!member || member.status !== "active" || member.standing.effectiveRole !== basis.role || member.standing.transitionPending || member.standing.restriction !== null && member.standing.restriction.until > now) return false
  for (const source of basis.sources) {
    if (source.kind !== "share") continue
    if (!effectiveAccess(state, { kind: "member", id: member.id }, source.share.project, now).sources.some((s) => canonicalJson(s) === canonicalJson(source))) return false
  }
  return managesHome(state, member.id, home, now)
}

// ---------------------------------------------------------------- lifetime

// Why a live rule has ended, or null while it stands: its deadline; the
// credential deleted, rehomed or edited (its config revision); or, as an
// exact grant would, any change to the consent behind it, the machine, its
// workload, its scope or the credential's references. A task grant also
// ends once it has been used as many times as it allows.
function ruleEnding(ctx: VaultContext, state: AccessState, row: RuleRow, now: number): Exclude<PolicyAreaGrantView["endedReason"], null | "revoked" | "replaced"> | null {
  if (now >= row.expires_at) return "expired"
  if (row.kind === "area" && row.uses >= (row.max_uses ?? 0)) return "uses-spent"
  const snapshot = JSON.parse(row.snapshot) as ProtectedSnapshot
  const item = items.getItem(ctx, row.slug)
  const credential = state.credentials.find((c) => c.id === row.item_id)
  if (!item || item.id !== row.item_id || item.configRev !== snapshot.item.configRevision || !credential || canonicalJson(credential.home) !== canonicalJson(snapshot.item.home)) return "credential-changed"
  if (managedSetting(ctx) !== null) return "access-changed"
  const consent = readConsent(ctx, row.lineage)
  if (!consent || !standingConsentCurrent(ctx, state, consent.lineage, consent.ask, now)) return "access-changed"
  if (row.co_lineage !== null) {
    const co = readConsent(ctx, row.co_lineage)
    if (!co || !coSignCurrent(ctx, state, co.lineage, credential.home, now)) return "access-changed"
  } else if (!managesHome(state, consent.lineage.basis.member, credential.home, now)) return "access-changed"
  if (row.workload !== null) {
    const workload = workloadRow(ctx, row.workload)
    if (!workload || workloadState(workload, now) !== "active") return "access-changed"
  }
  try {
    const fresh = approvedUseSnapshot(ctx, state, snapshotPrincipal(snapshot), snapshot.item, snapshot.project ? { project: snapshot.project, env: snapshot.environment } : null, now, snapshot.mode).snapshot
    fresh.requestDigest = snapshot.requestDigest
    if (canonicalJson(fresh) !== canonicalJson(snapshot)) return "access-changed"
  } catch (error) {
    if (error instanceof VaultError) return "access-changed"
    throw error
  }
  return null
}

type RuleActor = { kind: "member"; member: string; session: string | null } | { kind: "device"; device: string; workload: string | null } | { kind: "system" }
function ruleAudit(ctx: VaultContext, state: AccessState, row: Pick<RuleRow, "id" | "item_id" | "slug" | "device" | "workload">, actor: RuleActor, action: string, outcome: string, detail: Record<string, unknown>): void {
  const credential = state.credentials.find((c) => c.id === row.item_id)
  const device = state.devices.find((d) => d.id === row.device)
  const workload = row.workload === null ? null : workloadRow(ctx, row.workload)
  const by = workload ? { workload: { id: workload.id, label: workload.label } } : null
  if (credential?.home.kind === "member") {
    // A private event names a person or a machine; the vault's own endings
    // are told as the rule's machine's.
    const owner = device?.owner.kind === "team" ? { kind: "team" as const, team: device.owner.id } : { kind: "member" as const, member: device?.owner.id ?? "" }
    const privateActor = actor.kind === "member" ? { kind: "member" as const, member: actor.member } : { kind: "device" as const, device: row.device, owner, ...(by ? by : {}) }
    auditPrivateEvent(ctx, { action, at: ctx.now(), actor: privateActor, session: actor.kind === "member" ? actor.session : null, item: row.item_id, slug: row.slug, outcome, run: null }, credential.home.member)
    return
  }
  const actorName = actor.kind === "member" ? `member:${actor.member}` : actor.kind === "device" ? `device:${actor.device}` : "system"
  ctx.audit({ actor: actorName, action, target: row.id, detail: { item: row.slug, device: row.device, ...(by ? { by } : {}), ...detail } })
}

function endRule(ctx: VaultContext, state: AccessState, row: RuleRow, reason: NonNullable<PolicyAreaGrantView["endedReason"]>, at: number, actor: RuleActor): RuleRow {
  ctx.sql.exec("UPDATE policy_rules SET ended_at=?,ended_reason=? WHERE id=? AND ended_at IS NULL", at, reason, row.id)
  ctx.sql.exec("DELETE FROM policy_rule_anchors WHERE source=?", row.id)
  ruleAudit(ctx, state, row, actor, "rule.end", reason.replace("-", "_"), { reason, ...kindDetail(row) })
  return { ...row, ended_at: at, ended_reason: reason }
}
// A task grant's audit rows say so; a shape rule's are as before grants.
const kindDetail = (row: Pick<RuleRow, "kind">) => (row.kind === "area" ? { kind: "area" } : {})
// Records why a rule ended the first time the vault reads it ended.
function settleRule(ctx: VaultContext, state: AccessState, row: RuleRow, now: number): RuleRow {
  if (row.ended_at !== null) return row
  const reason = ruleEnding(ctx, state, row, now)
  return reason === null ? row : endRule(ctx, state, row, reason, reason === "expired" ? row.expires_at : now, { kind: "system" })
}

function ruleView(ctx: VaultContext, state: AccessState, row: RuleRow, viewer: AccessPrincipal): PolicyRuleView {
  const view = signedView(ctx, state, row, viewer)
  return { ...(JSON.parse(row.terms) as PolicyRuleTerms), ...view, endedReason: view.endedReason as PolicyRuleView["endedReason"] }
}
// A task grant as a list shows it: its terms, who signed, its receipt with
// each catalogue entry's words (the entry id where the catalogue no longer
// has it), and how it ended.
function grantView(ctx: VaultContext, state: AccessState, row: RuleRow, viewer: AccessPrincipal): PolicyAreaGrantView {
  const view = signedView(ctx, state, row, viewer)
  const terms = JSON.parse(row.terms) as PolicyAreaGrantTerms
  const entries = policyCatalogueNamed(terms.catalogue)?.entries ?? []
  const receipt = Object.entries(JSON.parse(row.receipt ?? "{}") as Record<string, number>).sort(([a], [b]) => (a < b ? -1 : 1)).map(([entry, count]) => ({ entry, words: entries.find((e) => e.id === entry)?.words ?? entry, count }))
  return { ...terms, ...view, receipt }
}
// A rule or a task grant, as its kind shows it.
function listedView(ctx: VaultContext, state: AccessState, row: RuleRow, viewer: AccessPrincipal): PolicyRuleView | PolicyAreaGrantView {
  return row.kind === "area" ? grantView(ctx, state, row, viewer) : ruleView(ctx, state, row, viewer)
}
// What a rule and a task grant both show: who signed, where, and its life.
function signedView(ctx: VaultContext, state: AccessState, row: RuleRow, viewer: AccessPrincipal) {
  const consent = readConsent(ctx, row.lineage)
  const guestViewer = viewer.kind === "member" && state.members.find((m) => m.id === viewer.memberId)?.standing.effectiveRole === "guest"
  // A guest learns a signer's name only when it is their own.
  const nameOf = (member: string | undefined) => {
    const signer = member === undefined ? undefined : state.members.find((m) => m.id === member)
    return signer && !(guestViewer && viewer.kind === "member" && viewer.memberId !== signer.id) ? signer.name : null
  }
  const approvedBy = nameOf(consent?.lineage.basis.member)
  const coSignedBy = row.co_lineage === null ? null : { name: nameOf(readConsent(ctx, row.co_lineage)?.lineage.basis.member) }
  return { id: row.id, approvedBy, coSignedBy, context: consent?.ask.context ?? null, createdAt: iso(row.created_at), endsAt: iso(row.ended_at ?? row.expires_at), uses: row.uses, lastUsedAt: row.last_used_at === null ? null : iso(row.last_used_at), status: row.ended_at === null ? "active" as const : "ended" as const, endedReason: row.ended_at === null ? null : row.ended_reason }
}

// source is the approval or proposal the rule came from; anchor is whose
// stored copy of the request the rule keeps (a co-signed proposal's own).
// now is the moment the caller read for the consent's deadline, so the rule
// lasts exactly its duration.
type NewRule = { id: string; terms: PolicyRuleTerms; termsDigest: string; source: string; anchor: string; lineage: ConsentLineage; coLineage: ConsentLineage | null; actor: string; session: string | null; now: number }
// The snapshot a rule binds, taken as it is created: what an exact grant for
// the same ask would bind, with no request digest (a rule covers a shape).
function checkedCredential(state: AccessState, item: ItemRecord): CheckedCredential {
  const credential = state.credentials.find((c) => c.id === item.id)
  if (!credential) throw new VaultError("not_found", "No such credential.")
  return { id: item.id, slug: item.slug, home: credential.home, version: item.version, configRevision: item.configRev }
}
function ruleSnapshot(ctx: VaultContext, state: AccessState, ask: AccessAsk, item: ItemRecord, now: number): ProtectedSnapshot {
  const principal = { kind: "device" as const, deviceId: ask.device, ...(ask.workload !== undefined ? { workload: ask.workload } : {}) }
  const bound = askBinding(ask)
  return approvedUseSnapshot(ctx, state, principal, checkedCredential(state, item), useContext(bound.context), now, bound.mode).snapshot
}
// The project and environment (or none) and the mode a rule serves: those
// of the ask it was approved for.
type RuleBinding = { context: ItemUseContext | null; mode: "relay" | "placeholder" }
const askBinding = (ask: AccessAsk): RuleBinding => ({ context: ask.context ?? null, mode: ask.mode === "placeholder" ? "placeholder" : "relay" })
const useContext = (context: ItemUseContext | null) => context ? { project: context.project, env: context.environment } : null
function createRule(ctx: VaultContext, state: AccessState, ask: AccessAsk, item: ItemRecord, rule: NewRule): RuleRow {
  const now = rule.now, id = rule.id
  const expiresAt = Math.min(now + rule.terms.ttlSeconds * 1000, rule.lineage.expiresAt, rule.coLineage?.expiresAt ?? Infinity)
  ctx.sql.exec("INSERT INTO policy_rules(id,item_id,slug,device,workload,terms,terms_digest,snapshot,source,lineage,co_lineage,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", id, item.id, item.slug, rule.terms.asker.device, rule.terms.asker.workload, canonicalJson(rule.terms), rule.termsDigest, canonicalJson(ruleSnapshot(ctx, state, ask, item, now)), rule.source, rule.lineage.id, rule.coLineage?.id ?? null, now, expiresAt)
  copyRuleAnchor(ctx, rule.anchor, id)
  const row = ruleRow(ctx, id)
  if (!row) throw new Error("Rule insertion failed")
  ruleAudit(ctx, state, row, { kind: "member", member: rule.actor, session: rule.session }, "rule.create", "created", { method: rule.terms.method, host: rule.terms.host, path: rule.terms.path, endsAt: iso(expiresAt), source: rule.source })
  return row
}

// A task grant, made as a rule is, but keeping no copy of the request: it
// covers each request by its catalogue entry, read from the request itself.
// One live grant per key and credential (ruling P1): a new one ends the
// one before as replaced. Every other pending ask from the key on the
// credential, in the grant's context and mode, whose stored request the
// grant covers is closed as superseded, with nothing sent: the agent sends
// it again and the grant lets it through.
type NewGrant = Omit<NewRule, "terms" | "anchor"> & { terms: PolicyAreaGrantTerms }
function createAreaGrant(ctx: VaultContext, state: AccessState, ask: AccessAsk, item: ItemRecord, grant: NewGrant): RuleRow {
  const now = grant.now, id = grant.id, asker = grant.terms.asker
  const actor: RuleActor = { kind: "member", member: grant.actor, session: grant.session }
  for (const live of ctx.sql.exec<RuleRow>("SELECT * FROM policy_rules WHERE kind='area' AND item_id=? AND device=? AND workload IS ? AND ended_at IS NULL", item.id, asker.device, asker.workload).toArray()) endRule(ctx, state, live, "replaced", now, actor)
  const expiresAt = Math.min(now + grant.terms.ttlSeconds * 1000, grant.lineage.expiresAt, grant.coLineage?.expiresAt ?? Infinity)
  ctx.sql.exec("INSERT INTO policy_rules(id,item_id,slug,device,workload,terms,terms_digest,snapshot,source,lineage,co_lineage,created_at,expires_at,kind,max_uses,receipt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'area',?,'{}')", id, item.id, item.slug, asker.device, asker.workload, canonicalJson(grant.terms), grant.termsDigest, canonicalJson(ruleSnapshot(ctx, state, ask, item, now)), grant.source, grant.lineage.id, grant.coLineage?.id ?? null, now, expiresAt, grant.terms.maxUses)
  const row = ruleRow(ctx, id)
  if (!row) throw new Error("Task grant insertion failed")
  ruleAudit(ctx, state, row, actor, "rule.create", "created", { kind: "area", host: grant.terms.host, catalogue: grant.terms.catalogue, areas: grant.terms.areas, maxUses: grant.terms.maxUses, endsAt: iso(expiresAt), source: grant.source })
  supersedeCoveredAsks(ctx, state, row, grant.terms, askBinding(ask), actor)
  return row
}
function supersedeCoveredAsks(ctx: VaultContext, state: AccessState, grant: RuleRow, terms: PolicyAreaGrantTerms, bound: RuleBinding, actor: Extract<RuleActor, { kind: "member" }>): void {
  const item = items.getItem(ctx, grant.slug), now = ctx.now()
  const credential = state.credentials.find((c) => c.id === grant.item_id)
  if (!item || item.id !== grant.item_id || !credential) return
  const asks = ctx.sql.exec<WorkspaceApprovalRow>("SELECT * FROM approvals WHERE device=? AND workload IS ? AND item=? AND status='pending' AND policy_status IS NULL AND bundle IS NULL AND expires_at>?", grant.device, grant.workload, grant.slug, now).toArray()
  for (const row of asks) {
    const ask = JSON.parse(row.ask) as AccessAsk
    if (ask.credential !== grant.item_id || canonicalJson(askBinding(ask)) !== canonicalJson(bound)) continue
    const request = storedRequest(ctx, row.id)
    if (!request || areaGrantEntry(terms, anchorOf(ctx, item, { device: grant.device, workload: grant.workload }, request)) === null) continue
    ctx.sql.exec("UPDATE approvals SET policy_status='superseded',superseded_by=NULL WHERE id=?", row.id)
    if (credential.home.kind === "member") auditPrivateEvent(ctx, { action: "approval.supersede", at: now, actor: { kind: "member", member: actor.member }, session: actor.session, item: credential.id, slug: row.item, outcome: "grant", run: null }, credential.home.member)
    else ctx.audit({ actor: `member:${actor.member}`, action: "approval.supersede", target: row.id, detail: { item: row.item, grant: grant.id } })
  }
}

// ---------------------------------------------------------------- the approval page

// rememberOptions.rule for a pending approval the viewer may decide: the
// terms at the narrowest path and the default duration, or why the request
// asks every time. Nothing when the request was not a relay by item held
// with the switch on, or the viewer may not make a rule for this machine.
export async function ruleOffer(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow): Promise<PolicyRuleOffer | undefined> {
  // A push never becomes a rule (design 2.4).
  if (!rulesOnHere(ctx) || managedSetting(ctx) !== null || row.status !== "pending" || isPushSubject(JSON.parse(row.subject) as { method: string })) return undefined
  const signer = ruleSigner(state, principal, JSON.parse(row.ask) as AccessAsk, ctx.now())
  if (signer === null) return undefined
  const stored = approvalAnchor(ctx, row), refusal = anchorRefusal(ctx, row.id)
  if (refusal !== null) return { terms: null, termsDigest: null, pathChoices: [], refused: refusal, coSign: false }
  if (stored === null) return undefined
  const choices = policyRulePathChoices(stored.anchor.destination.path)
  const built = choices.map((path) => ruleTermsFrom(stored.anchor, { path, ttlSeconds: RULE_DEFAULT_DURATION }))
  const first = built.find((b) => b.ok)
  if (!first) return { terms: null, termsDigest: null, pathChoices: [], refused: (built[0] as { reason: PolicyRuleRefusal } | undefined)?.reason ?? "rule.path", coSign: false }
  return { terms: first.terms, termsDigest: await policyRuleTermsDigest(first.terms), pathChoices: choices.filter((_, i) => built[i]?.ok), refused: null, coSign: signer === "co-sign" }
}

// rememberOptions.area, beside the rule's and under the same conditions,
// for an unprotected credential: the task grant the held request can start
// with its own area, 1 hour and 50 requests, and every area of the
// catalogue; or why it cannot start one. When the vault kept only why the
// request can never become a rule, a live key says so, and otherwise the
// request is not routine building, or not a service anyone reviewed.
export async function areaOffer(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow): Promise<PolicyAreaOffer | undefined> {
  if (!rulesOnHere(ctx) || managedSetting(ctx) !== null || row.status !== "pending" || projects.isProtectedItem(ctx, row.item)) return undefined
  const signer = ruleSigner(state, principal, JSON.parse(row.ask) as AccessAsk, ctx.now())
  if (signer === null) return undefined
  const stored = approvalAnchor(ctx, row), refusal = anchorRefusal(ctx, row.id)
  const refusedOffer = (reason: PolicyAreaRefusal): PolicyAreaOffer => ({ terms: null, termsDigest: null, areas: [], refused: reason, coSign: false })
  if (refusal !== null) return refusedOffer(heldAreaRefusal(row, refusal))
  if (stored === null) return undefined
  const built = areaGrantTermsFrom(stored.anchor, null)
  if (!built.ok) return refusedOffer(built.reason)
  const areas = (policyCatalogueNamed(built.terms.catalogue)?.areas ?? []).map((a) => ({ id: a.id, name: a.name, words: a.words, requestArea: a.id === built.requestArea }))
  return { terms: built.terms, termsDigest: await policyAreaGrantTermsDigest(built.terms), areas, refused: null, coSign: signer === "co-sign" }
}
// Why a held request the vault kept no bytes of cannot start a task grant.
function heldAreaRefusal(row: WorkspaceApprovalRow, refusal: PolicyRuleRefusal): PolicyAreaRefusal {
  if (refusal === "rule.live-key") return "area.live-key"
  const subject = JSON.parse(row.subject) as { method: string; url: string }
  const parsed = parseDestination(subject.method, subject.url)
  return parsed.ok && policyCatalogueFor(parsed.destination.host) !== null ? "area.not-routine" : "area.unreviewed"
}

export type RememberedRule = { kind: "rule"; terms: PolicyRuleTerms; termsDigest: string; signer: RuleSigner; item: ItemRecord }
// requestArea: the held request's own area, which a co-sign proposal keeps
// for its page.
export type RememberedArea = { kind: "area"; terms: PolicyAreaGrantTerms; termsDigest: string; signer: RuleSigner; item: ItemRecord; requestArea: string }
// The rule an approval's remember asks for, rebuilt by the vault from the
// stored request with the chosen path and duration; refused unless its
// digest is the one the passkey signed.
export async function prepareRemember(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow, remember: PolicyRememberRule): Promise<RememberedRule> {
  rulesAvailable(ctx)
  const signer = ruleSigner(state, principal, JSON.parse(row.ask) as AccessAsk, ctx.now())
  if (signer === null) throw new VaultError("forbidden", "Only the machine's owner can allow this from now on; approve it once instead.")
  const stored = approvalAnchor(ctx, row)
  if (stored === null) throw refused(anchorRefusal(ctx, row.id) ?? "rule.terms")
  const built = ruleTermsFrom(stored.anchor, { path: remember.path, ttlSeconds: remember.ttlSeconds })
  if (!built.ok) throw refused(built.reason)
  const termsDigest = await policyRuleTermsDigest(built.terms)
  if (termsDigest !== remember.termsDigest) throw new VaultError("conflict", "The rule's terms are not the ones the vault offers; reload the page and approve again.")
  return { kind: "rule", terms: built.terms, termsDigest, signer, item: stored.item }
}

// The task grant an approval's area remember asks for, rebuilt by the vault
// from the stored request, the key that sent it, the catalogue as it is now
// and the chosen areas, duration and uses; refused unless its digest is the
// one the passkey signed. While the person is cooling off, the approval's
// own step-up refuses it (step-up-rules.ts).
export async function prepareAreaRemember(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow, remember: PolicyRememberArea): Promise<RememberedArea> {
  rulesAvailable(ctx)
  const signer = ruleSigner(state, principal, JSON.parse(row.ask) as AccessAsk, ctx.now())
  if (signer === null) throw new VaultError("forbidden", "Only the machine's owner can let this agent carry on; approve it once instead.")
  if (projects.isProtectedItem(ctx, row.item)) throw new VaultError("environment_refused", "This credential backs a protected environment, so it asks every time.")
  const stored = approvalAnchor(ctx, row)
  if (stored === null) {
    const refusal = anchorRefusal(ctx, row.id)
    throw areaRefused(refusal === null ? "area.terms" : heldAreaRefusal(row, refusal))
  }
  const built = areaGrantTermsFrom(stored.anchor, { areas: remember.areas, ttlSeconds: remember.ttlSeconds, maxUses: remember.maxUses })
  if (!built.ok) throw areaRefused(built.reason)
  const termsDigest = await policyAreaGrantTermsDigest(built.terms)
  if (termsDigest !== remember.termsDigest) throw new VaultError("conflict", "The task grant's terms are not the ones the vault offers; reload the page and approve again.")
  return { kind: "area", terms: built.terms, termsDigest, signer, item: stored.item, requestArea: built.requestArea }
}

// Inside the approval's transaction, after the one request is granted: the
// rule itself, or, when a manager of the home must co-sign, a proposal at
// stage co-sign holding the owner's consent.
export function applyRemember(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: WorkspaceApprovalRow, prepared: RememberedRule | RememberedArea, invocation: WorkspaceInvocationContext): void {
  if (principal.kind !== "member" || invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only a person can allow a request from now on.")
  const current = items.getItem(ctx, prepared.item.slug)
  if (!current || current.id !== prepared.item.id || current.configRev !== prepared.item.configRev || current.version !== prepared.item.version) throw new VaultError("conflict", "The credential changed; reload the page and approve again.")
  const ask = JSON.parse(row.ask) as AccessAsk
  if (prepared.kind === "area" && prepared.signer === "co-sign") {
    // As a rule's co-sign: the grant's clock starts when a manager signs.
    const proposal = openRuleProposal(ctx, state, { asker: prepared.terms.asker, item: current, ask, terms: prepared.terms, termsDigest: prepared.termsDigest, requestArea: prepared.requestArea, source: row.id, extends: null, reason: null, requestedBy: { member: principal.memberId, self: false }, requester: `cosign:${row.id}`, stage: "co-sign", approver: { member: principal.memberId, invocation } })
    copyRuleAnchor(ctx, row.id, proposal.id)
    return
  }
  if (prepared.kind === "area") {
    const id = randomId("rul"), now = ctx.now()
    const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${id}`, principal.memberId, ask, now + prepared.terms.ttlSeconds * 1000, invocation)
    createAreaGrant(ctx, state, ask, current, { id, terms: prepared.terms, termsDigest: prepared.termsDigest, source: row.id, lineage, coLineage: null, actor: principal.memberId, session: invocation.auth.session, now })
    return
  }
  if (prepared.signer === "direct") {
    const id = randomId("rul"), now = ctx.now()
    const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${id}`, principal.memberId, ask, now + prepared.terms.ttlSeconds * 1000, invocation)
    createRule(ctx, state, ask, current, { id, terms: prepared.terms, termsDigest: prepared.termsDigest, source: row.id, anchor: row.id, lineage, coLineage: null, actor: principal.memberId, session: invocation.auth.session, now })
    return
  }
  const proposal = openRuleProposal(ctx, state, { asker: prepared.terms.asker, item: current, ask, terms: prepared.terms, termsDigest: prepared.termsDigest, source: row.id, extends: null, reason: null, requestedBy: { member: principal.memberId, self: false }, requester: `cosign:${row.id}`, stage: "co-sign", approver: { member: principal.memberId, invocation } })
  copyRuleAnchor(ctx, row.id, proposal.id)
}

// What a machine's approval status adds after a remember; nothing with the
// switch off, as before rules. A task grant is never named; its co-sign
// proposal is, as a rule's.
export function approvalRuleRefs(ctx: VaultContext, invocation: WorkspaceInvocationContext, approval: string): { rule?: { id: string; endsAt: string }; ruleProposal?: PolicyRuleProposalRef } {
  if (!rulesOnHere(ctx)) return {}
  const rule = directlyRememberedRule(ctx, approval)
  if (rule) return { rule: { id: rule.id, endsAt: iso(rule.ended_at ?? rule.expires_at) } }
  const proposal = one(ctx.sql.exec<ProposalRow>("SELECT * FROM policy_proposals WHERE requester=?", `cosign:${approval}`))
  if (!proposal) return {}
  const status = proposalStatus(ctx, proposal)
  const ref = { ruleProposal: { id: proposal.id, url: proposalUrl(ctx, invocation, proposal.id), bindingCode: proposal.code, expiresAt: iso(proposal.expires_at) } }
  if (isAreaTerms((JSON.parse(proposal.rule_terms) as ProposalTerms).terms)) return ref
  return status.rule ? { rule: status.rule } : ref
}

// The rule an approval's own remember made with one passkey. A co-signed
// proposal's rule names the approval it came from as its source too, both
// the remember's own co-sign proposal (cosign:<approval>, whose outcome
// approvalRuleRefs reads instead) and a machine's later proposal from the
// same approval, so a rule any proposal made is left out here. An
// extension's proposal only moves a rule's end, so it does not count.
function directlyRememberedRule(ctx: VaultContext, approval: string): RuleRow | null {
  return one(ctx.sql.exec<RuleRow>("SELECT * FROM policy_rules r WHERE r.source=? AND r.kind IS NULL AND NOT EXISTS (SELECT 1 FROM policy_proposals p WHERE p.outcome=r.id AND p.rule_terms IS NOT NULL AND p.requester NOT LIKE 'extend:%')", approval))
}

// The same refs on the approval page (ApprovalView.rule and ruleProposal),
// to a person who may read the rule, or the proposal's detail; nothing with
// the switch off or when the approval remembered nothing they may read.
export function approvalRuleView(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, invocation: WorkspaceInvocationContext, approval: string): { rule: PolicyRuleRef | null; ruleProposal: PolicyRuleProposalRef | null } | null {
  if (!rulesOnHere(ctx)) return null
  const refs = approvalRuleRefs(ctx, invocation, approval)
  if (refs.rule) {
    const rule = ruleRow(ctx, refs.rule.id)
    return rule && visibleRule(ctx, state, principal, rule) ? { rule: refs.rule, ruleProposal: null } : null
  }
  if (!refs.ruleProposal) return null
  const row = ruleProposalRow(ctx, refs.ruleProposal.id)
  try {
    return row && ruleProposalProjection(ctx, state, principal, row, invocation).view === "detail" ? { rule: null, ruleProposal: refs.ruleProposal } : null
  } catch (error) {
    if (error instanceof VaultError && error.code === "not_found") return null
    throw error
  }
}

// ---------------------------------------------------------------- the relay

// The live rule that lets this held request through without asking, or
// null. Only for a request the item's policy would hold for approval, by a
// key in an unmanaged workspace, in the project and environment (or none)
// its approval was asked in; the caller never asks for a protected item,
// environment or run. A rule that has ended is settled on the way.
export function coveringRule(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: ItemRecord, request: HeldRequest, mode: "relay" | "placeholder", context: ItemUseContext | null): string | null {
  if (!rulesOnHere(ctx) || managedSetting(ctx) !== null || projects.isProtectedItem(ctx, item.slug)) return null
  const asker = askerOf(principal)
  const candidates = ctx.sql.exec<RuleRow>("SELECT * FROM policy_rules WHERE item_id=? AND device=? AND workload IS ? AND kind IS NULL AND ended_at IS NULL ORDER BY created_at", item.id, asker.device, asker.workload).toArray()
  if (candidates.length === 0) return null
  const anchor = anchorOf(ctx, item, asker, request)
  const state = accessState(ctx), now = ctx.now()
  for (const candidate of candidates) {
    if (!servesUse(ctx, candidate, mode, context) || !ruleCovers(JSON.parse(candidate.terms) as PolicyRuleTerms, anchor)) continue
    if (settleRule(ctx, state, candidate, now).ended_at === null) return candidate.id
  }
  return null
}
// A rule or task grant serves the mode and the project and environment (or
// none) its approval was asked in.
function servesUse(ctx: VaultContext, row: RuleRow, mode: "relay" | "placeholder", context: ItemUseContext | null): boolean {
  return ((JSON.parse(row.snapshot) as ProtectedSnapshot).mode ?? "relay") === mode && canonicalJson(readConsent(ctx, row.lineage)?.ask.context ?? null) === canonicalJson(context)
}
// Inside the relay's last transaction: the rule still stands.
export function assertRuleCurrent(ctx: VaultContext, id: string): void {
  const row = ruleRow(ctx, id)
  if (!row || row.ended_at !== null || ruleEnding(ctx, accessState(ctx), row, ctx.now()) !== null) throw ruleEnded()
}

// The live task grant that lets this held request through without asking,
// and the catalogue entry it covers it as; or null. Asked only after
// coveringRule found none, under the same conditions. A grant that has
// ended is settled on the way.
export type CoveringGrant = { id: string; entry: string }
export function coveringAreaGrant(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: ItemRecord, request: HeldRequest, mode: "relay" | "placeholder", context: ItemUseContext | null): CoveringGrant | null {
  if (!rulesOnHere(ctx) || managedSetting(ctx) !== null || projects.isProtectedItem(ctx, item.slug)) return null
  const asker = askerOf(principal)
  const candidates = ctx.sql.exec<RuleRow>("SELECT * FROM policy_rules WHERE item_id=? AND device=? AND workload IS ? AND kind='area' AND ended_at IS NULL ORDER BY created_at", item.id, asker.device, asker.workload).toArray()
  if (candidates.length === 0) return null
  const anchor = anchorOf(ctx, item, asker, request)
  const state = accessState(ctx), now = ctx.now()
  for (const candidate of candidates) {
    if (!servesUse(ctx, candidate, mode, context)) continue
    const entry = areaGrantEntry(JSON.parse(candidate.terms) as PolicyAreaGrantTerms, anchor)
    if (entry !== null && settleRule(ctx, state, candidate, now).ended_at === null) return { id: candidate.id, entry: entry.id }
  }
  return null
}
// Inside the relay's last transaction: the grant still stands and has a
// use left, so of two requests racing for its last use, the second fails.
export function assertAreaGrantCurrent(ctx: VaultContext, id: string): void {
  const row = ruleRow(ctx, id)
  if (!row || row.kind !== "area" || row.ended_at !== null || ruleEnding(ctx, accessState(ctx), row, ctx.now()) !== null) throw ruleEnded()
}
// Counts the use under its catalogue entry; the use that reaches the most
// the grant allows ends it as uses-spent.
export function recordAreaGrantUse(ctx: VaultContext, grant: CoveringGrant, run: string | null): void {
  const row = ruleRow(ctx, grant.id)
  if (!row) return
  const receipt = JSON.parse(row.receipt ?? "{}") as Record<string, number>
  receipt[grant.entry] = (receipt[grant.entry] ?? 0) + 1
  ctx.sql.exec("UPDATE policy_rules SET uses=uses+1,last_used_at=?,receipt=? WHERE id=?", ctx.now(), canonicalJson(receipt), grant.id)
  const used = ruleRow(ctx, grant.id)!
  const state = accessState(ctx)
  ruleAudit(ctx, state, used, { kind: "device", device: used.device, workload: used.workload }, "rule.use", "allowed", { kind: "area", entry: grant.entry, uses: used.uses, ...(run ? { run } : {}) })
  if (used.uses >= (used.max_uses ?? 0)) endRule(ctx, state, used, "uses-spent", ctx.now(), { kind: "system" })
}
export function recordRuleUse(ctx: VaultContext, id: string, run: string | null): void {
  ctx.sql.exec("UPDATE policy_rules SET uses=uses+1,last_used_at=? WHERE id=?", ctx.now(), id)
  const row = ruleRow(ctx, id)
  if (!row) return
  ruleAudit(ctx, accessState(ctx), row, { kind: "device", device: row.device, workload: row.workload }, "rule.use", "allowed", { uses: row.uses, ...(run ? { run } : {}) })
}

// ---------------------------------------------------------------- proposals

const proposalUrl = (ctx: VaultContext, invocation: WorkspaceInvocationContext, id: string) => `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/p/${id}`
// What the approver reads: the request shape, the key, where it is asked
// (a project's environment, or outside any project) and, for a run's
// placeholder, that it comes from `mehen run`, and how long.
function ruleSummary(ctx: VaultContext, terms: PolicyRuleTerms, bound: RuleBinding): string {
  const days = terms.ttlSeconds / 86_400
  return `${terms.method} ${terms.host}${terms.path}${terms.graphql ? `, ${terms.graphql.fields.join(", ")}` : ""}, ${askedFrom(ctx, terms.asker, bound)}, ${days} day${days === 1 ? "" : "s"}`
}
// A task grant's: the areas by name, the key, where, how long and how many
// requests.
function areaSummary(ctx: VaultContext, terms: PolicyAreaGrantTerms, bound: RuleBinding): string {
  const areas = policyCatalogueNamed(terms.catalogue)?.areas ?? []
  const names = terms.areas.map((id) => areas.find((a) => a.id === id)?.name ?? id).join(", ")
  const minutes = terms.ttlSeconds / 60
  return `Task grant on ${terms.host}: ${names}, ${askedFrom(ctx, terms.asker, bound)}, ${minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hour${minutes === 60 ? "" : "s"}`}, up to ${terms.maxUses} requests`
}
function proposalSummary(ctx: VaultContext, terms: PolicyRuleTerms | PolicyAreaGrantTerms, bound: RuleBinding): string {
  return isAreaTerms(terms) ? areaSummary(ctx, terms, bound) : ruleSummary(ctx, terms, bound)
}
function askedFrom(ctx: VaultContext, asker: Asker, bound: RuleBinding): string {
  const machine = devicePolicyState(ctx, asker.device)?.name ?? asker.device
  const task = asker.workload === null ? null : workloadRow(ctx, asker.workload)?.label ?? null
  const project = bound.context === null ? null : accessState(ctx).projects.find((p) => p.id === bound.context?.project)?.slug ?? bound.context.project
  const where = bound.context === null ? "outside any project" : `in ${project} / ${bound.context.environment}`
  return `from ${task !== null ? `task ${task} on ` : ""}${machine}, ${where}${bound.mode === "placeholder" ? ", from `mehen run`" : ""}`
}
// What a person's passkey signs as the proposal's digest: its id, stage and
// terms, so an owner's approval never passes for a co-signer's.
function proposalDigest(row: ProposalRow): string {
  const held = JSON.parse(row.rule_terms) as ProposalTerms
  return digestOf({ domain: "mehen-policy-rule-proposal/v1", proposal: row.id, stage: row.stage, termsDigest: held.termsDigest, extends: held.extends, reason: row.reason })
}

// A task grant's proposal (terms of kind area) also keeps the held
// request's own area (requestArea).
type NewProposal = { asker: Asker; item: ItemRecord; ask: AccessAsk; terms: PolicyRuleTerms | PolicyAreaGrantTerms; termsDigest: string; requestArea?: string; source: string | null; extends: string | null; reason: string | null; requestedBy: RequestedBy; requester: string; stage: PolicyRuleProposalStatus["stage"]; approver: { member: string; invocation: WorkspaceInvocationContext } | null }
function openRuleProposal(ctx: VaultContext, state: AccessState, input: NewProposal): ProposalRow {
  const now = ctx.now(), id = randomId("pol")
  const lineage = input.approver ? storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${id}`, input.approver.member, input.ask, now + PROPOSAL_TTL_MS + input.terms.ttlSeconds * 1000, input.approver.invocation) : null
  const held: ProposalTerms = { terms: input.terms, termsDigest: input.termsDigest, source: input.source, extends: input.extends, configRevision: input.approver ? input.item.configRev : null, ...(input.requestArea !== undefined ? { requestArea: input.requestArea } : {}) }
  const deviceName = devicePolicyState(ctx, input.asker.device)?.name ?? input.asker.device
  ctx.sql.exec(
    "INSERT INTO policy_proposals(id,requester,requested_by,device_name,item,slug,device,requested,reason,snapshot,guard,digest,code,slot_revision,predecessor,preview,status,created_at,expires_at,decided_by,ask,lineage,rule_terms,stage) VALUES (?,?,?,?,?,?,?,?,?,'{}',?,'',?,0,'','{}','pending',?,?,?,?,?,?,?)",
    id, input.requester, canonicalJson(input.requestedBy), deviceName, input.item.id, input.item.slug, input.asker.device, canonicalJson(input.terms), input.reason ?? "", input.termsDigest, bindingCode(), now, now + PROPOSAL_TTL_MS, input.approver?.member ?? null, JSON.stringify(input.ask), lineage?.id ?? null, canonicalJson(held), input.stage,
  )
  const row = ruleProposalRow(ctx, id)
  if (!row) throw new Error("Proposal insertion failed")
  ctx.sql.exec("UPDATE policy_proposals SET digest=? WHERE id=?", proposalDigest(row), id)
  const actor: RuleActor = input.approver ? { kind: "member", member: input.approver.member, session: input.approver.invocation.auth.kind === "account" ? input.approver.invocation.auth.session : null } : { kind: "device", device: input.asker.device, workload: input.asker.workload }
  ruleAudit(ctx, state, { id, item_id: input.item.id, slug: input.item.slug, device: input.asker.device, workload: input.asker.workload }, actor, "rule.propose", "pending", { stage: input.stage, ...proposedDetail(input.terms), ...(input.extends ? { extends: input.extends, ttlSeconds: input.terms.ttlSeconds } : {}) })
  return row
}
// What a proposal's audit row says it would allow: a rule's request shape,
// or a task grant's host, areas, uses and duration, as rule.create says them.
function proposedDetail(terms: PolicyRuleTerms | PolicyAreaGrantTerms): Record<string, unknown> {
  return isAreaTerms(terms) ? { kind: "area", host: terms.host, catalogue: terms.catalogue, areas: terms.areas, maxUses: terms.maxUses, ttlSeconds: terms.ttlSeconds } : { method: terms.method, host: terms.host, path: terms.path }
}

// A proposal's status as the vault reads it now: a pending one past its
// time has expired, and one whose credential no longer stands, or (at stage
// co-sign) whose owner's consent no longer stands or whose credential was
// edited after the owner approved, is stale.
function proposalStatus(ctx: VaultContext, row: ProposalRow): PolicyRuleProposalStatus {
  const now = ctx.now()
  let status = row.status
  if (status === "pending" && row.expires_at <= now) status = "expired"
  if (status === "pending") {
    const item = items.getItem(ctx, row.slug)
    const consent = row.lineage ? readConsent(ctx, row.lineage) : null
    const held = JSON.parse(row.rule_terms) as ProposalTerms
    if (!item || item.id !== row.item || row.stage === "co-sign" && (item.configRev !== held.configRevision || !consent || !standingConsentCurrent(ctx, accessState(ctx), consent.lineage, consent.ask, now))) status = "stale"
  }
  const rule = row.outcome ? ruleRow(ctx, row.outcome) : null
  return { proposal: row.id, item: row.slug, status, stage: row.stage, bindingCode: row.code, summary: proposalSummary(ctx, (JSON.parse(row.rule_terms) as ProposalTerms).terms, askBinding(JSON.parse(row.ask) as AccessAsk)), expiresAt: iso(row.expires_at), rule: rule ? { id: rule.id, endsAt: iso(rule.ended_at ?? rule.expires_at) } : null }
}

// Who may act on a rule proposal now: at stage approve, an approver of the
// machine's ask; at stage co-sign, a manager of the credential's home other
// than the owner who approved. Anyone who may deny the ask may deny it.
function proposalRights(state: AccessState, principal: AccessPrincipal, row: ProposalRow, now: number): { canApprove: boolean; canDeny: boolean } {
  const ask = JSON.parse(row.ask) as AccessAsk
  if (principal.kind !== "member") return { canApprove: false, canDeny: false }
  const target = { ask, ...(ask.credential ? { credential: ask.credential } : {}) }
  const canApprove = row.stage === "approve" ? ruleSigner(state, principal, ask, now) !== null : principal.memberId !== row.decided_by && can(state, principal, { type: "policy.cosign" }, target, now).allowed
  return { canApprove, canDeny: can(state, principal, { type: "policy.deny" }, { ask }, now).allowed }
}

export function ruleProposalProjection(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: ProposalRow, invocation: WorkspaceInvocationContext): PolicyStandingProposalViewProjection {
  if (principal.kind !== "member") throw new VaultError("not_found", "No such object.")
  const ask = JSON.parse(row.ask) as AccessAsk, now = ctx.now()
  const rights = eligibility(state, principal.memberId, ask, now)
  const co = row.stage === "co-sign" && can(state, principal, { type: "policy.cosign" }, { ask, ...(ask.credential ? { credential: ask.credential } : {}) }, now).allowed
  if (!rights.canReadAskDetail && !rights.canDeny && !co) throw new VaultError("not_found", "No such object.")
  const status = proposalStatus(ctx, row)
  const owner = ownerRef(state, row.device)
  if (!rights.canReadAskDetail) return { view: "stop", id: row.id, workspace: invocation.workspace, machine: { device: row.device, name: row.device_name, owner }, item: { slug: row.slug }, status: status.status, eligibility: rights }
  const held = JSON.parse(row.rule_terms) as ProposalTerms
  const live = status.status === "pending" ? proposalRights(state, principal, row, now) : { canApprove: false, canDeny: false }
  const approver = row.stage === "co-sign" && row.decided_by ? state.members.find((m) => m.id === row.decided_by) : undefined
  const requested = JSON.parse(row.requested_by) as RequestedBy
  const approvedBy = row.stage === "co-sign" ? { name: approver?.name ?? null, self: row.decided_by === principal.memberId } : null
  if (isAreaTerms(held.terms)) {
    // The co-signer may keep any of the areas the owner signed, no others.
    const catalogue = policyCatalogueNamed(held.terms.catalogue)?.areas ?? []
    const areas = held.terms.areas.map((id) => { const a = catalogue.find((c) => c.id === id); return { id, name: a?.name ?? id, words: a?.words ?? "", requestArea: id === held.requestArea } })
    const grant: PolicyAreaProposalView = {
      ...status, kind: "area", extends: null, requestedBy: "device" in requested ? { ...requested, ...askingWorkload(ctx, held.terms.asker.workload) } : { member: requested.member, self: requested.member === principal.memberId },
      reason: row.reason === "" ? null : row.reason, terms: held.terms, termsDigest: held.termsDigest, areas, digest: proposalDigest(row), approvedBy, ...live,
    }
    return { view: "detail", proposal: { ...grant, workspace: invocation.workspace, owner, eligibility: rights } }
  }
  const view: PolicyRuleProposalView = {
    ...status, kind: "rule", extends: held.extends, requestedBy: "device" in requested ? { ...requested, ...askingWorkload(ctx, held.terms.asker.workload) } : { member: requested.member, self: requested.member === principal.memberId },
    reason: row.reason === "" ? null : row.reason, terms: held.terms, termsDigest: held.termsDigest, pathChoices: held.extends !== null ? [held.terms.path] : [...new Set([held.terms.anchorPath, held.terms.path])], digest: proposalDigest(row),
    approvedBy, ...live,
  }
  return { view: "detail", proposal: { ...view, workspace: invocation.workspace, owner, eligibility: rights } }
}

// The request a proposal is made from: a held (still pending) or approved
// request of this key, as the vault stored it, in the context and mode it
// was asked in; or an example the key names for one of its own credentials,
// in the context it names or none, checked as the relay would check its use.
async function proposalAnchor(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, input: PolicyRuleProposal, invocation: WorkspaceInvocationContext): Promise<{ anchor: PolicyRuleAnchor; item: ItemRecord; source: string | null; request: HeldRequest; bound: RuleBinding }> {
  const asker = askerOf(principal)
  if ("approval" in input.from) {
    const { row, bound, refusal, held } = heldAnchor(ctx, principal, input.from.approval, invocation, "propose from an example request instead")
    if (refusal !== null || held === null) throw refused(refusal ?? "rule.terms")
    return { ...held, source: row.id, bound }
  }
  const from = input.from
  const bound: RuleBinding = { context: from.context ?? null, mode: "relay" }
  const parsed = parseDestination(from.method, from.url)
  if (!parsed.ok) throw new VaultError("bad_request", "That is not a URL a rule can name.")
  visibleCredential(ctx, principal, from.item, { context: bound.context, mode: "relay" })
  const item = items.getItem(ctx, from.item)
  if (!item) throw new VaultError("not_found", `No credential called "${from.item}".`)
  authorise(ctx, invocation, { type: "item.use", context: bound.context }, { credential: item.id, mode: "relay" }, ctx.now())
  if (projects.isProtectedItem(ctx, item.slug)) throw new VaultError("environment_refused", "This credential backs a protected environment, so it asks every time.")
  let body: Uint8Array | null = null
  if (from.bodyBase64 !== undefined && from.bodyBase64 !== "") body = base64UrlDecode(from.bodyBase64.replace(/=+$/, "").replaceAll("+", "-").replaceAll("/", "_"))
  const url = new URL(from.url)
  url.hash = ""
  url.pathname = parsed.destination.path
  const request: HeldRequest = { destination: parsed.destination, url: url.href, body, contentType: from.contentType ?? null, contentEncoding: null }
  return { anchor: anchorOf(ctx, item, asker, request), item, source: null, request, bound }
}

// A held (still pending) or approved request of this key, as the vault
// stored it, in the context and mode it was asked in, once the key is still
// allowed to use its credential there: what a rule or a task grant proposal
// is made from. held is null when the vault kept only why the request can
// never become a rule (refusal). item, when named, must be the request's
// credential, or the approval is not found, as another key's is. instead
// says what to do when the request is gone or was denied.
type HeldAnchor = { row: WorkspaceApprovalRow; bound: RuleBinding; refusal: PolicyRuleRefusal | null; held: { anchor: PolicyRuleAnchor; item: ItemRecord; request: HeldRequest } | null }
function heldAnchor(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, approval: string, invocation: WorkspaceInvocationContext, instead: string, item?: string): HeldAnchor {
  const asker = askerOf(principal)
  const row = workspaceApproval(ctx, approval)
  if (!row || row.device !== asker.device || row.workload !== asker.workload || item !== undefined && row.item !== item) throw new VaultError("not_found", "No such approval.")
  if (row.status !== "approved" && !(row.status === "pending" && row.expires_at > ctx.now())) throw new VaultError("conflict", `That request was denied or has expired; ${instead}.`)
  const ask = JSON.parse(row.ask) as AccessAsk, bound = askBinding(ask)
  const refusal = anchorRefusal(ctx, row.id)
  const stored = refusal === null ? approvalAnchor(ctx, row) : null
  const request = refusal === null ? storedRequest(ctx, row.id) : null
  if (refusal === null && (!stored || !request)) throw new VaultError("not_found", `The vault no longer holds that request; ${instead}.`)
  authorise(ctx, invocation, { type: "item.use", context: bound.context }, { credential: stored?.item.id ?? ask.credential ?? "", mode: bound.mode }, ctx.now())
  return { row, bound, refusal, held: refusal === null && stored && request ? { ...stored, request } : null }
}

function assertRuleAskRoom(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>): void {
  if (openAskCount(ctx, principal.deviceId, ctx.now()) >= 20) throw new VaultError("rate_limited", "This machine already has 20 open asks. Settle one before asking again.")
  assertWorkloadAskRoom(ctx, principal.workload, ctx.now())
}

// The decision's terms: the proposal's, narrowed to the anchor's own path
// and a duration no longer, rebuilt from the stored request. An extension
// keeps the rule's own path: it moves only the deadline.
async function decidedTerms(ctx: VaultContext, row: ProposalRow, effective: { path: string; ttlSeconds: RuleDuration }): Promise<{ terms: PolicyRuleTerms; termsDigest: string; item: ItemRecord }> {
  const held = JSON.parse(row.rule_terms) as ProposalTerms
  if (isAreaTerms(held.terms)) throw new VaultError("bad_request", "Approve names the areas, duration and uses of a task grant.")
  if (held.extends !== null && effective.path !== held.terms.path) throw new VaultError("bad_request", "An extension keeps the rule's path; to narrow it, revoke the rule and allow the request again.")
  if (effective.path !== held.terms.path && effective.path !== held.terms.anchorPath || effective.ttlSeconds > held.terms.ttlSeconds) throw new VaultError("bad_request", "A decision may only narrow the proposed path and duration.")
  const item = items.getItem(ctx, row.slug)
  const request = storedRequest(ctx, row.id)
  if (!item || item.id !== row.item || !request) throw new VaultError("conflict", "The credential changed; this proposal is stale.")
  const built = ruleTermsFrom(anchorOf(ctx, item, held.terms.asker, request), effective)
  if (!built.ok) throw refused(built.reason)
  return { terms: built.terms, termsDigest: await policyRuleTermsDigest(built.terms), item }
}
// A task grant's co-sign: the owner's terms with the areas, duration and
// uses the co-signer keeps, each no more than proposed, checked against the
// stored request and the catalogue as they are now (every area still in
// it). The catalogue version stays the one the owner signed, so entries
// added since are not covered until someone signs again.
async function decidedAreaTerms(ctx: VaultContext, row: ProposalRow, effective: PolicyAreaEffective): Promise<{ terms: PolicyAreaGrantTerms; termsDigest: string; item: ItemRecord }> {
  const held = JSON.parse(row.rule_terms) as ProposalTerms
  if (!isAreaTerms(held.terms)) throw new VaultError("bad_request", "Approve names the path and duration; deny names neither.")
  const proposed = held.terms
  if (!effective.areas.every((a) => proposed.areas.includes(a)) || effective.ttlSeconds > proposed.ttlSeconds || effective.maxUses > proposed.maxUses) throw new VaultError("bad_request", "A decision may only narrow the proposed areas, duration and uses.")
  const item = items.getItem(ctx, row.slug)
  const request = storedRequest(ctx, row.id)
  if (!item || item.id !== row.item || !request) throw new VaultError("conflict", "The credential changed; this proposal is stale.")
  const built = areaGrantTermsFrom(anchorOf(ctx, item, proposed.asker, request), effective)
  if (!built.ok) throw areaRefused(built.reason)
  const terms: PolicyAreaGrantTerms = { ...proposed, areas: effective.areas, ttlSeconds: effective.ttlSeconds, maxUses: effective.maxUses }
  if (built.terms.catalogue !== terms.catalogue || built.terms.host !== terms.host) throw new VaultError("conflict", "The credential changed; this proposal is stale.")
  return { terms, termsDigest: await policyAreaGrantTermsDigest(terms), item }
}

const RuleDecisionInput = z.strictObject({ id: z.string().max(64), kind: z.literal("rule").optional(), decision: z.enum(["approve", "deny"]), effective: z.union([z.strictObject({ path: z.string(), ttlSeconds: z.number() }), z.strictObject({ areas: z.array(z.string()).max(16), ttlSeconds: z.number(), maxUses: z.number() })]).optional() })
type RuleDecisionInput = z.infer<typeof RuleDecisionInput>
async function ruleDecision(ctx: VaultContext, row: ProposalRow, input: RuleDecisionInput, invocation: WorkspaceInvocationContext) {
  const ask = JSON.parse(row.ask) as AccessAsk
  const decision = PolicyRuleDecisionSchema.safeParse(input.decision === "approve" ? { decision: "approve", effective: input.effective } : input.effective === undefined ? { decision: "deny" } : { decision: "deny", effective: input.effective })
  if (!decision.success) throw new VaultError("bad_request", "Approve names the path and duration; deny names neither.")
  if (decision.data.decision === "deny") {
    const allowed = authorise(ctx, invocation, { type: "policy.deny" }, { ask }, ctx.now())
    return { allowed, decided: null, expected: { type: "policy.decide" as const, proposal: row.id, digest: proposalDigest(row), decision: "deny" as const, effectDigest: null } }
  }
  const target = { ask, ...(ask.credential ? { credential: ask.credential } : {}) }
  const allowed = row.stage === "approve" ? authorise(ctx, invocation, { type: "policy.rule.approve" }, { ask }, ctx.now()) : authorise(ctx, invocation, { type: "policy.cosign" }, target, ctx.now())
  if (row.stage === "co-sign" && allowed.principal.kind === "member") notTheOwnersApprover(row, allowed.principal.memberId)
  const effective = decision.data.effective
  const decided = "path" in effective ? await decidedTerms(ctx, row, effective) : await decidedAreaTerms(ctx, row, effective)
  return { allowed, decided, expected: { type: "policy.decide" as const, proposal: row.id, digest: proposalDigest(row), decision: "approve" as const, effectDigest: decided.termsDigest } }
}

// A co-sign is a second person's: never the one who approved as the
// machine's owner, even once they manage the credential's home.
function notTheOwnersApprover(row: ProposalRow, memberId: string): void {
  if (row.decided_by === memberId) throw new VaultError("forbidden", "You approved this as the machine's owner; a second person must co-sign it.")
}

function decideRuleProposal(ctx: VaultContext, principal: AccessPrincipal, rowId: string, prepared: Awaited<ReturnType<typeof ruleDecision>>, invocation: WorkspaceInvocationContext): void {
  if (principal.kind !== "member" || invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only a person can decide a proposal.")
  const memberId = principal.memberId, session = invocation.auth.session
  ctx.storage.transactionSync(() => {
    const row = ruleProposalRow(ctx, rowId)
    if (!row) throw new VaultError("not_found", "No such object.")
    requireStepUp(ctx, prepared.allowed, prepared.expected, invocation)
    if (proposalDigest(row) !== prepared.expected.digest || proposalStatus(ctx, row).status !== "pending") throw new VaultError("conflict", "This proposal is no longer pending.")
    const state = eligibilityState(ctx, invocation), ask = JSON.parse(row.ask) as AccessAsk, now = ctx.now()
    const audited = { id: row.id, item_id: row.item, slug: row.slug, device: row.device, workload: ask.workload ?? null }
    if (prepared.decided === null) {
      ctx.sql.exec("UPDATE policy_proposals SET status='denied',decided_by=? WHERE id=?", memberId, row.id)
      // A denied extension names its rule, and a declined task grant its
      // kind and host, for the activity line.
      const denied = JSON.parse(row.rule_terms) as ProposalTerms
      ruleAudit(ctx, state, audited, { kind: "member", member: memberId, session }, "policy.deny", "denied", denied.extends !== null ? { extends: denied.extends, ttlSeconds: denied.terms.ttlSeconds } : isAreaTerms(denied.terms) ? { kind: "area", host: denied.terms.host } : {})
      return
    }
    const { terms, termsDigest, item } = prepared.decided
    const current = items.getItem(ctx, item.slug)
    if (!current || current.id !== item.id || current.configRev !== item.configRev || current.version !== item.version) throw new VaultError("conflict", "The credential changed; reload the page and decide again.")
    const held = JSON.parse(row.rule_terms) as ProposalTerms
    if (row.stage === "approve") {
      const signer = ruleSigner(state, principal, ask, now)
      if (signer === null) throw new VaultError("forbidden", "Only the machine's owner can allow this from now on.")
      // A rule or a task grant that also needs a manager of the
      // credential's home waits for one at stage co-sign, keeping a task
      // grant's requestArea.
      if (signer === "co-sign") {
        const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${row.id}`, memberId, ask, now + PROPOSAL_TTL_MS + terms.ttlSeconds * 1000, invocation)
        const next: ProposalRow = { ...row, stage: "co-sign", rule_terms: canonicalJson({ ...held, terms, termsDigest, configRevision: current.configRev }) }
        ctx.sql.exec("UPDATE policy_proposals SET stage='co-sign',decided_by=?,lineage=?,rule_terms=?,expires_at=?,digest=? WHERE id=?", memberId, lineage.id, next.rule_terms, now + PROPOSAL_TTL_MS, proposalDigest(next), row.id)
        ruleAudit(ctx, state, audited, { kind: "member", member: memberId, session }, "rule.propose", "pending", { stage: "co-sign", ...proposedDetail(terms) })
        return
      }
      // A machine's task grant proposal, approved with one passkey by
      // someone who also manages the credential's home.
      if (isAreaTerms(terms)) {
        const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${row.id}`, memberId, ask, now + terms.ttlSeconds * 1000, invocation)
        const grant = createAreaGrant(ctx, state, ask, current, { id: randomId("rul"), terms, termsDigest, source: row.id, lineage, coLineage: null, actor: memberId, session, now })
        ctx.sql.exec("UPDATE policy_proposals SET status='approved',decided_by=?,outcome=? WHERE id=?", memberId, grant.id, row.id)
        return
      }
      const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${row.id}`, memberId, ask, now + terms.ttlSeconds * 1000, invocation)
      const rule = createRule(ctx, state, ask, current, { id: randomId("rul"), terms, termsDigest, source: row.id, anchor: row.id, lineage, coLineage: null, actor: memberId, session, now })
      ctx.sql.exec("UPDATE policy_proposals SET status='approved',decided_by=?,outcome=? WHERE id=?", memberId, rule.id, row.id)
      return
    }
    notTheOwnersApprover(row, memberId)
    // Protected since the first signature: no rule or grant, as proposing refuses.
    if (projects.isProtectedItem(ctx, current.slug)) throw new VaultError("environment_refused", "This credential backs a protected environment, so it asks every time.")
    const owner = row.lineage ? readConsent(ctx, row.lineage) : null
    const credential = state.credentials.find((c) => c.id === item.id)
    if (!owner || !credential || !standingConsentCurrent(ctx, state, owner.lineage, owner.ask, now)) throw new VaultError("conflict", "The machine owner's approval no longer stands; this proposal is stale.")
    const coLineage = storeCoSignConsent(ctx, state, row.id, memberId, ask, credential.home, now + terms.ttlSeconds * 1000, invocation)
    if (isAreaTerms(terms)) {
      const grant = createAreaGrant(ctx, state, ask, current, { id: randomId("rul"), terms, termsDigest, source: held.source ?? row.id, lineage: owner.lineage, coLineage, actor: memberId, session, now })
      ctx.sql.exec("UPDATE policy_proposals SET status='approved',outcome=? WHERE id=?", grant.id, row.id)
      return
    }
    if (held.extends !== null) {
      const rule = ruleRow(ctx, held.extends)
      if (!rule || settleRule(ctx, accessState(ctx), rule, now).ended_at !== null) throw new VaultError("conflict", "The rule this would extend has ended.")
      const expiresAt = Math.min(now + terms.ttlSeconds * 1000, owner.lineage.expiresAt, coLineage.expiresAt)
      // The terms the co-signer signed: the rule's own with the new duration.
      ctx.sql.exec("UPDATE policy_rules SET lineage=?,co_lineage=?,expires_at=?,terms=?,terms_digest=? WHERE id=?", owner.lineage.id, coLineage.id, expiresAt, canonicalJson(terms), termsDigest, rule.id)
      // The new deadline may be sooner than the one the alarm is set for.
      sweepRuleAnchors(ctx)
      ruleAudit(ctx, state, rule, { kind: "member", member: memberId, session }, "rule.extend", "extended", { endsAt: iso(expiresAt), proposal: row.id })
      ctx.sql.exec("UPDATE policy_proposals SET status='approved',outcome=? WHERE id=?", rule.id, row.id)
      return
    }
    const rule = createRule(ctx, state, ask, current, { id: randomId("rul"), terms, termsDigest, source: held.source ?? row.id, anchor: row.id, lineage: owner.lineage, coLineage, actor: memberId, session, now })
    ctx.sql.exec("UPDATE policy_proposals SET status='approved',outcome=? WHERE id=?", rule.id, row.id)
  })
}

// ---------------------------------------------------------------- rules: who may act

function ruleAsk(ctx: VaultContext, row: RuleRow): AccessAsk {
  const consent = readConsent(ctx, row.lineage)
  if (!consent) throw new VaultError("not_found", "No such object.")
  return consent.ask
}
// A rule is the machine's own to read and end: the key that asked; a
// person reads it when they may read the ask's detail.
function visibleRule(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: RuleRow): boolean {
  if (principal.kind === "device") return row.device === principal.deviceId && row.workload === (principal.workload ?? null)
  if (principal.kind !== "member") return false
  return can(state, principal, { type: "approval.read" }, { ask: ruleAsk(ctx, row) }, ctx.now()).allowed
}
// Ending a rule narrows, so whoever may deny or stop its ask may end it:
// the machine itself, its owner (a member of its team, for a team's
// machine, never a guest), a manager of the ask's project, any admin (as
// policy.stop), or a manager of the credential's home who may read the ask
// (policy.cosigner_revoke, policy.cosign's rule, so a co-signer too), each
// in good standing (an identity-gated workspace's check included), and with
// the narrow checks a denial has. No passkey.
function mayRevoke(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, row: RuleRow): boolean {
  if (principal.kind === "device") return visibleRule(ctx, state, principal, row)
  if (principal.kind !== "member") return false
  const ask = ruleAsk(ctx, row), now = ctx.now()
  return can(state, principal, { type: "policy.stop" }, { ask }, now).allowed || can(state, principal, { type: "policy.deny" }, { ask }, now).allowed || can(state, principal, { type: "policy.cosigner_revoke" }, { ask, ...(ask.credential ? { credential: ask.credential } : {}) }, now).allowed
}

// A person's list (policy.rules by item or machine): every live rule, and
// only the POLICY_RULES_ENDED_LISTED most recently ended they may read, so a
// busy credential's or machine's list stays bounded. personRules lists no
// more ended rules than that, though it reads past the ones the viewer may
// not see; personListed cuts again once settling a live rule has ended it.
function personRules(ctx: VaultContext, state: AccessState, principal: AccessPrincipal, column: "item_id" | "device", value: string, kinds: KindClause): RuleRow[] {
  const live = ctx.sql.exec<RuleRow>(`SELECT * FROM policy_rules WHERE ${column}=? AND ended_at IS NULL${kinds}`, value).toArray()
  const ended: RuleRow[] = []
  for (const row of ctx.sql.exec<RuleRow>(`SELECT * FROM policy_rules WHERE ${column}=? AND ended_at IS NOT NULL${kinds} ORDER BY ended_at DESC, id`, value)) {
    if (ended.length === POLICY_RULES_ENDED_LISTED) break
    if (visibleRule(ctx, state, principal, row)) ended.push(row)
  }
  return [...live, ...ended]
}
// A person's own rules (policy.rules naming neither item nor machine, the
// My rules page): the live rules on a machine they own, or that they
// approved or co-signed, each one they could also read on its credential's
// or its machine's page (the caller's visibleRule check is the rest).
function ownRules(ctx: VaultContext, state: AccessState, principal: Extract<AccessPrincipal, { kind: "member" }>, kinds: KindClause): RuleRow[] {
  const machines = state.devices.filter((d) => d.owner.kind === "member" && d.owner.id === principal.memberId).map((d) => d.id), now = ctx.now()
  return ctx.sql.exec<RuleRow>(`SELECT * FROM policy_rules WHERE ended_at IS NULL${kinds} AND (device IN (SELECT value FROM json_each(?)) OR lineage IN (SELECT id FROM consent_lineage WHERE member=?) OR co_lineage IN (SELECT id FROM consent_lineage WHERE member=?))`, JSON.stringify(machines), principal.memberId, principal.memberId).toArray()
    .filter((r) => can(state, principal, { type: "devices.read" }, { device: r.device }, now).allowed || can(state, principal, { type: "item.read" }, { credential: r.item_id }, now).allowed)
}
function personListed(rules: RuleRow[]): RuleRow[] {
  const ended = rules.filter((r) => r.ended_at !== null).sort((a, b) => b.ended_at! - a.ended_at! || (a.id < b.id ? -1 : 1))
  return [...rules.filter((r) => r.ended_at === null), ...ended.slice(0, POLICY_RULES_ENDED_LISTED)]
}

const ExtendInput = PolicyRuleExtendSchema.extend({ id: z.string().max(64) })
async function extendDecision(ctx: VaultContext, principal: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext) {
  rulesAvailable(ctx)
  const input = parseOpInput(ExtendInput, raw)
  const row = ruleRow(ctx, input.id)
  const state = eligibilityState(ctx, invocation)
  if (!row || !visibleRule(ctx, state, principal, row)) throw new VaultError("not_found", "No such object.")
  // A task grant is short by design: a new approval starts another.
  if (row.kind === "area") throw new VaultError("bad_request", "A task grant cannot be extended; approve the next request and start a new one.")
  const ask = ruleAsk(ctx, row)
  if (ruleSigner(state, principal, ask, ctx.now()) === null) throw new VaultError("forbidden", "Only the machine's owner can extend this rule.")
  const allowed = authorise(ctx, invocation, { type: "policy.rule.approve" }, { ask }, ctx.now())
  const expected = { type: "policy.decide" as const, proposal: row.id, digest: row.terms_digest, decision: "approve" as const, effectDigest: await policyRuleExtendDigest(row.id, input.ttlSeconds) }
  // The rule's terms with the new duration, under their own digest: a direct
  // extension writes them, a co-signed one shows them to its co-signer.
  const terms = { ...(JSON.parse(row.terms) as PolicyRuleTerms), ttlSeconds: input.ttlSeconds }
  return { input, allowed, expected, terms, termsDigest: await policyRuleTermsDigest(terms) }
}

// ---------------------------------------------------------------- ops

// include=grants: task grants as well as rules. Without it a list is as it
// was before grants, so a released mehen's strict parse never meets one.
const ListInput = z.strictObject({ item: z.string().max(64).optional(), device: z.string().max(64).optional(), include: z.literal("grants").optional() })
// Which kinds a list reads, as SQL on policy_rules: shape rules only, or
// task grants too.
type KindClause = "" | " AND kind IS NULL"
// A task grant does not exist for a mehen before AREA_GRANT_CLI or of
// unknown version: never listed, its id is not found, and Mehen-Rule never
// names it (relay-workspace.ts). A person's requests (the web) are not
// versioned.
export function readsGrants(principal: AccessPrincipal, invocation: WorkspaceInvocationContext): boolean {
  if (principal.kind !== "device") return true
  const version = invocation.auth.kind === "device" ? invocation.auth.cliVersion ?? null : null
  return version !== null && compareVersions(version, AREA_GRANT_CLI) >= 0
}
export const workspacePolicyRuleOps: NonNullable<import("../core.ts").Area["workspaceOps"]> = {
  "policy.rules": { auth: ["account", "device"], handler(ctx, principal, raw, invocation): (PolicyRuleView | PolicyAreaGrantView)[] {
    rulesAvailable(ctx)
    if (principal.kind === "system") throw new VaultError("not_found", "No such object.")
    const input = parseOpInput(ListInput, raw)
    const kinds: KindClause = input.include === "grants" && readsGrants(principal, invocation) ? "" : " AND kind IS NULL"
    let found: RuleRow[]
    if (principal.kind === "device") {
      if (input.device !== undefined && input.device !== principal.deviceId) throw new VaultError("not_found", "No such object.")
      authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
      found = ctx.sql.exec<RuleRow>(`SELECT * FROM policy_rules WHERE device=? AND workload IS ?${kinds}`, principal.deviceId, principal.workload ?? null).toArray().filter((r) => input.item === undefined || r.slug === input.item)
    } else if (principal.kind === "member") {
      if (input.item !== undefined && input.device !== undefined) throw new VaultError("bad_request", "Name item or device, not both.")
      if (input.item !== undefined) {
        const item = items.getItem(ctx, input.item)
        if (!item) throw new VaultError("not_found", "No such object.")
        authorise(ctx, invocation, { type: "item.read" }, { credential: item.id }, ctx.now())
        found = personRules(ctx, eligibilityState(ctx, invocation), principal, "item_id", item.id, kinds)
      } else if (input.device !== undefined) {
        authorise(ctx, invocation, { type: "devices.read" }, { device: input.device }, ctx.now())
        found = personRules(ctx, eligibilityState(ctx, invocation), principal, "device", input.device, kinds)
      } else {
        authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
        found = ownRules(ctx, eligibilityState(ctx, invocation), principal, kinds)
      }
    } else throw new VaultError("not_found", "No such object.")
    const state = eligibilityState(ctx, invocation), now = ctx.now()
    const settled = ctx.storage.transactionSync(() => found.filter((r) => visibleRule(ctx, state, principal, r)).map((r) => settleRule(ctx, accessState(ctx), r, now)))
    const own = principal.kind === "member" && input.item === undefined && input.device === undefined
    return (own ? settled.filter((r) => r.ended_at === null) : principal.kind === "member" ? personListed(settled) : settled)
      .sort((a, b) => (a.ended_at === null ? 0 : 1) - (b.ended_at === null ? 0 : 1) || b.created_at - a.created_at)
      .map((r) => listedView(ctx, state, r, principal))
  } },
  "policy.rules.revoke": { auth: ["account", "device"], handler(ctx, principal, raw, invocation): PolicyRuleView | PolicyAreaGrantView | PolicyRuleStopped | Pick<PolicyAreaGrantView, "id" | "status" | "endedReason"> {
    rulesAvailable(ctx)
    const { id } = parseOpInput(z.strictObject({ id: z.string().max(64) }), raw)
    if (principal.kind === "system") throw new VaultError("not_found", "No such object.")
    return ctx.storage.transactionSync(() => {
      const state = eligibilityState(ctx, invocation)
      const found = ruleRow(ctx, id)
      if (!found || found.kind === "area" && !readsGrants(principal, invocation) || !visibleRule(ctx, state, principal, found) && !mayRevoke(ctx, state, principal, found)) throw new VaultError("not_found", "No such object.")
      if (!mayRevoke(ctx, state, principal, found)) throw new VaultError("forbidden", "You are not allowed to do that.")
      let row = settleRule(ctx, accessState(ctx), found, ctx.now())
      if (row.ended_at === null) {
        const actor: RuleActor = principal.kind === "device" ? { kind: "device", device: principal.deviceId, workload: principal.workload ?? null } : { kind: "member", member: principal.memberId, session: invocation.auth.kind === "account" ? invocation.auth.session : null }
        row = endRule(ctx, accessState(ctx), row, "revoked", ctx.now(), actor)
      }
      return visibleRule(ctx, state, principal, row) ? listedView(ctx, state, row, principal) : { id: row.id, status: "ended", endedReason: row.ended_reason }
    })
  } },
  "policy.rules.extend-action": { auth: ["account"], async handler(ctx, principal, raw, invocation) {
    if (principal.kind !== "member") throw new VaultError("forbidden", "Only a person can extend a rule.")
    return (await extendDecision(ctx, principal, raw, invocation)).expected
  } },
  "policy.rules.extend": { auth: ["account"], async handler(ctx, principal, raw, invocation): Promise<PolicyRuleExtended> {
    if (principal.kind !== "member" || invocation.auth.kind !== "account") throw new VaultError("forbidden", "Only a person can extend a rule.")
    const { input, allowed, expected, terms, termsDigest } = await extendDecision(ctx, principal, raw, invocation)
    const session = invocation.auth.session
    return ctx.storage.transactionSync(() => {
      requireStepUp(ctx, allowed, expected, invocation)
      const state = eligibilityState(ctx, invocation), now = ctx.now()
      const found = ruleRow(ctx, input.id)
      if (!found) throw new VaultError("not_found", "No such object.")
      const row = settleRule(ctx, accessState(ctx), found, now)
      if (row.ended_at !== null) throw new VaultError("conflict", "This rule has ended; allow the request again to make a new one.")
      const ask = ruleAsk(ctx, row)
      const item = items.getItem(ctx, row.slug)
      if (!item) throw new VaultError("conflict", "The credential changed.")
      if (ruleSigner(state, principal, ask, now) === "direct") {
        const lineage = storeConsent(ctx, state, `${STANDING_CONSENT_PREFIX}${row.id}`, principal.memberId, ask, now + input.ttlSeconds * 1000, invocation)
        const expiresAt = Math.min(now + input.ttlSeconds * 1000, lineage.expiresAt)
        ctx.sql.exec("UPDATE policy_rules SET lineage=?,co_lineage=NULL,expires_at=?,terms=?,terms_digest=? WHERE id=?", lineage.id, expiresAt, canonicalJson(terms), termsDigest, row.id)
        sweepRuleAnchors(ctx)
        ruleAudit(ctx, state, row, { kind: "member", member: principal.memberId, session }, "rule.extend", "extended", { endsAt: iso(expiresAt) })
        return { rule: ruleView(ctx, state, ruleRow(ctx, row.id)!, principal), coSign: null }
      }
      const requester = `extend:${row.id}`
      if (one(ctx.sql.exec("SELECT 1 FROM policy_proposals WHERE requester=? AND status='pending' AND expires_at>?", requester, now))) throw new VaultError("conflict", "An extension of this rule already waits for a co-signer.")
      ctx.sql.exec("UPDATE policy_proposals SET status='expired' WHERE requester=? AND status='pending'", requester)
      const proposal = openRuleProposal(ctx, state, { asker: terms.asker, item, ask, terms, termsDigest, source: row.source, extends: row.id, reason: null, requestedBy: { member: principal.memberId, self: false }, requester, stage: "co-sign", approver: { member: principal.memberId, invocation } })
      copyRuleAnchor(ctx, row.id, proposal.id)
      if (!storedRequest(ctx, proposal.id)) throw new VaultError("conflict", "The vault no longer holds the request this rule was made from; allow the request again to make a new rule.")
      return { rule: ruleView(ctx, state, row, principal), coSign: { id: proposal.id, url: proposalUrl(ctx, invocation, proposal.id), bindingCode: proposal.code, expiresAt: iso(proposal.expires_at) } }
    })
  } },
  "policy.rules.preview": { auth: ["device"], async handler(ctx, principal, raw, invocation): Promise<PolicyRulePreview> {
    rulesAvailable(ctx)
    if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
    const input = parseOpInput(PolicyRuleProposalSchema, raw)
    let anchor: PolicyRuleAnchor, bound: RuleBinding
    try { ({ anchor, bound } = await proposalAnchor(ctx, principal, input, invocation)) } catch (error) {
      // A held request that can never become a rule previews as refused.
      const refusal = error instanceof VaultError ? error.extra.ruleRefused as PolicyRuleRefusal | undefined : undefined
      if (refusal) return { terms: null, pathChoices: [], summary: REFUSAL_WORDS[refusal], refused: refusal }
      throw error
    }
    const choices = policyRulePathChoices(anchor.destination.path)
    const ttlSeconds = input.ttlSeconds ?? RULE_DEFAULT_DURATION
    const pathChoices = choices.filter((path) => ruleTermsFrom(anchor, { path, ttlSeconds }).ok)
    const built = ruleTermsFrom(anchor, { path: input.path ?? pathChoices[0] ?? anchor.destination.path, ttlSeconds })
    if (!built.ok) return { terms: null, pathChoices, summary: REFUSAL_WORDS[built.reason], refused: built.reason }
    return { terms: built.terms, pathChoices, summary: ruleSummary(ctx, built.terms, bound), refused: null }
  } },
  "policy.rules.propose": { auth: ["device"], async handler(ctx, principal, raw, invocation): Promise<PolicyRuleProposalCreated & { reused?: true }> {
    rulesAvailable(ctx)
    if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
    if (isAreaBody(raw)) return readsGrants(principal, invocation) ? proposeAreaGrant(ctx, principal, raw, invocation) : areaBodyBeforeGrants(raw)
    const input = parseOpInput(PolicyRuleProposalSchema, raw)
    refuseGuestMachine(ctx, principal, "A guest's machine cannot ask for a rule; it asks for each request instead.")
    const { anchor, item, source, request, bound } = await proposalAnchor(ctx, principal, input, invocation)
    const built = ruleTermsFrom(anchor, { path: input.path ?? anchor.destination.path, ttlSeconds: input.ttlSeconds ?? RULE_DEFAULT_DURATION })
    if (!built.ok) throw refused(built.reason)
    const termsDigest = await policyRuleTermsDigest(built.terms)
    return openMachineProposal(ctx, principal, invocation, { item, terms: built.terms, termsDigest, source, bound, reason: input.reason, say: "Send this link to the machine's owner; only their passkey turns the rule on.", keep: (id) => storeRuleAnchor(ctx, principal, item, id, request) })
  } },
}

function refuseGuestMachine(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, message: string): void {
  const state = accessState(ctx), owner = state.devices.find((d) => d.id === principal.deviceId)?.owner
  if (owner?.kind === "member" && state.members.find((m) => m.id === owner.id)?.standing.effectiveRole === "guest") throw new VaultError("forbidden", message)
}

// A machine's proposal, rule or task grant: the same terms, reason and
// binding asked again answer the pending proposal; anything else while one
// waits for this key and credential is a conflict. keep stores the
// proposal's own copy of the request its terms were rebuilt from.
type MachineProposal = { item: ItemRecord; terms: PolicyRuleTerms | PolicyAreaGrantTerms; termsDigest: string; requestArea?: string; source: string | null; bound: RuleBinding; reason: string; say: string; keep: (proposal: string) => void }
function openMachineProposal(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, invocation: WorkspaceInvocationContext, input: MachineProposal): PolicyRuleProposalCreated & { reused?: true } {
  const { item, termsDigest, bound } = input
  const asker = askerOf(principal), requester = asker.workload ?? asker.device
  return ctx.storage.transactionSync(() => {
    const state = accessState(ctx), now = ctx.now()
    const created = (row: ProposalRow) => ({ ...proposalStatus(ctx, row), url: proposalUrl(ctx, invocation, row.id), next: { url: proposalUrl(ctx, invocation, row.id), ...(principal.workload === undefined ? { command: `mehen wait ${row.id}` } : {}), say: input.say } })
    const pending = one(ctx.sql.exec<ProposalRow>("SELECT * FROM policy_proposals WHERE requester=? AND item=? AND device=? AND status='pending' AND rule_terms IS NOT NULL", requester, item.id, asker.device))
    if (pending && pending.expires_at > now) {
      const same = (JSON.parse(pending.rule_terms) as ProposalTerms).termsDigest === termsDigest && pending.reason === input.reason && canonicalJson(askBinding(JSON.parse(pending.ask) as AccessAsk)) === canonicalJson(bound)
      if (same) return { ...created(pending), reused: true as const }
      throw new VaultError("conflict", `This key already has a pending proposal for this credential (${pending.id}); cancel it first.`)
    }
    if (pending) ctx.sql.exec("UPDATE policy_proposals SET status='expired' WHERE id=?", pending.id)
    assertRuleAskRoom(ctx, principal)
    const snapshot = approvedUseSnapshot(ctx, state, principal, checkedCredential(state, item), useContext(bound.context), now, bound.mode)
    if (!snapshot.ask) throw new VaultError("bad_request", "This credential needs an approval subject.")
    const name = devicePolicyState(ctx, asker.device)?.name ?? asker.device
    const row = openRuleProposal(ctx, state, { asker, item, ask: snapshot.ask, terms: input.terms, termsDigest, ...(input.requestArea !== undefined ? { requestArea: input.requestArea } : {}), source: input.source, extends: null, reason: input.reason, requestedBy: { device: asker.device, deviceName: name, session: null }, requester, stage: "approve", approver: null })
    input.keep(row.id)
    return created(row)
  })
}

// POST /v1/policy/proposals with a task grant (PolicyAreaProposalSchema),
// from mehen AREA_GRANT_CLI or later: a proposal the machine's owner
// decides with a passkey, its terms rebuilt from the held request the
// machine names, the key, the catalogue as it is now and the areas,
// duration and uses asked for. Never for a guest's machine or a protected
// credential; the floor, a request outside the catalogue and a live key
// refuse as an approval's area remember does.
async function proposeAreaGrant(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, raw: unknown, invocation: WorkspaceInvocationContext): Promise<PolicyRuleProposalCreated & { reused?: true }> {
  const input = parseOpInput(PolicyAreaProposalSchema, raw)
  refuseGuestMachine(ctx, principal, "A guest's machine cannot ask for a task grant; it asks for each request instead.")
  const { row, bound, refusal, held } = heldAnchor(ctx, principal, input.from.approval, invocation, "send the request again and propose from its new ask", input.area.item)
  if (projects.isProtectedItem(ctx, row.item)) throw new VaultError("environment_refused", "This credential backs a protected environment, so it asks every time.")
  if (held === null) throw areaRefused(refusal === null ? "area.terms" : heldAreaRefusal(row, refusal))
  const built = areaGrantTermsFrom(held.anchor, { areas: input.area.areas, ttlSeconds: input.area.ttlSeconds ?? AREA_GRANT_DEFAULT_DURATION, maxUses: input.area.maxUses ?? AREA_GRANT_USES.default })
  if (!built.ok) throw areaRefused(built.reason)
  const termsDigest = await policyAreaGrantTermsDigest(built.terms)
  return openMachineProposal(ctx, principal, invocation, { item: held.item, terms: built.terms, termsDigest, requestArea: built.requestArea, source: row.id, bound, reason: input.reason, say: "Send this link to the machine's owner; only their passkey lets the agent carry on.", keep: (id) => copyRuleAnchor(ctx, row.id, id) })
}
const isAreaBody = (raw: unknown): boolean => typeof raw === "object" && raw !== null && "area" in raw
// To a mehen before AREA_GRANT_CLI, or of unknown version, a task grant's
// body answers as it did before grants: a rule proposal's body with a key
// too many.
function areaBodyBeforeGrants(raw: unknown): never {
  try { parseOpInput(PolicyRuleProposalSchema, raw) } catch (error) {
    if (error instanceof VaultError) throw new VaultError(error.code, error.message, { next: policyHelpNext })
    throw error
  }
  throw new VaultError("bad_request", "Invalid request.", { next: policyHelpNext })
}

// The rule-proposal halves of the policy.* ops policy-workspace.ts serves.
export const ruleProposalOps = {
  async status(ctx: VaultContext, principal: AccessPrincipal, id: string, wait: boolean, invocation: WorkspaceInvocationContext): Promise<PolicyRuleProposalStatus | PolicyStandingProposalViewProjection> {
    rulesAvailable(ctx)
    if (principal.kind === "member") {
      authorise(ctx, invocation, { type: "asks.read" }, {}, ctx.now())
      const row = ruleProposalRow(ctx, id)
      if (!row) throw new VaultError("not_found", "No such object.")
      return ruleProposalProjection(ctx, eligibilityState(ctx, invocation), principal, row, invocation)
    }
    if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
    const check = () => {
      authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
      const row = ruleProposalRow(ctx, id)
      const ask = row ? JSON.parse(row.ask) as AccessAsk : null
      if (!row || !ask || row.device !== principal.deviceId || (ask.workload ?? null) !== (principal.workload ?? null) || row.requester.includes(":") || isAreaProposal(row) && !readsGrants(principal, invocation)) throw new VaultError("not_found", "No such object.")
      return row
    }
    let row = check()
    const deadline = ctx.now() + Math.min(25_000, Math.max(0, row.expires_at - ctx.now()))
    while (wait && proposalStatus(ctx, row).status === "pending" && ctx.now() < deadline) {
      await waitForStorageWrite(ctx.storage, deadline - ctx.now())
      row = check()
    }
    return proposalStatus(ctx, row)
  },
  cancel(ctx: VaultContext, principal: AccessPrincipal, id: string, invocation: WorkspaceInvocationContext): PolicyRuleProposalStatus {
    rulesAvailable(ctx)
    if (principal.kind !== "device") throw new VaultError("not_found", "No such object.")
    return ctx.storage.transactionSync(() => {
      authorise(ctx, invocation, { type: "asks.read" }, { device: principal.deviceId }, ctx.now())
      const row = ruleProposalRow(ctx, id)
      const ask = row ? JSON.parse(row.ask) as AccessAsk : null
      if (!row || !ask || row.device !== principal.deviceId || (ask.workload ?? null) !== (principal.workload ?? null) || row.requester.includes(":") || isAreaProposal(row) && !readsGrants(principal, invocation)) throw new VaultError("not_found", "No such object.")
      if (proposalStatus(ctx, row).status !== "pending") throw new VaultError("conflict", "This proposal is no longer pending.")
      ctx.sql.exec("UPDATE policy_proposals SET status='cancelled' WHERE id=?", row.id)
      ruleAudit(ctx, accessState(ctx), { id: row.id, item_id: row.item, slug: row.slug, device: row.device, workload: ask.workload ?? null }, { kind: "device", device: principal.deviceId, workload: principal.workload ?? null }, "policy.cancel", "cancelled", {})
      return proposalStatus(ctx, ruleProposalRow(ctx, row.id)!)
    })
  },
  async action(ctx: VaultContext, raw: unknown, invocation: WorkspaceInvocationContext) {
    rulesAvailable(ctx)
    const input = parseOpInput(RuleDecisionInput, raw)
    const row = ruleProposalRow(ctx, input.id)
    if (!row) throw new VaultError("not_found", "No such object.")
    return (await ruleDecision(ctx, row, input, invocation)).expected
  },
  async decide(ctx: VaultContext, principal: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<PolicyStandingProposalViewProjection> {
    rulesAvailable(ctx)
    const input = parseOpInput(RuleDecisionInput, raw)
    const row = ruleProposalRow(ctx, input.id)
    if (!row) throw new VaultError("not_found", "No such object.")
    decideRuleProposal(ctx, principal, row.id, await ruleDecision(ctx, row, input, invocation), invocation)
    return ruleProposalProjection(ctx, eligibilityState(ctx, invocation), principal, ruleProposalRow(ctx, row.id)!, invocation)
  },
}

// Open rule proposals in Needs you, and in a machine's own `mehen pending`
// (its agent proposals; a co-sign or extension waits for people only).
export function ruleProposalsPending(ctx: VaultContext, principal: AccessPrincipal, invocation: WorkspaceInvocationContext): WorkspacePendingAsk[] {
  if (!rulesOnHere(ctx)) return []
  const state = eligibilityState(ctx, invocation)
  return ctx.sql.exec<ProposalRow>("SELECT * FROM policy_proposals WHERE rule_terms IS NOT NULL AND status='pending' AND expires_at>?", ctx.now()).toArray().flatMap<WorkspacePendingAsk>((row) => {
    const status = proposalStatus(ctx, row)
    if (status.status !== "pending") return []
    const title = isAreaProposal(row) ? `Task grant: ${row.slug}` : `Allow from now on: ${row.slug}`, url = proposalUrl(ctx, invocation, row.id)
    if (principal.kind === "device") {
      const ask = JSON.parse(row.ask) as AccessAsk
      if (row.device !== principal.deviceId || (ask.workload ?? null) !== (principal.workload ?? null) || row.requester.includes(":") || isAreaProposal(row) && !readsGrants(principal, invocation)) return []
      return [{ view: "detail", workspace: invocation.workspace, owner: ownerRef(state, row.device), detail: { kind: "policy", id: row.id, title, url, expiresAt: status.expiresAt, requestedBy: JSON.parse(row.requested_by) as RequestedBy, item: row.slug, bindingCode: row.code } }]
    }
    let view: PolicyStandingProposalViewProjection
    try { view = ruleProposalProjection(ctx, state, principal, row, invocation) } catch (error) { if (error instanceof VaultError && error.code === "not_found") return []; throw error }
    if (view.view === "stop") return [{ view: "stop", workspace: view.workspace, owner: view.machine.owner, stop: view }]
    if (!view.proposal.canApprove && !view.proposal.canDeny) return []
    // A co-sign's page shows no code to tick, so its row names none; an
    // extension reads as one, of the rule it would move.
    const held = JSON.parse(row.rule_terms) as ProposalTerms
    const personTitle = held.extends !== null ? `Extend ${held.extends}: ${row.slug}` : row.stage === "co-sign" ? isAreaTerms(held.terms) ? `Co-sign: let an agent carry on: ${row.slug}` : `Co-sign: allow from now on: ${row.slug}` : title
    return [{ view: "detail", workspace: view.proposal.workspace, owner: view.proposal.owner, detail: { kind: "policy", id: row.id, title: personTitle, url, expiresAt: status.expiresAt, requestedBy: view.proposal.requestedBy, item: row.slug, ...(row.stage === "co-sign" ? {} : { bindingCode: row.code }), createdAt: iso(row.created_at) } }]
  })
}
