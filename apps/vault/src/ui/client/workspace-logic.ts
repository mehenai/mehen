// The browser's pure logic for workspace projects, credentials and asks:
// the bodies the pages send, the canonical step-up action each expects the
// vault to hand back, and the checks made before a passkey signs anything.
// The page signs only an action it rebuilt itself from what it showed; a
// server action that differs (someone changed the project, a name was
// reused, the workspace was renamed) is refused with nothing signed. No DOM
// here, so the tests run it in workerd beside the real routes.

import type { ApiError, ApprovalSubject, ApprovalView } from "@mehen/protocol/api"
import { parseDestination } from "@mehen/protocol/binding"
import { type ItemBrowser, fillOrigin } from "@mehen/protocol/fill"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { settingsPinnedVersion } from "@mehen/protocol/kinds"
import type { ApprovalBatchState, CredentialHome, EnvironmentState, ProjectLevel, ShareSubject, WorkspaceApprovalBinding, WorkspaceRef, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { type PolicyRememberRule, type PolicyRuleProposalStage, type PolicyRuleProposalView, type PolicyRuleTerms, PolicyRuleTermsSchema, RULE_DURATIONS, type RuleDuration } from "@mehen/protocol/policy-mode"
import { AREA_GRANT_DURATIONS, type PolicyAreaEffective, type PolicyAreaGrantTerms, PolicyAreaGrantTermsSchema, type PolicyAreaProposalView, type PolicyRememberArea } from "@mehen/protocol/policy-mode"
import { policyRuleTermsDigest, policyRuleTermsDigestMatches } from "@mehen/protocol/policy-rules"
import { policyAreaGrantTermsDigest } from "@mehen/protocol/policy-rules"
import { AREA_PROPOSAL_COSIGN_WORDS, AREA_PROPOSAL_DENIED_WORDS, areaProposalAllowedWords } from "../wording.ts"
import { AREA_AREAS_PROBLEM, AREA_COSIGN_ASKED_WORDS, AREA_DURATION_PROBLEM, AREA_TERMS_PROBLEM, AREA_USES_CHOICES, AREA_USES_PROBLEM, areaAllowedWords } from "../wording.ts"
import { normaliseRemote } from "@mehen/protocol/remote"
import { RULE_COSIGN_ASKED_WORDS, RULE_DURATION_PROBLEM, RULE_NOT_NAMED_WORDS, RULE_PATH_PROBLEM, RULE_PROPOSAL_COSIGN_WORDS, RULE_PROPOSAL_DENIED_WORDS, RULE_PROPOSAL_DURATION_PROBLEM, RULE_TERMS_PROBLEM, SHARE_END_DATE_PROBLEM, SHARE_END_PASSED_PROBLEM, SHARE_END_TOO_LATE_PROBLEM, SHARE_NO_LONGER_ENDS_WORDS, ruleAllowedWords, ruleProposalExtendedWords, shareEndsLaterWords } from "../wording.ts"
import { type Built, type IntakeSubmission, digestOf } from "./logic.ts"

export type ShareTerms = { level: ProjectLevel; protected: boolean; expiresAt: string | null }
export type VariableSource = { kind: "item"; item: string; field: string } | { kind: "plain"; value: string } | null

// A change: the body for /projects/action { change, input } and for the
// mutation route, and the action the vault must hand back.
export type ProjectChange = { change: "create" | "environment" | "variable" | "share" | "delete" | "remote"; input: Record<string, unknown>; path: string; expected: Promise<WorkspaceStepUpAction> | WorkspaceStepUpAction }

// ---------------------------------------------------------------- projects

export function environmentChange(project: string, env: string, before: EnvironmentState, after: EnvironmentState): ProjectChange {
  const input = { project, env, before, protected: after.protected, fences: after.fences, fourEyes: after.fourEyes }
  return {
    change: "environment",
    input,
    path: `/projects/${encodeURIComponent(project)}/environments/${encodeURIComponent(env)}`,
    expected: digestOf({ change: "environment.update", project, env, protected: after.protected, fences: after.fences, fourEyes: after.fourEyes }).then((digest) => ({ type: "item.update", item: project, digest })),
  }
}

// Unset by sending neither a credential nor a plain value.
export function variableChange(project: string, env: string, name: string, before: VariableSource, after: VariableSource): ProjectChange {
  const source = after === null ? {} : after.kind === "item" ? { item: after.item, ...(after.field !== "" ? { field: after.field } : {}) } : { plain: after.value }
  const input = { project, env, name, before, ...source }
  const item = after?.kind === "item" ? after.item : null
  const field = after?.kind === "item" && after.field !== "" ? after.field : null
  const plain = after?.kind === "plain" ? after.value : null
  return {
    change: "variable",
    input,
    path: `/projects/${encodeURIComponent(project)}/vars/${encodeURIComponent(name)}`,
    expected: digestOf({ change: "var.set", project, env, name, item, field, plain }).then((digest) => ({ type: "item.update", item: project, digest })),
  }
}

export function shareChange(project: string, subject: ShareSubject, before: ShareTerms | null, after: ShareTerms | null): ProjectChange {
  const input = { project, subject, before, after }
  return { change: "share", input, path: `/projects/${encodeURIComponent(project)}/shares`, expected: { type: "project.share", project, subject, before, after } }
}

// The share form's end is a UTC day, "" for no end. The share ends at that
// day's last millisecond in UTC, the zone the page shows every time in; the
// day of the share's current end keeps that end exactly, so a change of
// level alone signs the end the share already has. The vault refuses an end
// that has passed or is more than 365 days away, so the page does first.
const SHARE_MAX_MS = 365 * 86_400_000

export type ShareForm = { level: ProjectLevel; protected: boolean; ends: string }

export function shareEndDay(expiresAt: string | null): string {
  if (expiresAt === null) return ""
  const at = new Date(expiresAt)
  return Number.isNaN(at.getTime()) ? "" : at.toISOString().slice(0, 10)
}

export function shareFormTerms(current: ShareTerms | null, form: ShareForm, now: number): Built<ShareTerms> {
  const day = form.ends.trim()
  let expiresAt: string | null = null
  if (day !== "" && current !== null && current.expiresAt !== null && shareEndDay(current.expiresAt) === day) expiresAt = current.expiresAt
  else if (day !== "") {
    expiresAt = `${day}T23:59:59.999Z`
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || shareEndDay(expiresAt) !== day) return { ok: false, problems: [SHARE_END_DATE_PROBLEM] }
  }
  if (expiresAt !== null && Date.parse(expiresAt) <= now) return { ok: false, problems: [SHARE_END_PASSED_PROBLEM] }
  if (expiresAt !== null && Date.parse(expiresAt) > now + SHARE_MAX_MS) return { ok: false, problems: [SHARE_END_TOO_LATE_PROBLEM] }
  return { ok: true, value: { level: form.level, protected: form.level === "manage" || form.protected, expiresAt } }
}

// The line beside the share button when a change removes or moves later the
// end a share has; null when it keeps, shortens or adds one.
export function shareEndChangeWords(before: ShareTerms | null, after: ShareTerms): string | null {
  if (before === null || before.expiresAt === null) return null
  if (after.expiresAt === null) return SHARE_NO_LONGER_ENDS_WORDS
  return Date.parse(after.expiresAt) > Date.parse(before.expiresAt) ? shareEndsLaterWords(after.expiresAt) : null
}

// The repository exactly as the vault will store it, shown before the
// passkey; null when it is not a git remote.
export function remoteChange(project: string, raw: string, bound: boolean): ProjectChange | null {
  const remote = normaliseRemote(raw)
  if (remote === null) return null
  return {
    change: "remote",
    input: { project, remote, bound },
    path: `/projects/${encodeURIComponent(project)}/remotes`,
    expected: digestOf({ change: bound ? "remote.bind" : "remote.unbind", project, remote }).then((digest) => ({ type: "item.update", item: project, digest })),
  }
}

export type NewEnvironment = { name: string; protected: boolean; fourEyes: boolean }

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/

export function projectCreate(slug: string, rawRemote: string, environments: readonly NewEnvironment[], defaultEnv: string): Built<ProjectChange> {
  const problems: string[] = []
  if (!SLUG.test(slug)) problems.push("Name the project with lowercase letters, digits and dashes.")
  const remote = rawRemote.trim() === "" ? null : normaliseRemote(rawRemote.trim())
  if (rawRemote.trim() !== "" && remote === null) problems.push("That is not a git remote.")
  if (problems.length) return { ok: false, problems }
  const envs = environments.map((e) => ({ name: e.name, protected: e.protected, fourEyes: e.fourEyes }))
  const input = { slug, remote, defaultEnv, environments: envs }
  return { ok: true, value: { change: "create", input, path: "/projects", expected: { type: "project.create", slug, remote, environments: envs } } }
}

export function projectDelete(project: string): ProjectChange {
  return { change: "delete", input: { project }, path: `/projects/${encodeURIComponent(project)}/delete`, expected: { type: "project.delete", project } }
}

// ---------------------------------------------------------------- checks before signing

export const CHANGED_SINCE_SHOWN: ApiError = {
  error: "conflict",
  message: "What the vault would sign is not what this page shows: something changed since the page loaded.",
  next: { say: "Nothing was signed. Reload the page and review the change again." },
}

export function sameAction(expected: WorkspaceStepUpAction, received: unknown): boolean {
  return canonicalJson(expected) === canonicalJson(received)
}

// The workspace as the page showed it against the workspace now. A rename
// or a different workspace behind the same address refuses the signature.
export function identityRefusal(shown: WorkspaceRef, now: WorkspaceRef): ApiError | null {
  if (shown.id !== now.id) return { error: "conflict", message: "This address now belongs to a different workspace than the one this page showed.", next: { say: "Nothing was signed. Open the workspace again from your list." } }
  if (shown.slug !== now.slug || shown.name !== now.name) return { error: "conflict", message: `This workspace was renamed to ${now.name} (${now.slug}) since the page loaded.`, next: { say: "Nothing was signed. Reload the page to confirm under its current name." } }
  return null
}

// The credential as its page showed it: the stable id and revisions the
// vault's person-facing description carries. An action about any other
// credential, a replacement under the same name included, is refused.
export type ShownItem = { id: string; kind: string; version: number; configRevision: number; dependencyRevision: number }

export function itemDeleteAction(shown: Pick<ShownItem, "id">): WorkspaceStepUpAction {
  return { type: "item.delete", item: shown.id }
}

export function itemRehomeAction(shown: Pick<ShownItem, "id" | "dependencyRevision">, before: CredentialHome, after: CredentialHome): WorkspaceStepUpAction {
  return { type: "item.rehome", item: shown.id, before, after, dependencyRevision: shown.dependencyRevision }
}

// A restore signs the credential's id, the version shown and its kept
// previous version, so a rotation since, or another kept value, refuses.
export async function itemRestoreAction(shown: Pick<ShownItem, "id" | "version">, previous: number): Promise<WorkspaceStepUpAction> {
  return { type: "item.restore", item: shown.id, digest: await digestOf({ item: shown.id, version: shown.version, previous }) }
}

// The credential page's "In web pages" card: the ceiling's choice (relay or
// fill; only offered on those) and the pages a person added, as shown and
// as edited. A save sends only what changed, through item.update; the last
// pages removed is null, as the vault stores none.
export type WebPages = { ceiling: string; signinOrigins: string[]; typeInto: string[] }
export type WebPagesChange = { ceiling?: "relay" | "fill"; browser?: ItemBrowser | null }

export function webPagesChange(shown: WebPages, now: WebPages): WebPagesChange | null {
  const change: WebPagesChange = {}
  if (now.ceiling !== shown.ceiling && (now.ceiling === "relay" || now.ceiling === "fill")) change.ceiling = now.ceiling
  if (canonicalJson([now.signinOrigins, now.typeInto]) !== canonicalJson([shown.signinOrigins, shown.typeInto]))
    change.browser = now.signinOrigins.length === 0 && now.typeInto.length === 0 ? null : { signinOrigins: now.signinOrigins, typeInto: now.typeInto }
  return Object.keys(change).length > 0 ? change : null
}

// A page typed into the card, as the origin the vault keeps, or null where
// fill could never use it (not https, an IP address, a user name in it).
export function webPageOrigin(typed: string): string | null {
  return fillOrigin(typed.trim())
}

// item.update signs the change with the version (settingsPinnedVersion) and
// configuration shown.
export async function itemUpdateAction(shown: Pick<ShownItem, "id" | "kind" | "version" | "configRevision">, change: unknown): Promise<WorkspaceStepUpAction> {
  return { type: "item.update", item: shown.id, digest: await digestOf({ change, version: settingsPinnedVersion(shown.kind, shown.version), configRevision: shown.configRevision }) }
}

// The credential read again before a restore: the one shown, unchanged,
// still keeping the previous version shown.
export function itemRestoreRefusal(shown: ShownItem, previous: number, now: Partial<ShownItem> & { previous?: { version: number } | null }): ApiError | null {
  return itemChangedRefusal(shown, now) ?? (now.version === shown.version && now.previous?.version === previous ? null : CHANGED_SINCE_SHOWN)
}

// The credential read again before signing: refused once it is not the
// one shown, or has changed since (for an OAuth connection, a token renewal
// is not a change: settingsPinnedVersion).
export function itemChangedRefusal(shown: ShownItem, now: Partial<ShownItem>): ApiError | null {
  if (now.id !== shown.id) return { error: "conflict", message: "This name now belongs to a different credential than the one this page showed.", next: { say: "Nothing was signed. Reload the page to see the credential that has this name now." } }
  if (now.version === undefined || settingsPinnedVersion(shown.kind, now.version) !== settingsPinnedVersion(shown.kind, shown.version) || now.configRevision !== shown.configRevision || now.dependencyRevision !== shown.dependencyRevision) return CHANGED_SINCE_SHOWN
  return null
}

// The owner-and-admin purge by name: the vault's preparation names only a
// delete and the stable id, nothing else about the credential.
export function purgeMatches(received: unknown): boolean {
  if (typeof received !== "object" || received === null) return false
  const a = received as Record<string, unknown>
  return a.type === "item.delete" && typeof a.item === "string" && Object.keys(a).length === 2
}

// ---------------------------------------------------------------- personal overrides

export type OverrideSource = { kind: "plain"; value: string } | { kind: "item"; item: string; field: string } | null

// "Use my own": the body the override routes take. The page picks the
// credential by slug; the vault's action carries that credential's stable
// id (itm_) in its place, never a slug, and the page checks every other
// part exactly.
const STABLE_ITEM_ID = /^itm_[A-Za-z0-9_-]+$/

export function overrideChange(project: string, environment: string, variable: string, source: OverrideSource) {
  const body = { environment, variable, source }
  return {
    path: `/projects/${encodeURIComponent(project)}/overrides`,
    body,
    matches(received: unknown): boolean {
      if (typeof received !== "object" || received === null) return false
      const a = received as Record<string, unknown>
      if (Object.keys(a).length !== 5 || a.type !== "override.set" || a.project !== project || a.environment !== environment || a.variable !== variable) return false
      const got = a.source as Record<string, unknown> | null | undefined
      if (source === null) return got === null
      if (typeof got !== "object" || got === null || got.kind !== source.kind) return false
      if (Object.keys(got).length !== (source.kind === "plain" ? 2 : 3)) return false
      return source.kind === "plain" ? got.value === source.value : typeof got.item === "string" && STABLE_ITEM_ID.test(got.item) && got.field === source.field
    },
  }
}

// "Use my own" is offered only where the project has a row for exactly
// that variable in exactly that environment, and the environment is not
// protected: overrides never apply there.
export function overrideOffered(project: { environments: readonly { name: string; protected: boolean }[]; vars: readonly { env: string; name: string }[] }, environment: string, variable: string): boolean {
  const env = project.environments.find((e) => e.name === environment)
  return env !== undefined && !env.protected && project.vars.some((v) => v.env === environment && v.name === variable)
}

// ---------------------------------------------------------------- homes

// The radio values the pages use: "member", "workspace", "project:<id>".
export function homeFromValue(value: string, member: string): CredentialHome | null {
  if (value === "member") return { kind: "member", member }
  if (value === "workspace") return { kind: "workspace" }
  if (value.startsWith("project:") && value.length > "project:".length) return { kind: "project", project: value.slice("project:".length) }
  return null
}

// The create body's home words: private, project (with its id), workspace.
export function homeInput(home: CredentialHome): { home: "private" | "workspace" } | { home: "project"; project: string } {
  return home.kind === "project" ? { home: "project", project: home.project } : { home: home.kind === "member" ? "private" : "workspace" }
}

export type CredentialStartWay = "intake" | "connect" | "custom-host" | "lease"

// The body to start a credential by intake, custom host, lease-only kind or connection.
export function credentialStart(
  provider: string,
  way: CredentialStartWay,
  slug: string,
  home: CredentialHome,
  custom?: { host?: string; header?: string },
): { path: "/intakes" | "/connect"; body: Record<string, unknown> } {
  if (way === "connect") return { path: "/connect", body: { provider, slug, requestClient: true, ...homeInput(home) } }
  if (way === "lease") return { path: "/intakes", body: { kind: provider, slug, ...homeInput(home) } }
  if (way === "custom-host") {
    const host = (custom?.host ?? "").trim().toLowerCase()
    const header = (custom?.header ?? "").trim()
    return {
      path: "/intakes",
      body: {
        kind: provider,
        slug,
        binding: { hosts: [host], schemes: ["https"] },
        ...(header !== "" ? { injection: { in: "header", name: header, format: "{key}" } } : {}),
        ...homeInput(home),
      },
    }
  }
  return { path: "/intakes", body: { provider, slug, ...homeInput(home) } }
}

// Where a started credential is filled in: a connection that first needs
// its OAuth client goes to that client's intake, which leads on to it.
export function createdAskPath(slug: string, created: { intake?: string | { intake: string }; connect?: string }): string | null {
  const ws = `/w/${encodeURIComponent(slug)}`
  const intake = typeof created.intake === "string" ? created.intake : created.intake?.intake
  if (intake !== undefined) return `${ws}/i/${encodeURIComponent(intake)}`
  return created.connect !== undefined ? `${ws}/c/${encodeURIComponent(created.connect)}` : null
}

// A rotation asks for a new intake on the existing name, with no provider:
// the vault keeps every other part of the credential. A connection is
// renewed by connecting again under its name and provider instead, which
// the vault takes as a reconnect.
export function rotationStart(slug: string, home: CredentialHome, connectProvider: string | null = null): { path: "/intakes" | "/connect"; body: Record<string, unknown> } {
  if (connectProvider !== null) return { path: "/connect", body: { provider: connectProvider, slug, ...homeInput(home) } }
  return { path: "/intakes", body: { slug, ...homeInput(home) } }
}

// The uniform "name not available" refusal and its rate limit, in words.
export function nameRefusalWords(error: ApiError): string | null {
  if (error.error === "conflict" && error.message === "name not available") return "That name is not available. Choose another; for a credential only you use, try adding your own name, as in openai-alex."
  if (error.error === "rate_limited" && error.message === "Too many unavailable names; try again later.") return "Too many names were not available this hour. Try again later."
  return null
}

// An intake's submission with the home the filler chose; the passkey signs
// both, exactly as the vault rebuilds them.
export async function intakeWithHome(submission: IntakeSubmission, home: CredentialHome): Promise<{ body: IntakeSubmission & { home: CredentialHome }; digest: string }> {
  const body = { ...submission, home }
  return { body, digest: await digestOf({ ...body, tags: [...body.tags].sort() }) }
}

// ---------------------------------------------------------------- approvals

// The standing rule the vault offers beside the approval (rememberOptions.rule
// with refused null), as the page showed it.
export type ApprovalRuleOffer = { terms: PolicyRuleTerms; termsDigest: string; pathChoices: string[]; coSign: boolean }

// `area`: the task grant offered (ApprovalAreaOffer), when one is.
export type WorkspaceApprovalBoot = { approval: string; digest: string; subject: ApprovalSubject; binding: WorkspaceApprovalBinding | null; headers: readonly [string, string][] | null; rule?: ApprovalRuleOffer; area?: ApprovalAreaOffer }

// The approval's digest recomputed from its subject and binding; Approve
// is offered only when it equals the digest the vault stored.
export async function approvalBindingMatches(boot: WorkspaceApprovalBoot): Promise<boolean> {
  if (boot.binding === null) return false
  if (boot.headers !== null && (await digestOf(boot.headers)) !== boot.subject.headersSha256) return false
  return (await digestOf({ subject: boot.subject, snapshotDigest: boot.binding.snapshotDigest, presentationDigest: boot.binding.presentationDigest })) === boot.digest
}

export type Constraints = ApprovalSubject["constraints"]

// What the approver chose, never more than the agent asked for.
export function chosenConstraints(asked: Constraints, uses: string, ttl: string): Built<Constraints> {
  const ttlSeconds = Number(ttl)
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > asked.ttlSeconds) return { ok: false, problems: ["Choose a time no longer than the agent asked for."] }
  if (uses === "unlimited") return asked.uses === null ? { ok: true, value: { uses: null, ttlSeconds } } : { ok: false, problems: ["Choose no more uses than the agent asked for."] }
  const n = Number(uses)
  if (!Number.isInteger(n) || n < 1 || (asked.uses !== null && n > asked.uses)) return { ok: false, problems: ["Choose no more uses than the agent asked for."] }
  return { ok: true, value: { uses: n, ttlSeconds } }
}

// `remember` rides only on an approval, inside the same signed action.
export function approvalDecision(boot: Pick<WorkspaceApprovalBoot, "approval" | "digest" | "subject">, decision: "approve" | "deny", constraints: Constraints, remember?: PolicyRememberRule | PolicyRememberArea): { body: { decision: "approve" | "deny"; constraints: Constraints; remember?: PolicyRememberRule | PolicyRememberArea }; expected: WorkspaceStepUpAction } {
  const signed = decision === "deny" ? boot.subject.constraints : constraints
  const rule = decision === "approve" && remember !== undefined ? { remember } : {}
  return { body: { decision, constraints: signed, ...rule }, expected: { type: "approval.decide", approval: boot.approval, digest: boot.digest, decision, constraints: signed, ...rule } }
}

// The offer's own terms hash to the digest the vault sent with them, so the
// panel shows the terms the vault rebuilds, and they are this approval's
// request: its credential, method, host and path, as the page's own digest
// check holds the subject to the vault's. The allowing action is offered
// only then.
export async function ruleOfferMatches(offer: ApprovalRuleOffer, subject: ApprovalSubject): Promise<boolean> {
  if (!PolicyRuleTermsSchema.safeParse(offer.terms).success || !offer.pathChoices.includes(offer.terms.path)) return false
  const asked = parseDestination(subject.method, subject.url)
  if (!asked.ok || offer.terms.item !== subject.item || offer.terms.method !== subject.method || offer.terms.host !== asked.destination.host || offer.terms.anchorPath !== asked.destination.path) return false
  return policyRuleTermsDigestMatches(offer.terms, offer.termsDigest)
}

// The remember the passkey signs for the path and duration chosen: the
// offer's terms with them, and those terms' digest, which the vault
// recomputes from the stored request before it makes the rule.
export async function rememberRule(offer: ApprovalRuleOffer, path: string, ttl: string): Promise<Built<PolicyRememberRule>> {
  const ttlSeconds = Number(ttl)
  if (!offer.pathChoices.includes(path)) return { ok: false, problems: [RULE_PATH_PROBLEM] }
  if (!(RULE_DURATIONS as readonly number[]).includes(ttlSeconds)) return { ok: false, problems: [RULE_DURATION_PROBLEM] }
  const terms = PolicyRuleTermsSchema.safeParse({ ...offer.terms, path, ttlSeconds })
  if (!terms.success) return { ok: false, problems: [RULE_TERMS_PROBLEM] }
  return { ok: true, value: { kind: "rule", path, ttlSeconds: terms.data.ttlSeconds, termsDigest: await policyRuleTermsDigest(terms.data) } }
}

// What approving with a rule did, in words, from the vault's answer to the
// decide (the approval as it now stands), never from what the page chose:
// the rule and its end when the vault names one, the co-sign proposal when
// a manager of the credential's home must allow it, and no "Allowed"
// otherwise. null when the answer is not an approved approval, so the page
// shows the approval as the vault reads it.
export function ruleOutcomeWords(answer: unknown): string | null {
  const approval = typeof answer === "object" && answer !== null && (answer as { view?: unknown }).view === "detail" ? (answer as { approval?: unknown }).approval : null
  if (typeof approval !== "object" || approval === null) return null
  const { status, rule, ruleProposal } = approval as Partial<Pick<ApprovalView, "status" | "rule" | "ruleProposal">>
  if (status !== "approved") return null
  const endsAt = rule ? Date.parse(rule.endsAt) : Number.NaN
  if (!Number.isNaN(endsAt)) return ruleAllowedWords(endsAt)
  if (ruleProposal) return RULE_COSIGN_ASKED_WORDS
  return RULE_NOT_NAMED_WORDS
}

// ---------------------------------------------------------------- rule proposals

// The rule proposal page (/w/<slug>/p/<pol_id>) as it showed the proposal:
// the credential it names, the terms as the vault rebuilt them, their
// digest, the paths it offers, and what the proposal's digest commits to
// (its stage, the rule an extension would move and the agent's reason).
export type RuleProposalBoot = { proposal: string; item: string; digest: string; stage: PolicyRuleProposalStage; extends: string | null; reason: string | null; terms: PolicyRuleTerms; termsDigest: string; pathChoices: string[] }

// The paths a decision may narrow to, narrowest first: the vault's choices
// that are the proposed path or the anchor's own, never a wider one.
export function ruleProposalPaths(terms: PolicyRuleTerms, pathChoices: readonly string[]): string[] {
  return [...new Set(pathChoices.filter((p) => p === terms.anchorPath || p === terms.path))].sort((a, b) => (a === terms.anchorPath ? -1 : b === terms.anchorPath ? 1 : 0))
}

// The durations a decision may choose: 1, 7 or 30 days, never longer than proposed.
export function ruleProposalDurations(terms: PolicyRuleTerms): number[] {
  return RULE_DURATIONS.filter((s) => s <= terms.ttlSeconds)
}

// The digest the vault stores for a rule proposal, rebuilt from what the
// page shows: its id, stage, terms digest, the rule it would extend and the
// agent's reason (none is the empty reason).
export function ruleProposalDigest(boot: Pick<RuleProposalBoot, "proposal" | "stage" | "termsDigest" | "extends" | "reason">): Promise<string> {
  return digestOf({ domain: "mehen-policy-rule-proposal/v1", proposal: boot.proposal, stage: boot.stage, termsDigest: boot.termsDigest, extends: boot.extends, reason: boot.reason ?? "" })
}

// The page's terms hash to the vault's terms digest and, with the stage,
// the extension and the reason it shows, to the proposal's digest, and the
// credential the page names is the one the terms name: Approve is offered
// only then.
export async function ruleProposalMatches(boot: RuleProposalBoot): Promise<boolean> {
  if (boot.item !== boot.terms.item || !PolicyRuleTermsSchema.safeParse(boot.terms).success || !boot.pathChoices.includes(boot.terms.path)) return false
  if (!(await policyRuleTermsDigestMatches(boot.terms, boot.termsDigest))) return false
  return (await ruleProposalDigest(boot)) === boot.digest
}

export type RuleProposalEffect = { effective: { path: string; ttlSeconds: RuleDuration }; effectDigest: string }

// The decision's effect for the path and duration chosen: within what was
// proposed, and the digest of the terms with them, which the vault
// rebuilds from the stored request before it signs off.
export async function ruleProposalEffect(boot: RuleProposalBoot, path: string, ttl: string): Promise<Built<RuleProposalEffect>> {
  const ttlSeconds = Number(ttl)
  if (!ruleProposalPaths(boot.terms, boot.pathChoices).includes(path)) return { ok: false, problems: [RULE_PATH_PROBLEM] }
  if (!ruleProposalDurations(boot.terms).includes(ttlSeconds) || (boot.extends !== null && ttlSeconds !== boot.terms.ttlSeconds)) return { ok: false, problems: [RULE_PROPOSAL_DURATION_PROBLEM] }
  const terms = PolicyRuleTermsSchema.safeParse({ ...boot.terms, path, ttlSeconds })
  if (!terms.success) return { ok: false, problems: [RULE_TERMS_PROBLEM] }
  return { ok: true, value: { effective: { path, ttlSeconds: terms.data.ttlSeconds }, effectDigest: await policyRuleTermsDigest(terms.data) } }
}

// The body for the proposal's /action and /decide, and the policy.decide
// the vault must hand back: approve names the effect, deny names none.
export function ruleProposalDecision(boot: Pick<RuleProposalBoot, "proposal" | "digest">, decision: "approve" | "deny", effect: RuleProposalEffect | null): { body: { decision: "approve"; effective: RuleProposalEffect["effective"] } | { decision: "deny" }; expected: WorkspaceStepUpAction } {
  if (decision === "approve" && effect !== null) return { body: { decision, effective: effect.effective }, expected: { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision, effectDigest: effect.effectDigest } }
  return { body: { decision: "deny" }, expected: { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision: "deny", effectDigest: null } }
}

// What deciding a rule proposal did, in words, from the vault's answer
// (the proposal as it now stands), never from what the page chose: the
// rule and its end, the co-sign it now waits for (only when this page
// moved this proposal there from approve), or the denial. null when the
// answer says none of these, so the page shows the proposal as the vault
// reads it.
export function ruleProposalOutcomeWords(answer: unknown, boot: Pick<RuleProposalBoot, "proposal" | "stage">): string | null {
  const proposal = typeof answer === "object" && answer !== null && (answer as { view?: unknown }).view === "detail" ? (answer as { proposal?: unknown }).proposal : null
  if (typeof proposal !== "object" || proposal === null) return null
  const { proposal: id, status, stage, rule, extends: extended } = proposal as Partial<Pick<PolicyRuleProposalView, "proposal" | "status" | "stage" | "rule" | "extends">>
  if (status === "denied") return RULE_PROPOSAL_DENIED_WORDS
  if (status === "pending" && stage === "co-sign") return boot.stage === "approve" && id === boot.proposal ? RULE_PROPOSAL_COSIGN_WORDS : null
  const endsAt = status === "approved" && rule ? Date.parse(rule.endsAt) : Number.NaN
  if (Number.isNaN(endsAt) || !rule) return null
  return typeof extended === "string" ? ruleProposalExtendedWords(rule.id, endsAt) : ruleAllowedWords(endsAt)
}

// ---------------------------------------------------------------- task grants on the approval page

// The task grant the vault offers beside the approval (rememberOptions.area
// with refused null), as the page showed it: the terms with the request's
// own area and the defaults, their digest, every area the person may tick
// and whether a manager of the credential's home must co-sign.
export type ApprovalAreaOffer = { terms: PolicyAreaGrantTerms; termsDigest: string; areas: { id: string; name: string; words: string; requestArea: boolean }[]; coSign: boolean }

// The offer's terms hash to the digest the vault sent with them, name this
// approval's credential and host, and tick the request's own area, which
// the page's list holds: the third button is offered only then.
export async function areaOfferMatches(offer: ApprovalAreaOffer, subject: ApprovalSubject): Promise<boolean> {
  if (!PolicyAreaGrantTermsSchema.safeParse(offer.terms).success) return false
  const asked = parseDestination(subject.method, subject.url)
  if (!asked.ok || offer.terms.item !== subject.item || offer.terms.host !== asked.destination.host) return false
  const own = offer.areas.filter((a) => a.requestArea)
  if (own.length !== 1 || canonicalJson(offer.terms.areas) !== canonicalJson([own[0]!.id])) return false
  return (await policyAreaGrantTermsDigest(offer.terms)) === offer.termsDigest
}

// The remember the passkey signs for the areas, duration and uses chosen:
// the offer's terms with them, and those terms' digest, which the vault
// recomputes from the stored request before it makes the grant.
export async function rememberArea(offer: ApprovalAreaOffer, areas: readonly string[], ttl: string, uses: string): Promise<Built<PolicyRememberArea>> {
  const ttlSeconds = Number(ttl), maxUses = Number(uses)
  const chosen = [...new Set(areas)].sort()
  if (chosen.length === 0 || !chosen.every((a) => offer.areas.some((o) => o.id === a))) return { ok: false, problems: [AREA_AREAS_PROBLEM] }
  if (!(AREA_GRANT_DURATIONS as readonly number[]).includes(ttlSeconds)) return { ok: false, problems: [AREA_DURATION_PROBLEM] }
  if (!(AREA_USES_CHOICES as readonly number[]).includes(maxUses)) return { ok: false, problems: [AREA_USES_PROBLEM] }
  const terms = PolicyAreaGrantTermsSchema.safeParse({ ...offer.terms, areas: chosen, ttlSeconds, maxUses })
  if (!terms.success) return { ok: false, problems: [AREA_TERMS_PROBLEM] }
  return { ok: true, value: { kind: "area", areas: terms.data.areas, ttlSeconds: terms.data.ttlSeconds, maxUses: terms.data.maxUses, termsDigest: await policyAreaGrantTermsDigest(terms.data) } }
}

// What approving with a task grant did, in words, from the vault's answer
// to the decide: the co-sign it waits for when the vault names one, and
// otherwise, once approved, the grant the passkey signed, which the vault
// made in the approval's own transaction. null when the answer is not an
// approved approval, so the page shows the approval as the vault reads it.
export function areaOutcomeWords(answer: unknown, signed: { ttlSeconds: number; maxUses: number }): string | null {
  const approval = typeof answer === "object" && answer !== null && (answer as { view?: unknown }).view === "detail" ? (answer as { approval?: unknown }).approval : null
  if (typeof approval !== "object" || approval === null) return null
  const { status, ruleProposal } = approval as Partial<Pick<ApprovalView, "status" | "ruleProposal">>
  if (status !== "approved") return null
  return ruleProposal ? AREA_COSIGN_ASKED_WORDS : areaAllowedWords(signed.ttlSeconds, signed.maxUses)
}

// ---------------------------------------------------------------- task grant proposals

// The task grant proposal page (/w/<slug>/p/<pol_id>) as it showed the
// proposal: the terms as the vault rebuilt them, read only, their digest,
// the proposal's digest and stage, and the credential it names.
export type AreaProposalBoot = { proposal: string; item: string; digest: string; stage: PolicyRuleProposalStage; reason: string | null; terms: PolicyAreaGrantTerms; termsDigest: string }

// The page's terms hash to the vault's terms digest and, with the stage and
// the reason, to the proposal's digest (a task grant extends nothing), and
// name the credential the page names: Approve is offered only then.
export async function areaProposalMatches(boot: AreaProposalBoot): Promise<boolean> {
  if (boot.item !== boot.terms.item || !PolicyAreaGrantTermsSchema.safeParse(boot.terms).success) return false
  if ((await policyAreaGrantTermsDigest(boot.terms)) !== boot.termsDigest) return false
  return (await ruleProposalDigest({ ...boot, extends: null })) === boot.digest
}

// The body for the proposal's /action and /decide, and the policy.decide
// the passkey signs: approving keeps the areas, duration and uses as
// signed, and signs the digest of those terms, which the vault rebuilds
// from the stored request before it makes the grant.
export async function areaProposalDecision(boot: Pick<AreaProposalBoot, "proposal" | "digest" | "terms">, decision: "approve" | "deny"): Promise<{ body: { decision: "approve"; effective: PolicyAreaEffective } | { decision: "deny" }; expected: WorkspaceStepUpAction }> {
  if (decision === "deny") return { body: { decision }, expected: { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision, effectDigest: null } }
  const effective: PolicyAreaEffective = { areas: boot.terms.areas, ttlSeconds: boot.terms.ttlSeconds, maxUses: boot.terms.maxUses }
  return { body: { decision, effective }, expected: { type: "policy.decide", proposal: boot.proposal, digest: boot.digest, decision, effectDigest: await policyAreaGrantTermsDigest({ ...boot.terms, ...effective }) } }
}

// What deciding a task grant proposal did, in words, from the vault's
// answer, never from what the page chose: the grant, its end and its uses,
// or the denial. null otherwise, so the page shows the proposal as the
// vault reads it.
export function areaProposalOutcomeWords(answer: unknown, boot: Pick<AreaProposalBoot, "proposal" | "stage">): string | null {
  const proposal = typeof answer === "object" && answer !== null && (answer as { view?: unknown }).view === "detail" ? (answer as { proposal?: unknown }).proposal : null
  if (typeof proposal !== "object" || proposal === null) return null
  const { proposal: id, status, stage, rule, terms } = proposal as Partial<Pick<PolicyAreaProposalView, "proposal" | "status" | "stage" | "rule" | "terms">>
  if (status === "denied") return AREA_PROPOSAL_DENIED_WORDS
  if (status === "pending" && stage === "co-sign") return boot.stage === "approve" && id === boot.proposal ? AREA_PROPOSAL_COSIGN_WORDS : null
  const endsAt = status === "approved" && rule ? Date.parse(rule.endsAt) : Number.NaN
  if (Number.isNaN(endsAt) || typeof terms?.maxUses !== "number") return null
  return areaProposalAllowedWords(endsAt, terms.maxUses)
}

// ---------------------------------------------------------------- Review together

// One row of Review together as its page showed it, from its boot data: a
// detail row with what its digest recomputes from, or a stop row, which
// may only be denied. section: where the page listed it (routine, floor,
// deny-only or own-page); only a pending row is ever in a batch. newer: a
// newer pending ask of the same shape follows the row (A2's newerSameShape).
export type ReviewRowBoot =
  | { approval: string; view: "detail"; section: ApprovalBatchState; pending: boolean; newer: boolean; digest: string; subject: ApprovalSubject; binding: WorkspaceApprovalBinding; headers: readonly [string, string][] | null }
  | { approval: string; view: "stop"; section: "deny-only" | "own-page"; pending: boolean }
export type ReviewChoice = { approval: string; decision: "approve" | "deny" }

// A pending row that may be approved in a batch, and one that may be denied
// in one: never a row decided on its own page.
export function reviewMayApprove(row: ReviewRowBoot): row is Extract<ReviewRowBoot, { view: "detail" }> {
  return row.pending && row.view === "detail" && (row.section === "routine" || row.section === "floor")
}
export function reviewMayDeny(row: ReviewRowBoot): boolean {
  return row.pending && row.section !== "own-page"
}

// What the bar's actions decide, from the ticked rows: Approve the ticked
// rows that may be approved (a ticked deny-only row is left for Deny
// ticked), Deny every ticked row that may be denied; each once, sorted by
// approval id, as approval.decide_many signs them.
export function reviewChoices(rows: readonly ReviewRowBoot[], ticked: ReadonlySet<string>, decision: "approve" | "deny"): ReviewChoice[] {
  const chosen = rows.filter((row) => ticked.has(row.approval) && (decision === "approve" ? reviewMayApprove(row) : reviewMayDeny(row)))
  return [...new Set(chosen.map((row) => row.approval))].sort().map((approval) => ({ approval, decision }))
}

// The body for /approval-batch/action and /approval-batch/decide.
export function reviewBatchBody(choices: readonly ReviewChoice[]): { entries: { id: string; decision: "approve" | "deny" }[] } {
  return { entries: choices.map((c) => ({ id: c.approval, decision: c.decision })) }
}

// The vault's approval.decide_many against the rows the page showed: one
// entry per choice, in the same sorted order, each with its decision, and
// for a detail row the stored digest and the terms the agent asked for,
// exactly as that row's own page signs them. A stop row shows no request,
// so its entry may only deny it, whatever digest the vault stored.
export function reviewBatchMatches(rows: readonly ReviewRowBoot[], choices: readonly ReviewChoice[], received: unknown): boolean {
  if (typeof received !== "object" || received === null) return false
  const action = received as { type?: unknown; entries?: unknown }
  if (action.type !== "approval.decide_many" || !Array.isArray(action.entries) || Object.keys(action).length !== 2 || action.entries.length !== choices.length) return false
  return choices.every((choice, i) => {
    const entry = action.entries as unknown[]
    const got = entry[i] as Record<string, unknown> | null
    const row = rows.find((r) => r.approval === choice.approval)
    if (typeof got !== "object" || got === null || row === undefined || got.approval !== choice.approval || got.decision !== choice.decision) return false
    if (row.view === "stop") return choice.decision === "deny" && typeof got.digest === "string"
    return canonicalJson(got) === canonicalJson({ approval: row.approval, digest: row.digest, decision: choice.decision, uses: row.subject.constraints.uses, ttlSeconds: row.subject.constraints.ttlSeconds })
  })
}

// The detail rows whose shown request does not recompute to the digest the
// vault stored, by approval id: none of them may be approved here.
export async function reviewBindingMismatches(rows: readonly ReviewRowBoot[]): Promise<string[]> {
  const out: string[] = []
  for (const row of rows) if (row.view === "detail" && !(await approvalBindingMatches(row))) out.push(row.approval)
  return out
}
