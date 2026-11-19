import { type Me, type NextStep, POSTURE_HEADER, RULE_HEADER } from "@mehen/protocol/api"
import { AREA_GRANT_DURATIONS, AREA_GRANT_USES, type AreaGrantDuration, POLICY_RULE_METHODS, type PolicyAreaProposal, PolicyAreaProposalSchema, type PolicyChange, PolicyChangeSchema, type PolicyContext, PolicyGrantIdSchema, type PolicyPreview, PolicyPreviewRequestSchema, type PolicyPropose, PolicyProposeSchema, PolicyProposalIdSchema, type PolicyProposalStatus, PolicyProposalStatusSchema, PolicyRouteScopeSchema, type PolicyRuleContext, type PolicyRulePreview, PolicyRuleIdSchema, type PolicyRuleList, type PolicyRuleProposal, PolicyRuleProposalSchema, type PolicyRuleProposalRef, type PolicyRuleRefusal, type PolicyRuleRef, type PolicyRuleView, PolicySlugSchema, type PolicyState, type PolicyStopped, PolicyWindowIdSchema, RULE_DURATIONS, type RuleDuration, policyLifetime } from "@mehen/protocol/policy-mode"
import { policyScopeEligibility } from "@mehen/protocol/policy-safety"
import { z } from "zod"
import { type Ask, type AskUrl, type AskVault, askSay, clockText, askUrl, askUrlFor, policyAsk, refusedLinkWarning, withContext } from "./ask.ts"
import { type Env, configWorkspace } from "./config.ts"
import { AreaRefusalSchema, type GrantView, RuleProposalRefSchema, type RuleOrGrantList, type RuleProposalStatus, RuleRefSchema, RuleRefusalSchema, isGrant, ruleOrGrantListSchema, rulePreviewSchema, checkedContext, checkedWidening, createdResponse, previewSchema, response, ruleListSchema, ruleViewSchema, ruleProposalCreated, ruleProposalStatusSchema, stateSchema, stoppedSchema, timestamp } from "./policy-responses.ts"
import { CliError, toCliError, usageError } from "./errors.ts"
import { type LedgerScope, removeLedgerEntry } from "./ledger.ts"
import { fetchContext, parseDurationSeconds, settle, showItem } from "./operations.ts"
import { VaultApiError } from "./vault-api.ts"
import { recordAsk } from "./commands/intake.ts"
import { type VaultSession, sessionLabel } from "./session.ts"

// What the policy operations need of a session: the vault's test fixture
// port (policy-fixture-port.ts) builds this shape without a key on disk.
export type PolicySession = Pick<VaultSession, "api" | "vaultUrl" | "configDir"> & { config: Pick<VaultSession["config"], "vault" | "tenant" | "device" | "backend"> & Partial<Pick<VaultSession["config"], "workspaceSlug" | "workspaceName" | "owner">> }

function ledgerScope(session: PolicySession): LedgerScope {
  return { vaultUrl: session.vaultUrl, workspace: session.config.tenant, device: session.config.device, workspaceSlug: session.config.workspaceSlug ?? null }
}
import type { VaultApi } from "./vault-api.ts"

const HELP = "mehen policy propose --help"
export function policyInput<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value)
  if (!parsed.success) throw usageError("Invalid policy input. Use one finite item and device scope with the documented fields.", HELP)
  return parsed.data
}

export function policyCapabilities(me: Me): Me["capabilities"] {
  const flags = (me as { capabilities?: Partial<Me["capabilities"]> }).capabilities
  return { environmentV2: flags?.environmentV2 === true, runBaseUrl: flags?.runBaseUrl === true, runFiles: flags?.runFiles === true, sealedEnvImport: flags?.sealedEnvImport === true, policyV1: flags?.policyV1 === true }
}

export async function readPolicyState(api: VaultApi, vaultUrl: string, me: Me): Promise<PolicyState | null> {
  if (!policyCapabilities(me).policyV1) return null
  try {
    const state = response(stateSchema, await api.request<unknown>("GET", "/v1/policy/state"))
    for (const row of state.widening) checkedWidening(row, vaultUrl)
    return state
  } catch {
    return null
  }
}

export async function showPolicy(session: PolicySession, item: string): Promise<PolicyContext> {
  policyInput(PolicySlugSchema, item)
  const context = checkedContext(await session.api.request<unknown>("GET", `/v1/policy/context?item=${encodeURIComponent(item)}`), session.vaultUrl)
  if (context.item !== item || context.selector.device !== session.config.device) throw new CliError("internal", "The policy context does not match this item and device.")
  return context
}

function ownSelector(change: PolicyChange, session: PolicySession, env: Env): void {
  if (change.selector.device !== session.config.device || change.selector.session !== null && change.selector.session !== sessionLabel(env)) {
    throw usageError("A policy change must select this enrolled device and its current MEHEN_SESSION, or explicitly select a null device-wide session.", HELP)
  }
}

export async function previewPolicy(session: PolicySession, value: unknown, env: Env): Promise<PolicyPreview> {
  const input = policyInput(PolicyPreviewRequestSchema, value)
  ownSelector(input.change, session, env)
  const preview = response(previewSchema, await session.api.request<unknown>("POST", "/v1/policy/preview", input))
  checkedContext(preview.context, session.vaultUrl)
  if (JSON.stringify(preview.change) !== JSON.stringify(input.change) || preview.reason !== input.reason) throw new CliError("conflict", "The preview changed the proposed scope. Read the policy again before proposing.", { command: `mehen policy show ${input.change.target.item}`, say: "The policy or active window changed. Read it again before proposing a change." })
  return preview
}

export type PolicyProposalResult = PolicyProposalStatus & { url: AskUrl | null; ask: Ask | null; next: NextStep | null; warning: string | null }

export async function proposePolicy(session: PolicySession, value: unknown, env: Env): Promise<PolicyProposalResult> {
  const input = policyInput(PolicyProposeSchema, value)
  ownSelector(input.change, session, env)
  const me = await session.api.request<Me>("GET", "/v1/me")
  const raw = await session.api.request<unknown>("POST", "/v1/policy/proposals", input)
  const created = createdResponse(raw)
  if (created.item !== input.change.target.item) throw new CliError("internal", "The proposal does not match the requested item.")
  if (created.status !== "pending") {
    await removeLedgerEntry(session.configDir, ledgerScope(session), created.proposal)
    settle("policy", created.proposal, created)
    return { ...created, ask: null, next: null, warning: null, url: null }
  }
  const scope = ledgerScope(session)
  const given = askUrl((raw as { url?: unknown }).url, scope)
  const matching = given?.route?.prefix === "p" && given.route.id === created.proposal ? given : null
  const link = matching ?? askUrlFor(scope, "policy", created.proposal)
  if (!link) throw new CliError("internal", "The vault returned no usable policy proposal link.")
  const warning = matching ? null : refusedLinkWarning(session.vaultUrl)
  const ask = withContext(policyAsk({ id: created.proposal, url: link.url, summary: `${created.summary}. No access has changed yet.`, bindingCode: created.bindingCode, expiresAt: created.expiresAt, requestedBy: { device: me.name, session: sessionLabel(env) } }), { origin: session.vaultUrl, workspace: configWorkspace(session.config), device: session.config.device })
  const next = { url: ask.url, command: `mehen wait ${ask.id}`, say: `Review this policy change in the vault and check the code ${created.bindingCode}. No access has changed yet.` }
  await recordAsk(session.configDir, ledgerScope(session), ask, created.item, `mehen policy show ${created.item}`, new Date())
  return { ...created, url: link.url, ask, next, warning }
}

export async function cancelPolicy(session: PolicySession, id: string): Promise<RuleProposalStatus> {
  policyInput(PolicyProposalIdSchema, id)
  const status = response(ruleProposalStatusSchema, await ruleCall(() => session.api.request<unknown>("POST", `/v1/policy/proposals/${id}/cancel`, {})))
  if (status.proposal !== id) throw new CliError("internal", "The cancelled proposal id does not match.")
  if (status.status !== "pending") await removeLedgerEntry(session.configDir, ledgerScope(session), id)
  return status
}

export async function stopPolicy(session: PolicySession, id: string): Promise<PolicyStopped> {
  policyInput(z.union([PolicyWindowIdSchema, PolicyGrantIdSchema]), id)
  const path = id.startsWith("pov_") ? "overrides" : "grants"
  const stopped = response(stoppedSchema, await session.api.request<unknown>("POST", `/v1/policy/${path}/${id}/revoke`, {}))
  if (stopped.id !== id) throw new CliError("internal", "The stopped policy id does not match.")
  return stopped
}

export type PolicyConvenience = {
  item: string; policyMode: string; action: string | null; session: boolean; device: boolean
  host: string; methods: string[]; path: string; anchorPath: string; reason: string; duration: string | null; until: string | null
}

export async function convenienceProposal(session: PolicySession, input: PolicyConvenience, env: Env, now = Date.now()): Promise<PolicyPropose> {
  if (input.session === input.device) throw usageError("Choose exactly one of --session or --device.", HELP)
  const label = sessionLabel(env)
  if (input.session && label === null) throw usageError("--session needs a non-empty MEHEN_SESSION; it never falls back to --device.", HELP)
  if (input.duration !== null && input.until !== null) throw usageError("--for and --until are mutually exclusive.", HELP)
  const kind = policyInput(z.enum(["mode", "allow"]), input.action ?? "mode")
  const policyMode = policyInput(z.enum(["relaxed", "yolo"]), input.policyMode)
  const scope = policyInput(PolicyRouteScopeSchema, { host: input.host, methods: [...new Set(input.methods)], path: input.path, anchorPath: input.anchorPath, basis: "reviewed" })
  const item = await showItem(session.api, input.item)
  if (!policyScopeEligibility(scope, item.binding).eligible) scope.basis = "unreviewed"
  if (!policyScopeEligibility(scope, item.binding).eligible) throw usageError("This scope has no eligible path pin or reviewed catalogue route. Ask for an exact approval instead.", HELP)
  const lifetime = policyLifetime(policyMode, scope.basis, kind)
  const notAfter = input.until === null ? null : policyInput(timestamp, input.until)
  const ttlSeconds = input.duration !== null ? parseDurationSeconds(input.duration, { max: lifetime.maximumSeconds, flag: "--for", help: HELP }) : notAfter !== null ? Math.min(lifetime.maximumSeconds, Math.floor((Date.parse(notAfter) - now) / 1000)) : lifetime.defaultSeconds
  const change = policyInput(PolicyChangeSchema, { kind, target: { kind: "item", item: input.item }, selector: { device: session.config.device, session: input.session ? label : null }, policyMode, scope, ttlSeconds, notAfter })
  const preview = await previewPolicy(session, { change, reason: input.reason }, env)
  return { change: preview.change, reason: preview.reason, baseDigest: preview.baseDigest, slotRevision: preview.slotRevision }
}

// Said of a change a human has not approved: what it would allow, never that it does.
export function policyScopeWarning(change: PolicyChange): string {
  return change.selector.session === null
    ? "If a human approves this, any program on this device could use the approved access."
    : `If a human approves this, any program on this device using session label ${change.selector.session} could use the approved access.`
}

// Reads at most limit + 1 bytes from a stream and stops there, so an oversized
// input is refused without being read into memory first.
export async function readBounded(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array | null> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      total += value.length
      if (total > limit) return null
    }
  } finally {
    await reader.cancel().catch(() => undefined)
  }
  const bytes = new Uint8Array(total)
  let at = 0
  for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length }
  return bytes
}

// ---------------------------------------------------------------- standing rules

// While standing rules are off, every rule route answers with today's
// forbidden for widening, and an older vault answers the same: both read as
// this one line, with the vault's next. Preview and proposals instead read a
// rule's body as a legacy window's and refuse its missing change; the body
// was checked against PolicyRuleProposalSchema before it was sent, so that
// refusal means the same.
const WIDENING_OFF = "Policy widening is not available yet."
const LEGACY_BODY = "Invalid request: change "
const POLICY_HELP_COMMAND = "mehen policy propose --help"
export const RULES_OFF_LINE = "Standing rules are not switched on for this workspace yet."
const RULE_REFUSED_NEXT = { say: "This request cannot be allowed from now on; it asks for approval every time. Do not propose it again." }
// The refusals a different path or duration fixes.
const RULE_PICK_AGAIN: readonly PolicyRuleRefusal[] = ["rule.path", "rule.binding", "rule.duration"]
const RULE_PICK_AGAIN_NEXT = { command: "mehen policy preview ...", say: "Pick one of preview's path choices (or 1d, 7d or 30d) and propose again." }
const AREA_REFUSED_NEXT = { say: "This request cannot start a task grant; it asks for approval each time. Do not propose a task grant from it again." }
// The task grant refusals other areas, a duration or a number of uses fix.
const AREA_PICK_AGAIN: readonly string[] = ["area.unknown", "area.duration", "area.uses"]
const AREA_PICK_AGAIN_NEXT = { command: "mehen policy propose --help", say: "Pick areas from the service's reviewed list, 15m, 1h or 4h, and 1 to 200 requests, and propose again." }

// A rule route's refusals as this client says them: switched off as one
// line, a refused rule with the vault's words for its refusal code and that
// code; anything else as the vault said it.
export async function ruleCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (error) {
    if (!(error instanceof VaultApiError)) throw error
    if (error.body.error === "bad_request" && error.body.next?.command === POLICY_HELP_COMMAND && error.body.message.startsWith(LEGACY_BODY)) throw new CliError("forbidden", RULES_OFF_LINE, error.body.next)
    if (error.body.error !== "forbidden") throw error
    const failure = toCliError(error)
    const refused = RuleRefusalSchema.safeParse(error.body.ruleRefused)
    if (refused.success) throw new CliError("forbidden", failure.message, error.body.next ?? (RULE_PICK_AGAIN.includes(refused.data) ? RULE_PICK_AGAIN_NEXT : RULE_REFUSED_NEXT), { ...failure.extras, ruleRefused: refused.data })
    const areaRefused = AreaRefusalSchema.safeParse(error.body.areaRefused)
    if (areaRefused.success) throw new CliError("forbidden", failure.message, error.body.next ?? (AREA_PICK_AGAIN.includes(areaRefused.data) ? AREA_PICK_AGAIN_NEXT : AREA_REFUSED_NEXT), { ...failure.extras, areaRefused: areaRefused.data })
    if (error.body.message === WIDENING_OFF) throw new CliError("forbidden", RULES_OFF_LINE, failure.next, failure.extras)
    throw failure
  }
}

export const RULE_DURATION_FLAGS: Record<string, RuleDuration> = { "1d": RULE_DURATIONS[0], "7d": RULE_DURATIONS[1], "30d": RULE_DURATIONS[2] }

// The request a rule is made from: a held or approved one, or an example.
export type RuleExample = { item: string; method: string; url: string; body: Uint8Array | null; contentType: string | null; context: PolicyRuleContext | null }
export type RuleSource = { approval: string } | RuleExample
export type RuleRequest = { source: RuleSource; path: string | null; duration: string | null; reason: string }

// The context an example request names: --project and --env together, or
// none (the rule then covers only requests made outside any project), as
// mehen fetch sends it.
export function ruleContext(project: string | null, environment: string | null, noContext: boolean, help: string): PolicyRuleContext | null {
  if (noContext && (project !== null || environment !== null)) throw usageError("Give --project and --env, or --no-context, not both.", help)
  return fetchContext(project, environment, help)
}

// The PolicyRuleProposal the vault reads, checked before anything is sent.
export function ruleProposal(input: RuleRequest, help: string): PolicyRuleProposal {
  const ttlSeconds = input.duration === null ? undefined : RULE_DURATION_FLAGS[input.duration]
  if (ttlSeconds === undefined && input.duration !== null) throw usageError("--for takes 1d, 7d or 30d.", help)
  const source = input.source
  let from: PolicyRuleProposal["from"]
  if ("approval" in source) from = { approval: source.approval }
  else {
    const method = source.method.toUpperCase()
    if (!(POLICY_RULE_METHODS as readonly string[]).includes(method)) throw usageError(`A standing rule covers only ${POLICY_RULE_METHODS.join(", ")} requests.`, help)
    from = {
      item: source.item, method: method as (typeof POLICY_RULE_METHODS)[number], url: source.url,
      ...(source.body !== null ? { bodyBase64: Buffer.from(source.body).toString("base64") } : {}),
      ...(source.contentType !== null ? { contentType: source.contentType } : {}),
      ...(source.context !== null ? { context: source.context } : {}),
    }
  }
  const parsed = PolicyRuleProposalSchema.safeParse({ from, ...(input.path !== null ? { path: input.path } : {}), ...(ttlSeconds !== undefined ? { ttlSeconds } : {}), reason: input.reason })
  if (!parsed.success) throw usageError(`Invalid rule proposal: ${parsed.error.issues.map((i) => `${i.path.join(".") || "proposal"}: ${i.message}`).join("; ")}.`, help)
  return parsed.data
}

// --for of a task grant: 15 minutes, 1 hour or 4 hours.
export const AREA_DURATION_FLAGS: Record<string, AreaGrantDuration> = { "15m": AREA_GRANT_DURATIONS[0], "1h": AREA_GRANT_DURATIONS[1], "4h": AREA_GRANT_DURATIONS[2] }

// A task grant from a held or approved request (approval) of this key on the
// credential item, for the areas named, checked before anything is sent:
// durations and uses against the protocol's lists. The vault rebuilds the
// terms and binds the grant to the context and mode that request was asked in.
export type AreaRequest = { approval: string; item: string; areas: readonly string[]; duration: string | null; uses: string | null; reason: string }
export function areaProposal(input: AreaRequest, help: string): PolicyAreaProposal {
  const ttlSeconds = input.duration === null ? undefined : AREA_DURATION_FLAGS[input.duration]
  if (ttlSeconds === undefined && input.duration !== null) throw usageError("A task grant's --for takes 15m, 1h or 4h.", help)
  const maxUses = input.uses === null ? undefined : /^[0-9]{1,3}$/.test(input.uses) ? Number(input.uses) : Number.NaN
  if (maxUses !== undefined && !(Number.isInteger(maxUses) && maxUses >= 1 && maxUses <= AREA_GRANT_USES.max)) throw usageError(`--uses takes a whole number from 1 to ${AREA_GRANT_USES.max}; the vault's default is ${AREA_GRANT_USES.default}.`, help)
  const parsed = PolicyAreaProposalSchema.safeParse({ from: { approval: input.approval }, area: { item: input.item, areas: [...input.areas], ...(ttlSeconds !== undefined ? { ttlSeconds } : {}), ...(maxUses !== undefined ? { maxUses } : {}) }, reason: input.reason })
  if (!parsed.success) throw usageError(`Invalid task grant proposal: ${parsed.error.issues.map((i) => `${i.path.join(".") || "proposal"}: ${i.message}`).join("; ")}.`, help)
  return parsed.data
}

// Which context a proposal sent, said back so the agent knows what the rule binds.
export function ruleContextLine(source: RuleSource, howToBind: string): string {
  if ("approval" in source) return `Context: the one ${source.approval} was asked in.`
  if (source.context) return `Context sent: project ${source.context.project}, environment ${source.context.environment}.`
  return `No context was sent: the rule will cover only requests made outside any project. ${howToBind}`
}

// The reason the vault's schema needs on a preview, which never stores it.
export const PREVIEW_REASON = "Preview only."

// POST /v1/policy/preview with a rule: what the vault would propose, or why not.
export async function previewRule(session: PolicySession, proposal: PolicyRuleProposal): Promise<PolicyRulePreview> {
  const input = response(PolicyRuleProposalSchema, proposal)
  return response(rulePreviewSchema, await ruleCall(() => session.api.request<unknown>("POST", "/v1/policy/preview", input)))
}

export function rulePreviewLines(preview: PolicyRulePreview): string[] {
  const paths = ["paths:", ...preview.pathChoices.map((path, index) => `  ${path}${index === 0 ? " (default)" : ""}`)]
  if (preview.refused) return [preview.summary, `This request cannot become a rule (${preview.refused}).`, ...(preview.pathChoices.length > 0 ? paths : [])]
  return [preview.summary, ...paths]
}

// "rule rul_x allows this from now on, until 7 Nov 14:00": the end as the vault sent it, in local time.
export function ruleUntilText(rule: PolicyRuleRef, options: { now?: Date } = {}): string {
  return `rule ${rule.id} allows this from now on, until ${clockText(rule.endsAt, options) ?? rule.endsAt}`
}

// GET /v1/policy/proposals/:id once: where a rule proposal stands, without waiting.
export async function readRuleProposal(session: PolicySession, id: string): Promise<RuleProposalStatus> {
  if (!PolicyProposalIdSchema.safeParse(id).success) throw usageError("Give a policy proposal id (pol_...).", "mehen policy --help")
  const status = response(ruleProposalStatusSchema, await ruleCall(() => session.api.request<unknown>("GET", `/v1/policy/proposals/${id}`)))
  if (status.proposal !== id) throw new CliError("internal", "The vault returned a different policy proposal.")
  return status
}

const RULE_OUTCOME_WORDS: Record<Exclude<RuleProposalStatus["status"], "pending" | "approved">, string> = {
  denied: "The person denied it. Do not propose it again without asking them.",
  expired: "It expired before anyone approved it. Propose it again only if the agent still needs it.",
  cancelled: "It was cancelled.",
  stale: "Access changed after it was asked for. Check mehen policy show before proposing again.",
}

export function ruleStatusLines(status: RuleProposalStatus, options: { now?: Date } = {}): string[] {
  const code = `the page shows code ${status.bindingCode}`
  const lines = [`${status.proposal} (${status.item}): ${status.summary}`]
  if (status.status === "pending") {
    lines.push(status.stage === "co-sign" ? `The machine's owner approved; a manager of the credential's home must co-sign it on the vault page; ${code}.` : `Waiting for the machine's owner to approve it on the vault page; ${code}.`)
  } else if (status.status === "approved") {
    lines.push(status.rule ? `Approved: ${ruleUntilText(status.rule, options)}.` : "Approved.")
  } else lines.push(RULE_OUTCOME_WORDS[status.status])
  return lines
}

// GET /v1/policy/rules: this key's rules, live first, then ended, newest first.
export async function listRules(session: PolicySession, item: string | null): Promise<PolicyRuleList> {
  if (item !== null && !PolicySlugSchema.safeParse(item).success) throw usageError("--item takes a credential's slug.", "mehen policy --help")
  const path = item === null ? "/v1/policy/rules" : `/v1/policy/rules?item=${encodeURIComponent(item)}`
  return response(ruleListSchema, await ruleCall(() => session.api.request<unknown>("GET", path)))
}

// GET /v1/policy/rules?include=grants: this key's rules and task grants.
// A vault that keeps task grants from this mehen's version lists rules only.
export async function listRulesAndGrants(session: PolicySession, item: string | null): Promise<RuleOrGrantList> {
  if (item !== null && !PolicySlugSchema.safeParse(item).success) throw usageError("--item takes a credential's slug.", "mehen policy --help")
  const path = item === null ? "/v1/policy/rules?include=grants" : `/v1/policy/rules?item=${encodeURIComponent(item)}&include=grants`
  return response(ruleOrGrantListSchema, await ruleCall(() => session.api.request<unknown>("GET", path)))
}

// "task grant: issues, pulls on api.github.com": what a task grant lets through.
export function grantRequestText(grant: Pick<GrantView, "areas" | "host">): string {
  return `task grant: ${grant.areas.join(", ")} on ${grant.host}`
}

// What each task grant has been used for so far, by catalogue entry.
export function grantReceiptLines(rows: RuleOrGrantList): string[] {
  return rows.filter(isGrant).filter((grant) => grant.receipt.length > 0).map((grant) => `${grant.id}: ${grant.receipt.map((r) => `${r.count} × ${r.words}`).join(", ")}`)
}

// "POST api.linear.app/graphql commentCreate": the request shape a rule allows.
export function ruleRequestText(rule: Pick<PolicyRuleView, "method" | "host" | "path" | "graphql">): string {
  return `${rule.method} ${rule.host}${rule.path}${rule.graphql ? ` ${rule.graphql.fields.join(", ")}` : ""}`
}

export function ruleContextText(context: PolicyRuleView["context"]): string {
  return context ? `${context.project} / ${context.environment}` : "outside any project"
}

// A task grant's row shows its areas, and its uses out of the most it allows.
export function ruleTableRows(rules: RuleOrGrantList, options: { now?: Date } = {}): string[][] {
  const when = (at: string) => clockText(at, options) ?? at
  return [
    ["ID", "ITEM", "REQUEST", "CONTEXT", "FROM", "ENDS", "USES", "LAST USED", "STATUS"],
    ...rules.map((rule) => [
      rule.id, rule.item, isGrant(rule) ? grantRequestText(rule) : ruleRequestText(rule), ruleContextText(rule.context), rule.asker.workload ? `workload ${rule.asker.workload}` : "machine",
      when(rule.endsAt), isGrant(rule) ? `${rule.uses} of ${rule.maxUses}` : String(rule.uses), rule.lastUsedAt ? when(rule.lastUsedAt) : "never", rule.status === "ended" ? `ended${rule.endedReason ? ` (${rule.endedReason})` : ""}` : "active",
    ]),
  ]
}

// POST /v1/policy/rules/:id/revoke: the rule ends now; requests it allowed ask again.
export async function revokeRule(session: PolicySession, id: string): Promise<PolicyRuleView> {
  if (!PolicyRuleIdSchema.safeParse(id).success) throw usageError(RULE_ID_ONLY, "mehen policy --help")
  const rule = response(ruleViewSchema, await ruleCall(() => session.api.request<unknown>("POST", `/v1/policy/rules/${id}/revoke`, {})))
  if (rule.id !== id) throw new CliError("internal", "The vault revoked a different rule.")
  return rule
}

export const RULE_ID_ONLY = "Policy windows and grants no longer exist; mehen policy revoke <rul_id> ends a standing rule."

// The item's live rules for mehen policy show, or null when the vault lists
// none at all: rules switched off, or a vault older than rules.
export async function liveRules(session: PolicySession, item: string): Promise<PolicyRuleList | null> {
  try {
    return (await listRules(session, item)).filter((rule) => rule.status === "active")
  } catch (error) {
    const code = toCliError(error).code
    if (code === "forbidden" || code === "not_found") return null
    throw error
  }
}

export function liveRuleLines(rules: PolicyRuleList, options: { now?: Date } = {}): string[][] {
  if (rules.length === 0) return [["Standing rules: none."]]
  const rows = rules.map((rule) => [`  ${rule.id}`, ruleRequestText(rule), ruleContextText(rule.context), rule.asker.workload ? `workload ${rule.asker.workload}` : "machine", `ends ${clockText(rule.endsAt, options) ?? rule.endsAt}`, `${rule.uses} use${rule.uses === 1 ? "" : "s"}`])
  return [["Standing rules:"], ...rows]
}

// Mehen-Rule on a relayed response: the rules and task grants that allowed
// it without asking, joined with ", " when there are several. The header is
// untrusted, so it is read only when every part is a well-formed rule id,
// and each one's end (and a task grant's uses) comes from the vault's own
// list, looked up once for this response and matched on the id; without it
// the id stands alone.
export type RuleAllowed = { id: string; endsAt: string | null; grant?: { uses: number; maxUses: number } }

export async function rulesAllowed(api: PolicySession["api"], response: Response, item: string | null, signal?: AbortSignal): Promise<RuleAllowed[] | null> {
  const ids = response.headers.get(RULE_HEADER)?.split(", ")
  if (ids === undefined || !ids.every((id) => PolicyRuleIdSchema.safeParse(id).success)) return null
  const path = item === null ? "/v1/policy/rules?include=grants" : `/v1/policy/rules?item=${encodeURIComponent(item)}&include=grants`
  try {
    const rules = ruleOrGrantListSchema.parse(await api.request<unknown>("GET", path, undefined, signal ? { signal } : {}))
    return ids.map((id) => {
      const rule = rules.find((r) => r.id === id)
      return { id, endsAt: rule?.endsAt ?? null, ...(rule && isGrant(rule) ? { grant: { uses: rule.uses, maxUses: rule.maxUses } } : {}) }
    })
  } catch {
    return ids.map((id) => ({ id, endsAt: null }))
  }
}

// Mehen-Posture on a relayed response: how careful the credential is let it
// through without asking (routine, trust), read only when every part is a
// level this mehen knows.
export type PostureAllowed = "routine" | "trust"
export function postureAllowed(response: Response): PostureAllowed[] | null {
  const levels = response.headers.get(POSTURE_HEADER)?.split(", ")
  if (levels === undefined || !levels.every((level): level is PostureAllowed => level === "routine" || level === "trust")) return null
  return levels as PostureAllowed[]
}
export function postureAllowedText(level: PostureAllowed): string {
  return level === "routine" ? "allowed without asking: this credential lets routine building through" : "allowed without asking: this credential trusts this machine"
}

// The vault's 409 when the rule that matched a request ended before the
// relay's last check: nothing was sent. The vault names no step, and the
// generic conflict step (mehen pending) would mislead, so this one says to
// send once more, which asks for approval. Matched on the vault's words,
// as the vault gives this conflict no code of its own.
const RULE_ENDED = "The rule that allowed this request has ended"

export function ruleEnded(error: unknown): unknown {
  if (!(error instanceof VaultApiError) || error.body.error !== "conflict" || error.body.next !== undefined || !error.body.message.startsWith(RULE_ENDED)) return error
  return new CliError("conflict", error.body.message, { say: "The standing rule that allowed this request has ended. Send it once more to ask for approval; do not retry in a loop." })
}

export function ruleAllowedText(rule: RuleAllowed, options: { now?: Date } = {}): string {
  const ends = rule.endsAt === null ? null : clockText(rule.endsAt, options)
  if (rule.grant) return `allowed without asking by task grant ${rule.id}, use ${rule.grant.uses} of ${rule.grant.maxUses}${ends === null ? "" : `, ends ${ends}`}`
  return ends === null ? `allowed without asking by rule ${rule.id}; see mehen policy ls` : `allowed without asking by rule ${rule.id}, ends ${ends}`
}

// After an approval remembered as a standing rule: the rule, or the proposal
// that waits for a co-signer, each checked. A proposal link that is not this
// vault's page for that proposal is dropped with it.
export type RememberedRule = { rule?: PolicyRuleRef; ruleProposal?: PolicyRuleProposalRef }

export function rememberedRule(status: object, vault: AskVault | null | undefined): RememberedRule {
  const raw = status as { rule?: unknown; ruleProposal?: unknown }
  const remembered: RememberedRule = {}
  const rule = RuleRefSchema.safeParse(raw.rule)
  if (rule.success) remembered.rule = rule.data
  const proposal = RuleProposalRefSchema.safeParse(raw.ruleProposal)
  const link = proposal.success ? askUrl(proposal.data.url, vault) : null
  if (proposal.success && link?.route?.prefix === "p" && link.route.id === proposal.data.id) remembered.ruleProposal = { ...proposal.data, url: link.url }
  return remembered
}

export type RuleProposalResult = RuleProposalStatus & { url: AskUrl | null; ask: Ask | null; next: NextStep | null; warning: string | null }

// POST /v1/policy/proposals with a rule: the pol_ ask a person approves on
// the vault page. Nothing is allowed until their passkey turns it on.
export async function proposeRule(session: PolicySession, proposal: PolicyRuleProposal): Promise<RuleProposalResult> {
  const input = response(PolicyRuleProposalSchema, proposal)
  const raw = await ruleCall(() => session.api.request<unknown>("POST", "/v1/policy/proposals", input))
  return proposalAsk(session, raw, "item" in input.from ? input.from.item : null)
}

// The vault's words when a task grant's body reached a route that reads it
// as a rule's: a vault from before task grants, or one that keeps them from
// this mehen's version.
const AREA_BODY_UNREAD = 'Unrecognized key: "area"'
export const AREA_UNAVAILABLE_LINE = "This vault does not take task grant proposals from this mehen yet."

// POST /v1/policy/proposals with a task grant: the pol_ ask the machine's
// owner decides on the vault page. Nothing is allowed until their passkey
// does it, and only for the areas, time and uses they keep.
export async function proposeArea(session: PolicySession, proposal: PolicyAreaProposal): Promise<RuleProposalResult> {
  const input = response(PolicyAreaProposalSchema, proposal)
  const raw = await ruleCall(async () => {
    try {
      return await session.api.request<unknown>("POST", "/v1/policy/proposals", input)
    } catch (error) {
      if (error instanceof VaultApiError && error.body.error === "bad_request" && error.body.message.includes(AREA_BODY_UNREAD)) throw new CliError("forbidden", AREA_UNAVAILABLE_LINE, { say: "Approve each request on its own for now; do not propose a task grant again." })
      throw error
    }
  })
  return proposalAsk(session, raw, input.area.item)
}

// The pol_ ask a proposal's answer opens, written to the ask ledger, or
// where it already stands.
async function proposalAsk(session: PolicySession, raw: unknown, item: string | null): Promise<RuleProposalResult> {
  const created = ruleProposalCreated(raw)
  if (item !== null && created.item !== item) throw new CliError("internal", "The proposal does not match the requested item.")
  if (created.status !== "pending") return { ...created, ask: null, next: null, warning: null, url: null }
  const me = await session.api.request<Me>("GET", "/v1/me")
  const scope = ledgerScope(session)
  const given = askUrl((raw as { url?: unknown }).url, scope)
  const matching = given?.route?.prefix === "p" && given.route.id === created.proposal ? given : null
  const link = matching ?? askUrlFor(scope, "policy", created.proposal)
  if (!link) throw new CliError("internal", "The vault returned no usable policy proposal link.")
  const warning = matching ? null : refusedLinkWarning(session.vaultUrl)
  const ask = withContext(policyAsk({ id: created.proposal, url: link.url, summary: `${created.summary}. No access has changed yet.`, bindingCode: created.bindingCode, expiresAt: created.expiresAt, requestedBy: { device: me.name, session: null } }), { origin: session.vaultUrl, workspace: configWorkspace(session.config), device: session.config.device })
  const next = { url: ask.url, command: `mehen wait ${ask.id}`, say: askSay(ask) }
  await recordAsk(session.configDir, scope, ask, created.item, `mehen policy show ${created.item}`, new Date())
  return { ...created, url: link.url, ask, next, warning }
}

export function policyStateLines(state: PolicyState | null): string[] {
  if (state === null) return ["policy windows:  unavailable from this vault"]
  const lines = [`Access observed at ${state.observedAt}.`]
  if (!state.widening.length) lines.push("No active policy windows or route grants were observed.")
  for (const row of state.widening) lines.push(`${row.policyMode}: ${row.item}, ${row.scope.methods.join("/")} ${row.scope.host}${row.scope.path}, expires ${row.expiresAt}`, row.selector.session === null ? `Any program on ${row.selector.device} can use this access.` : `Any program on ${row.selector.device} using session label ${row.selector.session} can use this access.`, `Review: ${row.reviewUrl}`)
  return lines
}
