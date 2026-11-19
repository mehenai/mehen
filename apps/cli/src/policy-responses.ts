import { PolicySchema } from "@mehen/protocol/api"
import { POLICY_AREA_REFUSALS, POLICY_RULE_REFUSALS, PolicyAreaGrantTermsSchema, type PolicyAreaGrantTerms, type PolicyAreaGrantView, PolicyChangeSchema, type PolicyContext, PolicyDeviceIdSchema, PolicyGrantIdSchema, PolicyProposalIdSchema, PolicyProposalStatusSchema, PolicyProposeSchema, PolicyRevisionSchema, PolicyRouteScopeSchema, PolicyRuleIdSchema, PolicyRuleProposalStatusSchema, PolicyRuleTermsSchema, PolicySelectorSchema, PolicySlugSchema, type PolicyRuleView, type PolicyState, PolicyWindowIdSchema } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { CliError } from "./errors.ts"

export const timestamp = z.iso.datetime({ offset: true })
const wideningSchema = z.object({
  id: z.union([PolicyWindowIdSchema, PolicyGrantIdSchema]), kind: z.enum(["mode", "route-grant"]), item: PolicySlugSchema,
  selector: PolicySelectorSchema, policyMode: z.enum(["relaxed", "yolo"]), scope: PolicyRouteScopeSchema,
  expiresAt: timestamp, parent: PolicyWindowIdSchema.nullable(), reviewUrl: z.string(), stopUrl: z.string(),
}).refine((v) => v.id.startsWith(v.kind === "mode" ? "pov_" : "gnt_"))
export const stateSchema = z.object({ widening: z.array(wideningSchema), observedAt: timestamp })
const floorSchema = z.object({ id: z.string(), host: z.string(), action: z.enum(["deny", "approve"]), reason: z.enum(["credential", "persistence", "send", "money", "sharing", "destructive", "opaque"]), rule: PolicySchema.shape.rules.element, ruleDigest: z.string() })
export const contextSchema = z.object({
  item: PolicySlugSchema, selector: PolicySelectorSchema, baseMode: z.literal("standard"), effectiveMode: z.enum(["standard", "relaxed", "yolo"]),
  basePolicy: PolicySchema, floor: z.array(floorSchema),
  snapshot: z.object({ itemId: z.string(), device: PolicyDeviceIdSchema, configRev: PolicyRevisionSchema, scopeRev: PolicyRevisionSchema, protectionRev: PolicyRevisionSchema, safetyDigest: z.string(), frozen: z.boolean() }),
  baseDigest: PolicyProposeSchema.shape.baseDigest, slotRevision: PolicyRevisionSchema, predecessor: wideningSchema.nullable(), state: stateSchema,
})
export const previewSchema = z.object({
  change: PolicyChangeSchema, reason: z.string(), context: contextSchema, baseDigest: PolicyProposeSchema.shape.baseDigest,
  slotRevision: PolicyRevisionSchema, summary: z.string(), diff: z.array(z.object({ field: z.string(), before: z.string(), after: z.string(), effect: z.enum(["narrower", "wider", "unchanged"]) })), warnings: z.array(z.string()),
})

export function response<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value)
  if (!parsed.success) throw new CliError("internal", "The vault returned an invalid policy response.")
  return parsed.data
}

export const stoppedSchema = z.object({ id: z.union([PolicyWindowIdSchema, PolicyGrantIdSchema]), stopped: z.array(z.union([PolicyWindowIdSchema, PolicyGrantIdSchema, PolicyProposalIdSchema])), status: z.literal("revoked"), effectiveAt: timestamp })

export function checkedWidening(value: PolicyState["widening"][number], vaultUrl: string): void {
  const path = value.kind === "mode" ? "overrides" : "grants"
  const origin = new URL(vaultUrl).origin
  if (value.reviewUrl !== `${origin}/policy/${path}/${value.id}` || value.stopUrl !== `${origin}/api/policy/${path}/${value.id}/revoke`) {
    throw new CliError("internal", "The vault returned an invalid policy review or Stop link.")
  }
}

export function checkedContext(value: unknown, vaultUrl: string): PolicyContext {
  const context = response(contextSchema, value)
  for (const row of context.state.widening) checkedWidening(row, vaultUrl)
  if (context.predecessor) checkedWidening(context.predecessor, vaultUrl)
  return context
}

// Standing rule answers as this client reads them: keys it does not know are
// stripped, so a vault that adds one does not break it, and a rule field an
// older vault does not send reads as absent.
export const RuleRefusalSchema = z.enum(POLICY_RULE_REFUSALS)
export const RuleRefSchema = z.object({ id: PolicyRuleIdSchema, endsAt: timestamp })
export const RuleProposalRefSchema = z.object({ id: PolicyProposalIdSchema, url: z.string(), bindingCode: z.string().max(64), expiresAt: timestamp })
export const ruleProposalStatusSchema = z.object({ ...PolicyRuleProposalStatusSchema.shape, stage: PolicyRuleProposalStatusSchema.shape.stage.optional(), rule: RuleRefSchema.nullable().optional() })
export type RuleProposalStatus = z.infer<typeof ruleProposalStatusSchema>
export const RuleTermsSchema = z.object(PolicyRuleTermsSchema.shape)
export const ruleViewSchema = z.object({
  ...RuleTermsSchema.shape,
  id: PolicyRuleIdSchema,
  approvedBy: z.string().nullable(),
  coSignedBy: z.object({ name: z.string().nullable() }).nullable(),
  context: z.object({ project: z.string(), environment: z.string() }).nullable(),
  createdAt: timestamp,
  endsAt: timestamp,
  uses: z.number().int().min(0),
  lastUsedAt: timestamp.nullable(),
  status: z.enum(["active", "ended"]),
  endedReason: z.enum(["expired", "revoked", "access-changed", "credential-changed"]).nullable(),
}) satisfies z.ZodType<PolicyRuleView>
export const ruleListSchema = z.array(ruleViewSchema)
// A task grant (a standing rule of kind area), from a vault asked with
// include=grants by a mehen it lets read them (0.3.17 or later).
export const AreaRefusalSchema = z.enum(POLICY_AREA_REFUSALS)
const RULE_ENDINGS = ruleViewSchema.shape.endedReason.unwrap().options
export const grantViewSchema = z.object({
  ...PolicyAreaGrantTermsSchema.shape,
  id: PolicyRuleIdSchema,
  approvedBy: z.string().nullable(),
  coSignedBy: z.object({ name: z.string().nullable() }).nullable(),
  context: z.object({ project: z.string(), environment: z.string() }).nullable(),
  createdAt: timestamp,
  endsAt: timestamp,
  uses: z.number().int().min(0),
  lastUsedAt: timestamp.nullable(),
  status: z.enum(["active", "ended"]),
  receipt: z.array(z.object({ entry: z.string(), words: z.string(), count: z.number().int().min(0) })),
  endedReason: z.enum([...RULE_ENDINGS, "uses-spent", "replaced"]).nullable(),
}) satisfies z.ZodType<PolicyAreaGrantView>
export type GrantView = z.infer<typeof grantViewSchema>
// GET /v1/policy/rules?include=grants: rules and task grants together.
export const ruleOrGrantListSchema = z.array(z.union([ruleViewSchema, grantViewSchema]))
export type RuleOrGrantList = z.infer<typeof ruleOrGrantListSchema>
export const isGrant = (row: RuleOrGrantList[number]): row is GrantView => "kind" in row && row.kind === "area"
// The signed terms of a listed task grant, without the view's fields, as
// the protocol's areaGrantEntry reads them.
export function grantTerms(grant: GrantView): PolicyAreaGrantTerms {
  const { kind, item, itemId, asker, host, catalogue, catalogueVersion, areas, ttlSeconds, maxUses } = grant
  return { kind, item, itemId, asker, host, catalogue, catalogueVersion, areas, ttlSeconds, maxUses }
}
export const rulePreviewSchema = z.object({ terms: RuleTermsSchema.nullable(), pathChoices: z.array(z.string()), summary: z.string(), refused: RuleRefusalSchema.nullable() })

export function ruleProposalCreated(raw: unknown): RuleProposalStatus {
  if (typeof raw !== "object" || raw === null) throw new CliError("internal", "The vault returned an invalid policy response.")
  const { url: _url, next: _next, ...status } = raw as Record<string, unknown>
  return response(ruleProposalStatusSchema, status)
}

export function createdResponse(raw: unknown) {
  if (typeof raw !== "object" || raw === null) throw new CliError("internal", "The vault returned an invalid policy response.")
  return response(PolicyProposalStatusSchema, Object.fromEntries(Object.entries(raw as Record<string, unknown>).filter(([key]) => key !== "url" && key !== "next")))
}
