import { AREA_GRANT_USES, POLICY_RULE_METHODS, PolicyAreaIdSchema, PolicyProposalIdSchema, PolicyRuleIdSchema, PolicySlugSchema } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { PREVIEW_REASON, type RuleSource, areaProposal, cancelPolicy, listRules, listRulesAndGrants, proposeArea, liveRules, previewRule, proposeRule, readRuleProposal, revokeRule, ruleContext, ruleContextLine, ruleProposal, showPolicy } from "../policy-operations.ts"
import { CliError, usageError } from "../errors.ts"
import { WORKSPACE_ARG, handing, plain, tool } from "./shared.ts"
import { decodeBase64 } from "./vault-fetch.ts"

const HELP = "mehen policy --help"
const DURATIONS = ["1d", "7d", "30d"] as const
// A task grant's: 15 minutes, 1 hour or 4 hours.
const AREA_DURATIONS = ["15m", "1h", "4h"] as const
const context = z.strictObject({ project: z.string().describe("the project id (prj_...)"), environment: z.string().describe("the environment name") })

// The request a rule is made from, as mehen policy preview|propose takes it:
// from (a held or approved apr_), or an example named by item, method and url.
const ruleFields = {
  from: z.string().optional(), item: PolicySlugSchema.optional(), method: z.string().optional(), url: z.string().optional(),
  body: z.string().optional(), bodyBase64: z.string().optional(), contentType: z.string().optional(), context: context.optional(),
  path: z.string().optional(), for: z.enum(DURATIONS).optional(),
}
// A task grant, on propose only: from (a held or approved apr_) on item, for
// the areas named, 15m, 1h or 4h and up to uses requests.
const areaFields = { from: z.string(), item: PolicySlugSchema, area: z.array(PolicyAreaIdSchema).min(1), for: z.enum(AREA_DURATIONS).optional(), uses: z.number().int().min(1).max(AREA_GRANT_USES.max).optional(), reason: z.string() }

// A propose names a rule's fields or a task grant's (area), never both.
const actionInput = z.union([
  z.strictObject({ action: z.literal("show"), item: PolicySlugSchema }),
  z.strictObject({ action: z.literal("ls"), item: PolicySlugSchema.optional(), grants: z.boolean().optional() }),
  z.strictObject({ action: z.literal("preview"), ...ruleFields, reason: z.string().optional() }),
  z.strictObject({ action: z.literal("propose"), ...ruleFields, reason: z.string() }),
  z.strictObject({ action: z.literal("propose"), ...areaFields }),
  z.strictObject({ action: z.literal("status"), id: PolicyProposalIdSchema }),
  z.strictObject({ action: z.literal("cancel"), id: PolicyProposalIdSchema }),
  z.strictObject({ action: z.literal("revoke"), id: PolicyRuleIdSchema }),
])

const ACTIONS = ["show", "ls", "preview", "propose", "status", "cancel", "revoke"] as const
const RULE_METHODS_TEXT = `${POLICY_RULE_METHODS.slice(0, -1).join(", ")} or ${POLICY_RULE_METHODS.at(-1)}`

const input = z.strictObject({
  action: z.enum(ACTIONS).describe("show needs item; ls takes item to narrow and grants to list task grants too; preview and propose need from, or item, method and url (propose also needs reason); propose with area needs from, item and reason; status and cancel need id (pol_); revoke needs id (rul_). Supply only those fields."),
  item: PolicySlugSchema.optional().describe("The item's slug: for show, ls, an example request, or the credential of from's request for a task grant."),
  from: z.string().optional().describe("preview or propose: a held or approved request (apr_), with its own context. Give no example fields with it."),
  method: z.string().optional().describe(`preview or propose example: ${RULE_METHODS_TEXT}.`),
  url: z.string().optional().describe("preview or propose example: the full upstream URL."),
  body: z.string().optional().describe("preview or propose example: request body as text."),
  bodyBase64: z.string().optional().describe("preview or propose example: request body as base64."),
  contentType: z.string().optional().describe("preview or propose example: the body's content type."),
  context: context.optional().describe("preview or propose example: the project environment the rule is bound to. Without it the rule covers only requests made outside any project."),
  path: z.string().optional().describe("preview or propose: one of preview's path choices; the default is the first."),
  for: z.enum([...DURATIONS, ...AREA_DURATIONS]).optional().describe("preview or propose: how long the rule lasts (1d, 7d or 30d), or with area the task grant (15m, 1h or 4h); the vault's default when absent."),
  area: z.array(PolicyAreaIdSchema).min(1).optional().describe("propose only: ask for a task grant instead of a rule, letting routine work in these areas of the service's reviewed list through, from the request from names on item, in its context. Never anything that always asks."),
  uses: z.number().int().min(1).max(AREA_GRANT_USES.max).optional().describe(`propose with area: the most requests the task grant allows, 1 to ${AREA_GRANT_USES.max}; ${AREA_GRANT_USES.default} when absent.`),
  grants: z.boolean().optional().describe("ls: list task grants as well as rules, each with its areas, uses, end and what it was used for."),
  reason: z.string().optional().describe("Required for propose: why the agent needs this allowed from now on. The person approving reads it."),
  id: z.union([PolicyProposalIdSchema, PolicyRuleIdSchema]).optional().describe("status or cancel: pol_; revoke: rul_."),
  workspace: WORKSPACE_ARG,
})

const ACTION_FIELDS: Record<(typeof ACTIONS)[number], string> = {
  show: "item", ls: "optionally item and grants",
  preview: "from, or item, method and url (optionally body or bodyBase64, contentType, context), and optionally path and for",
  propose: "reason and from, or item, method and url (optionally body or bodyBase64, contentType, context), and optionally path and for (1d, 7d or 30d); or for a task grant reason, from, item and area, and optionally for (15m, 1h or 4h) and uses",
  status: "id (pol_)", cancel: "id (pol_)", revoke: "id (rul_)",
}

type RuleArgs = z.infer<z.ZodObject<typeof ruleFields>>

const EXAMPLE_FIELDS = ["item", "method", "url", "body", "bodyBase64", "contentType", "context"] as const

function ruleSource(args: RuleArgs): RuleSource {
  if (args.from !== undefined) {
    if (EXAMPLE_FIELDS.some((name) => args[name] !== undefined)) throw usageError("from takes the request the vault holds, with its own context: give no item, method, url, body, bodyBase64, contentType or context with it.", HELP)
    return { approval: args.from }
  }
  if (args.item === undefined || args.method === undefined || args.url === undefined) throw usageError("Name the request: from (apr_), or item, method and url.", HELP)
  if (args.body !== undefined && args.bodyBase64 !== undefined) throw usageError("Give body or bodyBase64, not both.", HELP)
  const body = args.body !== undefined ? new TextEncoder().encode(args.body) : args.bodyBase64 !== undefined ? decodeBase64(args.bodyBase64) : null
  return { item: args.item, method: args.method, url: args.url, body, contentType: args.contentType ?? null, context: ruleContext(args.context?.project ?? null, args.context?.environment ?? null, false, HELP) }
}

export const vaultPolicy = tool({
  name: "vault_policy",
  title: "Standing rules and task grants",
  description: "Standing rules: ask a person to allow one request shape from now on, for 1, 7 or 30 days, or with area a task grant: routine work in a service's reviewed areas for 15 minutes to 4 hours and a number of requests. show reads an item's policy and live rules; ls lists rules (grants: task grants too); preview says what a rule would cover; propose asks and returns the ask to show; status reads a proposal; cancel withdraws it; revoke ends a rule. Agents cannot approve: only the person's passkey turns a rule on. Rules never cover sending messages, moving money, sharing or publishing, credential or access changes, anything left running or deletes, nor protected environments or credentials holding a live key. Never returns a secret.",
  input,
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  async call(value, deps) {
    // The workspace is the call's, not the action's: the action's own closed shape is checked without it.
    const { workspace, ...action } = value
    const parsed = actionInput.safeParse(action)
    if (!parsed.success) {
      const action = input.shape.action.safeParse((value as { action?: unknown } | null)?.action)
      const fields = action.success ? `For action ${action.data}, supply only action and ${ACTION_FIELDS[action.data]}.` : "Choose show, ls, preview, propose, status, cancel or revoke; agents cannot approve or set policy."
      throw new CliError("usage", fields, { command: HELP, say: fields })
    }
    const args = parsed.data
    if (args.action === "propose" && "area" in args) {
      const proposal = areaProposal({ approval: args.from, item: args.item, areas: args.area, duration: args.for ?? null, uses: args.uses === undefined ? null : String(args.uses), reason: args.reason }, HELP)
      const result = await proposeArea(await deps.session(workspace), proposal)
      return handing(result, result.ask, result.warning)
    }
    if (args.action === "preview" || args.action === "propose") {
      const source = ruleSource(args)
      const proposal = ruleProposal({ source, path: args.path ?? null, duration: args.for ?? null, reason: args.reason ?? PREVIEW_REASON }, HELP)
      const session = await deps.session(workspace)
      if (args.action === "preview") return plain(await previewRule(session, proposal))
      const result = await proposeRule(session, proposal)
      return handing({ ...result, note: ruleContextLine(source, "Give context to bind one.") }, result.ask, result.warning)
    }
    const session = await deps.session(workspace)
    if (args.action === "ls") return plain({ rules: args.grants === true ? await listRulesAndGrants(session, args.item ?? null) : await listRules(session, args.item ?? null) })
    if (args.action === "status") return plain(await readRuleProposal(session, args.id))
    if (args.action === "cancel") return plain(await cancelPolicy(session, args.id))
    if (args.action === "revoke") return plain(await revokeRule(session, args.id))
    const shown = await showPolicy(session, args.item)
    const rules = await liveRules(session, args.item)
    return plain(rules === null ? shown : { ...shown, rules })
  },
})
