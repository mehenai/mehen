import { MANDATE_CAP_MAX, MANDATE_CLASSES, MANDATE_MAX_ITEMS, MANDATE_PROPOSAL_CAP_DEFAULTS, MandateIdSchema, parseMandateReceiptsCursor } from "@mehen/protocol/mandate-terms"
import { PolicySlugSchema } from "@mehen/protocol/policy-mode"
import { z } from "zod"
import { CliError } from "../errors.ts"
import { SCHEDULE_EXAMPLE, askedForMandate, checkMandateRequest, listMandates, listedMandateNeedingSigner, mandateNext, mandatePageLink, mandateProposal, mandateUses, parseSince, pauseLiveMandate, pauseMandate, proposeMandate, showMandate } from "../mandate-operations.ts"
import { WORKSPACE_ARG, handing, plain, tool } from "./shared.ts"

const HELP = "mehen mandate --help"
const ACTIONS = ["propose", "list", "show", "uses", "pause"] as const
// The most receipts one uses answer carries; next carries on from there.
const USES_LIMIT = 500
const usesCursor = z.string().refine((cursor) => parseMandateReceiptsCursor(cursor) !== null, "Not a receipts cursor.")
const caps = z.strictObject(Object.fromEntries(MANDATE_CLASSES.map((c) => [c, z.number().int().min(1).max(MANDATE_CAP_MAX[c]).optional()])) as Record<(typeof MANDATE_CLASSES)[number], z.ZodOptional<z.ZodNumber>>)
const proposeFields = {
  items: z.union([z.literal("all"), z.array(PolicySlugSchema).min(1)]).optional(),
  classes: z.array(z.enum(MANDATE_CLASSES)).min(1).optional(),
  days: z.union([z.literal(1), z.literal(7), z.literal(30), z.literal(90)]).optional(),
  caps: caps.optional(),
  schedule: z.string().optional(),
  note: z.string(),
  reason: z.string().optional(),
}

const actionInput = z.union([
  z.strictObject({ action: z.literal("propose"), ...proposeFields }),
  z.strictObject({ action: z.literal("list") }),
  z.strictObject({ action: z.literal("show"), id: MandateIdSchema }),
  z.strictObject({ action: z.literal("uses"), id: MandateIdSchema, since: z.string().optional(), before: usesCursor.optional() }),
  z.strictObject({ action: z.literal("pause"), id: MandateIdSchema.optional() }),
])

// What tools/list offers: only what a machine may propose. input parses the
// wider values too, so the vault refuses them with its structured reason.
const proposeOffered = {
  items: z.array(PolicySlugSchema).min(1).max(MANDATE_MAX_ITEMS).optional(),
  days: z.union([z.literal(1), z.literal(7), z.literal(30)]).optional(),
  caps: z.strictObject(Object.fromEntries(MANDATE_CLASSES.map((c) => [c, z.number().int().min(1).max(MANDATE_PROPOSAL_CAP_DEFAULTS[c]).optional()])) as Record<(typeof MANDATE_CLASSES)[number], z.ZodOptional<z.ZodNumber>>).optional(),
}
const inputOf = (fields: { items: z.ZodType; days: z.ZodType; caps: z.ZodType }) => z.strictObject({
  action: z.enum(ACTIONS).describe("propose needs note; list takes nothing; show needs id; pause takes id, or none for this machine's live mandate; uses needs id and takes since and before. Supply only those fields."),
  items: fields.items.describe("propose: credential slugs; by default those this machine asked for in 30 days. The vault refuses any other."),
  classes: proposeFields.classes.describe("propose: read, change, send, delete; by default read and those asked for. The vault refuses others."),
  days: fields.days.describe("propose: 1, 7 or 30 days (the default)."),
  caps: fields.caps.describe("propose: requests a day per class, such as { send: 5 }; the default fills any left out."),
  schedule: proposeFields.schedule.describe(`propose: only in these hours, a time zone then windows separated by ";": "${SCHEDULE_EXAMPLE}". At any time when absent.`),
  note: z.string().optional().describe("Required for propose: what the mandate is for. The person signing reads it."),
  reason: proposeFields.reason.describe("propose: why this machine asks now; the note when absent."),
  id: MandateIdSchema.optional().describe("show, uses or pause: the mandate (mdt_); pause without it pauses this machine's live mandate in this workspace."),
  since: z.string().optional().describe("uses: only what went through since then, a time with its offset or a span back from now: 30m, 12h or 7d."),
  before: usesCursor.optional().describe(`uses: carry on from the next of an answer cut at ${USES_LIMIT} receipts.`),
  workspace: WORKSPACE_ARG,
})
const input = inputOf({ items: proposeFields.items, days: proposeFields.days, caps: caps.optional() })
const advertised = inputOf(proposeOffered)

const ACTION_FIELDS: Record<(typeof ACTIONS)[number], string> = {
  propose: "note, and optionally items, classes, days, caps, schedule and reason",
  list: "nothing more", show: "id (mdt_)", uses: "id (mdt_) and optionally since and before", pause: "optionally id (mdt_)",
}

export const vaultMandate = tool({
  name: "vault_mandate",
  title: "Mandates",
  description: `Mandates: ask a person to let this machine's held requests through without asking, with the credentials and kinds named, within daily caps, until a date and optionally only in certain hours. propose returns the ask to show, or the same open proposal (existing true) for the same terms; the person signs it with their passkey and may change any term. list, show and uses read its proposals, mandates, today's use (UTC) and what went through on trust, ${USES_LIMIT} at a time; pause stops this machine's mandate covering anything now, without id its live one here. A paused, tripped or ended mandate comes with next.url, its page, to pass to the person who signed it. Agents cannot sign, resume or stop a mandate. A mandate never covers credential, access or money changes, nor anything an ask's mandateCover says it cannot. Never returns a secret.`,
  input,
  advertised,
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  async call(value, deps) {
    const { workspace, ...action } = value
    const parsed = actionInput.safeParse(action)
    if (!parsed.success) {
      const action = input.shape.action.safeParse((value as { action?: unknown } | null)?.action)
      const fields = action.success ? `For action ${action.data}, supply only action and ${ACTION_FIELDS[action.data]}.` : "Choose propose, list, show, uses or pause; agents cannot sign, resume or stop a mandate."
      throw new CliError("usage", fields, { command: HELP, say: fields })
    }
    const args = parsed.data
    if (args.action === "propose") {
      const request = { items: args.items ?? null, classes: args.classes ?? null, days: args.days ?? null, caps: Object.fromEntries(Object.entries(args.caps ?? {}).filter(([, n]) => n !== undefined)) as Record<string, number>, schedule: args.schedule ?? null, note: args.note, reason: args.reason ?? null }
      const checked = checkMandateRequest(request, "mcp", HELP)
      const session = await deps.session(workspace)
      const proposal = checked ?? mandateProposal(request, "mcp", HELP, await askedForMandate(session))
      const result = await proposeMandate(session, proposal, deps.env, "mcp")
      return handing({ ...result, terms: proposal.terms }, result.ask, result.warning, `${result.existing ? "these terms are already waiting for the person to sign; this is the same link. " : ""}vault_mandate { "action": "list" } shows it again while it is open, and the mandate once it is signed`)
    }
    const since = args.action === "uses" && args.since !== undefined ? parseSince(args.since, "since", HELP) : null
    const session = await deps.session(workspace)
    if (args.action === "list") {
      const { mandates, proposals, warning } = await listMandates(session)
      const needing = listedMandateNeedingSigner(mandates)
      const next = needing ? mandateNext(needing, mandatePageLink(session, needing.id)) : null
      return { ...plain({ mandates, proposals, ...(next ? { next } : {}) }), warning }
    }
    if (args.action === "show") {
      const view = await showMandate(session, args.id, HELP)
      const next = view.state === "active" ? null : mandateNext(view, mandatePageLink(session, view.id))
      return plain({ ...view, ...(next ? { next } : {}) })
    }
    if (args.action === "uses") {
      const uses = await mandateUses(session, args.id, { since, before: args.before ?? null, limit: USES_LIMIT }, HELP)
      const truncated = uses.next !== null
      return plain({ mandate: args.id, ...(since === null ? {} : { since: new Date(since).toISOString() }), receipts: uses.receipts, truncated, next: uses.next, ...(truncated ? { note: `Cut at ${USES_LIMIT} receipts; pass before with next for older ones, or a shorter since.` } : {}) })
    }
    const paused = args.id === undefined ? await pauseLiveMandate(session, "mcp", HELP) : await pauseMandate(session, args.id, HELP)
    return plain({ mandate: paused.mandate, said: paused.said, ...(paused.next ? { next: paused.next } : {}) })
  },
})
