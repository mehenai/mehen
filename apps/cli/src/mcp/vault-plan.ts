import { APPROVAL_BUNDLE_MAX } from "@mehen/protocol/api"
import { z } from "zod"
import { askNext } from "../ask.ts"
import { PlanSchema, bundleLinkWarning, parsePlan, planCounts, submitPlan, unaskedNext } from "../approval-plan.ts"
import { checkPlan } from "../commands/check.ts"
import { mandateCoverText } from "../mandate-cover.ts"
import { WORKSPACE_ARG, handing, mcpThen, plain, servedBy, tool } from "./shared.ts"

export const vaultPlan = tool({
  name: "vault_plan",
  title: "Plan several writes for one review",
  description:
    `Several writes asked for at once, reviewed together by a human at one link. action check: each request against its item's stored binding and base policy, as \`mehen check\` does (advisory only), with the counts. action submit: the vault checks each request as vault_fetch would without sending any, and holds those that need a human in one bundle; hand over its ask and call vault_wait with the bnd_ id. ` +
    `Each result has its outcome (ask, allowed or refused), its approval id, mandateCover on an ask a mandate could cover (state says why it asked), and fetch (the vault_fetch arguments that send it, approval and context included); once approved, pass each fetch to vault_fetch as it is. At most ${APPROVAL_BUNDLE_MAX} requests; bodies are inline text (body) or bytes (bodyBase64), never files. A vault without bundles refuses forbidden: send the requests one by one with vault_fetch.`,
  input: z.object({
    action: z.enum(["check", "submit"]),
    plan: PlanSchema.describe('{ version: 1, reason?, project?, env?, requests: [{ item, method, url, headers?: ["Name: value"], body? | bodyBase64? }] }; project and env (the project environment, as vault_fetch context) go together'),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async call(args, deps) {
    const plan = await parsePlan(args.plan, { kind: "inline" }, deps.env, "mcp")
    const session = await deps.session(args.workspace)
    if (args.action === "check") {
      const { check } = await checkPlan(session.api, plan)
      return { ...plain(check), text: ["Local base-policy advice only. Live windows, floors, protection and grants are not included; this cannot predict permission to send. vault_plan submit asks the vault."] }
    }
    const submitted = await submitPlan(session, plan, deps.env, { surface: "mcp", command: null })
    const warning = bundleLinkWarning(submitted, session.ledger)
    const { ask, refusedLink: _refused, ...out } = submitted
    const next = ask ? askNext(ask, { command: null }) : unaskedNext(submitted, "mcp")
    const covers = submitted.results.flatMap((r) => (r.mandateCover ? [`request ${r.index + 1}: ${mandateCoverText(r.mandateCover, "mcp", servedBy(deps))}`] : []))
    const output = handing({ ...out, ...(ask ? { ask } : {}), next, counts: planCounts(submitted.results), ...(warning ? { warning } : {}) }, ask, warning, ask ? mcpThen(ask) : null)
    return covers.length > 0 ? { ...output, text: covers } : output
  },
})
