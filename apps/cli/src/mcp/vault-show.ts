import { summarisePolicy } from "@mehen/protocol/policy-summary"
import { z } from "zod"
import { showItem } from "../operations.ts"
import { READS, WORKSPACE_ARG, plain, tool } from "./shared.ts"

export const vaultShow = tool({
  name: "vault_show",
  title: "Show a credential",
  description:
    "Show one item's public metadata: kind, account, the hosts it may be sent to, its policy and `policySummary` (what goes through without a human, what needs approval, what is refused). Never the value.",
  input: z.object({ item: z.string().describe("the item's slug, e.g. openai-personal"), workspace: WORKSPACE_ARG }),
  annotations: READS,
  async call(args, deps) {
    const item = await showItem((await deps.session(args.workspace)).api, args.item)
    return plain({ ...item, policySummary: summarisePolicy(item.policy) })
  },
})
