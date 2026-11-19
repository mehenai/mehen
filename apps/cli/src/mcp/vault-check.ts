import { utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { checkRequest } from "../commands/check.ts"
import { showItem } from "../operations.ts"
import { READS, WORKSPACE_ARG, outputSchema, plain, tool } from "./shared.ts"

export const vaultCheck = tool({
  name: "vault_check",
  title: "Check a request against base policy",
  description: "Local base-policy advice only: evaluate this request against stored item binding and base policy without sending it. Live windows, floors, protection and grants are not included; this cannot predict permission to send. Creates no approval and never returns a secret.",
  input: z.object({
    item: z.string().describe("the item's slug"),
    method: z.string().describe("HTTP method"),
    url: z.string().describe("the full upstream URL"),
    headers: z.record(z.string(), z.string()).optional().describe("request headers, without the credential; the decision does not depend on them"),
    body: z.string().optional().describe("request body as text, when the item's policy reads bodies (vault_show lists its rules)"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: READS,
  output: outputSchema({ method: "string", url: "string", decision: "string", matched: "array", reason: ["string", "null"], bodyUnknown: "boolean", advisory: "boolean", scope: "string" }),
  async call(args, deps) {
    const item = await showItem((await deps.session(args.workspace)).api, args.item)
    const body = args.body !== undefined ? utf8(args.body) : null
    const result = checkRequest({ item: item.slug, method: args.method, url: args.url, binding: item.binding, policy: item.policy, body })
    return { ...plain(result), text: [`Local base-policy advice only. Live windows, floors, protection and grants are not included; this cannot predict permission to send. Read mehen policy show ${item.slug} for current state. The real fetch enforces current authority.`] }
  },
})
