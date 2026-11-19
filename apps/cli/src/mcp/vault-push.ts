import { PushDestinationSchema } from "@mehen/protocol/push"
import { z } from "zod"
import { pushRequest, requestPush } from "../operations.ts"
import { WORKSPACE_ARG, tool } from "./shared.ts"

export const vaultPush = tool({
  name: "vault_push",
  title: "Push a credential into a secret store",
  description:
    "Ask for one secret field of a credential to be put into a GitHub Actions, environment or Dependabot secret, a Vercel variable or a Cloudflare Worker secret. Every push needs a human's approval: the error is approval_required with `ask`, a checked link; hand it over with the destination and the code to check, then call vault_wait with the approval id, which ends once the vault has sent it (or the provider refused, provider_refused with providerStatus). The vault sends the value itself; it never reaches you. " +
    "A credential must first be allowed, on its page, to be put into other services' secret stores (mode_refused with that page's link). Never push again after a failure without asking the human.",
  input: z.object({
    item: z.string().describe("the credential to push, e.g. openai-prod"),
    field: z.string().optional().describe("which secret field, e.g. key; without it, the main secret field of the credential's kind"),
    to: PushDestinationSchema.describe("where it goes"),
    with: z.string().optional().describe("the GitHub, Vercel or Cloudflare credential that writes it; without it, the one this machine may use for that provider"),
    reason: z.string().optional().describe("why it is needed there; the human sees this"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  async call(args, deps) {
    const request = pushRequest({ item: args.item, field: args.field ?? null, to: args.to, with: args.with ?? null, reason: args.reason ?? null }, "vault_push")
    const { api } = await deps.session(args.workspace)
    return { structured: await requestPush(api, request), handover: [], warning: null }
  },
})
