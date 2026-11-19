import { ADOPTION_ID } from "@mehen/protocol/adopt"
import { z } from "zod"
import { statusByPlanRefs } from "../adopt/state.ts"
import { askUrlFor } from "../ask.ts"
import { usageError } from "../errors.ts"
import { adoptionStatus } from "../operations.ts"
import { READS, WORKSPACE_ARG, plain, tool } from "./shared.ts"

export const vaultAdoptStatus = tool({
  name: "vault_adopt_status",
  title: "Adoption batch status",
  description:
    "Where an adoption batch (adp_) stands: its state, each machine's uploads, while open the staged rows, and after approval the slug made for each plan ref and any refused, with why. " +
    "Returns the checked review link. Never a value. To block until a human decides, use vault_wait.",
  input: z.object({ adoption: z.string().describe("the batch id, adp_..."), workspace: WORKSPACE_ARG }),
  annotations: READS,
  async call(args, deps) {
    if (!ADOPTION_ID.test(args.adoption)) throw usageError(`${JSON.stringify(args.adoption)} is not an adoption id (adp_...).`)
    const session = await deps.session(args.workspace)
    const status = await statusByPlanRefs(deps.env, await adoptionStatus(session.api, args.adoption))
    return plain({ ...status, url: askUrlFor(session.ledger, "adoption", args.adoption)?.url ?? null })
  },
})
