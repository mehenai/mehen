// mandateCover on approval_required, to this machine itself: a mandate could
// let requests like this one through, and why this one asked. Its link is
// the machine's mandate page, checked against this vault as every link is;
// the line said for it by state never says why a mandate is not covering
// beyond what the state names.

import { MANDATE_CLASSES, type MandateCoverHint, MandateClassSchema, MandateIdSchema } from "@mehen/protocol/mandate-terms"
import { z } from "zod"
import { type AskVault, askUrl, mandatePageUrlFor } from "./ask.ts"
import type { MandateSurface } from "./mandate-operations.ts"

const MANDATE_COVER_STATES = ["none", "paused", "tripped", "ended", "outside_schedule", "unticked", "not_covering"] as const satisfies readonly MandateCoverHint["state"][]

export const MandateCoverHintSchema = z.object({
  classes: z.array(MandateClassSchema).min(1).max(MANDATE_CLASSES.length),
  state: z.enum(MANDATE_COVER_STATES),
  mandate: MandateIdSchema.nullable(),
  url: z.string().nullable(),
}) satisfies z.ZodType<MandateCoverHint>

// The hint as the vault sent it, or null when it is not one.
export function readMandateCover(raw: unknown): MandateCoverHint | null {
  const parsed = MandateCoverHintSchema.safeParse(raw)
  return parsed.success ? parsed.data : null
}

// url: the vault's when it is this vault's page for the hint's mandate,
// else the one built from the mandate's id, else null.
export function checkedMandateCover(hint: MandateCoverHint, vault: AskVault | null): MandateCoverHint {
  if (hint.mandate === null || vault === null) return { ...hint, url: null }
  const given = askUrl(hint.url, vault)
  if (given?.route?.prefix === "mandates" && given.route.id === hint.mandate) return { ...hint, url: given.url }
  return { ...hint, url: mandatePageUrlFor(vault, hint.mandate)?.url ?? null }
}

// The one line for a held request, by state, with the propose the surface
// really takes for "none": the command, or vault_mandate's arguments.
export function mandateCoverText(hint: MandateCoverHint, surface: MandateSurface): string {
  const at = hint.url ? `at ${hint.url}` : "on its page"
  switch (hint.state) {
    case "none": {
      const classes = MANDATE_CLASSES.filter((c) => hint.classes.includes(c))
      const propose = surface === "cli" ? `\`mehen mandate propose --classes ${classes.join(",")} --note "<why>"\`` : `vault_mandate { "action": "propose", "classes": [${classes.map((c) => `"${c}"`).join(", ")}], "note": "<why>" }`
      return `A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one: ${propose}.`
    }
    case "paused":
    case "tripped":
      return `This machine's mandate is ${hint.state}; the person who signed it can resume it ${at}.`
    case "ended":
      return `This machine's mandate has ended; its signer can sign it again ${at}, or propose a new one.`
    case "outside_schedule":
      return `This machine's mandate does not cover this time; it covers its hours only${hint.url ? ` (${hint.url})` : ""}.`
    case "unticked":
      return "This machine's mandate does not name this kind of request or this credential; if this keeps asking, propose wider terms."
    case "not_covering":
      return `This machine's mandate is not covering requests right now; its signer can see why ${at}.`
  }
}
