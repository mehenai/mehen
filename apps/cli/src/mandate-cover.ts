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

// The hint as mehen hands it on: items is the credential the held request
// used, which mehen adds because it sent it (the relay's item, a plan
// entry's), so the propose it suggests names that credential alone.
export type MandateCover = MandateCoverHint & { items?: string[] }

// The hint as the vault sent it, with the credential mehen relayed when it
// named one, or null when it is not one.
export function readMandateCover(raw: unknown, item: string | null = null): MandateCover | null {
  const parsed = MandateCoverHintSchema.safeParse(raw)
  if (!parsed.success) return null
  return item === null ? parsed.data : { ...parsed.data, items: [item] }
}

// url: the vault's when it is this vault's page for the hint's mandate,
// else the one built from the mandate's id, else null.
export function checkedMandateCover(hint: MandateCover, vault: AskVault | null): MandateCover {
  if (hint.mandate === null || vault === null) return { ...hint, url: null }
  const given = askUrl(hint.url, vault)
  if (given?.route?.prefix === "mandates" && given.route.id === hint.mandate) return { ...hint, url: given.url }
  return { ...hint, url: mandatePageUrlFor(vault, hint.mandate)?.url ?? null }
}

// The one line for a held request, by state, with the propose the surface
// really takes for "none": the command, or vault_mandate's arguments when
// the server serves it, for
// the credential and the classes this request needs and nothing more; the
// length is left to the default, which the person may shorten.
export function mandateCoverText(hint: MandateCover, surface: MandateSurface, served: (tool: string) => boolean = () => true): string {
  const tool = surface === "mcp" && served("vault_mandate")
  const at = hint.url ? `at ${hint.url}` : "on its page"
  const classes = MANDATE_CLASSES.filter((c) => hint.classes.includes(c))
  const items = hint.items ?? ["<slug>"]
  switch (hint.state) {
    case "none": {
      const propose = !tool ? `\`mehen mandate propose --items ${items.join(",")} --classes ${classes.join(",")} --note "<why>"\`` : `vault_mandate { "action": "propose", "items": [${items.map((i) => `"${i}"`).join(", ")}], "classes": [${classes.map((c) => `"${c}"`).join(", ")}], "note": "<why>" }`
      return `A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one for only this credential and these kinds: ${propose}.`
    }
    case "paused":
    case "tripped":
      return `This machine's mandate is ${hint.state}; the person who signed it can resume it ${at}.`
    case "ended":
      return `This machine's mandate has ended; its signer can sign it again ${at}, or propose a new one.`
    case "outside_schedule":
      return `This machine's mandate does not cover this time; it covers its hours only${hint.url ? ` (${hint.url})` : ""}.`
    case "unticked":
      return `This machine's mandate does not name ${classes.join(", ")} requests with ${hint.items ? hint.items.join(", ") : "this credential"}; if this keeps asking, propose its terms again with only those added (${!tool ? `\`mehen mandate show ${hint.mandate ?? "<mdt_id>"}\`` : `vault_mandate { "action": "show", "id": "${hint.mandate ?? "<mdt_id>"}" }`} lists them).`
    case "not_covering":
      return `This machine's mandate is not covering requests right now; its signer can see why ${at}.`
  }
}
