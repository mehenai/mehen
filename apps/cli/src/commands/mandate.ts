import { EXIT } from "@mehen/protocol/api"
import { MANDATE_CAP_DEFAULTS, MANDATE_RATE_LIMIT } from "@mehen/protocol/mandate-terms"
import type { ParsedArgs } from "../args.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { MANDATE_NEVER_COVERS, SCHEDULE_EXAMPLE, listMandates, listedMandateNeedingSigner, mandateLines, mandateNext, mandatePageLink, mandateProposal, mandateTableRows, mandateUses, openProposalLine, parseCapsFlag, parseSince, pauseLiveMandate, pauseMandate, proposeMandate, receiptTableRows, showMandate, splitFlag, stateText } from "../mandate-operations.ts"
import { note, printAsk, printJson, printLine, table } from "../output.ts"
import { openSession } from "../session.ts"
import { segments } from "../tty.ts"

const HELP = "mehen mandate --help"
const PROPOSED_THEN = "mehen mandate ls shows it again while it is open, and the mandate once it is signed"
const PROPOSE_FLAGS = ["items", "classes", "days", "caps", "schedule", "note", "reason"]
// The flags each action takes; anything else of this command's is refused.
const ACTION_FLAGS: Record<string, readonly string[]> = { propose: PROPOSE_FLAGS, ls: [], show: [], uses: ["since"], pause: [] }
const ALL_FLAGS = [...PROPOSE_FLAGS, "since"]
const REFUSED_ACTIONS: Record<string, string> = {
  resume: "A machine never resumes a mandate: the person who signed it resumes it from the mandate page.",
  stop: "A machine never stops a mandate: the person who signed it, or a workspace owner or admin, stops it from the mandate page. mehen mandate pause pauses it now.",
  sign: "A machine never signs a mandate: mehen mandate propose asks a person, who signs it with their passkey.",
}

function days(args: ParsedArgs): number | null {
  const text = args.string("days")
  if (text === null) return null
  if (!/^[0-9]{1,2}$/.test(text)) throw usageError("--days takes 1, 7, 30 or 90.", HELP)
  return Number(text)
}

export const mandateCommand: Command = {
  summary: "propose a mandate, list this machine's, follow what went through on trust, pause it",
  spec: {
    usage: "mehen mandate propose --note <text> [--items all|<slug>,...] [--classes read,change,send,delete] [--days 1|7|30|90] [--caps <class>=<n>,...] [--schedule <spec>] [--reason <text>] | ls | show <mdt_id> | uses <mdt_id> [--since <time>|30m|12h|7d] | pause [<mdt_id>]",
    flags: Object.fromEntries(ALL_FLAGS.map((name) => [name, { type: "string" as const }])),
    positionals: { min: 1, max: 2 },
  },
  examples: [
    ["mandate", "propose", "--note", "Nightly triage of the support inbox", "--items", "gmail-support,linear-work", "--classes", "read,change,send", "--caps", "send=20", "--schedule", "Europe/Paris mon-fri 08:00-19:00"],
    ["mandate", "ls"],
    ["mandate", "uses", "mdt_example", "--since", "1h"],
    ["mandate", "pause"],
  ],
  notes: [
    "A mandate lets this machine's held requests through without asking, within daily caps and until a date. A person signs it once, with their passkey, for their own machine; propose prints the link to hand them and exits 0; mehen mandate ls shows it again while it is open. Proposing the same terms again hands back the same link. They may change any term before signing.",
    `propose defaults: every credential this machine can use, all four classes (read is always included), 90 days, caps a day of ${MANDATE_CAP_DEFAULTS.read} reads, ${MANDATE_CAP_DEFAULTS.change} changes, ${MANDATE_CAP_DEFAULTS.send} sends and ${MANDATE_CAP_DEFAULTS.delete} deletes, at any time.`,
    `--schedule names the time zone once, then windows separated by ";": "${SCHEDULE_EXAMPLE}". Days are daily, or mon to sun with forward ranges (mon-fri) and commas; a window ending earlier than it starts runs past midnight.`,
    `A mandate never covers ${MANDATE_NEVER_COVERS}; those ask every time.`,
    `A cap reached makes that kind of request ask again until the next UTC day. More than ${MANDATE_RATE_LIMIT} requests beyond reading in a minute trips the whole mandate.`,
    "pause stops it covering anything now; with no id it pauses this machine's live mandate in this workspace, and refuses when there is none. This machine cannot resume, stop or sign one: the person who signed it resumes it from the mandate page, whose link show, ls and pause print (next.url in --json) for a paused, tripped or ended one.",
  ],
  async run({ args, json, env }) {
    const [action, id] = args.positionals
    const refused = REFUSED_ACTIONS[action ?? ""]
    if (refused) throw usageError(refused, HELP)
    const allowed = ACTION_FLAGS[action ?? ""]
    if (!allowed) throw usageError("Unknown mandate action: propose, ls, show, uses or pause.", HELP)
    const extra = ALL_FLAGS.find((name) => !allowed.includes(name) && args.string(name) !== null)
    if (extra) throw usageError(`mehen mandate ${action} takes no --${extra}.`, HELP)
    if (action === "propose" || action === "ls") {
      if (id !== undefined) throw usageError(`mehen mandate ${action} takes no id.`, HELP)
    } else if (id === undefined && action !== "pause") throw usageError(`mehen mandate ${action} takes one mandate id (mdt_...).`, HELP)
    if (action === "propose") {
      const items = args.string("items")
      const proposal = mandateProposal({
        items: items === "all" ? "all" : splitFlag(items),
        classes: splitFlag(args.string("classes")),
        days: days(args),
        caps: parseCapsFlag(args.string("caps"), HELP),
        schedule: args.string("schedule"),
        note: args.string("note") ?? "",
        reason: args.string("reason"),
      }, "cli", HELP)
      const result = await proposeMandate(await openSession(env), proposal, env, "cli")
      if (result.warning) note(`mehen: warning: ${result.warning}`)
      if (json) printJson({ ...result, terms: proposal.terms })
      else {
        if (result.existing) printLine("These terms are already waiting for the person to sign; this is the same link.")
        printAsk(result.ask, { env, noQr: args.bool("no-qr"), then: PROPOSED_THEN })
      }
      return EXIT.ok
    }
    const sinceText = args.string("since")
    const since = sinceText === null ? null : parseSince(sinceText, "--since", HELP)
    const session = await openSession(env)
    if (action === "ls") {
      const { mandates, proposals, warning } = await listMandates(session)
      if (warning) note(`mehen: warning: ${warning}`)
      const needing = listedMandateNeedingSigner(mandates)
      const url = needing ? mandatePageLink(session, needing.id) : null
      const next = needing ? mandateNext(needing, url) : null
      if (json) printJson({ mandates, proposals, ...(next ? { next } : {}) })
      else if (mandates.length === 0 && proposals.length === 0) printLine("No mandates for this machine. mehen mandate propose asks a person for one.")
      else {
        for (const proposal of proposals) printLine(segments(openProposalLine(proposal)))
        if (proposals.length > 0 && mandates.length > 0) printLine("")
        if (mandates.length > 0) for (const line of table(mandateTableRows(mandates))) printLine(line)
        if (needing) printLine(segments(`${needing.id}: ${stateText(needing, { url })}`))
      }
      return EXIT.ok
    }
    if (action === "pause") {
      const paused = id === undefined ? await pauseLiveMandate(session, "cli", HELP) : await pauseMandate(session, id, HELP)
      if (json) printJson({ mandate: paused.mandate, said: paused.said, ...(paused.next ? { next: paused.next } : {}) })
      else printLine(segments(paused.said))
      return EXIT.ok
    }
    const mandate = id as string
    if (action === "show") {
      const view = await showMandate(session, mandate, HELP)
      const url = view.state === "active" ? null : mandatePageLink(session, view.id)
      const next = mandateNext(view, url)
      if (json) printJson({ ...view, ...(next ? { next } : {}) })
      else for (const line of mandateLines(view, { url })) printLine(segments(line))
      return EXIT.ok
    }
    const { receipts } = await mandateUses(session, mandate, { since, before: null, limit: null }, HELP)
    if (json) printJson({ mandate, ...(since === null ? {} : { since: new Date(since).toISOString() }), receipts })
    else if (receipts.length === 0) printLine(segments(`Nothing has gone through on trust under ${mandate}${since === null ? "" : " in that time"}.`))
    else for (const line of table(receiptTableRows(receipts))) printLine(line)
    return EXIT.ok
  },
}
