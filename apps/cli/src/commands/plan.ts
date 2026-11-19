// mehen plan submit: several writes asked for at once. The vault runs each
// request of the plan through the relay's checks without sending any, and
// holds those that need a human in one bundle, reviewed together at one
// link; each request then goes with its own mehen fetch ... --approval.

import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { APPROVAL_BUNDLE_MAX, EXIT } from "@mehen/protocol/api"
import { askNext } from "../ask.ts"
import { type PlanResult, type PlanSubmitted, bundleLinkWarning, parsePlan, planCounts, submitPlan, unaskedNext } from "../approval-plan.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { mandateCoverText } from "../mandate-cover.ts"
import { shellWord } from "../operations.ts"
import { note, printAsk, printJson, printLine } from "../output.ts"
import { openSession } from "../session.ts"

const HELP = "mehen plan --help"

// The plan file as JSON, or a usage error that names it.
export async function readPlanFile(path: string, help: string): Promise<unknown> {
  let text: string
  try {
    text = await readFile(path, "utf8")
  } catch (error) {
    throw usageError(`Cannot read the plan ${path}: ${(error as Error).message}`, help)
  }
  try {
    return JSON.parse(text) as unknown
  } catch (error) {
    throw usageError(`The plan ${path} is not JSON: ${(error as Error).message}`, help)
  }
}

function resultLine(result: PlanResult): string {
  const head = `request ${result.index + 1}: ${result.method} ${result.url} with ${result.item}`
  if (result.outcome === "refused") return `${head}: refused (${result.error?.error ?? "refused"}): ${result.error?.message ?? ""}`
  if (result.outcome === "allowed") return `${head}: allowed without asking${result.approval ? ` (approved as ${result.approval})` : ""}`
  return `${head}: waits for approval ${result.approval}${result.bindingCode ? `, code ${result.bindingCode}` : ""}`
}

function printSubmitted(submitted: PlanSubmitted): void {
  for (const result of submitted.results) {
    printLine(resultLine(result))
    if (result.mandateCover) printLine(`  mandate: ${mandateCoverText(result.mandateCover, "cli")}`)
    if (result.repeat) printLine(`  repeat: ${result.repeat}`)
    else if (result.note) printLine(`  ${result.note}`)
    else if (result.error?.next?.say) printLine(`  next: ${result.error.next.say}`)
  }
  const counts = planCounts(submitted.results)
  if (counts.ask) {
    if (!submitted.ask) printLine(unaskedNext(submitted, "cli").say)
    printLine(`then:    mehen wait ${submitted.bundle}`)
    return
  }
  const parts = [counts.allowed ? `${counts.allowed} can be sent now with the repeat commands above` : null, counts.refused ? `${counts.refused} ${counts.refused === 1 ? "was" : "were"} refused` : null].filter((part) => part !== null)
  printLine(`Nothing in this plan waits for a human: ${parts.join("; ")}.`)
}

export const planCommand: Command = {
  summary: "ask for several writes at once, reviewed together at one link (mehen plan submit <plan.json>)",
  spec: { usage: "mehen plan submit <plan.json>", flags: {}, positionals: { min: 2, max: 2 } },
  examples: [["plan", "submit", "plan.json"], ["plan", "submit", "infra/contoso-plan.json", "--json"]],
  notes: [
    `The plan is JSON: { "version": 1, "reason": "<why, for the human>", "project": "prj_...", "env": "<name>", "requests": [{ "item": "<slug>", "method": "POST", "url": "https://...", "headers": ["Content-Type: application/json"], "body": "@body.json" }] }. reason, project, env, headers and body are optional; project and env go together, as --project and --env on mehen fetch.`,
    `A body is text, or "@file" relative to the plan, as -d on mehen fetch; bodyBase64 carries bytes instead. At most ${APPROVAL_BUNDLE_MAX} requests, and at most 1000000 bytes as the vault receives them.`,
    "Nothing is sent upstream. The vault checks each request as mehen fetch would and holds those that need a human in one bundle: one link to review them together, which mehen wait bnd_... follows. Each request's outcome is ask, allowed or refused, with repeat: the exact mehen fetch that sends it, with --approval once it is approved. A body no shell command can carry gets no repeat and a note instead.",
    "Exits 0 whenever the vault made the bundle, whatever each request's outcome; a refusal of the whole plan exits as that error. A vault without bundles is refused as forbidden: send the requests one by one with mehen fetch.",
  ],
  async run({ args, json, env }) {
    const [step, file] = args.positionals as [string, string]
    if (step !== "submit") throw usageError(`Unknown plan step ${JSON.stringify(step)}; use submit (and mehen check --plan to check a plan first).`, HELP)
    const path = resolve(file)
    const plan = await parsePlan(await readPlanFile(path, HELP), { kind: "file", path }, env, "cli")
    const session = await openSession(env)
    const submitted = await submitPlan(session, plan, env, { surface: "cli", command: `mehen plan submit ${shellWord(path)}` })
    const warning = bundleLinkWarning(submitted, session.ledger)
    if (warning) note(`mehen: warning: ${warning}`)
    const { ask, refusedLink: _refused, ...out } = submitted
    if (json) {
      const next = ask ? askNext(ask) : unaskedNext(submitted, "cli")
      printJson({ ...out, ...(ask ? { ask } : {}), next, counts: planCounts(submitted.results) })
      return EXIT.ok
    }
    if (ask) printAsk(ask, { env, noQr: args.bool("no-qr"), then: null })
    printSubmitted(submitted)
    return EXIT.ok
  },
}
