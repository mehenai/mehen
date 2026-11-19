import { constants } from "node:fs"
import { open } from "node:fs/promises"
import { EXIT } from "@mehen/protocol/api"
import { POLICY_REQUEST_LIMIT } from "@mehen/protocol/policy-mode"
import type { ParsedArgs } from "../args.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { PREVIEW_REASON, RULE_ID_ONLY, type RuleProposalResult, type RuleSource, areaProposal, cancelPolicy, grantReceiptLines, listRules, listRulesAndGrants, proposeArea, liveRuleLines, liveRules, policyStateLines, previewRule, proposeRule, readBounded, readRuleProposal, revokeRule, ruleContext, ruleContextLine, rulePreviewLines, ruleProposal, ruleRequestText, ruleStatusLines, ruleTableRows, showPolicy } from "../policy-operations.ts"
import { note, printAsk, printJson, printLine, table } from "../output.ts"
import { openSession } from "../session.ts"
import { segments } from "../tty.ts"

const HELP = "mehen policy --help"
const EXAMPLE_FLAGS = ["item", "method", "url", "data", "content-type", "project", "env"]
const RULE_FLAGS = ["from", ...EXAMPLE_FLAGS, "path", "for", "reason"]
// A task grant's own flags, on propose only.
const AREA_FLAGS = ["area", "uses"]
const USE_PROPOSE = "use mehen policy propose --from <apr_id>, or --item, --method and --url."

// Flags of the policy windows standing rules replaced: each is refused with
// what to use instead, never ignored.
const REMOVED_FLAGS: Record<string, string> = {
  "policy-mode": `--policy-mode no longer exists; policy windows were replaced by standing rules: ${USE_PROPOSE}`,
  session: `--session no longer exists; a standing rule is for the key that asked: ${USE_PROPOSE}`,
  device: `--device no longer exists; a standing rule is for the key that asked: ${USE_PROPOSE}`,
  action: `--action no longer exists; policy windows were replaced by standing rules: ${USE_PROPOSE}`,
  "anchor-path": "--anchor-path no longer exists; the vault takes the anchor from the request: use --url, and --path for one of its path choices.",
  host: "--host no longer exists; use --url with the full address.",
  until: "--until no longer exists; use --for 1d, 7d or 30d.",
  file: `--file no longer exists; ${USE_PROPOSE}`,
  new: "--new no longer exists; cancel the pending proposal with mehen policy cancel <pol_id>, then propose again.",
}
const REMOVED_SWITCHES = new Set(["session", "device", "new"])

function given(args: ParsedArgs, name: string): boolean {
  return REMOVED_SWITCHES.has(name) || name === "no-context" || name === "grants" ? args.bool(name) : args.list(name).length > 0
}

// The flags each action takes; anything else of this command's is refused.
const ACTION_FLAGS: Record<string, readonly string[]> = {
  show: [], ls: ["item", "grants"], status: [], cancel: [], revoke: [], stop: [],
  preview: [...RULE_FLAGS, "no-context"], propose: [...RULE_FLAGS, "no-context", ...AREA_FLAGS],
}
const ALL_FLAGS = [...RULE_FLAGS, "no-context", ...AREA_FLAGS, "grants"]

function single(args: ParsedArgs, name: string, required = false): string | null {
  const values = args.list(name)
  if (values.length > 1 || required && values.length !== 1) throw usageError(`Give --${name} exactly once.`, "mehen policy --help")
  return values[0] ?? null
}

// Never reads more than the limit plus one byte, from a file or from stdin.
async function boundedBytes(path: string): Promise<Uint8Array | null> {
  if (path === "-") return readBounded(Bun.stdin.stream(), POLICY_REQUEST_LIMIT)
  // Non-blocking, so a FIFO is refused as not a regular file instead of waiting for a writer.
  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK)
  try {
    if (!(await handle.stat()).isFile()) throw new Error("not a regular file")
    const buffer = new Uint8Array(POLICY_REQUEST_LIMIT + 1)
    let total = 0
    for (;;) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, null)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > POLICY_REQUEST_LIMIT) return null
    }
    return buffer.slice(0, total)
  } finally {
    await handle.close()
  }
}

// The example body, from -d text, -d @file or -d - (stdin), read up to the limit.
async function exampleBody(data: string | null): Promise<Uint8Array | null> {
  if (data === null) return null
  if (data !== "-" && !data.startsWith("@")) return new TextEncoder().encode(data)
  let bytes: Uint8Array | null
  try {
    bytes = await boundedBytes(data === "-" ? "-" : data.slice(1))
  } catch {
    throw usageError("Cannot read the example body.", HELP)
  }
  if (bytes === null) throw usageError("The example body must fit in 32 KiB.", HELP)
  return bytes
}

// The request a rule is made from: --from a held or approved request, or an
// example named by --item, --method and --url.
async function ruleSource(args: ParsedArgs): Promise<RuleSource> {
  const from = single(args, "from")
  if (from !== null) {
    if (EXAMPLE_FLAGS.some((name) => args.list(name).length) || args.bool("no-context")) throw usageError("--from takes the request the vault holds, with its own context: give no --item, --method, --url, -d, --content-type, --project, --env or --no-context with it.", HELP)
    return { approval: from }
  }
  const item = single(args, "item"), method = single(args, "method"), url = single(args, "url")
  if (item === null || method === null || url === null) throw usageError("Name the request: --from <apr_id>, or --item, --method and --url.", HELP)
  const context = ruleContext(single(args, "project"), single(args, "env"), args.bool("no-context"), HELP)
  return { item, method, url, body: await exampleBody(single(args, "data")), contentType: single(args, "content-type"), context }
}

// --area: a task grant from the held or approved request --from names, on
// the credential --item names, for the areas listed (comma-separated or
// --area given again). The request's own context and mode go with it.
function areaRequest(args: ParsedArgs, reason: string) {
  const from = single(args, "from"), item = single(args, "item")
  if (from === null || item === null) throw usageError("A task grant is proposed from a held or approved request: give --from <apr_id> and --item <slug> with --area.", HELP)
  if (["method", "url", "data", "content-type", "project", "env", "path"].some((name) => args.list(name).length > 0) || args.bool("no-context")) throw usageError("--area takes the context of the request --from names: give no --method, --url, -d, --content-type, --project, --env, --path or --no-context with it.", HELP)
  const areas = args.list("area").flatMap((value) => value.split(",")).map((area) => area.trim())
  return areaProposal({ approval: from, item, areas, duration: single(args, "for"), uses: single(args, "uses"), reason }, HELP)
}

function printRuleProposal(result: RuleProposalResult, env: Record<string, string | undefined>, noQr: boolean): void {
  if (result.ask) {
    printAsk(result.ask, { env, noQr })
    return
  }
  printLine(segments(`Proposal ${result.proposal} is ${result.status}.`))
}

export const policyCommand: Command = {
  summary: "propose, list and revoke standing rules; show an item's policy",
  spec: {
    usage: "mehen policy show <item> | ls [--item <slug>] [--grants] | preview|propose (--from <apr_id> | --item <slug> --method <METHOD> --url <url> [-d <body>|@file|-] [--content-type <type>] [--project <prj_id> --env <name> | --no-context]) [--path <pattern>] [--for 1d|7d|30d] [--reason <text>] | propose --from <apr_id> --item <slug> --area <area>[,<area>] [--for 15m|1h|4h] [--uses N] --reason <text> | status <pol_id> | cancel <pol_id> | revoke <rul_id> | stop <rul_id> (deprecated: use revoke)",
    flags: {
      "no-context": { type: "boolean" }, session: { type: "boolean" }, device: { type: "boolean" }, new: { type: "boolean" }, grants: { type: "boolean" },
      ...Object.fromEntries([...RULE_FLAGS, ...AREA_FLAGS, "policy-mode", "action", "anchor-path", "host", "until", "file"].map((name) => [name, name === "data" ? { type: "list" as const, short: "d" } : { type: "list" as const }])),
    },
    positionals: { min: 1, max: 2 },
  },
  examples: [["policy", "show", "example-key"], ["policy", "propose", "--from", "apr_example", "--reason", "Create tasks without asking each time"], ["policy", "propose", "--from", "apr_example", "--item", "github-work", "--area", "issues", "--for", "1h", "--reason", "Triage the backlog"], ["policy", "ls", "--grants"], ["policy", "revoke", "rul_example"]],
  notes: [
    "A standing rule allows one kind of request from now on, for 1, 7 or 30 days, without asking each time.",
    "Rules never cover requests that send messages, move money, share or publish, change credentials or access, set up something that keeps running, or delete or remove something, nor protected environments or credentials holding a live key.",
    "No access changes before a human's passkey decision. The person approves each proposal on the vault page.",
    "propose --reason is required; preview needs none.",
    "propose --area asks for a task grant instead: routine work in the areas named (the service's reviewed list), for 15m, 1h or 4h (default 1h) and up to --uses requests (1 to 200, default 50), on the credential --item names and in the context --from was asked in. Never anything that always asks.",
    "ls lists standing rules; --grants lists task grants with them, each with its areas, uses out of its most, its end and what it was used for.",
  ],
  async run({ args, json, env }) {
    const [action, id] = args.positionals
    const allowed = ACTION_FLAGS[action ?? ""]
    if (!allowed) throw usageError("Unknown policy action. Agents cannot approve or set policy.", HELP)
    const removed = Object.keys(REMOVED_FLAGS).find((name) => given(args, name))
    if (removed) throw usageError(REMOVED_FLAGS[removed]!, HELP)
    const extra = ALL_FLAGS.find((name) => !allowed.includes(name) && given(args, name))
    if (extra) throw usageError(`mehen policy ${action} takes no --${extra}.`, HELP)
    if (action === "preview" || action === "propose") {
      if (id) throw usageError(`${action} takes no id.`, HELP)
      if (action === "propose" && (given(args, "area") || given(args, "uses"))) {
        if (!given(args, "area")) throw usageError("--uses is for a task grant: give --area with it.", HELP)
        const reason = single(args, "reason")
        if (reason === null) throw usageError("Give --reason: why the agent needs to carry on without asking. The person approving reads it.", HELP)
        const proposal = areaRequest(args, reason)
        const result = await proposeArea(await openSession(env), proposal)
        if (result.warning) note(result.warning)
        if (json) printJson(result)
        else printRuleProposal(result, env, args.bool("no-qr"))
        return EXIT.ok
      }
      const source = await ruleSource(args)
      const reason = single(args, "reason")
      if (reason === null && action === "propose") throw usageError("Give --reason: why the agent needs this request allowed from now on. The person approving reads it.", HELP)
      const proposal = ruleProposal({ source, path: single(args, "path"), duration: single(args, "for"), reason: reason ?? PREVIEW_REASON }, HELP)
      const session = await openSession(env)
      if (action === "preview") {
        const preview = await previewRule(session, proposal)
        if (json) printJson(preview)
        else for (const line of rulePreviewLines(preview)) printLine(segments(line))
        return EXIT.ok
      }
      const result = await proposeRule(session, proposal)
      const contextLine = ruleContextLine(source, "Give --project and --env to bind one.")
      note(contextLine)
      if (result.warning) note(result.warning)
      if (json) printJson({ ...result, note: contextLine })
      else printRuleProposal(result, env, args.bool("no-qr"))
      return EXIT.ok
    }
    if (action === "ls") {
      if (id) throw usageError("ls takes no id; --item narrows it to one credential.", HELP)
      const session = await openSession(env)
      const rules = args.bool("grants") ? await listRulesAndGrants(session, single(args, "item")) : await listRules(session, single(args, "item"))
      if (json) printJson(rules)
      else if (rules.length === 0) printLine(args.bool("grants") ? "No standing rules or task grants. mehen policy propose asks for one." : "No standing rules. mehen policy propose asks for one.")
      else {
        for (const line of table(ruleTableRows(rules))) printLine(line)
        const receipts = grantReceiptLines(rules)
        if (receipts.length > 0) printLine("Used for:")
        for (const line of receipts) printLine(segments(`  ${line}`))
      }
      return EXIT.ok
    }
    if (!id) throw usageError(action === "show" ? "show takes one item's slug." : action === "revoke" || action === "stop" ? `${action} takes one rule id (rul_...).` : `${action} takes one policy proposal id (pol_...).`, HELP)
    if (action === "revoke" || action === "stop") {
      if (!id.startsWith("rul_")) throw usageError(RULE_ID_ONLY, HELP)
      if (action === "stop") note("mehen policy stop is deprecated; use mehen policy revoke.")
      const rule = await revokeRule(await openSession(env), id)
      if (json) printJson(rule)
      else printLine(segments(`Revoked rule ${rule.id} (${ruleRequestText(rule)}). Requests it allowed ask for approval again.`))
      return EXIT.ok
    }
    const session = await openSession(env)
    if (action === "status") {
      const status = await readRuleProposal(session, id)
      if (json) printJson(status)
      else for (const line of ruleStatusLines(status)) printLine(segments(line))
      return EXIT.ok
    }
    if (action === "cancel") {
      const result = await cancelPolicy(session, id)
      if (json) printJson(result)
      else printLine(segments(result.status === "cancelled" ? `Cancelled policy proposal ${result.proposal}.` : `Policy proposal ${result.proposal} is ${result.status}.`))
      return EXIT.ok
    }
    const context = await showPolicy(session, id)
    const rules = await liveRules(session, id)
    if (json) printJson(rules === null ? context : { ...context, rules })
    else {
      printLine(segments(`${context.item}: ${context.effectiveMode} (durable mode: ${context.baseMode})`))
      printLine(segments(`Base policy: ${JSON.stringify(context.basePolicy)}`))
      printLine(segments(`Effective floors: ${JSON.stringify(context.floor)}`))
      for (const line of policyStateLines(context.state)) printLine(segments(line))
      if (rules !== null) {
        const [head, ...rows] = liveRuleLines(rules)
        printLine(segments(head?.[0] ?? ""))
        for (const line of table(rows)) printLine(line)
      }
    }
    return EXIT.ok
  },
}
