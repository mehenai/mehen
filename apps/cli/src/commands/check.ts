// mehen check: a local dry run of one request against an item's binding and
// policy, with the protocol's own matcher (UX-MEHEN-TOOLS 2.5). It fetches the
// item's public metadata and nothing else: no relay call, no approval
// created, nothing sent upstream. Advisory every time: the vault decides.

import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { EXIT, type ExitCode, type ItemDescription } from "@mehen/protocol/api"
import { type Binding, type BindingCheck, type Destination, type Policy, bindingCutWords, checkBinding, evaluatePolicy, isLeaseOnly, parseDestination } from "@mehen/protocol/binding"
import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import { type PolicyRuleAnchor, areaGrantEntry, postureCovers } from "@mehen/protocol/policy-rules"
import { type ParsedPlan, parsePlan, sameShapes } from "../approval-plan.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { type VaultApi } from "../vault-api.ts"
import { type HomeSurface, parseHeader, showItem } from "../operations.ts"
import { type PolicySession, listRulesAndGrants } from "../policy-operations.ts"
import { grantTerms, isGrant } from "../policy-responses.ts"
import { clockText } from "../ask.ts"
import { printJson, printLine } from "../output.ts"
import { openSession } from "../session.ts"
import { readPlanFile } from "./plan.ts"
import { type Styler, type Text, colourEnabled, segments, styler } from "../tty.ts"

export type CheckDecision = "allow" | "approve" | "deny" | "binding_refused"

export type CheckMatch = { action: "allow" | "approve" | "deny"; note: string | null }

export type CheckResult = {
  item: string
  method: string
  url: string
  decision: CheckDecision
  matched: CheckMatch[]
  // Why the binding refused, when it did.
  reason: string | null
  // True when the item's rules read the body and none was given, so the
  // restrictive rules were taken to match.
  bodyUnknown: boolean
  advisory: true
  scope: "base-policy-only"
  mayCover?: CheckMayCover
}

// A hint that a request the base policy holds may go through without
// asking: a live task grant of this key whose areas take the request's
// catalogue entry, or the credential's posture for this machine. Never a
// floor refusal, a live key or a request outside the binding (the
// protocol's own areaGrantEntry and postureCovers).
export type CheckMayCover =
  | { kind: "grant"; id: string; areas: string[]; endsAt: string; uses: number; maxUses: number }
  | { kind: "posture"; level: "routine" | "trust" }

export const CHECK_EXIT: Record<CheckDecision, ExitCode> = { allow: EXIT.ok, approve: EXIT.approval, deny: EXIT.refused, binding_refused: EXIT.refused }

const ADVISORY = "Advisory: local base policy only. Live windows, floors, protection and grants are not included; this cannot predict permission to send. The real fetch enforces current authority."

function bindingReason(check: BindingCheck, binding: Binding, dest: Destination): string {
  if (check.ok) return ""
  if (isLeaseOnly(binding)) return "no host: the vault never sends this credential to a service"
  if (check.reason === "host") return `host ${dest.host} is not ${binding.hosts.join(" or ")}`
  if (check.reason === "scheme") return `scheme ${dest.scheme} is not ${(binding.schemes ?? ["https", "wss"]).join(" or ")}`
  if (check.reason === "port") return `port ${dest.port} is not ${(binding.ports ?? []).join(" or ") || "the default"}`
  if (check.reason === "path") return `path ${dest.path}${check.cutAt ? `, ${bindingCutWords(check.cutAt)},` : ""} is not under ${(binding.paths ?? []).join(", ")}`
  return `method ${dest.method} is not ${(binding.methods ?? []).join(" or ")}`
}

// Local stored-policy evaluation, not live authorisation.
export function checkRequest(input: { item: string; method: string; url: string; binding: Binding; policy: Policy; body: Bytes | null }): CheckResult {
  const parsed = parseDestination(input.method, input.url)
  if (!parsed.ok) throw usageError(`Invalid request: the URL cannot be checked (${parsed.error}).`, "mehen check --help")
  const dest = parsed.destination
  const head = { item: input.item, method: dest.method, url: input.url }
  const binding = checkBinding(input.binding, dest)
  if (!binding.ok) return { ...head, decision: "binding_refused", matched: [], reason: bindingReason(binding, input.binding, dest), bodyUnknown: false, advisory: true, scope: "base-policy-only" }
  const decision = evaluatePolicy(input.policy, dest, input.body)
  const bodyUnknown = input.body === null && decision.action !== "allow" && input.policy.rules.some((r) => r.body !== undefined)
  return { ...head, decision: decision.action, matched: decision.matched.map((r) => ({ action: r.action, note: r.note ?? null })), reason: null, bodyUnknown, advisory: true, scope: "base-policy-only" }
}

// The request as the vault would hold it for a grant or a posture: this
// key, the item's binding and policy, and the prefixes of its secrets (a
// live key is never covered). contentType: the -H Content-Type given, as
// mehen fetch would send it.
function checkAnchor(item: ItemDescription, destination: Destination, body: Bytes | null, contentType: string | null, key: { itemId: string; asker: PolicyRuleAnchor["asker"] }): PolicyRuleAnchor {
  return { item: item.slug, itemId: key.itemId, asker: key.asker, destination, body, contentType, contentEncoding: null, policy: item.policy, binding: item.binding as Binding, secretPrefixes: item.secretFields.map((f) => f.prefix).filter((p) => p !== "") }
}

// What may let a held request through, in the vault's order: a task grant,
// then the posture; null when neither may. Only a hint, never consulted for
// the decision or the exit code: the vault decides at send time, from the
// credential's protection, the request's mode and the grant's state then,
// none of which this machine can see. A request the base policy allows or
// refuses gets none.
export async function checkMayCover(session: Pick<PolicySession, "api">, item: ItemDescription, result: CheckResult, body: Bytes | null, contentType: string | null, now = Date.now()): Promise<CheckMayCover | null> {
  if (result.decision !== "approve") return null
  const parsed = parseDestination(result.method, result.url)
  if (!parsed.ok) return null
  let grants: Awaited<ReturnType<typeof listRulesAndGrants>>
  try {
    grants = await listRulesAndGrants(session as PolicySession, item.slug)
  } catch {
    grants = []
  }
  // Only a live grant made outside any project, as mehen check sends none.
  for (const grant of grants.filter(isGrant)) {
    if (grant.status !== "active" || Date.parse(grant.endsAt) <= now || grant.uses >= grant.maxUses || grant.context !== null) continue
    const entry = areaGrantEntry(grantTerms(grant), checkAnchor(item, parsed.destination, body, contentType, grant))
    if (entry !== null) return { kind: "grant", id: grant.id, areas: grant.areas, endsAt: grant.endsAt, uses: grant.uses, maxUses: grant.maxUses }
  }
  const posture = item.posture
  if (posture?.coversThisKey && (posture.level === "routine" || posture.level === "trust") && posture.catalogue !== null) {
    if (postureCovers(posture.level, posture.catalogue, checkAnchor(item, parsed.destination, body, contentType, { itemId: "", asker: { device: "", workload: null } })) !== null) return { kind: "posture", level: posture.level }
  }
  return null
}

// "A task grant on issues may cover this (rul_x, 3 of 50 uses, ends 16:40); the vault decides when it is sent."
export function mayCoverText(hint: CheckMayCover, options: { now?: Date; timeZone?: string } = {}): string {
  if (hint.kind === "posture") return hint.level === "routine" ? "This credential's posture lets routine building through and may cover this; the vault decides when it is sent." : "This credential trusts this machine and may cover this; the vault decides when it is sent."
  return `A task grant on ${hint.areas.join(", ")} may cover this (${hint.id}, ${hint.uses} of ${hint.maxUses} uses, ends ${clockText(hint.endsAt, options) ?? hint.endsAt}); the vault decides when it is sent.`
}

function quoted(matched: CheckMatch[]): string {
  const notes = matched.map((m) => (m.note ? `"${m.note}"` : "a rule without a note"))
  return notes.join(", ")
}

// The human lines (UX-MEHEN-TOOLS 2.5), the verdict word coloured on a TTY.
export function checkLines(result: CheckResult, policyDefault: Policy["default"], colour: Styler): Text[] {
  const rule = result.matched.length ? `${quoted(result.matched)} (${result.matched[0]?.action} rule${result.decision === "approve" ? `; policy default ${policyDefault}` : ""})` : `no rule matched; policy default ${policyDefault}`
  if (result.decision === "binding_refused") return [segments(colour.danger("outside the binding"), `: ${result.reason ?? ""}`), `  ${ADVISORY} Read mehen policy show ${result.item} for current state.`]
  if (result.decision === "allow") return [segments(colour.ok("allowed"), `: ${rule}`), `  ${ADVISORY} Read mehen policy show ${result.item} for current state.`]
  if (result.decision === "deny") return [segments(colour.danger("refused"), `: ${rule}`), `  ${ADVISORY} Read mehen policy show ${result.item} for current state.`]
  const lines: Text[] = [segments(colour.warn("needs approval"), `: ${rule}`)]
  if (result.mayCover) lines.push(`  ${mayCoverText(result.mayCover)}`)
  lines.push("  The base policy asks for approval. The real request may have a different result.")
  if (result.bodyUnknown) lines.push("  No body was given (-d), so rules that read the body were taken to match; check again with the body to be sure.")
  lines.push(`  ${ADVISORY} Read mehen policy show ${result.item} for current state.`)
  return lines
}

// ---------------------------------------------------------------- --plan

// Each request of a plan through checkRequest, as one plan check: how many
// the base policies let through, hold for approval or refuse, which requests
// share a shape, and the worst outcome's exit code. Indexes count from 0.
export type PlanCheck = {
  results: (CheckResult & { index: number })[]
  counts: { allow: number; approve: number; refuse: number }
  sameShape: number[][]
  advisory: true
  scope: "base-policy-only"
}

const SEVERITY: Record<CheckDecision, number> = { allow: 0, approve: 1, deny: 2, binding_refused: 2 }

export async function checkPlan(api: VaultApi, plan: ParsedPlan): Promise<{ check: PlanCheck; exit: ExitCode; defaults: Map<string, Policy["default"]> }> {
  const items = new Map<string, Awaited<ReturnType<typeof showItem>>>()
  for (const entry of plan.requests) if (!items.has(entry.item)) items.set(entry.item, await showItem(api, entry.item))
  const results = plan.requests.map((entry, index) => {
    const item = items.get(entry.item)!
    return { index, ...checkRequest({ item: item.slug, method: entry.method, url: entry.url, binding: item.binding, policy: item.policy, body: entry.data?.bytes ?? null }) }
  })
  const counts = { allow: results.filter((r) => r.decision === "allow").length, approve: results.filter((r) => r.decision === "approve").length, refuse: results.filter((r) => r.decision === "deny" || r.decision === "binding_refused").length }
  const worst = results.reduce<CheckDecision>((acc, r) => (SEVERITY[r.decision] > SEVERITY[acc] ? r.decision : acc), "allow")
  const defaults = new Map([...items].map(([slug, item]) => [slug, item.policy.default]))
  return { check: { results, counts, sameShape: sameShapes(plan), advisory: true, scope: "base-policy-only" }, exit: CHECK_EXIT[worst], defaults }
}

export function planCheckLines(check: PlanCheck, defaults: Map<string, Policy["default"]>, colour: Styler, surface: HomeSurface): Text[] {
  const lines: Text[] = []
  for (const result of check.results) {
    const [first, ...rest] = checkLines(result, defaults.get(result.item) ?? "approve", colour).filter((line) => !(typeof line === "string" && line.includes(ADVISORY)))
    lines.push(segments(`request ${result.index + 1} (${result.method} ${result.url}): `, first ?? ""), ...rest)
  }
  const { allow, approve, refuse } = check.counts
  lines.push(`${allow} would go through, ${approve} would ask and ${refuse} would be refused, by the base policies.`)
  for (const group of check.sameShape) {
    lines.push(`Requests ${group.map((i) => i + 1).join(", ")} go to the same place (item, method, host and path); a bundle keeps every one, so check you meant each.`)
  }
  lines.push(`  ${ADVISORY} ${surface === "cli" ? "mehen plan submit" : "vault_plan submit"} asks the vault.`)
  return lines
}

async function readData(data: string | null): Promise<Bytes | null> {
  if (data === null) return null
  if (data === "-") return new Uint8Array(await Bun.stdin.arrayBuffer())
  if (data.startsWith("@")) {
    try {
      return new Uint8Array(await readFile(data.slice(1)))
    } catch (error) {
      throw usageError(`Cannot read the body from ${data.slice(1)}: ${(error as Error).message}`, "mehen check --help")
    }
  }
  return utf8(data)
}

export const checkCommand: Command = {
  summary: "evaluate an item's base policy locally (advisory, not permission to send)",
  spec: {
    usage: "mehen check <item> <METHOD> <URL> [-H 'Name: value']... [-d @file|-|text]   (or mehen check --plan <plan.json>)",
    flags: { header: { type: "list", short: "H" }, data: { type: "string", short: "d" }, plan: { type: "string" } },
    positionals: { min: 0, max: 3 },
  },
  examples: [
    ["check", "openai-personal", "GET", "https://api.openai.com/v1/models"],
    ["check", "gmail-personal", "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", "-d", "@message.json", "--json"],
    ["check", "--plan", "plan.json"],
  ],
  notes: [
    "Exits 0 (base allow), 3 (base approval) or 5 (base refusal).",
    "A request the base policy holds is also checked against this key's live task grants and the credential's posture (how careful it is) for this machine, as a request outside any project: a line names a grant or posture that may cover it, and --json carries it as mayCover. Only a hint: the vault decides when the request is sent, and the exit code stays the base policy's. Give -H 'Content-Type: ...' as mehen fetch would send it.",
    "--plan checks every request of a mehen plan submit plan the same way: how many would go through, ask or be refused, and which share a shape (the same item, method, host and path). It exits as its worst request; --json prints { results, counts, sameShape } with each result's index counted from 0.",
    "Fetches the item's public metadata from the vault and evaluates its base binding and policy locally. It sends no request upstream and creates no approval. Its answer is advisory, not permission to send; live scope, protection, policy floors and grants can change the result.",
  ],
  async run({ args, json, env }) {
    const planFile = args.string("plan")
    if (planFile !== null) {
      if (args.positionals.length > 0 || args.list("header").length > 0 || args.string("data") !== null) throw usageError("--plan checks the requests in the plan; give no item, method, URL, -H or -d with it.", "mehen check --help")
      const path = resolve(planFile)
      const plan = await parsePlan(await readPlanFile(path, "mehen check --help"), { kind: "file", path }, env, "cli")
      const { api } = await openSession(env)
      const { check, exit, defaults } = await checkPlan(api, plan)
      if (json) printJson(check)
      else for (const line of planCheckLines(check, defaults, styler(colourEnabled(process.stdout, env)), "cli")) printLine(line)
      return exit
    }
    if (args.positionals.length !== 3) throw usageError("Usage: mehen check <item> <METHOD> <URL>, or mehen check --plan <plan.json>.", "mehen check --help")
    const [slug, method, url] = args.positionals as [string, string, string]
    const headers = args.list("header").map(parseHeader)
    const contentType = headers.filter(([name]) => name.toLowerCase() === "content-type").at(-1)?.[1] ?? null
    const body = await readData(args.string("data"))
    const session = await openSession(env)
    const item = await showItem(session.api, slug)
    const base = checkRequest({ item: item.slug, method, url, binding: item.binding, policy: item.policy, body })
    const mayCover = await checkMayCover(session, item, base, body, contentType)
    const result: CheckResult = mayCover ? { ...base, mayCover } : base
    if (json) {
      printJson(result)
      return CHECK_EXIT[result.decision]
    }
    for (const line of checkLines(result, item.policy.default, styler(colourEnabled(process.stdout, env)))) printLine(line)
    return CHECK_EXIT[result.decision]
  },
}
