// An agent's plan of several writes, asked for at once (mehen plan submit,
// mehen check --plan, vault_plan). Each request is built exactly as mehen
// fetch builds it (parseHeader, then relayRequest), so the later mehen
// fetch ... --approval apr_... sends the same bytes and the vault finds its
// approval. The vault answers with a bundle: one Review together page for
// every request it holds for a human.

import { readFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { APPROVAL_BUNDLE_MAX, type ApprovalBundleCreated, type NextStep, type RelayRequestInput } from "@mehen/protocol/api"
import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import type { MandateCoverHint } from "@mehen/protocol/mandate-terms"
import { z } from "zod"
import { type Ask, type AskVault, askUrl, askUrlFor, bundleAsk, isAskId, refusedLinkWarning, requestedBy, withContext } from "./ask.ts"
import type { Env } from "./config.ts"
import { CliError, usageError } from "./errors.ts"
import { addLedgerEntry } from "./ledger.ts"
import { checkedMandateCover, readMandateCover } from "./mandate-cover.ts"
import { decodeBase64 } from "./mcp/vault-fetch.ts"
import { type HomeSurface, fetchContext, parseHeader, relayRequest, shellWord } from "./operations.ts"
import { type VaultSession, sessionLabel } from "./session.ts"
import { VaultApiError } from "./vault-api.ts"

// The vault reads at most this many bytes of one JSON body (its
// MAX_JSON_BYTES); a bigger bundle is refused here, before anything is sent.
export const BUNDLE_MAX_BYTES = 1_000_000

const PlanRequestSchema = z.strictObject({
  item: z.string(),
  method: z.string(),
  url: z.string(),
  headers: z.array(z.string()).max(100).optional(),
  body: z.string().optional(),
  bodyBase64: z.string().optional(),
})

// version 1. project and env name the project environment every request is
// used for, as --project and --env do on mehen fetch.
export const PlanSchema = z.strictObject({
  version: z.literal(1),
  reason: z.string().max(200).optional(),
  project: z.string().optional(),
  env: z.string().optional(),
  requests: z.array(PlanRequestSchema).min(1),
})

// Where a plan came from: a file, whose "@name" bodies are files beside it,
// or a tool call, whose bodies are inline text or base64 only.
export type PlanSource = { kind: "file"; path: string } | { kind: "inline" }

// A request's body as the plan gave it: a file mehen read, or bytes.
type PlanData = { file: string; bytes: Bytes } | { file: null; bytes: Bytes }

// One request of a plan: what goes to the vault, and what repeats it.
export type PlanRequest = { request: RelayRequestInput; item: string; method: string; url: string; headers: string[]; data: PlanData | null }

export type ParsedPlan = { reason: string | null; context: { project: string; environment: string } | null; requests: PlanRequest[] }

function helpFor(surface: HomeSurface): string {
  return surface === "cli" ? "mehen plan --help" : "vault_plan"
}

async function planData(entry: z.infer<typeof PlanRequestSchema>, source: PlanSource, help: string): Promise<PlanData | null> {
  if (entry.body !== undefined && entry.bodyBase64 !== undefined) throw usageError("give body or bodyBase64, not both.", help)
  if (entry.bodyBase64 !== undefined) return { file: null, bytes: decodeBase64(entry.bodyBase64) }
  if (entry.body === undefined) return null
  if (source.kind === "inline") return { file: null, bytes: utf8(entry.body) }
  if (entry.body === "-") throw usageError('a plan body cannot be read from stdin ("-"); give text, "@file" or bodyBase64.', help)
  if (!entry.body.startsWith("@")) return { file: null, bytes: utf8(entry.body) }
  const file = resolve(dirname(source.path), entry.body.slice(1))
  try {
    return { file, bytes: new Uint8Array(await readFile(file)) }
  } catch (error) {
    throw usageError(`cannot read the body from ${file}: ${(error as Error).message}`, help)
  }
}

// What is wrong with a plan's shape, each issue under a request naming it
// counted from 1.
function planIssues(error: z.ZodError): string {
  return error.issues
    .map(({ path, message }) => {
      const [top, index, ...rest] = path
      if (top !== "requests" || typeof index !== "number") return path.length ? `${path.join(".")}: ${message}` : message
      return `Request ${index + 1} of the plan: ${rest.length ? `${rest.join(".")}: ` : ""}${message}`
    })
    .join("; ")
}

// The plan as the vault will get it, or a usage error naming the request
// (counted from 1) and what is wrong with it.
export async function parsePlan(raw: unknown, source: PlanSource, env: Env, surface: HomeSurface): Promise<ParsedPlan> {
  const help = helpFor(surface)
  const where = source.kind === "file" ? `The plan ${source.path}` : "The plan"
  const listed = (raw as { requests?: unknown } | null)?.requests
  if (Array.isArray(listed) && listed.length > APPROVAL_BUNDLE_MAX) throw usageError(`${where} has ${listed.length} requests; a bundle holds at most ${APPROVAL_BUNDLE_MAX}. Split it into plans of ${APPROVAL_BUNDLE_MAX} or fewer.`, help)
  const parsed = PlanSchema.safeParse(raw)
  if (!parsed.success) throw usageError(`${where} is not a plan mehen can read: ${planIssues(parsed.error)}`, help)
  const plan = parsed.data
  const context = fetchContext(plan.project ?? null, plan.env ?? null, help)
  const session = sessionLabel(env)
  const requests: PlanRequest[] = []
  for (const [index, entry] of plan.requests.entries()) {
    try {
      const headers = entry.headers ?? []
      const data = await planData(entry, source, help)
      const request = relayRequest({ item: entry.item, run: null, method: entry.method, url: entry.url, headers: headers.map(parseHeader), body: data?.bytes ?? null, approval: null, session, context })
      requests.push({ request, item: entry.item, method: entry.method, url: entry.url, headers, data })
    } catch (error) {
      if (error instanceof CliError && error.code === "usage") throw usageError(`Request ${index + 1} of the plan: ${error.message}`, help)
      throw error
    }
  }
  return { reason: plan.reason ?? null, context, requests }
}

// The body of POST /v1/approvals/bundles, refused here when the vault would
// not read it all.
export function bundleBody(plan: ParsedPlan, surface: HomeSurface): { requests: RelayRequestInput[]; reason?: string } {
  const body = { requests: plan.requests.map((r) => r.request), ...(plan.reason !== null ? { reason: plan.reason } : {}) }
  const size = utf8(JSON.stringify(body)).length
  if (size > BUNDLE_MAX_BYTES) throw usageError(`The plan's requests come to ${size} bytes; the vault reads at most ${BUNDLE_MAX_BYTES} in one bundle. Split it into smaller plans.`, helpFor(surface))
  return body
}

// UTF-8 text that reads back as the same bytes, or null.
function exactText(bytes: Bytes): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)
  } catch {
    return null
  }
}

// One option of a repeat. A value starting with - goes inline
// (--<name>=<value>), since parseArgs reads a separate argument starting
// with -- as the next option.
function optionWords(flag: string, name: string, value: string): string[] {
  return value.startsWith("-") ? [`--${name}=${value}`] : [flag, value]
}

// mehen fetch for the request with its headers, context and approval, and
// body: the body's words, already written for a shell.
function fetchLine(entry: PlanRequest, context: ParsedPlan["context"], approval: string | null, body: string[]): string {
  const head = ["mehen", "fetch", entry.item, entry.method, entry.url, ...entry.headers.flatMap((header) => optionWords("-H", "header", header))]
  const tail = [...(context ? [...optionWords("--project", "project", context.project), ...optionWords("--env", "env", context.environment)] : []), ...(approval ? ["--approval", approval] : [])]
  return [...head.map(shellWord), ...body, ...tail.map(shellWord)].join(" ")
}

// The shell command that sends the same request again, with its approval
// when it has one: -d '<text>' for a text body, -d @<absolute path> for a
// body read from a file. Null when no -d can carry the body: bytes that are
// not UTF-8, text holding NUL (which no command-line argument carries), or
// text mehen fetch would read as a file ("@...") or stdin ("-"), as
// --data=<text> would too.
export function repeatCommand(entry: PlanRequest, context: ParsedPlan["context"], approval: string | null): string | null {
  if (!entry.data) return fetchLine(entry, context, approval, [])
  if (entry.data.file) return fetchLine(entry, context, approval, ["-d", `@${entry.data.file}`].map(shellWord))
  const text = exactText(entry.data.bytes)
  if (text === null || text.includes("\u0000") || text.startsWith("@") || text === "-") return null
  return fetchLine(entry, context, approval, optionWords("-d", "data", text).map(shellWord))
}

// vault_fetch's arguments that send the same request again, with its
// approval when it has one.
export type PlanFetch = {
  item: string
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  bodyBase64?: string
  context?: { project: string; environment: string }
  approval?: string
}

// The fetch for a request, or why vault_fetch's headers record cannot hold
// its headers as the bundle sent them (a name given twice, or an order a
// record does not keep).
export function planFetch(entry: PlanRequest, context: ParsedPlan["context"], approval: string | null): { fetch: PlanFetch } | { why: string } {
  const headers = entry.request.headers
  const record = Object.fromEntries(headers)
  if (JSON.stringify(Object.entries(record)) !== JSON.stringify(headers)) {
    const twice = headers.find(([name], index) => headers.findIndex(([other]) => other === name) !== index)
    return { why: twice ? `the header ${twice[0]} given twice` : "these headers in the order the bundle sent them" }
  }
  const text = entry.data ? exactText(entry.data.bytes) : null
  const body = !entry.data ? {} : text !== null ? { body: text } : { bodyBase64: Buffer.from(entry.data.bytes).toString("base64") }
  return {
    fetch: { item: entry.item, method: entry.request.method, url: entry.request.url, headers: record, ...body, ...(context ? { context } : {}), ...(approval ? { approval } : {}) },
  }
}

// The repeat with a placeholder for the file that holds the body's bytes.
function fileRepeat(entry: PlanRequest, context: ParsedPlan["context"], approval: string | null): string {
  return `write the same bytes to a file and run ${fetchLine(entry, context, approval, ["-d", "@<a file holding these bytes>"])}`
}

function noRepeatNote(entry: PlanRequest, context: ParsedPlan["context"], approval: string | null, surface: HomeSurface): string {
  const head = "The body is not text a shell command can carry, so there is no repeat"
  if (surface === "mcp") return `${head}: pass fetch to vault_fetch as it is.`
  return `${head}: ${fileRepeat(entry, context, approval)}`
}

function noFetchNote(why: string, repeat: string | null, entry: PlanRequest, context: ParsedPlan["context"], approval: string | null): string {
  const head = `vault_fetch's headers record cannot hold ${why}, so there is no fetch`
  if (repeat !== null) return `${head}: send this request with its repeat in a shell instead.`
  return `${head} and no repeat, since the body is not text a shell command can carry: ${fileRepeat(entry, context, approval)}`
}

const BUNDLES_UNAVAILABLE = "Asking for several requests at once is not available yet."

// A vault without batch approvals refuses a bundle as forbidden, and one
// older still has no route for it; either way the requests go one by one.
function bundlesRefused(error: unknown, surface: HomeSurface): unknown {
  if (!(error instanceof VaultApiError)) return error
  const off = error.body.error === "forbidden" && error.body.next === undefined && error.body.message === BUNDLES_UNAVAILABLE
  if (!off && error.status !== 404) return error
  const fetch = surface === "cli" ? "mehen fetch" : "vault_fetch"
  return new CliError("forbidden", off ? BUNDLES_UNAVAILABLE : "This vault does not take several requests at once.", { say: `Send the requests one by one with ${fetch}; each that needs approval asks on its own.` })
}

const APPROVAL_ID = /^apr_[A-Za-z0-9_-]{1,60}$/

const CreatedSchema = z.object({
  bundle: z.string(),
  url: z.unknown(),
  expiresAt: z.string(),
  results: z.array(
    z.object({
      index: z.number().int().nonnegative(),
      outcome: z.enum(["ask", "allowed", "refused"]),
      approval: z.string().regex(APPROVAL_ID).optional(),
      bindingCode: z.string().optional(),
      error: z.object({ error: z.string(), message: z.string(), next: z.unknown().optional() }).optional(),
      mandateCover: z.unknown().optional(),
    }),
  ),
})

// What one request of a submitted plan came to. index counts from 0, as the
// vault's results do. repeat: the shell command that sends it (with its
// approval), or null with a note when there is none.
export type PlanResult = {
  index: number
  item: string
  method: string
  url: string
  outcome: "ask" | "allowed" | "refused"
  approval?: string
  bindingCode?: string
  error?: { error: string; message: string; next?: NextStep }
  // An ask only: a mandate could let requests like this through, and why
  // this one asked, its link checked against this vault.
  mandateCover?: MandateCoverHint
  repeat: string | null
  // vault_plan only: the vault_fetch arguments that send it, or null.
  fetch?: PlanFetch | null
  note?: string
}

// url and ask are null when the context has no workspace slug, so no /g/
// link can be checked; the bundle is still made and mehen wait follows it.
export type PlanSubmitted = { bundle: string; url: string | null; expiresAt: string; ask: Ask | null; results: PlanResult[]; refusedLink: boolean }

function unreadable(): CliError {
  return new CliError("internal", "The vault's answer to the bundle is not one mehen can read.", { say: "Check the vault URL and try again; if it keeps failing, report it with this message." })
}

// A refused request's next, with its link only when it is on this vault.
function refusalNext(raw: unknown, vault: AskVault): NextStep | undefined {
  if (typeof raw !== "object" || raw === null) return undefined
  const { url, command, say } = raw as Record<string, unknown>
  const link = url === undefined ? null : askUrl(url, vault)
  const next = { ...(link ? { url: link.url } : {}), ...(typeof command === "string" ? { command } : {}), say: typeof say === "string" ? say : "" }
  return next.say || next.command || "url" in next ? next : undefined
}

// Sends the plan as one bundle, records its ask in the ledger (so mehen wait
// and vault_wait find it), and returns each request's outcome with its
// repeat. `command` is what asks again, for the ledger.
export async function submitPlan(session: VaultSession, plan: ParsedPlan, env: Env, options: { surface: HomeSurface; command: string | null }): Promise<PlanSubmitted> {
  const body = bundleBody(plan, options.surface)
  let answer: unknown
  try {
    answer = await session.api.request<ApprovalBundleCreated>("POST", "/v1/approvals/bundles", body)
  } catch (error) {
    throw bundlesRefused(error, options.surface)
  }
  const parsed = CreatedSchema.safeParse(answer)
  if (!parsed.success) throw unreadable()
  const created = parsed.data
  const scope = session.ledger
  if (!isAskId("bundle", created.bundle)) throw unreadable()
  const link = askUrlFor(scope, "bundle", created.bundle)
  const given = link ? askUrl(created.url, scope) : null
  const refusedLink = !(given && given.route?.prefix === "g" && given.route.id === created.bundle)
  const mcp = options.surface === "mcp"
  const byIndex = new Map(created.results.map((r) => [r.index, r]))
  if (byIndex.size !== created.results.length || created.results.length !== plan.requests.length) throw unreadable()
  const results: PlanResult[] = plan.requests.map((entry, index) => {
    const result = byIndex.get(index)
    if (!result || (result.outcome === "ask" && result.approval === undefined)) throw unreadable()
    const head = { index, item: entry.item, method: entry.request.method, url: entry.url, outcome: result.outcome }
    if (result.outcome === "refused") {
      const next = refusalNext(result.error?.next, scope)
      return { ...head, error: { error: result.error?.error ?? "internal", message: result.error?.message ?? "The vault refused this request.", ...(next ? { next } : {}) }, repeat: null, ...(mcp ? { fetch: null } : {}) }
    }
    const approval = result.approval ?? null
    const cover = result.outcome === "ask" ? readMandateCover(result.mandateCover) : null
    const repeat = repeatCommand(entry, plan.context, approval)
    const fetch = mcp ? planFetch(entry, plan.context, approval) : null
    const note = fetch && "why" in fetch ? noFetchNote(fetch.why, repeat, entry, plan.context, approval) : repeat === null ? noRepeatNote(entry, plan.context, approval, options.surface) : null
    return {
      ...head,
      ...(approval ? { approval } : {}),
      ...(result.outcome === "ask" && result.bindingCode !== undefined ? { bindingCode: result.bindingCode } : {}),
      ...(cover ? { mandateCover: checkedMandateCover(cover, scope) } : {}),
      repeat,
      ...(fetch ? { fetch: "fetch" in fetch ? fetch.fetch : null } : {}),
      ...(note !== null ? { note } : {}),
    }
  })
  const asks = results.filter((r) => r.outcome === "ask")
  const codes = asks.every((r) => r.bindingCode !== undefined) ? asks.map((r) => r.bindingCode as string) : null
  const by = requestedBy(env, session.config.name ?? null)
  const ask = link && asks.length ? withContext(bundleAsk({ id: created.bundle, url: link.url, codes, asks: asks.length, reason: plan.reason, expiresAt: created.expiresAt, requestedBy: by }), session.context) : null
  if (ask) await addLedgerEntry(session.configDir, scope, { ask, slug: null, command: options.command })
  return { bundle: created.bundle, url: link?.url ?? null, expiresAt: created.expiresAt, ask, results, refusedLink }
}

// The warning when mehen did not show the vault's link to the bundle.
export function bundleLinkWarning(submitted: PlanSubmitted, vault: AskVault): string | null {
  if (!submitted.refusedLink) return null
  return `${refusedLinkWarning(vault)} ${submitted.url ? "mehen built the bundle's link from its id instead." : "This context has no workspace slug to build the bundle's link from."}`
}

// What comes next when there is no ask to hand over: following the bundle
// when requests wait for a human but mehen has no link to show, else
// sending the allowed ones.
export function unaskedNext(submitted: PlanSubmitted, surface: HomeSurface): NextStep {
  if (planCounts(submitted.results).ask) {
    const say = "Requests of this plan wait for a human, but mehen has no link to show for them: ask the human to review them in the vault"
    if (surface === "mcp") return { say: `${say}, then call vault_wait with ${submitted.bundle}.` }
    return { command: `mehen wait ${submitted.bundle} --timeout 60 --json`, say: `${say}, then follow the bundle with mehen wait.` }
  }
  if (surface === "mcp") return { say: "Nothing in this plan waits for a human: pass each allowed request's fetch to vault_fetch as it is; do not retry a refused one without asking the human." }
  return { say: "Nothing in this plan waits for a human: send each allowed request with its repeat; do not retry a refused one without asking the human." }
}

export type PlanCounts = { ask: number; allowed: number; refused: number }

export function planCounts(results: readonly { outcome: PlanResult["outcome"] }[]): PlanCounts {
  return { ask: results.filter((r) => r.outcome === "ask").length, allowed: results.filter((r) => r.outcome === "allowed").length, refused: results.filter((r) => r.outcome === "refused").length }
}

// The shape the vault compares asks by: the item, method, host and path.
// Groups of two or more requests of a plan with the same shape (indexes
// from 0), so an agent sees where it may have listed one write twice.
export function sameShapes(plan: ParsedPlan): number[][] {
  const groups = new Map<string, number[]>()
  for (const [index, entry] of plan.requests.entries()) {
    const url = new URL(entry.request.url)
    const key = JSON.stringify([entry.item, entry.request.method, url.host, url.pathname])
    groups.set(key, [...(groups.get(key) ?? []), index])
  }
  return [...groups.values()].filter((indexes) => indexes.length > 1)
}
