import type { RelayRequestInput } from "@mehen/protocol/api"
import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { FETCH_MAX_TIME_SECONDS, heldRequestNote, replayOwner, timedOut, withReplayNote } from "../commands/fetch.ts"
import { usageError } from "../errors.ts"
import { bodyForJson, rejectedHint, type UpstreamHead, fetchContext, parseSelectPath, readLimited, relayReplaces, relayRequest, replacingRefused, selectBody, upstreamHead } from "../operations.ts"
import { mandateAllowed, mandateCapped } from "../mandate-operations.ts"
import { type PostureAllowed, type RuleAllowed, postureAllowed, ruleEnded, rulesAllowed } from "../policy-operations.ts"
import { type ClaimedRequest, assertSavedBy, claimSavedRequest, neverSent, readSavedRequest, replayClock } from "../replay-cache.ts"
import { type VaultSession, sessionLabel, sessionWithLabel } from "../session.ts"
import { retrySafeMethod } from "../vault-api.ts"
import { type ToolCall, type ToolDeps, type ToolOutput, WORKSPACE_ARG, outputSchema, plain, tool } from "./shared.ts"
import { FETCH_BODY_LIMIT } from "./constants.ts"

export function decodeBase64(text: string): Bytes {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(text)) throw usageError("bodyBase64 is not base64.")
  return new Uint8Array(Buffer.from(text, "base64"))
}

const MCP_SELECT = { option: "select", help: "mehen fetch --help" }

type FetchHead = UpstreamHead & { rules?: RuleAllowed[]; postures?: PostureAllowed[]; mandate?: string; hint?: string }

// vault_fetch's result without select: the body as text, cut at 256 KiB.
async function fetchOutput(head: FetchHead, response: Response, method: string): Promise<ToolOutput> {
  const { bytes, truncated, size } = await readLimited(response, FETCH_BODY_LIMIT, method)
  return bodyOutput(head, bytes, truncated, size, [], method)
}

// A read cut short can be sent again to get the rest; a write cannot.
function bodyOutput(head: FetchHead, bytes: Bytes, truncated: boolean, size: number | null, notes: string[], method: string): ToolOutput {
  const strict = truncated ? null : bodyForJson(bytes)
  const text = strict && "body" in strict ? strict.body : new TextDecoder().decode(bytes)
  const cut = `The body was cut at 256 KiB${size ? ` of ${size} bytes` : ""}`
  if (truncated) notes.push(retrySafeMethod(method) ? `${cut}; pass select to pick the part you need from the whole response, or use \`mehen fetch -o <file>\` in a shell to save all of it.` : `${cut}. Sending the request again will not recover the rest and may do it twice: read the result back with a separate read, or ask the person.`)
  if (strict && "bodyBase64" in strict) notes.push("The body is not UTF-8 text; invalid bytes are shown as replacement characters.")
  return plain({ ...head, body: text, truncated, ...(notes.length ? { note: notes.join(" ") } : {}) })
}

type RelayOptions = { select?: string | undefined; timeoutSeconds?: number | undefined }

// One request through the relay, as vault_fetch answers it. A held answer
// saves the request for sending again once approved.
async function relayOutput(session: VaultSession, source: RelayRequestInput | (() => Promise<ClaimedRequest>), options: RelayOptions, deps: ToolDeps, call: ToolCall): Promise<ToolOutput> {
  const select = options.select === undefined ? null : parseSelectPath(options.select, MCP_SELECT)
  const { api } = session
  // A saved request is claimed only now, once every local check has passed.
  const claimed = typeof source === "function" ? await source() : null
  const request = claimed ? claimed.request : (source as RelayRequestInput)
  const timeout = options.timeoutSeconds === undefined ? null : AbortSignal.timeout(options.timeoutSeconds * 1000)
  const signal = timeout ? AbortSignal.any([call.signal, timeout]) : call.signal
  let reached = false
  // Read before the relay call starts: the saved request's hour runs from here.
  const sentAt = replayClock.now()
  try {
    const response = await api.relay(request, { signal })
    reached = true
    await claimed?.spent()
    const upstream = upstreamHead(response)
    const rules = await rulesAllowed(api, response, request.item ?? null, signal)
    const postures = postureAllowed(response)
    const mandate = mandateAllowed(response)
    const hint = await rejectedHint(api, upstream, request.item ?? null, signal)
    const head = { ...upstream, ...(rules ? { rules } : {}), ...(postures ? { postures } : {}), ...(mandate ? { mandate } : {}), ...(hint ? { hint } : {}) }
    if (select !== null) {
      const { bytes } = await readLimited(response, Number.POSITIVE_INFINITY, request.method)
      const chosen = selectBody(bytes, head.status, request.method, select, MCP_SELECT)
      if (!chosen.json) {
        const cut = bytes.length > FETCH_BODY_LIMIT
        const output = bodyOutput(head, cut ? bytes.slice(0, FETCH_BODY_LIMIT) : bytes, cut, bytes.length, [chosen.note], request.method)
        return { ...output, structured: { ...output.structured, selected: null, found: false } }
      }
      const picked = chosen.picked
      return plain({ ...head, selected: picked.value, found: picked.found, ...(picked.found ? {} : { note: `select ${options.select} matched nothing in the body.` }) })
    }
    return await fetchOutput(head, response, request.method)
  } catch (error) {
    if (claimed && !reached) await (neverSent(error, request, signal) ? claimed.unsent() : claimed.spent())
    if (timeout?.aborted && !call.signal.aborted && options.timeoutSeconds !== undefined) throw timedOut(options.timeoutSeconds, request.method)
    const held = call.signal.aborted ? null : await heldRequestNote(deps.env, session, request, error, sentAt)
    throw withReplayNote(replacingRefused(ruleEnded(await mandateCapped(api, error, signal)), request, "mcp"), held)
  }
}

// The request saved for an approval, sent again once from the enrolment
// that saved it, signed with the session label it was held with:
// vault_fetch with approval alone, and vault_wait with execute.
export async function resumeVaultFetch(approval: string, deps: ToolDeps, call: ToolCall, options: RelayOptions & { workspace?: string | undefined } = {}): Promise<ToolOutput> {
  if (options.select !== undefined) parseSelectPath(options.select, MCP_SELECT)
  const saved = await readSavedRequest(deps.env, approval)
  const opened = await deps.session(options.workspace ?? saved.workspace)
  assertSavedBy(saved, replayOwner(opened))
  const session = await sessionWithLabel(deps.env, opened, saved.request.session ?? null)
  return relayOutput(session, () => claimSavedRequest(deps.env, saved, replayOwner(session)), options, deps, call)
}

export const vaultFetch = tool({
  name: "vault_fetch",
  title: "Send a request with a credential",
  description:
    "One HTTP request with an item's credential, added by the vault on the way to an upstream in the item's binding. Returns status, headers and body (text, at most 256 KiB; select picks JSON from up to 32 MiB). " +
    "Any upstream status is a success here: read `status`, and `hint` if the credential was rejected. A refusal is an error with `next`; one needing a human carries `ask`: hand it over, call vault_wait, do not retry.",
  input: z.object({
    item: z.string().optional().describe("the item to use (or run)"),
    run: z.string().optional().describe("a mehen run id whose placeholders the request carries (instead of item)"),
    method: z.string().optional().describe("HTTP method"),
    url: z.string().optional().describe("the full upstream URL"),
    headers: z.record(z.string(), z.string()).optional().describe("request headers, without the credential"),
    body: z.string().optional().describe("request body as text"),
    bodyBase64: z.string().optional().describe("request body as base64, for binary bodies"),
    approval: z.string().optional().describe("an approved apr_ id; alone, it sends the saved request"),
    replaces: z.string().optional().describe("your open apr_ ask this corrected request supersedes"),
    context: z.object({ project: z.string().describe("prj_..."), environment: z.string().describe("its name") }).optional().describe("the project environment it is used for, for a protected, team or guest credential; never changes the workspace"),
    select: z.string().optional().describe("one part of a JSON response, such as data.0.id (. for all), returned as `selected` from the whole response"),
    timeoutSeconds: z.number().int().min(1).max(FETCH_MAX_TIME_SECONDS).optional().describe("stop waiting after this many seconds; a write then is outcome_unknown"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  output: outputSchema({ statusText: "string", headers: "object", body: "string", truncated: "boolean", found: "boolean", note: "string", rules: "array", postures: "array" }),
  async call(args, deps, call) {
    if (args.method === undefined && args.url === undefined && args.item === undefined && args.run === undefined) {
      if (args.approval === undefined) throw usageError("Give method and url with item or run, or approval alone to send the request saved when it was held.", "vault_fetch")
      const given = (["headers", "body", "bodyBase64", "replaces", "context"] as const).filter((name) => args[name] !== undefined)
      if (given.length > 0) throw usageError(`approval alone sends the request saved for it as it was; leave out ${given.join(", ")}.`, "vault_fetch")
      return resumeVaultFetch(args.approval, deps, call, { select: args.select, timeoutSeconds: args.timeoutSeconds, workspace: args.workspace })
    }
    if (args.method === undefined || args.url === undefined) throw usageError("Give method and url together, with item or run; or approval alone to send a saved request.", "vault_fetch")
    if (args.body !== undefined && args.bodyBase64 !== undefined) throw usageError("Give body or bodyBase64, not both.")
    const body = args.body !== undefined ? utf8(args.body) : args.bodyBase64 !== undefined ? decodeBase64(args.bodyBase64) : null
    const request = relayRequest({
      item: args.item ?? null,
      run: args.run ?? null,
      method: args.method,
      url: args.url,
      headers: Object.entries(args.headers ?? {}),
      body,
      approval: args.approval ?? null,
      replaces: relayReplaces(args.replaces ?? null, "mcp"),
      session: sessionLabel(deps.env),
      context: args.context ? fetchContext(args.context.project, args.context.environment, "vault_fetch") : null,
    })
    return relayOutput(await deps.session(args.workspace), request, { select: args.select, timeoutSeconds: args.timeoutSeconds }, deps, call)
  },
})
