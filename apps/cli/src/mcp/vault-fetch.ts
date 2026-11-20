import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { FETCH_MAX_TIME_SECONDS, timedOut } from "../commands/fetch.ts"
import { usageError } from "../errors.ts"
import { bodyForJson, rejectedHint, type UpstreamHead, fetchContext, parseSelectPath, readLimited, relayReplaces, relayRequest, replacingRefused, selectBody, upstreamHead } from "../operations.ts"
import { mandateAllowed, mandateCapped } from "../mandate-operations.ts"
import { type PostureAllowed, type RuleAllowed, postureAllowed, ruleEnded, rulesAllowed } from "../policy-operations.ts"
import { sessionLabel } from "../session.ts"
import { retrySafeMethod } from "../vault-api.ts"
import { type ToolOutput, WORKSPACE_ARG, outputSchema, plain, tool } from "./shared.ts"
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

export const vaultFetch = tool({
  name: "vault_fetch",
  title: "Send a request with a credential",
  description:
    "Make one HTTP request with an item's credential: the vault adds it on the way to the upstream, which must be in the item's binding. Returns the upstream status, headers and body as the vault returns them (text, at most 256 KiB, possibly decompressed, scrubbed or with headers removed). select takes a JSON field from the full response, up to 32 MiB. " +
    "Any upstream status is a success here; read `status`, and `hint` if the credential was rejected. A vault refusal is an error with `next`; when a human must approve or reconnect, it also carries `ask` and a link: hand them over and call vault_wait with the id, do not retry.",
  input: z.object({
    item: z.string().optional().describe("the item to use (or run)"),
    run: z.string().optional().describe("a mehen run id whose placeholders the request carries (instead of item)"),
    method: z.string().describe("HTTP method"),
    url: z.string().describe("the full upstream URL"),
    headers: z.record(z.string(), z.string()).optional().describe("request headers, without the credential"),
    body: z.string().optional().describe("request body as text"),
    bodyBase64: z.string().optional().describe("request body as base64, for binary bodies"),
    approval: z.string().optional().describe("an approved apr_ id, when retrying after an approval"),
    replaces: z.string().optional().describe("your open apr_ ask this corrected request supersedes; for several writes use vault_plan"),
    context: z.object({ project: z.string().describe("the project id (prj_...)"), environment: z.string().describe("the environment name") }).optional().describe("the project environment the credential is used for; needed for a protected, team or guest credential. Never changes the workspace."),
    select: z.string().optional().describe('one part of a JSON response, by keys and indexes: data.0.id, .items[2]["display name"], or . for all; returned as `selected` instead of `body`, from the whole response however large'),
    timeoutSeconds: z.number().int().min(1).max(FETCH_MAX_TIME_SECONDS).optional().describe("stop waiting after this many seconds: a read is then a network error, a write outcome_unknown"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  output: outputSchema({ statusText: "string", headers: "object", body: "string", truncated: "boolean", found: "boolean", note: "string", rules: "array", postures: "array" }),
  async call(args, deps, call) {
    if (args.body !== undefined && args.bodyBase64 !== undefined) throw usageError("Give body or bodyBase64, not both.")
    const select = args.select === undefined ? null : parseSelectPath(args.select, MCP_SELECT)
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
    const { api } = await deps.session(args.workspace)
    const timeout = args.timeoutSeconds === undefined ? null : AbortSignal.timeout(args.timeoutSeconds * 1000)
    const signal = timeout ? AbortSignal.any([call.signal, timeout]) : call.signal
    try {
      const response = await api.relay(request, { signal })
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
        return plain({ ...head, selected: picked.value, found: picked.found, ...(picked.found ? {} : { note: `select ${args.select} matched nothing in the body.` }) })
      }
      return await fetchOutput(head, response, request.method)
    } catch (error) {
      if (timeout?.aborted && !call.signal.aborted && args.timeoutSeconds !== undefined) throw timedOut(args.timeoutSeconds, request.method)
      throw replacingRefused(ruleEnded(await mandateCapped(api, error, signal)), request, "mcp")
    }
  },
})
