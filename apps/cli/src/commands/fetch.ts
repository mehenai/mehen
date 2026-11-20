// mehen fetch: one HTTP request through the vault relay. The vault injects the
// item's secret; the upstream body comes back on stdout byte for byte.

import { constants } from "node:fs"
import { type FileHandle, lstat, open, readFile } from "node:fs/promises"
import { EXIT } from "@mehen/protocol/api"
import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import type { Command } from "../command.ts"
import type { RelayRequestInput } from "@mehen/protocol/api"
import type { Env } from "../config.ts"
import { CliError, outcomeUnknown, toCliError, usageError } from "../errors.ts"
import {
  type UpstreamHead,
  bodyForJson,
  parseDurationSeconds,
  parseHeader,
  selectBody,
  parseSelectPath,
  readChunk,
  readLimited,
  fetchContext,
  rejectedHint,
  relayReplaces,
  relayRequest,
  replacingRefused,
  upstreamHead,
} from "../operations.ts"
import { mandateAllowed, mandateAllowedText, mandateCapped } from "../mandate-operations.ts"
import { note, printJson, writeStdout } from "../output.ts"
import { postureAllowed, postureAllowedText, ruleAllowedText, ruleEnded, rulesAllowed } from "../policy-operations.ts"
import { type ClaimedRequest, type ReplayNote, type ReplayOwner, assertSavedBy, claimSavedRequest, neverSent, readSavedRequest, saveHeldRequest } from "../replay-cache.ts"
import { type VaultSession, openSession, sessionLabel, sessionWithLabel } from "../session.ts"
import { type VaultApi, VaultApiError, retrySafeMethod } from "../vault-api.ts"

async function readData(data: string | null): Promise<Bytes | null> {
  if (data === null) return null
  if (data === "-") return new Uint8Array(await Bun.stdin.arrayBuffer())
  if (data.startsWith("@")) {
    const path = data.slice(1)
    try {
      return new Uint8Array(await readFile(path))
    } catch (error) {
      throw usageError(`Cannot read the body from ${path}: ${(error as Error).message}`, "mehen fetch --help")
    }
  }
  return utf8(data)
}

// --max-time: at most ten minutes, like the vault's own long requests.
export const FETCH_MAX_TIME_SECONDS = 600

// A read that timed out is safe to repeat; a write may have taken effect.
export function timedOut(seconds: number, method: string): CliError {
  const message = `No complete answer through the vault within ${seconds} s, so mehen stopped waiting.`
  if (!retrySafeMethod(method)) return outcomeUnknown(message)
  return new CliError("network", message, {
    say: "A read changes nothing upstream: send it again, or give --max-time more time.",
  })
}

function outputRefused(output: string, reason: string): CliError {
  return new CliError("usage", `Refusing to write the body to ${output}: ${reason}. Nothing was sent.`, {
    command: "mehen fetch --help",
    say: "Give -o the path of a new file or a regular file in a directory that exists and that you can write to.",
  })
}

// Opened before the vault is called, so a bad -o never follows a request
// that may change state upstream. A symbolic link in the final place is
// refused (lstat, then O_NOFOLLOW for the race); an existing file is only
// truncated once the response has arrived, so a refused request leaves it
// as it was.
async function openOutput(output: string): Promise<FileHandle> {
  try {
    const info = await lstat(output)
    if (info.isSymbolicLink()) throw outputRefused(output, "it is a symbolic link, so mehen would write to wherever it points")
    if (!info.isFile()) throw outputRefused(output, "it is not a regular file")
  } catch (error) {
    if (error instanceof CliError) throw error
    if ((error as { code?: string }).code !== "ENOENT") throw outputRefused(output, (error as Error).message)
  }
  let handle: FileHandle
  try {
    handle = await open(output, constants.O_WRONLY | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o666)
  } catch (error) {
    const code = (error as { code?: string }).code
    if (code === "ELOOP") throw outputRefused(output, "it is a symbolic link, so mehen would write to wherever it points")
    if (code === "ENOENT") throw outputRefused(output, "its directory does not exist")
    if (code === "EISDIR") throw outputRefused(output, "it is a directory")
    throw outputRefused(output, (error as Error).message)
  }
  if (!(await handle.stat()).isFile()) {
    await handle.close()
    throw outputRefused(output, "it is not a regular file")
  }
  return handle
}

export type OutputFile = { handle: FileHandle; path: string }

// The answer arrived but could not be written out: the request was sent,
// so sending it again to get the output could do a write twice.
function outputFailed(output: OutputFile, error: unknown, method: string, status: number): CliError {
  const detail = error instanceof Error ? error.message : String(error)
  return new CliError("failed", `The request was sent and the upstream answered ${status}, but mehen could not write its answer to ${output.path}: ${detail}.`, {
    say: retrySafeMethod(method) ? `Fix ${output.path} (space, permissions), then run the request again.` : `Do not send the request again to get the output: it was sent and may have taken effect. Fix ${output.path} and read the result back with a separate read, or ask the human.`,
  })
}

export async function writeBody(response: Response, output: OutputFile | null, method: string, status: number): Promise<number> {
  const file = async (step: () => Promise<unknown>) => {
    try {
      await step()
    } catch (error) {
      throw outputFailed(output as OutputFile, error, method, status)
    }
  }
  if (output) await file(() => output.handle.truncate(0))
  if (!response.body) return 0
  const reader = response.body.getReader()
  let total = 0
  for (;;) {
    const { done, value } = await readChunk(reader, method)
    if (done) break
    const chunk = new Uint8Array(value)
    total += chunk.length
    if (output) await file(() => output.handle.write(chunk))
    else await writeStdout(chunk)
  }
  return total
}

// Closing the output: a failure is the output's only when nothing else
// failed and an answer arrived; it never replaces the error that did.
export async function closeOutput(output: OutputFile, method: string, status: number | null, failedAlready: boolean): Promise<void> {
  try {
    await output.handle.close()
  } catch (error) {
    if (!failedAlready && status !== null) throw outputFailed(output, error, method, status)
  }
}

function headerLines(head: UpstreamHead): string[] {
  return [`mehen: ${head.status}${head.statusText ? ` ${head.statusText}` : ""}`, ...Object.entries(head.headers).map(([name, value]) => `  ${name}: ${value}`)]
}

// How a fetch prints its answer: the flags that change only the output.
export type FetchOutputOptions = { json: boolean; output: string | null; select: (string | number)[] | null; selectText: string | null; include: boolean; fail: boolean; maxTime: number | null }

const PLAIN_OUTPUT: FetchOutputOptions = { json: false, output: null, select: null, selectText: null, include: false, fail: false, maxTime: null }

export function replayOwner(session: VaultSession): ReplayOwner {
  return { vault: session.vaultUrl, workspace: session.config.tenant, device: session.config.device }
}

// A held answer (approval_required with its apr_ id) saves the request for
// sending again once approved, and says so beside the vault's refusal.
export async function heldRequestNote(env: Env, session: VaultSession, request: RelayRequestInput, error: unknown): Promise<ReplayNote | null> {
  if (!(error instanceof VaultApiError) || error.body.error !== "approval_required" || typeof error.body.approval !== "string") return null
  return saveHeldRequest(env, replayOwner(session), error.body.approval, request)
}

export function withReplayNote(error: unknown, note: ReplayNote | null): unknown {
  if (note === null) return error
  const failure = toCliError(error)
  if (failure.code !== "approval_required") return error
  return new CliError(failure.code, failure.message, failure.next, { ...failure.extras, replay: note })
}

// A request to send: given, or a saved one, claimed only once every local
// step before the network has passed.
export type FetchSource = RelayRequestInput | (() => Promise<ClaimedRequest>)

// One request through the relay, its answer printed as the flags ask.
export async function sendFetch(env: Env, session: VaultSession, source: FetchSource, options: FetchOutputOptions): Promise<number> {
  const { json, output, select, selectText, maxTime } = options
  const file = output === null ? null : { handle: await openOutput(output), path: output }
  let claimed: ClaimedRequest | null = null
  try {
    claimed = typeof source === "function" ? await source() : null
  } catch (error) {
    if (file) await file.handle.close().catch(() => undefined)
    throw error
  }
  const request = claimed ? claimed.request : (source as RelayRequestInput)
  const item = request.item ?? null
  let answered: number | null = null
  let failed = false
  let reached = false
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | null = null
  const api: VaultApi = session.api
  try {
    timer = maxTime === null ? null : setTimeout(() => controller.abort(), maxTime * 1000)
    const response = await api.relay(request, { signal: controller.signal })
    reached = true
    await claimed?.spent()
    const upstream = upstreamHead(response)
    answered = upstream.status
    if (options.include) for (const line of headerLines(upstream)) note(line)
    else note(`mehen: ${upstream.status}${upstream.statusText ? ` ${upstream.statusText}` : ""}${upstream.item ? `  Mehen-Item: ${upstream.item}` : ""}`)
    const rules = await rulesAllowed(api, response, item, controller.signal)
    for (const rule of rules ?? []) note(`mehen: ${ruleAllowedText(rule)}`)
    const postures = postureAllowed(response)
    for (const level of postures ?? []) note(`mehen: ${postureAllowedText(level)}`)
    const mandate = mandateAllowed(response)
    if (mandate) note(`mehen: ${mandateAllowedText(mandate)}`)
    const hint = await rejectedHint(api, upstream, item, controller.signal)
    if (hint) note(`mehen: ${hint}`)
    const head = { ...upstream, ...(rules ? { rules } : {}), ...(postures ? { postures } : {}), ...(mandate ? { mandate } : {}), ...(hint ? { hint } : {}) }
    if (select !== null) {
      const { bytes } = await readLimited(response, Number.POSITIVE_INFINITY, request.method)
      const chosen = selectBody(bytes, head.status, request.method, select)
      if (!chosen.json) {
        note(`mehen: ${chosen.note}`)
        if (json) printJson({ ...head, ...bodyForJson(bytes), selected: null, found: false, note: chosen.note })
        else await writeStdout(bytes)
      } else {
        const picked = chosen.picked
        if (!picked.found) note(`mehen: --select ${selectText} matched nothing in the body, so it prints null`)
        if (json) printJson({ ...head, selected: picked.value, found: picked.found })
        else await writeStdout(utf8(`${JSON.stringify(picked.value, null, 2)}\n`))
      }
    } else if (output !== null) {
      const written = await writeBody(response, file, request.method, upstream.status)
      note(`mehen: wrote ${written} bytes to ${output}`)
      if (json) printJson({ ...head, output, bytes: written })
    } else if (json) {
      const { bytes } = await readLimited(response, Number.POSITIVE_INFINITY, request.method)
      printJson({ ...head, ...bodyForJson(bytes) })
    } else {
      await writeBody(response, null, request.method, upstream.status)
    }
    if (options.fail && head.status >= 400) {
      throw new CliError("upstream_status", `The upstream answered ${head.status}${head.statusText ? ` ${head.statusText}` : ""}.`, {
        say: "The vault relayed the request; the upstream service refused it. Read the body for its reason.",
      })
    }
    return EXIT.ok
  } catch (error) {
    failed = true
    if (claimed && !reached) await (neverSent(error, request, controller.signal) ? claimed.unsent() : claimed.spent())
    if (controller.signal.aborted && maxTime !== null) throw timedOut(maxTime, request.method)
    const held = await heldRequestNote(env, session, request, error)
    throw withReplayNote(replacingRefused(ruleEnded(await mandateCapped(api, error, controller.signal)), request, "cli"), held)
  } finally {
    if (timer) clearTimeout(timer)
    if (file) await closeOutput(file, request.method, answered, failed)
  }
}

// The saved request for an approval, sent again once from the enrolment
// that saved it, signed with the session label it was held with. Every
// local check runs first; the claim comes right before sending.
export async function resumeFetch(env: Env, approval: string, options: FetchOutputOptions = PLAIN_OUTPUT): Promise<number> {
  const saved = await readSavedRequest(env, approval)
  const opened = await openSession({ ...env, MEHEN_WORKSPACE: env.MEHEN_WORKSPACE ?? saved.workspace })
  assertSavedBy(saved, replayOwner(opened))
  const session = await sessionWithLabel(env, opened, saved.request.session ?? null)
  return sendFetch(env, session, () => claimSavedRequest(env, saved, replayOwner(session)), options)
}

// Flags that change the request, which --resume takes from what was saved.
const REQUEST_FLAGS = ["header", "data", "run", "approval", "replaces", "project", "env"] as const

export const fetchCommand: Command = {
  summary: "make an HTTP request with an item's credential, through the vault",
  spec: {
    usage:
      "mehen fetch <item> <METHOD> <URL> [-H 'Name: value']... [-d @file|-|text] [--project <prj_id> --env <name>] [--approval apr_...] [--replaces apr_...] [--fail] [-o <file>] [--select <path>] [-i] [--max-time <duration>]   (or mehen fetch --run <run> <METHOD> <URL>, or mehen fetch --resume <apr_id>)",
    flags: {
      header: { type: "list", short: "H" },
      project: { type: "string" },
      env: { type: "string" },
      data: { type: "string", short: "d" },
      run: { type: "string" },
      approval: { type: "string" },
      replaces: { type: "string" },
      resume: { type: "string" },
      fail: { type: "boolean" },
      output: { type: "string", short: "o" },
      select: { type: "string" },
      include: { type: "boolean", short: "i" },
      "max-time": { type: "string" },
    },
    positionals: { min: 0, max: 3 },
  },
  examples: [
    ["fetch", "openai-personal", "GET", "https://api.openai.com/v1/models", "--select", "data.0.id"],
    ["fetch", "openai-personal", "POST", "https://api.openai.com/v1/responses", "-H", "Content-Type: application/json", "-d", "@body.json"],
    ["fetch", "github-work", "GET", "https://api.github.com/repos/acme/app/tarball", "-o", "app.tar.gz", "--max-time", "2m"],
    ["fetch", "stripe-prod", "GET", "https://api.stripe.com/v1/balance", "--project", "prj_3kQ9vXyZ7", "--env", "prod"],
    ["fetch", "--resume", "apr_7Hq2"],
  ],
  notes: [
    "The response body goes to stdout as the vault returns it; the status and Mehen-Item go to stderr, and so does the rule or mandate, when one allowed the request without asking. Any upstream status exits 0 unless --fail.",
    "When the service rejects the credential itself (401, or a 403 saying its scope is too narrow), stderr and --json's hint say how to replace or reconnect it.",
    "The vault may already have decompressed or scrubbed the body and removed response headers; it is not a byte-for-byte copy of the original upstream response.",
    "Never set an auth header yourself: the vault injects the credential where the item says.",
    "--project and --env name the project environment the credential is used for; a protected, team or guest credential needs them. They never change the workspace.",
    "A request held for approval (exit 3) is saved on this machine for an hour, with a body up to 64 KiB (--json's replay says whether). Once mehen wait says approved, --resume apr_... sends the saved request again, once, from this machine; it takes the output flags only. Without a saved request, repeat the request byte for byte with --approval apr_...; a different method, URL, header or body asks again.",
    "--replaces apr_... marks this request as a corrected version of this machine's open ask to the same place: when it is held for approval, that ask reads superseded and the new one is the one to wait on. Without it, a second ask stays open beside the first; to ask for several writes at once, use mehen plan submit.",
  ],
  async run({ args, json, env }) {
    const output = args.string("output")
    const selectText = args.string("select")
    if (output !== null && selectText !== null) throw usageError("Give --output or --select, not both: --select prints the part it picks.", "mehen fetch --help")
    if (output === "-" || output === "") throw usageError("--output takes a file path; leave it out to write the body to stdout.", "mehen fetch --help")
    const select = selectText === null ? null : parseSelectPath(selectText)
    const maxTimeText = args.string("max-time")
    const maxTime = maxTimeText === null ? null : parseDurationSeconds(maxTimeText, { max: FETCH_MAX_TIME_SECONDS, flag: "--max-time", help: "mehen fetch --help" })
    if (maxTime === 0) throw usageError("--max-time must be at least 1 s.", "mehen fetch --help")
    const options: FetchOutputOptions = { json, output, select, selectText, include: args.bool("include"), fail: args.bool("fail"), maxTime }
    const resume = args.string("resume")
    if (resume !== null) {
      const given = REQUEST_FLAGS.filter((flag) => (flag === "header" ? args.list(flag).length > 0 : args.string(flag) !== null))
      if (args.positionals.length > 0 || given.length > 0) throw usageError(`--resume sends the request saved for ${resume} as it was; give no item, method or URL${given.length ? `, and no --${given.join(", --")}` : ""}.`, "mehen fetch --help")
      if (!/^apr_[A-Za-z0-9_-]{1,60}$/.test(resume)) throw usageError(`--resume takes the approval id (apr_...) a held request was given; ${JSON.stringify(resume)} is not one.`, "mehen fetch --help")
      return resumeFetch(env, resume, options)
    }
    const run = args.string("run")
    const expected = run === null ? 3 : 2
    if (args.positionals.length !== expected) {
      throw usageError(run === null ? "Usage: mehen fetch <item> <METHOD> <URL>" : "Usage: mehen fetch --run <run> <METHOD> <URL> (no item with --run)", "mehen fetch --help")
    }
    const [item, method, url] = run === null ? (args.positionals as [string, string, string]) : [null, ...(args.positionals as [string, string])]
    const request = relayRequest({
      item,
      run,
      method,
      url,
      headers: args.list("header").map(parseHeader),
      body: await readData(args.string("data")),
      approval: args.string("approval"),
      replaces: relayReplaces(args.string("replaces"), "cli"),
      session: sessionLabel(env),
      context: fetchContext(args.string("project"), args.string("env"), "mehen fetch --help"),
    })
    return sendFetch(env, await openSession(env), request, options)
  },
}
