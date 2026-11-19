// mehen fetch: one HTTP request through the vault relay. The vault injects the
// item's secret; the upstream body comes back on stdout byte for byte.

import { constants } from "node:fs"
import { type FileHandle, lstat, open, readFile } from "node:fs/promises"
import { EXIT } from "@mehen/protocol/api"
import { type Bytes, utf8 } from "@mehen/protocol/bytes"
import type { Command } from "../command.ts"
import { CliError, usageError } from "../errors.ts"
import {
  type UpstreamHead,
  bodyForJson,
  parseDurationSeconds,
  parseHeader,
  parseJsonBody,
  parseSelectPath,
  readLimited,
  fetchContext,
  relayReplaces,
  relayRequest,
  replacingRefused,
  selectJson,
  upstreamHead,
} from "../operations.ts"
import { mandateAllowed, mandateAllowedText, mandateCapped } from "../mandate-operations.ts"
import { note, printJson, writeStdout } from "../output.ts"
import { postureAllowed, postureAllowedText, ruleAllowedText, ruleEnded, rulesAllowed } from "../policy-operations.ts"
import { openSession, sessionLabel } from "../session.ts"
import type { VaultApi } from "../vault-api.ts"

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

export function timedOut(seconds: number): CliError {
  return new CliError("network", `No complete answer through the vault within ${seconds} s, so mehen stopped waiting.`, {
    say: "The request may still have reached the upstream. Check whether it took effect before you send it again, or give --max-time more time.",
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

async function writeBody(response: Response, handle: FileHandle | null): Promise<number> {
  await handle?.truncate(0)
  if (!response.body) return 0
  const reader = response.body.getReader()
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    const chunk = new Uint8Array(value)
    total += chunk.length
    if (handle) await handle.write(chunk)
    else await writeStdout(chunk)
  }
  return total
}

function headerLines(head: UpstreamHead): string[] {
  return [`mehen: ${head.status}${head.statusText ? ` ${head.statusText}` : ""}`, ...Object.entries(head.headers).map(([name, value]) => `  ${name}: ${value}`)]
}

export const fetchCommand: Command = {
  summary: "make an HTTP request with an item's credential, through the vault",
  spec: {
    usage:
      "mehen fetch <item> <METHOD> <URL> [-H 'Name: value']... [-d @file|-|text] [--project <prj_id> --env <name>] [--approval apr_...] [--replaces apr_...] [--fail] [-o <file>] [--select <path>] [-i] [--max-time <duration>]   (or mehen fetch --run <run> <METHOD> <URL>)",
    flags: {
      header: { type: "list", short: "H" },
      project: { type: "string" },
      env: { type: "string" },
      data: { type: "string", short: "d" },
      run: { type: "string" },
      approval: { type: "string" },
      replaces: { type: "string" },
      fail: { type: "boolean" },
      output: { type: "string", short: "o" },
      select: { type: "string" },
      include: { type: "boolean", short: "i" },
      "max-time": { type: "string" },
    },
    positionals: { min: 2, max: 3 },
  },
  examples: [
    ["fetch", "openai-personal", "GET", "https://api.openai.com/v1/models", "--select", "data.0.id"],
    ["fetch", "openai-personal", "POST", "https://api.openai.com/v1/responses", "-H", "Content-Type: application/json", "-d", "@body.json"],
    ["fetch", "github-work", "GET", "https://api.github.com/repos/acme/app/tarball", "-o", "app.tar.gz", "--max-time", "2m"],
    ["fetch", "stripe-prod", "GET", "https://api.stripe.com/v1/balance", "--project", "prj_3kQ9vXyZ7", "--env", "prod"],
  ],
  notes: [
    "The response body goes to stdout as the vault returns it; the status and Mehen-Item go to stderr, and so does the rule or mandate, when one allowed the request without asking. Any upstream status exits 0 unless --fail.",
    "The vault may already have decompressed or scrubbed the body and removed response headers; it is not a byte-for-byte copy of the original upstream response.",
    "Never set an auth header yourself: the vault injects the credential where the item says.",
    "--project and --env name the project environment the credential is used for; a protected, team or guest credential needs them. They never change the workspace.",
    "--replaces apr_... marks this request as a corrected version of this machine's open ask to the same place: when it is held for approval, that ask reads superseded and the new one is the one to wait on. Without it, a second ask stays open beside the first; to ask for several writes at once, use mehen plan submit.",
  ],
  async run({ args, json, env }) {
    const run = args.string("run")
    const expected = run === null ? 3 : 2
    if (args.positionals.length !== expected) {
      throw usageError(run === null ? "Usage: mehen fetch <item> <METHOD> <URL>" : "Usage: mehen fetch --run <run> <METHOD> <URL> (no item with --run)", "mehen fetch --help")
    }
    const output = args.string("output")
    const selectText = args.string("select")
    if (output !== null && selectText !== null) throw usageError("Give --output or --select, not both: --select prints the part it picks.", "mehen fetch --help")
    if (output === "-" || output === "") throw usageError("--output takes a file path; leave it out to write the body to stdout.", "mehen fetch --help")
    const select = selectText === null ? null : parseSelectPath(selectText)
    const maxTimeText = args.string("max-time")
    const maxTime = maxTimeText === null ? null : parseDurationSeconds(maxTimeText, { max: FETCH_MAX_TIME_SECONDS, flag: "--max-time", help: "mehen fetch --help" })
    if (maxTime === 0) throw usageError("--max-time must be at least 1 s.", "mehen fetch --help")
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
    const handle = output === null ? null : await openOutput(output)
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | null = null
    let api: VaultApi | null = null
    try {
      api = (await openSession(env)).api
      timer = maxTime === null ? null : setTimeout(() => controller.abort(), maxTime * 1000)
      const response = await api.relay(request, { signal: controller.signal })
      const upstream = upstreamHead(response)
      if (args.bool("include")) for (const line of headerLines(upstream)) note(line)
      else note(`mehen: ${upstream.status}${upstream.statusText ? ` ${upstream.statusText}` : ""}${upstream.item ? `  Mehen-Item: ${upstream.item}` : ""}`)
      const rules = await rulesAllowed(api, response, item, controller.signal)
      for (const rule of rules ?? []) note(`mehen: ${ruleAllowedText(rule)}`)
      const postures = postureAllowed(response)
      for (const level of postures ?? []) note(`mehen: ${postureAllowedText(level)}`)
      const mandate = mandateAllowed(response)
      if (mandate) note(`mehen: ${mandateAllowedText(mandate)}`)
      const head = { ...upstream, ...(rules ? { rules } : {}), ...(postures ? { postures } : {}), ...(mandate ? { mandate } : {}) }
      if (select !== null) {
        const { bytes } = await readLimited(response, Number.POSITIVE_INFINITY)
        const picked = selectJson(parseJsonBody(bytes, head.status), select)
        if (!picked.found) note(`mehen: --select ${selectText} matched nothing in the body, so it prints null`)
        if (json) printJson({ ...head, selected: picked.value, found: picked.found })
        else await writeStdout(utf8(`${JSON.stringify(picked.value, null, 2)}\n`))
      } else if (output !== null) {
        const written = await writeBody(response, handle)
        note(`mehen: wrote ${written} bytes to ${output}`)
        if (json) printJson({ ...head, output, bytes: written })
      } else if (json) {
        const { bytes } = await readLimited(response, Number.POSITIVE_INFINITY)
        printJson({ ...head, ...bodyForJson(bytes) })
      } else {
        await writeBody(response, null)
      }
      if (args.bool("fail") && head.status >= 400) {
        throw new CliError("upstream_status", `The upstream answered ${head.status}${head.statusText ? ` ${head.statusText}` : ""}.`, {
          say: "The vault relayed the request; the upstream service refused it. Read the body for its reason.",
        })
      }
      return EXIT.ok
    } catch (error) {
      if (controller.signal.aborted && maxTime !== null) throw timedOut(maxTime)
      throw replacingRefused(ruleEnded(api ? await mandateCapped(api, error, controller.signal) : error), request, "cli")
    } finally {
      if (timer) clearTimeout(timer)
      await handle?.close()
    }
  },
}
