// mehen mcp: a stdio MCP server (JSON-RPC 2.0, one message per line) exposing
// the vault as tools. No tool ever returns a secret: the vault never sends
// one to a device, and relayed responses are scrubbed by the vault. When a
// human must act, a tool hands over a link: `ask` in structuredContent and a
// resource_link in content, both built only from a link that passed askUrl
// against the configured vault. Nothing an agent can send here approves,
// enrols, revokes or freezes anything: those happen on the vault's pages
// with a passkey, or at a terminal.

import { realpathSync } from "node:fs"
import { z } from "zod"
import type { VaultFileOptions } from "./agent-profiles.ts"
import { type Ask, type AskResourceLink, askForError, askResourceLink, askText } from "./ask.ts"
import { type Config, type Env, resolveVaultUrl } from "./config.ts"
import { CliError, exitCodeFor, toCliError } from "./errors.ts"
import { errorJson, errorLines, reportError } from "./output.ts"
import { type VaultSession, openContext } from "./session.ts"
import { terminalText, visibleText } from "./tty.ts"
import { VERSION } from "./version.ts"
import { flushCliAdvice } from "./http-client.ts"
import { installation, mcpHandoverNow, selfExecutable } from "./install-state.ts"
import { sha256 } from "./release-client.ts"
import { healInForeground } from "./update.ts"
import { CallRegistry } from "./mcp/call-registry.ts"
import { type McpResumePayload, StdinLines, assertStillVerified, prepareHandover, quietWithin, resumeInto, takeResume } from "./mcp/handover.ts"
import { SelfWatch } from "./mcp/self-watch.ts"
import { TOOL_SCHEMA_NEXT, toolNext } from "./mcp/tool-next.ts"
import { APP_TOOLS, TOOLS, TOOLSETS_ENV, TOOLSET_NAMES, TOOL_COMMAND, type Toolset, resolveToolsets, servedTools, toolsetOf } from "./mcp/registry.ts"
import { CARDS, CARD_FOR_TOOL, appsNegotiated, readCard } from "./mcp/ui/cards.ts"
import { displayChanged, narrowedSpan, resolveSlot, startServer, validateSlot } from "./mcp/binding.ts"
import { type McpServer, type ProgressToken, type SpanSlot, type ToolDeps, type ToolOutput, mcpThen, servedBy } from "./mcp/shared.ts"

export { CallRegistry } from "./mcp/call-registry.ts"
export { FETCH_BODY_LIMIT, WAIT_DEFAULT_SECONDS, WAIT_MAX_SECONDS, PROGRESS_INTERVAL_MS } from "./mcp/constants.ts"
export { mcpThen } from "./mcp/shared.ts"
export { progressMessage } from "./mcp/vault-wait.ts"
export const MCP_PROTOCOL_VERSION = "2025-11-25"
// The MCP revisions a host may ask for. A host that asks for one of them gets
// it back, as the MCP lifecycle requires; any other request gets the latest.
// A host on an older revision ignores the result fields it does not know.
export const MCP_PROTOCOL_VERSIONS: readonly string[] = [MCP_PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05"]

export function negotiatedProtocolVersion(requested: unknown): string {
  return typeof requested === "string" && MCP_PROTOCOL_VERSIONS.includes(requested) ? requested : MCP_PROTOCOL_VERSION
}

// The instructions name only the tools a server serves: the core's always,
// then a sentence for each toolset that adds a step to them.
const CORE_INSTRUCTIONS =
  "Mehen lets you use credentials without reading them. Start with vault_status. " +
  "No tool enrols this machine: when vault_status says it is not enrolled and you cannot run commands, ask the human to run its next.command in a terminal and open the link it prints. " +
  "Use credentials by name with vault_fetch (vault_list shows which exist); never ask a human to paste a value into the chat, and never put a key, token or placeholder into a URL, header or body yourself. " +
  "When something is missing, call vault_request, give the human the `ask` (the link, what it is for, what to check, when it expires), then vault_wait with the id. " +
  "In a checkout with a mehen.toml, vault_env says how its variables resolve. " +
  "Every error carries `next` and, when a human must open something, `ask`: relay them; never open the link yourself. " +
  "An error's `next.tool` is the tool that does its step, with `next.arguments` to add to the call (keep the call's other arguments when it is the tool you called; fill in any <placeholder>); a `next.command` without `next.tool` only the mehen command line runs: if you cannot run commands, ask the human to run it in a terminal. " +
  "Approvals happen on the vault's page with a passkey; nothing you send can approve anything. " +
  "This server may use several workspaces; `vault_status` lists them; pass `workspace` when it lists more than one and the checkout does not bind one."

const TOOLSET_INSTRUCTIONS: Partial<Record<Toolset, string>> = {
  inspect: "When something fails and the error does not say why, vault_doctor checks this machine and says what to do. vault_templates finds the provider to name in vault_request. vault_check is local base-policy advice only, not permission to send; the vault decides when vault_fetch sends.",
  connect: "For an account the human signs in to (Gmail, GitHub), call vault_connect instead of vault_request, then vault_wait.",
  policy: "vault_policy shows an item's current policy and proposes standing rules; vault_mandate proposes a mandate. Only the human's passkey turns either on.",
}

export function mcpInstructions(toolsets: readonly Toolset[]): string {
  const extra = toolsets.flatMap((name) => TOOLSET_INSTRUCTIONS[name] ?? [])
  const served = `Toolsets served: ${toolsets.join(", ")}.`
  const rest = toolsets.length === TOOLSET_NAMES.length ? "" : " Other tools come in toolsets the harness adds with `mehen mcp --toolsets <names>`; a call to one this server does not serve is refused with tool_not_served, which names its toolset and the mehen command that does the same."
  return [CORE_INSTRUCTIONS, ...extra, served + rest].join(" ")
}

function listed(t: (typeof TOOLS)[number]): Record<string, unknown> {
  const { $schema: _schema, ...inputSchema } = z.toJSONSchema(t.advertised ?? t.input, { io: "input" }) as Record<string, unknown>
  return { name: t.name, title: t.title, description: t.description, inputSchema, ...(t.output ? { outputSchema: t.output } : {}), annotations: t.annotations }
}

type ToolLists = { tools: typeof TOOLS; plain: Record<string, unknown>[]; apps: Record<string, unknown>[]; hash: string }
const toolLists = new Map<string, ToolLists>()

// The lists a server with these toolsets answers tools/list with: the plain
// one, and the one a host that negotiated MCP Apps gets (the same tools,
// each linked one naming its card, then the tools only a card calls).
function listsFor(toolsets: readonly Toolset[]): ToolLists {
  const key = toolsets.join(",")
  const cached = toolLists.get(key)
  if (cached) return cached
  const tools = servedTools(toolsets)
  const plain = tools.map(listed)
  const apps = [
    ...tools.map((t) => {
      const resourceUri = CARD_FOR_TOOL.get(t.name)
      return resourceUri ? { ...listed(t), _meta: { ui: { resourceUri } } } : listed(t)
    }),
    ...APP_TOOLS.map((t) => ({ ...listed(t), _meta: { ui: { visibility: ["app"] } } })),
  ]
  const lists = { tools, plain, apps, hash: sha256(new TextEncoder().encode(JSON.stringify([plain, apps]))) }
  toolLists.set(key, lists)
  return lists
}

const servedToolsets = (deps: ToolDeps): readonly Toolset[] => deps.toolsets ?? ["core"]

type JsonRpcId = string | number

type JsonRpcResponse =
  | { jsonrpc: "2.0"; id: JsonRpcId | null; result: unknown }
  | { jsonrpc: "2.0"; id: JsonRpcId | null; error: { code: number; message: string } }

const PARSE_ERROR = -32700
const INVALID_REQUEST = -32600
const METHOD_NOT_FOUND = -32601
const INVALID_PARAMS = -32602
// MCP's code for a resources/read of a uri the server does not have.
const RESOURCE_NOT_FOUND = -32002

function failure(id: JsonRpcId | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } }
}

// A tool result for a failure: the same body and lines every mehen command
// renders (output.ts errorJson and errorLines), so a link the vault hands
// back is checked against the configured vault here too. The text is for a
// host that shows plain text: no TTY, so no colour and no QR. When the
// refusal hands over a link, content also carries the resource_link for the
// same ask; isError stays true, since the call did not do what was asked.
const NOT_A_TTY = { isTTY: false, write: () => true }

// The resource_link a host renders as a button. `uri` is the checked ask
// url as it is; `name` and `description` are display text a host shows a
// human, so they cross the same boundary as the text block (hidden and
// control characters spelled out). structuredContent keeps the raw ask.
export function resourceLink(ask: Ask): AskResourceLink {
  const link = askResourceLink(ask)
  return { ...link, name: visibleText(link.name), description: visibleText(link.description) }
}

// The vault and slug a call's link is checked against: the workspace the call
// used, never one a cwd or the link suggests; before any slot was used, the
// vault a new enrolment would use.
function callVault(deps: ToolDeps): { vaultUrl: string; workspaceSlug: string | null } | null {
  return deps.used ?? newEnrolmentVault(deps.env)
}

function newEnrolmentVault(env: Env): { vaultUrl: string; workspaceSlug: string | null } | null {
  try {
    return { vaultUrl: resolveVaultUrl(env, null), workspaceSlug: null }
  } catch {
    return null
  }
}

async function toolError(failure: CliError, tool: string, deps: ToolDeps): Promise<Record<string, unknown>> {
  const vaultUrl = callVault(deps)
  const { ask } = askForError(failure, deps.env, vaultUrl)
  const served = servedBy(deps)
  const error = toolNext(failure, tool, served)
  const options = { env: deps.env, vaultUrl, then: mcpThen, surface: "mcp" as const, served }
  const lines = errorLines(error, NOT_A_TTY, options).map(terminalText)
  const text = [`${error.code}: ${visibleText(error.message)}`, ...lines.slice(1)].join("\n")
  return { content: [{ type: "text", text }, ...(ask ? [resourceLink(ask)] : [])], structuredContent: errorJson(error, options), isError: true }
}

// The text a host shows for a success: the ask block for each link handed
// over (with the MCP then: line), else the result as compact JSON spelled
// out (hidden characters made visible; JSON has already escaped every
// control, so a host can still parse it). Indenting would add half again to
// what a host counts against its limit. structuredContent stays raw.
function successText(output: ToolOutput): string {
  if (output.handover.length === 0) {
    return [...(output.text ?? []), JSON.stringify(output.structured)].map(visibleText).join("\n\n")
  }
  const blocks = output.handover.map(({ ask, then }) => askText(ask, { then }))
  return [...(output.text ?? []).map(visibleText), ...(output.warning ? [`warning: ${visibleText(output.warning)}`] : []), ...blocks].join("\n\n")
}

function progressToken(params: Record<string, unknown>): ProgressToken | null {
  const meta = params._meta
  if (typeof meta !== "object" || meta === null) return null
  const token = (meta as Record<string, unknown>).progressToken
  return typeof token === "string" || typeof token === "number" ? token : null
}

// Null: no such tool. A call the host cancelled while it ran gets no
// result either way (the host has stopped listening for it): the error the
// abort raised is rethrown and handleMessage sends nothing.
async function callTool(params: Record<string, unknown>, shared: ToolDeps, signal: AbortSignal): Promise<Record<string, unknown> | null> {
  const found = listsFor(servedToolsets(shared)).tools.find((t) => t.name === params.name) ?? APP_TOOLS.find((t) => t.name === params.name)
  if (!found) {
    const name = typeof params.name === "string" ? params.name : null
    const toolset = name === null ? null : toolsetOf(name)
    return name === null || toolset === null ? null : toolError(notServed(name, toolset, servedToolsets(shared)), name, { ...shared, used: null })
  }
  // This call's own record of the workspace it used.
  const deps: ToolDeps = {
    ...shared,
    used: null,
    async session(workspace, selection) {
      return record(await shared.session(workspace, selection))
    },
    async open(slot) {
      return record(await shared.open(slot))
    },
  }
  const record = (session: VaultSession): VaultSession => {
    deps.used = { vaultUrl: session.vaultUrl, workspaceSlug: session.config.workspaceSlug ?? null }
    return session
  }
  const parsed = found.input.safeParse(params.arguments ?? {})
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => (i.path.length ? `${i.path.join(".")}: ${i.message}` : i.message)).join("; ")
    return toolError(new CliError("usage", `Invalid arguments for ${found.name}: ${detail}`, TOOL_SCHEMA_NEXT), found.name, deps)
  }
  try {
    const output = await found.call(parsed.data, deps, { progressToken: progressToken(params), signal })
    const links = output.handover.map(({ ask }) => resourceLink(ask))
    return { content: [{ type: "text", text: successText(output) }, ...links], structuredContent: output.structured, isError: false }
  } catch (error) {
    if (signal.aborted) throw error
    return toolError(await healedRefusal(toCliError(error), deps), found.name, deps)
  }
}

// A tool this server knows but does not list: the toolset that has it, and
// the mehen command that does the same for an agent that can run one.
function notServed(name: string, toolset: Toolset, served: readonly Toolset[]): CliError {
  const command = `${TOOL_COMMAND[name] ?? "mehen --help"} --json`
  return new CliError("tool_not_served", `${name} is in the ${toolset} toolset, which this server does not serve (it serves ${served.join(", ")}).`, {
    say: `Run \`${command}\` instead if you can run commands; otherwise ask the human to run \`mehen setup --toolsets ${toolset}\`, which sets ${TOOLSETS_ENV} in this agent's entry, and restart the agent.`,
    command,
  })
}

// A call refused cli_outdated runs the foreground heal inside the call
// (90 s), then returns the refusal: with a newer mehen now on disk, the
// step is to restart the agent, since this server keeps its image;
// otherwise the vault's own `next`. Nothing is retried.
async function healedRefusal(failure: CliError, deps: ToolDeps): Promise<CliError> {
  if (failure.code !== "cli_outdated") return failure
  await flushCliAdvice()
  const healed = await healInForeground(deps.env)
  if (healed === null) return failure
  return new CliError("cli_outdated", failure.message, { say: `mehen updated itself to ${healed.to} on disk; restart the agent to load it, then retry` }, failure.extras)
}

export async function handleMessage(message: unknown, deps: ToolDeps): Promise<JsonRpcResponse | null> {
  if (typeof message !== "object" || message === null || Array.isArray(message)) return failure(null, INVALID_REQUEST, "Expected one JSON-RPC 2.0 object per line.")
  const m = message as Record<string, unknown>
  const hasId = typeof m.id === "string" || typeof m.id === "number"
  const id = hasId ? (m.id as JsonRpcId) : null
  if (m.jsonrpc !== "2.0" || typeof m.method !== "string") return hasId ? failure(id, INVALID_REQUEST, "Not a JSON-RPC 2.0 request.") : null
  const params = typeof m.params === "object" && m.params !== null ? (m.params as Record<string, unknown>) : {}
  // Notifications need no answer; cancelled stops the call it names.
  if (id === null) {
    if (m.method === "notifications/cancelled") deps.calls.cancel(params.requestId)
    return null
  }
  switch (m.method) {
    case "initialize":
      deps.apps.negotiated = appsNegotiated(params)
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: negotiatedProtocolVersion(params.protocolVersion),
          // The tool list changes only with a handover.
          capabilities: { tools: { listChanged: deps.mcpHandover?.handover === "on" }, ...(deps.apps.negotiated ? { resources: {} } : {}) },
          serverInfo: { name: "mehen", title: "Mehen", version: VERSION },
          instructions: mcpInstructions(servedToolsets(deps)),
        },
      }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} }
    case "tools/list": {
      const lists = listsFor(servedToolsets(deps))
      return { jsonrpc: "2.0", id, result: { tools: deps.apps.negotiated ? lists.apps : lists.plain } }
    }
    case "resources/list":
      if (!deps.apps.negotiated) return failure(id, METHOD_NOT_FOUND, `Method ${m.method} is not supported.`)
      return { jsonrpc: "2.0", id, result: { resources: CARDS } }
    case "resources/templates/list":
      if (!deps.apps.negotiated) return failure(id, METHOD_NOT_FOUND, `Method ${m.method} is not supported.`)
      return { jsonrpc: "2.0", id, result: { resourceTemplates: [] } }
    // A card is served whatever was negotiated: it is a fixed document.
    case "resources/read": {
      if (typeof params.uri !== "string") return failure(id, INVALID_PARAMS, "resources/read needs a uri.")
      const card = await readCard(params.uri)
      return card ? { jsonrpc: "2.0", id, result: card } : failure(id, RESOURCE_NOT_FOUND, "Resource not found")
    }
    case "tools/call": {
      const signal = deps.calls.begin(id)
      try {
        const result = await callTool(params, deps, signal)
        if (signal.aborted) return null
        return result ? { jsonrpc: "2.0", id, result } : failure(id, INVALID_PARAMS, `Unknown tool ${JSON.stringify(params.name)}.`)
      } catch (error) {
        if (signal.aborted) return null
        throw error
      } finally {
        deps.calls.end(id)
      }
    }
    default:
      return failure(id, METHOD_NOT_FOUND, `Method ${m.method} is not supported.`)
  }
}

// The server a `mehen mcp` process runs: its root, ceiling, pin
// and startup manifest, with every startup refusal made before stdin is read.
export async function bindMcpContext(env: Env, cwd: string, files: VaultFileOptions = {}): Promise<McpServer> {
  return startServer(env, cwd, files)
}

// Sessions are cached by the full identity of what they opened, never by a
// process-wide singleton, so two contexts with the same workspace id at
// different origins, or two devices in one workspace, can never share one.
export function sessionKey(dir: string, config: { vault: string; tenant: string; device: string }): string {
  let real = dir
  try {
    real = realpathSync(dir)
  } catch {
    // A directory that vanished keys as named; the open fails on its own.
  }
  return JSON.stringify([real, config.vault, config.tenant, config.device])
}

export function mcpDeps(env: Env, server: McpServer, notify: ToolDeps["notify"], toolsets: readonly Toolset[] = resolveToolsets(null, env)): ToolDeps {
  // Cached by full identity, with the config each session was opened under:
  // the same identity with refreshed display fields (a rename that status
  // recorded) is reopened so its ledger scope and call provenance follow
  // the disk.
  const opened = new Map<string, { session: Promise<VaultSession>; config: Config }>()
  const validate = (slot: SpanSlot) => validateSlot(env, server, slot)
  const open = async (slot: SpanSlot): Promise<VaultSession> => {
    // The slot's latch and guards run on every call, before any cached
    // session is returned or a signature made.
    const config = await validate(slot)
    const key = sessionKey(slot.dir, config)
    const cached = opened.get(key)
    if (cached && !displayChanged(cached.config, config)) return cached.session
    const session = openContext(env, { dir: slot.dir, config, reason: "workspace" }).catch((error: unknown) => {
      opened.delete(key)
      throw error
    })
    opened.set(key, { session, config })
    return session
  }
  return {
    env,
    server,
    apps: { negotiated: false },
    used: null,
    async session(workspace, selection) {
      return open(await resolveSlot(server, workspace, selection))
    },
    span: (workspace) => narrowedSpan(server, workspace),
    open,
    validate,
    notify,
    calls: new CallRegistry(),
    toolsets,
  }
}

// The handover is on unless settings.json has
// `"mcpHandover": false`, when automatic updates are on and the runtime
// has execve (mcpHandoverDecision): decided at the server's start, and
// decided again before each switch commits. `args` are the arguments
// after `mcp`, for the re-exec.
// This setting replaced a compiled-off constant, and is on by default from
// 0.3.15.
export type ServeOptions = { args?: string[]; toolsets?: string | null; stage?: (stage: HandoverStage) => Promise<void>; hashed?: () => void; running?: string }

// Test seams only, awaited: as the self-watch reads a replacement, after
// the look that follows each call, when a held partial line puts a switch
// off, as a hold-off starts and gives up, when one is not started again
// for the calls the last gave up on, and once the new image accepted
// the payload. A test orders the host's writes against a switch with them.
// `hashed`, synchronous, runs between the last hash and the last look
// before the exec. `running` is the version the self-watch takes this
// image for, so a test's replacement can be this same build.
export type HandoverStage = "verifying" | "checked" | "partial" | "holdoff" | "holdoff-expired" | "holdoff-skipped" | "accepted"

// The seams for a server started through main(), which passes none (tests only).
let seamsForTests: Pick<ServeOptions, "stage" | "hashed" | "running"> = {}
export function setServeSeamsForTests(seams: Pick<ServeOptions, "stage" | "hashed" | "running">): void {
  seamsForTests = seams
}

export async function serveMcp(parentEnv: Env, options: ServeOptions = {}): Promise<number> {
  // A resume payload never outlives the start. One handed over is taken
  // whatever this image's own decision says now: the old image committed
  // to it, and it only narrows what a fresh start allows. The decision
  // governs only whether this image starts later switches.
  const taken = takeResume(parentEnv)
  const env = taken.env
  const mcpHandover = await mcpHandoverNow(env)
  const handover = mcpHandover.handover === "on"
  let server: McpServer
  let toolsets: Toolset[]
  let resumed: McpResumePayload | null = null
  try {
    toolsets = resolveToolsets(options.toolsets ?? null, env)
    server = await bindMcpContext(env, process.cwd())
    if (taken.payload !== null) resumed = await resumeInto(server, taken.payload)
  } catch (error) {
    // Before any stdin is read: nothing is served on stdout, and the host's
    // log (stderr) says why.
    const failure = toCliError(error)
    reportError(failure, false, { env, noQr: true, vaultUrl: newEnrolmentVault(env) })
    return exitCodeFor(failure.code)
  }
  // Every write is counted until the kernel has it, for the handover's
  // quiet point.
  let writing = 0
  const write = (value: unknown) => {
    writing++
    process.stdout.write(`${JSON.stringify(value)}\n`, () => {
      writing--
    })
  }
  const inflight = new Set<Promise<void>>()
  const self = selfExecutable(env)
  const stage = options.stage ?? seamsForTests.stage
  const hashed = options.hashed ?? seamsForTests.hashed
  const running = options.running ?? seamsForTests.running
  const watch = self === null ? null : await SelfWatch.create({ env, binary: installation(self).binary, busy: () => inflight.size > 0, handover: mcpHandover, ...(running ? { running } : {}), ...(stage ? { hooks: { afterRead: () => stage("verifying") } } : {}) })
  const deps = { ...mcpDeps(env, server, write, toolsets), selfWatch: watch, mcpHandover }
  const toolsHash = listsFor(toolsets).hash
  let handshake = resumed ? { protocolVersion: resumed.protocolVersion, clientInfo: resumed.clientInfo, apps: resumed.apps ?? false } : null
  deps.apps.negotiated = handshake?.apps ?? false
  if (resumed && resumed.toolsHash !== toolsHash) write({ jsonrpc: "2.0", method: "notifications/tools/list_changed", params: {} })
  const send = (response: JsonRpcResponse | null) => {
    if (response) write(response)
  }
  // Set by a notifications/cancelled; the read loop clears it.
  let cancelRead = false
  const dispatch = (line: string) => {
    if (!line.trim()) return
    let message: unknown
    try {
      message = JSON.parse(line)
    } catch {
      send(failure(null, PARSE_ERROR, "The line is not valid JSON."))
      return
    }
    const call = isToolCall(message)
    if ((message as { method?: unknown } | null)?.method === "notifications/cancelled") cancelRead = true
    if (handshake === null) handshake = initializeParams(message)
    const task = handleMessage(message, deps)
      // With the handover on, a verified replacement is switched to, not
      // announced: the restart text applies once a switch to it is refused.
      .then((response) => send(call && watch ? withRestartNotice(response, watch) : response))
      .catch((error: unknown) => {
        console.error(JSON.stringify({ msg: "mcp handler failed", error: error instanceof Error ? error.message : String(error) }))
      })
      .finally(() => {
        inflight.delete(task)
        // After every call, off the request path.
        if (call && watch) void watch.check().then(() => stage?.("checked"))
      })
    inflight.add(task)
  }
  watch?.startTimer()
  const detach = watch === null ? () => {} : stopOnExit(watch)
  try {
    if (handover) {
      const reader = new StdinLines()
      // The calls in flight when a hold-off last gave up: while any of them
      // still is, a read is not held off again (a long vault_wait would
      // otherwise delay every message behind it), unless the last read
      // carried a cancel, which may be ending one of them now.
      let gaveUpOn = new Set<Promise<void>>()
      for (;;) {
        const ready = watch?.switchable() ?? null
        const skip = !cancelRead && [...gaveUpOn].some((task) => inflight.has(task))
        cancelRead = false
        if (watch && ready && handshake && reader.partial()) await stage?.("partial")
        else if (watch && ready && handshake && skip) await stage?.("holdoff-skipped")
        else if (watch && ready && handshake) {
          await stage?.("holdoff")
          if (!(await quietWithin(() => inflight.size === 0 && writing === 0))) {
            gaveUpOn = new Set(inflight)
            await stage?.("holdoff-expired")
          } else {
            try {
              // The setting as it is now: turned off since the start, it
              // stops this switch before anything is committed to.
              const now = await mcpHandoverNow(env)
              if (now.handover === "off") throw new Error(`the handover was turned off: ${now.reason}`)
              const exec = await prepareHandover({ env, server, replacement: ready, binary: watch.binary, executables: watch.executables, args: options.args ?? [], handshake, startedAt: new Date().toISOString(), toolsHash })
              await stage?.("accepted")
              // A guard only: both decisions above are off without execve.
              if (typeof process.execve !== "function") throw new Error("this runtime cannot execve")
              if (inflight.size === 0 && writing === 0) {
                // execve keeps the pid, so no sweep would ever take a
                // directory marked with it: the marker goes now, with every
                // copy but the idle updater's recent launches. It goes before
                // the last look, so nothing but execve follows that look; when
                // the look refuses, the directory is an unmarked one the
                // sweep takes later.
                watch.releaseForExec()
                assertStillVerified(exec.file, ready, hashed)
                process.execve(exec.file, exec.argv, exec.env)
              }
            } catch (error) {
              // No switch: this image keeps serving (restart-required).
              watch.switchRefused(ready)
              console.error(JSON.stringify({ msg: "mcp handover cancelled", reason: error instanceof Error ? error.message : String(error) }))
            }
          }
        }
        const lines = await reader.next()
        if (lines === null) break
        for (const line of lines) dispatch(line)
      }
    } else {
      const decoder = new TextDecoder()
      let buffer = ""
      const reader = Bun.stdin.stream().getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        let newline = buffer.indexOf("\n")
        while (newline !== -1) {
          dispatch(buffer.slice(0, newline))
          buffer = buffer.slice(newline + 1)
          newline = buffer.indexOf("\n")
        }
      }
      dispatch(buffer + decoder.decode())
    }
    await Promise.all(inflight)
  } finally {
    detach()
    watch?.stop()
  }
  return 0
}

const STOP_SIGNALS = ["SIGTERM", "SIGINT", "SIGHUP"] as const

// The watch and its private directory go with the server however it ends,
// not only when stdin closes: on SIGTERM, SIGINT or SIGHUP the watch stops
// and the signal is raised again, so the server still ends by it; on exit
// the directory is removed synchronously, best effort.
function stopOnExit(watch: SelfWatch): () => void {
  const onExit = () => {
    try {
      watch.stop()
    } catch {}
  }
  const onSignal = (signal: NodeJS.Signals) => {
    onExit()
    detach()
    process.kill(process.pid, signal)
  }
  const detach = () => {
    process.off("exit", onExit)
    for (const signal of STOP_SIGNALS) process.off(signal, onSignal)
  }
  process.on("exit", onExit)
  for (const signal of STOP_SIGNALS) process.on(signal, onSignal)
  return detach
}

function isToolCall(message: unknown): boolean {
  return typeof message === "object" && message !== null && (message as Record<string, unknown>).method === "tools/call"
}

// The handshake a handover carries over, from the host's initialize.
function initializeParams(message: unknown): { protocolVersion: string; clientInfo: { name: string; version: string }; apps: boolean } | null {
  if (typeof message !== "object" || message === null) return null
  const m = message as Record<string, unknown>
  if (m.method !== "initialize" || typeof m.params !== "object" || m.params === null) return null
  const params = m.params as Record<string, unknown>
  const client = typeof params.clientInfo === "object" && params.clientInfo !== null ? (params.clientInfo as Record<string, unknown>) : {}
  return { protocolVersion: typeof params.protocolVersion === "string" ? params.protocolVersion : MCP_PROTOCOL_VERSION, clientInfo: { name: typeof client.name === "string" ? client.name : "unknown", version: typeof client.version === "string" ? client.version : "unknown" }, apps: appsNegotiated(params) }
}

// A tool result carries the restart-required text block
// when a verified newer mehen is on disk: in the next result, then at most
// hourly. structuredContent is left as the tool returned it.
function withRestartNotice(response: JsonRpcResponse | null, watch: Pick<SelfWatch, "notice">): JsonRpcResponse | null {
  if (response === null || !("result" in response)) return response
  const result = response.result as { content?: unknown }
  if (!Array.isArray(result.content)) return response
  const text = watch.notice()
  if (text === null) return response
  return { ...response, result: { ...result, content: [...result.content, { type: "text", text }] } }
}
