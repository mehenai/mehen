import { type CallRegistry } from "./call-registry.ts"
import { z } from "zod"
import { type Ask } from "../ask.ts"
import { type Config, type Env } from "../config.ts"
import type { CliMcp, McpHandover } from "../install-state.ts"
import { type ManifestWorkspace } from "../run/manifest.ts"
import { type VaultSession } from "../session.ts"
import type { CeilingEntry, FoundCorrupt, FoundPending } from "../slots.ts"
import type { Toolset } from "./registry.ts"

export type ProgressToken = string | number
export type JsonRpcNotification = { jsonrpc: "2.0"; method: string; params: Record<string, unknown> }

// The identity one slot serves for the life of the server: latched on the
// slot's first successful validation, or by the enrolment vault_wait
// finished, and never replaced (design 15.7).
export type Latched = { vault: string; tenant: string; device: string }

// A slot is latched, or refused for the rest of the process
// (a tombstone) once its enrolment changed device or vanished.
export type SlotBinding = { latched: Latched } | { refused: { reason: string; since: string } }

// A ceiling entry as written and the origin and workspace id it resolved to
// at start; both null for an absent entry.
export type McpAdmittedEntry = { entry: string; origin: string | null; workspace: string | null }

// The directory and enrolment a slot was last validated with: its
// identity and display fields, never key material.
export type SeenSlot = { dir: string; config: Config }

// The latch table as it is carried across a re-exec.
// `allowed` is the resolved admitted set, never the environment strings,
// and `pin` the pin as it resolved at start; the new image must resolve
// the same set, pin and startup manifest. `seen` is for messages and
// listings only: the new image names a slot as the old one would have,
// and authorises nothing by it. Absent in a payload from before it.
export type McpLatchState = { v: 1; home: string; allowed: McpAdmittedEntry[] | null; pin: McpPin | null; manifest: { path: string; workspace: string | null; vault: string | null } | null; slots: Record<string, SlotBinding>; seen?: Record<string, SeenSlot> }

// An admitted entry with the parse of what was written.
export type Admission = McpAdmittedEntry & { prefix: string | null; selector: string }

// The pin (MEHEN_WORKSPACE, or mcp --workspace folded into it) as the
// workspace it resolved to at start: its origin and id; `text` is the
// selector as given, for messages only.
export type McpPin = { text: string; vault: string; tenant: string }

// One server spanning the allowed set of one root. The root, the
// ceiling and its resolution, the pin (MEHEN_WORKSPACE, or mcp --workspace
// folded into it) and the startup cwd manifest are fixed at start; the
// latch table grows as slots are first used and never widens what the
// ceiling admitted. On a managed host `managed` is the pinned slot and the
// only one ever read (rule 0).
export type McpServer = {
  home: string
  managed: string | null
  ceiling: CeilingEntry[] | null
  allowed: Admission[] | null
  pin: McpPin | null
  manifest: ManifestWorkspace | null
  // Keyed by the slot's real path.
  slots: Map<string, SlotBinding>
  // The directory and config each latched slot was last validated with, so
  // a slot that vanished or changed is still named, and refused, by a call.
  seen: Map<string, SeenSlot>
  realRoot: string
}

// An active slot a call may use: on disk now, or latched earlier and no
// longer readable as the active slot it was (`onDisk` false).
export type SpanSlot = { dir: string; config: Config; onDisk: boolean }

// What a spanning tool covers: the active slots, the pending enrolments,
// the corrupt slots (reported only) and the admitted entries that match
// nothing on disk (allowed, not enrolled).
export type Span = { active: SpanSlot[]; pending: FoundPending[]; corrupt: FoundCorrupt[]; absent: Admission[] }

// How a call that needs one workspace chooses it: the `workspace` argument,
// and for vault_env its own cwd manifest, which must then agree (`strict`).
export type CallSelection = { manifest?: ManifestWorkspace | null; strict?: boolean }

// Whether the host's initialize negotiated MCP Apps (SEP-1865, the
// io.modelcontextprotocol/ui extension). One server process serves one
// connection, so this is the connection's.
export type McpApps = { negotiated: boolean }

export type ToolDeps = {
  env: Env
  server: McpServer
  apps: McpApps
  // The one slot this call uses, its latch checked, and a
  // session on it.
  session(workspace?: string | null, selection?: CallSelection): Promise<VaultSession>
  // Every slot a spanning tool covers: the named workspace's, else the pin's, else the allowed set.
  span(workspace?: string | null): Promise<Span>
  // A session on one spanned slot, its latch checked first.
  open(slot: SpanSlot): Promise<VaultSession>
  // The latch check alone, for a slot doctor is about to sign for.
  validate(slot: SpanSlot): Promise<Config>
  // The vault and workspace this call last used, for checking a link in its error.
  used: { vaultUrl: string; workspaceSlug: string | null } | null
  // Test seams only: awaited between an enrolment's activation commit and
  // the server's completion validation.
  barriers?: { afterActivation?: () => Promise<void> }
  // Sends a server-to-client notification (notifications/progress).
  notify(notification: JsonRpcNotification): void
  calls: CallRegistry
  // The server's watch over its own executable: the
  // verified newer binary on disk, for `cli.mcp`; absent in-process.
  selfWatch?: { cliMcp(): CliMcp | null } | null
  // The server's handover decision at its start, for `cli.mcpHandover`
  // and `tools.listChanged`; absent in-process.
  mcpHandover?: McpHandover
  // The toolsets this server lists and calls, fixed at its start; the core
  // alone when absent.
  toolsets?: readonly Toolset[]
}

// What the host attached to this call: a progressToken means it wants
// notifications/progress while the call runs; the signal aborts when the
// host cancels the request.
export type ToolCall = { progressToken: ProgressToken | null; signal: AbortSignal }

// A link handed to a human, with the then: line for its block (null drops it).
type Handover = { ask: Ask; then: string | null }

// What a tool produced: the structuredContent, every ask it hands over (each
// becomes a resource_link and its block is the text), and a warning when a
// link the vault returned was refused and rebuilt.
export type ToolOutput = { structured: Record<string, unknown>; handover: Handover[]; warning: string | null; text?: string[] }

// The optional argument every tool but vault_templates takes.
export const WORKSPACE_ARG = z.string().optional().describe("slug or id, when several workspaces could serve")

// The startup checkout's project, for a call that uses that checkout's
// workspace (or any, when the checkout names none): a project never
// follows a call into another workspace.
export function manifestProject(server: McpServer, config: Config): string | null {
  const manifest = server.manifest
  if (!manifest) return null
  if (manifest.workspace !== null && (manifest.workspace !== config.tenant || (manifest.vault !== null && manifest.vault !== config.vault))) return null
  return manifest.project
}

export function plain(structured: Record<string, unknown>): ToolOutput {
  return { structured, handover: [], warning: null }
}

// The then: line of an ask block in MCP: the tool to call, never a shell
// command. The id passed isWaitId when the ask was built (wait is null otherwise).
export function mcpThen(ask: Ask): string | null {
  return ask.wait ? `vault_wait { "id": ${JSON.stringify(ask.id)} }` : null
}

export function handing(structured: Record<string, unknown>, ask: Ask | null, warning: string | null, then?: string | null): ToolOutput {
  return { structured, handover: ask ? [{ ask, then: then === undefined ? mcpThen(ask) : then }] : [], warning }
}

// The MCP tool annotations: hints a host may use to let a read through
// without asking, or to warn before a call that acts on the world.
// destructiveHint and idempotentHint apply only when readOnlyHint is false
// (the MCP spec), so a tool that only reads leaves them out.
export type ToolAnnotations = { readOnlyHint: true; openWorldHint: boolean } | { readOnlyHint: false; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean }

// A tool that only reads: from the vault, this machine or the catalogue.
export const READS: ToolAnnotations = { readOnlyHint: true, openWorldHint: false }

type OutputType = "string" | "integer" | "boolean" | "array" | "object" | "null"

// The fields of a tool's structuredContent, by type, none required: an
// error's structuredContent is the error body, and a host that checks
// results against outputSchema (the MCP TypeScript SDK checks errors too)
// would refuse it otherwise. No field an error body carries is named
// (error, next, status, item and the rest), so the two never disagree.
export function outputSchema(fields: Record<string, OutputType | OutputType[]>): Record<string, unknown> {
  return { type: "object", properties: Object.fromEntries(Object.entries(fields).map(([name, type]) => [name, { type }])) }
}

type Tool<S extends z.ZodType> = {
  name: string
  title: string
  description: string
  input: S
  // What tools/list advertises when narrower than what input parses: the
  // vault then answers a wider value with its own structured refusal.
  advertised?: z.ZodType
  output?: Record<string, unknown>
  annotations: ToolAnnotations
  call(args: z.infer<S>, deps: ToolDeps, call: ToolCall): Promise<ToolOutput>
}

export function tool<S extends z.ZodType>(definition: Tool<S>): Tool<z.ZodType> {
  return definition as unknown as Tool<z.ZodType>
}
