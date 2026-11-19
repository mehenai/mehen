import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path"
import { usageError } from "../errors.ts"
import { WAIT_MAX_SECONDS } from "../mcp/constants.ts"
import { info } from "./files.ts"
import type { SkillBase } from "./skills.ts"

export type AgentName = "claude-code" | "codex" | "cursor" | "pi" | "gemini" | "opencode" | "vscode" | "claude-desktop"
// One harness setup writes the `mehen` entry into. `key` is its ownership
// key in setup-state.json (the file relative to HOME, or absolute for an
// --mcp-file outside it); `base` is the directory every read and write of
// the file is contained in (HOME, or that file's own directory); `skills`
// is the folder the harness reads skills from, null when it reads none.
export type Agent = { name: AgentName | "mcp-file"; binary: string | null; dir: string | null; file: string; key: string; base: string; section: string; restart: string; skills: SkillBase | null; toml?: boolean }
export const MCP_FILE = "mcp-file"

export function agents(home: string, platform = process.platform): Agent[] {
  const mac = platform === "darwin"
  const vscode = mac ? "Library/Application Support/Code/User" : ".config/Code/User"
  const desktop = mac ? "Library/Application Support/Claude" : ".config/Claude"
  const list: Omit<Agent, "key" | "base">[] = [
    { name: "claude-code", binary: "claude", dir: ".claude", file: ".claude.json", section: "mcpServers", skills: ".claude", restart: "Restart Claude Code." },
    { name: "codex", binary: "codex", dir: ".codex", file: ".codex/config.toml", section: "mcp_servers", toml: true, skills: ".agents", restart: "Restart Codex." },
    { name: "cursor", binary: "cursor", dir: ".cursor", file: ".cursor/mcp.json", section: "mcpServers", skills: ".agents", restart: "Reload the Cursor window." },
    { name: "pi", binary: "pi", dir: ".pi", file: ".pi/agent/mcp.json", section: "mcpServers", skills: ".agents", restart: "Restart pi (check with `pi mcp list`)." },
    { name: "gemini", binary: "gemini", dir: ".gemini", file: ".gemini/settings.json", section: "mcpServers", skills: ".agents", restart: "Restart Gemini CLI and trust the folder you work in; user-level servers are off in untrusted folders." },
    { name: "opencode", binary: "opencode", dir: ".config/opencode", file: ".config/opencode/opencode.json", section: "mcp", skills: ".agents", restart: "Restart OpenCode." },
    { name: "vscode", binary: "code", dir: vscode, file: `${vscode}/mcp.json`, section: "servers", skills: ".agents", restart: "Run Developer: Reload Window in VS Code (default user profile)." },
    { name: "claude-desktop", binary: "claude-desktop", dir: desktop, file: `${desktop}/claude_desktop_config.json`, section: "mcpServers", skills: null, restart: "Quit and reopen Claude Desktop." },
  ]
  return list.map((agent) => ({ ...agent, dir: join(home, agent.dir!), file: join(home, agent.file), key: agent.file, base: home }))
}

function insideHome(home: string, path: string): boolean {
  const rel = relative(home, path)
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)
}

// `--mcp-file <path>`: `mcpServers.mehen` in any JSON MCP client's
// file. Under HOME it is owned like an agent file; elsewhere its own
// directory, which must exist, contains every read and write of it.
export function mcpFileAgent(home: string, path: string): Agent {
  const file = resolve(path)
  const under = insideHome(home, file)
  return { name: MCP_FILE, binary: null, dir: null, file, key: under ? relative(home, file) : file, base: under ? home : dirname(file), section: "mcpServers", skills: null, restart: `Restart the client that reads ${file}.` }
}
// A retired per-workspace registration's state key: a known agent's file,
// `#`, and a `mehen-<slug>` server, the only shape 0.2.0 wrote (design
// 15.7). Every other key is a whole file path, so a file name that merely
// contains `#` is never read as another file's server.
export function legacyServerKey(key: string, known: Agent[]): boolean {
  return known.some((agent) => agent.name !== MCP_FILE && key.startsWith(`${agent.key}#mehen-`))
}
// The --mcp-file agent a setup-state key records, or null when the key is
// a known agent's file or a retired registration of one.
export function recordedMcpFile(home: string, key: string, known: Agent[]): Agent | null {
  if (known.some((agent) => agent.key === key) || legacyServerKey(key, known)) return null
  return mcpFileAgent(home, isAbsolute(key) ? key : join(home, key))
}
// An --mcp-file outside HOME is contained in its own directory, pinned by
// identity for the whole run: it must be a real directory, not a
// link, and every read and write first checks it is still the same one,
// so a link that replaces it can never become the containment root. A file
// under HOME is contained in HOME as before (no pin).
export type PinnedBase = { path: string; dev: number; ino: number }
export async function pinMcpFileBase(agent: Agent, home: string): Promise<PinnedBase | null> {
  if (agent.name !== MCP_FILE || agent.base === home) return null
  const base = await info(agent.base)
  if (!base || base.isSymbolicLink() || !base.isDirectory()) throw usageError(`${agent.base} is not an existing real directory; --mcp-file outside HOME writes only into an existing directory, never through a symbolic link.`)
  return { path: agent.base, dev: base.dev, ino: base.ino }
}
export async function assertPinnedBase(pin: PinnedBase | null): Promise<void> {
  if (pin === null) return
  const base = await info(pin.path)
  if (!base || base.isSymbolicLink() || !base.isDirectory() || base.dev !== pin.dev || base.ino !== pin.ino) {
    throw usageError(`${pin.path} is no longer the directory setup checked (it was replaced or turned into a link), so nothing was written there. Look at it, then run mehen setup --json again.`)
  }
}

// Where an entry keeps its environment.
export function envField(agent: Agent): "env" | "environment" {
  return agent.name === "opencode" ? "environment" : "env"
}
// A harness's own tool-call limit for the entry: vault_wait's longest wait
// and a minute's margin, so the harness never stops a wait Mehen would
// still answer. Codex counts seconds (tool_timeout_sec), OpenCode and
// Gemini CLI milliseconds (timeout); the others have no per-server key.
export const TOOL_TIMEOUT_SECONDS = WAIT_MAX_SECONDS + 60
function toolTimeout(agent: Agent): Record<string, number> {
  if (agent.name === "codex") return { tool_timeout_sec: TOOL_TIMEOUT_SECONDS }
  if (agent.name === "opencode" || agent.name === "gemini") return { timeout: TOOL_TIMEOUT_SECONDS * 1000 }
  return {}
}
// The one MCP server entry an agent file gets: always `mehen mcp`,
// with the harness's tool timeout and the env setup decided (the ceiling
// and the root), or none.
export function serverEntry(agent: Agent, binary: string, env: Record<string, unknown> | null = null): Record<string, unknown> {
  const extra = { ...toolTimeout(agent), ...(env !== null && Object.keys(env).length > 0 ? { [envField(agent)]: env } : {}) }
  if (agent.name === "opencode") return { type: "local", command: [binary, "mcp"], enabled: true, ...extra }
  if (agent.name === "vscode" || agent.name === "claude-code") return { type: "stdio", command: binary, args: ["mcp"], ...extra }
  return { command: binary, args: ["mcp"], ...extra }
}
