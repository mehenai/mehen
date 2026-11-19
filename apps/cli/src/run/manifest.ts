// mehen.toml: the committed project manifest, and the git facts sent with it.
//
// Discovery walks up from the current directory to the nearest mehen.toml and
// stops at the git worktree root; outside a repo only the current directory
// counts. No guessing from paths, so a temp dir cannot escape into $HOME.

import { existsSync, readFileSync, realpathSync } from "node:fs"
import { dirname, join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { canonicalOrigin } from "../config.ts"
import { CliError } from "../errors.ts"
import { CommandError } from "./deps.ts"

export const MANIFEST_FILE = "mehen.toml"

export type ManifestVar = { name: string; source: "vault" } | { name: string; source: "plain"; value: string }

// `workspace` is the workspace id and `vault` its canonical origin (design
// 6.5): both optional in a v1 manifest, both written by mehen init. They
// select a local context; they never authorise anything.
export type Manifest = {
  path: string
  project: string
  workspace: string | null
  vault: string | null
  defaultEnv: string | null
  vars: ManifestVar[]
}

const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/

export type GitFacts = {
  // The worktree root, or null outside a repo.
  root: string | null
  remote: string | null
  head: string | null
}

function git(cwd: string, args: string[]): string | null {
  try {
    const result = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "ignore" })
    if (result.exitCode !== 0) return null
    const out = result.stdout.toString().trim()
    return out === "" ? null : out
  } catch {
    return null
  }
}

// "git@github.com:a/b.git", "https://github.com/a/b" and "ssh://git@github.com:22/a/b.git"
// all become "github.com/a/b": host and path, no user, port or ".git", lower
// case. Local paths and file:// remotes identify no shared repo: null.
export function normaliseRemote(url: string | null): string | null {
  if (url === null) return null
  const raw = url.trim()
  let host: string
  let path: string
  const scp = raw.match(/^(?:[^@/:]+@)?([^/:]+):(?!\/\/)(.+)$/)
  if (!raw.includes("://") && scp?.[1] && scp[2]) {
    host = scp[1]
    path = scp[2]
  } else {
    let parsed: URL
    try {
      parsed = new URL(raw)
    } catch {
      return null
    }
    if (parsed.protocol === "file:" || parsed.hostname === "") return null
    host = parsed.hostname
    path = parsed.pathname
  }
  const cleanPath = path.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\.git$/, "")
  if (cleanPath === "") return null
  return `${host}/${cleanPath}`.toLowerCase()
}

export function gitFacts(cwd: string): GitFacts {
  const root = git(cwd, ["rev-parse", "--show-toplevel"])
  if (root === null) return { root: null, remote: null, head: null }
  return {
    root: realpathSync(root),
    remote: normaliseRemote(git(cwd, ["remote", "get-url", "origin"])),
    head: git(cwd, ["rev-parse", "--short", "HEAD"]),
  }
}

export function findManifest(cwd: string, root: string | null): string | null {
  const start = realpathSync(cwd)
  if (root === null) {
    const only = join(start, MANIFEST_FILE)
    return existsSync(only) ? only : null
  }
  for (let dir = start; ; dir = dirname(dir)) {
    const candidate = join(dir, MANIFEST_FILE)
    if (existsSync(candidate)) return candidate
    if (dir === root || dirname(dir) === dir) return null
  }
}

export function parseManifest(path: string, text: string): Manifest {
  const invalid = (why: string) => new CommandError(EXIT.error, `${path} is not a valid mehen.toml: ${why}`, { say: "Fix mehen.toml, or run mehen init in a fresh repo to write one." })
  let data: Record<string, unknown>
  try {
    data = Bun.TOML.parse(text) as Record<string, unknown>
  } catch (error) {
    throw invalid(error instanceof Error ? error.message : String(error))
  }
  const project = data.project
  if (typeof project !== "string" || project === "") throw invalid('project = "prj_..." is required')
  const workspace = data.workspace
  if (workspace !== undefined && (typeof workspace !== "string" || !WORKSPACE_ID.test(workspace))) throw invalid('workspace = "tn_..." must be the workspace id')
  const vault = data.vault
  if (vault !== undefined && typeof vault !== "string") throw invalid("vault must be the vault's https origin")
  let vaultOrigin: string | null = null
  if (vault !== undefined) {
    try {
      vaultOrigin = canonicalOrigin(vault)
    } catch (error) {
      throw invalid(error instanceof Error ? error.message : String(error))
    }
  }
  const defaultEnv = data.default_env
  if (defaultEnv !== undefined && typeof defaultEnv !== "string") throw invalid("default_env must be a string")
  const table = data.vars ?? {}
  if (typeof table !== "object" || table === null || Array.isArray(table)) throw invalid("[vars] must be a table")
  const vars: ManifestVar[] = []
  for (const [name, value] of Object.entries(table)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) throw invalid(`${name} is not a valid variable name`)
    if (value === "vault") vars.push({ name, source: "vault" })
    else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") vars.push({ name, source: "plain", value: String(value) })
    else throw invalid(`${name} must be "vault" or a plain value`)
  }
  return { path, project, workspace: workspace ?? null, vault: vaultOrigin, defaultEnv: defaultEnv ?? null, vars }
}

// What the cwd's manifest says about which workspace it belongs to, for
// context selection (design 15.6): null only when there is no manifest. A
// manifest that is present but unreadable or invalid is a local refusal
// (workspace_unbound, exit 2) before any selection completes, key is read
// or request is signed: it cannot say which workspace it belongs to, and
// nothing in it, its origin included, is trusted.
export type ManifestWorkspace = { path: string; project: string; workspace: string | null; vault: string | null }

export function manifestWorkspace(cwd: string): ManifestWorkspace | null {
  let path: string | null
  try {
    path = findManifest(cwd, gitFacts(cwd).root)
  } catch {
    return null
  }
  if (path === null) return null
  let text: string
  try {
    text = readFileSync(path, "utf8")
  } catch (error) {
    throw invalidManifest(path, `it cannot be read (${error instanceof Error ? error.message : String(error)})`)
  }
  try {
    const { project, workspace, vault } = parseManifest(path, text)
    return { path, project, workspace, vault }
  } catch (error) {
    const why = error instanceof Error ? error.message.replace(`${path} is not a valid mehen.toml: `, "") : String(error)
    throw invalidManifest(path, why)
  }
}

function invalidManifest(path: string, why: string): CliError {
  return new CliError("workspace_unbound", `${path} is not a valid mehen.toml (${why}), so it cannot say which workspace this checkout belongs to.`, {
    command: "mehen workspace bind",
    say: "Fix mehen.toml (the message says what is wrong), then run `mehen workspace bind` in the checkout to record its workspace and vault; nothing is sent until it parses.",
  })
}

export type Located = { manifest: Manifest; git: GitFacts; worktree: string }

export function locateManifest(cwd: string, facts: GitFacts = gitFacts(cwd)): Located {
  const path = findManifest(cwd, facts.root)
  if (path === null) {
    const where = facts.root === null ? `${cwd} (not in a git repo, so only this directory counts)` : `${cwd} or above it up to the worktree root ${facts.root}`
    throw new CommandError(EXIT.error, `no ${MANIFEST_FILE} in ${where}`, {
      say: "Run mehen init at the repo root to create the project and write mehen.toml.",
      command: "mehen init",
    })
  }
  return { manifest: parseManifest(path, readFileSync(path, "utf8")), git: facts, worktree: facts.root ?? realpathSync(cwd) }
}
