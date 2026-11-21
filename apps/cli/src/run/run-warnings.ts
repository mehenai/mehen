// The warnings mehen run prints when the child might not get what the vault
// delivered: a .env file a loader reads by itself, a Node too old to use the
// local relay, or a run whose placeholders never passed through the relay.
// Each is printed once per run and never stops it.

import { readdirSync, realpathSync, statSync } from "node:fs"
import { basename, isAbsolute, join, relative, resolve } from "node:path"
import type { NextStep } from "@mehen/protocol/api"

export const RUN_COMPATIBILITY_URL = "https://docs.mehen.dev/guides/run-compatibility"

export type RunWarning = { message: string; next: NextStep; commands?: string[] }

// Committed examples, which hold names rather than values.
const DOTENV_EXAMPLES: ReadonlySet<string> = new Set([".env.example", ".env.sample", ".env.template"])

function isDotenvName(name: string): boolean {
  return (name === ".env" || name.startsWith(".env.")) && !DOTENV_EXAMPLES.has(name)
}

// A folder by its real path, so a linked working folder and the manifest's
// folder name each file once.
function realFolder(dir: string): string {
  try {
    return realpathSync(dir)
  } catch {
    return resolve(dir)
  }
}

// Every .env or .env.* file directly in these folders, once each, sorted.
// A folder that cannot be read has none.
export function dotenvFiles(dirs: readonly string[]): string[] {
  const found = new Set<string>()
  for (const dir of new Set(dirs.map(realFolder))) {
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of names) {
      if (!isDotenvName(name)) continue
      const path = join(dir, name)
      try {
        if (statSync(path).isFile()) found.add(path)
      } catch {
        // A dangling link loads nothing.
      }
    }
  }
  return [...found].sort()
}

function shownPath(path: string, cwd: string): string {
  const rel = relative(cwd, path)
  return rel === "" || rel.startsWith("..") || isAbsolute(rel) ? path : rel
}

export function dotenvWarning(files: readonly string[], cwd: string, command: string): RunWarning | null {
  if (files.length === 0) return null
  const shown = files.map((f) => shownPath(f, cwd))
  const one = shown.length === 1
  return {
    message: `${shown.join(", ")} ${one ? "is" : "are"} next to this run: Bun, Next.js, Vite, dotenv and others load ${one ? "it" : "them"} by themselves, so ${command} can see ${one ? "its" : "their"} plaintext values instead of the vault's`,
    next: { say: `Move ${one ? "its" : "their"} keys into the vault with mehen adopt file, which prints the steps that follow, then take ${one ? "the file" : "each file"} out of play with mehen adopt retire.` },
    commands: shown.map((f) => `mehen adopt file ${f}`),
  }
}

// The commands that start Node, by the basename of argv[0].
const NODE_COMMANDS: ReadonlySet<string> = new Set(["node", "npm", "npx", "pnpm", "yarn", "tsx"])

export function startsNode(argv0: string): boolean {
  return NODE_COMMANDS.has(basename(argv0).replace(/\.(exe|cmd)$/i, ""))
}

// What a Node version misses of NODE_USE_ENV_PROXY, or null when it routes
// every request through the proxy. fetch() honours it from 24.0.0 and
// 22.21.0, node:http and node:https from 24.5.0 and 22.21.0 (Node's cli.md
// and http.md, Built-in Proxy Support). 23 never had it.
export function nodeProxyGap(version: string): "none" | "fetch-only" | null {
  const match = /^v?(\d+)\.(\d+)\.\d+/.exec(version.trim())
  if (match === null) return null
  const major = Number(match[1])
  const minor = Number(match[2])
  if (major >= 25 || (major === 24 && minor >= 5) || (major === 22 && minor >= 21)) return null
  return major === 24 ? "fetch-only" : "none"
}

export function nodeWarning(version: string): RunWarning | null {
  const gap = nodeProxyGap(version)
  if (gap === null) return null
  const what = gap === "fetch-only" ? "honours NODE_USE_ENV_PROXY for fetch() only, so node:http and node:https requests skip" : "ignores NODE_USE_ENV_PROXY, so its requests skip"
  return {
    message: `Node ${version} ${what} mehen's local relay: a placeholder they send goes straight to the API, which answers 401`,
    next: { say: `Use Node 22.21.0 or later on 22, or 24.5.0 or later. Other options: ${RUN_COMPATIBILITY_URL}` },
  }
}

// The version of the Node the child will run, from the child's own PATH, or
// null when the command does not start Node, none is found, or it does not
// answer within two seconds.
export async function childNodeVersion(argv0: string, env: Record<string, string>, cwd: string, timeoutMs = 2000): Promise<string | null> {
  if (!startsNode(argv0)) return null
  const name = basename(argv0).replace(/\.(exe|cmd)$/i, "")
  const binary = Bun.which(name === "node" ? argv0 : "node", { PATH: env.PATH ?? "", cwd })
  if (binary === null) return null
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const child = Bun.spawn([binary, "--version"], { env, cwd, stdin: "ignore", stdout: "pipe", stderr: "ignore" })
    // A version manager's shim can leave a grandchild holding stdout open, so
    // the wait ends on the timer, not on the pipe closing.
    const late = new Promise<null>((done) => {
      timer = setTimeout(() => {
        child.kill("SIGKILL")
        done(null)
      }, timeoutMs)
    })
    const text = await Promise.race([new Response(child.stdout).text(), late])
    return text === null ? null : (/^v\d+\.\d+\.\d+/.exec(text.trim())?.[0] ?? null)
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

export function bypassWarning(hosts: readonly string[], command: string): RunWarning | null {
  if (hosts.length === 0) return null
  const listed = hosts.length > 3 ? `${hosts.slice(0, 3).join(", ")} and ${hosts.length - 3} more` : hosts.join(", ")
  return {
    message: `no connection to ${listed} came through mehen's local relay. If ${command} called ${hosts.length === 1 ? "it" : "them"}, it bypassed the proxy (some HTTP clients ignore HTTPS_PROXY) and the API saw only the placeholder`,
    next: { say: `Check that the program's HTTP client uses HTTPS_PROXY and the run's CA: ${RUN_COMPATIBILITY_URL}` },
  }
}
