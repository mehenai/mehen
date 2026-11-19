// Where `mehen adopt scan` looks and how it reads a file. Reading is the
// only place a value enters the process: lstat first, refuse symlinks,
// other users' files and anything over 1 MiB, then open with O_NOFOLLOW.
// A refusal names the path and why, never a byte of the file.

import { constants } from "node:fs"
import { lstat, open, readdir, realpath } from "node:fs/promises"
import { basename, dirname, join, relative, sep } from "node:path"
import { EnvName } from "@mehen/protocol/api"
import { slugFrom } from "../run/init.ts"

export const MAX_SOURCE_BYTES = 1024 * 1024

// A dotenv file name's suffix to the environment it is for.
export const ENV_BY_SUFFIX: Readonly<Record<string, string>> = { local: "dev", development: "dev", dev: "dev", production: "prod", prod: "prod", staging: "staging", stage: "staging", test: "test", testing: "test" }

// The environment a dotenv file is for, from its name. A local override is
// for the environment of the file it overrides: .env.production.local is prod.
export function envForFile(path: string): string {
  const name = basename(path).toLowerCase()
  const suffix = /^\.env\.(.+?)(\.local)?$/.exec(name)?.[1]
  if (suffix === undefined) return "dev"
  if (Object.hasOwn(ENV_BY_SUFFIX, suffix)) return ENV_BY_SUFFIX[suffix] as string
  const slug = slugFrom(suffix).slice(0, 32)
  return EnvName.safeParse(slug).success ? slug : "dev"
}

// An override file in its base's folder: .env.local over .env,
// .env.production.local over .env.production.
export function overridesFile(path: string, base: string): boolean {
  return dirname(path) === dirname(base) && basename(path).startsWith(`${basename(base)}.`)
}

// dotenv: .env, .env.*, .dev.vars, *.env. envrc: literal exports only.
// json: settings files, key names at any depth. plist and systemd: service
// units. The rest are login state at fixed paths (spec section 9).
export type SourceType = "dotenv" | "envrc" | "json" | "secrets-file" | "plist" | "systemd" | "gh-hosts" | "kubeconfig" | "talosconfig" | "gcloud-adc" | "wrangler" | "docker"

// What a source is for, which decides its proposed home (decision 5).
export type SourceCategory = "repo" | "local-secrets" | "settings" | "service" | "login" | "config"

export const SKIP_DIRS: ReadonlySet<string> = new Set(["node_modules", ".git", "vendor", "dist", "build", ".venv", "Library"])

const EXAMPLE_SUFFIX = /\.(example|sample|template|dist|defaults)$/i
// config.example.json, settings.local.sample.json: a template, not settings.
const EXAMPLE_PART = /(^|\.)(example|sample|template)s?\./i
const SETTINGS_JSON = /(^|[._-])(settings|config|credentials|secrets)([._-][^/]*)?\.json$/i

export function sourceType(path: string): SourceType | null {
  const name = basename(path)
  if (EXAMPLE_SUFFIX.test(name) || EXAMPLE_PART.test(name)) return null
  if (name === ".envrc") return "envrc"
  if (name === ".env" || name.startsWith(".env.") || name === ".dev.vars" || name.endsWith(".env")) return "dotenv"
  if (name.endsWith(".plist") && basename(dirname(path)) === "LaunchAgents") return "plist"
  if (name.endsWith(".service") && dirname(path).endsWith(`systemd${sep}user`)) return "systemd"
  if (SETTINGS_JSON.test(name)) return "json"
  // Anything else kept in a .local-secrets folder: NAME=value lines, or one
  // key or token on its own (parseSecretsFile).
  if (path.split(sep).includes(".local-secrets") && !name.startsWith(".")) return "secrets-file"
  return null
}

export type ScanRoot = { path: string; depth: number }

// The roots a scan walks when none is given (spec 2.1).
export function defaultRoots(home: string, platform: NodeJS.Platform = process.platform): ScanRoot[] {
  const roots: ScanRoot[] = [
    { path: join(home, "code"), depth: 6 },
    { path: join(home, ".config"), depth: 4 },
    { path: join(home, ".local-secrets"), depth: 3 },
  ]
  if (platform === "darwin") roots.push({ path: join(home, "Library", "LaunchAgents"), depth: 1 })
  else roots.push({ path: join(home, ".config", "systemd", "user"), depth: 1 })
  return roots
}

export type LoginFile = { path: string; type: SourceType }

// Login state and settings at fixed paths, read when they exist (decision 8).
export function loginFiles(home: string, platform: NodeJS.Platform = process.platform): LoginFile[] {
  const files: LoginFile[] = [
    { path: join(home, ".config", "gh", "hosts.yml"), type: "gh-hosts" },
    { path: join(home, ".kube", "config"), type: "kubeconfig" },
    { path: join(home, ".talos", "config"), type: "talosconfig" },
    { path: join(home, ".config", "gcloud", "application_default_credentials.json"), type: "gcloud-adc" },
    { path: join(home, ".wrangler", "config", "default.toml"), type: "wrangler" },
    { path: join(home, ".config", ".wrangler", "config", "default.toml"), type: "wrangler" },
    { path: join(home, ".docker", "config.json"), type: "docker" },
    { path: join(home, ".claude", "settings.json"), type: "json" },
  ]
  if (platform === "darwin") files.push({ path: join(home, "Library", "Preferences", ".wrangler", "config", "default.toml"), type: "wrangler" })
  return files
}

export function isLoginType(type: SourceType): boolean {
  return type === "gh-hosts" || type === "kubeconfig" || type === "talosconfig" || type === "gcloud-adc" || type === "wrangler" || type === "docker"
}

export function sourceCategory(path: string, type: SourceType, inRepo: boolean): SourceCategory {
  if (isLoginType(type)) return "login"
  if (type === "plist" || type === "systemd") return "service"
  if (path.split(sep).includes(".local-secrets")) return "local-secrets"
  if (type === "json") return "settings"
  return inRepo ? "repo" : "config"
}

const ARCHIVED = new Set(["archive", "archived", "old", "attic"])

// A folder put aside: ci-runner.retired-20261003, ci-runner-retired,
// ci-runner_retired_20261003, app.bak, app.bak-20261027, config.old-2024,
// app.backup.1, app~.
const RETIRED_FOLDER = /([._-]retired([-._].*)?|\.(bak|backup|old|orig)([-.].*)?|~)$/i
// billing-old, unless it is `liveRepo`: a repo root with an origin, such as
// a live site-old.
const OLD_FOLDER = /-old$/i

// Leading marks count for nothing: _archive and .old are archives too. The
// file's own name is backupCopy's.
export function archivedPath(path: string, liveRepo: string | null = null): boolean {
  if (path.split(sep).some((part) => ARCHIVED.has(part.toLowerCase().replace(/^[._-]+/, "")))) return true
  const parts = dirname(path).split(sep)
  return parts.some((part, i) => RETIRED_FOLDER.test(part) || (OLD_FOLDER.test(part) && parts.slice(0, i + 1).join(sep) !== liveRepo))
}

const FIXTURES = new Set(["test", "tests", "__tests__", "fixtures", "__fixtures__", "testdata", "test-data", "example", "examples", "samples"])

// A folder of test fixtures or examples below home: a cloned project's
// tests/.env or examples/.env holds sample values.
export function fixturePath(path: string, home: string): boolean {
  const below = relative(home, dirname(path))
  return below.split(sep).some((part) => FIXTURES.has(part.toLowerCase()))
}

const BACKUP_SUFFIX = /\.(bak|backup|orig|old)([-.][^/]*)?$|~$/i

// keys.env.bak-20261027, .env.orig, .env.old: a copy someone kept aside.
export function backupCopy(path: string): boolean {
  return BACKUP_SUFFIX.test(basename(path))
}

// The file a backup copy was taken of: .env for .env.bak-20260908-174826.
export function backupBase(path: string): string {
  return join(dirname(path), basename(path).replace(BACKUP_SUFFIX, ""))
}

// The git worktree a file is in, by looking for .git upwards; no process
// per file. Null outside a repo.
export async function repoRootOf(path: string, stop: string): Promise<string | null> {
  for (let dir = dirname(path); ; dir = dirname(dir)) {
    try {
      await lstat(join(dir, ".git"))
      return dir
    } catch {}
    if (dir === stop || dirname(dir) === dir) return null
  }
}

export type ReadResult = { ok: true; text: string; mtimeMs: number } | { ok: false; why: string }

const BINARY_PROBE = 8192

// The one way adopt reads a source. The text stays in the caller's memory.
export async function readSource(path: string): Promise<ReadResult> {
  let info: Awaited<ReturnType<typeof lstat>>
  try {
    info = await lstat(path)
  } catch {
    return { ok: false, why: "cannot be read" }
  }
  if (info.isSymbolicLink()) return { ok: false, why: "a symlink" }
  if (!info.isFile()) return { ok: false, why: "not a regular file" }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) return { ok: false, why: "owned by another user" }
  if (info.size > MAX_SOURCE_BYTES) return { ok: false, why: "over 1 MiB" }
  let handle: Awaited<ReturnType<typeof open>>
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch {
    return { ok: false, why: "cannot be opened" }
  }
  try {
    const stat = await handle.stat()
    if (!stat.isFile()) return { ok: false, why: "not a regular file" }
    if (stat.dev !== info.dev || stat.ino !== info.ino || stat.uid !== info.uid) return { ok: false, why: "changed while it was read" }
    const buffer = new Uint8Array(MAX_SOURCE_BYTES + 1)
    let total = 0
    for (;;) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, null)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > MAX_SOURCE_BYTES) return { ok: false, why: "over 1 MiB" }
    }
    const bytes = buffer.subarray(0, total)
    if (bytes.subarray(0, BINARY_PROBE).includes(0)) return { ok: false, why: "binary" }
    let text: string
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
    } catch {
      return { ok: false, why: "binary" }
    }
    return { ok: true, text: text.replace(/^\uFEFF/, ""), mtimeMs: stat.mtimeMs }
  } finally {
    await handle.close()
  }
}

export type WalkSkip = { path: string; why: string }

// Every candidate file under a root, as a real path inside that root. A
// symlinked file is followed only when it resolves inside the root and its
// target is not excluded; a symlinked directory is never entered.
export async function walkRoot(root: ScanRoot, accept: (path: string) => boolean, excluded: (path: string) => boolean, skipped: WalkSkip[]): Promise<string[]> {
  let top: string
  try {
    top = await realpath(root.path)
  } catch {
    return []
  }
  const found: string[] = []
  const visit = async (dir: string, depth: number): Promise<void> => {
    let entries: import("node:fs").Dirent[]
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (depth < root.depth && !SKIP_DIRS.has(entry.name)) await visit(path, depth + 1)
        continue
      }
      if (entry.isSymbolicLink()) {
        if (!accept(path)) continue
        let target: string
        try {
          target = await realpath(path)
        } catch {
          continue
        }
        if (relative(top, target).startsWith("..")) skipped.push({ path, why: "a symlink out of the root" })
        else if (!excluded(target)) found.push(target)
        continue
      }
      if (entry.isFile() && accept(path)) found.push(path)
    }
  }
  await visit(top, 1)
  return found
}
