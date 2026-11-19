// mehen adopt scan: find the files on this machine that hold credentials,
// classify every name in them, and write what was found without a value.
// Values live only in this function's memory while it classifies them;
// equal values share a duplicate label made under a key that exists only
// for this run, so neither the labels nor the file say anything about a
// value across runs.

import { lstat, realpath } from "node:fs/promises"
import { dirname, join, relative, resolve, sep } from "node:path"
import { type Bytes, randomBytes, sha256, utf8 } from "@mehen/protocol/bytes"
import { KindSchema } from "@mehen/protocol/api"
import { secretLikeness } from "@mehen/protocol/secret-likeness"
import type { ItemKind } from "@mehen/protocol/kinds"
import { z } from "zod"
import { type Env, homeDir } from "../config.ts"
import { CliError } from "../errors.ts"
import { resolveHome } from "../home.ts"
import { gitFacts } from "../run/manifest.ts"
import { type SourceClass, type SourceStatus, classify, isPublicField } from "./classify.ts"
import type { OutputGuard } from "./output-guard.ts"
import { parseSource } from "./parse.ts"
import { adoptDir, machineName, readPrivateJson, writePrivateFile } from "./state.ts"
import { type ScanRoot, type SourceCategory, type SourceType, type WalkSkip, archivedPath, backupCopy, envForFile, fixturePath, defaultRoots, loginFiles, overridesFile, readSource, repoRootOf, sourceCategory, sourceType, walkRoot } from "./sources.ts"

export type ProposedHome = "private" | "workspace" | "project"

export type ScanEntry = {
  // "s" and base32 of the real path and the name: stable across scans,
  // never derived from the value.
  id: string
  path: string
  type: SourceType
  category: SourceCategory
  variable: string | null
  pointer: string | null
  line: number
  repo: { root: string; remote: string | null } | null
  // The unit whose environment this is, for a service.
  unit: string | null
  class: SourceClass
  kind: ItemKind | null
  provider: string | null
  field: string | null
  reason: string
  // Equal values within this scan share a label; null when unique.
  dup: string | null
  stale: string[]
  status: SourceStatus
  why: string | null
  storeOnly: string | null
  home: ProposedHome
  // A public field (an OAuth client id, an access key id) whose value looks
  // like a secret: the vault refuses it in the clear, so a human adds it.
  publicLooksSecret: boolean
  // A config value that looks like a secret: the vault refuses it as a
  // plain value, so the plan skips its variable.
  configLooksSecret: boolean
  // A secret whose shape marks it as a production key (Stripe sk_live_):
  // the plan leaves it out when its file is for an environment that is
  // not protected.
  liveKey: boolean
  // When the file last changed (ISO), sent with the source on upload.
  // Absent from older scan files.
  mtime?: string
}

export type ScanUnit = { path: string; type: "launchd" | "systemd"; envFiles: string[] }

export type ScanResult = {
  version: 1
  machine: string
  scannedAt: string
  roots: string[]
  files: number
  skipped: WalkSkip[]
  errors: { path: string; line: number; why: string }[]
  units: ScanUnit[]
  entries: ScanEntry[]
}

export type ScanOptions = {
  home: string
  machine: string
  roots: ScanRoot[]
  // Also scan the default roots and the fixed login and settings files.
  defaults: boolean
  include: string[]
  exclude: string[]
  // Never entered: the mehen config root, which holds keys and adopt's own files.
  excludeDirs: string[]
  guard: OutputGuard
  now?: Date
  platform?: NodeJS.Platform
}

const YEAR_MS = 365 * 24 * 3_600_000

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567"

// RFC 4648 base32, lower case, no padding.
function base32Encode(bytes: Bytes): string {
  let out = ""
  let bits = 0
  let value = 0
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff
    bits += 8
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31]
  return out
}

function globMatch(patterns: string[], path: string): boolean {
  return patterns.some((p) => new Bun.Glob(p).match(path) || new Bun.Glob(p).match(path.split(sep).at(-1) ?? path))
}

function within(path: string, dir: string): boolean {
  const rel = relative(dir, path)
  return rel === "" || (!rel.startsWith("..") && !rel.startsWith(sep))
}

async function hmacKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", randomBytes(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
}

async function digest(key: CryptoKey, value: string): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(value)))
  return Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("")
}

function randomLabel(): string {
  return `d${base32Encode(randomBytes(5)).slice(0, 6)}`
}

async function sourceIds(keys: string[]): Promise<string[]> {
  const full = await Promise.all(keys.map(async (k) => base32Encode(await sha256(k))))
  for (let length = 4; ; length += 2) {
    const ids = full.map((f) => `s${f.slice(0, length)}`)
    if (new Set(ids).size === ids.length || length >= 12) return ids
  }
}

function homeFor(category: SourceCategory): ProposedHome {
  return category === "repo" || category === "service" ? "project" : "private"
}

type RepoInfo = { root: string; remote: string | null; idle: boolean }

function lastCommitMs(root: string): number | null {
  try {
    const result = Bun.spawnSync(["git", "log", "-1", "--format=%ct"], { cwd: root, stdout: "pipe", stderr: "ignore" })
    const seconds = Number.parseInt(result.stdout.toString().trim(), 10)
    return Number.isFinite(seconds) ? seconds * 1000 : null
  } catch {
    return null
  }
}

type Candidate = { path: string; type: SourceType; unit: string | null }

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const now = options.now ?? new Date()
  const platform = options.platform ?? process.platform
  const roots = [...options.roots, ...(options.defaults ? defaultRoots(options.home, platform) : [])]
  const skipped: WalkSkip[] = []
  // The walk sees real paths, so an excluded folder counts by its real path too.
  const excludeDirs = [...options.excludeDirs, ...(await Promise.all(options.excludeDirs.map((d) => realpath(d).catch(() => d))))]
  const excluded = (path: string) => excludeDirs.some((d) => within(path, d)) || globMatch(options.exclude, path)
  const accept = (path: string) => !excluded(path) && (sourceType(path) !== null || globMatch(options.include, path))
  const queue: Candidate[] = []
  for (const root of roots) options.guard.addPath(root.path)
  for (const root of roots) for (const path of await walkRoot(root, accept, excluded, skipped)) queue.push({ path, type: sourceType(path) ?? "dotenv", unit: null })
  if (options.defaults) {
    for (const login of loginFiles(options.home, platform)) {
      try {
        await lstat(login.path)
        if (!globMatch(options.exclude, login.path)) queue.push({ path: login.path, type: login.type, unit: null })
      } catch {}
    }
  }
  // Units first, each followed by its EnvironmentFiles, so a file a unit
  // names keeps its unit even when a walk found it too.
  const isUnit = (c: Candidate) => c.type === "plist" || c.type === "systemd"
  // Units in path order among themselves: an env file two units name is
  // the first unit's, and readdir's order differs between filesystems.
  queue.sort((a, b) => Number(isUnit(b)) - Number(isUnit(a)) || (isUnit(a) && isUnit(b) ? (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) : 0))
  const key = await hmacKey()
  const seen = new Set<string>()
  const repos = new Map<string, RepoInfo | null>()
  const units: ScanUnit[] = []
  const errors: ScanResult["errors"] = []
  type Found = Omit<ScanEntry, "id" | "dup"> & { digest: string | null; mtimeMs: number }
  const found: Found[] = []
  let files = 0
  for (let i = 0; i < queue.length; i++) {
    const candidate = queue[i] as Candidate
    if (seen.has(candidate.path)) continue
    seen.add(candidate.path)
    options.guard.addPath(candidate.path)
    const read = await readSource(candidate.path)
    if (!read.ok) {
      skipped.push({ path: candidate.path, why: read.why })
      continue
    }
    files++
    const parsed = parseSource(candidate.type, read.text, options.home)
    for (const e of parsed.errors) errors.push({ path: candidate.path, line: e.line, why: e.why })
    if (isUnit(candidate)) {
      units.push({ path: candidate.path, type: candidate.type === "plist" ? "launchd" : "systemd", envFiles: parsed.envFiles })
      queue.splice(i + 1, 0, ...parsed.envFiles.map((envFile): Candidate => ({ path: envFile, type: "dotenv", unit: candidate.path })))
    }
    const rootDir = await repoRootOf(candidate.path, options.home)
    if (rootDir !== null && !repos.has(rootDir)) {
      const facts = gitFacts(rootDir)
      const last = lastCommitMs(rootDir)
      repos.set(rootDir, facts.root ? { root: facts.root, remote: facts.remote, idle: last !== null && now.getTime() - last > YEAR_MS } : null)
    }
    const repo = rootDir === null ? null : (repos.get(rootDir) ?? null)
    const category: SourceCategory = candidate.unit ? "service" : sourceCategory(candidate.path, candidate.type, repo !== null)
    const fileStale: string[] = []
    if (now.getTime() - read.mtimeMs > YEAR_MS) fileStale.push("file unchanged for 12 months")
    if (archivedPath(candidate.path, repo?.remote ? rootDir : null)) fileStale.push("archived path")
    if (fixturePath(candidate.path, options.home)) fileStale.push("test or example folder")
    if (backupCopy(candidate.path)) fileStale.push("backup copy")
    if (repo?.idle) fileStale.push("repo idle for 12 months")
    if (repo && repo.remote === null && category === "repo") fileStale.push("repo has no origin")
    for (const entry of parsed.entries) {
      const c = classify({ type: candidate.type, variable: entry.variable, pointer: entry.pointer, value: entry.value, path: candidate.path })
      options.guard.addName(entry.variable)
      options.guard.addName(entry.pointer)
      if (entry.value !== null) options.guard.add(entry.value, c.class)
      found.push({
        path: candidate.path,
        type: candidate.type,
        category,
        variable: entry.variable,
        pointer: entry.pointer,
        line: entry.line,
        repo: repo && category === "repo" ? { root: repo.root, remote: repo.remote } : null,
        unit: candidate.unit ?? (candidate.type === "plist" || candidate.type === "systemd" ? candidate.path : null),
        class: c.class,
        kind: c.kind,
        provider: c.provider,
        field: c.field,
        reason: c.reason,
        stale: [...fileStale],
        status: c.status,
        why: c.why,
        storeOnly: c.storeOnly,
        home: homeFor(category),
        publicLooksSecret: entry.value !== null && c.kind !== null && c.field !== null && isPublicField(c.kind, c.field) && secretLikeness(entry.value) !== null,
        configLooksSecret: entry.value !== null && c.class === "config" && secretLikeness(entry.value) !== null,
        liveKey: c.liveKey,
        digest: entry.value !== null && entry.value !== "" && c.class === "secret" ? await digest(key, entry.value) : null,
        mtimeMs: read.mtimeMs,
      })
    }
  }
  // A newer file in the same place holding the same name with another value
  // supersedes this one. In a repo the same place is the same repository
  // (every worktree and clone of one remote), folder below the checkout root
  // and environment; outside one it is the same folder; a unit is never
  // superseded. Other folders and other environments hold their own values
  // by design, and an override file wins over its base whatever the file
  // times say.
  const placeOf = (f: Found): string | null => (f.unit ? null : f.repo ? `${f.repo.remote ?? f.repo.root}\u0000${relative(f.repo.root, dirname(f.path))}\u0000${envForFile(f.path)}` : dirname(f.path))
  for (const f of found) {
    const place = placeOf(f)
    if (f.digest === null || f.variable === null || place === null) continue
    if (found.some((o) => o !== f && o.variable === f.variable && placeOf(o) === place && o.digest !== null && o.digest !== f.digest && o.mtimeMs > f.mtimeMs && !overridesFile(f.path, o.path))) f.stale.push("superseded by a newer file")
  }
  const groups = new Map<string, number>()
  for (const f of found) if (f.digest) groups.set(f.digest, (groups.get(f.digest) ?? 0) + 1)
  const labels = new Map<string, string>()
  for (const [d, count] of groups) if (count > 1) labels.set(d, randomLabel())
  found.sort((a, b) => (a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1))
  const ids = await sourceIds(found.map(sourceKey))
  const entries = found.map(({ digest: d, mtimeMs, ...f }, i): ScanEntry => ({ id: ids[i] as string, ...f, stale: f.stale.slice(0, 4), dup: d ? (labels.get(d) ?? null) : null, mtime: new Date(mtimeMs).toISOString() }))
  // In path and line order, as the entries are: readdir's order differs
  // between filesystems, and a scan reads the same on every machine.
  errors.sort((a, b) => (a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1))
  return { version: 1, machine: options.machine, scannedAt: now.toISOString(), roots: roots.map((r) => r.path), files, skipped, errors, units, entries: orderedKeys(entries) }
}

// Where a value was found, without it: one per path, variable and pointer.
export function sourceKey(source: { path: string; variable: string | null; pointer: string | null }): string {
  return `${source.path}\u0000${source.variable ?? ""}\u0000${source.pointer ?? ""}`
}

// Entries in a fixed key order, so the file reads the same way each time.
function orderedKeys(entries: ScanEntry[]): ScanEntry[] {
  return entries.map((e) => ({ id: e.id, path: e.path, type: e.type, category: e.category, variable: e.variable, pointer: e.pointer, line: e.line, repo: e.repo, unit: e.unit, class: e.class, kind: e.kind, provider: e.provider, field: e.field, reason: e.reason, dup: e.dup, stale: e.stale, status: e.status, why: e.why, storeOnly: e.storeOnly, home: e.home, publicLooksSecret: e.publicLooksSecret, configLooksSecret: e.configLooksSecret, liveKey: e.liveKey, ...(e.mtime === undefined ? {} : { mtime: e.mtime }) }))
}

export type ScanCounts = { files: number; secrets: number; distinct: number; config: number; unsupported: number }

export function scanCounts(result: ScanResult): ScanCounts {
  const secrets = result.entries.filter((e) => e.class === "secret" && e.status === "new")
  const distinct = new Set(secrets.map((e) => e.dup ?? e.id)).size
  return {
    files: result.files,
    secrets: secrets.length,
    distinct,
    config: result.entries.filter((e) => e.class === "config").length,
    unsupported: result.entries.filter((e) => e.status !== "new").length + result.skipped.length,
  }
}

// What --json and vault_adopt_scan print: the counts, one line per folder,
// and the files that did not parse, one line per file. A machine's scan
// runs to hundreds of entries and thousands of unparsed lines, more than an
// agent's context should take; every entry is in the scan file.
const REPORT_LIMIT = 50

export type ScanFolder = { folder: string; category: SourceCategory; home: ProposedHome; secrets: number; config: number; unknown: number; unsupported: number; stale: number }
export type ScanReport = ScanCounts & {
  scan: string
  folders: ScanFolder[]
  errors: { path: string; lines: number; first: number; why: string }[]
  errorFiles: number
  // The folders holding files that did not parse, most files first: a
  // person moves those by hand, and 85 exports in one folder are one line.
  unreadFolders: { folder: string; files: number }[]
  skipped: ScanResult["skipped"]
  skippedFiles: number
  next: { command: string }
}

export function scanReport(result: ScanResult, path: string): ScanReport {
  const folders = new Map<string, ScanFolder>()
  for (const e of result.entries) {
    const key = folderOf(e)
    const f = folders.get(key) ?? { folder: key, category: e.category, home: e.home, secrets: 0, config: 0, unknown: 0, unsupported: 0, stale: 0 }
    if (e.status !== "new") f.unsupported++
    else if (e.class === "secret") f.secrets++
    else if (e.class === "config") f.config++
    else f.unknown++
    if (e.stale.length) f.stale++
    folders.set(key, f)
  }
  const errors = new Map<string, { path: string; lines: number; first: number; why: string }>()
  for (const e of result.errors) {
    const f = errors.get(e.path)
    if (f) f.lines++
    else errors.set(e.path, { path: e.path, lines: 1, first: e.line, why: e.why })
  }
  const unread = new Map<string, number>()
  for (const file of errors.keys()) unread.set(dirname(file), (unread.get(dirname(file)) ?? 0) + 1)
  return {
    scan: path,
    ...scanCounts(result),
    folders: [...folders.values()].sort((a, b) => a.folder.localeCompare(b.folder)).slice(0, REPORT_LIMIT * 2),
    errors: [...errors.values()].slice(0, REPORT_LIMIT),
    errorFiles: errors.size,
    unreadFolders: [...unread].map(([folder, files]) => ({ folder, files })).sort((a, b) => b.files - a.files || a.folder.localeCompare(b.folder)).slice(0, REPORT_LIMIT),
    skipped: result.skipped.slice(0, REPORT_LIMIT),
    skippedFiles: result.skipped.length,
    next: { command: `mehen adopt plan --scan ${path} --json` },
  }
}

export function scanSummary(result: ScanResult, path: string): string {
  const c = scanCounts(result)
  return `found ${c.files} files, ${c.secrets} secret variables (${c.distinct} distinct values), ${c.config} config, ${c.unsupported} unsupported; wrote ${path}`
}

export function defaultScanPath(dir: string): string {
  return join(dir, "scan.json")
}

export function folderOf(entry: Pick<ScanEntry, "path" | "repo">): string {
  return entry.repo?.root ?? dirname(entry.path)
}

export type ScanInput = { roots: string[]; defaults: boolean; depth: number; include: string[]; exclude: string[]; out: string | null }

// The scan as `mehen adopt scan` and vault_adopt_scan run it: the default
// roots only when no root is given, the mehen config root never entered,
// and the result written 0600 for `plan`.
export async function scanToFile(env: Env, input: ScanInput, guard: OutputGuard): Promise<{ result: ScanResult; path: string }> {
  const home = homeDir(env)
  const root = resolveHome(env).root
  const result = await scan({
    home,
    machine: machineName(),
    roots: input.roots.map((path) => ({ path: resolve(path), depth: input.depth })),
    defaults: input.defaults && input.roots.length === 0,
    include: input.include,
    exclude: input.exclude,
    excludeDirs: [root],
    guard,
  })
  const path = input.out ? resolve(input.out) : defaultScanPath(adoptDir(env))
  await writePrivateFile(path, `${JSON.stringify(result, null, 2)}\n`, guard)
  return { result, path }
}

const ScanEntrySchema = z.strictObject({
  id: z.string(),
  path: z.string(),
  type: z.enum(["dotenv", "envrc", "json", "secrets-file", "plist", "systemd", "gh-hosts", "kubeconfig", "talosconfig", "gcloud-adc", "wrangler", "docker"]),
  category: z.enum(["repo", "local-secrets", "settings", "service", "login", "config"]),
  variable: z.string().nullable(),
  pointer: z.string().nullable(),
  line: z.number().int(),
  repo: z.strictObject({ root: z.string(), remote: z.string().nullable() }).nullable(),
  unit: z.string().nullable(),
  class: z.enum(["secret", "config", "unknown"]),
  kind: KindSchema.nullable(),
  provider: z.string().nullable(),
  field: z.string().nullable(),
  reason: z.string(),
  dup: z.string().nullable(),
  stale: z.array(z.string()),
  status: z.enum(["new", "unsupported", "dynamic", "skipped", "connector"]),
  why: z.string().nullable(),
  storeOnly: z.string().nullable(),
  home: z.enum(["private", "workspace", "project"]),
  publicLooksSecret: z.boolean(),
  configLooksSecret: z.boolean(),
  liveKey: z.boolean(),
  mtime: z.iso.datetime().optional(),
})

export const ScanResultSchema = z.strictObject({
  version: z.literal(1),
  machine: z.string(),
  scannedAt: z.string(),
  roots: z.array(z.string()),
  files: z.number().int(),
  skipped: z.array(z.strictObject({ path: z.string(), why: z.string() })),
  errors: z.array(z.strictObject({ path: z.string(), line: z.number().int(), why: z.string() })),
  units: z.array(z.strictObject({ path: z.string(), type: z.enum(["launchd", "systemd"]), envFiles: z.array(z.string()) })),
  entries: z.array(ScanEntrySchema),
})

// A scan written before publicLooksSecret (0.3.6), configLooksSecret or
// liveKey, read only to say so: a plan from it could not tell which config
// the vault refuses or which keys are live.
const OlderScanSchema = ScanResultSchema.extend({ entries: z.array(ScanEntrySchema.extend({ publicLooksSecret: z.boolean().optional(), configLooksSecret: z.boolean().optional(), liveKey: z.boolean().optional() })) })

export async function readScan(path: string): Promise<ScanResult> {
  const raw = await readPrivateJson(path, "scan")
  const parsed = ScanResultSchema.safeParse(raw)
  if (parsed.success) return parsed.data
  if (OlderScanSchema.safeParse(raw).success) throw new CliError("bad_request", `${path} was written by an older mehen; scan again.`, { command: "mehen adopt scan", say: "Scan again with this mehen; the plan is built from a fresh scan." })
  throw new CliError("bad_request", `${path} is not an adopt scan file.`, { command: "mehen adopt scan", say: "Scan again; the plan is built from a fresh scan." })
}
