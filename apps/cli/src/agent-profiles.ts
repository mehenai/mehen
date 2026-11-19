import { type Stats, constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, readSync, realpathSync } from "node:fs"
import { userInfo } from "node:os"
import { dirname, isAbsolute, join, normalize, relative, sep } from "node:path"
import { z } from "zod"
import { Tag, ModeSchema } from "@mehen/protocol/api"
import { CliError } from "./errors.ts"

// The complete device scope a version-3 pin records: the
// private-credentials tick is required, never defaulted. Its modes are
// frozen with the managed harness's parser (the device-scope-v2 corpus): no fill and at
// most five, until both repos widen together.
export const DeviceScopeSchema = z.object({
  tags: z.array(Tag).max(32),
  projects: z.array(z.string().min(1).max(64)).max(32),
  maxEnvironment: z.enum(["unprotected", "protected"]),
  modes: z.array(ModeSchema.exclude(["reveal", "fill"])).min(1).max(5),
  privateCredentials: z.boolean(),
}).strict()
export type DeviceScope = z.infer<typeof DeviceScopeSchema>
export type VaultContextPin = {
  agentDir: string
  configDir: string
  origin: string
  tenant: string
  device: string | null
  scope: DeviceScope
  envProjects?: string[]
}
export const VAULT_CONTEXTS_VERSION = 3
export type VaultContexts = { version: typeof VAULT_CONTEXTS_VERSION; contexts: Record<string, VaultContextPin> }
export type VaultProfileEnv = Record<string, string | undefined>
// `path` only names the file in the pin_outdated instruction; nothing is read from it here.
export type VaultParseOptions = { allowLoopbackHttpForTests?: boolean; path?: string }

const contextKey = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/)
const tenantId = z.string().regex(/^tn_[A-Za-z0-9]{8,40}$/)
const deviceId = z.string().regex(/^dev_[A-Za-z0-9]{8,40}$/)
const projectId = z.string().regex(/^prj_[A-Za-z0-9_-]{1,60}$/)
const privatePath = z.string().refine(canonicalAbsolutePath, "Use an absolute canonical path.")
const MAX_MAP_BYTES = 32 * 1024

function refuse(): never {
  throw new Error("Vault pin verification failed. Ask the owner to review the explicit context and its evidence.")
}

// A version-2 map (no privateCredentials) is recognised and refused as
// pin_outdated. The next is an owner review and rewrite of the file, never
// a value learnt from status or defaulted here (design 9.7).
function pinOutdated(value: Record<string, unknown>, options: VaultParseOptions): never {
  const contexts = typeof value.contexts === "object" && value.contexts !== null ? Object.values(value.contexts as Record<string, unknown>) : []
  const devices = contexts.flatMap((pin) => {
    const device = typeof pin === "object" && pin !== null ? (pin as { device?: unknown }).device : undefined
    return deviceId.safeParse(device).success ? [device as string] : []
  })
  const page = devices.length === 1 ? `/w/<slug>/devices/${devices[0]}` : "/w/<slug>/devices/<device>"
  const file = options.path ?? "the pin map"
  throw new CliError("pin_outdated", `The vault pin map${options.path ? ` ${options.path}` : ""} is version 2; version 3 records privateCredentials in every scope.`, {
    command: "mehen status --json",
    say: `The owner reviews this machine's scope on ${page} and rewrites the pin in ${file} as version 3 with privateCredentials set to what that page shows, then run mehen status --json to verify.`,
  })
}
function canonicalAbsolutePath(path: string): boolean {
  return isAbsolute(path) && !path.includes("\0") && normalize(path) === path && (path === sep || !path.endsWith(sep))
}
function normalisedOrigin(value: string, options: VaultParseOptions): boolean {
  try {
    const url = new URL(value)
    return value === url.origin && !url.username && !url.password &&
      (url.protocol === "https:" || (options.allowLoopbackHttpForTests === true && url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))
  } catch { return false }
}
function pinSchema(options: VaultParseOptions) {
  return z.object({
    agentDir: privatePath,
    configDir: privatePath,
    origin: z.string().refine(value => normalisedOrigin(value, options)),
    tenant: tenantId,
    device: deviceId.nullable(),
    scope: DeviceScopeSchema.refine(scope => new Set(scope.tags).size === scope.tags.length),
    envProjects: z.array(projectId).max(32).refine(ids => new Set(ids).size === ids.length).optional(),
  }).strict()
}

// JSON.parse alone discards duplicate keys. Scan original tokens, including escaped keys.
function strictJson(text: string): unknown {
  if (Buffer.byteLength(text, "utf8") > MAX_MAP_BYTES) refuse()
  let value: unknown
  try { value = JSON.parse(text) } catch { return refuse() }
  const stack: { keys: Set<string> | null; keyExpected: boolean }[] = []
  for (const match of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}[\],:]|[^\s{}[\],:]+/g)) {
    const token = match[0]
    const top = stack.at(-1)
    if (token === "{") stack.push({ keys: new Set(), keyExpected: true })
    else if (token === "[") stack.push({ keys: null, keyExpected: false })
    else if (token === "}" || token === "]") stack.pop()
    else if (token === "," && top?.keys) top.keyExpected = true
    else if (token === ":" && top) top.keyExpected = false
    else if (token.startsWith('"') && top?.keys && top.keyExpected) {
      const key = JSON.parse(token) as string
      if (top.keys.has(key)) refuse()
      top.keys.add(key)
      top.keyExpected = false
    }
  }
  return value
}

export function parseVaultContexts(text: string, options: VaultParseOptions = {}): VaultContexts {
  const value = strictJson(text)
  if (typeof value === "object" && value !== null && !Array.isArray(value) && (value as { version?: unknown }).version === 2) pinOutdated(value as Record<string, unknown>, options)
  const result = z.object({ version: z.literal(VAULT_CONTEXTS_VERSION), contexts: z.record(contextKey, pinSchema(options)) }).strict().safeParse(value)
  if (!result.success) refuse()
  assertVaultCatalogue(result.data)
  return result.data
}

/** Same-workspace (origin, tenant) tag ceilings must be identical or disjoint, without inferred persona names. */
export function assertVaultCatalogue(map: VaultContexts): void {
  const seen = new Map<string, Set<string>[]>()
  for (const pin of Object.values(map.contexts)) {
    const tags = new Set(pin.scope.tags)
    if (tags.size !== pin.scope.tags.length) refuse()
    const group = `${pin.origin} ${pin.tenant}`
    const previous = seen.get(group) ?? []
    for (const other of previous) {
      const overlap = [...tags].filter(tag => other.has(tag)).length
      if (overlap > 0 && (overlap !== tags.size || overlap !== other.size)) refuse()
    }
    previous.push(tags)
    seen.set(group, previous)
  }
}
export function assertVaultPinAdmitted(pin: VaultContextPin): asserts pin is VaultContextPin & { device: string } {
  if (pin.device === null || pin.scope.tags.length === 0) refuse()
}

/** Config has no scope. Pass the existing config shape, not a new local scope cache. */
export function assertLocalVaultIdentity(pin: VaultContextPin, config: unknown): void {
  assertVaultPinAdmitted(pin)
  const parsed = z.object({ vault: z.string(), tenant: z.string(), device: z.string() }).safeParse(config)
  if (!parsed.success || parsed.data.vault !== pin.origin || parsed.data.tenant !== pin.tenant || parsed.data.device !== pin.device) refuse()
}
export function scopeEqual(left: DeviceScope, right: DeviceScope): boolean {
  const sameList = (a: string[], b: string[]) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort())
  return left.maxEnvironment === right.maxEnvironment && left.privateCredentials === right.privateCredentials && sameList(left.tags, right.tags) && sameList(left.projects, right.projects) && sameList(left.modes, right.modes)
}

const authenticatedStatusSchema = z.object({ vault: z.string(), tenant: tenantId, device: deviceId, scope: DeviceScopeSchema })
function assertAuthenticatedStatusMatches(pin: VaultContextPin, evidence: unknown): void {
  const parsed = authenticatedStatusSchema.safeParse(evidence)
  if (!parsed.success || parsed.data.vault !== pin.origin || parsed.data.tenant !== pin.tenant || (pin.device !== null && parsed.data.device !== pin.device) || !scopeEqual(pin.scope, parsed.data.scope)) refuse()
}

/** The caller must acquire this evidence through authenticated status. No I/O or learning occurs here. */
export function assertAuthenticatedVaultScope(pin: VaultContextPin, authenticatedStatus: unknown): void {
  assertVaultPinAdmitted(pin)
  assertAuthenticatedStatusMatches(pin, authenticatedStatus)
}

/** Compare authenticated enrolment against owner intent only. Never finalises or admits a null-device pin. */
export function assertAuthenticatedVaultEnrolment(pin: VaultContextPin, authenticatedEnrolment: unknown): void {
  assertAuthenticatedStatusMatches(pin, authenticatedEnrolment)
}

/** Consistency only. The consumer detects/verifies the marker and supplies real verified directories. */
export function assertManagedVaultSelection(map: VaultContexts, key: string, env: VaultProfileEnv, defaultConfigDir: string): VaultContextPin {
  const pin = map.contexts[key]
  if (!contextKey.safeParse(key).success || Object.keys(map.contexts).length !== 1 || !pin || !env.MEHEN_CONFIG_DIR || env.MEHEN_CONFIG_DIR === defaultConfigDir || env.MEHEN_CONFIG_DIR !== pin.configDir || env.MEHEN_MANAGED_CONTEXT !== key) refuse()
  assertVaultPinAdmitted(pin)
  return pin
}
export function assertVaultEnvProject(pin: VaultContextPin, project: string): void {
  if (!projectId.safeParse(project).success || !pin.envProjects?.includes(project)) refuse()
}

/** Call only after filesystem, local identity and authenticated scope verification. No key material is read. */
export function buildVaultChildEnv(parent: VaultProfileEnv, key: string, pin: VaultContextPin): VaultProfileEnv {
  assertVaultPinAdmitted(pin)
  if (!contextKey.safeParse(key).success || (parent.MEHEN_CONFIG_DIR !== undefined && parent.MEHEN_CONFIG_DIR !== pin.configDir) || (parent.MEHEN_MANAGED_CONTEXT !== undefined && parent.MEHEN_MANAGED_CONTEXT !== key)) refuse()
  const result = { ...parent }
  delete result.MEHEN_VAULT_URL
  return { ...result, MEHEN_CONFIG_DIR: pin.configDir, MEHEN_MANAGED_CONTEXT: key }
}

type VaultFileStat = Pick<Stats, "uid" | "mode" | "size" | "dev" | "ino" | "isDirectory" | "isFile" | "isSymbolicLink">
export type VaultFileOptions = VaultParseOptions & {
  ownerRoot?: string
  /** Synthetic metadata seam for ownership tests; never sourced from a pin. */
  lstat?: (path: string) => VaultFileStat
  readFile?: (fd: number) => string
}
type FileCheck = { uid: number; root: string; stat: (path: string) => VaultFileStat }

// The passwd home of a uid. Bun's os.userInfo() reports the process's initial
// HOME as its home directory, so it is never the source: a lookup is keyed by
// uid and ignores the environment. `not-found` is only ever answered when the
// lookup can prove that no passwd entry exists for the uid (no account, so no
// home for the marker to live in); every failure, every malformed answer and
// every case that cannot be proved is `error`, which refuses.
export type PasswdHomeResult = { kind: "found"; home: string } | { kind: "not-found" } | { kind: "error"; reason: string }
export type PasswdHomeLookup = (uid: number) => PasswdHomeResult
// The system calls the lookup makes, injectable so tests can exercise each
// platform's path. `run` gets an absolute binary; `absent` means the binary or
// file does not exist, `failed` anything else that stopped it.
export type CommandOutcome = { kind: "exited"; code: number; stdout: Uint8Array } | { kind: "absent" } | { kind: "failed"; reason: string }
export type FileOutcome = { kind: "read"; bytes: Uint8Array } | { kind: "absent" } | { kind: "failed"; reason: string }
export type PasswdLookupIo = { run: (binary: string, args: string[]) => CommandOutcome; readFile: (path: string) => FileOutcome }
// What a parser makes of lookup output: the uid's home, no record for it, or
// output that cannot be trusted at all.
export type PasswdParse = { kind: "found"; home: string } | { kind: "none" } | { kind: "malformed"; reason: string }

const DECIMAL = /^(0|[1-9][0-9]*)$/
// C0 controls and DEL: a record is one line of printable text.
const CONTROL = /[\u0000-\u001f\u007f]/

function strictText(bytes: Uint8Array): string | null {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes) } catch { return null }
}

// One passwd(5) record, name:password:uid:gid:gecos:home:shell, validated as
// a whole: exactly seven fields, a name, decimal uid and gid, no controls.
type PasswdRecord = { uid: string; home: string }
function passwdRecord(line: string): PasswdRecord | string {
  if (CONTROL.test(line)) return "a record holds a control character"
  const fields = line.split(":")
  if (fields.length !== 7) return `a record has ${fields.length} fields, not 7`
  const [name, , uid, gid, , home] = fields as [string, string, string, string, string, string, string]
  if (!name) return "a record has no name"
  if (!DECIMAL.test(uid) || !DECIMAL.test(gid)) return "a record's uid or gid is not decimal"
  return { uid, home }
}

/** `getent passwd <uid>` on success: exactly one record, for this uid, with a home, and at most its final newline. */
export function passwdHomeFromGetent(text: string, uid: number): PasswdParse {
  const line = text.endsWith("\n") ? text.slice(0, -1) : text
  if (line.includes("\n")) return { kind: "malformed", reason: "getent answered more than one line" }
  const record = passwdRecord(line)
  if (typeof record === "string") return { kind: "malformed", reason: `getent: ${record}` }
  if (record.uid !== String(uid)) return { kind: "malformed", reason: "getent answered for another uid" }
  if (!record.home) return { kind: "malformed", reason: "getent's record has no home" }
  return { kind: "found", home: record.home }
}

/** /etc/passwd as a database: every non-empty record must be valid; the first record for the uid wins, as getpwuid's files backend does. */
export function passwdHomeFromPasswdFile(text: string, uid: number): PasswdParse {
  let found: string | null = null
  for (const line of text.split("\n")) {
    if (line === "") continue
    const record = passwdRecord(line)
    if (typeof record === "string") return { kind: "malformed", reason: `/etc/passwd: ${record}` }
    if (found === null && record.uid === String(uid)) {
      if (!record.home) return { kind: "malformed", reason: "/etc/passwd: the uid's record has no home" }
      found = record.home
    }
  }
  return found === null ? { kind: "none" } : { kind: "found", home: found }
}

const DSCACHEUTIL_KEYS = ["name", "password", "uid", "gid", "dir", "shell", "gecos"] as const
/**
 * `dscacheutil -q user -a uid <uid>`: empty output, or exactly one record of
 * the seven native properties, each once, as `key: value` lines (split at the
 * first `: `, so a colon in a value is data), then one blank line.
 */
export function passwdHomeFromDscacheutil(text: string, uid: number): PasswdParse {
  if (text === "") return { kind: "none" }
  if (!text.endsWith("\n\n")) return { kind: "malformed", reason: "dscacheutil's record is not one block ending in a blank line" }
  const lines = text.slice(0, -2).split("\n")
  if (lines.length !== DSCACHEUTIL_KEYS.length) return { kind: "malformed", reason: `dscacheutil answered ${lines.length} lines, not one record of ${DSCACHEUTIL_KEYS.length}` }
  const fields = new Map<string, string>()
  for (const line of lines) {
    if (CONTROL.test(line)) return { kind: "malformed", reason: "dscacheutil's record holds a control character" }
    const at = line.indexOf(":")
    const key = at < 0 ? line : line.slice(0, at)
    const rest = at < 0 ? null : line.slice(at + 1)
    if (rest === null || (rest !== "" && !rest.startsWith(" "))) return { kind: "malformed", reason: "dscacheutil answered a line that is not `key: value`" }
    if (!(DSCACHEUTIL_KEYS as readonly string[]).includes(key)) return { kind: "malformed", reason: `dscacheutil answered an unknown property ${JSON.stringify(key)}` }
    if (fields.has(key)) return { kind: "malformed", reason: `dscacheutil answered ${key} twice` }
    fields.set(key, rest.slice(1))
  }
  const recordUid = fields.get("uid")!, gid = fields.get("gid")!, home = fields.get("dir")!
  if (!fields.get("name")) return { kind: "malformed", reason: "dscacheutil's record has no name" }
  if (!DECIMAL.test(recordUid) || !/^-?(0|[1-9][0-9]*)$/.test(gid)) return { kind: "malformed", reason: "dscacheutil's uid or gid is not decimal" }
  if (recordUid !== String(uid)) return { kind: "malformed", reason: "dscacheutil answered for another uid" }
  if (!home) return { kind: "malformed", reason: "dscacheutil's record has no home" }
  return { kind: "found", home }
}

// /etc/nsswitch.conf's passwd sources, without the [STATUS=action] items. A
// missing file or line is glibc's (and musl's only) default, files.
export function passwdSources(text: string | null): string[] | null {
  if (text === null) return ["files"]
  const lines = text.split("\n").map((line) => line.replace(/#.*/, "").trim()).filter((line) => /^passwd\s*:/.test(line))
  if (lines.length > 1) return null
  if (lines.length === 0) return ["files"]
  const tokens = lines[0]!.replace(/^passwd\s*:/, "").trim().split(/\s+/).filter(Boolean)
  const sources = tokens.filter((token) => !/^\[[^\]]*\]$/.test(token))
  return sources.some((source) => /[[\]]/.test(source)) ? null : sources
}

function errorOutcome(error: unknown): { kind: "absent" } | { kind: "failed"; reason: string } {
  const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "unknown"
  return code === "ENOENT" ? { kind: "absent" } : { kind: "failed", reason: code }
}
const systemPasswdLookupIo: PasswdLookupIo = {
  // An empty environment: PATH, LD_PRELOAD and the like are the caller's.
  run: (binary, args) => {
    try {
      const result = Bun.spawnSync([binary, ...args], { env: {}, stdin: "ignore", stdout: "pipe", stderr: "ignore", timeout: 5_000 })
      if (result.exitCode === null) return { kind: "failed", reason: `stopped by ${result.signalCode ?? "a signal"}` }
      return { kind: "exited", code: result.exitCode, stdout: result.stdout }
    } catch (error) { return errorOutcome(error) }
  },
  readFile: (path) => {
    try { return { kind: "read", bytes: readFileSync(path) } } catch (error) { return errorOutcome(error) }
  },
}

function fromParse(parse: PasswdParse, none: PasswdHomeResult): PasswdHomeResult {
  return parse.kind === "found" ? { kind: "found", home: parse.home } : parse.kind === "malformed" ? { kind: "error", reason: parse.reason } : none
}
function decodedParse(bytes: Uint8Array, what: string, parse: (text: string) => PasswdParse): PasswdParse {
  const text = strictText(bytes)
  return text === null ? { kind: "malformed", reason: `${what} is not valid UTF-8` } : parse(text)
}

// Linux: getent (NSS) first. A successful answer is the answer, and a
// malformed one refuses without falling back. A missing, failed or "not
// found" getent falls back to /etc/passwd read strictly. No entry is proved
// only when getent found none (or does not exist), /etc/passwd has none and
// nsswitch.conf names files as the only passwd source.
function linuxPasswdHome(uid: number, io: PasswdLookupIo): PasswdHomeResult {
  const getent = io.run("/usr/bin/getent", ["passwd", String(uid)])
  if (getent.kind === "exited" && getent.code === 0) return fromParse(decodedParse(getent.stdout, "getent's answer", (text) => passwdHomeFromGetent(text, uid)), { kind: "error", reason: "getent answered nothing" })
  const getentNone = getent.kind === "absent" || (getent.kind === "exited" && getent.code === 2)
  const file = io.readFile("/etc/passwd")
  if (file.kind !== "read") return { kind: "error", reason: `/etc/passwd cannot be read (${file.kind === "failed" ? file.reason : "missing"})` }
  const parse = decodedParse(file.bytes, "/etc/passwd", (text) => passwdHomeFromPasswdFile(text, uid))
  if (parse.kind === "malformed") return { kind: "error", reason: parse.reason }
  if (parse.kind === "found") return getent.kind === "exited" && getent.code === 2 ? { kind: "error", reason: "getent found no entry but /etc/passwd has one" } : { kind: "found", home: parse.home }
  if (!getentNone) return { kind: "error", reason: getent.kind === "failed" ? `getent failed (${getent.reason})` : `getent exited ${getent.kind === "exited" ? getent.code : "abnormally"}` }
  const nsswitch = io.readFile("/etc/nsswitch.conf")
  if (nsswitch.kind === "failed") return { kind: "error", reason: `/etc/nsswitch.conf cannot be read (${nsswitch.reason})` }
  const text = nsswitch.kind === "read" ? strictText(nsswitch.bytes) : null
  if (nsswitch.kind === "read" && text === null) return { kind: "error", reason: "/etc/nsswitch.conf is not valid UTF-8" }
  const sources = passwdSources(text)
  if (sources === null) return { kind: "error", reason: "/etc/nsswitch.conf's passwd line cannot be read" }
  if (sources.length !== 1 || sources[0] !== "files") return { kind: "error", reason: `passwd entries may come from ${sources.join(", ") || "nowhere"}, so no entry cannot be proved` }
  return { kind: "not-found" }
}

/** Linux: getent (NSS), then /etc/passwd. macOS: the directory service by uid (no record is never proof of none). Elsewhere: an error. */
export function systemPasswdHome(uid: number, platform: NodeJS.Platform = process.platform, io: PasswdLookupIo = systemPasswdLookupIo): PasswdHomeResult {
  if (platform === "darwin") {
    const out = io.run("/usr/bin/dscacheutil", ["-q", "user", "-a", "uid", String(uid)])
    if (out.kind !== "exited" || out.code !== 0) return { kind: "error", reason: out.kind === "exited" ? `dscacheutil exited ${out.code}` : out.kind === "failed" ? `dscacheutil failed (${out.reason})` : "dscacheutil is missing" }
    return fromParse(decodedParse(out.stdout, "dscacheutil's answer", (text) => passwdHomeFromDscacheutil(text, uid)), { kind: "error", reason: "the directory service has no record for the uid, which does not prove there is none" })
  }
  if (platform === "linux") return linuxPasswdHome(uid, io)
  return { kind: "error", reason: `there is no passwd lookup for ${platform}` }
}

// Why the passwd home cannot be trusted, walking the path as the account
// database gives it (never following a link): every component a real
// directory, none writable by group or others, ancestors this user's or
// root's, the home this user's. Null when it can be trusted.
export function untrustedPasswdHome(home: string, uid: number, stat: (path: string) => VaultFileStat = lstatSync): string | null {
  let current = ""
  for (const component of ["", ...home.split(sep).filter(Boolean)]) {
    current = component === "" ? sep : join(current, component)
    let info: VaultFileStat
    try { info = stat(current) } catch { return `${current} does not exist or cannot be read` }
    const isHome = current === home
    if (info.isSymbolicLink()) return `${current} is a symlink`
    if (!info.isDirectory()) return `${current} is not a directory`
    if (isHome ? info.uid !== uid : info.uid !== uid && info.uid !== 0) return `${current} is not owned by this user${isHome ? "" : " or root"}`
    if ((info.mode & 0o022) !== 0) return `${current} can be written by group or others`
  }
  return null
}

// The owner root: the verified passwd home, or no-entry when the lookup proved
// this uid has no account (then there is no marker to find).
export type OwnerRoot = { kind: "home"; root: string } | { kind: "no-entry" }
let passwdHomeLookup: PasswdHomeLookup = systemPasswdHome
let cachedOwnerRoot: OwnerRoot | undefined

/** Tests only: stand in for the passwd lookup (null restores the system's) and forget the cached owner root. */
export function setPasswdHomeLookupForTests(lookup: PasswdHomeLookup | null): void {
  passwdHomeLookup = lookup ?? systemPasswdHome
  cachedOwnerRoot = undefined
}

// `lookup`: the account database gave no usable answer; `home`: it named a
// home that cannot be trusted.
function ownerRootUnresolved(uid: number | undefined, why: string, failed: "lookup" | "home" = "lookup"): CliError {
  const who = uid === undefined ? "this user" : `uid ${uid}`
  const fix = failed === "lookup"
    ? `Give ${who} a passwd entry whose home directory exists (getent passwd <uid> on Linux, dscacheutil -q user -a uid <uid> on macOS).`
    : `The passwd home of ${who} must be an existing directory this user owns, with no symlink and no group- or world-writable directory on its path, so not below a world-writable one such as /tmp; if this host is managed, ask its owner to check it.`
  return new CliError("key_insecure", `Refusing to run: the passwd home of ${who} ${why}, so whether this host is managed cannot be verified.`, {
    say: `${fix} HOME and MEHEN_HOME do not move where the managed-host marker is read.`,
  })
}

/**
 * The passwd home, looked up by uid once per process and verified before it
 * is cached; HOME and MEHEN_HOME are caller-controlled environment. A failed
 * lookup or an untrusted home refuses key_insecure and caches nothing.
 */
export function resolveOwnerRoot(): OwnerRoot {
  if (cachedOwnerRoot !== undefined) return cachedOwnerRoot
  const uid = process.getuid?.()
  if (uid === undefined) throw ownerRootUnresolved(uid, "cannot be looked up on this platform")
  const result = passwdHomeLookup(uid)
  if (result.kind === "error") throw ownerRootUnresolved(uid, `cannot be resolved (${result.reason})`)
  if (result.kind === "not-found") return (cachedOwnerRoot = { kind: "no-entry" })
  const home = result.home
  if (!canonicalAbsolutePath(home)) throw ownerRootUnresolved(uid, `is not a canonical absolute path (${JSON.stringify(home)})`, "home")
  const untrusted = untrustedPasswdHome(home, uid)
  if (untrusted !== null) throw ownerRootUnresolved(uid, `(${home}) cannot be trusted: ${untrusted}`, "home")
  return (cachedOwnerRoot = { kind: "home", root: home })
}
/** The verified passwd home; a uid with no passwd entry has none, which refuses here. */
export function defaultOwnerRoot(): string {
  const owner = resolveOwnerRoot()
  if (owner.kind === "no-entry") refuse()
  return owner.root
}
function fileCheck(options: VaultFileOptions): FileCheck {
  const owner = userInfo()
  return { uid: owner.uid, root: options.ownerRoot === undefined ? defaultOwnerRoot() : realpathSync(options.ownerRoot), stat: options.lstat ?? lstatSync }
}
function directory(path: string, check: FileCheck, ownerOnly: boolean, ancestor: boolean): void {
  const stat = check.stat(path)
  if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.uid !== check.uid && !(ancestor && stat.uid === 0)) || (stat.mode & 0o022) !== 0 || (ownerOnly && (stat.mode & 0o7777) !== 0o700)) refuse()
}
function verifyDirectories(target: string, check: FileCheck, privateTarget: boolean, missingAllowed = false): boolean {
  if (!canonicalAbsolutePath(target)) refuse()
  const below = relative(check.root, target)
  if (below === ".." || below.startsWith(".." + sep) || isAbsolute(below)) refuse()
  let current: string = sep
  directory(current, check, privateTarget && current === target, check.root !== sep)
  for (const component of check.root.split(sep).filter(Boolean)) {
    current = join(current, component)
    directory(current, check, privateTarget && current === target, current !== check.root)
  }
  for (const component of below.split(sep).filter(Boolean)) {
    current = join(current, component)
    try { directory(current, check, privateTarget && current === target, false) } catch (error) {
      if (missingAllowed && isMissing(error)) return false
      throw error
    }
  }
  return true
}
export function verifyVaultDirectory(path: string, options: VaultFileOptions = {}): void {
  verifyDirectories(path, fileCheck(options), true)
}
function privateFile(path: string, check: FileCheck): VaultFileStat {
  if (!canonicalAbsolutePath(path)) refuse()
  verifyDirectories(dirname(path), check, true)
  const stat = check.stat(path)
  if (stat.isSymbolicLink() || !stat.isFile() || stat.uid !== check.uid || (stat.mode & 0o7777) !== 0o600) refuse()
  return stat
}
export function verifyVaultPrivateFile(path: string, options: VaultFileOptions = {}): void {
  privateFile(path, fileCheck(options))
}
function readPrivateFile(path: string, options: VaultFileOptions, marker: boolean, check = fileCheck(options)): string {
  const before = privateFile(path, check)
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const opened = fstatSync(fd)
    if (!opened.isFile() || opened.uid !== check.uid || (opened.mode & 0o7777) !== 0o600 || opened.dev !== before.dev || opened.ino !== before.ino) refuse()
    if (marker) {
      if (options.readFile) options.readFile(fd)
      else readSync(fd, Buffer.alloc(1), 0, 1, 0)
      privateFile(path, check)
      return ""
    }
    if (opened.size > MAX_MAP_BYTES) refuse()
    const text = (options.readFile ?? (handle => new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(handle))))(fd)
    // Recheck components after opening. Same-uid hostile replacement remains out of scope.
    privateFile(path, check)
    if (Buffer.byteLength(text, "utf8") > MAX_MAP_BYTES) refuse()
    return text
  } finally { closeSync(fd) }
}
export function readVaultContextsFile(path: string, options: VaultFileOptions = {}): VaultContexts {
  return parseVaultContexts(readPrivateFile(path, options, false), { ...options, path })
}
function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"
}

/** Default discovery deliberately ignores HOME. Missing parents are absence, unsafe parents are refusal. */
export function readManagedVaultMarker(path: string | undefined = undefined, options: VaultFileOptions = {}): boolean {
  // A uid the lookup proved has no passwd entry has no home: not managed.
  if (path === undefined && options.ownerRoot === undefined && resolveOwnerRoot().kind === "no-entry") return false
  const check = fileCheck(options)
  const markerPath = path ?? join(check.root, ".config", "mehen", "managed-agents")
  if (!canonicalAbsolutePath(markerPath)) refuse()
  if (!verifyDirectories(dirname(markerPath), check, false, true)) return false
  try { check.stat(markerPath) } catch (error) {
    if (isMissing(error)) return false
    throw error
  }
  readPrivateFile(markerPath, options, true, check)
  return true
}
