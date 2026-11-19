// What the guard hooks look for, whichever agent asks: a tool about to read
// a file that holds secrets, a shell command that reads one or carries a
// provider key, and a write that would put a key into a file. Local rules
// only: no vault, no network, nothing read but the paths named, so a hook
// answers in milliseconds and never fails for want of a connection.

import { secretPrefix, PLACEHOLDER_CORE } from "@mehen/protocol"
import { type Dirent, existsSync, lstatSync, readdirSync, readlinkSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path"
import { loginFiles, sourceType } from "../adopt/sources.ts"
import { type ShellNode, type Word, parseShell } from "./shell.ts"

export type Finding = { rule: "secret-file" | "secret-in-command" | "secret-in-write"; reason: string; path?: string }

const KEY_FILE = /\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)$/i
const SSH_PRIVATE = /^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/
const DOTFILES = new Set([".netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass", ".my.cnf"])

function under(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir + sep)
}

// The folders whose files are the vault's or this machine's own keys.
function privateDirs(home: string, extra: string[]): string[] {
  return [join(home, ".config", "mehen"), join(home, ".aws"), join(home, ".ssh"), join(home, ".gnupg"), ...extra]
}

// A word with * or ? in it: whether it could name a secret file, tried
// against the names secret files have.
const SECRET_NAMES = [".env", ".env.local", ".env.production", ".envrc", ".dev.vars", "id_rsa", "id_ed25519", "server.pem", "tls.key", "credentials", ".npmrc", ".netrc"]

function globMatchesSecret(word: string): boolean {
  const name = basename(word)
  if (!/[*?]/.test(name)) return false
  const pattern = new RegExp(`^${name.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`)
  return SECRET_NAMES.some((candidate) => pattern.test(candidate))
}

// A folder a vault keeps its data in, wherever it was started: it holds the
// directory database and the objects folder side by side.
function vaultFolder(dir: string, cache?: Map<string, boolean>): boolean {
  const known = cache?.get(dir)
  if (known !== undefined) return known
  const is = existsSync(join(dir, "directory.sqlite")) && existsSync(join(dir, "objects"))
  cache?.set(dir, is)
  return is
}

function insideVaultData(path: string, cache?: Map<string, boolean>): boolean {
  let dir = dirname(path)
  for (let i = 0; i < 6; i++) {
    if (vaultFolder(dir, cache)) return true
    const up = dirname(dir)
    if (up === dir) return false
    dir = up
  }
  return false
}

// A path a tool call names (not a shell word), as the tool reads it: a
// leading ~ is the home folder. Shell words reach secretFile with HOME
// already expanded, once, by the tokeniser in shell.ts.
export function toolPath(raw: string, home: string): string {
  return raw.replace(/^~(?=$|\/)/, home)
}

export type SecretFileOptions = { physical?: boolean; cache?: Map<string, boolean> }

// Where a path really is on disk, or null when some part of it does not
// exist: each part in order, a link replaced by what it points at before
// the next part (a later .. included) is read. Done here rather than with
// realpath, whose handling of .. after a link differs between runtimes.
function realOrNull(path: string, hops = 0): string | null {
  if (hops > 40) return null
  let current: string = sep
  for (const part of path.split(sep)) {
    if (part === "" || part === ".") continue
    if (part === "..") {
      current = dirname(current)
      continue
    }
    const next = join(current, part)
    let link: string | null = null
    try {
      if (lstatSync(next).isSymbolicLink()) link = readlinkSync(next)
    } catch {
      return null
    }
    if (link === null) current = next
    else {
      const target = realOrNull(isAbsolute(link) ? link : `${current}${sep}${link}`, hops + 1)
      if (target === null) return null
      current = target
    }
  }
  return current
}

function shown(path: string, home: string): string {
  for (const h of [home, realOrNull(home)]) if (h && under(path, h)) return `~${path.slice(h.length)}`
  return path
}

// Why reading this path would put a secret in front of the agent, or null.
// The path is taken literally: no ~ or $HOME. One that exists is judged
// where it really is on disk, its links and .. resolved in order; then, or
// when it does not exist, by the path as written.
export function secretFile(raw: string, cwd: string, home = homedir(), vaultDirs: string[] = [], options: SecretFileOptions = {}): string | null {
  const joined = isAbsolute(raw) ? raw : `${cwd}${sep}${raw}`
  const written = normalize(joined)
  const real = options.physical === false ? null : realOrNull(joined)
  if (real !== null && real !== written) {
    const why = classify(real, home, vaultDirs, options.cache)
    if (why !== null) return `it is a link to ${shown(real, home)}, and ${why}`
  }
  return classify(written, home, vaultDirs, options.cache)
}

// The home folder as given and as it really is on disk, when they differ.
function homes(home: string): string[] {
  const real = realOrNull(home)
  return real && real !== home ? [home, real] : [home]
}

function classify(path: string, home: string, vaultDirs: string[], cache?: Map<string, boolean>): string | null {
  const name = basename(path)
  if (/^\/proc\/[^/]+\/environ$/.test(path)) return "it is a process's environment, which can hold keys"
  if (insideVaultData(path, cache)) return "it is a Mehen vault's own data"
  if (name.endsWith(".pub")) return null
  for (const h of homes(home)) {
    for (const dir of privateDirs(h, vaultDirs)) if (under(path, dir)) return dir === join(h, ".config", "mehen") ? "it is one of Mehen's own files on this machine" : vaultDirs.includes(dir) ? "it is the vault's own data" : `it is under ${dir.replace(h, "~")}, where keys live`
    if (loginFiles(h).some((file) => file.type !== "json" && file.path === path)) return "it holds a CLI's login"
  }
  const type = sourceType(path)
  if (type === "dotenv" || type === "envrc") return "it is an environment file, which holds keys"
  if (type === "secrets-file") return "it is in a .local-secrets folder"
  if (KEY_FILE.test(name)) return "it is a key or certificate store"
  if (SSH_PRIVATE.test(name)) return "it is an SSH private key"
  if (DOTFILES.has(name)) return "it holds registry or login credentials"
  return null
}

// A provider key in text: a PEM private key, a URL with a password, or a
// token with a well-known key prefix and a random-looking tail. Mehen's own
// placeholders are not keys and are skipped. Never says which value.
export function secretInText(text: string): string | null {
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) return "a private key"
  if (/[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:[^/\s@'"$]{6,}@/i.test(text)) return "a URL with a password in it"
  const cleaned = text.replace(PLACEHOLDER_CORE, " ")
  for (const token of cleaned.split(/[\s"'`=:,;()[\]{}<>|&]+/)) {
    const prefix = secretPrefix(token)
    if (!prefix) continue
    const tail = token.slice(prefix.length)
    if (tail.length >= 16 && /[A-Za-z]/.test(tail) && /[0-9]/.test(tail) && !/[a-z]{6,}_[a-z]{4,}/.test(tail)) return `a key that starts like a provider key ("${prefix}")`
  }
  return null
}

// Commands that read or copy what their arguments name.
const READERS = new Set(["cat", "bat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "cut", "sort", "uniq", "tr", "xxd", "od", "hexdump", "base64", "strings", "source", ".", "cp", "scp", "rsync", "tar", "zip", "jq", "yq", "python", "python3", "node", "bun", "deno", "ruby", "perl", "php", "curl", "wget", "nc", "diff", "cmp", "vim", "vi", "nano", "emacs", "code", "open", "xdg-open", "dotenv", "env", "export", "git"])

// Of those, the ones whose operands are only the files they read: a word
// the guard cannot know there is a file it cannot check. The options listed
// take a value, which is not a file.
const FILE_READERS: Record<string, string> = { cat: "", bat: "lmHrp", less: "bhjkoOpPtTxyz", more: "n", head: "nc", tail: "ncs", xxd: "lcsgo", od: "AjNtw", hexdump: "nsef", base64: "w", strings: "nte", sort: "ktoST", uniq: "fsw", cut: "dfcb", diff: "", cmp: "in", source: "", ".": "", grep: "", egrep: "", fgrep: "", cp: "St" }

const CANT_FILES = (what: string, word: string) => `can't tell which files ${what} reads (${word} is only known when the shell runs it); name the files directly`
const CANT_FOLDER = (what: string, path: string) => `can't tell which folder ${what} would read ${path} from after an earlier folder change the guard does not follow; name the file by its full path`

const KEY_NAME = /[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*/i
const ENV_DUMP = new Set(["env", "printenv", "export", "set", "declare", "typeset"])

// A command that prints the environment (env, printenv, export -p, set,
// declare -x) or one key variable from it.
function environmentRead(words: string[], command: string): string | null {
  const program = basename(words[0] ?? "")
  const args = words.slice(1)
  if (ENV_DUMP.has(program)) {
    const named = args.filter((a) => !a.startsWith("-"))
    // env with a command runs that command; with none (or only assignments)
    // it prints everything. set with options (set -e) prints nothing.
    const dumps = program === "env" ? named.every((a) => a.includes("=")) : program === "set" ? args.length === 0 : named.length === 0
    if (dumps) return `\`${program}\` would print the environment, which can hold keys`
    if (program === "printenv" && named.some((a) => KEY_NAME.test(a))) return "`printenv` would print a key variable"
  }
  if ((program === "echo" || program === "printf") && new RegExp(`\\$\\{?${KEY_NAME.source}`, "i").test(command)) return `\`${program}\` would print a key variable`
  return null
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/
const RESERVED = new Set(["!", "if", "then", "else", "elif", "do", "while", "until", "{"])

function shownWord(word: Word): string {
  return word.text ? word.text : "a variable or a substitution"
}

// ---- the folder a command runs in ---------------------------------------

// Every folder the line might be in at this point, or null when an earlier
// change the guard does not model leaves it unknown.
type Cwds = string[] | null
type Link = { target: string; kind: "symbolic" | "hard"; written: string }
type State = { cwds: Cwds; stack: Cwds[]; links: Map<string, Link> }

const MAX_CWDS = 8

function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory()
  } catch {
    return false
  }
}

function union(a: Cwds, b: Cwds): Cwds {
  if (a === null || b === null) return null
  const all = [...new Set([...a, ...b])]
  return all.length > MAX_CWDS ? null : all
}

// Where `cd <word>` leaves the line, from every folder it might be in: a
// folder that exists is where the cd goes; one that does not may yet be
// made by the time it runs, so the line may be in either.
function changeTo(cwds: Cwds, arg: Word | undefined, home: string): Cwds {
  if (arg === undefined) return [home]
  if (arg.dynamic || arg.glob || arg.text === "-" || /^[+-]\d+$/.test(arg.text)) return null
  if (cwds === null) return isAbsolute(arg.text) && isDir(arg.text) ? [normalize(arg.text)] : null
  return union([], cwds.flatMap((cwd) => {
    const dir = resolve(cwd, arg.text)
    return isDir(dir) ? [dir] : [cwd, dir]
  }))
}

function operandsOf(args: Word[]): Word[] {
  let i = 0
  while (i < args.length && !(args[i] as Word).dynamic && (args[i] as Word).text.startsWith("-") && (args[i] as Word).text.length > 1) {
    if ((args[i] as Word).text === "--") {
      i++
      break
    }
    i++
  }
  return args.slice(i)
}

// cd, pushd and popd, with the directory stack. In a pipeline or in the
// background a cd runs in a subshell; the line may then be in either.
function folderChange(program: string, args: Word[], state: State, home: string, apart: boolean): void {
  const before = state.cwds
  const operands = operandsOf(args)
  if (program === "cd") state.cwds = changeTo(before, operands[0], home)
  else if (program === "pushd") {
    const arg = operands[0]
    if (arg === undefined) {
      const top = state.stack.pop()
      if (top !== undefined) {
        state.stack.push(before)
        state.cwds = top
      }
    } else {
      state.stack.push(before)
      state.cwds = changeTo(before, arg, home)
    }
  } else if (program === "popd") {
    const top = operands.length ? undefined : state.stack.pop()
    state.cwds = top === undefined ? null : top
  }
  if (apart) state.cwds = union(before, state.cwds)
}

// ---- links made earlier on the line -------------------------------------

function linkFor(path: string, links: Map<string, Link>): { link: Link; target: string } | null {
  for (const [at, link] of links) {
    if (path === at) return { link, target: link.target }
    if (link.kind === "symbolic" && path.startsWith(at + sep)) return { link, target: link.target + path.slice(at.length) }
  }
  return null
}

type LnArgs = { symbolic: boolean; relative: boolean; into: Word | null; single: boolean; operands: Word[] }

function lnArgs(args: Word[]): LnArgs {
  const parsed: LnArgs = { symbolic: false, relative: false, into: null, single: false, operands: [] }
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (word.dynamic || !text.startsWith("-") || text === "-") {
      parsed.operands.push(word)
      continue
    }
    if (text === "--") {
      parsed.operands.push(...args.slice(i + 1))
      break
    }
    if (text.startsWith("--")) {
      const [name, value] = text.split(/=(.*)/s) as [string, string | undefined]
      if (name === "--symbolic") parsed.symbolic = true
      else if (name === "--relative") parsed.relative = true
      else if (name === "--no-target-directory") parsed.single = true
      else if (name === "--target-directory") parsed.into = value !== undefined ? { ...word, text: value } : (args[++i] ?? null)
      else if (name === "--suffix" && value === undefined) i++
      continue
    }
    for (let j = 1; j < text.length; j++) {
      const flag = text[j] as string
      if (flag === "s") parsed.symbolic = true
      else if (flag === "r") parsed.relative = true
      else if (flag === "T") parsed.single = true
      else if (flag === "t" || flag === "S") {
        const value = text.slice(j + 1)
        const taken = value ? { ...word, text: value } : (args[++i] ?? null)
        if (flag === "t") parsed.into = taken
        break
      }
    }
  }
  return parsed
}

// What ln would make: one (target, link) pair per link, the forms of GNU ln.
function lnPairs(ln: LnArgs, cwd: string): { target: Word; link: string }[] {
  const ops = ln.operands
  if (ln.into) return ops.map((target) => ({ target, link: join(resolve(cwd, ln.into?.text ?? "."), basename(target.text)) }))
  if (ops.length === 1) return [{ target: ops[0] as Word, link: join(cwd, basename((ops[0] as Word).text)) }]
  if (ops.length === 2 && (ln.single || !isDir(resolve(cwd, (ops[1] as Word).text)))) return [{ target: ops[0] as Word, link: resolve(cwd, (ops[1] as Word).text) }]
  const dir = resolve(cwd, (ops.at(-1) as Word).text)
  return ops.slice(0, -1).map((target) => ({ target, link: join(dir, basename(target.text)) }))
}

// ---- grep -r -------------------------------------------------------------

// A grep glob as a regular expression over one base name, with \ quoting
// the next character as GNU grep's --exclude does.
function globRegex(glob: string): RegExp {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i] as string
    if (ch === "\\" && i + 1 < glob.length) {
      out += (glob[++i] as string).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    } else if (ch === "*") out += ".*"
    else if (ch === "?") out += "."
    else if (ch === "[") {
      const close = glob.indexOf("]", i + 2)
      if (close === -1) out += "\\["
      else {
        out += `[${glob.slice(i + 1, close).replace(/^!/, "^").replace(/\\/g, "\\\\")}]`
        i = close
      }
    } else out += ch.replace(/[.+^${}()|\\]/g, "\\$&")
  }
  return new RegExp(`^${out}$`)
}

// How far the guard walks a recursive grep's folders before it stops and
// refuses: a scope it cannot see the whole of might hold a key file.
export const GREP_WALK_DEPTH = 16
export const GREP_WALK_ENTRIES = 10_000

// Folders the walk does not enter, as they rarely hold the person's own
// keys and make up most of a tree: grep still searches them, so a key file
// in one can reach the agent. Only folders; one named on the command line
// is walked.
export const GREP_WALK_SKIPS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__"])

type GrepFilter = { include: boolean; re: RegExp }
type GrepArgs = { recursive: boolean; deref: boolean; filters: GrepFilter[]; excludeDirs: RegExp[]; files: Word[]; refuse: string | null }

const GREP_LONG_VALUE = new Set(["--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context", "--directories", "--devices", "--exclude", "--include", "--exclude-dir", "--exclude-from", "--label", "--binary-files", "--group-separator"])
const GREP_SHORT_VALUE = "efmABCdD"

function grepArgs(args: Word[]): GrepArgs {
  const parsed: GrepArgs = { recursive: false, deref: false, filters: [], excludeDirs: [], files: [], refuse: null }
  const operands: Word[] = []
  let pattern = false
  const option = (name: string, value: Word | undefined) => {
    if (name === "--recursive" || name === "r") parsed.recursive = true
    if (name === "--dereference-recursive" || name === "R") parsed.recursive = parsed.deref = true
    if ((name === "--directories" || name === "d") && value?.text === "recurse") parsed.recursive = true
    if (name === "--regexp" || name === "--file" || name === "e" || name === "f") pattern = true
    // A filter whose glob the shell decides is left out: checking more files
    // than grep reads is the safe side.
    if (value === undefined || value.dynamic) return
    if (name === "--exclude" || name === "--include") parsed.filters.push({ include: name === "--include", re: globRegex(value.text) })
    if (name === "--exclude-dir") parsed.excludeDirs.push(globRegex(value.text.replace(/\/+$/, "")))
  }
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (word.dynamic || !text.startsWith("-") || text === "-") {
      operands.push(word)
      continue
    }
    if (text === "--") {
      operands.push(...args.slice(i + 1))
      break
    }
    if (text.startsWith("--")) {
      const eq = text.indexOf("=")
      const name = eq === -1 ? text : text.slice(0, eq)
      const value = eq === -1 ? (GREP_LONG_VALUE.has(name) ? args[++i] : undefined) : { ...word, text: text.slice(eq + 1) }
      option(name, value)
      continue
    }
    for (let j = 1; j < text.length; j++) {
      const flag = text[j] as string
      if (GREP_SHORT_VALUE.includes(flag)) {
        const rest = text.slice(j + 1)
        option(flag, rest ? { ...word, text: rest } : args[++i])
        break
      }
      option(flag, undefined)
    }
  }
  parsed.files = pattern ? operands : operands.slice(1)
  return parsed
}

// --include and --exclude as GNU grep applies them: "If contradictory
// --include and --exclude options are given, the last matching one wins.
// If no --include or --exclude options match, a file is included unless
// the first such option is --include."
function grepReads(name: string, filters: GrepFilter[]): boolean {
  let decision: boolean | null = null
  for (const filter of filters) if (filter.re.test(name)) decision = filter.include
  return decision ?? !filters[0]?.include
}

type Walk = { found: string } | { refused: string } | null

// A breadth-first walk of what grep -r would read under `dir` (its real
// path), skipping what the command excludes and the folders in
// GREP_WALK_SKIPS, until it finds a key file or runs past its bounds. -r
// skips the links it meets, as grep does; -R follows them, each folder
// once.
function walkForSecrets(dir: string, target: string, grep: GrepArgs, home: string, vaultDirs: string[]): Walk {
  const cache = new Map<string, boolean>()
  const seen = new Set<string>()
  const identity = (path: string) => {
    const info = statSync(path)
    return `${info.dev}:${info.ino}`
  }
  seen.add(identity(dir))
  const queue: { path: string; shown: string; depth: number }[] = [{ path: dir, shown: target, depth: 0 }]
  let entries = 0
  const tooMany = { refused: `\`grep -r\` over ${target} would read too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check them for key files; search a narrower folder, or leave the large ones out with --exclude-dir` }
  const tooDeep = { refused: `\`grep -r\` over ${target} goes too deep (more than ${GREP_WALK_DEPTH} folders down) for the guard to check it for key files; search a narrower folder` }
  while (queue.length) {
    const { path, shown, depth } = queue.shift() as { path: string; shown: string; depth: number }
    if (vaultFolder(path, cache)) return { found: shown }
    let names: Dirent[]
    try {
      names = readdirSync(path, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of names) {
      if (++entries > GREP_WALK_ENTRIES) return tooMany
      let full = join(path, entry.name)
      const label = join(shown, entry.name)
      let folder = entry.isDirectory()
      if (entry.isSymbolicLink()) {
        if (!grep.deref) continue
        const real = realOrNull(full)
        if (real === null) continue
        full = real
        folder = isDir(real)
      }
      if (folder) {
        if (GREP_WALK_SKIPS.has(entry.name) || grep.excludeDirs.some((re) => re.test(entry.name))) continue
        if (depth + 1 > GREP_WALK_DEPTH) return tooDeep
        if (grep.deref) {
          const id = identity(full)
          if (seen.has(id)) continue
          seen.add(id)
        }
        queue.push({ path: full, shown: label, depth: depth + 1 })
        continue
      }
      if (!grepReads(entry.name, grep.filters)) continue
      if (secretFile(full, "/", home, vaultDirs, { physical: false, cache }) !== null) return { found: label }
    }
  }
  return null
}

// ---- what a name could be ------------------------------------------------

// Files that live in the protected folders under names that are ordinary
// elsewhere: in a folder the guard cannot see, `credentials` may be
// ~/.aws/credentials.
const PROTECTED_FILE_NAMES = new Set(["credentials", "config", "known_hosts", "authorized_keys", "hosts.yml", "default.toml", "config.json", "application_default_credentials.json", "pubring.kbx", "trustdb.gpg", "directory.sqlite"])

// The protected folders, as runs of folder names: ~/.aws is [".aws"],
// ~/.config/gh is [".config", "gh"].
function protectedRuns(home: string, vaultDirs: string[]): string[][] {
  const dirs = [...privateDirs(home, vaultDirs), ...loginFiles(home).filter((f) => f.type !== "json").map((f) => dirname(f.path))]
  const runs = dirs.map((dir) => {
    const rel = relative(home, dir)
    const parts = (rel.startsWith("..") || isAbsolute(rel) ? dir : rel).split(sep).filter(Boolean)
    return rel.startsWith("..") || isAbsolute(rel) ? parts.slice(-2) : parts
  })
  return [...runs, [".local-secrets"]]
}

function containsRun(parts: string[], run: string[]): boolean {
  for (let i = 0; i + run.length <= parts.length; i++) if (run.every((name, j) => parts[i + j] === name)) return true
  return false
}

// Whether a file of this name is a key file wherever it is, by the rules.
function secretName(name: string): boolean {
  if (name.endsWith(".pub")) return false
  const type = sourceType(`${sep}${name}`)
  return type === "dotenv" || type === "envrc" || KEY_FILE.test(name) || SSH_PRIVATE.test(name) || /^id_/.test(name) || DOTFILES.has(name)
}

// Whether a relative path could name a key file from some folder: its name
// is a key file's, or one kept in a protected folder, or it passes through
// a protected folder.
function couldNameSecret(path: string, home: string, vaultDirs: string[]): boolean {
  const parts = path.split(sep).filter((p) => p && p !== "." && p !== "..")
  const name = parts.at(-1) ?? ""
  if (secretName(name) || PROTECTED_FILE_NAMES.has(name)) return true
  return protectedRuns(home, vaultDirs).some((run) => containsRun(parts, run))
}

// ---- find, as a source of file names ----------------------------------------

// Extensions that key files the rules know end with.
const SECRET_EXTENSIONS = new Set(["env", "envrc", "vars", "pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx", "npmrc", "netrc", "pypirc", "pgpass", "cnf", "sqlite", "gpg", "kbx"])

// Names a key file the rules know may have, to test a pattern against: the
// fixed ones, and one of each family.
const SECRET_WITNESSES = [".env", ".env.local", ".env.development", ".env.dev", ".env.production", ".env.prod", ".env.test", ".env.staging", ".env.ci", ".env.preview", "x.env", ".envrc", ".dev.vars", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk", ...[...DOTFILES], ...PROTECTED_FILE_NAMES]

// Whether every name a find pattern matches is provably not a key file's:
// a literal name that is not one, or a pattern ending in a literal
// extension that no key file the rules know has. Anything else (*, .*,
// *.env, a pattern with no extension) could match one.
function safeFindPattern(pattern: string, caseless: boolean): boolean {
  const last = pattern.split("/").at(-1) ?? ""
  if (!/[*?[\\]/.test(pattern)) return !secretName(last) && !PROTECTED_FILE_NAMES.has(last)
  const extension = /\.([A-Za-z0-9]+)$/.exec(pattern)?.[1]
  if (extension === undefined || SECRET_EXTENSIONS.has(extension.toLowerCase())) return false
  const re = new RegExp(globRegex(last).source, caseless ? "i" : "")
  return !SECRET_WITNESSES.some((name) => re.test(name))
}

const FIND_NAME_TESTS = new Set(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename"])
const FIND_VALUE_TESTS = new Set(["-type", "-xtype", "-maxdepth", "-mindepth", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-newer", "-anewer", "-cnewer", "-size", "-perm", "-user", "-group", "-uid", "-gid", "-links", "-inum", "-used", "-fstype", "-printf", "-samefile"])
const FIND_FLAG_TESTS = new Set(["-print", "-print0", "-empty", "-readable", "-writable", "-executable", "-ls", "-delete", "-quit", "-true", "-depth", "-xdev", "-mount", "-follow", "-nouser", "-nogroup", "-daystart", "-noleaf", "-ignore_readdir_race", "-a", "-and"])
const FIND_EXEC = new Set(["-exec", "-execdir", "-ok", "-okdir"])

type FindModel = { why: string | null; execs: Word[][] }

// A find of the common form: starting folders, then a conjunction of
// tests and actions. `why` says why the files it yields cannot be told
// safe, or is null when every one of its name patterns provably cannot
// match a key file's name and no starting folder is or holds a protected
// one.
function findModel(args: Word[], cwds: Cwds, ctx: Context): FindModel {
  const model: FindModel = { why: null, execs: [] }
  const fail = (why: string) => {
    model.why ??= why
  }
  let i = 0
  while (i < args.length && ["-H", "-L", "-P"].includes((args[i] as Word).text)) i++
  const starts: Word[] = []
  while (i < args.length && !/^[-(!,)]/.test((args[i] as Word).text) && (args[i] as Word).text !== "!") starts.push(args[i++] as Word)
  const protectedDirs = [...privateDirs(ctx.home, ctx.vaultDirs), ...loginFiles(ctx.home).filter((f) => f.type !== "json").map((f) => dirname(f.path))]
  for (const start of starts.length ? starts : [{ text: ".", dynamic: false, glob: false }]) {
    if (start.dynamic || start.glob) fail(`it starts from ${shownWord(start)}, which only the shell knows`)
    else if (!isAbsolute(start.text) && cwds === null) fail("it starts from a folder the guard cannot follow")
    else
      for (const cwd of isAbsolute(start.text) ? ["/"] : (cwds as string[])) {
        const dir = resolve(cwd, start.text)
        if (classify(dir, ctx.home, ctx.vaultDirs) !== null || protectedDirs.some((p) => dir === sep || under(p, dir))) fail(`it starts from ${shown(dir, ctx.home)}, which is or holds a protected folder`)
      }
  }
  const patterns: { word: Word | undefined; caseless: boolean }[] = []
  for (; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (word.dynamic) {
      fail(`its expression has ${shownWord(word)}, which only the shell knows`)
      continue
    }
    if (FIND_NAME_TESTS.has(text)) {
      patterns.push({ word: args[++i], caseless: text.startsWith("-i") })
      continue
    }
    if (["-o", "-or", "!", "-not", "(", ")", ","].includes(text)) {
      fail(`its expression uses ${text}, which the guard does not follow`)
      continue
    }
    if (FIND_VALUE_TESTS.has(text)) {
      i++
      continue
    }
    if (FIND_FLAG_TESTS.has(text)) continue
    if (FIND_EXEC.has(text)) {
      const block: Word[] = []
      for (i++; i < args.length; i++) {
        const part = args[i] as Word
        if (!part.dynamic && (part.text === ";" || (part.text === "+" && block.at(-1)?.text === "{}"))) break
        block.push(part)
      }
      model.execs.push(block)
      continue
    }
    fail(`its expression uses ${text}, which the guard does not follow`)
  }
  if (patterns.length === 0) fail("it has no -name, -iname or -path pattern")
  for (const { word, caseless } of patterns) {
    if (word === undefined || word.dynamic) fail("one of its patterns is only known when the shell runs it")
    else if (!safeFindPattern(word.text, caseless)) fail(`its pattern '${word.text}' could match a key file's name`)
  }
  return model
}

const FED_HINT = "name the files directly, or feed it from a find with a -name pattern such as '*.ts'"

// ---- reading the line ------------------------------------------------------

type Context = { home: string; vaultDirs: string[]; command: string; findings: Finding[] }

function refuse(ctx: Context, reason: string): void {
  if (!ctx.findings.some((f) => f.reason === reason)) ctx.findings.push({ rule: "secret-file", reason })
}

// Whether `program` reading `word` would read a key file, from every folder
// the line might be in; a finding is added for the first.
// `program` is how the reason names the reader, `cat` in backticks.
function judgeRead(ctx: Context, state: State, cwds: Cwds, program: string, word: Word, strict: boolean): boolean {
  if (word.dynamic) {
    if (!strict) return false
    refuse(ctx, CANT_FILES(program, shownWord(word)))
    return true
  }
  if (word.glob) {
    if (!globMatchesSecret(word.text)) return false
    ctx.findings.push({ rule: "secret-file", reason: `${program} would read ${shown(word.text, ctx.home)}: the pattern matches environment or key files`, path: shown(word.text, ctx.home) })
    return true
  }
  const text = word.text
  const written = shown(text, ctx.home)
  if (!isAbsolute(text) && cwds === null) {
    // The folder is unknown: a path that could not name a key file from
    // any folder is fine; one that could is refused.
    if (!couldNameSecret(text, ctx.home, ctx.vaultDirs)) return false
    refuse(ctx, CANT_FOLDER(program, written))
    return true
  }
  for (const cwd of isAbsolute(text) ? ["/"] : (cwds as string[])) {
    const path = isAbsolute(text) ? text : `${cwd}${sep}${text}`
    const linked = linkFor(normalize(path), state.links)
    if (linked) {
      const why = secretFile(linked.target, "/", ctx.home, ctx.vaultDirs)
      if (why) {
        ctx.findings.push({ rule: "secret-file", reason: `${program} would read ${written}, a ${linked.link.kind} link made earlier in this command to ${linked.link.written}: ${why}`, path: written })
        return true
      }
    }
    const why = secretFile(path, "/", ctx.home, ctx.vaultDirs)
    if (why) {
      ctx.findings.push({ rule: "secret-file", reason: `${program} would read ${written}: ${why}`, path: written })
      return true
    }
  }
  return false
}

// The operands of a file reader, without its options and their values.
function fileOperands(program: string, args: Word[]): Word[] {
  const withValue = FILE_READERS[program] ?? ""
  const out: Word[] = []
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as Word
    if (word.dynamic || !word.text.startsWith("-") || word.text === "-") {
      out.push(word)
      continue
    }
    if (word.text === "--") {
      out.push(...args.slice(i + 1))
      break
    }
    if (word.text.startsWith("--")) continue
    const last = word.text.at(-1) as string
    if (word.text.length === 2 && withValue.includes(last)) i++
  }
  // cp's last operand is where it writes, unless -t names that folder.
  return program === "cp" && !args.some((w) => /^(-t|--target-directory)/.test(w.text)) ? out.slice(0, -1) : out
}

type Unwrapped = { words: Word[]; cwds: Cwds; reads: Word[]; fed: boolean; refuse: string | null }

function takeValue(args: Word[], i: number, word: Word, attached: string): [Word | undefined, number] {
  return attached ? [{ ...word, text: attached }, i] : [args[i + 1], i + 1]
}

// GNU env: options, then NAME=value, then the command it runs. -C changes
// the command's folder, and -S splits one string into words.
function unwrapEnv(rest: Word[], out: Unwrapped, ctx: Context): Word[] | null {
  let i = 0
  for (; i < rest.length; i++) {
    const word = rest[i] as Word
    const text = word.text
    if (word.dynamic || !text.startsWith("-")) break
    if (text === "--") {
      i++
      break
    }
    if (text === "-" || ["-i", "--ignore-environment", "-0", "--null", "-v", "--debug", "--list-signal-handling"].includes(text)) continue
    if (/^--(block|default|ignore)-signal(=|$)/.test(text)) continue
    let name: string
    let value: Word | undefined
    if (text.startsWith("--")) {
      const eq = text.indexOf("=")
      name = eq === -1 ? text : text.slice(0, eq)
      if (!["--unset", "--chdir", "--split-string"].includes(name)) {
        out.refuse = `can't tell what \`env\` runs with ${text}; run the command without it`
        return null
      }
      ;[value, i] = eq === -1 ? [rest[i + 1], i + 1] : [{ ...word, text: text.slice(eq + 1) }, i]
    } else {
      const flags = text.slice(1)
      const at = flags.search(/[uCS]/)
      if (at === -1) {
        if (/^[i0v]+$/.test(flags)) continue
        out.refuse = `can't tell what \`env\` runs with ${text}; run the command without it`
        return null
      }
      if (!/^[i0v]*$/.test(flags.slice(0, at))) {
        out.refuse = `can't tell what \`env\` runs with ${text}; run the command without it`
        return null
      }
      name = { u: "--unset", C: "--chdir", S: "--split-string" }[flags[at] as "u" | "C" | "S"]
      ;[value, i] = takeValue(rest, i, word, flags.slice(at + 1))
    }
    if (value === undefined) break
    if (name === "--chdir") out.cwds = value.dynamic ? null : out.cwds === null ? (isAbsolute(value.text) ? [value.text] : null) : out.cwds.map((cwd) => resolve(cwd, value.text))
    if (name === "--split-string") {
      const nodes = value.dynamic ? [] : parseShell(value.text, ctx.home)
      const only = nodes[0]
      if (nodes.length !== 1 || only?.kind !== "command" || only.inputs.length || only.next !== null || only.words.some((w) => w.dynamic)) {
        out.refuse = `can't tell what \`env -S\` runs; run the command without it`
        return null
      }
      return [...only.words, ...rest.slice(i + 1)]
    }
  }
  return rest.slice(i)
}

const SUDO_VALUE = new Set(["-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt", "--close-from", "--role", "--type", "--other-user", "--command-timeout"])
const XARGS_VALUE = "nLPdsEIa"

// The program a command line really runs, past variable assignments and the
// wrappers that run their arguments as a command: command, builtin, env,
// exec, nohup, time, sudo and xargs. A wrapper that would run nothing (env
// alone prints the environment, command -v only looks a name up) is kept.
function unwrap(words: Word[], cwds: Cwds, ctx: Context): Unwrapped {
  const out: Unwrapped = { words, cwds, reads: [], fed: false, refuse: null }
  let current = words
  for (let depth = 0; depth < 8; depth++) {
    let i = 0
    while (i < current.length - 1 && !(current[i] as Word).dynamic && ASSIGNMENT.test((current[i] as Word).text)) i++
    current = current.slice(i)
    out.words = current
    const head = current[0]
    if (!head || head.dynamic) return out
    let rest = current.slice(1)
    switch (basename(head.text)) {
      case "command": {
        let j = 0
        let lookup = false
        while (j < rest.length && !(rest[j] as Word).dynamic && (rest[j] as Word).text.startsWith("-")) {
          if ((rest[j] as Word).text === "--") {
            j++
            break
          }
          if (/[vV]/.test((rest[j] as Word).text)) lookup = true
          j++
        }
        if (lookup) return out
        rest = rest.slice(j)
        break
      }
      case "builtin":
      case "nohup":
        break
      case "exec": {
        let j = 0
        while (j < rest.length && /^-[cla]+$/.test((rest[j] as Word).text)) j += (rest[j] as Word).text.endsWith("a") ? 2 : 1
        rest = rest.slice(j)
        break
      }
      case "time": {
        let j = 0
        while (j < rest.length && (rest[j] as Word).text.startsWith("-")) j += ["-f", "-o"].includes((rest[j] as Word).text) ? 2 : 1
        rest = rest.slice(j)
        break
      }
      case "env": {
        const next = unwrapEnv(rest, out, ctx)
        if (next === null) return out
        let j = 0
        while (j < next.length && !(next[j] as Word).dynamic && ASSIGNMENT.test((next[j] as Word).text)) j++
        rest = next.slice(j)
        if (!rest.length) {
          out.words = [head]
          return out
        }
        break
      }
      case "sudo": {
        let j = 0
        while (j < rest.length && (rest[j] as Word).text.startsWith("-") && !(rest[j] as Word).dynamic) {
          const text = (rest[j] as Word).text
          if (text === "--") {
            j++
            break
          }
          const chdir = /^(?:-D|--chdir)(?:=(.*))?$/.exec(text)
          if (chdir) {
            const dir = chdir[1] !== undefined ? { ...(rest[j] as Word), text: chdir[1] } : rest[++j]
            if (dir) out.cwds = dir.dynamic ? null : out.cwds === null ? (isAbsolute(dir.text) ? [dir.text] : null) : out.cwds.map((cwd) => resolve(cwd, dir.text))
          } else if (SUDO_VALUE.has(text)) j++
          j++
        }
        rest = rest.slice(j)
        break
      }
      case "xargs": {
        let j = 0
        while (j < rest.length && (rest[j] as Word).text.startsWith("-") && !(rest[j] as Word).dynamic) {
          const word = rest[j] as Word
          const text = word.text
          if (text === "--") {
            j++
            break
          }
          if (text.startsWith("--")) {
            const eq = text.indexOf("=")
            const name = eq === -1 ? text : text.slice(0, eq)
            const takes = ["--arg-file", "--max-args", "--max-lines", "--max-procs", "--delimiter", "--max-chars", "--replace", "--eof", "--process-slot-var"].includes(name)
            const value = eq !== -1 ? { ...word, text: text.slice(eq + 1) } : takes && !["--replace", "--eof"].includes(name) ? rest[++j] : undefined
            if (name === "--arg-file" && value) out.reads.push(value)
            j++
            continue
          }
          const flag = text[1] as string
          if (XARGS_VALUE.includes(flag)) {
            const value = text.length > 2 ? { ...word, text: text.slice(2) } : rest[++j]
            if (flag === "a" && value) out.reads.push(value)
          }
          j++
        }
        rest = rest.slice(j)
        out.fed = true
        if (!rest.length) return out
        break
      }
      default:
        return out
    }
    if (!rest.length) return out
    current = rest
  }
  out.words = current
  return out
}

// One simple command: its folder changes, links, environment dumps, grep
// -r walks and the files it reads.
type CommandNode = Extract<ShellNode, { kind: "command" }>

// Why the files `xargs` hands its program cannot be told safe, or null when
// they come straight from a find the guard can read whose names cannot be a
// key file's.
function xargsInput(ctx: Context, state: State, node: CommandNode, producer: CommandNode | null, fromFile: boolean): string | null {
  if (fromFile) return "its input is a file, not a find"
  if (node.op !== "|" || producer === null || producer.next !== "|") return "its input is not a find"
  const words = unwrap(producer.words, state.cwds, ctx).words
  if (words[0]?.dynamic || basename(words[0]?.text ?? "") !== "find") return "its input is not a find"
  return findModel(words.slice(1), state.cwds, ctx).why
}

function command(ctx: Context, state: State, node: CommandNode, producer: CommandNode | null = null): void {
  let words = node.words
  while (words.length && !(words[0] as Word).dynamic && RESERVED.has((words[0] as Word).text)) words = words.slice(1)
  const apart = node.op === "|" || node.next === "|" || node.next === "&"
  const unwrapped = unwrap(words, state.cwds, ctx)
  const first = unwrapped.words[0]
  const name = first === undefined ? "the redirect" : first.dynamic ? "the command" : `\`${basename(first.text)}\``
  for (const input of node.inputs) if (judgeRead(ctx, state, state.cwds, name, input, true)) break
  if (unwrapped.refuse) {
    refuse(ctx, unwrapped.refuse)
    return
  }
  for (const read of unwrapped.reads) judgeRead(ctx, state, state.cwds, "`xargs`", read, true)
  words = unwrapped.words
  const cwds = unwrapped.cwds
  const head = words[0]
  if (!head) return
  const program = head.dynamic ? "" : basename(head.text)
  const args = words.slice(1)

  if (program === "cd" || program === "pushd" || program === "popd") {
    folderChange(program, args, state, ctx.home, apart)
    return
  }
  if (["sh", "bash", "zsh", "dash", "ksh"].includes(program)) {
    const flag = args.findIndex((a) => !a.dynamic && /^-[a-z]*c[a-z]*$/.test(a.text))
    if (flag === -1) return
    const script = args[flag + 1]
    if (!script || script.dynamic) return refuse(ctx, `can't tell what \`${program} -c\` runs; run the command directly`)
    return lines(ctx, { ...state, cwds, stack: [...state.stack] }, parseShell(script.text, ctx.home))
  }
  if (program === "eval") {
    if (args.some((a) => a.dynamic)) return refuse(ctx, "can't tell what `eval` runs; run the command directly")
    return lines(ctx, state, parseShell(args.map((a) => a.text).join(" "), ctx.home))
  }
  const dump = environmentRead(words.map((w) => w.text), ctx.command)
  if (dump) {
    ctx.findings.push({ rule: "secret-file", reason: dump })
    return
  }
  if (program === "ln") {
    const ln = lnArgs(args)
    if (cwds === null || ln.operands.some((w) => w.dynamic) || ln.operands.length === 0) return
    for (const cwd of cwds) {
      for (const { target, link } of lnPairs(ln, cwd)) {
        const base = ln.symbolic && !ln.relative ? dirname(link) : cwd
        const at = isAbsolute(target.text) ? normalize(target.text) : `${base}${sep}${target.text}`
        const written = shown(target.text, ctx.home)
        state.links.set(normalize(link), { target: at, kind: ln.symbolic ? "symbolic" : "hard", written })
        const why = secretFile(at, "/", ctx.home, ctx.vaultDirs)
        if (why && !ctx.findings.some((f) => f.path === written)) ctx.findings.push({ rule: "secret-file", reason: `\`${ln.symbolic ? "ln -s" : "ln"}\` would make a ${ln.symbolic ? "symbolic" : "hard"} link to ${written}: ${why}`, path: written })
      }
    }
    return
  }
  if (program === "grep" || program === "egrep" || program === "fgrep") {
    const grep = grepArgs(args)
    if (grep.recursive) {
      for (const target of grep.files.length ? grep.files : [{ text: ".", dynamic: false, glob: false }]) {
        if (target.dynamic) return refuse(ctx, CANT_FILES("`grep -r`", shownWord(target)))
        if (!isAbsolute(target.text) && cwds === null) return refuse(ctx, CANT_FOLDER("`grep -r`", shown(target.text, ctx.home)))
        for (const cwd of isAbsolute(target.text) ? ["/"] : (cwds as string[])) {
          const real = realOrNull(resolve(cwd, target.text))
          if (real === null || !isDir(real)) continue
          const walk = walkForSecrets(real, shown(target.text, ctx.home), grep, ctx.home, ctx.vaultDirs)
          if (walk && "found" in walk) {
            ctx.findings.push({ rule: "secret-file", reason: `\`grep -r\` would read ${walk.found}` })
            return
          }
          if (walk) return refuse(ctx, walk.refused)
        }
      }
    }
    if (unwrapped.fed) {
      const why = xargsInput(ctx, state, node, producer, unwrapped.reads.length > 0)
      if (why) return refuse(ctx, `can't tell which files \`xargs ${program}\` reads: ${why}; ${FED_HINT}`)
    }
    for (const file of grep.files) if (judgeRead(ctx, state, cwds, `\`${program}\``, file, true)) return
    return
  }
  if (program === "find") {
    const model = findModel(args, cwds, ctx)
    for (const block of model.execs) {
      const runner = block[0]
      if (!runner) continue
      const reader = runner.dynamic || basename(runner.text) in FILE_READERS
      if (reader && model.why && block.some((w) => w.text.includes("{}"))) {
        refuse(ctx, `can't tell which files \`find -exec ${runner.dynamic ? "" : basename(runner.text)}\` reads: ${model.why}; ${FED_HINT}`)
        continue
      }
      // The command -exec runs, with the found file left out: anything
      // else it names is judged as any command's would be.
      command(ctx, { ...state, stack: [...state.stack] }, { kind: "command", words: block.filter((w) => w.text !== "{}"), inputs: [], op: "start", next: null })
    }
    return
  }
  const strict = program in FILE_READERS
  if (!(READERS.has(program) || head.dynamic)) return
  if (unwrapped.fed && strict) {
    const why = xargsInput(ctx, state, node, producer, unwrapped.reads.length > 0)
    if (why) return refuse(ctx, `can't tell which files \`xargs ${program}\` reads: ${why}; ${FED_HINT}`)
  }
  const operands = strict ? fileOperands(program, args) : args.filter((w) => w.dynamic || !w.text.startsWith("-"))
  for (const word of operands) if (judgeRead(ctx, state, cwds, name, word, strict)) return
}

function lines(ctx: Context, state: State, nodes: ShellNode[]): void {
  const saved: { cwds: Cwds; stack: Cwds[]; previous: CommandNode | null }[] = []
  // The command before, at this level: what a pipe feeds the next one.
  let previous: CommandNode | null = null
  for (const node of nodes) {
    if (node.kind === "open") {
      saved.push({ cwds: state.cwds, stack: [...state.stack], previous })
      previous = null
    } else if (node.kind === "close") {
      const back = saved.pop()
      if (back) {
        state.cwds = back.cwds
        state.stack = back.stack
        previous = back.previous
      }
    } else if (node.kind === "unknown") refuse(ctx, `can't tell what this command runs (${node.why}); run the part that reads files on its own`)
    else {
      command(ctx, state, node, previous)
      previous = node
    }
  }
}

export function commandFindings(command: string, cwd: string, home = homedir(), vaultDirs: string[] = []): Finding[] {
  const findings: Finding[] = []
  const inText = secretInText(command)
  if (inText) findings.push({ rule: "secret-in-command", reason: `the command carries ${inText}` })
  lines({ home, vaultDirs, command, findings }, { cwds: [cwd], stack: [], links: new Map() }, parseShell(command, home))
  return findings
}
