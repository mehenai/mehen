// What the guard hooks look for, whichever agent asks: a tool about to read
// a file that holds secrets, a shell command that reads one or carries a
// provider key, and a write that would put a key into a file. Local rules
// only: no vault, no network, nothing read but the paths named, so a hook
// answers in milliseconds and never fails for want of a connection.

import { secretPrefix, PLACEHOLDER_CORE } from "@mehen/protocol"
import { type Dirent, existsSync, readdirSync, realpathSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { basename, dirname, join, normalize, resolve, sep } from "node:path"
import { loginFiles, sourceType } from "../adopt/sources.ts"

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

// $HOME, ${HOME} and a leading ~ as the home folder, as the shell would
// read them; nothing is ever run to find out.
export function expandHome(word: string, home: string): string {
  return word.replace(/^~(?=$|\/)/, home).replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home)
}

export type SecretFileOptions = { follow?: boolean; cache?: Map<string, boolean> }

// Why reading this file would put a secret in front of the agent, or null.
// A link that exists is judged by what it points at too.
export function secretFile(raw: string, cwd: string, home = homedir(), vaultDirs: string[] = [], options: SecretFileOptions = {}): string | null {
  const path = normalize(resolve(cwd, expandHome(raw, home)))
  const why = classify(path, home, vaultDirs, options.cache)
  if (why !== null || options.follow === false) return why
  let real: string
  try {
    real = realpathSync(path)
  } catch {
    return null
  }
  if (real === path) return null
  const through = classify(real, home, vaultDirs, options.cache)
  return through === null ? null : `it is a link to ${real.replace(home, "~")}, and ${through}`
}

function classify(path: string, home: string, vaultDirs: string[], cache?: Map<string, boolean>): string | null {
  const name = basename(path)
  if (/^\/proc\/[^/]+\/environ$/.test(path)) return "it is a process's environment, which can hold keys"
  if (insideVaultData(path, cache)) return "it is a Mehen vault's own data"
  if (name.endsWith(".pub")) return null
  for (const dir of privateDirs(home, vaultDirs)) if (under(path, dir)) return dir === join(home, ".config", "mehen") ? "it is one of Mehen's own files on this machine" : vaultDirs.includes(dir) ? "it is the vault's own data" : `it is under ${dir.replace(home, "~")}, where keys live`
  if (loginFiles(home).some((file) => file.type !== "json" && file.path === path)) return "it holds a CLI's login"
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

// Splits a command line into segments (pipes, ;, &&, ||) and words, well
// enough to see which program reads which path. Quotes are honoured;
// anything cleverer (substitutions, eval) is read as plain words.
// $HOME and ${HOME} at i: the length of the reference, or 0.
function homeReference(command: string, i: number): number {
  const ahead = command.slice(i)
  if (ahead.startsWith("${HOME}")) return 7
  return /^\$HOME(?![A-Za-z0-9_])/.test(ahead) ? 5 : 0
}

function segments(command: string, home: string): string[][] {
  const out: string[][] = []
  let words: string[] = []
  let word = ""
  let quote: string | null = null
  const push = () => {
    if (word) words.push(word)
    word = ""
  }
  for (let i = 0; i < command.length; i++) {
    const ch = command[i] as string
    const reference = ch === "$" && quote !== "'" ? homeReference(command, i) : 0
    if (reference) {
      word += home
      i += reference - 1
      continue
    }
    if (quote) {
      if (ch === quote) quote = null
      else word += ch
      continue
    }
    if (ch === "'" || ch === '"') quote = ch
    else if (ch === " " || ch === "\t" || ch === "\n") push()
    else if (ch === "|" || ch === ";" || ch === "&" || ch === "<" || ch === ">" || ch === "(" || ch === ")" || ch === "`" || ch === "$") {
      push()
      if (ch === "<") words.push("<")
      if (ch === "|" || ch === ";" || ch === "&" || ch === "(" || ch === ")" || ch === "`") {
        if (words.length) out.push(words)
        words = []
      }
    } else word += ch
  }
  push()
  if (words.length) out.push(words)
  return out
}

// A variable whose name says it holds a key.
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

// Leading options of a wrapper, and the ones among them that take a value.
function dropOptions(args: string[], withValue: readonly string[]): string[] {
  let i = 0
  while (i < args.length && (args[i] as string).startsWith("-")) {
    const option = args[i] as string
    i++
    if (option === "--") break
    if (withValue.includes(option)) i++
  }
  return args.slice(i)
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

// The program a command line really runs, past variable assignments and the
// wrappers that run their arguments as a command: command, builtin, env,
// exec, nohup, time, sudo and xargs. A wrapper that would run nothing (env
// alone prints the environment, command -v only looks a name up) is kept.
export function unwrap(words: string[]): string[] {
  let current = words
  for (let depth = 0; depth < 8; depth++) {
    let i = 0
    while (i < current.length - 1 && ASSIGNMENT.test(current[i] as string)) i++
    current = current.slice(i)
    const program = basename(current[0] ?? "")
    let rest = current.slice(1)
    switch (program) {
      case "command":
        if (rest.includes("-v") || rest.includes("-V")) return current
        rest = dropOptions(rest, [])
        break
      case "builtin":
      case "nohup":
        break
      case "exec":
        rest = dropOptions(rest, ["-a"])
        break
      case "time":
        rest = dropOptions(rest, ["-f", "-o"])
        break
      case "env":
        rest = dropOptions(rest, ["-u", "-C", "-S", "--unset", "--chdir", "--split-string"])
        while (rest.length && ASSIGNMENT.test(rest[0] as string)) rest = rest.slice(1)
        break
      case "sudo":
        rest = dropOptions(rest, ["-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D", "--user", "--group", "--host", "--prompt"])
        break
      case "xargs":
        rest = dropOptions(rest, ["-n", "-I", "-L", "-P", "-d", "-s", "-E", "-a", "--max-args", "--max-lines", "--max-procs", "--delimiter", "--arg-file"])
        break
      default:
        return current
    }
    if (rest.length === 0) return current
    current = rest
  }
  return current
}

// A shell glob as a regular expression over one name.
function globRegex(glob: string): RegExp {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i] as string
    if (ch === "*") out += ".*"
    else if (ch === "?") out += "."
    else if (ch === "[") {
      const close = glob.indexOf("]", i + 1)
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

type GrepArgs = { recursive: boolean; targets: string[]; excludes: RegExp[]; includes: RegExp[]; excludeDirs: RegExp[] }

const GREP_LONG_VALUE = new Set(["--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context", "--directories", "--devices", "--exclude", "--include", "--exclude-dir", "--exclude-from", "--label", "--binary-files", "--group-separator"])
const GREP_SHORT_VALUE = "efmABCdD"

function grepArgs(args: string[]): GrepArgs {
  const parsed: GrepArgs = { recursive: false, targets: [], excludes: [], includes: [], excludeDirs: [] }
  const operands: string[] = []
  let pattern = false
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string
    if (arg === "--") {
      operands.push(...args.slice(i + 1))
      break
    }
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=")
      const name = eq === -1 ? arg : arg.slice(0, eq)
      let value = eq === -1 ? undefined : arg.slice(eq + 1)
      if (value === undefined && GREP_LONG_VALUE.has(name)) value = args[++i]
      if (name === "--recursive" || name === "--dereference-recursive") parsed.recursive = true
      if (name === "--regexp" || name === "--file") pattern = true
      if (value !== undefined && name === "--exclude") parsed.excludes.push(globRegex(value))
      if (value !== undefined && name === "--include") parsed.includes.push(globRegex(value))
      if (value !== undefined && name === "--exclude-dir") parsed.excludeDirs.push(globRegex(value))
      continue
    }
    if (arg.startsWith("-") && arg.length > 1) {
      for (let j = 1; j < arg.length; j++) {
        const flag = arg[j] as string
        if (flag === "r" || flag === "R") parsed.recursive = true
        if (GREP_SHORT_VALUE.includes(flag)) {
          if (flag === "e" || flag === "f") pattern = true
          if (j === arg.length - 1) i++
          break
        }
      }
      continue
    }
    operands.push(arg)
  }
  const targets = pattern ? operands : operands.slice(1)
  parsed.targets = targets.length ? targets : ["."]
  return parsed
}

type Walk = { found: string } | { refused: string } | null

// A breadth-first walk of what grep -r would read under `dir`, skipping what
// the command excludes, until it finds a key file or runs past its bounds.
function walkForSecrets(dir: string, target: string, grep: GrepArgs, cwd: string, home: string, vaultDirs: string[]): Walk {
  const cache = new Map<string, boolean>()
  const queue: { path: string; shown: string; depth: number }[] = [{ path: dir, shown: target, depth: 0 }]
  let entries = 0
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
      if (++entries > GREP_WALK_ENTRIES) return { refused: `\`grep -r\` over ${target} would read too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check them for key files; search a narrower folder, or leave the large ones out with --exclude-dir` }
      const full = join(path, entry.name)
      const label = join(shown, entry.name)
      if (entry.isDirectory()) {
        if (grep.excludeDirs.some((re) => re.test(entry.name))) continue
        if (depth + 1 > GREP_WALK_DEPTH) return { refused: `\`grep -r\` over ${target} goes too deep (more than ${GREP_WALK_DEPTH} folders down) for the guard to check it for key files; search a narrower folder` }
        queue.push({ path: full, shown: label, depth: depth + 1 })
        continue
      }
      if (grep.excludes.some((re) => re.test(entry.name))) continue
      if (grep.includes.length && !grep.includes.some((re) => re.test(entry.name))) continue
      if (secretFile(full, cwd, home, vaultDirs, { follow: entry.isSymbolicLink(), cache }) !== null) return { found: label }
    }
  }
  return null
}

// grep -r over a folder that holds a secret file, at any depth, reads it,
// unless the command's own --exclude, --exclude-dir or --include leaves
// every such file out.
function recursiveRead(words: string[], cwd: string, home: string, vaultDirs: string[]): string | null {
  if (!["grep", "egrep", "fgrep"].includes(basename(words[0] ?? ""))) return null
  const grep = grepArgs(words.slice(1))
  if (!grep.recursive) return null
  for (const target of grep.targets) {
    const dir = resolve(cwd, expandHome(target, home))
    try {
      if (!statSync(dir).isDirectory()) continue
    } catch {
      continue
    }
    const walk = walkForSecrets(dir, target, grep, cwd, home, vaultDirs)
    if (walk && "found" in walk) return `\`grep -r\` would read ${walk.found}`
    if (walk) return walk.refused
  }
  return null
}

// ln makes a link to its sources: a link to a key file is a way to read it
// under a name the guard would not know.
function linkTargets(args: string[]): string[] {
  const operands: string[] = []
  let into = false
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string
    if (arg === "-t" || arg === "--target-directory") {
      into = true
      i++
    } else if (arg.startsWith("--target-directory=")) into = true
    else if (!arg.startsWith("-")) operands.push(arg)
  }
  return into || operands.length < 2 ? operands : operands.slice(0, -1)
}

export function commandFindings(command: string, cwd: string, home = homedir(), vaultDirs: string[] = []): Finding[] {
  const findings: Finding[] = []
  const inText = secretInText(command)
  if (inText) findings.push({ rule: "secret-in-command", reason: `the command carries ${inText}` })
  // Each folder a cd earlier in the line may have moved to: a relative path
  // is judged against all of them, since && and || decide which one holds.
  const cwds = [cwd]
  const secretIn = (word: string): string | null => {
    for (const dir of cwds) {
      const why = secretFile(word, dir, home, vaultDirs)
      if (why) return why
    }
    return null
  }
  for (const raw of segments(command, home)) {
    const words = unwrap(raw)
    const program = basename(words[0] ?? "")
    const args = words.slice(1)
    if ((program === "cd" || program === "pushd") && args.length) {
      const dir = args.find((a) => !a.startsWith("-") || a === "-")
      if (dir && dir !== "-") cwds.push(resolve(cwds.at(-1) as string, expandHome(dir, home)))
      continue
    }
    const why = environmentRead(words, command) ?? cwds.map((dir) => recursiveRead(words, dir, home, vaultDirs)).find((w) => w !== null) ?? null
    if (why) findings.push({ rule: "secret-file", reason: why })
    if (program === "ln") {
      for (const source of linkTargets(args)) {
        const linked = secretIn(source)
        if (linked) {
          findings.push({ rule: "secret-file", reason: `\`ln\` would link to ${source}: ${linked}`, path: source })
          break
        }
      }
      continue
    }
    const reads = READERS.has(program) || words.includes("<")
    if (!reads) continue
    // cp and its kin only read their sources: copying a template onto .env
    // writes it, and shows the agent nothing.
    const operands = program === "cp" ? args.slice(0, -1) : args
    for (const word of operands) {
      if (word.startsWith("-") || word === "<") continue
      const found = /[*?]/.test(basename(word)) ? (globMatchesSecret(word) ? "the pattern matches environment or key files" : null) : secretIn(word)
      if (found) {
        findings.push({ rule: "secret-file", reason: `\`${program}\` would read ${word}: ${found}`, path: word })
        break
      }
    }
  }
  return findings
}
