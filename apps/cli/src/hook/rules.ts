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
import { KEY_VARIABLE, type Op, type ShellNode, type Word, literal, parseShell } from "./shell.ts"
import { OPTION_SPECS, own, parseOptions } from "./options.ts"

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
  const pattern = globMatcher(name.replace(/[^*?]/g, "\\$&"))
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
const ENV_DUMP = new Set(["env", "printenv", "export", "set", "declare", "typeset", "local", "readonly"])
const DECLARATIONS = new Set(["declare", "typeset", "local", "readonly", "export"])
// ps options that take a value, whose value is not a BSD option word.
const PS_VALUE = /^-[A-Za-z]*[oOpuUgGtCqk]$|^--(format|pid|ppid|user|group|tty|sort|cols|columns|rows)$/

// A command that prints the environment (env, printenv, set, export,
// declare and the like with no names), a key variable from it (printenv,
// declare -p and kin, echo and printf), or other processes' environments
// (ps e).
function environmentRead(words: Word[], command: string): string | null {
  const program = basename(words[0]?.text ?? "")
  const args = words.slice(1)
  const option = (a: Word) => !a.dynamic && /^[-+]/.test(a.text) && a.text.length > 1
  const named = args.filter((a) => !option(a))
  if (DECLARATIONS.has(program)) {
    const flags = args.filter(option).map((a) => a.text.slice(1)).join("")
    // -f and -F list functions, not variables.
    if (/[fF]/.test(flags)) return null
    if (flags.includes("p") || named.length === 0) {
      if (named.length === 0) return `\`${program}${flags ? ` -${flags}` : ""}\` would print the environment, which can hold keys`
      const key = named.find((a) => a.dynamic || KEY_VARIABLE.test(a.text.split("=")[0] as string))
      if (key) return `\`${program} -p\` would print ${key.dynamic ? "a variable only the shell knows" : `$${key.text}`}, which can hold a key`
    }
    return null
  }
  if (ENV_DUMP.has(program)) {
    const texts = named.map((a) => a.text)
    // env with a command runs that command; with none (or only assignments)
    // it prints everything. set with options (set -e) prints nothing.
    const dumps = program === "env" ? texts.every((a) => a.includes("=")) : program === "set" ? args.length === 0 : texts.length === 0
    if (dumps) return `\`${program}\` would print the environment, which can hold keys`
    if (program === "printenv" && named.some((a) => a.dynamic || KEY_NAME.test(a.text))) return "`printenv` would print a key variable"
  }
  if (program === "ps") {
    for (const [i, a] of args.entries()) {
      if (a.dynamic || a.text.startsWith("-") || !/^[A-Za-z]+$/.test(a.text) || !a.text.includes("e")) continue
      if (i > 0 && PS_VALUE.test(args[i - 1]?.text ?? "")) continue
      return "`ps e` would print other processes' environments, which can hold keys"
    }
  }
  if ((program === "echo" || program === "printf") && (args.some((a) => a.vars.some((v) => KEY_VARIABLE.test(v))) || new RegExp(`\\$\\{?${KEY_NAME.source}`, "i").test(command))) return `\`${program}\` would print a key variable`
  return null
}

// A piece of a word (an option's value), as a word of its own.
function part(word: Word, text: string): Word {
  return literal(text, word.dynamic)
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
// A folder as chdir(2) reaches it: each part in order on disk, a link
// replaced by what it points at before a later .. is read. When it does
// not exist, the path as written.
function physicalDir(cwd: string, text: string): string {
  const joined = isAbsolute(text) ? text : `${cwd}${sep}${text}`
  return realOrNull(joined) ?? normalize(joined)
}

function changeTo(cwds: Cwds, arg: Word | undefined, home: string, physical = false): Cwds {
  if (arg === undefined) return [home]
  if (arg.dynamic || arg.glob || arg.brace || arg.text === "-" || /^[+-]\d+$/.test(arg.text)) return null
  const to = (cwd: string) => (physical ? physicalDir(cwd, arg.text) : resolve(cwd, arg.text))
  if (cwds === null) return isAbsolute(arg.text) && isDir(arg.text) ? [to("/")] : null
  return union([], cwds.flatMap((cwd) => {
    const dir = to(cwd)
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
  // cd -P resolves links on disk; plain cd (or -L) works on the path as
  // written, as the shell does. The last of the two wins. An option the
  // guard does not know leaves the folder unknown; pushd -n and popd -n
  // change only the stack.
  const words = args.slice(0, args.length - operands.length).map((w) => w.text).filter((w) => w !== "--")
  const options = words.join("")
  const known = program === "cd" ? /^-[LPe@]+$/ : /^-n$/
  if (words.some((w) => !known.test(w))) {
    state.cwds = apart ? union(before, null) : null
    return
  }
  // More than one folder: bash refuses it, an older bash takes the first
  // and zsh reads two as a substitution, so the folder is not known.
  if (operands.length > 1) {
    if (program === "pushd") state.stack.push(null)
    state.cwds = apart ? union(before, null) : null
    return
  }
  const physical = options.lastIndexOf("P") > options.lastIndexOf("L")
  const onlyStack = program !== "cd" && options.includes("n")
  if (onlyStack) {
    if (program === "pushd") state.stack.push(operands[0] ? changeTo(before, operands[0], home) : null)
    else state.stack.pop()
    return
  }
  if (program === "cd") state.cwds = changeTo(before, operands[0], home, physical)
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
      else if (name === "--target-directory") parsed.into = value !== undefined ? part(word, value) : (args[++i] ?? null)
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
        const taken = value ? part(word, value) : (args[++i] ?? null)
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

// A grep glob matched against one base name, with \ quoting the next
// character as GNU grep's --exclude does: `*`, `?` and `[...]` sets (`!` or
// `^` first negates). Matched without backtracking past the last `*`, so
// the time is at most the pattern's length times the name's, whatever the
// pattern holds.
type GlobMatcher = { test(text: string): boolean }
type GlobToken = { kind: "star" } | { kind: "one"; test: (c: string) => boolean }

// POSIX classes as the C locale has them. Whether a character past ASCII
// is in a class, or in a class fnmatch does not know, the guard cannot
// say; it then answers the way that never lets a read through: a pattern
// that selects files (`more`) matches, and one that leaves files out
// (grep --exclude) does not.
const POSIX_CLASSES: Record<string, RegExp> = {
  alpha: /[A-Za-z]/,
  digit: /[0-9]/,
  alnum: /[A-Za-z0-9]/,
  upper: /[A-Z]/,
  lower: /[a-z]/,
  space: /[ \t\n\r\f\v]/,
  blank: /[ \t]/,
  punct: /[!-\/:-@[-`{-~]/,
  xdigit: /[0-9A-Fa-f]/,
  print: /[ -~]/,
  graph: /[!-~]/,
  cntrl: /[\x00-\x1f\x7f]/,
}

// Where a [:name:], [=c=] or [.c.] that opens at `at` ends (just past its
// closing bracket), or -1 when none opens there.
function posixEnd(text: string, at: number): number {
  const kind = text[at + 1]
  if (text[at] !== "[" || (kind !== ":" && kind !== "=" && kind !== ".")) return -1
  const end = text.indexOf(`${kind}]`, at + 2)
  return end === -1 ? -1 : end + 2
}

// In the set, out of it, or not known (null).
type Membership = boolean | null

function either(a: Membership, b: Membership): Membership {
  return a === true || b === true ? true : a === null || b === null ? null : false
}

// One member of a bracket set, starting at `k`: a character (plain, escaped
// with \\, or a one-character [=c=] or [.c.]), a [:class:], or a name fnmatch
// would reject (an unknown class, a longer collating name), which makes it
// fail the whole pattern; `end` is its last index.
type SetAtom = { kind: "char"; c: string; end: number } | { kind: "class"; test: (c: string) => Membership; end: number } | { kind: "invalid"; end: number }

function setAtom(set: string, k: number): SetAtom {
  const end = posixEnd(set, k)
  if (end !== -1) {
    const name = set.slice(k + 2, end - 2)
    if (set[k + 1] !== ":" && name.length === 1) return { kind: "char", c: name, end: end - 1 }
    const known = set[k + 1] === ":" ? own(POSIX_CLASSES, name) : undefined
    return known ? { kind: "class", test: (c) => (c.charCodeAt(0) > 0x7f ? null : known.test(c)), end: end - 1 } : { kind: "invalid", end: end - 1 }
  }
  if (set[k] === "\\" && k + 1 < set.length) return { kind: "char", c: set[k + 1] as string, end: k + 1 }
  return { kind: "char", c: set[k] as string, end: k }
}

function globClass(body: string, ignoreCase: boolean, more: boolean): { test: (c: string) => boolean; invalid: boolean } {
  const negate = body.startsWith("!") || body.startsWith("^")
  const items: [string, string][] = []
  const classes: ((c: string) => Membership)[] = []
  const set = negate ? body.slice(1) : body
  let invalid = false
  for (let k = 0; k < set.length; k++) {
    const first = setAtom(set, k)
    k = first.end
    // A range a-z, either end of which may be [.c.] or [=c=] (a-[.z.]); a
    // range with a class or an unreadable name at an end is not known.
    if (set[k + 1] === "-" && k + 2 < set.length && set[k + 2] !== "]") {
      const second = setAtom(set, k + 2)
      k = second.end
      if (first.kind === "invalid" || second.kind === "invalid") invalid = true
      else if (first.kind === "char" && second.kind === "char") items.push([first.c, second.c])
      else classes.push(() => null)
      continue
    }
    if (first.kind === "char") items.push([first.c, first.c])
    else if (first.kind === "class") classes.push(first.test)
    else invalid = true
  }
  const inSet = (c: string): Membership => {
    if (items.some(([lo, hi]) => c >= lo && c <= hi)) return true
    return classes.reduce<Membership>((found, test) => either(found, test(c)), false)
  }
  const test = (c: string) => {
    const found = ignoreCase ? either(inSet(c.toLowerCase()), inSet(c.toUpperCase())) : inSet(c)
    return found === null ? more : found !== negate
  }
  return { test, invalid }
}

function globMatcher(glob: string, ignoreCase = false, more = true): GlobMatcher {
  const fold = (c: string) => (ignoreCase ? c.toLowerCase() : c)
  const literal = (ch: string): GlobToken => {
    const folded = fold(ch)
    return { kind: "one", test: (c) => fold(c) === folded }
  }
  const tokens: GlobToken[] = []
  // A name fnmatch rejects fails the whole pattern, whatever else matches:
  // the guard then answers as `more` says for every name.
  let invalid = false
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i] as string
    if (ch === "\\" && i + 1 < glob.length) tokens.push(literal(glob[++i] as string))
    else if (ch === "*") {
      if (tokens.at(-1)?.kind !== "star") tokens.push({ kind: "star" })
    } else if (ch === "?") tokens.push({ kind: "one", test: () => true })
    else if (ch === "[") {
      // A ] first in the set (after any ! or ^), an escaped one, or one that
      // closes a [:class:] is part of the set, not its end.
      let close = i + 1
      if (glob[close] === "!" || glob[close] === "^") close++
      if (glob[close] === "]") close++
      while (close < glob.length && glob[close] !== "]") {
        const posix = posixEnd(glob, close)
        close = posix !== -1 ? posix : close + (glob[close] === "\\" ? 2 : 1)
      }
      if (close >= glob.length) close = -1
      if (close === -1) tokens.push(literal("["))
      else {
        const set = globClass(glob.slice(i + 1, close), ignoreCase, more)
        if (set.invalid) invalid = true
        tokens.push({ kind: "one", test: set.test })
        i = close
      }
    } else tokens.push(literal(ch))
  }
  return {
    test(text: string): boolean {
      if (invalid) return more
      let t = 0
      let at = 0
      let star = -1
      let starAt = 0
      while (at < text.length) {
        const token = tokens[t]
        if (token?.kind === "one" && token.test(text[at] as string)) {
          t++
          at++
        } else if (token?.kind === "star") {
          star = t++
          starAt = at
        } else if (star !== -1) {
          t = star + 1
          at = ++starAt
        } else return false
      }
      while (tokens[t]?.kind === "star") t++
      return t === tokens.length
    },
  }
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

type GrepFilter = { include: boolean; re: GlobMatcher }
type GrepArgs = { recursive: boolean; deref: boolean; filters: GrepFilter[]; excludeDirs: GlobMatcher[]; files: Word[]; refuse: string | null }

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
    if (name === "--exclude" || name === "--include") parsed.filters.push({ include: name === "--include", re: globMatcher(value.text, false, name === "--include") })
    if (name === "--exclude-dir") parsed.excludeDirs.push(globMatcher(value.text.replace(/\/+$/, ""), false, false))
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
      const value = eq === -1 ? (GREP_LONG_VALUE.has(name) ? args[++i] : undefined) : part(word, text.slice(eq + 1))
      option(name, value)
      continue
    }
    for (let j = 1; j < text.length; j++) {
      const flag = text[j] as string
      if (GREP_SHORT_VALUE.includes(flag)) {
        const rest = text.slice(j + 1)
        option(flag, rest ? part(word, rest) : args[++i])
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
// skips the links it meets, as grep does; -R follows them, stopping only
// where a folder would be its own ancestor.
function walkForSecrets(dir: string, target: string, grep: GrepArgs, home: string, vaultDirs: string[]): Walk {
  const cache = new Map<string, boolean>()
  const identity = (path: string) => {
    const info = statSync(path)
    return `${info.dev}:${info.ino}`
  }
  // A folder is skipped only when it is one of its own ancestors on the
  // path walked, so a folder reached two ways is walked both ways.
  const queue: { path: string; shown: string; depth: number; ancestors: string[] }[] = [{ path: dir, shown: target, depth: 0, ancestors: [identity(dir)] }]
  let entries = 0
  const tooMany = { refused: `\`grep -r\` over ${target} would read too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check them for key files; search a narrower folder, or leave the large ones out with --exclude-dir` }
  const tooDeep = { refused: `\`grep -r\` over ${target} goes too deep (more than ${GREP_WALK_DEPTH} folders down) for the guard to check it for key files; search a narrower folder` }
  while (queue.length) {
    const { path, shown, depth, ancestors } = queue.shift() as (typeof queue)[number]
    if (vaultFolder(path, cache)) return { found: shown }
    for (const entry of sortedEntries(path) ?? []) {
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
        const id = grep.deref ? identity(full) : ""
        if (grep.deref && ancestors.includes(id)) continue
        queue.push({ path: full, shown: label, depth: depth + 1, ancestors: grep.deref ? [...ancestors, id] : ancestors })
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

// ---- globs and braces ----------------------------------------------------

// How many words a brace may make before the guard refuses.
export const BRACE_LIMIT = 1024

function unescapePattern(pattern: string): string {
  return pattern.replace(/\\(.)/gs, "$1")
}

function hasGlob(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === "\\") i++
    else if (c === "*" || c === "?" || c === "[") return true
  }
  return false
}

// The words a brace expansion makes, in the shell's order: {a,b} and
// {1..3} or {a..c}, nested and in sequence. A numeric sequence is in the
// grammar only with plain integer ends (no leading zero, which pads every
// word) of at most BRACE_RANGE_END and a step to match; past those, or past
// BRACE_LIMIT words, the answer is a refusal.
export const BRACE_RANGE_END = 100_000
type Braces = { words: string[] } | { refuse: string }

const PLAIN_INTEGER = /^-?(0|[1-9]\d*)$/

function braceSequence(body: string): string[] | { refuse: string } | null {
  const numbers = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/.exec(body)
  if (numbers) {
    const ends = [numbers[1], numbers[2], numbers[3]].filter((n): n is string => n !== undefined)
    if (ends.some((n) => !PLAIN_INTEGER.test(n))) return { refuse: `{${body}} is a zero-padded brace sequence, which the guard does not follow` }
    const [from, to, by] = ends.map(Number) as [number, number, number | undefined]
    const step = Math.abs(by ?? 1) || 1
    if ([from, to, step].some((n) => !Number.isSafeInteger(n) || Math.abs(n) > BRACE_RANGE_END)) return { refuse: `{${body}} has ends past ${BRACE_RANGE_END}, which the guard does not follow` }
    if (Math.floor(Math.abs(to - from) / step) + 1 > BRACE_LIMIT) return { refuse: `{${body}} makes too many words (more than ${BRACE_LIMIT}) for the guard to check` }
    const words: string[] = []
    const up = from <= to
    for (let n = from, k = 0; (up ? n <= to : n >= to) && k <= BRACE_LIMIT; n += up ? step : -step, k++) words.push(String(n))
    return words
  }
  const letters = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?$/.exec(body)
  if (!letters) return null
  const [from, to] = [(letters[1] as string).charCodeAt(0), (letters[2] as string).charCodeAt(0)]
  const by = Number(letters[3] ?? 1)
  if (!PLAIN_INTEGER.test(letters[3] ?? "1") || !Number.isSafeInteger(by) || Math.abs(by) > BRACE_RANGE_END) return { refuse: `{${body}} has a step the guard does not follow` }
  const step = Math.abs(by) || 1
  const words: string[] = []
  for (let n = from; from <= to ? n <= to : n >= to; n += from <= to ? step : -step) words.push(String.fromCharCode(n))
  return words
}

function braceExpand(pattern: string, out: string[] = []): Braces {
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === "\\") {
      i++
      continue
    }
    if (c !== "{") continue
    let depth = 0
    let close = -1
    const commas: number[] = []
    for (let j = i; j < pattern.length; j++) {
      const d = pattern[j]
      if (d === "\\") j++
      else if (d === "{") depth++
      else if (d === "}" && --depth === 0) {
        close = j
        break
      } else if (d === "," && depth === 1) commas.push(j)
    }
    if (close === -1) break
    let alternatives: string[] | null = null
    if (commas.length) alternatives = [i, ...commas].map((at, k) => pattern.slice(at + 1, k < commas.length ? commas[k] : close))
    else {
      const sequence = braceSequence(pattern.slice(i + 1, close))
      if (sequence !== null && "refuse" in sequence) return sequence
      alternatives = sequence
    }
    if (alternatives === null) continue
    for (const alternative of alternatives) {
      const inner = braceExpand(pattern.slice(0, i) + alternative + pattern.slice(close + 1), out)
      if ("refuse" in inner) return inner
    }
    return { words: out }
  }
  out.push(pattern)
  return out.length > BRACE_LIMIT ? { refuse: `it makes too many words (more than ${BRACE_LIMIT}) for the guard to check` } : { words: out }
}

type Matches = { texts: string[]; unmatched: string[] } | { refused: string }

function sortedEntries(path: string): Dirent[] | null {
  try {
    return readdirSync(path, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  } catch {
    return null
  }
}

// The files a glob names from `cwd`, spelled as the shell passes them,
// within the walk's entry bound. A leading dot must be matched by a
// literal one, as in bash; . and .. are never matched.
function globMatches(pattern: string, cwd: string): string[] | null {
  const absolute = pattern.startsWith("/")
  const segments = pattern.split("/")
  let current: { fs: string; text: string }[] = [{ fs: absolute ? "/" : cwd, text: absolute ? "/" : "" }]
  let entries = 0
  const joinText = (text: string, name: string) => (text === "" ? name : text.endsWith("/") ? text + name : `${text}/${name}`)
  for (const [k, segment] of segments.entries()) {
    if (segment === "") continue
    const last = k === segments.length - 1
    if (!hasGlob(segment)) {
      const name = unescapePattern(segment)
      current = current.map((c) => ({ fs: `${c.fs}${sep}${name}`, text: joinText(c.text, name) }))
      continue
    }
    const re = globMatcher(segment)
    const dots = segment.startsWith(".") || segment.startsWith("\\.")
    const next: { fs: string; text: string }[] = []
    for (const c of current) {
      for (const entry of sortedEntries(c.fs) ?? []) {
        if (++entries > GREP_WALK_ENTRIES) return null
        if (entry.name.startsWith(".") && !dots) continue
        if (!re.test(entry.name)) continue
        const fs = `${c.fs}${sep}${entry.name}`
        if (!last && !isDir(fs)) continue
        next.push({ fs, text: joinText(c.text, entry.name) })
      }
    }
    current = next
  }
  return current.map((c) => c.text)
}

// What the shell makes of a glob or brace word from `cwd`: each match, or
// the word itself when a glob matches nothing (bash's default).
function expandWord(word: Word, cwd: string, shownAs: string): Matches {
  const tooMany = (what: string) => ({ refused: `${shownAs} ${what}; name the files directly` })
  const braces = word.brace ? braceExpand(word.pattern) : { words: [word.pattern] }
  if ("refuse" in braces) return { refused: `can't tell what this reads: ${braces.refuse}; name the files directly` }
  const words = braces.words
  const texts: string[] = []
  const unmatched: string[] = []
  for (const pattern of words) {
    if (!word.glob || !hasGlob(pattern)) {
      texts.push(unescapePattern(pattern))
      continue
    }
    const matches = globMatches(pattern, cwd)
    if (matches === null) return tooMany(`matches too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check`)
    if (!matches.length) unmatched.push(unescapePattern(pattern))
    texts.push(...(matches.length ? matches : [unescapePattern(pattern)]))
    if (texts.length > GREP_WALK_ENTRIES) return tooMany(`matches too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check`)
  }
  return { texts, unmatched }
}

// What an option word might name as a file, for programs whose options the
// guard does not list (git, curl, rsync, an editor): the word itself, as the
// shell expands it, and in each word a brace makes, the value after `=`, a
// value attached to a short option, each also without a leading @ (curl -d
// @file, a response file). A `key=value` word counts its value too (git -c
// include.path=file, curl -F name=@file). A part keeps the word's globs, so
// it is judged as the files it could match as well as its own spelling.
function fileCandidates(word: Word): Word[] {
  if (word.dynamic || word.process) return []
  const found: Word[] = [word]
  const braces = word.brace ? braceExpand(word.pattern) : { words: [word.pattern] }
  // A brace the guard will not expand is refused when the word is judged.
  if ("refuse" in braces) return found
  const seen = new Set<string>()
  for (const pattern of braces.words) {
    const parts: string[] = []
    const eq = unescapedIndex(pattern, "=")
    if (eq !== -1) parts.push(pattern.slice(eq + 1))
    if (/^-[A-Za-z]./.test(pattern) && !pattern.startsWith("--")) parts.push(pattern.slice(2))
    for (const part of [...parts]) if (part.startsWith("@")) parts.push(part.slice(1))
    if (pattern.startsWith("@")) parts.push(pattern.slice(1))
    for (const part of parts) {
      const text = unescapePattern(part)
      if (text === "" || text === "-" || seen.has(part)) continue
      seen.add(part)
      found.push({ text, dynamic: false, glob: word.glob && hasGlob(part), brace: false, pattern: part, vars: [] })
    }
  }
  return found
}

function unescapedIndex(pattern: string, char: string): number {
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === "\\") i++
    else if (c === char) return i
  }
  return -1
}

// ---- find feeding a reader --------------------------------------------------
//
// The one form the guard follows: `find [-H|-P] <start>... <tests>...
// [-print|-print0]` piped to `xargs [-0] <reader>`, or the same with
// `-exec|-execdir <reader> ... {} +|\;` as its one, last action. The tests
// are -name, -iname, -path, -ipath, -type f|d|l, -maxdepth and -mindepth,
// joined by -a. The guard walks the starts as find would, within grep's
// bounds and skipping grep's folders, and judges every entry the tests
// select as the reader would open it.

type FindTest = { kind: "name" | "path"; re: GlobMatcher } | { kind: "type"; type: "f" | "d" | "l" }
type FindAction = { kind: "print" | "print0" } | { kind: "exec" | "execdir"; words: Word[]; plus: boolean }
type FindSpec = { follow: boolean; starts: Word[]; tests: FindTest[]; maxdepth: number | null; mindepth: number; action: FindAction | null }

const FIND_ACTIONS = new Set(["-print", "-print0", "-exec", "-execdir", "-ok", "-okdir", "-delete", "-ls", "-printf", "-fprint", "-fprint0", "-fprintf", "-fls", "-prune", "-quit"])

function parseFind(args: Word[]): FindSpec | { refuse: string } {
  const spec: FindSpec = { follow: false, starts: [], tests: [], maxdepth: null, mindepth: 0, action: null }
  let i = 0
  for (; i < args.length && /^-[HLPDO]/.test((args[i] as Word).text) && !(args[i] as Word).dynamic; i++) {
    const text = (args[i] as Word).text
    if (text === "-H") spec.follow = true
    else if (text === "-P") spec.follow = false
    else if (text === "-L") return { refuse: "uses -L, which follows every link" }
    else break
  }
  for (; i < args.length; i++) {
    const word = args[i] as Word
    if (!word.dynamic && (/^[-(!,)]/.test(word.text) && word.text !== "-")) break
    if (word.dynamic || word.glob || word.brace) return { refuse: `starts from ${word.dynamic ? "a folder" : word.text} only the shell knows` }
    spec.starts.push(word)
  }
  if (!spec.starts.length) spec.starts.push(literal("."))
  for (; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (word.dynamic) return { refuse: "has a word in its expression only the shell knows" }
    if (spec.action) return { refuse: FIND_ACTIONS.has(text) ? `has more than one action (${text})` : `has ${text} after its action` }
    if (text === "-a" || text === "-and") continue
    if (["-name", "-iname", "-path", "-ipath"].includes(text)) {
      const value = args[++i]
      if (value === undefined || value.dynamic) return { refuse: `has a ${text} pattern only the shell knows` }
      if (value.glob || value.brace) return { refuse: `has a ${text} pattern the shell expands first; quote it` }
      if (/\[[^\]]*\[[:=.]/.test(value.text)) return { refuse: `uses a POSIX character class in ${text}, which the guard does not follow` }
      spec.tests.push({ kind: text.endsWith("name") ? "name" : "path", re: globMatcher(value.text, text.startsWith("-i")) })
      continue
    }
    if ((text === "-type" || text === "-maxdepth" || text === "-mindepth") && (args[i + 1] === undefined || args[i + 1]?.dynamic || args[i + 1]?.glob || args[i + 1]?.brace)) return { refuse: `has a ${text} value only the shell knows` }
    if (text === "-type") {
      const value = args[++i]?.text
      if (value !== "f" && value !== "d" && value !== "l") return { refuse: `uses -type ${value ?? ""}, which the guard does not follow` }
      spec.tests.push({ kind: "type", type: value })
      continue
    }
    if (text === "-maxdepth" || text === "-mindepth") {
      const value = args[++i]?.text ?? ""
      if (!/^\d+$/.test(value)) return { refuse: `has ${text} ${value}, which is not a number` }
      if (text === "-maxdepth") spec.maxdepth = Number(value)
      else spec.mindepth = Number(value)
      continue
    }
    if (text === "-print" || text === "-print0") {
      spec.action = { kind: text === "-print" ? "print" : "print0" }
      continue
    }
    if (text === "-exec" || text === "-execdir") {
      const block: Word[] = []
      let plus = false
      for (i++; i < args.length; i++) {
        const part = args[i] as Word
        if (!part.dynamic && part.text === ";") break
        if (!part.dynamic && part.text === "+" && block.at(-1)?.text === "{}") {
          plus = true
          break
        }
        block.push(part)
      }
      if (i >= args.length) return { refuse: `has a ${text} with no ; or + to end it` }
      spec.action = { kind: text === "-exec" ? "exec" : "execdir", words: block, plus }
      continue
    }
    if (text === "-ok" || text === "-okdir") return { refuse: `uses ${text}, which asks before each file` }
    return { refuse: `uses ${text}, which the guard does not follow` }
  }
  return spec
}

// One entry find selects: as it prints it, the folder find ran from, and
// the real folder that holds it (where -execdir runs).
type Selected = { printed: string; cwd: string; dir: string; name: string }

type FileKind = "f" | "d" | "l" | "other"

function kindOf(info: { isSymbolicLink(): boolean; isDirectory(): boolean; isFile(): boolean }): FileKind {
  return info.isSymbolicLink() ? "l" : info.isDirectory() ? "d" : info.isFile() ? "f" : "other"
}

function statKind(path: string, follow: boolean): FileKind | null {
  try {
    return kindOf(follow ? statSync(path) : lstatSync(path))
  } catch {
    return null
  }
}

// The entries a find selects, from every folder the line might be in,
// within the walk's bounds.
function selectFind(spec: FindSpec, cwds: Cwds, ctx: Context): { entries: Selected[] } | { refuse: string } {
  const entries: Selected[] = []
  let seen = 0
  const limit = spec.maxdepth ?? Number.POSITIVE_INFINITY
  for (const start of spec.starts) {
    if (!isAbsolute(start.text) && cwds === null) return { refuse: "starts from a folder the guard cannot follow after an earlier folder change" }
    for (const cwd of isAbsolute(start.text) ? ["/"] : (cwds as string[])) {
      const root = isAbsolute(start.text) ? start.text : `${cwd}${sep}${start.text}`
      const rootKind = statKind(root, spec.follow)
      if (rootKind === null) continue
      const rootName = start.text.replace(/\/+$/, "").split("/").at(-1) || start.text
      const queue: { fs: string; printed: string; name: string; kind: FileKind; depth: number; parent: string }[] = [{ fs: rootKind === "d" ? (realOrNull(root) ?? root) : root, printed: start.text, name: rootName, kind: rootKind, depth: 0, parent: realOrNull(dirname(root)) ?? normalize(dirname(root)) }]
      while (queue.length) {
        const node = queue.shift() as (typeof queue)[number]
        const selected = node.depth >= spec.mindepth && spec.tests.every((test) => (test.kind === "type" ? test.type === node.kind : test.re.test(test.kind === "name" ? node.name : node.printed)))
        if (selected) entries.push({ printed: node.printed, cwd, dir: node.parent, name: node.name })
        if (node.kind !== "d" || node.depth >= limit || (node.depth > 0 && GREP_WALK_SKIPS.has(node.name))) continue
        if (node.depth + 1 > GREP_WALK_DEPTH) return { refuse: `goes too deep (more than ${GREP_WALK_DEPTH} folders down) for the guard to check what it selects; add -maxdepth or start lower` }
        for (const entry of sortedEntries(node.fs) ?? []) {
          if (++seen > GREP_WALK_ENTRIES) return { refuse: `walks too many files (more than ${GREP_WALK_ENTRIES}) for the guard to check what it selects; start from a narrower folder` }
          const printed = node.printed.endsWith("/") ? node.printed + entry.name : `${node.printed}/${entry.name}`
          queue.push({ fs: `${node.fs}${sep}${entry.name}`, printed, name: entry.name, kind: kindOf(entry), depth: node.depth + 1, parent: node.fs })
        }
      }
    }
  }
  return { entries }
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"])

// Whether a program may read the files it is handed.
function readsFiles(head: Word | undefined): boolean {
  if (head === undefined) return false
  if (head.dynamic) return true
  const program = basename(head.text)
  return READERS.has(program) || Object.hasOwn(FILE_READERS, program) || SHELLS.has(program) || program === "eval"
}

const FED_HINT = "name the files directly, or feed it from a find of -name, -path and -type tests"

type XargsInfo = { null: boolean; bad: string | null }

// The names `xargs` hands its program, from the find piped into it, or why
// the guard cannot tell them. `split` names one plain xargs would split.
function xargsNames(ctx: Context, state: State, node: CommandNode, producer: CommandNode | null, xargs: XargsInfo): { names: string[]; split: string | null } | { refuse: string } {
  if (xargs.bad) return { refuse: `xargs ${xargs.bad} is not followed by the guard` }
  if (node.op !== "|" || producer === null || producer.next !== "|") return { refuse: "its input is not a find" }
  const produced = unwrap(producer.words, state.cwds, ctx)
  const head = produced.words[0]
  if (produced.refuse || head === undefined || head.dynamic || basename(head.text) !== "find") return { refuse: "its input is not a find" }
  const spec = parseFind(produced.words.slice(1))
  if ("refuse" in spec) return { refuse: `its find ${spec.refuse}` }
  if (spec.action && spec.action.kind !== "print" && spec.action.kind !== "print0") return { refuse: "its find runs -exec" }
  const print0 = spec.action?.kind === "print0"
  if (print0 && !xargs.null) return { refuse: "its find prints with -print0 but xargs has no -0" }
  if (!print0 && xargs.null) return { refuse: "xargs -0 expects names ended by NUL, and its find has no -print0" }
  const selected = selectFind(spec, produced.cwds, ctx)
  if ("refuse" in selected) return { refuse: `its find ${selected.refuse}` }
  const names = [...new Set(selected.entries.map((e) => e.printed))]
  return { names, split: print0 ? null : (names.find((n) => /[\s'"\\]/.test(n)) ?? null) }
}

// ---- reading the line ------------------------------------------------------

// `outside` lists the constructs on the line outside the grammar the guard
// reads; `reads` says whether anything on it reads a file or prints the
// environment; `nested` counts the subshells and substitutions around the
// command being read.
// `words` holds every command's words, for the check on a line outside
// the grammar.
// `arithmetic`: the line has let or an integer variable (declare -i), so a
// key variable named bare in any word may be read.
type Context = { home: string; vaultDirs: string[]; command: string; findings: Finding[]; outside: string[]; reads: boolean; nested: number; words: Word[][]; arithmetic: boolean }

function outside(ctx: Context, why: string, runs = false): void {
  if (!ctx.outside.includes(why)) ctx.outside.push(why)
  if (runs) ctx.reads = true
}

// Assignments that change how the shell finds files, expands words or
// starts: outside the grammar.
const SPECIAL_VARIABLES = new Set(["HOME", "IFS", "GLOBIGNORE", "PATH", "CDPATH", "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS"])
const ASSIGNED = /^([A-Za-z_][A-Za-z0-9_]*)\+?=/

function specialAssignment(words: Word[]): string | null {
  for (const word of words) {
    const name = ASSIGNED.exec(word.text)?.[1]
    if (name === undefined) return null
    if (SPECIAL_VARIABLES.has(name)) return name
  }
  return null
}

// The programs a line is said to read with: they read the files they are
// given, or run a file they are given. env and export count only when
// they print the environment.
function isReader(program: string): boolean {
  return (READERS.has(program) && program !== "env" && program !== "export") || Object.hasOwn(FILE_READERS, program) || SHELLS.has(program)
}

function refuse(ctx: Context, reason: string): void {
  if (!ctx.findings.some((f) => f.reason === reason)) ctx.findings.push({ rule: "secret-file", reason })
}

// Whether `program` reading `word` would read a key file, from every folder
// the line might be in; a finding is added for the first.
// `program` is how the reason names the reader, `cat` in backticks.
function judgeRead(ctx: Context, state: State, cwds: Cwds, program: string, word: Word, strict: boolean): boolean {
  // A process substitution's commands are read on their own.
  if (word.process) return false
  if (word.dynamic) {
    if (!strict) return false
    refuse(ctx, CANT_FILES(program, shownWord(word)))
    return true
  }
  if (word.glob || word.brace) {
    // A glob or brace: expanded against each folder as the shell would,
    // and each word it makes judged. One that matches nothing reaches the
    // program as it is, and is still refused when its pattern could be a
    // key file's name.
    const written = shown(word.text, ctx.home)
    const absolute = word.pattern.startsWith("/")
    if (!absolute && cwds === null) {
      const text = word.pattern.replace(/\\(.)/gs, "$1")
      if (!globMatchesSecret(text) && !couldNameSecret(text, ctx.home, ctx.vaultDirs)) return false
      refuse(ctx, CANT_FOLDER(program, written))
      return true
    }
    for (const cwd of absolute ? ["/"] : (cwds as string[])) {
      const expanded = expandWord(word, cwd, written)
      if ("refused" in expanded) {
        refuse(ctx, `can't tell which files ${program} reads: ${expanded.refused}`)
        return true
      }
      for (const text of expanded.texts) if (judgeRead(ctx, state, [cwd], program, literal(text), strict)) return true
      const unmatched = expanded.unmatched.find((text) => globMatchesSecret(text))
      if (unmatched !== undefined) {
        ctx.findings.push({ rule: "secret-file", reason: `${program} would read ${shown(unmatched, ctx.home)}: the pattern matches environment or key files`, path: shown(unmatched, ctx.home) })
        return true
      }
    }
    return false
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


// `child` says the program runs in a process of its own (under env, sudo,
// nohup, xargs or a time binary), so a cd there does not move this shell.
type Unwrapped = { words: Word[]; cwds: Cwds; reads: Word[]; xargs: XargsInfo | null; refuse: string | null; child: boolean }

export const MAX_WRAPPERS = 8
const WRAPPERS = new Set(["command", "builtin", "nohup", "exec", "time", "env", "sudo", "xargs"])
// Builtins that change this shell's folder or state.
const STATE_BUILTINS = new Set(["cd", "pushd", "popd", "source", ".", "exec", "eval", "export", "set", "shopt", "alias", "unset"])

function takeValue(args: Word[], i: number, word: Word, attached: string): [Word | undefined, number] {
  return attached ? [part(word, attached), i] : [args[i + 1], i + 1]
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
      ;[value, i] = eq === -1 ? [rest[i + 1], i + 1] : [part(word, text.slice(eq + 1)), i]
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
    if (name === "--chdir") out.cwds = value.dynamic ? null : out.cwds === null ? (isAbsolute(value.text) ? [physicalDir("/", value.text)] : null) : out.cwds.map((cwd) => physicalDir(cwd, value.text))
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

// The program a command line really runs, past variable assignments and the
// wrappers that run their arguments as a command: command, builtin, env,
// exec, nohup, time, sudo and xargs. A wrapper that would run nothing (env
// alone prints the environment, command -v only looks a name up) is kept.
function unwrap(words: Word[], cwds: Cwds, ctx: Context): Unwrapped {
  const out: Unwrapped = { words, cwds, reads: [], xargs: null, refuse: null, child: false }
  let current = words
  for (let depth = 0; depth < MAX_WRAPPERS; depth++) {
    const special = specialAssignment(current)
    if (special) outside(ctx, `an assignment to ${special}`)
    let i = 0
    // NAME=value, its value possibly only known when the shell runs it.
    while (i < current.length - 1 && ASSIGNMENT.test((current[i] as Word).text)) i++
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
          const text = (rest[j] as Word).text
          if (text === "--") {
            j++
            break
          }
          // command takes only -p, -v and -V; with any other option it runs
          // nothing, so what follows is not run as a command.
          if (!/^-[pvV]+$/.test(text)) {
            outside(ctx, `command ${text}`)
            return out
          }
          if (/[vV]/.test(text)) lookup = true
          j++
        }
        if (lookup) return out
        rest = rest.slice(j)
        break
      }
      case "builtin":
        break
      case "nohup":
        out.child = true
        if (rest[0] && !rest[0].dynamic && rest[0].text.startsWith("-") && rest[0].text !== "--") {
          out.refuse = `can't tell what \`nohup\` runs with ${rest[0].text}; run the command without it`
          return out
        }
        if (rest[0]?.text === "--") rest = rest.slice(1)
        break
      case "exec": {
        outside(ctx, "exec")
        let j = 0
        while (j < rest.length && /^-[cla]+$/.test((rest[j] as Word).text)) j += (rest[j] as Word).text.endsWith("a") ? 2 : 1
        rest = rest.slice(j)
        break
      }
      case "time": {
        // Bare `time` is the shell's keyword, which runs builtins such as
        // cd in this shell; a path names a time program, a child process.
        // Before a builtin that changes this shell's folder or state it is
        // outside the grammar; before any other command it only times it.
        if (head.text === "time" && depth === 0 && i === 0) {
          const timed = rest.find((w) => w.dynamic || !w.text.startsWith("-"))
          if (timed === undefined || (!timed.dynamic && STATE_BUILTINS.has(timed.text))) outside(ctx, "the time keyword before a shell builtin")
        } else out.child = true
        let j = 0
        while (j < rest.length && (rest[j] as Word).text.startsWith("-") && !(rest[j] as Word).dynamic) {
          const text = (rest[j] as Word).text
          if (text === "--") {
            j++
            break
          }
          if (!/^-[apvq]+$|^-[fo]$|^--(format|output)(=.*)?$|^--(append|portability|verbose|quiet)$/.test(text)) {
            out.refuse = `can't tell what \`time\` runs with ${text}; run the command without it`
            return out
          }
          j += /^-[fo]$|^--(format|output)$/.test(text) ? 2 : 1
        }
        rest = rest.slice(j)
        break
      }
      case "env": {
        out.child = true
        const next = unwrapEnv(rest, out, ctx)
        if (next === null) return out
        const special = specialAssignment(next)
        if (special) outside(ctx, `an assignment to ${special}`)
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
        out.child = true
        let j = 0
        while (j < rest.length && (rest[j] as Word).text.startsWith("-") && !(rest[j] as Word).dynamic) {
          const text = (rest[j] as Word).text
          if (text === "--") {
            j++
            break
          }
          const chdir = /^(?:-D|--chdir)(?:=(.*))?$/.exec(text)
          if (chdir) {
            const dir = chdir[1] !== undefined ? part((rest[j] as Word), chdir[1]) : rest[++j]
            if (dir) out.cwds = dir.dynamic ? null : out.cwds === null ? (isAbsolute(dir.text) ? [physicalDir("/", dir.text)] : null) : out.cwds.map((cwd) => physicalDir(cwd, dir.text))
          } else if (SUDO_VALUE.has(text)) j++
          else if (!/^-[AbEeHiKklnPSsVv]+$|^--(preserve-env(=.*)?|login|shell|stdin|non-interactive|askpass|background|set-home|reset-timestamp|remove-timestamp|validate)$|^--(user|group|host|prompt|close-from|role|type|other-user|command-timeout)=.*$/.test(text)) {
            out.refuse = `can't tell what \`sudo\` runs with ${text}; run the command without it`
            return out
          }
          j++
        }
        rest = rest.slice(j)
        break
      }
      case "xargs": {
        // The options whose effect on the names is known: -0, -n, -L, -P,
        // -s, -r, -t and -x. Any other is noted, and refused when xargs
        // feeds a reader; -a still has its file judged.
        const info: XargsInfo = { null: false, bad: null }
        const bad = (option: string) => {
          info.bad ??= option
        }
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
            if (name === "--null") info.null = true
            else if (["--max-args", "--max-lines", "--max-procs", "--max-chars"].includes(name)) {
              if (eq === -1) j++
            } else if (!["--no-run-if-empty", "--verbose", "--exit"].includes(name)) {
              bad(name)
              if (["--arg-file", "--delimiter", "--process-slot-var"].includes(name)) {
                const value = eq !== -1 ? part(word, text.slice(eq + 1)) : rest[++j]
                if (name === "--arg-file" && value) out.reads.push(value)
              }
            }
            j++
            continue
          }
          for (let k = 1; k < text.length; k++) {
            const flag = text[k] as string
            if (flag === "0") info.null = true
            else if ("rtx".includes(flag)) continue
            else if ("nLPs".includes(flag)) {
              if (k === text.length - 1) j++
              break
            } else {
              bad(`-${flag}`)
              if ("aIJdE".includes(flag)) {
                const value = k < text.length - 1 ? part(word, text.slice(k + 1)) : rest[++j]
                if (flag === "a" && value) out.reads.push(value)
              }
              break
            }
          }
          j++
        }
        rest = rest.slice(j)
        out.xargs = info
        out.child = true
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
  const last = current[0]
  if (last && !last.dynamic && WRAPPERS.has(basename(last.text))) out.refuse = `can't tell what this runs: more than ${MAX_WRAPPERS} wrappers in a row; run the command directly`
  return out
}

type CommandNode = Extract<ShellNode, { kind: "command" }>

const SHELL_VALUE_OPTIONS = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"])
const SHELL_LONG = new Set(["--login", "--noprofile", "--norc", "--posix", "--verbose", "--restricted", "--debugger", "--dump-strings", "--dump-po-strings", "--noediting", "--pretty-print", "--help", "--version"])

// A shell run as a command: with -c, the commands in its string are read
// as a line of their own; otherwise the file it is given is a read, its
// contents not inspected; with none, -s or -, it runs what its input
// holds, which is refused when that input is a pipe or a here-document.
// -o, +o, -O and +O set options the guard does not model.
function shellRun(ctx: Context, state: State, node: CommandNode, program: string, args: Word[], cwds: Cwds): void {
  let command = false
  let stdin = false
  let operand: Word | undefined
  let i = 0
  for (; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (word.dynamic || text === "-" || !/^[-+]/.test(text)) break
    if (text === "--") {
      i++
      break
    }
    if (SHELL_VALUE_OPTIONS.has(text)) {
      if (/^[-+][oO]$/.test(text)) outside(ctx, `${program} ${text}`)
      // --rcfile and --init-file name a file the shell reads first.
      else if (args[i + 1]) judgeRead(ctx, state, cwds, `\`${program} ${text}\``, args[i + 1] as Word, true)
      i++
      continue
    }
    if (text.startsWith("--")) {
      if (!SHELL_LONG.has(text)) outside(ctx, `${program} ${text}`)
      continue
    }
    if (!/^[-+][abefhkmnptuvxBCEHPTilrsDc]+$/.test(text) && !/[oO]/.test(text)) outside(ctx, `${program} ${text}`)
    if (/[oO]/.test(text)) {
      outside(ctx, `${program} ${text}`)
      i++
      continue
    }
    if (text.startsWith("-") && text.includes("c")) command = true
    if (text.startsWith("-") && text.includes("s")) stdin = true
  }
  operand = args[i]
  if (command) {
    if (!operand || operand.dynamic) return outside(ctx, `\`${program} -c\` with commands only the shell knows`, true)
    return lines(ctx, { ...state, cwds, stack: [...state.stack] }, parseShell(operand.text, ctx.home))
  }
  if (stdin || operand === undefined || operand.text === "-") {
    if (node.op === "|" || node.heredoc) refuse(ctx, `can't tell what \`${program}\` runs: it reads its commands from its input; run them directly`)
    return
  }
  judgeRead(ctx, state, cwds, `\`${program}\``, operand, true)
}

// One simple command: its folder changes, links, environment dumps, grep
// -r walks and the files it reads. `producer` is the command piped into it
// at this level; `conditional` says it may not run (inside if, while,
// until, for or case).
// The words a command's words make once the shell has expanded their
// braces, which it does before anything else: `grep -f.{e..e}nv` is
// `grep -f.env`, and `{-f,-x}.env` is two options. A brace the guard will
// not expand is kept as written, and refused where it is judged; past
// GREP_WALK_ENTRIES words in all, the command is refused.
function expandBraces(ctx: Context, words: Word[]): Word[] | null {
  const out: Word[] = []
  for (const word of words) {
    if (!word.brace || word.dynamic || word.process) {
      out.push(word)
      continue
    }
    const braces = braceExpand(word.pattern)
    if ("refuse" in braces) {
      out.push(word)
      continue
    }
    for (const pattern of braces.words) out.push({ text: unescapePattern(pattern), dynamic: false, glob: word.glob && hasGlob(pattern), brace: false, pattern, vars: word.vars })
    if (out.length > GREP_WALK_ENTRIES) {
      refuse(ctx, `can't tell what this runs: its braces make more than ${GREP_WALK_ENTRIES} words; name the files directly`)
      return null
    }
  }
  return out
}

function command(ctx: Context, state: State, node: CommandNode, producer: CommandNode | null = null, conditional = false): void {
  const expanded = expandBraces(ctx, node.words)
  if (expanded === null) return
  let words = expanded
  while (words.length && !(words[0] as Word).dynamic && RESERVED.has((words[0] as Word).text)) words = words.slice(1)
  const apart = node.op === "|" || node.next === "|" || conditional
  const unwrapped = unwrap(words, state.cwds, ctx)
  const first = unwrapped.words[0]
  const name = first === undefined ? "the redirect" : first.dynamic ? "the command" : `\`${basename(first.text)}\``
  if (node.inputs.length || unwrapped.reads.length) ctx.reads = true
  // A line of only NAME=value assignments runs no program, whatever the value.
  const assignsOnly = unwrapped.words.length === 1 && first !== undefined && ASSIGNMENT.test(first.text)
  if (first && !assignsOnly && (first.dynamic || isReader(basename(first.text)))) ctx.reads = true
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

  // What xargs hands a reader comes from the find piped into it: the
  // reader is judged with those names, from its own folder.
  if (unwrapped.xargs && readsFiles(head)) {
    const fed = xargsNames(ctx, state, node, producer, unwrapped.xargs)
    if ("refuse" in fed) return refuse(ctx, `can't tell which files \`xargs ${program || "the command"}\` reads: ${fed.refuse}; ${FED_HINT}`)
    const before = ctx.findings.length
    command(ctx, { ...state, cwds, stack: [...state.stack] }, { kind: "command", words: [...words, ...fed.names.map((n) => literal(n))], inputs: [], op: "start", next: null, heredoc: false })
    if (ctx.findings.length === before && fed.split) refuse(ctx, `can't tell which files \`xargs ${program}\` reads: xargs would split ${fed.split} at its blanks or quotes; use find -print0 with xargs -0`)
    return
  }
  if (program === "cd" || program === "pushd" || program === "popd") {
    // A cd in a process of its own does not move this shell. One inside a
    // subshell, a substitution or a pipeline is outside the grammar.
    if (unwrapped.child) return
    if (ctx.nested > 0) return outside(ctx, "a folder change inside a subshell or a substitution")
    if (node.op === "|" || node.next === "|") return outside(ctx, "a folder change in a pipeline")
    // A command run in the background with & runs in a subshell.
    if (node.next === "&") return
    folderChange(program, args, state, ctx.home, apart)
    return
  }
  if (program === "function") return outside(ctx, "a function definition")
  if (program === "shopt") return outside(ctx, "shopt")
  if (program === "alias" || program === "unalias") return outside(ctx, "an alias", true)
  if (program === "coproc") return outside(ctx, "a coprocess", true)
  if (program === "source" || program === ".") outside(ctx, `\`${program}\``)
  if (program === "set" && args.some((a) => !a.dynamic && /^[-+][A-Za-z]*[of]/.test(a.text))) outside(ctx, "set -o or set -f")
  // let evaluates arithmetic, which reads variables by bare name; a name
  // reference (declare -n) makes one variable another under a new name.
  if (program === "let") {
    outside(ctx, "let")
    ctx.arithmetic = true
  }
  if (["declare", "typeset", "local"].includes(program)) {
    const flags = args.filter((a) => !a.dynamic && /^[-+][A-Za-z]+$/.test(a.text)).map((a) => a.text.slice(1)).join("")
    // A name reference reads whatever variable its value names, which the
    // guard cannot know, so it is stopped.
    if (flags.includes("n")) outside(ctx, `${program} -n, which reads a variable it cannot name`, true)
    // An integer variable evaluates what is assigned to it as arithmetic.
    if (flags.includes("i")) {
      outside(ctx, `${program} -i`)
      ctx.arithmetic = true
    }
  }
  if (["export", "declare", "typeset", "readonly", "local", "unset"].includes(program)) {
    const special = args.map((a) => ASSIGNED.exec(a.text)?.[1] ?? a.text).find((n) => SPECIAL_VARIABLES.has(n))
    if (special) outside(ctx, `an assignment to ${special}`)
  }
  if (SHELLS.has(program)) return shellRun(ctx, state, node, program, args, cwds)
  if (program === "eval") {
    outside(ctx, "eval")
    if (args.some((a) => a.dynamic)) return outside(ctx, "eval of a word only the shell knows", true)
    return lines(ctx, state, parseShell(args.map((a) => a.text).join(" "), ctx.home))
  }
  const dump = environmentRead(words, ctx.command)
  if (dump) {
    ctx.reads = true
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
    const parsed = parseOptions(own(OPTION_SPECS, program) as NonNullable<(typeof OPTION_SPECS)[string]>, args)
    if (parsed.unknown) outside(ctx, `\`${program} ${parsed.unknown}\``)
    for (const file of parsed.files) if (judgeRead(ctx, state, cwds, `\`${program}\``, file, true)) return
    const grep = grepArgs(args)
    if (grep.recursive) {
      for (const target of grep.files.length ? grep.files : [literal(".")]) {
        if (target.dynamic) return refuse(ctx, CANT_FILES("`grep -r`", shownWord(target)))
        if (!isAbsolute(target.text) && cwds === null) return refuse(ctx, CANT_FOLDER("`grep -r`", shown(target.text, ctx.home)))
        for (const cwd of isAbsolute(target.text) ? ["/"] : (cwds as string[])) {
          const expanded = target.glob || target.brace ? expandWord(target, cwd, shown(target.text, ctx.home)) : { texts: [target.text], unmatched: [] }
          if ("refused" in expanded) return refuse(ctx, `can't tell which files \`grep -r\` reads: ${expanded.refused}`)
          for (const text of expanded.texts) {
            const real = realOrNull(isAbsolute(text) ? text : `${cwd}${sep}${text}`)
            if (real === null || !isDir(real)) continue
            const walk = walkForSecrets(real, shown(text, ctx.home), grep, ctx.home, ctx.vaultDirs)
            if (walk && "found" in walk) {
              ctx.findings.push({ rule: "secret-file", reason: `\`grep -r\` would read ${walk.found}` })
              return
            }
            if (walk) return refuse(ctx, walk.refused)
          }
        }
      }
    }
    for (const file of grep.files) if (judgeRead(ctx, state, cwds, `\`${program}\``, file, true)) return
    return
  }
  if (program === "find") return findExec(ctx, state, args, cwds)
  readers(ctx, state, cwds, name, program, head, args)
}

// Programs given a file to run: the first operand after their options is
// the script, judged as a read, and one only the shell knows is refused.
// A programme string (-c, -e) is not a file and is not inspected.
const INTERPRETERS: Record<string, { program: string; value: string }> = {
  python: { program: "c", value: "WXm" },
  python3: { program: "c", value: "WXm" },
  node: { program: "ep", value: "rC" },
  bun: { program: "e", value: "r" },
  deno: { program: "", value: "" },
  ruby: { program: "e", value: "rICEF" },
  perl: { program: "eE", value: "" },
  php: { program: "r", value: "dcz" },
}
const INTERPRETER_LONG_PROGRAM = new Set(["--eval", "--print", "--command"])
const INTERPRETER_LONG_VALUE = new Set(["--require", "--import", "--loader", "--experimental-loader", "--input-type", "--conditions", "--title", "--env-file", "--check-hash-based-pycs"])
// Readers whose operands are all files, but whose options are too many to
// list: an operand only the shell knows is refused, and every option word
// is judged as a possible file.
const OPEN_FILE_READERS = new Set(["bat", "less", "more", "xxd", "source", "."])

function readers(ctx: Context, state: State, cwds: Cwds, name: string, program: string, head: Word, args: Word[]): void {
  const spec = own(OPTION_SPECS, program)
  if (spec) {
    const parsed = parseOptions(spec, args)
    if (parsed.unknown) outside(ctx, `\`${program} ${parsed.unknown}\``)
    for (const file of parsed.files) if (judgeRead(ctx, state, cwds, name, file, true)) return
    let operands = spec.operands === "none" ? [] : parsed.operands
    if (spec.operands === "program-then-files" && !parsed.programGiven) operands = operands.slice(1)
    if (spec.operands === "sources" && !parsed.target) operands = operands.slice(0, -1)
    for (const word of operands) {
      if (judgeRead(ctx, state, cwds, name, word, true)) return
      if (program === "strings" && !word.dynamic && word.text.startsWith("@") && judgeRead(ctx, state, cwds, name, literal(word.text.slice(1)), false)) return
    }
    return
  }
  const interpreter = own(INTERPRETERS, program)
  if (interpreter) {
    let i = 0
    let script = true
    for (; i < args.length; i++) {
      const word = args[i] as Word
      const text = word.text
      if (word.dynamic || word.process || text === "-" || !text.startsWith("-")) break
      if (text === "--") {
        i++
        break
      }
      if (text.startsWith("--")) {
        const option = text.split("=")[0] as string
        if (INTERPRETER_LONG_PROGRAM.has(option)) script = false
        if (!text.includes("=") && (INTERPRETER_LONG_PROGRAM.has(option) || INTERPRETER_LONG_VALUE.has(option))) i++
        continue
      }
      const at = [...text.slice(1)].findIndex((c) => interpreter.program.includes(c) || interpreter.value.includes(c))
      if (at === -1) continue
      const flag = text[at + 1] as string
      if (interpreter.program.includes(flag) || (program.startsWith("python") && flag === "m")) script = false
      if (at + 2 === text.length) i++
    }
    if (script && args[i] && judgeRead(ctx, state, cwds, name, args[i] as Word, true)) return
    for (const word of args) for (const candidate of fileCandidates(word)) if (judgeRead(ctx, state, cwds, name, candidate, false)) return
    return
  }
  if (OPEN_FILE_READERS.has(program)) {
    for (const word of args) {
      if (!word.dynamic && word.text.startsWith("-")) {
        for (const candidate of fileCandidates(word)) if (judgeRead(ctx, state, cwds, name, candidate, false)) return
      } else if (judgeRead(ctx, state, cwds, name, word, true)) return
    }
    return
  }
  if (!(READERS.has(program) || head.dynamic)) return
  for (const word of args) for (const candidate of fileCandidates(word)) if (judgeRead(ctx, state, cwds, name, candidate, false)) return
}

// The commands a find runs with -exec or -execdir. A reader among them is
// judged with every entry the find selects, `{}` replaced as find replaces
// it, from find's folder or, for -execdir, the entry's; anything else is
// judged as any command would be.
function findExec(ctx: Context, state: State, args: Word[], cwds: Cwds): void {
  const blocks: Word[][] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i]?.dynamic || !["-exec", "-execdir", "-ok", "-okdir"].includes(args[i]?.text ?? "")) continue
    const block: Word[] = []
    for (i++; i < args.length && !(args[i]?.text === ";" || (args[i]?.text === "+" && block.at(-1)?.text === "{}")); i++) block.push(args[i] as Word)
    blocks.push(block)
  }
  const plain = (block: Word[]) => command(ctx, { ...state, cwds, stack: [...state.stack] }, { kind: "command", words: block.filter((w) => w.text !== "{}"), inputs: [], op: "start", next: null, heredoc: false })
  const reading = blocks.filter((block) => readsFiles(unwrap(block.filter((w) => w.text !== "{}"), cwds, ctx).words[0]))
  if (!reading.length) return blocks.forEach(plain)
  const runner = unwrap(reading[0] as Word[], cwds, ctx).words[0]
  const label = `\`find -exec ${runner && !runner.dynamic ? basename(runner.text) : "the command"}\``
  const spec = parseFind(args)
  if ("refuse" in spec) return refuse(ctx, `can't tell which files ${label} reads: its find ${spec.refuse}; ${FED_HINT}`)
  const action = spec.action
  if (action === null || (action.kind !== "exec" && action.kind !== "execdir")) return
  plain(action.words)
  const selected = selectFind(spec, cwds, ctx)
  if ("refuse" in selected) return refuse(ctx, `can't tell which files ${label} reads: its find ${selected.refuse}; ${FED_HINT}`)
  const before = ctx.findings.length
  const run = (cwd: string, names: string[]) => {
    const words = action.plus ? action.words.flatMap((w) => (w.text === "{}" ? names.map((n) => literal(n)) : [w])) : action.words.map((w) => (w.text.includes("{}") ? literal(w.text.replaceAll("{}", names[0] as string), w.dynamic) : w))
    command(ctx, { ...state, cwds: [cwd], stack: [...state.stack] }, { kind: "command", words, inputs: [], op: "start", next: null, heredoc: false })
  }
  if (action.kind === "exec" && action.plus) {
    const byCwd = new Map<string, string[]>()
    for (const entry of selected.entries) byCwd.set(entry.cwd, [...(byCwd.get(entry.cwd) ?? []), entry.printed])
    for (const [cwd, names] of byCwd) if (ctx.findings.length === before) run(cwd, names)
    return
  }
  for (const entry of selected.entries) {
    if (ctx.findings.length !== before) return
    if (action.kind === "execdir") run(entry.dir, [`./${entry.name}`])
    else run(entry.cwd, [entry.printed])
  }
}

// A list's elements, joined by && and ||: `states` is the folder after
// each, `pureAnd` whether only && has joined them so far.
// `start` and `startStack` are where the list began: a list run in the
// background with & leaves this shell there.
type AndOr = { states: Cwds[]; pureAnd: boolean; start: Cwds; startStack: Cwds[] }

const COMPOUND_OPEN = new Set(["if", "while", "until", "for", "case", "select"])
// Words that start a construct outside the grammar when they start a
// command: loops, conditionals, groups, tests, negation, coprocesses.
const OUTSIDE_KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "select", "function", "{", "}", "[[", "]]", "!", "coproc"])
const COMPOUND_CLOSE = new Set(["fi", "done", "esac"])

function unionAll(states: Cwds[]): Cwds {
  return states.reduce<Cwds>((all, s) => union(all, s), [])
}

// The folder a list element starts in. After ;, & or the start, a new
// and-or list begins, from any folder the last one could have ended in.
// After &&, from the folder the element before left, when only && came
// before it; otherwise, from any folder seen in the list so far.
function enter(state: State, list: AndOr | null, op: Op): AndOr | null {
  if (op === "|") return list
  if ((op === "&&" || op === "||") && list) {
    if (op === "||") list.pureAnd = false
    state.cwds = list.pureAnd ? (list.states.at(-1) as Cwds) : unionAll(list.states)
    return list
  }
  if (list && list.states.length > 1) state.cwds = unionAll(list.states.slice(1))
  return { states: [state.cwds], pureAnd: true, start: state.cwds, startStack: [...state.stack] }
}

function lines(ctx: Context, state: State, nodes: ShellNode[]): void {
  type Saved = { cwds: Cwds; stack: Cwds[]; previous: CommandNode | null; list: AndOr | null; compound: number; sub: boolean; process: boolean }
  const saved: Saved[] = []
  // The command before, at this level: what a pipe feeds the next one.
  let previous: CommandNode | null = null
  let list: AndOr | null = null
  let compound = 0
  for (const node of nodes) {
    if (node.kind === "open") {
      // A process substitution runs in a process of its own: what it does
      // to its folder ends with it, as the restore below models.
      if (!node.process) ctx.nested++
      if (!node.sub) list = enter(state, list, node.op)
      saved.push({ cwds: state.cwds, stack: [...state.stack], previous, list, compound, sub: node.sub, process: node.process === true })
      previous = null
      list = null
      compound = 0
    } else if (node.kind === "close") {
      const back = saved.pop()
      if (!back?.process) ctx.nested = Math.max(0, ctx.nested - 1)
      if (back) {
        state.cwds = back.cwds
        state.stack = back.stack
        previous = back.previous
        list = back.list
        compound = back.compound
        if (!back.sub) list?.states.push(state.cwds)
      }
    } else if (node.kind === "unknown") outside(ctx, node.why, node.runs)
    else {
      list = enter(state, list, node.op)
      const head = node.words[0]
      const keyword = head && !head.dynamic ? head.text : ""
      if (COMPOUND_OPEN.has(keyword)) compound++
      if (OUTSIDE_KEYWORDS.has(keyword)) outside(ctx, `\`${keyword}\``, keyword === "coproc")
      ctx.words.push(node.words, node.inputs)
      command(ctx, state, node, previous, compound > 0)
      if (COMPOUND_CLOSE.has(keyword)) compound = Math.max(0, compound - 1)
      list?.states.push(state.cwds)
      // An and-or list ended by & runs in a subshell: its folder changes
      // leave this shell where the list began.
      if (node.next === "&" && list) {
        state.cwds = list.start
        state.stack = [...list.startStack]
        list.states = [list.start]
      }
      previous = node
    }
  }
  if (list && list.states.length > 1) state.cwds = unionAll(list.states.slice(1))
}

// On a line outside the grammar, the guard cannot tell which words are
// commands, so every word counts: a program that reads or prints, a shell
// or an interpreter, a name a key file could have, or a key variable's
// expansion makes the line one that reads.
const PRINTERS = new Set([...ENV_DUMP, "ps", "echo", "printf"])
const PRINTER_CHECKS = 64

function anyWordReads(ctx: Context): boolean {
  let printers = 0
  for (const words of ctx.words) {
    for (const [i, word] of words.entries()) {
      if (word.vars.some((v) => KEY_VARIABLE.test(v))) return true
      if (word.dynamic || word.process) continue
      const text = word.text
      if (ctx.arithmetic && (text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []).some((name) => KEY_VARIABLE.test(name))) return true
      const program = basename(text)
      if (isReader(program) || own(INTERPRETERS, program) !== undefined || program === "printenv") return true
      if (PRINTERS.has(program)) {
        if (++printers > PRINTER_CHECKS) return true
        if (environmentRead(words.slice(i), ctx.command) !== null) return true
      }
      // A glob on its own reads nothing; the program beside it is what counts.
      if (!word.glob && !word.brace && couldNameSecret(text, ctx.home, ctx.vaultDirs)) return true
      if (isAbsolute(text) && classify(normalize(text), ctx.home, ctx.vaultDirs) !== null) return true
    }
  }
  return false
}

// Whether the line reads a variable through another, ${!v} with any
// operator after it (${!v:-x}, ${!v@Q}, ${!v[0]}), whose name is only known
// when the shell runs: anywhere in the text, quoted or not, so a literal one
// is stopped too. ${!prefix*}, ${!prefix@}, ${!a[@]} and ${!a[*]} list
// names or keys, not values, and pass.
function readsIndirectly(command: string): boolean {
  for (const match of command.matchAll(/\$\{!([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const rest = command.slice((match.index ?? 0) + match[0].length)
    if (!/^[*@]\}/.test(rest) && !/^\[[@*]\]\}/.test(rest)) return true
  }
  return false
}

export function commandFindings(command: string, cwd: string, home = homedir(), vaultDirs: string[] = []): Finding[] {
  const findings: Finding[] = []
  const inText = secretInText(command)
  if (inText) findings.push({ rule: "secret-in-command", reason: `the command carries ${inText}` })
  const ctx: Context = { home, vaultDirs, command, findings, outside: [], reads: false, nested: 0, words: [], arithmetic: false }
  lines(ctx, { cwds: [cwd], stack: [], links: new Map() }, parseShell(command, home))
  if (readsIndirectly(command)) outside(ctx, "${!name}, which reads a variable the guard cannot name", true)
  if (ctx.outside.length && !ctx.reads) ctx.reads = anyWordReads(ctx)
  // The allowlist: a line that uses anything outside the grammar and reads
  // a file or prints the environment is refused, whatever else was found.
  if (ctx.outside.length && ctx.reads) findings.unshift({ rule: "secret-file", reason: `can't tell what this reads (it uses ${ctx.outside[0]}, which the guard does not follow); run the read on its own` })
  return findings
}
