// What the guard hooks look for, whichever agent asks: a tool about to read
// a file that holds secrets, a shell command that reads one or carries a
// provider key, and a write that would put a key into a file. Local rules
// only: no vault, no network, nothing read but the paths named, so a hook
// answers in milliseconds and never fails for want of a connection.

import { secretPrefix, PLACEHOLDER_CORE } from "@mehen/protocol"
import { existsSync, readdirSync } from "node:fs"
import { homedir } from "node:os"
import { basename, dirname, isAbsolute, join, normalize, resolve, sep } from "node:path"
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
function insideVaultData(path: string): boolean {
  let dir = dirname(path)
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(dir, "directory.sqlite")) && existsSync(join(dir, "objects"))) return true
    const up = dirname(dir)
    if (up === dir) return false
    dir = up
  }
  return false
}

// Why reading this file would put a secret in front of the agent, or null.
export function secretFile(raw: string, cwd: string, home = homedir(), vaultDirs: string[] = []): string | null {
  const path = normalize(isAbsolute(raw) ? raw : resolve(cwd, raw.replace(/^~(?=$|\/)/, home)))
  const name = basename(path)
  if (/^\/proc\/[^/]+\/environ$/.test(path)) return "it is a process's environment, which can hold keys"
  if (insideVaultData(path)) return "it is a Mehen vault's own data"
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
function segments(command: string): string[][] {
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

const RECURSIVE = /^-(?:[a-zA-Z]*[rR][a-zA-Z]*|-recursive|-dereference-recursive)$/

// grep -r over a folder that holds a secret file reads it, unless the
// command leaves such files out.
function recursiveRead(words: string[], cwd: string, home: string, vaultDirs: string[]): string | null {
  if (basename(words[0] ?? "") !== "grep" || !words.slice(1).some((w) => RECURSIVE.test(w))) return null
  if (words.some((w) => w.startsWith("--exclude"))) return null
  const operands = words.slice(1).filter((w) => !w.startsWith("-"))
  const targets = operands.length > 1 ? operands.slice(1) : ["."]
  for (const target of targets) {
    const dir = resolve(cwd, target.replace(/^~(?=$|\/)/, home))
    let names: string[] = []
    try {
      names = readdirSync(dir)
    } catch {
      continue
    }
    const found = names.find((name) => secretFile(join(dir, name), cwd, home, vaultDirs) !== null)
    if (found) return `\`grep -r\` would read ${join(target, found)}`
  }
  return null
}

export function commandFindings(command: string, cwd: string, home = homedir(), vaultDirs: string[] = []): Finding[] {
  const findings: Finding[] = []
  const inText = secretInText(command)
  if (inText) findings.push({ rule: "secret-in-command", reason: `the command carries ${inText}` })
  for (const words of segments(command)) {
    const why = environmentRead(words, command) ?? recursiveRead(words, cwd, home, vaultDirs)
    if (why) findings.push({ rule: "secret-file", reason: why })
  }
  for (const words of segments(command)) {
    const program = basename(words[0] ?? "")
    const reads = READERS.has(program) || words.includes("<")
    if (!reads) continue
    // cp and its kin only read their sources: copying a template onto .env
    // writes it, and shows the agent nothing.
    const args = program === "cp" ? words.slice(1, -1) : words.slice(1)
    for (const word of args) {
      if (word.startsWith("-") || word === "<") continue
      const why = /[*?]/.test(basename(word)) ? (globMatchesSecret(word) ? "the pattern matches environment or key files" : null) : secretFile(word, cwd, home, vaultDirs)
      if (why) {
        findings.push({ rule: "secret-file", reason: `\`${program}\` would read ${word}: ${why}`, path: word })
        break
      }
    }
  }
  return findings
}
