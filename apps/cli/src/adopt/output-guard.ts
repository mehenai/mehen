// The last check on everything adopt writes: stdout, stderr, the scan and
// plan files, the state file, the ask ledger and MCP results. Every value
// the process read that is a secret or unknown is a needle (redact.ts
// buildNeedles: the value and its common encodings); text that contains one
// is never written, and the command fails with "internal error: output
// withheld". Values under six characters are not matched, so output is also
// limited by construction to ids, slugs, paths, names, counts and URLs.
//
// Output is made of a fixed vocabulary, the paths adopt read and the
// variable names and JSON pointers in those files, so a value that equals or
// sits inside one of those words or names, equals a path or a folder above
// it, or sits inside one of its parts is not a needle: it would stop ordinary
// output (SESSION_SECRET=secret, HOME in a plist, a settings file's
// `"tokenEnv": "SLACK_BOT_TOKEN"` beside a .env that sets SLACK_BOT_TOKEN)
// and the output holds it anyway.

import { KINDS } from "@mehen/protocol/kinds"
import { buildNeedles } from "@mehen/protocol/redact"
import { sep } from "node:path"
import { CliError, toCliError } from "../errors.ts"
import type { SourceClass } from "./classify.ts"
import { ENV_BY_SUFFIX } from "./sources.ts"

export const WITHHELD = "internal error: output withheld"

export class OutputWithheld extends CliError {
  constructor() {
    super("internal", WITHHELD, { say: "mehen stopped because a line it was about to write contained a value it read. Nothing was printed; report this with the command you ran." })
  }
}

// Classes, statuses, source types, categories, homes, kinds, field names
// and environment names: the words the scan and plan files are built from.
const VOCABULARY: readonly string[] = [
  ...new Set([
    "secret",
    "config",
    "unknown",
    "new",
    "unsupported",
    "dynamic",
    "skipped",
    "dotenv",
    "envrc",
    "json",
    "secrets-file",
    "plist",
    "systemd",
    "launchd",
    "gh-hosts",
    "kubeconfig",
    "talosconfig",
    "gcloud-adc",
    "wrangler",
    "docker",
    "repo",
    "local-secrets",
    "settings",
    "service",
    "login",
    "private",
    "workspace",
    "project",
    ...Object.keys(KINDS),
    ...Object.values(KINDS).flatMap((k) => k.fields.map((f) => f.name)),
    ...Object.entries(ENV_BY_SUFFIX).flat(),
  ]),
]

type Needle = { pattern: RegExp }

export class OutputGuard {
  private reads = 0
  private values: string[] = []
  private paths = new Set<string>()
  private names = new Set<string>()
  private needles: Needle[] | null = null

  // Called with every value read and its class, before anything that could
  // echo it. Plain config is not a needle.
  add(value: string, cls: SourceClass): void {
    this.reads++
    if (cls === "config") return
    this.values.push(value)
    this.needles = null
  }

  // A file or folder adopt read or walked.
  addPath(path: string): void {
    if (this.paths.has(path)) return
    this.paths.add(path)
    this.needles = null
  }

  // A variable name or JSON pointer from a file adopt read: output names it.
  addName(name: string | null): void {
    if (name === null || name === "" || this.names.has(name)) return
    this.names.add(name)
    this.needles = null
  }

  get size(): number {
    return this.reads
  }

  private inOutputWords(value: string): boolean {
    if (VOCABULARY.some((word) => word.includes(value))) return true
    for (const name of this.names) if (name.includes(value)) return true
    const folder = value.length > 1 && value.endsWith(sep) ? value.slice(0, -1) : value
    for (const path of this.paths) if (path === folder || path.startsWith(`${folder}${sep}`) || path.split(sep).some((part) => part.includes(value))) return true
    return false
  }

  private current(): Needle[] {
    if (this.needles === null) this.needles = buildNeedles(this.values.filter((value) => !this.inOutputWords(value)).map((value) => ({ label: "adopt", value })))
    return this.needles
  }

  clean(text: string): boolean {
    for (const needle of this.current()) if (text.search(needle.pattern) !== -1) return false
    return true
  }

  assertClean(text: string): void {
    if (!this.clean(text)) throw new OutputWithheld()
  }

  // An error as it may be shown: its message, next step and extras checked
  // like any other line, else the withheld error in its place.
  error(error: unknown): CliError {
    const failure = toCliError(error)
    if (failure instanceof OutputWithheld) return failure
    return this.clean(JSON.stringify({ message: failure.message, next: failure.next, extras: failure.extras })) ? failure : new OutputWithheld()
  }
}
