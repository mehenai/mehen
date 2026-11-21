// mehen backup keygen | snapshot | check | restore | export | status | open
// | compare: Mehen is never the only copy. Before `adopt submit` (before
// `adopt retire` for a single file `adopt file` planned), `snapshot`
// encrypts every file the adopt plan names to a backup key whose private
// half is on no enrolled machine; `export` has the vault encrypt what an
// owner may export to a backup key they registered with a passkey. Stock
// `age -d` opens both. keygen, check, restore, open and compare run
// offline: none talks to the vault, reads a slot or uses the device key.
// export and status ask the vault as this machine, and snapshot does only
// to find your own backup keys when none is named. No MCP tool
// exists for any of them.

import { EXIT } from "@mehen/protocol/api"
import { BackupRecipientIdSchema } from "@mehen/protocol/backup"
import type { ParsedArgs } from "../args.ts"
import type { Command } from "../command.ts"
import type { Env } from "../config.ts"
import { toCliError, usageError } from "../errors.ts"
import { note, printJson, printLine } from "../output.ts"
import { segments } from "../tty.ts"
import { openSession } from "../session.ts"
import { checkExport, checkSnapshot, isSnapshotName } from "../backup/check.ts"
import { compareBackups, compareLines } from "../backup/compare.ts"
import { exportDir, exportTargets, exportTo, readBackupStatus, ownRecipients, statusLines } from "../backup/export.ts"
import { generateBackupKey } from "../backup/keygen.ts"
import { bundleSummary, openBundle, summaryLines } from "../backup/open.ts"
import { type EnvRestoreResult, type RestoreMode, type RestoreResult, enrolledMachineCheck, readIdentity, refuseKeyArgument, restoreEnv, restoreSnapshot } from "../backup/restore.ts"
import { RECIPIENTS_ENV, backupRecipients, namedRecipients, takeSnapshot } from "../backup/snapshot.ts"
import { relativeAgo } from "./items.ts"

const USAGE = "mehen backup keygen --out <path> [--on-enrolled-machine] | snapshot --plan <path> --to <dir> [--recipient <age1...>]... | check <snp_id.age|export.age> | restore <snp_id.age> --identity <file|-> (--verify-only | --to <dir> | --in-place [--force]) [--on-enrolled-machine] | restore <export.age> --identity <file|-> --env <dir> | export --to <dir> [--recipient <bkr_id>]... | status | open <export.age> --identity <file|-> | compare <snp_id.age> <export.age> --identity <file|-> --map <file>"
const HELP = "mehen backup --help"

const FLAGS_FOR: Record<string, readonly string[]> = {
  keygen: ["out", "on-enrolled-machine"],
  snapshot: ["plan", "to", "recipient"],
  check: [],
  restore: ["identity", "verify-only", "to", "in-place", "force", "env", "on-enrolled-machine"],
  export: ["to", "recipient"],
  status: [],
  open: ["identity", "on-enrolled-machine"],
  compare: ["identity", "map", "on-enrolled-machine"],
}

// How many archive paths each action takes after its name.
const FILES_FOR: Record<string, number> = { check: 1, restore: 1, open: 1, compare: 2 }

const ALL_FLAGS = ["out", "plan", "to", "recipient", "identity", "verify-only", "in-place", "force", "env", "map", "on-enrolled-machine"] as const

function given(args: ParsedArgs, flag: string): boolean {
  return args.string(flag) !== null || args.bool(flag) || args.list(flag).length > 0
}

function required(args: ParsedArgs, flag: string, action: string): string {
  const value = args.string(flag)
  if (value === null || value === "") throw usageError(`mehen backup ${action} needs --${flag}. Usage: ${USAGE}`, HELP)
  return value
}

function restoreMode(args: ParsedArgs): RestoreMode {
  const modes = [args.bool("verify-only"), args.string("to") !== null, args.bool("in-place")].filter(Boolean).length
  if (modes !== 1) throw usageError("mehen backup restore needs exactly one of --verify-only, --to <dir> or --in-place for a snapshot, or --env <dir> for an export.", HELP)
  if (args.bool("force") && !args.bool("in-place")) throw usageError("--force goes with --in-place only.", HELP)
  if (args.bool("verify-only")) return { kind: "verify-only" }
  if (args.bool("in-place")) return { kind: "in-place", force: args.bool("force") }
  return { kind: "to", dir: required(args, "to", "restore") }
}

function restoreLines(result: RestoreResult): string[] {
  const day = result.createdAt.slice(0, 10)
  if (result.mode === "verify-only") return [`restorable: ${result.files} file${result.files === 1 ? "" : "s"} from ${result.machine}, ${day} (${result.id})`]
  const lines = result.results.map((r) => {
    if (r.outcome === "different") return `different  ${r.path} (left as it is; --force replaces it and keeps the old one beside it)`
    if (r.outcome === "replaced") return `replaced   ${r.path} (the old file is ${r.kept})`
    return `${r.outcome.padEnd(10)} ${r.path}`
  })
  return [...lines, `restored ${result.written} of ${result.files} file${result.files === 1 ? "" : "s"} from ${result.machine}, ${day} (${result.id})`]
}

function envRestoreLines(result: EnvRestoreResult): string[] {
  const lines: string[] = []
  for (const p of result.projects) {
    lines.push(`wrote ${p.manifest}`)
    for (const f of p.files) {
      lines.push(`wrote ${f.path}: ${f.variables} variable${f.variables === 1 ? "" : "s"}`)
      for (const m of f.missing) lines.push(`  missing ${m.variable} (${m.item}): ${m.why}`)
    }
  }
  for (const s of result.skipped) lines.push(`skipped ${s.project}: ${s.why}`)
  lines.push(`restored ${result.projects.length} project${result.projects.length === 1 ? "" : "s"} from ${result.id} (${result.workspace.slug}, ${result.exportedAt.slice(0, 10)}); every agent on this machine can read these files`)
  return lines
}

async function readStdin(): Promise<string> {
  return await new Response(Bun.stdin.stream()).text()
}

// The identity for restore, open and compare: refused on an enrolled
// machine without --on-enrolled-machine, then read from a file or stdin.
async function identityFor(args: ParsedArgs, env: Env, action: "restore" | "open" | "compare"): Promise<string[]> {
  const identity = required(args, "identity", action)
  const warning = await enrolledMachineCheck(env, args.bool("on-enrolled-machine"), action)
  if (warning !== null) note(`mehen: warning: ${warning}`)
  return await readIdentity(identity, readStdin)
}

// --recipient for a snapshot is an age key; for an export it names a
// registered backup key by id, never a key: the vault holds the keys.
function exportRecipients(args: ParsedArgs): string[] {
  const named = args.list("recipient")
  for (const r of named) refuseKeyArgument(r, "mehen backup export --recipient takes a backup key's id (bkr_...)")
  const wrong = named.find((r) => !BackupRecipientIdSchema.safeParse(r).success)
  if (wrong !== undefined) throw usageError(`mehen backup export --recipient takes a backup key's id (bkr_...), as \`mehen backup status\` lists them, not ${JSON.stringify(wrong.slice(0, 80))}.`, HELP)
  return named
}

async function snapshotRecipients(args: ParsedArgs, env: Env): Promise<string[]> {
  const named = namedRecipients(args.list("recipient"), env)
  for (const r of named) refuseKeyArgument(r, `mehen backup snapshot --recipient and ${RECIPIENTS_ENV} take a public key (age1...)`)
  if (named.length > 0) return backupRecipients(args.list("recipient"), env)
  try {
    return backupRecipients([], env, await ownRecipients((await openSession(env)).api))
  } catch (error) {
    const reason = toCliError(error)
    if (reason.code === "usage") throw reason
    return backupRecipients([], env, [], reason.message)
  }
}

export const backupCommand: Command = {
  summary: "keep your own encrypted copies, off Mehen: keygen, snapshot, export, status, check, open, restore and compare (age)",
  spec: {
    usage: USAGE,
    flags: {
      out: { type: "string" },
      plan: { type: "string" },
      to: { type: "string" },
      recipient: { type: "list" },
      identity: { type: "string" },
      "verify-only": { type: "boolean" },
      "in-place": { type: "boolean" },
      force: { type: "boolean" },
      env: { type: "string" },
      map: { type: "string" },
      "on-enrolled-machine": { type: "boolean" },
    },
    positionals: { min: 1, max: 3 },
  },
  examples: [
    ["backup", "keygen", "--out", "/Volumes/key/mehen-backup.txt"],
    ["backup", "snapshot", "--plan", "plan.json", "--to", "/Volumes/backup/mehen", "--recipient", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"],
    ["backup", "check", "/Volumes/backup/mehen/snp_x.age", "--json"],
    ["backup", "restore", "/Volumes/backup/mehen/snp_x.age", "--identity", "-", "--verify-only"],
    ["backup", "restore", "snp_x.age", "--identity", "key.txt", "--to", "staging"],
    ["backup", "restore", "snp_x.age", "--identity", "key.txt", "--in-place"],
    ["backup", "export", "--to", "/Users/sam/Backups/mehen"],
    ["backup", "status", "--json"],
    ["backup", "open", "mehen-acme-2026-11-01-bkx_x.age", "--identity", "-"],
    ["backup", "restore", "mehen-acme-2026-11-01-bkx_x.age", "--identity", "-", "--env", "restored"],
    ["backup", "compare", "snp_x.age", "mehen-acme-2026-11-01-bkx_x.age", "--identity", "-", "--map", "adoption.json"],
  ],
  notes: [
    "keygen writes a new age identity (mode 0600, never over a file) and prints only its recipient. Run it on a machine no agent uses; keep the identity in a password manager no agent can read and on paper, never on an enrolled machine.",
    `snapshot reads every file the adopt plan names, encrypts them to each --recipient (or ${RECIPIENTS_ENV}, comma-separated) and writes <snp_id>.age and a <snp_id>.json sidecar, after proving the archive opens to exactly what it read. Stock \`age -d\` opens it. adopt submit is refused until a snapshot holds every file the plan names, except for a single file planned with adopt file; adopt retire holds every file no snapshot holds.`,
    "check needs no key: it compares the archive with its sidecar and checks its age header.",
    "restore reads the identity from a file or stdin (--identity -), never an argument, and runs offline. --to takes a new or empty directory, never /, that is this user's and private to it (0700), below directories only this user or root can write, so never under /tmp; the same goes for restore --env. --in-place restores only a snapshot this machine took, and only the paths its record lists: it writes missing files; with --force it replaces those that differ and keeps each old one as <path>.mehen-restore-<time>. Restored files keep their permission bits, never setuid or setgid.",
    `snapshot with no --recipient and no ${RECIPIENTS_ENV} encrypts to your own active backup keys, asked of the vault as this machine; never to another person's key. With none of your own, name one with --recipient.`,
    "export asks the vault for an export to each backup key you added that has passed its day of cooling-off (or each --recipient bkr_... named): the vault encrypts it, so this machine only ever receives ciphertext. Each is checked against the SHA-256 the vault reported and written as mehen-<workspace>-<date>-<bkx_id>.age (0600, never over a file) with a .json sidecar holding no slug and no value. One export per key every ten minutes; run it daily from launchd or cron. Only an owner exports, from a browser or one of their own machines.",
    "status lists the workspace's backup keys and, for your own, the last export and how many credentials and variables changed since (stale).",
    "open, restore --env and compare read the identity like restore and run offline on the key machine. open prints counts, slugs and what was left out, never a value. restore --env writes <dir>/<project>/mehen.toml and <dir>/<project>/<env>.env (0600) and names every variable the export does not hold. compare checks every adopted source in a snapshot against the export, using `mehen adopt status <adp_id> --json` saved to --map; it exits 1 on any difference or gap and names paths and variables only. With --json it adds the export's time (exportedAt) and every source that matched (matching), which `mehen adopt retire --compared` reads.",
  ],
  async run({ args, json, env }) {
    const [action, target] = args.positionals
    for (const positional of args.positionals) refuseKeyArgument(positional, "mehen backup takes an action and an archive path")
    if (action === undefined || !Object.hasOwn(FLAGS_FOR, action)) throw usageError(`Unknown backup action ${JSON.stringify(action ?? "")}. Usage: ${USAGE}`, HELP)
    const allowed = FLAGS_FOR[action] as readonly string[]
    const stray = ALL_FLAGS.find((flag) => !allowed.includes(flag) && given(args, flag))
    if (stray !== undefined) throw usageError(`mehen backup ${action} takes no --${stray}. Usage: ${USAGE}`, HELP)
    if (args.positionals.length - 1 !== (FILES_FOR[action] ?? 0)) throw usageError(`Usage: ${USAGE}`, HELP)

    if (action === "keygen") {
      const out = required(args, "out", "keygen")
      const warning = await enrolledMachineCheck(env, args.bool("on-enrolled-machine"), "keygen")
      if (warning !== null) note(`mehen: warning: ${warning}`)
      const result = await generateBackupKey({ out, env })
      if (json) printJson(result)
      else {
        note(`mehen: wrote the backup identity to ${result.identityFile} (mode 0600). Keep it in a password manager no agent can read and on paper, never on an enrolled machine, then delete this copy.`)
        printLine(result.recipient)
      }
      return EXIT.ok
    }

    if (action === "snapshot") {
      const recipients = await snapshotRecipients(args, env)
      const result = await takeSnapshot({ planPath: required(args, "plan", "snapshot"), to: required(args, "to", "snapshot"), recipients, env })
      if (json) printJson(result)
      else {
        printLine(`snapshot ${result.id}: ${result.files} file${result.files === 1 ? "" : "s"} from ${result.machine}, encrypted to ${result.recipients.map((r) => r.fingerprint).join(", ")}; self-check passed`)
        printLine(`wrote ${result.archive} and ${result.sidecar}; copy both off this machine`)
      }
      return EXIT.ok
    }

    if (action === "export") {
      const to = required(args, "to", "export")
      const named = exportRecipients(args)
      const { api } = await openSession(env)
      const targets = named.length > 0 ? named : exportTargets(await readBackupStatus(api), [])
      const dir = await exportDir(to)
      const written = []
      for (const recipient of targets) {
        const one = await exportTo(api, dir, recipient)
        written.push(one)
        if (!json) {
          printLine(`export ${one.id}: ${one.items} credential${one.items === 1 ? "" : "s"}, ${one.projects} project${one.projects === 1 ? "" : "s"}, ${one.excluded} left out; encrypted by the vault to ${one.recipient.fingerprint} (${one.recipient.id})`)
          printLine(`wrote ${one.archive} and ${one.sidecar}`)
        }
      }
      if (json) printJson({ exports: written })
      return EXIT.ok
    }

    if (action === "status") {
      const { api } = await openSession(env)
      const status = await readBackupStatus(api)
      if (json) printJson(status)
      else for (const line of statusLines(status, (iso) => relativeAgo(iso, new Date()) ?? iso)) printLine(segments(line))
      return EXIT.ok
    }

    if (action === "open") {
      const identities = await identityFor(args, env, "open")
      const summary = bundleSummary(await openBundle(target as string, identities))
      if (json) printJson(summary)
      else for (const line of summaryLines(summary)) printLine(segments(line))
      return EXIT.ok
    }

    if (action === "compare") {
      const map = required(args, "map", "compare")
      const identities = await identityFor(args, env, "compare")
      const result = await compareBackups({ snapshotPath: target as string, exportPath: args.positionals[2] as string, mapPath: map, identities })
      if (json) printJson(result)
      else for (const line of compareLines(result)) printLine(line)
      return result.different.length === 0 && result.missing.length === 0 ? EXIT.ok : EXIT.error
    }

    if (action === "check" && !isSnapshotName(target as string)) {
      const result = await checkExport(target as string)
      if (json) printJson({ ok: true, ...result })
      else printLine(`ok: ${result.id} of ${result.workspace.slug}, ${result.exportedAt.slice(0, 10)}: ${result.items} credential${result.items === 1 ? "" : "s"}, encrypted to ${result.recipient.fingerprint} (${result.recipient.id}); length, SHA-256 and age header match the sidecar`)
      return EXIT.ok
    }

    if (action === "check") {
      const result = await checkSnapshot(target as string)
      if (json) printJson({ ok: true, ...result })
      else printLine(`ok: ${result.id} from ${result.machine}, ${result.createdAt.slice(0, 10)}: ${result.files} file${result.files === 1 ? "" : "s"}, ${result.recipients.length} recipient${result.recipients.length === 1 ? "" : "s"} (${result.recipients.map((r) => r.fingerprint).join(", ")}); length, SHA-256 and age header match the sidecar`)
      return EXIT.ok
    }

    const envDir = args.string("env")
    if (envDir !== null || !isSnapshotName(target as string)) {
      if (envDir === null || args.bool("verify-only") || args.string("to") !== null || args.bool("in-place") || args.bool("force")) throw usageError("An export restores with --env <dir> alone (`mehen backup open` lists what it holds); --verify-only, --to and --in-place are for a snapshot (<snp_id>.age).", HELP)
      const identities = await identityFor(args, env, "restore")
      const result = await restoreEnv({ archivePath: target as string, identities, dir: envDir })
      if (json) printJson(result)
      else for (const line of envRestoreLines(result)) printLine(line)
      return EXIT.ok
    }
    const mode = restoreMode(args)
    const identities = await identityFor(args, env, "restore")
    const result = await restoreSnapshot({ archivePath: target as string, identities, mode, env })
    if (json) printJson(result)
    else for (const line of restoreLines(result)) printLine(line)
    return EXIT.ok
  },
}
