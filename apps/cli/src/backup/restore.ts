// mehen backup restore <snp_id>.age --identity <file|->: open a snapshot
// with the backup identity, entirely offline: no network, no slot, no
// device key. The identity comes only from a file or stdin, never from an
// argument, and belongs on a machine no agent uses; on a machine whose
// MEHEN_HOME holds an enrolment the command refuses unless told
// --on-enrolled-machine, and then warns.
//
//   --verify-only   decrypt and check every file's SHA-256; write nothing
//   --to <dir>      write each file to <dir>/<its absolute path>; <dir> is
//                   new or empty, never /, this user's and 0700, below
//                   directories only this user or root can write
//   --in-place      on the machine that took it, write the files that are
//                   missing; with --force, replace those that differ,
//                   keeping each old one beside it as
//                   <path>.mehen-restore-<time>
//
// mehen backup restore <bkx>.age --identity - --env <dir> opens an export
// from the vault instead, the same way, and writes per project its
// mehen.toml (the text `mehen init` writes) and one <env>.env per
// environment: plain variables as they are, references with the exported
// value, and each reference the export does not hold named as missing.

import { lstat, mkdir, readdir, rename } from "node:fs/promises"
import { dirname, join } from "node:path"
import { EnvName, type Project, Slug, VarName } from "@mehen/protocol/api"
import { BACKUP_LIMITS, type BackupBundle, type Snapshot, SnapshotSchema, sha256Hex, snapshotFileLimit } from "@mehen/protocol/backup"
import { fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { type Env } from "../config.ts"
import { CliError, usageError } from "../errors.ts"
import { ENROLMENT_RECORD_FILE, PENDING_DIR, WORKSPACES_DIR, ensureSafeDirectory, resolveHome } from "../home.ts"
import { legacyLayout } from "../migration.ts"
import { manifestText } from "../run/init.ts"
import { ageDecrypt } from "./age.ts"
import { backupFailure, fromBase64, readRegularFile, realTarget, writeNewFile } from "./files.ts"
import { MAX_ARCHIVE_BYTES } from "./check.ts"
import { openBundle } from "./open.ts"
import { readSnapshotRecords } from "./state.ts"

const IDENTITY_LINE = /^AGE-SECRET-KEY-1[0-9A-Z]+$/

// The X25519 identities in an identity file's text, as age-keygen writes
// it: comment lines and blank lines are skipped.
export function parseIdentities(text: string): string[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"))
  if (lines.length === 0 || !lines.every((l) => IDENTITY_LINE.test(l))) {
    throw new CliError("usage", "The identity holds no age X25519 identity (a line AGE-SECRET-KEY-1...), or a line that is not one.", { command: "mehen backup --help", say: "Give the identity file `age-keygen` or `mehen backup keygen` wrote, with --identity <file> or on stdin with --identity -." })
  }
  return lines
}

// A backup identity typed as an argument is refused, and never repeated:
// every message that names the argument would print the key.
export function refuseKeyArgument(value: string, what: string): void {
  if (value.trim().toUpperCase().startsWith("AGE-SECRET-KEY-")) throw usageError(`${what}, never the key itself: a key on the command line lands in shell history and process lists. Remove it from your history.`, "mehen backup --help")
}

// The identity's text from --identity: `-` reads stdin, anything else is a
// file this user owns that nobody else can read. A key given as the value
// itself is refused without being repeated.
export async function readIdentity(spec: string, readStdin: () => Promise<string>): Promise<string[]> {
  refuseKeyArgument(spec, "--identity takes a file or - (stdin)")
  if (spec === "-") return parseIdentities(await readStdin())
  const read = await readRegularFile(spec, { maxBytes: 65_536, ownOnly: true })
  if (read === null) throw usageError(`There is no identity file at ${spec}.`, "mehen backup --help")
  if ((read.info.mode & 0o077) !== 0) {
    throw new CliError("key_insecure", `Refusing to use ${spec}: other users on this machine can read it.`, { command: `chmod 600 ${spec}`, say: `Restrict it with \`chmod 600 ${spec}\`, or pipe the identity in with --identity - instead.` })
  }
  return parseIdentities(fromUtf8(new Uint8Array(read.bytes)))
}

async function entries(dir: string): Promise<string[]> {
  return await readdir(dir).catch(() => [])
}

// Does this MEHEN_HOME hold an enrolment, active or pending, in either
// layout? Names only: no slot, config or key is read. backup never migrates
// the root, so a legacy one (config and keys at the root) counts as it is.
export async function holdsEnrolment(root: string): Promise<boolean> {
  if (await legacyLayout(root)) return true
  for (const kind of [WORKSPACES_DIR, PENDING_DIR]) {
    for (const origin of await entries(join(root, kind))) if ((await entries(join(root, kind, origin))).length > 0) return true
  }
  if ((await entries(join(root, "contexts"))).length > 0) return true
  return (await lstat(join(root, ENROLMENT_RECORD_FILE)).catch(() => null)) !== null
}

// Refuses keygen or restore without --on-enrolled-machine on a machine
// that holds an enrolment, where an agent running as this user could read
// the identity; the warning to print when allowed, or null.
export async function enrolledMachineCheck(env: Env, allowed: boolean, action: "keygen" | "restore" | "open" | "compare"): Promise<string | null> {
  const { root } = resolveHome(env)
  if (!(await holdsEnrolment(root))) return null
  const warning = `${root} holds a Mehen enrolment, so agents run here. The backup identity opens every snapshot and belongs on a machine no agent uses; remove it from this machine when you are done.`
  const instead = action === "keygen" ? "Make the key on a machine no agent uses, or pass --on-enrolled-machine if you will move it off this one at once." : `Run the ${action} on the key machine, or pass --on-enrolled-machine if this really is a break-glass ${action}.`
  if (!allowed) throw usageError(`${warning} ${instead}`, "mehen backup --help")
  return warning
}

export type RestoreMode = { kind: "verify-only" } | { kind: "to"; dir: string } | { kind: "in-place"; force: boolean }

export type RestoredFile = { path: string; outcome: "verified" | "written" | "unchanged" | "different" | "replaced"; kept?: string }

export type RestoreResult = { id: string; machine: string; createdAt: string; files: number; mode: RestoreMode["kind"]; written: number; results: RestoredFile[] }

export type RestoreOptions = { archivePath: string; identities: readonly string[]; mode: RestoreMode; env: Env; now?: () => Date }

export type Opened = { file: Snapshot["files"][number]; bytes: Uint8Array }

export type OpenedSnapshot = { snapshot: Snapshot; files: Opened[]; ciphertext: { bytes: number; sha256: string } }

export async function openSnapshot(archivePath: string, identities: readonly string[]): Promise<OpenedSnapshot> {
  const archive = await readRegularFile(archivePath, { maxBytes: MAX_ARCHIVE_BYTES, ownOnly: false })
  if (archive === null) throw backupFailure(`There is no archive at ${archivePath}.`, "Name the .age file `mehen backup snapshot` wrote.")
  let plaintext: Uint8Array
  try {
    plaintext = await ageDecrypt(archive.bytes, identities)
  } catch {
    throw backupFailure(`The identity does not open ${archivePath}, or the archive is damaged.`, `Check the archive with \`mehen backup check ${archivePath}\`, then try the identity the snapshot was encrypted to (its sidecar lists the recipients).`)
  }
  let snapshot: Snapshot
  try {
    snapshot = SnapshotSchema.parse(JSON.parse(fromUtf8(new Uint8Array(plaintext))))
  } catch {
    throw backupFailure(`${archivePath} opens, but not to a mehen-snapshot/v1 archive.`, "Use a snapshot `mehen backup snapshot` wrote.")
  } finally {
    plaintext.fill(0)
  }
  const seen = new Set<string>()
  const files: Opened[] = []
  for (const file of snapshot.files) {
    const bytes = fromBase64(file.content)
    if (seen.has(file.path) || bytes.length !== file.size || bytes.length > snapshotFileLimit(snapshot, file) || (await sha256Hex(bytes)) !== file.sha256) {
      throw backupFailure(`${archivePath} opens, but its copy of ${file.path} is damaged.`, "Use another copy of this snapshot.")
    }
    seen.add(file.path)
    files.push({ file, bytes })
  }
  return { snapshot, files, ciphertext: { bytes: archive.bytes.length, sha256: await sha256Hex(archive.bytes) } }
}

// A new file with the recorded permission bits and mtime, and the recorded
// owner when running as root. Setuid, setgid and sticky bits are dropped:
// anyone who knows the recipient can make an archive the identity opens.
// Parents that do not exist are made 0700.
async function writeRestored(path: string, opened: Opened): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const owner = process.getuid?.() === 0 ? { owner: { uid: opened.file.uid, gid: opened.file.gid } } : {}
  await writeNewFile(path, opened.bytes, { mode: opened.file.mode & 0o777, mtimeMs: opened.file.mtimeMs, ...owner })
}

function keptPath(path: string, now: Date): string {
  return `${path}.mehen-restore-${now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")}`
}

async function sameContent(path: string, opened: Opened): Promise<boolean | null> {
  const info = await lstat(path).catch((error: unknown) => ((error as { code?: string }).code === "ENOENT" ? null : undefined))
  if (info === null) return null
  if (info === undefined || !info.isFile() || info.size !== opened.bytes.length) return false
  const read = await readRegularFile(path, { maxBytes: opened.bytes.length, ownOnly: false }).catch(() => null)
  return read !== null && (await sha256Hex(read.bytes)) === opened.file.sha256
}

// The paths --in-place may write: those this machine's own record of the
// snapshot lists, and its plan. An archive is no proof of where its files
// belong or what they held (anyone who knows the recipient can make one),
// so a snapshot this machine did not take, a plan digest its record does
// not hold, a path its record does not list, a file over one source's cap
// anywhere but the recorded plan path, or an archive whose length and
// SHA-256 are not the ones recorded when it was written refuses before
// anything is written.
async function inPlacePaths(env: Env, { snapshot, files, ciphertext }: OpenedSnapshot): Promise<void> {
  const record = (await readSnapshotRecords(env)).find((r) => r.id === snapshot.id)
  const staging = { command: "mehen backup restore <snp_id.age> --identity <file|-> --to <staging dir>", say: "Restore it into an empty staging directory with --to, check the files, and copy back the ones you need." }
  if (record === undefined) throw new CliError("failed", `Refusing to restore in place: snapshot ${snapshot.id} was not taken on this machine (its MEHEN_HOME holds no record of it), so where its files belong is not known.`, staging)
  if (snapshot.planDigest !== record.planDigest) throw new CliError("failed", `Refusing to restore in place: this archive of snapshot ${snapshot.id} names a plan digest that is not the one this machine recorded, so nothing was written.`, staging)
  const allowed = new Set([...record.paths, record.planPath])
  const stray = files.find(({ file }) => !allowed.has(file.path))
  if (stray !== undefined) throw new CliError("failed", `Refusing to restore in place: the archive holds ${stray.file.path}, which this machine's record of snapshot ${snapshot.id} does not list, so nothing was written.`, staging)
  const big = files.find(({ file }) => file.size > BACKUP_LIMITS.maxFileBytes && file.path !== record.planPath)
  if (big !== undefined) throw new CliError("failed", `Refusing to restore in place: the archive's copy of ${big.file.path} is larger than ${BACKUP_LIMITS.maxFileBytes} bytes, and only the plan at ${record.planPath} may be, so nothing was written.`, staging)
  if (record.ciphertext === undefined) throw new CliError("failed", `Refusing to restore in place: this machine's record of snapshot ${snapshot.id} holds no digest of its archive, so this archive cannot be shown to be the one it wrote, and nothing was written.`, staging)
  if (ciphertext.bytes !== record.ciphertext.bytes || ciphertext.sha256 !== record.ciphertext.sha256) throw new CliError("failed", `Refusing to restore in place: this archive of snapshot ${snapshot.id} is not the archive this machine wrote (its length or SHA-256 is not the one recorded), so nothing was written.`, staging)
}

// The --to (or --env) base: never /, and either missing or an empty
// directory, so a restore there is a staging copy, never a restore in place
// without the in-place checks. Like MEHEN_HOME it is this
// user's and private, below directories only this user or root can write,
// so nobody else can move, replace or read what is restored there; missing
// components are made 0700 one at a time.
async function stagingDir(dir: string, flag: "--to" | "--env" = "--to"): Promise<string> {
  const base = realTarget(dir)
  const say = `Name a new or empty staging directory with ${flag}, such as ~/mehen-restore.`
  if (dirname(base) === base) throw backupFailure(`Refusing to restore to ${base}: ${flag} takes a staging directory, not the root of the filesystem.${flag === "--to" ? " Use --in-place to restore files where they were." : ""}`, say)
  const info = await lstat(base).catch(() => null)
  if (info !== null && !info.isDirectory()) throw backupFailure(`Refusing to restore to ${base}: it is not a directory.`, say)
  if (info !== null && (await readdir(base)).length > 0) throw backupFailure(`Refusing to restore to ${base}: it is not empty.`, say)
  ensureSafeDirectory(base, (path, why) => stagingRefusal(base, path, why, flag))
  return base
}

// The walk's reason is the whole refusal. chmod is the next step only for
// the directory itself, this user's and open to others; for anything else
// (another user's, or a bad directory above it) only a new one helps.
export function stagingRefusal(base: string, path: string, why: string, flag: "--to" | "--env"): CliError {
  const tooOpen = path === base && why.startsWith("is open to other users")
  return backupFailure(`Refusing to restore to ${base}: ${path} ${why}.`, tooOpen ? `Run \`chmod 700 ${base}\`, then restore again.` : `Name a new directory under your home with ${flag}, such as ~/mehen-restore.`)
}

export async function restoreSnapshot(options: RestoreOptions): Promise<RestoreResult> {
  const openedSnapshot = await openSnapshot(options.archivePath, options.identities)
  const { snapshot, files } = openedSnapshot
  const results: RestoredFile[] = []
  const mode = options.mode
  if (mode.kind === "verify-only") {
    for (const { file } of files) results.push({ path: file.path, outcome: "verified" })
  } else if (mode.kind === "to") {
    const base = await stagingDir(mode.dir)
    for (const opened of files) {
      await writeRestored(join(base, opened.file.path), opened)
      results.push({ path: join(base, opened.file.path), outcome: "written" })
    }
  } else {
    await inPlacePaths(options.env, openedSnapshot)
    const now = options.now?.() ?? new Date()
    for (const opened of files) {
      const path = opened.file.path
      const same = await sameContent(path, opened)
      if (same === null) {
        await writeRestored(path, opened)
        results.push({ path, outcome: "written" })
      } else if (same) {
        results.push({ path, outcome: "unchanged" })
      } else if (!mode.force) {
        results.push({ path, outcome: "different" })
      } else {
        const kept = keptPath(path, now)
        if (await lstat(kept).catch(() => null)) throw backupFailure(`Refusing to replace ${path}: ${kept} already exists.`, `Move ${kept} aside, then run the command again.`)
        await rename(path, kept)
        await writeRestored(path, opened)
        results.push({ path, outcome: "replaced", kept })
      }
    }
  }
  return {
    id: snapshot.id,
    machine: snapshot.machine,
    createdAt: snapshot.createdAt,
    files: files.length,
    mode: mode.kind,
    written: results.filter((r) => r.outcome === "written" || r.outcome === "replaced").length,
    results,
  }
}

// ---- an export from the vault, as .env files: restore --env ---------------

export type EnvMissing = { variable: string; item: string; why: string }
export type EnvFileResult = { env: string; path: string; variables: number; missing: EnvMissing[] }
export type EnvRestoreResult = { id: string; workspace: BackupBundle["workspace"]; exportedAt: string; dir: string; projects: { slug: string; manifest: string; files: EnvFileResult[] }[]; skipped: { project: string; why: string }[] }

const ID_TEXT = /^[A-Za-z0-9_-]{1,80}$/

// One NAME=value line dotenv reads back exactly: single quotes keep the
// value literal (newlines included); a value with a single quote is double
// quoted with its backslashes, quotes, dollars, backticks and line breaks
// escaped.
export function dotenvLine(name: string, value: string): string {
  if (!value.includes("'")) return `${name}='${value}'`
  const escaped = value.replace(/[\\"$`]/g, (c) => `\\${c}`).replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t")
  return `${name}="${escaped}"`
}

// Text from the bundle in a comment line: no line break or control
// character can end the comment and start a variable.
function oneLine(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f]/g, " ")
}

function lookup(bundle: BackupBundle, slug: string, field: string): { ok: true; value: string } | { ok: false; why: string } {
  const item = bundle.items.find((i) => i.slug === slug)
  if (item === undefined) return { ok: false, why: bundle.excluded.find((e) => e.slug === slug)?.reason ?? "not in this export" }
  const value = item.secretFields[field] ?? item.publicFields[field]
  if (value === undefined) return { ok: false, why: bundle.excluded.find((e) => e.slug === slug)?.reason ?? `the export holds no field ${field} for it` }
  return { ok: true, value }
}

// The text of one environment's .env, and what it could not fill. The
// registrant's own overrides win, as they do for their mehen run.
export function envFileText(bundle: BackupBundle, project: BackupBundle["projects"][number], env: BackupBundle["projects"][number]["environments"][number]): { text: string; variables: number; missing: EnvMissing[] } {
  const values = new Map<string, string>()
  const missing: EnvMissing[] = []
  const take = (variable: string, source: { plain: string } | { item: string; field: string; notExported?: true }) => {
    if (!VarName.safeParse(variable).success) return
    if ("plain" in source) return values.set(variable, source.plain)
    if (source.notExported) return missing.push({ variable, item: source.item, why: bundle.excluded.find((e) => e.slug === source.item)?.reason ?? "outside what you may export" })
    const found = lookup(bundle, source.item, source.field)
    if (found.ok) values.set(variable, found.value)
    else missing.push({ variable, item: source.item, why: found.why })
  }
  for (const [variable, source] of Object.entries(env.vars)) take(variable, source)
  for (const o of bundle.overrides.filter((x) => x.project === project.id && x.environment === env.name)) {
    const at = missing.findIndex((m) => m.variable === o.variable)
    if (at !== -1) missing.splice(at, 1)
    values.delete(o.variable)
    take(o.variable, o.source.kind === "plain" ? { plain: o.source.value } : { item: o.source.item, field: o.source.field })
  }
  const names = [...values.keys()].sort()
  const lines = [
    `# ${project.slug} ${env.name}, restored from Mehen export ${bundle.id} (${bundle.exportedAt}).`,
    "# Every agent on this machine can read this file, as before Mehen. Delete it once Mehen is back.",
    ...names.map((n) => dotenvLine(n, values.get(n) as string)),
    ...missing.map((m) => `# ${m.variable} is missing: ${oneLine(m.item)}, ${oneLine(m.why)}`),
    "",
  ]
  return { text: lines.join("\n"), variables: names.length, missing }
}

export type EnvRestoreOptions = { archivePath: string; identities: readonly string[]; dir: string }

// Anyone who knows the recipient can make a bundle the identity opens, so
// every name that becomes a path or goes into mehen.toml is checked first.
export async function restoreEnv(options: EnvRestoreOptions): Promise<EnvRestoreResult> {
  const bundle = await openBundle(options.archivePath, options.identities)
  if (!ID_TEXT.test(bundle.workspace.id) || !Slug.safeParse(bundle.workspace.slug).success || URL.canParse(bundle.vault) === false || new URL(bundle.vault).origin !== bundle.vault) {
    throw backupFailure(`${options.archivePath} opens, but names a workspace or vault mehen will not write into mehen.toml.`, "Use an export `mehen backup export` or the Settings page wrote.")
  }
  const base = await stagingDir(options.dir, "--env")
  const projects: EnvRestoreResult["projects"] = []
  const skipped: EnvRestoreResult["skipped"] = []
  for (const project of bundle.projects) {
    const envs = project.environments.filter((e) => EnvName.safeParse(e.name).success)
    if (!Slug.safeParse(project.slug).success || !ID_TEXT.test(project.id) || envs.length !== project.environments.length) {
      skipped.push({ project: project.id, why: "its slug, id or an environment name cannot be a file name" })
      continue
    }
    const dir = join(base, project.slug)
    await mkdir(dir, { mode: 0o700 })
    const defaultEnv = project.defaultEnv !== null && EnvName.safeParse(project.defaultEnv).success ? project.defaultEnv : (envs[0]?.name ?? "dev")
    const manifest = join(dir, "mehen.toml")
    const shape: Pick<Project, "id" | "defaultEnv"> = { id: project.id, defaultEnv }
    await writeNewFile(manifest, utf8(manifestText(shape as Project, { vault: bundle.vault, tenant: bundle.workspace.id, workspaceSlug: bundle.workspace.slug, workspaceName: bundle.workspace.name })))
    const files: EnvFileResult[] = []
    for (const env of envs) {
      const { text, variables, missing } = envFileText(bundle, project, env)
      const path = join(dir, `${env.name}.env`)
      const bytes = utf8(text)
      await writeNewFile(path, bytes)
      bytes.fill(0)
      files.push({ env: env.name, path, variables, missing })
    }
    projects.push({ slug: project.slug, manifest, files })
  }
  return { id: bundle.id, workspace: bundle.workspace, exportedAt: bundle.exportedAt, dir: base, projects, skipped }
}
