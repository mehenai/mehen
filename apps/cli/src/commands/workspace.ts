// mehen workspace: the slots on this machine.
//
//   list      every slot in the allowed set, pending and corrupt ones
//             included, and every absent ceiling entry: no network unless --check
//   show      the slot the current directory selects, and why
//   forget    retire one slot locally (no network): `forget <slug or id>`
//             or `forget --slot <path>`
//   bind      record the checkout's workspace and vault in mehen.toml
//
// `workspace default` is gone: there is no default. Nothing here
// shares, invites or changes a workspace: those are a human's decisions in
// the browser. bind trusts only slots already enrolled on this machine, and
// never an origin a repository or a server suggests.

import { lstat, readdir, rm } from "node:fs/promises"
import { userInfo } from "node:os"
import { readFileSync, writeFileSync } from "node:fs"
import { join, resolve, sep } from "node:path"
import { EXIT, type NextStep, type Project } from "@mehen/protocol/api"
import type { WorkspaceRef } from "@mehen/protocol/workspace"
import { parseArgs } from "../args.ts"
import { type Config, type Env, configWorkspace, workspaceLabel } from "../config.ts"
import { type CliErrorCode, CliError, toCliError, usageError } from "../errors.ts"
import { requestedBy } from "../ask.ts"
import { LOCKS_DIR, PENDING_DIR, WORKSPACES_DIR, managedHost, resolveHome } from "../home.ts"
import { noteBlock, printBlock, printJson, printLine } from "../output.ts"
import { segments } from "../tty.ts"
import { type ManifestWorkspace, manifestWorkspace } from "../run/manifest.ts"
import { openContext } from "../session.ts"
import { withSlotLocks } from "../slot-lock.ts"
import { type AbsentEntry, type ActiveSlot, type CorruptSlot, type EndedSlot, type FoundSlot, type LocalContext, type PendingSlot, type SelectionReason, allowedSlots, contextAmbiguous, contextMatches, insideCeiling, listActive, listSlots, readCeiling, resolveAllowed, selectSlot, slotView, workspaceNotAllowed, workspaceUnknown } from "../slots.ts"
import { type VaultCheck, absentEntry, slotCheck as checkSlot } from "./device.ts"
import { mutateSlot, publicKeyOnDisk } from "./activate.ts"
import { VaultApiError } from "../vault-api.ts"

export const WORKSPACE_SUMMARY = "list, show, forget or bind a checkout to this machine's workspaces (mehen workspace list|show|forget|bind)"

const USAGE = "mehen workspace list [--check] | show | forget (<slug or id> | --slot <path>) | bind"

export const WORKSPACE_HELP = [
  `usage: ${USAGE}`,
  `  ${WORKSPACE_SUMMARY}`,
  "",
  "examples:",
  "  mehen workspace list --json",
  "  mehen workspace show",
  "  mehen workspace forget acme",
  "  mehen workspace bind",
  "",
  "  list shows every workspace slot on this machine (active, pending, ended with the key kept, corrupt, and MEHEN_WORKSPACES entries not enrolled yet) without talking to the vault; --check asks each vault whether the enrolment still works and records a renamed workspace's new slug and name.",
  "  show says which workspace --workspace, MEHEN_WORKSPACE, the checkout's mehen.toml or the only enrolment picks here, and why.",
  "  forget retires one slot on this machine only (its key, config and ledger, or a pending enrolment); the device stays on the Machines page until an owner revokes it. --slot <path> names a duplicate or unreadable slot.",
  "  bind finds which enrolled workspace holds the checkout's project and writes workspace and vault into mehen.toml; it refuses when none or several do.",
  "  --json prints one JSON object per line on stdout, errors included. More: mehen guide.",
].join("\n")

// The published shapes; VaultCheck is status's (device.ts).
export type { VaultCheck } from "./device.ts"
export type ListAll = { home: string; allowed: string[] | null; workspaces: ((ActiveSlot & { check?: VaultCheck }) | PendingSlot | CorruptSlot | EndedSlot | AbsentEntry)[] }
export type WorkspaceShow = { slot: string | null; reason: SelectionReason; workspace: WorkspaceRef | null; origin: string | null; device: string | null; manifest: { path: string; workspace: string | null; vault: string | null } | null }
export type ForgetResult = { forgotten: true; slot: string; state: "active" | "pending" | "corrupt" | "ended"; device: string | null; enrolment: string | null; note: string }

// One string per row: each is printed as one segment, so a line break
// inside a recorded name is spelled out rather than starting a row.
function entryLines(entry: ListAll["workspaces"][number]): string[] {
  switch (entry.state) {
    case "active": {
      const where = entry.workspace.slug && entry.workspace.name ? `${entry.workspace.name} (${entry.workspace.slug}, ${entry.workspace.id})` : entry.workspace.id
      const owner = entry.owner ? `, owned by ${entry.owner.name}${entry.owner.kind === "team" ? " (team)" : ""}` : ""
      const check = entry.check ? (entry.check.ok ? "  [ok]" : `  [${entry.check.error}: ${entry.check.message}]`) : ""
      return [`  ${where} at ${entry.origin}: ${entry.device}${owner}`, `      ${entry.slot}${check}`]
    }
    case "pending":
      return [`  ${entry.intent.workspace} at ${entry.origin}: enrolment ${entry.enrolment} waiting for approval${entry.legacy ? " (from before this version; never renewed)" : ""}`, `      ${entry.slot}`, `      then: mehen wait ${entry.enrolment}`]
    case "corrupt":
      return [`  corrupt (${entry.reason}): ${entry.detail}`, `      ${entry.slot}`, `      next: ${entry.next.say}`]
    case "ended":
      return [`  ${entry.slug}: the enrolment attempt ended; the key is kept`, `      ${entry.slot}`, `      next: ${entry.next.say}`]
    case "absent":
      return [`  ${entry.entry}: allowed, not enrolled`, `      next: ${entry.next.say}`]
  }
}

async function list(env: Env, json: boolean, check: boolean): Promise<number> {
  const device = requestedBy(env).device
  let body: ListAll
  if (managedHost()) {
    const selected = await selectSlot(env, { manifest: null })
    const views: ListAll["workspaces"] = []
    if (selected.config) {
      const view = await slotView({ state: "active", dir: selected.dir, config: selected.config }, device)
      views.push(view.state === "active" && check ? { ...view, check: await checkSlot(env, { dir: selected.dir, config: selected.config }, { refreshNames: true }) } : view)
    }
    body = { home: resolveHome(env).root, allowed: null, workspaces: views }
  } else {
    const allowed = await allowedSlots(env)
    const views: ListAll["workspaces"] = []
    for (const found of [...allowed.slots, ...allowed.corrupt] as FoundSlot[]) {
      const view = await slotView(found, device)
      if (view.state === "active" && check && found.state === "active") views.push({ ...view, check: await checkSlot(env, { dir: found.dir, config: found.config }, { refreshNames: true }) })
      else views.push(view)
    }
    for (const entry of allowed.absent) views.push(absentEntry(entry.text, entry.selector))
    body = { home: allowed.root, allowed: allowed.ceiling ? allowed.ceiling.map((e) => e.text) : null, workspaces: views }
  }
  if (json) {
    printJson(body)
    return EXIT.ok
  }
  if (body.workspaces.length === 0) {
    printLine("No workspace is enrolled on this machine. Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page.")
    return EXIT.ok
  }
  for (const entry of body.workspaces) for (const line of entryLines(entry)) printLine(segments(line))
  return EXIT.ok
}

const REASONS: Record<SelectionReason, string> = {
  ledger: "it alone records the ask being waited on",
  managed: "this host is managed and the launcher's pin names it",
  workspace: "--workspace or MEHEN_WORKSPACE names it",
  manifest: "the checkout's mehen.toml names its workspace",
  only: "it is the only workspace this machine (or MEHEN_WORKSPACES) allows",
  none: "nothing is enrolled here yet",
}

async function show(env: Env, json: boolean): Promise<number> {
  const manifest = manifestWorkspace(process.cwd())
  const selected = await selectSlot(env, { manifest })
  const config = selected.config
  const body: WorkspaceShow = {
    slot: config ? selected.dir : null,
    reason: selected.reason,
    workspace: config ? configWorkspace(config) : null,
    origin: config?.vault ?? null,
    device: config?.device ?? null,
    manifest: manifest ? { path: manifest.path, workspace: manifest.workspace, vault: manifest.vault } : null,
  }
  if (json) {
    printJson(body)
    return EXIT.ok
  }
  if (config) {
    printLine(segments(`${selected.dir}: ${workspaceLabel(config)} at ${config.vault} as ${config.device}`))
    printLine(`  because ${REASONS[selected.reason]}`)
  } else printLine("No workspace is selected: this machine is not enrolled in one yet. Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page.")
  if (manifest) printLine(`  mehen.toml: ${manifest.path}${manifest.workspace ? ` (workspace ${manifest.workspace}${manifest.vault ? ` at ${manifest.vault}` : ""})` : " (no workspace recorded; mehen workspace bind writes one)"}`)
  return EXIT.ok
}

function refuseManaged(what: string): void {
  if (managedHost()) {
    throw new CliError("workspace_mismatch", `This host is managed: ${what} is decided by the launcher's pin, not here.`, { say: "On a managed host the owner's pin selects the workspace; its owner changes the slots." })
  }
}

// --slot <path>: inside <root>/workspaces/<o>/ or <root>/pending/<o>/, two
// levels down, each a real directory this user owns.
async function slotByPath(root: string, raw: string): Promise<{ dir: string; kind: "workspaces" | "pending"; origin: string; name: string }> {
  const dir = resolve(raw)
  const refuse = (why: string) => usageError(`--slot ${raw} ${why}; it must be a slot directory under ${join(root, WORKSPACES_DIR)} or ${join(root, PENDING_DIR)}.`, "mehen workspace --help")
  const relative = dir.startsWith(root + sep) ? dir.slice(root.length + 1).split(sep) : null
  if (!relative || relative.length !== 3 || (relative[0] !== WORKSPACES_DIR && relative[0] !== PENDING_DIR)) throw refuse("is not a slot of this root")
  const uid = userInfo().uid
  for (const path of [join(root, relative[0] as string), join(root, relative[0] as string, relative[1] as string), dir]) {
    let info: Awaited<ReturnType<typeof lstat>>
    try {
      info = await lstat(path)
    } catch {
      throw refuse("does not exist")
    }
    if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== uid) throw refuse(`passes through ${path}, which is a link, not a directory, or not this user's`)
  }
  return { dir, kind: relative[0] as "workspaces" | "pending", origin: relative[1] as string, name: relative[2] as string }
}

// The directory forget selected, by identity rather than path:
// its device and inode, and what is in it (each entry's name, type, inode,
// size and modification time, read with lstat; no file is opened). A
// directory removed and made again, or rewritten in place, differs.
type SlotIdentity = { dev: number; ino: number; contents: string }

async function slotIdentity(dir: string): Promise<SlotIdentity | null> {
  try {
    const info = await lstat(dir)
    if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== userInfo().uid) return null
    const entries: string[] = []
    for (const name of (await readdir(dir)).sort()) {
      const entry = await lstat(join(dir, name))
      entries.push(`${name}:${entry.isFile() ? "f" : entry.isDirectory() ? "d" : entry.isSymbolicLink() ? "l" : "o"}:${entry.ino}:${entry.size}:${entry.mtimeMs}`)
    }
    return { dev: info.dev, ino: info.ino, contents: entries.join("/") }
  } catch {
    return null
  }
}

function sameIdentity(a: SlotIdentity | null, b: SlotIdentity | null): boolean {
  return a !== null && b !== null && a.dev === b.dev && a.ino === b.ino && a.contents === b.contents
}

// The slot as selected and as found again under the lock: the same
// directory, the same state, and for a pending slot the same attempt (id
// and key), for a corrupt one the same reason and detail.
function sameSlot(seen: FoundSlot, now: FoundSlot | undefined): boolean {
  if (!now || now.state !== seen.state) return false
  if (seen.state === "pending" && now.state === "pending") return now.record.id === seen.record.id && now.record.jwk.x === seen.record.jwk.x && now.record.jwk.y === seen.record.jwk.y
  if (seen.state === "corrupt" && now.state === "corrupt") return now.reason === seen.reason && now.detail === seen.detail
  return false
}

// Under the slot's lock, immediately before anything is removed: is the
// slot still inside the effective ceiling, by a fresh discovery of the root
//? A display refresh can change an active slot's slug while its
// device and key stay; the earlier snapshot does not prove admission now.
async function assertStillAdmitted(env: Env, root: string, dir: string): Promise<void> {
  const ceiling = readCeiling(env)
  if (ceiling === null) return
  const now = resolveAllowed(await listSlots(root), ceiling)
  if (!now.slots.some((f) => f.dir === dir)) throw workspaceNotAllowed(`The slot ${dir}`, ceiling)
}

// A pending or corrupt slot: under its lock, re-read, then remove it whole.
async function retireUnderLock(env: Env, root: string, slot: FoundSlot, identity: SlotIdentity | null): Promise<"applied" | "superseded" | "gone"> {
  const parts = slot.dir.slice(root.length + 1).split(sep)
  const lock = join(root, LOCKS_DIR, parts[1] as string, `${parts[0] === WORKSPACES_DIR ? "active" : "pending"}-${parts[2]}.lock`)
  return withSlotLocks([lock], async () => {
    const now = (await listSlots(root)).find((f) => f.dir === slot.dir)
    if (!now) return "gone"
    if (!sameSlot(slot, now) || !sameIdentity(identity, await slotIdentity(slot.dir))) return "superseded"
    await assertStillAdmitted(env, root, slot.dir)
    await rm(slot.dir, { recursive: true, force: true })
    return "applied"
  })
}

async function forget(env: Env, json: boolean, selector: string | undefined, slotPath: string | null): Promise<number> {
  refuseManaged("retiring a workspace")
  if (selector === undefined && slotPath === null) throw usageError("mehen workspace forget needs a workspace slug or id, or --slot <path>.", "mehen workspace --help")
  const allowed = await allowedSlots(env)
  const root = allowed.root
  let target: FoundSlot | null = null
  if (selector !== undefined) {
    if (!insideCeiling(allowed, selector, null)) throw workspaceNotAllowed(`Workspace ${selector}`, allowed.ceiling ?? [])
    const matches = allowed.slots.filter((f) => (f.state === "active" ? contextMatches(f, selector) : f.record.intent.workspace === selector))
    if (matches.length === 0) throw workspaceUnknown(selector)
    if (matches.length > 1 && slotPath === null) {
      throw new CliError("context_ambiguous", `${selector} matches ${matches.length} slots on this machine: ${matches.map((m) => m.dir).join("; ")}.`, {
        command: `mehen workspace forget --slot ${matches[0]?.dir}`,
        say: "Name the one to retire with --slot <path>.",
      })
    }
    target = matches.length === 1 ? (matches[0] as FoundSlot) : null
  }
  if (slotPath !== null) {
    const named = await slotByPath(root, slotPath)
    const found = (await listSlots(root)).find((f) => f.dir === named.dir) ?? null
    if (!found) throw usageError(`--slot ${slotPath} is not a slot mehen recognises.`, "mehen workspace --help")
    if (target !== null && target.dir !== found.dir) throw usageError(`--slot ${slotPath} is not the slot ${selector} names (${target.dir}).`, "mehen workspace --help")
    if (selector !== undefined && target === null && !(found.state === "active" ? contextMatches(found, selector) : found.state === "pending" && found.record.intent.workspace === selector)) {
      throw usageError(`--slot ${slotPath} is not a slot of ${selector}.`, "mehen workspace --help")
    }
    target = found
  }
  const slot = target as FoundSlot
  // A path only says which slot; it never widens the ceiling. Under a
  // restricted MEHEN_WORKSPACES the target must be a slot of A; a corrupt
  // one, whose workspace cannot be established, is refused there.
  if (allowed.ceiling !== null && !allowed.slots.some((f) => f.dir === slot.dir)) {
    throw workspaceNotAllowed(`The slot ${slot.dir}`, allowed.ceiling)
  }
  // The retirement is a compare-and-mutate under the slot's lock: an active slot through mutateSlot, only while it still holds the
  // device and key seen here; a pending or corrupt one only while discovery
  // still finds the same attempt (or the same corrupt slot) at that path.
  // Admission is checked again inside the lock, against the slot as it is
  // now; the directory must be the one selected here, not one made again at
  // the same path.
  const changed = (result: "superseded" | "gone") =>
    new CliError("failed", `The slot ${slot.dir} changed while mehen looked at it${result === "superseded" ? ": another mehen process replaced it meanwhile" : ""}; nothing was removed.`, {
      command: "mehen workspace list",
      say: "Another mehen process changed this workspace's slot while this one ran; check `mehen workspace list`, then run the command again.",
    })
  const identity = await slotIdentity(slot.dir)
  const retired =
    slot.state === "active"
      ? await mutateSlot(slot.dir, { device: slot.config.device, jwk: await publicKeyOnDisk(slot.dir, slot.config.backend) }, async () => {
          const now = await slotIdentity(slot.dir)
          if (identity === null || now === null || now.dev !== identity.dev || now.ino !== identity.ino) throw changed("superseded")
          await assertStillAdmitted(env, root, slot.dir)
          return null
        })
      : await retireUnderLock(env, root, slot, identity)
  if (retired !== "applied") throw changed(retired)
  const device = slot.state === "active" ? slot.config.device : null
  const enrolment = slot.state === "pending" ? slot.record.id : null
  const note =
    slot.state === "active"
      ? `Device ${slot.config.device} was forgotten on this machine only; it stays on the workspace's Machines page until an owner revokes it.`
      : slot.state === "pending"
        ? `Enrolment ${slot.record.id} was forgotten on this machine; if someone approves its link now, the vault gets a device this machine cannot use, so reject it instead.`
        : slot.reason === "attempt_ended"
          ? "The ended enrolment attempt and its kept key were removed from this machine; the next enrol makes a new key. Nothing was sent to the vault."
          : "The corrupt slot was removed from this machine; nothing was sent to the vault."
  const result: ForgetResult = { forgotten: true, slot: slot.dir, state: slot.state === "corrupt" && slot.reason === "attempt_ended" ? "ended" : slot.state, device, enrolment, note }
  if (json) printJson(result)
  else printLine(`Forgot ${slot.dir}. ${note}`)
  return EXIT.ok
}

// The top-level `workspace` and `vault` keys of mehen.toml, replaced in
// place or inserted after `project`, before the first table. Every other
// byte of the file is kept.
export function bindManifestText(text: string, workspace: { id: string; slug: string | null; name: string | null }, vault: string): string {
  const comment = workspace.slug && workspace.name ? `  # workspace ${workspace.name.replace(/[\r\n]/g, " ")} (${workspace.slug}); the id prefix is historical` : ""
  const lines = text.split("\n")
  const firstTable = lines.findIndex((line) => /^\s*\[/.test(line))
  const top = firstTable === -1 ? lines.length : firstTable
  const keyLine = (key: string) => lines.slice(0, top).findIndex((line) => new RegExp(`^\\s*${key}\\s*=`).test(line))
  const replacements: [string, string][] = [["workspace", `workspace = ${JSON.stringify(workspace.id)}${comment}`], ["vault", `vault = ${JSON.stringify(vault)}`]]
  let insertAt = keyLine("project") + 1
  for (const [key, line] of replacements) {
    const at = keyLine(key)
    if (at !== -1) lines[at] = line
    else {
      lines.splice(insertAt, 0, line)
      insertAt += 1
    }
  }
  return lines.join("\n")
}

type Bound = { context: LocalContext; project: Project }

async function findProject(env: Env, context: LocalContext, project: string): Promise<Bound | null> {
  const session = await openContext(env, { ...context, reason: "workspace" })
  try {
    const found = await session.api.request<Project>("GET", `/v1/projects/${encodeURIComponent(project)}`)
    return found.id === project ? { context, project: found } : null
  } catch (error) {
    if (error instanceof VaultApiError && (error.body.error === "not_found" || error.body.error === "forbidden" || error.body.error === "project_unshared")) return null
    throw error
  }
}

async function bind(env: Env, json: boolean): Promise<number> {
  const manifest: ManifestWorkspace | null = manifestWorkspace(process.cwd())
  if (!manifest) throw usageError("No mehen.toml here: run `mehen workspace bind` inside a checkout that has one, or `mehen init` to create the project.", "mehen workspace --help")
  // The candidates are the allowed set's active slots; on a managed host
  // only the pinned one, explicitly.
  const candidates: LocalContext[] = await listActive(env)
  const found: Bound[] = []
  for (const context of candidates) {
    const bound = await findProject(env, context, manifest.project)
    if (bound) found.push(bound)
  }
  if (found.length === 0) {
    throw new CliError("workspace_unknown", `No workspace this machine is enrolled in holds project ${manifest.project}.`, {
      command: "mehen workspace list",
      say: "Enrol this machine in the project's workspace with `mehen enrol --workspace <slug>`, or ask the owner to share the project with this machine's owner.",
    })
  }
  if (found.length > 1) throw contextAmbiguous(manifest.project, found.map((b) => b.context))
  const { context } = found[0] as Bound
  const config: Config = context.config
  const workspace = { id: config.tenant, slug: config.workspaceSlug ?? null, name: config.workspaceName ?? null }
  const before = readFileSync(manifest.path, "utf8")
  const after = bindManifestText(before, workspace, config.vault)
  const changed = after !== before
  if (changed) writeFileSync(manifest.path, after)
  if (json) printJson({ bound: true, changed, path: manifest.path, project: manifest.project, workspace: configWorkspace(config) ?? { id: config.tenant }, vault: config.vault, slot: context.dir })
  else printLine(segments(`${changed ? "Bound" : "Already bound:"} ${manifest.path} to ${workspaceLabel(config)} at ${config.vault} (project ${manifest.project}).`))
  return EXIT.ok
}

export async function workspaceCommand(argv: string[], env: Env): Promise<number> {
  const args = parseArgs(argv, { usage: USAGE, flags: { check: { type: "boolean" }, slot: { type: "string" } }, positionals: { min: 0, max: 2 } })
  const [verb, selector] = args.positionals
  if (args.bool("help")) {
    printBlock(WORKSPACE_HELP)
    return EXIT.ok
  }
  // No verb: the help is the usage error, on stderr as for `mehen` alone.
  if (verb === undefined) {
    noteBlock(WORKSPACE_HELP)
    return EXIT.usage
  }
  const json = args.bool("json")
  const slot = args.string("slot")
  if (slot !== null && verb !== "forget") throw usageError(`--slot belongs to mehen workspace forget. Usage: ${USAGE}`, "mehen workspace --help")
  switch (verb) {
    case "list":
      if (selector !== undefined) throw usageError(`Usage: ${USAGE}`, "mehen workspace --help")
      return list(env, json, args.bool("check"))
    case "show":
      if (selector !== undefined) throw usageError(`Usage: ${USAGE}`, "mehen workspace --help")
      return show(env, json)
    case "forget":
      return forget(env, json, selector, slot)
    case "default":
      throw usageError("mehen workspace default is gone: there is no default workspace. Name one with --workspace <slug>, set MEHEN_WORKSPACE for a shell, or bind a checkout with `mehen workspace bind`.", "mehen workspace --help")
    case "bind":
      if (selector !== undefined) throw usageError(`Usage: ${USAGE}`, "mehen workspace --help")
      return bind(env, json)
    default:
      throw usageError(`Unknown mehen workspace verb ${JSON.stringify(verb)}.`, "mehen workspace --help")
  }
}
