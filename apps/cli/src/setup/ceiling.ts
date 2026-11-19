// What setup writes into the `env` of the one `mehen` entry it registers.
//
//
// The effective ceiling is the inherited MEHEN_WORKSPACES narrowed by
// `--workspaces a,b`. A new entry carries it in MEHEN_WORKSPACES whenever it
// is restricted (an unrestricted ceiling is the key left out), as tn_ ids
// for the active slots it admits, origin-prefixed when the root holds more
// than one origin, and as slugs for a pending or absent workspace. Every
// value written is checked against the inherited ceiling: setup never
// writes an entry wider than the process it runs in.
// MEHEN_HOME is written when the root is not the default one.

import { join, resolve } from "node:path"
import type { VaultFileOptions } from "../agent-profiles.ts"
import type { Env } from "../config.ts"
import { CliError, usageError } from "../errors.ts"
import { managedHost, originKey, resolveHome, rootAboveSlot } from "../home.ts"
import { type CeilingEntry, type FoundActive, type FoundPending, listSlots, readCeiling, resolveAllowed, workspaceNotAllowed } from "../slots.ts"

const WORKSPACE_ID = /^tn_[A-Za-z0-9]{8,40}$/

export type SetupCeiling = {
  // The resolved root of the process running setup.
  root: string
  // MEHEN_HOME to write, or null for the default root.
  home: string | null
  // MEHEN_WORKSPACES entries to write, or null when unrestricted.
  allowed: string[] | null
  // Allowed workspaces with no active slot in the root: absent or pending.
  unenrolled: string[]
  // Whether the root holds an active slot (setup's `next`).
  enrolled: boolean
  // Why a preserved MEHEN_WORKSPACES is wider than the effective ceiling,
  // or null when it is inside it.
  wider(preserved: string): string | null
}

type Usable = FoundActive | FoundPending

// Setup cannot write a managed host's pin into an entry (rule 0): the
// owner provisions a managed agent's MCP entry.
export function managedSetupRefused(): CliError {
  return new CliError("workspace_mismatch", "This host is managed: mehen setup cannot write the owner's pin into an agent's MCP entry, so it wrote nothing.", {
    say: "Ask the host's owner to provision the agent's MCP entry from its pin; on a managed host nothing else registers a server.",
  })
}

function text(entry: { origin: string | null; selector: string }): string {
  return entry.origin === null ? entry.selector : `${entry.origin}/${entry.selector}`
}

function entryOf(value: string): CeilingEntry {
  return (readCeiling({ MEHEN_WORKSPACES: value }) as CeilingEntry[])[0] as CeilingEntry
}

// The slots an entry admits today.
function matchesOf(usable: Usable[], entry: CeilingEntry): Usable[] {
  return usable.filter((slot) => resolveAllowed([slot], [entry]).slots.length === 1)
}

// Is `entry` inside `ceiling` (null: unrestricted)? Every slot it admits
// today must be admitted by the ceiling; a tn_ id that names an admitted
// active slot is exact; a slug, or an id that names nothing yet, could
// admit a slot that appears later, so the ceiling must spell it too (same
// selector, at its origin or at any).
function inside(usable: Usable[], entry: CeilingEntry, ceiling: CeilingEntry[] | null): boolean {
  if (ceiling === null) return true
  const admitted = new Set(ceiling.flatMap((c) => matchesOf(usable, c)).map((slot) => slot.dir))
  const matches = matchesOf(usable, entry)
  if (!matches.every((slot) => admitted.has(slot.dir))) return false
  if (WORKSPACE_ID.test(entry.selector) && matches.length > 0) return true
  return ceiling.some((c) => c.selector === entry.selector && (c.origin === null || c.origin === entry.origin))
}

function list(ceiling: CeilingEntry[]): string {
  return ceiling.length === 0 ? "nothing" : ceiling.map((e) => e.text).join(", ")
}

// The ceiling `--workspaces` asks for: undefined when not given; null for `*`.
function requestedCeiling(workspaces: string | null): CeilingEntry[] | null | undefined {
  if (workspaces === null) return undefined
  return readCeiling({ MEHEN_WORKSPACES: workspaces })
}

// The env setup writes, resolved once against the slots in the root.
// Refuses (writing nothing) when `--workspaces` reaches outside the
// inherited ceiling, on a managed host, and wherever every command
// refuses: a retired MEHEN_CONFIG_DIR, a bare entry at two origins.
export async function resolveSetupCeiling(env: Env, home: string, workspaces: string | null, files: VaultFileOptions = {}): Promise<SetupCeiling> {
  if (managedHost(files)) throw managedSetupRefused()
  const { root } = resolveHome({ ...env, HOME: home }, { files })
  const found = await listSlots(root)
  const usable = found.filter((f): f is Usable => f.state !== "corrupt")
  const origins = new Set(usable.map((slot) => (slot.state === "active" ? slot.config.vault : slot.record.origin)))
  const inherited = readCeiling(env)
  resolveAllowed(found, inherited)
  const requested = requestedCeiling(workspaces)
  if (requested === null && inherited !== null) throw workspaceNotAllowed("--workspaces *", inherited)
  if (requested) resolveAllowed(found, requested)
  const effective = requested === undefined ? inherited : requested
  const allowed: string[] = []
  const unenrolled: string[] = []
  if (effective !== null) {
    const add = (value: string, from: CeilingEntry) => {
      if (!inside(usable, entryOf(value), inherited)) throw workspaceNotAllowed(`--workspaces entry ${from.text}`, inherited ?? [])
      if (!allowed.includes(value)) allowed.push(value)
    }
    for (const entry of effective) {
      const matches = matchesOf(usable, entry)
      if (matches.length === 0) {
        add(text(entry), entry)
        if (!unenrolled.includes(entry.selector)) unenrolled.push(entry.selector)
        continue
      }
      for (const slot of matches) {
        if (slot.state === "active") {
          add(origins.size > 1 ? `${originKey(slot.config.vault)}/${slot.config.tenant}` : slot.config.tenant, entry)
          continue
        }
        // A pending slot has no id yet: its slug, at its origin unless the
        // bare slug is exactly as narrow (one origin, and so written above).
        const prefixed = `${originKey(slot.record.origin)}/${slot.slug}`
        const bare = origins.size <= 1 && entry.origin === null && inside(usable, entryOf(slot.slug), inherited)
        add(bare ? slot.slug : prefixed, entry)
        if (!unenrolled.includes(slot.slug)) unenrolled.push(slot.slug)
      }
    }
  }
  return {
    root,
    home: root === resolve(join(home, ".config", "mehen")) ? null : root,
    allowed: effective === null ? null : allowed,
    unenrolled,
    enrolled: usable.some((slot) => slot.state === "active"),
    wider(preserved: string): string | null {
      if (effective === null) return null
      let entries: CeilingEntry[] | null
      try {
        entries = readCeiling({ MEHEN_WORKSPACES: preserved })
      } catch {
        return `its MEHEN_WORKSPACES=${JSON.stringify(preserved)} is not a list of workspaces`
      }
      if (entries === null) return `its MEHEN_WORKSPACES=${JSON.stringify(preserved)} allows every workspace, but this setup may allow only ${list(effective)}`
      const outside = entries.find((e) => !inside(usable, e, effective))
      return outside ? `its MEHEN_WORKSPACES entry ${outside.text} is outside what this setup may allow (${list(effective)})` : null
    },
  }
}

// --print: the env the entry is rendered with, from the environment
// alone. The managed-host marker is the one read; the root and the
// ceiling are taken as typed, never resolved against the slots.
export function printCeiling(env: Env, home: string, workspaces: string | null, files: VaultFileOptions = {}): { home: string | null; allowed: string[] | null } {
  if (managedHost(files)) throw managedSetupRefused()
  if (env.MEHEN_MANAGED_CONTEXT) {
    throw new CliError("workspace_mismatch", "The launcher claims a managed context (MEHEN_MANAGED_CONTEXT), but this host has no managed-host marker.", {
      say: "Unset MEHEN_MANAGED_CONTEXT, or ask the owner to provision this host as managed.",
    })
  }
  const named = (name: "MEHEN_HOME" | "MEHEN_CONFIG_DIR"): string | null => {
    const value = env[name]
    if (!value) return null
    if (value.includes("\0") || !value.startsWith("/")) throw usageError(`${name} must be an absolute path.`)
    return resolve(value)
  }
  const explicit = named("MEHEN_HOME")
  const alias = named("MEHEN_CONFIG_DIR")
  if (explicit !== null && alias !== null && explicit !== alias) throw new CliError("config_dir_retired", `MEHEN_HOME (${explicit}) and MEHEN_CONFIG_DIR (${alias}) disagree.`, { say: "Set MEHEN_HOME only; unset MEHEN_CONFIG_DIR." })
  const slot = alias === null ? null : rootAboveSlot(alias)
  if (slot) throw new CliError("config_dir_retired", `MEHEN_CONFIG_DIR ${alias} names a slot, not a config root.`, { say: `Set MEHEN_HOME=${slot.root} instead; MEHEN_CONFIG_DIR is only an alias of the root now.` })
  const root = explicit ?? alias ?? resolve(join(home, ".config", "mehen"))
  const typed = (value: string | undefined): string[] | null => {
    if (value === undefined || readCeiling({ MEHEN_WORKSPACES: value }) === null) return null
    return value.split(",").map((piece) => piece.trim()).filter((piece) => piece !== "")
  }
  const inherited = typed(env.MEHEN_WORKSPACES)
  const requested = workspaces === null ? undefined : typed(workspaces)
  if (requested !== undefined && inherited !== null) {
    const outside = requested === null ? "*" : requested.find((entry) => !inherited.includes(entry))
    if (outside !== undefined) throw workspaceNotAllowed(`--workspaces entry ${outside}`, readCeiling(env) ?? [])
  }
  return { home: root === resolve(join(home, ".config", "mehen")) ? null : root, allowed: requested === undefined ? inherited : requested }
}
