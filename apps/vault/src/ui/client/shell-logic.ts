// The workspace tab's identity and what it may still do, with no DOM, so the
// server tests can check it. A workspace page boots with the origin, the
// account and the workspace (id, slug, name) the server authenticated; every
// cache key carries all of them, a response that arrives after the tab's
// generation moved on is dropped, and once another tab reports a sign-out or
// a different account, or the page leaves for the back-forward cache, this
// tab refuses every further call before anything is sent. Nothing unlocks a
// stale tab: only a fresh page from the server does. The server stays the
// authority: this only stops a stale tab acting on stale screens.

import type { ApiError } from "@mehen/protocol/api"
import { spellCardText } from "../../relay/spelling.ts"

export const SHELL_CHANNEL = "mehen-shell"

// Sent on every workspace call; the prefix refuses a request whose header
// names another workspace than the one its path resolves to.
export const WORKSPACE_HEADER = "Mehen-Workspace"

export type ShellIdentity = {
  origin: string
  account: string
  workspace: { id: string; slug: string; name: string }
  // Workspace pages and reads the server serves, for links and the palette.
  pages: readonly string[]
  reads: readonly string[]
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value !== ""
}

function strings(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((v) => typeof v === "string") ? (value as string[]) : null
}

// The boot payload's `shell`, or null when the page is not a workspace page
// or the payload is malformed. A payload for another origin is refused: the
// tab would otherwise key its caches by an origin it is not on.
export function readShellIdentity(raw: unknown, pageOrigin: string): ShellIdentity | null {
  if (typeof raw !== "object" || raw === null) return null
  const shell = raw as Record<string, unknown>
  const workspace = shell.workspace as Record<string, unknown> | null | undefined
  const pages = strings(shell.pages)
  const reads = strings(shell.reads)
  if (!isString(shell.origin) || shell.origin !== pageOrigin || !isString(shell.account) || pages === null || reads === null) return null
  if (typeof workspace !== "object" || workspace === null || !isString(workspace.id) || !isString(workspace.slug) || typeof workspace.name !== "string") return null
  return { origin: shell.origin, account: shell.account, workspace: { id: workspace.id, slug: workspace.slug, name: workspace.name }, pages, reads }
}

export type ShellMessage = { kind: "account"; origin: string; account: string } | { kind: "signed-out"; origin: string }

export function parseShellMessage(data: unknown): ShellMessage | null {
  if (typeof data !== "object" || data === null) return null
  const m = data as Record<string, unknown>
  if (m.kind === "signed-out" && isString(m.origin)) return { kind: "signed-out", origin: m.origin }
  if (m.kind === "account" && isString(m.origin) && isString(m.account)) return { kind: "account", origin: m.origin, account: m.account }
  return null
}

// "restored": the page went into the back-forward cache, so whoever is
// signed in now is unknown; it reloads rather than trusting what it shows.
export type StaleReason = "signed-out" | "account-changed" | "restored"

// "Personal (alex) at https://app.mehen.dev": names repeat, the slug and
// origin say which. The name is spelled, so a direction override or a
// control character shows as its marker and cannot reorder the rest.
export function workspaceWords(identity: Pick<ShellIdentity, "origin" | "workspace">): string {
  return `${spellCardText(identity.workspace.name)} (${identity.workspace.slug}) at ${identity.origin}`
}

export function workspacePath(identity: Pick<ShellIdentity, "workspace">, path = "/"): string {
  return `/w/${encodeURIComponent(identity.workspace.slug)}${path}`
}

// The refusal a stale tab shows, worded by why it went stale.
export function staleRefusal(identity: ShellIdentity, reason: StaleReason): ApiError {
  const where = workspaceWords(identity)
  switch (reason) {
    case "signed-out":
      return { error: "unauthenticated", message: `This tab is out of date: you signed out in another tab. It still shows ${where}.`, next: { url: `/signin?next=${encodeURIComponent(workspacePath(identity))}`, say: "Nothing was sent. Sign in again, then carry on from the workspace's page." } }
    case "account-changed":
      return { error: "conflict", message: `This tab is out of date: another account signed in to this browser. It still shows ${where} as the account that opened it.`, next: { url: "/", say: "Nothing was sent. Reload to carry on as the account signed in now." } }
    case "restored":
      return { error: "conflict", message: `This tab is out of date: it was put away and brought back, so it reloads before showing ${where} again.`, next: { url: workspacePath(identity), say: "Nothing was sent. The page reloads as whoever is signed in now." } }
  }
}

export type CallStart = { ok: true; generation: number } | { ok: false; refusal: ApiError }

export class ShellState {
  readonly identity: ShellIdentity
  private generation = 0
  private reason: StaleReason | null = null
  private readonly cache = new Map<string, unknown>()

  constructor(identity: ShellIdentity) {
    this.identity = identity
  }

  // Origin, account, workspace id and path: two workspaces, two accounts or
  // two origins with the same ids never share an entry.
  cacheKey(path: string): string {
    return JSON.stringify([this.identity.origin, this.identity.account, this.identity.workspace.id, path])
  }

  // The prefixed API path for a workspace read or action.
  apiPath(path: string): string {
    return `/api/w/${encodeURIComponent(this.identity.workspace.slug)}${path}`
  }

  get stale(): StaleReason | null {
    return this.reason
  }

  refusal(): ApiError | null {
    return this.reason === null ? null : staleRefusal(this.identity, this.reason)
  }

  // Drops every cached response and every call still in flight.
  clear(): void {
    this.generation += 1
    this.cache.clear()
  }

  markStale(reason: StaleReason): void {
    if (this.reason === null) this.reason = reason
    this.clear()
  }

  // A message from another tab. True when it made this tab stale.
  receive(message: ShellMessage | null): boolean {
    if (message === null || message.origin !== this.identity.origin || this.reason !== null) return false
    if (message.kind === "signed-out") this.markStale("signed-out")
    else if (message.account !== this.identity.account) this.markStale("account-changed")
    return this.reason !== null
  }

  // Before a call: refused outright once stale, so nothing is sent.
  begin(): CallStart {
    const refusal = this.refusal()
    return refusal === null ? { ok: true, generation: this.generation } : { ok: false, refusal }
  }

  // After a call: a response from before a generation bump is discarded.
  settle(generation: number): ApiError | null {
    if (generation === this.generation && this.reason === null) return null
    return this.refusal() ?? { error: "conflict", message: `This answer arrived after the page moved on from ${workspaceWords(this.identity)}, so it was dropped.`, next: { say: "Try again." } }
  }

  cached<T>(path: string): T | undefined {
    return this.cache.get(this.cacheKey(path)) as T | undefined
  }

  // Stores a response only if no bump happened since its call began.
  remember(path: string, generation: number, value: unknown): boolean {
    if (this.settle(generation) !== null) return false
    this.cache.set(this.cacheKey(path), value)
    return true
  }
}
