// What the adopt card draws, from a vault_adopt_scan report (adopt/scan.ts
// ScanReport) or a vault_adopt_status result. Pure and DOM-free; only what
// the result holds is shown, and every field is read as untrusted data.

import type { CallToolResult } from "./bridge.ts"
import { openableUrl } from "./ask-card-logic.ts"

export const FOLDER_LIMIT = 12
export const UNREAD_LIMIT = 6
export const STATUS_LIST_LIMIT = 12

export type ScanFigure = { label: string; value: number }
export type ScanFolderRow = { folder: string; home: string; secrets: number; config: number }

export type ScanView = {
  kind: "scan"
  figures: ScanFigure[]
  folders: ScanFolderRow[]
  moreFolders: number
  unread: string[]
  moreUnread: number
  skipped: number
  next: string | null
}

export type AdoptionState = "open" | "approved" | "cancelled" | "expired"

export type StatusView = {
  kind: "status"
  adoption: string
  state: AdoptionState
  expiresAt: string | null
  machines: { name: string; items: number }[]
  created: string[]
  moreCreated: number
  refused: { ref: string; reason: string }[]
  moreRefused: number
  url: string | null
}

export type AdoptCardView = { kind: "none" } | ScanView | StatusView

export const ADOPTION_LABELS: Record<AdoptionState, string> = { open: "Waiting for you", approved: "Approved", cancelled: "Cancelled", expired: "Expired" }

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0
}

function list(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(record).filter((r): r is Record<string, unknown> => r !== null) : []
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

// "85 files in /Users/sam/code/old could not be read; move what they hold by hand".
export function unreadSentence(folder: string, files: number): string {
  return `${plural(files, "file", "files")} in ${folder} could not be read; move what ${files === 1 ? "it holds" : "they hold"} by hand`
}

function scanView(report: Record<string, unknown>): ScanView {
  const figures: ScanFigure[] = [
    { label: "files read", value: count(report.files) },
    { label: "secrets", value: count(report.secrets) },
    { label: "distinct values", value: count(report.distinct) },
    { label: "config", value: count(report.config) },
    { label: "unsupported", value: count(report.unsupported) },
  ]
  const folders = list(report.folders)
    .filter((f) => typeof f.folder === "string")
    .map((f) => ({ folder: f.folder as string, home: typeof f.home === "string" ? f.home : "", secrets: count(f.secrets), config: count(f.config) }))
    .sort((a, b) => b.secrets - a.secrets || a.folder.localeCompare(b.folder))
  const unread = list(report.unreadFolders)
    .filter((u) => typeof u.folder === "string" && count(u.files) > 0)
    .map((u) => unreadSentence(u.folder as string, count(u.files)))
  const next = record(report.next)
  return {
    kind: "scan",
    figures,
    folders: folders.slice(0, FOLDER_LIMIT),
    moreFolders: Math.max(folders.length - FOLDER_LIMIT, 0),
    unread: unread.slice(0, UNREAD_LIMIT),
    moreUnread: Math.max(unread.length - UNREAD_LIMIT, 0),
    skipped: count(report.skippedFiles),
    next: typeof next?.command === "string" ? next.command : null,
  }
}

const ADOPTION_STATES: readonly string[] = ["open", "approved", "cancelled", "expired"]

function statusView(status: Record<string, unknown>): StatusView {
  const created = list(status.created)
    .filter((c) => typeof c.slug === "string")
    .map((c) => c.slug as string)
  const refused = list(status.refused)
    .filter((r) => typeof r.ref === "string")
    .map((r) => ({ ref: r.ref as string, reason: typeof r.reason === "string" ? r.reason : "" }))
  const url = typeof status.url === "string" && openableUrl(status.url) ? status.url : null
  return {
    kind: "status",
    adoption: status.adoption as string,
    state: status.status as AdoptionState,
    expiresAt: typeof status.expiresAt === "string" ? status.expiresAt : null,
    machines: list(status.machines).map((m) => ({ name: typeof m.name === "string" ? m.name : typeof m.device === "string" ? m.device : "a machine", items: count(m.items) })),
    created: created.slice(0, STATUS_LIST_LIMIT),
    moreCreated: Math.max(created.length - STATUS_LIST_LIMIT, 0),
    refused: refused.slice(0, STATUS_LIST_LIMIT),
    moreRefused: Math.max(refused.length - STATUS_LIST_LIMIT, 0),
    url,
  }
}

export function adoptCardView(result: CallToolResult): AdoptCardView {
  if (result.isError === true) return { kind: "none" }
  const structured = record(result.structuredContent)
  if (!structured) return { kind: "none" }
  if (typeof structured.adoption === "string" && typeof structured.status === "string" && ADOPTION_STATES.includes(structured.status)) return statusView(structured)
  if (Array.isArray(structured.folders) && typeof structured.files === "number") return scanView(structured)
  return { kind: "none" }
}

export function itemsText(n: number): string {
  return plural(n, "item", "items")
}

export function adoptionStateFor(askState: string): AdoptionState | null {
  if (askState === "waiting") return "open"
  if (askState === "done") return "approved"
  if (askState === "cancelled" || askState === "expired") return askState
  return null
}
