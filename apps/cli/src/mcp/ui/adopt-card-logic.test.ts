import { describe, expect, test } from "bun:test"
import type { AdoptionStatus } from "@mehen/protocol/adopt"
import type { ScanReport } from "../../adopt/scan.ts"
import type { CallToolResult } from "./bridge.ts"
import { FOLDER_LIMIT, UNREAD_LIMIT, adoptCardView, adoptionStateFor, unreadSentence } from "./adopt-card-logic.ts"

const ok = (structuredContent: Record<string, unknown>): CallToolResult => ({ content: [{ type: "text", text: "..." }], structuredContent, isError: false })

function folder(name: string, secrets: number, config = 0): ScanReport["folders"][number] {
  return { folder: `/Users/sam/code/${name}`, category: "repo", home: "project", secrets, config, unknown: 0, unsupported: 0, stale: 0 }
}

// vault_adopt_scan's structuredContent is scanReport() as it is (adopt/scan.ts).
const report: ScanReport = {
  scan: "/Users/sam/.config/mehen/adopt/scan.json",
  files: 41,
  secrets: 23,
  distinct: 19,
  config: 30,
  unsupported: 4,
  folders: [folder("alpha", 1, 2), folder("billing-api", 9, 3), folder("web", 4), folder("zeta", 9)],
  errors: [{ path: "/Users/sam/old/exports/a.sh", lines: 3, first: 1, why: "not a KEY=value line" }],
  errorFiles: 86,
  unreadFolders: [
    { folder: "/Users/sam/old/exports", files: 85 },
    { folder: "/Users/sam/code/tmp", files: 1 },
  ],
  skipped: [{ path: "/Users/sam/code/link", why: "a symlink out of the root" }],
  skippedFiles: 3,
  next: { command: "mehen adopt plan --scan /Users/sam/.config/mehen/adopt/scan.json --json" },
}

// vault_adopt_status's structuredContent: the batch and its checked /b/ link.
const status = (over: Partial<AdoptionStatus> = {}): AdoptionStatus & { url: string | null } => ({
  adoption: "adp_mcp001",
  status: "open",
  expiresAt: "2026-11-03T12:00:00.000Z",
  machines: [{ device: "dev_x", name: "office", items: 2 }],
  url: "https://vault.example.com/w/acme/b/adp_mcp001",
  ...over,
})

describe("the scan", () => {
  test("counts, folders with the most secrets first, unread folders as sentences, skipped files and the next command", () => {
    expect(adoptCardView(ok(report))).toEqual({
      kind: "scan",
      figures: [
        { label: "files read", value: 41 },
        { label: "secrets", value: 23 },
        { label: "distinct values", value: 19 },
        { label: "config", value: 30 },
        { label: "unsupported", value: 4 },
      ],
      folders: [
        { folder: "/Users/sam/code/billing-api", home: "project", secrets: 9, config: 3 },
        { folder: "/Users/sam/code/zeta", home: "project", secrets: 9, config: 0 },
        { folder: "/Users/sam/code/web", home: "project", secrets: 4, config: 0 },
        { folder: "/Users/sam/code/alpha", home: "project", secrets: 1, config: 2 },
      ],
      moreFolders: 0,
      unread: ["85 files in /Users/sam/old/exports could not be read; move what they hold by hand", "1 file in /Users/sam/code/tmp could not be read; move what it holds by hand"],
      moreUnread: 0,
      skipped: 3,
      next: "mehen adopt plan --scan /Users/sam/.config/mehen/adopt/scan.json --json",
    })
    expect(unreadSentence("/Users/sam/x", 2)).toBe("2 files in /Users/sam/x could not be read; move what they hold by hand")
  })

  test("long lists are cut with how many more", () => {
    const many: ScanReport = { ...report, folders: Array.from({ length: FOLDER_LIMIT + 5 }, (_, i) => folder(`f${i}`, i)), unreadFolders: Array.from({ length: UNREAD_LIMIT + 2 }, (_, i) => ({ folder: `/Users/sam/u${i}`, files: 1 })) }
    const view = adoptCardView(ok(many))
    expect(view).toMatchObject({ moreFolders: 5, moreUnread: 2 })
    if (view.kind !== "scan") throw new Error("not a scan")
    expect(view.folders).toHaveLength(FOLDER_LIMIT)
    expect(view.folders[0]?.secrets).toBe(FOLDER_LIMIT + 4)
    expect(view.unread).toHaveLength(UNREAD_LIMIT)
  })
})

describe("the batch", () => {
  test("an open batch with its machines and its link", () => {
    expect(adoptCardView(ok(status()))).toEqual({
      kind: "status",
      adoption: "adp_mcp001",
      state: "open",
      expiresAt: "2026-11-03T12:00:00.000Z",
      machines: [{ name: "office", items: 2 }],
      created: [],
      moreCreated: 0,
      refused: [],
      moreRefused: 0,
      url: "https://vault.example.com/w/acme/b/adp_mcp001",
    })
  })

  test("an approved batch with what was created and what was refused, and why", () => {
    const view = adoptCardView(ok(status({ status: "approved", created: [{ ref: "a001", slug: "openai-billing-api" }], refused: [{ ref: "a002", reason: "slug taken" }] })))
    expect(view).toMatchObject({ kind: "status", state: "approved", created: ["openai-billing-api"], refused: [{ ref: "a002", reason: "slug taken" }] })
  })

  test("a link that is not https is not drawn, and an error or an unknown shape draws nothing", () => {
    expect(adoptCardView(ok({ ...status(), url: "javascript:alert(1)" }))).toMatchObject({ url: null })
    expect(adoptCardView(ok({ ...status(), url: null }))).toMatchObject({ url: null })
    expect(adoptCardView({ content: [], structuredContent: { error: "usage", message: "x", next: null }, isError: true })).toEqual({ kind: "none" })
    expect(adoptCardView(ok({ ...status(), status: "sideways" }))).toEqual({ kind: "none" })
    expect(adoptCardView(ok({ something: "else" }))).toEqual({ kind: "none" })
  })

  test("vault_ask_state's states as a batch's", () => {
    expect(["waiting", "done", "cancelled", "expired", "declined"].map(adoptionStateFor)).toEqual(["open", "approved", "cancelled", "expired", null])
  })
})
