// The Workspaces view with fixture data, for the console gallery
// (console-gallery.ts): the list in every filter, searched, a page with
// more, and unreadable; one workspace with its backups and restores, the
// restore checklist and forms open, frozen, a restore waiting, the only
// operator, and its object not answering. The fixtures are the console
// routes' own answer types.

import type { OperatorProposalView } from "@mehen/protocol/operator-proposals"
import type { OperatorWorkspaceDetail, OperatorWorkspaceList, OperatorWorkspaceRow } from "@mehen/protocol/operator-workspaces"
import type { ConsoleGalleryEntry } from "./console-gallery.ts"
import { operatorWorkspacePage, operatorWorkspacesPage } from "./pages/operator-workspaces.ts"
import type { AccountShell } from "./shell.ts"

const NOW = Date.parse("2026-10-29T18:30:00Z")
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()
const DAY = 24 * 60
const date = (days: number) => at(-days * DAY).slice(0, 10)

const ALEX = { account: "acc_4Hq9Tz2Lm7Vb1Nc8", name: "Alex Rae" }
const TOM = { account: "acc_7Tn2Qw5Er8Ty1Ui4", name: "Tom Barker" }
const PRIYA = { account: "acc_9Pr3Ya5Sh7Ma1Kx", name: "Priya Shah" }

const row = (overrides: Partial<OperatorWorkspaceRow>): OperatorWorkspaceRow => ({ kind: "workspace", id: "tn_Northwind8Qw2", slug: "northwind", name: "Northwind", status: "active", owners: [ALEX, PRIYA], members: 14, createdBy: ALEX, createdAt: at(-400 * DAY), ...overrides })
const ROWS: OperatorWorkspaceRow[] = [
  row({ id: "tn_Northwind4Lk9", slug: "northwind", name: "Northwind Office", status: "creating", owners: null, members: 1, createdBy: PRIYA, createdAt: at(-5) }),
  row({ id: "tn_Fernhill7Bv3x", slug: "fernhill", name: "Fernhill & Co <script>", status: "deleting", owners: [TOM], members: 3, createdBy: TOM, createdAt: at(-60 * DAY) }),
  row({}),
  row({ id: "tn_Personal2Zx5", slug: "alex", name: "Alex", owners: [ALEX], members: 1, createdAt: at(-500 * DAY) }),
]
const LIST: OperatorWorkspaceList = { filter: "all", q: "", workspaces: ROWS, next: "eyJhdCI6MSwiaWQiOiJ0bl94In0" }

const WORKSPACE: OperatorWorkspaceDetail["workspace"] = { id: "tn_Northwind8Qw2", slug: "northwind", name: "Northwind", status: "active", frozen: false, createdAt: at(-400 * DAY), createdBy: ALEX, deleteAfter: null, displayRevision: 4, slugs: [{ slug: "llev", retiredAt: at(-200 * DAY) }] }
const DETAIL: OperatorWorkspaceDetail = {
  you: ALEX.account,
  workspace: WORKSPACE,
  people: { owners: [ALEX, PRIYA], roles: { owner: 2, admin: 1, member: 9, guest: 2 }, joining: 1, unconfirmed: 1 },
  backups: {
    lastDump: { date: date(1), bytes: 482_113, sha256: "9f2c".repeat(16), rootVersion: 2, at: at(-DAY + 90) },
    lastFailure: null,
    dumps: [date(1), date(2), date(3), date(4), date(5), "2026-10-01", "2026-09-01"],
    restores: [{ id: "vri_3f9a1c7e5b2d4a8f9e1c3b5d7f9a1c3e", source: "pitr", target: at(-40 * DAY), actor: "operator:alex", state: "done", createdAt: at(-38 * DAY), completedAt: at(-38 * DAY + 50), error: null }],
  },
  restore: null,
  operators: 3,
  missing: [],
  events: [
    { id: "dpe_w2", at: at(-38 * DAY), kind: "workspace.restore", actor: `operator:${TOM.account}`, approver: `operator:${ALEX.account}`, target: WORKSPACE.id, details: { intent: "vri_3f9a1c7e5b2d4a8f9e1c3b5d7f9a1c3e" } },
    { id: "dpe_w1", at: at(-38 * DAY - 30), kind: "proposal.open", actor: `operator:${TOM.account}`, approver: null, target: WORKSPACE.id, details: { kind: "workspace.restore" } },
  ],
}
const RESTORE_OPEN: OperatorProposalView = { id: "opp_7Qw2Er4Ty6Ui8Op0", kind: "workspace.restore", target: WORKSPACE.id, targetName: "Northwind", params: { source: "pitr", target: at(-3 * 60) }, digest: "k2Lm9Pq4Rs7Tu1Vw3Xy5Za8Bc0De2Fg4Hi6Jk8Lm0N", proposedBy: TOM, proposedAt: at(-40), expiresAt: at(23 * 60 + 20), approvedBy: null, approvedAt: null, declinedBy: null, state: "open", closedAt: null, awaiting: "approval" }

export function operatorWorkspacesGallery(shell: AccountShell): ConsoleGalleryEntry[] {
  const group = "Operator: workspaces"
  return [
    { id: "operator-workspaces", group, title: "Workspaces: every workspace", note: "Newest first: name, slug, id, status, owners by name, members counted, who created it and when; the filters, search, and Older workspaces. A hostile name is spelled.", page: operatorWorkspacesPage(shell, LIST) },
    { id: "operator-workspaces-searched", group, title: "Workspaces: searched, nothing matches", note: "Said plainly, with what search takes.", page: operatorWorkspacesPage(shell, { filter: "active", q: "acme", workspaces: [], next: null }) },
    { id: "operator-workspaces-managed", group, title: "Workspaces: platform-managed", note: "By platform, never by subject; each opens its platform.", page: operatorWorkspacesPage(shell, { filter: "managed", q: "", next: null, workspaces: [{ kind: "managed", id: "tn_Managed4Rt8Yq", platform: { id: "plt_8kQw2Lm4Zp7Rt5Vx", slug: "globex", name: "Globex" }, status: "active", createdAt: at(-9 * DAY) }, { kind: "managed", id: "tn_Managed1Zx9Cv", platform: { id: "plt_8kQw2Lm4Zp7Rt5Vx", slug: "globex", name: "Globex" }, status: "purged", createdAt: at(-90 * DAY) }] }) },
    { id: "operator-workspaces-failed", group, title: "Workspaces: the list could not be read", note: "Said plainly, never an empty list.", page: operatorWorkspacesPage(shell, null) },
    { id: "operator-workspace", group, title: "One workspace", note: "Its facts, people by role with its owners named, backups and recent restores, its operator events; Freeze, and the restore checklist before both restore forms, open.", page: operatorWorkspacePage(shell, DETAIL), open: ["restore-pitr", "restore-dump"] },
    { id: "operator-workspace-frozen", group, title: "One workspace: frozen, a restore waiting, a dump failed", note: "No Freeze: only its owners unfreeze it. The restore waits for a second operator, approved on Operators.", page: operatorWorkspacePage(shell, { ...DETAIL, workspace: { ...WORKSPACE, frozen: true }, restore: RESTORE_OPEN, backups: { ...DETAIL.backups, lastFailure: { date: date(0), error: "too_large: the database is 120 MB, past the 100 MB a dump reads into memory.", attempts: 3 } } }) },
    { id: "operator-workspace-alone", group, title: "One workspace: the only operator", note: "Restore disabled with Needs a second operator; use the script. Freeze still offered: it needs one.", page: operatorWorkspacePage(shell, { ...DETAIL, operators: 1 }), open: ["restore-pitr"] },
    { id: "operator-workspace-unread", group, title: "One workspace: its object did not answer", note: "Whether it is frozen, its owners and the unconfirmed said as not read; no Freeze until it can be read. What the directory holds still shows.", page: operatorWorkspacePage(shell, { ...DETAIL, workspace: { ...WORKSPACE, frozen: null }, people: { ...DETAIL.people, owners: null, unconfirmed: null }, backups: { lastDump: null, lastFailure: null, dumps: [], restores: [] }, events: [] }) },
  ]
}
