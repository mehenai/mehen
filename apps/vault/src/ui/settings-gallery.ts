// The workspace settings page with fixture data, for scripts/ui-gallery.ts:
// its four rights states (an owner, a member, and each of them frozen), a
// guest, a read that failed, the Freeze confirm step open, the longest
// name and short name, backup keys as an owner and as an admin sees them,
// and how often Mehen asks: an owner at Let it work, a level picked that
// asks less and one that asks more while frozen, a member reading it, an
// owner frozen at Ask on writes, and the dial switched off. Nothing here is imported by the Worker.

import type { BackupRecipientView, BackupStatus } from "@mehen/protocol/backup"
import type { ApprovalDial, MembershipView, WorkspaceRole, WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { approvalDialSignsWords } from "./approval-dial-words.ts"
import { workspaceSettingsPage } from "./pages/workspace-settings.ts"
import type { WorkspacePageKey, WorkspaceShell } from "./shell.ts"
import { GALLERY_MEMBERSHIPS, GALLERY_ORIGIN, type ShellGalleryEntry } from "./shell-gallery.ts"

const PAGES: readonly WorkspacePageKey[] = ["home", "needs", "credentials", "projects", "machines", "people", "teams", "connect-agent", "audit", "settings", "asks"]
const ACCOUNT = "acc_4Hq9Tz2Lm7Vb1Nc8"
const NORTHWIND = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const LONG = { id: "tn_9qWe4Rt7Yu1Io3Pa", slug: "montgomery-fitzwilliam-office-consultant", name: "The Montgomery-Fitzwilliam household, office and consultancy co." }

function shell(role: WorkspaceRole, workspace: MembershipView["workspace"] = NORTHWIND): WorkspaceShell {
  const own: MembershipView = { workspace, member: "mem_alex0001", role, pendingRole: null, status: "active" }
  return {
    identity: { origin: GALLERY_ORIGIN, account: ACCOUNT, workspace },
    accountName: "Alex Rae",
    memberships: [own, ...GALLERY_MEMBERSHIPS.filter((m) => m.workspace.id !== workspace.id)],
    pages: PAGES,
    reads: ["/pending", "/items", "/devices", "/projects", "/settings"],
    accountPages: ["workspaces", "needs-you", "account"],
    accountHeld: false,
  }
}

// What GET /api/w/:ws/settings answers for each role, as the evaluator
// does: rename and unfreeze for an owner, freeze for anyone but a guest,
// and the approval dial either way for an owner or admin, never asking
// less while frozen.
function view(role: WorkspaceRole, frozen = false, level: ApprovalDial = "writes"): WorkspaceSettingsView {
  const elevated = role === "owner" || role === "admin"
  return { frozen, rights: { rename: role === "owner", freeze: role !== "guest", unfreeze: role === "owner" }, approvals: { level, askLess: elevated && !frozen && level !== "work", askMore: elevated && level !== "writes" } }
}

const page = (role: WorkspaceRole, frozen = false, workspace?: MembershipView["workspace"], level?: ApprovalDial) => workspaceSettingsPage(shell(role, workspace), { settings: view(role, frozen, level), role })
// The client's state once a level is picked: that radio checked, the line
// saying what is signed, and Save's label (the gallery shows every button
// enabled already).
function picked(from: ApprovalDial, to: ApprovalDial, less: boolean): [string, string][] {
  return [
    [`value="${from}" checked`, `value="${from}"`],
    [`value="${to}"`, `value="${to}" checked`],
    ['data-region="approvals-signs" hidden></p>', `data-region="approvals-signs">${approvalDialSignsWords(from, to, less)}</p>`],
    ['data-action="approvals-save">Save<', `data-action="approvals-save">${less ? "Save with passkey" : "Save"}<`],
  ]
}

const NOW = "2026-11-10T09:00:00.000Z"
const KEY = "age177alz07nqxguqq8swrxq5d3gfzrrhqzqgkhd4ddwpm2m52hk44qqgqryyulm"
function recipient(over: Partial<BackupRecipientView>): BackupRecipientView {
  return { id: "bkr_safe0001", recipient: KEY, fingerprint: "age177alz07n...gqryyulm", label: "1Password and the safe", status: "active", registrant: { member: "mem_alex0001", name: "Alex Rae" }, mine: true, registeredAt: "2026-10-01T09:00:00.000Z", activeAt: "2026-10-02T09:00:00.000Z", lastExport: { id: "bkx_k2m9q4", at: "2026-10-30T09:00:00.000Z", items: 41 }, changedSince: 14, rights: { export: true, remove: true }, ...over }
}
// What GET /api/w/:ws/backup/recipients answers: for the owner who added
// them, an active key whose last export is stale and a key still waiting
// out its day; for an admin, the same keys without export or remove.
export function backupsView(role: "owner" | "admin"): BackupStatus {
  const own = role === "owner"
  const others = { mine: false, lastExport: null, changedSince: null, rights: { export: false, remove: false } }
  return {
    recipients: [recipient(own ? {} : others), recipient({ id: "bkr_paper002", label: "Paper copy", status: "pending", registeredAt: "2026-11-10T08:00:00.000Z", activeAt: "2026-11-11T08:00:00.000Z", lastExport: null, changedSince: 55, rights: { export: false, remove: true }, ...(own ? {} : others) })],
    rights: { add: own },
    now: NOW,
  }
}

export const SETTINGS_GALLERY_IDS = ["ws-settings-owner", "ws-settings-member", "ws-settings-frozen-owner", "ws-settings-frozen-member", "ws-settings-guest", "ws-settings-unavailable", "ws-settings-freeze-confirm", "ws-settings-long", "ws-settings-backups-owner", "ws-settings-backups-admin", "ws-settings-approvals-work", "ws-settings-approvals-less", "ws-settings-approvals-more", "ws-settings-approvals-off"] as const

export function settingsGallery(): ShellGalleryEntry[] {
  return [
    { id: "ws-settings-owner", group: "Workspace settings", title: "Settings, owner", note: "Every right: the facts with the workspace id for mehen.toml, Name and short name with a passkey each, How often Mehen asks at Ask on writes with both levels offered, and Freeze as the quiet outline button in its red-edged card.", page: page("owner") },
    { id: "ws-settings-member", group: "Workspace settings", title: "Settings, member", note: "A member may only freeze: the facts say only an owner changes the name or short name, no rename forms are drawn, and How often Mehen asks is the level in a sentence with who can change it.", page: page("member") },
    { id: "ws-settings-frozen-owner", group: "Workspace settings", title: "Settings, frozen, owner", note: "Frozen: the alert leads with Read Activity first and Unfreeze with passkey in the widening style; Freeze is gone.", page: page("owner", true) },
    { id: "ws-settings-frozen-member", group: "Workspace settings", title: "Settings, frozen, member", note: "Frozen, seen by a member: ask an owner to unfreeze it; nothing to press.", page: page("member", true) },
    { id: "ws-settings-guest", group: "Workspace settings", title: "Settings, guest", note: "A guest has no right here: one sentence and nothing else.", page: page("guest") },
    { id: "ws-settings-unavailable", group: "Workspace settings", title: "Settings, read failed", note: "The settings read failed: the notice, and the machine's own freeze command.", page: workspaceSettingsPage(shell("owner"), { settings: null, role: "owner" }) },
    { id: "ws-settings-freeze-confirm", group: "Workspace settings", title: "Settings, Freeze pressed", note: "The confirm step the client shows: the consequence in full, then the one filled Freeze now and Cancel. No passkey.", page: page("member"), swap: [['data-region="freeze-start">', 'data-region="freeze-start" hidden>'], ['data-region="freeze-confirm" hidden>', 'data-region="freeze-confirm">']] },
    { id: "ws-settings-long", group: "Workspace settings", title: "Settings, the longest name and short name", note: "A 64-character name and a 40-character short name in the facts and the forms, at every width.", page: page("owner", false, LONG) },
    { id: "ws-settings-backups-owner", group: "Workspace settings", title: "Settings, backup keys, owner", note: "The owner's two keys: one active whose last export is over a week old with changes since, so the warning shows with Download an export, and one waiting out its day; then the add form with a passkey.", page: workspaceSettingsPage(shell("owner"), { settings: view("owner"), role: "owner", backups: backupsView("owner") }) },
    { id: "ws-settings-backups-admin", group: "Workspace settings", title: "Settings, backup keys, admin", note: "An admin sees every key, who added it and when it works, and nothing to press: only an owner adds or exports, and only the owner who added a key or another owner removes it.", page: workspaceSettingsPage(shell("admin"), { settings: view("admin"), role: "admin", backups: backupsView("admin") }) },
    { id: "ws-settings-approvals-work", group: "Workspace settings", title: "Settings, How often Mehen asks, Let it work", note: "An owner at Let it work: it is chosen, Ask on writes is offered (asking more needs no passkey), the lines say what Let it work never covers, and Save waits for a change.", page: page("owner", false, undefined, "work") },
    { id: "ws-settings-approvals-less", group: "Workspace settings", title: "Settings, How often Mehen asks, asking less picked", note: "Let it work picked from Ask on writes: the line says what the passkey signs, both levels, and Save with passkey is enabled.", page: page("admin"), swap: picked("writes", "work", true) },
    { id: "ws-settings-approvals-more", group: "Workspace settings", title: "Settings, How often Mehen asks, asking more picked, frozen", note: "Frozen at Let it work, an owner may still ask more: Ask on writes is picked, and the line says no passkey is needed.", page: page("owner", true, undefined, "work"), swap: picked("work", "writes", false) },
    { id: "ws-settings-approvals-off", group: "Workspace settings", title: "Settings, How often Mehen asks, switched off", note: "With the dial off or in a managed workspace the read carries no level: no card, and the lead does not mention it.", page: workspaceSettingsPage(shell("owner"), { settings: { frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }, role: "owner" }) },
  ]
}
