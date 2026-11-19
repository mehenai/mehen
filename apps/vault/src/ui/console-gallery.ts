// The consoles with fixture data, for scripts/ui-gallery.ts: the
// operator's list, register page (pasting a key, a key made in the
// browser and shown once, a refused paste, the ids handed over) and one
// platform in every status, with its forms and danger zone open, being
// removed and removed; a platform admin's list and platform, with its
// forms open, the last live key kept, the defaults refused and retired;
// the Operators view with one operator and with three, open proposals for
// each reader, and the operator role's acceptance card on Your account;
// the Audit view (filtered, paged, empty and refused filters) and the
// Settings view (with two operators, alone, and a proposal open); the
// Accounts view, searched and filtered, and one account in each state an
// operator acts on; the console links in a workspace's rail; and the
// Workspaces view (operator-workspaces-gallery.ts). The fixtures are the
// console routes' own answer types. Nothing here is imported by the Worker.

import type { OperatorAccountDetail, OperatorAccountList, OperatorAccountSummary } from "@mehen/protocol/operator-accounts"
import type { OperatorAuditEvent, OperatorAuditPage } from "@mehen/protocol/operator-audit"
import type { OperatorProposalView, OperatorView, OperatorsView } from "@mehen/protocol/operator-proposals"
import type { OperatorSettingsView } from "@mehen/protocol/operator-settings"
import type { AdminPlatformDetail, OperatorPlatformDetail, OperatorPlatformList, PlatformAdminView, PlatformEventPage, PlatformKeyView } from "@mehen/protocol/platform-console"
import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS } from "@mehen/protocol/platform"
import { PASTED_KEY_PROBLEMS } from "./client/platform-key-logic.ts"
import { escapeHtml } from "./html.ts"
import type { PageInput } from "./layout.ts"
import { accountPage } from "./pages/account.ts"
import { operatorAccountPage, operatorAccountsPage } from "./pages/operator-accounts.ts"
import { operatorAuditPage } from "./pages/operator-audit.ts"
import { operatorsPage } from "./pages/operator-operators.ts"
import { operatorSettingsPage } from "./pages/operator-settings.ts"
import { OPERATOR_PATH, operatorListPage, operatorPlatformPage, operatorRegisterPage } from "./pages/operator.ts"
import { adminListPage, adminPlatformPage } from "./pages/platform-admin.ts"
import { workspaceHomePage } from "./pages/workspaces.ts"
import { operatorWorkspacesGallery } from "./operator-workspaces-gallery.ts"
import { GALLERY_MEMBERSHIPS, GALLERY_ORIGIN, GALLERY_SESSION } from "./shell-gallery.ts"
import type { AccountShell, WorkspaceShell } from "./shell.ts"

const NOW = Date.parse("2026-10-29T18:30:00Z")
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()
const DAY = 24 * 60

const ACCOUNT = "acc_4Hq9Tz2Lm7Vb1Nc8"
const OPERATOR = `operator:${ACCOUNT}`

// The account shell of an account that is both the operator and an admin.
export const CONSOLE_ACCOUNT_SHELL: AccountShell = { origin: GALLERY_ORIGIN, account: ACCOUNT, name: "Alex Rae", accountPages: ["workspaces", "needs-you", "account", "operator", "platforms"] }
// An admin only: no Operator link.
const ADMIN_SHELL: AccountShell = { origin: GALLERY_ORIGIN, account: "acc_7Tn2Qw5Er8Ty1Ui4", name: "Tom Barker", accountPages: ["workspaces", "needs-you", "account", "platforms"] }

// The console pages' boot pages the gallery must show.
export const CONSOLE_PAGES = ["operator", "operator-register", "operator-platform", "operator-operators", "operator-accounts", "operator-account", "operator-audit", "operator-settings", "platforms", "platform-admin", "operator-workspaces", "operator-workspace"] as const

export type ConsoleGalleryEntry = { id: string; group: string; title: string; note: string; page: PageInput; reveal?: string[]; hide?: string[]; open?: string[]; fill?: Record<string, string>; inject?: Record<string, string>; swap?: [string | RegExp, string][] }

// Not a key: the PKCS8 header of a P-256 key, then filler of the same
// alphabet and length, so the box is drawn as a real one would be.
const PRIVATE_KEY_FIXTURE = `MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg${"Gallery-fixture-not-a-private-key_".repeat(5)}`.slice(0, 184)
const THUMBPRINT = "ZlSQ8zyOFnhkWls5Qf2JrXm9cTbA7hLp0eNvK1sYdGw"

function key(id: string, overrides: Partial<PlatformKeyView> = {}): PlatformKeyView {
  return { id, thumbprint: THUMBPRINT, createdAt: at(-30 * DAY), createdBy: OPERATOR, expiresAt: null, revokedAt: null, live: true, ...overrides }
}

const KEY_LIVE = key("pky_9fQ2mX7vR4tLp8Wz")
const KEY_ENDING = key("pky_3hNc6Yb9Gd2Ks1Pw", { createdAt: at(-90 * DAY), expiresAt: at(20 * 60) })
const KEY_REVOKED = key("pky_5tFj8Rw1Qx4Mn7Lz", { createdAt: at(-120 * DAY), revokedAt: at(-60 * DAY), live: false })
const ADMIN: PlatformAdminView = { account: "acc_7Tn2Qw5Er8Ty1Ui4", name: "Tom Barker", addedAt: at(-7 * DAY), addedBy: OPERATOR }

const GLOBEX: OperatorPlatformDetail = {
  id: "plt_8kQw2Lm4Zp7Rt5Vx",
  slug: "globex",
  name: "Globex",
  status: "active",
  statusAt: at(-30 * DAY),
  statusBy: OPERATOR,
  statusReason: null,
  retireAfter: null,
  removal: null,
  createdAt: at(-30 * DAY),
  createdBy: OPERATOR,
  limits: DEFAULT_PLATFORM_LIMITS,
  subjects: { creating: 1, active: 212, deleting: 3, deleted: 14, purged: 40 },
  keys: [KEY_LIVE, KEY_ENDING, KEY_REVOKED],
  admins: [ADMIN],
  defaults: { ...INITIAL_PLATFORM_DEFAULTS, templates: ["openai", "anthropic", "github-pat"], tags: ["globex"], rules: { openai: [{ action: "approve", methods: ["DELETE"], paths: ["/v1/**"] }] } },
  defaultsRevision: 4,
  usage: { asOf: at(-9), devices: 37, itemsAdded: 18, itemsDeleted: 2, decisions: 64, refusals: 5 },
  operatorActions24h: 1,
}

const EVENTS: PlatformEventPage = {
  events: [
    { id: "pev_7", at: at(-40), actor: `admin:${ADMIN.account}`, action: "admin.defaults", detail: { revision: 4 } },
    { id: "pev_6", at: at(-3 * 60), actor: OPERATOR, action: "operator.rotate_key", detail: { key: KEY_LIVE.id, overlapHours: 24 } },
    { id: "pev_5", at: at(-2 * DAY), actor: "platform:pky_3hNc6Yb9Gd2Ks1Pw", action: "subjects.remove_all", detail: { marked: 0, deleting: 0 } },
    { id: "pev_4", at: at(-7 * DAY), actor: OPERATOR, action: "operator.add_admin", detail: { account: ADMIN.account } },
    { id: "pev_3", at: at(-60 * DAY), actor: OPERATOR, action: "operator.revoke_key", detail: { key: KEY_REVOKED.id } },
    { id: "pev_2", at: at(-80 * DAY), actor: "system", action: "platform.something_new", detail: {} },
    { id: "pev_1", at: at(-120 * DAY), actor: OPERATOR, action: "operator.register", detail: { key: KEY_REVOKED.id, thumbprint: THUMBPRINT } },
  ],
  next: "1761000000000.pev_1",
}

const operator = (platform: OperatorPlatformDetail, events: PlatformEventPage | null = EVENTS) => operatorPlatformPage(CONSOLE_ACCOUNT_SHELL, { platform, events, older: events?.next ? `${OPERATOR_PATH}/platforms/${platform.slug}?before=${encodeURIComponent(events.next)}#events` : null, now: NOW })

const SUSPENDED: OperatorPlatformDetail = { ...GLOBEX, slug: "acme-assist", name: "Acme Assist", id: "plt_3hNc6Yb9Gd2Ks1Pw", status: "suspended", statusAt: at(-2 * 60), statusReason: "Its key leaked in a public repository; waiting for the new one", admins: [], operatorActions24h: 2, keys: [KEY_LIVE] }
const RETIRING: OperatorPlatformDetail = { ...GLOBEX, slug: "old-helper", name: "Old Helper", id: "plt_5tFj8Rw1Qx4Mn7Lz", status: "retiring", statusAt: at(-DAY), retireAfter: at(13 * DAY) }
const REMOVING: OperatorPlatformDetail = { ...GLOBEX, status: "retiring", statusAt: at(-30), retireAfter: at(-30), removal: { requestedAt: at(-30), by: OPERATOR, slug: "globex", completedAt: null }, subjects: { creating: 0, active: 0, deleting: 180, deleted: 36, purged: 40 }, keys: [{ ...KEY_LIVE, revokedAt: at(-30), live: false }] }
const REMOVED: OperatorPlatformDetail = { ...REMOVING, slug: "removed-x7Kq2mP9vR4tLw8zN3bY5cJh", status: "retired", statusBy: "system", statusAt: at(-10), retireAfter: null, removal: { requestedAt: at(-6 * 60), by: OPERATOR, slug: "globex", completedAt: at(-10) }, subjects: { creating: 0, active: 0, deleting: 0, deleted: 0, purged: 256 }, admins: [] }
const HOSTILE: OperatorPlatformDetail = {
  ...GLOBEX,
  slug: "hostile-names",
  name: "Platform\u202e <b>name</b> that keeps going on and on for sixty-four",
  status: "suspended",
  statusReason: "Reason with \u200b hidden and <i>markup</i> and a very long line that wraps across the card",
  admins: [{ ...ADMIN, name: "Admin\u0007 <script>x</script> with a long name" }],
}
const HOSTILE_EVENTS: PlatformEventPage = { events: [{ id: "pev_h", at: at(-5), actor: "operator:al\u202eex", action: "operator.<b>odd</b>", detail: { reason: "Words \u200b<i>with</i> a very long reason that runs past the end of the row on a phone", nested: { not: "shown" } } }], next: null }

const LIST: OperatorPlatformList = { platforms: [GLOBEX, SUSPENDED, RETIRING, REMOVED], workspaceCreation: "accounts", missing: [] }

// The register page with a key made: the make choice ticked, the pasted
// field hidden and the private key shown once.
const MADE: Pick<ConsoleGalleryEntry, "reveal" | "hide" | "fill" | "swap"> = {
  reveal: ["key-make", "key-made"],
  hide: ["key-paste"],
  fill: { "private-key": PRIVATE_KEY_FIXTURE, "key-thumbprint": THUMBPRINT },
  swap: [['value="paste" data-input="key-source" checked>', 'value="paste" data-input="key-source">'], ['value="make" data-input="key-source">', 'value="make" data-input="key-source" checked>']],
}

function operatorGallery(): ConsoleGalleryEntry[] {
  const group = "Operator"
  return [
    { id: "operator-list", group, title: "Operator: every platform", note: "Each platform with its slug, live subjects of its limit, live keys and admins, and its status; a removed one says its slug is free.", page: operatorListPage(CONSOLE_ACCOUNT_SHELL, LIST) },
    { id: "operator-list-empty", group, title: "Operator: no platforms yet", note: "The first run: what a platform is, and Register; on a deployment where the operator allows each account to create workspaces.", page: operatorListPage(CONSOLE_ACCOUNT_SHELL, { platforms: [], workspaceCreation: "operator", missing: [] }) },
    { id: "operator-list-requirements", group, title: "Operator: your account lacks a security key", note: "Said before any passkey: exactly what the operator's own account lacks, and the way to Your account.", page: operatorListPage(CONSOLE_ACCOUNT_SHELL, { ...LIST, missing: ["security-key"] }) },
    { id: "operator-list-failed", group, title: "Operator: the list could not be read", note: "Said plainly, never an empty list.", page: operatorListPage(CONSOLE_ACCOUNT_SHELL, null) },
    { id: "operator-register", group, title: "Register a platform", note: "Name, slug and the public key, pasted by default.", page: operatorRegisterPage(CONSOLE_ACCOUNT_SHELL, [REMOVING]) },
    { id: "operator-register-made", group, title: "Register: a key made in the browser", note: "The private half shown once with the plain warning, how the server loads it, the thumbprint, and the box to tick before Register is taken.", page: operatorRegisterPage(CONSOLE_ACCOUNT_SHELL, [REMOVING]), ...MADE },
    { id: "operator-register-refused", group, title: "Register: a private key pasted", note: "Refused under the field before any passkey, as the script refuses a key file with d.", page: operatorRegisterPage(CONSOLE_ACCOUNT_SHELL, [REMOVING]), reveal: ["key-problem"], fill: { "key-problem": PASTED_KEY_PROBLEMS.private } },
    { id: "operator-register-done", group, title: "Register: done", note: "The platform id and key id to hand over, and the way to its page; the form and any made key are gone.", page: operatorRegisterPage(CONSOLE_ACCOUNT_SHELL, [REMOVING]), reveal: ["register-done"], hide: ["register"], fill: { "done-platform": GLOBEX.id, "done-key": KEY_LIVE.id } },
    { id: "operator-platform", group, title: "Operator: one platform", note: "Status, subjects by status, the last day's usage and operator changes, keys, events, limits, admins and the danger zone, all folded.", page: operator(GLOBEX) },
    { id: "operator-platform-forms", group, title: "Operator: one platform, its forms open", note: "Suspend with the reason and slug, rotate with a pasted key and the overlap, revoke a key, every limit, and adding an admin.", page: operator(GLOBEX), open: ["suspend", "rotate", "revoke-key", "limits-edit", "admin-add"] },
    { id: "operator-platform-danger", group, title: "Operator: the danger zone open", note: "Delete every subject, retire and remove completely, each saying what it does and what is kept, with the slug typed back.", page: operator(GLOBEX), open: ["delete-subjects", "retire", "remove"] },
    { id: "operator-platform-suspended", group, title: "Operator: a suspended platform", note: "Who suspended it and why; Resume in the widening style; retiring is only at once.", page: operator(SUSPENDED), open: ["retire"] },
    { id: "operator-platform-retiring", group, title: "Operator: a retiring platform", note: "Its date, Resume while the date is ahead, and no second retire.", page: operator(RETIRING) },
    { id: "operator-platform-removing", group, title: "Operator: being removed", note: "Its calls refused, subjects being deleted and purged, the slug freed when the last is purged; nothing to change meanwhile.", page: operator(REMOVING) },
    { id: "operator-platform-removed", group, title: "Operator: removed", note: "The row kept under its reserved slug, and when the old slug was freed.", page: operator(REMOVED) },
    { id: "operator-platform-reads-failed", group, title: "Operator: no usage yet, events failed, no admins", note: "Each card says what it could not read or has not got yet.", page: operator({ ...GLOBEX, usage: null, admins: [] }, null) },
    { id: "operator-platform-hostile", group, title: "Operator: hostile names", note: "A name, reason, admin, actor and event with markup and hidden characters: spelled, never markup; a nested detail is left out.", page: operator(HOSTILE, HOSTILE_EVENTS) },
  ]
}

const ADMIN_GLOBEX: AdminPlatformDetail = { id: GLOBEX.id, slug: GLOBEX.slug, name: GLOBEX.name, status: "active", statusAt: GLOBEX.statusAt, retireAfter: null, subjects: GLOBEX.subjects, limits: GLOBEX.limits, keys: GLOBEX.keys, defaults: GLOBEX.defaults, defaultsRevision: GLOBEX.defaultsRevision, usage: GLOBEX.usage }
const admin = (platform: AdminPlatformDetail, events: PlatformEventPage | null = EVENTS) => adminPlatformPage(ADMIN_SHELL, { platform, events, older: null })

const DEFAULTS_PROBLEMS = ["rules.openai.0: A platform rule may only hold (approve) or refuse (deny).", 'templates.3: The catalogue has no template "made-up".']

function adminGallery(): ConsoleGalleryEntry[] {
  const group = "Platform admin"
  return [
    { id: "platforms-list", group, title: "Platforms: the ones you administer", note: "Only the platforms this account administers, with live subjects and status.", page: adminListPage(ADMIN_SHELL, { platforms: [ADMIN_GLOBEX, { ...ADMIN_GLOBEX, slug: "acme-assist", name: "Acme Assist", status: "suspended" }] }) },
    { id: "platform-admin", group, title: "Platform admin: one platform", note: "Subjects and usage, keys, the defaults summarised, events; status and limits read only, with who changes them.", page: admin(ADMIN_GLOBEX) },
    { id: "platform-admin-forms", group, title: "Platform admin: its forms open", note: "Add a key (made here, shown once), revoke one, the defaults as JSON, and deleting one subject by its string.", page: admin(ADMIN_GLOBEX), open: ["add-key", "revoke-key", "defaults-edit", "delete-subject"], ...MADE },
    { id: "platform-admin-last-key", group, title: "Platform admin: the last live key", note: "One live key: no revoke here, and why.", page: admin({ ...ADMIN_GLOBEX, keys: [KEY_LIVE, KEY_REVOKED] }) },
    { id: "platform-admin-defaults-refused", group, title: "Platform admin: defaults refused", note: "The schema's own reasons under the editor, before any passkey.", page: admin(ADMIN_GLOBEX), open: ["defaults-edit"], reveal: ["defaults-problems"], inject: { "defaults-problems": DEFAULTS_PROBLEMS.map((p) => `<li>${escapeHtml(p)}</li>`).join("") } },
    { id: "platform-admin-retired", group, title: "Platform admin: retired", note: "Nothing left to change: no forms, no danger zone.", page: admin({ ...ADMIN_GLOBEX, status: "retired", keys: [{ ...KEY_LIVE, revokedAt: at(-DAY), live: false }], subjects: { creating: 0, active: 0, deleting: 0, deleted: 0, purged: 256 } }) },
  ]
}

// ---------------------------------------------------------------- the Operators view

const TOM = "acc_7Tn2Qw5Er8Ty1Ui4"
const RAVI = "acc_2Dk8Lp4Ws6Qa9Ze3"
const KIM = "acc_6Km1Nr3Vt5Yc7Xb2"
const operatorView = (account: string, name: string, overrides: Partial<OperatorView> = {}): OperatorView => ({ account, name, since: at(-90 * DAY), grantedBy: "operator:alex", passkeys: 3, securityKeys: 1, recoveryReady: true, lastSeenAt: at(-20), missing: [], ...overrides })
const ALEX_OPERATOR = operatorView(ACCOUNT, "Alex Rae", { since: at(-200 * DAY), passkeys: 4, securityKeys: 2, lastSeenAt: at(-1) })
const OPERATORS = [ALEX_OPERATOR, operatorView(TOM, "Tom Barker", { grantedBy: "operator:alex" }), operatorView(RAVI, "Ravi Okafor", { grantedBy: OPERATOR, since: at(-3 * DAY), lastSeenAt: at(-2 * DAY) })]
const proposal = (overrides: Partial<OperatorProposalView>): OperatorProposalView => ({ id: "opp_4Rt8Yq2Wm6Lk1Nz9", kind: "operator.grant", target: KIM, targetName: "Kim Lee", params: {}, digest: "u3bK9yQ2mX7vR4tLp8WzZlSQ8zyOFnhkWls5Qf2JrXm", proposedBy: { account: TOM, name: "Tom Barker" }, proposedAt: at(-3 * 60), expiresAt: at(21 * 60), approvedBy: null, approvedAt: null, declinedBy: null, state: "open", closedAt: null, awaiting: "approval", ...overrides })
const GRANT_OPEN = proposal({})
const REVOKE_MINE = proposal({ id: "opp_8Hc3Vb5Nm1Qx7Kw2", kind: "operator.revoke", target: RAVI, targetName: "Ravi Okafor", proposedBy: { account: ACCOUNT, name: "Alex Rae" } })
const GRANT_ACCEPTING = proposal({ id: "opp_1Zx9Cv3Bn7Ml5Kj4", approvedBy: { account: RAVI, name: "Ravi Okafor" }, approvedAt: at(-60), awaiting: "acceptance" })
const RECENT = [
  proposal({ id: "opp_r1", kind: "operator.grant", target: RAVI, targetName: "Ravi Okafor", proposedBy: { account: ACCOUNT, name: "Alex Rae" }, approvedBy: { account: TOM, name: "Tom Barker" }, approvedAt: at(-3 * DAY - 60), state: "applied", closedAt: at(-3 * DAY), awaiting: null, proposedAt: at(-3 * DAY - 120) }),
  proposal({ id: "opp_r2", kind: "operator.revoke", target: TOM, targetName: "Tom Barker", proposedBy: { account: RAVI, name: "Ravi Okafor" }, declinedBy: { account: ACCOUNT, name: "Alex Rae" }, state: "declined", closedAt: at(-2 * DAY), awaiting: null, proposedAt: at(-2 * DAY - 30) }),
]
const OPERATOR_EVENTS: OperatorsView["events"] = [
  { id: "dpe_3", at: at(-3 * 60), kind: "proposal.open", actor: `operator:${TOM}`, approver: null, target: KIM, details: { kind: "operator.grant" } },
  { id: "dpe_2", at: at(-2 * DAY), kind: "proposal.decline", actor: OPERATOR, approver: null, target: TOM, details: {} },
  { id: "dpe_1", at: at(-3 * DAY), kind: "operator.grant", actor: OPERATOR, approver: `operator:${TOM}`, target: RAVI, details: { acceptedAt: at(-3 * DAY) } },
  { id: "dpe_0", at: at(-90 * DAY), kind: "operator.grant", actor: "operator:alex", approver: null, target: TOM, details: { via: "scripts/operator.ts" } },
]
const VIEW: OperatorsView = { you: ACCOUNT, operators: OPERATORS, open: [GRANT_OPEN, REVOKE_MINE, GRANT_ACCEPTING], recent: RECENT, events: OPERATOR_EVENTS }
const ALONE: OperatorsView = { you: ACCOUNT, operators: [ALEX_OPERATOR], open: [], recent: [], events: [OPERATOR_EVENTS[3] as OperatorsView["events"][number]] }

function operatorsGallery(): ConsoleGalleryEntry[] {
  const group = "Operator"
  return [
    { id: "operator-operators", group, title: "Operators: three operators", note: "Each operator with their passkeys and security keys, recovery and last seen; Revoke on the others and Resign on you; Approve and Decline on another's proposal, Cancel on yours, and one approved waiting for its target; the grant form, recent proposals and the events.", page: operatorsPage(CONSOLE_ACCOUNT_SHELL, VIEW) },
    { id: "operator-operators-alone", group, title: "Operators: the only operator", note: "Every two-operator change disabled with Needs a second operator; use the script, and Resign too, since Mehen needs at least one operator.", page: operatorsPage(CONSOLE_ACCOUNT_SHELL, ALONE) },
    { id: "operator-operators-missing", group, title: "Operators: an operator missing a security key", note: "Your own account's lack said at the top, and another operator's on their row.", page: operatorsPage(CONSOLE_ACCOUNT_SHELL, { ...VIEW, operators: [{ ...ALEX_OPERATOR, securityKeys: 0, missing: ["security-key"] }, ...OPERATORS.slice(1).map((o, i) => (i === 1 ? { ...o, recoveryReady: false, missing: ["recovery" as const] } : o))] }) },
    { id: "operator-operators-failed", group, title: "Operators: the view could not be read", note: "Said plainly, never an empty list.", page: operatorsPage(CONSOLE_ACCOUNT_SHELL, null) },
    { id: "account-operator-invitation", group, title: "Your account: become an operator", note: "Who proposed and who approved, until when, and Accept with passkey.", page: accountPage(CONSOLE_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, { ...ACCOUNT_CARDS_EMPTY, operatorInvitation: { proposal: GRANT_ACCEPTING.id, digest: GRANT_ACCEPTING.digest, proposedBy: GRANT_ACCEPTING.proposedBy, approvedBy: { account: RAVI, name: "Ravi Okafor" }, expiresAt: GRANT_ACCEPTING.expiresAt, missing: [] } }) },
    { id: "account-operator-invitation-missing", group, title: "Your account: become an operator, a security key first", note: "Accept disabled, saying what the account lacks.", page: accountPage(CONSOLE_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN, { ...ACCOUNT_CARDS_EMPTY, operatorInvitation: { proposal: GRANT_ACCEPTING.id, digest: GRANT_ACCEPTING.digest, proposedBy: GRANT_ACCEPTING.proposedBy, approvedBy: { account: RAVI, name: "Ravi Okafor" }, expiresAt: GRANT_ACCEPTING.expiresAt, missing: ["security-key"] } }) },
  ]
}

// ---------------------------------------------------------------- the Audit and Settings views

const auditEvent = (overrides: Partial<OperatorAuditEvent>): OperatorAuditEvent => ({ id: "dpe_a0", at: at(-60), source: "deployment", action: "settings.narrow", actor: OPERATOR, actorName: "Alex Rae", approver: null, approverName: null, target: "workspace_creation", targetName: null, details: {}, proposal: null, ...overrides })
const WIDEN_PROPOSAL = { id: "opp_7Wd3Ns5Kq9Lx2Vb4", kind: "settings.widen", proposedBy: { account: TOM, name: "Tom Barker" }, approvedBy: { account: ACCOUNT, name: "Alex Rae" }, declinedBy: null }
const AUDIT: OperatorAuditPage = {
  events: [
    auditEvent({ id: "dpe_a5", at: at(-20), action: "settings.widen", actor: `operator:${TOM}`, actorName: "Tom Barker", approver: OPERATOR, approverName: "Alex Rae", details: { proposal: WIDEN_PROPOSAL.id, digest: "u3bK9yQ2mX7vR4tLp8WzZlSQ8zyOFnhkWls5Qf2JrXm", params: { value: "accounts", from: "operator" } }, proposal: { ...WIDEN_PROPOSAL, state: "applied" } }),
    auditEvent({ id: "dpe_a4", at: at(-50), action: "proposal.open", actor: `operator:${TOM}`, actorName: "Tom Barker", details: { proposal: WIDEN_PROPOSAL.id, kind: "settings.widen", params: { value: "accounts", from: "operator" } }, proposal: { ...WIDEN_PROPOSAL, state: "applied" } }),
    auditEvent({ id: "pev_a3", at: at(-3 * 60), source: "platform", action: "operator.suspend", target: "globex", targetName: "Globex", details: { reason: "Key leaked in a client log" } }),
    auditEvent({ id: "evt_a2", at: at(-DAY), source: "account", action: "operator.allow_workspaces", target: KIM, targetName: "Kim Lee", details: { by: OPERATOR, allowed: 1 } }),
    auditEvent({ id: "dpe_a1", at: at(-2 * DAY), action: "proposal.decline", actor: OPERATOR, details: { proposal: "opp_r2", kind: "operator.revoke", proposedBy: `operator:${RAVI}` }, target: TOM, targetName: "Tom Barker", proposal: { id: "opp_r2", kind: "operator.revoke", state: "declined", proposedBy: { account: RAVI, name: "Ravi Okafor" }, approvedBy: null, declinedBy: { account: ACCOUNT, name: "Alex Rae" } } }),
    auditEvent({ id: "dpe_a0", at: at(-90 * DAY), action: "settings.set", actor: "operator:alex", actorName: null, details: { via: "scripts/operator.ts", params: { value: "operator" } } }),
  ],
  next: `${Date.parse(at(-90 * DAY))}.dpe_a0`,
}

const SETTINGS: OperatorSettingsView = {
  you: ACCOUNT,
  operators: 3,
  missing: [],
  settings: [
    { key: "workspace_creation", value: "operator", stored: "operator", ceiling: "accounts", updatedAt: at(-60), updatedBy: OPERATOR, updatedByName: "Alex Rae" },
    { key: "signup_mode", value: "invite", stored: null, ceiling: "open", updatedAt: null, updatedBy: null, updatedByName: null },
  ],
  open: [],
  history: [
    { id: "dpe_s1", at: at(-60), kind: "settings.narrow", actor: OPERATOR, approver: null, target: "workspace_creation", details: { params: { value: "operator" } } },
    { id: "dpe_s0", at: at(-90 * DAY), kind: "settings.set", actor: "operator:alex", approver: null, target: "workspace_creation", details: { via: "scripts/operator.ts", params: { value: "accounts" } } },
  ],
}
const SETTINGS_OPEN: OperatorSettingsView = {
  ...SETTINGS,
  open: [proposal({ id: WIDEN_PROPOSAL.id, kind: "settings.widen", target: "workspace_creation", targetName: null, params: { value: "accounts", from: "operator" } })],
  history: [{ id: "dpe_s2", at: at(-3 * 60), kind: "proposal.open", actor: `operator:${TOM}`, approver: null, target: "workspace_creation", details: { kind: "settings.widen", params: { value: "accounts", from: "operator" } } }, ...SETTINGS.history],
}

function auditSettingsGallery(): ConsoleGalleryEntry[] {
  const group = "Operator"
  return [
    { id: "operator-audit", group, title: "Audit: every operator change", note: "Deployment, platform and account rows newest first, each with its actor and approver named, a proposal's outcome and who proposed and approved it; the D1-not-a-hash-chain note; the filters; Older events.", page: operatorAuditPage(CONSOLE_ACCOUNT_SHELL, { page: AUDIT, query: {} }) },
    { id: "operator-audit-filtered", group, title: "Audit: filtered, nothing matches", note: "The filters kept in the form, and the empty list saying what would be here.", page: operatorAuditPage(CONSOLE_ACCOUNT_SHELL, { page: { events: [], next: null }, query: { actor: TOM, action: "platform.", from: "2026-10-01", to: "2026-10-29" } }) },
    { id: "operator-audit-refused", group, title: "Audit: filters the view does not take", note: "Said, and nothing read.", page: operatorAuditPage(CONSOLE_ACCOUNT_SHELL, { page: null, query: null }) },
    { id: "operator-audit-failed", group, title: "Audit: the list could not be read", note: "Said plainly, never an empty list.", page: operatorAuditPage(CONSOLE_ACCOUNT_SHELL, { page: null, query: {} }) },
    { id: "operator-settings", group, title: "Settings: three operators", note: "Workspace creation narrowed by you, with Propose to widen; sign-up by invitation, with request access and open shown as not available yet; the ceilings, the operators needed and the changes.", page: operatorSettingsPage(CONSOLE_ACCOUNT_SHELL, SETTINGS) },
    { id: "operator-settings-open", group, title: "Settings: a widening proposed", note: "Another operator's proposal with Approve and Decline, and its event in the changes.", page: operatorSettingsPage(CONSOLE_ACCOUNT_SHELL, SETTINGS_OPEN) },
    { id: "operator-settings-alone", group, title: "Settings: the only operator", note: "Narrowing still works; every widening disabled with Needs a second operator, the warning before narrowing, and the script named as the break-glass.", page: operatorSettingsPage(CONSOLE_ACCOUNT_SHELL, { ...SETTINGS, operators: 1, settings: [{ ...SETTINGS.settings[0]!, value: "accounts", stored: null, updatedAt: null, updatedBy: null, updatedByName: null }, SETTINGS.settings[1]!] }) },
    { id: "operator-settings-ceiling", group, title: "Settings: capped by the deploy", note: "A stored value above a lowered ceiling shows what is in force and can be narrowed to it, and a wider choice says the deploy must allow more first.", page: operatorSettingsPage(CONSOLE_ACCOUNT_SHELL, { ...SETTINGS, settings: [{ ...SETTINGS.settings[0]!, value: "operator", stored: "accounts", ceiling: "operator" }, { ...SETTINGS.settings[1]!, ceiling: "invite" }] }) },
    { id: "operator-settings-failed", group, title: "Settings: could not be read", note: "Said plainly.", page: operatorSettingsPage(CONSOLE_ACCOUNT_SHELL, null) },
  ]
}

const accountSummary = (account: string, name: string, overrides: Partial<OperatorAccountSummary> = {}): OperatorAccountSummary => ({ account, name, email: null, status: "active", createdAt: at(-120 * DAY), operator: false, suspendedAt: null, coolingOff: null, transitionPending: false, recovery: "codes", lastSeenAt: at(-2 * 60), workspaces: 2, passkeys: { count: 2, synced: 1, securityKeys: 0 }, workspaceCreation: "default", ...overrides })
const KIM_ACCOUNT = accountSummary(KIM, "Kim Lee", { email: "kim@example.com", workspaces: 3 })
const ACCOUNT_ROWS: OperatorAccountSummary[] = [
  accountSummary(TOM, "Tom Barker", { operator: true, email: "tom@example.com", passkeys: { count: 3, synced: 1, securityKeys: 1 }, workspaceCreation: "operator-allowed" }),
  accountSummary(RAVI, "Ravi Okafor", { operator: true, coolingOff: { reason: "recovery", until: at(4 * 60) }, lastSeenAt: at(-5) }),
  KIM_ACCOUNT,
  accountSummary("acc_3Sx5Pq7Ry9Uw2Gv4", "Sam Reid", { suspendedAt: at(-DAY), transitionPending: true, lastSeenAt: at(-3 * DAY), workspaceCreation: "operator-denied" }),
  accountSummary("acc_9Bn4Mh6Jk8Lf1Dz3", "Priya Shah", { recovery: null, workspaces: 0, passkeys: { count: 1, synced: 1, securityKeys: 0 }, lastSeenAt: null }),
]
const ACCOUNT_LIST: OperatorAccountList = { you: ACCOUNT, operators: 3, workspaceCreation: "operator", missing: [], accounts: ACCOUNT_ROWS, next: `${Date.parse(at(-120 * DAY))}~acc_9Bn4Mh6Jk8Lf1Dz3` }
const KIM_DETAIL: OperatorAccountDetail = {
  you: ACCOUNT,
  operators: 3,
  workspaceCreationDefault: "operator",
  missing: [],
  account: KIM_ACCOUNT,
  emails: ["kim@example.com"],
  deletedAt: null,
  workspaces: [
    { workspace: "tn_8Wq2Er4Ty6Ui8Op0", slug: "acme", name: "Acme", roleHint: "admin", state: "member", since: at(-100 * DAY) },
    { workspace: "tn_2As4Df6Gh8Jk0Lz1", slug: "kim-lee", name: "Kim's workspace", roleHint: "owner", state: "member", since: at(-110 * DAY) },
    { workspace: "tn_5Zx7Cv9Bn1Mq3Wr5", slug: "sandbox", name: "Sandbox", roleHint: "member", state: "joining", since: at(-DAY) },
  ],
  passkeys: [
    { name: "MacBook", authenticator: "Built into a device", synced: true, addedVia: "signup", createdAt: at(-120 * DAY), lastUsedAt: at(-2 * 60) },
    { name: null, authenticator: "A security key", synced: false, addedVia: "settings", createdAt: at(-60 * DAY), lastUsedAt: null },
  ],
  sessions: { web: 2, app: 1, recovery: 0, lastSeenAt: at(-2 * 60) },
  events: [
    { id: "evt_3", at: at(-2 * 60), action: "account.signin", detail: {} },
    { id: "evt_2", at: at(-DAY), action: "operator.deny_workspaces", detail: { by: OPERATOR, allowed: 0 } },
    { id: "evt_1", at: at(-120 * DAY), action: "account.signup", detail: {} },
  ],
  open: [],
  breakGlass: null,
}
const KIM_LEFT = { ...KIM_DETAIL, workspaces: KIM_DETAIL.workspaces.map((w) => ({ ...w, state: "left" as const })), account: { ...KIM_ACCOUNT, workspaces: 0 } }

function accountsGallery(): ConsoleGalleryEntry[] {
  const group = "Operator"
  return [
    { id: "operator-accounts", group, title: "Accounts: every account", note: "Search and the filters; each row with its pills (operator, suspended, cooling off, transition pending, no recovery), workspaces, passkeys, recovery, where workspace creation comes from and last seen; Older accounts.", page: operatorAccountsPage(CONSOLE_ACCOUNT_SHELL, { list: ACCOUNT_LIST, q: "", filter: "all" }) },
    { id: "operator-accounts-empty", group, title: "Accounts: a search that matches nothing", note: "Said plainly, with the search and filter kept.", page: operatorAccountsPage(CONSOLE_ACCOUNT_SHELL, { list: { ...ACCOUNT_LIST, accounts: [], next: null }, q: "nobody", filter: "suspended" }) },
    { id: "operator-accounts-failed", group, title: "Accounts: the list could not be read", note: "Said plainly, never an empty list.", page: operatorAccountsPage(CONSOLE_ACCOUNT_SHELL, { list: null, q: "", filter: "all" }) },
    { id: "operator-account", group, title: "Account: in three workspaces", note: "The account, its workspaces with the role as a hint, passkeys and sessions as metadata, events; Allow, Deny and Back to default; Suspend; Recover access open, and Delete listing the workspaces whose owners remove it first.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, KIM_DETAIL), open: ["recover", "delete"] },
    { id: "operator-account-deletable", group, title: "Account: in no workspace, the only operator", note: "Delete with the name typed back, and both two-operator changes disabled with Needs a second operator; use the script.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_LEFT, operators: 1 }), open: ["recover", "delete"] },
    { id: "operator-account-suspended", group, title: "Account: suspended, a proposal waiting", note: "Lift with passkey; recovering access waits for the suspension to be lifted; the open proposal links to Operators.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_DETAIL, account: { ...KIM_ACCOUNT, suspendedAt: at(-DAY), transitionPending: true }, open: [proposal({ id: "opp_6Dl2Kp4Jh8Gf0Sa1", kind: "account.delete", target: KIM, params: { nameHash: "Gallery-fixture-not-a-name-hash-0123456789A" } })] }), open: ["recover"] },
    { id: "operator-account-link", group, title: "Account: the recovery link ready for you", note: "Shown once, to the operator who proposed it, with a passkey.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_DETAIL, breakGlass: { intent: "bgi_5f3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f", state: "ready", expiresAt: at(40), proposedBy: OPERATOR, yours: true, linkTaken: false } }), reveal: ["break-glass-link"], fill: { link: "https://app.mehen.dev/signup#Gallery-fixture-not-a-code" } },
    { id: "operator-account-link-theirs", group, title: "Account: the recovery link ready for another operator", note: "Only the operator who checked who the person is takes it.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_DETAIL, breakGlass: { intent: "bgi_5f3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f", state: "ready", expiresAt: at(40), proposedBy: `operator:${TOM}`, yours: false, linkTaken: false } }) },
    { id: "operator-account-operator", group, title: "Account: an operator", note: "Never suspended, recovered or deleted here: end their operator role first, or use the script.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_DETAIL, account: ACCOUNT_ROWS[0] as OperatorAccountSummary }), open: ["recover", "delete"] },
    { id: "operator-account-yours", group, title: "Account: your own", note: "Another operator changes it.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, { ...KIM_DETAIL, you: KIM }) },
    { id: "operator-account-failed", group, title: "Account: could not be read", note: "Said plainly.", page: operatorAccountPage(CONSOLE_ACCOUNT_SHELL, null) },
  ]
}

const ACCOUNT_CARDS_EMPTY = { passkeys: { ok: true as const, value: [] }, sessions: { ok: true as const, value: [] }, mayEndOtherSessions: true, recovery: { ok: true as const, value: { active: null } }, now: NOW }

// A workspace's rail and More sheet with both console links.
function consoleLinksEntry(): ConsoleGalleryEntry {
  const own = GALLERY_MEMBERSHIPS[1]
  if (own === undefined) throw new Error("the shell gallery lists a second membership")
  const shell: WorkspaceShell = {
    identity: { origin: GALLERY_ORIGIN, account: ACCOUNT, workspace: own.workspace },
    accountName: "Alex Rae",
    memberships: GALLERY_MEMBERSHIPS,
    pages: ["home", "needs", "credentials", "projects", "machines", "people", "teams", "connect-agent", "audit", "settings"],
    reads: [],
    accountPages: CONSOLE_ACCOUNT_SHELL.accountPages,
    accountHeld: false,
  }
  return { id: "console-links-workspace", group: "Operator", title: "A workspace, with the console links", note: "Operator and Platforms in the rail's foot, the switcher and the More sheet, only for an account that has them.", page: workspaceHomePage(shell), open: ["more-sheet"] }
}

export function consoleGallery(): ConsoleGalleryEntry[] {
  return [...operatorGallery(), ...operatorsGallery(), ...accountsGallery(), ...auditSettingsGallery(), ...adminGallery(), consoleLinksEntry(), ...operatorWorkspacesGallery(CONSOLE_ACCOUNT_SHELL)]
}
