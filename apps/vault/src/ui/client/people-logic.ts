// What the people, team, machine and Connect an agent pages may offer, and
// the exact words and copied text they use, with no DOM, so the server pages,
// the browser and the tests share one answer. The server stays the authority:
// these rules mirror the evaluator (vault/access.ts) so a page never offers a
// control the workspace would refuse, but a control here grants nothing.

import type { WorkloadScope } from "@mehen/protocol/workload"
import { type EnrolRequestedScope, type InviteEmailed, type InviteTerms, InviteTermsSchema, inviteJoinsStraightAway, inviteMayActivate, type OwnerRef, PENDING_RESTRICTION_UNTIL, type WorkspaceDeviceScope, type WorkspaceMemberView, type WorkspaceRole, WorkspaceSlugSchema, type WorkspaceStepUpAction } from "@mehen/protocol/workspace"

export const ROLE_LABELS: Readonly<Record<WorkspaceRole, string>> = { owner: "Owner", admin: "Admin", member: "Member", guest: "Guest" }

// Who is looking: this account's membership in the workspace, from the
// account read. `blocked`: the account is restricted after a recovery or a
// security change is still reaching its workspaces, so it may read, deny,
// narrow and freeze, nothing that widens or changes people.
export type PeopleViewer = { member: string; role: WorkspaceRole; blocked: boolean }

export function elevated(role: WorkspaceRole): boolean {
  return role === "owner" || role === "admin"
}

export type MemberAction = "confirm" | "role" | "suspend" | "reinstate" | "remove"

function lastOwner(subject: WorkspaceMemberView, members: readonly WorkspaceMemberView[]): boolean {
  return subject.status === "active" && subject.role === "owner" && !members.some((m) => m.member !== subject.member && m.status === "active" && m.role === "owner")
}

// The changes this viewer may offer on another person, in the evaluator's
// terms: owners and admins only, an admin never on an owner, the last active
// owner never changed, and nothing at all while the account is held back.
// The viewer's own row offers nothing here: leaving is a separate step.
export function memberActions(viewer: PeopleViewer, subject: WorkspaceMemberView, members: readonly WorkspaceMemberView[]): MemberAction[] {
  if (viewer.blocked || !elevated(viewer.role) || subject.member === viewer.member) return []
  const overOwner = subject.role === "owner" && viewer.role !== "owner"
  if (subject.status === "unconfirmed") return overOwner ? [] : ["confirm"]
  if (overOwner || lastOwner(subject, members)) return []
  return subject.status === "active" ? ["role", "suspend", "remove"] : ["role", "reinstate", "remove"]
}

// The roles this viewer may move another person to: an admin never makes
// an owner, and the current role is not a change.
// The page puts a disabled placeholder first (ROLE_PLACEHOLDER), so no role
// is ever chosen by default.
export const ROLE_PLACEHOLDER = "Change role to ..."

export function roleChoices(viewer: PeopleViewer, subject: WorkspaceMemberView): WorkspaceRole[] {
  const all: WorkspaceRole[] = viewer.role === "owner" ? ["owner", "admin", "member", "guest"] : ["admin", "member", "guest"]
  return all.filter((r) => r !== subject.role)
}

// Who may be invited at which role: an owner any, an admin no owner.
export function inviteRoles(viewer: PeopleViewer): WorkspaceRole[] {
  if (viewer.blocked || !elevated(viewer.role)) return []
  return viewer.role === "owner" ? ["owner", "admin", "member", "guest"] : ["admin", "member", "guest"]
}

// The confirmation a person signs, word for word: activation is a fresh
// grant of exactly these terms, never a status flip.
export function activationWords(name: string, role: WorkspaceRole): string {
  return `Confirming activates ${name} as ${ROLE_LABELS[role]} with exactly these terms. Your passkey signs them; if any term changed since the invitation, the vault refuses and nothing is granted.`
}

export const ACTIVATION_BUTTON = "Confirm with passkey"

export type InviteForm = {
  role: string
  binding: "email" | "open"
  email: string
  teams: readonly string[]
  shares: readonly { project: string; level: string; protected: boolean }[]
  days: number
  // "Confirm them myself when they join": ticked keeps onJoin confirm.
  confirmMyself: boolean
}

export type Built<T> = { ok: true; value: T } | { ok: false; problems: string[] }

// Seven days is the most an invitation may last; the browser's clock may be
// ahead of the vault's, so it asks for a little less.
export const INVITE_MAX_DAYS = 7
const CLOCK_MARGIN_MS = 10 * 60_000

// The complete terms the invitation signs. Only a guest may have an open
// link, and a guest has project shares and no teams or manage level. An
// email-bound invitation below owner lets the person straight in unless the
// inviter ticks to confirm them; an owner invitation or an open link always
// waits for confirmation.
export function buildInviteTerms(form: InviteForm, now: number): Built<InviteTerms> {
  const problems: string[] = []
  const role = form.role as WorkspaceRole
  if (!["owner", "admin", "member", "guest"].includes(form.role)) problems.push("Choose a role.")
  const guest = role === "guest"
  const open = guest && form.binding === "open"
  const email = form.email.trim().toLowerCase()
  if (!open && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) problems.push(guest ? "Type the guest's email, or choose an open link." : "Type the email this invitation is for.")
  if (guest && form.shares.length === 0) problems.push("A guest needs at least one shared project.")
  if (guest && form.shares.some((s) => s.level === "manage")) problems.push("A guest can use or edit a project, not manage it.")
  if (form.shares.some((s) => !["use", "edit", "manage"].includes(s.level))) problems.push("Choose a level for every project.")
  const days = Math.min(INVITE_MAX_DAYS, Math.max(1, Math.round(form.days)))
  if (problems.length > 0) return { ok: false, problems }
  const bound = open ? null : email
  const terms = {
    role,
    email: bound,
    teams: guest ? [] : [...new Set(form.teams)],
    shares: form.shares.map((s) => ({ project: s.project, level: s.level, protected: s.protected, expiresAt: null })),
    expiresAt: new Date(now + days * 86_400_000 - CLOCK_MARGIN_MS).toISOString(),
    onJoin: form.confirmMyself || !inviteMayActivate({ role, email: bound }) ? "confirm" : "activate",
  }
  const parsed = InviteTermsSchema.safeParse(terms)
  return parsed.success ? { ok: true, value: parsed.data } : { ok: false, problems: ["These invitation terms are not allowed."] }
}

// Whether the form offers "Confirm them myself when they join": only where
// the invitation could let the person straight in.
export function confirmChoiceShown(role: string, binding: "email" | "open"): boolean {
  return role !== "owner" && !(role === "guest" && binding === "open")
}

// Whether the form offers "Email the link to them", ticked: only an
// invitation bound to one email has an address to send it to.
export function emailLinkShown(role: string, binding: "email" | "open"): boolean {
  return !(role === "guest" && binding === "open")
}

// What happens when the invited person joins, as the invitation's terms say.
export function onJoinWords(terms: Pick<InviteTerms, "role" | "email" | "onJoin">): string {
  return inviteJoinsStraightAway(terms) ? "Joins straight away" : "You confirm them when they join"
}

// The line above a new invitation's link: whether Mehen emailed it, then
// what it does. A link that was not emailed is always there to copy.
function emailedWords(email: string | null, emailed: InviteEmailed): string {
  if (emailed === "sent" && email !== null) return `Mehen emailed this link to ${email}.`
  if (emailed === "limited") return "This link was not emailed: too many invitation emails have gone from your account or to this address lately. Send it to them yourself."
  if (emailed === "failed") return "This link could not be emailed. Send it to them yourself."
  return "Send this link to the person you invited."
}

export function inviteMadeWords(terms: Pick<InviteTerms, "role" | "email" | "onJoin">, emailed: InviteEmailed = "not_requested"): string {
  return `${emailedWords(terms.email, emailed)} ${inviteJoinsStraightAway(terms) ? "It works once, and only for that email: they join straight away once they prove it." : "It works once; nobody can use the workspace until an owner or admin confirms them."}`
}

// The message to send with a new invitation.
// The workspace's name goes in only when it is plain words; otherwise its
// checked short name does, so a copied message never carries a hidden or
// control character. An open guest link has no email to verify.
const PLAIN_NAME = /^[\p{L}\p{N}][\p{L}\p{N} .,'&()-]{0,63}$/u

export function inviteMessage(workspace: { name: string; slug: string }, link: string, terms: Pick<InviteTerms, "role" | "email" | "onJoin">): string {
  const name = PLAIN_NAME.test(workspace.name) ? workspace.name : workspace.slug
  const steps = terms.email !== null ? "verify your work Google account, create a passkey and save your recovery codes" : "create a passkey and save your recovery codes"
  const then = inviteJoinsStraightAway(terms) ? "Then you connect your agent." : "I confirm you once you have joined, then you connect your agent."
  return `You are invited to ${name} on Mehen, where our agents use credentials without ever seeing them. Open this link, ${steps}; it takes about three minutes. ${then} ${link}`
}

// A machine's owner as words: a person by name, or a team.
export function ownerWords(owner: OwnerRef): string {
  return owner.kind === "team" ? `team ${owner.name}` : owner.name
}

// Whether this viewer may revoke, narrow or propose wider scope on a
// machine: owners and admins any, a person their own; a team's machine only
// owners and admins. Narrowing and revoking stay open while the account is
// held back; proposing wider scope does not.
export type MachineControls = { revoke: boolean; narrow: boolean; propose: boolean }

export function machineControls(viewer: PeopleViewer | null, owner: OwnerRef, revoked: boolean): MachineControls {
  if (viewer === null || revoked) return { revoke: false, narrow: false, propose: false }
  const own = owner.kind === "member" && owner.member === viewer.member
  const may = elevated(viewer.role) || own
  // A guest cannot propose their own wider scope: that needs an insider to
  // admit it. The insider proposes, and the guest accepts on this page.
  return { revoke: may, narrow: may, propose: may && !viewer.blocked && viewer.role !== "guest" }
}

// ---------------------------------------------------------------- Connect an agent

// Only these reach copied text: the grammar-checked slug, the canonical
// origin and a connect code in the issuer's own alphabet. A display name
// never does, whatever it contains, and neither does the workspace id:
// nothing here needs one. Every command is valid shell exactly as printed:
// plain words, and the one pipe of the installer line.
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?$/

// The code the connect-code issuer mints (directory/enrolment.ts
// enrolmentCode: eight of 31 letters and digits).
const CONNECT_CODE = /^[2-9A-HJKMNP-Z]{8}$/

export const INSTALL_COMMAND = "curl -fsSL https://mehen.dev/install | sh"
export const SETUP_COMMAND = "mehen setup"

export type AgentSetup = { prompt: string; install: string; setup: string; enrol: string }

// The prompt and the three commands of Connect an agent, with the connect code when the issuer gave one. Null when the
// slug, the origin or the code is not what the grammar allows: the page then
// offers nothing to copy.
export function agentSetup(origin: string, slug: string, code: string | null = null): AgentSetup | null {
  if (!ORIGIN.test(origin) || !WorkspaceSlugSchema.safeParse(slug).success) return null
  if (code !== null && !CONNECT_CODE.test(code)) return null
  const withCode = code === null ? "" : ` with connect code ${code}`
  return {
    prompt: `Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace ${slug} at ${origin}${withCode}. I will approve it in my browser; never ask me for a key, password or secret.`,
    install: INSTALL_COMMAND,
    setup: SETUP_COMMAND,
    enrol: `mehen enrol --workspace ${slug}${code === null ? "" : ` --connect ${code}`}`,
  }
}

// ---------------------------------------------------------------- scopes and time

export const PENDING_UNTIL_WORDS = "until recovery completes"

// The largest time a Date can hold; anything at or past it is the pending
// sentinel, never a renderable date.
const MAX_DATE_MS = 8.64e15

// A restriction's end: a date, or, while the recovery has not committed
// (the server's null, or the shared sentinel), the words above. Never the
// sentinel as a year.
export function restrictionUntil(until: string | number | null, format: (value: string) => string): string {
  if (until === null || until === PENDING_RESTRICTION_UNTIL) return PENDING_UNTIL_WORDS
  const ms = typeof until === "number" ? until : Date.parse(until)
  if (!Number.isFinite(ms) || ms > MAX_DATE_MS) return PENDING_UNTIL_WORDS
  return `until ${format(new Date(ms).toISOString())}`
}

const MODE_ORDER = ["relay", "sign", "mint", "placeholder", "fill", "lease"] as const

// The ways a machine may use credentials, in the words people see; the mode names stay in the form's values only.
export const MODE_PLAIN: Readonly<Record<(typeof MODE_ORDER)[number], string>> = {
  relay: "through the vault only",
  sign: "signing",
  mint: "short-lived tokens",
  placeholder: "stand-in values",
  fill: "typing into web pages",
  lease: "the real value on this machine",
}

// The vault refuses a scope whose only mode is fill (every released mehen
// reads at least one mode, and one below 0.3.17 is answered without fill).
export const FILL_ONLY_WORDS = "A machine needs at least one other way to use credentials besides typing into web pages."

export const MODES_LABEL = "How agents may use credentials through it"

function modeWords(modes: readonly string[]): string {
  const words = MODE_ORDER.filter((m) => modes.includes(m)).map((m) => MODE_PLAIN[m])
  if (words.length === 0) return "None"
  const sentence = words.length === 1 ? (words[0] as string) : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`
  return `${sentence.charAt(0).toUpperCase()}${sentence.slice(1)}`
}

// One line per field, empty lists said as "every", so a reader never takes
// an empty list for nothing.
export function scopeLines(scope: WorkspaceDeviceScope, projectSlug: (id: string) => string): { label: string; value: string }[] {
  return [
    { label: "Credentials", value: scope.tags.length === 0 ? "Every credential its owner may use" : `Only those tagged ${scope.tags.join(", ")}` },
    { label: "Projects", value: scope.projects.length === 0 ? "Every project its owner may use" : `Only ${scope.projects.map(projectSlug).join(", ")}` },
    { label: "Environments", value: scope.maxEnvironment === "protected" ? "Protected environments too, where its owner may run them" : "Unprotected environments only" },
    { label: MODES_LABEL, value: modeWords(scope.modes) },
    { label: "Private credentials", value: scope.privateCredentials ? "Yes: it may use its owner's private credentials" : "No" },
    ...(scope.workloads === "required" ? [{ label: "Workloads", value: WORKLOADS_ONLY_WORDS }] : []),
    ...(scope.serviceRuns ? [{ label: SERVICES_LABEL, value: SERVICE_RUNS_WORDS }] : []),
  ]
}

export const WORKLOADS_ONLY_WORDS = "Acts only through short-lived workloads"
export const SERVICES_LABEL = "Services"
export const SERVICE_RUNS_WORDS = "Yes: it may start service runs (mehen run --service), which renew with no maximum life"

// A workload's scope in words: each field that narrows its machine's, or
// that it may use all its machine may.
export function workloadScopeLines(scope: WorkloadScope, projectSlug: (id: string) => string): string[] {
  const lines = [
    ...(scope.items ? [`Only ${scope.items.join(", ")}`] : []),
    ...(scope.tags ? [`Only credentials tagged ${scope.tags.join(", ")}`] : []),
    ...(scope.projects ? [`Only in ${scope.projects.map(projectSlug).join(", ")}`] : []),
    ...(scope.modes ? [`Only these ways: ${modeWords(scope.modes).toLowerCase()}`] : []),
  ]
  return lines.length > 0 ? lines : ["All its machine may use"]
}

// What a machine asked for at enrolment, in plain words: one line for each
// way it narrowed the usual scope. Empty when it asked for nothing less.
export function requestedLines(requested: EnrolRequestedScope | undefined, projectSlug: (id: string) => string): string[] {
  if (!requested) return []
  return [
    ...(requested.tags ? [`Uses only these credentials: those tagged ${requested.tags.join(", ")}`] : []),
    ...(requested.projects ? [`Works only in ${requested.projects.map(projectSlug).join(", ")}`] : []),
    ...(requested.modes ? [`Only these ways of using credentials: ${modeWords(requested.modes).toLowerCase()}`] : []),
    ...(requested.privateCredentials === false ? ["Never uses your private credentials"] : []),
    ...(requested.workloads === "required" ? [WORKLOADS_ONLY_WORDS] : []),
  ]
}

// The scope the change form asks for. Tags stay as they are (the form does
// not edit them); a team's machine never gets the private tick. The services
// tick is kept absent on a scope that never had it. Whether it
// narrows (applied at once) or widens (a proposal the owning account must
// accept) is the protocol's scopeChangeIsNarrowing, as the server decides.
// `projects` is null when the page offered no project editor (the project
// list could not be read, or the filter names projects this person cannot
// see): the machine's filter is then kept exactly, never dropped.
export type ScopeForm = { modes: readonly string[]; maxEnvironment: string; privateCredentials: boolean; serviceRuns: boolean; projects: readonly string[] | null }

export function scopeFromForm(before: WorkspaceDeviceScope, owner: OwnerRef, form: ScopeForm): Built<WorkspaceDeviceScope> {
  const modes = MODE_ORDER.filter((m) => form.modes.includes(m))
  if (modes.length === 0) return { ok: false, problems: ["Keep at least one way to use credentials, or revoke the machine."] }
  if (modes.length === 1 && modes[0] === "fill") return { ok: false, problems: [FILL_ONLY_WORDS] }
  return {
    ok: true,
    value: {
      tags: [...before.tags],
      projects: form.projects === null ? [...before.projects] : [...new Set(form.projects)],
      maxEnvironment: form.maxEnvironment === "protected" ? "protected" : "unprotected",
      modes,
      privateCredentials: owner.kind === "member" && form.privateCredentials,
      // The form does not edit it: dropping "required" would be a widening.
      ...(before.workloads !== undefined ? { workloads: before.workloads } : {}),
      ...(form.serviceRuns || before.serviceRuns !== undefined ? { serviceRuns: form.serviceRuns } : {}),
    },
  }
}

// ---------------------------------------------------------------- a scope proposal

// What the machine page's proposal card carries: the proposal, its machine
// and key, and, for the admission signer only, the project they admit or
// reject for (null for the owning account, who sends none).
export type RescopeShown = { proposal: string; device: string; thumbprint: string; project: string | null }

// The reject the passkey signs: exactly these terms, so the vault's plan for
// anything else is refused before a step-up starts.
export function rescopeRejectAction(shown: RescopeShown): WorkspaceStepUpAction {
  return { type: "device.rescope_reject", device: shown.device, thumbprint: shown.thumbprint, proposal: shown.proposal }
}

// The body for planning and sending an Admit or a Reject (POST
// /devices/:id/rescope-admit and /rescope-reject): the proposal, and the
// admission signer's project when the card carries one.
export function rescopeSignBody(shown: RescopeShown): { proposal: string; project?: string } {
  return { proposal: shown.proposal, ...(shown.project !== null ? { project: shown.project } : {}) }
}

export const RESCOPE_REJECTED_WORDS = "You rejected this proposal. Nothing changed on this machine: it may use exactly what it could before."

// ---------------------------------------------------------------- people and delegation

// A person's name as people tell them apart: with the stable member id
// beside it whenever someone else here has the same name. Plain text, for
// accessible names and option labels; the page marks hidden characters.
export function personLabel(person: { member: string; name: string }, everyone: readonly { member: string; name: string }[]): string {
  const twin = everyone.some((other) => other.member !== person.member && other.name === person.name)
  return twin ? `${person.name} (${person.member})` : person.name
}

// The workspace credentials a grant of these projects also lets someone use:
// each project's variables that point at a credential whose home is the
// whole workspace. Null when that cannot be told completely (the projects or
// credentials could not be read, a project is missing, or a variable points
// somewhere this person cannot see): the page then withholds the signing
// control rather than imply nothing is delegated.
export type ProjectVariables = { id: string; vars: readonly { item: string | null; note?: string }[] }
export type CredentialHomeOf = { slug: string; home: { kind: string } }

export function delegatedCredentials(projectIds: readonly string[], projects: readonly ProjectVariables[] | null, credentials: readonly CredentialHomeOf[] | null): string[] | null {
  if (projectIds.length === 0) return []
  if (projects === null || credentials === null) return null
  const homes = new Map(credentials.map((c) => [c.slug, c.home.kind]))
  const found = new Set<string>()
  for (const id of new Set(projectIds)) {
    const project = projects.find((p) => p.id === id)
    if (!project) return null
    for (const variable of project.vars) {
      if (variable.item === null) {
        if (variable.note !== undefined) return null
        continue
      }
      const home = homes.get(variable.item)
      if (home === undefined) return null
      if (home === "workspace") found.add(variable.item)
    }
  }
  return [...found].sort()
}
