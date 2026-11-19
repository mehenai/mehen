// A workspace's machines: the list (/w/:ws/devices) and one machine
// (/w/:ws/devices/:id, where the new-machine notice lands, so revoke and
// narrow are one tap from the top). The enrolment page a new machine's link
// opens is workspace-enrol.ts.
//
// Accepting your own machine and admitting someone else's are different
// acts with different words (vault/areas/workspace-devices.ts
// enrolmentWording): acceptance says the machine will act as you; admission
// never accepts on that person's behalf.

import type { MandateOpenProposal, MandateView, WorkloadView } from "@mehen/protocol"
import { compareVersions } from "@mehen/protocol/version"
import type { OwnerRef, WorkspaceDeviceScope, WorkspaceDeviceView, WorkspaceEnrolEvidenceView, WorkspaceProject, RescopeProposalView } from "@mehen/protocol/workspace"
import type { CliAdvice } from "../../cli-version.ts"
import { enrolmentWording } from "../../vault/areas/workspace-devices.ts"
import { askWarnings } from "../ask-safety.ts"
import { MODE_PLAIN, MODES_LABEL, SERVICES_LABEL, type MachineControls, type PeopleViewer, elevated, machineControls, scopeLines, workloadScopeLines } from "../client/people-logic.ts"
import { cardText, emptyState, fingerprintWords, kv, notice, pageHead, pill, responsiveTable, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, kindTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type PolicyRulesCardData, machineRulesLine, policyRulesCard } from "../policy-rules-list.ts"
import { mandateCard } from "./mandates.ts"
import type { WorkspaceShell } from "../shell.ts"
import { workspaceHref } from "../shell.ts"
import { TASK_LABEL_WORDS, relativeAgo } from "../wording.ts"
import { spellCardText } from "../../relay/spelling.ts"
import { FILL_CLI_VERSION, cliReadsFill } from "../../vault/fill-old-cli.ts"

const BACKEND_WORDS: Record<string, string> = {
  "secure-enclave": "Secure Enclave key (cannot leave the machine)",
  software: "Software key in a file on the machine",
}

function backendWords(backend: string): string {
  return BACKEND_WORDS[backend] ?? backend
}

// The key type in words, with the pill that says what a software key
// cannot prove. Shared by the enrol page and the machine cards.
export function keyWords(backend: string): Html {
  return html`${cardText(backendWords(backend))}${backend === "software" ? html` ${pill("cannot prove hardware", "muted", false)}` : ""}`
}

// `delegation`: for a team machine's admission, the whole-workspace
// credentials its team's shared projects let it use; null when that could
// not be read (admission is then withheld). Left out elsewhere.
// `workloads`: the machine's live workloads, on its own page; null when they
// could not be read.
// `cli`: the vault's CLI_MINIMUM_VERSION and the recommended version, the
// published release or CLI_RECOMMENDED_VERSION when higher (cli-version.ts
// cliAdvice), which each machine's version is marked against.
// `rules`: the machine's standing rules, on its own page, read only with
// POLICY_RULES on.
// `fill`: whether BROWSER_FILL is on here, which offers typing into web
// pages among the ways a machine may use credentials.
// `mandate`: on its own page with MANDATES on, the machine's live mandate,
// or null for none; left out, no Carry on without asking card. `proposals`:
// its open ones, for its owner.
export type MachinesData = { viewer: PeopleViewer | null; projects: WorkspaceProject[] | null; now: number; delegation?: string[] | null; workloads?: WorkloadView[] | null; cli?: CliAdvice; rules?: PolicyRulesCardData; fill?: boolean; mandate?: MandateView | null; proposals?: MandateOpenProposal[] }

const MODES = ["relay", "sign", "mint", "placeholder", "lease"] as const
const MODES_WITH_FILL = ["relay", "sign", "mint", "placeholder", "fill", "lease"] as const
export const FILL_UPDATE_FIRST_WORDS = `Update mehen on this machine first (${FILL_CLI_VERSION} or later).`

// One way of using credentials, ticked as the machine has it. Fill is
// added only once the machine's mehen last proved it reads it (ruling F2);
// a machine that has it may always give it up.
function modeTick(m: (typeof MODES_WITH_FILL)[number], device: WorkspaceDeviceView, controls: MachineControls): Html {
  const held = device.scope.modes.includes(m)
  const needsUpdate = m === "fill" && !held && !cliReadsFill(device.lastCliVersion)
  const disabled = (!controls.propose && !held) || needsUpdate
  return html`<label class="tick"><input type="checkbox" data-input="scope-mode" value="${m}"${held ? html` checked` : ""}${disabled ? html` disabled` : ""}><span>${MODE_PLAIN[m].charAt(0).toUpperCase()}${MODE_PLAIN[m].slice(1)}</span></label>${needsUpdate && controls.propose ? html`<p class="hint" data-region="fill-update-first">${FILL_UPDATE_FIRST_WORDS}</p>` : ""}`
}

function slugOf(projects: readonly WorkspaceProject[] | null): (id: string) => string {
  return (id) => projects?.find((p) => p.id === id)?.slug ?? "a project you cannot see"
}

export function scopeList(scope: WorkspaceDeviceScope, projects: readonly WorkspaceProject[] | null): Html {
  return html`<dl class="kv facts scope">${scopeLines(scope, slugOf(projects)).map((l) => html`<dt>${l.label}</dt><dd>${cardText(l.value)}</dd>`)}</dl>`
}

export function ownerLine(owner: OwnerRef): Html {
  return owner.kind === "team" ? html`Team ${cardText(owner.name)}` : cardText(owner.name)
}

function evidenceWords(evidence: WorkspaceEnrolEvidenceView): Html {
  return html`${"name" in evidence ? cardText(evidence.name) : "Signed with a passkey"}, ${timeTag(evidence.at)}`
}

function seen(lastSeenAt: string | null, now: number): Html {
  if (lastSeenAt === null) return html`never`
  const ago = relativeAgo(lastSeenAt, now)
  return ago !== null ? html`${ago}` : timeTag(lastSeenAt)
}

// The mehen a machine last called with: below the vault's minimum it is
// refused until it updates, below the recommended version an update is
// waiting. A revoked machine is not marked.
function cliVersion(device: WorkspaceDeviceView, cli: CliAdvice | undefined): Html | null {
  const version = device.lastCliVersion
  if (version === null) return null
  const below = (floor: string | null | undefined) => !device.revoked && !!floor && compareVersions(version, floor) < 0
  const mark = below(cli?.minimum) ? pill("too old to connect", "warn", false) : below(cli?.recommended) ? pill("update available", "warn", false) : null
  return html`<span data-region="cli-version">mehen ${version}${mark !== null ? html` ${mark}` : ""}</span>`
}

// ---------------------------------------------------------------- the list

function deviceRow(shell: WorkspaceShell, device: WorkspaceDeviceView, data: MachinesData): Html {
  const version = cliVersion(device, data.cli)
  return html`<li class="row${device.revoked ? " muted" : ""}">
    ${kindTile("machine", device.backend, undefined, device.name)}
    <a class="row-main" href="${workspaceHref(shell.identity.workspace.slug, `/devices/${encodeURIComponent(device.device)}`)}"><span class="row-title">${cardText(device.name)}</span><span class="row-sub">${ownerLine(device.owner)} · seen ${seen(device.lastSeenAt, data.now)}${version !== null ? html` · ${version}` : ""}</span></a>
    <span class="row-side">${device.revoked ? pill("revoked", "muted", false) : device.pendingRescope !== null ? pill("scope change waiting", "warn") : device.scope.privateCredentials ? pill("private credentials", "accent", false) : ""}</span>
  </li>`
}

export function machinesPage(shell: WorkspaceShell, devices: WorkspaceDeviceView[], data: MachinesData): PageInput {
  const live = devices.filter((d) => !d.revoked)
  const gone = devices.filter((d) => d.revoked)
  return {
    title: "Machines",
    viewer: null,
    workspace: shell,
    current: "machines",
    boot: { page: "machines" },
    body: html`${pageHead({ title: "Machines", lead: "Each machine acts for its owner, a person or a team, and never reaches further than its owner may.", actions: html`<a class="btn secondary" href="${workspaceHref(shell.identity.workspace.slug, "/connect-agent")}">${icon("terminal")}<span>Connect an agent</span></a>` })}
      <section class="card">${live.length === 0 ? emptyState("cpu", "No machines yet", "Connect an agent to enrol one.") : html`<ul class="rows">${live.map((d) => deviceRow(shell, d, data))}</ul>`}</section>
      ${gone.length > 0 ? html`<section class="card"><h2>Revoked</h2><ul class="rows compact">${gone.map((d) => deviceRow(shell, d, data))}</ul></section>` : ""}`,
  }
}

// ---------------------------------------------------------------- one machine

// The change form: every field, filled with the machine's scope now. The
// browser compares old and new as the vault does: a narrower scope applies
// at once; anything wider becomes a proposal its owning account accepts.
function scopeForm(device: WorkspaceDeviceView, controls: MachineControls, projects: readonly WorkspaceProject[] | null, viewer: PeopleViewer | null, fill: boolean): Html {
  const scope = device.scope
  const team = device.owner.kind === "team"
  const whose = device.owner.kind === "member" && device.owner.member === viewer?.member ? html`my` : html`${cardText(device.owner.name)}'s`
  return html`<details class="fold" data-region="scope-change"><summary>${icon("chevronRight")}<span>${controls.propose ? "Change what it may use" : "Narrow what it may use"}</span></summary>
    <form class="stack" data-form="scope-change" novalidate>
      <fieldset class="field"><legend class="label">${MODES_LABEL}</legend>${(fill || scope.modes.includes("fill") ? MODES_WITH_FILL : MODES).map((m) => modeTick(m, device, controls))}</fieldset>
      <fieldset class="field"><legend class="label">Environments</legend>
        <label class="tick"><input type="radio" name="scope-env" data-input="scope-env" value="unprotected"${scope.maxEnvironment === "unprotected" ? html` checked` : ""}><span>Unprotected only</span></label>
        <label class="tick"><input type="radio" name="scope-env" data-input="scope-env" value="protected"${scope.maxEnvironment === "protected" ? html` checked` : ""}${!controls.propose && scope.maxEnvironment !== "protected" ? html` disabled` : ""}><span>Protected too, where its owner may run them</span></label>
      </fieldset>
      ${team ? html`<p class="small muted">A team's machine never uses anyone's private credentials.</p>` : html`<label class="tick"><input type="checkbox" data-input="scope-private"${scope.privateCredentials ? html` checked` : ""}${!controls.propose && !scope.privateCredentials ? html` disabled` : ""}><span>It may use ${whose} private credentials</span></label>`}
      <label class="tick"><input type="checkbox" data-input="scope-service"${scope.serviceRuns ? html` checked` : ""}${!controls.propose && !scope.serviceRuns ? html` disabled` : ""}><span>May run services: <code>mehen run --service</code> renews with no maximum life, in unprotected environments only</span></label>
      ${projectEditor(scope, controls, projects)}
      <p class="small muted" data-region="scope-kind">${controls.propose ? html`Narrowing applies at once. Anything wider is a proposal: ${team ? "an owner or admin signs it" : html`${cardText(device.owner.name)} must accept it on their own machine`}.` : html`Narrowing applies at once. To widen it, ask the person who invited you, or an owner or admin, to propose the wider scope; you then accept it on this page.`}</p>
      <button type="submit" class="btn primary">${icon("passkey")}<span>Sign the change with passkey</span></button>
    </form>
  </details>`
}

// The project filter's editor, only where it can show the whole filter:
// with the project list unreadable, or the filter naming a project this
// person cannot see, there is none and the filter is kept exactly. Someone
// who may only narrow sees just the filter's own projects (or, with no
// filter, every project, where ticking one narrows).
function projectEditor(scope: WorkspaceDeviceScope, controls: MachineControls, projects: readonly WorkspaceProject[] | null): Html {
  const kept = (why: string) => html`<p class="small muted" data-region="scope-projects-kept">${why}</p>`
  if (projects === null) return scope.projects.length > 0 ? kept("Its project filter is kept as it is: the project list could not be read.") : html``
  if (scope.projects.some((id) => !projects.some((p) => p.id === id))) return kept("Its project filter includes projects you cannot see, so it is kept as it is.")
  const offered = !controls.propose && scope.projects.length > 0 ? projects.filter((p) => scope.projects.includes(p.id)) : projects
  if (offered.length === 0) return html``
  return html`<fieldset class="field" data-region="scope-projects"><legend class="label">Only these projects (none ticked: every project its owner may use, which is wider)</legend>${offered.map((p) => html`<label class="tick"><input type="checkbox" data-input="scope-project" value="${p.id}"${scope.projects.includes(p.id) ? html` checked` : ""}><span><code>${cardText(p.slug)}</code></span></label>`)}</fieldset>`
}

// Every string on the machine page someone else chose, for the ask warnings:
// the machine's name and host, where and by what it was
// started, its owner, who accepted and admitted it where the page names
// them, the proposer and signers, and every scope entry.
function rescopeTexts(device: WorkspaceDeviceView, proposal: RescopeProposalView, projects: readonly WorkspaceProject[] | null): string[] {
  const entries = (scope: WorkspaceDeviceScope) => [...scope.tags, ...scope.projects.map(slugOf(projects))]
  const named = (evidence: WorkspaceEnrolEvidenceView | null) => (evidence !== null && "name" in evidence ? [evidence.name] : [])
  return [
    device.name,
    ...(device.host !== null ? [device.host] : []),
    ...(device.start !== null ? [device.start.clientLabel, ...(device.start.place !== null ? [device.start.place] : [])] : []),
    device.owner.name,
    ...named(device.acceptance),
    ...named(device.admission),
    proposal.proposer.name,
    ...proposal.requiredSigners.map((s) => s.name),
    ...entries(proposal.before),
    ...entries(proposal.after),
  ]
}

// The project an admission signer admits or rejects for. The vault judges
// admission on a project the guest owner holds an active share on and the
// signer manages (vault/access.ts rescopeAdmitAuthority), and the proposal
// records none, so the page picks the first such project by slug. With
// none, the signer is offered neither Admit nor Reject.
function admissionProject(device: WorkspaceDeviceView, viewer: PeopleViewer, projects: readonly WorkspaceProject[] | null, now: number): string | null {
  if (device.owner.kind !== "member" || projects === null) return null
  const guest = device.owner.member
  const manages = (project: WorkspaceProject) => elevated(viewer.role) || project.access.level === "manage"
  const shared = (project: WorkspaceProject) => (project.shares ?? []).some((s) => s.subject.kind === "member" && s.subject.member === guest && (s.expiresAt === null || Date.parse(s.expiresAt) > now))
  return [...projects].filter((p) => manages(p) && shared(p)).sort((a, b) => (a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0))[0]?.id ?? null
}

// The rescope proposal is an ask, in the decision card's order: eyebrow,
// what changes (now beside proposed), who signs, the warning, the actions.
// Reject is offered to whoever is offered Accept or Admit: a passkey step
// over the vault's device.rescope_reject for exactly the proposal, machine
// and key this card carries, which ends the proposal and changes nothing on
// the machine. Plain, it is the quiet button beside Accept or Admit. With
// hidden or control characters in anything the card shows, the warning
// comes first, the card turns red, Reject is the emphasised button and
// accepting drops to a quiet one (still a passkey step).
function proposalCard(device: WorkspaceDeviceView, proposal: RescopeProposalView, viewer: PeopleViewer | null, account: string, projects: readonly WorkspaceProject[] | null, now: number): Html {
  // Only the owning account, not held back, on an open proposal that has
  // not run out; the server refuses anything else anyway. Admit likewise
  // only for the designated admission signer: the vault shows a signer's
  // account to that signer alone, so an omitted account is someone else's.
  const open = proposal.state === "open" && Date.parse(proposal.expiresAt) > now
  const mineToAccept = viewer !== null && !viewer.blocked && open && proposal.requiredSigners.some((s) => s.as === "owner_acceptance" && s.account === account) && !proposal.signedBy.includes(account)
  const admission = proposal.requiredSigners.find((s) => s.as === "admission")
  const ownMachine = device.owner.kind === "member" && device.owner.member === viewer?.member
  const project = viewer !== null && !viewer.blocked && open && admission !== undefined && !ownMachine && admission.account === account && !proposal.signedBy.includes(account) ? admissionProject(device, viewer, projects, now) : null
  const mayAdmit = project !== null
  const warnings = askWarnings(rescopeTexts(device, proposal, projects))
  const warned = warnings.length > 0
  const accepting = warned ? "btn quiet" : "btn primary"
  const reject = html`<button type="button" class="${warned ? "btn danger" : "btn quiet"}" data-action="rescope-reject" data-proposal="${proposal.id}">${icon("passkey")}<span>Reject this proposal</span></button>`
  const before = scopeLines(proposal.before, slugOf(projects))
  const after = scopeLines(proposal.after, slugOf(projects))
  // By label, so a line only one side has (Workloads, Services) still lines up.
  const labels = [...new Set([...before, ...after].map((line) => line.label))]
  const value = (lines: typeof before, label: string) => lines.find((line) => line.label === label)?.value ?? (label === "Workloads" ? "Directly or through workloads" : label === SERVICES_LABEL ? "No" : "")
  const rows = labels.map((label) => [label, cardText(value(before, label)), cardText(value(after, label))])
  return html`<section class="card decision${warned ? " warned" : ""}" data-region="proposal" data-proposal="${proposal.id}" data-device="${proposal.device}" data-thumbprint="${proposal.thumbprint}"${project !== null ? html` data-project="${project}"` : ""}>
    ${warned ? html`<div data-region="warnings">${notice("error", "Check this request yourself", warnings.join(" "))}</div>` : ""}
    <p class="eyebrow">A wider scope is waiting</p>
    <h2>Change what ${cardText(device.name)} may use</h2>
    <p>${cardText(proposal.proposer.name)} proposed it; it ends ${timeTag(proposal.expiresAt)}. Nothing changes until every signer below has signed.</p>
    ${responsiveTable(["What", "Now", "Proposed"], rows)}
    <h3>Who signs</h3>
    <ul class="plain">${proposal.requiredSigners.map((s) => html`<li>${cardText(s.name)}: ${s.as === "owner_acceptance" ? "accepts it as their own machine" : "admits it"}</li>`)}</ul>
    ${mineToAccept ? html`<p class="warning">${enrolmentWording("accept", "").warning}.</p>` : ""}
    ${mayAdmit ? html`<p class="small muted">${enrolmentWording("admit", device.owner.name).warning}</p>` : ""}
    ${mineToAccept || mayAdmit ? html`<div class="actions" data-region="rescope-actions">
      ${warned ? reject : ""}
      ${mineToAccept ? html`<button type="button" class="${accepting}" data-action="rescope-accept" data-proposal="${proposal.id}">${icon("passkey")}<span>Accept this scope on my own machine</span></button>` : ""}
      ${mayAdmit ? html`<button type="button" class="${accepting}" data-action="rescope-admit" data-proposal="${proposal.id}">${icon("passkey")}<span>Admit ${cardText(device.owner.name)}'s machine at this scope</span></button>` : ""}
      ${warned ? "" : reject}
    </div>
    <p class="small" data-region="rescope-rejected" role="status" hidden></p>` : ""}
  </section>`
}

// The machine's live workloads: short-lived keys it made for its tasks,
// each narrower than the machine. The label is the machine's words. A
// person who may revoke the machine may end any one of them, with a passkey.
function workloadsCard(workloads: readonly WorkloadView[] | null | undefined, revoke: boolean, projects: readonly WorkspaceProject[] | null, now: number): Html {
  if (workloads === undefined) return html``
  if (workloads === null) return html`<section class="card" data-region="workloads"><h2>Workloads</h2><p class="muted">Its workloads could not be read.</p></section>`
  if (workloads.length === 0) return html``
  return html`<section class="card" data-region="workloads"><h2>Workloads</h2><p class="small muted">Short-lived keys this machine made for its tasks. Each may use only what is listed, within what the machine may use.</p>
    <ul class="rows">${workloads.map((w) => html`<li class="row" data-workload="${w.workload}">
      <span class="row-main"><span class="row-title"><code>${cardText(w.label)}</code> <span class="muted small">(${TASK_LABEL_WORDS})</span></span>
        <span class="row-sub">${workloadScopeLines(w.scope, slugOf(projects)).join(". ")}. Ends ${timeTag(w.expiresAt)} · seen ${seen(w.lastSeenAt, now)}</span></span>
      ${revoke ? html`<span class="row-side"><button type="button" class="btn danger-quiet" data-action="workload-revoke" data-workload="${w.workload}">${icon("passkey")}<span>Revoke</span></button></span>` : ""}
    </li>`)}</ul></section>`
}

// Revoking is the one destructive act here: in a folded danger zone at the
// bottom, as the outline button, with what it does said before it.
function dangerZone(): Html {
  return html`<details class="card fold danger-zone" data-region="danger-zone"><summary>${icon("chevronRight")}<span>Revoke this machine</span></summary>
    <p>Revoking stops its runs and requests through Mehen at once. It cannot recall a request already sent or a value already leased; rotate an exposed credential at its service. There is no transfer: a new owner enrols a fresh key.</p>
    <div class="actions"><button type="button" class="btn danger-quiet" data-action="device-revoke">${icon("passkey")}<span>Revoke with passkey</span></button></div>
  </details>`
}

export function machinePage(shell: WorkspaceShell, device: WorkspaceDeviceView, data: MachinesData): PageInput {
  const controls = machineControls(data.viewer, device.owner, device.revoked)
  const start = device.start
  const rulesLine = machineRulesLine(shell.identity.workspace.slug, data.rules)
  return {
    title: spellCardText(device.name),
    viewer: null,
    workspace: shell,
    current: "machines",
    ...(rulesLine !== undefined ? { policyRules: rulesLine } : {}),
    boot: { page: "machine", device: device.device, scope: device.scope, owner: device.owner, propose: controls.propose },
    body: html`${pageHead({
      eyebrow: "Machine",
      title: cardText(device.name),
      lead: device.revoked ? html`Revoked ${device.revokedAt !== undefined ? timeTag(device.revokedAt) : ""}. It can no longer act.` : html`Acts for ${ownerLine(device.owner)}. Last seen ${seen(device.lastSeenAt, data.now)}. Check it is one you expected; narrow or revoke it if not.`,
    })}
      ${device.pendingRescope !== null && !device.revoked ? proposalCard(device, device.pendingRescope, data.viewer, shell.identity.account, data.projects, data.now) : ""}
      <section class="card"><h2>The machine</h2>${fingerprintWords(device.fingerprintWords)}${kv([
        ["Owner", ownerLine(device.owner)],
        ["Host", device.host !== null ? cardText(device.host) : html`<span class="muted">not given</span>`],
        ["Key", keyWords(device.backend)],
        ...(start !== null ? ([["Asked", html`<span data-region="start">${timeTag(start.at)}</span>`], ["From", start.place !== null ? cardText(start.place) : html`<span class="muted">not known</span>`], ["Client", cardText(start.clientLabel)]] as const) : []),
        ["Enrolled", timeTag(device.createdAt)],
        ...(device.acceptance !== null ? ([["Accepted by its owner", evidenceWords(device.acceptance)]] as const) : []),
        ...(device.admission !== null ? ([["Admitted", evidenceWords(device.admission)]] as const) : []),
        ["Last seen", seen(device.lastSeenAt, data.now)],
        ["CLI version", cliVersion(device, data.cli) ?? html`<span class="muted">not reported yet</span>`],
      ], "facts")}</section>
      <section class="card"><h2>What it may use</h2>${scopeList(device.scope, data.projects)}${controls.narrow ? scopeForm(device, controls, data.projects, data.viewer, data.fill === true) : ""}</section>${data.mandate !== undefined && data.viewer !== null ? mandateCard(shell, { viewer: { role: data.viewer.role, member: data.viewer.member, held: data.viewer.blocked }, device, mandate: data.mandate, proposals: data.proposals ?? [], now: data.now }) : ""}
      ${device.revoked ? "" : workloadsCard(data.workloads, controls.revoke, data.projects, data.now)}
      ${policyRulesCard(shell.identity.workspace.slug, data.rules, data.projects)}${controls.revoke ? dangerZone() : ""}`,
  }
}
