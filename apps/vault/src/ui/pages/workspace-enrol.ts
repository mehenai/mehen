// The enrolment page a new machine's link opens: /w/:ws/e/<code> (the code
// form) or /w/:ws/e/enr_<id> (the id form, which never carries the clear
// code). Both forms hide the same persisted group, and the browser's check
// is keyed by the ref the page was opened with.
//
// Accepting your own machine and admitting someone else's are different
// acts with different words (vault/areas/workspace-devices.ts
// enrolmentWording): acceptance says the machine will act as you; admission
// never accepts on that person's behalf. The page carries three of the four
// fingerprint groups and the hidden one's check hash, never the group
// itself, the thumbprint or the key: the exact action to sign comes from the
// vault only once the typed group matches.
//
// A live link takes the ask pages' one decision layout: the
// warning card first when anything the page shows holds hidden or control
// characters, the decision card, the check, what it may use, what happens
// next, and the decision bar with Reject and Accept or Admit, Reject the
// filled danger button when warned. A lapsed link shows its three groups,
// how to bring it back and, for an owner or admin, Reject; a settled one
// its outcome, with the button to the same machine's newer link when the
// vault names one.

import type { WorkspaceEnrolView, WorkspaceRole } from "@mehen/protocol/workspace"
import { ENROLMENT_TTL_MS } from "../../directory/enrolment.ts"
import { enrolmentWording } from "../../vault/areas/workspace-devices.ts"
import { askPlace, decisionBar, warningCard } from "../ask-evidence.ts"
import { askWarnings, enrolTexts } from "../ask-safety.ts"
import { type PeopleViewer, requestedLines } from "../client/people-logic.ts"
import { GROUP_WORDS, cardText, copyBox, countdownTimer, fingerprintGlyphs, fingerprintWords, notice, stateCard } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon, kindTile } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { WorkspaceShell } from "../shell.ts"
import { workspaceHref } from "../shell.ts"
import { GUEST_ADMISSION_WORDS, TYPE_GROUP_WORDS, formatTime } from "../wording.ts"
import { type MachinesData, keyWords, ownerLine, scopeList } from "./machines.ts"
import { delegationWords } from "./people.ts"

const ENROL_SECONDS = ENROLMENT_TTL_MS / 1000

// What the private tick left off means for the agent on the machine: a
// device without it can neither use nor create a credential in its owner's
// private home (vault/access.ts), so its agent asks in a project instead.
// A guest cannot widen their own machine (people-logic machineControls): an
// insider proposes it and the guest accepts it on the machine's page.
const PRIVATE_OFF_LEAD = "Left off, an agent on this machine cannot use or ask for credentials only you can see; it can still use the other credentials you may use, and ask for new ones in a project you can edit."
export const PRIVATE_OFF_WORDS = `${PRIVATE_OFF_LEAD} You can turn it on later from the machine's page.`
export const GUEST_PRIVATE_OFF_WORDS = `${PRIVATE_OFF_LEAD} To turn it on later, ask the person who invited you to propose it; you then accept it on the machine's page.`

function glyphSlots(fp: WorkspaceEnrolView["fingerprint"]): string[] {
  const slots: string[] = [...fp.groups]
  slots.splice(fp.hidden, 0, "")
  return slots
}

function requestedWords(view: WorkspaceEnrolView): Html {
  return view.requestedOwner.kind === "team" ? html`a machine for team ${cardText(view.requestedOwner.name)}` : html`a machine for whoever accepts it as their own`
}

// A machine that asked for less than usual says so first, in its own terms.
function requestedNotice(view: WorkspaceEnrolView, data: Pick<MachinesData, "projects">): Html {
  const lines = requestedLines(view.requested, (id) => data.projects?.find((p) => p.id === id)?.slug ?? "a project you cannot see")
  if (lines.length === 0) return html``
  return html`<div data-region="enrol-requested"><p class="eyebrow">This machine asked for less than usual</p><ul class="plain">${lines.map((line) => html`<li>${cardText(line)}</li>`)}</ul></div>`
}

// What this viewer may do now. Acceptance is offered only while the owning
// account has not yet accepted: once it has, the machine waits for
// admission, and accepting again would change nothing.
function enrolChoices(view: WorkspaceEnrolView): { accept: boolean; admit: boolean; reject: boolean } {
  return { accept: view.actions.includes("accept") && view.state === "pending_owner_acceptance", admit: view.actions.includes("admit"), reject: view.actions.includes("reject") }
}

function ownerName(view: WorkspaceEnrolView): string {
  return view.owner !== null ? view.owner.name : view.requestedOwner.kind === "team" ? view.requestedOwner.name : ""
}

// A team's machine reaches every whole-workspace credential its team's
// projects reference: named before the passkey, or no admission at all.
function admitOffered(view: WorkspaceEnrolView, delegation: string[] | null | undefined): boolean {
  return enrolChoices(view).admit && (view.requestedOwner.kind !== "team" || (delegation !== undefined && delegation !== null))
}

function admitLabel(view: WorkspaceEnrolView): { label: string; warning: string } {
  return view.requestedOwner.kind === "team" ? { label: `Admit this machine for team ${ownerName(view)}`, warning: "Admission does not accept this machine as your own." } : enrolmentWording("admit", ownerName(view))
}

// The page's own links, under the workspace.
function enrolHref(shell: WorkspaceShell, ref: string): string {
  return workspaceHref(shell.identity.workspace.slug, `/e/${encodeURIComponent(ref)}`)
}

function fingerprintCard(view: WorkspaceEnrolView, typing: boolean, form: boolean): Html {
  const fp = view.fingerprint
  const which = GROUP_WORDS[fp.hidden] ?? `${fp.hidden + 1}th`
  return html`<section class="card fp" data-region="enrol-check"><p class="eyebrow">Does the terminal show this key?</p>
    <p class="muted small">Three groups are here; the ${which} is hidden. ${typing ? "Type it from the terminal to prove you looked." : "The person at the machine types it."}</p>
    ${fingerprintWords(fp.words)}${fingerprintGlyphs(glyphSlots(fp), fp.hidden)}
    ${typing ? html`<div class="fp-input"><label for="fingerprint-group">Type the ${which} group</label><input id="fingerprint-group" type="text"${form ? html` form="decide"` : ""} data-input="fingerprint-group" placeholder="····" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="8"></div>` : ""}
    <p class="note">If anything differs, reject: someone else made this request.</p>
  </section>`
}

// Every name in it through cardText, as everywhere else on the page. Only
// a guest's own machine waits for admission after it is accepted.
function nextWords(view: WorkspaceEnrolView, accept: boolean, admit: boolean, role: WorkspaceRole | null): Html | null {
  const name = cardText(view.name)
  const workspace = cardText(view.workspace.name)
  if (accept && role === "guest") return html`Accepting makes ${name} act as you in ${workspace}; it then waits for an owner, an admin or a manager of its shared project to admit it. Rejecting ends this link and enrols nothing.`
  if (accept) return html`Accepting makes ${name} act as you in ${workspace}; its agent's <code>mehen wait</code> then finishes by itself. Rejecting ends this link and enrols nothing.`
  if (admit) return html`Admitting lets ${name} into ${workspace} with what it may use below. Rejecting ends this link and enrols nothing.`
  return null
}

// Every string an enrolment page shows: the view's own, and what the page
// resolves around it, the project names its scope lists and the
// credentials a team's admission delegates.
function enrolWarnings(view: WorkspaceEnrolView, data: Pick<MachinesData, "projects" | "delegation">): string[] {
  const projects = (data.projects ?? []).filter((p) => view.scope.projects.includes(p.id)).map((p) => p.slug)
  return askWarnings([...enrolTexts(view), ...projects, ...(data.delegation ?? [])])
}

function livePage(shell: WorkspaceShell, view: WorkspaceEnrolView, data: MachinesData, base: Pick<PageInput, "title" | "viewer" | "workspace" | "focus">): PageInput {
  const choices = enrolChoices(view)
  const admit = admitOffered(view, data.delegation)
  const typing = choices.accept || choices.admit
  const deciding = choices.accept || admit || choices.reject
  const warnings = enrolWarnings(view, data)
  const warned = warnings.length > 0
  const acceptWords = enrolmentWording("accept", "")
  const admitWords = admitLabel(view)
  const next = nextWords(view, choices.accept, admit, data.viewer?.role ?? null)
  const accepting = choices.accept ? { action: "enrol-accept", label: acceptWords.label, passkey: true, disabled: true } : admit ? { action: "enrol-admit", label: cardText(admitWords.label), passkey: true, disabled: true } : null
  return {
    ...base,
    bar: deciding,
    boot: { page: "workspace-enrol", ref: view.ref, check: view.fingerprint.check, hidden: view.fingerprint.hidden, enrolment: view.enrolment, digest: view.digest, owner: view.owner ?? (view.requestedOwner.kind === "team" ? { kind: "team", team: view.requestedOwner.team, name: view.requestedOwner.name } : null), role: data.viewer?.role ?? null, lease: view.lease, fingerprint: { groups: view.fingerprint.groups, hidden: view.fingerprint.hidden, words: view.fingerprint.words }, ...(choices.accept && data.viewer !== null ? { acceptance: { workspace: view.workspace.id, enrolment: view.enrolment, account: shell.identity.account, member: data.viewer.member, scope: view.scope, start: view.start } } : {}) },
    body: html`${warningCard(warnings)}<section class="card decision enrol-head${warned ? " warned" : ""}" aria-label="The decision" data-region="decision">
        <div class="decision-head">${kindTile("machine", view.backend, "lg", view.name)}<div><p class="eyebrow">A new machine wants to join</p><h1>${cardText(view.name)}</h1></div></div>
        <p class="who ask-context">${askPlace(shell.identity.origin, view.workspace)} · ${requestedWords(view)}${view.claimed ? html`, started for <b>${cardText(view.claimed.name)}</b>` : ""}</p>
        <dl class="summary">
          <dt>Host</dt><dd>${view.host !== null ? cardText(view.host) : html`<span class="muted">not given</span>`}</dd>
          <dt>Key</dt><dd>${keyWords(view.backend)}</dd>
          <dt>Asked</dt><dd data-region="enrol-start">${formatTime(view.start.at)}${view.start.place !== null ? html` from ${cardText(view.start.place)}` : ""} by ${cardText(view.start.clientLabel)}</dd>
          <dt>You are</dt><dd data-region="enrol-acceptor">${view.acceptorPlace !== null ? html`in ${cardText(view.acceptorPlace)}` : view.acceptorLocal === true ? "on this machine" : "somewhere the vault cannot place"}</dd>
          ${view.owner !== null ? html`<dt>Accepted by</dt><dd>${ownerLine(view.owner)}</dd>` : ""}
          <dt>This link</dt><dd>${countdownTimer(view.expiresAt, ENROL_SECONDS, data.now)}</dd>
        </dl>
        ${choices.accept
          ? html`<form class="stack" id="decide" data-form="decide" novalidate>${view.requested?.privateCredentials === false ? "" : html`<label class="tick" data-region="enrol-private"><input type="checkbox" data-input="enrol-private"${view.scope.privateCredentials ? html` checked` : ""}><span>It may use my private credentials${view.scope.privateCredentials ? " (on by default for your own machine)" : data.viewer?.role === "guest" ? " (off by default for a guest's machine)" : ""}</span></label><p class="small muted" data-region="enrol-private-hint">${data.viewer?.role === "guest" ? GUEST_PRIVATE_OFF_WORDS : PRIVATE_OFF_WORDS}</p>`}
            <div data-region="accept-warning">${notice("warn", "It will act as you", `${acceptWords.warning}.`)}</div></form>`
          : deciding ? html`<form id="decide" data-form="decide" novalidate></form>` : ""}
        ${admit ? html`<p class="small muted" data-region="admit-warning">${admitWords.warning}</p>` : ""}
      </section>
      ${fingerprintCard(view, typing, deciding)}
      <section class="card"><h2>What it may use</h2>${requestedNotice(view, data)}${scopeList(view.scope, data.projects)}<p class="small muted">Its reach is this scope within what its owner may use. Narrow it later from the machine's page.</p></section>
      ${choices.admit && view.requestedOwner.kind === "team" ? html`<section class="card"><p data-region="admit-delegation"><b>This also lets it use:</b> ${delegationWords(data.delegation ?? null)}</p></section>` : ""}
      ${!choices.admit && view.state === "pending_admission" && data.viewer?.role === "guest" ? html`<section class="card"><p data-region="guest-admission">${GUEST_ADMISSION_WORDS}</p><p class="label">This page's link</p>${copyBox(`${shell.identity.origin}${enrolHref(shell, view.ref)}`)}</section>` : ""}
      ${!deciding && data.viewer?.role !== "guest" ? html`<p class="muted">Only the person this machine is for can accept it. A team's machine is admitted by an owner or admin, and a guest's machine also needs admission.</p>` : ""}
      ${next !== null ? html`<div class="ask-next">${notice("info", "What happens next", next)}</div>` : ""}
      ${deciding
        ? decisionBar({
            warned,
            form: "decide",
            caption: html`<span class="enables" data-region="enrol-enables">${typing && accepting !== null ? TYPE_GROUP_WORDS : ""}</span>`,
            decline: choices.reject ? { action: "enrol-reject", label: "Reject" } : null,
            accept: accepting,
          })
        : ""}`,
  }
}

// Past its hour but inside its day: the three visible groups, how to bring
// the same link back, and Reject for an owner or admin.
function lapsedPage(shell: WorkspaceShell, view: WorkspaceEnrolView, data: MachinesData, base: Pick<PageInput, "title" | "viewer" | "workspace" | "focus">): PageInput {
  const reject = view.actions.includes("reject")
  const warnings = enrolWarnings(view, data)
  const until = formatTime(view.hardExpiresAt)
  const fp = view.fingerprint
  return {
    ...base,
    boot: { page: "enrol-closed" },
    body: html`${warningCard(warnings)}${stateCard({
      tone: "expired",
      icon: "clock",
      heading: "This link has lapsed",
      lead: html`<b>${cardText(view.name)}</b> asked to join ${cardText(view.workspace.name)}. This link has lapsed. Ask the agent to run <code>mehen wait ${view.enrolment}</code> or <code>mehen enrol --workspace ${view.workspace.slug}</code> again; the same link comes back to life until ${until}.`,
      after: html`<div data-region="enrol-lapsed">${fingerprintWords(fp.words)}${fingerprintGlyphs(glyphSlots(fp), fp.hidden)}</div>`,
      primary: reject ? html`<button type="button" class="btn ${warnings.length > 0 ? "danger" : "danger-quiet"}" data-action="enrol-reject" data-ref="${view.ref}">Reject</button>` : undefined,
      secondary: html`<a class="btn secondary" href="${workspaceHref(shell.identity.workspace.slug, "/devices")}">${icon("cpu")}<span>Machines</span></a>`,
    })}`,
  }
}

// Settled: enrolled, rejected, or ran out, and for a link the same machine
// replaced, the button to its newer one.
function closedPage(shell: WorkspaceShell, view: WorkspaceEnrolView, data: MachinesData, base: Pick<PageInput, "title" | "viewer" | "workspace" | "focus">): PageInput {
  const warnings = enrolWarnings(view, data)
  const heading = view.state === "active" ? "Enrolled" : view.state === "rejected" ? "Rejected" : "This link ran out"
  const successor = view.state === "expired" ? view.successor : null
  const lead =
    view.state === "active"
      ? html`<b>${cardText(view.name)}</b> is enrolled in ${cardText(view.workspace.name)}. ${view.startedByAgent === true ? html`Its agent's <code>mehen wait</code> finishes by itself; restart the agent once so its Mehen tools load.` : "The terminal that asked carries on by itself."} Review the machine from the machines page.`
      : view.state === "rejected"
        ? html`Nothing was enrolled. If you did not expect <b>${cardText(view.name)}</b>, check which agents can reach your machines.`
        : successor !== null
          ? html`This link ran out. The same machine asked again; its new link is valid until ${formatTime(successor.expiresAt)}.`
          : html`Nothing was enrolled. <b>${cardText(view.name)}</b> has to ask again.`
  const machines = html`<a class="btn secondary" href="${workspaceHref(shell.identity.workspace.slug, "/devices")}">${icon("cpu")}<span>Machines</span></a>`
  return {
    ...base,
    boot: { page: "enrol-closed" },
    body: html`${warningCard(warnings)}${stateCard({
      tone: view.state === "active" ? "ok" : "muted",
      icon: view.state === "active" ? "check" : "x",
      heading,
      lead,
      ...(successor !== null ? { primary: html`<a class="btn primary" href="${enrolHref(shell, successor.enrolment)}" data-region="enrol-successor">${icon("arrowRight")}<span>Open the newer link</span></a>` } : {}),
      secondary: machines,
    })}`,
  }
}

export function enrolmentPage(shell: WorkspaceShell, view: WorkspaceEnrolView, data: MachinesData): PageInput {
  const open = view.state === "pending_owner_acceptance" || view.state === "pending_admission"
  const base = { title: "A machine", viewer: null, workspace: shell, focus: true }
  if (!open || view.lease === "terminal") return closedPage(shell, view, data, base)
  if (view.lease === "lapsed") return lapsedPage(shell, view, data, base)
  return livePage(shell, view, data, base)
}
