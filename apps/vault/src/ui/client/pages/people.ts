// The browser side of the people, team and machine pages. Each
// change asks the workspace for the exact action to sign (or builds it from
// what the page shows, where the vault returns it whole), signs it with a
// passkey bound to this workspace, sends it, and reloads so the page shows
// the vault's own state. A refusal is shown as the vault words it.
// Everything written into the page goes in through textContent.

import { scopeChangeIsNarrowing } from "@mehen/protocol/step-up-rules"
import type { InviteEmailed, OwnerRef, WorkspaceDeviceScope, WorkspaceRole, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { STALE_TAB_STATUS, VaultFailure, workspaceApi } from "../api.ts"
import { type Boot, all, el, find, inputValue, must, showProblems, withBusy } from "../dom.ts"
import { RESCOPE_REJECTED_WORDS, type RescopeShown, agentSetup, buildInviteTerms, confirmChoiceShown, emailLinkShown, inviteMadeWords, inviteMessage, rescopeRejectAction, rescopeSignBody, scopeFromForm } from "../people-logic.ts"
import type { ShellState } from "../shell-logic.ts"
import { workspaceStepUp } from "../step-up.ts"
import { CHANGED_SINCE_SHOWN, sameAction } from "../workspace-logic.ts"
import { initPolicyRules } from "./policy-rules.ts"

export type Planned = { action: WorkspaceStepUpAction }

// Plan, sign, send, reload.
export async function signed(shell: ShellState, plan: () => Promise<WorkspaceStepUpAction>, path: string, body: Record<string, unknown>): Promise<void> {
  const action = await plan()
  const stepUp = await workspaceStepUp(shell, action)
  await workspaceApi(shell, path, { ...body, stepUp })
  location.reload()
}

function memberPlan(shell: ShellState, member: string, change: string, role?: string): () => Promise<WorkspaceStepUpAction> {
  return async () => (await workspaceApi<Planned>(shell, `/members/${encodeURIComponent(member)}/action`, { change, ...(role ? { role } : {}) })).action
}

// ---------------------------------------------------------------- people

function wireInvite(shell: ShellState): void {
  const form = find<HTMLFormElement>('[data-form="invite"]')
  if (!form) return
  const button = must<HTMLButtonElement>('[data-action="invite-create"]', form)
  const preview = refreshDelegation(form, button)
  form.addEventListener("change", preview)
  preview()
  // "Confirm them myself" only where the invitation could let them straight in.
  const binding = () => (find<HTMLInputElement>('[data-input="invite-binding"]:checked', form)?.value === "open" ? "open" : "email")
  const confirmChoice = find('[data-region="invite-confirm-myself"]', form)
  // "Email the link to them" only where there is an address to send it to.
  const emailLink = find('[data-region="invite-email-link"]', form)
  const refreshConfirmChoice = () => {
    const role = inputValue('[data-input="invite-role"]', form)
    if (confirmChoice) confirmChoice.hidden = !confirmChoiceShown(role, binding())
    if (emailLink) emailLink.hidden = !emailLinkShown(role, binding())
  }
  form.addEventListener("change", refreshConfirmChoice)
  refreshConfirmChoice()
  // A guest needs a shared project: open the Access fold for one.
  const access = find<HTMLDetailsElement>('[data-region="invite-access"]', form)
  find<HTMLSelectElement>('[data-input="invite-role"]', form)?.addEventListener("change", (event) => {
    if (access && (event.target as HTMLSelectElement).value === "guest") access.open = true
  })
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    const shares = all<HTMLElement>("[data-share]", form)
      .filter((row) => find<HTMLInputElement>('[data-input="invite-project"]', row)?.checked === true)
      .map((row) => ({ project: row.dataset.share ?? "", level: inputValue('[data-input="invite-level"]', row), protected: find<HTMLInputElement>('[data-input="invite-protected"]', row)?.checked === true }))
    const built = buildInviteTerms({
      role: inputValue('[data-input="invite-role"]', form),
      binding: binding(),
      email: inputValue('[data-input="invite-email"]', form),
      teams: all<HTMLInputElement>('[data-input="invite-team"]:checked', form).map((i) => i.value),
      shares,
      days: Number(inputValue('[data-input="invite-days"]', form)),
      confirmMyself: find<HTMLInputElement>('[data-input="invite-confirm-myself"]', form)?.checked === true,
    }, Date.now())
    if (!built.ok) {
      showProblems(built.problems)
      return
    }
    void withBusy(button, "Waiting for your passkey...", async () => {
      const action: WorkspaceStepUpAction = { type: "member.invite", terms: built.value }
      const stepUp = await workspaceStepUp(shell, action)
      const email = built.value.email !== null && find<HTMLInputElement>('[data-input="invite-email-link"]', form)?.checked === true
      const made = await workspaceApi<{ url: string; emailed: InviteEmailed }>(shell, "/invites", { terms: built.value, email, stepUp })
      form.hidden = true
      must('[data-region="invite-url"]').textContent = made.url
      must('[data-region="invite-made-lead"]').textContent = inviteMadeWords(built.value, made.emailed)
      must('[data-region="invite-message"]').textContent = inviteMessage(shell.identity.workspace, made.url, built.value)
      must('[data-region="invite-made"]').hidden = false
      await refreshInvites(shell)
    })
  })
}

// The link just made must stay on screen, so the invitations list is read
// again from this page's own address instead of reloading it. If that read
// fails the list stays as it was; a reload shows it.
async function refreshInvites(shell: ShellState): Promise<void> {
  const current = find('[data-region="invites"]')
  if (current === null) return
  try {
    const response = await fetch(location.pathname + location.search, { credentials: "same-origin", cache: "no-store", headers: { accept: "text/html" } })
    if (!response.ok || !(response.headers.get("content-type") ?? "").startsWith("text/html")) return
    const fresh = new DOMParser().parseFromString(await response.text(), "text/html").querySelector<HTMLElement>('[data-region="invites"]')
    if (fresh === null) return
    const list = document.importNode(fresh, true)
    current.replaceWith(list)
    wireInviteRevokes(shell, list)
  } catch {
    return
  }
}

function wireInviteRevokes(shell: ShellState, root: ParentNode): void {
  for (const button of all<HTMLButtonElement>('[data-action="invite-revoke"]', root)) {
    const invite = button.dataset.invite ?? ""
    button.addEventListener("click", () => void withBusy(button, "Revoking...", async () => {
      await workspaceApi(shell, `/invites/${encodeURIComponent(invite)}/revoke`, {})
      location.reload()
    }))
  }
}

// The whole-workspace credentials the ticked projects would let the invited
// person use, shown before the passkey. If any ticked project's reach could
// not be read, the invitation cannot be signed.
function refreshDelegation(form: HTMLElement, button: HTMLButtonElement): () => void {
  const region = find('[data-region="invite-delegation"]', form)
  const list = find('[data-region="invite-delegation-list"]', form)
  const unknown = find('[data-region="invite-delegation-unknown"]', form)
  return () => {
    const ticked = all<HTMLElement>("[data-share]", form).filter((row) => find<HTMLInputElement>('[data-input="invite-project"]', row)?.checked === true)
    const blind = ticked.some((row) => row.dataset.delegatesUnknown !== undefined)
    const slugs = [...new Set(ticked.flatMap((row) => (row.dataset.delegates ?? "").split(" ").filter((slug) => slug !== "")))].sort()
    if (region) region.hidden = ticked.length === 0
    if (unknown) unknown.hidden = !blind
    list?.replaceChildren(...(slugs.length === 0 ? [el("li", null, "No whole-workspace credentials")] : slugs.map((slug) => el("li", "mono", slug))))
    button.disabled = blind
  }
}

function wireConfirm(shell: ShellState, button: HTMLButtonElement): void {
  const member = button.dataset.member ?? ""
  const panel = find<HTMLElement>(`[data-region="confirm-panel"][data-member="${CSS.escape(member)}"]`)
  if (!panel) return
  const sign = must<HTMLButtonElement>('[data-action="member-confirm-sign"]', panel)
  const error = must('[data-region="confirm-error"]', panel)
  let action: WorkspaceStepUpAction | null = null
  button.addEventListener("click", () => {
    void withBusy(button, "Reading the terms...", async () => {
      action = await memberPlan(shell, member, "confirm")()
      const digest = action.type === "member.confirm" ? action.termsDigest : ""
      panel.hidden = false
      const terms = all<HTMLElement>("[data-terms-digest]", panel)
      for (const t of terms) t.hidden = t.dataset.termsDigest !== digest
      const match = terms.find((t) => !t.hidden)
      // What the terms delegate must be known before they are signed.
      const blind = match !== undefined && find('[data-region="delegation-unknown"]', match) !== null
      error.hidden = match !== undefined && !blind
      error.textContent = match === undefined ? "The terms this person would get are not the ones on this page any more. Reload the page before confirming." : blind ? "What these terms would let them use could not be read. Reload the page before confirming." : ""
      sign.disabled = match === undefined || blind
    })
  })
  sign.addEventListener("click", () => {
    const planned = action
    if (planned === null) return
    void withBusy(sign, "Waiting for your passkey...", () => signed(shell, async () => planned, `/members/${encodeURIComponent(member)}/confirm`, {}))
  })
}

// The role picker starts on its placeholder: Change role stays disabled
// until a role is chosen, and a choice of owner is marked as widening.
function wireRolePicker(select: HTMLSelectElement): void {
  const member = select.dataset.member ?? ""
  const button = find<HTMLButtonElement>(`[data-action="member-role"][data-member="${CSS.escape(member)}"]`)
  if (!button) return
  const refresh = () => {
    button.disabled = select.value === ""
    button.classList.toggle("widen", select.value === "owner")
  }
  select.addEventListener("change", refresh)
  refresh()
}

const MEMBER_ID = /^mem_[A-Za-z0-9_-]+$/

// The member a #confirm-<member> fragment names, or null for anything else:
// a bad bookmark or a supplied link must not stop the page from working.
function confirmFragmentMember(hash: string): string | null {
  const raw = /^#confirm-(.+)$/.exec(hash)?.[1]
  if (raw === undefined) return null
  let member: string
  try {
    member = decodeURIComponent(raw)
  } catch {
    return null
  }
  return MEMBER_ID.test(member) ? member : null
}

// Needs you links a confirmation to /people#confirm-<member>: open that
// person's Manage fold, read the terms and bring the panel into view.
function openConfirmFromHash(): void {
  const member = confirmFragmentMember(location.hash)
  if (member === null) return
  const review = find<HTMLButtonElement>(`[data-action="member-confirm"][data-member="${CSS.escape(member)}"]`)
  if (!review) return
  review.click()
  review.scrollIntoView({ block: "center" })
}

export function initPeople(_boot: Boot, shell: ShellState | null): void {
  if (shell === null) return
  wireInvite(shell)
  for (const select of all<HTMLSelectElement>('[data-input="member-role"]')) wireRolePicker(select)
  for (const button of all<HTMLButtonElement>('[data-action="member-confirm"]')) wireConfirm(shell, button)
  for (const change of ["suspend", "reinstate", "remove"] as const) {
    for (const button of all<HTMLButtonElement>(`[data-action="member-${change}"]`)) {
      const member = button.dataset.member ?? ""
      button.addEventListener("click", () => void withBusy(button, "Waiting for your passkey...", () => signed(shell, memberPlan(shell, member, change), `/members/${encodeURIComponent(member)}/${change}`, {})))
    }
  }
  for (const button of all<HTMLButtonElement>('[data-action="member-role"]')) {
    const member = button.dataset.member ?? ""
    button.addEventListener("click", () => {
      const role = inputValue(`[data-input="member-role"][data-member="${CSS.escape(member)}"]`) as WorkspaceRole
      void withBusy(button, "Waiting for your passkey...", () => signed(shell, memberPlan(shell, member, "role", role), `/members/${encodeURIComponent(member)}/role`, { role }))
    })
  }
  wireInviteRevokes(shell, document)
  // Last, so every action above is wired whatever the fragment says.
  openConfirmFromHash()
}

// ---------------------------------------------------------------- teams

function teamPlan(shell: ShellState, input: Record<string, unknown>): () => Promise<WorkspaceStepUpAction> {
  return async () => (await workspaceApi<Planned>(shell, "/teams/action", input)).action
}

export function initTeams(_boot: Boot, shell: ShellState | null): void {
  if (shell === null) return
  const create = find<HTMLFormElement>('[data-form="team-create"]')
  create?.addEventListener("submit", (event) => {
    event.preventDefault()
    const name = inputValue('[data-input="team-name"]', create).trim()
    const slug = inputValue('[data-input="team-slug"]', create).trim().toLowerCase()
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', create), "Waiting for your passkey...", async () => {
      const action = await teamPlan(shell, { kind: "create", name, slug })()
      await signed(shell, async () => action, "/teams", { team: action.type === "team.update" ? action.team : "", name, slug })
    })
  })
  for (const form of all<HTMLFormElement>('[data-form="team-rename"]')) {
    const team = form.dataset.team ?? ""
    form.addEventListener("submit", (event) => {
      event.preventDefault()
      const name = inputValue('[data-input="team-name"]', form).trim()
      const slug = inputValue('[data-input="team-slug"]', form).trim().toLowerCase()
      void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), "Waiting for your passkey...", () => signed(shell, teamPlan(shell, { kind: "rename", team, name, slug }), `/teams/${encodeURIComponent(team)}/update`, { change: "rename", name, slug }))
    })
  }
  for (const button of all<HTMLButtonElement>('[data-action="team-delete"]')) {
    const team = button.dataset.team ?? ""
    button.addEventListener("click", () => void withBusy(button, "Waiting for your passkey...", () => signed(shell, teamPlan(shell, { kind: "delete", team }), `/teams/${encodeURIComponent(team)}/update`, { change: "delete" })))
  }
  for (const button of all<HTMLButtonElement>('[data-action="team-member-add"]')) {
    const team = button.dataset.team ?? ""
    button.addEventListener("click", () => {
      const member = inputValue(`[data-input="team-member"][data-team="${CSS.escape(team)}"]`)
      void withBusy(button, "Waiting for your passkey...", () => signed(shell, teamPlan(shell, { kind: "members", team, member, change: "add" }), `/teams/${encodeURIComponent(team)}/members`, { member, change: "add" }))
    })
  }
  for (const button of all<HTMLButtonElement>('[data-action="team-member-remove"]')) {
    const team = button.dataset.team ?? ""
    const member = button.dataset.member ?? ""
    button.addEventListener("click", () => void withBusy(button, "Waiting for your passkey...", () => signed(shell, teamPlan(shell, { kind: "members", team, member, change: "remove" }), `/teams/${encodeURIComponent(team)}/members`, { member, change: "remove" })))
  }
}

// ---------------------------------------------------------------- one machine

export const NARROW_ONLY_WORDS = "You can only narrow this machine here. Ask the person who invited you, or an owner or admin, to propose a wider scope; you then accept it on this page."

function devicePlan(shell: ShellState, device: string, change: Record<string, unknown>, project?: string): () => Promise<WorkspaceStepUpAction> {
  return async () => (await workspaceApi<Planned>(shell, `/devices/${encodeURIComponent(device)}/action`, { change, ...(project !== undefined ? { project } : {}) })).action
}

// The proposal card's terms, as the server rendered them.
function rescopeShown(card: HTMLElement): RescopeShown {
  return { proposal: card.dataset.proposal ?? "", device: card.dataset.device ?? "", thumbprint: card.dataset.thumbprint ?? "", project: card.dataset.project ?? null }
}

export function initMachine(boot: Boot, shell: ShellState | null): void {
  if (shell === null) return
  const device = String(boot.device ?? "")
  const before = boot.scope as WorkspaceDeviceScope
  const owner = boot.owner as OwnerRef
  const base = `/devices/${encodeURIComponent(device)}`
  const revoke = find<HTMLButtonElement>('[data-action="device-revoke"]')
  revoke?.addEventListener("click", () => void withBusy(revoke, "Waiting for your passkey...", () => signed(shell, devicePlan(shell, device, { kind: "revoke" }), `${base}/revoke`, {})))
  // One workload, by the id the server rendered: the vault plans the exact
  // workload.revoke for this machine and that workload.
  for (const button of all<HTMLButtonElement>('[data-action="workload-revoke"]')) {
    const workload = button.dataset.workload ?? ""
    button.addEventListener("click", () => void withBusy(button, "Waiting for your passkey...", () => signed(shell, devicePlan(shell, device, { kind: "workload_revoke", workload }), `${base}/workloads/${encodeURIComponent(workload)}/revoke`, {})))
  }
  const form = find<HTMLFormElement>('[data-form="scope-change"]')
  form?.addEventListener("submit", (event) => {
    event.preventDefault()
    const built = scopeFromForm(before, owner, {
      modes: all<HTMLInputElement>('[data-input="scope-mode"]:checked', form).map((i) => i.value),
      maxEnvironment: find<HTMLInputElement>('[data-input="scope-env"]:checked', form)?.value ?? "unprotected",
      privateCredentials: find<HTMLInputElement>('[data-input="scope-private"]', form)?.checked === true,
      serviceRuns: find<HTMLInputElement>('[data-input="scope-service"]', form)?.checked === true,
      // No editor on the page: the filter is kept exactly, never dropped.
      projects: find('[data-region="scope-projects"]', form) === null ? null : all<HTMLInputElement>('[data-input="scope-project"]:checked', form).map((i) => i.value),
    })
    if (!built.ok) {
      showProblems(built.problems)
      return
    }
    const after = built.value
    const narrowing = scopeChangeIsNarrowing(before, after)
    if (!narrowing && boot.propose !== true) {
      showProblems([NARROW_ONLY_WORDS])
      return
    }
    const kind = narrowing ? "rescope" : "rescope_propose"
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), "Waiting for your passkey...", () => signed(shell, devicePlan(shell, device, { kind, before, after }), `${base}/rescope`, { before, after }))
  })
  const card = find<HTMLElement>('[data-region="proposal"]')
  if (card) wireRescopeCard(shell, device, card)
  initPolicyRules(shell)
}

// The proposal card's passkey actions. Accept sends the proposal alone;
// Admit and Reject send the admission signer's project when the card
// carries one. Reject plans the vault's action, refuses unless it is
// exactly the device.rescope_reject this card shows, then asks the passkey
// and sends; on success the card says the proposal was rejected and nothing
// changed on the machine. Any refusal shows the vault's own words.
function wireRescopeCard(shell: ShellState, device: string, card: HTMLElement): void {
  const base = `/devices/${encodeURIComponent(device)}`
  const shown = rescopeShown(card)
  const accept = find<HTMLButtonElement>('[data-action="rescope-accept"]', card)
  accept?.addEventListener("click", () => void withBusy(accept, "Waiting for your passkey...", () => signed(shell, devicePlan(shell, device, { kind: "rescope_accept", proposal: shown.proposal }), `${base}/rescope-accept`, { proposal: shown.proposal })))
  const admit = find<HTMLButtonElement>('[data-action="rescope-admit"]', card)
  admit?.addEventListener("click", () => void withBusy(admit, "Waiting for your passkey...", () => signed(shell, devicePlan(shell, device, { kind: "rescope_admit", proposal: shown.proposal }, shown.project ?? undefined), `${base}/rescope-admit`, rescopeSignBody(shown))))
  const reject = find<HTMLButtonElement>('[data-action="rescope-reject"]', card)
  reject?.addEventListener("click", () => void withBusy(reject, "Waiting for your passkey...", async () => {
    const action = await devicePlan(shell, device, { kind: "rescope_reject", proposal: shown.proposal }, shown.project ?? undefined)()
    if (!sameAction(rescopeRejectAction(shown), action)) throw new VaultFailure(STALE_TAB_STATUS, CHANGED_SINCE_SHOWN)
    const stepUp = await workspaceStepUp(shell, action)
    await workspaceApi(shell, `${base}/rescope-reject`, { ...rescopeSignBody(shown), stepUp })
    must('[data-region="rescope-actions"]', card).hidden = true
    const said = must('[data-region="rescope-rejected"]', card)
    said.textContent = RESCOPE_REJECTED_WORDS
    said.hidden = false
  }))
}

// ---------------------------------------------------------------- Connect an agent

// Ask the connect-code issuer once, on load. A code fills the prompt and
// the enrol box through agentSetup, so only a code in the issuer's alphabet
// reaches copied text; any refusal, a vault that does not issue codes yet
// included, leaves the boxes as served, without --connect, and enables them.
export function initConnectAgent(_boot: Boot, shell: ShellState | null): void {
  const waiting = find('[data-region="connect-code-waiting"]')
  if (shell === null || waiting === null) return
  const settle = () => {
    waiting.hidden = true
    for (const button of all<HTMLButtonElement>('[data-box="prompt"] button[data-copy], [data-box="enrol"] button[data-copy]')) button.disabled = false
  }
  void workspaceApi<{ code: string; expiresAt: string }>(shell, "/connect-code", {})
    .then((answer) => {
      const setup = agentSetup(shell.identity.origin, shell.identity.workspace.slug, typeof answer?.code === "string" ? answer.code : "")
      if (setup === null) return
      const prompt = find('[data-box="prompt"] code')
      const enrol = find('[data-box="enrol"] code')
      if (prompt === null || enrol === null) return
      prompt.textContent = setup.prompt
      enrol.textContent = setup.enrol
      const expiry = find('[data-region="connect-code-expiry"]')
      const ends = new Date(answer.expiresAt)
      if (expiry) expiry.textContent = Number.isNaN(ends.getTime()) ? "tomorrow" : ends.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
      const note = find('[data-region="connect-code-note"]')
      if (note) note.hidden = false
    })
    .catch((error: unknown) => {
      // Not found: this vault does not issue codes yet; nothing to say.
      const say = error instanceof VaultFailure && error.status !== 404 ? error.body.next?.say : undefined
      const refused = find('[data-region="connect-code-refused"]')
      if (refused && say !== undefined) {
        refused.textContent = say
        refused.hidden = false
      }
    })
    .finally(settle)
}
