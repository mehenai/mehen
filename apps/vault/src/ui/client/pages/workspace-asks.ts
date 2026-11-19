// The workspace ask pages in the browser: an approval or its stop view,
// adding a credential (intake), connecting an account, declining a policy
// proposal, deciding a standing rule's proposal, and a new machine's
// enrolment. Every decision is signed with a
// passkey bound to this workspace through workspace-sign.ts, which refuses
// before the passkey unless the vault's action is the one this page rebuilt
// from what it showed, and unless the workspace is still the one shown.
// Calls go through workspaceApi, so a stale tab sends nothing.
//
// Each page's actions share one gate: a predicate over what the page shows
// (digest and tick, filled fields, the typed group) and whether an action
// is in flight. The gate alone turns an action on, at load, on every input
// and after every attempt, failed or not, and an action whose predicate
// does not hold does nothing however it is reached. The decision form never
// submits natively.

import type { ApiError } from "@mehen/protocol/api"
import type { CredentialHome, OwnerRef, WorkspaceRole, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { VaultFailure, workspaceApi } from "../api.ts"
import { type Boot, all, find, must, showProblems, withBusy } from "../dom.ts"
import { type IntakeBoot, buildIntakeSubmission, intakeNeedsAcceptance, intakeSigninPages, typedGroupState } from "../logic.ts"
import type { ShellState } from "../shell-logic.ts"
import { CHANGED_SINCE_SHOWN, type RuleProposalBoot, type WorkspaceApprovalBoot, approvalBindingMatches, intakeWithHome, rememberRule, ruleOfferMatches, ruleOutcomeWords, ruleProposalEffect, ruleProposalMatches, ruleProposalOutcomeWords, sameAction } from "../workspace-logic.ts"
import { CHECKING_PAGE_WORDS, GROUP_MATCHES_WORDS, RULE_MISMATCH_WORDS, RULE_PROPOSAL_PAGE_MISMATCH_WORDS, TICK_CODE_WORDS, TYPE_GROUP_WORDS, allowWords, ruleChosenTermsWords } from "../../wording.ts"
import { type AreaProposalBoot, areaOfferMatches, areaOutcomeWords, areaProposalMatches, areaProposalOutcomeWords, rememberArea } from "../workspace-logic.ts"
import { AREA_MISMATCH_WORDS, areaApproveLabel } from "../../wording.ts"
import { CONNECT_CLIENT_UNKNOWN, type ConnectTerms, POLICY_DENY_BODY, type ShownAcceptance, type ShownFingerprint, acceptanceMismatch, approvalCaption, connectStartExpected } from "../ask-logic.ts"
import { homeOfKey } from "../../home-key.ts"
import { browserPasskey, decideApproval, decideRuleProposal, denyFromStop, signAction, signed } from "../workspace-sign.ts"
import { decideAreaProposal } from "../workspace-sign.ts"
import { askPage, needShell } from "./workspace.ts"

function refuse(body: ApiError): never {
  throw new VaultFailure(409, body)
}

// ---------------------------------------------------------------- the gate

export type Gate = {
  refresh: () => void
  busy: () => boolean
  run: (button: HTMLButtonElement, waiting: string, action: () => Promise<void>) => void
}

// The actions of one page and when each may run. `ready` is asked for each
// button; while any action runs, all are off. `after` runs on every refresh
// (the caption, say).
export function gate(buttons: readonly (HTMLButtonElement | null)[], ready: (button: HTMLButtonElement) => boolean, after: () => void = () => undefined): Gate {
  let busy = false
  const refresh = () => {
    for (const b of buttons) if (b !== null) b.disabled = busy || !ready(b)
    after()
  }
  const run = (button: HTMLButtonElement, waiting: string, action: () => Promise<void>) => {
    if (busy || !ready(button)) return
    busy = true
    refresh()
    void withBusy(button, waiting, action).finally(() => {
      busy = false
      refresh()
    })
  }
  return { refresh, busy: () => busy, run }
}

// Enter in a field the decision form owns never submits it: the actions
// are buttons, each behind its gate.
function holdDecideForm(): void {
  find<HTMLFormElement>("#decide")?.addEventListener("submit", (event) => event.preventDefault())
}

function wire(button: HTMLButtonElement | null, g: Gate, waiting: string, action: () => Promise<void>): void {
  button?.addEventListener("click", () => g.run(button, waiting, action))
}

// ---------------------------------------------------------------- approval

// The bar's Change opens the terms fold; the terms line follows the
// choices, everywhere it is shown.
function wireTerms(onChange: () => void): void {
  const fold = find('[data-region="terms-form"]')
  if (fold === null) return
  for (const button of all<HTMLButtonElement>('[data-action="change-terms"]')) {
    button.addEventListener("click", () => {
      const open = fold.hidden
      fold.hidden = !open
      document.body.classList.toggle("terms-open", open)
      for (const b of all<HTMLButtonElement>('[data-action="change-terms"]')) b.setAttribute("aria-expanded", String(open))
    })
  }
  for (const select of all<HTMLSelectElement>("select", fold)) select.addEventListener("change", onChange)
}

export function initWorkspaceApproval(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  holdDecideForm()
  if (raw.view === "stop") {
    const deny = find<HTMLButtonElement>('[data-action="deny"]')
    const g = gate([deny], () => true)
    wire(deny, g, "Waiting for your passkey...", async () => {
      await denyFromStop(shell, String(raw.approval ?? ""))
      location.reload()
    })
    g.refresh()
    return
  }
  const boot = raw as unknown as WorkspaceApprovalBoot & Boot
  const approve = find<HTMLButtonElement>('[data-action="approve"]')
  const allow = find<HTMLButtonElement>('[data-action="approve-rule"]')
  const carry = find<HTMLButtonElement>('[data-action="approve-area"]')
  const deny = find<HTMLButtonElement>('[data-action="deny"]')
  const tick = find<HTMLInputElement>('[data-input="code-matches"]')
  const caption = find('[data-region="bar-caption"]')
  let digest: "checking" | "match" | "mismatch" = "checking"
  // The rule's terms for the path and duration now chosen: checking from
  // each change until their digest is rebuilt, and only the latest counts.
  let rule: "checking" | "match" | "mismatch" = "checking"
  let latestRule = 0
  // The panel's choices hold still while a decision is signed, so the
  // passkey signs what the panel shows, and for good once it is done.
  let ruleDone = false
  // The task grant's terms for the areas, duration and uses now chosen, as
  // the rule's; none while no area is ticked, which is a choice to make
  // rather than a mismatch to report.
  let area: "checking" | "match" | "mismatch" | "none" = "checking"
  let latestArea = 0
  const panelInputs = all<HTMLInputElement>('[data-region="rule-panel"] input, [data-region="area-panel"] input')
  const approvable = () => digest === "match" && tick?.checked === true
  const g = gate([deny, approve, allow, carry], (b) => (b === approve ? approvable() : b === allow ? approvable() && rule === "match" : b === carry ? approvable() && area === "match" : true), () => {
    // The live caption carries a rule mismatch too: the line saying so only
    // turns visible, which a screen reader may not announce.
    if (caption && approve) caption.textContent = approvalCaption(digest, tick?.checked === true) || (rule === "mismatch" ? RULE_MISMATCH_WORDS : area === "mismatch" ? AREA_MISMATCH_WORDS : "")
    for (const input of panelInputs) input.disabled = ruleDone || g.busy()
  })
  tick?.addEventListener("change", g.refresh)
  const rulePath = () => find<HTMLInputElement>('[data-input="rule-path"]:checked')?.value ?? ""
  const ruleTtl = () => find<HTMLInputElement>('[data-input="rule-ttl"]:checked')?.value ?? ""
  const recheckRule = () => {
    const offer = boot.rule
    if (offer === undefined) return
    const mine = ++latestRule
    rule = "checking"
    g.refresh()
    void Promise.all([ruleOfferMatches(offer, boot.subject), rememberRule(offer, rulePath(), ruleTtl())]).then(([offered, built]) => {
      if (mine !== latestRule) return
      rule = offered && built.ok ? "match" : "mismatch"
      const mismatch = find('[data-region="rule-mismatch"]')
      if (mismatch) mismatch.hidden = rule !== "mismatch"
      // The off button says why, while the line saying so is shown.
      if (rule === "mismatch" && mismatch) allow?.setAttribute("aria-describedby", mismatch.id)
      else allow?.removeAttribute("aria-describedby")
      g.refresh()
    })
  }
  for (const input of all<HTMLInputElement>('[data-input="rule-path"], [data-input="rule-ttl"]')) input.addEventListener("change", recheckRule)
  recheckRule()
  const areaChoice = () => ({
    areas: all<HTMLInputElement>('[data-input="area-area"]:checked').map((i) => i.value),
    ttl: find<HTMLInputElement>('[data-input="area-ttl"]:checked')?.value ?? "",
    uses: find<HTMLInputElement>('[data-input="area-uses"]:checked')?.value ?? "",
  })
  const recheckArea = () => {
    const offer = boot.area
    if (offer === undefined) return
    const mine = ++latestArea, chosen = areaChoice()
    area = "checking"
    // The third button names the areas ticked and the duration chosen; a
    // co-sign's says only that a manager is asked.
    const label = carry?.querySelector("span:last-child")
    if (label && !offer.coSign) label.textContent = areaApproveLabel(chosen.areas.map((id) => offer.areas.find((a) => a.id === id)?.name ?? id), Number(chosen.ttl))
    g.refresh()
    void Promise.all([areaOfferMatches(offer, boot.subject), rememberArea(offer, chosen.areas, chosen.ttl, chosen.uses)]).then(([offered, built]) => {
      if (mine !== latestArea) return
      area = offered && built.ok ? "match" : offered && chosen.areas.length === 0 ? "none" : "mismatch"
      const mismatch = find('[data-region="area-mismatch"]')
      if (mismatch) mismatch.hidden = area !== "mismatch"
      if (area === "mismatch" && mismatch) carry?.setAttribute("aria-describedby", mismatch.id)
      else carry?.removeAttribute("aria-describedby")
      g.refresh()
    })
  }
  for (const input of all<HTMLInputElement>('[data-input="area-area"], [data-input="area-ttl"], [data-input="area-uses"]')) input.addEventListener("change", recheckArea)
  recheckArea()
  // A page with no terms to choose (a push) signs the terms as asked.
  const asked = boot.subject.constraints
  const uses = () => find<HTMLSelectElement>('[data-input="uses"]')?.value ?? (asked.uses === null ? "unlimited" : String(asked.uses))
  const ttl = () => find<HTMLSelectElement>('[data-input="ttl"]')?.value ?? String(asked.ttlSeconds)
  wireTerms(() => {
    for (const text of all('[data-region="terms-text"]')) text.textContent = allowWords(uses() === "unlimited" ? null : Number(uses()), Number(ttl()))
  })
  void approvalBindingMatches(boot).then((ok) => {
    digest = ok ? "match" : "mismatch"
    const good = find('[data-region="digest-match"]')
    const bad = find('[data-region="digest-mismatch"]')
    if (good) good.hidden = !ok
    if (bad) bad.hidden = ok
    g.refresh()
  })
  g.refresh()
  const choice = (decision: "approve" | "deny") => ({ decision, codeTicked: tick?.checked === true, uses: uses(), ttl: ttl() })
  for (const [button, decision] of [[deny, "deny"], [approve, "approve"]] as const) {
    wire(button, g, "Waiting for your passkey...", async () => {
      await decideApproval(shell, boot, choice(decision))
      location.reload()
    })
  }
  wire(allow, g, "Waiting for your passkey...", async () => {
    const answer = await decideApproval<unknown>(shell, boot, { ...choice("approve"), rule: { path: rulePath(), ttl: ruleTtl() } })
    const words = ruleOutcomeWords(answer)
    if (words === null) return location.reload()
    ruleDone = true
    ruleConfirmed(words)
  })
  wire(carry, g, "Waiting for your passkey...", async () => {
    const chosen = areaChoice()
    const answer = await decideApproval<unknown>(shell, boot, { ...choice("approve"), area: chosen })
    const words = areaOutcomeWords(answer, { ttlSeconds: Number(chosen.ttl), maxUses: Number(chosen.uses) })
    if (words === null) return location.reload()
    ruleDone = true
    ruleConfirmed(words)
  })
}

// After a decision on a rule (approving with one on the approval page, or
// deciding a rule's proposal) the page says what happened in place of the
// decision form, the time left, the terms, what happens next and the bar,
// from the vault's answer; a reload shows it settled.
function ruleConfirmed(words: string): void {
  const confirmed = document.createElement("p")
  confirmed.className = "strip"
  confirmed.setAttribute("data-region", "rule-confirmed")
  confirmed.setAttribute("role", "status")
  confirmed.setAttribute("tabindex", "-1")
  confirmed.textContent = words
  find('[data-form="decide"]')?.replaceWith(confirmed)
  for (const input of all<HTMLInputElement>('[data-region="rule-panel"] input, [data-region="area-panel"] input')) input.disabled = true
  for (const leftover of all('[data-region="decision"] .meta, .ask-next, [data-region="bar"]')) leftover.hidden = true
  document.body.classList.remove("has-bar", "terms-open")
  // The focused button went with the bar: focus moves to what happened.
  confirmed.focus()
}

// ---------------------------------------------------------------- policy proposals

function isPolicyDenial(proposal: string): (a: unknown) => boolean {
  return (a) => typeof a === "object" && a !== null && (a as { type?: unknown }).type === "policy.decide" && (a as { proposal?: unknown }).proposal === proposal && (a as { decision?: unknown }).decision === "deny" && (a as { effectDigest?: unknown }).effectDigest === null
}

// A rule proposal's stop view: Stop declines it, with whatever digest the
// vault stored.
export function initWorkspacePolicy(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  holdDecideForm()
  const id = String(raw.proposal ?? "")
  const path = `/policy/proposals/${encodeURIComponent(id)}`
  const deny = find<HTMLButtonElement>('[data-action="deny"]')
  const g = gate([deny], () => true)
  wire(deny, g, "Waiting for your passkey...", async () => {
    await signed(shell, { prepare: { path: `${path}/action`, body: { decision: "deny" } }, matches: isPolicyDenial(id), mutation: { path: `${path}/decide`, body: POLICY_DENY_BODY } })
    location.reload()
  })
  g.refresh()
}

// ---------------------------------------------------------------- rule proposals

// A standing rule's proposal: Approve once the page's terms hash to the
// vault's digests, the code is ticked where the page shows one and the
// chosen path and duration rebuild (only the latest choice counts); Deny
// always. The choices hold still while a decision is signed and for good
// once it is done, and what happened is said from the vault's answer.
export function initWorkspaceRuleProposal(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  holdDecideForm()
  const boot = raw as unknown as RuleProposalBoot & { coded: boolean } & Boot
  const approve = find<HTMLButtonElement>('[data-action="approve"]')
  const deny = find<HTMLButtonElement>('[data-action="deny"]')
  const tick = find<HTMLInputElement>('[data-input="code-matches"]')
  const caption = find('[data-region="bar-caption"]')
  const mismatch = find('[data-region="rule-mismatch"]')
  let digest: "checking" | "match" | "mismatch" = "checking"
  let effect: "checking" | "match" | "mismatch" = "checking"
  let latest = 0
  let done = false
  const panelInputs = all<HTMLInputElement>('[data-region="rule-panel"] input')
  const ticked = () => !boot.coded || tick?.checked === true
  const g = gate([deny, approve], (b) => (b === approve ? digest === "match" && effect === "match" && ticked() : true), () => {
    if (caption && approve) caption.textContent = digest === "mismatch" || effect === "mismatch" ? RULE_PROPOSAL_PAGE_MISMATCH_WORDS : digest === "checking" ? CHECKING_PAGE_WORDS : boot.coded && !ticked() ? TICK_CODE_WORDS : ""
    for (const input of panelInputs) input.disabled = done || g.busy()
    if (mismatch) mismatch.hidden = digest !== "mismatch" && effect !== "mismatch"
    if (mismatch && !mismatch.hidden) approve?.setAttribute("aria-describedby", mismatch.id)
    else approve?.removeAttribute("aria-describedby")
  })
  tick?.addEventListener("change", g.refresh)
  const path = () => find<HTMLInputElement>('[data-input="rule-path"]:checked')?.value ?? ""
  const ttl = () => find<HTMLInputElement>('[data-input="rule-ttl"]:checked')?.value ?? ""
  const recheck = () => {
    const mine = ++latest
    effect = "checking"
    for (const text of all('[data-region="terms-text"]')) text.textContent = ruleChosenTermsWords(boot.terms, path(), Number(ttl()))
    g.refresh()
    void ruleProposalEffect(boot, path(), ttl()).then((built) => {
      if (mine !== latest) return
      effect = built.ok ? "match" : "mismatch"
      g.refresh()
    })
  }
  for (const input of all<HTMLInputElement>('[data-input="rule-path"], [data-input="rule-ttl"]')) input.addEventListener("change", recheck)
  if (approve !== null) recheck()
  void ruleProposalMatches(boot).then((ok) => {
    digest = ok ? "match" : "mismatch"
    const good = find('[data-region="digest-match"]')
    const bad = find('[data-region="digest-mismatch"]')
    if (good) good.hidden = !ok
    if (bad) bad.hidden = ok
    g.refresh()
  })
  g.refresh()
  for (const [button, decision] of [[deny, "deny"], [approve, "approve"]] as const) {
    wire(button, g, "Waiting for your passkey...", async () => {
      const answer = await decideRuleProposal<unknown>(shell, boot, { decision, codeTicked: tick?.checked === true, path: path(), ttl: ttl() })
      const words = ruleProposalOutcomeWords(answer, boot)
      if (words === null) return location.reload()
      done = true
      ruleConfirmed(words)
    })
  }
}

// A task grant proposal: the terms as they were signed, read only; Approve
// once the page's copy hashes to the vault's digests (and an agent's code
// is ticked), Deny always.
export function initWorkspaceAreaProposal(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  holdDecideForm()
  const boot = raw as unknown as AreaProposalBoot & { coded: boolean } & Boot
  const approve = find<HTMLButtonElement>('[data-action="approve"]')
  const deny = find<HTMLButtonElement>('[data-action="deny"]')
  const tick = find<HTMLInputElement>('[data-input="code-matches"]')
  const caption = find('[data-region="bar-caption"]')
  const mismatch = find('[data-region="area-mismatch"]')
  let digest: "checking" | "match" | "mismatch" = "checking"
  const ticked = () => !boot.coded || tick?.checked === true
  const g = gate([deny, approve], (b) => (b === approve ? digest === "match" && ticked() : true), () => {
    if (caption && approve) caption.textContent = digest === "mismatch" ? RULE_PROPOSAL_PAGE_MISMATCH_WORDS : digest === "checking" ? CHECKING_PAGE_WORDS : boot.coded && !ticked() ? TICK_CODE_WORDS : ""
    if (mismatch) mismatch.hidden = digest !== "mismatch"
    if (mismatch && !mismatch.hidden) approve?.setAttribute("aria-describedby", mismatch.id)
    else approve?.removeAttribute("aria-describedby")
  })
  tick?.addEventListener("change", g.refresh)
  void areaProposalMatches(boot).then((ok) => {
    digest = ok ? "match" : "mismatch"
    const good = find('[data-region="digest-match"]')
    const bad = find('[data-region="digest-mismatch"]')
    if (good) good.hidden = !ok
    if (bad) bad.hidden = ok
    g.refresh()
  })
  g.refresh()
  for (const [button, decision] of [[deny, "deny"], [approve, "approve"]] as const) {
    wire(button, g, "Waiting for your passkey...", async () => {
      const answer = await decideAreaProposal<unknown>(shell, boot, { decision, codeTicked: tick?.checked === true })
      const words = areaProposalOutcomeWords(answer, boot)
      if (words === null) return location.reload()
      ruleConfirmed(words)
    })
  }
}

// ---------------------------------------------------------------- intake and connect

type HomeBoot = { home: CredentialHome; homes?: CredentialHome[] }

// The home the person chose, from the homes the vault permitted: the
// checked radio's value names one of them exactly, or nothing is signed.
function chosenHome(boot: HomeBoot): CredentialHome {
  const picked = find<HTMLInputElement>('[data-input="home"]:checked')?.value
  if (picked === undefined) return boot.home
  const home = homeOfKey(picked, boot.homes ?? [boot.home])
  if (home === null) refuse(CHANGED_SINCE_SHOWN)
  return home
}

// The folded Belongs to names the home now chosen, whatever the fold
// shows: each radio's own label, as the page rendered it.
function wireHomeSummary(): void {
  const current = find('[data-region="home-current"]')
  for (const radio of all<HTMLInputElement>('[data-input="home"]')) {
    radio.addEventListener("change", () => {
      const label = find('[data-region="home-label"]', radio.closest("label") ?? document)?.textContent
      if (current && radio.checked && label) current.textContent = label
    })
  }
}

// Stop this request, on a warned intake or connect: the same cancel the
// Needs you row sends, then the page shows the closed request.
function cancelRequest(shell: ShellState, button: HTMLButtonElement): () => Promise<void> {
  return async () => {
    const kind = button.dataset.kind === "connect" ? "/connect" : "/intakes"
    await workspaceApi(shell, `${kind}/${encodeURIComponent(button.dataset.id ?? "")}/cancel`, {})
    location.reload()
  }
}

type IntakePageBoot = IntakeBoot & HomeBoot & { sealKey: { jwk: JsonWebKey }; then?: unknown }

export function initWorkspaceIntake(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const boot = raw as unknown as IntakePageBoot
  holdDecideForm()
  wireHomeSummary()
  const form = must('[data-form="intake"]')
  const button = must<HTMLButtonElement>('[data-action="submit-intake"]')
  const cancel = find<HTMLButtonElement>('[data-action="cancel-request"]')
  const accept = find<HTMLInputElement>('[data-input="accept-destination"]', form)
  const allowReads = find<HTMLInputElement>('[data-input="allow-reads"]', form)
  const fields = all<HTMLInputElement | HTMLTextAreaElement>("[data-field]", form)
  wireFillChoice(boot, form)
  const filled = () => {
    const have = new Set(fields.filter((f) => f.value.trim() !== "").map((f) => f.dataset.field ?? ""))
    return !boot.fields.some((f) => f.required && !have.has(f.name)) && !(intakeNeedsAcceptance(boot) && accept?.checked !== true)
  }
  const g = gate([button, cancel], (b) => b !== button || filled())
  accept?.addEventListener("change", g.refresh)
  for (const f of fields) f.addEventListener("input", g.refresh)
  g.refresh()
  if (cancel) wire(cancel, g, "Stopping...", cancelRequest(shell, cancel))
  wire(button, g, "Sealing and waiting for your passkey...", async () => {
    const values: Record<string, string> = {}
    for (const f of fields) values[f.dataset.field ?? ""] = f.value
    const home = chosenHome(boot)
    const key = await importSealPublicKey(boot.sealKey.jwk)
    const typeIntoSignIn = find<HTMLInputElement>('[data-input="fill-ceiling"]:checked', form)?.value === "fill"
    const built = await buildIntakeSubmission(boot, values, accept?.checked ?? false, (v, context) => seal(key, v, context), allowReads?.checked ?? false, typeIntoSignIn)
    if (!built.ok) return showProblems(built.problems)
    const { body, digest } = await intakeWithHome(built.value.submission, home)
    const intake = `/intakes/${encodeURIComponent(boot.intake)}`
    const action: WorkspaceStepUpAction = { type: "intake.submit", intake: boot.intake, digest }
    await signAction(shell, action, { path: `${intake}/submit`, body }, undefined, browserPasskey)
    for (const f of fields) f.value = ""
    const then = typeof boot.then === "string" && /^con_[A-Za-z0-9_-]+$/.test(boot.then) ? boot.then : null
    location.assign(then !== null ? askPage(shell, "/connect", then) : `/w/${encodeURIComponent(shell.identity.workspace.slug)}/items/${encodeURIComponent(boot.slug)}`)
  })
}

// The fill choice's sign-in page line follows the sign-in address as typed.
function wireFillChoice(boot: IntakeBoot, form: HTMLElement): void {
  const line = find('[data-region="fill-signin-page"]', form)
  const httpsOnly = find('[data-region="fill-https-only"]', form)
  const url = find<HTMLInputElement>('[data-field="url"]', form)
  if (boot.fillChoice !== true || line === null || httpsOnly === null || url === null) return
  url.addEventListener("input", () => {
    const pages = intakeSigninPages(url.value, boot.binding)
    line.textContent = pages.words ?? ""
    line.hidden = pages.words === null
    httpsOnly.hidden = !pages.httpsOnly
  })
}

type ConnectPageBoot = HomeBoot & { connect: string; terms: ConnectTerms }

export function initWorkspaceConnect(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const boot = raw as unknown as ConnectPageBoot
  holdDecideForm()
  wireHomeSummary()
  const button = must<HTMLButtonElement>('[data-action="start-connect"]')
  const cancel = find<HTMLButtonElement>('[data-action="cancel-request"]')
  const g = gate([button, cancel], () => true)
  if (cancel) wire(cancel, g, "Stopping...", cancelRequest(shell, cancel))
  wire(button, g, "Waiting for your passkey...", async () => {
    const home = chosenHome(boot)
    const expected = connectStartExpected(boot.connect, boot.terms, home)
    if (expected === null) refuse(CONNECT_CLIENT_UNKNOWN)
    const path = `/connect/${encodeURIComponent(boot.connect)}`
    const started = await signed<{ authorizeUrl: string }>(shell, { prepare: { path: `${path}/action`, body: { home } }, matches: (a) => sameAction(expected, a), mutation: { path: `${path}/start`, body: { home } } })
    const target = new URL(started.authorizeUrl)
    if (target.protocol !== "https:") throw new Error("The vault returned a sign-in address that is not https, so this page will not open it.")
    location.assign(target.href)
  })
  g.refresh()
}

// ---------------------------------------------------------------- enrolment

type EnrolBoot = { ref: string; check: string; enrolment: string; digest: string; owner: OwnerRef | null; role: WorkspaceRole | null; fingerprint: ShownFingerprint; acceptance?: ShownAcceptance }

// The typed group turns the actions on once it hashes to the page's check
// for this ref; each new keystroke drops the old answer at once and only
// the latest hash counts. The vault checks the group again, counting wrong
// ones, before it returns the acceptance to sign; the page compares that
// with what it showed before the passkey (it never holds the thumbprint
// until then).
export function initWorkspaceEnrol(raw: Boot, shell: ShellState | null): void {
  if (shell === null) return
  const boot = raw as unknown as EnrolBoot
  holdDecideForm()
  const base = `/enrolments/${encodeURIComponent(boot.ref)}`
  const group = find<HTMLInputElement>('[data-input="fingerprint-group"]')
  const accept = find<HTMLButtonElement>('[data-action="enrol-accept"]')
  const admit = find<HTMLButtonElement>('[data-action="enrol-admit"]')
  const reject = find<HTMLButtonElement>('[data-action="enrol-reject"]')
  const enables = find('[data-region="enrol-enables"]')
  let typed = ""
  let matches = false
  let latest = 0
  const g = gate([reject, accept, admit], (b) => b === reject || matches, () => {
    if (enables && (accept || admit)) enables.textContent = matches ? GROUP_MATCHES_WORDS : TYPE_GROUP_WORDS
  })
  group?.addEventListener("input", () => {
    const value = group.value
    const mine = ++latest
    matches = false
    typed = ""
    g.refresh()
    void typedGroupState(boot.ref, boot.check, value).then((state) => {
      if (mine !== latest) return
      typed = state.group
      matches = state.state === "matches"
      g.refresh()
    })
  })
  g.refresh()
  wire(accept, g, "Waiting for your passkey...", async () => {
    const shown = boot.acceptance
    if (shown === undefined) refuse(CHANGED_SINCE_SHOWN)
    const privateCredentials = find<HTMLInputElement>('[data-input="enrol-private"]')?.checked === true
    const sent = typed
    const planned = await workspaceApi<{ action: unknown }>(shell, `${base}/action`, { kind: "accept", group: sent, privateCredentials })
    if (acceptanceMismatch(planned.action, shown, boot.fingerprint, privateCredentials, sent) !== null) refuse(CHANGED_SINCE_SHOWN)
    await signAction(shell, planned.action as WorkspaceStepUpAction, { path: `${base}/accept`, body: { group: sent, privateCredentials } }, undefined, browserPasskey)
    location.reload()
  })
  wire(admit, g, "Waiting for your passkey...", async () => {
    if (boot.owner === null || boot.role === null) refuse(CHANGED_SINCE_SHOWN)
    const action: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: boot.enrolment, digest: boot.digest, owner: boot.owner, admissionRole: boot.role }
    await signAction(shell, action, { path: `${base}/admit`, body: { group: typed } }, undefined, browserPasskey)
    location.reload()
  })
  wire(reject, g, "Rejecting...", async () => {
    await workspaceApi(shell, `${base}/reject`, {})
    location.reload()
  })
}

// A lapsed or settled enrolment link: only an owner's or admin's Reject of
// a lapsed one does anything, on the ref the button names.
export function initWorkspaceEnrolClosed(_boot: Boot, shell: ShellState | null): void {
  if (shell === null) return
  const reject = find<HTMLButtonElement>('[data-action="enrol-reject"][data-ref]')
  const g = gate([reject], () => true)
  wire(reject, g, "Rejecting...", async () => {
    await workspaceApi(shell, `/enrolments/${encodeURIComponent(reject?.dataset.ref ?? "")}/reject`, {})
    location.reload()
  })
}
