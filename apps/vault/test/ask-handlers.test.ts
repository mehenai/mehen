// The browser handlers of the workspace ask pages (ui/client/pages/
// workspace-asks.ts), run against the pages the server renders
// (test/mini-dom.ts) with the API answered here and the passkey prompt
// stubbed, as people-handlers.test.ts does. Approve stays off
// until the page's own recompute of the vault's digest matches and the code
// is ticked; a button in the bar, outside the card's form, reaches its
// handler and signs exactly the terms shown; both enrolment forms check the
// typed group against the page's ref; a warned intake or connect stops
// through the cancel routes; the policy page only declines; the task
// grant panel signs the areas, duration and uses it shows, and its
// proposal page the terms it shows.
import { afterEach, describe, expect, it, vi } from "vitest"
import type { WorkspaceApprovalView, WorkspaceEnrolView, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { fingerprintGroupCheck } from "@mehen/protocol/fingerprint"
import { renderDocument } from "../src/ui/layout.ts"
import type { PageInput } from "../src/ui/layout.ts"
import { approvalSubjectOf, workspaceApprovalPage, workspaceAreaProposalPage, workspaceRuleProposalPage } from "../src/ui/pages/workspace-asks.ts"
import { enrolmentPage } from "../src/ui/pages/workspace-enrol.ts"
import { PEOPLE_PROJECTS, peopleShell } from "../src/ui/people-gallery.ts"
import { GALLERY_AREA_OFFER, GALLERY_AREA_PROPOSAL, GALLERY_AREA_TERMS, GALLERY_COSIGN_OFFER, GALLERY_COSIGN_PROPOSAL, GALLERY_RULE_ITEM, GALLERY_RULE_OFFER, GALLERY_RULE_PROPOSAL, GALLERY_RULE_TERMS, GALLERY_FILL_INTAKE, PEOPLE_ENROL, PEOPLE_ENROL_BY_ID, galleryAreaApproval, galleryCosignApproval, galleryPushApproval, galleryRuleApproval, galleryRunApproval, workspaceAsksGallery } from "../src/ui/workspace-asks-gallery.ts"
import { VIEWERS, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import type { PolicyAreaOffer, PolicyRememberArea, PolicyRememberRule, PolicyRuleOffer } from "@mehen/protocol/policy-mode"
import { policyAreaGrantTermsDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { digestOf } from "../src/ui/client/logic.ts"
import { APPROVAL_KEYS } from "../src/ui/client/shortcut-keys.ts"
import { type ConnectTerms, acceptanceMismatch, connectStartExpected } from "../src/ui/client/ask-logic.ts"
import { type ApprovalRuleOffer, rememberRule, ruleProposalDigest, ruleProposalEffect } from "../src/ui/client/workspace-logic.ts"
import { initWorkspaceApproval, initWorkspaceAreaProposal, initWorkspaceConnect, initWorkspaceEnrol, initWorkspaceEnrolClosed, initWorkspaceIntake, initWorkspacePolicy, initWorkspaceRuleProposal } from "../src/ui/client/pages/workspace-asks.ts"
import { fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { THUMBPRINT } from "../src/ui/people-gallery.ts"
import type { CredentialHome } from "@mehen/protocol/workspace"
import { AREA_MISMATCH_WORDS, GROUP_MATCHES_WORDS, PAGE_MISMATCH_WORDS, RULE_COSIGN_ASKED_WORDS, RULE_NOT_NAMED_WORDS, RULE_PROPOSAL_COSIGN_WORDS, RULE_PROPOSAL_DENIED_WORDS, RULE_MISMATCH_WORDS, RULE_PROPOSAL_PAGE_MISMATCH_WORDS, TICK_CODE_WORDS, TYPE_GROUP_WORDS, areaAllowedWords, areaApproveLabel, areaProposalAllowedWords, ruleAllowedWords } from "../src/ui/wording.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle } from "./mini-dom.ts"

// rememberRule and ruleProposalEffect as the pages call them, so a test can hold their answers back
// and let them land out of order; every other test gets the real one.
vi.mock("../src/ui/client/workspace-logic.ts", async (original) => {
  const real = await original<typeof import("../src/ui/client/workspace-logic.ts")>()
  return { ...real, rememberRule: vi.fn(real.rememberRule), ruleProposalEffect: vi.fn(real.ruleProposalEffect) }
})

vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => ({ id: "test-assertion" }),
  startRegistration: async () => ({ id: "test-registration" }),
}))

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

type Answer = { status: number; body: unknown }
const ok = (body: unknown = {}): Answer => ({ status: 200, body })
const WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const API = "/api/w/northwind"
const ASSERTION = { nonce: "n", assertion: { id: "test-assertion" } }

function shell(): ShellState {
  return new ShellState({ origin: "https://app.mehen.dev", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: WORKSPACE, pages: [], reads: [] })
}

// The calls every signed change makes once its action is checked, and
// the routes a test names; anything else is not found.
function signing(routes: Record<string, unknown>): (path: string) => Answer {
  return (path) => {
    if (path === API) return ok(WORKSPACE)
    if (path === `${API}/stepup/start`) return ok({ nonce: "n", options: { challenge: "c" } })
    if (path in routes) return ok(routes[path])
    return { status: 404, body: { error: "not_found", message: `No route ${path}.` } }
  }
}

function open(page: PageInput, respond: (path: string, body: unknown) => Answer): MiniBrowser {
  browser = installPage(renderDocument(page).value, respond, "https://app.mehen.dev/w/northwind/")
  return browser
}

function gallery(id: string): PageInput {
  const found = workspaceAsksGallery().find((e) => e.id === id)
  if (found === undefined) throw new Error(`no gallery entry ${id}`)
  return found.page
}

const $ = (selector: string): MiniElement => {
  const found = browser!.document.querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}
// The workspace's own calls, without the wider-access poller's.
const paths = () => browser!.calls.map((c) => c.path).filter((p) => p.startsWith(API))
const call = (path: string) => browser!.calls.find((c) => c.path === path)

function select(selector: string, value: string): void {
  const el = $(selector)
  el.value = value
  el.dispatchEvent(new MiniEvent("change", { bubbles: true }))
}

function typeInto(selector: string, value: string): void {
  const el = $(selector)
  el.value = value
  el.dispatchEvent(new MiniEvent("input", { bubbles: true }))
}

// ---------------------------------------------------------------- approval

const decider = { role: "admin" as const, member: "mem_tom00001" }

// The gallery's run approval with the digest the vault would have stored
// for what it shows, or with another one.
async function runApproval(matching: boolean): Promise<Extract<WorkspaceApprovalView, { view: "detail" }>> {
  const view = galleryRunApproval(true, ["Tom"])
  if (view.view !== "detail" || !view.binding) throw new Error("detail")
  const digest = await digestOf({ subject: approvalSubjectOf(view.approval), snapshotDigest: view.binding.snapshotDigest, presentationDigest: view.binding.presentationDigest })
  return { ...view, approval: { ...view.approval, digest: matching ? digest : "a-digest-the-page-cannot-rebuild" } }
}

function approvalPage(view: WorkspaceApprovalView): PageInput {
  return workspaceApprovalPage(galleryShell(decider), { viewer: decider, view, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") })
}

describe("the workspace approval page", () => {
  it("keeps Approve off until the page's digest matches and the code is ticked, and says why in the bar", async () => {
    const page = approvalPage(await runApproval(true))
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    expect($('[data-action="approve"]').disabled).toBe(true)
    expect($('[data-region="bar-caption"]').textContent).toBe(TICK_CODE_WORDS)
    await settle()
    expect($('[data-region="digest-match"]').hidden).toBe(false)
    expect($('[data-action="approve"]').disabled).toBe(true)
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(false)
    expect($('[data-region="bar-caption"]').textContent).toBe("")
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(true)
    expect($('[data-action="deny"]').disabled).toBe(false)
  })

  it("leaves Approve off with the mismatch shown when the stored digest is not the one the page rebuilds", async () => {
    const page = approvalPage(await runApproval(false))
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(true)
    expect($('[data-region="digest-mismatch"]').hidden).toBe(false)
    expect($('[data-region="digest-match"]').hidden).toBe(true)
    expect($('[data-region="bar-caption"]').textContent).toBe(PAGE_MISMATCH_WORDS)
  })

  it("a click on Approve in the bar, outside the card's form, signs approval.decide with the stored digest and the chosen terms", async () => {
    const view = await runApproval(true)
    const a = view.approval
    const page = approvalPage(view)
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } }
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: { status: "approved" } }))
    initWorkspaceApproval(page.boot, shell())
    const approve = $('[data-action="approve"]')
    expect(approve.closest('[data-form="decide"]')).toBeNull()
    expect(approve.closest('[data-region="bar"]')).not.toBeNull()
    expect(approve.getAttribute("form")).toBe("decide")
    expect($("#decide").getAttribute("data-form")).toBe("decide")
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="change-terms"]').click()
    expect($('[data-region="terms-form"]').hidden).toBe(false)
    select('[data-input="ttl"]', "60")
    for (const text of browser!.document.querySelectorAll('[data-region="terms-text"]')) expect(text.textContent).toBe("Once, within 1 minute")
    approve.click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/action`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } })
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, stepUp: ASSERTION })
    expect(browser!.reloaded).toBe(1)
  })

  it("a push has no terms to change: Approve signs approval.decide with the terms the push asked for", async () => {
    const pushed = galleryPushApproval({ owner: "northwind", repo: "platform", parent: null, fork: false, private: true, newDestination: false, exists: true, id: "apr_9pq4wn2kx7" })
    if (pushed.view !== "detail" || !pushed.binding) throw new Error("detail")
    const digest = await digestOf({ subject: approvalSubjectOf(pushed.approval), snapshotDigest: pushed.binding.snapshotDigest, presentationDigest: pushed.binding.presentationDigest })
    const a = { ...pushed.approval, digest }
    const page = approvalPage({ ...pushed, approval: a })
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } }
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: { status: "approved" } }))
    initWorkspaceApproval(page.boot, shell())
    expect(browser!.document.querySelector('[data-input="uses"]')).toBeNull()
    expect(browser!.document.querySelector('[data-action="change-terms"]')).toBeNull()
    await settle()
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(false)
    $('[data-action="approve"]').click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/action`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } })
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 600 }, stepUp: ASSERTION })
    expect(browser!.reloaded).toBe(1)
  })

  it("Decline signs the terms the agent asked for, whatever is chosen", async () => {
    const view = await runApproval(true)
    const a = view.approval
    const page = approvalPage(view)
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "deny", constraints: a.constraints }
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: { status: "denied" } }))
    initWorkspaceApproval(page.boot, shell())
    select('[data-input="ttl"]', "60")
    $('[data-action="deny"]').click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/action`)?.body).toEqual({ decision: "deny", constraints: a.constraints })
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "deny", constraints: a.constraints, stepUp: ASSERTION })
  })

  it("refuses before the passkey when the vault's action is not the one the page rebuilt", async () => {
    const view = await runApproval(true)
    const a = view.approval
    const page = approvalPage(view)
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 5, ttlSeconds: 3600 } } }))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve"]').click()
    await settle()
    expect(paths()).toEqual([`${API}/approvals/${a.approval}/action`])
  })

  it("D and Y reach the bar's Decline and Approve, T the tick in the card's form", async () => {
    open(approvalPage(await runApproval(true)), signing({}))
    expect(browser!.document.querySelector(APPROVAL_KEYS.d!.selector)?.closest('[data-region="bar"]')).not.toBeNull()
    expect(browser!.document.querySelector(APPROVAL_KEYS.y!.selector)?.closest('[data-region="bar"]')).not.toBeNull()
    expect(browser!.document.querySelector(APPROVAL_KEYS.t!.selector)?.closest("#decide")).not.toBeNull()
  })

  it("the stop view's one Stop declines whatever the vault stored", async () => {
    const stop = gallery("ws-approval-stop")
    const id = String(stop.boot.approval)
    open(stop, signing({ [`${API}/approvals/${id}/action`]: { type: "approval.decide", approval: id, digest: "stored", decision: "deny", constraints: { uses: 1, ttlSeconds: 60 } }, [`${API}/approvals/${id}/decide`]: { status: "denied" } }))
    initWorkspaceApproval(stop.boot, shell())
    expect($('[data-action="deny"]').textContent).toBe("Stop")
    $('[data-action="deny"]').click()
    await settle()
    expect(call(`${API}/approvals/${id}/decide`)?.body).toEqual({ decision: "deny", stepUp: ASSERTION })
  })
})

// ---------------------------------------------------------------- allow this from now on

// The gallery's GitHub comment the vault offers as a rule (or its Linear
// comment a manager must co-sign), with the digest the vault would have
// stored for what it shows.
async function ruleApproval(offer: PolicyRuleOffer = GALLERY_RULE_OFFER): Promise<Extract<WorkspaceApprovalView, { view: "detail" }>> {
  const view = offer === GALLERY_COSIGN_OFFER ? galleryCosignApproval() : galleryRuleApproval(offer)
  if (view.view !== "detail" || !view.binding) throw new Error("detail")
  const digest = await digestOf({ subject: approvalSubjectOf(view.approval), snapshotDigest: view.binding.snapshotDigest, presentationDigest: view.binding.presentationDigest })
  return { ...view, approval: { ...view.approval, digest } }
}

function ownerPage(view: WorkspaceApprovalView): PageInput {
  return workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") })
}

// The vault's answer to the decide: the approval as it now stands, with
// what a remember made.
function decided(view: Extract<WorkspaceApprovalView, { view: "detail" }>, approval: Record<string, unknown>): WorkspaceApprovalView {
  return { ...view, approval: { ...view.approval, status: "approved", decidedBy: { name: "Alex", self: true }, ...approval } }
}

function choose(selector: string): void {
  $(selector).click()
}

const WIDE = "/repos/northwind/platform/issues/*/comments"

describe("Approve and allow this from now on", () => {
  it("stays off until the page's digest matches and the code is ticked, beside Approve once", async () => {
    const page = ownerPage(await ruleApproval())
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    const allow = $('[data-action="approve-rule"]')
    expect(allow.disabled).toBe(true)
    await settle()
    expect(allow.disabled).toBe(true)
    $('[data-input="code-matches"]').click()
    expect(allow.disabled).toBe(false)
    expect($('[data-action="approve"]').disabled).toBe(false)
    expect($('[data-region="rule-mismatch"]').hidden).toBe(true)
    expect(allow.getAttribute("aria-describedby")).toBeNull()
    expect($('[data-region="bar-caption"]').textContent).toBe("")
    $('[data-input="code-matches"]').click()
    expect(allow.disabled).toBe(true)
  })

  it("stays off while the offer's terms do not hash to the vault's digest; Approve once still works", async () => {
    const page = ownerPage(await ruleApproval({ ...GALLERY_RULE_OFFER, termsDigest: "x".repeat(43) }))
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve-rule"]').disabled).toBe(true)
    expect($('[data-action="approve"]').disabled).toBe(false)
    expect($('[data-region="rule-mismatch"]').hidden).toBe(false)
    expect($('[data-action="approve-rule"]').getAttribute("aria-describedby")).toBe("rule-mismatch")
    expect($("#rule-mismatch").getAttribute("data-region")).toBe("rule-mismatch")
    // The live bar caption says so too, as a line that only turns visible may go unannounced.
    expect($('[data-region="bar-caption"]').textContent).toBe(RULE_MISMATCH_WORDS)
  })

  it("a path or duration change turns it off until that choice's digest is rebuilt", async () => {
    const page = ownerPage(await ruleApproval())
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const allow = $('[data-action="approve-rule"]')
    expect(allow.disabled).toBe(false)
    choose(`[data-input="rule-path"][value="${WIDE}"]`)
    expect(allow.disabled).toBe(true)
    allow.click()
    await settle()
    expect(allow.disabled).toBe(false)
    choose('[data-input="rule-ttl"][value="86400"]')
    expect(allow.disabled).toBe(true)
    await settle()
    expect(allow.disabled).toBe(false)
    expect(paths()).toEqual([])
  })

  it("when rebuilt digests land out of order, only the last change's counts", async () => {
    const real = (await vi.importActual<typeof import("../src/ui/client/workspace-logic.ts")>("../src/ui/client/workspace-logic.ts")).rememberRule
    type Built = Awaited<ReturnType<typeof rememberRule>>
    const held: { path: string; ttl: string; land: (b: Built) => void }[] = []
    const page = ownerPage(await ruleApproval())
    const offer = page.boot.rule as ApprovalRuleOffer
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const allow = $('[data-action="approve-rule"]')
    const mismatch = $('[data-region="rule-mismatch"]')
    expect(allow.disabled).toBe(false)
    vi.mocked(rememberRule).mockImplementation((_offer, path, ttl) => new Promise<Built>((land) => held.push({ path, ttl, land: (b) => land(b) })))
    try {
      // The older change fails late; the newer one, rebuilt first, holds.
      choose(`[data-input="rule-path"][value="${WIDE}"]`)
      choose('[data-input="rule-ttl"][value="86400"]')
      expect(held.map((h) => [h.path, h.ttl])).toEqual([[WIDE, "604800"], [WIDE, "86400"]])
      held[1]!.land(await real(offer, WIDE, "86400"))
      await settle()
      expect([allow.disabled, mismatch.hidden]).toEqual([false, true])
      held[0]!.land({ ok: false, problems: ["late"] })
      await settle()
      expect([allow.disabled, mismatch.hidden]).toEqual([false, true])
      // The older change holds late; the newer one, rebuilt first, fails.
      choose('[data-input="rule-ttl"][value="2592000"]')
      choose('[data-input="rule-ttl"][value="604800"]')
      held[3]!.land({ ok: false, problems: ["newest"] })
      await settle()
      expect([allow.disabled, mismatch.hidden]).toEqual([true, false])
      held[2]!.land(await real(offer, WIDE, "2592000"))
      await settle()
      expect([allow.disabled, mismatch.hidden]).toEqual([true, false])
    } finally {
      vi.mocked(rememberRule).mockImplementation(real)
    }
    expect(paths()).toEqual([])
  })

  it("signs one approval.decide that remembers the chosen path and duration, then says until the end the vault names, in place of the form and the bar", async () => {
    const view = await ruleApproval()
    const a = view.approval
    const remember = { kind: "rule", path: WIDE, ttlSeconds: 86_400, termsDigest: await policyRuleTermsDigest({ ...GALLERY_RULE_TERMS, path: WIDE, ttlSeconds: 86_400 }) }
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember: remember as PolicyRememberRule }
    const page = ownerPage(view)
    // The vault ended the rule sooner than the day chosen (its approver's
    // access ends first): the page says the vault's end.
    const endsAt = "2026-10-28T09:15:00.000Z"
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: decided(view, { rule: { id: "rul_7kq2mw4zx1", endsAt }, ruleProposal: null }) }))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    choose(`[data-input="rule-path"][value="${WIDE}"]`)
    choose('[data-input="rule-ttl"][value="86400"]')
    await settle()
    $('[data-action="approve-rule"]').click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/action`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember })
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember, stepUp: ASSERTION })
    expect(paths().filter((p) => p.endsWith("/decide"))).toHaveLength(1)
    expect(browser!.reloaded).toBe(0)
    const words = $('[data-region="rule-confirmed"]').textContent
    expect(words).toBe(ruleAllowedWords(Date.parse(endsAt)))
    const confirmed = $('[data-region="rule-confirmed"]')
    expect([confirmed.getAttribute("role"), confirmed.getAttribute("tabindex")]).toEqual(["status", "-1"])
    expect((browser!.document as MiniElement & { activeElement?: MiniElement }).activeElement).toBe(confirmed)
    // What was said before the decision goes: the time to decide, what Approve
    // once would allow and what happens next.
    for (const leftover of ['[data-region="decision"] .meta', ".ask-next"]) expect($(leftover).hidden, leftover).toBe(true)
    expect(words).toMatch(/^Approved\. Allowed from now on until \d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC\.$/)
    expect(browser!.document.querySelector('[data-form="decide"]')).toBeNull()
    expect($('[data-region="bar"]').hidden).toBe(true)
    for (const input of browser!.document.querySelectorAll('[data-region="rule-panel"] input')) expect(input.disabled).toBe(true)
  })

  it("locks the path and duration while signing, so the passkey signs what the panel shows, and unlocks them when signing fails", async () => {
    const view = await ruleApproval()
    const a = view.approval
    let answer: (value: Answer) => void = () => undefined
    const respond = signing({})
    const page = ownerPage(view)
    open(page, (path, body) => (path === `${API}/approvals/${a.approval}/action` ? new Promise<Answer>((resolve) => (answer = resolve)) as never : respond(path, body)))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve-rule"]').click()
    const radios = browser!.document.querySelectorAll('[data-region="rule-panel"] input')
    for (const radio of radios) expect(radio.disabled).toBe(true)
    await settle()
    expect(paths()).toEqual([`${API}/approvals/${a.approval}/action`])
    choose(`[data-input="rule-path"][value="${WIDE}"]`)
    choose('[data-input="rule-ttl"][value="86400"]')
    expect($('[data-input="rule-path"]:checked').value).toBe(GALLERY_RULE_TERMS.path)
    expect($('[data-input="rule-ttl"]:checked').value).toBe("604800")
    answer({ status: 409, body: { error: "conflict", message: "This approval is no longer pending." } })
    await settle()
    for (const radio of radios) expect(radio.disabled).toBe(false)
    expect(paths().filter((p) => p.endsWith("/decide"))).toEqual([])
  })

  it("a decide the vault refuses shows its error and keeps the form and the bar, with no confirmation", async () => {
    const view = await ruleApproval()
    const a = view.approval
    const remember = { kind: "rule" as const, path: GALLERY_RULE_TERMS.path, ttlSeconds: 604_800 as const, termsDigest: GALLERY_RULE_OFFER.refused === null ? GALLERY_RULE_OFFER.termsDigest : "" }
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember }
    const respond = signing({ [`${API}/approvals/${a.approval}/action`]: expected })
    const refusal = { error: "conflict", message: "The rule's terms are not the ones the vault offers.", next: { say: "Nothing was approved. Reload the page and decide again." } }
    const page = ownerPage(view)
    open(page, (path, body) => (path === `${API}/approvals/${a.approval}/decide` ? { status: 409, body: refusal } : respond(path, body)))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve-rule"]').click()
    await settle()
    expect(paths().filter((p) => p.endsWith("/decide"))).toHaveLength(1)
    const error = $(".notice.error")
    expect(error.hidden).toBe(false)
    expect(error.textContent).toContain(refusal.message)
    expect(browser!.document.querySelector('[data-region="rule-confirmed"]')).toBeNull()
    expect($('[data-form="decide"]').hidden).toBe(false)
    expect($('[data-region="bar"]').hidden).toBe(false)
    expect(browser!.document.body.textContent).not.toContain("Allowed from now on")
    expect(browser!.reloaded).toBe(0)
    expect($('[data-action="approve-rule"]').disabled).toBe(false)
  })

  it("co-sign: says the request was approved once and a manager of the credential's home was asked to co-sign", async () => {
    const view = await ruleApproval(GALLERY_COSIGN_OFFER)
    const a = view.approval
    if (GALLERY_COSIGN_OFFER.refused !== null) throw new Error("offered")
    const remember = { kind: "rule" as const, path: "/graphql", ttlSeconds: 604_800 as const, termsDigest: GALLERY_COSIGN_OFFER.termsDigest }
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember }
    const page = ownerPage(view)
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: decided(view, { rule: null, ruleProposal: { id: "pol_3cs9kq2mz8", url: "https://app.mehen.dev/w/northwind/p/pol_3cs9kq2mz8", bindingCode: "M4TR", expiresAt: "2026-10-28T18:30:00.000Z" } }) }))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve-rule"]').click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember, stepUp: ASSERTION })
    expect($('[data-region="rule-confirmed"]').textContent).toBe(RULE_COSIGN_ASKED_WORDS)
    expect(browser!.reloaded).toBe(0)
  })

  it("says nothing is allowed from now on when the vault's answer names no rule, whatever the page offered, and reloads on an answer that is not approved", async () => {
    const view = await ruleApproval()
    const a = view.approval
    const remember = { kind: "rule" as const, path: GALLERY_RULE_TERMS.path, ttlSeconds: 604_800 as const, termsDigest: GALLERY_RULE_OFFER.refused === null ? GALLERY_RULE_OFFER.termsDigest : "" }
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember }
    for (const [answer, words] of [[decided(view, {}), RULE_NOT_NAMED_WORDS], [{ status: "approved" }, null], [decided(view, { status: "stale", rule: { id: "rul_7kq2mw4zx1", endsAt: "2026-10-28T09:15:00.000Z" } }), null]] as const) {
      const page = ownerPage(view)
      open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: answer }))
      initWorkspaceApproval(page.boot, shell())
      await settle()
      $('[data-input="code-matches"]').click()
      $('[data-action="approve-rule"]').click()
      await settle()
      expect(browser!.document.querySelector('[data-region="rule-confirmed"]')?.textContent ?? null).toBe(words)
      expect(browser!.reloaded).toBe(words === null ? 1 : 0)
      expect(browser!.document.body.textContent).not.toContain("Allowed from now on")
      browser!.restore()
    }
  })

  it("Approve once on the same page remembers nothing and reloads as before", async () => {
    const view = await ruleApproval()
    const a = view.approval
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } }
    const page = ownerPage(view)
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: { status: "approved" } }))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve"]').click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, stepUp: ASSERTION })
    expect(browser!.reloaded).toBe(1)
  })
})

// ---------------------------------------------------------------- let the agent carry on

// The gallery's D1 database create the vault offers a task grant on, with
// the digest the vault would have stored for what it shows.
async function areaApproval(area: PolicyAreaOffer = GALLERY_AREA_OFFER): Promise<Extract<WorkspaceApprovalView, { view: "detail" }>> {
  const view = galleryAreaApproval(undefined, area)
  if (view.view !== "detail" || !view.binding) throw new Error("detail")
  const digest = await digestOf({ subject: approvalSubjectOf(view.approval), snapshotDigest: view.binding.snapshotDigest, presentationDigest: view.binding.presentationDigest })
  return { ...view, approval: { ...view.approval, digest } }
}
const areaName = (id: string) => GALLERY_AREA_OFFER.areas.find((a) => a.id === id)!.name
// What the panel shows chosen: the areas ticked, the duration and the uses.
const panelChoice = () => ({
  areas: browser!.document.querySelectorAll('[data-input="area-area"]').filter((i) => i.checked).map((i) => i.value),
  ttl: browser!.document.querySelectorAll('[data-input="area-ttl"]').filter((i) => i.checked).map((i) => i.value),
  uses: browser!.document.querySelectorAll('[data-input="area-uses"]').filter((i) => i.checked).map((i) => i.value),
})

describe("Approve, and let this agent carry on", () => {
  it("names the areas and duration the panel shows on the button, and signs one approval.decide remembering exactly them", async () => {
    const view = await areaApproval()
    const a = view.approval
    const terms = { ...GALLERY_AREA_TERMS, areas: ["kv"], ttlSeconds: 900 as const, maxUses: 25 as const }
    const remember: PolicyRememberArea = { kind: "area", areas: ["kv"], ttlSeconds: 900, maxUses: 25, termsDigest: await policyAreaGrantTermsDigest(terms) }
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: a.approval, digest: a.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember }
    const page = ownerPage(view)
    open(page, signing({ [`${API}/approvals/${a.approval}/action`]: expected, [`${API}/approvals/${a.approval}/decide`]: decided(view, { rule: null, ruleProposal: null }) }))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const carry = $('[data-action="approve-area"]')
    const label = () => carry.querySelector("span:last-child")!.textContent
    expect(carry.disabled).toBe(false)
    expect(label()).toBe(areaApproveLabel([areaName("d1")], 3600))
    choose('[data-input="area-area"][value="d1"]')
    choose('[data-input="area-area"][value="kv"]')
    choose('[data-input="area-ttl"][value="900"]')
    choose('[data-input="area-uses"][value="25"]')
    await settle()
    expect(panelChoice()).toEqual({ areas: ["kv"], ttl: ["900"], uses: ["25"] })
    expect(label()).toBe(areaApproveLabel([areaName("kv")], 900))
    expect(carry.disabled).toBe(false)
    carry.click()
    await settle()
    expect(call(`${API}/approvals/${a.approval}/action`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember })
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
    expect(call(`${API}/approvals/${a.approval}/decide`)?.body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 }, remember, stepUp: ASSERTION })
    expect(paths().filter((p) => p.endsWith("/decide"))).toHaveLength(1)
    expect($('[data-region="rule-confirmed"]').textContent).toBe(areaAllowedWords(900, 25))
    expect(browser!.reloaded).toBe(0)
  })

  it("with every area unticked, turns the button off without calling it a mismatch, and sends nothing", async () => {
    const view = await areaApproval()
    const page = ownerPage(view)
    open(page, signing({}))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const carry = $('[data-action="approve-area"]')
    expect(carry.disabled).toBe(false)
    choose('[data-input="area-area"][value="d1"]')
    await settle()
    expect(panelChoice().areas).toEqual([])
    expect(carry.disabled).toBe(true)
    expect($('[data-region="area-mismatch"]').hidden).toBe(true)
    expect(carry.getAttribute("aria-describedby")).toBeNull()
    expect($('[data-region="bar-caption"]').textContent).toBe("")
    expect($('[data-action="approve"]').disabled).toBe(false)
    carry.click()
    await settle()
    expect(paths()).toEqual([])
  })

  it("refuses an offer whose terms changed from the vault's digest, or that ticks other than the request's own area, and sends nothing for it", async () => {
    const offers: PolicyAreaOffer[] = [
      { ...GALLERY_AREA_OFFER, terms: { ...GALLERY_AREA_TERMS, maxUses: 200 } },
      { ...GALLERY_AREA_OFFER, terms: { ...GALLERY_AREA_TERMS, areas: ["kv"] }, termsDigest: await policyAreaGrantTermsDigest({ ...GALLERY_AREA_TERMS, areas: ["kv"] }) },
    ]
    for (const offer of offers) {
      const page = ownerPage(await areaApproval(offer))
      open(page, signing({}))
      initWorkspaceApproval(page.boot, shell())
      await settle()
      $('[data-input="code-matches"]').click()
      const carry = $('[data-action="approve-area"]')
      expect(carry.disabled).toBe(true)
      expect($('[data-region="area-mismatch"]').hidden).toBe(false)
      expect(carry.getAttribute("aria-describedby")).toBe("area-mismatch")
      expect($('[data-region="bar-caption"]').textContent).toBe(AREA_MISMATCH_WORDS)
      expect($('[data-action="approve"]').disabled).toBe(false)
      carry.click()
      await settle()
      expect(paths()).toEqual([])
      browser!.restore()
    }
  })
})

// The task grant a co-signer decides: the terms as the first person signed
// them, read only, sent back exactly; where the first person unticked an
// area, the narrower terms.
describe("the task grant proposal page", () => {
  const p = GALLERY_AREA_PROPOSAL.proposal
  const PROPOSAL = `${API}/policy/proposals/${p.proposal}`

  it("signs one policy.decide for exactly the areas, duration and uses it shows, narrowed where the first person unticked an area", async () => {
    for (const areas of [["d1", "kv"], ["kv"]]) {
      const terms = { ...p.terms, areas }
      const termsDigest = await policyAreaGrantTermsDigest(terms)
      const digest = await ruleProposalDigest({ proposal: p.proposal, stage: p.stage, termsDigest, extends: null, reason: p.reason })
      const page = workspaceAreaProposalPage(galleryShell(VIEWERS.manager), { ...p, terms, termsDigest, digest, areas: GALLERY_AREA_OFFER.areas.filter((a) => areas.includes(a.id)) }, { provider: "cloudflare", account: null }, Date.parse("2026-10-27T18:30:00Z"))
      const expected: WorkspaceStepUpAction = { type: "policy.decide", proposal: p.proposal, digest, decision: "approve", effectDigest: termsDigest }
      open(page, signing({ [`${PROPOSAL}/action`]: expected, [`${PROPOSAL}/decide`]: { view: "detail", proposal: { ...p, terms, status: "approved", rule: { id: "rul_2ga8kq4mz7", endsAt: "2026-10-27T19:30:00.000Z" }, canApprove: false, canDeny: false } } }))
      initWorkspaceAreaProposal(page.boot, shell())
      expect(browser!.document.querySelectorAll('[data-region="area-areas"] li').map((li) => li.querySelector("b")!.textContent)).toEqual(areas.map(areaName))
      expect($('[data-region="area-ttl"]').textContent).toBe("1 hour")
      expect($('[data-region="area-uses"]').textContent).toBe("50 requests")
      await settle()
      $('[data-action="approve"]').click()
      await settle()
      const body = { decision: "approve", effective: { areas, ttlSeconds: 3600, maxUses: 50 } }
      expect(call(`${PROPOSAL}/action`)?.body).toEqual(body)
      expect(call(`${API}/stepup/start`)?.body).toEqual({ action: expected })
      expect(call(`${PROPOSAL}/decide`)?.body).toEqual({ ...body, stepUp: ASSERTION })
      expect($('[data-region="rule-confirmed"]').textContent).toBe(areaProposalAllowedWords(Date.parse("2026-10-27T19:30:00.000Z"), 50))
      browser!.restore()
    }
  })
})

// ---------------------------------------------------------------- enrolment

const GROUP = "5NZV"

async function withCheck(view: WorkspaceEnrolView): Promise<WorkspaceEnrolView> {
  return { ...view, fingerprint: { ...view.fingerprint, check: await fingerprintGroupCheck(view.ref, GROUP) } }
}

function enrolPage(view: WorkspaceEnrolView): PageInput {
  return enrolmentPage(peopleShell("member", { member: "mem_tom01" }), view, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: PEOPLE_PROJECTS, now: 0 })
}

describe("the enrolment page, both forms", () => {
  for (const [form, fixture] of [["code", PEOPLE_ENROL], ["id", PEOPLE_ENROL_BY_ID]] as const) {
    it(`${form} form: Accept turns on only for the group that hashes to the page's check, keyed by the page's ref`, async () => {
      const view = await withCheck(fixture)
      const page = enrolPage(view)
      expect(page.boot.hidden).toBe(PEOPLE_ENROL.fingerprint.hidden)
      open(page, signing({ [`${API}/enrolments/${encodeURIComponent(view.ref)}/action`]: { action: { type: "enrol.accept" } } }))
      initWorkspaceEnrol(page.boot, shell())
      const accept = $('[data-action="enrol-accept"]')
      expect(accept.disabled).toBe(true)
      expect($('[data-region="enrol-enables"]').textContent).toBe(TYPE_GROUP_WORDS)
      typeInto('[data-input="fingerprint-group"]', "2222")
      await settle()
      expect(accept.disabled).toBe(true)
      typeInto('[data-input="fingerprint-group"]', GROUP.toLowerCase())
      await settle()
      expect(accept.disabled).toBe(false)
      expect($('[data-region="enrol-enables"]').textContent).toBe(GROUP_MATCHES_WORDS)
      expect(accept.closest('[data-region="bar"]')).not.toBeNull()
      accept.click()
      await settle()
      // Tom, a member, accepts his own machine with the private tick on by default.
      expect(call(`${API}/enrolments/${encodeURIComponent(view.ref)}/action`)?.body).toEqual({ kind: "accept", group: GROUP, privateCredentials: true })
    })
  }

  it("the code form's check does not match on the id form, so neither page can borrow the other's", async () => {
    const byCode = await withCheck(PEOPLE_ENROL)
    const page = enrolPage({ ...PEOPLE_ENROL_BY_ID, fingerprint: byCode.fingerprint })
    open(page, signing({}))
    initWorkspaceEnrol(page.boot, shell())
    typeInto('[data-input="fingerprint-group"]', GROUP)
    await settle()
    expect($('[data-action="enrol-accept"]').disabled).toBe(true)
  })

  it("Reject is on from the start and posts the reject for the page's ref", async () => {
    const page = enrolPage(PEOPLE_ENROL_BY_ID)
    open(page, signing({ [`${API}/enrolments/enr_new01/reject`]: { state: "rejected" } }))
    initWorkspaceEnrol(page.boot, shell())
    expect($('[data-action="enrol-reject"]').disabled).toBe(false)
    $('[data-action="enrol-reject"]').click()
    await settle()
    expect(paths()).toEqual([`${API}/enrolments/enr_new01/reject`])
    expect(browser!.reloaded).toBe(1)
  })

  it("a lapsed link's Reject posts the reject for its ref", async () => {
    const lapsed = gallery("enrol-lapsed")
    open(lapsed, signing({ [`${API}/enrolments/enr_new01/reject`]: { state: "rejected" } }))
    initWorkspaceEnrolClosed(lapsed.boot, shell())
    $('[data-action="enrol-reject"]').click()
    await settle()
    expect(paths()).toEqual([`${API}/enrolments/enr_new01/reject`])
  })
})

// ---------------------------------------------------------------- intake and connect

describe("intake and connect", () => {
  it("a warned intake's Stop this request posts the intake's cancel", async () => {
    const page = gallery("ws-intake-deceptive")
    open(page, signing({ [`${API}/intakes/int_9vq3mz7kd2/cancel`]: { status: "cancelled" } }))
    initWorkspaceIntake(page.boot, shell())
    expect($('[data-action="submit-intake"]').disabled).toBe(true)
    $('[data-action="cancel-request"]').click()
    await settle()
    expect(paths()).toEqual([`${API}/intakes/int_9vq3mz7kd2/cancel`])
    expect(call(`${API}/intakes/int_9vq3mz7kd2/cancel`)?.body).toEqual({})
    expect(browser!.reloaded).toBe(1)
  })

  it("the intake's Seal and save in the bar turns on once the field is filled", () => {
    const page = gallery("ws-intake")
    open(page, signing({}))
    initWorkspaceIntake(page.boot, shell())
    const button = $('[data-action="submit-intake"]')
    expect(button.closest('[data-region="bar"]')).not.toBeNull()
    expect(button.disabled).toBe(true)
    typeInto('[data-field="key"]', "sk-test")
    expect(button.disabled).toBe(false)
  })

  it("a warned connect's Stop this request posts the connect's cancel", async () => {
    const page = gallery("ws-connect-deceptive")
    open(page, signing({ [`${API}/connect/con_3kd9vx2mq7/cancel`]: { status: "cancelled" } }))
    initWorkspaceConnect(page.boot, shell())
    expect($('[data-action="start-connect"]').closest('[data-region="bar"]')).not.toBeNull()
    $('[data-action="cancel-request"]').click()
    await settle()
    expect(paths()).toEqual([`${API}/connect/con_3kd9vx2mq7/cancel`])
  })

  it("Continue refuses a connect.start that names only this connect and the chosen home", async () => {
    const page = gallery("ws-connect")
    const action = `${API}/connect/con_8vw2kq5mz3/action`
    open(page, signing({ [action]: { type: "connect.start", connect: "con_8vw2kq5mz3", home: { kind: "workspace" } } }))
    initWorkspaceConnect(page.boot, shell())
    $('[data-input="home"][value="member:mem_alex0001"]').click()
    $('[data-action="start-connect"]').click()
    await settle()
    expect(call(action)?.body).toEqual({ home: { kind: "member", member: "mem_alex0001" } })
    expect(paths()).toEqual([action])
  })
})

// ---------------------------------------------------------------- policy

describe("the workspace policy page", () => {
  it("the stop view's Stop declines the proposal the vault stored", async () => {
    const page = gallery("ws-policy-stop")
    const stopAction = `${API}/policy/proposals/pol_8kq2mw4zx1/action`
    open(page, signing({ [stopAction]: { type: "policy.decide", proposal: "pol_8kq2mw4zx1", digest: "stored", decision: "deny", effectDigest: null }, [`${API}/policy/proposals/pol_8kq2mw4zx1/decide`]: {} }))
    initWorkspacePolicy(page.boot, shell())
    $('[data-action="deny"]').click()
    await settle()
    expect(paths()).toEqual([stopAction, API, `${API}/stepup/start`, `${API}/policy/proposals/pol_8kq2mw4zx1/decide`])
  })
})

// ---------------------------------------------------------------- ask fixes

// The connect page signs only the connect.start it showed, member for
// member, with the home chosen; any other prepared action stops before the
// workspace read, the step-up, the passkey, the start and the redirect.
describe("connect: every term of connect.start is the page's own", () => {
  const ACTION = `${API}/connect/con_8vw2kq5mz3/action`
  const START = `${API}/connect/con_8vw2kq5mz3/start`
  function expectedFor(page: PageInput, home: CredentialHome): WorkspaceStepUpAction {
    const expected = connectStartExpected(String(page.boot.connect), page.boot.terms as ConnectTerms, home)
    if (expected === null) throw new Error("no client")
    return expected
  }
  const MEMBER: CredentialHome = { kind: "member", member: "mem_alex0001" }

  it("signs and redirects for the exact action, after the passkey", async () => {
    const page = gallery("ws-connect")
    const expected = expectedFor(page, MEMBER)
    expect(expected).toEqual({ type: "connect.start", connect: "con_8vw2kq5mz3", provider: "google-gmail", slug: "gmail-alex", home: MEMBER, tags: ["mail"], expectedAccount: "alex@northwind.example", scopes: ["https://www.googleapis.com/auth/gmail.readonly"], intent: "create", target: null, targetRevision: null, client: "itm_gclient01", clientRevision: 1, dependencyRevision: 0 })
    open(page, signing({ [ACTION]: expected, [START]: { authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth?state=s" } }))
    initWorkspaceConnect(page.boot, shell())
    $('[data-action="start-connect"]').click()
    await settle()
    expect(paths()).toEqual([ACTION, API, `${API}/stepup/start`, START])
    expect(call(START)?.body).toEqual({ home: MEMBER, stepUp: ASSERTION })
    expect(browser!.assigned).toEqual(["https://accounts.google.com/o/oauth2/v2/auth?state=s"])
  })

  const CHANGES: [string, Record<string, unknown>][] = [
    ["type", { type: "intake.submit" }],
    ["connect", { connect: "con_another0001" }],
    ["provider", { provider: "microsoft-outlook" }],
    ["slug", { slug: "gmail-other" }],
    ["home", { home: { kind: "workspace" } }],
    ["tags", { tags: ["mail", "wider"] }],
    ["expectedAccount", { expectedAccount: "other@example.com" }],
    ["scopes", { scopes: ["https://www.googleapis.com/auth/gmail.readonly", "https://mail.google.com/"] }],
    ["intent", { intent: "rotate" }],
    ["target", { target: "itm_target0001" }],
    ["targetRevision", { targetRevision: 7 }],
    ["client", { client: "itm_gclient02" }],
    ["clientRevision", { clientRevision: 2 }],
    ["dependencyRevision", { dependencyRevision: 1 }],
    ["an extra member", { extra: true }],
  ]
  for (const [member, change] of CHANGES) {
    it(`a prepared action with another ${member} stops before any step-up, passkey, start or redirect`, async () => {
      const page = gallery("ws-connect")
      open(page, signing({ [ACTION]: { ...expectedFor(page, MEMBER), ...change }, [START]: { authorizeUrl: "https://accounts.google.com/" } }))
      initWorkspaceConnect(page.boot, shell())
      $('[data-action="start-connect"]').click()
      await settle()
      expect(paths()).toEqual([ACTION])
      expect(browser!.assigned).toEqual([])
      expect($("#notice").textContent).toContain("changed")
    })
  }

  it("a page that saw no OAuth client signs nothing at all", async () => {
    const page = gallery("ws-connect")
    const boot = { ...page.boot, terms: { ...(page.boot.terms as ConnectTerms), client: null, clientRevision: null } }
    open({ ...page, boot }, signing({}))
    initWorkspaceConnect(boot, shell())
    $('[data-action="start-connect"]').click()
    await settle()
    expect(paths()).toEqual([])
    expect($("#notice").textContent).toContain("does not know which OAuth client")
  })
})

// The planned acceptance is compared with the page before the passkey.
const VISIBLE_GROUPS = fingerprintGroups(fingerprintOf(THUMBPRINT))
const HIDDEN = PEOPLE_ENROL.fingerprint.hidden
const TRUE_GROUP = VISIBLE_GROUPS[HIDDEN]!

async function coherentEnrol(view: WorkspaceEnrolView): Promise<WorkspaceEnrolView> {
  return { ...view, fingerprint: { groups: VISIBLE_GROUPS.filter((_, i) => i !== HIDDEN), hidden: HIDDEN, check: await fingerprintGroupCheck(view.ref, TRUE_GROUP), words: fingerprintWords(THUMBPRINT) } }
}

function exactAcceptance(page: PageInput, privateCredentials = false): Record<string, unknown> {
  const shown = page.boot.acceptance as { scope: Record<string, unknown> } & Record<string, unknown>
  return { type: "enrol.accept", ...shown, scope: { ...shown.scope, privateCredentials }, thumbprint: THUMBPRINT }
}

describe("enrolment Accept signs only the acceptance the page showed", () => {
  for (const [form, fixture] of [["code", PEOPLE_ENROL], ["id", PEOPLE_ENROL_BY_ID]] as const) {
    it(`${form} form: the exact acceptance is signed, after the workspace read and with the typed group`, async () => {
      const page = enrolPage(await coherentEnrol(fixture))
      const base = `${API}/enrolments/${encodeURIComponent(fixture.ref)}`
      expect(JSON.stringify(page.boot)).not.toContain(THUMBPRINT)
      open(page, signing({ [`${base}/action`]: { action: exactAcceptance(page, true) }, [`${base}/accept`]: { state: "active" } }))
      initWorkspaceEnrol(page.boot, shell())
      typeInto('[data-input="fingerprint-group"]', TRUE_GROUP)
      await settle()
      $('[data-action="enrol-accept"]').click()
      await settle()
      expect(paths()).toEqual([`${base}/action`, API, `${API}/stepup/start`, `${base}/accept`])
      expect(call(`${base}/accept`)?.body).toEqual({ group: TRUE_GROUP, privateCredentials: true, stepUp: ASSERTION })
      expect(browser!.reloaded).toBe(1)
    })
  }

  const OTHER_THUMBPRINT = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5"
  const CHANGES: [string, (a: Record<string, unknown>) => Record<string, unknown>][] = [
    ["another action family", () => ({ type: "policy.decide", proposal: "pol_other00001", digest: "d", decision: "approve", effectDigest: "e" })],
    ["another workspace", (a) => ({ ...a, workspace: "tn_another000001" })],
    ["another enrolment", (a) => ({ ...a, enrolment: "enr_another01" })],
    ["another account", (a) => ({ ...a, account: "acc_another000001" })],
    ["another member", (a) => ({ ...a, member: "mem_another01" })],
    ["private credentials the person unticked", (a) => ({ ...a, scope: { ...(a.scope as object), privateCredentials: true } })],
    ["a wider scope", (a) => ({ ...a, scope: { ...(a.scope as object), maxEnvironment: "protected" } })],
    ["another start", (a) => ({ ...a, start: { ...(a.start as object), place: "Elsewhere" } })],
    ["another key", (a) => ({ ...a, thumbprint: OTHER_THUMBPRINT })],
    ["no key", (a) => ({ ...a, thumbprint: 7 })],
    ["an extra member", (a) => ({ ...a, extra: true })],
  ]
  for (const [what, change] of CHANGES) {
    it(`a planned acceptance with ${what} stops before the step-up`, async () => {
      const page = enrolPage(await coherentEnrol(PEOPLE_ENROL_BY_ID))
      const base = `${API}/enrolments/enr_new01`
      open(page, signing({ [`${base}/action`]: { action: change(exactAcceptance(page)) } }))
      initWorkspaceEnrol(page.boot, shell())
      // The person unticks the private tick, so the page shows it off.
      $('[data-input="enrol-private"]').click()
      typeInto('[data-input="fingerprint-group"]', TRUE_GROUP)
      await settle()
      $('[data-action="enrol-accept"]').click()
      await settle()
      expect(paths()).toEqual([`${base}/action`])
    })
  }

  it("acceptanceMismatch compares the key's own groups and words with the page's", async () => {
    const page = enrolPage(await coherentEnrol(PEOPLE_ENROL))
    const shown = page.boot.acceptance as Parameters<typeof acceptanceMismatch>[1]
    const fp = page.boot.fingerprint as Parameters<typeof acceptanceMismatch>[2]
    expect(acceptanceMismatch(exactAcceptance(page), shown, fp, false, TRUE_GROUP)).toBeNull()
    expect(acceptanceMismatch(exactAcceptance(page, true), shown, fp, true, TRUE_GROUP)).toBeNull()
    expect(acceptanceMismatch(exactAcceptance(page), shown, fp, false, "2222")).toBe("another key")
    expect(acceptanceMismatch(exactAcceptance(page), shown, { ...fp, words: [...fp.words].reverse() }, false, TRUE_GROUP)).toBe("another key")
  })
})

// The folded Belongs to always names the home that will be signed.
describe("the collapsed home names the home being signed", () => {
  it("connect: private to workspace, the closed fold's summary follows, and the start signs workspace", async () => {
    const page = gallery("ws-connect")
    const WORKSPACE_HOME: CredentialHome = { kind: "workspace" }
    const expected = connectStartExpected(String(page.boot.connect), page.boot.terms as ConnectTerms, WORKSPACE_HOME)
    open(page, signing({ [`${API}/connect/con_8vw2kq5mz3/action`]: expected, [`${API}/connect/con_8vw2kq5mz3/start`]: { authorizeUrl: "https://accounts.google.com/" } }))
    initWorkspaceConnect(page.boot, shell())
    const fold = $('[data-region="home-choice"]')
    expect(fold.getAttribute("open")).toBeNull()
    expect($('[data-region="home-current"]').textContent).toBe("Only me")
    $('[data-input="home"][value="workspace"]').click()
    expect($('[data-region="home-current"]').textContent).toBe("Whole workspace")
    $('[data-input="home"][value="member:mem_alex0001"]').click()
    expect($('[data-region="home-current"]').textContent).toBe("Only me")
    $('[data-input="home"][value="workspace"]').click()
    $('[data-action="start-connect"]').click()
    await settle()
    expect(call(`${API}/connect/con_8vw2kq5mz3/start`)?.body).toMatchObject({ home: WORKSPACE_HOME })
  })

  it("intake: project to workspace, the summary follows, and the submission signs workspace", async () => {
    const page = gallery("ws-intake")
    open(page, signing({ [`${API}/intakes/int_4hz8rq2nk1/submit`]: { item: { slug: "openai-staging" } } }))
    initWorkspaceIntake(page.boot, shell())
    expect($('[data-region="home-current"]').textContent).toBe("This project (platform)")
    $('[data-input="home"][value="workspace"]').click()
    expect($('[data-region="home-current"]').textContent).toBe("Whole workspace")
    typeInto('[data-field="key"]', "sk-test-not-a-secret")
    $('[data-action="submit-intake"]').click()
    await settle(60)
    expect((call(`${API}/intakes/int_4hz8rq2nk1/submit`)?.body as { home?: unknown } | undefined)?.home).toEqual({ kind: "workspace" })
  })

  it("intake: the sign-in page follows the address typed, and only Type it into the sign-in page signs the fill ceiling", async () => {
    const page = gallery("ws-intake-fill")
    const submit = `${API}/intakes/${GALLERY_FILL_INTAKE.intake}/submit`
    open(page, signing({ [submit]: { item: { slug: GALLERY_FILL_INTAKE.slug } } }))
    initWorkspaceIntake(page.boot, shell())
    const line = $('[data-region="fill-signin-page"]'), httpsOnly = $('[data-region="fill-https-only"]')
    expect(line.textContent).toBe("Sign-in page: https://github.com")
    typeInto('[data-field="url"]', "http://github.com/login")
    expect(httpsOnly.hidden).toBe(false)
    expect(line.textContent).toBe("Sign-in page: https://github.com")
    typeInto('[data-field="url"]', "https://login.github.com/session")
    expect(httpsOnly.hidden).toBe(true)
    expect(line.hidden).toBe(false)
    expect(line.textContent).toBe("Sign-in pages: https://login.github.com, https://github.com")
    typeInto('[data-field="username"]', "alex@example.com")
    typeInto('[data-field="password"]', "not-a-real-password")
    $('[data-input="accept-destination"]').click()
    $('[data-input="fill-ceiling"][value="fill"]').click()
    $('[data-action="submit-intake"]').click()
    await settle(60)
    const { stepUp: _stepUp, ...signed } = call(submit)?.body as { stepUp: unknown; tags: string[] } & Record<string, unknown>
    expect(signed.ceiling).toBe("fill")
    expect(call(`${API}/stepup/start`)?.body).toEqual({ action: { type: "intake.submit", intake: GALLERY_FILL_INTAKE.intake, digest: await digestOf({ ...signed, tags: [...signed.tags].sort() }) } })
  })

  it("intake: Not at all, as it starts, sends no ceiling, so the body signs as it did before the choice", async () => {
    const page = gallery("ws-intake-fill")
    const submit = `${API}/intakes/${GALLERY_FILL_INTAKE.intake}/submit`
    open(page, signing({ [submit]: { item: { slug: GALLERY_FILL_INTAKE.slug } } }))
    initWorkspaceIntake(page.boot, shell())
    typeInto('[data-field="url"]', "https://github.com/login")
    typeInto('[data-field="username"]', "alex@example.com")
    typeInto('[data-field="password"]', "not-a-real-password")
    $('[data-input="accept-destination"]').click()
    $('[data-action="submit-intake"]').click()
    await settle(60)
    expect(Object.keys(call(submit)?.body as object).sort()).toEqual(["binding", "home", "publicFields", "sealed", "slug", "stepUp", "tags"])
  })

  it("a radio value naming no permitted home signs nothing", async () => {
    const page = gallery("ws-connect")
    open(page, signing({}))
    initWorkspaceConnect(page.boot, shell())
    const radio = $('[data-input="home"][value="workspace"]')
    radio.setAttribute("value", "member:mem_somebody")
    radio.click()
    $('[data-action="start-connect"]').click()
    await settle()
    expect(paths()).toEqual([])
  })
})

// The gate alone turns an action on, during and after an attempt.
function deferred(): { promise: Promise<Answer>; release: (answer: Answer) => void } {
  let release: (answer: Answer) => void = () => undefined
  const promise = new Promise<Answer>((resolve) => (release = resolve))
  return { promise, release }
}

const REFUSED: Answer = { status: 409, body: { error: "conflict", message: "Refused for the test." } }

describe("async attempts never leave an action on that fails its gate", () => {
  it("approval: unticking during an attempt keeps Approve off through its failure", async () => {
    const view = await runApproval(true)
    const page = approvalPage(view)
    const pending = deferred()
    const action = `${API}/approvals/${view.approval.approval}/action`
    open(page, (path) => (path === action ? (pending.promise as unknown as Promise<never>) : signing({})(path)))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const approve = $('[data-action="approve"]')
    approve.click()
    await settle()
    expect(approve.disabled).toBe(true)
    expect($('[data-action="deny"]').disabled).toBe(true)
    $('[data-input="code-matches"]').click()
    expect(approve.disabled).toBe(true)
    approve.click()
    $('[data-action="deny"]').click()
    pending.release(REFUSED)
    await settle()
    expect(approve.disabled).toBe(true)
    expect($('[data-action="deny"]').disabled).toBe(false)
    expect(paths()).toEqual([action])
  })

  it("approval: a cancelled passkey restores the gate, not a bare enabled button", async () => {
    const view = await runApproval(true)
    const page = approvalPage(view)
    const expected: WorkspaceStepUpAction = { type: "approval.decide", approval: view.approval.approval, digest: view.approval.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } }
    open(page, (path) => (path === `${API}/stepup/start` ? REFUSED : signing({ [`${API}/approvals/${view.approval.approval}/action`]: expected })(path)))
    initWorkspaceApproval(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve"]').click()
    await settle()
    expect($('[data-action="approve"]').disabled).toBe(false)
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(true)
  })

  it("enrolment: a new group drops the old match at once, and a failed attempt does not turn Accept back on", async () => {
    const page = enrolPage(await coherentEnrol(PEOPLE_ENROL_BY_ID))
    const base = `${API}/enrolments/enr_new01`
    const pending = deferred()
    open(page, (path) => (path === `${base}/action` ? (pending.promise as unknown as Promise<never>) : signing({})(path)))
    initWorkspaceEnrol(page.boot, shell())
    typeInto('[data-input="fingerprint-group"]', TRUE_GROUP)
    await settle()
    const accept = $('[data-action="enrol-accept"]')
    expect(accept.disabled).toBe(false)
    accept.click()
    await settle()
    typeInto('[data-input="fingerprint-group"]', "2222")
    expect(accept.disabled).toBe(true)
    pending.release(REFUSED)
    await settle()
    expect(accept.disabled).toBe(true)
    expect($('[data-region="enrol-enables"]').textContent).toBe(TYPE_GROUP_WORDS)
    accept.click()
    await settle()
    expect(paths()).toEqual([`${base}/action`])
  })

  it("enrolment: rapid input settles on the last value's answer only", async () => {
    const page = enrolPage(await coherentEnrol(PEOPLE_ENROL))
    open(page, signing({}))
    initWorkspaceEnrol(page.boot, shell())
    typeInto('[data-input="fingerprint-group"]', TRUE_GROUP)
    await settle()
    expect($('[data-action="enrol-accept"]').disabled).toBe(false)
    // The next keystroke turns it off before its hash is known.
    typeInto('[data-input="fingerprint-group"]', "2222")
    expect($('[data-action="enrol-accept"]').disabled).toBe(true)
    $('[data-action="enrol-accept"]').click()
    typeInto('[data-input="fingerprint-group"]', TRUE_GROUP)
    typeInto('[data-input="fingerprint-group"]', "2222")
    await settle()
    expect($('[data-action="enrol-accept"]').disabled).toBe(true)
    $('[data-action="enrol-accept"]').click()
    await settle()
    expect(paths()).toEqual([])
  })

  it("intake: emptying the field during an attempt keeps Seal and save off through its failure", async () => {
    const page = gallery("ws-intake")
    const pending = deferred()
    open(page, (path) => (path === API ? (pending.promise as unknown as Promise<never>) : signing({})(path)))
    initWorkspaceIntake(page.boot, shell())
    typeInto('[data-field="key"]', "sk-test-not-a-secret")
    const button = $('[data-action="submit-intake"]')
    button.click()
    await settle(60)
    expect(button.disabled).toBe(true)
    typeInto('[data-field="key"]', "")
    pending.release(REFUSED)
    await settle(60)
    expect(button.disabled).toBe(true)
    button.click()
    await settle(60)
    expect(paths()).toEqual([API])
  })
})

// Every live ask page's decision form holds Enter, whatever field it
// comes from; the gated actions are the only way to decide.
describe("the decision form never submits natively", () => {
  const INITS: [string, (boot: PageInput["boot"], s: ShellState) => void][] = [
    ["ws-approval-decider", initWorkspaceApproval],
    ["ws-approval-stop", initWorkspaceApproval],
    ["ws-intake", initWorkspaceIntake],
    ["ws-connect", initWorkspaceConnect],
    ["ws-policy-stop", initWorkspacePolicy],
    ["enrol-accept", initWorkspaceEnrol],
  ]
  for (const [id, init] of INITS) {
    it(`${id}: a submit of #decide is held and sends nothing`, async () => {
      const page = gallery(id)
      open(page, signing({}))
      init(page.boot, shell())
      const allowed = $("#decide").dispatchEvent(new MiniEvent("submit", { bubbles: true }))
      expect(allowed).toBe(false)
      await settle()
      expect(paths()).toEqual([])
      expect(browser!.assigned).toEqual([])
    })
  }
})

// On every ask page with a bar, the bar is not a form, its controls
// all belong to the decision form by form="decide", and that form is
// outside it.
describe("every bar belongs to its page's decision form", () => {
  const withBars = workspaceAsksGallery().filter((e) => e.page.bar === true)

  it("covers every gallery page with a bar", () => {
    expect(withBars.map((e) => e.id).sort()).toEqual(expect.arrayContaining(["ws-approval-decider", "ws-approval-stop", "ws-approval-stop-hostile", "ws-intake", "ws-connect", "ws-policy-stop", "enrol-accept", "enrol-admit", "enrol-team-admit"]))
  })

  for (const entry of withBars) {
    it(`${entry.id}: the bar is outside #decide and every control in it is tied to it`, () => {
      open(entry.page, signing({}))
      const bar = $('[data-region="bar"]')
      expect(bar.localName).toBe("div")
      expect(bar.closest("form")).toBeNull()
      const form = $("#decide")
      expect(form.localName).toBe("form")
      expect(form.closest('[data-region="bar"]')).toBeNull()
      const controls = bar.querySelectorAll("button, select, input, textarea")
      expect(controls.length).toBeGreaterThan(0)
      for (const c of controls) expect(c.getAttribute("form"), `${entry.id} ${c.getAttribute("data-action") ?? c.getAttribute("data-input") ?? c.localName}`).toBe("decide")
      for (const b of bar.querySelectorAll("button")) expect(b.getAttribute("type")).toBe("button")
      expect(browser!.document.querySelectorAll('form.bar, [data-form="policy"]')).toEqual([])
    })
  }
})

// ---------------------------------------------------------------- rule proposals

describe("the rule proposal page", () => {
  const p = GALLERY_RULE_PROPOSAL.proposal
  const PROPOSAL = `${API}/policy/proposals/${p.proposal}`
  const EXACT = p.terms.anchorPath
  const proposalPage = (proposal: Partial<typeof p> = {}): PageInput => workspaceRuleProposalPage(galleryShell(VIEWERS.owner), { view: "detail", proposal: { ...p, ...proposal } }, GALLERY_RULE_ITEM, Date.parse("2026-10-27T18:30:00Z"))
  const approved = async (path: string, ttlSeconds: 86_400 | 604_800 | 2_592_000): Promise<WorkspaceStepUpAction> => ({ type: "policy.decide", proposal: p.proposal, digest: p.digest, decision: "approve", effectDigest: await policyRuleTermsDigest({ ...p.terms, path, ttlSeconds }) })
  // The vault's answer to the decide: the proposal as it now stands.
  const answered = (proposal: Record<string, unknown>) => ({ view: "detail", proposal: { ...p, canApprove: false, canDeny: false, ...proposal } })

  it("keeps Approve off until the page's digests match and the code is ticked; Deny is on", async () => {
    const page = proposalPage()
    open(page, signing({}))
    initWorkspaceRuleProposal(page.boot, shell())
    const approve = $('[data-action="approve"]')
    expect(approve.disabled).toBe(true)
    await settle()
    expect($('[data-region="digest-match"]').hidden).toBe(false)
    expect(approve.disabled).toBe(true)
    expect($('[data-region="bar-caption"]').textContent).toBe(TICK_CODE_WORDS)
    $('[data-input="code-matches"]').click()
    expect(approve.disabled).toBe(false)
    expect($('[data-region="bar-caption"]').textContent).toBe("")
    expect($('[data-action="deny"]').disabled).toBe(false)
  })

  it("says in the bar the terms the passkey would sign as the path and duration are chosen, and labels the card's line as what the agent proposed", async () => {
    const page = proposalPage()
    open(page, signing({}))
    initWorkspaceRuleProposal(page.boot, shell())
    await settle()
    const bar = $('[data-region="terms-text"]')
    expect(bar.textContent).toBe(`POST api.github.com${p.terms.path}, 30 days`)
    choose('[data-input="rule-ttl"][value="86400"]')
    choose(`[data-input="rule-path"][value="${EXACT}"]`)
    expect(bar.textContent).toBe(`POST api.github.com${EXACT}, 1 day`)
    expect($('[data-region="rule-summary"]').textContent).toBe(`The agent proposed: ${p.summary}`)
  })

  it("stays off, says why and describes Approve by it when the reason shown is not the one the vault's digest covers", async () => {
    const page = proposalPage({ reason: "Something the vault never stored" })
    open(page, signing({}))
    initWorkspaceRuleProposal(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    expect($('[data-action="approve"]').disabled).toBe(true)
    expect($('[data-region="digest-mismatch"]').hidden).toBe(false)
    expect($('[data-region="rule-mismatch"]').hidden).toBe(false)
    expect($('[data-action="approve"]').getAttribute("aria-describedby")).toBe("rule-mismatch")
    expect($('[data-region="bar-caption"]').textContent).toBe(RULE_PROPOSAL_PAGE_MISMATCH_WORDS)
    expect($('[data-action="deny"]').disabled).toBe(false)
  })

  it("signs one policy.decide for the narrowed path and duration, then says until when from the vault's answer, as a focused status", async () => {
    const expected = await approved(EXACT, 604_800)
    const page = proposalPage()
    open(page, signing({ [`${PROPOSAL}/action`]: expected, [`${PROPOSAL}/decide`]: answered({ status: "approved", rule: { id: "rul_4hq8mz2kx7", endsAt: "2026-11-03T18:30:00.000Z" } }) }))
    initWorkspaceRuleProposal(page.boot, shell())
    await settle()
    choose(`[data-input="rule-path"][value="${EXACT}"]`)
    choose('[data-input="rule-ttl"][value="604800"]')
    $('[data-input="code-matches"]').click()
    await settle()
    $('[data-action="approve"]').click()
    await settle()
    const body = { decision: "approve", effective: { path: EXACT, ttlSeconds: 604_800 } }
    expect(call(`${PROPOSAL}/action`)?.body).toEqual(body)
    expect(call(`${PROPOSAL}/decide`)?.body).toEqual({ ...body, stepUp: ASSERTION })
    const confirmed = $('[data-region="rule-confirmed"]')
    expect(confirmed.textContent).toBe(ruleAllowedWords(Date.parse("2026-11-03T18:30:00.000Z")))
    expect([confirmed.getAttribute("role"), confirmed.getAttribute("tabindex")]).toEqual(["status", "-1"])
    expect((browser!.document as MiniElement & { activeElement?: MiniElement }).activeElement).toBe(confirmed)
    for (const gone of ['[data-region="bar"]', '[data-region="decision"] .meta', ".ask-next"]) expect($(gone).hidden, gone).toBe(true)
    for (const input of browser!.document.querySelectorAll('[data-region="rule-panel"] input')) expect(input.disabled).toBe(true)
    expect(browser!.reloaded).toBe(0)
  })

  it("says what the vault's answer names: the co-sign it waits for, a denial, or nothing it can vouch for, then reloads", async () => {
    const expected = await approved(p.terms.path, 2_592_000)
    for (const [answer, words] of [[answered({ status: "pending", stage: "co-sign" }), RULE_PROPOSAL_COSIGN_WORDS], [answered({ status: "approved", rule: null }), null], [{ status: "approved" }, null]] as const) {
      const page = proposalPage()
      open(page, signing({ [`${PROPOSAL}/action`]: expected, [`${PROPOSAL}/decide`]: answer }))
      initWorkspaceRuleProposal(page.boot, shell())
      await settle()
      $('[data-input="code-matches"]').click()
      $('[data-action="approve"]').click()
      await settle()
      expect(browser!.document.querySelector('[data-region="rule-confirmed"]')?.textContent ?? null).toBe(words)
      expect(browser!.reloaded).toBe(words === null ? 1 : 0)
      browser!.restore()
    }
  })

  it("reads a co-sign answer as approved only when this page moved this proposal there from approve; otherwise it reloads", async () => {
    const co = GALLERY_COSIGN_PROPOSAL.proposal
    const cases = [
      [proposalPage(), PROPOSAL, await approved(p.terms.path, 2_592_000), answered({ status: "pending", stage: "co-sign", proposal: "pol_other" })],
      [gallery("ws-rule-proposal-cosign"), `${API}/policy/proposals/${co.proposal}`, { type: "policy.decide", proposal: co.proposal, digest: co.digest, decision: "approve", effectDigest: await policyRuleTermsDigest(co.terms) }, answered({ ...co, status: "pending", stage: "co-sign" })],
    ] as const
    for (const [page, at, expected, answer] of cases) {
      open(page, signing({ [`${at}/action`]: expected, [`${at}/decide`]: answer }))
      initWorkspaceRuleProposal(page.boot, shell())
      await settle()
      browser!.document.querySelector('[data-input="code-matches"]')?.click()
      $('[data-action="approve"]').click()
      await settle()
      expect(call(`${at}/decide`), at).toBeDefined()
      expect(browser!.document.querySelector('[data-region="rule-confirmed"]'), at).toBeNull()
      expect(browser!.reloaded, at).toBe(1)
      browser!.restore()
    }
  })

  it("Deny signs policy.decide with no effect and says no rule was made", async () => {
    const page = proposalPage()
    open(page, signing({ [`${PROPOSAL}/action`]: { type: "policy.decide", proposal: p.proposal, digest: p.digest, decision: "deny", effectDigest: null }, [`${PROPOSAL}/decide`]: answered({ status: "denied" }) }))
    initWorkspaceRuleProposal(page.boot, shell())
    $('[data-action="deny"]').click()
    await settle()
    expect(call(`${PROPOSAL}/decide`)?.body).toEqual({ decision: "deny", stepUp: ASSERTION })
    expect($('[data-region="rule-confirmed"]').textContent).toBe(RULE_PROPOSAL_DENIED_WORDS)
  })

  it("locks the path and duration while signing and unlocks them when signing fails, with the vault's error and the bar kept", async () => {
    let answer: (value: Answer) => void = () => undefined
    const respond = signing({})
    const page = proposalPage()
    open(page, (path, body) => (path === `${PROPOSAL}/action` ? new Promise<Answer>((resolve) => (answer = resolve)) as never : respond(path, body)))
    initWorkspaceRuleProposal(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    $('[data-action="approve"]').click()
    const radios = browser!.document.querySelectorAll('[data-region="rule-panel"] input')
    for (const radio of radios) expect(radio.disabled).toBe(true)
    await settle()
    choose(`[data-input="rule-path"][value="${EXACT}"]`)
    choose('[data-input="rule-ttl"][value="86400"]')
    expect($('[data-input="rule-path"]:checked').value).toBe(p.terms.path)
    expect($('[data-input="rule-ttl"]:checked').value).toBe("2592000")
    answer({ status: 409, body: { error: "conflict", message: "This proposal is no longer pending." } })
    await settle()
    for (const radio of radios) expect(radio.disabled).toBe(false)
    expect($(".notice.error").textContent).toContain("This proposal is no longer pending.")
    expect(browser!.document.querySelector('[data-region="rule-confirmed"]')).toBeNull()
    expect($('[data-region="bar"]').hidden).toBe(false)
    expect(paths().filter((x) => x.endsWith("/decide"))).toEqual([])
  })

  it("when rebuilt effects land out of order, only the last change's counts", async () => {
    const real = (await vi.importActual<typeof import("../src/ui/client/workspace-logic.ts")>("../src/ui/client/workspace-logic.ts")).ruleProposalEffect
    type Built = Awaited<ReturnType<typeof ruleProposalEffect>>
    const held: ((b: Built) => void)[] = []
    const page = proposalPage()
    open(page, signing({}))
    initWorkspaceRuleProposal(page.boot, shell())
    await settle()
    $('[data-input="code-matches"]').click()
    const approve = $('[data-action="approve"]')
    expect(approve.disabled).toBe(false)
    vi.mocked(ruleProposalEffect).mockImplementation(() => new Promise<Built>((land) => held.push(land)))
    try {
      choose('[data-input="rule-ttl"][value="86400"]')
      choose('[data-input="rule-ttl"][value="604800"]')
      held[1]!({ ok: false, problems: ["newest"] })
      await settle()
      held[0]!(await real(page.boot as never, p.terms.path, "86400"))
      await settle()
      expect(approve.disabled).toBe(true)
    } finally {
      vi.mocked(ruleProposalEffect).mockImplementation(real)
    }
  })

  it("at co-sign there is no code to tick: Approve turns on once the digests match", async () => {
    const page = gallery("ws-rule-proposal-cosign")
    open(page, signing({}))
    initWorkspaceRuleProposal(page.boot, shell())
    expect(browser!.document.querySelector('[data-input="code-matches"]')).toBeNull()
    await settle()
    expect($('[data-action="approve"]').disabled).toBe(false)
  })
})
