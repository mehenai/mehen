// The mandate pages' gallery states (mandates-gallery.ts), registered in the
// gallery script: each draws the buttons only for who may press them, the
// words for its state, never a credential the reader cannot see, and the
// sign page's summary in the design's words. The home's strip and the
// capped ask are in their own galleries.
import { describe, expect, it } from "vitest"
import { escapeHtml } from "./html.ts"
import { renderDocument } from "./layout.ts"
import { GALLERY_MANDATE, mandatesGallery } from "./mandates-gallery.ts"
import { MANDATE_PROPOSAL_CAP_DEFAULTS, MANDATE_CAP_DEFAULTS, type MandateView } from "@mehen/protocol/mandate-terms"
import { mandateControls, mandateSignDefaults, mandatePage, mandateSignPage, mandatesPage } from "./pages/mandates.ts"
import { PEOPLE_DEVICE, peopleShell } from "./people-gallery.ts"
import { VIEWERS, galleryShell } from "./workspace-projects-gallery.ts"
import type { Viewer } from "./workspace-rights.ts"
import { shellGallery } from "./shell-gallery.ts"
import { workspaceAsksGallery } from "./workspace-asks-gallery.ts"
import { HELD_WORDS } from "./workspace-rights.ts"
import { MANDATE_ALL_CREDENTIALS, MANDATE_ALL_LATER_WORDS, MANDATE_CANDIDATES_UNREAD_WORDS, mandateDayWords, MANDATE_HIDDEN_CREDENTIAL, MANDATE_NEVER_CANDIDATE_WORDS, MANDATE_PROPOSAL_SUPERSEDED_WORDS, MANDATE_REVIEWED_WORDS, MANDATE_REVOKED_WORDS, MANDATE_STATE_WORDS, MANDATE_UNREVIEWED_WORDS, MANDATE_WAITING_TITLE, mandateLapsedWords } from "./wording.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""
const NOW = Date.parse("2026-10-27T18:30:00Z")
const DAY = 86_400_000

function shown(id: string, entries = mandatesGallery()): string {
  const found = entries.find((e) => e.id === id)
  if (!found) throw new Error(`no gallery entry ${id}`)
  return renderDocument(found.page).value
}
const actions = (page: string) => [...new Set([...page.matchAll(/data-action="(mandate-[a-z]+)"/g)].map((m) => m[1]))].sort()

describe("the mandate gallery", () => {
  it("is in the gallery, with every page and state", () => {
    expect(GALLERY_SCRIPT).toContain('import { mandatesGallery } from "../src/ui/mandates-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...mandatesGallery(),")
    expect(mandatesGallery().map((e) => e.id)).toEqual([
      "ws-mandates-list", "ws-mandates-empty", "ws-mandate-active", "ws-mandate-active-admin", "ws-mandate-hidden", "ws-mandate-paused", "ws-mandate-tripped", "ws-mandate-lapsed", "ws-mandate-ending", "ws-mandate-stopped", "ws-mandate-expired",
      "ws-mandate-sign", "ws-mandate-sign-none", "ws-mandate-sign-proposal", "ws-mandate-sign-superseded", "ws-mandate-sign-all", "ws-mandate-sign-renew", "ws-mandate-sign-not-owner", "machine-mandate-trust", "machine-mandate-waiting", "machine-mandate-active", "machine-mandate-paused", "machine-mandate-admin",
    ])
    expect(shellGallery().some((e) => e.id === "workspace-home-mandates")).toBe(true)
    expect(shellGallery().some((e) => e.id === "workspace-home-mandates-resume")).toBe(true)
    expect(workspaceAsksGallery().some((e) => e.id === "ws-approval-mandate-capped")).toBe(true)
    expect(workspaceAsksGallery().some((e) => e.id === "ws-approval-mandate-cover")).toBe(true)
  })

  it("offers each reader only the buttons the vault would let them press", () => {
    expect(actions(shown("ws-mandate-active"))).toEqual(["mandate-pause", "mandate-stop"])
    expect(actions(shown("ws-mandate-active-admin"))).toEqual(["mandate-pause", "mandate-stop"])
    expect(actions(shown("ws-mandate-paused"))).toEqual(["mandate-resume", "mandate-stop"])
    expect(actions(shown("ws-mandate-tripped"))).toEqual(["mandate-resume", "mandate-stop"])
    expect(actions(shown("ws-mandate-lapsed"))).toEqual(["mandate-pause", "mandate-resume", "mandate-stop"])
    expect(actions(shown("ws-mandate-ending"))).toEqual(["mandate-pause", "mandate-renew", "mandate-stop"])
    expect(actions(shown("ws-mandate-stopped"))).toEqual(["mandate-renew"])
    expect(actions(shown("ws-mandate-expired"))).toEqual(["mandate-renew"])
    expect(actions(shown("machine-mandate-trust"))).toEqual(["mandate-trust"])
    expect(actions(shown("machine-mandate-waiting"))).toEqual(["mandate-proposal", "mandate-trust"])
    expect(actions(shown("machine-mandate-active"))).toEqual(["mandate-pause", "mandate-stop"])
    expect(actions(shown("machine-mandate-paused"))).toEqual(["mandate-resume", "mandate-stop"])
    expect(shown("machine-mandate-paused")).toContain('data-region="mandate-resume-hint"')
    expect(shown("ws-mandate-paused")).toContain('data-region="mandate-resume-hint"')
    expect(actions(shown("machine-mandate-admin"))).toEqual(["mandate-pause", "mandate-stop"])
    expect(shown("ws-mandate-ending")).toContain(`href="/w/northwind/sign-mandate?renew=${GALLERY_MANDATE.id}" data-action="mandate-renew">Renew</a>`)
    for (const id of ["ws-mandate-stopped", "ws-mandate-expired"]) expect(shown(id), id).toContain('data-action="mandate-renew">Sign again with these terms</a>')
  })

  it("decides who may press which from the view, the reader's role and the time", () => {
    const member = { role: "member" as const, member: "mem_kim00001" }
    const notSigner = { ...GALLERY_MANDATE, signer: { name: "Tom Barker", self: false } }
    expect(mandateControls(notSigner, member, NOW)).toEqual({ pause: false, stop: false, resume: false, renew: false })
    expect(mandateControls(notSigner, { role: "admin", member: "mem_kim00001" }, NOW)).toEqual({ pause: true, stop: true, resume: false, renew: false })
    // An owner or admin takes over a signer's or the machine's pause; the
    // signer of a paused one is offered Resume instead.
    expect(mandateControls({ ...notSigner, state: "paused" }, { role: "admin", member: "mem_kim00001" }, NOW)).toEqual({ pause: true, stop: true, resume: false, renew: false })
    expect(mandateControls({ ...notSigner, state: "paused" }, member, NOW).pause).toBe(false)
    expect(mandateControls({ ...notSigner, state: "tripped" }, { role: "admin", member: "mem_kim00001" }, NOW).pause).toBe(false)
    // A held account may still narrow: Pause and Stop, never Resume or Renew.
    const held = { role: "member" as const, member: "mem_tom01", held: true }
    expect(mandateControls(GALLERY_MANDATE, held, NOW)).toEqual({ pause: true, stop: true, resume: false, renew: false })
    expect(mandateControls({ ...GALLERY_MANDATE, state: "paused", expiresAt: new Date(NOW + DAY).toISOString() }, held, NOW)).toEqual({ pause: false, stop: true, resume: false, renew: false })
    // Renew from three days before the end; once it ended, however long
    // ago, Sign again with these terms.
    const at = (offset: number) => new Date(NOW + offset).toISOString()
    expect(mandateControls({ ...GALLERY_MANDATE, expiresAt: at(3 * DAY + 1) }, member, NOW).renew).toBe(false)
    expect(mandateControls({ ...GALLERY_MANDATE, expiresAt: at(3 * DAY) }, member, NOW).renew).toBe(true)
    expect(mandateControls({ ...GALLERY_MANDATE, state: "expired", expiresAt: at(-3 * DAY) }, member, NOW).renew).toBe(true)
    expect(mandateControls({ ...GALLERY_MANDATE, state: "expired", expiresAt: at(-30 * DAY) }, member, NOW).renew).toBe(true)
    expect(mandateControls({ ...GALLERY_MANDATE, state: "stopped", expiresAt: at(DAY) }, member, NOW).renew).toBe(true)
    expect(mandateControls({ ...GALLERY_MANDATE, state: "stopped", expiresAt: at(DAY) }, held, NOW).renew).toBe(false)
    // A revoked machine's mandate ended for good: nothing to sign again.
    expect(mandateControls({ ...GALLERY_MANDATE, state: "stopped", endedReason: "revoked", expiresAt: at(DAY) }, member, NOW)).toEqual({ pause: false, stop: false, resume: false, renew: false })
  })

  it("says a revoked machine's mandate ended for good, and offers its owner no form for it", () => {
    const viewer = { role: "member" as const, member: "mem_tom01" }
    const revoked = { ...GALLERY_MANDATE, state: "stopped" as const, endedReason: "revoked" as const }
    const page = renderDocument(mandatePage(galleryShell(viewer), { viewer, mandate: revoked, receipts: null, now: NOW })).value
    expect(page).toContain(escapeHtml(MANDATE_REVOKED_WORDS))
    expect(actions(page)).toEqual([])
    const sign = renderDocument(mandateSignPage(peopleShell("member", { member: viewer.member }), { viewer, device: { ...PEOPLE_DEVICE, revoked: true }, candidates: { items: [] }, start: mandateSignDefaults(PEOPLE_DEVICE.name), proposal: null, renews: null, replaces: null, now: NOW })).value
    expect(sign).toContain(escapeHtml(MANDATE_REVOKED_WORDS))
    expect(sign).not.toContain('data-form="mandate-sign"')
    expect(sign).not.toContain("Only Tom Barker can")
  })

  it("says what each state means, and that a lapsed one covers nothing until its signer resumes it", () => {
    for (const state of ["paused", "tripped", "stopped", "expired"] as const) expect(shown(`ws-mandate-${state}`)).toContain(escapeHtml(MANDATE_STATE_WORDS[state]))
    expect(shown("ws-mandate-lapsed")).toContain(escapeHtml(mandateLapsedWords("Tom Barker", true)))
    expect(shown("ws-mandate-active")).not.toContain('data-region="mandate-lapsed"')
    expect(shown("ws-mandate-ending")).toContain("Ends in 2 days")
    expect(shown("ws-mandate-active")).not.toContain('data-region="mandate-ends-in"')
  })

  it("never names a credential the reader cannot see", () => {
    const admin = shown("ws-mandate-active-admin")
    expect(admin).toContain("<code>slack-platform</code> <span data-region=\"mandate-hidden-items\">and 1 credential you cannot see</span>")
    expect(admin).not.toContain("github-tom")
    const hidden = shown("ws-mandate-hidden")
    expect(hidden).toContain(`<span data-region="mandate-hidden-items">${MANDATE_HIDDEN_CREDENTIAL}</span>`)
    const receipts = hidden.slice(hidden.indexOf('data-region="mandate-receipts"'))
    expect(receipts.match(/data-region="mandate-receipt" data-hidden/g)).toHaveLength(4)
    for (const leak of ["github-tom", "slack-platform", "api.github.com", "slack.com", "github.issues.comment", "run_7Hq2Lm4Zp7Rt5Vx"]) expect(receipts).not.toContain(leak)
  })

  it("lists receipts newest first, with a service nobody has reviewed and the next page", () => {
    const page = shown("ws-mandate-active")
    const receipts = page.slice(page.indexOf('data-region="mandate-receipts"'))
    expect(receipts.indexOf("api.github.com")).toBeLessThan(receipts.indexOf("slack.com"))
    expect(receipts).toContain("on a service nobody has reviewed")
    expect(receipts).toContain(`href="/w/northwind/mandates/${GALLERY_MANDATE.id}?before=1761500000000.mdu_0001"`)
  })

  it("summarises the terms in the design's words before the passkey", () => {
    const proposal = shown("ws-mandate-sign-proposal")
    const summary = proposal.slice(proposal.indexOf('data-region="mandate-summary"'))
    expect(summary).toContain(escapeHtml("tom-laptop may read, change and send with 2 credentials, github-tom and slack-platform, without asking you, until 26 Nov 2026 UTC, at most 500 reads, 100 changes and 10 sends a day, only on Monday, Tuesday, Wednesday, Thursday and Friday from 08:00 to 19:00, Europe/London time."))
    // An open proposal is one the vault would take: within what a machine
    // may propose.
    const caps = Object.fromEntries([...proposal.matchAll(/data-input="mandate-cap" data-class="(\w+)" value="(\d+)"/g)].map((m) => [m[1], Number(m[2])]))
    for (const [c, n] of Object.entries(caps)) expect(n, c).toBeLessThanOrEqual(MANDATE_PROPOSAL_CAP_DEFAULTS[c as keyof typeof MANDATE_PROPOSAL_CAP_DEFAULTS])
    expect(summary).toContain(escapeHtml(MANDATE_REVIEWED_WORDS))
    expect(summary).toContain(escapeHtml(MANDATE_UNREVIEWED_WORDS))
    expect(summary).not.toContain(escapeHtml(MANDATE_ALL_LATER_WORDS))
    expect(proposal).toContain("&quot;proposal&quot;:&quot;mdp_tomlaptop0000000001&quot;")
    const all = shown("ws-mandate-sign-all")
    expect(all).toContain(escapeHtml("tom-laptop may read, change, send and delete with every credential it can use whose home you manage, now and later, without asking you, until 25 Jan 2027 UTC, at most 5,000 reads, 2,000 changes, 50 sends and 20 deletes a day."))
    expect(all).toContain(escapeHtml(MANDATE_ALL_LATER_WORDS))
    expect(all).toContain(`data-input="mandate-items" value="all" checked><span>${escapeHtml(MANDATE_ALL_CREDENTIALS)}</span>`)
    expect(MANDATE_ALL_CREDENTIALS).toBe("Every credential it can use whose home you manage, now and later")
  })

  it("says whose home every credential means on a mandate's page", () => {
    const everything = { ...GALLERY_MANDATE, items: "all" as const }
    const terms = (viewer: Viewer, mandate: MandateView) => renderDocument(mandatePage(galleryShell(viewer), { viewer, mandate, receipts: null, now: NOW })).value
    expect(terms({ role: "member", member: "mem_tom01" }, everything)).toContain(`<span data-region="mandate-items">${escapeHtml(MANDATE_ALL_CREDENTIALS)}</span>`)
    expect(terms(VIEWERS.owner, { ...everything, signer: { name: "Tom Barker", self: false } })).toContain('<span data-region="mandate-items">Every credential it can use whose home Tom Barker manages, now and later</span>')
  })

  it("renews behind Use these terms: the form opens narrow, the old terms shown in words with the button, filled in only from the template", () => {
    const page = shown("ws-mandate-sign-renew")
    const live = page.slice(0, page.indexOf('<template data-region="mandate-source-form">'))
    expect(live).toContain('data-region="mandate-source"')
    expect(live).toContain('data-action="mandate-use-source"')
    expect(live).toContain('data-input="mandate-ttl" value="30" checked')
    expect(page).toContain('<template data-region="mandate-source-form">')
  })

  it("shows a closed proposal's terms only behind Use these terms, never in the live form", () => {
    const page = shown("ws-mandate-sign-superseded")
    const live = page.slice(0, page.indexOf('<template data-region="mandate-source-form">'))
    expect(live).toContain('data-action="mandate-use-source"')
    expect([...live.matchAll(/data-input="mandate-class" value="(\w+)" checked/g)].map((m) => m[1])).toEqual(["read"])
  })

  it("opens fresh on the narrowest terms: read alone, every cap at a machine's proposal default, a note naming the machine, 30 days and nothing to sign yet", () => {
    const page = shown("ws-mandate-sign")
    expect(page).toContain('data-input="mandate-class" value="read" checked disabled')
    for (const cls of ["change", "send", "delete"]) expect(page).not.toMatch(new RegExp(`data-input="mandate-class" value="${cls}" checked`))
    // Every cap starts at what a machine may propose; the larger maxima stay for a deliberate edit.
    for (const [cls, cap] of Object.entries(MANDATE_PROPOSAL_CAP_DEFAULTS)) expect(page).toMatch(new RegExp(`data-input="mandate-cap" data-class="${cls}"[^>]* value="${cap}"`))
    expect(page).toContain(`data-input="mandate-note" maxlength="200" autocomplete="off" value="Routine work on ${PEOPLE_DEVICE.name}"`)
    expect(page).toContain('data-input="mandate-ttl" value="30" checked')
    expect(page).toContain('data-action="mandate-sign" disabled')
    expect(shown("ws-mandate-sign-not-owner")).not.toContain('data-form="mandate-sign"')
    expect(shown("ws-mandate-sign-renew")).toContain('data-region="mandate-replaces"')
  })

  it("offers a credential no mandate covers unticked, and never tickable, with the reason", () => {
    const page = shown("ws-mandate-sign")
    expect(page).toContain(`<input type="checkbox" data-input="mandate-item" value="itm_stripelive00001" data-slug="stripe-live" data-never="live-key" disabled><span><code>stripe-live</code> <span class="small muted" data-region="mandate-never">${escapeHtml(MANDATE_NEVER_CANDIDATE_WORDS["live-key"])}</span>`)
    // Named by the terms it starts from, it is still unticked, and the
    // summary leaves it out.
    const named = renderDocument(mandateSignPage(peopleShell("member", { member: "mem_tom01" }), { viewer: { role: "member", member: "mem_tom01" }, device: PEOPLE_DEVICE, candidates: { items: [{ id: "itm_githubtom0000001", slug: "github-tom", never: null }, { id: "itm_stripelive00001", slug: "stripe-live", never: "live-key" }] }, start: { ...mandateSignDefaults(PEOPLE_DEVICE.name), items: ["itm_githubtom0000001", "itm_stripelive00001"] }, proposal: null, renews: null, replaces: null, now: NOW })).value
    expect([...named.matchAll(/data-input="mandate-item" value="(\w+)"[^>]*checked/g)].map((m) => m[1])).toEqual(["itm_githubtom0000001"])
    const summary = named.slice(named.indexOf('data-region="mandate-summary"'))
    expect(summary).toContain("github-tom")
    expect(summary).not.toContain("stripe-live")
  })

  it("tells the machine's owner why there is no form, never that someone else must sign", () => {
    const tom = (viewer: Viewer, candidates: { items: [] } | null) => renderDocument(mandateSignPage(peopleShell("member", { member: viewer.member }), { viewer, device: PEOPLE_DEVICE, candidates, start: mandateSignDefaults(PEOPLE_DEVICE.name), proposal: null, renews: null, replaces: null, now: NOW })).value
    const held = tom({ role: "member", member: "mem_tom01", held: true }, null)
    expect(held).toContain(escapeHtml(HELD_WORDS))
    const unread = tom({ role: "member", member: "mem_tom01" }, null)
    expect(unread).toContain(escapeHtml(MANDATE_CANDIDATES_UNREAD_WORDS))
    for (const page of [held, unread]) {
      expect(page).not.toContain('data-form="mandate-sign"')
      expect(page).not.toContain("Only Tom Barker can")
    }
  })

  it("marks a hidden character in a name in its notices and the page's title", () => {
    const device = { id: PEOPLE_DEVICE.device, name: "tom\u202elaptop" }
    const lapsed = { ...GALLERY_MANDATE, device, signer: { name: "Tom\u202eDavies", self: true }, signerCurrent: false }
    const page = renderDocument(mandatePage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, mandate: lapsed, receipts: null, now: NOW })).value
    const sign = renderDocument(mandateSignPage(peopleShell("member", { member: "mem_tom01" }), { viewer: { role: "member", member: "mem_alex" }, device: { ...PEOPLE_DEVICE, name: device.name, owner: { kind: "member", member: "mem_tom01", name: "Tom\u202eDavies" } }, candidates: null, start: mandateSignDefaults(PEOPLE_DEVICE.name), proposal: null, renews: null, replaces: null, now: NOW })).value
    for (const shownPage of [page, sign]) {
      expect(shownPage).not.toContain("\u202e")
      expect(shownPage).toMatch(/<title>[^<]*\[RLO U\+202E\][^<]*<\/title>/)
    }
    expect(page.slice(page.indexOf('data-region="mandate-lapsed"'))).toContain('<mark class="marker">')
    expect(sign).toContain('<mark class="marker">')
  })

  it("dates the end in the reader's time zone when the page has it, and says UTC when it does not", () => {
    expect(mandateDayWords("2027-01-25T23:30:00Z", "Pacific/Auckland")).toBe("26 Jan 2027")
    expect(mandateDayWords("2027-09-25T12:00:00Z", "Europe/London")).toBe("25 Sep 2027")
    expect(mandateDayWords("2027-01-25T23:30:00Z")).toBe("25 Jan 2027 UTC")
  })

  it("offers Pause all for the active mandates the reader may pause, at the revisions shown, and Sign the same for the signer's other machines", () => {
    const list = shown("ws-mandates-list")
    expect(list).toContain(`data-action="mandate-pause-all" data-pause="${GALLERY_MANDATE.id}:2" data-confirm="Pause this machine&#39;s mandate?`)
    expect(list).toContain('<p class="small refused" data-region="mandates-pause-all-refused" aria-live="polite" hidden></p>')
    expect(shown("ws-mandates-empty")).not.toContain("mandate-pause-all")
    const tom = mandatesPage(galleryShell(VIEWERS.manager), { viewer: VIEWERS.manager, mandates: [{ ...GALLERY_MANDATE, signer: { name: "Tom Barker", self: false } }], proposals: [], now: NOW })
    expect(renderDocument(tom).value).not.toContain("mandate-pause-all")
    const active = shown("ws-mandate-active")
    expect(active.slice(active.indexOf('data-region="mandate-sign-same"'))).toContain(`href="/w/northwind/sign-mandate?device=dev_tomdesk00001&amp;from=${GALLERY_MANDATE.id}">Sign the same for tom-desk</a>`)
    expect(shown("ws-mandate-active-admin")).not.toContain('data-region="mandate-sign-same"')
  })

  it("lists what machines proposed above the mandates, and on the machine's own card, each linking to its sign page", () => {
    const list = shown("ws-mandates-list")
    expect(list.indexOf('data-region="mandate-proposals"')).toBeGreaterThan(-1)
    expect(list.indexOf('data-region="mandate-proposals"')).toBeLessThan(list.indexOf('data-region="mandates-live"'))
    expect(list).toContain('href="/w/northwind/sign-mandate?proposal=mdp_alexdesk000000001"')
    expect(list).toContain(escapeHtml(MANDATE_WAITING_TITLE))
    expect(shown("ws-mandates-empty")).not.toContain('data-region="mandate-proposals"')
    const card = shown("machine-mandate-waiting")
    expect(card.slice(card.indexOf('data-region="mandate-waiting"'))).toContain('href="/w/northwind/sign-mandate?proposal=mdp_tomlaptop0000000001"')
    expect(shown("machine-mandate-trust")).not.toContain('data-region="mandate-waiting"')
  })

  it("says a proposal closed because a mandate was signed for its machine since, and links to it", () => {
    const page = shown("ws-mandate-sign-superseded")
    expect(page).toContain(escapeHtml(MANDATE_PROPOSAL_SUPERSEDED_WORDS))
    expect(page.slice(page.indexOf('data-region="mandate-proposed"'))).toContain(`href="/w/northwind/mandates/${GALLERY_MANDATE.id}"`)
    expect(page).toContain("&quot;proposal&quot;:null")
    expect(shown("ws-mandate-sign-proposal")).not.toContain(escapeHtml(MANDATE_PROPOSAL_SUPERSEDED_WORDS))
  })

  it("ticks neither credentials choice when the machine has none to offer, so every credential is chosen, never assumed", () => {
    const page = shown("ws-mandate-sign-none")
    expect(page).toContain('data-region="mandate-no-candidates"')
    expect(page).not.toMatch(/data-input="mandate-items" value="(listed|all)"[^>]* checked/)
    expect(page).toContain('data-action="mandate-sign" disabled')
  })
})
