// The workspace ask and enrolment pages, rendered from the gallery's
// fixtures: what each role sees and what it never sees. A stop view carries
// nothing about the request, a guest never sees who else could decide, the
// terms go no higher than asked, the request pages link only under their
// workspace, and an enrolment carries three groups and the hidden one's
// check, never the hidden group, the thumbprint or the key.

import { describe, expect, it } from "vitest"
import { WorkspaceEnrolViewSchema } from "@mehen/protocol/workspace"
import { type PageInput, renderDocument } from "./layout.ts"
import { escapeHtml, html } from "./html.ts"
import { ACCOUNT_HELD_WORDS, SETTLED_APPROVAL_WORDS, ruleProposalTexts, workspaceApprovalPage, workspaceLinks, workspaceProposalPage, workspaceRuleProposalPage } from "./pages/workspace-asks.ts"
import { GUEST_PRIVATE_OFF_WORDS, PRIVATE_OFF_WORDS, enrolmentPage } from "./pages/workspace-enrol.ts"
import { workspaceReviewPage } from "./pages/workspace-review.ts"
import { peopleShell } from "./people-gallery.ts"
import { pushStoreWords } from "./push-wording.ts"
import { GALLERY_FOREIGN_PRIVATE, VIEWERS, galleryShell } from "./workspace-projects-gallery.ts"
import { GALLERY_COSIGN_OFFER, GALLERY_COSIGN_PROPOSAL, GALLERY_EXTEND_PROPOSAL, GALLERY_PROPOSED_TERMS, GALLERY_READ_ONLY_PROPOSAL, GALLERY_RULE_ITEM, GALLERY_RULE_OFFER, GALLERY_RULE_PROPOSAL, GALLERY_RULE_TERMS, GALLERY_TASK, PEOPLE_ENROL, POLICY_STOP, WORKSPACE_ASK_PAGE_KINDS, GALLERY_REVIEW_GROUP, galleryEmailApproval, galleryFillSignInApproval, galleryPushApproval, galleryRuleApproval, galleryRunApproval, workspaceAsksGallery } from "./workspace-asks-gallery.ts"
import { POLICY_RULE_REFUSALS, type PolicyRuleOffer, type PolicyRuleRefusal, type PolicyRuleTerms, policyRulePathChoices } from "@mehen/protocol/policy-mode"
import { policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { REQUEST_BODY_HEADING, RULE_REASON_LABEL, RULE_REASON_WORDS, RULE_REFUSAL_WORDS } from "./wording.ts"
import { AREA_REFUSAL_WORDS } from "./wording.ts"
import { areaRefused } from "../vault/areas/policy-rules-workspace.ts"
import { GALLERY_AREA_OFFER, GALLERY_AREA_PROPOSAL, GALLERY_AREA_TERMS, GALLERY_D1_RULE_OFFER, galleryAreaApproval } from "./workspace-asks-gallery.ts"
import { workspaceAreaProposalPage } from "./pages/workspace-asks.ts"
import { POLICY_AREA_REFUSALS, type PolicyAreaOffer } from "@mehen/protocol/policy-mode"
import { policyAreaGrantTermsDigest } from "@mehen/protocol/policy-rules"
import { type AreaProposalBoot, type WorkspaceApprovalBoot, areaOfferMatches, areaProposalDecision, areaProposalMatches, areaProposalOutcomeWords, ruleOfferMatches } from "./client/workspace-logic.ts"
import { type RuleProposalBoot, approvalDecision, chosenConstraints, ruleProposalDigest, ruleProposalMatches } from "./client/workspace-logic.ts"
import { FILL_GRANTS } from "../vault/areas/browser-workspace.ts"
import type { ShellGalleryEntry } from "./shell-gallery.ts"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""
const GOLDEN = import.meta.glob<string>("./golden/*.html", { query: "?raw", import: "default", eager: true })

function entry(id: string): ShellGalleryEntry {
  const found = workspaceAsksGallery().find((e) => e.id === id)
  if (found === undefined) throw new Error(`no gallery entry ${id}`)
  return found
}

function rendered(id: string): string {
  return renderDocument(entry(id).page).value
}

// The part of a page between two markers, to look at one card.
function between(text: string, from: string, to: string): string {
  const start = text.indexOf(from)
  const end = text.indexOf(to, start + from.length)
  return text.slice(start, end === -1 ? undefined : end)
}

describe("the workspace asks gallery", () => {
  it("is registered in the gallery script, with every page kind once per id", () => {
    expect(GALLERY_SCRIPT).toContain('import { workspaceAsksGallery } from "../src/ui/workspace-asks-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...workspaceAsksGallery(),")
    const entries = workspaceAsksGallery()
    expect(new Set(entries.map((e) => e.id)).size).toBe(entries.length)
    const kinds = new Set(entries.map((e) => e.page.boot.page))
    for (const kind of WORKSPACE_ASK_PAGE_KINDS) expect(kinds, kind).toContain(kind)
  })

  it("uses fixtures in the frozen protocol shapes", () => {
    expect(WorkspaceEnrolViewSchema.parse(PEOPLE_ENROL)).toEqual(PEOPLE_ENROL)
  })
})

describe("private metadata", () => {
  it("someone else's private credential appears on no ask page but the stop views", () => {
    const named: string[] = []
    for (const e of workspaceAsksGallery()) {
      if (["ws-approval-stop", "ws-approval-stop-hostile", "ws-policy-stop"].includes(e.id)) continue
      // Review together's private stop rows name the credential as the stop view does; nothing else on the page may.
      let text = renderDocument(e.page).value
      const stops = e.page.boot.page === "ws-review" ? (e.page.boot.rows as { approval: string; view: string }[]).filter((r) => r.view === "stop") : []
      for (const { approval } of stops) {
        const at = text.indexOf(`data-approval="${approval}"`), start = text.lastIndexOf("<li", at), end = text.indexOf("</li>", at) + "</li>".length
        if (text.slice(start, end).includes(GALLERY_FOREIGN_PRIVATE)) named.push(e.id)
        text = text.slice(0, start) + text.slice(end)
      }
      expect(text, e.id).not.toContain(GALLERY_FOREIGN_PRIVATE)
    }
    expect(named).toEqual(expect.arrayContaining(["ws-review", "ws-review-hostile-stop", "ws-review-deny-only"]))
  })

  it("the stop view names the machine, its owner and the credential's slug, and nothing about the request", () => {
    const stop = between(rendered("ws-approval-stop"), "<main", "</main>")
    expect(stop).toContain("kim-laptop")
    expect(stop).toContain("github-kim")
    expect(stop).toContain('data-action="deny"')
    for (const hidden of ["RUN", "/projects/", "K7Q-2MX", "Belongs to", "api.github.com", "data-action=\"approve\"", "binding", "digest", "Snapshot"]) expect(stop, hidden).not.toContain(hidden)
  })
})

describe("controls", () => {
  it("a guest never sees who else could decide", () => {
    // Even were the vault to send names, a guest's page leaves them out.
    const asGuest = workspaceApprovalPage(galleryShell(VIEWERS.guest), { viewer: VIEWERS.guest, view: galleryRunApproval(false, ["Tom"]), project: null, items: [] })
    expect(renderDocument(asGuest).value).not.toContain("Who can approve")
    expect(renderDocument(asGuest).value).not.toContain('data-region="deciders"')
    expect(rendered("ws-approval-decider")).toContain('data-region="deciders">Who can approve: Tom.')
  })

  it("the machine's owner under four-eyes reads the request, may deny, and is not offered Approve", () => {
    const page = rendered("ws-approval-owner-four-eyes")
    expect(page).toContain('data-region="four-eyes"')
    expect(page).toContain('data-region="cannot-approve"')
    expect(page).toContain('data-action="deny"')
    expect(page).not.toContain('data-action="approve"')
  })

  it("the decider's terms go no higher than what was asked", () => {
    const page = rendered("ws-approval-decider")
    const uses = between(page, 'data-input="uses"', "</select>")
    expect(uses.match(/<option /g)?.length).toBe(1)
    const ttl = between(page, 'data-input="ttl"', "</select>")
    expect(ttl).not.toContain('value="14400"')
    expect(ttl).not.toContain('value="86400"')
    // Each select starts on its first choice, the least the ask allows,
    // and the terms line says so.
    expect(ttl.match(/<option /g)?.length).toBeGreaterThan(1)
    expect(ttl).toMatch(/^data-input="ttl"><option value="60" selected>/)
    expect(uses).toMatch(/^data-input="uses"><option value="1" selected>/)
    expect(page).toContain('<span data-region="terms-text">Once, within 1 minute</span>')
    expect(page).toContain('data-region="run-credentials"')
    expect(page).toMatch(/<code>OPENAI_API_KEY<\/code> from <code>openai-prod<\/code> <span class="belongs" data-belongs="workspace">Belongs to: Whole workspace/)
    expect(page).toContain('<code>GITHUB_TOKEN</code> from <span class="muted">a credential outside your reach</span>')
    // An exact request starts at the least too; only a fill ask starts at what it asked.
    const request = rendered("ws-approval-request")
    expect(between(request, 'data-input="uses"', "</select>")).toMatch(/^data-input="uses"><option value="1" selected>/)
    expect(between(request, 'data-input="ttl"', "</select>")).toMatch(/^data-input="ttl"><option value="60" selected>/)
  })
})

// The terms a page's selects start on, as the browser reads them to sign.
function selected(page: string, input: "uses" | "ttl"): string {
  return between(page, `data-input="${input}"`, "</select>").match(/<option value="([^"]*)" selected>/)?.[1] ?? ""
}

describe("the approval card for typing into a web page", () => {
  it("names the field, whose it is and the sign-in page, says what one approval covers, and starts at what was asked", () => {
    const page = rendered("ws-approval-fill-signin")
    const decision = between(page, 'data-region="decision"', 'class="jump"')
    expect(decision).toContain('An agent on <b class="asker-name">mac-mini</b> wants to</p><h1>Type the password for alex@example.com into github.com</h1>')
    expect(decision).toContain("<dt>Page</dt><dd>https://github.com</dd>")
    expect(decision).toContain(`<dt>Allows</dt><dd>This also lets it type the one-time code on https://github.com, up to ${FILL_GRANTS.signIn.uses} fields in all, for the next 10 minutes. The username needs no approval.</dd>`)
    expect(decision).toContain(`Task: <b>${GALLERY_TASK.label}</b>`)
    expect(page).not.toContain('data-region="warnings"')
    expect(page).not.toContain('data-action="approve-rule"')
    expect(page).toContain("Approve with passkey")
    expect(page).toContain('<span data-region="terms-text">6 times, within 10 minutes</span>')
    // What the passkey signs: the defaults are the ask's own terms, and Once is one use.
    const view = galleryFillSignInApproval()
    if (view.view !== "detail") throw new Error("Expected a detail view")
    const asked = view.approval.constraints
    const boot = { approval: view.approval.approval, digest: view.approval.digest, subject: { item: view.approval.item.slug, method: "FILL", url: view.approval.request.url, contentType: null, contentEncoding: null, headersSha256: view.approval.request.headersSha256, bodySha256: view.approval.request.bodySha256, constraints: asked } }
    const sign = (uses: string, ttl: string) => {
      const chosen = chosenConstraints(asked, uses, ttl)
      if (!chosen.ok) throw new Error(chosen.problems.join(" "))
      return approvalDecision(boot, "approve", chosen.value).expected
    }
    expect(sign(selected(page, "uses"), selected(page, "ttl"))).toMatchObject({ type: "approval.decide", decision: "approve", constraints: { uses: 6, ttlSeconds: 600 } })
    expect(sign("1", selected(page, "ttl"))).toMatchObject({ constraints: { uses: 1, ttlSeconds: 600 } })
  })

  it("warns that typing into another service's page puts the credential there, asks every time, and offers no remember", () => {
    const page = rendered("ws-approval-fill-type-into")
    expect(between(page, 'data-region="warnings"', "</div>")).toContain("This puts the credential into another service. Every time asks you first.")
    expect(page).toContain('class="card decision warned"')
    expect(page).toContain("<h1>Type the key of cloudflare-api-token into dash.cloudflare.com</h1>")
    expect(page).toContain("<dt>Allows</dt><dd>Typed once, within the next 10 minutes.</dd>")
    expect(page).not.toContain('data-action="approve-rule"')
    expect(page).not.toContain('data-region="rule-panel"')
    expect([selected(page, "uses"), selected(page, "ttl")]).toEqual(["1", "600"])
  })
})

describe("settled decisions and the exact request", () => {
  it("a guest never sees who decided a settled ask, approved or denied; insiders do; self reads as you", () => {
    for (const status of ["approved", "denied"] as const) {
      const view = galleryRunApproval(false, [])
      if (view.view !== "detail") throw new Error("detail")
      view.approval.status = status
      view.approval.decidedBy = { name: "SECRET-DECIDER-NAME", self: false }
      const guest = renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.guest), { viewer: VIEWERS.guest, view, project: null, items: [] })).value
      expect(guest, status).not.toContain("SECRET-DECIDER-NAME")
      expect(guest, status).toContain('data-region="settled"')
      expect(renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [] })).value).toContain("by SECRET-DECIDER-NAME")
      view.approval.decidedBy = { name: "SECRET-DECIDER-NAME", self: true }
      expect(renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.guest), { viewer: VIEWERS.guest, view, project: null, items: [] })).value).toContain("by you")
    }
  })

  it("a settled approval says what its status means for the agent, for every status, and an open one does not", () => {
    for (const status of ["approved", "denied", "expired", "used", "ended", "revoked", "stale"] as const) {
      const view = galleryRunApproval(true, [])
      if (view.view !== "detail") throw new Error("detail")
      view.approval.status = status
      const page = renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [] })).value
      expect(page, status).toContain(`<p class="small muted" data-region="settled-words">${escapeHtml(SETTLED_APPROVAL_WORDS[status])}</p>`)
    }
    expect(rendered("ws-approval-request")).not.toContain('data-region="settled-words"')
  })

  it("an account cooling off is told before it fills in or ticks anything, and only where it would be refused", () => {
    const held = rendered("ws-intake-held")
    expect(held).toContain('data-region="account-held"')
    expect(held).toContain(escapeHtml(ACCOUNT_HELD_WORDS.intake))
    expect(held.indexOf('data-region="account-held"')).toBeLessThan(held.indexOf('data-form="intake"'))
    expect(rendered("ws-intake")).not.toContain('data-region="account-held"')
    const view = galleryRunApproval(true, [])
    const approving = renderDocument(workspaceApprovalPage({ ...galleryShell(VIEWERS.owner), accountHeld: true }, { viewer: VIEWERS.owner, view, project: null, items: [] })).value
    expect(approving).toContain(escapeHtml(ACCOUNT_HELD_WORDS.approval))
    if (view.view !== "detail") throw new Error("detail")
    view.approval.status = "approved"
    expect(renderDocument(workspaceApprovalPage({ ...galleryShell(VIEWERS.owner), accountHeld: true }, { viewer: VIEWERS.owner, view, project: null, items: [] })).value).not.toContain('data-region="account-held"')
  })

  it("the readable view shows every signed header, the content type, the warning and the email; the stop view none", () => {
    const page = between(rendered("ws-approval-request"), '<div id="notice"', "</main>")
    for (const shown of ["X-Goog-Request-Reason", "quarterly-report", "fwdHeadersDigestxxxxxxxxxxxxxxxxxxxxxxxxxxx", "application/json", "bodyDigestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "Part 2 of this message could not be read", "priya@acme.example", "Quarterly numbers", "Hi Priya"]) expect(page, shown).toContain(shown)
    const stop = rendered("ws-approval-stop")
    for (const hidden of ["X-Goog-Request-Reason", "could not be read", "Headers sent"]) expect(stop, hidden).not.toContain(hidden)
    expect(galleryEmailApproval().view).toBe("detail")
  })
})

describe("links", () => {
  it("the request pages link only under the workspace", () => {
    for (const id of ["ws-intake", "ws-connect"]) {
      const page = rendered(id)
      expect(page, id).not.toMatch(/href="\/(items|i|c)\//)
      expect(page, id).not.toContain('href="/connect"')
      expect(page, id).not.toContain('href="/#needs-you"')
      expect(page, id).toContain('data-region="home-choice"')
    }
    expect(workspaceLinks(html`<a href="/items/x">x</a><a href="/connect">c</a><a href="/#needs-you">n</a>`, "northwind").value).toBe('<a href="/w/northwind/items/x">x</a><a href="/w/northwind/credentials">c</a><a href="/needs-you">n</a>')
  })
})

describe("enrolment", () => {
  it("owning acceptance and admission have different words; accept warns", () => {
    const accept = rendered("enrol-accept")
    expect(accept).toContain("Accept as my own machine")
    expect(accept).toContain("If someone sent you this link, do not accept it: they accept their own machine and you admit it.")
    expect(accept).not.toContain('data-action="enrol-admit"')
    const admit = rendered("enrol-admit")
    expect(admit).toContain("Admit Gina (contractor)&#39;s machine")
    expect(admit).toContain("Admission does not accept this machine as your own.")
    expect(admit).not.toContain('data-action="enrol-accept"')
  })

  it("shows start time, place and client beside the acceptor's place, the private tick on for a member's own machine and off for a guest's", () => {
    const body = rendered("enrol-accept")
    expect(body).toContain('data-region="enrol-start"')
    expect(body).toContain('data-region="enrol-acceptor"')
    expect(body).toMatch(/data-input="enrol-private" checked>/)
    expect(body).toContain("(on by default for your own machine)")
    expect(body).not.toContain("off by default")
    const guest = rendered("enrol-accept-guest")
    expect(guest).toMatch(/data-input="enrol-private">/)
    expect(guest).toContain("(off by default for a guest&#39;s machine)")
    expect(guest).not.toContain("on by default")
  })

  it("says what the private tick left off means for the agent, and where to change it later", () => {
    const body = rendered("enrol-accept")
    expect(body).toContain('data-region="enrol-private-hint"')
    expect(body).toContain(escapeHtml(PRIVATE_OFF_WORDS))
    expect(rendered("enrol-scoped")).not.toContain('data-region="enrol-private-hint"')
  })

  it("tells a guest, who cannot widen their own machine, who turns private credentials on later", () => {
    const guest = rendered("enrol-accept-guest")
    expect(guest).toContain(escapeHtml(GUEST_PRIVATE_OFF_WORDS))
    expect(guest).not.toContain(escapeHtml(PRIVATE_OFF_WORDS))
    expect(rendered("enrol-accept")).not.toContain(escapeHtml(GUEST_PRIVATE_OFF_WORDS))
  })

  it("tells only a guest that their accepted machine then waits for admission", () => {
    const member = rendered("enrol-accept")
    expect(member).not.toContain("a guest&#39;s machine")
    expect(member).not.toContain("waits for an owner, an admin or a manager")
    expect(member).toContain("<code>mehen wait</code> then finishes by itself")
    const guest = rendered("enrol-accept-guest")
    expect(guest).toContain("it then waits for an owner, an admin or a manager of its shared project to admit it")
  })

  it("an enrolled machine's link says it is enrolled and what the agent does next", () => {
    const enrolled = (view: Partial<typeof PEOPLE_ENROL>) => renderDocument(enrolmentPage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_ENROL, state: "active", lease: "terminal", owner: { kind: "member", member: "mem_tom01", name: "Tom" }, actions: [], ...view }, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: null, now: 0 })).value
    const body = enrolled({ startedByAgent: true })
    expect(body).toContain("<h1>Enrolled</h1>")
    expect(body).not.toContain("Already enrolled")
    expect(body).toContain("restart the agent once so its Mehen tools load")
    expect(body).not.toContain("The terminal that asked carries on by itself.")
    // No agent is known to have asked (mehen up in a terminal): no agent to restart.
    const terminal = enrolled({})
    expect(terminal).toContain("The terminal that asked carries on by itself.")
    expect(terminal).not.toContain("restart the agent")
  })

  it("names where the acceptor is: a place, this machine on a local vault, or nowhere it can place", () => {
    const acceptor = (body: string) => /data-region="enrol-acceptor">([^<]*)</.exec(body)?.[1]
    expect(acceptor(rendered("enrol-accept"))).toBe("in Amsterdam, NL")
    expect(acceptor(rendered("enrol-accept-local"))).toBe("on this machine")
    const nowhere = renderDocument(enrolmentPage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_ENROL, acceptorPlace: null }, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: null, now: 0 })).value
    expect(acceptor(nowhere)).toBe("somewhere the vault cannot place")
  })

  it("carries three groups and the hidden one's check, never the hidden group, the thumbprint or the key", () => {
    const body = rendered("enrol-accept")
    for (const shown of PEOPLE_ENROL.fingerprint.groups) expect(body).toContain(shown)
    expect(body).toContain('data-region="fingerprint-hidden"')
    expect(body).toContain('data-input="fingerprint-group"')
    expect(body).not.toMatch(/thumbprint|"jwk"|Q3x9Lw2Zk8/)
    expect(body).toContain("&quot;check&quot;:&quot;check_hash&quot;")
  })

  it("a waiting guest is told who admits by role and gets the link, never a list of people", () => {
    const body = rendered("enrol-guest-waiting")
    expect(body).toContain("Send this link to the person who invited you or to a manager of the shared project")
    expect(body).toContain('<div class="copybox"><code>https://app.mehen.dev/w/northwind/e/K7QX-29PD</code>')
    expect(body).not.toMatch(/data-action="enrol-(accept|admit)"|Tom Barker|Noor/)
  })

  it("names what a team admission delegates before the passkey, and withholds signing when it is unknown", () => {
    const team = rendered("enrol-team-admit")
    expect(team).toContain("<b>This also lets it use:</b>")
    expect(team).toContain("<code>openai-shared</code>")
    expect(team.indexOf('data-region="admit-delegation"')).toBeLessThan(team.indexOf('data-action="enrol-admit"'))
    const unknown = rendered("enrol-team-unknown")
    expect(unknown).toContain('data-region="delegation-unknown"')
    expect(unknown).not.toContain('data-action="enrol-admit"')
  })
})

// Where the buttons live, what is folded, and the
// enrolment page's two forms and its lapsed and closed cards.
describe("the decision layout", () => {
  it("puts the buttons in the fixed bar outside the card's form, each tied to it by form=decide", () => {
    for (const id of ["ws-approval-decider", "ws-approval-request", "ws-approval-deceptive", "ws-intake", "ws-connect", "enrol-accept", "enrol-admit"]) {
      const page = rendered(id)
      expect(page, id).toContain('id="decide"')
      const card = between(page, 'id="decide"', "</form>")
      expect(card, id).not.toMatch(/<button[^>]*data-action="(approve|deny|submit-intake|start-connect|enrol-accept|enrol-admit|enrol-reject)"/)
      const bar = between(page, 'data-region="bar"', "</main>")
      for (const button of bar.match(/<button[^>]*data-action="(approve|deny|submit-intake|start-connect|enrol-accept|enrol-admit|enrol-reject|cancel-request)"[^>]*>/g) ?? []) expect(button, id).toContain('form="decide"')
      expect(bar.match(/<button[^>]*data-action=/g)?.length ?? 0, id).toBeGreaterThan(0)
      expect(entry(id).page.bar, id).toBe(true)
    }
    const approval = rendered("ws-approval-decider")
    expect(approval).toContain('<form class="stack" id="decide" data-form="decide" novalidate>')
    expect(between(approval, 'data-region="bar"', "</main>")).toMatch(/data-input="uses"/)
    expect(approval).toContain('<select form="decide" data-input="uses">')
    expect(approval).toContain('<select form="decide" data-input="ttl">')
  })

  it("keeps the declining action first in the document and the accepting one disabled until its checks pass", () => {
    for (const [id, decline, accept] of [["ws-approval-decider", "deny", "approve"], ["enrol-accept", "enrol-reject", "enrol-accept"], ["enrol-admit", "enrol-reject", "enrol-admit"], ["ws-intake-deceptive", "cancel-request", "submit-intake"]] as const) {
      const bar = between(rendered(id), 'data-region="bar"', "</main>")
      expect(bar.indexOf(`data-action="${decline}"`), id).toBeLessThan(bar.indexOf(`data-action="${accept}"`))
      expect(between(bar, `data-action="${accept}"`, ">"), id).toContain("disabled")
      expect(between(bar, `data-action="${decline}"`, ">"), id).not.toContain("disabled")
    }
    expect(between(rendered("ws-approval-decider"), 'data-region="bar-caption"', "</span>")).toContain("Tick the code to continue.")
  })

  it("shows the whole request and email unfolded and folds only the digests, the body's own hash beside it", () => {
    const page = between(rendered("ws-approval-request"), "<main", "</main>")
    const fold = between(page, 'data-region="technical"', "</details>")
    for (const digest of ["d1Gest0fSubjectAndBindingxxxxxxxxxxxxxxxxxx", "s9Lq2nR8vW3xY6zA1bC4dE7fG0hJ5kM2pQ8tU1wX4y0", "p2Mw5rT8yB1eH4kN7qS0vX3zA6cF9iL2oR5uY8bD1g0", "bodyDigestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "fwdHeadersDigestxxxxxxxxxxxxxxxxxxxxxxxxxxx", 'data-region="digest-match"', 'data-region="digest-mismatch"', 'data-region="binding"']) expect(fold, digest).toContain(digest)
    // The boot carries the digests for the browser's recompute; the page
    // shows them only in the fold, but for the body's own SHA-256, which
    // stays beside the body the vault read.
    const outside = page.replace(fold, "").replace(/data-boot="[^"]*"/, "")
    for (const digest of ["d1Gest0fSubjectAndBinding", "fwdHeadersDigestxxx", "s9Lq2nR8vW3x"]) expect(outside, digest).not.toContain(digest)
    expect(between(outside, 'data-region="exact-request"', "</section>")).toContain("<dt>Body SHA-256</dt><dd><code class=\"hash\">bodyDigestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</code></dd>")
    const details = page.match(/<details[\s\S]*?<\/details>/g) ?? []
    for (const evidence of ["X-Goog-Request-Reason", "quarterly-report", "Hi Priya", "priya@acme.example", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", "application/json", "{&quot;raw&quot;:&quot;...&quot;}"]) {
      expect(outside, evidence).toContain(evidence)
      for (const d of details) expect(d, evidence).not.toContain(evidence)
    }
    expect(page.indexOf('data-region="decision"')).toBeLessThan(page.indexOf('id="truth"'))
    expect(page.indexOf('id="truth"')).toBeLessThan(page.indexOf('data-region="exact-request"'))
  })

  it("says the body is the vault's reading of it, not the bytes sent", () => {
    const page = rendered("ws-approval-request")
    expect(page).toContain("<h3>The request body, as the vault reads it</h3>")
    expect(page).toContain('data-region="body-note">Valid JSON is formatted and form fields decoded for reading; a body that is not UTF-8 text is shown only as its size and cannot be inspected here. The passkey signs the body as it was sent, by the SHA-256 below. Do not approve a request whose contents you cannot verify.</p>')
    expect(page).toContain("What the passkey signs, as the vault reads it.")
    expect(page).not.toContain("Everything the passkey signs.")
  })

  it("a warned page leads with the warning card and flips the emphasis; an unwarned one does not", () => {
    const warned = between(rendered("ws-approval-deceptive"), "<main", "</main>")
    expect(warned.indexOf('data-region="warnings"')).toBeLessThan(warned.indexOf('data-region="decision"'))
    expect(warned).toContain('role="alert" data-region="warnings"')
    expect(warned).toContain('class="card decision warned"')
    expect(warned).toMatch(/class="btn danger" data-action="deny"/)
    expect(warned).toMatch(/class="btn quiet" data-action="approve" disabled/)
    expect(warned).toContain("[RLO U+202E]")
    expect(warned).not.toContain("\u202E")
    const plain = rendered("ws-approval-decider")
    expect(plain).not.toContain('data-region="warnings"')
    expect(plain).toMatch(/class="btn secondary" data-action="deny"/)
    expect(plain).toMatch(/class="btn primary" data-action="approve" disabled/)
    const intake = rendered("ws-intake")
    expect(intake).not.toContain('data-action="cancel-request"')
    expect(rendered("ws-intake-deceptive")).toMatch(/class="btn danger" data-action="cancel-request" data-kind="intake" data-id="int_9vq3mz7kd2"/)
  })

  it("names Stopping in What happens next only where the bar has Stop this request", () => {
    for (const id of ["ws-intake", "ws-connect"]) {
      const page = rendered(id)
      expect(page, id).not.toContain("Stopping closes the link")
      expect(page, id).toContain("Not expecting this? Close the page")
    }
    for (const id of ["ws-intake-deceptive", "ws-connect-deceptive"]) {
      const page = rendered(id)
      expect(page, id).toContain('data-action="cancel-request"')
      expect(page, id).toContain("Stopping closes the link")
    }
  })

  it("puts Belongs to after what is being asked, folded with the current choice", () => {
    const intake = rendered("ws-intake")
    expect(intake.indexOf('data-region="intake-head"')).toBeLessThan(intake.indexOf('data-region="home-choice"'))
    expect(between(intake, 'data-region="home-choice"', "</details>")).toContain('Belongs to: <span data-region="home-current">This project (platform)</span>. Change')
    const connect = rendered("ws-connect")
    expect(connect.indexOf('data-region="connect-scopes"')).toBeLessThan(connect.indexOf('data-region="home-choice"'))
  })

  it("the stop view has one action, Stop, in the bar, and the sentence", () => {
    const stop = between(rendered("ws-approval-stop"), "<main", "</main>")
    expect(stop).toContain("A machine is waiting")
    expect(stop).toContain("You may stop this request. Your rights do not include its full details.")
    expect(between(stop, 'data-region="bar"', "</div>\n  </div>")).toMatch(/<button type="button" form="decide" class="btn secondary" data-action="deny"><span>Stop<\/span><\/button>/)
    expect(stop.match(/data-action=/g)?.length).toBe(1)
  })
})

describe("the policy proposal stop page", () => {
  it("its stop view carries nothing about the proposal", () => {
    const stop = between(rendered("ws-policy-stop"), "<main", "</main>")
    expect(entry("ws-policy-stop").page.boot).toEqual({ page: "ws-policy", proposal: "pol_8kq2mw4zx1", view: "stop" })
    for (const hidden of ["api.github.com", "relaxed", "digest", "Triage"]) expect(stop, hidden).not.toContain(hidden)
    expect(stop).toContain("github-kim")
  })
})

describe("the enrolment page's forms and cards", () => {
  it("the code and id forms hide the same group with the same check, and the id form carries no code", () => {
    const code = entry("enrol-accept").page
    const byId = entry("enrol-by-id").page
    expect(byId.boot).toMatchObject({ page: "workspace-enrol", ref: "enr_new01", hidden: code.boot.hidden, check: code.boot.check })
    expect(code.boot).toMatchObject({ ref: "K7QX-29PD" })
    const body = between(rendered("enrol-by-id"), "<html", "</html>")
    expect(body).not.toContain("K7QX-29PD")
    expect(body).not.toContain("K7QX29PD")
    for (const shown of PEOPLE_ENROL.fingerprint.groups) expect(body).toContain(shown)
    expect(body).toContain('data-input="fingerprint-group"')
  })

  it("a lapsed link shows its three groups, how to bring it back and Reject, and no accept", () => {
    const page = rendered("enrol-lapsed")
    expect(entry("enrol-lapsed").page.boot).toEqual({ page: "enrol-closed" })
    for (const shown of PEOPLE_ENROL.fingerprint.groups) expect(page).toContain(shown)
    expect(page).toContain("This link has lapsed. Ask the agent to run <code>mehen wait enr_new01</code> or <code>mehen enrol --workspace northwind</code> again; the same link comes back to life until")
    expect(page).toContain('data-action="enrol-reject" data-ref="enr_new01"')
    expect(page).not.toMatch(/data-action="enrol-(accept|admit)"|data-input="fingerprint-group"/)
    const viewer = renderDocument(enrolmentPage(peopleShell("member", { member: "mem_tom01" }), { ...PEOPLE_ENROL, lease: "lapsed", actions: [] }, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: null, now: 0 })).value
    expect(viewer).not.toContain('data-action="enrol-reject"')
  })

  it("a replaced link offers the newer one only when the vault names it", () => {
    const page = rendered("enrol-superseded")
    expect(page).toContain("This link ran out. The same machine asked again; its new link is valid until")
    expect(page).toContain('href="/w/northwind/e/enr_new02" data-region="enrol-successor"')
    const alone = renderDocument(enrolmentPage(peopleShell("owner"), { ...PEOPLE_ENROL, state: "expired", lease: "terminal", actions: [], reason: "superseded", successor: null }, { viewer: { member: "mem_alex01", role: "owner", blocked: false }, projects: null, now: 0 })).value
    expect(alone).toContain("This link ran out")
    expect(alone).not.toContain("enrol-successor")
    expect(alone).not.toContain("asked again")
  })
})

describe("asks a workload made", () => {
  it("keep the machine line and add the task, quieter, in the machine's words", () => {
    for (const id of ["ws-approval-workload", "ws-intake-workload", "ws-connect-workload"]) {
      const body = rendered(id)
      expect(body, id).toContain('<p class="small muted" data-region="ask-task">Task: <b>globex:grant-7f3k</b>, as the machine named it</p>')
      expect(body, id).toContain("mac-mini")
    }
    expect(rendered("ws-approval-workload")).toContain("<dt>Task</dt><dd><code>globex:grant-7f3k</code>")
    expect(rendered("ws-approval-request")).not.toContain('data-region="ask-task"')
  })

  it("an enrolment that asked for less than usual says so, hides the private tick and names workloads only", () => {
    const body = rendered("enrol-scoped")
    expect(body).toContain("This machine asked for less than usual")
    expect(body).toContain("Uses only these credentials: those tagged ci")
    expect(body).toContain("Only these ways of using credentials: through the vault only and stand-in values")
    expect(body).toContain("Never uses your private credentials")
    expect(body).toContain("Acts only through short-lived workloads")
    expect(body).not.toContain('data-input="enrol-private"')
    expect(rendered("enrol-accept")).toContain('data-input="enrol-private"')
    expect(rendered("enrol-accept")).not.toContain("asked for less than usual")
  })
})

describe("lease-only credentials", () => {
  const LEASE_ONLY_WORDS = "No host: only delivered into a process with <code>mehen run</code>."

  it("an intake with no host reads the lease-only words, never the reserved host, and asks no one to accept a destination", () => {
    const page = entry("ws-intake-lease-only").page.body.value
    expect(page).toContain(LEASE_ONLY_WORDS)
    expect(page).not.toContain(LEASE_ONLY_HOST)
    expect(page).not.toContain('data-input="accept-destination"')
    expect(page).not.toContain('data-input="allow-reads"')
    expect(page).not.toContain("Proposed by the agent, not verified")
  })

  it("an adoption row with no host reads what its ceiling allows, never the reserved host, and starts ticked", () => {
    const page = entry("ws-adoption-lease-only").page.body.value
    expect(page.split(LEASE_ONLY_WORDS)).toHaveLength(3)
    expect(page.split("No host: stored only; a human can allow <code>mehen run</code> by setting its ceiling to lease.")).toHaveLength(2)
    expect(page.split('data-region="lease-only">No host: stored only.</p>')).toHaveLength(2)
    expect(page).not.toContain(LEASE_ONLY_HOST)
    expect(page).not.toContain('data-region="custom-destination"')
    expect(page.match(/data-input="include" checked/g)).toHaveLength(4)
  })
})

// Approve and allow this from now on, only when the vault offers a
// standing rule (rememberOptions.rule); without an offer the page is the
// one it was before rules.
describe("allow this from now on", () => {
  const owner = VIEWERS.owner
  const render = (view: ReturnType<typeof galleryRuleApproval>, viewer = owner) => renderDocument(workspaceApprovalPage(galleryShell(viewer), { viewer, view, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") })).value
  const withRule = (rule: PolicyRuleOffer | undefined, route = false) => {
    const view = galleryRuleApproval()
    if (view.view !== "detail") throw new Error("detail")
    const { rememberOptions: _offered, ...approval } = view.approval
    return { ...view, approval: rule === undefined ? (route ? { ...approval, rememberOptions: { route: null } } : approval) : { ...approval, rememberOptions: { route: null, rule } } }
  }
  const refusedOffer = (refused: PolicyRuleRefusal): PolicyRuleOffer => ({ terms: null, termsDigest: null, pathChoices: [], refused, coSign: false })

  it("with no offer the page is byte for byte the page without rules, whatever else rememberOptions holds", () => {
    const none = render(withRule(undefined))
    expect(render(withRule(undefined, true))).toBe(none)
    expect(none).toContain("<span>Approve with passkey</span>")
    for (const absent of ["approve-rule", "rule-panel", "rule-refused", "Approve once", "from now on", "&quot;rule&quot;"]) expect(none, absent).not.toContain(absent)
    expect(render(withRule(GALLERY_RULE_OFFER))).not.toBe(none)
    // An offer beside an approval this viewer may not give changes nothing.
    const cannot = (rule: PolicyRuleOffer | undefined) => {
      const view = withRule(rule)
      return render({ ...view, approval: { ...view.approval, eligibility: { ...view.approval.eligibility, canApprove: false, reason: "Not an eligible approver" } } })
    }
    expect(cannot(GALLERY_RULE_OFFER)).toBe(cannot(undefined))
  })

  // Main's own bytes before rules reached the pages (golden/, rendered by
  // the code before standing rules): the boot and the body, card, panel and bar.
  it("with no offer, an approval and a proposal's stop view render exactly as main did", () => {
    const golden = (name: string) => GOLDEN[`./golden/${name}.html`] ?? ""
    const bytes = (page: PageInput) => `${JSON.stringify(page.boot)}\n${page.body.value}\n`
    const view = withRule(undefined)
    expect(bytes(workspaceApprovalPage(galleryShell(owner), { viewer: owner, view, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") }))).toBe(golden("ws-approval-no-offer"))
    for (const id of ["ws-approval-request", "ws-policy-stop"]) expect(bytes(entry(id).page), id).toBe(golden(id))
  })

  it("offers Approve once beside Approve and allow this from now on, both off until their checks pass", () => {
    const page = rendered("ws-approval-rule")
    const bar = between(page, 'data-region="bar"', "</main>")
    expect(bar).toMatch(/class="btn primary" data-action="approve" disabled>.*<span>Approve once<\/span>/)
    expect(bar).toMatch(/<button type="button" form="decide" class="btn secondary" data-action="approve-rule" disabled>.*<span>Approve and allow this from now on<\/span>/)
    expect(bar.indexOf('data-action="deny"')).toBeLessThan(bar.indexOf('data-action="approve-rule"'))
    expect(entry("ws-approval-rule").page.boot.rule).toEqual({ terms: GALLERY_RULE_TERMS, termsDigest: GALLERY_RULE_OFFER.termsDigest, pathChoices: GALLERY_RULE_OFFER.pathChoices, coSign: false })
  })

  it("the panel says what it allows, for whom, for how long, what still asks and what ends it sooner", () => {
    const panel = between(rendered("ws-approval-rule"), 'data-region="rule-panel"', "</section>")
    expect(panel).toContain("<h2>From now on, without asking you</h2>")
    expect(panel).toContain("<dt>Credential</dt><dd><code>github-alex</code>, acting as alex-northwind</dd>")
    expect(panel).toContain('<span class="method">POST</span> <code>api.github.com/repos/northwind/platform/issues/12/comments</code>')
    expect(panel).not.toContain('data-region="rule-graphql"')
    expect(panel).toContain('data-region="rule-who">This machine, mac-mini</dd>')
    const paths = panel.match(/<input type="radio" form="decide" name="rule-path" data-input="rule-path" value="[^"]+"( checked)?>/g) ?? []
    expect(paths).toEqual(['<input type="radio" form="decide" name="rule-path" data-input="rule-path" value="/repos/northwind/platform/issues/12/comments" checked>', '<input type="radio" form="decide" name="rule-path" data-input="rule-path" value="/repos/northwind/platform/issues/*/comments">'])
    const ttls = panel.match(/data-input="rule-ttl" value="\d+"( checked)?><span>[^<]+/g) ?? []
    expect(ttls).toEqual(['data-input="rule-ttl" value="86400"><span>1 day', 'data-input="rule-ttl" value="604800" checked><span>7 days', 'data-input="rule-ttl" value="2592000"><span>30 days'])
    expect(panel).toContain("<dt>Still asks</dt><dd>Anything else on this credential, and any request that sends, pays, shares or deletes</dd>")
    expect(panel).toContain("<dt>Ends sooner</dt><dd>if access changes or this credential is edited</dd>")
    expect(panel).toContain('<p class="small refused" id="rule-mismatch" aria-live="polite" data-region="rule-mismatch" hidden>')
    expect(panel).not.toContain('data-region="rule-cosign"')
    expect(panel).not.toContain('data-region="rule-context"')
  })

  it("names the GraphQL root fields, the task that asked and the context the approval names", () => {
    const panel = between(rendered("ws-approval-rule-cosign"), 'data-region="rule-panel"', "</section>")
    expect(panel).toContain('<span data-region="rule-graphql">GraphQL mutation <code>commentCreate</code> only</span>')
    expect(panel).toContain('data-region="rule-who">Only task globex:grant-7f3k on kim-laptop</dd>')
    const view = withRule(GALLERY_RULE_OFFER)
    const inProject = render({ ...view, approval: { ...view.approval, details: [...view.approval.details, { label: "Project", value: "platform" }, { label: "Environment", value: "dev" }] } })
    expect(inProject).toContain('<dt>Context</dt><dd data-region="rule-context">Project platform and environment dev</dd>')
  })

  it("names Who from the key the terms name, by the request's names only when they are that key's", () => {
    const view = withRule(GALLERY_RULE_OFFER)
    const who = (asker: PolicyRuleTerms["asker"], workload?: { id: string; label: string }) => between(render({ ...view, approval: { ...view.approval, requestedBy: { ...view.approval.requestedBy, ...(workload ? { workload } : {}) }, rememberOptions: { route: null, rule: { ...GALLERY_RULE_OFFER, terms: { ...GALLERY_RULE_TERMS, asker } } as PolicyRuleOffer } } }), 'data-region="rule-who">', "</dd>")
    expect(who({ device: "dev_macmini1", workload: null })).toBe('data-region="rule-who">This machine, mac-mini')
    expect(who({ device: "dev_otherbox01", workload: null })).toBe('data-region="rule-who">This machine, dev_otherbox01')
    expect(who({ device: "dev_macmini1", workload: "wl_task8kq2mw4z" }, { id: "wl_task8kq2mw4z", label: "globex:grant-7f3k" })).toBe('data-region="rule-who">Only task globex:grant-7f3k on mac-mini')
    expect(who({ device: "dev_macmini1", workload: "wl_othertask01" }, { id: "wl_task8kq2mw4z", label: "globex:grant-7f3k" })).toBe('data-region="rule-who">Only task wl_othertask01 on mac-mini')
  })

  it("co-sign: the second button asks a manager, and one line says a manager of the home must co-sign first", () => {
    const page = rendered("ws-approval-rule-cosign")
    expect(between(page, 'data-region="bar"', "</main>")).toMatch(/data-action="approve-rule" disabled>.*<span>Approve once and ask a manager to allow it from now on<\/span>/)
    expect(page).toContain('<p class="small" data-region="rule-cosign">A manager of this credential&#39;s home must co-sign before it takes effect.</p>')
    expect(entry("ws-approval-rule-cosign").page.boot.rule).toMatchObject({ coSign: true })
  })

  it("every refusal code has its own words, and a refused offer shows one muted line and only Approve once", () => {
    expect(Object.keys(RULE_REFUSAL_WORDS).sort()).toEqual([...POLICY_RULE_REFUSALS].sort())
    expect(new Set(Object.values(RULE_REFUSAL_WORDS)).size).toBe(POLICY_RULE_REFUSALS.length)
    for (const code of POLICY_RULE_REFUSALS) {
      const words = RULE_REFUSAL_WORDS[code]
      expect(words, code).toMatch(/^[A-Z].*\.$/)
      expect(words, code).not.toMatch(/[\u2013\u2014\u2015\u2E3A]/)
      const page = render(withRule(refusedOffer(code)))
      expect(page, code).toContain(`<p class="small muted" data-region="rule-refused">${escapeHtml(words)}</p>`)
      expect(page, code).toContain("<span>Approve once</span>")
      for (const absent of ["approve-rule", "rule-panel", "&quot;rule&quot;"]) expect(page, `${code} ${absent}`).not.toContain(absent)
    }
    expect(rendered("ws-approval-rule-refused")).toContain("This request sends mail or a message, so it asks every time.")
  })

  it("the gallery's offers carry the digest of their own terms", async () => {
    for (const offer of [GALLERY_RULE_OFFER, GALLERY_COSIGN_OFFER]) {
      if (offer.refused !== null) throw new Error("offered")
      expect(await policyRuleTermsDigest(offer.terms)).toBe(offer.termsDigest)
      expect(offer.pathChoices).toEqual(policyRulePathChoices(offer.terms.anchorPath))
    }
  })
})

// The task grant beside the approval (rememberOptions.area): the third
// button, the panel and its choices, the co-sign variant and the refusals.
describe("let this agent carry on", () => {
  const render = (view: ReturnType<typeof galleryAreaApproval>, viewer = VIEWERS.owner) => renderDocument(workspaceApprovalPage(galleryShell(viewer), { viewer, view, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") })).value
  const withArea = (area: PolicyAreaOffer) => {
    const view = galleryAreaApproval()
    if (view.view !== "detail") throw new Error("detail")
    return { ...view, approval: { ...view.approval, rememberOptions: { route: null, rule: GALLERY_D1_RULE_OFFER, area } } }
  }

  it("offers the third button beside Approve once and allow from now on, off until its checks pass, naming the area and 1 hour", () => {
    const bar = between(rendered("ws-approval-area"), 'data-region="bar"', "</main>")
    expect(bar).toMatch(/class="btn primary" data-action="approve" disabled>.*<span>Approve once<\/span>/)
    expect(bar).toMatch(/data-action="approve-rule" disabled>.*<span>Approve and allow this from now on<\/span>/)
    expect(bar).toMatch(/<button type="button" form="decide" class="btn secondary" data-action="approve-area" disabled>.*<span>Approve, and let this agent carry on with D1 databases for 1 hour<\/span>/)
    expect(bar.indexOf('data-action="approve-rule"')).toBeLessThan(bar.indexOf('data-action="approve-area"'))
    expect(entry("ws-approval-area").page.boot.area).toEqual({ terms: GALLERY_AREA_TERMS, termsDigest: GALLERY_AREA_OFFER.termsDigest, areas: (GALLERY_AREA_OFFER as { areas: unknown }).areas, coSign: false })
  })

  it("the panel ticks the request's own area among the others with their words, 1 hour and 50 requests chosen, and says what still asks", () => {
    const panel = between(rendered("ws-approval-area"), 'data-region="area-panel"', "</section>")
    expect(panel).toContain("<h2>Carry on without asking you</h2>")
    expect(panel).toContain('data-region="area-who">This machine, mac-mini</dd>')
    const ticks = panel.match(/data-input="area-area" value="[^"]+" data-name="[^"]+"( checked)?/g) ?? []
    expect(ticks).toHaveLength(11)
    expect(ticks.filter((t) => t.endsWith(" checked"))).toEqual(['data-input="area-area" value="d1" data-name="D1 databases" checked'])
    expect(panel).toContain("<b>DNS records</b> <span class=\"muted small\">Adds A, AAAA and CNAME records</span>")
    expect(panel.match(/data-input="area-ttl" value="\d+"( checked)?><span>[^<]+/g)).toEqual(['data-input="area-ttl" value="900"><span>15 minutes', 'data-input="area-ttl" value="3600" checked><span>1 hour', 'data-input="area-ttl" value="14400"><span>4 hours'])
    expect(panel.match(/data-input="area-uses" value="\d+"( checked)?><span>[^<]+/g)).toEqual(['data-input="area-uses" value="25"><span>25 requests', 'data-input="area-uses" value="50" checked><span>50 requests', 'data-input="area-uses" value="100"><span>100 requests', 'data-input="area-uses" value="200"><span>200 requests'])
    expect(panel).toContain('<dt>Still asks</dt><dd data-region="area-still-asks">Deletes, secrets, sending, sharing, payments, and anything outside these areas</dd>')
    expect(panel).toContain('<p class="small refused" id="area-mismatch" aria-live="polite" data-region="area-mismatch" hidden>')
    expect(panel).not.toContain('data-region="area-cosign"')
  })

  it("co-sign: the third button approves once and asks a manager, and the panel says one must co-sign", () => {
    const page = rendered("ws-approval-area-cosign")
    expect(between(page, 'data-region="bar"', "</main>")).toMatch(/data-action="approve-area" disabled>.*<span>Approve once and ask a manager to let it carry on<\/span>/)
    expect(page).toContain('<p class="small" data-region="area-cosign">A manager of this credential&#39;s home must co-sign before the agent may carry on.</p>')
    expect(page).toContain('data-region="area-who">This machine, kim-laptop</dd>')
    expect(entry("ws-approval-area-cosign").page.boot.area).toMatchObject({ coSign: true })
  })

  it("says each refusal in the vault's own sentence, the one a refused remember carries", () => {
    for (const code of POLICY_AREA_REFUSALS) {
      const page = render(withArea({ terms: null, termsDigest: null, areas: [], refused: code, coSign: false }))
      expect(page, code).toContain(`<p class="small muted" data-region="area-refused">${escapeHtml(areaRefused(code).message)}</p>`)
    }
  })

  it("every refusal code has its own words, and a refused offer shows one muted line, no panel and no third button", () => {
    expect(Object.keys(AREA_REFUSAL_WORDS).sort()).toEqual([...POLICY_AREA_REFUSALS].sort())
    expect(new Set(Object.values(AREA_REFUSAL_WORDS)).size).toBe(POLICY_AREA_REFUSALS.length)
    for (const code of POLICY_AREA_REFUSALS) {
      const words = AREA_REFUSAL_WORDS[code]
      expect(words, code).toMatch(/^[A-Z].*\.$/)
      expect(words, code).not.toMatch(/[\u2013\u2014\u2015\u2E3A]/)
      const page = render(withArea({ terms: null, termsDigest: null, areas: [], refused: code, coSign: false }))
      expect(page, code).toContain(`<p class="small muted" data-region="area-refused">${escapeHtml(words)}</p>`)
      for (const absent of ["approve-area", "area-panel", "&quot;area&quot;"]) expect(page, `${code} ${absent}`).not.toContain(absent)
    }
    const refused = rendered("ws-approval-area-refused")
    expect(refused).toContain("This request is not routine building, so it cannot start a task grant.")
    expect(refused).toContain("This request sends mail or a message, so it asks every time.")
    expect(between(refused, 'data-region="bar"', "</main>")).not.toContain("approve-")
  })

  it("an offer beside an approval this viewer may not give changes nothing", () => {
    const cannot = (view: Extract<ReturnType<typeof galleryAreaApproval>, { view: "detail" }>) => render({ ...view, approval: { ...view.approval, eligibility: { ...view.approval.eligibility, canApprove: false, reason: "Not an eligible approver" } } })
    const none = withArea(GALLERY_AREA_OFFER)
    const { area: _area, ...without } = none.approval.rememberOptions
    expect(cannot(none)).toBe(cannot({ ...none, approval: { ...none.approval, rememberOptions: without } }))
  })

  it("the gallery's offers carry the digest of their own terms, and the page's checks pass on them", async () => {
    for (const id of ["ws-approval-area", "ws-approval-area-cosign"]) {
      const boot = entry(id).page.boot as unknown as WorkspaceApprovalBoot
      expect(await policyAreaGrantTermsDigest(boot.area!.terms), id).toBe(boot.area!.termsDigest)
      expect(await areaOfferMatches(boot.area!, boot.subject), id).toBe(true)
      expect(await policyRuleTermsDigest(boot.rule!.terms), id).toBe(boot.rule!.termsDigest)
      expect(await ruleOfferMatches(boot.rule!, boot.subject), id).toBe(true)
    }
  })
})

// A task grant waiting for a co-signer: the terms as the first person signed
// them, read only, and Approve with passkey or Deny.
describe("the task grant proposal page", () => {
  type Proposal = (typeof GALLERY_AREA_PROPOSAL)["proposal"]
  const page = (proposal: Partial<Proposal>) => workspaceAreaProposalPage(galleryShell(VIEWERS.manager), { ...GALLERY_AREA_PROPOSAL.proposal, ...proposal }, { provider: "cloudflare", account: null }, Date.parse("2026-10-27T18:30:00Z"))
  const body = (proposal: Partial<Proposal>) => renderDocument(page(proposal)).value

  it("holds its digests to the vault's, so the page offers Approve, and signs the terms as they were signed", async () => {
    const boot = entry("ws-area-proposal-cosign").page.boot as unknown as AreaProposalBoot
    expect(boot).toMatchObject({ page: "ws-area-proposal", view: "detail", coded: false, proposal: "pol_6ag3kq8mw2", stage: "co-sign", terms: GALLERY_AREA_PROPOSAL.proposal.terms })
    expect(await areaProposalMatches(boot)).toBe(true)
    expect(await areaProposalMatches({ ...boot, terms: { ...boot.terms, maxUses: 100 } })).toBe(false)
    expect(await areaProposalMatches({ ...boot, item: "github-alex" })).toBe(false)
    const { body: sent, expected } = await areaProposalDecision(boot, "approve")
    expect(sent).toEqual({ decision: "approve", effective: { areas: ["d1", "kv"], ttlSeconds: 3600, maxUses: 50 } })
    expect(expected).toEqual({ type: "policy.decide", proposal: "pol_6ag3kq8mw2", digest: boot.digest, decision: "approve", effectDigest: boot.termsDigest })
    expect((await areaProposalDecision(boot, "deny")).expected).toMatchObject({ decision: "deny", effectDigest: null })
  })

  it("shows who approved first and the areas, how long and how many as signed, with no choices, and Deny and Approve with passkey", () => {
    const text = rendered("ws-area-proposal-cosign")
    expect(text).toContain("<h1>Let an agent carry on: cloudflare-api-token-local-secrets-2</h1>")
    expect(text).toContain('data-region="area-approved-by">Approved by Kim as the machine&#39;s owner; a manager of this credential&#39;s home must co-sign.</p>')
    const panel = between(text, 'data-region="area-panel"', "</section>")
    expect(panel).toContain("<h2>Carry on without asking you</h2>")
    expect(panel).toContain('data-region="area-who">This machine, dev_kimlaptop1</dd>')
    expect(panel).toContain("<li><b>D1 databases</b> <span class=\"muted small\">Creates and changes D1 databases, not the data in them</span></li>")
    expect(panel).toContain("<li><b>KV namespaces and values</b>")
    expect(panel).not.toContain("DNS records")
    expect(panel).toContain('data-region="area-ttl">1 hour</dd>')
    expect(panel).toContain('data-region="area-uses">50 requests</dd>')
    expect(panel).not.toContain("<input")
    expect(text).not.toContain('data-input="code-matches"')
    const bar = between(text, 'data-region="bar"', "</main>")
    expect(bar).toContain('data-region="terms-text">D1 databases and KV namespaces and values on api.cloudflare.com, for 1 hour, up to 50 requests</span>')
    expect(bar).toMatch(/data-action="deny"><span>Deny<\/span>/)
    expect(bar).toMatch(/data-action="approve" disabled>.*<span>Approve with passkey<\/span>/)
  })

  it("gives the person who approved first the vault's words, not an Approve that fails", () => {
    const own = body({ approvedBy: { name: "Kim", self: true }, canApprove: false })
    expect(own).toContain('data-region="cannot-approve">You approved this as the machine&#39;s owner; a second person must co-sign it. You can deny it.</p>')
    expect(own).not.toContain('data-action="approve"')
    expect(own).toContain('data-action="deny"')
  })

  it("settled: the grant, its end and its uses from the vault, or why there is none, and no bar", () => {
    const approved = rendered("ws-area-proposal-approved")
    expect(approved).toMatch(/data-region="settled-words">Approved\. The agent may carry on until [^<]+, up to 50 requests\.<\/p>/)
    expect(approved).not.toContain('data-region="bar"')
    expect(body({ status: "denied", canApprove: false, canDeny: false })).toContain("It was denied, so no task grant was made and the agent was told no.")
  })

  it("reads the vault's answer to a decision in words, never what the page chose", () => {
    const boot = { proposal: "pol_6ag3kq8mw2", stage: "co-sign" as const }
    const answer = (proposal: Partial<Proposal>) => ({ view: "detail", proposal: { ...GALLERY_AREA_PROPOSAL.proposal, ...proposal } })
    expect(areaProposalOutcomeWords(answer({ status: "approved", rule: { id: "rul_2ga8kq4mz7", endsAt: "2026-10-27T19:30:00.000Z" } }), boot)).toBe("Approved. The agent may carry on until 27 Oct 2026, 19:30 UTC, up to 50 requests.")
    expect(areaProposalOutcomeWords(answer({ status: "denied" }), boot)).toBe("Denied. No task grant was made, and the agent has been told no.")
    expect(areaProposalOutcomeWords(answer({ status: "pending" }), boot)).toBeNull()
    expect(areaProposalOutcomeWords({ error: "conflict" }, boot)).toBeNull()
  })

  it("the route's page sends a task grant's detail to its own page", () => {
    expect(workspaceProposalPage(galleryShell(VIEWERS.manager), GALLERY_AREA_PROPOSAL, null).boot.page).toBe("ws-area-proposal")
  })
})

describe("the rule proposal page", () => {
  const WIDE = GALLERY_PROPOSED_TERMS.path
  const EXACT = GALLERY_RULE_TERMS.anchorPath
  type Proposal = (typeof GALLERY_RULE_PROPOSAL)["proposal"]
  const page = (proposal: Partial<Proposal>, shell = galleryShell(VIEWERS.owner)) => workspaceRuleProposalPage(shell, { view: "detail", proposal: { ...GALLERY_RULE_PROPOSAL.proposal, ...proposal } }, GALLERY_RULE_ITEM, Date.parse("2026-10-27T18:30:00Z"))
  const body = (proposal: Partial<Proposal>) => renderDocument(page(proposal)).value
  const radios = (text: string, name: string) => text.match(new RegExp(`data-input="${name}" value="[^"]+"( checked)?`, "g")) ?? []

  it("holds every fixture's digests to the vault's, so the page offers Approve", async () => {
    for (const view of [GALLERY_RULE_PROPOSAL, GALLERY_COSIGN_PROPOSAL, GALLERY_EXTEND_PROPOSAL, GALLERY_READ_ONLY_PROPOSAL]) {
      const p = view.proposal
      expect(await policyRuleTermsDigest(p.terms), p.proposal).toBe(p.termsDigest)
      expect(await ruleProposalDigest(p), p.proposal).toBe(p.digest)
      expect(await ruleProposalMatches(page(p).boot as unknown as RuleProposalBoot), p.proposal).toBe(true)
    }
  })

  it("offers the paths narrowest first, the proposed one chosen, and never one wider than proposed", () => {
    expect(radios(rendered("ws-rule-proposal"), "rule-path")).toEqual([`data-input="rule-path" value="${EXACT}"`, `data-input="rule-path" value="${WIDE}" checked`])
    const exact = body({ terms: { ...GALLERY_PROPOSED_TERMS, path: EXACT }, pathChoices: [EXACT, WIDE] })
    expect(radios(exact, "rule-path")).toEqual([`data-input="rule-path" value="${EXACT}" checked`])
    expect(page({ terms: { ...GALLERY_PROPOSED_TERMS, path: EXACT }, pathChoices: [EXACT, WIDE] }).boot.pathChoices).toEqual([EXACT])
  })

  it("offers 1, 7 or 30 days, never longer than proposed, the proposed one chosen", () => {
    expect(radios(rendered("ws-rule-proposal"), "rule-ttl")).toEqual(['data-input="rule-ttl" value="86400"', 'data-input="rule-ttl" value="604800"', 'data-input="rule-ttl" value="2592000" checked'])
    expect(radios(body({ terms: { ...GALLERY_PROPOSED_TERMS, ttlSeconds: 604_800 } }), "rule-ttl")).toEqual(['data-input="rule-ttl" value="86400"', 'data-input="rule-ttl" value="604800" checked'])
  })

  it("quotes the agent's reason as its own words, escaped and inside the warning scan", () => {
    const panel = between(rendered("ws-rule-proposal"), 'data-region="rule-panel"', "</section>")
    expect(panel).toContain(`<p class="eyebrow">${escapeHtml(RULE_REASON_LABEL)}</p><p class="small muted">${RULE_REASON_WORDS}</p><blockquote class="reason" data-region="rule-reason">Post the deploy status on each issue it closes</blockquote>`)
    const hostile = body({ reason: "<script>alert(1)</script> \u202Eevil" })
    expect(hostile).not.toContain("<script>alert(1)</script>")
    expect(hostile).toContain("&lt;script&gt;alert(1)&lt;/script&gt;")
    expect(hostile).toContain('data-region="warnings"')
    expect(ruleProposalTexts({ ...GALLERY_RULE_PROPOSAL.proposal }, GALLERY_RULE_ITEM)).toEqual(expect.arrayContaining(["Post the deploy status on each issue it closes", WIDE, EXACT, "alex-northwind", "mac-mini", "K7M2QX"]))
  })

  it("an agent's proposal shows its code, the panel and what it proposed, with Deny and Approve with passkey", () => {
    const text = rendered("ws-rule-proposal")
    expect(text).toContain("<h1>Allow from now on: github-alex</h1>")
    expect(text).toContain('<label class="tick"><input type="checkbox" data-input="code-matches"><span>The agent showed me the code <code class="code-inline">K7M2QX</code></span></label>')
    expect(text).toContain('data-region="rule-summary"><span class="muted">The agent proposed:</span> POST api.github.com/repos/northwind/platform/issues/*/comments, from mac-mini, outside any project, 30 days</p>')
    expect(text).toContain('data-region="rule-who">This machine, mac-mini</dd>')
    const bar = between(text, 'data-region="bar"', "</main>")
    expect(bar).toMatch(/data-action="deny"><span>Deny<\/span>/)
    expect(bar).toMatch(/data-action="approve" disabled>.*<span>Approve with passkey<\/span>/)
    // The title and tile name the credential the hashed terms name.
    const other = body({ item: "github-other" })
    expect(other).toContain("<h1>Allow from now on: github-alex</h1>")
    expect(other).not.toContain("github-other</h1>")
    expect(page({ item: "github-other" }).boot).toMatchObject({ item: "github-other", terms: { item: "github-alex" } })
    expect(entry("ws-rule-proposal").page.boot).toMatchObject({ page: "ws-rule-proposal", view: "detail", coded: true, proposal: "pol_7rk2mq9vx4", item: "github-alex", digest: GALLERY_RULE_PROPOSAL.proposal.digest, stage: "approve", extends: null, terms: GALLERY_PROPOSED_TERMS, pathChoices: [EXACT, WIDE] })
  })

  it("at stage co-sign says who approved as the machine's owner, with no code to tick", () => {
    const text = rendered("ws-rule-proposal-cosign")
    expect(text).toContain("Approved by Kim as the machine&#39;s owner; a manager of this credential&#39;s home must co-sign.")
    expect(text).toContain('data-region="rule-summary"><span class="muted">Proposed:</span> POST api.linear.app/graphql')
    expect(body({ ...GALLERY_COSIGN_PROPOSAL.proposal, approvedBy: { name: null, self: false } })).toContain('data-region="rule-approved-by">Approved by the machine&#39;s owner; a manager of this credential&#39;s home must co-sign.</p>')
    expect(text).not.toContain('data-input="code-matches"')
    expect(text).toContain('data-region="rule-who">Only task globex:grant-7f3k on kim-laptop</dd>')
    expect(text).toMatch(/data-action="approve" disabled>.*<span>Approve with passkey<\/span>/)
  })

  it("gives the person who approved first the vault's words, not an Approve that fails", () => {
    // Kim approved the agent's proposal as the machine's owner: the vault
    // says it was her, though the agent asked.
    const own = body({ ...GALLERY_COSIGN_PROPOSAL.proposal, approvedBy: { name: "Kim", self: true }, canApprove: false })
    expect(own).toContain('data-region="cannot-approve">You approved this as the machine&#39;s owner; a second person must co-sign it. You can deny it.</p>')
    expect(own).not.toContain('data-action="approve"')
    expect(own).not.toContain('data-input="rule-path"')
    expect(own).toContain('data-action="deny"')
    const other = body({ ...GALLERY_COSIGN_PROPOSAL.proposal, canApprove: false })
    expect(other).toContain("Only a manager of this credential&#39;s home, other than the person who approved it, can co-sign it.")
  })

  it("an extension reads Extend the rule for up to the new duration, never an end the page works out, with only the rule's path and the new duration", () => {
    const text = rendered("ws-rule-proposal-extend")
    expect(text).toContain("<h1>Extend rul_4hq8mz2kx7 for up to 30 days</h1>")
    expect(between(text, "<h1>", "</h1>")).not.toContain("2026")
    expect(radios(text, "rule-path")).toEqual([`data-input="rule-path" value="${EXACT}" checked`])
    expect(radios(text, "rule-ttl")).toEqual(['data-input="rule-ttl" value="2592000" checked'])
  })

  it("read only: the terms as proposed, and no choices, form or bar", () => {
    const text = rendered("ws-rule-proposal-read-only")
    expect(text).toContain('data-region="read-only">You can read this proposal. Your rights do not let you approve or deny it.</p>')
    for (const absent of ['data-input="rule-path"', 'data-form="decide"', 'data-region="bar"', 'data-input="code-matches"']) expect(text, absent).not.toContain(absent)
    expect(text).toContain(`data-region="rule-path"><code>${WIDE}</code>`)
    expect(text).toContain('data-region="rule-ttl">30 days</dd>')
    expect(entry("ws-rule-proposal-read-only").page.bar).toBe(false)
  })

  it("settled: the rule and its end from the vault, or why there is none", () => {
    expect(body({ status: "approved", rule: { id: "rul_4hq8mz2kx7", endsAt: "2026-11-26T18:30:00.000Z" }, canApprove: false, canDeny: false })).toContain('data-region="settled-words">Approved. Allowed from now on until 26 Nov 2026, 18:30 UTC.</p>')
    const denied = body({ status: "denied", canApprove: false, canDeny: false })
    expect(denied).toContain("It was denied, so no rule was made and the agent was told no.")
    expect(denied).not.toContain('data-region="bar"')
  })

  it("the route's page: a rule's detail goes to its page, and a stop view renders as main did", () => {
    const golden = (name: string) => GOLDEN[`./golden/${name}.html`] ?? ""
    const bytes = (p: PageInput) => `${JSON.stringify(p.boot)}\n${p.body.value}\n`
    expect(bytes(workspaceProposalPage(galleryShell(VIEWERS.owner), POLICY_STOP, null))).toBe(golden("ws-policy-stop"))
    expect(workspaceProposalPage(galleryShell(VIEWERS.owner), GALLERY_RULE_PROPOSAL, GALLERY_RULE_ITEM).boot.page).toBe("ws-rule-proposal")
  })
})

describe("Review together", () => {
  // One row of the page by its approval id, from its <li> to the next.
  const row = (text: string, id: string) => {
    const start = text.indexOf(`data-approval="${id}"`)
    const end = text.indexOf("</li>", start)
    return start === -1 ? "" : text.slice(start, end)
  }
  const section = (text: string, name: string) => between(text, `data-section="${name}" aria-label`, "</section>")
  const ticked = (text: string, id: string) => /data-input="pick" checked/.test(row(text, id))
  const tickable = (text: string, id: string) => row(text, id).includes('data-input="pick"')

  it("lists each row under the section the vault placed it in, Ready first", () => {
    const page = rendered("ws-review")
    const order = ["routine", "floor", "own-page", "deny-only", "settled"].map((s) => page.indexOf(`data-section="${s}" aria-label`))
    expect(order.every((at, i) => at !== -1 && (i === 0 || at > order[i - 1]!))).toBe(true)
    for (const id of ["apr_d1old0001", "apr_kvlist003", "apr_d1new0002"]) expect(section(page, "routine"), id).toContain(id)
    for (const id of ["apr_dnsdel004", "apr_protkv005"]) expect(section(page, "floor"), id).toContain(id)
    for (const id of ["apr_warned006", "apr_runstop07"]) expect(section(page, "own-page"), id).toContain(id)
    for (const id of ["apr_denyonly8", "apr_privst009"]) expect(section(page, "deny-only"), id).toContain(id)
    expect(section(page, "settled")).toContain("apr_settled10")
    expect(page).toContain("<h2>Ready</h2>")
    expect(page).toContain("<h2>Look at these first</h2>")
    expect(page).toContain("<h2>Decide on its own page</h2>")
    expect(page).toContain("<h2>You can only deny these</h2>")
  })

  it("ticks only routine rows no newer ask of the same shape follows; never a floor, protected, deny-only or settled row", () => {
    const page = rendered("ws-review")
    expect(ticked(page, "apr_kvlist003")).toBe(true)
    expect(ticked(page, "apr_d1new0002")).toBe(true)
    expect(ticked(page, "apr_d1old0001")).toBe(false)
    expect(row(page, "apr_d1old0001")).toContain("A newer ask to the same place is further down.")
    expect(row(page, "apr_d1new0002")).not.toContain("A newer ask to the same place")
    for (const id of ["apr_dnsdel004", "apr_protkv005", "apr_denyonly8", "apr_privst009"]) {
      expect(tickable(page, id), id).toBe(true)
      expect(ticked(page, id), id).toBe(false)
    }
    for (const id of ["apr_warned006", "apr_runstop07", "apr_settled10"]) expect(tickable(page, id), id).toBe(false)
  })

  it("marks the floor and the protected credential, opens their requests, and names why a row is decided on its own page", () => {
    const page = rendered("ws-review")
    expect(row(page, "apr_dnsdel004")).toContain('<span class="pill warn dot">Deletes</span>')
    expect(row(page, "apr_dnsdel004")).toContain('data-region="review-request" open')
    expect(row(page, "apr_protkv005")).toContain('<span class="pill warn dot">Protected</span>')
    expect(row(page, "apr_protkv005")).not.toContain("Cannot be read for safety")
    expect(row(page, "apr_kvlist003")).toMatch(/data-region="review-request">/)
    expect(row(page, "apr_warned006")).toContain("Carries a warning")
    expect(row(page, "apr_warned006")).toContain('href="/w/northwind/a/apr_warned006">Open its own page</a>')
    expect(row(page, "apr_warned006")).not.toContain("data-region=\"review-request\"")
    expect(row(page, "apr_runstop07")).toContain("Decide it on its own page")
    expect(row(page, "apr_denyonly8")).toContain('<span class="pill muted dot">Deny only</span>')
    // A private row says what the stop view says, nothing about the request.
    for (const hidden of ["request-line", "row-code", "review-request"]) expect(row(page, "apr_privst009"), hidden).not.toContain(hidden)
    expect(page).toContain('class="review-row settled" data-row data-approval="apr_settled10"')
    expect(row(page, "apr_settled10")).toContain('<span class="pill ok dot">approved</span>')
  })

  it("has one code tick in the bar counting the ticked rows, Deny ticked, and Approve off until the script checks", () => {
    const page = rendered("ws-review")
    expect(page.match(/data-input="codes-checked"/g)?.length).toBe(1)
    expect(page).toContain("I checked the codes against the agent&#39;s message (2 ticked)")
    expect(page).toContain('data-action="deny-ticked"')
    expect(page).toMatch(/data-action="approve-ticked" disabled>.*Approve 2 with passkey</)
    expect(page).toContain("To shorten a grant or allow it from now on, open its own page.")
    // An ask may sign more than one use: approving lets it through as asked, not once.
    expect(page).toContain("Approving lets each ticked request through as it was asked")
    expect(page).not.toContain("once, within")
    const boot = entry("ws-review").page.boot as unknown as { rows: { approval: string; section: string; pending: boolean; view: string }[] }
    expect(boot.rows.find((r) => r.approval === "apr_warned006")).toMatchObject({ section: "own-page", pending: true })
    expect(boot.rows.find((r) => r.approval === "apr_privst009")).toEqual({ approval: "apr_privst009", view: "stop", section: "deny-only", pending: true })
    expect(boot.rows.find((r) => r.approval === "apr_settled10")).toMatchObject({ pending: false })
    // The poll redraws a row whose newer-ask state changed, so the boot carries it.
    expect(boot.rows.find((r) => r.approval === "apr_d1old0001")).toMatchObject({ newer: true })
    expect(boot.rows.find((r) => r.approval === "apr_d1new0002")).toMatchObject({ newer: false })
  })

  it("quotes a bundle's reason as the agent's words and names its task", () => {
    const page = rendered("ws-review-bundle")
    expect(page).toContain("mac-mini</b>")
    expect(page).toContain(": 3 requests to approve together")
    expect(page).toContain('<blockquote class="reason" data-region="bundle-reason">Set up the staging D1 databases for the preview deploys</blockquote>')
    expect(page).toContain("the agent&#39;s words, not verified")
    expect(page).toContain("globex:grant-7f3k")
  })

  it("warns first and fills Deny ticked when the machine name or reason hides characters", () => {
    const page = rendered("ws-review-hostile")
    expect(page.indexOf('data-region="warnings"')).toBeGreaterThan(-1)
    expect(page.indexOf('data-region="warnings"')).toBeLessThan(page.indexOf('data-region="review-head"'))
    expect(page).toMatch(/class="btn danger" data-action="deny-ticked"/)
  })

  it("warns first when only a stop row's credential name hides characters, as the stop view does", () => {
    const page = rendered("ws-review-hostile-stop")
    expect(page.indexOf('data-region="warnings"')).toBeGreaterThan(-1)
    expect(page.indexOf('data-region="warnings"')).toBeLessThan(page.indexOf('data-region="review-head"'))
    expect(page).toMatch(/class="btn danger" data-action="deny-ticked"/)
    expect(rendered("ws-review-bundle")).not.toContain('data-region="warnings"')
    // A row's title hiding characters warns the same way.
    const [first, ...rest] = GALLERY_REVIEW_GROUP.rows
    const titled = first!.view === "detail" ? { ...first!, approval: { ...first!.approval, title: "Create D1 database\u202Eweiverp" } } : first!
    const viewer = { role: "admin" as const, member: "mem_tom00001" }
    expect(renderDocument(workspaceReviewPage(galleryShell(viewer), { viewer, group: GALLERY_REVIEW_GROUP.group, view: { ...GALLERY_REVIEW_GROUP, rows: [titled, ...rest] } })).value).toContain('data-region="warnings"')
    expect(rendered("ws-review")).not.toContain('data-region="warnings"')
  })

  it("says approving is refused while the account cools off", () => {
    expect(rendered("ws-review-held")).toContain(ACCOUNT_HELD_WORDS.approval)
    expect(rendered("ws-review")).not.toContain(ACCOUNT_HELD_WORDS.approval)
  })

  it("offers no bar when only asks for their own pages wait, no Approve when only asks it may deny wait, and says nothing waits once everything is decided", () => {
    const own = rendered("ws-review-own-page")
    expect(own).not.toContain('data-region="bar"')
    expect(own).not.toContain('data-input="pick"')
    const denyOnly = rendered("ws-review-deny-only")
    expect(denyOnly).toContain('data-action="deny-ticked"')
    expect(denyOnly).not.toContain('data-action="approve-ticked"')
    expect(denyOnly).not.toContain("with passkey")
    const settled = rendered("ws-review-settled")
    expect(settled).toContain("Nothing waiting here. 3 decided in the last hour.")
    expect(settled).not.toContain('data-region="bar"')
    const empty = rendered("ws-review-empty")
    expect(empty).toContain("Nothing waiting here.")
    expect(empty).toContain('href="/w/northwind/pending"')
  })

  it("shows a superseded ask as replaced, linked to the newer one, with no bar", () => {
    const page = rendered("ws-approval-superseded")
    expect(page).toContain("Replaced by a newer ask from the same machine")
    expect(page).toContain('href="/w/northwind/a/apr_9tq4mw2zx8">Open the newer ask</a>')
    expect(page).toContain(SETTLED_APPROVAL_WORDS.superseded)
    expect(page).not.toContain('data-region="bar"')
  })
})

// A machine's push into another service's secret store (design
// push-providers 4): the card's facts, the vault's warning kept first and
// as written, the pills from structured fields only, nothing to choose but
// Decline and Approve with passkey, and the exact request without the JSON.
describe("a push approval", () => {
  const PUSHES = ["ws-approval-push", "ws-approval-push-new", "ws-approval-push-fork", "ws-approval-push-deceptive"] as const
  const main = (id: string) => between(rendered(id), "<main", "</main>")
  const where = (id: string) => between(main(id), 'data-region="push-where">', "</dd>")

  it("is titled as the vault put it, under the machine, with where, store, name, value, using and who can read it there", () => {
    const page = main("ws-approval-push")
    expect(page).toContain('<p class="eyebrow">An agent on <b class="asker-name">mac-mini</b> wants to</p><h1>Put openai-prod into GitHub northwind/platform, Actions secret OPENAI_API_KEY, using github-ci</h1>')
    const summary = between(page, 'data-region="push-summary"', "</dl>")
    expect(summary).toContain("<dt>Where</dt><dd data-region=\"push-where\">GitHub repository northwind/platform, owned by the organisation northwind</dd>")
    expect(summary).toContain("<dt>Store</dt><dd>Actions secret</dd>")
    expect(summary).toContain('<dt>Name</dt><dd><code>OPENAI_API_KEY</code><br><span class="small muted" data-region="push-exists">Already there, updated 1 Oct 2026, 18:30 UTC: this replaces it.</span></dd>')
    expect(summary).toContain('<dt>Value</dt><dd><code>openai-prod</code>, field <code>key</code>, version 3<br><span class="small muted" data-region="push-value-facts">starts <code>mehen_fixture_</code>, fingerprint <code>fixtureFp001</code></span></dd>')
    expect(summary).toContain("<dt>Using</dt><dd>github-ci (as northwind-bot)</dd>")
    expect(summary).toContain("<dt>Who can read it there</dt><dd>Anyone who can run or change workflows in northwind/platform.</dd>")
    expect(main("ws-approval-push-fork")).toContain('data-region="push-exists">Mehen could not check whether it exists.</span>')
    expect(main("ws-approval-push-new")).toContain('data-region="push-exists">Not there yet: this creates it.</span>')
  })

  it("keeps any other detail the vault sent, after the summary, as any approval shows it", () => {
    const view = galleryPushApproval({ owner: "northwind", repo: "platform", parent: null, fork: false, private: true, newDestination: false, exists: true, id: "apr_8wq3kz6mn2", reason: "The deploy workflow needs the production key." })
    if (view.view !== "detail") throw new Error("detail")
    view.approval.details.push({ label: "Previously pushed", value: "Never to this repository" })
    const page = between(renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [] })).value, "<main", "</main>")
    const more = between(page, 'data-region="push-details"', "</dl>")
    expect(more).toContain("<dt>Previously pushed</dt><dd>Never to this repository</dd>")
    for (const known of ["<dt>Where</dt>", "<dt>Value</dt>", "<dt>Using</dt>", "The agent says"]) expect(more, known).not.toContain(known)
    expect(page.indexOf('data-region="push-summary"')).toBeLessThan(page.indexOf('data-region="push-details"'))
    expect(page.indexOf('data-region="push-details"')).toBeLessThan(page.indexOf('data-region="push-reason"'))
    expect(main("ws-approval-push")).not.toContain('data-region="push-details"')
  })

  it("leaves the value's prefix and fingerprint out when the page could not read them", () => {
    expect(main("ws-approval-push-new")).not.toContain('data-region="push-value-facts"')
    expect(main("ws-approval-push-new")).not.toContain("fingerprint")
  })

  it("draws New destination, Fork of and Public repository from the push's fields, and none for a known private repository", () => {
    expect(where("ws-approval-push")).not.toContain("pill")
    expect(where("ws-approval-push-new")).toContain('<span class="pill danger">New destination</span>')
    expect(where("ws-approval-push-new")).not.toContain("Fork of")
    const fork = where("ws-approval-push-fork")
    expect(fork).toContain("owned by the user tom-dev")
    for (const pill of ['<span class="pill danger">New destination</span>', '<span class="pill danger">Fork of northwind/platform</span>', '<span class="pill warn">Public repository</span>']) expect(fork, pill).toContain(pill)
    // The pills follow the fields, never the warnings' words.
    const view = galleryPushApproval({ owner: "northwind", repo: "platform", parent: null, fork: false, private: true, newDestination: false, exists: true, id: "apr_8wq3kz6mn2" })
    if (view.view !== "detail") throw new Error("detail")
    view.approval.warnings.push("This workspace has never pushed to northwind.", "Fork of someone/else: its owner, not this workspace, controls it.")
    const page = renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [] })).value
    expect(between(page, 'data-region="push-where">', "</dd>")).not.toContain("pill")
  })

  // The Vercel adapter writes every target as a sensitive variable
  // (push/vercel.ts), Development included, so the card says so for each.
  it("names a Vercel variable sensitive for every target, as the vault writes it", () => {
    for (const target of ["production", "preview", "development"] as const) {
      const words = pushStoreWords({ provider: "vercel", project: "web-app", team: null, target, name: "OPENAI_API_KEY" })
      expect(words, target).toBe(`${target.charAt(0).toUpperCase()}${target.slice(1)} variable (sensitive)`)
    }
  })

  it("keeps every vault warning first, as written, with Decline emphasised and no separate notice", () => {
    for (const id of PUSHES) {
      const page = main(id)
      expect(page.indexOf('data-region="warnings"'), id).toBeLessThan(page.indexOf('data-region="decision"'))
      expect(between(page, 'data-region="warnings"', "</div>"), id).toContain("<li>Mehen cannot take this back. Removing it later is done in GitHub.</li>")
      expect(page.split("Mehen cannot take this back").length - 1, id).toBe(1)
      expect(page, id).toMatch(/class="btn danger" data-action="deny"><span>Decline<\/span>/)
      expect(page, id).toMatch(/class="btn quiet" data-action="approve" disabled>.*<span>Approve with passkey<\/span>/)
    }
    const fork = between(main("ws-approval-push-fork"), 'data-region="warnings"', "</div>")
    expect(fork).toContain("<li>This workspace has never pushed to tom-dev.</li><li>Fork of northwind/platform: its owner, not this workspace, controls it.</li>")
  })

  it("offers no uses, duration or allowing from now on, whatever the vault sent", () => {
    const view = galleryPushApproval({ owner: "northwind", repo: "platform", parent: null, fork: false, private: true, newDestination: false, exists: true, id: "apr_8wq3kz6mn2" })
    if (view.view !== "detail") throw new Error("detail")
    view.approval.rememberOptions = { route: null, rule: GALLERY_RULE_OFFER }
    const pages = [...PUSHES.map(main), renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view, project: null, items: [] })).value]
    for (const page of pages) {
      for (const absent of ['data-input="uses"', 'data-input="ttl"', 'data-region="terms-form"', 'data-action="change-terms"', "It will allow", 'data-action="approve-rule"', 'data-region="rule-panel"', "from now on", "Asked for"]) expect(page, absent).not.toContain(absent)
      expect(page).toContain('data-input="code-matches"')
    }
  })

  it("offers a push whose push view is missing or unreadable only Decline and Approve, with the vault's summary and warnings and no terms, rule or remember", () => {
    const base = galleryPushApproval({ owner: "northwind", repo: "platform", parent: null, fork: false, private: true, newDestination: false, exists: true, id: "apr_8wq3kz6mn2" })
    if (base.view !== "detail") throw new Error("detail")
    const { push, ...withoutPush } = base.approval
    for (const approval of [withoutPush, { ...base.approval, push: { ...push!, destination: "nowhere" } }]) {
      const page = between(renderDocument(workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view: { ...base, approval: { ...approval, rememberOptions: { route: null, rule: GALLERY_RULE_OFFER } } }, project: null, items: [] })).value, "<main", "</main>")
      for (const absent of ['data-input="uses"', 'data-input="ttl"', 'data-region="terms-form"', 'data-action="change-terms"', "It will allow", 'data-action="approve-rule"', 'data-region="rule-panel"', "from now on"]) expect(page, absent).not.toContain(absent)
      expect(page).toContain("<dt>Using</dt><dd>github-ci (as northwind-bot)</dd>")
      expect(between(page, 'data-region="warnings"', "</div>")).toContain("<li>Mehen cannot take this back. Removing it later is done in GitHub.</li>")
      expect(page).toMatch(/class="btn danger" data-action="deny"><span>Decline<\/span>/)
      expect(page).toMatch(/data-action="approve" disabled>.*<span>Approve with passkey<\/span>/)
    }
  })

  it("quotes the agent's reason as its own words, marked where it hides characters", () => {
    expect(between(main("ws-approval-push"), 'data-region="push-reason"', "</div>")).toContain('<p class="eyebrow">The agent says</p><p class="small muted">Written by the agent. The vault does not check it.</p><blockquote class="reason">The deploy workflow needs the production key.</blockquote>')
    expect(main("ws-approval-push-fork")).not.toContain('data-region="push-reason"')
    const deceptive = main("ws-approval-push-deceptive")
    const reason = between(deceptive, 'data-region="push-reason"', "</div>")
    expect(reason).toContain("[RLO U+202E]")
    expect(deceptive).not.toContain("\u202E")
    const warnings = between(deceptive, 'data-region="warnings"', "</div>")
    expect(warnings.indexOf("Mehen cannot take this back")).toBeLessThan(warnings.indexOf("</li><li>"))
  })

  it("shows the exact request as PUSH, its URL, the body's hash and what the hash covers, never an id or the JSON", () => {
    const page = main("ws-approval-push")
    const request = between(page, 'data-region="exact-request"', "</section>")
    expect(request).toContain('<span class="method">PUSH</span> <code class="url">mehen-push:github:northwind/platform/OPENAI_API_KEY</code>')
    expect(request).toContain("<h3>What the hash covers</h3>")
    expect(request).toContain('<p class="muted small">The body SHA-256 is the hash of these, with both credentials&#39; ids and settings revisions, and the version of the one carrying it. The page does not show the exact JSON, because it names a credential&#39;s id.</p>')
    expect(request).toContain('<dt>Body SHA-256</dt><dd><code class="hash">pushBodyDigestOfTheHashedFieldsxxxxxxxxxxxx</code></dd>')
    const hashed = between(request, 'data-region="push-hashed"', "</dl>")
    for (const row of ["<dt>Credential</dt><dd><code>openai-prod</code></dd>", "<dt>Field</dt><dd><code>key</code></dd>", "<dt>Version</dt><dd>3</dd>", "<dt>Destination</dt><dd><code>github:northwind/platform/OPENAI_API_KEY</code></dd>", "<dt>Using</dt><dd><code>github-ci</code></dd>"]) expect(hashed, row).toContain(row)
    expect(page.replace(/data-boot="[^"]*"/, "")).not.toMatch(/itm_/)
    for (const absent of ["Content type", "No body.", REQUEST_BODY_HEADING]) expect(request, absent).not.toContain(absent)
  })

  it("says how far the push got once decided, and nothing while it waits", () => {
    for (const id of PUSHES) expect(main(id), id).not.toContain('data-region="push-outcome"')
    expect(between(main("ws-approval-push-done"), 'data-region="push-outcome"', "</p>")).toContain('<span class="pill ok dot">Put into GitHub: replaced.</span>')
    expect(between(main("ws-approval-push-refused"), 'data-region="push-outcome"', "</p>")).toContain('<span class="pill danger dot">GitHub refused it (403).</span>')
    expect(between(main("ws-approval-push-not-sent"), 'data-region="push-outcome"', "</p>")).toContain('<span class="pill danger dot">Not sent: nothing was sent.</span>')
    for (const id of ["ws-approval-push-done", "ws-approval-push-refused", "ws-approval-push-not-sent"]) expect(main(id), id).not.toContain('data-region="bar"')
  })

  it("leaves every other approval as it was: no push parts without a push subject", () => {
    for (const e of workspaceAsksGallery()) {
      if (e.id.startsWith("ws-approval-push")) continue
      const page = renderDocument(e.page).value
      for (const absent of ["push-summary", "push-reason", "push-outcome", "What the hash covers"]) expect(page, `${e.id} ${absent}`).not.toContain(absent)
    }
  })
})
