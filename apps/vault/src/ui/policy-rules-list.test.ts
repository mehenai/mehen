// The "Allowed without asking" card and the compact line
// (policy-rules-list.ts, policy-indicator.ts policyRulesLine), rendered as
// the credential and machine pages render them: no rules is no card and
// the page unchanged; each row's terms; Extend only where the vault may
// allow it; the stopped-only row carries no term; the line counts the
// viewer's own live rules and links where they are listed.

import { describe, expect, it } from "vitest"
import { POLICY_RULES_ENDED_LISTED, type PolicyRuleView } from "@mehen/protocol/policy-mode"
import { renderDocument } from "./layout.ts"
import { machinePage } from "./pages/machines.ts"
import { workspaceCredentialPage } from "./pages/workspace-credentials.ts"
import { PEOPLE_DEVICE, PEOPLE_PROJECTS, peopleShell } from "./people-gallery.ts"
import { policyRulesLine } from "./policy-indicator.ts"
import { galleryRule } from "./policy-rules-gallery.ts"
import { type PolicyRulesCardData, type RuleMachine, RULES_ENDED_SHOWN, credentialRulesLine, hasActiveRule, machineRulesLine, policyRulesCard } from "./policy-rules-list.ts"
import { ruleTermsOf, stoppedOnlyRow } from "./policy-rules-row.ts"
import { escapeHtml } from "./html.ts"
import { GALLERY_NOW } from "./shell-gallery.ts"
import { GALLERY_FIXTURES, GALLERY_ITEMS, VIEWERS, description, galleryProject, galleryShell } from "./workspace-projects-gallery.ts"
import { GALLERY_WORKLOADS } from "./people-gallery.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const MINE: RuleMachine = { name: "alex-mbp", owner: { kind: "member", member: "mem_alex0001", name: "Alex" } }
const THEIRS: RuleMachine = { name: "tom-laptop", owner: { kind: "member", member: "mem_tom00001", name: "Tom" } }
const TEAMS: RuleMachine = { name: "ci-runner", owner: { kind: "team", team: "tm_plat0001", name: "Platform" } }
const machines = new Map([["dev_mine0001", MINE], ["dev_theirs01", THEIRS], ["dev_team0001", TEAMS]])
const rule = (id: string, device: string, over: Partial<PolicyRuleView> = {}) => galleryRule(NOW, { id, item: "openai-prod", asker: { device, workload: null }, method: "POST", host: "api.openai.com", path: "/v1/embeddings", ...over })
const card = (rules: PolicyRuleView[], over: Partial<PolicyRulesCardData> = {}): PolicyRulesCardData => ({ rules, machines, tasks: new Map(), viewer: { member: "mem_alex0001", role: "owner", held: false }, showCredential: false, ...over })
const rowOf = (markup: string, id: string) => {
  const at = markup.indexOf(`data-rule="${id}"`)
  return markup.slice(at, markup.indexOf("</li>", at))
}

describe("no rules, no card", () => {
  it("renders nothing for no rules or none read, and the pages are byte for byte the same as without rules", () => {
    expect(policyRulesCard("northwind", undefined).value).toBe("")
    expect(policyRulesCard("northwind", card([])).value).toBe("")
    const owner = galleryShell(VIEWERS.owner)
    const item = description(GALLERY_ITEMS[0]!)
    const plain = renderDocument(workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item, projects: [] })).value
    expect(renderDocument(workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item, projects: [], rules: card([]) })).value).toBe(plain)
    const tom = peopleShell("member", { member: "mem_tom01" })
    const data = { viewer: { member: "mem_tom01", role: "member" as const, blocked: false }, projects: PEOPLE_PROJECTS, now: NOW }
    const bare = renderDocument(machinePage(tom, PEOPLE_DEVICE, data)).value
    expect(renderDocument(machinePage(tom, PEOPLE_DEVICE, { ...data, rules: card([], { showCredential: true }) })).value).toBe(bare)
    expect(bare).not.toContain("policy-rules")
  })
})

describe("the pages with no live rule", () => {
  it("with no live rule to show both pages are byte for byte their golden output", async () => {
    const owner = galleryShell(VIEWERS.owner)
    const item = { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0]!), projects: [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)] }
    const tom = peopleShell("member", { member: "mem_tom01" })
    const data = { viewer: { member: "mem_tom01", role: "member" as const, blocked: false }, projects: PEOPLE_PROJECTS, now: GALLERY_NOW, workloads: GALLERY_WORKLOADS }
    const ended = [rule("rul_gone0001", "dev_mine0001", { status: "ended", endedReason: "expired" })]
    for (const rules of [undefined, card([]), card(ended)]) {
      // Golden output of the page with no live rule; regenerate with `vitest -u` when the page deliberately changes.
      await expect(renderDocument(workspaceCredentialPage(owner, { ...item, ...(rules !== undefined ? { rules } : {}) })).value).toMatchFileSnapshot("./__snapshots__/credential-no-rules.html")
      await expect(renderDocument(machinePage(tom, PEOPLE_DEVICE, { ...data, ...(rules !== undefined ? { rules: { ...rules, showCredential: true } } : {}) })).value).toMatchFileSnapshot("./__snapshots__/machine-no-rules.html")
    }
  })
})

describe("the rows", () => {
  it("shows who, the request, GraphQL fields, the approver, uses with the last use, the end, and Stop", () => {
    const shown = policyRulesCard("northwind", card([
      rule("rul_mine0001", "dev_mine0001", { uses: 3, lastUsedAt: new Date(NOW - 60_000).toISOString() }),
      rule("rul_task0001", "dev_theirs01", { asker: { device: "dev_theirs01", workload: "wl_task0001" }, host: "api.linear.app", path: "/graphql", anchorPath: "/graphql", graphql: { fields: ["commentCreate", "issueCreate"], nestedFields: ["id"] }, approvedBy: null }),
    ], { tasks: new Map([["wl_task0001", "ci:job-4182"]]) })).value
    const mine = rowOf(shown, "rul_mine0001")
    expect(mine).toContain("<code>POST api.openai.com/v1/embeddings</code>")
    expect(mine).toContain("<dt>Who</dt><dd>alex-mbp</dd>")
    expect(mine).toContain("<dt>Approved by</dt><dd>Tom Barker</dd>")
    expect(mine).toContain('<dt>Used</dt><dd>3 times, last <time datetime="2026-10-27T18:29:00.000Z"')
    expect(mine).toContain('<dt data-region="rule-ends-label">Ends</dt><dd data-region="rule-ends"><time datetime="2026-11-01T18:30:00.000Z"')
    expect(mine).toContain('data-action="rule-stop" data-rule="rul_mine0001"')
    // The live region is there and shown before anything is said in it.
    expect(mine).toContain('<div class="small" role="status" tabindex="-1" data-region="rule-outcome"></div>')
    expect(mine).not.toContain("GraphQL fields")
    const task = rowOf(shown, "rul_task0001")
    expect(task).toContain('<dt>Who</dt><dd>task <code>ci:job-4182</code> <span class="muted small">(as the machine named it)</span> on tom-laptop</dd>')
    expect(task).toContain("<dt>GraphQL fields</dt><dd><code>commentCreate</code>, <code>issueCreate</code></dd>")
    expect(task).toContain('<dt>Approved by</dt><dd><span class="muted">not shown</span></dd>')
    expect(task).toContain("<dt>Used</dt><dd>Not yet</dd>")
    // Uses counted with no time of the last: no dangling "last".
    for (const [uses, words] of [[1, "Once"], [3, "3 times"]] as const) expect(rowOf(policyRulesCard("northwind", card([rule("rul_nolast01", "dev_mine0001", { uses, lastUsedAt: null })])).value, "rul_nolast01")).toContain(`<dt>Used</dt><dd>${words}</dd>`)
    // The credential's own page does not name it again; a machine's does.
    expect(shown).not.toContain("<dt>Credential</dt>")
    expect(policyRulesCard("northwind", card([rule("rul_mine0001", "dev_mine0001")], { showCredential: true })).value).toContain('<dt>Credential</dt><dd><a href="/w/northwind/items/openai-prod"><code>openai-prod</code></a></dd>')
  })

  it("says where the rule applies under Context in the approval page's words, by the project's slug, and who co-signed it", () => {
    const projects = [{ id: "prj_platform01", slug: "platform" }]
    const shown = policyRulesCard("northwind", card([
      rule("rul_ctx00001", "dev_mine0001", { context: { project: "prj_platform01", environment: "prod" }, coSignedBy: { name: "Kim Lee" } }),
      rule("rul_none0001", "dev_mine0001"),
      rule("rul_gone0001", "dev_mine0001", { context: { project: "prj_gone0001", environment: "dev" }, approvedBy: null, coSignedBy: { name: null } }),
    ]), projects).value
    expect(rowOf(shown, "rul_ctx00001")).toContain("<dt>Context</dt><dd>Project platform and environment prod</dd>")
    expect(rowOf(shown, "rul_ctx00001")).toContain("<dt>Approved by</dt><dd>Tom Barker, co-signed by Kim Lee</dd>")
    expect(rowOf(shown, "rul_none0001")).toContain("<dt>Context</dt><dd>outside any project</dd>")
    expect(rowOf(shown, "rul_none0001")).toContain("<dt>Approved by</dt><dd>Tom Barker</dd>")
    // A project the page could not read is named by its id, as the vault names it.
    expect(rowOf(shown, "rul_gone0001")).toContain("<dt>Context</dt><dd>Project prj_gone0001 and environment dev</dd>")
    expect(rowOf(shown, "rul_gone0001")).toContain('<dt>Approved by</dt><dd><span class="muted">not shown</span>, co-signed by a manager</dd>')
  })

  it("offers Extend for the viewer's own machine and a team's, never someone else's, a guest's view or a held account's", () => {
    const rules = [rule("rul_mine0001", "dev_mine0001"), rule("rul_their001", "dev_theirs01"), rule("rul_team0001", "dev_team0001")]
    const extendable = (data: PolicyRulesCardData) => rules.filter((r) => rowOf(policyRulesCard("northwind", data).value, r.id).includes('data-action="rule-extend"')).map((r) => r.id)
    expect(extendable(card(rules))).toEqual(["rul_mine0001", "rul_team0001"])
    expect(extendable(card(rules, { viewer: { member: "mem_alex0001", role: "owner", held: true } }))).toEqual([])
    expect(extendable(card(rules, { viewer: { member: "mem_alex0001", role: "guest", held: false } }))).toEqual([])
    expect(extendable(card(rules, { viewer: null }))).toEqual([])
    // Every live row has Stop: the vault decides who may.
    for (const r of rules) expect(rowOf(policyRulesCard("northwind", card(rules)).value, r.id)).toContain('data-action="rule-stop"')
    // Extend carries the terms the row shows, for the page to check the
    // vault's action against.
    expect(rowOf(policyRulesCard("northwind", card(rules)).value, "rul_mine0001")).toContain(`data-rule-terms="${escapeHtml(JSON.stringify(ruleTermsOf(rules[0]!)))}"`)
    const extend = rowOf(policyRulesCard("northwind", card(rules)).value, "rul_mine0001")
    expect(extend).toContain('value="86400"><span>1 day</span>')
    expect(extend).toContain('value="604800" checked><span>7 days</span>')
    expect(extend).toContain('value="2592000"><span>30 days</span>')
  })

  it("an ended rule says Stopped or Ended with why, and offers neither Stop nor Extend", () => {
    const shown = policyRulesCard("northwind", card([rule("rul_live0001", "dev_mine0001"), rule("rul_stop0001", "dev_mine0001", { status: "ended", endedReason: "revoked" }), rule("rul_time0001", "dev_mine0001", { status: "ended", endedReason: "expired" })])).value
    const stopped = rowOf(shown, "rul_stop0001")
    expect(stopped).toContain('<span class="pill muted">Stopped</span>')
    // Read again later, the page cannot say who stopped it.
    expect(stopped).toContain('<p class="small muted" data-region="rule-ended">Someone stopped it.</p>')
    expect(stopped).toContain('<dt data-region="rule-ends-label">Ended</dt>')
    expect(stopped).not.toContain("rule-stop")
    expect(stopped).not.toContain("rule-extend")
    expect(rowOf(shown, "rul_time0001")).toContain('<span class="pill muted">Ended</span>')
    expect(rowOf(shown, "rul_time0001")).toContain("Its time ran out.")
  })

  it("spells a hostile machine name, task label and approver as card text", () => {
    const hostile = "evil\u202e\" <b>x</b>"
    const shown = policyRulesCard("northwind", card([rule("rul_host0001", "dev_host0001", { asker: { device: "dev_host0001", workload: "wl_host0001" }, approvedBy: hostile })], { machines: new Map([["dev_host0001", { name: hostile, owner: THEIRS.owner }]]), tasks: new Map([["wl_host0001", hostile]]) })).value
    expect(shown).not.toContain("<b>x</b>")
    expect(shown).not.toContain("\u202e")
    expect(shown).toContain('<mark class="marker">')
    // The project, environment and co-signer too.
    const where = policyRulesCard("northwind", card([rule("rul_host0002", "dev_mine0001", { context: { project: "prj_host0001", environment: hostile }, coSignedBy: { name: hostile } })]), [{ id: "prj_host0001", slug: hostile }]).value
    const row = rowOf(where, "rul_host0002")
    expect(row).not.toContain("<b>x</b>")
    expect(row).not.toContain("\u202e")
    expect(row).toContain('<dt>Context</dt><dd>Project evil<mark class="marker">')
    expect(row).toContain(', co-signed by evil<mark class="marker">')
  })

  it("the stopped-only row is the id, why and its status, and nothing of what the rule allowed", () => {
    expect(stoppedOnlyRow({ id: "rul_hidden001", status: "ended", endedReason: "revoked" }).value).toBe(`<li class="row" data-region="rule" data-rule="rul_hidden001" data-rule-state="ended">
    <div class="row-main"><span class="row-title">Rule <code>rul_hidden001</code></span><span class="row-sub">You may stop this rule, but not read what it allows. It was stopped.</span><div class="small" role="status" tabindex="-1" data-region="rule-outcome">Stopped.</div></div>
    <span class="row-side" data-region="rule-status"><span class="pill muted">Stopped</span></span>
  </li>`)
  })
})

describe("ended rules", () => {
  const live = rule("rul_live0001", "dev_mine0001")
  // Ended an hour apart, the first most recently.
  const gone = (n: number) => rule(`rul_gone000${n}`, "dev_mine0001", { status: "ended", endedReason: "expired", endsAt: new Date(NOW - n * 3_600_000).toISOString() })

  it("show no card when no rule is active", () => {
    expect(policyRulesCard("northwind", card([gone(1), gone(2)])).value).toBe("")
    expect(hasActiveRule([gone(1)])).toBe(false)
    expect(hasActiveRule([gone(1), live])).toBe(true)
  })

  it("are listed under Ended after the live ones, the 5 most recent, with a count of the rest", () => {
    const shown = policyRulesCard("northwind", card([gone(7), gone(2), live, gone(6), gone(1), gone(3), gone(5), gone(4)])).value
    const ended = shown.slice(shown.indexOf("<h3>Ended</h3>"))
    expect(shown.indexOf('data-rule="rul_live0001"')).toBeLessThan(shown.indexOf("<h3>Ended</h3>"))
    expect([...ended.matchAll(/data-rule="(rul_\w+)"/g)].map((m) => m[1])).toEqual(["rul_gone0001", "rul_gone0002", "rul_gone0003", "rul_gone0004", "rul_gone0005"])
    expect(ended).toContain('<p class="small muted" data-region="rules-ended-more">2 older ended rules are not shown.</p>')
    expect(policyRulesCard("northwind", card([live, gone(1)])).value).not.toContain("rules-ended-more")
    expect(policyRulesCard("northwind", card([live])).value).not.toContain("<h3>Ended</h3>")
  })

  // The vault lists only the POLICY_RULES_ENDED_LISTED most recently ended
  // rules, so a full list may leave more out than the card can count.
  it("count the rest as at least that many when the vault's list of ended rules is full", () => {
    const full = Array.from({ length: POLICY_RULES_ENDED_LISTED }, (_, i) => gone(i + 1))
    const older = POLICY_RULES_ENDED_LISTED - RULES_ENDED_SHOWN
    expect(policyRulesCard("northwind", card([live, ...full])).value).toContain(`<p class="small muted" data-region="rules-ended-more">At least ${older} older ended rules are not shown.</p>`)
    expect(policyRulesCard("northwind", card([live, ...full.slice(1)])).value).toContain(`<p class="small muted" data-region="rules-ended-more">${older - 1} older ended rules are not shown.</p>`)
  })
})

describe("the compact line", () => {
  const rules = [rule("rul_mine0001", "dev_mine0001"), rule("rul_mine0002", "dev_mine0001", { item: "github-alex" }), rule("rul_their001", "dev_theirs01"), rule("rul_gone0001", "dev_mine0001", { status: "ended", endedReason: "expired" })]

  it("counts only the viewer's own machines' live rules, and is absent when there are none", () => {
    expect(credentialRulesLine("northwind", card(rules))).toEqual({ count: 2, href: "/w/northwind/devices/dev_mine0001" })
    expect(credentialRulesLine("northwind", card(rules.slice(2)))).toBeUndefined()
    expect(credentialRulesLine("northwind", undefined)).toBeUndefined()
    expect(credentialRulesLine("northwind", card(rules, { viewer: null }))).toBeUndefined()
    // Two of the viewer's machines: the line links to the machines.
    const second = new Map([...machines, ["dev_mine0002", { ...MINE, name: "alex-mini" }]])
    expect(credentialRulesLine("northwind", card([...rules, rule("rul_mini0001", "dev_mine0002")], { machines: second }))?.href).toBe("/w/northwind/devices")
  })

  it("on a machine's page links to the one credential its rules are on, or to the card", () => {
    expect(machineRulesLine("northwind", card(rules.slice(0, 1)))).toEqual({ count: 1, href: "/w/northwind/items/openai-prod" })
    expect(machineRulesLine("northwind", card(rules))).toEqual({ count: 2, href: "#policy-rules" })
  })

  it("is drawn in the indicator's styling at the top of the page, and only when there is one", () => {
    expect(policyRulesLine({ count: 1, href: "/w/northwind/devices/dev_mine0001" }).value).toBe(`<section class="notice warn attention" data-region="policy-rules-line" aria-label="Allowed without asking" aria-live="polite">
    <p class="notice-title"><a href="/w/northwind/devices/dev_mine0001" data-region="policy-rules-count">1 request allowed without asking</a></p>
  </section>`)
    const owner = galleryShell(VIEWERS.owner)
    const page = renderDocument(workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0]!), projects: [], rules: card(rules) })).value
    expect(page).toContain('<section class="notice warn attention" data-region="policy-rules-line" aria-label="Allowed without asking" aria-live="polite">\n    <p class="notice-title"><a href="/w/northwind/devices/dev_mine0001" data-region="policy-rules-count">2 requests allowed without asking</a></p>\n  </section><div id="notice"')
    expect(renderDocument(workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0]!), projects: [], rules: card(rules.slice(2)) })).value).not.toContain("policy-rules-line")
  })
})
