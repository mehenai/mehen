// askWarnings: the warnings an ask page shows, over every string it
// renders, by the cards' own rules; and every ask page family's warned
// state: a right-to-left override, a zero-width space
// and a C0 control in each text field the page shows each warn; the
// rendered document carries the marker and never the raw character; the
// warning card comes first; the declining action is the filled danger
// button and the accepting one quiet, still off; the boot keeps the raw
// strings the digests are over.

import { describe, expect, it } from "vitest"
import type { PolicyRuleOffer } from "@mehen/protocol/policy-mode"
import type { WorkspaceApprovalView, WorkspaceConnectView, WorkspaceEnrolView, WorkspaceIntakeView } from "@mehen/protocol/workspace"
import { CONTROL_WARNING, DECEPTIVE_WARNING, textWarnings } from "../relay/spelling.ts"
import { approvalTexts, askWarnings, connectTexts, decisionEmphasis, enrolTexts, intakeTexts, mergedWarnings, stopTexts } from "./ask-safety.ts"
import { renderDocument } from "./layout.ts"
import type { PageInput } from "./layout.ts"
import { workspaceApprovalPage, workspaceConnectPage, workspaceIntakePage, workspaceRuleProposalPage } from "./pages/workspace-asks.ts"
import { workspaceAreaProposalPage } from "./pages/workspace-asks.ts"
import { enrolmentPage } from "./pages/workspace-enrol.ts"
import { PEOPLE_PROJECTS, peopleShell } from "./people-gallery.ts"
import { GALLERY_COSIGN_OFFER, GALLERY_RULE_OFFER, GALLERY_RULE_PROPOSAL, GALLERY_RULE_TERMS, PEOPLE_ENROL, galleryEmailApproval, galleryRuleApproval, galleryRunApproval, workspaceAsksGallery } from "./workspace-asks-gallery.ts"
import { GALLERY_AREA_PROPOSAL, galleryAreaApproval } from "./workspace-asks-gallery.ts"
import { VIEWERS, galleryShell } from "./workspace-projects-gallery.ts"

describe("askWarnings", () => {
  it("warns about nothing in plain text", () => {
    expect(askWarnings([])).toEqual([])
    expect(askWarnings(["tom-laptop", "toms-mbp.local", "Send an email to priya@acme.example", "Ünïcödé, emoji 🙂 and a tab\there"])).toEqual([])
  })

  it("warns once about a direction override or an invisible character in any string", () => {
    expect(askWarnings(["tom-laptop", "pay\u202Eexe.fdp"])).toEqual([DECEPTIVE_WARNING])
    expect(askWarnings(["Mac\u200bOffice", "Am\u202esterdam", "\u2066isolated\u2069"])).toEqual([DECEPTIVE_WARNING])
  })

  it("warns once about a control character in any string", () => {
    expect(askWarnings(["Pay\u0000load"])).toEqual([CONTROL_WARNING])
    expect(askWarnings(["a bell\u0007", "a lone carriage return\rhere", "an escape \u001b[31m"])).toEqual([CONTROL_WARNING])
  })

  it("gives both warnings, the hidden characters first, when a page has both", () => {
    expect(askWarnings(["Pay\u0000load", "Tom\u202e"])).toEqual([DECEPTIVE_WARNING, CONTROL_WARNING])
  })

  it("does not warn about text that only looks like a marker or a spelled control", () => {
    expect(askWarnings(["[RLO U+202E] typed by hand", "\\u0000 typed by hand"])).toEqual([])
  })

  it("follows the cards' own rules exactly", () => {
    const texts = ["plain", "pay\u202Eexe.fdp", "Pay\u0000load", "line\r\nend"]
    for (let i = 0; i <= texts.length; i++) expect(askWarnings(texts.slice(0, i))).toEqual(textWarnings(texts.slice(0, i)))
  })

  it("keeps the vault's own warnings first and adds each of the page's once", () => {
    expect(mergedWarnings(["Part 2 could not be read."], ["Tom\u202e"])).toEqual(["Part 2 could not be read.", DECEPTIVE_WARNING])
    expect(mergedWarnings([DECEPTIVE_WARNING], ["Tom\u202e"])).toEqual([DECEPTIVE_WARNING])
  })

  it("puts the declining action in the primary position only when warned", () => {
    expect(decisionEmphasis(false)).toEqual({ decline: "secondary", accept: "primary" })
    expect(decisionEmphasis(true)).toEqual({ decline: "danger", accept: "quiet" })
  })
})

// The three kinds of character the matrix names, and their markers.
const HOSTILE = [
  { raw: "\u202E", marker: "[RLO U+202E]", warning: DECEPTIVE_WARNING },
  { raw: "\u200B", marker: "[ZWSP U+200B]", warning: DECEPTIVE_WARNING },
  { raw: "\u0007", marker: "\\u0007", warning: CONTROL_WARNING },
] as const

type Case = { field: string; page: (bad: string) => PageInput; decline: string; accept: string | null }

function detail(view: WorkspaceApprovalView): Extract<WorkspaceApprovalView, { view: "detail" }> {
  if (view.view !== "detail") throw new Error("detail")
  return structuredClone(view)
}

const decider = { role: "admin" as const, member: "mem_tom00001" }

function approvalWith(edit: (a: Extract<WorkspaceApprovalView, { view: "detail" }>["approval"], bad: string) => void, base: () => WorkspaceApprovalView = galleryEmailApproval): (bad: string) => PageInput {
  return (bad) => {
    const view = detail(base())
    view.approval.warnings = []
    edit(view.approval, bad)
    return workspaceApprovalPage(galleryShell(decider), { viewer: decider, view, project: null, items: [] })
  }
}

const INTAKE_FIXTURE: WorkspaceIntakeView = {
  intake: "int_4hz8rq2nk1", status: "open", kind: "api-key", slug: "openai-staging", provider: "openai", providerName: "OpenAI", reason: "The staging deploy needs a key.", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null }, rotates: false,
  fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }], binding: { value: { hosts: ["api.openai.com"] }, verified: true }, injection: { value: null, verified: true }, customPolicy: false, tags: [], sealKey: { jwk: { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }, kid: "seal-2026-10" }, expiresAt: "2026-10-28T14:30:00.000Z",
  home: { kind: "project", project: "prj_platform01" }, permittedHomes: [{ kind: "member", member: "mem_alex0001" }, { kind: "project", project: "prj_platform01" }, { kind: "workspace" }], intent: "create", target: null, client: null, dependencyRevision: 0,
}

const CONNECT_FIXTURE: WorkspaceConnectView = {
  connect: "con_8vw2kq5mz3", status: "open", provider: "google-gmail", providerName: "Gmail", slug: "gmail-alex", scopes: ["https://www.googleapis.com/auth/gmail.readonly"], tags: ["mail"], expect: "alex@northwind.example", reason: "Read the support inbox.", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null }, reconnect: false, currentScopes: null, account: null, message: null, expiresAt: "2026-10-27T18:45:00.000Z",
  home: { kind: "member", member: "mem_alex0001" }, permittedHomes: [{ kind: "member", member: "mem_alex0001" }, { kind: "workspace" }], intent: "create", target: null, client: { item: "itm_gclient01", configRevision: 1 }, dependencyRevision: 0,
}

function intakeWith(edit: (v: WorkspaceIntakeView, bad: string) => void): (bad: string) => PageInput {
  return (bad) => {
    const view = structuredClone(INTAKE_FIXTURE)
    edit(view, bad)
    return workspaceIntakePage(galleryShell(VIEWERS.owner), view, [], 0)
  }
}

function connectWith(edit: (v: WorkspaceConnectView, bad: string) => void): (bad: string) => PageInput {
  return (bad) => {
    const view = structuredClone(CONNECT_FIXTURE)
    edit(view, bad)
    return workspaceConnectPage(galleryShell(VIEWERS.owner), view, [], 0)
  }
}

function enrolWith(edit: (v: WorkspaceEnrolView, bad: string) => void): (bad: string) => PageInput {
  return (bad) => {
    const view = structuredClone(PEOPLE_ENROL)
    edit(view, bad)
    return enrolmentPage(peopleShell("member", { member: "mem_tom01" }), view, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: PEOPLE_PROJECTS, now: 0 })
  }
}

type RuleProposal = typeof GALLERY_RULE_PROPOSAL.proposal
function proposalWith(edit: (p: RuleProposal, bad: string) => void, account = (_bad: string) => "alex-northwind"): (bad: string) => PageInput {
  return (bad) => {
    const proposal = structuredClone(GALLERY_RULE_PROPOSAL.proposal)
    edit(proposal, bad)
    return workspaceRuleProposalPage(galleryShell(VIEWERS.owner), { view: "detail", proposal }, { provider: "github", account: account(bad) }, 0)
  }
}
// The rule proposal page's strings that the panel shows.
const PROPOSAL_PANEL_CASES: Case[] = [
  { field: "rule proposal reason", page: proposalWith((p, bad) => (p.reason = `Post the${bad} status`)), decline: "deny", accept: "approve" },
  { field: "rule proposal machine name", page: proposalWith((p, bad) => (p.requestedBy = { device: "dev_macmini1", deviceName: `mac${bad}office`, session: null })), decline: "deny", accept: "approve" },
  { field: "rule proposal task label", page: proposalWith((p, bad) => { p.requestedBy = { device: "dev_macmini1", deviceName: "mac-mini", session: null, workload: { id: "wl_task8kq2mw4z", label: `globex${bad}grant` } }; p.terms = { ...p.terms, asker: { device: "dev_macmini1", workload: "wl_task8kq2mw4z" } } }), decline: "deny", accept: "approve" },
  { field: "rule proposal account", page: proposalWith(() => undefined, (bad) => `alex${bad}northwind`), decline: "deny", accept: "approve" },
]

type AreaProposal = typeof GALLERY_AREA_PROPOSAL.proposal
function areaProposalWith(edit: (p: AreaProposal, bad: string) => void): (bad: string) => PageInput {
  return (bad) => {
    const proposal = structuredClone(GALLERY_AREA_PROPOSAL.proposal)
    edit(proposal, bad)
    return workspaceAreaProposalPage(galleryShell(VIEWERS.manager), proposal, { provider: "cloudflare", account: null }, 0)
  }
}
// The task grant proposal page's strings: the vault's summary, who approved
// first and the areas' names.
const AREA_PROPOSAL_CASES: Case[] = [
  { field: "task grant proposal summary", page: areaProposalWith((p, bad) => (p.summary = `Task grant on api.cloudflare.com: D1 databases, from kim${bad}laptop`)), decline: "deny", accept: "approve" },
  { field: "task grant proposal approver", page: areaProposalWith((p, bad) => (p.approvedBy = { name: `Ki${bad}m` })), decline: "deny", accept: "approve" },
  { field: "task grant proposal area name", page: areaProposalWith((p, bad) => (p.areas = p.areas.map((a) => ({ ...a, name: `${a.name}${bad}` })))), decline: "deny", accept: "approve" },
]

const CASES: Case[] = [
  ...PROPOSAL_PANEL_CASES,
  ...AREA_PROPOSAL_CASES,
  // The vault's summary names the project and environment.
  { field: "rule proposal project and environment", page: proposalWith((p, bad) => (p.summary = `POST api.github.com/repos/northwind/platform/issues/*/comments, from mac-mini, in plat${bad}form / de${bad}v, 30 days`)), decline: "deny", accept: "approve" },
  { field: "approval title", page: approvalWith((a, bad) => (a.title = `Send ${bad}it`)), decline: "deny", accept: "approve" },
  { field: "approval body", page: approvalWith((a, bad) => (a.request.body = `{"raw":"pay${bad}now"}`)), decline: "deny", accept: "approve" },
  { field: "approval header", page: approvalWith((a, bad) => (a.request.headers = [["X-Note", `head${bad}er`]])), decline: "deny", accept: "approve" },
  { field: "email section", page: approvalWith((a, bad) => { if (a.email) a.email.sections = [{ heading: "Text", note: null, text: `Hi${bad}there` }] }), decline: "deny", accept: "approve" },
  { field: "approval URL", page: approvalWith((a, bad) => (a.request.url = `https://gmail.googleapis.com/send${bad}`)), decline: "deny", accept: "approve" },
  { field: "session label", page: approvalWith((a, bad) => (a.requestedBy = { ...a.requestedBy, session: `agent${bad}work` })), decline: "deny", accept: "approve" },
  { field: "machine name", page: approvalWith((a, bad) => (a.requestedBy = { ...a.requestedBy, deviceName: `mac${bad}office` })), decline: "deny", accept: "approve" },
  { field: "run argv", page: approvalWith((a, bad) => (a.request.body = `"node"\n"de${bad}ploy.js"`), () => galleryRunApproval(true, ["Tom"])), decline: "deny", accept: "approve" },
  { field: "intake reason", page: intakeWith((v, bad) => (v.reason = `Needs a key${bad}.`)), decline: "cancel-request", accept: "submit-intake" },
  { field: "intake machine name", page: intakeWith((v, bad) => (v.requestedBy = { device: "dev_macmini1", deviceName: `mac${bad}office`, session: null })), decline: "cancel-request", accept: "submit-intake" },
  { field: "connect reason", page: connectWith((v, bad) => (v.reason = `Read${bad} mail.`)), decline: "cancel-request", accept: "start-connect" },
  { field: "connect expected account", page: connectWith((v, bad) => (v.expect = `alex${bad}@northwind.example`)), decline: "cancel-request", accept: "start-connect" },
  { field: "connect scope", page: connectWith((v, bad) => (v.scopes = [`https://www.googleapis.com/auth/gmail${bad}.readonly`])), decline: "cancel-request", accept: "start-connect" },
  { field: "enrolment machine name", page: enrolWith((v, bad) => (v.name = `tom${bad}laptop`)), decline: "enrol-reject", accept: "enrol-accept" },
  { field: "enrolment host", page: enrolWith((v, bad) => (v.host = `toms${bad}.local`)), decline: "enrol-reject", accept: "enrol-accept" },
  { field: "enrolment place", page: enrolWith((v, bad) => (v.start = { ...v.start, place: `Amster${bad}dam` })), decline: "enrol-reject", accept: "enrol-accept" },
  { field: "enrolment scope entry", page: enrolWith((v, bad) => (v.scope = { ...v.scope, tags: [`ai${bad}`] })), decline: "enrol-reject", accept: "enrol-accept" },
]

function button(document: string, action: string): string {
  const found = new RegExp(`<button[^>]*data-action="${action}"[^>]*>`).exec(document)
  if (found === null) throw new Error(`no ${action} button`)
  return found[0]
}

function main(document: string): string {
  return document.slice(document.indexOf("<main"), document.indexOf("</main>"))
}

describe("every ask page family's warned state", () => {
  for (const c of CASES) {
    for (const h of HOSTILE) {
      it(`${c.field} with ${h.marker}: warning first, marker shown, raw never, decline filled, accept quiet and off`, () => {
        const page = c.page(h.raw)
        const document = renderDocument(page).value
        const body = main(document)
        expect(body.replace(/<[^>]+>/g, ""), h.marker).toContain(h.marker)
        const visible = body.replace(/data-boot="[^"]*"/, "")
        expect(visible).not.toContain(h.raw)
        expect(body).toContain('data-region="warnings"')
        expect(body).toContain(h.warning.slice(0, 40))
        const warningAt = body.indexOf('data-region="warnings"')
        expect(warningAt).toBeLessThan(body.indexOf('data-region="decision"') === -1 ? body.indexOf('data-region="bar"') : body.indexOf('data-region="decision"'))
        expect(body.indexOf("<section")).toBeGreaterThan(warningAt)
        expect(button(document, c.decline)).toMatch(/class="btn danger"/)
        if (c.accept !== null) {
          expect(button(document, c.accept)).toMatch(/class="btn quiet"/)
          expect(button(document, c.accept)).toMatch(/ disabled>/)
        }
        expect(document).toContain('class="bar warned"')
      })
    }
  }

  it("the boot keeps the raw strings the digests are over", () => {
    const page = approvalWith((a, bad) => {
      a.request.url = `https://gmail.googleapis.com/send${bad}`
      a.request.headers = [["X-Note", `head${bad}er`]]
    })("\u202E")
    const boot = /data-boot="([^"]+)"/.exec(renderDocument(page).value)?.[1] ?? ""
    expect(boot).toContain("\\u202E")
  })

  it("an unwarned page keeps Decline secondary and Approve primary, and shows no warning card", () => {
    const document = renderDocument(approvalWith(() => undefined)("")).value
    expect(document).not.toContain('data-region="warnings"')
    expect(button(document, "deny")).toMatch(/class="btn secondary"/)
    expect(button(document, "approve")).toMatch(/class="btn primary"/)
    expect(document).not.toContain('class="bar warned"')
  })

  it("a warned page that offers a rule keeps both accepting actions quiet and off, Decline filled", () => {
    for (const h of HOSTILE) {
      const document = renderDocument(approvalWith((a, bad) => (a.title = `Comment ${bad}here`), galleryRuleApproval)(h.raw)).value
      expect(button(document, "deny"), h.marker).toMatch(/class="btn danger"/)
      for (const accept of ["approve", "approve-rule"]) {
        expect(button(document, accept), `${h.marker} ${accept}`).toMatch(/class="btn quiet"/)
        expect(button(document, accept), `${h.marker} ${accept}`).toMatch(/ disabled>/)
      }
      expect(main(document).replace(/data-boot="[^"]*"/, ""), h.marker).not.toContain(h.raw)
    }
    const plain = renderDocument(approvalWith(() => undefined, galleryRuleApproval)("")).value
    expect(button(plain, "approve-rule")).toMatch(/class="btn secondary"/)
    expect(button(plain, "approve")).toMatch(/class="btn primary"/)
  })

  it("a warned page that offers a task grant keeps all three accepting actions quiet and off, Decline filled", () => {
    for (const h of HOSTILE) {
      const document = renderDocument(approvalWith((a, bad) => (a.title = `Create ${bad}here`), galleryAreaApproval)(h.raw)).value
      expect(button(document, "deny"), h.marker).toMatch(/class="btn danger"/)
      for (const accept of ["approve", "approve-rule", "approve-area"]) {
        expect(button(document, accept), `${h.marker} ${accept}`).toMatch(/class="btn quiet"/)
        expect(button(document, accept), `${h.marker} ${accept}`).toMatch(/ disabled>/)
      }
    }
    const plain = renderDocument(approvalWith(() => undefined, galleryAreaApproval)("")).value
    expect(button(plain, "approve-area")).toMatch(/class="btn secondary"/)
  })

  // The task grant panel shows who asked and the account: each warns, and
  // the panel marks it.
  const AREA_PANEL_CASES: { field: string; page: (bad: string) => PageInput }[] = [
    { field: "machine name", page: approvalWith((a, bad) => (a.requestedBy = { ...a.requestedBy, deviceName: `mac${bad}office` }), galleryAreaApproval) },
    { field: "account", page: approvalWith((a, bad) => (a.item = { ...a.item, account: `cf${bad}account` }), galleryAreaApproval) },
  ]
  for (const c of AREA_PANEL_CASES) {
    for (const h of HOSTILE) {
      it(`a task grant panel's ${c.field} with ${h.marker} is warned, marked in the panel and never raw`, () => {
        const body = main(renderDocument(c.page(h.raw)).value)
        expect(body).toContain('data-region="warnings"')
        const panel = body.slice(body.indexOf('data-region="area-panel"'), body.indexOf("</section>", body.indexOf('data-region="area-panel"')))
        expect(panel.replace(/<[^>]+>/g, ""), h.marker).toContain(h.marker)
        expect(panel).not.toContain(h.raw)
        expect(body.replace(/data-boot="[^"]*"/, "")).not.toContain(h.raw)
      })
    }
  }

  // The panel of a rule offer shows who asked, the task, the account and
  // the project and environment: each warns, and the panel marks it.
  const RULE_PANEL_CASES: { field: string; page: (bad: string) => PageInput }[] = [
    { field: "machine name", page: approvalWith((a, bad) => (a.requestedBy = { ...a.requestedBy, deviceName: `mac${bad}office` }), galleryRuleApproval) },
    { field: "task label", page: approvalWith((a, bad) => { a.requestedBy = { device: "dev_kimlaptop1", deviceName: "kim-laptop", session: null, workload: { id: "wl_task8kq2mw4z", label: `globex${bad}grant` } }; a.rememberOptions = { route: null, rule: GALLERY_COSIGN_OFFER } }, galleryRuleApproval) },
    { field: "account", page: approvalWith((a, bad) => (a.item = { ...a.item, account: `alex${bad}northwind` }), galleryRuleApproval) },
    { field: "project", page: approvalWith((a, bad) => (a.details = [...a.details, { label: "Project", value: `plat${bad}form` }]), galleryRuleApproval) },
    { field: "environment", page: approvalWith((a, bad) => (a.details = [...a.details, { label: "Environment", value: `de${bad}v` }]), galleryRuleApproval) },
  ]
  for (const c of RULE_PANEL_CASES) {
    for (const h of HOSTILE) {
      it(`a rule panel's ${c.field} with ${h.marker} is warned, marked in the panel and never raw`, () => {
        const body = main(renderDocument(c.page(h.raw)).value)
        expect(body).toContain('data-region="warnings"')
        expect(body).toContain(h.warning.slice(0, 40))
        const panel = body.slice(body.indexOf('data-region="rule-panel"'), body.indexOf("</section>", body.indexOf('data-region="rule-panel"')))
        expect(panel.replace(/<[^>]+>/g, ""), h.marker).toContain(h.marker)
        expect(panel).not.toContain(h.raw)
        expect(body.replace(/data-boot="[^"]*"/, "")).not.toContain(h.raw)
      })
    }
  }

  for (const c of PROPOSAL_PANEL_CASES) {
    for (const h of HOSTILE) {
      it(`${c.field} with ${h.marker} is marked in the rule panel`, () => {
        const body = main(renderDocument(c.page(h.raw)).value)
        const panel = body.slice(body.indexOf('data-region="rule-panel"'), body.indexOf("</section>", body.indexOf('data-region="rule-panel"')))
        expect(panel.replace(/<[^>]+>/g, ""), h.marker).toContain(h.marker)
        expect(panel).not.toContain(h.raw)
      })
    }
  }

  it("a warned stop view keeps its one action Stop, filled danger", () => {
    const stop = workspaceAsksGallery().find((e) => e.id === "ws-approval-stop-hostile")
    const document = renderDocument(stop!.page).value
    expect(button(document, "deny")).toMatch(/class="btn danger"/)
    expect(document).not.toContain('data-action="approve"')
    expect(main(document)).not.toContain("\u202E")
    expect(main(document).indexOf('data-region="warnings"')).toBeGreaterThan(-1)
    expect(main(document).indexOf('data-region="warnings"')).toBeLessThan(main(document).indexOf('data-region="stop"'))
  })
})

describe("the per-page text lists", () => {
  it("name every string their page family shows", () => {
    const run = detail(galleryRunApproval(true, ["Tom"])).approval
    for (const text of [run.title, run.request.url, run.requestedBy.deviceName, run.workspace.name, "OPENAI_API_KEY", "Tom"]) expect(approvalTexts(run), text).toContain(text)
    const email = detail(galleryEmailApproval()).approval
    for (const text of ["priya@acme.example", "Quarterly numbers", "Hi Priya, the numbers are attached.", "X-Goog-Request-Reason", "quarterly-report"]) expect(approvalTexts(email), text).toContain(text)
    // A rule offer: every path the panel offers and each string of its terms.
    const ruled = detail(galleryRuleApproval({ ...GALLERY_RULE_OFFER, terms: { ...GALLERY_RULE_TERMS, item: "github-rule", queryNames: ["per_page"] } } as PolicyRuleOffer)).approval
    for (const text of ["/repos/northwind/platform/issues/*/comments", "github-rule", "itm_github01", "api.github.com", "per_page"]) expect(approvalTexts(ruled), text).toContain(text)
    const cosigned = detail(galleryRuleApproval(GALLERY_COSIGN_OFFER)).approval
    for (const text of ["commentCreate", "success", "wl_task8kq2mw4z", "dev_kimlaptop1"]) expect(approvalTexts(cosigned), text).toContain(text)
    // A task grant offer: every area the panel lists and its terms.
    const granted = detail(galleryAreaApproval()).approval
    for (const text of ["DNS records", "Adds A, AAAA and CNAME records", "itm_cloudflare1", "api.cloudflare.com", "cloudflare-api-token"]) expect(approvalTexts(granted), text).toContain(text)
    for (const text of ["The staging deploy needs a key.", "openai-staging", "api.openai.com", "API key", "mac-mini"]) expect(intakeTexts(INTAKE_FIXTURE), text).toContain(text)
    for (const text of ["Read the support inbox.", "alex@northwind.example", "https://www.googleapis.com/auth/gmail.readonly", "gmail-alex"]) expect(connectTexts(CONNECT_FIXTURE), text).toContain(text)
    for (const text of ["tom-laptop", "toms-mbp.local", "Amsterdam, NL", "mehen 0.2.0 on macOS"]) expect(enrolTexts(PEOPLE_ENROL), text).toContain(text)
    expect(stopTexts({ view: "stop", id: "apr_1", workspace: run.workspace, machine: { device: "dev_1", name: "kim-laptop", owner: { kind: "member", member: "mem_1", name: "Kim" } }, item: { slug: "github-kim" }, status: "pending", eligibility: run.eligibility })).toEqual(expect.arrayContaining(["kim-laptop", "Kim", "github-kim"]))
  })
})

// Every state of every family is warned over what it shows,
// including what the page resolves around the view (project names, the
// credentials a team's admission delegates, the homes offered).
type StateCase = { name: string; page: (bad: string) => PageInput; decline: string | null; head?: string }

function enrolData(edit: (v: WorkspaceEnrolView, bad: string) => void, data: (bad: string) => { projects?: typeof PEOPLE_PROJECTS; delegation?: string[] | null; role?: "owner" | "member" } = () => ({})): (bad: string) => PageInput {
  return (bad) => {
    const view = structuredClone(PEOPLE_ENROL)
    edit(view, bad)
    const extra = data(bad)
    return enrolmentPage(peopleShell(extra.role ?? "member", { member: "mem_tom01" }), view, { viewer: { member: "mem_tom01", role: extra.role ?? "member", blocked: false }, projects: extra.projects ?? PEOPLE_PROJECTS, now: 0, ...(extra.delegation !== undefined ? { delegation: extra.delegation } : {}) })
  }
}

const STATES: StateCase[] = [
  { name: "lapsed enrolment, machine name", page: enrolData((v, bad) => { v.name = `tom${bad}laptop`; v.lease = "lapsed"; v.actions = ["reject"] }, () => ({ role: "owner" })), decline: "enrol-reject" },
  { name: "terminal enrolment, machine name", page: enrolData((v, bad) => { v.name = `tom${bad}laptop`; v.state = "rejected"; v.lease = "terminal"; v.actions = [] }), decline: null },
  { name: "enrolment, a scope project's name", page: enrolData((v) => { v.scope = { ...v.scope, projects: ["prj_platform01"] } }, (bad) => ({ projects: [{ ...PEOPLE_PROJECTS[0]!, slug: `plat${bad}form` }] })), decline: "enrol-reject" },
  { name: "team admission, a delegated credential", page: enrolData((v) => { v.requestedOwner = { kind: "team", team: "tm_platform01", name: "Platform" }; v.actions = ["admit", "reject"] }, (bad) => ({ role: "owner", delegation: [`openai${bad}-shared`] })), decline: "enrol-reject" },
  { name: "connect outcome, the account signed in", page: connectWith((v, bad) => { v.status = "mismatch"; v.account = `bob${bad}@example.com` }), decline: null },
  { name: "connect waiting for its client, the reason", page: connectWith((v, bad) => { v.reason = `Read${bad} mail.`; v.awaiting = { intake: "int_client01", url: "https://app.mehen.dev/w/northwind/i/int_client01", status: "open" } }), decline: null },
  { name: "intake completed, the name it was saved as", page: intakeWith((v, bad) => { v.status = "completed"; v.slug = `openai${bad}` }), decline: null },
  { name: "live intake, a project home offered", page: (bad) => workspaceIntakePage(galleryShell(VIEWERS.owner), structuredClone(INTAKE_FIXTURE), [{ ...PEOPLE_PROJECTS[0]!, slug: `plat${bad}form` }], 0), decline: "cancel-request", head: 'class="card decision intake-head warned"' },
  { name: "live connect, the reason", page: connectWith((v, bad) => (v.reason = `Read${bad} mail.`)), decline: "cancel-request", head: 'class="card decision connect-head warned"' },
]

describe("every state warns over what it shows", () => {
  for (const c of STATES) {
    for (const h of HOSTILE) {
      it(`${c.name} with ${h.marker}`, () => {
        const document = renderDocument(c.page(h.raw)).value
        const body = main(document)
        expect(body.replace(/<[^>]+>/g, ""), "marker").toContain(h.marker)
        expect(body.replace(/data-boot="[^"]*"/, ""), "raw").not.toContain(h.raw)
        expect(body).toContain('role="alert" data-region="warnings"')
        expect(body).toContain(h.warning.slice(0, 40))
        const firstSection = body.search(/<section|<details/)
        expect(body.indexOf('data-region="warnings"')).toBeLessThan(firstSection)
        if (c.decline !== null) expect(button(document, c.decline)).toMatch(/class="btn danger"/)
        if (c.head !== undefined) expect(body).toContain(c.head)
      })
    }
  }

  it("a terminal enrolment gains no action from being warned", () => {
    const document = renderDocument(STATES[1]!.page("\u202E")).value
    expect(main(document)).not.toMatch(/data-action="enrol-(accept|admit|reject)"/)
  })

  it("an unwarned lapsed Reject stays the quiet danger outline", () => {
    const document = renderDocument(enrolData((v) => { v.lease = "lapsed"; v.actions = ["reject"] }, () => ({ role: "owner" }))("")).value
    expect(button(document, "enrol-reject")).toMatch(/class="btn danger-quiet"/)
    expect(document).not.toContain('data-region="warnings"')
  })
})
