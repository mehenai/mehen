// The browser handlers PM added to client/pages/people.ts, run against the pages the server renders
// (test/mini-dom.ts) with the API answered by the test: Connect an agent's
// connect-code fetch and its fallback, the person's role picker, the
// confirmation anchor from Needs you (a malformed one ignored), and Reject
// on a scope proposal, with the passkey prompt stubbed.
import { afterEach, describe, expect, it, vi } from "vitest"
import type { RescopeProposalView, WorkspaceDeviceView, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { renderDocument } from "../src/ui/layout.ts"
import { connectAgentPage } from "../src/ui/pages/connect-agent.ts"
import { machinePage } from "../src/ui/pages/machines.ts"
import { peoplePage } from "../src/ui/pages/people.ts"
import { GUEST_SHARED_PROJECTS, HOSTILE_NAME, PEOPLE_DEVICE, PEOPLE_INVITES, PEOPLE_PROJECTS, THUMBPRINT, peopleData, peopleShell } from "../src/ui/people-gallery.ts"
import { RESCOPE_REJECTED_WORDS } from "../src/ui/client/people-logic.ts"
import { CHANGED_SINCE_SHOWN } from "../src/ui/client/workspace-logic.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { initConnectAgent, initMachine, initPeople } from "../src/ui/client/pages/people.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle, submit } from "./mini-dom.ts"

vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => ({ id: "test-assertion" }),
}))

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

type Answer = { status: number; body: unknown }

function open(markup: string, respond: (path: string, body: unknown) => Answer, href?: string): MiniBrowser {
  browser = installPage(markup, respond, href)
  return browser
}

const $ = (selector: string): MiniElement => {
  const found = browser!.document.querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}

function shell(): ShellState {
  return new ShellState({ origin: "https://app.mehen.dev", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }, pages: [], reads: [] })
}

const connectPage = () => renderDocument(connectAgentPage(peopleShell("member"))).value
const code = (box: string) => $(`[data-box="${box}"] code`).textContent
const copyDisabled = (box: string) => $(`[data-box="${box}"] button`).disabled

describe("Connect an agent: the connect code", () => {
  it("asks the issuer once, then fills the prompt and the enrol box with the code and enables them", async () => {
    const page = open(connectPage(), () => ({ status: 200, body: { code: "7XK2M9QP", expiresAt: "2026-10-28T18:30:00.000Z" } }))
    expect(copyDisabled("prompt")).toBe(true)
    expect(copyDisabled("enrol")).toBe(true)
    expect(copyDisabled("install")).toBe(false)
    initConnectAgent({ page: "connect-agent" }, shell())
    await settle()
    expect(page.calls).toEqual([{ path: "/api/w/northwind/connect-code", body: {} }])
    expect(code("prompt")).toBe("Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev with connect code 7XK2M9QP. I will approve it in my browser; never ask me for a key, password or secret.")
    expect(code("enrol")).toBe("mehen enrol --workspace northwind --connect 7XK2M9QP")
    expect(code("install")).toBe("curl -fsSL https://mehen.dev/install | sh")
    expect(code("setup")).toBe("mehen setup")
    expect(copyDisabled("prompt")).toBe(false)
    expect(copyDisabled("enrol")).toBe(false)
    expect($('[data-region="connect-code-note"]').hidden).toBe(false)
    expect($('[data-region="connect-code-waiting"]').hidden).toBe(true)
  })

  it("works without a code: a vault that issues none leaves the boxes as served, enabled, and says nothing", async () => {
    open(connectPage(), () => ({ status: 404, body: { error: "not_found", message: "Not found.", next: { say: "Check the address." } } }))
    initConnectAgent({ page: "connect-agent" }, shell())
    await settle()
    expect(code("prompt")).toBe("Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret.")
    expect(code("enrol")).toBe("mehen enrol --workspace northwind")
    expect(copyDisabled("prompt")).toBe(false)
    expect(copyDisabled("enrol")).toBe(false)
    expect($('[data-region="connect-code-refused"]').hidden).toBe(true)
    expect($('[data-region="connect-code-note"]').hidden).toBe(true)
  })

  it("on a refusal shows the vault's words and keeps the boxes without --connect", async () => {
    open(connectPage(), () => ({ status: 429, body: { error: "rate_limited", message: "Too many connect codes.", retryAfter: 60, next: { say: "Wait a minute, then reload the page for a connect code." } } }))
    initConnectAgent({ page: "connect-agent" }, shell())
    await settle()
    expect(code("enrol")).toBe("mehen enrol --workspace northwind")
    expect($('[data-region="connect-code-refused"]').hidden).toBe(false)
    expect($('[data-region="connect-code-refused"]').textContent).toBe("Wait a minute, then reload the page for a connect code.")
    expect(copyDisabled("enrol")).toBe(false)
  })

  it("never copies an answer that is not a code in the issuer's alphabet", async () => {
    for (const bad of ["7XK2M9QP; curl evil", "<b>x</b>", "7xk2m9qp", 42]) {
      open(connectPage(), () => ({ status: 200, body: { code: bad, expiresAt: "2026-10-28T18:30:00.000Z" } }))
      initConnectAgent({ page: "connect-agent" }, shell())
      await settle()
      expect(code("enrol"), String(bad)).toBe("mehen enrol --workspace northwind")
      expect(code("prompt"), String(bad)).not.toContain("connect code")
      expect(copyDisabled("enrol")).toBe(false)
      browser?.restore()
    }
  })
})

describe("people: the role picker and the confirmation anchor", () => {
  it("keeps Change role disabled until a role is chosen, and marks owner as widening", () => {
    open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, () => ({ status: 200, body: {} }))
    initPeople({ page: "people" }, shell())
    const select = $('[data-input="member-role"][data-member="mem_noor01"]')
    const button = $('[data-action="member-role"][data-member="mem_noor01"]')
    expect(select.value).toBe("")
    expect(button.disabled).toBe(true)
    select.value = "member"
    select.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    expect(button.disabled).toBe(false)
    expect(button.classList.contains("widen")).toBe(false)
    select.value = "owner"
    select.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    expect(button.classList.contains("widen")).toBe(true)
  })

  it("opens a person's confirmation from #confirm-<member>, reading the terms", async () => {
    const page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, () => ({ status: 200, body: { action: { type: "member.confirm", termsDigest: "dgst_hostile_terms" } } }), "https://vault.test/w/northwind/people#confirm-mem_hostile01")
    initPeople({ page: "people" }, shell())
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual(["/api/w/northwind/members/mem_hostile01/action"])
    expect($("#confirm-mem_hostile01").hidden).toBe(false)
  })

  // A bad bookmark or a supplied link: a lone %, a malformed UTF-8 escape,
  // or a well-formed member who is not on the page.
  for (const fragment of ["#confirm-%", "#confirm-%C3%28", "#confirm-mem_nobody01"]) {
    it(`ignores ${fragment} and keeps Remove and invitation Revoke working`, async () => {
      const page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, () => ({ status: 200, body: {} }), `https://vault.test/w/northwind/people${fragment}`)
      expect(() => initPeople({ page: "people" }, shell())).not.toThrow()
      await settle()
      expect(page.calls).toEqual([])
      $('[data-action="member-remove"][data-member="mem_tom01"]').click()
      await settle()
      expect(page.calls[0]?.path).toBe("/api/w/northwind/members/mem_tom01/action")
      const revoke = $('[data-action="invite-revoke"]')
      revoke.click()
      await settle()
      expect(page.calls.map((c) => c.path).at(-1)).toBe(`/api/w/northwind/invites/${revoke.dataset.invite}/revoke`)
    })
  }
})

describe("people: making an invitation", () => {
  const MADE = { ...PEOPLE_INVITES[0]!, id: "inv_new01", terms: { ...PEOPLE_INVITES[0]!.terms, email: "ravi@northwind.example", teams: [] }, boundEmail: "ravi@northwind.example" }
  const after = () => renderDocument(peoplePage(peopleShell("owner"), { ...peopleData("owner"), invites: [MADE, ...PEOPLE_INVITES] })).value
  let outcome: string | null = null
  afterEach(() => { outcome = null })
  const vault = (path: string, body?: unknown): Answer => {
    if (path === "/api/w/northwind/stepup/start") return { status: 200, body: { nonce: "nonce_1", options: { challenge: "c" } } }
    if (path === "/api/w/northwind/invites") return { status: 201, body: { invite: MADE, url: "https://app.mehen.dev/signup#the-code", emailed: outcome ?? ((body as { email: boolean }).email ? "sent" : "not_requested") } }
    if (path === "/w/northwind/people") return { status: 200, body: after() }
    return { status: 200, body: {} }
  }

  it("shows the link and lists the new invitation without a reload, its Revoke wired", async () => {
    const page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    expect(browser!.document.querySelector('[data-region="invites"] [data-invite="inv_new01"]')).toBeNull()
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    submit($('[data-form="invite"]'))
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual(["/api/w/northwind/stepup/start", "/api/w/northwind/invites", "/w/northwind/people"])
    expect($('[data-region="invite-made"]').hidden).toBe(false)
    expect($('[data-region="invite-url"]').textContent).toBe("https://app.mehen.dev/signup#the-code")
    expect(browser!.document.querySelectorAll('[data-region="invites"]')).toHaveLength(1)
    expect($('[data-region="invites"] [data-invite="inv_new01"]').textContent).toContain("ravi@northwind.example")
    expect(page.reloaded).toBe(0)
    $('[data-action="invite-revoke"][data-invite="inv_new01"]').click()
    await settle()
    expect(page.calls.at(-1)?.path).toBe("/api/w/northwind/invites/inv_new01/revoke")
  })

  const sentTerms = (page: MiniBrowser) => (page.calls.find((c) => c.path === "/api/w/northwind/invites")?.body as { terms: { onJoin?: string } } | undefined)?.terms

  it("signs onJoin activate by default, and confirm when the inviter ticks Confirm them myself; the words above the link say which", async () => {
    let page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    expect($('[data-region="invite-confirm-myself"]').hidden).toBe(false)
    expect(($('[data-input="invite-confirm-myself"]') as MiniElement & { checked: boolean }).checked).toBe(false)
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    submit($('[data-form="invite"]'))
    await settle()
    expect(sentTerms(page)?.onJoin).toBe("activate")
    expect($('[data-region="invite-made-lead"]').textContent).toBe("Mehen emailed this link to ravi@northwind.example. It works once, and only for that email: they join straight away once they prove it.")
    expect($('[data-region="invite-message"]').textContent).toContain("Then you connect your agent.")
    browser?.restore()

    page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    ;($('[data-input="invite-confirm-myself"]') as MiniElement & { checked: boolean }).checked = true
    submit($('[data-form="invite"]'))
    await settle()
    expect(sentTerms(page)?.onJoin).toBe("confirm")
    expect($('[data-region="invite-made-lead"]').textContent).toBe("Mehen emailed this link to ravi@northwind.example. It works once; nobody can use the workspace until an owner or admin confirms them.")
    expect($('[data-region="invite-message"]').textContent).toContain("I confirm you once you have joined")
  })

  const sentBody = (page: MiniBrowser) => page.calls.find((c) => c.path === "/api/w/northwind/invites")?.body as { email: boolean } | undefined

  it("ticks Email the link to them by default for an email, and asks the vault to send it only while ticked", async () => {
    let page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    expect($('[data-region="invite-email-link"]').hidden).toBe(false)
    expect(($('[data-input="invite-email-link"]') as MiniElement & { checked: boolean }).checked).toBe(true)
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    submit($('[data-form="invite"]'))
    await settle()
    expect(sentBody(page)?.email).toBe(true)
    browser?.restore()

    page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    ;($('[data-input="invite-email-link"]') as MiniElement & { checked: boolean }).checked = false
    submit($('[data-form="invite"]'))
    await settle()
    expect(sentBody(page)?.email).toBe(false)
    expect($('[data-region="invite-made-lead"]').textContent).toBe("Send this link to the person you invited. It works once, and only for that email: they join straight away once they prove it.")
    expect($('[data-region="invite-url"]').textContent).toBe("https://app.mehen.dev/signup#the-code")
  })

  for (const [emailed, words] of [
    ["sent", "Mehen emailed this link to ravi@northwind.example."],
    ["limited", "This link was not emailed: too many invitation emails have gone from your account or to this address lately. Send it to them yourself."],
    ["failed", "This link could not be emailed. Send it to them yourself."],
  ] as const) it(`says what became of the email when the vault answers ${emailed}, with the link to copy`, async () => {
    outcome = emailed
    open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    submit($('[data-form="invite"]'))
    await settle()
    expect($('[data-region="invite-made-lead"]').textContent).toBe(`${words} It works once, and only for that email: they join straight away once they prove it.`)
    expect($('[data-region="invite-made"]').hidden).toBe(false)
    expect($('[data-region="invite-url"]').textContent).toBe("https://app.mehen.dev/signup#the-code")
    expect($("#notice").hidden).toBe(true)
  })

  it("never asks to email an open guest link, and hides the tick for one", async () => {
    const page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    const form = $('[data-form="invite"]')
    $('[data-input="invite-role"]').value = "guest"
    ;($('[data-input="invite-binding"][value="email"]') as MiniElement & { checked: boolean }).checked = false
    ;($('[data-input="invite-binding"][value="open"]') as MiniElement & { checked: boolean }).checked = true
    ;($('[data-share="prj_site01"] [data-input="invite-project"]') as MiniElement & { checked: boolean }).checked = true
    form.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    expect($('[data-region="invite-email-link"]').hidden).toBe(true)
    submit(form)
    await settle()
    expect(sentBody(page)).toMatchObject({ terms: { email: null }, email: false })
  })

  it("hides Confirm them myself for an owner invitation and an open guest link, which always wait", () => {
    open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, vault, "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    const role = $('[data-input="invite-role"]'), form = $('[data-form="invite"]'), choice = () => $('[data-region="invite-confirm-myself"]').hidden
    const change = () => form.dispatchEvent(new MiniEvent("change", { bubbles: true }))
    role.value = "owner"
    change()
    expect(choice()).toBe(true)
    role.value = "guest"
    change()
    expect(choice()).toBe(false)
    ;($('[data-input="invite-binding"][value="email"]') as MiniElement & { checked: boolean }).checked = false
    ;($('[data-input="invite-binding"][value="open"]') as MiniElement & { checked: boolean }).checked = true
    change()
    expect(choice()).toBe(true)
  })

  it("keeps the link on screen and the list as it was when the page cannot be read again", async () => {
    const page = open(renderDocument(peoplePage(peopleShell("owner"), peopleData("owner"))).value, (path, body) => (path === "/w/northwind/people" ? { status: 500, body: { error: "internal", message: "Down." } } : vault(path, body)), "https://vault.test/w/northwind/people")
    initPeople({ page: "people" }, shell())
    $('[data-input="invite-email"]').value = "ravi@northwind.example"
    submit($('[data-form="invite"]'))
    await settle()
    expect($('[data-region="invite-made"]').hidden).toBe(false)
    expect($('[data-region="invites"] [data-invite="inv_open01"]')).toBeTruthy()
    expect($("#notice").hidden).toBe(true)
    expect(page.reloaded).toBe(0)
  })
})

// Reject on the machine page's scope proposal: the plan must be exactly the
// device.rescope_reject the card carries before a passkey is asked; the
// owning account sends the proposal alone, the admission signer its project.
describe("Reject on a scope proposal", () => {
  const ACCOUNT = "acc_4Hq9Tz2Lm7Vb1Nc8"
  const NOW = Date.parse("2026-10-27T18:30:00Z")
  const base = "/api/w/northwind/devices/dev_tomlaptop01"
  const pending = (proposer: string, signers: RescopeProposalView["requiredSigners"]): RescopeProposalView => ({ id: "rsp_w", device: PEOPLE_DEVICE.device, thumbprint: THUMBPRINT, before: PEOPLE_DEVICE.scope, after: { ...PEOPLE_DEVICE.scope, maxEnvironment: "protected" }, beforeDigest: "b", afterDigest: "a", proposer: { member: "mem_alex01", name: proposer }, requiredSigners: signers, signedBy: [], expiresAt: "2026-10-28T18:30:00.000Z", state: "open" })
  // Tom's own machine, plain or with a hostile proposer (Reject emphasised).
  const ownPage = (proposer = "Alex Rae") => {
    const device = { ...PEOPLE_DEVICE, pendingRescope: pending(proposer, [{ account: ACCOUNT, name: "Tom Barker", as: "owner_acceptance" }]) }
    return { device, markup: renderDocument(machinePage(peopleShell("member", { member: "mem_tom01" }), device, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: PEOPLE_PROJECTS, now: NOW })).value }
  }
  // Gina's machine, with Noor (this account) as the admission signer.
  const admissionPage = () => {
    const device = { ...PEOPLE_DEVICE, owner: { kind: "member" as const, member: "mem_guest01", name: "Gina (contractor)" }, pendingRescope: pending("Alex Rae", [{ name: "Gina (contractor)", as: "owner_acceptance" }, { account: ACCOUNT, name: "Noor Eddial", as: "admission" }]) }
    return { device, markup: renderDocument(machinePage(peopleShell("admin", { member: "mem_noor01" }), device, { viewer: { member: "mem_noor01", role: "admin", blocked: false }, projects: GUEST_SHARED_PROJECTS, now: NOW })).value }
  }
  const boot = (device: WorkspaceDeviceView) => ({ page: "machine", device: device.device, scope: device.scope, owner: device.owner, propose: true })
  const REJECT: WorkspaceStepUpAction = { type: "device.rescope_reject", device: "dev_tomlaptop01", thumbprint: THUMBPRINT, proposal: "rsp_w" }
  const refusalOf = (error: string, message: string) => ({ status: error === "conflict" ? 409 : 404, body: { error, message, next: { say: "Reload the page to see the machine as it is now." } } })
  // The vault as the test answers it: the plan, the step-up start and the send.
  const vault = (answers: { plan?: Answer; send?: Answer } = {}) => (path: string): Answer => {
    if (path.endsWith("/action")) return answers.plan ?? { status: 200, body: { action: REJECT } }
    if (path === "/api/w/northwind/stepup/start") return { status: 200, body: { nonce: "nonce_1", options: { challenge: "c" } } }
    return answers.send ?? { status: 200, body: { ...pending("Alex Rae", []), state: "rejected" } }
  }
  const STEP_UP = { nonce: "nonce_1", assertion: { id: "test-assertion" } }

  for (const [kind, proposer] of [["plain", "Alex Rae"], ["warned", HOSTILE_NAME]] as const) {
    it(`${kind}: signs exactly the terms the card shows, sends the proposal alone, then says it was rejected and nothing changed`, async () => {
      const { device, markup } = ownPage(proposer)
      const page = open(markup, vault())
      initMachine(boot(device), shell())
      const card = $('[data-region="proposal"]')
      // The terms the page shows are the ones the passkey signs.
      expect({ type: "device.rescope_reject", device: card.dataset.device, thumbprint: card.dataset.thumbprint, proposal: card.dataset.proposal }).toEqual(REJECT)
      expect(card.dataset.project).toBeUndefined()
      expect($('[data-action="rescope-reject"]').classList.contains(kind === "warned" ? "danger" : "quiet")).toBe(true)
      $('[data-action="rescope-reject"]').click()
      await settle()
      expect(page.calls).toEqual([
        { path: `${base}/action`, body: { change: { kind: "rescope_reject", proposal: "rsp_w" } } },
        { path: "/api/w/northwind/stepup/start", body: { action: REJECT } },
        { path: `${base}/rescope-reject`, body: { proposal: "rsp_w", stepUp: STEP_UP } },
      ])
      expect($('[data-region="rescope-actions"]').hidden).toBe(true)
      const said = $('[data-region="rescope-rejected"]')
      expect(said.hidden).toBe(false)
      expect(said.textContent).toBe(RESCOPE_REJECTED_WORDS)
      expect(said.textContent).toBe("You rejected this proposal. Nothing changed on this machine: it may use exactly what it could before.")
      expect(page.reloaded).toBe(0)
      expect($("#notice").hidden).toBe(true)
    })
  }

  // Each differs from what the card shows in one term.
  for (const [why, planned] of [
    ["another proposal", { ...REJECT, proposal: "rsp_other" }],
    ["another key", { ...REJECT, thumbprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    ["another machine", { ...REJECT, device: "dev_other" }],
    ["an acceptance", { type: "device.rescope_accept", device: "dev_tomlaptop01", thumbprint: THUMBPRINT, account: ACCOUNT, before: PEOPLE_DEVICE.scope, after: PEOPLE_DEVICE.scope, admission: false }],
  ] as const) {
    it(`refuses a plan for ${why} with no passkey and nothing sent`, async () => {
      const { device, markup } = ownPage()
      const page = open(markup, vault({ plan: { status: 200, body: { action: planned } } }))
      initMachine(boot(device), shell())
      $('[data-action="rescope-reject"]').click()
      await settle()
      expect(page.calls.map((c) => c.path)).toEqual([`${base}/action`])
      expect($("#notice").textContent).toContain(CHANGED_SINCE_SHOWN.message)
      expect($('[data-region="rescope-rejected"]').hidden).toBe(true)
      expect($('[data-region="rescope-actions"]').hidden).toBe(false)
    })
  }

  it("on a 409 after the passkey shows the vault's message and claims nothing", async () => {
    const { device, markup } = ownPage()
    const page = open(markup, vault({ send: refusalOf("conflict", "This scope proposal was already accepted.") }))
    initMachine(boot(device), shell())
    $('[data-action="rescope-reject"]').click()
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual([`${base}/action`, "/api/w/northwind/stepup/start", `${base}/rescope-reject`])
    expect($("#notice").hidden).toBe(false)
    expect($("#notice").textContent).toContain("This scope proposal was already accepted.")
    expect($('[data-region="rescope-rejected"]').hidden).toBe(true)
    expect($('[data-region="rescope-actions"]').hidden).toBe(false)
    expect(page.reloaded).toBe(0)
  })

  it("on a 409 or 404 from the plan shows the vault's message and asks no passkey", async () => {
    for (const [error, message] of [["conflict", "This scope proposal expired or changed. Review a new proposal."], ["not_found", "No such scope proposal."]] as const) {
      const { device, markup } = ownPage()
      const page = open(markup, vault({ plan: refusalOf(error, message) }))
      initMachine(boot(device), shell())
      $('[data-action="rescope-reject"]').click()
      await settle()
      expect(page.calls.map((c) => c.path), error).toEqual([`${base}/action`])
      expect($("#notice").textContent, error).toContain(message)
      expect($('[data-region="rescope-rejected"]').hidden, error).toBe(true)
      browser?.restore()
    }
  })

  it("on a 404 after the passkey shows the vault's message", async () => {
    const { device, markup } = ownPage()
    open(markup, vault({ send: refusalOf("not_found", "No such machine.") }))
    initMachine(boot(device), shell())
    $('[data-action="rescope-reject"]').click()
    await settle()
    expect($("#notice").textContent).toContain("No such machine.")
    expect($('[data-region="rescope-rejected"]').hidden).toBe(true)
  })

  it("the admission signer's Reject and Admit both send the card's project; the owner's Accept sends the proposal alone", async () => {
    const { device, markup } = admissionPage()
    const rejecting = open(markup, vault())
    initMachine(boot(device), shell())
    expect($('[data-region="proposal"]').dataset.project).toBe("prj_site01")
    $('[data-action="rescope-reject"]').click()
    await settle()
    expect(rejecting.calls).toEqual([
      { path: `${base}/action`, body: { change: { kind: "rescope_reject", proposal: "rsp_w" }, project: "prj_site01" } },
      { path: "/api/w/northwind/stepup/start", body: { action: REJECT } },
      { path: `${base}/rescope-reject`, body: { proposal: "rsp_w", project: "prj_site01", stepUp: STEP_UP } },
    ])
    browser?.restore()

    const ADMIT: WorkspaceStepUpAction = { type: "device.rescope", device: "dev_tomlaptop01", thumbprint: THUMBPRINT, before: PEOPLE_DEVICE.scope, after: { ...PEOPLE_DEVICE.scope, maxEnvironment: "protected" } }
    const admitting = open(markup, (path) => (path.endsWith("/action") ? { status: 200, body: { action: ADMIT } } : vault()(path)))
    initMachine(boot(device), shell())
    $('[data-action="rescope-admit"]').click()
    await settle()
    expect(admitting.calls).toEqual([
      { path: `${base}/action`, body: { change: { kind: "rescope_admit", proposal: "rsp_w" }, project: "prj_site01" } },
      { path: "/api/w/northwind/stepup/start", body: { action: ADMIT } },
      { path: `${base}/rescope-admit`, body: { proposal: "rsp_w", project: "prj_site01", stepUp: STEP_UP } },
    ])
    expect(admitting.reloaded).toBe(1)
    browser?.restore()

    const own = ownPage()
    const accepting = open(own.markup, (path) => (path.endsWith("/action") ? { status: 200, body: { action: { type: "device.rescope_accept" } } } : vault()(path)))
    initMachine(boot(own.device), shell())
    $('[data-action="rescope-accept"]').click()
    await settle()
    expect(accepting.calls[0]).toEqual({ path: `${base}/action`, body: { change: { kind: "rescope_accept", proposal: "rsp_w" } } })
    expect(accepting.calls[2]).toEqual({ path: `${base}/rescope-accept`, body: { proposal: "rsp_w", stepUp: STEP_UP } })
  })
})
