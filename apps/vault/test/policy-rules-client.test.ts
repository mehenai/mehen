// Stop and Extend on the "Allowed without asking" card, run through the
// real machine and credential page handlers (client/pages/people.ts,
// client/pages/workspace.ts, which wire client/pages/policy-rules.ts)
// against the gallery's server-rendered pages (test/mini-dom.ts), with the
// vault answered by the test and the passkey prompt stubbed.
import { afterEach, describe, expect, it, vi } from "vitest"
import { policyRuleExtendDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import type { PolicyRuleView } from "@mehen/protocol/policy-mode"
import { renderDocument } from "../src/ui/layout.ts"
import { policyRulesGallery } from "../src/ui/policy-rules-gallery.ts"
import { ruleTermsOf, stoppedOnlyRow } from "../src/ui/policy-rules-row.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { initMachine } from "../src/ui/client/pages/people.ts"
import { initWorkspaceCredential } from "../src/ui/client/pages/workspace.ts"
import { CHANGED_SINCE_SHOWN } from "../src/ui/client/workspace-logic.ts"
import { type MiniBrowser, MiniElement, installPage, parseHtml, settle } from "./mini-dom.ts"
import { galleryGrant, galleryRule } from "../src/ui/policy-rules-gallery.ts"
import { workspaceCredentialPage } from "../src/ui/pages/workspace-credentials.ts"
import { GALLERY_NOW } from "../src/ui/shell-gallery.ts"
import { GALLERY_ITEMS, VIEWERS, description, galleryShell } from "../src/ui/workspace-projects-gallery.ts"

// hold: the passkey prompt stays open until the test releases it.
// cancel: the person closes it, as the browser reports.
const passkeys = vi.hoisted(() => ({ count: 0, hold: null as Promise<void> | null, cancel: false }))
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => {
    passkeys.count++
    await passkeys.hold
    if (passkeys.cancel) throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError")
    return { id: "test-assertion" }
  },
}))

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
  passkeys.count = 0
  passkeys.hold = null
  passkeys.cancel = false
})

const WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const CHAT = "rul_tomchat0001"
const BASE = `/api/w/northwind/policy/rules/${CHAT}`
type Answer = { status: number; body: unknown }
const ok = (body: unknown): Answer => ({ status: 200, body })

function entry(id: string) {
  const found = policyRulesGallery().find((e) => e.id === id)
  if (!found) throw new Error(`no gallery entry ${id}`)
  return found
}

function shell(): ShellState {
  return new ShellState({ origin: "https://app.mehen.dev", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace: WORKSPACE, pages: [], reads: [] })
}

// The machine page as the server renders it for its owner, wired.
function openMachine(respond: (path: string, body: unknown) => Answer): MiniBrowser {
  const page = entry("machine-rules").page
  browser = installPage(renderDocument(page).value, respond, "https://app.mehen.dev/w/northwind/devices/dev_tomlaptop01")
  initMachine(page.boot, shell())
  return browser
}

const $ = (selector: string, root?: MiniElement): MiniElement => {
  const found = (root ?? browser!.document).querySelector(selector)
  if (!found) throw new Error(`no ${selector}`)
  return found
}
const row = (rule: string) => $(`[data-region="rule"][data-rule="${rule}"]`)
const outcome = (rule: string) => $('[data-region="rule-outcome"]', row(rule))
// Focus is on the row's outcome, which takes it without being a tab stop.
const focusedOnOutcome = (rule: string) => browser!.document.activeElement === outcome(rule) && outcome(rule).getAttribute("tabindex") === "-1"
const line = () => $('[data-region="policy-rules-line"]')

// An element as its tags, attributes and text, blank text left out.
type Shape = [string, [string, string][], (Shape | string)[]]
function shape(element: MiniElement): Shape {
  const children = element.childNodes.flatMap((c) => (c instanceof MiniElement ? [shape(c)] : c.textContent.trim() === "" ? [] : [c.textContent]))
  return [element.localName, [...element.attributes].sort(([a], [b]) => a.localeCompare(b)), children]
}

function chatView(over: Partial<PolicyRuleView>): PolicyRuleView {
  return { item: "openai-shared", itemId: "itm_openaishared", asker: { device: "dev_tomlaptop01", workload: null }, method: "POST", host: "api.openai.com", path: "/v1/chat/completions", anchorPath: "/v1/chat/completions", queryNames: [], graphql: null, ttlSeconds: 604_800, id: CHAT, approvedBy: "Tom Barker", coSignedBy: null, context: null, createdAt: "2026-10-25T18:30:00.000Z", endsAt: "2026-11-01T18:30:00.000Z", uses: 14, lastUsedAt: "2026-10-27T18:18:00.000Z", status: "active", endedReason: null, ...over }
}

describe("Stop", () => {
  it("posts revoke with no passkey, then the row says Stopped and why, offers neither Stop nor Extend, and the line counts one fewer", async () => {
    const page = openMachine((path) => {
      if (path === `${BASE}/revoke`) return ok(chatView({ status: "ended", endedReason: "revoked", endsAt: "2026-10-27T18:31:00.000Z" }))
      if (path === "/api/w/northwind/policy/rules/rul_tomlinear001/revoke") return ok(chatView({ id: "rul_tomlinear001", status: "ended", endedReason: "revoked" }))
      return { status: 404, body: { error: "not_found", message: "No." } }
    })
    expect(line().textContent.trim()).toBe("2 requests allowed without asking")
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect(page.calls).toEqual([{ path: `${BASE}/revoke`, body: {} }])
    expect(passkeys.count).toBe(0)
    const stopped = row(CHAT)
    expect(stopped.getAttribute("data-rule-state")).toBe("ended")
    expect($('[data-region="rule-status"]', stopped).textContent).toBe("Stopped")
    expect($('[data-region="rule-ended"]', stopped).hidden).toBe(false)
    expect($('[data-region="rule-ended"]', stopped).textContent).toBe("It was stopped.")
    expect($('[data-region="rule-ends-label"]', stopped).textContent).toBe("Ended")
    expect($('[data-region="rule-ends"]', stopped).textContent).toBe("27 Oct 2026, 18:31 UTC")
    expect(stopped.querySelector('[data-action="rule-stop"]')).toBeNull()
    expect(stopped.querySelector('[data-action="rule-extend"]')).toBeNull()
    // Said in the row's live region, and focus stays in the row.
    expect(outcome(CHAT).hidden).toBe(false)
    expect(outcome(CHAT).textContent).toBe("Stopped.")
    expect(focusedOnOutcome(CHAT)).toBe(true)
    expect(line().hidden).toBe(false)
    expect(line().textContent.trim()).toBe("1 request allowed without asking")
    // The other rule's Stop ends the last one: the line goes.
    $('[data-action="rule-stop"]', row("rul_tomlinear001")).click()
    await settle()
    expect(line().hidden).toBe(true)
  })

  it("a stopped-only answer leaves only the rule's id and its status: every term the row showed goes", async () => {
    openMachine(() => ok({ id: CHAT, status: "ended", endedReason: "revoked" }))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    const stopped = row(CHAT)
    expect(stopped.textContent.replace(/\s+/g, " ").trim()).toBe(`Rule ${CHAT}You may stop this rule, but not read what it allows. It was stopped.Stopped. Stopped`)
    expect(outcome(CHAT).textContent).toBe("Stopped.")
    expect(focusedOnOutcome(CHAT)).toBe(true)
    for (const term of ["api.openai.com", "chat/completions", "openai-shared", "tom-laptop", "Tom Barker", "14 times"]) expect(stopped.textContent).not.toContain(term)
    expect(stopped.querySelector('[data-region="rule-terms"]')).toBeNull()
    expect(stopped.hasAttribute("data-rule-own")).toBe(false)
    expect(line().textContent.trim()).toBe("1 request allowed without asking")
  })

  it("a rule that had already ended when Stop reached the vault says why it ended, not Stopped.", async () => {
    openMachine(() => ok(chatView({ status: "ended", endedReason: "expired", endsAt: "2026-10-27T18:29:00.000Z" })))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect($('[data-region="rule-status"]', row(CHAT)).textContent).toBe("Ended")
    expect($('[data-region="rule-ended"]', row(CHAT)).textContent).toBe("Its time ran out.")
    expect(outcome(CHAT).textContent).toBe("Its time ran out.")
    expect(focusedOnOutcome(CHAT)).toBe(true)
  })

  it("a stopped-only answer for a rule that had already ended says why it ended, not Stopped.", async () => {
    const answer = { id: CHAT, status: "ended", endedReason: "expired" } as const
    openMachine(() => ok(answer))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect(outcome(CHAT).textContent).toBe("Its time ran out.")
    expect(row(CHAT).textContent).not.toContain("Stopped")
    expect(shape(row(CHAT))).toEqual(shape(parseHtml(stoppedOnlyRow(answer).value).querySelector('[data-region="rule"]')!))
    expect(stoppedOnlyRow(answer).value).not.toContain("Stopped")
  })

  it("an end the page cannot read as a time is shown as sent, and the stop still lands", async () => {
    openMachine(() => ok(chatView({ status: "ended", endedReason: "revoked", endsAt: "not a time" })))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect($("#notice").textContent).toBe("")
    expect(row(CHAT).getAttribute("data-rule-state")).toBe("ended")
    expect($('[data-region="rule-ends"]', row(CHAT)).textContent).toBe("not a time")
    expect($('[data-region="rule-ends"]', row(CHAT)).querySelector("time")).toBeNull()
    expect(outcome(CHAT).textContent).toBe("Stopped.")
  })

  it("the stopped-only row the page draws is the server's stoppedOnlyRow, node for node", async () => {
    const answer = { id: CHAT, status: "ended", endedReason: "revoked" } as const
    openMachine(() => ok(answer))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect(shape(row(CHAT))).toEqual(shape(parseHtml(stoppedOnlyRow(answer).value).querySelector('[data-region="rule"]')!))
  })

  it("a refused stop keeps the row as it was and shows the vault's words", async () => {
    openMachine(() => ({ status: 403, body: { error: "forbidden", message: "You are not allowed to do that." } }))
    $('[data-action="rule-stop"]', row(CHAT)).click()
    await settle()
    expect(row(CHAT).getAttribute("data-rule-state")).toBe("active")
    expect($("#notice").textContent).toContain("You are not allowed to do that.")
    expect(outcome(CHAT).textContent).toBe("")
  })
})

describe("Extend", () => {
  // The vault's action, over the digest of the terms the row shows (the
  // gallery's chat rule's, which chatView spells) unless told otherwise.
  const action = async (ttlSeconds: 86_400 | 604_800 | 2_592_000, terms: Partial<PolicyRuleView> = {}) => ({ type: "policy.decide", proposal: CHAT, digest: await policyRuleTermsDigest(ruleTermsOf(chatView(terms))), decision: "approve", effectDigest: await policyRuleExtendDigest(CHAT, ttlSeconds) })
  const vaultFor = (planned: unknown, decided: unknown) => (path: string): Answer => {
    if (path === `${BASE}/extend/action`) return ok(planned)
    if (path === "/api/w/northwind") return ok(WORKSPACE)
    if (path === "/api/w/northwind/stepup/start") return ok({ nonce: "n", options: { challenge: "c", allowCredentials: [] } })
    if (path === `${BASE}/extend/decide`) return ok(decided)
    return { status: 404, body: { error: "not_found", message: "No." } }
  }

  it("the chosen duration's digest gates one passkey; the row shows its new end", async () => {
    const planned = await action(2_592_000)
    const page = openMachine(vaultFor(planned, { rule: chatView({ endsAt: "2026-11-26T18:30:00.000Z" }), coSign: null }))
    $('[data-input="rule-ttl"][value="2592000"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual([`${BASE}/extend/action`, "/api/w/northwind", "/api/w/northwind/stepup/start", `${BASE}/extend/decide`])
    expect(page.calls[0]!.body).toEqual({ ttlSeconds: 2_592_000 })
    expect(passkeys.count).toBe(1)
    expect($('[data-region="rule-ends"]', row(CHAT)).textContent).toBe("26 Nov 2026, 18:30 UTC")
    expect(outcome(CHAT).hidden).toBe(false)
    expect(outcome(CHAT).textContent).toBe("Extended. It now ends 26 Nov 2026, 18:30 UTC.")
    expect(focusedOnOutcome(CHAT)).toBe(true)
  })

  it("an action over other terms than the row shows signs nothing; once extended, the row's terms are the new ones and the next extension signs over them", async () => {
    const stale = openMachine(vaultFor(await action(604_800, { ttlSeconds: 2_592_000 }), null))
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(stale.calls.map((c) => c.path)).toEqual([`${BASE}/extend/action`])
    expect(passkeys.count).toBe(0)
    expect($("#notice").textContent).toContain(CHANGED_SINCE_SHOWN.message)
    stale.restore()

    let planned = await action(2_592_000)
    const page = openMachine((path, body) => vaultFor(planned, { rule: chatView({ ttlSeconds: 2_592_000, endsAt: "2026-11-26T18:30:00.000Z" }), coSign: null })(path, body))
    $('[data-input="rule-ttl"][value="2592000"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(JSON.parse($('[data-action="rule-extend"]', row(CHAT)).getAttribute("data-rule-terms")!)).toEqual(ruleTermsOf(chatView({ ttlSeconds: 2_592_000 })))
    planned = await action(86_400, { ttlSeconds: 2_592_000 })
    $('[data-input="rule-ttl"][value="86400"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(page.calls.filter((c) => c.path === `${BASE}/extend/decide`).map((c) => c.body)).toMatchObject([{ ttlSeconds: 2_592_000 }, { ttlSeconds: 86_400 }])
    expect(passkeys.count).toBe(2)
  })

  it("while the passkey prompt is open the row's controls all wait: a duration changed or a button clicked again sends nothing more", async () => {
    let release = () => {}
    passkeys.hold = new Promise((resolve) => (release = resolve))
    const page = openMachine(vaultFor(await action(2_592_000), { rule: chatView({ endsAt: "2026-11-26T18:30:00.000Z" }), coSign: null }))
    const controls = () => ['[data-input="rule-ttl"]', '[data-action="rule-extend"]', '[data-action="rule-stop"]'].flatMap((s) => row(CHAT).querySelectorAll(s))
    $('[data-input="rule-ttl"][value="2592000"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(passkeys.count).toBe(1)
    expect(controls().length).toBe(5)
    expect(controls().filter((c) => !c.disabled)).toEqual([])
    $('[data-input="rule-ttl"][value="86400"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    $('[data-action="rule-stop"]', row(CHAT)).click()
    expect($('[data-input="rule-ttl"]:checked', row(CHAT)).getAttribute("value")).toBe("2592000")
    release()
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual([`${BASE}/extend/action`, "/api/w/northwind", "/api/w/northwind/stepup/start", `${BASE}/extend/decide`])
    expect(page.calls[3]!.body).toMatchObject({ ttlSeconds: 2_592_000 })
    expect(passkeys.count).toBe(1)
    // Done, the row is live again.
    expect(controls().filter((c) => c.disabled)).toEqual([])
  })

  // The row as it was: the same end, Extend offered and live, nothing said.
  const unchanged = () => {
    expect($('[data-region="rule-ends"]', row(CHAT)).textContent).toBe("1 Nov 2026, 18:30 UTC")
    expect($('[data-action="rule-extend"]', row(CHAT)).disabled).toBe(false)
    expect(row(CHAT).querySelectorAll('[data-input="rule-ttl"]').filter((i) => i.disabled)).toEqual([])
    expect(outcome(CHAT).textContent).toBe("")
  }

  it("refused at decide, the row stays as it was and the vault's words are shown", async () => {
    const planned = await action(604_800)
    const page = openMachine((path, body) => (path === `${BASE}/extend/decide` ? { status: 409, body: { error: "conflict", message: "This rule has ended." } } : vaultFor(planned, null)(path, body)))
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(page.calls.map((c) => c.path).at(-1)).toBe(`${BASE}/extend/decide`)
    expect(passkeys.count).toBe(1)
    expect($("#notice").textContent).toContain("This rule has ended.")
    unchanged()
  })

  it("with the passkey prompt closed, nothing is decided and the row stays as it was", async () => {
    passkeys.cancel = true
    const page = openMachine(vaultFor(await action(604_800), null))
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(passkeys.count).toBe(1)
    expect(page.calls.map((c) => c.path)).not.toContain(`${BASE}/extend/decide`)
    unchanged()
  })

  it("a double click on Extend asks one passkey and sends one extension", async () => {
    const page = openMachine(vaultFor(await action(604_800), { rule: chatView({}), coSign: null }))
    $('[data-action="rule-extend"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(page.calls.filter((c) => c.path === `${BASE}/extend/action`)).toHaveLength(1)
    expect(page.calls.filter((c) => c.path === `${BASE}/extend/decide`)).toHaveLength(1)
    expect(passkeys.count).toBe(1)
  })

  it("an action for another duration than the one chosen signs nothing", async () => {
    const page = openMachine(vaultFor(await action(604_800), null))
    $('[data-input="rule-ttl"][value="86400"]', row(CHAT)).click()
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    expect(page.calls.map((c) => c.path)).toEqual([`${BASE}/extend/action`])
    expect(passkeys.count).toBe(0)
    expect($("#notice").textContent).toContain(CHANGED_SINCE_SHOWN.message)
    expect(outcome(CHAT).textContent).toBe("")
  })

  it("a co-sign answer says it is extended once a manager of the credential's home co-signs, with the link and the binding code, and Extend goes", async () => {
    const coSign = { id: "pol_extendchat01", url: "https://elsewhere.test/phish", bindingCode: "7XK2M9QP", expiresAt: "2026-10-29T18:30:00.000Z" }
    openMachine(vaultFor(await action(604_800), { rule: chatView({}), coSign }))
    $('[data-action="rule-extend"]', row(CHAT)).click()
    await settle()
    const outcome = $('[data-region="rule-outcome"]', row(CHAT))
    expect(outcome.hidden).toBe(false)
    expect(outcome.textContent).toBe("Extended once a manager of this credential's home co-signs.Send a manager of this credential's home this link: https://app.mehen.dev/w/northwind/p/pol_extendchat01Binding code: 7XK2M9QP")
    // The link is built from the proposal's id, never the url the vault sent.
    expect($("a", outcome).getAttribute("href")).toBe("https://app.mehen.dev/w/northwind/p/pol_extendchat01")
    expect(row(CHAT).querySelector('[data-action="rule-extend"]')).toBeNull()
    expect(focusedOnOutcome(CHAT)).toBe(true)
    expect($('[data-region="rule-ends"]', row(CHAT)).textContent).toBe("1 Nov 2026, 18:30 UTC")
    // What the gallery shows for this state is what the client drew.
    const shown = renderDocument(entry("machine-rule-cosign").page).value.replace(...(entry("machine-rule-cosign").swap![0] as [RegExp, string]))
    expect(shown).toContain(`<div class="small" role="status" tabindex="-1" data-region="rule-outcome"><p>Extended once a manager of this credential&#39;s home co-signs.</p><p>Send a manager of this credential&#39;s home this link: <a href="https://app.mehen.dev/w/northwind/p/pol_extendchat01">`)
  })
})

describe("the credential page", () => {
  // A live task grant and a live rule, both on the viewer's own machine.
  it("counts no task grant in the line: once the last rule is stopped the line goes, though a grant is live", async () => {
    const mine = { device: "dev_alexmbp0001", workload: null }
    const grant = galleryGrant(GALLERY_NOW, { id: "rul_alexgrant001", item: "openai-prod", itemId: "itm_openaiprod", host: "api.openai.com", asker: mine, areas: ["d1"] })
    const rule = galleryRule(GALLERY_NOW, { id: "rul_alexprod0001", item: "openai-prod", asker: mine, method: "POST", host: "api.openai.com", path: "/v1/embeddings" })
    const machines = new Map([["dev_alexmbp0001", { name: "alex-mbp", owner: { kind: "member" as const, member: VIEWERS.owner.member, name: "Alex" } }]])
    const page = workspaceCredentialPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, item: description(GALLERY_ITEMS[0]!), projects: [], rules: { rules: [grant, rule], machines, tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: false } })
    browser = installPage(renderDocument(page).value, () => ok({ ...rule, status: "ended", endedReason: "revoked" }), "https://app.mehen.dev/w/northwind/items/openai-prod")
    initWorkspaceCredential(page.boot, shell())
    expect(line().textContent.trim()).toBe("1 request allowed without asking")
    $('[data-action="rule-stop"]', row("rul_alexprod0001")).click()
    await settle()
    expect(browser.calls).toEqual([{ path: "/api/w/northwind/policy/rules/rul_alexprod0001/revoke", body: {} }])
    expect(row("rul_alexgrant001").getAttribute("data-rule-state")).toBe("active")
    expect(line().hidden).toBe(true)
  })

  it("wires the same card: Stop on someone else's machine's rule changes no line, which counts the viewer's own", async () => {
    const page = entry("ws-credential-rules").page
    browser = installPage(renderDocument(page).value, () => ok({ ...chatView({ id: "rul_tomprod00001", status: "ended", endedReason: "revoked" }) }), "https://app.mehen.dev/w/northwind/items/openai-prod")
    initWorkspaceCredential(page.boot, shell())
    expect(line().textContent.trim()).toBe("1 request allowed without asking")
    expect(row("rul_tomprod00001").querySelector('[data-action="rule-extend"]')).toBeNull()
    $('[data-action="rule-stop"]', row("rul_tomprod00001")).click()
    await settle()
    expect(browser.calls).toEqual([{ path: "/api/w/northwind/policy/rules/rul_tomprod00001/revoke", body: {} }])
    expect(row("rul_tomprod00001").getAttribute("data-rule-state")).toBe("ended")
    expect(line().textContent.trim()).toBe("1 request allowed without asking")
  })
})
