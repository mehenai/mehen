import { describe, expect, test } from "bun:test"
import { type Ask, type AskCheck, type AskUrl, adoptionAsk, approvalAsk, askedBy, askUrl, checkSentence, connectAsk, enrolAsk, intakeAsk, policyAsk, relativeExpiry as askRelativeExpiry, withContext } from "../../ask.ts"
import { plainText } from "../../tty.ts"
import type { CallToolResult } from "./bridge.ts"
import { ERROR_BACKOFF_MS, FOLLOW_WAIT_SECONDS, LIST_LIMIT, MIN_SPACING_MS, askCardView, askStateFrom, askedByText, checkLine, followAsk, isExpired, modelContext, openableUrl, relativeExpiry } from "./ask-card-logic.ts"

const VAULT = { vaultUrl: "https://vault.example.com", workspaceSlug: "acme" }
const link = (path: string): AskUrl => (askUrl(`https://vault.example.com/w/acme${path}`, VAULT) as { url: AskUrl }).url
const by = { device: "office", session: "pi-1" }
const context = { origin: "https://vault.example.com", workspace: { id: "ten_1", slug: "acme", name: "Acme" }, device: "dev_1" }
const later = "2026-11-02T13:00:00.000Z"

const approval = withContext(approvalAsk({ id: "apr_7Hq2", url: link("/a/apr_7Hq2"), summary: "Send an email to sam@example.com", bindingCode: "K7Q2MX", item: "gmail-work", account: "sam@example.com", expiresAt: later, requestedBy: by }), context)
const intake = withContext(intakeAsk({ id: "int_9", url: link("/i/int_9"), name: "openai-personal", kind: "api-key", provider: "openai", reason: "run the evals", expiresAt: later, requestedBy: by }), context)
const connect = withContext(connectAsk({ id: "con_4", url: link("/c/con_4"), name: "gmail-work", provider: "google-gmail", account: "sam@example.com", reason: "read the inbox", expiresAt: later, requestedBy: by }), context)
const policy = withContext(policyAsk({ id: "pol_2", url: link("/p/pol_2"), summary: "Relax a route for an hour. No access has changed yet.", bindingCode: "P0LC", expiresAt: later, requestedBy: by }), context)
const adoption = withContext(adoptionAsk({ id: "adp_5", url: link("/b/adp_5"), items: 3, machine: "office", expiresAt: later, requestedBy: by }), context)
const enrol = enrolAsk({ id: "enr_1", url: link("/e/ABCD2345"), name: "office", backend: "software", fingerprint: "AB12 CD34", expiresAt: later, requestedBy: by })

const ok = (structuredContent: Record<string, unknown>): CallToolResult => ({ content: [{ type: "text", text: "..." }], structuredContent, isError: false })
const failed = (structuredContent: Record<string, unknown>): CallToolResult => ({ content: [{ type: "text", text: "..." }], structuredContent, isError: true })

describe("the card's words are ask.ts's words", () => {
  test("the check line reads as checkSentence, with the value apart", () => {
    const checks: AskCheck[] = [
      { label: "fingerprint", value: "AB12 CD34" },
      { label: "code", value: "K7Q2MX" },
      { label: "account", value: "sam@example.com" },
      { label: "asked by", value: "office, session pi-1" },
      { label: "codes", value: "K7Q2MX, 9PZ4QA (2)" },
    ]
    for (const check of checks) {
      const line = checkLine(check)
      expect(`${line.lead}${line.value}${line.tail}`).toBe(plainText(checkSentence(check)))
      expect(line.value).toBe(check.value)
    }
  })

  test("who asked reads as askedBy, and the expiry as relativeExpiry", () => {
    expect(askedByText(by)).toBe(askedBy(by))
    expect(askedByText({ device: "office", session: null })).toBe(askedBy({ device: "office", session: null }))
    const now = new Date("2026-11-02T12:00:00.000Z")
    for (const ms of [-1, 0, 30_000, 59_999, 60_000, 47 * 60_000 + 1, 3_600_000, 36 * 3_600_000, 3 * 86_400_000]) {
      const at = new Date(now.getTime() + ms).toISOString()
      expect(relativeExpiry(at, now)).toBe(askRelativeExpiry(at, now))
    }
    expect(relativeExpiry("not a time", now)).toBeNull()
    expect(isExpired(null, now)).toBe(false)
    expect(isExpired("2026-11-02T11:59:00.000Z", now)).toBe(true)
  })
})

describe("askCardView", () => {
  test("vault_request: one ask with its check, who asked folded into the check, and a live intake id", () => {
    const view = askCardView(ok({ intake: "int_9", url: intake.url, expiresAt: later, kind: "api-key", name: "openai-personal", provider: "openai", ask: intake, next: { url: intake.url, say: "..." } }))
    expect(view).toEqual({
      kind: "single",
      note: null,
      ask: {
        id: "int_9",
        live: true,
        workspace: "acme",
        title: "Add a credential",
        what: intake.what,
        check: { lead: "the page says it was asked by ", value: "office, session pi-1", tail: "" },
        account: null,
        askedBy: null,
        expiresAt: later,
        url: intake.url,
        openable: true,
      },
    })
  })

  test("vault_connect: the account is in the check once; the client step says it is the first of two", () => {
    const view = askCardView(ok({ connect: "con_4", url: connect.url, expiresAt: later, provider: "google-gmail", client: "google-oauth-client", name: "gmail-work", account: "sam@example.com", ask: connect, next: {} }))
    expect(view).toMatchObject({ kind: "single", note: null, ask: { id: "con_4", account: null, askedBy: "office, session pi-1", check: { lead: "the page shows account ", value: "sam@example.com", tail: "; sign in as that account" } } })
    const step = askCardView(ok({ step: "client", intake: "int_9", url: intake.url, connect: "con_4", provider: "google-gmail", client: "google-oauth-client", name: "gmail-work", ask: intake, next: {}, then: "Once vault_wait says ..." }))
    expect(step).toMatchObject({ kind: "single", ask: { id: "int_9" }, note: expect.stringContaining("Step 1 of 2") })
  })

  test("vault_policy: a standing rule proposal draws an Allow from now on card with the summary, code, who asked, expiry and Open", () => {
    const rule = withContext(policyAsk({ id: "pol_3", url: link("/p/pol_3"), summary: "POST api.example.com/tasks, from office, outside any project, 7 days. No access has changed yet.", bindingCode: "R1LE", expiresAt: later, requestedBy: by }), context)
    const view = askCardView(ok({ proposal: "pol_3", item: "example-key", status: "pending", stage: "approve", bindingCode: "R1LE", summary: "POST api.example.com/tasks", expiresAt: later, rule: null, url: rule.url, ask: rule, next: {}, warning: null }))
    expect(view).toMatchObject({ kind: "single", ask: { id: "pol_3", title: "Allow from now on", what: rule.what, url: rule.url, check: { value: "R1LE" }, askedBy: "office, session pi-1", expiresAt: later, openable: true, live: true } })
  })

  test("vault_policy: a proposal draws its ask; show and preview draw nothing", () => {
    expect(askCardView(ok({ proposal: "pol_2", item: "example-key", status: "pending", bindingCode: "P0LC", summary: "Relax", expiresAt: later, outcome: null, url: policy.url, ask: policy, next: {}, warning: null }))).toMatchObject({ kind: "single", ask: { id: "pol_2", live: true, check: { value: "P0LC" } } })
    expect(askCardView(ok({ item: "example-key", selector: { device: "dev_1", session: null }, policyMode: "standard" }))).toEqual({ kind: "none" })
  })

  test("an approval shows its code, its account and who asked", () => {
    expect(askCardView(failed({ error: "approval_required", message: "Approval required", next: { url: approval.url, say: "..." }, approval: "apr_7Hq2", ask: approval }))).toMatchObject({
      kind: "single",
      ask: { id: "apr_7Hq2", title: "Approve a request", check: { value: "K7Q2MX" }, account: "sam@example.com", askedBy: "office, session pi-1", live: true },
    })
  })

  test("an error with no ask, and a result with nothing in it, draw nothing", () => {
    expect(askCardView(failed({ error: "usage", message: "Invalid arguments", next: { say: "Fix the arguments." } }))).toEqual({ kind: "none" })
    expect(askCardView({ content: [] })).toEqual({ kind: "none" })
    expect(askCardView(ok({ pending: [] }))).toEqual({ kind: "none" })
  })

  test("vault_pending: a list of at most eight, then how many more; an enrolment is drawn but not followed", () => {
    const asks: Ask[] = [approval, intake, connect, policy, adoption, enrol, approval, intake, connect, policy]
    const view = askCardView(ok({ pending: asks }))
    expect(view.kind).toBe("list")
    if (view.kind !== "list") return
    expect(view.asks).toHaveLength(LIST_LIMIT)
    expect(view.more).toBe(2)
    expect(view.asks.map((a) => [a.id, a.live])).toEqual([["apr_7Hq2", true], ["int_9", true], ["con_4", true], ["pol_2", true], ["adp_5", true], ["enr_1", false], ["apr_7Hq2", true], ["int_9", true]])
    expect(view.asks[5]?.workspace).toBeNull()
    expect(askCardView(ok({ pending: [adoption] }))).toMatchObject({ kind: "single", ask: { id: "adp_5" } })
  })

  test("untrusted fields are data: a malformed ask is dropped and a link that is not https is not openable", () => {
    expect(askCardView(ok({ ask: { ...intake, url: 7 } }))).toEqual({ kind: "none" })
    expect(askCardView(ok({ pending: [{ ...intake, title: null }, "x", null, intake] }))).toMatchObject({ kind: "single", ask: { id: "int_9" } })
    expect(askCardView(ok({ ask: { ...intake, check: { label: "<b>", value: "x" } } }))).toMatchObject({ ask: { check: null } })
    expect(askCardView(ok({ ask: { ...intake, url: "javascript:alert(1)" } }))).toMatchObject({ ask: { openable: false } })
    expect(openableUrl("https://vault.example.com/w/acme/a/apr_1")).toBe(true)
    expect(openableUrl("http://localhost:8787/w/acme/a/apr_1")).toBe(true)
    expect(openableUrl("http://127.0.0.1:8787/w/acme/a/apr_1")).toBe(true)
    expect(openableUrl("http://vault.example.com/w/acme/a/apr_1")).toBe(false)
    expect(openableUrl("https://user:pw@vault.example.com/")).toBe(false)
    expect(openableUrl("data:text/html,x")).toBe(false)
    expect(openableUrl("not a url")).toBe(false)
  })
})

describe("following an ask", () => {
  test("askStateFrom reads vault_ask_state's answer for this id only", () => {
    const result = ok({ id: "apr_1", kind: "approval", state: "declined", expiresAt: later, message: "The human denied approval apr_1: Send." })
    expect(askStateFrom(result, "apr_1")).toEqual({ state: "declined", expiresAt: later, message: "The human denied approval apr_1: Send." })
    expect(askStateFrom(result, "apr_2")).toBeNull()
    expect(askStateFrom(ok({ id: "apr_1", state: "approved" }), "apr_1")).toBeNull()
    expect(askStateFrom(failed({ error: "network", message: "down" }), "apr_1")).toBeNull()
  })

  type Fake = { calls: Record<string, unknown>[]; sleeps: number[]; reads: string[] }
  function fake(answers: (CallToolResult | Error)[], options: { expired?: () => boolean; stopped?: () => boolean } = {}) {
    const seen: Fake = { calls: [], sleeps: [], reads: [] }
    let clock = 0
    const run = followAsk({
      id: "apr_1",
      workspace: "acme",
      call: async (args) => {
        seen.calls.push(args)
        clock += 20_000
        const answer = answers.shift() ?? new Error("no more answers")
        if (answer instanceof Error) throw answer
        return answer
      },
      sleep: async (ms) => {
        seen.sleeps.push(ms)
        clock += ms
      },
      now: () => clock,
      expired: options.expired ?? (() => false),
      stopped: options.stopped ?? (() => false),
      onRead: (read) => seen.reads.push(read.state),
    })
    return { run, seen }
  }
  const state = (s: string) => ok({ id: "apr_1", kind: "approval", state: s, expiresAt: later, message: "m" })

  test("calls vault_ask_state with the ask's workspace and a 20 s wait until the ask settles", async () => {
    const { run, seen } = fake([state("waiting"), state("waiting"), state("done")])
    expect(await run).toEqual({ end: "settled", state: "done" })
    expect(seen.calls).toEqual(Array(3).fill({ id: "apr_1", workspace: "acme", waitSeconds: FOLLOW_WAIT_SECONDS }))
    expect(seen.reads).toEqual(["waiting", "waiting", "done"])
    expect(seen.sleeps).toEqual([])
  })

  test("backs off 30 s after an error and stops after five in a row; a good answer resets the count", async () => {
    const { run, seen } = fake([new Error("x"), failed({ error: "network" }), state("waiting"), new Error("x"), new Error("x"), new Error("x"), new Error("x"), new Error("x")])
    expect(await run).toEqual({ end: "errors" })
    expect(seen.calls).toHaveLength(8)
    expect(seen.sleeps).toEqual(Array(6).fill(ERROR_BACKOFF_MS))
  })

  test("a host that answers waiting at once is asked again no sooner than the minimum spacing", async () => {
    let clock = 0
    const sleeps: number[] = []
    const answers = [state("waiting"), state("cancelled")]
    const calls: Record<string, unknown>[] = []
    const end = await followAsk({
      id: "apr_1",
      workspace: null,
      call: async (args) => {
        calls.push(args)
        return answers.shift() as CallToolResult
      },
      sleep: async (ms) => {
        sleeps.push(ms)
      },
      now: () => (clock += 100),
      expired: () => false,
      stopped: () => false,
      onRead: () => undefined,
    })
    expect(end).toEqual({ end: "settled", state: "cancelled" })
    // With no workspace on the ask, none is sent.
    expect(calls[0]).toEqual({ id: "apr_1", waitSeconds: FOLLOW_WAIT_SECONDS })
    expect(sleeps).toHaveLength(1)
    expect(sleeps[0]).toBeGreaterThan(MIN_SPACING_MS - 1000)
  })

  test("stops when the link expires or the card is torn down", async () => {
    expect(await fake([state("waiting")], { expired: () => true }).run).toEqual({ end: "expired" })
    let calls = 0
    const torn = fake([state("waiting"), state("waiting")], { stopped: () => calls++ > 0 })
    expect(await torn.run).toEqual({ end: "stopped" })
    expect(torn.seen.reads).toEqual([])
  })

  test("the agent learns one ask as { ask, state } and several together", () => {
    expect(modelContext([])).toBeNull()
    expect(modelContext([{ id: "apr_1", state: "done" }])).toEqual({ ask: "apr_1", state: "done" })
    expect(modelContext([{ id: "apr_1", state: "done" }, { id: "int_2", state: "declined" }])).toEqual({ asks: [{ ask: "apr_1", state: "done" }, { ask: "int_2", state: "declined" }] })
  })
})
