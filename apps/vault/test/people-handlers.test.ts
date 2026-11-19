// The browser handlers of the people, machine and account setup pages, run
// against the pages the server renders (test/mini-dom.ts), with the API
// answered by the test and the passkey prompt stubbed. Each test drives the
// real events and checks the request bodies and what the page then shows.
import { afterEach, describe, expect, it, vi } from "vitest"
import { generateRecoveryCode } from "@mehen/protocol/recovery-code"
import { renderDocument } from "../src/ui/layout.ts"
import { recoverPage, signinPage } from "../src/ui/pages/account.ts"
import { CONFIRMATION_REMOVED_WORDS, INVITE_TERMS_WORDS, recoverPendingPage, workspaceSignupPage } from "../src/ui/pages/account-setup.ts"
import { formatTime } from "../src/ui/wording.ts"
import { machinePage } from "../src/ui/pages/machines.ts"
import { peoplePage } from "../src/ui/pages/people.ts"
import { PEOPLE_DEVICE, PEOPLE_INVITES, PEOPLE_PROJECTS, peopleData, peopleShell } from "../src/ui/people-gallery.ts"
import { ACCOUNT_PASSKEYS, accountGallery } from "../src/ui/account-gallery.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { BOOTSTRAP_KEY, INVITE_KEY, RESULT_KEY, initAccountRecovery, initRecoverPending, initWorkspaceCreate, initWorkspaceSignup, suggestWorkspaceSlug } from "../src/ui/client/pages/account-setup.ts"
import { CONFIRMATION_POLL_MS, RECOVERY_POLL_MS, nextRecoveryPoll } from "../src/ui/client/confirmation-poll.ts"
import { initAccount, initRecover, initSignin } from "../src/ui/client/pages/account.ts"
import { NARROW_ONLY_WORDS, initMachine, initPeople } from "../src/ui/client/pages/people.ts"
import { type MiniBrowser, type MiniElement, MiniEvent, installPage, settle, submit } from "./mini-dom.ts"

vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: async () => ({ id: "test-assertion" }),
  startRegistration: async () => ({ id: "test-registration" }),
}))

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
  vi.useRealTimers()
})

type Answer = { status: number; body: unknown }
const ok = (body: unknown = {}): Answer => ({ status: 200, body })
const never = () => new Promise<never>(() => undefined)

function open(markup: string, respond: (path: string, body: unknown) => Answer | Promise<never>, href?: string): MiniBrowser {
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

const paths = () => browser!.calls.map((c) => c.path)

describe("joining from an invitation at /signup", () => {
  const codes = Array.from({ length: 10 }, generateRecoveryCode)
  const PEEK = { workspace: { name: "Northwind", slug: "northwind" }, role: "member", bound: true, emailCode: "off", expiresAt: "2026-11-04T18:00:00.000Z" }
  const WORKSPACE = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
  const PROOF_NEXT = { url: "/signup", say: "Verify the invited email with Google, then continue." }
  const membership = (status: "unconfirmed" | "active") => ({ workspace: WORKSPACE, member: "mem_new", role: "member", pendingRole: null, status, pending: 0 })
  const session = (memberships: unknown[] = []) => ({ account: "acc_new", name: "Tom", canCreateWorkspaces: false, workspaceCreation: "default", recoverySetupRequired: false, securityEpoch: 0, pendingTransition: null, restricted: null, memberships })

  type Answers = { peek?: Answer; account?: () => Answer | Promise<never>; join?: Answer; onboarding?: "bootstrap" | "join"; result?: Answer; home?: string; landing?: Answer }
  function respond(answers: Answers = {}) {
    return (path: string): Answer | Promise<never> => {
      if (path === "/api/auth/invite/peek") return answers.peek ?? ok(PEEK)
      if (path === "/api/auth/oidc/google/start") return ok({ url: "https://accounts.google.com/o/oauth2/v2/auth?state=s" })
      if (path === "/api/auth/oidc/google/result") return answers.result ?? ok({ purpose: "invite", identity: { provider: "google", email: "tom@northwind.example", subject: "g-tom", name: null }, workspace: WORKSPACE.id })
      if (path === "/api/auth/signup/options") return ok({ options: { challenge: "c" } })
      if (path === "/api/auth/signup/verify") return ok({ account: "acc_new", onboarding: answers.onboarding ?? "join" })
      if (path === "/api/account/stepup/start") return ok({ nonce: "n", options: { challenge: "c" } })
      if (path === "/api/account/recovery/generate") return ok({ batch: "b", codes, confirmPosition: 2, expiresAt: "2026-10-27T19:00:00.000Z" })
      if (path === "/api/account/recovery/confirm") return ok()
      if (path === "/api/account/passkeys/options") return ok({ options: { challenge: "c" } })
      if (path === "/api/account/passkeys/verify") return ok({ passkey: {} })
      if (path === "/api/account/invites/join") return answers.join ?? ok({ member: "mem_new", state: "pending_confirmation" })
      if (path === "/api/account") return answers.account?.() ?? ok(session())
      if (path === `/api/account/onboarding/${WORKSPACE.id}`) return answers.landing ?? ok({ next: answers.home ?? "https://vault.test/w/northwind/connect-agent" })
      return { status: 404, body: { error: "not_found", message: "No such route." } }
    }
  }

  // The tab's sessionStorage, kept across a reload or the trip to Google.
  function tab(initial: Record<string, string> = {}) {
    const map = new Map(Object.entries(initial))
    return { map, store: { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, String(v)), removeItem: (k: string) => void map.delete(k) } }
  }
  type Tab = ReturnType<typeof tab>

  // Loads /signup in this tab, as the server renders it for this browser.
  async function load(storage: Tab, href: string, state: { signedIn: boolean; recoveryReady: boolean; firstAccount?: boolean }, answers: Answers = {}) {
    browser?.restore()
    open(renderDocument(workspaceSignupPage(state)).value, respond(answers), href)
    ;(globalThis as Record<string, unknown>).sessionStorage = storage.store
    initWorkspaceSignup({ page: "workspace-signup", ...state })
    await settle()
  }
  const signedOut = { signedIn: false, recoveryReady: false }
  const ready = { signedIn: true, recoveryReady: true }
  const shown = () => ["signup-verify", "signup-passkey", "signup-recovery", "signup-join", "signup-waiting", "signup-invite-unknown", "signup-no-invite"].filter((r) => !$(`[data-region="${r}"]`).hidden)
  const stepClasses = () => browser!.document.querySelectorAll('[data-region="signup-invite"] .step').map((li) => (li.hidden ? "hidden" : li.classList.contains("done") ? "done" : li.classList.contains("current") ? "current" : "todo"))
  const bodyOf = (path: string) => browser!.calls.filter((c) => c.path === path).map((c) => c.body)

  async function saveCodes() {
    $('[data-action="make-codes"]').click()
    await settle()
    expect($('[data-region="codes-list"]').children).toHaveLength(10)
    // Not offered again once shown: a second press would replace them.
    expect($('[data-action="make-codes"]').hidden).toBe(true)
    ;($('[data-input="codes-confirm"]') as MiniElement).value = codes[1]!
    $('[data-action="confirm-codes"]').click()
    await settle()
    expect(browser!.calls.find((c) => c.path === "/api/account/recovery/confirm")?.body).toEqual({ batch: "b", code: codes[1] })
    // Shown once: gone from the page once acknowledged.
    expect($('[data-region="codes-list"]').children).toHaveLength(0)
  }

  it("a signed-out new invitee: Google first, back to the same page, passkey, recovery, then the join by itself and the wait", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#the-code", signedOut)
    expect(bodyOf("/api/auth/invite/peek")).toEqual([{ code: "the-code" }])
    expect($('[data-region="signup-invite"]').hidden).toBe(false)
    expect($('[data-region="signup-invite"] h1').textContent).toBe("You are invited to Northwind as a member.")
    expect(shown()).toEqual(["signup-verify"])
    // Until when it works, and what to do if it was not expected, before anything is created.
    expect($('[data-region="invite-terms"]').hidden).toBe(false)
    expect($('[data-region="invite-terms"]').textContent).toBe(`${INVITE_TERMS_WORDS[0]}${formatTime(PEEK.expiresAt)}${INVITE_TERMS_WORDS[1]}`)
    expect(stepClasses()).toEqual(["current", "todo", "todo", "todo"])
    expect(storage.map.get(INVITE_KEY)).toBe("the-code")
    $('[data-action="verify-google"]').click()
    await settle()
    expect(bodyOf("/api/auth/oidc/google/start")).toEqual([{ purpose: "invite", invite: "the-code", next: "/signup" }])
    expect(browser!.assigned).toEqual(["https://accounts.google.com/o/oauth2/v2/auth?state=s"])

    // Google sends the browser back to /signup#oidc=<id>.
    await load(storage, "https://vault.test/signup#oidc=oidr_1", signedOut)
    expect(storage.map.get(RESULT_KEY)).toBe("oidr_1")
    expect(bodyOf("/api/auth/oidc/google/result")).toEqual([{ result: "oidr_1", purpose: "invite" }])
    expect($('[data-region="verified"]').textContent).toContain("tom@northwind.example")
    expect(shown()).toEqual(["signup-passkey"])
    expect(stepClasses()).toEqual(["done", "current", "todo", "todo"])
    ;($('[data-input="name"]') as MiniElement).value = "Tom"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(bodyOf("/api/auth/signup/options")).toEqual([{ invite: "the-code", name: "Tom", oidcResult: "oidr_1" }])
    expect(bodyOf("/api/auth/signup/verify")).toEqual([{ invite: "the-code", name: "Tom", oidcResult: "oidr_1", response: { id: "test-registration" } }])
    expect(shown()).toEqual(["signup-recovery"])
    expect($('[data-region="invite-terms"]').hidden).toBe(true)
    expect(paths()).not.toContain("/api/account/invites/join")
    await saveCodes()
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "the-code", oidcResult: "oidr_1" }])
    expect(shown()).toEqual(["signup-waiting"])
    expect(stepClasses()).toEqual(["done", "done", "done", "done"])
    expect($('[data-region="signup-waiting"] h2').textContent).toBe("Waiting for Northwind to confirm you")
    expect($('[data-region="signup-waiting"] code').textContent).toBe("I have joined Northwind on Mehen; please confirm me on the People page.")
    // The proof is spent; the code stays so a reload finds the wait.
    expect(storage.map.has(RESULT_KEY)).toBe(false)
    expect(storage.map.get(INVITE_KEY)).toBe("the-code")
    expect(browser!.assigned).toEqual([])
  })

  it("an already signed-in invitee with recovery ready: only the Google step and the join; on confirmation Connect an agent", async () => {
    vi.useFakeTimers()
    const storage = tab({ [INVITE_KEY]: "the-code" })
    let confirmed = false
    const answers: Answers = { account: () => ok(session(browser!.calls.some((c) => c.path === "/api/account/invites/join") ? [membership(confirmed ? "active" : "unconfirmed")] : [])) }
    browser?.restore()
    open(renderDocument(workspaceSignupPage(ready)).value, respond(answers), "https://vault.test/signup")
    ;(globalThis as Record<string, unknown>).sessionStorage = storage.store
    initWorkspaceSignup({ page: "workspace-signup", ...ready })
    await vi.advanceTimersByTimeAsync(0)
    expect(shown()).toEqual(["signup-verify"])
    expect(paths()).not.toContain("/api/auth/signup/options")
    browser!.restore()
    open(renderDocument(workspaceSignupPage(ready)).value, respond(answers), "https://vault.test/signup#oidc=oidr_2")
    ;(globalThis as Record<string, unknown>).sessionStorage = storage.store
    initWorkspaceSignup({ page: "workspace-signup", ...ready })
    await vi.advanceTimersByTimeAsync(0)
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "the-code", oidcResult: "oidr_2" }])
    expect(shown()).toEqual(["signup-waiting"])
    expect(paths()).not.toContain("/api/auth/signup/options")
    expect(paths()).not.toContain("/api/account/recovery/generate")
    await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
    expect(browser!.assigned).toEqual([])
    confirmed = true
    await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
    expect(browser!.assigned).toEqual(["https://vault.test/w/northwind/connect-agent"])
    expect(storage.map.size).toBe(0)
    expect(vi.getTimerCount()).toBe(0)
  })

  it("an invitation that lets them straight in skips the wait: the join answers active and the page goes where onboarding names", async () => {
    const storage = tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" })
    const joined = () => browser!.calls.some((c) => c.path === "/api/account/invites/join")
    await load(storage, "https://vault.test/signup", ready, { join: ok({ member: "mem_new", state: "active" }), account: () => ok(session(joined() ? [membership("active")] : [])) })
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "the-code", oidcResult: "oidr_1" }])
    expect(shown()).not.toContain("signup-waiting")
    expect(browser!.assigned).toEqual(["https://vault.test/w/northwind/connect-agent"])
    expect(storage.map.size).toBe(0)
  })

  it("Your name starts as the name Google gave with the proof, and stays editable; with no name from Google it stays empty", async () => {
    const google = (name: string | null): Answer => ok({ purpose: "invite", identity: { provider: "google", email: "tom@northwind.example", subject: "g-tom", name }, workspace: WORKSPACE.id })
    await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", signedOut, { result: google("  Tom Jones ") })
    expect(shown()).toEqual(["signup-passkey"])
    expect(($('[data-input="name"]') as MiniElement).value).toBe("Tom Jones")
    expect($('[data-action="signup"]').disabled).toBe(false)
    ;($('[data-input="name"]') as MiniElement).value = "Tom"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(bodyOf("/api/auth/signup/options")).toEqual([{ invite: "the-code", name: "Tom", oidcResult: "oidr_1" }])
    for (const name of [null, "   ", "x".repeat(65)]) {
      await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", signedOut, { result: google(name) })
      expect(shown()).toEqual(["signup-passkey"])
      expect(($('[data-input="name"]') as MiniElement).value).toBe("")
      expect($('[data-action="signup"]').disabled).toBe(true)
    }
    // An open guest link has no Google step, so nothing to fill it from.
    await load(tab(), "https://vault.test/signup#guest-code", signedOut, { peek: ok({ ...PEEK, role: "guest", bound: false }), result: google("Tom Jones") })
    expect(shown()).toEqual(["signup-passkey"])
    expect(paths()).not.toContain("/api/auth/oidc/google/result")
    expect(($('[data-input="name"]') as MiniElement).value).toBe("")
  })

  it("a stale Google proof shows Verify again and nothing else, and drops the proof", async () => {
    const storage = tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_old" })
    await load(storage, "https://vault.test/signup", ready, { join: { status: 403, body: { error: "identity_required", message: "Prove the invited email before joining.", next: PROOF_NEXT } } })
    expect(shown()).toEqual(["signup-verify"])
    expect($('[data-region="verify-lapsed"]').hidden).toBe(false)
    expect($('[data-region="verify-lapsed"]').textContent).toBe("Your email check has lapsed. Verify again to join.")
    expect($('[data-region="verify-lead"]').hidden).toBe(true)
    expect($("#notice").hidden).toBe(true)
    expect(storage.map.has(RESULT_KEY)).toBe(false)
    // A proof the vault no longer reads at all is the same lapse.
    const again = tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_gone" })
    await load(again, "https://vault.test/signup", signedOut, { result: { status: 403, body: { error: "identity_required", message: "Google verification could not be completed. Start the Google step again from the page that asked for it." } } })
    expect(shown()).toEqual(["signup-verify"])
    expect($('[data-region="verify-lapsed"]').hidden).toBe(false)
    expect(paths()).not.toContain("/api/auth/signup/options")
    expect(again.map.has(RESULT_KEY)).toBe(false)
  })

  it("a reload resumes at the same step from sessionStorage: 1, 2, 3 and 4", async () => {
    await load(tab({ [INVITE_KEY]: "the-code" }), "https://vault.test/signup", signedOut)
    expect(shown()).toEqual(["signup-verify"])
    await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", signedOut)
    expect(shown()).toEqual(["signup-passkey"])
    await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", { signedIn: true, recoveryReady: false })
    expect(shown()).toEqual(["signup-recovery"])
    expect(stepClasses()).toEqual(["done", "done", "current", "todo"])
    expect(paths()).not.toContain("/api/account/invites/join")
    // Step 4 before the join went through: it joins.
    await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", ready)
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "the-code", oidcResult: "oidr_1" }])
    expect(shown()).toEqual(["signup-waiting"])
    // Step 4 after it: the membership is there, so the page waits and never joins again.
    const after = tab({ [INVITE_KEY]: "the-code" })
    await load(after, "https://vault.test/signup", ready, { account: () => ok(session([membership("unconfirmed")])) })
    expect(shown()).toEqual(["signup-waiting"])
    expect(paths()).not.toContain("/api/account/invites/join")
    expect(paths()).not.toContain("/api/auth/oidc/google/result")
    // Already confirmed: where the vault's onboarding answer names, Connect an agent.
    const done = tab({ [INVITE_KEY]: "the-code" })
    await load(done, "https://vault.test/signup", ready, { account: () => ok(session([membership("active")])) })
    expect(paths().filter((p) => p.startsWith("/api/account/onboarding/"))).toEqual([`/api/account/onboarding/${WORKSPACE.id}`])
    expect(browser!.assigned).toEqual(["https://vault.test/w/northwind/connect-agent"])
    expect(done.map.size).toBe(0)
    // The home while the vault names it (an identity check due), and when it
    // cannot answer or names a place off this vault: never an error page.
    for (const [landing, home] of [
      [ok({ next: "https://vault.test/w/northwind/" }), "https://vault.test/w/northwind/"],
      [{ status: 503, body: { error: "upstream_failed", message: "Workspace security metadata is temporarily unavailable.", retryAfter: 60 } }, "/w/northwind/"],
      [ok({ next: "https://attacker.test/w/northwind/connect-agent" }), "/w/northwind/"],
    ] as const) {
      const fallback = tab({ [INVITE_KEY]: "the-code" })
      await load(fallback, "https://vault.test/signup", ready, { account: () => ok(session([membership("active")])), landing })
      expect(browser!.assigned).toEqual([home])
      expect($("#notice").hidden).toBe(true)
      expect(fallback.map.size).toBe(0)
    }
  })

  // Signing out in another tab, ending every session (sessions/end-all) and
  // a security change all end this browser's session: the vault answers 401.
  {
    const refusal = { error: "unauthenticated", message: "Sign in with your passkey to continue." }
    it("sign-out or every session ended mid-wait: the poll stops and links to sign in, next=/workspaces", async () => {
      vi.useFakeTimers()
      let gone = false
      browser?.restore()
      open(renderDocument(workspaceSignupPage(ready)).value, respond({ account: () => (gone ? { status: 401, body: refusal } : ok(session([membership("unconfirmed")]))) }), "https://vault.test/signup")
      ;(globalThis as Record<string, unknown>).sessionStorage = tab({ [INVITE_KEY]: "the-code" }).store
      initWorkspaceSignup({ page: "workspace-signup", ...ready })
      await vi.advanceTimersByTimeAsync(0)
      expect(shown()).toEqual(["signup-waiting"])
      await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
      expect($('[data-region="confirm-ended"]').hidden).toBe(true)
      gone = true
      await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
      expect($('[data-region="confirm-ended"]').hidden).toBe(false)
      expect($('[data-region="confirm-ended"]').textContent).toContain("Your session has ended. Sign in to keep waiting.")
      expect($('[data-region="confirm-ended"] a').getAttribute("href")).toBe("/signin?next=%2Fworkspaces")
      expect($('[data-region="confirm-retrying"]').hidden).toBe(true)
      expect(vi.getTimerCount()).toBe(0)
      const asked = paths().filter((p) => p === "/api/account").length
      await vi.advanceTimersByTimeAsync(10 * CONFIRMATION_POLL_MS)
      expect(paths().filter((p) => p === "/api/account").length).toBe(asked)
      expect(browser!.assigned).toEqual([])
    })
  }

  it("a membership removed while it waits: the poll stops and says it was not confirmed, with the way to the workspaces", async () => {
    vi.useFakeTimers()
    let removed = false
    browser?.restore()
    open(renderDocument(workspaceSignupPage(ready)).value, respond({ account: () => ok(session(removed ? [] : [membership("unconfirmed")])) }), "https://vault.test/signup")
    ;(globalThis as Record<string, unknown>).sessionStorage = tab({ [INVITE_KEY]: "the-code" }).store
    initWorkspaceSignup({ page: "workspace-signup", ...ready })
    await vi.advanceTimersByTimeAsync(0)
    expect(shown()).toEqual(["signup-waiting"])
    await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
    expect($('[data-region="confirm-removed"]').hidden).toBe(true)
    removed = true
    await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
    expect($('[data-region="confirm-removed"]').hidden).toBe(false)
    expect($('[data-region="confirm-removed"]').textContent).toContain(CONFIRMATION_REMOVED_WORDS)
    expect($('[data-region="confirm-removed"] a').getAttribute("href")).toBe("/workspaces")
    expect($('[data-region="confirm-ended"]').hidden).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    expect(browser!.assigned).toEqual([])
  })

  it("a transient confirmation-poll failure keeps waiting, says it is retrying, then moves on once confirmed", async () => {
    vi.useFakeTimers()
    const answers: (Answer | "network")[] = [ok(session([membership("unconfirmed")])), "network", { status: 503, body: { error: "upstream_failed", message: "Workspace security metadata is temporarily unavailable.", retryAfter: 60 } }, ok(session([membership("active")]))]
    browser?.restore()
    open(renderDocument(workspaceSignupPage(ready)).value, (path) => {
      if (path !== "/api/account") return respond()(path)
      const next = answers.shift()!
      if (next === "network") throw new TypeError("network down")
      return next
    }, "https://vault.test/signup")
    ;(globalThis as Record<string, unknown>).sessionStorage = tab({ [INVITE_KEY]: "the-code" }).store
    initWorkspaceSignup({ page: "workspace-signup", ...ready })
    await vi.advanceTimersByTimeAsync(0)
    expect(shown()).toEqual(["signup-waiting"])
    await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
    expect($('[data-region="confirm-retrying"]').hidden).toBe(false)
    expect($('[data-region="confirm-retrying"]').textContent).toBe("Could not check just now; retrying.")
    expect(shown()).toEqual(["signup-waiting"])
    await vi.advanceTimersByTimeAsync(nextRecoveryPoll(0, undefined))
    expect($('[data-region="confirm-retrying"]').hidden).toBe(false)
    // The vault asked for a minute: not sooner.
    await vi.advanceTimersByTimeAsync(59_000)
    expect(browser!.assigned).toEqual([])
    await vi.advanceTimersByTimeAsync(1_000)
    expect(browser!.assigned).toEqual(["https://vault.test/w/northwind/connect-agent"])
    expect(vi.getTimerCount()).toBe(0)
  })

  // The vault's onboarding `next` is followed only on this vault.
  for (const [name, next, followed] of [
    ["the workspace's home", "https://vault.test/w/northwind/", "https://vault.test/w/northwind/"],
    ["a same-origin address whose path starts //", "https://vault.test//attacker.test/path", "https://vault.test//attacker.test/path"],
    ["an external absolute address", "https://attacker.test/w/northwind/", null],
    ["a scheme-relative external address", "//attacker.test/path", null],
    ["a malformed address", "http://[", null],
  ] as const) {
    it(`once confirmed, follows ${name} ${followed === null ? "never, keeps the invitation and retries with backoff" : "as the absolute address on this vault"}`, async () => {
      vi.useFakeTimers()
      const storage = tab({ [INVITE_KEY]: "the-code" })
      browser?.restore()
      open(renderDocument(workspaceSignupPage(ready)).value, respond({ home: next, account: () => ok(session([membership(paths().filter((p) => p === "/api/account").length > 1 ? "active" : "unconfirmed")])) }), "https://vault.test/signup")
      ;(globalThis as Record<string, unknown>).sessionStorage = storage.store
      initWorkspaceSignup({ page: "workspace-signup", ...ready })
      await vi.advanceTimersByTimeAsync(0)
      expect(shown()).toEqual(["signup-waiting"])
      await vi.advanceTimersByTimeAsync(CONFIRMATION_POLL_MS)
      expect(paths().filter((p) => p.startsWith("/api/account/onboarding/"))).toHaveLength(1)
      if (followed !== null) {
        expect(browser!.assigned).toEqual([followed])
        expect(storage.map.size).toBe(0)
        expect(vi.getTimerCount()).toBe(0)
        return
      }
      expect(browser!.assigned).toEqual([])
      expect(storage.map.get(INVITE_KEY)).toBe("the-code")
      expect($('[data-region="confirm-retrying"]').hidden).toBe(false)
      // Not hot: the next check waits the backoff.
      const asked = browser!.calls.length
      await vi.advanceTimersByTimeAsync(nextRecoveryPoll(0, undefined) - 1)
      expect(browser!.calls.length).toBe(asked)
      await vi.advanceTimersByTimeAsync(1)
      expect(paths().filter((p) => p.startsWith("/api/account/onboarding/"))).toHaveLength(2)
      expect(browser!.assigned).toEqual([])
      expect(vi.getTimerCount()).toBe(1)
    })
  }

  it("never sends a Google proof without a stored invitation", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#oidc=oidr_stray", signedOut)
    expect(shown()).toEqual(["signup-no-invite"])
    expect($('[data-region="signup-no-invite"]').textContent).toContain("Mehen never creates accounts on its own.")
    expect(browser!.calls).toEqual([])
    expect(storage.map.size).toBe(0)
    // A new invitation replaces the stored one and drops the old one's proof.
    const swapped = tab({ [INVITE_KEY]: "old-code", [RESULT_KEY]: "oidr_old" })
    await load(swapped, "https://vault.test/signup#new-code", signedOut)
    expect(swapped.map.get(INVITE_KEY)).toBe("new-code")
    expect(swapped.map.has(RESULT_KEY)).toBe(false)
    expect(shown()).toEqual(["signup-verify"])
    expect(JSON.stringify(browser!.calls)).not.toContain("oidcResult")
  })

  it("an open guest invitation skips the Google step and sends no proof", async () => {
    const storage = tab({ [RESULT_KEY]: "oidr_stray" })
    await load(storage, "https://vault.test/signup#guest-code", signedOut, { peek: ok({ ...PEEK, role: "guest", bound: false }) })
    expect(shown()).toEqual(["signup-passkey"])
    expect(stepClasses()).toEqual(["hidden", "current", "todo", "todo"])
    expect($('[data-region="signup-invite"] h1').textContent).toBe("You are invited to Northwind as a guest.")
    ;($('[data-input="name"]') as MiniElement).value = "Gina"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    await saveCodes()
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "guest-code" }])
    expect(JSON.stringify(browser!.calls)).not.toContain("oidcResult")
  })

  it("bootstrap: an unknown code signed out is the plain passkey step; after recovery the first account goes to its workspaces and never joins", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#the-bootstrap-code", signedOut, { peek: { status: 404, body: { error: "not_found", message: "No such invite." } }, onboarding: "bootstrap" })
    expect(shown()).toEqual(["signup-passkey"])
    expect($('[data-region="signup-plain"]').hidden).toBe(false)
    expect($('[data-region="signup-plain-lead"]').hidden).toBe(false)
    expect($('[data-region="signup-bootstrap-lead"]').hidden).toBe(true)
    expect($('[data-region="signup-invite"]').hidden).toBe(true)
    ;($('[data-input="name"]') as MiniElement).value = "Alex"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(bodyOf("/api/auth/signup/verify")).toEqual([{ invite: "the-bootstrap-code", name: "Alex", response: { id: "test-registration" } }])
    expect($('[data-region="signup-plain-lead"]').hidden).toBe(true)
    expect($('[data-region="signup-bootstrap-lead"]').hidden).toBe(false)
    await saveCodes()
    expect(browser!.assigned).toEqual(["/workspaces"])
    expect(paths()).not.toContain("/api/account/invites/join")
    expect(storage.map.size).toBe(0)
  })

  it("a new vault's owner is welcomed, never told an invitation may have expired, and the welcome goes once the account exists", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#the-bootstrap-code", { ...signedOut, firstAccount: true }, { onboarding: "bootstrap" })
    expect(shown()).toEqual(["signup-passkey"])
    // No invitation to peek at on a vault with no account, and no account to sign in with.
    expect(paths()).not.toContain("/api/auth/invite/peek")
    expect(browser!.document.querySelector("title")?.textContent).toBe("Welcome to your vault · Mehen")
    expect($('[data-region="signup-passkey"]').textContent).not.toContain("Already have an account here?")
    expect($('[data-region="signup-plain"] h1').textContent).toBe("Welcome to your vault")
    expect($('[data-region="signup-first-lead"]').hidden).toBe(false)
    expect($('[data-region="signup-plain-lead"]').hidden).toBe(true)
    ;($('[data-input="name"]') as MiniElement).value = "Alex"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect($('[data-region="signup-first-lead"]').hidden).toBe(true)
    expect($('[data-region="signup-bootstrap-lead"]').hidden).toBe(false)
  })

  it("bootstrap survives a reload: the spent code goes, the returned account is kept, and recovery resumes for that account only", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#the-bootstrap-code", signedOut, { peek: { status: 404, body: { error: "not_found", message: "No such invite." } }, onboarding: "bootstrap" })
    ;($('[data-input="name"]') as MiniElement).value = "Alex"
    submit($('[data-form="workspace-signup"]'))
    await settle()
    expect(shown()).toEqual(["signup-recovery"])
    expect([...storage.map]).toEqual([[BOOTSTRAP_KEY, "acc_new"]])

    // Reloaded before recovery: signed in now, the vault names the same account and recovery is missing.
    const recoveryMissing = { ...session(), recoverySetupRequired: true }
    await load(storage, "https://vault.test/signup", { signedIn: true, recoveryReady: false }, { peek: { status: 404, body: { error: "not_found", message: "No such invite." } }, account: () => ok(recoveryMissing) })
    expect(shown()).toEqual(["signup-recovery"])
    expect($('[data-region="signup-plain"]').hidden).toBe(false)
    expect($('[data-region="signup-plain-lead"]').hidden).toBe(true)
    expect($('[data-region="signup-bootstrap-lead"]').hidden).toBe(false)
    expect(paths()).toEqual(["/api/account"])
    await saveCodes()
    expect(browser!.assigned).toEqual(["/workspaces"])
    expect(paths()).not.toContain("/api/account/invites/join")
    expect(paths()).not.toContain("/api/auth/invite/peek")
    expect(storage.map.size).toBe(0)
  })

  it("bootstrap reloaded after recovery is done goes on to the workspaces", async () => {
    const storage = tab({ [BOOTSTRAP_KEY]: "acc_new" })
    await load(storage, "https://vault.test/signup", ready, { account: () => ok(session()) })
    expect(browser!.assigned).toEqual(["/workspaces"])
    expect(shown()).toEqual([])
    expect(storage.map.size).toBe(0)
  })

  it("a bootstrap marker never resumes for another signed-in account, or signed out", async () => {
    const other = tab({ [BOOTSTRAP_KEY]: "acc_new" })
    await load(other, "https://vault.test/signup", { signedIn: true, recoveryReady: false }, { account: () => ok({ ...session(), account: "acc_other", recoverySetupRequired: true }) })
    expect(shown()).toEqual(["signup-no-invite"])
    expect(browser!.assigned).toEqual([])
    expect(other.map.size).toBe(0)
    const out = tab({ [BOOTSTRAP_KEY]: "acc_new" })
    await load(out, "https://vault.test/signup", signedOut)
    expect(shown()).toEqual(["signup-no-invite"])
    expect(browser!.calls).toEqual([])
    expect(out.map.size).toBe(0)
    // An invitation opened in the tab replaces the marker.
    const opened = tab({ [BOOTSTRAP_KEY]: "acc_new" })
    await load(opened, "https://vault.test/signup#the-code", signedOut)
    expect(shown()).toEqual(["signup-verify"])
    expect(opened.map.has(BOOTSTRAP_KEY)).toBe(false)
  })

  it("signed in, an invitation that does not work says so and offers nothing to sign", async () => {
    const storage = tab()
    await load(storage, "https://vault.test/signup#dead-code", ready, { peek: { status: 404, body: { error: "not_found", message: "No such invite." } } })
    expect(shown()).toEqual(["signup-invite-unknown"])
    expect(paths()).toEqual(["/api/auth/invite/peek"])
    expect(storage.map.size).toBe(0)
  })

  it("a second passkey instead of codes satisfies recovery through the account endpoints, then joins", async () => {
    await load(tab({ [INVITE_KEY]: "the-code", [RESULT_KEY]: "oidr_1" }), "https://vault.test/signup", { signedIn: true, recoveryReady: false })
    expect($('[data-action="make-codes"]').textContent).toContain("Save recovery codes")
    expect($('[data-action="add-second-passkey"]').textContent).toBe("Or add a second passkey")
    $('[data-action="add-second-passkey"]').click()
    await settle()
    expect(browser!.calls.find((c) => c.path === "/api/account/stepup/start")?.body).toEqual({ action: { type: "passkey.add" } })
    expect(browser!.calls.find((c) => c.path === "/api/account/passkeys/verify")?.body).toEqual({ response: { id: "test-registration" }, name: "Second passkey" })
    expect(bodyOf("/api/account/invites/join")).toEqual([{ code: "the-code", oidcResult: "oidr_1" }])
    expect(paths()).not.toContain("/api/stepup")
  })
})

describe("a new workspace", () => {
  it("suggests the short name from the name: lower case, dashes for spaces, letters, digits and single dashes, 3 to 40", () => {
    expect(suggestWorkspaceSlug("Acme Corp")).toBe("acme-corp")
    expect(suggestWorkspaceSlug("  Alex's  Home  Lab ")).toBe("alexs-home-lab")
    expect(suggestWorkspaceSlug("Zürich Café")).toBe("zurich-cafe")
    expect(suggestWorkspaceSlug("2026 Plans")).toBe("plans")
    expect(suggestWorkspaceSlug("a -- b -- c")).toBe("a-b-c")
    expect(suggestWorkspaceSlug("x".repeat(39) + " y")).toBe("x".repeat(39))
    for (const short of ["", "Me", "!!", "12", "日本"]) expect(suggestWorkspaceSlug(short), short).toBeNull()
  })

  it("fills the short name as the name is typed, until the person edits the short name", () => {
    const entry = accountGallery().find((e) => e.id === "workspaces-new")!
    open(renderDocument(entry.page).value, () => never())
    initWorkspaceCreate()
    const name = $('[data-input="workspace-name"]')
    const slug = $('[data-input="workspace-slug"]')
    const type = (input: MiniElement, value: string) => {
      input.value = value
      input.dispatchEvent(new MiniEvent("input", { bubbles: true }))
    }
    type(name, "Home")
    expect(slug.value).toBe("home")
    type(name, "Home Lab")
    expect(slug.value).toBe("home-lab")
    type(name, "Me")
    expect(slug.value).toBe("")
    type(name, "Home Lab")
    type(slug, "lab")
    type(name, "Home Lab Two")
    expect(slug.value).toBe("lab")
  })
})

// A deep link's fragment, kept by the browser across the sign-in redirect,
// is put back on the page sign-in returns to.
describe("sign in from a deep link", () => {
  const NEXT = "/w/northwind/people"
  const signin = (href: string) => {
    open(renderDocument(signinPage(NEXT)).value, (path) => (path === "/api/auth/signin/options" ? ok({ flow: "flow_1", options: { challenge: "c" } }) : ok()), href)
    initSignin({ page: "signin", next: NEXT })
    $('[data-action="signin"]').click()
  }

  it("returns to the page with the fragment the link carried", async () => {
    signin(`https://vault.test/signin?next=${encodeURIComponent(NEXT)}#confirm-mem_tom01`)
    await settle()
    expect(paths()).toEqual(["/api/auth/signin/options", "/api/auth/signin/verify"])
    expect(browser!.assigned).toEqual(["/w/northwind/people#confirm-mem_tom01"])
  })

  it("returns to the page as named when the link had no fragment", async () => {
    signin(`https://vault.test/signin?next=${encodeURIComponent(NEXT)}`)
    await settle()
    expect(browser!.assigned).toEqual([NEXT])
  })
})

describe("the account page", () => {
  const entry = () => accountGallery().find((e) => e.id === "account")!
  const failed = (status: number, error: string, message: string): Answer => ({ status, body: { error, message } })

  // The account page in this browser, with confirm() answering `yes` and
  // this browser's own storage and colour scheme for the appearance chips.
  function openAccount(respond: (path: string, body: unknown) => Answer | Promise<never>, yes = true) {
    open(renderDocument(entry().page).value, respond, "https://vault.test/account")
    const g = globalThis as Record<string, unknown>
    const saved = { confirm: g.confirm, localStorage: g.localStorage, matchMedia: g.matchMedia }
    const stored = new Map<string, string>()
    const asked: string[] = []
    g.confirm = (text: string) => (asked.push(text), yes)
    g.localStorage = { getItem: (k: string) => stored.get(k) ?? null, setItem: (k: string, v: string) => void stored.set(k, v), removeItem: (k: string) => void stored.delete(k) }
    g.matchMedia = () => ({ matches: false })
    Object.assign(browser!.document, { documentElement: browser!.document.querySelector("html") })
    const restore = browser!.restore
    browser!.restore = () => {
      restore()
      Object.assign(g, saved)
    }
    initAccount()
    return { stored, asked }
  }

  it("renames a passkey through the account route, with no passkey prompt", async () => {
    openAccount((path) => (path.endsWith("/rename") ? ok({ passkey: {} }) : never()))
    const row = `[data-passkey-row="${ACCOUNT_PASSKEYS[1]!.passkey}"]`
    $(`${row} [data-action="rename-passkey"]`).click()
    expect($(`${row} [data-region="rename"]`).hidden).toBe(false)
    ;($(`${row} [data-input="rename"]`) as MiniElement).value = "YubiKey"
    $(`${row} [data-action="save-rename"]`).click()
    await settle()
    expect(browser!.calls).toEqual([{ path: `/api/account/passkeys/${ACCOUNT_PASSKEYS[1]!.passkey}/rename`, body: { name: "YubiKey" } }])
    expect(browser!.reloaded).toBe(1)
  })

  it("removes a passkey only after a passkey step-up for exactly that passkey, and shows the vault's refusal", async () => {
    const target = ACCOUNT_PASSKEYS[1]!.passkey
    openAccount((path) => (path === "/api/account/stepup/start" ? ok({ nonce: "n", options: { challenge: "c" } }) : path.endsWith("/remove") ? failed(409, "conflict", "Keep at least one account passkey.") : never()))
    $(`[data-action="remove-passkey"][data-passkey="${target}"]`).click()
    await settle()
    expect(browser!.calls).toEqual([
      { path: "/api/account/stepup/start", body: { action: { type: "passkey.remove", passkey: target } } },
      { path: `/api/account/passkeys/${target}/remove`, body: { stepUp: { nonce: "n", assertion: { id: "test-assertion" } } } },
    ])
    expect(browser!.reloaded).toBe(0)
    expect($("#notice").textContent).toContain("Keep at least one account passkey.")
  })

  it("asks first and sends nothing when the removal is not confirmed", async () => {
    const { asked } = openAccount(() => never(), false)
    $(`[data-action="remove-passkey"][data-passkey="${ACCOUNT_PASSKEYS[0]!.passkey}"]`).click()
    await settle()
    expect(asked[0]).toContain("Remove MacBook Touch ID?")
    expect(browser!.calls).toEqual([])
  })

  it("adds a passkey: a step-up, then the new passkey, through the account routes", async () => {
    openAccount((path) => (path === "/api/account/stepup/start" ? ok({ nonce: "n", options: { challenge: "c" } }) : path === "/api/account/passkeys/options" ? ok({ options: { challenge: "c" } }) : path === "/api/account/passkeys/verify" ? ok({ passkey: {} }) : never()))
    ;($('[data-input="passkey-name"]') as MiniElement).value = "Desk key"
    $('[data-action="add-passkey"][data-kind="security-key"]').click()
    await settle()
    expect(browser!.calls).toEqual([
      { path: "/api/account/stepup/start", body: { action: { type: "passkey.add" } } },
      { path: "/api/account/passkeys/options", body: { stepUp: { nonce: "n", assertion: { id: "test-assertion" } }, kind: "security-key" } },
      { path: "/api/account/passkeys/verify", body: { response: { id: "test-registration" }, name: "Desk key" } },
    ])
    expect(browser!.reloaded).toBe(1)
    expect(paths()).not.toContain("/api/stepup")
  })

  it("ends another session in place, and ending this browser's own says so and goes to sign in", async () => {
    const { asked } = openAccount((path) => (path.endsWith("/end") ? ok() : never()))
    $('[data-action="end-session"][data-session="ses_phone01"]').click()
    await settle()
    expect(browser!.calls).toEqual([{ path: "/api/account/sessions/ses_phone01/end", body: {} }])
    expect(asked).toEqual([])
    expect(browser!.reloaded).toBe(1)
    $('[data-action="end-session"][data-session="ses_current01"]').click()
    await settle()
    expect(asked).toEqual(["Sign out of this browser? You will need your passkey to sign in here again."])
    expect(browser!.calls[1]).toEqual({ path: "/api/account/sessions/ses_current01/end", body: {} })
    expect(browser!.assigned).toEqual(["/signin"])
  })

  it("signs out everywhere, this browser included, only once confirmed", async () => {
    const declined = openAccount(() => never(), false)
    $('[data-action="end-all-sessions"]').click()
    await settle()
    expect(declined.asked[0]).toContain("this browser too")
    expect(browser!.calls).toEqual([])
    browser!.restore()
    openAccount((path) => (path === "/api/account/sessions/end-all" ? ok({ pending: false }) : never()))
    $('[data-action="end-all-sessions"]').click()
    await settle()
    expect(browser!.calls).toEqual([{ path: "/api/account/sessions/end-all", body: {} }])
    expect(browser!.assigned).toEqual(["/signin"])
  })

  it("Ask every time ends this browser's passkey grace window with no passkey prompt", async () => {
    openAccount((path) => (path === "/api/account/stepup/grace/end" ? ok({}) : never()))
    expect($('[data-region="stepup-grace"]').textContent).toContain("Passkey confirmed, no need to confirm again until")
    $('[data-action="end-stepup-grace"]').click()
    await settle()
    expect(browser!.calls).toEqual([{ path: "/api/account/stepup/grace/end", body: {} }])
    expect(browser!.reloaded).toBe(1)
  })

  it("keeps the appearance choice in this browser only", () => {
    const { stored } = openAccount(() => never())
    $('[data-theme-choice="dark"]').click()
    expect(stored.get("mehen-theme")).toBe("dark")
    expect($('[data-theme-choice="dark"]').getAttribute("aria-pressed")).toBe("true")
    expect($('[data-theme-choice="light"]').getAttribute("aria-pressed")).toBe("false")
    $('[data-theme-choice="light"]').click()
    expect(stored.has("mehen-theme")).toBe(false)
    expect(browser!.calls).toEqual([])
  })
})

describe("people", () => {
  function owner(data = peopleData("owner")) {
    return renderDocument(peoplePage(peopleShell("owner"), data)).value
  }

  it("confirmation enables signing only for the terms whose digest the vault returns", async () => {
    for (const [digest, enabled] of [["dgst_hostile_terms", true], ["dgst_other", false]] as const) {
      open(owner(), (path) => (path.endsWith("/members/mem_hostile01/action") ? ok({ action: { type: "member.confirm", member: "mem_hostile01", termsDigest: digest, identityRuleRevision: 0 } }) : never()))
      initPeople({ page: "people" }, shell())
      $('[data-action="member-confirm"]').click()
      await settle()
      expect($('[data-action="member-confirm-sign"]').disabled, digest).toBe(!enabled)
      expect($('[data-region="confirm-error"]').hidden, digest).toBe(enabled)
      browser!.restore()
    }
  })

  it("confirmation stays unsigned when what the terms delegate cannot be read", async () => {
    const invites = PEOPLE_INVITES.map((i) => (i.id === "inv_used01" ? { ...i, terms: { ...i.terms, shares: [{ project: "prj_site01", level: "edit" as const, protected: false, expiresAt: null }] } } : i))
    open(owner({ ...peopleData("owner"), invites, credentials: null }), (path) => (path.endsWith("/action") ? ok({ action: { type: "member.confirm", member: "mem_hostile01", termsDigest: "dgst_hostile_terms", identityRuleRevision: 0 } }) : never()))
    initPeople({ page: "people" }, shell())
    $('[data-action="member-confirm"]').click()
    await settle()
    expect($('[data-action="member-confirm-sign"]').disabled).toBe(true)
    expect($('[data-region="confirm-error"]').textContent).toContain("could not be read")
  })

  it("the invite form shows what the ticked projects delegate, and cannot be signed when that is unknown", () => {
    open(owner(), () => never())
    initPeople({ page: "people" }, shell())
    expect($('[data-region="invite-delegation"]').hidden).toBe(true)
    $('[data-share="prj_site01"] [data-input="invite-project"]').click()
    expect($('[data-region="invite-delegation"]').hidden).toBe(false)
    expect($('[data-region="invite-delegation-list"]').textContent).toBe("openai-shared")
    expect($('[data-action="invite-create"]').disabled).toBe(false)
    $('[data-share="prj_site01"] [data-input="invite-project"]').click()
    $('[data-share="prj_platform01"] [data-input="invite-project"]').click()
    expect($('[data-region="invite-delegation-list"]').textContent).toBe("No whole-workspace credentials")
    browser!.restore()
    open(owner({ ...peopleData("owner"), credentials: null }), () => never())
    initPeople({ page: "people" }, shell())
    $('[data-share="prj_site01"] [data-input="invite-project"]').click()
    expect($('[data-region="invite-delegation-unknown"]').hidden).toBe(false)
    expect($('[data-action="invite-create"]').disabled).toBe(true)
  })
})

describe("machine scope changes", () => {
  const viewer = { member: "mem_alex01", role: "owner" as const, blocked: false }
  const planned = () => browser!.calls.find((c) => c.path.endsWith("/action"))?.body as { change: { kind: string; after: { projects: string[]; modes: string[] } } } | undefined

  function machine(device: typeof PEOPLE_DEVICE, projects: typeof PEOPLE_PROJECTS | null, who = viewer, fill?: boolean) {
    const page = machinePage(peopleShell(who.role, { member: who.member }), device, { viewer: who, projects, now: 0, ...(fill !== undefined ? { fill } : {}) })
    open(renderDocument(page).value, (path) => (path.endsWith("/action") ? ok({ action: { type: "device.revoke", device: device.device } }) : never()))
    initMachine(page.boot, shell())
  }

  function untickMode(mode: string) {
    $(`[data-input="scope-mode"][value="${mode}"]`).click()
  }

  for (const [name, projects] of [["unreadable", null], ["partly hidden", PEOPLE_PROJECTS]] as const) {
    it(`keeps the project filter when the project list is ${name}: narrowing a mode stays a narrowing`, async () => {
      machine({ ...PEOPLE_DEVICE, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_hidden"] } }, projects)
      untickMode("sign")
      submit($('[data-form="scope-change"]'))
      await settle()
      expect(planned()?.change.kind).toBe("rescope")
      expect(planned()?.change.after.projects).toEqual(["prj_hidden"])
    })
  }

  describe("typing into web pages", () => {
    const fillTick = () => browser!.document.querySelector('[data-input="scope-mode"][value="fill"]')
    const UPDATE_FIRST = "Update mehen on this machine first (0.3.17 or later)."

    it("is not offered where it is off: the form is today's", () => {
      machine({ ...PEOPLE_DEVICE, lastCliVersion: "0.3.17" }, PEOPLE_PROJECTS, viewer, false)
      expect(fillTick()).toBeNull()
      expect($("main").textContent).not.toContain("web pages")
    })

    it("is a tick on a machine whose mehen can type, and ticking it proposes the wider scope", async () => {
      machine({ ...PEOPLE_DEVICE, lastCliVersion: "0.3.17" }, PEOPLE_PROJECTS, viewer, true)
      expect(fillTick()?.disabled).toBe(false)
      expect(fillTick()?.parent?.textContent).toContain("Typing into web pages")
      expect($("main").textContent).not.toContain(UPDATE_FIRST)
      fillTick()!.click()
      submit($('[data-form="scope-change"]'))
      await settle()
      expect(planned()?.change).toMatchObject({ kind: "rescope_propose", after: { modes: ["relay", "sign", "mint", "placeholder", "fill"] } })
    })

    for (const version of ["0.3.16", null]) {
      it(`is off with the words to update first on a machine running ${version ?? "an unknown version"}`, () => {
        machine({ ...PEOPLE_DEVICE, lastCliVersion: version }, PEOPLE_PROJECTS, viewer, true)
        expect(fillTick()?.disabled).toBe(true)
        expect($('[data-region="fill-update-first"]').textContent).toBe(UPDATE_FIRST)
      })
    }

    it("stays ticked and can be taken away on a machine that has it, whatever its version", async () => {
      machine({ ...PEOPLE_DEVICE, lastCliVersion: "0.3.16", scope: { ...PEOPLE_DEVICE.scope, modes: ["relay", "fill"] } }, PEOPLE_PROJECTS, viewer, true)
      expect(fillTick()?.checked).toBe(true)
      expect(fillTick()?.disabled).toBe(false)
      untickMode("fill")
      submit($('[data-form="scope-change"]'))
      await settle()
      expect(planned()?.change).toMatchObject({ kind: "rescope", after: { modes: ["relay"] } })
    })

    it("is never a machine's only way, said before any passkey", async () => {
      machine({ ...PEOPLE_DEVICE, lastCliVersion: "0.3.17", scope: { ...PEOPLE_DEVICE.scope, modes: ["relay", "fill"] } }, PEOPLE_PROJECTS, viewer, true)
      untickMode("relay")
      submit($('[data-form="scope-change"]'))
      await settle()
      expect(browser!.calls).toEqual([])
      expect($("#notice").textContent).toContain("A machine needs at least one other way to use credentials besides typing into web pages.")
    })
  })

  it("a team machine with an unreadable project list never drifts to every project", async () => {
    machine({ ...PEOPLE_DEVICE, owner: { kind: "team", team: "tm_platform01", name: "Platform" }, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_site01"] } }, null)
    untickMode("mint")
    submit($('[data-form="scope-change"]'))
    await settle()
    expect(planned()?.change).toMatchObject({ kind: "rescope", after: { projects: ["prj_site01"] } })
  })

  it("clearing every project on purpose is a widening proposal", async () => {
    machine({ ...PEOPLE_DEVICE, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_site01"] } }, PEOPLE_PROJECTS)
    $('[data-input="scope-project"][value="prj_site01"]').click()
    submit($('[data-form="scope-change"]'))
    await settle()
    expect(planned()?.change).toMatchObject({ kind: "rescope_propose", after: { projects: [] } })
  })

  it("a guest can narrow but is told to ask an insider for anything wider, with nothing sent", async () => {
    const guest = { member: "mem_guest01", role: "guest" as const, blocked: false }
    machine({ ...PEOPLE_DEVICE, owner: { kind: "member", member: "mem_guest01", name: "Gina" }, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_site01"] } }, PEOPLE_PROJECTS, guest)
    $('[data-input="scope-project"][value="prj_site01"]').click()
    submit($('[data-form="scope-change"]'))
    await settle()
    expect(browser!.calls).toEqual([])
    expect($("#notice").textContent).toContain(NARROW_ONLY_WORDS)
    browser!.restore()
    machine({ ...PEOPLE_DEVICE, owner: { kind: "member", member: "mem_guest01", name: "Gina" } }, PEOPLE_PROJECTS, guest)
    untickMode("sign")
    submit($('[data-form="scope-change"]'))
    await settle()
    expect(planned()?.change.kind).toBe("rescope")
  })
})

describe("recovery", () => {
  it("flag on: a recovery code always continues to the passkey page, never to a guessed place", async () => {
    const code = generateRecoveryCode()
    open(renderDocument(recoverPage(true)).value, (path) => (path === "/api/auth/recovery" ? { status: 202, body: { pending: true, transition: "trn_1" } } : never()))
    initRecover({ page: "recover", workspaces: true })
    ;($('[data-input="recovery-code"]') as MiniElement).value = code
    submit($('[data-form="recover"]'))
    await settle()
    expect(browser!.assigned).toEqual(["/recover/passkey"])
  })

  it("the pending page polls the ceremony's status and reloads once it is no longer pending", async () => {
    vi.useFakeTimers()
    let state = "pending"
    open(renderDocument(recoverPendingPage()).value, (path) => (path === "/api/auth/recovery/status" ? ok({ state }) : never()))
    initRecoverPending()
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(paths()).toEqual(["/api/auth/recovery/status"])
    expect(browser!.reloaded).toBe(0)
    expect(vi.getTimerCount()).toBe(1)
    state = "live"
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(browser!.reloaded).toBe(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it("a rate-limited status read waits the vault's retryAfter, then keeps polling until live, never resending the code", async () => {
    vi.useFakeTimers()
    const answers: Answer[] = [{ status: 429, body: { error: "rate_limited", message: "Too many attempts. Try again shortly.", retryAfter: 40 } }, ok({ state: "pending" }), ok({ state: "live" })]
    open(renderDocument(recoverPendingPage()).value, (path) => (path === "/api/auth/recovery/status" ? answers.shift()! : never()))
    initRecoverPending()
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(browser!.calls).toHaveLength(1)
    expect($("#notice").hidden).toBe(false)
    expect(vi.getTimerCount()).toBe(1)
    await vi.advanceTimersByTimeAsync(39_000)
    expect(browser!.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(browser!.calls).toHaveLength(2)
    expect(browser!.reloaded).toBe(0)
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(browser!.calls).toHaveLength(3)
    expect(browser!.reloaded).toBe(1)
    expect(paths().every((p) => p === "/api/auth/recovery/status")).toBe(true)
    expect(browser!.document.querySelector('[data-form="recover-passkey"]')).toBeNull()
  })

  it("a network failure and then a server error back off, and the next live read reloads once", async () => {
    vi.useFakeTimers()
    const answers: (Answer | "network")[] = ["network", { status: 503, body: { error: "upstream_failed", message: "The vault is busy." } }, ok({ state: "live" })]
    open(renderDocument(recoverPendingPage()).value, (path) => {
      if (path !== "/api/auth/recovery/status") return never()
      const next = answers.shift()!
      if (next === "network") throw new TypeError("network down")
      return next
    })
    initRecoverPending()
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(browser!.calls).toHaveLength(1)
    expect(nextRecoveryPoll(0, undefined)).toBe(RECOVERY_POLL_MS)
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(browser!.calls).toHaveLength(2)
    expect(browser!.reloaded).toBe(0)
    // The second failure doubles the wait.
    await vi.advanceTimersByTimeAsync(2 * RECOVERY_POLL_MS - 1)
    expect(browser!.calls).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1)
    expect(browser!.calls).toHaveLength(3)
    expect(browser!.reloaded).toBe(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it("two pending tabs stay well inside the shared sign-in limiter, and wait it out when it is spent", async () => {
    vi.useFakeTimers()
    // The production limiter: 20 reads a minute for the address both tabs share.
    const LIMIT = 20
    let window = 0, state = "pending", limited = 0
    const perMinute: number[] = []
    open(renderDocument(recoverPendingPage()).value, (path) => {
      if (path !== "/api/auth/recovery/status") return never()
      window += 1
      if (window > LIMIT) {
        limited += 1
        return { status: 429, body: { error: "rate_limited", message: "Too many attempts.", retryAfter: 60 } }
      }
      return ok({ state })
    })
    initRecoverPending()
    initRecoverPending()
    for (let minute = 0; minute < 10; minute++) {
      await vi.advanceTimersByTimeAsync(60_000)
      perMinute.push(window)
      window = 0
    }
    expect(Math.max(...perMinute)).toBeLessThanOrEqual(8)
    expect(limited).toBe(0)
    expect(vi.getTimerCount()).toBe(2)
    // Spend the shared budget from elsewhere: each tab is refused once, then
    // waits the full minute it was told before asking again.
    window = LIMIT
    const before = browser!.calls.length
    await vi.advanceTimersByTimeAsync(RECOVERY_POLL_MS)
    expect(limited).toBe(2)
    window = 0
    await vi.advanceTimersByTimeAsync(59_000)
    expect(browser!.calls.length).toBe(before + 2)
    state = "live"
    await vi.advanceTimersByTimeAsync(1_000)
    expect(browser!.reloaded).toBe(2)
    expect(vi.getTimerCount()).toBe(0)
  })

  it("Copy and Download hand over the ten codes one a line, and typing one back is still asked for", async () => {
    const codes = Array.from({ length: 10 }, generateRecoveryCode)
    const entry = accountGallery().find((e) => e.id === "account-recovery")!
    open(renderDocument(entry.page).value, (path) => (path === "/api/account/stepup/start" ? ok({ nonce: "n", options: {} }) : path === "/api/account/recovery/generate" ? ok({ batch: "b", codes, confirmPosition: 3, expiresAt: "x" }) : never()))
    const copied: string[] = []
    vi.stubGlobal("navigator", { clipboard: { writeText: async (text: string) => void copied.push(text) } })
    const saved: { name: unknown; href: string; blob: Blob }[] = []
    const blobs = new Map<string, Blob>()
    const urls = URL as unknown as Record<string, unknown>
    const before = { create: urls.createObjectURL, revoke: urls.revokeObjectURL }
    urls.createObjectURL = (blob: Blob) => {
      const href = `blob:https://vault.test/${blobs.size}`
      blobs.set(href, blob)
      return href
    }
    urls.revokeObjectURL = () => undefined
    const document = browser!.document as unknown as { createElement: (tag: string) => MiniElement }
    const create = document.createElement
    document.createElement = (tag: string) => {
      const made = create(tag)
      if (tag === "a") made.addEventListener("click", () => saved.push({ name: (made as unknown as { download?: unknown }).download, href: made.href, blob: blobs.get(made.href)! }))
      return made
    }
    try {
      initAccountRecovery()
      // The second passkey comes after the codes, never above them.
      const order = browser!.document.querySelectorAll('[data-action="make-codes"], [data-region="codes-issued"], [data-action="add-second-passkey"]').map((e) => e.getAttribute("data-action") ?? e.getAttribute("data-region"))
      expect(order).toEqual(["make-codes", "codes-issued", "add-second-passkey"])
      $('[data-action="make-codes"]').click()
      await settle()
      $('[data-action="copy-codes"]').click()
      await settle()
      expect(copied).toEqual([`${codes.join("\n")}\n`])
      $('[data-action="download-codes"]').click()
      expect(saved.map((d) => d.name)).toEqual(["mehen-recovery-codes.txt"])
      expect(await saved[0]!.blob.text()).toBe(`${codes.join("\n")}\n`)
      expect($('[data-region="codes-issued"]').hidden).toBe(false)
      expect($('[data-region="codes-position"]').textContent).toBe("3")
      expect($('[data-region="recovery-done"]').hidden).toBe(true)
    } finally {
      document.createElement = create
      urls.createObjectURL = before.create
      urls.revokeObjectURL = before.revoke
      vi.unstubAllGlobals()
    }
  })

  it("the account recovery page wires the same recovery step", async () => {
    const entry = accountGallery().find((e) => e.id === "account-recovery")!
    open(renderDocument(entry.page).value, (path) => (path === "/api/account/stepup/start" ? ok({ nonce: "n", options: {} }) : path === "/api/account/recovery/generate" ? ok({ batch: "b", codes: Array.from({ length: 10 }, generateRecoveryCode), confirmPosition: 1, expiresAt: "x" }) : never()))
    initAccountRecovery()
    $('[data-action="make-codes"]').click()
    await settle()
    expect($('[data-region="codes-issued"]').hidden).toBe(false)
  })
})
