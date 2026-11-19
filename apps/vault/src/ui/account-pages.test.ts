// The account page (/account) as rendered: the restricted and pending
// notices first, then the account, its workspaces and the cards for
// passkeys, sessions, recovery and appearance, each from its own account
// read; the fallback when the account read cannot answer; and the sign-in
// page's line for someone with no invitation. Then /account through the
// real Worker for the deployment's first account.
import { describe, expect, it } from "vitest"
import type { AccountSessionsRead } from "@mehen/protocol/api"
import type { AccountSession } from "@mehen/protocol/workspace"
import { renderDocument } from "./layout.ts"
import { type AccountCards, accountPage, accountStatusPage, signinPage } from "./pages/account.ts"
import { ACCOUNT_PASSKEYS, ACCOUNT_SESSIONS } from "./account-gallery.ts"
import { PEOPLE_ORIGIN, PEOPLE_SESSION } from "./people-gallery.ts"
import type { AccountShell } from "./shell.ts"
import { SESSIONS_RECOVERY_LIMIT_WORDS } from "./wording.ts"
import { body, journey, type Person } from "../../test/e2e/workspace-journey.ts"
import { registration, softwarePasskey } from "../../test/e2e/passkeys.ts"

const SHELL: AccountShell = { origin: PEOPLE_ORIGIN, account: PEOPLE_SESSION.account, name: "Alex Rae", accountPages: ["workspaces", "account"] }
const NOW = Date.parse("2026-10-27T18:30:00Z")
const CARDS: AccountCards = { passkeys: { ok: true, value: ACCOUNT_PASSKEYS }, sessions: { ok: true, value: ACCOUNT_SESSIONS }, mayEndOtherSessions: true, recovery: { ok: true, value: { active: { generatedAt: "2026-10-13T18:30:00Z", total: 10, left: 9 } } }, now: NOW }

function render(session: AccountSession, cards: AccountCards = CARDS): string {
  return renderDocument(accountPage(SHELL, session, PEOPLE_ORIGIN, cards)).value
}

const order = (body: string, regions: string[]) => regions.map((r) => body.indexOf(r))

describe("/account", () => {
  const states: [string, AccountSession, string | null][] = [
    ["plain", PEOPLE_SESSION, null],
    ["restricted", { ...PEOPLE_SESSION, restricted: { reason: "recovery", until: null, notice: "ntc_1" } }, 'data-region="account-restricted"'],
    ["pending transition", { ...PEOPLE_SESSION, pendingTransition: { id: "trn_1", reservedEpoch: 2, targets: 3, acknowledged: 1, state: "pending" } }, 'data-region="account-pending"'],
  ]
  for (const [name, session, notice] of states) {
    it(`renders for a ${name} account: the notice first, then the account, workspaces and every card`, () => {
      const body = render(session)
      const cards = ['data-region="account-passkeys"', 'data-region="account-sessions"', 'data-region="account-recovery"', 'data-region="appearance"']
      for (const card of cards) expect(body, card).toContain(card)
      if (notice !== null) {
        expect(body).toContain(notice)
        // The docs' and the refusals' name for the state.
        if (name === "restricted") expect(body).toContain("<h2>Your account is cooling off</h2>")
        const at = order(body, [notice, "<h2>Account</h2>", "<h2>Workspaces</h2>", ...cards])
        expect([...at].sort((a, b) => a - b)).toEqual(at)
      } else expect(body).not.toMatch(/data-region="account-(restricted|pending)"/)
      expect(body).toContain(`<code>${session.account}</code>`)
      expect(body).toContain('data-slot="oidc-account-identities" hidden')
      expect(body).toContain('"page":"account"'.replaceAll('"', "&quot;"))
    })
  }

  it("lists passkeys with rename and remove, and the only one cannot be removed until another is added", () => {
    const two = render(PEOPLE_SESSION)
    expect(two).toContain(`data-passkey-row="${ACCOUNT_PASSKEYS[0]!.passkey}"`)
    expect(two).toContain("MacBook Touch ID")
    expect(two).toContain("this session")
    expect(two.match(/data-action="remove-passkey"[^>]*>/g)?.every((b) => !b.includes("data-keep-disabled"))).toBe(true)
    expect(two).toContain('data-action="add-passkey" data-kind="device"')
    expect(two).toContain('data-action="add-passkey" data-kind="security-key"')
    const one = render(PEOPLE_SESSION, { ...CARDS, passkeys: { ok: true, value: [ACCOUNT_PASSKEYS[0]!] } })
    expect(one).toMatch(/data-action="remove-passkey"[^>]*data-keep-disabled disabled title="Add another passkey first."/)
    expect(one).toContain("Your only passkey. Add another before you can remove it.")
  })

  it("inside a passkey grace window says until when, with Ask every time; outside one says nothing", () => {
    const until = "2026-10-27T18:42:00.000Z"
    const body = render(PEOPLE_SESSION, { ...CARDS, grace: { until } })
    expect(body).toMatch(new RegExp(`data-region="stepup-grace"[\\s\\S]*Passkey confirmed, no need to confirm again until <time datetime="${until}"`))
    expect(body).toContain('data-action="end-stepup-grace" disabled>Ask every time</button>')
    for (const grace of [null, undefined]) expect(render(PEOPLE_SESSION, { ...CARDS, grace })).not.toContain('data-region="stepup-grace"')
  })

  it("says what ending this browser's session does, and that ending everywhere includes it", () => {
    const body = render(PEOPLE_SESSION)
    expect(body).toMatch(/data-action="end-session" data-session="ses_current01" data-current="1"[^>]*>[\s\S]*?Sign out here/)
    expect(body).toMatch(/data-action="end-session" data-session="ses_phone01" data-current="0"[^>]*>[\s\S]*?End</)
    expect(body).toContain("this browser")
    expect(body).toContain("Sign out everywhere, this browser too")
    expect(body).toContain("Machines are separate")
    expect(body).not.toContain(SESSIONS_RECOVERY_LIMIT_WORDS)
  })

  it("when this sign-in may not end the others, offers only its own sign-out and says why", () => {
    const body = render(PEOPLE_SESSION, { ...CARDS, mayEndOtherSessions: false })
    expect(body).toMatch(/data-action="end-session" data-session="ses_current01" data-current="1"[^>]*>[\s\S]*?Sign out here/)
    expect(body).toContain("Jeff on iPhone")
    expect(body).not.toContain('data-session="ses_phone01"')
    expect(body).not.toContain('data-current="0"')
    expect(body).not.toContain('data-action="end-all-sessions"')
    expect(body).not.toContain("Sign out everywhere")
    expect(body).toContain(`<p class="small muted" data-region="sessions-recovery-limit">${SESSIONS_RECOVERY_LIMIT_WORDS}</p>`)
  })

  it("shows recovery read-only, with the way to set it up on its own page", () => {
    const body = render(PEOPLE_SESSION)
    expect(body).toContain("Recovery codes: 9 of 10 left")
    expect(body).toContain('href="/account/recovery"')
    expect(body).not.toMatch(/data-action="(make-codes|confirm-codes|generate-codes)"/)
    const required = render({ ...PEOPLE_SESSION, recoverySetupRequired: true }, { ...CARDS, recovery: { ok: true, value: { active: null } } })
    expect(required).toContain("No recovery codes yet. Recovery needs setting up again.")
    expect(required).toContain("Set up recovery")
  })

  it("with no codes and a passkey that syncs, recovery codes read as advice, not a requirement", () => {
    const synced = ACCOUNT_PASSKEYS[0]!
    expect(synced.synced).toBe(true)
    const advice = render(PEOPLE_SESSION, { ...CARDS, passkeys: { ok: true, value: [synced] }, recovery: { ok: true, value: { active: null } } })
    expect(advice).toContain('<p data-region="recovery-status">Your passkey syncs through your password manager, so you can get back in if you lose this device. Recovery codes are a second way back in.</p>')
    expect(advice).not.toContain("No recovery codes yet")
    const deviceOnly = render({ ...PEOPLE_SESSION, recoverySetupRequired: true }, { ...CARDS, passkeys: { ok: true, value: [ACCOUNT_PASSKEYS[1]!] }, recovery: { ok: true, value: { active: null } } })
    expect(deviceOnly).toContain("No recovery codes yet. Recovery needs setting up again.")
    expect(deviceOnly).not.toContain("Your passkey syncs")
  })

  it("offers the three appearance choices, light pressed by default", () => {
    const body = render(PEOPLE_SESSION)
    expect(body.match(/data-theme-choice="(light|dark|system)"/g)).toEqual(['data-theme-choice="light"', 'data-theme-choice="dark"', 'data-theme-choice="system"'])
    expect(body).toContain('data-theme-choice="light" aria-pressed="true"')
  })

  it("spells hostile passkey and browser names and invents nothing when a card's read fails", () => {
    const hostile = render(PEOPLE_SESSION, { ...CARDS, passkeys: { ok: true, value: [{ ...ACCOUNT_PASSKEYS[0]!, name: "Key\u200b <b>Admin</b>" }, ACCOUNT_PASSKEYS[1]!] }, sessions: { ok: true, value: [{ ...ACCOUNT_SESSIONS[0]!, client: "Chrome\u202e <i>x</i>" }] } })
    expect(hostile).not.toContain("<b>Admin</b>")
    expect(hostile).not.toContain("<i>x</i>")
    expect(hostile).not.toMatch(/[\u200b\u202e]/)
    const failed = { ok: false as const, status: 503, error: { error: "upstream_failed" as const, message: "The vault is busy." } }
    const body = render(PEOPLE_SESSION, { passkeys: failed, sessions: failed, mayEndOtherSessions: false, recovery: failed, now: NOW })
    for (const what of ["your passkeys", "your sessions", "your recovery"]) expect(body, what).toContain(what)
    expect(body).not.toContain("data-passkey-row")
    expect(body).not.toContain('data-action="end-all-sessions"')
    expect(body).not.toContain("No recovery codes yet")
  })

  it("the fallback still renders when the account read cannot answer", () => {
    const body = renderDocument(accountStatusPage(SHELL, { pendingTransition: null, recoverySetupRequired: true }, { error: "upstream_failed", message: "Workspace security metadata is temporarily unavailable." })).value
    expect(body).toContain("Workspace security metadata is temporarily unavailable.")
    expect(body).toContain('data-region="account-unavailable"')
    expect(body).toContain('data-region="recovery-required"')
  })
})

describe("sign in", () => {
  it("tells someone with no invitation who to ask", () => {
    const body = renderDocument(signinPage("/")).value
    expect(body).toContain("No invitation yet? Ask the person who runs your workspace to invite you; Mehen never creates accounts on its own.")
  })
})

describe("/account through the real Worker", () => {
  it("shows the first account's own passkey, this browser's session and its recovery state from the account routes", async () => {
    const f = await journey()
    const response = await f.request("/account", f.alex, undefined, { accept: "text/html" })
    expect(response.status).toBe(200)
    const body = await response.text()
    const passkey = await f.db.prepare("SELECT handle FROM passkeys WHERE account=?").bind(f.alex.account).first<{ handle: string }>()
    expect(body).toContain(`data-passkey-row="${passkey!.handle}"`)
    expect(body).toContain("Your only passkey. Add another before you can remove it.")
    expect(body).toMatch(/data-action="end-session" data-session="ses_[^"]+" data-current="1"/)
    expect(body).toContain("No recovery codes yet. Recovery needs setting up again.")
    await f.recoverySetup(f.alex)
    expect(await (await f.request("/account", f.alex, undefined, { accept: "text/html" })).text()).toContain("Recovery codes: 10 of 10 left")
  })

  it("while a recovery is open, a recovered sign-in is offered only its own sign-out and the older passkey's sign-in every control", async () => {
    const f = await journey()
    await f.recoverySetup(f.alex)
    const page = async (person: Person) => {
      const response = await f.request("/account", person, undefined, { accept: "text/html" })
      expect(response.status).toBe(200)
      return response.text()
    }
    const read = async (person: Person) => body<AccountSessionsRead>(await f.request("/api/account/sessions", person))
    const offersEveryControl = async (person: Person) => {
      expect((await read(person)).mayEndOtherSessions).toBe(true)
      const html = await page(person)
      expect(html).toMatch(/data-action="end-session" data-session="ses_[^"]+" data-current="0"/)
      expect(html).toContain("Sign out everywhere, this browser too")
      expect(html).not.toContain(SESSIONS_RECOVERY_LIMIT_WORDS)
    }
    // Without a recovery, a sign-in may end the others.
    await f.signin(f.alex)
    await offersEveryControl(f.alex)
    // A recovery code starts the recovery; the new passkey is registered through its ceremony.
    const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
    const recovered: Person = { ...f.alex, cookie: started.headers.get("set-cookie")?.split(";")[0] ?? "", passkey: await softwarePasskey(), counter: 0 }
    expect(await body(started)).toEqual({ pending: false, transition: expect.stringMatching(/^trn_/) })
    const options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/recovery/passkey/options", recovered, {}))
    const added = await f.request("/api/auth/recovery/passkey/verify", recovered, { response: await registration(recovered.passkey, options.options.challenge), name: "Recovered" })
    recovered.cookie = added.headers.get("set-cookie")?.split(";")[0] ?? ""
    expect(await body(added)).toEqual({})
    // The owner signs in again with the passkey from before the recovery.
    await f.signin(f.alex)
    const listed = await read(recovered)
    expect(listed.mayEndOtherSessions).toBe(false)
    expect(listed.sessions).toHaveLength(2)
    const limited = await page(recovered)
    expect(limited).toMatch(/data-action="end-session" data-session="ses_[^"]+" data-current="1"/)
    expect(limited).not.toContain('data-current="0"')
    expect(limited).not.toContain('data-action="end-all-sessions"')
    expect(limited).toContain(SESSIONS_RECOVERY_LIMIT_WORDS)
    await offersEveryControl(f.alex)
  })
})
