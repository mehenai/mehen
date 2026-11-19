// The emailed code that proves an invited email, through the real Worker
// with a fake EMAIL binding (test/fake-email.ts).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { EMAIL_IDENTITY_RULE, EMAIL_SEND_FAILED, emailCodeHash, inviteCodeEmail } from "../../src/directory/email-proof.ts"
import { setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { fakeEmail, sentCode, type FakeEmail } from "../fake-email.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { linkGoogle, setGoogleRule, webGate } from "./oidc-journey.ts"
import { registration, softwarePasskey } from "./passkeys.ts"
import { body, refusal, workJourney, type Person } from "./workspace-journey.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
type Row = { id: string; invite_hash: string; email: string; code_hash: string; key_version: number; cookie_hash: string; account: string | null; created_at: number; expires_at: number; attempts: number; sends_window: number; state: string; consumed_at: number | null }

let google: Awaited<ReturnType<typeof fakeGoogle>>
let email: FakeEmail
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher); email = fakeEmail() })
afterEach(() => setOidcFetchForTest(null))

const EMAIL = "colleague@northwind.example"
function memberTerms() { return { role: "member" as const, email: EMAIL, teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString() } }
async function journey() { const f = await workJourney(); f.env.EMAIL = email; return f }
async function rows(f: Journey) { return (await f.db.prepare("SELECT * FROM email_proofs ORDER BY created_at,id").all<Row>()).results }
async function start(f: Journey, code: string, cookie?: string) { return f.request("/api/auth/email/start", undefined, { code }, cookie ? { cookie } : {}) }
function cookieOf(response: Response) { return response.headers.get("set-cookie")?.split(";")[0] ?? "" }
async function verify(f: Journey, code: string, emailCode: string, cookie: string) { return f.request("/api/auth/email/verify", undefined, { code, emailCode }, cookie ? { cookie } : {}) }
// A code sent for the invitation to this browser: its cookie and the digits.
async function sent(f: Journey, code: string) { const response = await start(f, code); await body(response); return { cookie: cookieOf(response), digits: sentCode(email.sent.at(-1)) } }
function wrong(digits: string) { return String((Number(digits) + 1) % 1_000_000).padStart(6, "0") }
const NOT_RIGHT = { error: "bad_request", message: "That code is not right. Check the email and try again." }
const DEAD = { error: "bad_request", message: "That code has expired, been replaced or had too many wrong tries. Send a new code." }
const UNUSABLE = { error: "identity_required", message: "The emailed code could not be checked. Send a new code from the page that asked for it." }
const SPENT_WORDS = "This invitation has had too many codes or wrong tries today. Verify with Google, or ask whoever invited you for a new invitation."
const ADDRESS_LIMITED_WORDS = "Too many codes have been sent to the invited address. Verify with Google, or try again later."
// Every row sent moved back in time, as if sent that long ago.
async function age(f: Journey, ms: number) { await f.db.prepare("UPDATE email_proofs SET created_at=created_at-?,expires_at=expires_at-?").bind(ms, ms).run() }
// A code sent and typed back in one browser: the proof handle and its cookie.
async function proved(f: Journey, code: string, person?: Person) {
  const response = await f.request("/api/auth/email/start", person, { code }), cookie = cookieOf(response)
  await body(response)
  const browser = [person?.cookie, cookie].filter(Boolean).join("; ")
  const verified = await body<{ emailProof: string }>(await f.request("/api/auth/email/verify", undefined, { code, emailCode: sentCode(email.sent.at(-1)) }, { cookie: browser }))
  return { emailProof: verified.emailProof, cookie }
}
// A new account made on /signup with the proof, in the browser that holds it.
async function signupWith(f: Journey, code: string, proof: { emailProof: string; cookie: string }, name = "Colleague") {
  const passkey = await softwarePasskey(), options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options", undefined, { invite: code, name, emailProof: proof.emailProof }, { cookie: proof.cookie }))
  const registered = await f.request("/api/auth/signup/verify", undefined, { invite: code, name, emailProof: proof.emailProof, response: await registration(passkey, options.options.challenge) }, { cookie: proof.cookie })
  const session = registered.headers.get("set-cookie")!.split(";")[0]!, created = await body<{ account: string; onboarding: string }>(registered)
  expect(created.onboarding).toBe("join")
  const person: Person = { account: created.account, cookie: `${session}; ${proof.cookie}`, passkey, counter: 0, codes: [] }
  return person
}

describe("emailed invitation codes: start", () => {
  it("sends one code to the invitation's own address, from EMAIL_FROM, and keeps only its keyed hash", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    const response = await start(f, invite.code), started = await body<{ sent: boolean; expiresAt: string }>(response)
    expect(started).toEqual({ sent: true, expiresAt: expect.any(String) })
    expect(Date.parse(started.expiresAt) - Date.now()).toBeGreaterThan(590_000)
    expect(response.headers.get("set-cookie")).toMatch(/^__Host-mehen_email=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=1200$/)
    expect(email.sent).toHaveLength(1)
    const [message] = email.sent, code = sentCode(message)
    expect(message).toMatchObject({ from: { name: "Mehen", email: "no-reply@mehen.dev" }, to: EMAIL, subject: `Your Mehen code: ${code}` })
    for (const part of [message!.text!, message!.html!]) {
      expect(part).toContain(code)
      expect(part).toContain("It expires in 10 minutes.")
      expect(part).toContain("Alex invited you to the Northwind workspace on Mehen.")
      expect(part).toContain("If you did not ask for this, ignore this email.")
      expect(part).not.toMatch(/https?:|href=/)
    }
    const [row] = await rows(f)
    expect(row).toMatchObject({ email: EMAIL, key_version: 1, attempts: 0, sends_window: 1, state: "sent", account: null, consumed_at: null })
    expect(row!.expires_at - row!.created_at).toBe(600_000)
    expect(row!.code_hash).toBe(await emailCodeHash(f.env, 1, row!.id, code))
    expect(Object.values(row!)).not.toContain(code)
  })

  it("a workspace or inviter name that looks like a link or a domain is not put in the email", () => {
    const mail = (workspace: string, inviter: string) => { const built = inviteCodeEmail({ from: "Mehen <no-reply@mehen.dev>", to: EMAIL, code: "123456", workspace, inviter }); return [built.text!, built.html!] }
    for (const name of ["Acme. Verify at acme-login.example", "https://acme.example", "see www.acme", "mail help@acme", "acme.io"]) {
      for (const part of mail(name, "Alex")) {
        expect(part).toContain("Alex invited you to a workspace on Mehen.")
        expect(part).not.toContain(name)
      }
      for (const part of mail("Northwind", name)) {
        expect(part).toContain("Someone invited you to the Northwind workspace on Mehen.")
        expect(part).not.toContain(name)
      }
    }
    for (const part of mail("Acme Inc.", "J. Smith")) expect(part).toContain("J. Smith invited you to the Acme Inc. workspace on Mehen.")
  })

  it("answers nothing about the address, and refuses an open link, a dead code and a role under an identity rule without sending", async () => {
    const f = await journey()
    await refusal(await start(f, "not-an-invite-code"), 404, { error: "not_found", message: "No such invite." })
    const guest = await f.invite(f.alex, f.work, { role: "guest", email: null, teams: [], shares: [{ project: f.project.id, level: "edit", protected: true, expiresAt: null }], expiresAt: new Date(Date.now() + 86400000).toISOString() })
    await refusal(await start(f, guest.code), 400, { error: "bad_request", message: "This invitation is not for one email address, so it needs no code." })
    await linkGoogle(f, google); await setGoogleRule(f, google); await webGate(f, google)
    const ruled = await f.invite(f.alex, f.work, memberTerms())
    await refusal(await start(f, ruled.code), 403, { error: "identity_required", message: EMAIL_IDENTITY_RULE })
    expect(email.sent).toEqual([])
    expect(await rows(f)).toEqual([])
  })

  it("sends at most three codes an invitation an hour, each replacing the one before", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    for (let i = 0; i < 3; i++) expect(await body(await start(f, invite.code))).toMatchObject({ sent: true })
    expect((await rows(f)).map(row => [row.sends_window, row.state])).toEqual([[1, "consumed"], [2, "consumed"], [3, "sent"]])
    const limited = await start(f, invite.code)
    expect(limited.status).toBe(429)
    expect(await limited.json()).toEqual({ error: "rate_limited", message: "This invitation has been sent three codes in the last hour. Verify with Google, or try again later.", retryAfter: expect.any(Number) })
    expect(email.sent).toHaveLength(3)
    await f.db.prepare("UPDATE email_proofs SET created_at=created_at-3600000 WHERE sends_window=1").run()
    expect(await body(await start(f, invite.code))).toMatchObject({ sent: true })
    expect(email.sent).toHaveLength(4)
  })

  it("sends at most five codes an invitation a day, even when asked in parallel, then says to use Google or ask for a new invitation", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    for (let i = 0; i < 3; i++) expect(await body(await start(f, invite.code))).toMatchObject({ sent: true })
    await age(f, 2 * 3_600_000)
    const parallel = await Promise.all([1, 2, 3].map(() => start(f, invite.code)))
    expect(parallel.map(response => response.status).sort()).toEqual([200, 200, 429])
    expect(email.sent).toHaveLength(5)
    await age(f, 2 * 3_600_000)
    await refusal(await start(f, invite.code), 429, { error: "rate_limited", message: SPENT_WORDS })
    expect(email.sent).toHaveLength(5)
    // The rows are kept for a day, so the cron does not forget the sends.
    await f.cron()
    expect(await rows(f)).toHaveLength(5)
    await age(f, 20 * 3_600_000)
    expect(await body(await start(f, invite.code))).toMatchObject({ sent: true })
  })

  it("sends at most five codes an hour and ten a day to one address across all its invitations, even when asked in parallel", async () => {
    const f = await journey(), invites = async (n: number) => Promise.all(Array.from({ length: n }, (_, i) => f.invite(f.alex, i % 2 ? f.personal : f.work, memberTerms())))
    const first = await invites(6)
    const parallel = await Promise.all(first.map(invite => start(f, invite.code)))
    expect(parallel.map(response => response.status).sort()).toEqual([200, 200, 200, 200, 200, 429])
    const limited = parallel.find(response => response.status === 429)!
    expect(await limited.json()).toEqual({ error: "rate_limited", message: ADDRESS_LIMITED_WORDS, retryAfter: expect.any(Number) })
    expect(email.sent).toHaveLength(5)
    await age(f, 2 * 3_600_000)
    const second = await invites(6)
    for (const invite of second.slice(0, 5)) expect(await body(await start(f, invite.code))).toMatchObject({ sent: true })
    await age(f, 2 * 3_600_000)
    const refused = await start(f, second[5]!.code)
    expect(refused.status).toBe(429)
    const day = await refused.json() as { message: string; retryAfter: number }
    expect(day).toEqual({ error: "rate_limited", message: ADDRESS_LIMITED_WORDS, retryAfter: expect.any(Number) })
    expect(day.retryAfter).toBeGreaterThan(19 * 3600)
    expect(email.sent).toHaveLength(10)
    // Another address is not held up.
    const other = await f.invite(f.alex, f.work, { ...memberTerms(), email: "someone@northwind.example" })
    expect(await body(await start(f, other.code))).toMatchObject({ sent: true })
    await age(f, 21 * 3_600_000)
    expect(await body(await start(f, second[5]!.code))).toMatchObject({ sent: true })
  })

  it("a send Email Sending refuses keeps no code, is not counted, and logs only the error code", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    try {
      email.failWith = "E_SENDER_NOT_VERIFIED"
      await refusal(await start(f, invite.code), 502, { error: "upstream_failed", message: EMAIL_SEND_FAILED })
      expect(errors.mock.calls.map(call => String(call[0]))).toEqual([JSON.stringify({ at: "email.code.send", error: "E_SENDER_NOT_VERIFIED" })])
      f.env.EMAIL = undefined
      await refusal(await start(f, invite.code), 502, { error: "upstream_failed", message: EMAIL_SEND_FAILED })
      expect(await rows(f)).toEqual([])
      expect(JSON.stringify(errors.mock.calls)).not.toContain(EMAIL)
    } finally { errors.mockRestore() }
  })
})

describe("emailed invitation codes: verify", () => {
  it("the code typed back once, in this browser, becomes a proof of the invitation's email for ten minutes", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), code = await sent(f, invite.code)
    const verified = await body<{ emailProof: string; email: string; expiresAt: string }>(await verify(f, invite.code, ` ${code.digits.slice(0, 3)} ${code.digits.slice(3)} `, code.cookie))
    expect(verified).toEqual({ emailProof: expect.stringMatching(/^eml_/), email: EMAIL, expiresAt: expect.any(String) })
    const [row] = await rows(f)
    expect(row).toMatchObject({ id: verified.emailProof, state: "verified", attempts: 0 })
    expect(row!.expires_at).toBe(Date.parse(verified.expiresAt))
    await refusal(await verify(f, invite.code, code.digits, code.cookie), 400, DEAD)
  })

  it("is bound to the browser it was sent to: another browser's cookie, or none, cannot use the code", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), code = await sent(f, invite.code)
    await refusal(await verify(f, invite.code, code.digits, "__Host-mehen_email=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 400, DEAD)
    await refusal(await verify(f, invite.code, code.digits, ""), 403, { error: "identity_required", message: "The emailed code could not be checked. Send a new code from the page that asked for it." })
    const other = await f.invite(f.alex, f.work, { ...memberTerms(), email: "someone@northwind.example" })
    await refusal(await verify(f, other.code, code.digits, code.cookie), 400, DEAD)
    expect((await rows(f))[0]).toMatchObject({ state: "sent", attempts: 0 })
    expect(await body(await verify(f, invite.code, code.digits, code.cookie))).toMatchObject({ email: EMAIL })
  })

  it("counts wrong codes and kills the code at the fifth", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), code = await sent(f, invite.code)
    for (let i = 1; i <= 4; i++) {
      await refusal(await verify(f, invite.code, i === 4 ? "12a456" : wrong(code.digits), code.cookie), 400, NOT_RIGHT)
      expect((await rows(f))[0]!.attempts).toBe(i)
    }
    await refusal(await verify(f, invite.code, wrong(code.digits), code.cookie), 400, { error: "bad_request", message: "That code is not right, and after five tries it no longer works. Send a new code." })
    await refusal(await verify(f, invite.code, code.digits, code.cookie), 400, DEAD)
    expect((await rows(f))[0]).toMatchObject({ state: "sent", attempts: 5 })
    // A new code starts again, and the one before stays dead.
    const again = await sent(f, invite.code)
    expect(await body(await verify(f, invite.code, again.digits, again.cookie))).toMatchObject({ email: EMAIL })
  })

  it("an invitation takes at most ten wrong codes a day across all its codes, even in parallel; then not even the right one works", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    const first = await sent(f, invite.code)
    for (let i = 0; i < 5; i++) await verify(f, invite.code, wrong(first.digits), first.cookie)
    const second = await sent(f, invite.code)
    for (let i = 0; i < 4; i++) await refusal(await verify(f, invite.code, wrong(second.digits), second.cookie), 400, NOT_RIGHT)
    const third = await sent(f, invite.code)
    const guesses = await Promise.all([1, 2, 3, 4].map(() => verify(f, invite.code, wrong(third.digits), third.cookie)))
    expect(guesses.map(response => response.status)).toEqual([400, 400, 400, 400])
    expect((await rows(f)).map(row => row.attempts)).toEqual([5, 4, 1])
    await refusal(await verify(f, invite.code, third.digits, third.cookie), 400, { error: "bad_request", message: SPENT_WORDS })
    expect((await rows(f))[2]).toMatchObject({ state: "sent", attempts: 1 })
    await age(f, 2 * 3_600_000)
    await refusal(await start(f, invite.code), 429, { error: "rate_limited", message: SPENT_WORDS })
    expect(email.sent).toHaveLength(3)
  })

  it("the tenth wrong code says to use Google or ask for a new invitation", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    const first = await sent(f, invite.code)
    for (let i = 0; i < 5; i++) await verify(f, invite.code, wrong(first.digits), first.cookie)
    const second = await sent(f, invite.code)
    for (let i = 0; i < 4; i++) await verify(f, invite.code, wrong(second.digits), second.cookie)
    await refusal(await verify(f, invite.code, wrong(second.digits), second.cookie), 400, { error: "bad_request", message: SPENT_WORDS })
  })

  it("a code ten minutes old, or one a newer code replaced, no longer works", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), first = await sent(f, invite.code)
    await f.db.prepare("UPDATE email_proofs SET expires_at=? WHERE state='sent'").bind(Date.now() - 1).run()
    await refusal(await verify(f, invite.code, first.digits, first.cookie), 400, DEAD)
    const second = await sent(f, invite.code), third = await sent(f, invite.code)
    await refusal(await verify(f, invite.code, second.digits, second.cookie), 400, DEAD)
    expect(await body(await verify(f, invite.code, third.digits, third.cookie))).toMatchObject({ email: EMAIL })
  })
})

describe("emailed invitation codes: the signup and the join take the proof as they take Google's", () => {
  it("an email-bound member invitation: code, passkey, recovery, join, the proof spent, owner confirmation", async () => {
    const f = await journey(), terms = memberTerms(), invite = await f.invite(f.alex, f.work, terms), proof = await proved(f, invite.code)
    const colleague = await signupWith(f, invite.code, proof)
    expect(await f.db.prepare("SELECT state,account,joining_membership FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "joining", account: colleague.account, joining_membership: null })
    await f.recoverySetup(colleague)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "pending_confirmation" })
    expect(await f.db.prepare("SELECT state,joining_membership,consumed_at IS NOT NULL AS consumed FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "consumed", joining_membership: joined.member, consumed: 1 })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM oidc_identities WHERE account=?").bind(colleague.account).first()).toEqual({ n: 0 })
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", joined.member)).toEqual([{ status: "unconfirmed" }])
    // Spent: the same proof joins nothing again.
    await refusal(await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof }), 403, UNUSABLE)
    expect(await body(await f.memberChange(f.alex, f.work, joined.member, "confirm"))).toMatchObject({ member: joined.member, role: "member", status: "active" })
  })

  it("an invitation signed to let the person straight in does so with a code as with Google, with no identity check installed", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, { ...memberTerms(), onJoin: "activate" }), proof = await proved(f, invite.code)
    const colleague = await signupWith(f, invite.code, proof)
    await f.recoverySetup(colleague)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "active" })
    expect(await f.db.prepare("SELECT state FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "consumed" })
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", joined.member)).toEqual([{ status: "active" }])
    expect(await f.sql(f.work, "SELECT COUNT(*) AS n FROM workspace_identity_checks WHERE member=?", joined.member)).toEqual([{ n: 0 }])
    expect((await f.request(`/api/w/${f.work.slug}`, colleague)).status).toBe(200)
  })

  it("a signed-in account proves the invited email with a code and joins another workspace", async () => {
    const f = await journey(), tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
    const invite = await f.invite(f.alex, f.personal, memberTerms()), proof = await proved(f, invite.code, tom)
    expect(await f.db.prepare("SELECT account FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ account: tom.account })
    await refusal(await f.request("/api/account/invites/join", tom, { code: invite.code }), 403, { error: "identity_required", message: "Prove the invited email before joining.", next: { url: "/signup", say: "Verify the invited email with Google, then continue." } })
    const browser = { ...tom, cookie: `${tom.cookie}; ${proof.cookie}` }
    expect(await body(await f.request("/api/account/invites/join", browser, { code: invite.code, emailProof: proof.emailProof }))).toMatchObject({ state: "pending_confirmation" })
  })

  it("the proof is bound to its browser: without its cookie, or with another's, the signup and the join refuse it", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), proof = await proved(f, invite.code)
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague", emailProof: proof.emailProof }), 403, UNUSABLE)
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague", emailProof: proof.emailProof }, { cookie: "__Host-mehen_email=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }), 403, UNUSABLE)
    // Another invitation's proof is not this one's.
    const other = await f.invite(f.alex, f.work, { ...memberTerms(), email: "someone@northwind.example" })
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: other.code, name: "Colleague", emailProof: proof.emailProof }, { cookie: proof.cookie }), 403, UNUSABLE)
    const colleague = await signupWith(f, invite.code, proof)
    await f.recoverySetup(colleague)
    const bare = { ...colleague, cookie: colleague.cookie.split("; ")[0]! }
    await refusal(await f.request("/api/account/invites/join", bare, { code: invite.code, emailProof: proof.emailProof }), 403, UNUSABLE)
    expect(await body(await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof }))).toMatchObject({ state: "pending_confirmation" })
  })

  it("refuses an email proof when the invited role falls under the workspace's identity rule", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), proof = await proved(f, invite.code)
    await linkGoogle(f, google); await setGoogleRule(f, google); await webGate(f, google)
    await refusal(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name: "Colleague", emailProof: proof.emailProof }, { cookie: proof.cookie }), 403, { error: "identity_required", message: EMAIL_IDENTITY_RULE })
    expect(await f.db.prepare("SELECT state,account FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "verified", account: null })
  })

  it("the join itself refuses an email proof once the invited role falls under the identity rule: no membership, and the proof not spent", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), proof = await proved(f, invite.code)
    const colleague = await signupWith(f, invite.code, proof)
    await f.recoverySetup(colleague)
    await linkGoogle(f, google); await setGoogleRule(f, google); await webGate(f, google)
    await refusal(await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof }), 403, { error: "identity_required", message: EMAIL_IDENTITY_RULE })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE account=?").bind(colleague.account).first()).toEqual({ n: 0 })
    expect(await f.db.prepare("SELECT state,joining_membership,consumed_at FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "joining", joining_membership: null, consumed_at: null })
  })

  it("a proof that lapses mid-join ends the join at the next cron: the membership goes and the invitation is free again", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms()), proof = await proved(f, invite.code)
    const colleague = await signupWith(f, invite.code, proof)
    await f.recoverySetup(colleague)
    f.faults.blockWorkspace = f.work.id
    const failed = await f.request("/api/account/invites/join", colleague, { code: invite.code, emailProof: proof.emailProof })
    expect(failed.status).toBe(500)
    f.faults.blockWorkspace = ""
    const held = await f.db.prepare("SELECT joining_membership FROM email_proofs WHERE id=? AND state='joining'").bind(proof.emailProof).first<{ joining_membership: string }>()
    expect(await f.db.prepare("SELECT state FROM memberships WHERE id=?").bind(held!.joining_membership).first()).toEqual({ state: "joining" })
    await f.db.prepare("UPDATE email_proofs SET expires_at=? WHERE id=?").bind(Date.now() - 1, proof.emailProof).run()
    await f.cron()
    expect(await f.db.prepare("SELECT state FROM email_proofs WHERE id=?").bind(proof.emailProof).first()).toEqual({ state: "consumed" })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE id=?").bind(held!.joining_membership).first()).toEqual({ n: 0 })
    expect(await f.db.prepare("SELECT used_at,used_by_account FROM invite_codes WHERE code_hash=(SELECT invite_hash FROM email_proofs WHERE id=?)").bind(proof.emailProof).first()).toEqual({ used_at: null, used_by_account: null })
  })
})

describe("emailed invitation codes: what /signup offers", () => {
  it("the peek offers the code for an email-bound invitation, only Google under the identity rule, and nothing without the binding", async () => {
    const f = await journey(), invite = await f.invite(f.alex, f.work, memberTerms())
    const peek = async (code: string) => body<{ emailCode: string }>(await f.request("/api/auth/invite/peek", undefined, { code }))
    expect(await peek(invite.code)).toMatchObject({ bound: true, emailCode: "offered" })
    const guest = await f.invite(f.alex, f.work, { role: "guest", email: null, teams: [], shares: [{ project: f.project.id, level: "edit", protected: true, expiresAt: null }], expiresAt: new Date(Date.now() + 86400000).toISOString() })
    expect(await peek(guest.code)).toMatchObject({ bound: false, emailCode: "off" })
    f.env.EMAIL = undefined
    expect(await peek(invite.code)).toMatchObject({ emailCode: "off" })
    f.env.EMAIL = email
    await linkGoogle(f, google); await setGoogleRule(f, google); await webGate(f, google)
    expect(await peek((await f.invite(f.alex, f.work, memberTerms())).code)).toMatchObject({ bound: true, emailCode: "identity_rule" })
    expect(JSON.stringify(await peek(invite.code))).not.toContain("colleague")
  })
})
