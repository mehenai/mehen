// A vault that can neither verify Google nor send email (the local host sets
// neither GOOGLE_SIGNIN_CLIENT_ID nor an EMAIL binding) never makes an
// invitation nobody could complete, and says why; an open guest link still
// works end to end. With either way of proving an email the vault is as
// before.
import { describe, expect, it } from "vitest"
import type { InviteTerms } from "@mehen/protocol"
import { EMAIL_INVITES_UNAVAILABLE, emailInvitesCompletable } from "../../src/directory/invite-email.ts"
import { LINK_ONLY_INVITE_WORDS } from "../../src/ui/pages/people.ts"
import { body, expectedMember, refusal, workJourney } from "./workspace-journey.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>

const DAY = 86_400_000
const HTML = { accept: "text/html" }
const memberTerms = (): InviteTerms => ({ role: "member", email: "colleague@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 2 * DAY).toISOString(), onJoin: "confirm" })
const guestTerms = (project: string): InviteTerms => ({ role: "guest", email: null, teams: [], shares: [{ project, level: "edit", protected: false, expiresAt: null }], expiresAt: new Date(Date.now() + 2 * DAY).toISOString(), onJoin: "confirm" })

function local(f: Journey): Journey {
  delete f.env.GOOGLE_SIGNIN_CLIENT_ID
  delete f.env.GOOGLE_SIGNIN_CLIENT_SECRET
  f.env.EMAIL = undefined
  return f
}
async function page(f: Journey, path: string): Promise<string> {
  const response = await f.request(path, f.alex, undefined, HTML)
  expect(response.status, path).toBe(200)
  return response.text()
}
async function nothingMade(f: Journey): Promise<void> {
  expect(await f.db.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
  expect(await f.sql(f.work, "SELECT id FROM invites")).toEqual([])
}

describe("whether a vault can complete an email-bound invitation", () => {
  it("can with Google sign-in or with Email Sending, and cannot with neither", async () => {
    const f = await workJourney()
    const env = { ...f.env, GOOGLE_SIGNIN_CLIENT_ID: undefined, GOOGLE_SIGNIN_CLIENT_SECRET: undefined, EMAIL: undefined }
    expect(emailInvitesCompletable(env)).toBe(false)
    expect(emailInvitesCompletable({ ...env, GOOGLE_SIGNIN_CLIENT_ID: "test-google-client", GOOGLE_SIGNIN_CLIENT_SECRET: "test-only-google-secret" })).toBe(true)
    expect(emailInvitesCompletable({ ...env, EMAIL: f.env.EMAIL })).toBe(true)
    // A Google client with no secret cannot finish Google's step.
    expect(emailInvitesCompletable({ ...env, GOOGLE_SIGNIN_CLIENT_ID: "test-google-client" })).toBe(false)
    expect(emailInvitesCompletable({ ...env, EMAIL: f.env.EMAIL, EMAIL_FROM: undefined })).toBe(false)
  })
})

describe("a vault that cannot verify an email address", () => {
  it("refuses an email-bound invitation before making anything, emailed or not, and says to invite by link", async () => {
    const f = local(await workJourney())
    for (const email of [false, true]) {
      const terms = memberTerms()
      await refusal(await f.signed(`/api/w/${f.work.slug}/invites`, f.alex, { terms, email }, { type: "member.invite", terms }, f.work.slug), 400, { error: "bad_request", message: EMAIL_INVITES_UNAVAILABLE })
    }
    const guest: InviteTerms = { ...guestTerms(f.project.id), email: "gina@example.test" }
    await refusal(await f.signed(`/api/w/${f.work.slug}/invites`, f.alex, { terms: guest, email: false }, { type: "member.invite", terms: guest }, f.work.slug), 400, { error: "bad_request", message: EMAIL_INVITES_UNAVAILABLE })
    await nothingMade(f)
  })

  it("offers only a guest by link on the People page, with the line that says why, and the Get started step says to invite by link", async () => {
    const f = local(await workJourney())
    const people = await page(f, `/w/${f.work.slug}/people`)
    const roles = [...(/<select data-input="invite-role">([\s\S]*?)<\/select>/.exec(people)?.[1] ?? "").matchAll(/<option value="([a-z]+)"/g)].map((m) => m[1])
    expect(roles).toEqual(["guest"])
    expect(people).toContain('value="open" checked')
    expect(people).not.toContain('value="email"')
    expect(people).not.toContain('data-input="invite-email"')
    expect(people).not.toContain('data-input="invite-email-link"')
    expect(people).toContain(LINK_ONLY_INVITE_WORDS)
    const home = await page(f, `/w/${f.work.slug}/`)
    expect(home).toContain("Invite someone by link; you confirm them once they have joined.")
    expect(home).not.toContain("Email-bound invitations")
  })

  it("a second person signs up through a guest link with a passkey, joins, and the owner confirms them", async () => {
    const f = local(await workJourney())
    const made = await f.invite(f.alex, f.work, guestTerms(f.project.id))
    expect(made.emailed).toBe("not_requested")
    expect(await body(await f.request("/api/auth/invite/peek", undefined, { code: made.code }))).toMatchObject({ role: "guest", bound: false, emailCode: "off" })
    const gina = await f.signup(made.code, "Gina")
    await f.recoverySetup(gina)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", gina, { code: made.code }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "pending_confirmation" })
    expect(await page(f, `/w/${f.work.slug}/people`)).toContain(`data-action="member-confirm" data-member="${joined.member}"`)
    expect(await body(await f.memberChange(f.alex, f.work, joined.member, "confirm"))).toEqual(expectedMember(joined.member, "Gina", "guest"))
    const session = await body<{ memberships: { member: string; status: string }[] }>(await f.request("/api/account", gina))
    expect(session.memberships.find((m) => m.member === joined.member)?.status).toBe("active")
    // Joined and confirmed, a guest can be made a member, as the line says.
    expect(await body(await f.memberChange(f.alex, f.work, joined.member, "role", "member"))).toMatchObject({ member: joined.member, role: "member", status: "active" })
  })
})

describe("a vault that can verify an email address", () => {
  it("still makes an email-bound invitation and offers it first on the People page", async () => {
    const f = await workJourney()
    const made = await f.invite(f.alex, f.work, memberTerms())
    expect(made.url).toMatch(/\/signup#/)
    const people = await page(f, `/w/${f.work.slug}/people`)
    expect(people).toContain('value="email" checked')
    expect(people).toContain('<option value="member" selected>')
    expect(people).not.toContain(LINK_ONLY_INVITE_WORDS)
    expect(await page(f, `/w/${f.work.slug}/`)).not.toContain("Invite someone by link")
  })

  it("makes one with Google alone or with Email Sending alone", async () => {
    const google = local(await workJourney())
    google.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"
    google.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
    expect((await google.invite(google.alex, google.work, memberTerms())).url).toMatch(/\/signup#/)
    const email = await workJourney()
    delete email.env.GOOGLE_SIGNIN_CLIENT_ID
    expect((await email.invite(email.alex, email.work, memberTerms())).url).toMatch(/\/signup#/)
  })
})
