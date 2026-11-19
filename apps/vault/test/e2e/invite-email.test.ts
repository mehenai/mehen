// The link to a new email-bound invitation, emailed to the invited address
// as it is made, through the real Worker with a fake EMAIL binding
// (test/fake-email.ts).
import { beforeEach, describe, expect, it } from "vitest"
import type { InviteTerms } from "@mehen/protocol"
import { inviteLinkEmail } from "../../src/directory/invite-email.ts"
import { fakeEmail, type FakeEmail } from "../fake-email.ts"
import { body, refusal, workJourney } from "./workspace-journey.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>

let email: FakeEmail
beforeEach(() => { email = fakeEmail() })

const EMAIL = "colleague@northwind.example"
const HOUR = 3_600_000
const DAY = 86_400_000
function memberTerms(to = EMAIL): InviteTerms { return { role: "member", email: to, teams: [], shares: [], expiresAt: new Date(Date.now() + 2 * DAY).toISOString() } }
async function journey() { const f = await workJourney(); f.env.EMAIL = email; return f }
async function emailRows(f: Journey) { return (await f.db.prepare("SELECT email,inviter,workspace FROM invite_emails ORDER BY created_at,id").all()).results }
async function emailedAudit(f: Journey) { return f.sql<{ actor: string; action: string; target: string; detail: string }>(f.work, "SELECT actor,action,target,detail FROM audit WHERE action='invite.emailed' ORDER BY seq") }
// Sends already counted, made that long ago, by this inviter or another.
async function counted(f: Journey, n: number, input: { email?: string; inviter?: string; ago?: number }) {
  for (let i = 0; i < n; i++) await f.db.prepare("INSERT INTO invite_emails(id,email,inviter,workspace,created_at) VALUES (?,?,?,?,?)").bind(`ivm_seed${i}_${Math.random()}`, input.email ?? `other${i}@example.test`, input.inviter ?? `acc_other${i}`, "tn_elsewhere", Date.now() - (input.ago ?? 60_000)).run()
}
async function inviteActive(f: Journey, id: string) { return f.db.prepare("SELECT state FROM invite_codes WHERE invite=?").bind(id).first() }

describe("emailing a new invitation's link", () => {
  it("sends one message to the invited address with the link, the inviter, the workspace, the role, the expiry and what to do if unexpected", async () => {
    const f = await journey(), terms = memberTerms(), made = await f.invite(f.alex, f.work, terms, true)
    expect(made.emailed).toBe("sent")
    expect(made.url).toBe(`${f.env.VAULT_ORIGIN}/signup#${made.code}`)
    expect(email.sent).toHaveLength(1)
    const [message] = email.sent
    expect(message).toMatchObject({ from: { name: "Mehen", email: "no-reply@mehen.dev" }, to: EMAIL, subject: "Alex invited you to Northwind on Mehen" })
    const expires = new Date(terms.expiresAt), day = `${expires.getUTCDate()} ${expires.toLocaleString("en-GB", { month: "long", timeZone: "UTC" })} ${expires.getUTCFullYear()}`
    for (const part of [message!.text!, message!.html!]) {
      expect(part).toContain(made.url)
      expect(part).toContain("Alex invited you to the Northwind workspace on Mehen, as a member.")
      expect(part).toContain("The link works once, and only for this email address.")
      expect(part).toContain(`It expires on ${day} at `)
      expect(part).toContain(" UTC.")
      expect(part).toContain("If you were not expecting this, ignore it: nothing happens until you open the link and prove this address.")
    }
    expect(message!.html!).toContain(`href="${made.url}"`)
    expect(await emailRows(f)).toEqual([{ email: EMAIL, inviter: f.alex.account, workspace: f.work.id }])
    const [audited, ...more] = await emailedAudit(f)
    expect(more).toEqual([])
    expect(audited).toMatchObject({ actor: `member:${await f.member(f.alex, f.work)}`, action: "invite.emailed", target: made.invite.id })
    expect(JSON.parse(audited!.detail)).toEqual({ by: expect.any(Object), email: EMAIL })
  })

  it("sends nothing when not asked: the answer says not_requested", async () => {
    const f = await journey(), made = await f.invite(f.alex, f.work, memberTerms(), false)
    expect(made.emailed).toBe("not_requested")
    expect(made.url).toBe(`${f.env.VAULT_ORIGIN}/signup#${made.code}`)
    expect(email.sent).toEqual([])
    expect(await emailRows(f)).toEqual([])
    expect(await emailedAudit(f)).toEqual([])
  })

  it("makes the invitation from a page opened before invitations were emailed, which says nothing about email: not_requested", async () => {
    const f = await journey(), terms = memberTerms()
    const response = await f.signed(`/api/w/${f.work.slug}/invites`, f.alex, { terms }, { type: "member.invite", terms }, f.work.slug)
    expect(await body<{ emailed: string }>(response, 201)).toMatchObject({ emailed: "not_requested" })
    expect(email.sent).toEqual([])
    expect(await emailRows(f)).toEqual([])
  })

  it("refuses to email an open link, which has no address, before making anything", async () => {
    const f = await journey()
    const terms: InviteTerms = { role: "guest", email: null, teams: [], shares: [{ project: f.project.id, level: "edit", protected: true, expiresAt: null }], expiresAt: new Date(Date.now() + DAY).toISOString() }
    const response = await f.signed(`/api/w/${f.work.slug}/invites`, f.alex, { terms, email: true }, { type: "member.invite", terms }, f.work.slug)
    await refusal(response, 400, { error: "bad_request", message: "An open link names no email address, so it cannot be emailed." })
    expect(email.sent).toEqual([])
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM invite_codes").first()).toEqual({ n: 0 })
    expect(await f.sql(f.work, "SELECT id FROM invites")).toEqual([])
  })

  it("still makes the invitation when the binding refuses: failed, the link in the answer, nothing counted or recorded", async () => {
    const f = await journey()
    email.failWith = "E_SENDER_NOT_VERIFIED"
    const made = await f.invite(f.alex, f.work, memberTerms(), true)
    expect(made.emailed).toBe("failed")
    expect(made.url).toBe(`${f.env.VAULT_ORIGIN}/signup#${made.code}`)
    expect(await inviteActive(f, made.invite.id)).toEqual({ state: "active" })
    expect(await emailRows(f)).toEqual([])
    expect(await emailedAudit(f)).toEqual([])
  })

  it("an inviter is sent at most 10 an hour and 30 a day, past which the invitation is made but not emailed", async () => {
    const f = await journey()
    await counted(f, 9, { inviter: f.alex.account })
    expect((await f.invite(f.alex, f.work, memberTerms("first@example.test"), true)).emailed).toBe("sent")
    const hour = await f.invite(f.alex, f.work, memberTerms("second@example.test"), true)
    expect(hour.emailed).toBe("limited")
    expect(await inviteActive(f, hour.invite.id)).toEqual({ state: "active" })
    expect(email.sent.map(m => m.to)).toEqual(["first@example.test"])
    await f.db.prepare("UPDATE invite_emails SET created_at=created_at-? WHERE inviter=?").bind(HOUR, f.alex.account).run()
    expect((await f.invite(f.alex, f.work, memberTerms("third@example.test"), true)).emailed).toBe("sent")
    await counted(f, 19, { inviter: f.alex.account, ago: 2 * HOUR })
    const day = await f.invite(f.alex, f.work, memberTerms("fourth@example.test"), true)
    expect(day.emailed).toBe("limited")
    expect(await inviteActive(f, day.invite.id)).toEqual({ state: "active" })
    expect(email.sent).toHaveLength(2)
    expect(await emailedAudit(f)).toHaveLength(2)
  })

  it("one address is sent at most 3 a day across every inviter and workspace", async () => {
    const f = await journey()
    await counted(f, 2, { email: EMAIL, ago: 20 * HOUR })
    expect((await f.invite(f.alex, f.work, memberTerms(), true)).emailed).toBe("sent")
    const limited = await f.invite(f.alex, f.personal, memberTerms(), true)
    expect(limited.emailed).toBe("limited")
    expect(limited.url).toContain("/signup#")
    expect(email.sent).toHaveLength(1)
    expect((await f.invite(f.alex, f.work, memberTerms("someone-else@example.test"), true)).emailed).toBe("sent")
  })

  it("the sweep removes counted sends after a day and keeps the day's", async () => {
    const f = await journey()
    await counted(f, 2, { ago: DAY + 1000 })
    await counted(f, 1, { email: "recent@example.test", ago: HOUR })
    await f.cron()
    expect((await emailRows(f)).map(row => (row as { email: string }).email)).toEqual(["recent@example.test"])
  })

  it("keeps the code out of D1 and the workspace's log", async () => {
    const f = await journey(), made = await f.invite(f.alex, f.work, memberTerms(), true)
    expect(made.emailed).toBe("sent")
    const tables = (await f.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*'").all<{ name: string }>()).results
    for (const { name } of tables) expect(JSON.stringify((await f.db.prepare(`SELECT * FROM "${name}"`).all()).results), name).not.toContain(made.code)
    expect(JSON.stringify(await f.snapshot(f.work))).not.toContain(made.code)
  })
})

describe("the invitation email's names", () => {
  const mail = (workspace: string, inviter: string) => inviteLinkEmail({ from: "Mehen <no-reply@mehen.dev>", to: EMAIL, url: "https://app.mehen.dev/signup#abc", workspace, inviter, role: "admin", expiresAt: "2026-11-09T18:00:00.000Z" })

  it("leaves out a workspace or inviter name that looks like a link, in the subject and the body", () => {
    for (const name of ["Acme. Verify at acme-login.example", "https://acme.example", "see www.acme", "mail help@acme", "acme.io", "Acme\r\nX-Mailer: 1", "Acme\u202e", "Acme\u2028Your account is suspended", "Acme\u2029X"]) {
      const asWorkspace = mail(name, "Alex"), asInviter = mail("Northwind", name)
      expect(asWorkspace.subject).toBe("Alex invited you to a workspace on Mehen")
      expect(asInviter.subject).toBe("Someone invited you to Northwind on Mehen")
      for (const part of [asWorkspace.text!, asWorkspace.html!]) {
        expect(part).toContain("Alex invited you to a workspace on Mehen, as an admin.")
        expect(part).not.toContain(name)
      }
      for (const part of [asInviter.text!, asInviter.html!]) {
        expect(part).toContain("Someone invited you to the Northwind workspace on Mehen, as an admin.")
        expect(part).not.toContain(name)
      }
    }
    const plain = mail("Acme Inc.", "J. Smith")
    expect(plain.subject).toBe("J. Smith invited you to Acme Inc. on Mehen")
    expect(plain.text).toContain("J. Smith invited you to the Acme Inc. workspace on Mehen, as an admin.")
    expect(plain.text).toContain("It expires on 9 November 2026 at 18:00 UTC.")
  })
})
