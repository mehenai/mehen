// Connect codes and the claim they make (section 9 items 11
// and 12), through the real Worker. A code routes an enrolment to one
// account and claims it; only that account can accept the machine, on the
// code page or the id page. Every refused code answers with the same bytes
// and inserts nothing; the clear code is never stored, returned or logged.
import { describe, expect, it, vi } from "vitest"
import { createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, jwkThumbprint, webCryptoSigner, type WorkspaceEnrolView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { body, refusal, workJourney, type Person } from "./e2e/workspace-journey.ts"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { sha256Text } from "../src/directory/session.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
const REFUSED = '{"error":"forbidden","message":"The connect code is not valid for this workspace."}'
async function issue(f: Journey, person: Person, slug = "northwind") {
  const response = await f.request(`/api/w/${slug}/connect-code`, person, {})
  expect(response.headers.get("cache-control")).toBe("no-store")
  return body<{ code: string; expiresAt: string }>(response)
}
// A machine starting with a connect code, as `mehen enrol --connect` does.
async function startWith(f: Journey, connect: string | undefined, headers: Record<string, string> = {}, workspace = "northwind") {
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const input = { workspace, owner: { kind: "self" }, name: "claimed-machine", backend: "software", jwk, ...(connect === undefined ? {} : { connect }) }
  const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
  const response = await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof, ...headers })
  const thumbprint = await jwkThumbprint(jwk)
  return { response, keys, thumbprint }
}
async function started(f: Journey, connect: string | undefined) {
  const machine = await startWith(f, connect)
  const value = await body<{ enrolment: string; code: string }>(machine.response, 201)
  const group = fingerprintGroups(fingerprintOf(machine.thumbprint))[await fingerprintGroupIndex(value.code)]!
  return { ...machine, started: value, group }
}
const enrolmentCount = async (f: Journey) => (await f.db.prepare("SELECT COUNT(*) AS n FROM enrolments").first<{ n: number }>())!.n
async function people(f: Journey) {
  const member = await f.guest(f.alex, f.work, f.project.id, "Mia")
  await body(await f.memberChange(f.alex, f.work, member.member!, "role", "member"))
  const admin = await f.guest(f.alex, f.work, f.project.id, "Ada")
  await body(await f.memberChange(f.alex, f.work, admin.member!, "role", "admin"))
  return { member, admin }
}
function acceptAction(f: Journey, person: Person, machine: Awaited<ReturnType<typeof started>>, view: WorkspaceEnrolView, member: string): WorkspaceStepUpAction {
  return { type: "enrol.accept", workspace: f.work.id, enrolment: machine.started.enrolment, thumbprint: machine.thumbprint, account: person.account, member, scope: view.scope, start: view.start }
}

describe("the connect code issuer", () => {
  it("mints a code shown once, stores only its hash, binds it to the account for a day and replaces it on reissue", async () => {
    const f = await workJourney()
    const first = await issue(f, f.alex)
    expect(first.code).toMatch(/^[2-9A-HJKMNP-Z]{8}$/)
    expect(Date.parse(first.expiresAt) - Date.now()).toBeGreaterThan(86_400_000 - 60_000)
    const rows = (await f.db.prepare("SELECT * FROM enrol_connect_codes").all()).results
    expect(rows).toEqual([{ code_hash: await sha256Text(first.code), account: f.alex.account, workspace: f.work.id, created_at: expect.any(Number), expires_at: Date.parse(first.expiresAt) }])
    expect(JSON.stringify(rows)).not.toContain(first.code)
    const second = await issue(f, f.alex)
    expect(second.code).not.toBe(first.code)
    expect((await f.db.prepare("SELECT code_hash FROM enrol_connect_codes").all()).results).toEqual([{ code_hash: await sha256Text(second.code) }])
    const old = await startWith(f, first.code)
    expect(old.response.status).toBe(403)
    expect(await old.response.text()).toBe(REFUSED)
  })

  it("refuses a suspended member with the workspace's own code before writing anything, and limits issuance per account", async () => {
    const f = await workJourney(), { member } = await people(f)
    await f.sql(f.work, "UPDATE members SET status='suspended' WHERE id=?", member.member!)
    const refused = await f.request("/api/w/northwind/connect-code", member, {})
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject({ error: "owner_inactive" })
    expect((await f.db.prepare("SELECT COUNT(*) AS n FROM enrol_connect_codes").first<{ n: number }>())!.n).toBe(0)
    const limiter = f.env.AUTH_RATE_LIMITER
    f.env.AUTH_RATE_LIMITER = { limit: async ({ key }: { key: string }) => ({ success: !key.startsWith("connect-code:") }) } as unknown as RateLimit
    try { await refusal(await f.request("/api/w/northwind/connect-code", f.alex, {}), 429, { error: "rate_limited", message: "Too many connect codes. Try again shortly.", retryAfter: 60 }) } finally { f.env.AUTH_RATE_LIMITER = limiter }
  })
})

describe("starting with a connect code", () => {
  it("claims the attempt for the code's account and never stores, returns or logs the clear code", async () => {
    const f = await workJourney(), logs = vi.spyOn(console, "log"), errors = vi.spyOn(console, "error")
    try {
      const { code } = await issue(f, f.alex)
      const machine = await startWith(f, code.toLowerCase().replace(/^(....)/, "$1-"))
      const text = await machine.response.clone().text()
      const value = await body<{ enrolment: string }>(machine.response, 201)
      expect(text).not.toContain(code)
      const row = await f.db.prepare("SELECT * FROM enrolments WHERE id=?").bind(value.enrolment).first()
      expect(row).toMatchObject({ claimed_account: f.alex.account })
      expect(JSON.stringify(row)).not.toContain(code)
      expect(JSON.stringify([...logs.mock.calls, ...errors.mock.calls])).not.toContain(code)
    } finally { logs.mockRestore(); errors.mockRestore() }
  })

  it("refuses unknown, malformed, expired, other-workspace, removed-account, ended-membership and suspended-member codes with identical bytes and no row", async () => {
    const f = await workJourney(), { member } = await people(f)
    const bytes: string[] = []
    const attempt = async (code: string) => {
      const before = await enrolmentCount(f), machine = await startWith(f, code)
      expect(machine.response.status).toBe(403)
      bytes.push(await machine.response.text())
      expect(await enrolmentCount(f)).toBe(before)
    }
    await attempt("23456789")
    await attempt("not a code")
    const expired = await issue(f, f.alex)
    await f.db.prepare("UPDATE enrol_connect_codes SET created_at=created_at-86400001,expires_at=expires_at-86400001 WHERE code_hash=?").bind(await sha256Text(expired.code)).run()
    await attempt(expired.code)
    const personal = await issue(f, f.alex, "alex")
    await attempt(personal.code)
    const removed = await issue(f, member)
    await f.db.prepare("UPDATE accounts SET status='deleting' WHERE id=?").bind(member.account).run()
    await attempt(removed.code)
    await f.db.prepare("UPDATE accounts SET status='active' WHERE id=?").bind(member.account).run()
    await f.db.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(member.account, f.work.id).run()
    await attempt(removed.code)
    await f.db.prepare("UPDATE memberships SET state='member' WHERE account=? AND workspace=?").bind(member.account, f.work.id).run()
    await f.sql(f.work, "UPDATE members SET status='suspended' WHERE id=?", member.member!)
    await attempt(removed.code)
    expect(bytes).toHaveLength(7)
    for (const value of bytes) expect(value).toBe(REFUSED)
    // The same code works for a live, active member.
    await f.sql(f.work, "UPDATE members SET status='active' WHERE id=?", member.member!)
    expect((await startWith(f, removed.code)).response.status).toBe(201)
  })

  it("spends the per-address limiter before the lookup and trips at the twenty-first attempt", async () => {
    const f = await workJourney(), counts = new Map<string, number>(), limiter = f.env.AUTH_RATE_LIMITER
    f.env.AUTH_RATE_LIMITER = { limit: async ({ key }: { key: string }) => { const n = (counts.get(key) ?? 0) + 1; counts.set(key, n); return { success: n <= 20 } } } as unknown as RateLimit
    try {
      for (let i = 0; i < 20; i++) expect((await startWith(f, "23456789", { "cf-connecting-ip": "203.0.113.7" })).response.status).toBe(403)
      const before = await enrolmentCount(f)
      const limited = await startWith(f, "23456789", { "cf-connecting-ip": "203.0.113.7" })
      await refusal(limited.response, 429, { error: "rate_limited", message: "Too many connect code attempts. Try again shortly.", retryAfter: 60 })
      expect(await enrolmentCount(f)).toBe(before)
      expect((await startWith(f, "23456789", { "cf-connecting-ip": "203.0.113.8" })).response.status).toBe(403)
      expect(counts.get("enrol-connect:203.0.113.7")).toBe(21)
      // Without a code nothing is spent.
      expect((await startWith(f, undefined, { "cf-connecting-ip": "203.0.113.7" })).response.status).toBe(201)
      expect(counts.get("enrol-connect:203.0.113.7")).toBe(21)
    } finally { f.env.AUTH_RATE_LIMITER = limiter }
  })

  it("the cron deletes expired codes and the codes of an ended membership", async () => {
    const f = await workJourney(), { member } = await people(f)
    const alex = await issue(f, f.alex), mia = await issue(f, member)
    await f.db.prepare("UPDATE memberships SET state='left' WHERE account=? AND workspace=?").bind(member.account, f.work.id).run()
    await f.cron()
    expect((await f.db.prepare("SELECT code_hash FROM enrol_connect_codes").all()).results).toEqual([{ code_hash: await sha256Text(alex.code) }])
    expect(mia.code).not.toBe(alex.code)
    await f.db.prepare("UPDATE enrol_connect_codes SET created_at=created_at-86400001,expires_at=expires_at-86400001").run()
    await f.cron()
    expect((await f.db.prepare("SELECT COUNT(*) AS n FROM enrol_connect_codes").first<{ n: number }>())!.n).toBe(0)
  })
})

describe("the claim at acceptance", () => {
  it("an owner and an admin cannot accept a claimed machine on either page; the claimed account can", async () => {
    const f = await workJourney(), { member, admin } = await people(f)
    const { code } = await issue(f, member)
    const machine = await started(f, code)
    const memberId = await f.member(member, f.work)
    for (const person of [f.alex, admin]) {
      for (const ref of [machine.started.code, machine.started.enrolment]) {
        const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${ref}`, person))
        expect(view.actions).toEqual(["reject"])
        expect(view.claimed).toEqual({ account: member.account, name: "Mia" })
        const before = await f.db.prepare("SELECT group_attempts,status FROM enrolments WHERE id=?").bind(machine.started.enrolment).first()
        await refusal(await f.request(`/api/w/northwind/enrolments/${ref}/action`, person, { kind: "accept", group: machine.group, privateCredentials: false }), 403, { error: "forbidden", message: "This machine was started for another account." })
        const action = acceptAction(f, person, machine, view, await f.member(person, f.work))
        await refusal(await f.signed(`/api/w/northwind/enrolments/${ref}/accept`, person, { group: machine.group, privateCredentials: false }, action, "northwind"), 403, { error: "forbidden", message: "This machine was started for another account." })
        expect(await f.db.prepare("SELECT group_attempts,status FROM enrolments WHERE id=?").bind(machine.started.enrolment).first()).toEqual(before)
      }
    }
    expect(await f.sql(f.work, "SELECT id FROM devices WHERE enrolment=?", machine.started.enrolment)).toEqual([])
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, member))
    expect(view.actions).toEqual(["accept", "reject"])
    expect(view).not.toHaveProperty("code")
    expect(JSON.stringify(view)).not.toContain(machine.started.code)
    const accepted = await body<WorkspaceEnrolView>(await f.signed(`/api/w/northwind/enrolments/${machine.started.enrolment}/accept`, member, { group: machine.group, privateCredentials: view.scope.privateCredentials }, acceptAction(f, member, machine, view, memberId), "northwind"))
    expect(accepted).toMatchObject({ state: "active", owner: { kind: "member", member: memberId }, lease: "terminal" })
  })

  it("a claimed account suspended after the page read is refused at acceptance", async () => {
    const f = await workJourney(), { member } = await people(f)
    const machine = await started(f, (await issue(f, member)).code)
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.code}`, member))
    const action = acceptAction(f, member, machine, view, await f.member(member, f.work))
    await f.sql(f.work, "UPDATE members SET status='suspended' WHERE account=?", member.account)
    const response = await f.signed(`/api/w/northwind/enrolments/${machine.started.code}/accept`, member, { group: machine.group, privateCredentials: false }, action, "northwind")
    expect(response.status).toBe(403)
    expect(await response.json()).toMatchObject({ error: "owner_inactive" })
    expect(await f.sql(f.work, "SELECT id FROM devices WHERE enrolment=?", machine.started.enrolment)).toEqual([])
  })
})

describe("the id page's visibility", () => {
  it("a plain member never sees an unclaimed start by id, and still opens it with the agent's code", async () => {
    const f = await workJourney(), { member } = await people(f)
    const machine = await started(f, undefined)
    const unknown = await f.request("/api/w/northwind/enrolments/enr_doesnotexist", member)
    const hidden = await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, member)
    expect(hidden.status).toBe(404)
    expect(await hidden.text()).toBe(await unknown.text())
    for (const ref of ["tn_Nw4dQ2m8xPLsJyKb3Rtvz", "not-a-ref", "enr_"]) expect((await f.request(`/api/w/northwind/enrolments/${ref}`, f.alex)).status).toBe(404)
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.code}`, member))).toMatchObject({ ref: machine.started.code, code: machine.started.code, actions: ["accept", "reject"] })
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, f.alex))).toMatchObject({ ref: machine.started.enrolment, actions: ["accept", "reject"], lease: "live", claimed: null })
  })

  it("the guest that accepted its machine may view it by id while it waits for admission, with no action; another guest may not", async () => {
    const f = await workJourney()
    const guest = await f.guest(f.alex, f.work, f.project.id, "Gina"), other = await f.guest(f.alex, f.work, f.project.id, "Gus")
    const machine = await started(f, undefined)
    expect(await body<{ state: string }>(await f.acceptMachine(guest, f.work, { ...machine, started: { ...machine.started, url: "" } }, false))).toMatchObject({ state: "pending_admission" })
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, guest))
    expect(view).toMatchObject({ state: "pending_admission", actions: [], lease: "live" })
    await refusal(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}/reject`, guest, {}), 403, { error: "forbidden", message: "Only an owner or admin can reject this machine now." })
    const unknown = await f.request("/api/w/northwind/enrolments/enr_doesnotexist", other)
    const refused = await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, other)
    expect(refused.status).toBe(404)
    expect(await refused.text()).toBe(await unknown.text())
    // Lapsed, the accepting guest still sees it and still cannot act.
    await f.db.prepare("UPDATE enrolments SET expires_at=? WHERE id=?").bind(Date.now() - 1, machine.started.enrolment).run()
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, guest))).toMatchObject({ state: "pending_admission", actions: [], lease: "lapsed" })
    expect((await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, other)).status).toBe(404)
    // The owner sees it to admit (live) and only to reject (lapsed).
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${machine.started.enrolment}`, f.alex))).toMatchObject({ actions: ["reject"], lease: "lapsed" })
  })
})
