// The renewable enrolment lease through the real Worker (section 9
// item 13): renewal keeps the id, the code and the link, moves only the
// lease, never past the hard cap, at most once a minute, and settles a
// terminal attempt in its refusal so the CLI never polls twice.
import { describe, expect, it } from "vitest"
import { createProof, fingerprintGroupCheck, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, webCryptoSigner, type WorkspaceEnrolStatus, type WorkspaceEnrolView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { ENROLMENT_MAX_LIFE_MS, ENROLMENT_SETTLED_KEEP_MS, ENROLMENT_TTL_MS } from "../src/directory/enrolment.ts"
import { acceptedScope, body, refusal, workJourney, type Person } from "./e2e/workspace-journey.ts"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
type Started = Awaited<ReturnType<Journey["startMachine"]>>
const pendingOf = (f: Journey, start: Started) => ({ workspace: f.work, keys: start.keys, device: start.started.enrolment })
const renew = (f: Journey, start: Started) => f.deviceCall(pendingOf(f, start), `/v1/enrol/${start.started.enrolment}/renew`, undefined, "enrol", start.started.enrolment, "POST")
const poll = async (f: Journey, start: Started) => body<WorkspaceEnrolStatus>(await f.deviceCall(pendingOf(f, start), `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
const row = (f: Journey, start: Started) => f.db.prepare("SELECT status,expires_at,hard_expires_at,renewed_at,renewals,group_attempts,code_hash,expired_reason FROM enrolments WHERE id=?").bind(start.started.enrolment).first<{ status: string; expires_at: number; hard_expires_at: number; renewed_at: number | null; renewals: number; group_attempts: number; code_hash: string; expired_reason: string | null }>()
// Moves the last renewal back past the one-a-minute window.
const allowRenewal = (f: Journey, start: Started) => f.db.prepare("UPDATE enrolments SET renewed_at=renewed_at-60000 WHERE id=? AND renewed_at IS NOT NULL").bind(start.started.enrolment).run()
async function settled(response: Response, enrolment: WorkspaceEnrolStatus) {
  await refusal(response, 409, { error: "conflict", message: "This enrolment can no longer be renewed.", enrolment })
}

describe("enrolment lease renewal", () => {
  it("renews in place: same id, no code or link, a fresh hour up to the hard cap, once a minute", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const before = await row(f, start)
    expect(before!.hard_expires_at - before!.expires_at).toBe(ENROLMENT_MAX_LIFE_MS - ENROLMENT_TTL_MS)
    await f.db.prepare("UPDATE enrolments SET expires_at=expires_at-1000000 WHERE id=?").bind(start.started.enrolment).run()
    const renewed = await body<Record<string, unknown>>(await renew(f, start))
    expect(Object.keys(renewed).sort()).toEqual(["enrolment", "expiresAt", "hardExpiresAt"])
    expect(renewed).toEqual({ enrolment: start.started.enrolment, expiresAt: expect.any(String), hardExpiresAt: new Date(before!.hard_expires_at).toISOString() })
    const after = await row(f, start)
    expect(after).toMatchObject({ status: "pending", renewals: 1, code_hash: before!.code_hash, hard_expires_at: before!.hard_expires_at, group_attempts: 0 })
    expect(after!.expires_at).toBeGreaterThan(before!.expires_at - 1000000)
    expect(Date.parse(renewed.expiresAt as string)).toBe(after!.expires_at)
    const again = await renew(f, start)
    expect(again.status).toBe(409)
    const refused = await again.json() as Record<string, unknown>
    expect(refused).toEqual({ error: "conflict", message: "This enrolment was renewed less than a minute ago; keep waiting.", retryAfter: expect.any(Number) })
    expect(refused.retryAfter as number).toBeGreaterThan(0)
    expect(refused.retryAfter as number).toBeLessThanOrEqual(60)
    expect(await row(f, start)).toEqual(after)
  })

  it("a lapsed lease survives the cron, reads pending and comes back to life on renewal", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    await f.db.prepare("UPDATE enrolments SET expires_at=? WHERE id=?").bind(Date.now() - 1, start.started.enrolment).run()
    await f.cron()
    expect(await row(f, start)).toMatchObject({ status: "pending", expired_reason: null })
    const lapsed = await poll(f, start)
    expect(lapsed).toEqual({ status: "pending_owner_acceptance", expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
    expect(Date.parse((lapsed as { expiresAt: string }).expiresAt)).toBeLessThan(Date.now())
    await body(await renew(f, start))
    const live = await poll(f, start) as { expiresAt: string }
    expect(Date.parse(live.expiresAt)).toBeGreaterThan(Date.now())
  })

  it("past the hard cap the attempt is terminal and renewal settles it as expired by the cap", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    await f.db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now() - 2, Date.now() - 1, start.started.enrolment).run()
    const before = await row(f, start)
    await settled(await renew(f, start), { status: "expired", reason: "hard_cap" })
    expect(await row(f, start)).toEqual(before)
    expect(await poll(f, start)).toEqual({ status: "expired", reason: "hard_cap" })
    // Nobody opened it, so the run that ends it at the cap also prunes it; the answer is the same.
    await f.cron()
    expect(await row(f, start)).toBeNull()
    expect(await poll(f, start)).toEqual({ status: "expired", reason: "hard_cap" })
  })

  it("accept then renew settles with the full active answer; reject then renew settles rejected", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    expect(await body<{ state: string }>(await f.acceptMachine(f.alex, f.work, start))).toMatchObject({ state: "active" })
    const active = await poll(f, start)
    expect(active).toMatchObject({ status: "active", workspace: f.work, scope: acceptedScope() })
    await settled(await renew(f, start), active)
    const other = await f.startMachine(f.work)
    await body(await f.request(`/api/w/northwind/enrolments/${other.started.code}/reject`, f.alex, {}))
    await settled(await renew(f, other), { status: "rejected" })
  })

  it("a superseding start ends the older attempt as superseded", async () => {
    const f = await workJourney(), first = await f.startMachine(f.work)
    // The same key asks again: today's one live link per key.
    const keys = first.keys, jwk = await publicJwk(keys)
    const input = { workspace: "northwind", owner: { kind: "self" }, name: "integration-machine", backend: "software", jwk }
    const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
    await body(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
    expect(await row(f, first)).toMatchObject({ status: "expired", expired_reason: "superseded" })
    expect(await poll(f, first)).toEqual({ status: "expired", reason: "superseded" })
    await settled(await renew(f, first), { status: "expired", reason: "superseded" })
  })

  it("renewal between a guest's acceptance and its admission keeps the stored acceptance and the admission succeeds", async () => {
    const f = await workJourney(), guest = await f.guest(f.alex, f.work, f.project.id, "Gina"), start = await f.startMachine(f.work)
    const accepted = await body<{ state: string; digest: string; owner: import("@mehen/protocol").OwnerRef }>(await f.acceptMachine(guest, f.work, start, false))
    expect(accepted.state).toBe("pending_admission")
    const stored = async () => (await f.sql<{ value: string }>(f.work, "SELECT value FROM workspace_enrolments WHERE id=?", start.started.enrolment))[0]!.value
    const before = await stored()
    await body(await renew(f, start))
    expect(await stored()).toBe(before)
    const action: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: start.started.enrolment, digest: accepted.digest, owner: accepted.owner, admissionRole: "owner" }
    expect(await body<{ state: string; digest: string }>(await f.signed(`/api/w/northwind/enrolments/${start.started.code}/admit`, f.alex, { group: start.group, project: f.project.id }, action, "northwind"))).toMatchObject({ state: "active", digest: accepted.digest })
  })

  it("renewal never reaches the workspace, so it succeeds while the workspace is unreachable", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const namespace = f.env.TENANT_VAULT
    // Every workspace operation fails; the Worker's own cutover probe still answers.
    f.env.TENANT_VAULT = new Proxy(namespace, { get(target, key) {
      if (key !== "getByName") { const value = Reflect.get(target, key) as unknown; return typeof value === "function" ? value.bind(target) : value }
      return (name: string) => { const stub = target.getByName(name); return new Proxy(stub, { get(object, prop) { if (prop === "invoke") return async () => { throw new Error("Injected unreachable workspace") }; const value = Reflect.get(object, prop) as unknown; return typeof value === "function" ? value.bind(object) : value } }) }
    } })
    try { await body(await renew(f, start)) } finally { f.env.TENANT_VAULT = namespace }
    expect(await row(f, start)).toMatchObject({ status: "pending", renewals: 1 })
  })

  it("the typed-group budget is never reset by renewal, and five misses settle renewal as rejected", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const wrong = start.group === "2222" ? "3333" : "2222"
    const plan = () => f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: wrong, privateCredentials: true })
    for (let i = 0; i < 2; i++) expect((await plan()).status).toBe(403)
    await body(await renew(f, start))
    expect(await row(f, start)).toMatchObject({ group_attempts: 2 })
    await allowRenewal(f, start)
    await body(await renew(f, start))
    expect(await row(f, start)).toMatchObject({ group_attempts: 2, renewals: 2 })
    for (let i = 0; i < 3; i++) await plan()
    expect(await row(f, start)).toMatchObject({ group_attempts: 5, status: "rejected" })
    await allowRenewal(f, start)
    await settled(await renew(f, start), { status: "rejected" })
  })

  it("a row from before the lease is never extended and is refused once its life ends", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const life = Date.now() + 900_000
    await f.db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=?,hidden_group=NULL WHERE id=?").bind(life, life, start.started.enrolment).run()
    expect(await body(await renew(f, start))).toEqual({ enrolment: start.started.enrolment, expiresAt: new Date(life).toISOString(), hardExpiresAt: new Date(life).toISOString() })
    await f.db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=?,renewed_at=NULL WHERE id=?").bind(Date.now() - 1, Date.now() - 1, start.started.enrolment).run()
    await settled(await renew(f, start), { status: "expired", reason: "hard_cap" })
  })

  it("an attempt maintenance pruned answers its poll and its renewal as settled expired, so the machine that started it starts afresh", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    await f.db.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='hard_cap',expires_at=?,hard_expires_at=?,reconciled_at=? WHERE id=?").bind(Date.now() - ENROLMENT_SETTLED_KEEP_MS - 2, Date.now() - ENROLMENT_SETTLED_KEEP_MS - 1, Date.now(), start.started.enrolment).run()
    await f.cron()
    expect(await row(f, start)).toBeNull()
    expect(await poll(f, start)).toEqual({ status: "expired", reason: "hard_cap" })
    await settled(await renew(f, start), { status: "expired", reason: "hard_cap" })
  })

  it("an attempt superseded before anyone opened it is pruned once past its hard cap, with no thirty-day wait, and still answers its poll as expired", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    await f.db.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='superseded',expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now() - 2, Date.now() - 1, start.started.enrolment).run()
    await f.cron()
    expect(await row(f, start)).toBeNull()
    expect(await poll(f, start)).toEqual({ status: "expired", reason: "hard_cap" })
    await settled(await renew(f, start), { status: "expired", reason: "hard_cap" })
  })

  it("an attempt superseded while its page registered it in the workspace keeps that workspace, and so its thirty days", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    // The workspace's copy is made, then the same key starts again before the page records where.
    const original = f.env.TENANT_VAULT
    f.env.TENANT_VAULT = new Proxy(original, { get(target, key) {
      if (key === "getByName") return (name: string) => {
        const stub = target.getByName(name)
        return new Proxy(stub, { get(object, prop) {
          if (prop === "invoke") return async (invocation: { op: string }) => {
            const result = await object.invoke(invocation as Parameters<typeof object.invoke>[0])
            if (invocation.op === "access.enrol.register") await f.db.prepare("UPDATE enrolments SET status='expired',pending_state=NULL,expired_reason='superseded' WHERE id=?").bind(start.started.enrolment).run()
            return result
          }
          const value = Reflect.get(object, prop) as unknown
          return typeof value === "function" ? value.bind(object) : value
        } })
      }
      const value = Reflect.get(target, key) as unknown
      return typeof value === "function" ? value.bind(target) : value
    } })
    try { await refusal(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex), 409, { error: "conflict", message: "This enrolment changed. Refresh its page." }) } finally { f.env.TENANT_VAULT = original }
    expect(await f.db.prepare("SELECT status,tenant FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ status: "expired", tenant: f.work.id })
    await f.db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now() - 2, Date.now() - 1, start.started.enrolment).run()
    await f.cron()
    expect(await row(f, start)).toMatchObject({ status: "expired", expired_reason: "superseded" })
  })

  it("refuses another key's proof, a replayed proof and an unknown attempt without touching the row", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const before = await row(f, start)
    const stranger = { workspace: f.work, keys: await newDeviceKey(), device: start.started.enrolment }
    const forged = await f.deviceCall(stranger, `/v1/enrol/${start.started.enrolment}/renew`, undefined, "enrol", start.started.enrolment, "POST")
    expect(forged.status).toBe(401)
    expect(await forged.json()).toMatchObject({ error: "proof_invalid" })
    const unknown = await f.deviceCall(pendingOf(f, start), "/v1/enrol/enr_unknown123/renew", undefined, "enrol", "enr_unknown123", "POST")
    await settled(unknown, { status: "expired", reason: "hard_cap" })
    const proofFor = async () => {
        return createProof(webCryptoSigner(start.started.enrolment, start.keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol/${start.started.enrolment}/renew`, body: null }, { tenant: "enrol" })
    }
    const proof = await proofFor()
    await body(await f.request(`/v1/enrol/${start.started.enrolment}/renew`, undefined, undefined, { "Mehen-Proof": proof }, "POST"))
    const renewedRow = await row(f, start)
    await allowRenewal(f, start)
    const replayed = await f.request(`/v1/enrol/${start.started.enrolment}/renew`, undefined, undefined, { "Mehen-Proof": proof }, "POST")
    await refusal(replayed, 401, { error: "proof_invalid", message: "This Mehen-Proof has already been used. Sign every request afresh." })
    expect((await row(f, start))!.renewals).toBe(renewedRow!.renewals)
    expect(before!.renewals).toBe(0)
  })
})

describe("a 0.2.0 client against the lease", () => {
  it("POST /v1/enrol and its poll keep every field a 0.2.0 CLI reads, and it never needs to renew", async () => {
    const f = await workJourney(), keys = await newDeviceKey(), jwk = await publicJwk(keys)
    // 0.2.0 sends no connect code and identifies as Bun.
    const input = { workspace: "northwind", owner: { kind: "self" }, name: "old-cli", backend: "software", jwk }
    const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
    const started = await body<{ enrolment: string; code: string; url: string; fingerprint: string; expiresAt: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof, "user-agent": "Bun/1.4.2" }), 201)
    expect(started).toEqual({ enrolment: expect.stringMatching(/^enr_/), code: expect.stringMatching(/^[2-9A-HJKMNP-Z]{8}$/), url: `${ORIGIN}/w/northwind/e/${started.code}`, fingerprint: expect.any(String), expiresAt: expect.any(String), hardExpiresAt: expect.any(String) })
    const machine = { workspace: f.work, keys, device: started.enrolment }
    const pending = await body<{ status: string; expiresAt: string }>(await f.deviceCall(machine, `/v1/enrol/${started.enrolment}`, undefined, "enrol"))
    expect(pending.status).toBe("pending_owner_acceptance")
    expect(pending.expiresAt).toBe(started.expiresAt)
    // 0.2.0 polls until its own clock passes expiresAt, then starts again.
    expect(Date.parse(started.expiresAt) - Date.now()).toBeGreaterThan(ENROLMENT_TTL_MS - 60_000)
  })
})

describe("the enrolment page API at each lease, by code and by id", () => {
  it("both forms hide the same group; the id form carries no code; a wrong group on either spends the one counter", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const byCode = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
    const byId = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.enrolment}`, f.alex))
    expect(byId.fingerprint.hidden).toBe(byCode.fingerprint.hidden)
    expect(byId.fingerprint.groups).toEqual(byCode.fingerprint.groups)
    expect(byId.fingerprint.check).toBe(await fingerprintGroupCheck(start.started.enrolment, start.group))
    expect(byCode.fingerprint.check).toBe(await fingerprintGroupCheck(start.started.code, start.group))
    expect(byId).toMatchObject({ ref: start.started.enrolment, lease: "live", reason: null, successor: null, claimed: null })
    expect(byId).not.toHaveProperty("code")
    expect(JSON.stringify(byId)).not.toContain(start.started.code)
    expect(JSON.stringify(byId)).not.toContain(start.thumbprint)
    const wrong = start.group === "2222" ? "3333" : "2222"
    expect((await f.request(`/api/w/northwind/enrolments/${start.started.enrolment}/action`, f.alex, { kind: "accept", group: wrong, privateCredentials: true })).status).toBe(403)
    await refusal(await f.request(`/api/w/northwind/enrolments/${start.started.code}/action`, f.alex, { kind: "accept", group: wrong, privateCredentials: true }), 403, { error: "forbidden", message: "That is not the hidden group of this key. Type it from the terminal: 3 attempts left before this enrolment is rejected." })
    expect(await row(f, start)).toMatchObject({ group_attempts: 2 })
  })

  it("a lapsed link shows from D1 alone, refuses accept and admit, and an owner may reject it", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work), member = await f.guest(f.alex, f.work, f.project.id, "Mia")
    await body(await f.memberChange(f.alex, f.work, member.member!, "role", "member"))
    await f.db.prepare("UPDATE enrolments SET expires_at=? WHERE id=?").bind(Date.now() - 1, start.started.enrolment).run()
    const hard = (await row(f, start))!.hard_expires_at
    for (const ref of [start.started.code, start.started.enrolment]) {
      const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${ref}`, f.alex))
      expect(view).toMatchObject({ state: "pending_owner_acceptance", lease: "lapsed", actions: ["reject"], owner: null, hardExpiresAt: new Date(hard).toISOString() })
      const lapsed = { error: "conflict", message: `This link has lapsed. Ask the agent to continue; the same link comes back to life until ${new Date(hard).toISOString().slice(0, 16).replace("T", " ")} UTC.` }
      await refusal(await f.request(`/api/w/northwind/enrolments/${ref}/action`, f.alex, { kind: "accept", group: start.group, privateCredentials: true }), 409, lapsed)
      await refusal(await f.request(`/api/w/northwind/enrolments/${ref}/accept`, f.alex, { group: start.group, privateCredentials: true }), 409, lapsed)
      await refusal(await f.request(`/api/w/northwind/enrolments/${ref}/admit`, f.alex, { group: start.group }), 409, lapsed)
    }
    // Never registered while lapsed.
    expect(await f.sql(f.work, "SELECT id FROM workspace_enrolments WHERE id=?", start.started.enrolment)).toEqual([])
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, member))).toMatchObject({ lease: "lapsed", actions: [] })
    await refusal(await f.request(`/api/w/northwind/enrolments/${start.started.code}/reject`, member, {}), 403, { error: "forbidden", message: "Only an owner or admin can reject this machine now." })
    expect(await row(f, start)).toMatchObject({ status: "pending" })
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.enrolment}/reject`, f.alex, {}))).toMatchObject({ state: "rejected", lease: "terminal", actions: [] })
    expect(await poll(f, start)).toEqual({ status: "rejected" })
    await settled(await renew(f, start), { status: "rejected" })
  })

  it("a superseded page names its successor only for the same key, intent, owner intent and claim, and only to whoever may see it", async () => {
    const f = await workJourney(), member = await f.guest(f.alex, f.work, f.project.id, "Mia")
    await body(await f.memberChange(f.alex, f.work, member.member!, "role", "member"))
    const first = await f.startMachine(f.work)
    const again = async (workspace: string) => {
      const jwk = await publicJwk(first.keys), input = { workspace, owner: { kind: "self" }, name: "integration-machine", backend: "software", jwk }
      const proof = await createProof(webCryptoSigner("new", first.keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
      return body<{ enrolment: string; expiresAt: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
    }
    const successor = await again("northwind")
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${first.started.enrolment}`, f.alex))).toMatchObject({ state: "expired", lease: "terminal", reason: "superseded", actions: [], successor: { enrolment: successor.enrolment, expiresAt: successor.expiresAt } })
    // A plain member holding the old code cannot see the successor.
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${first.started.code}`, member))).toMatchObject({ reason: "superseded", successor: null })
    // The same key asking for another workspace is no successor of this one.
    await again("alex")
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${successor.enrolment}`, f.alex))).toMatchObject({ reason: "superseded", successor: null })
  })

  it("a settled attempt with no workspace copy is shown by code only to a member the workspace admits to read", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    const people = async (name: string) => { const person = await f.guest(f.alex, f.work, f.project.id, name); await body(await f.memberChange(f.alex, f.work, person.member!, "role", "member")); return person }
    const active = await people("Ann"), suspended = await people("Sam"), unconfirmed = await people("Una"), gated = await people("Gil")
    await f.db.prepare("UPDATE enrolments SET status='expired',expired_reason='hard_cap',pending_state=NULL,expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now() - 2, Date.now() - 1, start.started.enrolment).run()
    expect(await f.db.prepare("SELECT tenant FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ tenant: null })
    const path = `/api/w/northwind/enrolments/${start.started.code}`
    expect(await body<WorkspaceEnrolView>(await f.request(path, active))).toMatchObject({ state: "expired", lease: "terminal", reason: "hard_cap", actions: [] })
    await f.sql(f.work, "UPDATE members SET status='suspended' WHERE id=?", suspended.member!)
    await f.sql(f.work, "UPDATE members SET status='unconfirmed' WHERE id=?", unconfirmed.member!)
    const refused = async (person: Person, error: string) => {
      const response = await f.request(path, person)
      expect(response.status).toBe(403)
      const text = await response.text()
      expect(JSON.parse(text)).toMatchObject({ error })
      expect(text).not.toContain("integration-machine")
    }
    await refused(suspended, "owner_inactive")
    await refused(unconfirmed, "owner_inactive")
    // An identity rule covering members, which this member never passed.
    await f.sql(f.work, "INSERT OR REPLACE INTO tenant_state(key,value) VALUES ('identity_rule',?)", JSON.stringify({ provider: "google", domains: ["northwind.example"], roles: ["member"] }))
    await refused(gated, "identity_required")
  })

  it("a registered attempt's successor registers beside it, opens and completes, and the old copy keeps its evidence", async () => {
    const f = await workJourney(), guest = await f.guest(f.alex, f.work, f.project.id, "Gina"), first = await f.startMachine(f.work)
    // The first attempt is registered and carries a guest's stored acceptance.
    expect(await body<{ state: string }>(await f.acceptMachine(guest, f.work, first, false))).toMatchObject({ state: "pending_admission" })
    const stored = async (id: string) => (await f.sql<{ value: string }>(f.work, "SELECT value FROM workspace_enrolments WHERE id=?", id))[0]?.value
    const before = await stored(first.started.enrolment)
    expect(before).toContain("acceptance")
    const jwk = await publicJwk(first.keys), input = { workspace: "northwind", owner: { kind: "self" }, name: "integration-machine", backend: "software", jwk }
    const proof = await createProof(webCryptoSigner("new", first.keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
    const next = await body<{ enrolment: string; code: string; expiresAt: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
    const old = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${first.started.enrolment}`, f.alex))
    expect(old).toMatchObject({ reason: "superseded", successor: { enrolment: next.enrolment, expiresAt: next.expiresAt } })
    const view = await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${old.successor!.enrolment}`, f.alex))
    expect(view).toMatchObject({ state: "pending_owner_acceptance", lease: "live", actions: ["accept", "reject"] })
    const action: WorkspaceStepUpAction = { type: "enrol.accept", workspace: f.work.id, enrolment: next.enrolment, thumbprint: first.thumbprint, account: f.alex.account, member: await f.member(f.alex, f.work), scope: view.scope, start: view.start }
    expect(await body<WorkspaceEnrolView>(await f.signed(`/api/w/northwind/enrolments/${next.enrolment}/accept`, f.alex, { group: fingerprintGroups(fingerprintOf(first.thumbprint))[await fingerprintGroupIndex(next.code)], privateCredentials: view.scope.privateCredentials }, action, "northwind"))).toMatchObject({ state: "active" })
    expect(await body(await f.deviceCall({ workspace: f.work, keys: first.keys, device: next.enrolment }, `/v1/enrol/${next.enrolment}`, undefined, "enrol"))).toMatchObject({ status: "active", workspace: f.work })
    expect(await f.sql(f.work, "SELECT id FROM workspace_enrolments WHERE thumbprint=? ORDER BY id", first.thumbprint)).toHaveLength(2)
    expect(await stored(first.started.enrolment)).toBe(before)
  })

  it("an attempt from before 0008 has no id page; its code page still works", async () => {
    const f = await workJourney(), start = await f.startMachine(f.work)
    await f.db.prepare("UPDATE enrolments SET hidden_group=NULL,hard_expires_at=expires_at WHERE id=?").bind(start.started.enrolment).run()
    await refusal(await f.request(`/api/w/northwind/enrolments/${start.started.enrolment}`, f.alex), 404, { error: "not_found", message: "No such enrolment." })
    expect(await body<WorkspaceEnrolView>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))).toMatchObject({ lease: "live", actions: ["accept", "reject"] })
    expect(await body<{ state: string }>(await f.acceptMachine(f.alex, f.work, start))).toMatchObject({ state: "active" })
  })
})
