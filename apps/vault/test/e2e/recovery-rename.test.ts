import { expect, it } from "vitest"
import { PENDING_RESTRICTION_UNTIL, type WorkspaceStepUpAction } from "@mehen/protocol"
import { assertion, registration, softwarePasskey } from "./passkeys.ts"
import { body, refusal, workJourney, type Person } from "./workspace-journey.ts"

it("machine crash: a committed acceptance with a lost reply is reconciled by the real cron", async () => {
  const f = await workJourney(), start = await f.startMachine(f.work)
  f.faults.lostReply = "access.enrol.accept"
  expect((await f.acceptMachine(f.alex, f.work, start)).status).toBe(500)
  expect(await f.db.prepare("SELECT status,device,mirror_acknowledged FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ status: "pending", device: null, mirror_acknowledged: 0 })
  const [created] = await f.sql<{ id: string }>(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)
  expect(created).toBeTruthy()
  await f.cron()
  expect(await f.db.prepare("SELECT status,device,mirror_acknowledged FROM enrolments WHERE id=?").bind(start.started.enrolment).first()).toEqual({ status: "active", device: created!.id, mirror_acknowledged: 1 })
  const poll = await f.deviceCall({ workspace: f.work, keys: start.keys, device: start.started.enrolment }, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol")
  expect(await body(poll)).toEqual({ status: "active", tenant: f.work.id, workspace: f.work, device: created!.id, owner: { kind: "member", member: await f.member(f.alex, f.work), name: "Alex" }, scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials: true } })
})

it("recovery: real code, owner/admin notices, pending older-factor cancellation and lazy lift", async () => {
  const f = await workJourney()
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "admin"))
  const coOwner = await f.guest(f.alex, f.work, f.project.id, "Co-owner")
  await body(await f.memberChange(f.alex, f.work, coOwner.member!, "role", "owner"))
  // Observe the start before the barrier commits: notices must not wait for
  // the unavailable DO. A surviving older factor signs in again to cancel.
  f.faults.blockInstall = true
  const response = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
  const ceremonyCookie = response.headers.get("set-cookie")?.split(";")[0]
  const recovery = await body<{ pending: boolean; transition: string }>(response, 202)
  expect(recovery).toEqual({ pending: true, transition: expect.stringMatching(/^trn_/) })
  const notices = (await f.db.prepare("SELECT id,restricted_until FROM account_notices WHERE account=? AND kind='recovery'").bind(f.alex.account).all<{ id: string; restricted_until: number | null }>()).results
  expect(notices).toEqual([{ id: expect.stringMatching(/^ntc_/), restricted_until: null }])
  const notice = notices[0]!.id
  const outbox = await f.sql<{ account: string; payload: string }>(f.work, "SELECT account,payload FROM notice_outbox WHERE json_extract(payload,'$.kind')='account_security'")
  expect(outbox.map(row => row.account).sort()).toEqual([coOwner.account, tom.account].sort())
  for (const row of outbox) expect(JSON.parse(row.payload)).toEqual({ kind: "account_security", workspace: f.work, account: f.alex.account, name: "Alex", event: "recovery", at: expect.any(String), client: "A browser", place: null, restrictedUntil: null })
  expect(await f.sql(f.work, "SELECT state FROM account_security WHERE account=?", f.alex.account)).toHaveLength(1)
  await f.signin(f.alex)
  const action: WorkspaceStepUpAction = { type: "recovery.resolve", notice, outcome: "cancel" }
  const cancelled = await f.signed(`/api/account/recovery/${notice}/resolve`, f.alex, { outcome: "cancel" }, action)
  expect(await body(cancelled)).toEqual({ pending: true })
  expect(await f.db.prepare("SELECT resolved_at FROM account_notices WHERE id=?").bind(notice).first()).toEqual({ resolved_at: null })
  // Pending recovery has not made an authenticated ceremony session.
  const dead = { ...f.alex, cookie: ceremonyCookie ?? "" }
  expect((await f.request("/api/auth/recovery/passkey/options", dead, {})).status).toBe(401)
  f.faults.blockInstall = false
  f.faults.blockRestriction = true
  await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE id=?").bind(recovery.transition).run()
  await f.cron()
  expect(await f.db.prepare("SELECT security_epoch,security_transition,restricted_until FROM accounts WHERE id=?").bind(f.alex.account).first()).toEqual({ security_epoch: 2, security_transition: null, restricted_until: null })
  expect(await f.db.prepare("SELECT outcome FROM account_notices WHERE id=?").bind(notice).first()).toEqual({ outcome: "cancel" })
  const [guard] = await f.sql<{ state: string }>(f.work, "SELECT state FROM account_security WHERE account=?", f.alex.account)
  const transition = await f.db.prepare("SELECT revoked_sessions FROM account_security_transitions WHERE id=?").bind(recovery.transition).first<{ revoked_sessions: string }>()
  const expectedSecurity = { account: f.alex.account, installedEpoch: 2, pending: null, deleting: false, revokedSessionIds: JSON.parse(transition!.revoked_sessions) as string[], removedFactorIds: [], restriction: { reason: "recovery", until: PENDING_RESTRICTION_UNTIL, notice } }
  expect(JSON.parse(guard!.state)).toEqual(expectedSecurity)
  f.faults.blockRestriction = false
  await f.db.prepare("UPDATE account_events SET next_retry_at=0").run()
  await f.cron()
  const [lifted] = await f.sql<{ state: string }>(f.work, "SELECT state FROM account_security WHERE account=?", f.alex.account)
  expect(JSON.parse(lifted!.state)).toEqual({ ...expectedSecurity, restriction: null })
  await f.signin(f.alex)
  expect(await body(await f.request("/api/w/northwind", f.alex))).toEqual(f.work)
})

it("recovery stolen-sheet: a recovered factor cannot resolve a later notice while an older one governs", async () => {
  const f = await workJourney()
  const firstResponse = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
  const firstCookie = firstResponse.headers.get("set-cookie")?.split(";")[0] ?? ""
  expect(await body(firstResponse)).toEqual({ pending: false, transition: expect.stringMatching(/^trn_/) })
  const stolen: Person = { ...f.alex, cookie: firstCookie, passkey: await softwarePasskey(), counter: 0 }
  const options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/recovery/passkey/options", stolen, {}))
  const added = await f.request("/api/auth/recovery/passkey/verify", stolen, { response: await registration(stolen.passkey, options.options.challenge), name: "Recovered" })
  stolen.cookie = added.headers.get("set-cookie")?.split(";")[0] ?? ""
  expect(await body(added)).toEqual({})
  expect(await body(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[1] }))).toEqual({ pending: false, transition: expect.stringMatching(/^trn_/) })
  await f.signin(stolen)
  const notices = (await f.db.prepare("SELECT id,at,restricted_until FROM account_notices WHERE account=? AND kind='recovery' ORDER BY at").bind(f.alex.account).all<{ id: string; at: number; restricted_until: number }>()).results
  expect(notices).toHaveLength(2)
  const before = (await f.db.prepare("SELECT * FROM accounts WHERE id=?").bind(f.alex.account).all()).results
  const noticeBefore = (await f.db.prepare("SELECT * FROM account_notices WHERE account=? ORDER BY id").bind(f.alex.account).all()).results
  for (const outcome of ["cancel", "keep"] as const) {
    const action: WorkspaceStepUpAction = { type: "recovery.resolve", notice: notices[1]!.id, outcome }
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/api/account/stepup/start", stolen, { action }))
    await refusal(await f.request(`/api/account/recovery/${notices[1]!.id}/resolve`, stolen, { outcome, stepUp: { nonce, assertion: await assertion(stolen.passkey, options.challenge, ++stolen.counter) } }), 403, { error: "forbidden", message: "Only an older account passkey can resolve recovery." })
    expect((await f.db.prepare("SELECT * FROM accounts WHERE id=?").bind(f.alex.account).all()).results).toEqual(before)
    expect((await f.db.prepare("SELECT * FROM account_notices WHERE account=? ORDER BY id").bind(f.alex.account).all()).results).toEqual(noticeBefore)
  }
})

it("recovery: the recovered sign-in cannot end the older passkey's sign-ins, which may end the recovered ones and still cancel", async () => {
  const f = await workJourney()
  const currentSession = async (person: Person) => (await body<{ sessions: { session: string; current: boolean }[] }>(await f.request("/api/account/sessions", person))).sessions.find(session => session.current)!.session
  const lives = async (session: string) => (await f.db.prepare("SELECT COUNT(*) AS n FROM web_sessions WHERE id=?").bind(session).first<{ n: number }>())?.n === 1
  // Without a recovery, one sign-in ends another as before.
  await f.signin(f.alex)
  const spare = { ...f.alex }
  await f.signin(f.alex)
  expect(await body(await f.request(`/api/account/sessions/${await currentSession(spare)}/end`, f.alex, {}))).toEqual({})
  expect((await f.request("/api/account", spare)).status).toBe(401)
  // A recovery code starts the recovery; passkey B is registered through its ceremony.
  const started = await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] })
  const recovered: Person = { ...f.alex, cookie: started.headers.get("set-cookie")?.split(";")[0] ?? "", passkey: await softwarePasskey(), counter: 0 }
  expect(await body(started)).toEqual({ pending: false, transition: expect.stringMatching(/^trn_/) })
  const options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/recovery/passkey/options", recovered, {}))
  const added = await f.request("/api/auth/recovery/passkey/verify", recovered, { response: await registration(recovered.passkey, options.options.challenge), name: "Recovered" })
  recovered.cookie = added.headers.get("set-cookie")?.split(";")[0] ?? ""
  expect(await body(added)).toEqual({})
  const notice = (await f.db.prepare("SELECT id FROM account_notices WHERE account=? AND kind='recovery' AND resolved_at IS NULL").bind(f.alex.account).first<{ id: string }>())!.id
  const recoveredKey = (await f.db.prepare("SELECT handle FROM passkeys WHERE account=? AND added_via='recovery'").bind(f.alex.account).first<{ handle: string }>())!.handle
  // The owner signs in again with passkey A, after the notice.
  await f.signin(f.alex)
  const owner = await currentSession(f.alex), recoveredSession = await currentSession(recovered)
  const refused = { error: "forbidden", message: "During a recovery, only a sign-in with a passkey from before it can end other sign-ins. Cancelling the recovery ends the new ones." }
  await refusal(await f.request(`/api/account/sessions/${owner}/end`, recovered, {}), 403, refused)
  await refusal(await f.request("/api/account/sessions/end-all", recovered, {}), 403, refused)
  expect(await lives(owner)).toBe(true)
  expect(await f.db.prepare("SELECT security_transition FROM accounts WHERE id=?").bind(f.alex.account).first()).toEqual({ security_transition: null })
  // Passkey A's sign-in, though newer than the notice, may end a recovered one; a recovered one may still end itself.
  const first = { ...recovered }
  await f.signin(recovered)
  const second = await currentSession(recovered)
  await f.signin(recovered)
  const third = { ...recovered }
  expect(await body(await f.request(`/api/account/sessions/${second}/end`, f.alex, {}))).toEqual({})
  expect(await lives(second)).toBe(false)
  expect(await body(await f.request(`/api/account/sessions/${await currentSession(third)}/end`, third, {}))).toEqual({})
  expect((await f.request("/api/account", third)).status).toBe(401)
  expect(await lives(recoveredSession)).toBe(true)
  // The cancel through step-up still goes through and queues the recovered sign-in and passkey.
  f.faults.blockInstall = true
  const cancelled = await f.signed(`/api/account/recovery/${notice}/resolve`, f.alex, { outcome: "cancel" }, { type: "recovery.resolve", notice, outcome: "cancel" })
  expect(await body(cancelled)).toEqual({ pending: true })
  const queued = await f.db.prepare("SELECT t.id,t.revoked_sessions,t.removed_factors FROM account_security_transitions t JOIN accounts a ON a.security_transition=t.id WHERE a.id=?").bind(f.alex.account).first<{ id: string; revoked_sessions: string; removed_factors: string }>()
  expect(JSON.parse(queued!.revoked_sessions)).toEqual(expect.arrayContaining([recoveredSession, owner]))
  expect(JSON.parse(queued!.removed_factors)).toEqual([recoveredKey])
  expect((await f.request("/api/account", first)).status).toBe(401)
  f.faults.blockInstall = false
  await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE id=?").bind(queued!.id).run()
  await f.cron()
  expect(await f.db.prepare("SELECT outcome FROM account_notices WHERE id=?").bind(notice).first()).toEqual({ outcome: "cancel" })
  expect(await lives(recoveredSession)).toBe(false)
  expect(await f.db.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE handle=?").bind(recoveredKey).first()).toEqual({ n: 0 })
  // Once the recovery is resolved, one sign-in ends another as before.
  await f.signin(f.alex)
  const later = { ...f.alex }
  await f.signin(f.alex)
  expect(await body(await f.request(`/api/account/sessions/${await currentSession(later)}/end`, f.alex, {}))).toEqual({})
  expect((await f.request("/api/account", later)).status).toBe(401)
  expect(await body(await f.request("/api/account/sessions/end-all", f.alex, {}))).toEqual({ pending: false })
})

it("rename: reserve, apply, finalise, permanent alias redirect and uniform sixth-alias refusal", async () => {
  const f = await workJourney()
  // A failed final D1 batch proves the reservation and applied DO state are
  // independently recoverable. No public operation calls an area directly.
  await f.db.prepare("CREATE TRIGGER integration_rename_failure BEFORE UPDATE OF slug ON workspaces WHEN NEW.slug='northwind-1' BEGIN SELECT RAISE(ABORT,'injected finalise failure'); END").run()
  const rename = (from: string, to: string) => f.signed(`/api/w/${from}/settings`, f.alex, { change: "slug", slug: to }, { type: "workspace.update", name: "Northwind", slug: to }, from)
  expect((await rename("northwind", "northwind-1")).status).toBe(500)
  const reservation = await f.db.prepare("SELECT id,new_slug,old_slug FROM workspace_slug_reservations WHERE workspace=?").bind(f.work.id).first<{ id: string; new_slug: string; old_slug: string }>()
  expect(reservation).toEqual({ id: expect.stringMatching(/^wrs_/), new_slug: "northwind-1", old_slug: "northwind" })
  const [applied] = await f.sql<{ value: string }>(f.work, "SELECT value FROM tenant_state WHERE key='workspace'")
  expect(JSON.parse(applied!.value)).toEqual({ ...f.work, slug: "northwind-1" })
  expect(await f.db.prepare("SELECT slug FROM workspaces WHERE id=?").bind(f.work.id).first()).toEqual({ slug: "northwind" })
  expect((await f.request("/api/w/northwind-1", f.alex)).status).toBe(404)
  await f.db.prepare("DROP TRIGGER integration_rename_failure").run()
  await f.db.prepare("UPDATE workspace_slug_reservations SET expires_at=0 WHERE workspace=?").bind(f.work.id).run()
  await f.cron()
  expect(await f.db.prepare("SELECT * FROM workspace_slug_reservations").all().then(value => value.results)).toEqual([])
  for (let i = 2; i <= 5; i++) expect(await body(await rename(`northwind-${i - 1}`, `northwind-${i}`))).toEqual({ workspace: { ...f.work, slug: `northwind-${i}` }, displayRev: i + 1 })
  const redirect = await f.request("/w/northwind/?from=alias", f.alex)
  expect(redirect.status).toBe(302)
  expect(redirect.headers.get("location")).toBe("/w/northwind-5/?from=alias")
  const before = (await f.db.prepare("SELECT * FROM workspace_slugs ORDER BY slug").all()).results
  expect(before).toHaveLength(5)
  for (const name of ["northwind-6", "alex", "legacy-closed"]) await refusal(name.startsWith("legacy-") ? await f.request("/api/w/northwind-5/settings", f.alex, { change: "slug", slug: name }) : await rename("northwind-5", name), 409, { error: "conflict", message: "name not available" })
  expect((await f.db.prepare("SELECT * FROM workspace_slugs ORDER BY slug").all()).results).toEqual(before)
})
