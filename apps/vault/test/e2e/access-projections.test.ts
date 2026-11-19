import { expect, it } from "vitest"
import { AccountSessionSchema, PENDING_RESTRICTION_UNTIL, WorkspaceDeviceViewSchema } from "@mehen/protocol"
import { body, workJourney } from "./workspace-journey.ts"

it("account projections: creator permission, pending recovery null deadline and source machine context", async () => {
  const f = await workJourney()
  const account = AccountSessionSchema.parse(await body(await f.request("/api/account", f.alex)))
  expect(account.canCreateWorkspaces).toBe(true)
  await f.db.prepare("UPDATE accounts SET can_create_workspaces=0,can_create_workspaces_op=? WHERE id=?").bind(crypto.randomUUID(), f.alex.account).run()
  expect(AccountSessionSchema.parse(await body(await f.request("/api/account", f.alex))).canCreateWorkspaces).toBe(false)
  const start = await f.startMachine(f.work)
  const pending = await body<{ start: unknown }>(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  await body(await f.acceptMachine(f.alex, f.work, start))
  const [accepted] = await f.sql<{ id: string }>(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)
  const machines = await body<{ devices: unknown[] }>(await f.request("/api/w/northwind/devices", f.alex))
  expect(machines.devices.map(value => WorkspaceDeviceViewSchema.parse(value)).find(value => value.device === accepted!.id)?.start).toEqual(pending.start)
  f.faults.blockWorkspace = f.personal.id
  await body(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] }), 202)
  await f.signin(f.alex)
  // Exercise the persisted sentinel shape while the real recovery barrier is
  // pending. Initial reservation keeps the account column null; recomputed
  // unresolved-notice restrictions may carry this open-ended marker.
  await f.db.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id=?").bind(PENDING_RESTRICTION_UNTIL, f.alex.account).run()
  const recovered = AccountSessionSchema.parse(await body(await f.request("/api/account", f.alex)))
  expect(recovered.restricted).toMatchObject({ reason: "recovery", until: null })
  expect(recovered.pendingTransition?.state).toBe("pending")
  const page = await f.request("/account", f.alex, undefined, { accept: "text/html" })
  expect(page.status).toBe(200)
  expect(await page.text()).toContain("Until recovery completes")
  // The real recovery writer uses null for a pending notice deadline. Also pin
  // the defensive projection of a sentinel-bearing historical notice.
  await f.db.prepare("UPDATE account_notices SET restricted_until=? WHERE account=? AND kind='recovery'").bind(PENDING_RESTRICTION_UNTIL, f.alex.account).run()
  const notices = await body<{ restrictedUntil: string | null }[]>(await f.request("/api/account/notices", f.alex))
  expect(notices.some(value => value.restrictedUntil === null)).toBe(true)
})

it("expiry: real directory cron closes a no-device source and further acceptance stays refused", async () => {
  const f = await workJourney(), start = await f.startMachine(f.work)
  await body(await f.request(`/api/w/northwind/enrolments/${start.started.code}`, f.alex))
  await f.db.prepare("UPDATE enrolments SET expires_at=?,hard_expires_at=? WHERE id=?").bind(Date.now() - 1, Date.now() - 1, start.started.enrolment).run()
  await f.sql(f.work, "UPDATE workspace_enrolments SET value=json_set(value,'$.detail.hardExpiresAt',?) WHERE id=?", new Date(Date.now() - 1).toISOString(), start.started.enrolment)
  await f.cron()
  const source = await f.db.prepare("SELECT status,reconciled_at FROM enrolments WHERE id=?").bind(start.started.enrolment).first<{ status: string; reconciled_at: number | null }>()
  expect(source?.status).toBe("expired")
  expect(source?.reconciled_at).not.toBeNull()
  const before = await f.snapshot(f.work)
  expect((await f.request(`/api/w/northwind/enrolments/${start.started.code}/accept`, f.alex, { privateCredentials: false, group: start.group })).status).toBe(404)
  expect(await f.snapshot(f.work)).toEqual(before)
})
