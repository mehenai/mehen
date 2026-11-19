import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import worker from "../../src/index.ts"
import { ORIGIN } from "../helpers.ts"
import { expect, it, vi } from "vitest"
import { body, refusal, workJourney } from "./workspace-journey.ts"

it("resolveWorkspace retries only when due: surviving reads and freeze work with one unavailable target, widening refuses", async () => {
  const f = await workJourney()
  f.faults.blockWorkspace = f.personal.id
  const recovery = await body<{ pending: boolean; transition: string }>(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] }), 202)
  expect(recovery).toEqual({ pending: true, transition: expect.stringMatching(/^trn_/) })
  await f.signin(f.alex)
  // Make the retry due, then enter through the workspace resolver, not an
  // account route or a manually called retry function.
  await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE state='pending'").run()
  const calls = f.faults.installCalls
  expect(await body(await f.request("/api/w/northwind", f.alex))).toEqual(f.work)
  expect(f.faults.installCalls).toBe(calls + 1)
  expect(await body(await f.request("/api/w/northwind", f.alex))).toEqual(f.work)
  expect(f.faults.installCalls).toBe(calls + 1)
  const [guard] = await f.sql<{ state: string }>(f.work, "SELECT state FROM account_security WHERE account=?", f.alex.account)
  const transition = await f.db.prepare("SELECT revoked_sessions,target_restrictions FROM account_security_transitions WHERE id=?").bind(recovery.transition).first<{ revoked_sessions: string; target_restrictions: string }>()
  const revokedSessionIds = JSON.parse(transition!.revoked_sessions) as string[], restriction = JSON.parse(transition!.target_restrictions) as unknown
  expect(JSON.parse(guard!.state)).toEqual({ account: f.alex.account, installedEpoch: 0, pending: { transitionId: recovery.transition, reservedEpoch: 1, revokedSessionIds, removedFactorIds: [], restriction }, restriction, revokedSessionIds, removedFactorIds: [], deleting: false })
  const before = await f.snapshot(f.work)
  await refusal(await f.request("/api/w/northwind/projects/action", f.alex, { change: "create", input: { slug: "blocked-project", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fourEyes: false }] } }), 403, { error: "account_pending", message: "You are not allowed to do that.", next: { url: "https://vault.test/account", say: "Wait for this account security change to finish." }, transition: { id: recovery.transition, reservedEpoch: 1, targets: 0, acknowledged: 0, state: "pending" } })
  expect(await f.snapshot(f.work)).toEqual(before)
  expect(await body(await f.request("/api/w/northwind/freeze", f.alex, {}))).toEqual({})
  expect(await f.sql(f.work, "SELECT value FROM tenant_state WHERE key='frozen'")).toEqual([{ value: "true" }])
  expect(await f.db.prepare("SELECT security_epoch FROM accounts WHERE id=?").bind(f.alex.account).first()).toEqual({ security_epoch: 0 })
})

it("resolveWorkspace returns while a due security install is still held", async () => {
  const f = await workJourney()
  f.faults.blockWorkspace = f.personal.id
  await body(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] }), 202)
  await f.signin(f.alex)
  await f.db.prepare("UPDATE account_security_transitions SET next_retry_at=0 WHERE state='pending'").run()
  let release: () => void = () => undefined
  f.faults.holdInstall = new Promise<void>(resolve => { release = resolve })
  const calls = f.faults.installCalls, ctx = createExecutionContext()
  const response = worker.fetch(new Request(`${ORIGIN}/api/w/northwind`, { headers: { cookie: f.alex.cookie } }), f.env, ctx)
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const outcome = await Promise.race([response, new Promise<null>(resolve => { timer = setTimeout(() => resolve(null), 1000) })])
    expect(outcome, "workspace response must not await the held install").not.toBeNull()
    if (outcome) expect(await body(outcome)).toEqual(f.work)
  } finally {
    clearTimeout(timer)
    release()
    await waitOnExecutionContext(ctx)
    await response
  }
  expect(f.faults.installCalls).toBe(calls + 1)
})

it("resolveWorkspace logs a background D1 retry failure without rejecting the response or waitUntil", async () => {
  const f = await workJourney()
  f.faults.blockWorkspace = f.personal.id
  const recovery = await body<{ transition: string }>(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] }), 202)
  await f.signin(f.alex)
  const db = new Proxy(f.db, { get(target, prop) {
    if (prop === "prepare") return (query: string) => {
      if (query.startsWith("UPDATE account_security_transitions SET attempts=")) throw new Error("Injected retry D1 failure")
      return target.prepare(query)
    }
    const value = Reflect.get(target, prop) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  const errors = vi.spyOn(console, "error"), ctx = createExecutionContext()
  try {
    expect(await body(await worker.fetch(new Request(`${ORIGIN}/api/w/northwind`, { headers: { cookie: f.alex.cookie } }), { ...f.env, DB: db }, ctx))).toEqual(f.work)
    await waitOnExecutionContext(ctx)
    expect(errors).toHaveBeenCalledExactlyOnceWith(JSON.stringify({ at: "account.security.retry", transition: recovery.transition }))
  } finally { errors.mockRestore() }
})
