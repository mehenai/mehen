// Workloads: creation, management, proofs and ending, through the real
// Worker and Durable Object.
import { WORKLOAD_MAX_LIVE_PER_DEVICE, createProof, webCryptoSigner, type WorkloadView } from "@mehen/protocol"
import { expect, it } from "vitest"
import { ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { body } from "./e2e/workspace-journey.ts"
import { workloadJourney } from "./workload-journey.ts"

const ended = { error: "workload_ended", message: "This workload has ended. Create a new one from its device.", next: { say: "This task's workload has ended; its device must create a new workload for it." } }

it("a device creates a workload that signs for itself and reads the device with its workload", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, { modes: ["relay"] }, "globex:grant-1")
  expect(task.view.workload).toMatch(/^wl_/)
  expect(Date.parse(task.view.expiresAt) - Date.parse(task.view.createdAt)).toBe(3600_000)
  expect(Date.parse(task.view.hardExpiresAt) - Date.parse(task.view.createdAt)).toBe(7 * 86400_000)
  const device = await body<Record<string, unknown>>(await f.deviceCall(f.machine, "/v1/me"))
  expect("workload" in device).toBe(false)
  const me = await body<Record<string, unknown> & { workload: WorkloadView }>(await f.workloadCall(f.as(task), "/v1/me"))
  const { workload, ...rest } = me
  expect(rest).toEqual(device)
  expect(workload).toMatchObject({ workload: task.view.workload, label: "globex:grant-1", state: "active", lastSeenAt: expect.any(String) })
  expect(await body(await f.deviceCall(f.machine, "/v1/workloads"))).toEqual({ workloads: [{ ...task.view, lastSeenAt: expect.any(String) }] })
  expect(await body(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}`))).toMatchObject({ workload: task.view.workload })
  const audit = await f.sql<{ action: string; detail: string }>(f.work, "SELECT action,detail FROM audit WHERE action='workload.created'")
  expect(audit).toHaveLength(1)
  expect(JSON.parse(audit[0]!.detail)).toMatchObject({ workload: { id: task.view.workload, label: "globex:grant-1" }, scope: { modes: ["relay"] } })
  expect(audit[0]!.detail).not.toContain(task.view.thumbprint)
})

it("refuses a scope outside the device, a reused key, and a workload managing workloads", async () => {
  const f = await workloadJourney()
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const refused = await f.deviceCall(f.machine, "/v1/workloads", { jwk, label: "wide", scope: { modes: ["lease"] } })
  expect(refused.status).toBe(400)
  expect(await refused.json()).toMatchObject({ error: "bad_request", message: expect.stringContaining("scope.modes") })
  const deviceKey = await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(f.machine.keys), label: "same", scope: {} })
  expect(deviceKey.status).toBe(409)
  const task = await f.createWorkload(f.machine)
  const reused = await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(task.keys), label: "again", scope: {} })
  expect(reused.status).toBe(409)
  for (const [path, input, method] of [["/v1/workloads", { jwk, label: "child", scope: {} }, "POST"], ["/v1/workloads", undefined, "GET"], [`/v1/workloads/${task.view.workload}`, undefined, "GET"], [`/v1/workloads/${task.view.workload}/renew`, {}, "POST"], [`/v1/workloads/${task.view.workload}`, undefined, "DELETE"], ["/v1/devices/self/revoke", undefined, "POST"]] as const) {
    const response = await f.workloadCall(f.as(task), path, input, method)
    expect(response.status, `${method} ${path}`).toBe(403)
    expect(await response.json()).toMatchObject({ error: "forbidden" })
  }
  expect((await body<{ workloads: unknown[] }>(await f.deviceCall(f.machine, "/v1/workloads"))).workloads).toHaveLength(1)
  expect((await body<{ revoked: boolean }>(await f.deviceCall(f.machine, "/v1/me"))).revoked).toBeUndefined()
})

// BROWSER_FILL is on in the test env; with it off the vault refuses every
// fill workload (fill-unavailable.ts), as before fill shipped.
it("gives a workload fill only when its device has fill and its device's mehen last proved 0.3.17 or later", async () => {
  const f = await workloadJourney()
  const jwk = await publicJwk(await newDeviceKey())
  const ask = (modes: string[]) => f.deviceCall(f.machine, "/v1/workloads", { jwk, label: "fill", scope: { modes } })
  expect(await body(await ask(["relay", "fill"]), 400)).toEqual({ error: "bad_request", message: 'scope.modes: "fill" is outside this machine\'s scope.' })
  const scope = (await f.sql<{ scope: string }>(f.work, "SELECT scope FROM devices WHERE id=?", f.machine.device))[0]!.scope
  await f.sql(f.work, "UPDATE devices SET scope=? WHERE id=?", JSON.stringify({ ...JSON.parse(scope), modes: [...JSON.parse(scope).modes, "fill"] }), f.machine.device)
  const name = (await f.sql<{ name: string }>(f.work, "SELECT name FROM devices WHERE id=?", f.machine.device))[0]!.name
  for (const [version, runs] of [[null, "runs an unknown version of mehen"], ["0.3.16", "runs mehen 0.3.16"]] as const) {
    await f.sql(f.work, "UPDATE devices SET last_cli_version=? WHERE id=?", version, f.machine.device)
    expect(await body(await ask(["fill"]), 403)).toEqual({ error: "mode_refused", message: `${name} ${runs}; typing into web pages needs 0.3.17 or later.`, next: { say: "Update mehen on that machine first, then allow it again." } })
  }
  expect((await body<{ workloads: unknown[] }>(await f.deviceCall(f.machine, "/v1/workloads"))).workloads).toEqual([])
  await f.sql(f.work, "UPDATE devices SET last_cli_version='0.3.17' WHERE id=?", f.machine.device)
  await body(await ask(["relay", "fill"]), 201)
  expect((await f.sql<{ scope: string }>(f.work, "SELECT scope FROM workloads WHERE device=?", f.machine.device)).map((w) => JSON.parse(w.scope).modes)).toEqual([["relay", "fill"]])
})

it("no workload freezes the workspace, whatever its scope; its device's own key still does", async () => {
  const f = await workloadJourney()
  for (const scope of [{}, { items: ["openai-main"], modes: ["relay" as const] }]) {
    const task = await f.createWorkload(f.machine, scope, `task-${Object.keys(scope).length}`)
    expect(await body(await f.workloadCall(f.as(task), "/v1/freeze", {}), 403)).toEqual({ error: "forbidden", message: "A workload cannot freeze the workspace. Its device's own key can." })
  }
  expect(await f.sql(f.work, "SELECT value FROM tenant_state WHERE key='frozen'")).toEqual([])
  expect(await body(await f.deviceCall(f.machine, "/v1/freeze", {}))).toEqual({})
  expect(await f.sql(f.work, "SELECT value FROM tenant_state WHERE key='frozen'")).toEqual([{ value: "true" }])
})

it("a workload's proof never verifies with its device's key, nor a device proof with a workload's, and nonces are per key", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine)
  const url = `${ORIGIN}/v1/me`
  const forged = await createProof(webCryptoSigner(f.machine.device, f.machine.keys.privateKey, task.view.workload), { method: "GET", url }, { tenant: f.work.id })
  expect((await f.request("/v1/me", undefined, undefined, { "Mehen-Proof": forged })).status).toBe(401)
  const swapped = await createProof(webCryptoSigner(f.machine.device, task.keys.privateKey), { method: "GET", url }, { tenant: f.work.id })
  expect((await f.request("/v1/me", undefined, undefined, { "Mehen-Proof": swapped })).status).toBe(401)
  const fresh = await createProof(webCryptoSigner(f.machine.device, task.keys.privateKey, task.view.workload), { method: "GET", url }, { tenant: f.work.id })
  expect((await f.request("/v1/me", undefined, undefined, { "Mehen-Proof": fresh })).status).toBe(200)
  const replay = await f.request("/v1/me", undefined, undefined, { "Mehen-Proof": fresh })
  expect(replay.status).toBe(401)
  expect(await replay.json()).toMatchObject({ error: "proof_invalid" })
  const nonces = await f.sql<{ device: string }>(f.work, "SELECT device FROM device_nonces")
  expect(nonces.some((n) => n.device === task.view.workload)).toBe(true)
  const unknown = await f.workloadCall({ ...f.as(task), id: "wl_unknown0001" }, "/v1/me")
  expect(unknown.status).toBe(401)
  expect(await unknown.json()).toMatchObject({ error: "unauthenticated" })
})

it("a workload proof that does not verify learns nothing about whether the workload has ended", async () => {
  const f = await workloadJourney()
  const revoked = await f.createWorkload(f.machine, {}, "revoked"), expired = await f.createWorkload(f.machine, {}, "expired")
  await body(await f.deviceCall(f.machine, `/v1/workloads/${revoked.view.workload}`, undefined, undefined, undefined, "DELETE"))
  await f.sql(f.work, "UPDATE workloads SET expires_at=? WHERE id=?", Date.now() - 1000, expired.view.workload)
  const stranger = await newDeviceKey()
  for (const task of [revoked, expired]) {
    const forged = await f.workloadCall({ ...f.as(task), keys: stranger }, "/v1/me")
    expect(forged.status).toBe(401)
    expect(await forged.json()).toEqual({ error: "proof_invalid", message: "The Mehen-Proof signature does not verify with this workload's key." })
    const signed = await f.workloadCall(f.as(task), "/v1/me")
    expect(signed.status).toBe(403)
    expect(await signed.json()).toEqual(ended)
  }
  // Once its device is revoked, a live workload's wrongly signed proof is still only proof_invalid.
  const live = await f.createWorkload(f.machine, {}, "live")
  expect(await (await f.deviceCall({ ...f.machine, keys: stranger }, "/v1/me")).json()).toEqual({ error: "proof_invalid", message: "The Mehen-Proof signature does not verify with this device's key." })
  await body(await f.deviceCall(f.machine, "/v1/devices/self/revoke", {}))
  const forged = await f.workloadCall({ ...f.as(live), keys: stranger }, "/v1/me")
  expect(forged.status).toBe(401)
  expect(await forged.json()).toMatchObject({ error: "proof_invalid" })
  expect(await (await f.workloadCall(f.as(live), "/v1/me")).json()).toEqual(ended)
  // The device's own proof keeps its order: revoked before the signature.
  const deviceForged = await f.deviceCall({ ...f.machine, keys: stranger }, "/v1/me")
  expect(await deviceForged.json()).toMatchObject({ error: "device_revoked" })
})

it("renew never passes the hard expiry, revoke is idempotent, and an ended workload is refused on its next request", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, {}, "task-renew", 120)
  const renewed = await body<WorkloadView>(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}/renew`, { ttlSeconds: 86400 }))
  expect(Date.parse(renewed.expiresAt)).toBeGreaterThan(Date.parse(task.view.expiresAt))
  expect(Date.parse(renewed.expiresAt)).toBeLessThanOrEqual(Date.parse(renewed.hardExpiresAt))
  await f.sql(f.work, "UPDATE workloads SET hard_expires_at=? WHERE id=?", Date.now() + 90_000, task.view.workload)
  const capped = await body<WorkloadView>(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}/renew`, { ttlSeconds: 86400 }))
  expect(capped.expiresAt).toBe(capped.hardExpiresAt)
  expect((await f.workloadCall(f.as(task), "/v1/me")).status).toBe(200)
  const first = await body<WorkloadView>(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}`, undefined, undefined, undefined, "DELETE"))
  expect(first).toMatchObject({ state: "revoked", revokedBy: "device", revokedAt: expect.any(String) })
  expect(await body(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}`, undefined, undefined, undefined, "DELETE"))).toEqual(first)
  const after = await f.workloadCall(f.as(task), "/v1/me")
  expect(after.status).toBe(403)
  expect(await after.json()).toEqual(ended)
  const again = await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}/renew`, {})
  expect(again.status).toBe(403)
  expect(await again.json()).toMatchObject({ error: "workload_ended" })
  expect(await body(await f.deviceCall(f.machine, "/v1/workloads"))).toEqual({ workloads: [] })
  const other = await f.enrolMachine(f.alex, f.work)
  expect((await f.deviceCall(other, `/v1/workloads/${task.view.workload}`)).status).toBe(404)
  expect((await f.deviceCall(other, `/v1/workloads/${task.view.workload}`, undefined, undefined, undefined, "DELETE")).status).toBe(404)
})

// The alarm sweep that records the expiry is in workloads-ending.test.ts.
it("an expired workload is refused before any sweep", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, {}, "task-expire")
  await f.sql(f.work, "UPDATE workloads SET expires_at=? WHERE id=?", Date.now() - 1000, task.view.workload)
  const response = await f.workloadCall(f.as(task), "/v1/items")
  expect(response.status).toBe(403)
  expect(await response.json()).toEqual(ended)
  expect(await body(await f.deviceCall(f.machine, `/v1/workloads/${task.view.workload}`))).toMatchObject({ state: "expired" })
})

it("revoking the device ends every workload it made", async () => {
  const f = await workloadJourney()
  const one = await f.createWorkload(f.machine, {}, "one"), two = await f.createWorkload(f.machine, {}, "two")
  expect(await body(await f.deviceCall(f.machine, "/v1/devices/self/revoke", {}))).toEqual({})
  for (const task of [one, two]) {
    const response = await f.workloadCall(f.as(task), "/v1/me")
    expect(response.status).toBe(403)
    expect(await response.json()).toEqual(ended)
  }
  expect(await f.sql(f.work, "SELECT revoked_by FROM workloads ORDER BY id")).toEqual([{ revoked_by: "device_revoked" }, { revoked_by: "device_revoked" }])
})

it("refuses more live workloads than the per-device limit", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine)
  const now = Date.now()
  for (let i = 1; i < WORKLOAD_MAX_LIVE_PER_DEVICE; i++) await f.sql(f.work, "INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES (?,?,?,?,?,?,?,?,?)", `wl_filler${String(i).padStart(4, "0")}`, f.machine.device, "filler", "{}", `thumb-${i}`, "{}", now, now + 3600_000, now + 86400_000)
  const keys = await newDeviceKey()
  const response = await f.deviceCall(f.machine, "/v1/workloads", { jwk: await publicJwk(keys), label: "one-too-many", scope: {} })
  expect(response.status).toBe(429)
  expect(await response.json()).toMatchObject({ error: "rate_limited" })
  expect(task.view.state).toBe("active")
})

it("one workload holds at most five open asks, intakes and connections together, while a sibling workload can still ask", async () => {
  const f = await workloadJourney()
  const intake = (slug: string) => ({ kind: "api-key", slug, provider: "openai", reason: "model", home: "workspace" })
  const busy = await f.createWorkload(f.machine, {}, "busy"), sibling = await f.createWorkload(f.machine, {}, "sibling")
  for (const slug of ["task-1", "task-2", "task-3"]) await body(await f.workloadCall(f.as(busy), "/v1/intakes", intake(slug)), 201)
  // A connection that also asks for its client is two asks.
  await body(await f.workloadCall(f.as(busy), "/v1/connect", { provider: "google-gmail", slug: "gmail-task", reason: "mail", home: "workspace", requestClient: true }))
  expect(await body(await f.workloadCall(f.as(busy), "/v1/intakes", intake("task-6")), 429)).toEqual({ error: "rate_limited", message: "This task's workload already has 5 open asks, its own limit. Settle one before asking again." })
  expect(await f.sql(f.work, "SELECT count(*) AS n FROM workspace_credential_requests WHERE requester_workload=?", busy.view.workload)).toEqual([{ n: 5 }])
  await body(await f.workloadCall(f.as(sibling), "/v1/intakes", intake("sibling-1")), 201)
  await body(await f.deviceCall(f.machine, "/v1/intakes", intake("device-1")), 201)
  // Settling one makes room again.
  const [first] = await f.sql<{ id: string }>(f.work, "SELECT id FROM workspace_credential_requests WHERE requester_workload=? AND slug='task-1'", busy.view.workload)
  await body(await f.workloadCall(f.as(busy), `/v1/intakes/${first!.id}/cancel`, {}))
  await body(await f.workloadCall(f.as(busy), "/v1/intakes", intake("task-6")), 201)
})

it("enrolment proofs refuse a workload claim", async () => {
  const f = await workloadJourney()
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const input = { workspace: f.work.slug, owner: { kind: "self" }, name: "sneaky", backend: "software", jwk }
  const proof = await createProof(webCryptoSigner("new", keys.privateKey, "wl_task0001"), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
  const response = await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof })
  expect(response.status).toBe(401)
  expect(await response.json()).toMatchObject({ error: "unauthenticated", message: expect.stringContaining("workload") })
})

// Suspension, removal, leaving and revocation are driven through their real
// routes in workloads-ending.test.ts. A team cannot be deleted while it owns
// an active machine, so the team.delete ending is a backstop driven here
// through the hook team deletion runs.
it("a deleted team's machines end their workloads as owner_inactive, and a narrowing rescope ends none", async () => {
  const f = await workloadJourney()
  const task = await f.createWorkload(f.machine, {}, "team-task")
  const { runInDurableObject } = await import("cloudflare:test")
  const { env } = await import("cloudflare:workers")
  const { accessChanged } = await import("../src/vault/areas/workspace-runtime.ts")
  // A narrowing rescope is not an ending: the workload stays, narrowed live.
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => instance.context.storage.transactionSync(() => accessChanged(instance.context, null, "rescope", { device: f.machine.device })))
  expect((await f.workloadCall(f.as(task), "/v1/me")).status).toBe(200)
  await f.sql(f.work, "UPDATE devices SET owner_kind='team',owner_id='tm_backstop01' WHERE id=?", f.machine.device)
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => instance.context.storage.transactionSync(() => accessChanged(instance.context, null, "team.delete", { team: "tm_backstop01" })))
  expect(await f.sql(f.work, "SELECT revoked_by FROM workloads WHERE id=?", task.view.workload)).toEqual([{ revoked_by: "owner_inactive" }])
  const response = await f.workloadCall(f.as(task), "/v1/me")
  expect(response.status).toBe(403)
  expect(await response.json()).toEqual(ended)
})
