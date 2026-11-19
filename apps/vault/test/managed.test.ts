// Managed workspaces (areas/managed.ts, managed-platform.ts): a platform's
// subject end to end in workerd, with the platform directory stubbed.
import { afterEach, expect, it, vi } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { base64UrlEncode, importSealPublicKey, seal, type PlatformApprovalView, type PlatformDeviceView, type PlatformProjectView, type SubjectView } from "@mehen/protocol"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { freshTenant, ORIGIN } from "./helpers.ts"
import { registerManagedDirectory, managedDirectory } from "../src/vault/managed-platform.ts"
import { accessSnapshot } from "./access-test-support.ts"
import { KEY, PLATFORM, SUBJECT, afterDeletionBegan, invokeAs, json, managedSubject, platform, platformAuth, refused, signed, sql, stubDirectory } from "./managed-support.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { AREAS } from "../src/vault/registry.ts"
import type { TenantVault } from "../src/vault/tenant-vault.ts"

const cleanups: (() => void)[] = []
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup()
  setUpstreamFetch(null)
  vi.useRealTimers()
})
async function subject(limits: Parameters<typeof managedSubject>[0] = {}) {
  const f = await managedSubject(limits)
  cleanups.push(f.restore)
  return f
}
// Moves the vault's clock past the platform row's 30-second refresh.
function afterRefresh(seconds = 31): void {
  vi.useFakeTimers({ toFake: ["Date"] })
  vi.setSystemTime(Date.now() + seconds * 1000)
}
// A provider that records each request, its body read where it arrived.
const upstream: { requests: Request[]; bodies: string[] } = { requests: [], bodies: [] }
function fakeProvider(): void {
  upstream.requests = []
  upstream.bodies = []
  setUpstreamFetch(async (request) => {
    upstream.requests.push(request)
    upstream.bodies.push(new TextDecoder().decode(await request.arrayBuffer()))
    return new Response("{}", { headers: { "content-type": "application/json" } })
  })
}
function relay(item: string, method: string, url: string, approval?: string) {
  return { item, method, url, headers: [], ...(approval ? { approval } : {}) }
}

it("provisions a subject once, with no enrolment, and its devices idempotently by key within the mode ceiling", async () => {
  const f = await subject({ devicesPerSubject: 2 })
  expect(await platform<SubjectView>(f.tenant, "platform.subjects.ensure", { body: {} })).toEqual({ subject: SUBJECT, status: "active", createdAt: expect.any(String), counts: { devices: 0, items: 0, projects: 0 } })
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const created = await platform<PlatformDeviceView>(f.tenant, "platform.devices.create", { body: { name: "agent-1", jwk, modes: ["relay"], label: "globex:agent-1" } })
  expect(created).toEqual({ device: expect.stringMatching(/^dev_/), tenant: f.tenant, name: "agent-1", label: "globex:agent-1", scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false, workloads: "required" }, createdAt: expect.any(String), revoked: false, created: true })
  expect(await platform(f.tenant, "platform.devices.create", { body: { name: "again", jwk, modes: ["relay", "placeholder"] } })).toEqual({ ...created, created: false })
  for (const modes of [["lease"], ["relay", "sign"], ["reveal"], ["mint"]]) {
    expect(await refused(invokeAs(f.tenant, "platform.devices.create", { body: { name: "wide", jwk: await publicJwk(await newDeviceKey()), modes } }, platformAuth()))).toMatchObject({ error: "bad_request" })
  }
  const machine = { device: created.device, keys }
  const me = await json<{ tenant: string; scope: { workloads: string }; workspace: { slug: string; name: string } }>(await signed(f.tenant, machine, "/v1/me"))
  expect(me).toMatchObject({ tenant: f.tenant, device: created.device, workspace: { id: f.tenant, slug: "managed", name: "Globex" }, scope: { workloads: "required" } })
  await f.device()
  expect(await refused(invokeAs(f.tenant, "platform.devices.create", { body: { name: "third", jwk: await publicJwk(await newDeviceKey()), modes: ["relay"] } }, platformAuth()))).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  const task = await f.workload(machine)
  expect(await refused(invokeAs(f.tenant, "platform.devices.create", { body: { name: "reused", jwk: await publicJwk(task.keys), modes: ["relay"] } }, platformAuth()))).toMatchObject({ error: "conflict" })
  const revoked = await platform<PlatformDeviceView>(f.tenant, "platform.devices.revoke", { params: { device: created.device } })
  expect(revoked).toMatchObject({ device: created.device, revoked: true })
  expect(revoked).not.toHaveProperty("created")
  expect(await platform(f.tenant, "platform.devices.revoke", { params: { device: created.device } })).toEqual(revoked)
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/me"), 403)).error).toBe("workload_ended")
  expect(await refused(invokeAs(f.tenant, "platform.devices.create", { body: { name: "back", jwk, modes: ["relay"] } }, platformAuth()))).toMatchObject({ error: "conflict" })
  const listed = await platform<{ devices: { device: string; revoked: boolean; liveWorkloads: number }[] }>(f.tenant, "platform.devices.list", {})
  expect(listed.devices.map((d) => [d.device === created.device, d.revoked, d.liveWorkloads])).toEqual([[true, true, 0], [false, false, 0]])
})

it("seals a key in an intake, refuses a box for another intake or field and a second submit, then relays it through a workload unchanged", async () => {
  const f = await subject()
  fakeProvider()
  const opened = await platform<{ intake: string; sealKey: { jwk: JsonWebKey }; fields: unknown[]; binding: unknown; rotates: boolean; setup: unknown }>(f.tenant, "platform.intakes.create", { body: { slug: "openai-main", service: { template: "openai" } } })
  expect(opened).toEqual({ intake: expect.stringMatching(/^int_/), sealKey: { jwk: expect.objectContaining({ kty: "EC" }), kid: expect.any(String) }, fields: [{ name: "key", label: expect.any(String), secret: true, required: true, multiline: false, hint: expect.toSatisfy((v) => v === null || typeof v === "string") }], binding: { hosts: ["api.openai.com"], known: true }, rotates: false, setup: null, expiresAt: expect.any(String) })
  const other = await platform<{ intake: string }>(f.tenant, "platform.intakes.create", { body: { slug: "openai-other", service: { template: "openai" } } })
  const key = await importSealPublicKey(opened.sealKey.jwk)
  const submit = (sealed: unknown) => invokeAs(f.tenant, "platform.intakes.submit", { params: { intake: opened.intake }, body: { sealed } }, platformAuth())
  expect(await refused(submit({ key: await seal(key, "sk-test-not-real-0001", `intake/${other.intake}/key`) }))).toMatchObject({ error: "bad_request" })
  expect(await refused(submit({ key: await seal(key, "sk-test-not-real-0001", `intake/${opened.intake}/other`) }))).toMatchObject({ error: "bad_request" })
  const item = await platform<{ item: Record<string, unknown> }>(f.tenant, "platform.intakes.submit", { params: { intake: opened.intake }, body: { sealed: { key: await seal(key, "sk-test-not-real-0001", `intake/${opened.intake}/key`) } } })
  expect(item.item).toMatchObject({ slug: "openai-main", kind: "api-key", provider: "openai", hosts: ["api.openai.com"] })
  expect(JSON.stringify(item)).not.toContain("sk-test-not-real")
  expect(await refused(submit({ key: await seal(key, "sk-test-not-real-0002", `intake/${opened.intake}/key`) }))).toMatchObject({ error: "conflict" })
  const machine = await f.device()
  const task = await f.workload(machine)
  expect(await json(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/models")))).toBeDefined()
  expect(upstream.requests.map((r) => [r.url, r.headers.get("authorization")])).toEqual([["https://api.openai.com/v1/models", "Bearer sk-test-not-real-0001"]])
  expect((await json<{ error: string }>(await signed(f.tenant, machine, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/models")), 403)).error).toBe("workload_required")
})

it("keeps the platform intake's audit row as it was, naming no ceiling", async () => {
  const f = await subject()
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const audit = await platform<{ events: { action: string; target: string; detail: string }[] }>(f.tenant, "platform.audit.read", {})
  const row = audit.events.find((e) => e.action === "intake.complete")!
  expect(row.target).toBe("openai-main")
  expect(JSON.parse(row.detail)).toEqual({ item: expect.stringMatching(/^itm_/), outcome: "allowed", run: null, platform: PLATFORM, by: { platform: PLATFORM, key: KEY } })
})

// A held request through the relay: a key for one host holds everything
// unless the platform lets reads through.
async function heldRequest(f: Awaited<ReturnType<typeof subject>>, method = "POST") {
  await f.intake("example-key", { host: "api.example.com" }, { key: "ex-test-not-real-0001" })
  const machine = await f.device()
  const task = await f.workload(machine)
  const held = await json<{ error: string; approval: string; next: Record<string, unknown>; deciders: string[] }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", method, "https://api.example.com/v1/things")), 409)
  return { machine, task, held }
}

// APPROVAL_BATCHES is on in the test env; a managed workspace still gets
// no batch approvals: no group, shape or floor, and no replacing an ask.
it("never batches a managed workspace's asks, with APPROVAL_BATCHES on", async () => {
  const f = await subject()
  const { task, held } = await heldRequest(f)
  expect(await sql(f.tenant, "SELECT review_group,shape,floor,bundle,superseded_by,policy_status FROM approvals WHERE id=?", held.approval)).toEqual([{ review_group: null, shape: null, floor: null, bundle: null, superseded_by: null, policy_status: null }])
  const replacing = await json<{ error: string; message: string }>(await signed(f.tenant, task, "/v1/relay", { ...relay("example-key", "POST", "https://api.example.com/v1/things?again=1"), replaces: held.approval }), 403)
  expect(replacing).toEqual({ error: "forbidden", message: "Replacing an ask is not available yet." })
  expect(await sql(f.tenant, "SELECT id,policy_status FROM approvals")).toEqual([{ id: held.approval, policy_status: null }])
})

// POLICY_POSTURES is on in the test env; a managed workspace has no
// postures, so its held requests are never counted toward a nudge.
it("never counts a managed workspace's asks toward a posture nudge, with POLICY_POSTURES on", async () => {
  const f = await subject()
  await heldRequest(f)
  expect(await sql(f.tenant, "SELECT * FROM posture_ask_counts")).toEqual([])
  expect(await sql(f.tenant, "SELECT * FROM item_postures")).toEqual([])
})

it("decides a held request once, bound to its digest, within the platform's limit, with consent on a platform basis", async () => {
  const f = await subject({ decisionTtlSeconds: 300 })
  fakeProvider()
  const { task, held } = await heldRequest(f)
  expect(held).toEqual({ error: "approval_required", message: "This request needs approval.", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String), expiresAt: expect.any(String), deciders: [], next: { say: "The platform decides this request." } })
  const view = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })
  expect(view).toMatchObject({ approval: held.approval, status: "pending", device: task.device, workload: { id: task.workload, label: "globex:grant-1" }, item: "example-key", request: { method: "POST", url: "https://api.example.com/v1/things" }, decidedBy: null })
  expect(await platform(f.tenant, "platform.approvals.list", { query: { status: "pending" } })).toEqual({ approvals: [view] })
  const decide = (body: Record<string, unknown>) => invokeAs(f.tenant, "platform.approvals.decide", { params: { approval: held.approval }, body }, platformAuth())
  expect(await refused(decide({ decision: "approve", digest: "A".repeat(43) }))).toEqual({ error: "conflict", message: "The request changed; ask again." })
  expect(await refused(decide({ decision: "approve", digest: view.digest, ttlSeconds: 901 }))).toMatchObject({ error: "bad_request" })
  expect(await refused(decide({ decision: "approve", digest: view.digest, ttlSeconds: 600 }))).toEqual({ error: "bad_request", message: "A decision lasts at most 300 seconds on this platform." })
  const auth = platformAuth()
  const decided = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.decide", { params: { approval: held.approval }, body: { decision: "approve", digest: view.digest, ref: "globex:card-1" } }, auth)
  expect(decided).toMatchObject({ status: "approved", decidedBy: { platform: PLATFORM, key: KEY, ref: "globex:card-1" } })
  expect(await refused(decide({ decision: "approve", digest: view.digest }))).toEqual({ error: "conflict", message: "The request changed; ask again." })
  const [grant] = await sql<{ uses_left: number; expires_at: number; basis: string }>(f.tenant, "SELECT g.uses_left,g.expires_at,c.basis FROM protected_use_grants g JOIN consent_lineage c ON c.id=g.lineage WHERE g.approval=?", held.approval)
  expect(grant!.uses_left).toBe(1)
  expect(grant!.expires_at - Date.now()).toBeLessThanOrEqual(300_000)
  const [managedRow] = await sql<{ value: string }>(f.tenant, "SELECT value FROM tenant_state WHERE key='managed'")
  expect(JSON.parse(grant!.basis).platform).toEqual({ kind: "platform", platform: PLATFORM, key: KEY, subject: SUBJECT, member: JSON.parse(managedRow!.value).member })
  await json(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things", held.approval)))
  expect(upstream.requests).toHaveLength(1)
  expect(await platform(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })).toMatchObject({ status: "used" })
  const again = await json<{ error: string; approval: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things", held.approval)), 409)
  expect(again.error).toBe("approval_required")
  expect(again.approval).not.toBe(held.approval)
  const denied = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.decide", { params: { approval: again.approval }, body: { decision: "deny", digest: (await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: again.approval } })).digest } })
  expect(denied.status).toBe("denied")
  const [row] = await sql<{ actor: string; detail: string }>(f.tenant, "SELECT actor,detail FROM audit WHERE action='approval.approve'")
  expect(row!.actor).toBe(`platform:${PLATFORM}`)
  expect(JSON.parse(row!.detail)).toMatchObject({ platform: PLATFORM, by: { platform: PLATFORM, key: KEY }, attestation: { digest: view.digest, jti: auth.jti, ref: "globex:card-1" } })
})

it("inherits the platform's defaults live, within 30 seconds, narrowing only, and stores none of them", async () => {
  const f = await subject()
  fakeProvider()
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const { task, held } = await heldRequest(f)
  const pending = held.approval
  const getRead = () => signed(f.tenant, task, "/v1/relay", relay("example-key", "GET", "https://api.example.com/v1/things"))
  expect((await json<{ error: string }>(await getRead(), 409)).error).toBe("approval_required")
  f.directory.defaults = { ...f.directory.defaults, customReads: "allow", rules: { openai: [{ action: "deny", methods: ["GET"], paths: ["/v1/models"], note: "globex keeps models private" }] } }
  f.directory.defaultsRevision = 2
  const reads = f.directory.reads
  expect((await json<{ error: string }>(await getRead(), 409)).error).toBe("approval_required")
  expect(f.directory.reads).toBe(reads)
  afterRefresh()
  await json(await getRead())
  expect(f.directory.reads).toBe(reads + 1)
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things")), 409)).error).toBe("approval_required")
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/models")), 403)).error).toBe("policy_denied")
  // The catalogue's own holds and refusals stand whatever the defaults say.
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/organization/users")), 403)).error).toBe("policy_denied")
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "DELETE", "https://api.openai.com/v1/files/file-1")), 409)).error).toBe("approval_required")
  await json(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/files")))
  const described = await platform<{ items: { slug: string; policy: { rules: unknown[] } }[] }>(f.tenant, "platform.items.list", {})
  expect(described.items.find((i) => i.slug === "openai-main")?.policy.rules).toContainEqual({ action: "deny", methods: ["GET"], paths: ["/v1/models"], note: "globex keeps models private" })
  // An approval asked under the old defaults is stale, pending or granted.
  const stale = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: pending } })
  expect(stale.status).toBe("stale")
  expect(await refused(invokeAs(f.tenant, "platform.approvals.decide", { params: { approval: pending }, body: { decision: "approve", digest: stale.digest } }, platformAuth()))).toMatchObject({ error: "conflict" })
  const fresh = await json<{ approval: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things")), 409)
  const freshView = await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: fresh.approval } })
  await platform(f.tenant, "platform.approvals.decide", { params: { approval: fresh.approval }, body: { decision: "approve", digest: freshView.digest } })
  f.directory.defaultsRevision = 3
  afterRefresh(62)
  expect((await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: fresh.approval } })).status).toBe("stale")
  const spent = await json<{ error: string; approval: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things", fresh.approval)), 409)
  expect(spent.approval).not.toBe(fresh.approval)
  expect(upstream.requests.map((r) => r.method)).toEqual(["GET", "GET"])
  const stored = await sql<{ key: string; value: string }>(f.tenant, "SELECT key,value FROM tenant_state")
  expect(stored.map((r) => r.key).sort()).toEqual(expect.not.arrayContaining(["defaults", "limits", "platform"]))
  expect(JSON.stringify(stored)).not.toContain("globex keeps models private")
  expect(JSON.stringify(await sql(f.tenant, "SELECT policy FROM items"))).not.toContain("globex keeps models private")
})

it("refuses device calls within 30 seconds of a suspension or of the subject being deleted", async () => {
  const f = await subject()
  fakeProvider()
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const machine = await f.device()
  const task = await f.workload(machine)
  const use = () => signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/files"))
  await json(await use())
  f.directory.platform.status = "suspended"
  await json(await use())
  afterRefresh()
  expect(await json(await use(), 403)).toEqual({ error: "platform_suspended", message: "This platform is suspended." })
  expect(await refused(invokeAs(f.tenant, "platform.items.list", {}, platformAuth()))).toEqual({ error: "platform_suspended", message: "This platform is suspended." })
  f.directory.platform.status = "retiring"
  afterRefresh(62)
  await json(await use())
  f.directory.workspaces.set(f.tenant, { subject: SUBJECT, status: "deleting" })
  afterRefresh(93)
  expect(await json(await use(), 403)).toEqual({ error: "device_revoked", message: "This device has been revoked." })
  f.directory.platform.status = "suspended"
  f.directory.workspaces.set(f.tenant, { subject: SUBJECT, status: "active" })
  afterRefresh(124)
  expect(await json(await signed(f.tenant, machine, "/v1/devices/self/revoke", {}))).toEqual({})
})

it("names the platform on every audit row, from a call, a device, an alarm or a sweep, in a chain from the platform's own first link", async () => {
  const f = await subject()
  const { task } = await heldRequest(f)
  await platform(f.tenant, "platform.workspace.freeze", { body: {} })
  await platform(f.tenant, "platform.workspace.unfreeze", { body: {} })
  // A sweep, as an alarm runs it: the workload expires and the sweep ends it.
  afterRefresh(3700)
  await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), async (instance: TenantVault) => { await instance.alarm() })
  await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), (instance: TenantVault) => { instance.context.audit({ actor: "system", action: "test.sweep" }) })
  const page = await platform<{ events: { seq: number; actor: string; action: string; detail: string; prev: string }[]; head: { seq: number }; verified: boolean; filtered: boolean }>(f.tenant, "platform.audit.read", { query: { limit: "200" } })
  expect(page.verified).toBe(true)
  expect(page.filtered).toBe(false)
  const events = [...page.events].reverse()
  expect(events[0]).toMatchObject({ seq: 1, action: "workspace.create", actor: `platform:${PLATFORM}`, prev: `mehen/audit/v1/platform/${PLATFORM}/${f.tenant}` })
  expect(JSON.parse(events[0]!.detail)).toEqual({ subject: SUBJECT, platform: PLATFORM, by: { platform: PLATFORM, key: KEY } })
  for (const event of events) expect(JSON.parse(event.detail), event.action).toMatchObject({ platform: PLATFORM })
  const actors = new Set(events.map((e) => e.actor.split(":")[0]))
  expect(actors).toEqual(new Set(["platform", "device", "system"]))
  expect(events.filter((e) => e.actor.startsWith("platform:")).every((e) => JSON.parse(e.detail).by?.key === KEY)).toBe(true)
  expect(events.map((e) => e.action)).toEqual(expect.arrayContaining(["workload.created", "approval.request", "workspace.freeze", "workspace.unfreeze", "test.sweep"]))
  expect(events.some((e) => e.actor === "system" && e.action.startsWith("workload."))).toBe(true)
  expect(events.find((e) => e.action === "workload.created")?.actor).toBe(`device:${task.device}`)
  const second = await platform<{ events: { seq: number }[]; next: string | null }>(f.tenant, "platform.audit.read", { query: { limit: "2" } })
  expect(second.events).toHaveLength(2)
  expect((await platform<{ events: { seq: number }[] }>(f.tenant, "platform.audit.read", { query: { cursor: second.next } })).events[0]!.seq).toBe(second.events[1]!.seq - 1)
})

it("lets no platform operation reach anything but its own platform.* list, and never another platform's or subject's workspace", async () => {
  const f = await subject()
  const platformOps = AREAS.flatMap((area) => Object.entries(area.workspaceOps ?? {})).filter(([, spec]) => spec.auth.includes("platform")).map(([name]) => name)
  expect(platformOps.every((name) => name.startsWith("platform."))).toBe(true)
  const others = AREAS.flatMap((area) => Object.keys(area.workspaceOps ?? {})).filter((name) => !name.startsWith("platform."))
  expect(others).toEqual(expect.arrayContaining(["items.update", "items.rehome", "items.action", "projects.share", "devices.rescope", "devices.rescope_accept", "access.enrol.accept", "access.unfreeze", "approvals.decide", "intake.submit"]))
  expect(await refused(invokeAs(f.tenant, "platform.subjects.purge", {}, platformAuth()))).toEqual({ error: "forbidden", message: "You are not allowed to do that." })
  for (const op of others) expect(await refused(invokeAs(f.tenant, op, {}, platformAuth())), op).toEqual({ error: "forbidden", message: "You are not allowed to do that." })
  for (const auth of [platformAuth("globex_subject_0002"), platformAuth(SUBJECT, "plt_otherPlatform"), platformAuth("globex_subject_0002", "plt_otherPlatform")]) {
    expect(await refused(invokeAs(f.tenant, "platform.subjects.get", {}, auth))).toEqual({ error: "not_found", message: "No such subject." })
    expect(await refused(invokeAs(f.tenant, "platform.subjects.ensure", { body: {} }, auth))).toEqual({ error: "not_found", message: "No such subject." })
  }
  const empty = freshTenant()
  expect(await refused(invokeAs(empty, "platform.items.list", {}, platformAuth()))).toEqual({ error: "not_found", message: "No such subject." })
  expect(await refused(invokeAs(empty, "platform.subjects.ensure", { body: {} }, platformAuth()))).toEqual({ error: "not_found", message: "No such subject." })
  // The PlatformVault spends the proof's nonce; the workspace spends nothing.
  const proof = platformAuth()
  await platform(f.tenant, "platform.subjects.get", {}, proof)
  expect(await sql(f.tenant, "SELECT 1 FROM device_nonces WHERE device=?", KEY)).toEqual([])
})

it("removes a subject whose workspace was never set up, finding nothing to delete, and does so again on a retry", async () => {
  const empty = freshTenant()
  for (let i = 0; i < 2; i++) {
    const removed = await platform<{ purgeAfter: number }>(empty, "platform.subjects.remove", { body: {} })
    expect(removed.purgeAfter).toBeLessThanOrEqual(Date.now())
  }
  expect(await sql(empty, "SELECT key FROM tenant_state WHERE key LIKE 'managed%'")).toEqual([])
  expect(await refused(invokeAs(empty, "platform.subjects.get", {}, platformAuth()))).toEqual({ error: "not_found", message: "No such subject." })
})

it("never sets up a subject removed while its creation awaited the directory, so the purge still erases it", async () => {
  const { directory, restore } = stubDirectory()
  cleanups.push(restore)
  const tenant = freshTenant()
  directory.workspaces.set(tenant, { subject: SUBJECT, status: "creating" })
  const stub = managedDirectory()
  let release = () => {}
  const held = new Promise<void>((resolve) => { release = resolve })
  cleanups.push(registerManagedDirectory({ async read(db, t) { const row = await stub.read(db, t); await held; return row }, purged: stub.purged }))
  const ensuring = invokeAs(tenant, "platform.subjects.ensure", { params: {}, query: null, body: {} }, platformAuth())
  await vi.waitFor(() => expect(directory.reads).toBe(1))
  await platform(tenant, "platform.subjects.remove", { body: {} })
  directory.workspaces.set(tenant, { subject: SUBJECT, status: "deleted" })
  release()
  expect(await refused(ensuring)).toEqual({ error: "not_found", message: "No such subject." })
  expect(await sql(tenant, "SELECT key FROM tenant_state WHERE key IN ('managed','managed_status','workspace')")).toEqual([])
  expect(await sql(tenant, "SELECT count(*) AS n FROM members")).toEqual([{ n: 0 }])
  expect((await platform<{ purgeAfter: number }>(tenant, "platform.subjects.remove", { body: {} })).purgeAfter).toBeLessThanOrEqual(Date.now())
  expect(await invokeAs(tenant, "platform.subjects.purge", {}, { kind: "system", reason: "platform directory" })).toEqual({ ok: true, value: { auditHead: null } })
})

it("answers with no link, page or command, to the platform and to its devices", async () => {
  const f = await subject()
  const answers: unknown[] = []
  const keep = async <T>(value: Promise<T>): Promise<T> => { const settled = await value; answers.push(settled); return settled }
  await keep(platform(f.tenant, "platform.subjects.get"))
  const machine = await f.device()
  const task = await f.workload(machine)
  await keep(platform(f.tenant, "platform.devices.list"))
  const asked = await keep(json<{ intake: string }>(await signed(f.tenant, task, "/v1/intakes", { kind: "api-key", slug: "asked-key", provider: "openai", reason: "The agent needs OpenAI.", home: "workspace" }), 201))
  expect(asked).toEqual({ intake: expect.stringMatching(/^int_/), expiresAt: expect.any(String) })
  const sealKey = await json<{ jwk: JsonWebKey }>(await (await import("./helpers.ts")).fetchWorker("/v1/seal-key"))
  await keep(platform(f.tenant, "platform.intakes.submit", { params: { intake: asked.intake }, body: { sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), "sk-test-not-real-0003", `intake/${asked.intake}/key`) } } }))
  expect((await json<{ status: string }>(await signed(f.tenant, task, `/v1/intakes/${asked.intake}`))).status).toBe("completed")
  const { held } = await heldRequest(f)
  answers.push(held)
  await keep(platform(f.tenant, "platform.approvals.list"))
  await keep(platform(f.tenant, "platform.items.list"))
  // Four tasks with five open intakes each fill the machine's 20: a fifth
  // task's intake is refused at the cap, and the platform decides, so it
  // carries no link either.
  for (let t = 0; t < 4; t++) {
    const busy = await f.workload(machine)
    for (let n = 0; n < 5; n++) await json(await signed(f.tenant, busy, "/v1/intakes", { kind: "api-key", slug: `cap-${t}-${n}`, provider: "openai", reason: "The agent needs OpenAI.", home: "workspace" }), 201)
  }
  const full = await keep(json<{ error: string; message: string; next?: { say: string } }>(await signed(f.tenant, await f.workload(machine), "/v1/intakes", { kind: "api-key", slug: "cap-over", provider: "openai", reason: "The agent needs OpenAI.", home: "workspace" }), 429))
  expect(full).toEqual({ error: "rate_limited", message: "This machine already has 20 open asks.", next: { say: "The platform decides this machine's open asks; ask for the rest once some are settled." } })
  const text = JSON.stringify(answers)
  expect(text).not.toContain(ORIGIN)
  expect(text).not.toContain("mehen ")
  expect(text).not.toMatch(/"command":/)
  expect(text).not.toMatch(/"next":\{[^}]*"url"/)
})

it("names who a system call deletes a subject for in its audit: the platform admin, from the console", async () => {
  const f = await subject()
  expect(await invokeAs(f.tenant, "platform.subjects.remove", { params: {}, query: null, body: {} }, { kind: "system", reason: "platform admin console", actor: "admin:acc_admin" })).toMatchObject({ ok: true })
  expect(await sql(f.tenant, "SELECT actor FROM audit WHERE action='workspace.delete'")).toEqual([{ actor: "admin:acc_admin" }])
  const swept = await subject()
  await invokeAs(swept.tenant, "platform.subjects.remove", { params: {}, query: null, body: {} }, { kind: "system", reason: "platform directory" })
  expect(await sql(swept.tenant, "SELECT actor FROM audit WHERE action='workspace.delete'")).toEqual([{ actor: "system" }])
})

it("deletes a subject: devices revoked, every secret and item gone, the audit kept until the purge erases everything", async () => {
  const f = await subject({ auditRetentionDays: 0 })
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  await platform(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" } })
  const machine = await f.device()
  const task = await f.workload(machine)
  // A provider's rejection of an OAuth client, kept on the client.
  await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), (_instance: TenantVault, state) => { state.storage.sql.exec("INSERT INTO workspace_oauth_client_rejections(client,client_version,at) VALUES ('itm_client',1,0)") })
  const removed = await platform<{ purgeAfter: number }>(f.tenant, "platform.subjects.remove", { body: {} })
  expect(await sql(f.tenant, "SELECT * FROM workspace_oauth_client_rejections")).toEqual([])
  expect(removed).toEqual({ purgeAfter: expect.any(Number) })
  expect(removed.purgeAfter).toBeLessThanOrEqual(Date.now())
  expect(await platform(f.tenant, "platform.subjects.remove", { body: {} })).toEqual(removed)
  expect(await platform<SubjectView>(f.tenant, "platform.subjects.get")).toMatchObject({ status: "deleted", counts: { devices: 0, items: 0, projects: 0 } })
  expect(await sql(f.tenant, "SELECT (SELECT count(*) FROM items) AS items,(SELECT count(*) FROM item_secrets) AS secrets,(SELECT count(*) FROM projects) AS projects,(SELECT count(*) FROM devices WHERE revoked_at IS NULL) AS devices,(SELECT count(*) FROM workloads WHERE revoked_at IS NULL) AS workloads")).toEqual([{ items: 0, secrets: 0, projects: 0, devices: 0, workloads: 0 }])
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/me"), 403)).error).toBe("workload_ended")
  expect((await json<{ error: string }>(await signed(f.tenant, machine, "/v1/me"), 403)).error).toBe("device_revoked")
  expect(await refused(invokeAs(f.tenant, "platform.items.list", {}, platformAuth()))).toEqual({ error: "not_found", message: "No such subject." })
  const audit = await platform<{ events: { action: string; detail: string; hash: string }[]; verified: boolean }>(f.tenant, "platform.audit.read", {})
  expect(audit.verified).toBe(true)
  expect(JSON.parse(audit.events.find((e) => e.action === "workspace.delete")!.detail)).toMatchObject({ platform: PLATFORM, items: 1, projects: 1, devices: 1 })
  expect(JSON.stringify(audit)).not.toContain("sk-test-not-real")
  const head = audit.events[0]!.hash
  const purged = await invokeAs(f.tenant, "platform.subjects.purge", { params: {}, query: null, body: null }, { kind: "system", reason: "test" })
  expect(purged).toEqual({ ok: true, value: { auditHead: head } })
  expect(f.directory.purged).toEqual([{ tenant: f.tenant, head }])
  expect(await invokeAs(f.tenant, "platform.subjects.purge", { params: {}, query: null, body: null }, { kind: "system", reason: "test" })).toEqual({ ok: true, value: { auditHead: null } })
  expect(await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), (_instance: TenantVault, state) => state.storage.sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\'").toArray())).toEqual([])
  expect(await json(await signed(f.tenant, machine, "/v1/me"), 401)).toMatchObject({ error: "unauthenticated" })
  expect(await refused(invokeAs(f.tenant, "platform.audit.read", {}, platformAuth()))).toEqual({ error: "not_found", message: "No such workspace." })
})

it("records the final audit head in the directory before the sweep's purge erases anything, and erases nothing when that fails", async () => {
  const f = await subject({ auditRetentionDays: 0 })
  await platform(f.tenant, "platform.subjects.remove", { body: {} })
  const head = (await platform<{ events: { hash: string }[] }>(f.tenant, "platform.audit.read", {})).events[0]!.hash
  const working = managedDirectory()
  const putBack = registerManagedDirectory({ read: working.read, async purged() { throw new Error("the directory is unavailable") } })
  const purge = () => invokeAs(f.tenant, "platform.subjects.purge", { params: {}, query: null, body: null }, { kind: "system", reason: "test" })
  try {
    expect(await refused(purge())).toMatchObject({ error: "internal" })
  } finally {
    putBack()
  }
  expect((await platform<{ events: { hash: string }[] }>(f.tenant, "platform.audit.read", {})).events[0]!.hash).toBe(head)
  expect(await purge()).toEqual({ ok: true, value: { auditHead: head } })
  expect(f.directory.purged).toEqual([{ tenant: f.tenant, head }])
})

it("keeps a deleted subject's audit until its purge date, and purges by its own alarm", async () => {
  const f = await subject({ auditRetentionDays: 30 })
  await platform(f.tenant, "platform.subjects.remove", { body: {} })
  expect(await refused(invokeAs(f.tenant, "platform.subjects.purge", {}, { kind: "system", reason: "test" }))).toEqual({ error: "conflict", message: "This subject's audit is kept until its purge date." })
  const [due] = await sql<{ area: string; key: string; due_at: number }>(f.tenant, "SELECT area,key,due_at FROM schedule WHERE area='managed'")
  expect(due).toMatchObject({ area: "managed", key: "purge" })
  expect(due!.due_at - Date.now()).toBeGreaterThan(29 * 86_400_000)
  afterRefresh(31 * 86_400)
  await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), async (instance: TenantVault) => { await instance.alarm() })
  expect(f.directory.purged.map((p) => p.tenant)).toEqual([f.tenant])
  expect(await refused(invokeAs(f.tenant, "platform.subjects.get", {}, platformAuth()))).toEqual({ error: "not_found", message: "No such workspace." })
})

it("keeps projects for computers: unprotected, variables set against what was last read, and no lease for any run", async () => {
  const f = await subject({ projectsPerSubject: 1 })
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const project = await platform<PlatformProjectView>(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }, { name: "prod" }], defaultEnv: "computers" } })
  expect(project).toEqual({ id: expect.stringMatching(/^prj_/), slug: "computers", defaultEnv: "computers", environments: [{ name: "computers" }, { name: "prod" }], vars: [], created: true })
  expect(await sql(f.tenant, "SELECT name,protected,four_eyes FROM environments ORDER BY name")).toEqual([{ name: "computers", protected: 0, four_eyes: 0 }, { name: "prod", protected: 0, four_eyes: 0 }])
  expect(await refused(invokeAs(f.tenant, "platform.projects.create", { body: { slug: "more", environments: [{ name: "dev" }], defaultEnv: "dev" } }, platformAuth()))).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  const setVar = (name: string, body: Record<string, unknown>) => invokeAs(f.tenant, "platform.projects.setVar", { params: { project: project.id, name }, body }, platformAuth())
  await platform(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "REGION" }, body: { env: "computers", before: null, plain: "eu-west-1" } })
  expect(await refused(setVar("REGION", { env: "computers", before: null, plain: "eu-west-2" }))).toMatchObject({ error: "conflict" })
  expect(await refused(setVar("TOKEN", { env: "computers", before: null, plain: "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD" }))).toMatchObject({ error: "bad_request" })
  await platform(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "REGION" }, body: { env: "computers", before: { plain: "eu-west-1" }, plain: "eu-west-2" } })
  const withKey = await platform<PlatformProjectView>(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "OPENAI_KEY" }, body: { env: "computers", before: null, item: "openai-main" } })
  expect(withKey.vars).toEqual([{ name: "OPENAI_KEY", env: "computers", source: "item", item: "openai-main", field: "key" }, { name: "REGION", env: "computers", source: "plain", value: "eu-west-2" }])
  await platform(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "OPENAI_KEY" }, body: { env: "computers", before: { item: "openai-main", field: null }, item: "openai-main", field: "key" } })
  expect(await platform(f.tenant, "platform.projects.get", { params: { project: project.id } })).toEqual(withKey)
  const machine = await f.device()
  const task = await f.workload(machine, { projects: [project.id], modes: ["placeholder"] })
  const run = await json<{ run: string; vars: { name: string; delivery: string }[] }>(await signed(f.tenant, task, "/v1/runs", { project: project.id, env: "computers", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["OPENAI_KEY", "REGION"], command: "globex computer" }), 201)
  expect(run.vars.find((v) => v.name === "OPENAI_KEY")?.delivery).toBe("placeholder")
  const lease = await signed(f.tenant, task, "/v1/lease", { run: run.run, item: "openai-main" })
  expect(lease.status).toBeGreaterThanOrEqual(400)
  expect(await lease.text()).not.toContain("sk-test-not-real")
  expect(await platform(f.tenant, "platform.projects.remove", { params: { project: project.id }, body: {} })).toEqual({ deleted: true })
  expect(await refused(invokeAs(f.tenant, "platform.projects.get", { params: { project: project.id } }, platformAuth()))).toMatchObject({ error: "not_found" })
  expect(await sql(f.tenant, "SELECT ended_at IS NOT NULL AS ended FROM runs")).toEqual([{ ended: 1 }])
})

it("answers a repeated project create with the same project, refuses the slug in another shape, and leaves another subject's project alone", async () => {
  const f = await subject({ projectsPerSubject: 1 })
  const create = (slug: string, environments: string[], defaultEnv: string, tenant = f.tenant, auth = platformAuth()) => invokeAs(tenant, "platform.projects.create", { params: {}, query: null, body: { slug, environments: environments.map((name) => ({ name })), defaultEnv } }, auth)
  const made = await platform<PlatformProjectView & { created: boolean }>(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }, { name: "prod" }], defaultEnv: "computers" } })
  expect(made.created).toBe(true)
  await platform(f.tenant, "platform.projects.setVar", { params: { project: made.id, name: "REGION" }, body: { env: "computers", before: null, plain: "eu-west-1" } })
  // A repeat, environments in another order and the platform at its limit, answers the project as it is now.
  const again = await create("computers", ["prod", "computers"], "computers")
  expect(again.ok ? again.value : again.error.vaultError).toEqual({ id: made.id, slug: "computers", defaultEnv: "computers", environments: [{ name: "computers" }, { name: "prod" }], vars: [{ name: "REGION", env: "computers", source: "plain", value: "eu-west-1" }], created: false })
  for (const [environments, defaultEnv] of [[["computers", "prod"], "prod"], [["computers"], "computers"], [["computers", "prod", "dev"], "computers"]] as const) {
    expect(await refused(create("computers", [...environments], defaultEnv)), `${environments.join(",")} ${defaultEnv}`).toEqual({ error: "conflict", message: "That name is in use by another project." })
  }
  expect(await sql(f.tenant, "SELECT id FROM projects")).toEqual([{ id: made.id }])
  expect(await sql(f.tenant, "SELECT count(*) AS count FROM audit WHERE action='project.create'")).toEqual([{ count: 1 }])
  // Another subject of the platform makes its own project under the same slug.
  const other = "globex_subject_0002", tenant = freshTenant()
  f.directory.workspaces.set(tenant, { subject: other, status: "creating" })
  await platform(tenant, "platform.subjects.ensure", { body: {} }, platformAuth(other))
  f.directory.workspaces.set(tenant, { subject: other, status: "active" })
  const theirs = await create("computers", ["dev"], "dev", tenant, platformAuth(other))
  expect(theirs.ok ? theirs.value : theirs.error.vaultError).toEqual({ id: expect.stringMatching(/^prj_/), slug: "computers", defaultEnv: "dev", environments: [{ name: "dev" }], vars: [], created: true })
  expect(theirs.ok ? (theirs.value as PlatformProjectView).id : null).not.toBe(made.id)
  expect(await platform(f.tenant, "platform.projects.get", { params: { project: made.id } })).toEqual({ id: made.id, slug: "computers", defaultEnv: "computers", environments: [{ name: "computers" }, { name: "prod" }], vars: [{ name: "REGION", env: "computers", source: "plain", value: "eu-west-1" }] })
})

it("opens intakes only for what the platform offers, with its tags, set-up steps and limits, and keeps a custom provider's definition fixed", async () => {
  const f = await subject({ itemsPerSubject: 3, openRequestsPerSubject: 2 })
  f.directory.defaults = { ...f.directory.defaults, templates: ["openai", "google-oauth-client"], tags: ["globex"] }
  afterRefresh()
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "anthropic-main", service: { template: "anthropic" } } }, platformAuth()))).toEqual({ error: "bad_request", message: "This platform does not offer that service." })
  const google = await platform<{ intake: string; fields: { name: string; secret: boolean }[]; setup: { title: string; body: string }[] | null }>(f.tenant, "platform.intakes.create", { body: { slug: "google-oauth-client", service: { template: "google-oauth-client" } } })
  expect(google.fields.map((field) => [field.name, field.secret])).toEqual([["client_id", false], ["client_secret", true]])
  expect(google.setup?.map((step) => step.title)).toContain("Publish the app to production")
  expect(JSON.stringify(google.setup)).toContain("{callback}")
  await platform(f.tenant, "platform.intakes.cancel", { params: { intake: google.intake }, body: {} })
  const definition = { name: "Example", authorizeUrl: "https://auth.example.com/authorize", tokenUrl: "https://auth.example.com/oauth2/token", scopes: ["read"], pkce: "S256", clientAuth: "client_secret_basic", hosts: ["api.example.com"] }
  const requests = await sql(f.tenant, "SELECT id FROM workspace_credential_requests")
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "public-client", service: { customProvider: { ...definition, clientAuth: "none" } } } }, platformAuth()))).toEqual({ error: "bad_request", message: "A client without a secret is not supported yet." })
  expect(await sql(f.tenant, "SELECT id FROM workspace_credential_requests")).toEqual(requests)
  const custom = await f.intake("example-client", { customProvider: definition }, { client_secret: "cs-test-not-real-0001" }, { client_id: "example-client-id" })
  expect(custom.item).toMatchObject({ slug: "example-client", kind: "oauth-client", provider: null, hosts: ["auth.example.com"], tags: ["globex"], ceiling: "relay" })
  // The secret may only ever go to the exact token endpoint: its host and path, by POST.
  const pinned = { binding: JSON.stringify({ hosts: ["auth.example.com"], paths: ["/oauth2/token"], methods: ["POST"] }), injection: null, ceiling: "relay", provider: null, custom_provider: JSON.stringify(definition, Object.keys(definition).sort()) }
  expect(await sql(f.tenant, "SELECT binding,injection,ceiling,provider,custom_provider FROM items WHERE slug='example-client'")).toEqual([pinned])
  fakeProvider()
  const task = await f.workload(await f.device())
  for (const [method, url] of [["POST", "https://auth.example.com/oauth2/other"], ["GET", "https://auth.example.com/oauth2/token"], ["POST", "https://api.example.com/oauth2/token"]] as const) {
    const off = await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-client", method, url)), 403)
    expect(off.error, `${method} ${url}`).not.toBe("approval_required")
  }
  expect(upstream.requests).toEqual([])
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "example-client", service: { customProvider: { ...definition, tokenUrl: "https://evil.example.com/token" } } } }, platformAuth()))).toEqual({ error: "conflict", message: "A provider definition is fixed; add a new item for a new one." })
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "example-client", service: { template: "openai" } } }, platformAuth()))).toEqual({ error: "conflict", message: "That name belongs to another kind of credential." })
  // A rotation replaces the secret; the definition and binding stay as written.
  const rotation = await platform<{ intake: string; rotates: boolean; fields: { name: string }[]; binding: { hosts: string[] }; sealKey: { jwk: JsonWebKey } }>(f.tenant, "platform.intakes.create", { body: { slug: "example-client", service: { customProvider: definition } } })
  expect(rotation).toMatchObject({ rotates: true, fields: [{ name: "client_secret" }], binding: { hosts: ["auth.example.com"] } })
  const rotated = await seal(await importSealPublicKey(rotation.sealKey.jwk), "cs-test-not-real-0002", `intake/${rotation.intake}/client_secret`)
  await platform(f.tenant, "platform.intakes.submit", { params: { intake: rotation.intake }, body: { sealed: { client_secret: rotated } } })
  expect(await sql(f.tenant, "SELECT binding,injection,ceiling,provider,custom_provider FROM items WHERE slug='example-client'")).toEqual([pinned])
  // Three items at most, counting open intakes for new ones; two open requests at most.
  await f.intake("openai-a", { template: "openai" }, { key: "sk-test-not-real-0001" })
  await platform(f.tenant, "platform.intakes.create", { body: { slug: "openai-b", service: { template: "openai" } } })
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "openai-c", service: { template: "openai" } } }, platformAuth()))).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  const removed = await platform<{ slug: string; deleted: boolean; providerRevoked: boolean }>(f.tenant, "platform.items.remove", { params: { slug: "openai-a" } })
  expect(removed).toEqual({ slug: "openai-a", deleted: true, providerRevoked: false })
  expect(await refused(invokeAs(f.tenant, "platform.items.remove", { params: { slug: "openai-a" } }, platformAuth()))).toEqual({ error: "not_found", message: "No such item." })
  await platform(f.tenant, "platform.intakes.create", { body: { slug: "openai-c", service: { template: "openai" } } })
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "example-client", service: { customProvider: definition } } }, platformAuth()))).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  expect((await platform<{ items: { slug: string }[] }>(f.tenant, "platform.items.list", { query: { kind: "oauth-client" } })).items.map((i) => i.slug)).toEqual(["example-client"])
})

it("refuses writes in a frozen workspace and keeps reads working", async () => {
  const f = await subject()
  fakeProvider()
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const machine = await f.device()
  const task = await f.workload(machine)
  expect(await platform(f.tenant, "platform.workspace.freeze", { body: {} })).toEqual({ frozen: true })
  expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "openai-b", service: { template: "openai" } } }, platformAuth()))).toEqual({ error: "frozen", message: "This workspace is frozen." })
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/files")), 423)).error).toBe("frozen")
  await platform(f.tenant, "platform.items.list", {})
  expect(await platform(f.tenant, "platform.workspace.unfreeze", { body: {} })).toEqual({ frozen: false })
  await json(await signed(f.tenant, task, "/v1/relay", relay("openai-main", "GET", "https://api.openai.com/v1/files")))
})

// A connection as the platform's connect stores one (areas/oauth-workspace.ts),
// seeded straight into the workspace with its tokens sealed.
async function seedConnection(tenant: string, slug: string): Promise<void> {
  await runInDurableObject(env.TENANT_VAULT.getByName(tenant), async (instance: TenantVault, state) => {
    const ctx = instance.context
    const member = JSON.parse(state.storage.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key='managed'").one().value).member as string
    const { prepareCredential, storeCredential } = await import("../src/vault/areas/items-workspace.ts")
    const prepared = await prepareCredential(ctx, { slug, kind: "oauth-connection", provider: "google-gmail", account: "person@example.com", accountVerified: true, tags: [], home: { kind: "workspace" }, ceiling: "relay", binding: { hosts: ["gmail.googleapis.com"] }, policy: { default: "approve", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {access_token}" }, publicFields: {}, secretFields: { access_token: "ya29-test-not-real", refresh_token: "1//refresh-test-not-real" }, description: null }, null)
    ctx.storage.transactionSync(() => storeCredential(ctx, prepared, { kind: "member", memberId: member, account: "sbj_x", session: "seed", securityEpoch: 0, sessionCheck: null }, "item.create"))
  })
}

it("hands a connection's token back to its provider before deleting it, by item and with the subject", async () => {
  const f = await subject()
  fakeProvider()
  await seedConnection(f.tenant, "gmail")
  expect(await platform(f.tenant, "platform.items.remove", { params: { slug: "gmail" } })).toEqual({ slug: "gmail", deleted: true, providerRevoked: true })
  expect(upstream.requests.map((r) => r.url)).toEqual(["https://oauth2.googleapis.com/revoke"])
  expect(upstream.bodies).toEqual(["token=1%2F%2Frefresh-test-not-real"])
  await seedConnection(f.tenant, "gmail-2")
  await platform(f.tenant, "platform.subjects.remove", { body: {} })
  expect(upstream.requests).toHaveLength(2)
  const audit = await platform<{ events: { action: string; detail: string }[] }>(f.tenant, "platform.audit.read")
  expect(JSON.parse(audit.events.find((e) => e.action === "workspace.delete")!.detail)).toMatchObject({ items: 1, providerRevoked: 1 })
  expect(JSON.stringify(audit)).not.toContain("test-not-real")
})

it("refuses a one-host intake for an address the relay cannot reach when it is created, before any request is opened", async () => {
  const f = await subject()
  for (const host of ["10.0.0.1", "203.0.113.7", "[2001:db8::1]", "intranet", "printer.local", "db.internal"]) {
    expect(await refused(invokeAs(f.tenant, "platform.intakes.create", { body: { slug: "lan-key", service: { host } } }, platformAuth())), host).toEqual({ error: "bad_request", message: "That address is not one a key can be sent to: use a public host name, not an IP address or a private name." })
  }
  expect(await sql(f.tenant, "SELECT id FROM workspace_credential_requests")).toEqual([])
  expect(await platform(f.tenant, "platform.intakes.create", { body: { slug: "example-key", service: { host: "api.example.com" } } })).toMatchObject({ binding: { hosts: ["api.example.com"], known: false } })
})

it("stales on a defaults change only an approval still pending or still usable; a denied, used or ended one keeps its ending", async () => {
  const f = await subject()
  fakeProvider()
  const { task, held } = await heldRequest(f)
  const view = (approval: string) => platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval } })
  const decide = async (approval: string, decision: "approve" | "deny", ttlSeconds?: number) => platform<PlatformApprovalView>(f.tenant, "platform.approvals.decide", { params: { approval }, body: { decision, digest: (await view(approval)).digest, ...(ttlSeconds ? { ttlSeconds } : {}) } })
  const ask = async (url = "https://api.example.com/v1/things") => (await json<{ approval: string }>(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", url)), 409)).approval
  await decide(held.approval, "approve")
  await json(await signed(f.tenant, task, "/v1/relay", relay("example-key", "POST", "https://api.example.com/v1/things", held.approval)))
  const denied = await ask()
  await decide(denied, "deny")
  const granted = await ask()
  await decide(granted, "approve", 60)
  // Another request: the same one again would spend the grant just given.
  const pending = await ask("https://api.example.com/v1/others")
  f.directory.defaultsRevision = 2
  afterRefresh()
  await platform(f.tenant, "platform.subjects.get")
  expect(await Promise.all([held.approval, denied, granted, pending].map(async (id) => (await view(id)).status))).toEqual(["used", "denied", "stale", "stale"])
  afterRefresh(120)
  await platform(f.tenant, "platform.subjects.get")
  expect((await view(granted)).status).toBe("ended")
})

it("holds an intake a device's workload makes to the platform's template list, and gives it the platform's default tags", async () => {
  const f = await subject()
  f.directory.defaults = { ...f.directory.defaults, templates: ["openai"], tags: ["globex"] }
  afterRefresh()
  const task = await f.workload(await f.device())
  const ask = (provider: string, slug: string, tags?: string[]) => signed(f.tenant, task, "/v1/intakes", { kind: "api-key", slug, provider, reason: "The agent needs a key.", home: "workspace", ...(tags ? { tags } : {}) })
  expect(await json(await ask("anthropic", "anthropic-main"), 400)).toMatchObject({ error: "bad_request", message: "This platform does not offer that service." })
  expect(await sql(f.tenant, "SELECT id FROM workspace_credential_requests")).toEqual([])
  const asked = await json<{ intake: string }>(await ask("openai", "openai-main", ["agent"]), 201)
  const sealKey = await json<{ jwk: JsonWebKey }>(await (await import("./helpers.ts")).fetchWorker("/v1/seal-key"))
  const submitted = await platform<{ item: { tags: string[] } }>(f.tenant, "platform.intakes.submit", { params: { intake: asked.intake }, body: { sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), "sk-test-not-real-0004", `intake/${asked.intake}/key`) } } })
  expect([...submitted.item.tags].sort()).toEqual(["agent", "globex"])
})

it("submits an intake whose binding and injection a workload proposed only with the terms the platform attests, equal to the proposal, and checks terms sent for any other", async () => {
  const f = await subject()
  const task = await f.workload(await f.device())
  const binding = { hosts: ["collector.example.com"] }
  const injection = { in: "header", name: "X-Api-Key", format: "{key}" }
  const asked = await json<{ intake: string }>(await signed(f.tenant, task, "/v1/intakes", { kind: "api-key", slug: "collector-key", reason: "The agent needs a key.", home: "workspace", binding, injection }), 201)
  const key = await importSealPublicKey((await json<{ jwk: JsonWebKey }>(await (await import("./helpers.ts")).fetchWorker("/v1/seal-key"))).jwk)
  const submit = async (intake: string, terms?: unknown) => invokeAs(f.tenant, "platform.intakes.submit", { params: { intake }, body: { sealed: { key: await seal(key, "sk-test-not-real-0005", `intake/${intake}/key`) }, ...(terms === undefined ? {} : { terms }) } }, platformAuth())
  expect(await refused(submit(asked.intake))).toEqual({ error: "bad_request", message: "A workload proposed this intake's terms: send the terms your user was shown, its binding and injection." })
  expect(await refused(submit(asked.intake, { binding: { hosts: ["api.example.com"] }, injection }))).toEqual({ error: "bad_request", message: "The terms sent differ from this intake's: binding." })
  expect(await refused(submit(asked.intake, { binding, injection: { in: "header", name: "Authorization", format: "Bearer {key}" } }))).toEqual({ error: "bad_request", message: "The terms sent differ from this intake's: injection." })
  expect(await refused(submit(asked.intake, { binding: { ...binding, schemes: ["http"] }, injection: null }))).toEqual({ error: "bad_request", message: "The terms sent differ from this intake's: binding, injection." })
  expect(await sql(f.tenant, "SELECT slug FROM items")).toEqual([])
  const stored = await submit(asked.intake, { binding, injection })
  expect(stored.ok ? (stored.value as { item: { hosts: string[] } }).item.hosts : stored).toEqual(["collector.example.com"])
  // A platform-opened intake submits with no terms, as before; terms sent
  // for one are checked against its own.
  const opened = await platform<{ intake: string }>(f.tenant, "platform.intakes.create", { body: { slug: "example-key", service: { host: "api.example.com" } } })
  expect(await refused(submit(opened.intake, { binding, injection: { in: "header", name: "Authorization", format: "Bearer {key}" } }))).toEqual({ error: "bad_request", message: "The terms sent differ from this intake's: binding." })
  expect((await submit(opened.intake, { binding: { hosts: ["api.example.com"] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" } })).ok).toBe(true)
})

it("counts items in the transaction that stores one, so intakes submitted at once never pass the item limit", async () => {
  const f = await subject({ itemsPerSubject: 2 })
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  // Intakes a workload asked for, none counted at creation.
  const task = await f.workload(await f.device())
  const asked = await Promise.all(["openai-a", "openai-b", "openai-c"].map(async (slug) => (await json<{ intake: string }>(await signed(f.tenant, task, "/v1/intakes", { kind: "api-key", slug, provider: "openai", reason: "The agent needs OpenAI.", home: "workspace" }), 201)).intake))
  const key = await importSealPublicKey((await json<{ jwk: JsonWebKey }>(await (await import("./helpers.ts")).fetchWorker("/v1/seal-key"))).jwk)
  // Sealing waits on a timer here, as on a slow host, so the submits
  // interleave between their first reads and the transactions that store.
  await runInDurableObject(env.TENANT_VAULT.getByName(f.tenant), (instance: TenantVault) => {
    const sealField = instance.context.sealField
    Object.assign(instance.context, { async sealField(...args: Parameters<typeof sealField>) { await new Promise((resolve) => setTimeout(resolve, 20)); return sealField(...args) } })
  })
  const submits = await Promise.all(asked.map(async (intake) => invokeAs(f.tenant, "platform.intakes.submit", { params: { intake }, body: { sealed: { key: await seal(key, "sk-test-not-real-0002", `intake/${intake}/key`) } } }, platformAuth())))
  expect(submits.filter((s) => s.ok)).toHaveLength(1)
  for (const failed of submits.filter((s) => !s.ok)) expect(failed.ok ? null : failed.error.vaultError).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  expect(await sql(f.tenant, "SELECT count(*) AS count FROM items")).toEqual([{ count: 2 }])
})

it("writes nothing for a platform call admitted just before its subject's deletion began", async () => {
  const f = await subject()
  fakeProvider()
  const { task, held } = await heldRequest(f)
  const digest = (await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: held.approval } })).digest
  const project = await platform<PlatformProjectView>(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" } })
  const opened = await platform<{ intake: string; sealKey: { jwk: JsonWebKey } }>(f.tenant, "platform.intakes.create", { body: { slug: "openai-main", service: { template: "openai" } } })
  const sealed = { key: await seal(await importSealPublicKey(opened.sealKey.jwk), "sk-test-not-real-0001", `intake/${opened.intake}/key`) }
  const before = await accessSnapshot(f.tenant)
  const calls: [string, { params?: Record<string, string>; body?: unknown }][] = [
    ["platform.devices.create", { body: { name: "late", jwk: await publicJwk(await newDeviceKey()), modes: ["relay"] } }],
    ["platform.devices.revoke", { params: { device: task.device } }],
    ["platform.items.remove", { params: { slug: "example-key" } }],
    ["platform.intakes.create", { body: { slug: "openai-other", service: { template: "openai" } } }],
    ["platform.intakes.submit", { params: { intake: opened.intake }, body: { sealed } }],
    ["platform.intakes.cancel", { params: { intake: opened.intake }, body: {} }],
    ["platform.approvals.decide", { params: { approval: held.approval }, body: { decision: "approve", digest } }],
    ["platform.projects.create", { body: { slug: "more", environments: [{ name: "dev" }], defaultEnv: "dev" } }],
    ["platform.projects.setVar", { params: { project: project.id, name: "REGION" }, body: { env: "computers", before: null, plain: "eu-west-1" } }],
    ["platform.projects.remove", { params: { project: project.id }, body: {} }],
    ["platform.workspace.freeze", { body: {} }],
    ["platform.workspace.unfreeze", { body: {} }],
  ]
  for (const [op, input] of calls) expect(await afterDeletionBegan(f.tenant, op, input), op).toEqual({ error: "not_found", message: "No such subject." })
  expect(await accessSnapshot(f.tenant)).toBe(before)
})

it("deletes every held request with its subject, and keeps device and workload rows with no name, label or scope, for authentication only", async () => {
  const f = await subject({ auditRetentionDays: 30 })
  fakeProvider()
  await f.intake("example-key", { host: "api.example.com" }, { key: "ex-test-not-real-0001" })
  await f.intake("openai-main", { template: "openai" }, { key: "sk-test-not-real-0001" })
  const project = await platform<PlatformProjectView>(f.tenant, "platform.projects.create", { body: { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" } })
  await platform(f.tenant, "platform.projects.setVar", { params: { project: project.id, name: "OPENAI_KEY" }, body: { env: "computers", before: null, item: "openai-main" } })
  const machine = await f.device()
  const task = await f.workload(machine, { projects: [project.id] })
  await json(await signed(f.tenant, task, "/v1/runs", { project: project.id, env: "computers", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: ["OPENAI_KEY"], command: "globex computer" }), 201)
  // A drafted email held for a decision and approved, and one still pending.
  const draft = (to: string, words: string) => ({ ...relay("example-key", "POST", `https://api.example.com/v1/drafts/${to}`), headers: [["x-draft-subject", `Subject for ${to}`]], body: base64UrlEncode(new Uint8Array(new TextEncoder().encode(words))) })
  const approved = await json<{ approval: string }>(await signed(f.tenant, task, "/v1/relay", draft("bob-held-path", "Dear Bob, the held words")), 409)
  const digest = (await platform<PlatformApprovalView>(f.tenant, "platform.approvals.get", { params: { approval: approved.approval } })).digest
  await platform(f.tenant, "platform.approvals.decide", { params: { approval: approved.approval }, body: { decision: "approve", digest } })
  await json(await signed(f.tenant, task, "/v1/relay", draft("carol-held-path", "Dear Carol, the pending words")), 409)
  expect(await sql(f.tenant, "SELECT (SELECT count(*) FROM approvals) AS approvals,(SELECT count(*) FROM protected_use_grants) AS grants,(SELECT count(*) FROM consent_lineage) AS consent,(SELECT count(*) FROM runs) AS runs,(SELECT count(*) FROM exposures) AS exposures")).toEqual([{ approvals: 2, grants: 1, consent: 1, runs: 1, exposures: 2 }])
  await platform(f.tenant, "platform.subjects.remove", { body: {} })
  const tables = (await sql<{ name: string }>(f.tenant, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'")).map((t) => t.name)
  const kept: Record<string, unknown[]> = {}
  for (const table of tables) {
    const found = await sql(f.tenant, `SELECT * FROM ${table}`)
    if (found.length) kept[table] = found
  }
  expect(Object.keys(kept).sort()).toEqual(expect.arrayContaining(["audit", "devices", "members", "tenant_state", "workloads"]))
  for (const table of Object.keys(kept)) expect(["account_security", "audit", "device_nonces", "devices", "members", "schedule", "tenant_state", "workloads"], table).toContain(table)
  const everything = JSON.stringify(kept)
  for (const held of ["held words", "pending words", "Subject for", "bob-held-path", "carol-held-path", "x-draft-subject", "globex computer"]) expect(everything, held).not.toContain(held)
  const { audit: _audit, ...rest } = kept
  for (const named of ["agent-1", "globex:agent-1", "globex:grant-1", project.id]) expect(JSON.stringify(rest), named).not.toContain(named)
  expect(await sql(f.tenant, "SELECT name=id AS unnamed,provisioned_by FROM devices")).toEqual([{ unnamed: 1, provisioned_by: null }])
  expect(await sql(f.tenant, "SELECT label,scope FROM workloads")).toEqual([{ label: "", scope: "{}" }])
  expect((await json<{ error: string }>(await signed(f.tenant, task, "/v1/me"), 403)).error).toBe("workload_ended")
  expect((await json<{ error: string }>(await signed(f.tenant, machine, "/v1/me"), 403)).error).toBe("device_revoked")
  expect((await platform<{ verified: boolean }>(f.tenant, "platform.audit.read", {})).verified).toBe(true)
})
