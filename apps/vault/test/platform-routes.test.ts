// /v1/platform through the real Worker (src/routes/platform.ts): the
// platform's own routes against D1, every subject route against a
// stand-in for the managed workspace's operations.

import { runInDurableObject } from "cloudflare:test"
import { describe, expect, it, vi } from "vitest"
import { PLATFORM_ROUTES, PLATFORM_SUBJECTS_PAGE_SIZE, platformSubjectHash } from "@mehen/protocol"
import type { PlatformVault } from "../src/platform/platform-vault.ts"
import { PLATFORM_WORKSPACE_ROUTES, assertPlatformRoutesClaimed } from "../src/routes/platform.ts"
import { platformOAuthRoutes } from "../src/routes/platform-oauth.ts"
import { AREAS } from "../src/vault/registry.ts"
import { DEFAULT_WORKSPACE_ANSWER, PURGE_AFTER, type WorkspaceAnswer, addSubject, answerOf, platformEnv, platformFetch, registerPlatform } from "./platform-fixtures.ts"

const SUBJECT = "subject-0001"
const subjectPath = (subject = SUBJECT) => `/v1/platform/subjects/${subject}`

async function bytesOf(response: Response): Promise<{ status: number; headers: [string, string][]; body: string }> {
  return { status: response.status, headers: [...response.headers.entries()].sort(), body: await response.text() }
}

describe("the platform's own routes", () => {
  it("views the platform: status, limits, defaults, live subjects and keys, nothing more", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, "subject-live1")
    await addSubject(env, platform.id, "subject-gone1", "deleted")
    const { status, body } = await answerOf(await platformFetch(env, platform, { method: "GET", path: "/v1/platform" }))
    expect(status).toBe(200)
    expect(Object.keys(body).sort()).toEqual(["defaults", "defaultsRevision", "keys", "limits", "platform", "usage"])
    expect(body.platform).toEqual({ id: platform.id, slug: platform.slug, name: `Platform ${platform.slug}`, status: "active" })
    expect(body.usage).toEqual({ subjects: 1 })
    expect(body.keys).toEqual([{ id: platform.key, createdAt: expect.any(String), expiresAt: null, revoked: false }])
    expect(body.defaults).toEqual({ scopes: {}, tags: [], customReads: "approve", rules: {} })
  })

  it("lists only its own subjects, a page at a time", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const other = await registerPlatform(env)
    for (let i = 0; i < PLATFORM_SUBJECTS_PAGE_SIZE + 1; i++) await addSubject(env, platform.id, `subject-${String(i).padStart(4, "0")}`)
    await addSubject(env, platform.id, "subject-purged", "purged")
    await addSubject(env, other.id, "subject-other")
    const first = await answerOf(await platformFetch(env, platform, { method: "GET", path: "/v1/platform/subjects" }))
    const subjects = first.body.subjects as { subject: string }[]
    expect(subjects).toHaveLength(PLATFORM_SUBJECTS_PAGE_SIZE)
    expect(typeof first.body.next).toBe("string")
    const second = await answerOf(await platformFetch(env, platform, { method: "GET", path: `/v1/platform/subjects?cursor=${first.body.next as string}` }))
    const rest = second.body.subjects as { subject: string }[]
    expect(rest).toHaveLength(1)
    expect(second.body.next).toBeNull()
    const all = [...subjects, ...rest].map((s) => s.subject)
    expect(new Set(all).size).toBe(PLATFORM_SUBJECTS_PAGE_SIZE + 1)
    expect(all).not.toContain("subject-other")
    const theirs = await answerOf(await platformFetch(env, other, { method: "GET", path: "/v1/platform/subjects" }))
    expect((theirs.body.subjects as { subject: string }[]).map((s) => s.subject)).toEqual(["subject-other"])
  })

  it("puts defaults: checked, the revision moved, the change recorded in D1 and in the platform's audit", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const allow = await answerOf(await platformFetch(env, platform, { method: "PUT", path: "/v1/platform/defaults", body: { scopes: {}, tags: [], customReads: "approve", rules: { openai: [{ action: "allow", methods: ["GET"] }] } } }))
    expect(allow.status).toBe(400)
    expect(allow.body.error).toBe("bad_request")
    const defaults = { templates: ["openai"], scopes: {}, tags: ["globex"], customReads: "allow", rules: { openai: [{ action: "deny", methods: ["DELETE"] }] } }
    const put = await answerOf(await platformFetch(env, platform, { method: "PUT", path: "/v1/platform/defaults", body: defaults }))
    expect(put).toEqual({ status: 200, body: { defaults, defaultsRevision: 2 } })
    const view = await answerOf(await platformFetch(env, platform, { method: "GET", path: "/v1/platform" }))
    expect(view.body).toMatchObject({ defaults, defaultsRevision: 2 })
    const events = await env.DB.prepare("SELECT actor,action,detail FROM platform_events WHERE platform=?").bind(platform.id).all<{ actor: string; action: string; detail: string }>()
    expect(events.results).toHaveLength(1)
    expect(events.results[0]).toMatchObject({ actor: `platform:${platform.key}`, action: "defaults.put" })
    const detail = JSON.parse(events.results[0]?.detail ?? "{}") as { revision: number; before: string; after: string }
    expect(detail.revision).toBe(2)
    expect(detail.before).not.toBe(detail.after)
    const audit = await runInDurableObject(env.PLATFORM_VAULT.getByName(platform.id), (_: PlatformVault, state) => state.storage.sql.exec<{ actor: string; action: string; detail: string }>("SELECT actor,action,detail FROM audit ORDER BY seq").toArray())
    expect(audit).toHaveLength(1)
    expect(audit[0]).toMatchObject({ actor: `platform:${platform.id}`, action: "defaults.put" })
    expect(JSON.parse(audit[0]?.detail ?? "{}")).toMatchObject({ revision: 2, before: detail.before, after: detail.after, by: { platform: platform.id, key: platform.key } })
  })

  it("deletes every subject only when confirmed with its own slug, and leaves other platforms alone", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const other = await registerPlatform(env)
    await addSubject(env, platform.id, "subject-aaaa")
    await addSubject(env, platform.id, "subject-bbbb", "creating")
    await addSubject(env, platform.id, "subject-cccc", "deleted")
    await addSubject(env, other.id, "subject-aaaa")
    const wrong = await answerOf(await platformFetch(env, platform, { method: "DELETE", path: "/v1/platform/subjects", body: { confirm: other.slug } }))
    expect(wrong).toEqual({ status: 400, body: { error: "bad_request", message: "Confirm with this platform's own slug." } })
    const done = await answerOf(await platformFetch(env, platform, { method: "DELETE", path: "/v1/platform/subjects", body: { confirm: platform.slug } }))
    expect(done).toEqual({ status: 200, body: { deleting: 2 } })
    const statuses = await env.DB.prepare("SELECT platform,subject,status FROM managed_workspaces ORDER BY platform,subject").all<{ platform: string; subject: string; status: string }>()
    expect(statuses.results.filter((r) => r.platform === platform.id).map((r) => r.status)).toEqual(["deleting", "deleting", "deleted"])
    expect(statuses.results.filter((r) => r.platform === other.id).map((r) => r.status)).toEqual(["active"])
    expect(await env.DB.prepare("SELECT action FROM platform_events WHERE platform=?").bind(platform.id).all()).toMatchObject({ results: [{ action: "subjects.remove_all" }] })
  })

  it("answers an unknown platform path and a wrong method as the rest of the vault does", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    expect((await answerOf(await platformFetch(env, platform, { method: "GET", path: "/v1/platform/nope" }))).status).toBe(404)
    expect((await platformFetch(env, platform, { method: "POST", path: "/v1/platform" })).status).toBe(405)
  })
})

describe("a subject", () => {
  it("is made once and found after: 201, then 200, with the workspace made under platform auth", async () => {
    const { env, calls } = await platformEnv()
    const platform = await registerPlatform(env)
    const made = await answerOf(await platformFetch(env, platform, { method: "PUT", path: subjectPath(), body: {} }))
    expect(made).toEqual({ status: 201, body: { subject: SUBJECT, status: "active", createdAt: expect.any(String), counts: { devices: 1, items: 2, projects: 3 } } })
    const again = await answerOf(await platformFetch(env, platform, { method: "PUT", path: subjectPath(), body: {} }))
    expect(again).toEqual({ status: 200, body: made.body })
    const rows = await env.DB.prepare("SELECT tenant,subject,subject_hash,status FROM managed_workspaces WHERE platform=?").bind(platform.id).all<{ tenant: string; subject: string; subject_hash: string; status: string }>()
    expect(rows.results).toEqual([{ tenant: expect.stringMatching(/^tn_[A-Za-z0-9]{8,40}$/), subject: SUBJECT, subject_hash: await platformSubjectHash(platform.id, SUBJECT), status: "active" }])
    expect(calls).toHaveLength(2)
    expect(calls[0]).toEqual({ tenant: rows.results[0]?.tenant, op: "platform.subjects.ensure", input: { params: {}, query: null, body: {} }, auth: { kind: "platform", platform: platform.id, key: platform.key, subject: SUBJECT, jti: expect.any(String), iat: expect.any(Number) } })
  })

  it("is bound by the platform's subject quota, refused while retiring or still being deleted, and made anew once deleted", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env, { limits: { subjects: 1 } })
    expect((await platformFetch(env, platform, { method: "PUT", path: subjectPath("subject-one1"), body: {} })).status).toBe(201)
    const over = await answerOf(await platformFetch(env, platform, { method: "PUT", path: subjectPath("subject-two2"), body: {} }))
    expect(over).toEqual({ status: 403, body: { error: "quota_exceeded", message: "That is past this platform's limit of 1 subjects." } })
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM managed_workspaces WHERE subject='subject-two2'").first()).toEqual({ n: 0 })
    await env.DB.prepare("UPDATE managed_workspaces SET status='deleting' WHERE platform=?").bind(platform.id).run()
    const deleting = await answerOf(await platformFetch(env, platform, { method: "PUT", path: subjectPath("subject-one1"), body: {} }))
    expect(deleting).toEqual({ status: 409, body: { error: "conflict", message: "That subject is still being deleted; try again once it is." } })
    await env.DB.prepare("UPDATE managed_workspaces SET status='deleted',purge_after=? WHERE platform=?").bind(PURGE_AFTER, platform.id).run()
    expect((await platformFetch(env, platform, { method: "PUT", path: subjectPath("subject-one1"), body: {} })).status).toBe(201)
    expect(await env.DB.prepare("SELECT COUNT(DISTINCT tenant) AS n FROM managed_workspaces WHERE subject='subject-one1'").first()).toEqual({ n: 2 })
    const retiring = await registerPlatform(env, { status: "retiring" })
    const refused = await answerOf(await platformFetch(env, retiring, { method: "PUT", path: subjectPath(), body: {} }))
    expect(refused).toEqual({ status: 403, body: { error: "platform_suspended", message: "This platform is retiring and takes no new subjects." } })
  })

  it("finishes a creation the workspace failed, on the next call", async () => {
    let fail = true
    const { env, calls } = await platformEnv((call) => (call.op === "platform.subjects.ensure" && fail ? { ok: false, error: { vaultError: { error: "internal", message: "Something went wrong inside the vault." }, status: 500 } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    vi.spyOn(console, "error").mockImplementation(() => undefined)
    expect((await platformFetch(env, platform, { method: "PUT", path: subjectPath(), body: {} })).status).toBe(500)
    expect(await env.DB.prepare("SELECT status FROM managed_workspaces WHERE platform=?").bind(platform.id).first()).toEqual({ status: "creating" })
    fail = false
    expect((await platformFetch(env, platform, { method: "PUT", path: subjectPath(), body: {} })).status).toBe(201)
    expect(new Set(calls.map((c) => c.tenant)).size).toBe(1)
    expect(await env.DB.prepare("SELECT status FROM managed_workspaces WHERE platform=?").bind(platform.id).first()).toEqual({ status: "active" })
    vi.restoreAllMocks()
  })

  it("is never listed, read or reached by another platform, even with the same subject string: not_found as absent", async () => {
    const { env, calls } = await platformEnv()
    const owner = await registerPlatform(env)
    const stranger = await registerPlatform(env)
    await platformFetch(env, owner, { method: "PUT", path: subjectPath(), body: {} })
    const reached = calls.length
    const probes = [
      { method: "GET", path: subjectPath() },
      { method: "DELETE", path: subjectPath(), body: {} },
      { method: "GET", path: `${subjectPath()}/devices` },
      { method: "GET", path: `${subjectPath()}/audit` },
      { method: "POST", path: `${subjectPath()}/freeze`, body: {} },
    ]
    for (const probe of probes) {
      const theirs = await bytesOf(await platformFetch(env, stranger, probe))
      const absent = await bytesOf(await platformFetch(env, stranger, { ...probe, path: probe.path.replace(SUBJECT, "subject-none") }))
      expect(theirs).toEqual(absent)
      expect(theirs.status).toBe(404)
      expect(JSON.parse(theirs.body)).toEqual({ error: "not_found", message: "No such subject." })
    }
    expect(calls).toHaveLength(reached)
    expect(((await answerOf(await platformFetch(env, stranger, { method: "GET", path: "/v1/platform/subjects" }))).body.subjects as unknown[])).toEqual([])
    expect((await platformFetch(env, owner, { method: "GET", path: subjectPath() })).status).toBe(200)
  })

  it("is read with the workspace's counts, and a deleted one until its purge", async () => {
    const { env, calls } = await platformEnv()
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, "subject-made", "creating")
    expect((await answerOf(await platformFetch(env, platform, { method: "GET", path: subjectPath("subject-made") }))).body).toMatchObject({ status: "creating", counts: { devices: 0, items: 0, projects: 0 } })
    expect(calls).toHaveLength(0)
    await addSubject(env, platform.id, "subject-gone", "deleted")
    const gone = await answerOf(await platformFetch(env, platform, { method: "GET", path: subjectPath("subject-gone") }))
    expect(gone).toEqual({ status: 200, body: { subject: "subject-gone", status: "deleted", createdAt: expect.any(String), counts: { devices: 1, items: 2, projects: 3 } } })
    expect(calls.map((c) => c.op)).toEqual(["platform.subjects.get"])
  })

  it("is deleted once: the workspace emptied, then deleted in D1 with its purge date; repeating answers the same", async () => {
    const { env, calls } = await platformEnv()
    const platform = await registerPlatform(env)
    const tenant = await addSubject(env, platform.id, SUBJECT)
    const removed = await answerOf(await platformFetch(env, platform, { method: "DELETE", path: subjectPath(), body: {} }))
    expect(removed).toEqual({ status: 200, body: { subject: SUBJECT, status: "deleted", purgeAfter: new Date(PURGE_AFTER).toISOString() } })
    expect(calls.map((c) => [c.tenant, c.op])).toEqual([[tenant, "platform.subjects.remove"]])
    expect(await env.DB.prepare("SELECT status,purge_after FROM managed_workspaces WHERE tenant=?").bind(tenant).first()).toEqual({ status: "deleted", purge_after: PURGE_AFTER })
    expect(await answerOf(await platformFetch(env, platform, { method: "DELETE", path: subjectPath(), body: {} }))).toEqual(removed)
    expect(calls).toHaveLength(1)
    expect((await platformFetch(env, platform, { method: "DELETE", path: subjectPath("subject-none"), body: {} })).status).toBe(404)
  })
})

describe("a subject's workspace routes", () => {
  it("call platform.<route name> with the parsed params, query and body, under platform auth", async () => {
    const answers: Record<string, unknown> = {
      "platform.items.remove": { slug: "openai", deleted: true, providerRevoked: false },
      "platform.audit.read": { events: [], head: null, verified: true, filtered: false, next: null },
    }
    const { env, calls } = await platformEnv((call) => (call.op in answers ? { ok: true, value: answers[call.op] } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    const tenant = await addSubject(env, platform.id, SUBJECT)
    expect(await answerOf(await platformFetch(env, platform, { method: "DELETE", path: `${subjectPath()}/items/openai` }))).toEqual({ status: 200, body: answers["platform.items.remove"] })
    expect((await platformFetch(env, platform, { method: "GET", path: `${subjectPath()}/audit?limit=5&cursor=9` })).status).toBe(200)
    expect(calls.map(({ tenant: t, op, input, auth }) => ({ t, op, input, kind: auth.kind, subject: auth.subject }))).toEqual([
      { t: tenant, op: "platform.items.remove", input: { params: { slug: "openai" }, query: null, body: null }, kind: "platform", subject: SUBJECT },
      { t: tenant, op: "platform.audit.read", input: { params: {}, query: { limit: 5, cursor: "9" }, body: null }, kind: "platform", subject: SUBJECT },
    ])
  })

  it("answer only what the contract names, with 201 or 200 for a device by whether it was made", async () => {
    const device = { device: "dev_abc", tenant: "tn_Alpha123456", name: "Agent", label: null, scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false, workloads: "required" }, createdAt: new Date().toISOString(), revoked: false }
    let created = true
    const { env } = await platformEnv((call) => (call.op === "platform.devices.create" ? { ok: true, value: { ...device, created, secret: "sk-should-never-leave" } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, SUBJECT)
    const body = { name: "Agent", jwk: { kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) }, modes: ["relay"] }
    const first = await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/devices`, body })
    expect(first.status).toBe(201)
    const text = await first.text()
    expect(JSON.parse(text)).toEqual(device)
    expect(text).not.toContain("sk-should-never-leave")
    created = false
    expect((await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/devices`, body })).status).toBe(200)
  })

  it("answer 201 for a project made and 200 for the same project again, without the created flag", async () => {
    const project = { id: "prj_abc", slug: "computers", defaultEnv: "computers", environments: [{ name: "computers" }], vars: [] }
    let created = true
    const { env } = await platformEnv((call) => (call.op === "platform.projects.create" ? { ok: true, value: { ...project, created } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, SUBJECT)
    const body = { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" }
    expect(await answerOf(await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/projects`, body }))).toEqual({ status: 201, body: project })
    created = false
    expect(await answerOf(await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/projects`, body }))).toEqual({ status: 200, body: project })
  })

  it("refuse a bad path, query or body before the workspace is called, and pass the workspace's refusals through without a link or command", async () => {
    const { env, calls } = await platformEnv((call) => (call.op === "platform.approvals.decide" ? { ok: false, error: { vaultError: { error: "conflict", message: "The request changed; ask again.", next: { url: "https://vault.test/w/x/approvals/apr_one", command: "mehen wait apr_one", say: "Read the approval again." } }, status: 409 } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, SUBJECT)
    const refusals = [
      await platformFetch(env, platform, { method: "DELETE", path: `${subjectPath()}/devices/not-a-device` }),
      await platformFetch(env, platform, { method: "GET", path: `${subjectPath()}/devices?extra=1` }),
      await platformFetch(env, platform, { method: "GET", path: `${subjectPath()}/items?kind=api-key&kind=api-key` }),
      await platformFetch(env, platform, { method: "DELETE", path: `${subjectPath()}/devices/dev_abc`, body: {} }),
      await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/devices`, body: { name: "Agent", modes: ["lease"] } }),
    ]
    for (const refusal of refusals) expect((await answerOf(refusal)).body.error).toBe("bad_request")
    expect(calls).toHaveLength(0)
    const decide = await answerOf(await platformFetch(env, platform, { method: "POST", path: `${subjectPath()}/approvals/apr_one/decide`, body: { decision: "approve", digest: "d".repeat(43) } }))
    expect(decide).toEqual({ status: 409, body: { error: "conflict", message: "The request changed; ask again.", next: { say: "Read the approval again." } } })
  })

  it("reach only an active subject, except its audit, which stays readable until the purge", async () => {
    const audit = { events: [], head: null, verified: true, filtered: false, next: null }
    const { env, calls } = await platformEnv((call) => (call.op === "platform.audit.read" ? { ok: true, value: audit } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    for (const status of ["creating", "deleting", "deleted"] as const) {
      const subject = `subject-${status}`
      await addSubject(env, platform.id, subject, status)
      expect((await platformFetch(env, platform, { method: "GET", path: `${subjectPath(subject)}/devices` })).status).toBe(404)
      expect((await platformFetch(env, platform, { method: "GET", path: `${subjectPath(subject)}/audit` })).status).toBe(status === "creating" ? 404 : 200)
    }
    expect(calls.map((c) => c.op)).toEqual(["platform.audit.read", "platform.audit.read"])
  })

  it("never pass on an answer outside the contract", async () => {
    const { env } = await platformEnv((call) => (call.op === "platform.devices.list" ? { ok: true, value: { devices: [{ device: "dev_x", secret: "sk" }] } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    await addSubject(env, platform.id, SUBJECT)
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    const answer = await answerOf(await platformFetch(env, platform, { method: "GET", path: `${subjectPath()}/devices` }))
    expect(answer).toEqual({ status: 500, body: { error: "internal", message: "Something went wrong inside the vault." } })
    expect(errors).toHaveBeenCalledWith(JSON.stringify({ at: "platform.answer", route: "devices.list" }))
    errors.mockRestore()
  })
})

describe("the platform's limits, counted by its PlatformVault", () => {
  it("refuse calls past callsPerMinute for that platform only, with retryAfter", async () => {
    const { env } = await platformEnv()
    const busy = await registerPlatform(env, { limits: { callsPerMinute: 2 } })
    const quiet = await registerPlatform(env, { limits: { callsPerMinute: 2 } })
    const at = Math.floor(Date.now() / 60_000) * 60_000 + 15_000
    vi.spyOn(Date, "now").mockReturnValue(at)
    try {
      for (let i = 0; i < 2; i++) expect((await platformFetch(env, busy, { method: "GET", path: "/v1/platform", now: at })).status).toBe(200)
      const limited = await answerOf(await platformFetch(env, busy, { method: "GET", path: "/v1/platform", now: at }))
      expect(limited).toEqual({ status: 429, body: { error: "rate_limited", message: "This platform is making too many calls; slow down.", retryAfter: 45 } })
      expect((await platformFetch(env, quiet, { method: "GET", path: "/v1/platform", now: at })).status).toBe(200)
    } finally {
      vi.restoreAllMocks()
    }
  })

  it("count writes per subject and decisions per subject and in all, never reads against them", async () => {
    const decided = { approval: "apr_one", status: "approved", digest: "d".repeat(43), device: "dev_a", workload: null, item: "openai", request: { method: "POST", url: "https://api.openai.com/v1/x", contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b" }, title: "t", warnings: [], constraints: { uses: 1, ttlSeconds: 900 }, expiresAt: new Date().toISOString(), decidedBy: null }
    const { env } = await platformEnv((call) => (call.op === "platform.approvals.decide" ? { ok: true, value: decided } : call.op === "platform.workspace.freeze" ? { ok: true, value: { frozen: true } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env, { limits: { subjectWritesPerMinute: 2, subjectDecisionsPerMinute: 1, decisionsPerMinute: 2 } })
    for (const subject of ["subject-aaaa", "subject-bbbb", "subject-cccc"]) await addSubject(env, platform.id, subject)
    const at = Math.floor(Date.now() / 60_000) * 60_000 + 30_000
    vi.spyOn(Date, "now").mockReturnValue(at)
    const decide = (subject: string) => platformFetch(env, platform, { method: "POST", path: `${subjectPath(subject)}/approvals/apr_one/decide`, body: { decision: "approve", digest: "d".repeat(43) }, now: at })
    try {
      expect((await decide("subject-aaaa")).status).toBe(200)
      expect((await answerOf(await decide("subject-aaaa"))).body.error).toBe("rate_limited")
      expect((await decide("subject-bbbb")).status).toBe(200)
      expect((await answerOf(await decide("subject-cccc"))).body.error).toBe("rate_limited")
      expect((await platformFetch(env, platform, { method: "POST", path: `${subjectPath("subject-cccc")}/freeze`, body: {}, now: at })).status).toBe(200)
      expect((await platformFetch(env, platform, { method: "POST", path: `${subjectPath("subject-cccc")}/freeze`, body: {}, now: at })).status).toBe(200)
      expect((await answerOf(await platformFetch(env, platform, { method: "POST", path: `${subjectPath("subject-cccc")}/freeze`, body: {}, now: at }))).body.error).toBe("rate_limited")
      expect((await platformFetch(env, platform, { method: "GET", path: subjectPath("subject-cccc"), now: at })).status).toBe(200)
      // The counters name each subject by its hash, never by its name.
      const names = await runInDurableObject(env.PLATFORM_VAULT.getByName(platform.id), (_: PlatformVault, state) => state.storage.sql.exec<{ name: string }>("SELECT name FROM platform_counters ORDER BY name").toArray().map((row) => row.name))
      expect(names.join("\n")).not.toContain("subject-")
      const hashes = Object.fromEntries(await Promise.all(["subject-aaaa", "subject-bbbb", "subject-cccc"].map(async (subject) => [subject, await platformSubjectHash(platform.id, subject)] as const)))
      expect(names).toEqual(expect.arrayContaining([`decisions:${hashes["subject-aaaa"]}`, `decisions:${hashes["subject-bbbb"]}`, `writes:${hashes["subject-cccc"]}`]))
    } finally {
      vi.restoreAllMocks()
    }
  })

  it("record each call's route and outcome, never its content", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    await platformFetch(env, platform, { method: "GET", path: "/v1/platform" })
    await platformFetch(env, platform, { method: "GET", path: subjectPath("subject-none") })
    const activity = await env.PLATFORM_VAULT.getByName(platform.id).activity(Date.now() - 3_600_000)
    expect(activity.routes).toEqual({ "platform.view": { ok: 1 }, "subjects.get": { not_found: 1 } })
  })
})

describe("the route table", () => {
  it("leaves to the workspace every subject route the directory does not answer, and the OAuth areas claim the connection routes", () => {
    expect(PLATFORM_WORKSPACE_ROUTES).toHaveLength(PLATFORM_ROUTES.length - 7)
    expect(PLATFORM_WORKSPACE_ROUTES.every((name) => PLATFORM_ROUTES.find((r) => r.name === name)?.path.startsWith("/v1/platform/subjects/:subject/"))).toBe(true)
    expect(() => assertPlatformRoutesClaimed(["connects.start", "connects.finish", "connects.get", "connects.cancel"])).not.toThrow()
    expect(() => assertPlatformRoutesClaimed(["connects.start", "connects.finish", "connects.get"])).toThrow("unclaimed connects.cancel")
    expect(() => assertPlatformRoutesClaimed(["connects.start", "connects.finish", "connects.get", "connects.cancel", "devices.create"])).toThrow("unexpected devices.create")
  })

  it("every route a managed workspace answers has its platform operation in a registered area, and the OAuth areas claim exactly theirs", () => {
    const ops = new Set(AREAS.flatMap((area) => Object.keys(area.workspaceOps ?? {})))
    for (const name of PLATFORM_WORKSPACE_ROUTES) expect([name, ops.has(`platform.${name}`)]).toEqual([name, true])
    expect(() => assertPlatformRoutesClaimed(platformOAuthRoutes)).not.toThrow()
  })
})
