// The account-wide Needs you through worker.fetch,
// API half. An enrolment aimed at a workspace reaches the people that
// workspace says may act on it with a real count;
// nobody else ever sees the row: not plain members, not guests, not
// unconfirmed or suspended members, not other workspaces, not ended sessions.
import { describe, expect, it } from "vitest"
import { canonicalJson, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, fingerprintWords, type WorkspaceDeviceScope, type WorkspaceNotice, type WorkspacePendingAsk, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { InboxItem, InboxResponse, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import { body, workJourney, type Person } from "./workspace-journey.ts"
import { nativeSession } from "./oidc-journey.ts"
import { interceptInbox } from "./inbox-intercept.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
const needsYou = async (f: Journey, person: Person) => body<InboxResponse>(await f.request("/api/needs-you", person))
const enrolRows = (inbox: { items: InboxItem[] }) => inbox.items.filter((i): i is Extract<InboxItem, { kind: "enrol" }> => i.kind === "enrol")
const kinds = (inbox: { items: InboxItem[] }) => inbox.items.map((i) => i.kind)
async function people(f: Journey) {
  const mia = await f.guest(f.alex, f.work, f.project.id, "Mia")
  await body(await f.memberChange(f.alex, f.work, mia.member!, "role", "member"))
  const ada = await f.guest(f.alex, f.work, f.project.id, "Ada")
  await body(await f.memberChange(f.alex, f.work, ada.member!, "role", "admin"))
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  return { mia, ada, tom }
}

describe("Needs you across workspaces", () => {
  it("an enrolment aimed at a workspace reaches its owner with a real count, one validator and nothing secret", async () => {
    const f = await workJourney()
    const empty = await f.request("/api/needs-you", f.alex)
    expect(empty.headers.get("cache-control")).toBe("no-store")
    expect(await body(empty)).toEqual({ workspaces: [f.work, f.personal].map((workspace) => ({ workspace, role: "owner", state: "ok", reason: null, count: 0, truncated: false })), items: [], notices: [], count: 0, complete: true })
    const start = await f.startMachine(f.work)
    const response = await f.request("/api/needs-you", f.alex), etag = response.headers.get("etag")!
    const inbox = await body<InboxResponse>(response)
    const [row] = enrolRows(inbox)
    const hidden = await fingerprintGroupIndex(start.started.code), groups: (string | null)[] = [...fingerprintGroups(fingerprintOf(start.thumbprint))]
    groups[hidden] = null
    const stored = await f.db.prepare("SELECT start_at,expires_at,hard_expires_at FROM enrolments WHERE id=?").bind(start.started.enrolment).first<{ start_at: number; expires_at: number; hard_expires_at: number }>()
    expect(row).toEqual({ kind: "enrol", workspace: f.work, href: `/w/northwind/e/${start.started.enrolment}`, action: "accept", createdAt: new Date(stored!.start_at).toISOString(), expiresAt: new Date(stored!.expires_at).toISOString(), enrol: { enrolment: start.started.enrolment, name: "integration-machine", host: null, backend: "software", start: { at: new Date(stored!.start_at).toISOString(), place: null, clientLabel: "A browser" }, session: null, requestedOwner: { kind: "self" }, owner: null, claimed: null, state: "pending_owner_acceptance", fingerprint: { groups, words: fingerprintWords(start.thumbprint) }, actions: ["accept", "reject"], hardExpiresAt: new Date(stored!.hard_expires_at).toISOString() } })
    expect(inbox).toMatchObject({ count: 1, complete: true })
    expect(inbox.workspaces.map((w) => [w.workspace.slug, w.count])).toEqual([["northwind", 1], ["alex", 0]])
    // Never the thumbprint, the code or the hidden group.
    const text = JSON.stringify(inbox)
    for (const secret of [start.thumbprint, start.started.code, start.group]) expect(text).not.toContain(secret)
    // Equal reads, equal validator; a matching If-None-Match is 304, with or without the weak prefix.
    expect(etag).toMatch(/^W\/"[A-Za-z0-9_-]{43}"$/)
    for (const tag of [etag, etag.slice(2)]) {
      const unchanged = await f.request("/api/needs-you", f.alex, undefined, { "if-none-match": tag })
      expect(unchanged.status).toBe(304); expect(unchanged.headers.get("etag")).toBe(etag); expect(await unchanged.text()).toBe("")
    }
    // The one-workspace read carries the same row; the other workspace has none.
    expect(await body<WorkspaceInboxResponse>(await f.request("/api/w/northwind/inbox", f.alex))).toEqual({ workspace: inbox.workspaces[0], items: [row], notices: [] })
    expect((await body<WorkspaceInboxResponse>(await f.request("/api/w/alex/inbox", f.alex))).items).toEqual([])
    // Accepted: the row leaves and the validator changes.
    await body(await f.acceptMachine(f.alex, f.work, start))
    const after = await f.request("/api/needs-you", f.alex, undefined, { "if-none-match": etag })
    expect(after.status).toBe(200); expect(after.headers.get("etag")).not.toBe(etag)
    expect(enrolRows(await body<InboxResponse>(after))).toEqual([])
    // The membership list no longer carries a pending count.
    const account = await body<{ memberships: Record<string, unknown>[] }>(await f.request("/api/account", f.alex))
    expect(account.memberships.every((m) => !("pending" in m))).toBe(true)
  })

  it("plain members, guests, unconfirmed and suspended members and other workspaces never see a row the workspace would not show them", async () => {
    const f = await workJourney()
    const { mia, ada, tom } = await people(f)
    const una = await f.guest(f.alex, f.work, f.project.id, "Una", false)
    const work = await f.startMachine(f.work), personal = await f.startMachine(f.personal)
    const owner = await needsYou(f, f.alex)
    expect(enrolRows(owner).map((r) => r.enrol.enrolment).sort()).toEqual([work.started.enrolment, personal.started.enrolment].sort())
    // The owner and an admin may confirm Una; both see the confirmation.
    for (const person of [f.alex, ada]) {
      const confirm = (await needsYou(f, person)).items.find((i) => i.kind === "confirm")
      expect(confirm).toMatchObject({ kind: "confirm", workspace: f.work, href: `/w/northwind/people#confirm-${una.member}`, action: "confirm", confirm: { member: una.member, name: "Una", role: "guest", boundEmail: null } })
    }
    const admin = await needsYou(f, ada)
    expect(enrolRows(admin).map((r) => [r.enrol.enrolment, r.enrol.actions])).toEqual([[work.started.enrolment, ["accept", "reject"]]])
    for (const person of [mia, tom]) {
      const inbox = await needsYou(f, person)
      expect(inbox.items).toEqual([])
      expect(inbox.workspaces.map((w) => [w.workspace.slug, w.state])).toEqual([["northwind", "ok"]])
      expect(JSON.stringify(inbox)).not.toContain(work.started.enrolment)
      expect((await f.request("/api/w/alex/inbox", person)).status).toBe(404)
    }
    const unconfirmed = await needsYou(f, una)
    expect(unconfirmed).toEqual({ workspaces: [{ workspace: f.work, role: null, state: "inactive", reason: null, count: null, truncated: false }], items: [], notices: [], count: 0, complete: true })
    // Suspended: the workspace refuses, whatever D1 says about the membership.
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/northwind/members/${ada.member}/action`, f.alex, { change: "suspend" }))
    await body(await f.signed(`/api/w/northwind/members/${ada.member}/suspend`, f.alex, {}, action, "northwind"))
    expect(await f.db.prepare("SELECT state FROM memberships WHERE id=?").bind(ada.member!).first()).toEqual({ state: "member" })
    expect(await needsYou(f, ada)).toEqual({ workspaces: [{ workspace: f.work, role: null, state: "inactive", reason: null, count: null, truncated: false }], items: [], notices: [], count: 0, complete: true })
    // An ended session reads nothing.
    expect(await body(await f.request("/api/account/sessions/end-all", mia, {}))).toEqual({ pending: false })
    expect((await f.request("/api/needs-you", mia)).status).toBe(401)
    expect((await f.request("/api/w/northwind/inbox", mia)).status).toBe(401)
    expect((await f.request("/api/needs-you")).status).toBe(401)
  })

  it("an admission is listed to whoever may admit it, never to the guest who accepted it; a claimed machine to its account first", async () => {
    const f = await workJourney()
    const { mia, ada, tom } = await people(f)
    const start = await f.startMachine(f.work)
    await body(await f.acceptMachine(tom, f.work, start, false))
    const admission = enrolRows(await needsYou(f, f.alex))
    expect(admission.map((r) => [r.action, r.enrol.state, r.enrol.actions, r.enrol.owner])).toEqual([["admit", "pending_admission", ["admit", "reject"], { kind: "member", member: tom.member, name: "Tom" }]])
    for (const person of [tom, mia]) expect(enrolRows(await needsYou(f, person))).toEqual([])
    // A connect code claims the next machine for Mia: she may accept it, the owner and admin only reject it.
    const { code } = await body<{ code: string }>(await f.request("/api/w/northwind/connect-code", mia, {}))
    const { createProof, webCryptoSigner } = await import("@mehen/protocol")
    const { newDeviceKey, publicJwk } = await import("../devices.ts")
    const keys = await newDeviceKey(), input = { workspace: "northwind", owner: { kind: "self" }, name: "mia-laptop", backend: "software", jwk: await publicJwk(keys), connect: code }
    const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: "https://vault.test/v1/enrol", body: JSON.stringify(input) }, { tenant: "enrol" })
    const claimed = await body<{ enrolment: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
    const row = (rows: Extract<InboxItem, { kind: "enrol" }>[]) => rows.find((r) => r.enrol.enrolment === claimed.enrolment)
    expect(row(enrolRows(await needsYou(f, mia)))).toMatchObject({ action: "accept", enrol: { actions: ["accept", "reject"], claimed: { account: mia.account, name: "Mia" } } })
    for (const person of [f.alex, ada]) expect(row(enrolRows(await needsYou(f, person)))).toMatchObject({ action: "reject", enrol: { actions: ["reject"], claimed: { account: mia.account, name: "Mia" } } })
    expect(row(enrolRows(await needsYou(f, tom)))).toBeUndefined()
    expect(JSON.stringify(await needsYou(f, mia))).not.toContain(code)
  })

  it("a scope proposal is listed to the signer it still needs, as the role it signs in", async () => {
    const f = await workJourney()
    const { mia, tom } = await people(f)
    const machine = await f.machine(mia, f.work)
    const current = await body<{ scope: WorkspaceDeviceScope }>(await f.deviceCall(machine, "/v1/me"))
    const after = { ...current.scope, maxEnvironment: "protected" as const }, base = `/api/w/northwind/devices/${machine.device}`
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, f.alex, { change: { kind: "rescope_propose", before: current.scope, after } }))
    const proposal = await body<{ id: string; requiredSigners: { as: string; account?: string }[]; signedBy: string[] }>(await f.signed(`${base}/rescope`, f.alex, { before: current.scope, after }, action, "northwind"))
    const rescope = (await needsYou(f, mia)).items.filter((i) => i.kind === "rescope")
    expect(rescope).toEqual([{ kind: "rescope", workspace: f.work, href: `/w/northwind/devices/${machine.device}`, action: "review", createdAt: null, expiresAt: expect.any(String), rescope: { proposal: proposal.id, device: machine.device, deviceName: "integration-machine", owner: { kind: "member", member: mia.member, name: "Mia" }, proposer: { member: await f.member(f.alex, f.work), name: "Alex" }, as: "owner_acceptance" } }])
    expect((await needsYou(f, tom)).items.filter((i) => i.kind === "rescope")).toEqual([])
    // Signed: nothing left to do for Mia.
    const planned = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, mia, { change: { kind: "rescope_accept", proposal: proposal.id } }))
    await body(await f.signed(`${base}/rescope-accept`, mia, { proposal: proposal.id }, planned.action, "northwind"))
    expect((await needsYou(f, mia)).items.filter((i) => i.kind === "rescope")).toEqual([])
  })

  it("the three notice envelopes and today's pending pass unchanged through /api/needs-you, /api/w/:ws/inbox and /app/v1/pending", async () => {
    const f = await workJourney()
    const at = new Date(Date.now() - 60_000).toISOString(), member = await f.member(f.alex, f.work)
    const payloads = [
      { kind: "machine_added", workspace: f.work, device: "dev_fixture", name: "Laptop", owner: { kind: "member", member, name: "Alex" }, place: "Amsterdam", at },
      { kind: "account_security", workspace: f.work, account: "acc_someone", name: "Sam", event: "recovery", at, client: "mehen 0.3.0", place: null, restrictedUntil: null },
      { kind: "protection_changed", workspace: f.work, project: { id: f.project.id, slug: "platform" }, env: "prod", changes: ["four_eyes_off"], by: member, at },
    ]
    const notices: WorkspaceNotice[] = payloads.map((payload, i) => ({ id: `ntc_fixture${i}`, account: f.alex.account, payload: payload as WorkspaceNotice["payload"], at: 1_000 + i, url: `https://vault.test/w/northwind${payload.kind === "machine_added" ? "/devices/dev_fixture" : "/"}` }))
    for (const notice of notices) await f.sql(f.work, "INSERT INTO notice_outbox(id,account,payload,created_at,next_retry_at) VALUES (?,?,?,?,?)", notice.id, notice.account, canonicalJson(notice.payload), notice.at, 0)
    await body(await f.request("/api/w/northwind/intakes", f.alex, { provider: "openai", slug: "waiting-key", home: "workspace" }), 201)
    const start = await f.startMachine(f.work)
    const account = await needsYou(f, f.alex)
    const workspace = await body<WorkspaceInboxResponse>(await f.request("/api/w/northwind/inbox", f.alex))
    const native = await nativeSession(f)
    const app = await body<{ pending: WorkspacePendingAsk[]; notices: WorkspaceNotice[]; inbox: InboxItem[] }>(await f.request("/app/v1/pending", undefined, undefined, native.headers))
    for (const read of [account.notices, workspace.notices, app.notices]) expect(read).toEqual(notices)
    // pending is today's shape, the asks of the member's own pending list; inbox is additive.
    expect(Object.keys(app).sort()).toEqual(["inbox", "notices", "pending", "truncated"])
    const listed = await body<{ pending: WorkspacePendingAsk[] }>(await f.request("/api/w/northwind/pending", f.alex))
    expect(app.pending).toEqual(listed.pending)
    expect(app.pending.map((ask) => ask.view === "detail" && ask.detail.kind)).toEqual(["intake"])
    expect(app.inbox).toEqual(account.items)
    expect(kinds({ items: app.inbox }).sort()).toEqual(["ask", "enrol"])
    expect(enrolRows({ items: app.inbox })[0]?.enrol.enrolment).toBe(start.started.enrolment)
  })

  it("the app read refuses whenever a workspace could not be read, and answers a healthy empty account as before", async () => {
    const f = await workJourney()
    const { mia } = await people(f)
    const app = await nativeSession(f, mia), owner = await nativeSession(f)
    const pending = (headers: Record<string, string>) => f.request("/app/v1/pending", undefined, undefined, headers)
    expect(await body(await pending(app.headers))).toEqual({ pending: [], notices: [], inbox: [], truncated: false })
    // A workspace whose vault throws: a retryable refusal, never an empty success.
    let restore = interceptInbox(f, async () => { throw new Error("Injected unreachable workspace") })
    const thrown = await pending(app.headers)
    expect(thrown.status).toBe(502)
    expect(await thrown.json()).toEqual({ error: "upstream_failed", message: "Northwind could not be read just now.", retryAfter: 5, next: { say: "Try again in a few seconds." } })
    restore()
    // A workspace that answers with its own refusal: that refusal, unchanged.
    restore = interceptInbox(f, async () => ({ ok: false, error: { vaultError: { error: "internal", message: "Injected internal refusal." }, status: 500 } }))
    const refused = await pending(app.headers)
    expect(refused.status).toBe(500)
    expect(await refused.json()).toEqual({ error: "internal", message: "Injected internal refusal." })
    restore()
    // A workspace that never answers: refused after its budget, not answered without it.
    let hold: () => void = () => {}
    restore = interceptInbox(f, (_workspace, _invocation, proceed) => new Promise((resolve) => { hold = () => resolve(proceed()) }))
    const timedOut = await pending(app.headers)
    expect(timedOut.status).toBe(502)
    expect(await timedOut.json()).toMatchObject({ error: "upstream_failed" })
    hold(); restore()
    // One healthy workspace with an ask beside one failing workspace: refused, the healthy ask not passed off as everything.
    await body(await f.request("/api/w/northwind/intakes", f.alex, { provider: "openai", slug: "waiting-key", home: "workspace" }), 201)
    restore = interceptInbox(f, async (workspace, _invocation, proceed) => { if (workspace === f.personal.id) throw new Error("Injected unreachable workspace"); return proceed() })
    const partial = await pending(owner.headers)
    expect(partial.status).toBe(502)
    expect(await partial.json()).toMatchObject({ error: "upstream_failed", message: "Personal could not be read just now." })
    // The web inbox shows the same state honestly instead.
    const web = await needsYou(f, f.alex)
    expect(web.workspaces.map((w) => [w.workspace.slug, w.state, w.reason])).toEqual([["northwind", "ok", null], ["alex", "unavailable", "error"]])
    expect(web).toMatchObject({ count: 1, complete: false })
    restore()
    expect((await body<{ pending: unknown[] }>(await pending(owner.headers))).pending).toHaveLength(1)
  })

  it("twenty-five unclaimed starts take only their share of the inbox: a fresh ask and a claimed machine are listed, and every read says the list is partial", async () => {
    const f = await workJourney()
    const now = Date.now()
    const insert = `INSERT INTO enrolments(id,code_hash,jwk,thumbprint,name,backend,status,created_at,expires_at,workspace_intent,owner_intent,start_at,start_client_label,pending_state,hard_expires_at,hidden_group,claimed_account)
      VALUES (?,?,'{}',?,?,'software','pending',?,?,'northwind','{"kind":"self"}',?,'mehen 0.3.0','pending_owner_acceptance',?,1,?)`
    // Unclaimed starts that all run out before the ask that follows them.
    await f.db.batch(Array.from({ length: 25 }, (_, i) => f.db.prepare(insert).bind(`enr_flood${String(i).padStart(2, "0")}`, `hash_flood${i}`, `flood${i}`.padEnd(43, "A"), `flood-${i}`, now, now + 600_000 + i, now, now + 86_400_000, null)))
    await f.db.prepare(insert).bind("enr_claimed", "hash_claimed", "claimed".padEnd(43, "A"), "claimed", now, now + 1_200_000, now, now + 86_400_000, f.alex.account).run()
    await body(await f.request("/api/w/northwind/intakes", f.alex, { provider: "openai", slug: "fresh-key", home: "workspace" }), 201)
    const inbox = await needsYou(f, f.alex)
    const work = inbox.items.filter((i) => i.workspace.id === f.work.id)
    expect(work.filter((i) => i.kind === "ask")).toHaveLength(1)
    expect(enrolRows({ items: work }).map((r) => r.enrol.enrolment)).toEqual(["enr_flood00", "enr_flood01", "enr_flood02", "enr_flood03", "enr_flood04", "enr_claimed"])
    expect(inbox.workspaces.map((w) => [w.workspace.slug, w.count, w.truncated])).toEqual([["northwind", 7, true], ["alex", 0, false]])
    expect(inbox.complete).toBe(false)
    const app = await body<{ pending: WorkspacePendingAsk[]; inbox: InboxItem[]; truncated: boolean }>(await f.request("/app/v1/pending", undefined, undefined, (await nativeSession(f)).headers))
    expect(app.inbox).toEqual(inbox.items)
    expect(app.pending.map((ask) => ask.view === "detail" && ask.detail.kind)).toEqual(["intake"])
    expect(app.truncated).toBe(true)
  })

  it("a member removed or demoted, or a session revoked, between the Worker's reads and the workspace's read sees only what the workspace now allows", async () => {
    const f = await workJourney()
    const { mia, ada } = await people(f)
    await f.guest(f.alex, f.work, f.project.id, "Una", false)
    const start = await f.startMachine(f.work)
    // Ada, an admin, sees the machine and Una's confirmation.
    const admin = await f.request("/api/needs-you", ada), adminTag = admin.headers.get("etag")!
    expect(kinds(await body<InboxResponse>(admin)).sort()).toEqual(["confirm", "enrol"])
    // Demoted after the Worker chose her workspaces and candidates: no machine, no confirmation, the new role.
    let restore = interceptInbox(f, async (_workspace, invocation, proceed) => {
      if ((invocation.auth as { account?: string }).account === ada.account) { restore(); await body(await f.memberChange(f.alex, f.work, ada.member!, "role", "member")) }
      return proceed()
    })
    const demoted = await f.request("/api/needs-you", ada, undefined, { "if-none-match": adminTag })
    restore()
    expect(demoted.status).toBe(200)
    expect(demoted.headers.get("etag")).not.toBe(adminTag)
    const demotedInbox = await body<InboxResponse>(demoted)
    expect(demotedInbox.items).toEqual([])
    expect(demotedInbox.workspaces).toEqual([{ workspace: f.work, role: "member", state: "ok", reason: null, count: 0, truncated: false }])
    expect(JSON.stringify(demotedInbox)).not.toContain(start.started.enrolment)
    // Removed after the Worker read her membership: nothing, no count, no role.
    await body(await f.request("/api/w/northwind/intakes", mia, { provider: "openai", slug: "mia-key", home: "private" }), 201)
    expect(kinds(await needsYou(f, mia))).toEqual(["ask"])
    restore = interceptInbox(f, async (_workspace, invocation, proceed) => {
      if ((invocation.auth as { account?: string }).account === mia.account) { restore(); await body(await f.memberChange(f.alex, f.work, mia.member!, "remove")) }
      return proceed()
    })
    const removed = await needsYou(f, mia)
    restore()
    expect(removed).toEqual({ workspaces: [{ workspace: f.work, role: null, state: "inactive", reason: null, count: null, truncated: false }], items: [], notices: [], count: 0, complete: true })
    // A session revoked after the Worker's session lookup: the workspace refuses it, the whole read is 401.
    restore = interceptInbox(f, async (_workspace, invocation, proceed) => {
      if ((invocation.auth as { account?: string }).account === ada.account) { restore(); expect(await body(await f.request("/api/account/sessions/end-all", ada, {}))).toEqual({ pending: false }) }
      return proceed()
    })
    const revoked = await f.request("/api/needs-you", ada)
    restore()
    expect(revoked.status).toBe(401)
    expect(await revoked.json()).toMatchObject({ error: "unauthenticated" })
  })

  it("a validator from another account, or from before a role change, never earns a 304; the one-workspace read keeps the membership and tab guards", async () => {
    const f = await workJourney()
    const { mia, ada } = await people(f)
    await f.startMachine(f.work)
    const alexTag = (await f.request("/api/needs-you", f.alex)).headers.get("etag")!
    const miaTag = (await f.request("/api/needs-you", mia)).headers.get("etag")!
    expect(miaTag).not.toBe(alexTag)
    const crossed = await f.request("/api/needs-you", mia, undefined, { "if-none-match": alexTag })
    expect(crossed.status).toBe(200)
    expect(crossed.headers.get("etag")).toBe(miaTag)
    expect(enrolRows(await body<InboxResponse>(crossed))).toEqual([])
    const adaTag = (await f.request("/api/needs-you", ada)).headers.get("etag")!
    expect(adaTag).not.toBe(miaTag)
    await body(await f.memberChange(f.alex, f.work, ada.member!, "role", "member"))
    const after = await f.request("/api/needs-you", ada, undefined, { "if-none-match": adaTag })
    expect(after.status).toBe(200)
    expect(enrolRows(await body<InboxResponse>(after))).toEqual([])
    expect(after.headers.get("etag")).not.toBe(adaTag)
    // Ada now reads exactly Mia's projection: equal content, equal validator; each read was still authorised on its own.
    expect(after.headers.get("etag")).toBe(miaTag)
    // The one-workspace read: another workspace's name, or a tab naming another workspace, is the unknown-workspace answer.
    expect((await f.request(`/api/w/${f.personal.slug}/inbox`, mia)).status).toBe(404)
    expect((await f.request("/api/w/northwind/inbox", mia, undefined, { "Mehen-Workspace": f.personal.id })).status).toBe(404)
    expect((await f.request("/api/w/northwind/inbox", mia, undefined, { "Mehen-Workspace": f.work.id })).status).toBe(200)
  })
})

// The page half (SH): /needs-you, the landing, the one-workspace filter and
// the picker's counts, all from the same inbox read.
describe("the Needs you pages", () => {
  const HTML = { accept: "text/html" }
  const page = async (f: Journey, path: string, person?: Person) => f.request(path, person, undefined, HTML)
  const bootOf = (html: string) => JSON.parse((/data-boot="([^"]*)"/.exec(html)?.[1] ?? "").replaceAll("&quot;", '"').replaceAll("&amp;", "&")) as Record<string, unknown>

  it("lands on /needs-you when something waits, lists the row with its deep link and the validator the poll sends, and nothing secret", async () => {
    const f = await workJourney()
    expect((await page(f, "/", f.alex)).headers.get("location")).toBe("/workspaces")
    const quiet = await (await page(f, "/needs-you", f.alex)).text()
    expect(quiet).toContain("<title>Needs you · Mehen</title>")
    expect(quiet).toContain("Nothing needs you")
    const start = await f.startMachine(f.work)
    expect((await page(f, "/", f.alex)).headers.get("location")).toBe("/needs-you")
    const response = await page(f, "/needs-you", f.alex)
    expect(response.status).toBe(200)
    const html = await response.text()
    expect(html).toContain("<title>(1) Needs you · Mehen</title>")
    expect(html).toContain(`href="/w/northwind/e/${start.started.enrolment}">Accept</a>`)
    expect(html).toContain('<a href="/w/northwind/">Northwind</a> <code class="slug">northwind</code>')
    for (const secret of [start.thumbprint, start.started.code]) expect(html).not.toContain(secret)
    const api = await f.request("/api/needs-you", f.alex)
    expect(bootOf(html)).toEqual({ page: "needs-you", account: f.alex.account, etag: api.headers.get("etag"), signedIn: { origin: "https://vault.test", account: f.alex.account } })
    // The poll's first ask with that validator is a 304.
    expect((await f.request("/api/needs-you", f.alex, undefined, { "if-none-match": String(bootOf(html).etag) })).status).toBe(304)
  })

  it("filters one workspace at /w/:ws/pending, counts it in the picker, and shows a plain member nothing they may not act on", async () => {
    const f = await workJourney()
    const start = await f.startMachine(f.work)
    const filter = await (await page(f, "/w/northwind/pending", f.alex)).text()
    expect(filter).toContain("Needs you in Northwind")
    expect(filter).toContain(`href="/w/northwind/e/${start.started.enrolment}"`)
    expect(filter).toMatch(/<a href="\/needs-you" aria-current="page">|href="\/needs-you"[^>]*aria-current="page"/)
    const personal = await (await page(f, "/w/alex/pending", f.alex)).text()
    expect(personal).toContain("Nothing is waiting for you in Personal")
    expect(personal).not.toContain(start.started.enrolment)
    const picker = await (await page(f, "/workspaces", f.alex)).text()
    expect(picker).toContain("Owner · 1 thing needs you")
    const mia = await f.guest(f.alex, f.work, f.project.id, "Mia")
    await body(await f.memberChange(f.alex, f.work, mia.member!, "role", "member"))
    const hers = await (await page(f, "/needs-you", mia)).text()
    expect(hers).not.toContain(start.started.enrolment)
    expect(hers).toContain("Nothing needs you")
  })

  it("sends a signed-out visitor to sign in and back", async () => {
    const f = await workJourney()
    const response = await page(f, "/needs-you")
    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe(`/signin?next=${encodeURIComponent("/needs-you")}`)
  })
})
