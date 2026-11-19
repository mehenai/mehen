import { describe, expect, it, vi } from "vitest"
import { canonicalJson, createProof } from "@mehen/protocol"
import { assertPendingProviders, registerWorkspacePendingProvider, workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { queueNotice } from "../src/vault/areas/workspace-runtime.ts"
import { projectFixture, projectState, inAccess, accountAuth } from "./projects-workspace-fixture.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { VaultError } from "../src/http.ts"
import type { InboxItem } from "@mehen/protocol/inbox"
import type { WorkspaceInboxAnswer } from "../src/vault/areas/pending-workspace.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { PendingList } from "@mehen/protocol/api"
const WORK = { id: "", slug: "work", name: "Work" }
function inboxAs(ctx: VaultContext, role: string): WorkspaceInboxAnswer {
  const state = projectState(ctx)
  return workspacePendingOps["pending.inbox"]!.handler(ctx, accessMember(state, role), { enrolments: [] }, { auth: accountAuth(role), workspace: { ...WORK, id: ctx.tenant } }) as WorkspaceInboxAnswer
}
const SUBJECT = { method: "POST", url: "https://api.example.com", contentType: null, contentEncoding: null, headersSha256: digestOf([]), constraints: { uses: 1, ttlSeconds: 600 } }
// One open approval per call, from dev_kim on a project credential.
function askFromKim(ctx: VaultContext, body: number): string {
  const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
  return prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace: { ...WORK, id: ctx.tenant }, presentation: { title: "Kim's ask", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, { ...SUBJECT, item: "key-project", bodySha256: digestOf(body) }, null, ctx.now()).approvalId
}
describe("workspace pending routing", () => {
  it("fails closed when a required provider is absent", () => {
    for (const registered of [new Set<string>(), new Set(["credentials"]), new Set(["policy"]), new Set(["credentials", "policy"])]) {
      try { assertPendingProviders(registered); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "internal", message: "A required pending provider is unavailable." }) }
    }
    expect(() => assertPendingProviders(new Set(["credentials", "policy", "adoptions"]))).not.toThrow()
  })
  it("a machine sees only its own asks and owning-account notices; denial-only pending has no detail", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const state = projectState(ctx), workspace = { id: ctx.tenant, slug: "work", name: "Work" }
      const privateItem = state.credentials.find((c) => c.home.kind === "member" && c.home.member === "mem_member")!
      const subject = { item: "key-member", method: "POST", url: "https://private.example.com", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf("private-body"), constraints: { uses: 1, ttlSeconds: 600 } }
      const first = prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_member" }, workspace, presentation: { title: "private-provider private-body", details: [], body: "private-body" }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...privateItem, slug: "key-member", version: 1 }, null, subject, null, ctx.now())
      const otherItem = state.credentials.find((c) => c.home.kind === "project")!
      prepareApprovedUse(ctx, state, { principal: { kind: "device", deviceId: "dev_kim" }, workspace, presentation: { title: "Another machine ask", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }, { ...otherItem, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, { ...subject, item: "key-project" }, null, ctx.now())
      queueNotice(ctx, { kind: "machine_added", workspace, device: "dev_member", name: "Laptop", owner: { kind: "member", member: "mem_member", name: "member" }, place: "Test", at: new Date(ctx.now()).toISOString() })
      const proof = await createProof({ deviceId: "dev_member", sign: async () => new Uint8Array(64) }, { method: "GET", url: "https://vault.test/v1/pending" }, { tenant: ctx.tenant })
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const result = await workspacePendingOps["pending.list"]!.handler(ctx, { kind: "device", deviceId: "dev_member" }, {}, { auth: { kind: "device", proof, method: "GET", url: "https://vault.test/v1/pending", bodyHash: "" }, workspace }) as { pending: import("@mehen/protocol").WorkspacePendingAsk[]; notices: unknown[] }
      expect(result.pending).toHaveLength(1)
      expect(result.pending[0]?.view === "detail" && result.pending[0].detail.id).toBe(first.approvalId)
      expect(result.notices).toEqual([]) // New-machine notices go to owners/admins, not colleagues.
      const owner = await workspacePendingOps["pending.list"]!.handler(ctx, accessMember(state, "owner"), {}, { auth: accountAuth(), workspace }) as { pending: import("@mehen/protocol").WorkspacePendingAsk[]; notices: { url: string }[] }
      const stop = owner.pending.find((p) => p.view === "stop")!
      expect(stop.view).toBe("stop")
      expect(canonicalJson(stop)).not.toContain("private-body"); expect(canonicalJson(stop)).not.toContain("private-provider")
      expect(owner.notices[0]?.url).toBe(`https://vault.test/w/work/devices/dev_member`)
      const guest = await workspacePendingOps["pending.list"]!.handler(ctx, accessMember(state, "guest"), {}, { auth: accountAuth("guest"), workspace }) as { pending: unknown[] }
      expect(guest.pending).toEqual([])
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
  it("pending.inbox gives each ask its own link, verb and times, names the viewer, and keeps createdAt off a machine's asks", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const id = askFromKim(ctx, 1)
      const [row] = ctx.sql.exec<{ created_at: number; expires_at: number }>("SELECT created_at,expires_at FROM approvals WHERE id=?", id).toArray()
      const owner = inboxAs(ctx, "owner")
      expect(owner.viewer).toEqual({ member: "mem_owner", role: "owner" })
      const item = owner.items.find((i): i is Extract<InboxItem, { kind: "ask" }> => i.kind === "ask")!
      expect({ ...item, ask: undefined }).toEqual({ kind: "ask", workspace: { id: ctx.tenant, slug: "work", name: "Work" }, href: `/w/work/a/${id}`, action: item.ask.view === "stop" ? "stop" : "decide", createdAt: new Date(row!.created_at).toISOString(), expiresAt: new Date(row!.expires_at).toISOString(), ask: undefined })
      if (item.ask.view === "detail") expect(item.ask.detail.createdAt).toBe(new Date(row!.created_at).toISOString())
      // The machine's own copy is exactly what a 0.2.0 CLI decodes: no createdAt.
      const proof = await createProof({ deviceId: "dev_kim", sign: async () => new Uint8Array(64) }, { method: "GET", url: "https://vault.test/v1/pending" }, { tenant: ctx.tenant })
      const machine = await workspacePendingOps["pending.list"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, {}, { auth: { kind: "device", proof, method: "GET", url: "https://vault.test/v1/pending", bodyHash: "" }, workspace: { ...WORK, id: ctx.tenant } }) as { pending: import("@mehen/protocol").WorkspacePendingAsk[] }
      expect(machine.pending).toHaveLength(1)
      expect(machine.pending[0]?.view === "detail" && Object.keys(machine.pending[0].detail)).not.toContain("createdAt")
      // A device is never an inbox caller.
      expect(() => workspacePendingOps["pending.inbox"]!.handler(ctx, { kind: "device", deviceId: "dev_kim" }, { enrolments: [] }, { auth: { kind: "device", proof, method: "GET", url: "https://vault.test/v1/pending", bodyHash: "" }, workspace: { ...WORK, id: ctx.tenant } })).toThrow()
    })
  })
  it("pending.inbox reads at most 200 approvals before filtering and says so, even when the caller may see none of them", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const source = askFromKim(ctx, 1)
      const [row] = ctx.sql.exec<Record<string, SqlStorageValue>>("SELECT * FROM approvals WHERE id=?", source).toArray()
      // Clones outside any review group, so each is a row of its own.
      const columns = Object.keys(row!), clone = (id: string) => columns.map((c) => c === "id" ? id : c === "review_group" ? null : row![c]!)
      for (let i = 0; i < 199; i++) ctx.sql.exec(`INSERT INTO approvals(${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`, ...clone(`apr_clone${String(i).padStart(3, "0")}`))
      expect(inboxAs(ctx, "guest")).toEqual({ viewer: { member: "mem_guest", role: "guest" }, items: [], notices: [], truncated: false })
      ctx.sql.exec(`INSERT INTO approvals(${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`, ...clone("apr_clone999"))
      expect(inboxAs(ctx, "guest")).toEqual({ viewer: { member: "mem_guest", role: "guest" }, items: [], notices: [], truncated: true })
      const owner = inboxAs(ctx, "owner")
      expect(owner.items).toHaveLength(25)
      expect(owner.truncated).toBe(true)
    })
  })
  it("pending.inbox reads at most 50 notices, returns the ten newest oldest first and says when it left some unread", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const workspace = { id: ctx.tenant, slug: "work", name: "Work" }
      const add = (i: number) => ctx.sql.exec("INSERT INTO notice_outbox(id,account,payload,created_at,next_retry_at) VALUES (?,?,?,?,?)", `ntc_${String(i).padStart(3, "0")}`, "acc_owner", canonicalJson({ kind: "deletion_scheduled", workspace, by: "mem_owner", at: new Date(0).toISOString(), deleteAfter: new Date(0).toISOString() }), 1_000 + i, 0)
      for (let i = 0; i < 50; i++) add(i)
      const fifty = inboxAs(ctx, "owner")
      expect(fifty.notices.map((n) => n.id)).toEqual(Array.from({ length: 10 }, (_, i) => `ntc_0${40 + i}`))
      expect(fifty.truncated).toBe(true) // fifty stored, ten returned
      ctx.sql.exec("DELETE FROM notice_outbox WHERE id NOT IN (SELECT id FROM notice_outbox ORDER BY created_at DESC LIMIT 10)")
      expect(inboxAs(ctx, "owner")).toMatchObject({ truncated: false })
      for (let i = 0; i < 41; i++) add(100 + i)
      // 51 stored: the oldest is never read, the newest ten are returned.
      const scanned = inboxAs(ctx, "owner")
      expect(scanned.notices.map((n) => n.id)).toEqual(Array.from({ length: 10 }, (_, i) => `ntc_${131 + i}`))
      expect(scanned.truncated).toBe(true)
      expect(inboxAs(ctx, "guest").notices).toEqual([])
    })
  })
  it("/v1/pending names a machine's review groups at the top level only to mehen 0.3.17 or later, and never changes a row", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const list = async (cliVersion: string | null | undefined, on: VaultContext = ctx) => {
        const proof = await createProof({ deviceId: "dev_kim", sign: async () => new Uint8Array(64) }, { method: "GET", url: "https://vault.test/v1/pending" }, { tenant: ctx.tenant })
        const auth = { kind: "device" as const, proof, method: "GET", url: "https://vault.test/v1/pending", bodyHash: "", ...(cliVersion === undefined ? {} : { cliVersion }) }
        return await workspacePendingOps["pending.list"]!.handler(on, { kind: "device", deviceId: "dev_kim" }, {}, { auth, workspace: { ...WORK, id: ctx.tenant } }) as PendingList
      }
      const single = askFromKim(ctx, 1)
      expect((await list("0.3.17")).groups).toEqual([])
      const second = askFromKim(ctx, 2)
      ctx.sql.exec("UPDATE approvals SET created_at=created_at+1000,expires_at=expires_at+1000 WHERE id=?", second)
      const group = ctx.sql.exec<{ review_group: string }>("SELECT review_group FROM approvals WHERE id=?", single).toArray()[0]!.review_group
      const current = await list("0.3.17")
      const code = ctx.sql.exec<{ code: string }>("SELECT code FROM approval_group_codes WHERE review_group=?", group).toArray()[0]!.code
      expect(current.groups).toEqual([{ id: group, url: `https://vault.test/w/work/g/${group}`, approvals: [single, second], bundle: false, code }])
      expect((await list("0.4.0")).groups).toEqual(current.groups)
      for (const old of ["0.3.16", "0.3.0", null, undefined]) {
        const answer = await list(old)
        expect(Object.keys(answer), String(old)).not.toContain("groups")
        expect(canonicalJson(answer.pending), String(old)).toBe(canonicalJson(current.pending))
      }
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
      expect(Object.keys(await list("0.3.17", off))).not.toContain("groups")
    })
  })
  it("the twenty-first open ask is refused before mutation/open/send", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, (ctx) => {
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "workspace")!, caller = { principal: { kind: "device" as const, deviceId: "dev_member" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" }, presentation: { title: "Test", details: [], body: null }, batch: { floor: [], shape: "test-shape", replaces: null } }
      const subject = { item: "key-workspace", method: "POST", url: "https://api.example.com", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf(null), constraints: { uses: 1, ttlSeconds: 600 } }
      for (let i=0;i<20;i++) prepareApprovedUse(ctx, state, caller, { ...item, slug: "key-workspace", version: 1 }, null, { ...subject, bodySha256: digestOf(i) }, null, ctx.now())
      const before = canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray()), open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      try { prepareApprovedUse(ctx, state, caller, { ...item, slug: "key-workspace", version: 1 }, null, { ...subject, bodySha256: digestOf(21) }, null, ctx.now()); throw new Error("accepted") } catch (error) { expect((error as VaultError).toJSON()).toEqual({ error: "rate_limited", message: "This machine already has 20 open asks. Settle one before asking again.", next: { url: `https://vault.test/w/work/g/${ctx.sql.exec<{ review_group: string }>("SELECT review_group FROM approvals LIMIT 1").toArray()[0]!.review_group}`, say: "Ask the person to decide this machine's open asks at the link, then ask for the rest." } }) }
      expect(canonicalJson(ctx.sql.exec("SELECT * FROM approvals").toArray())).toBe(before)
      expect(open).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); open.mockRestore(); send.mockRestore()
    })
  })
})
