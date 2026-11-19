// Scope proposal rows in Needs you are decided from live authority, never
// from the stored signer list alone. A guest machine's proposal
// names Kim, a prj_a manager, as its admission signer: Kim's row goes the
// moment Kim's managing share expires or is revoked, and every row goes when
// the proposal no longer matches its machine.
import { createExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { RescopeProposalViewSchema, type RescopeProposalView, type Share, type WorkspaceDeviceScope } from "@mehen/protocol"
import type { InboxItem } from "@mehen/protocol/inbox"
import { accountInbox, inboxEtag, workspaceInbox } from "../src/directory/account-inbox.ts"
import type { RequestContext } from "../src/routes/context.ts"
import type { WorkspaceInboxAnswer } from "../src/vault/areas/pending-workspace.ts"
import { accessState, setProjectShare } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"

async function kimProposal(tenant: string): Promise<{ before: WorkspaceDeviceScope; proposal: RescopeProposalView }> {
  const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_guest")!.scope })
  const after = { ...before, privateCredentials: true }
  const result = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_guest", before, after, project: "prj_a", admissionMember: "mem_kim" }, accountAuth("admin", { type: "device.rescope", device: "dev_guest", thumbprint: "dev_guest", before, after }))
  if (!result.ok) throw new Error(JSON.stringify(result))
  const proposal = RescopeProposalViewSchema.parse(result.value)
  expect(proposal.requiredSigners).toEqual([{ name: "guest", as: "owner_acceptance" }, { name: "Kim", as: "admission" }])
  return { before, proposal }
}
async function rescopeRows(tenant: string, role: string): Promise<Extract<InboxItem, { kind: "rescope" }>[]> {
  const result = await workspaceInvoke(tenant, "pending.inbox", { enrolments: [] }, accountAuth(role))
  if (!result.ok) throw new Error(JSON.stringify(result))
  return (result.value as WorkspaceInboxAnswer).items.filter((i): i is Extract<InboxItem, { kind: "rescope" }> => i.kind === "rescope")
}
const signers = async (tenant: string) => Object.fromEntries(await Promise.all(["owner", "admin", "member", "guest", "kim"].map(async (role) => [role, (await rescopeRows(tenant, role)).map((r) => r.rescope.as)] as const)))
async function kimShare(tenant: string): Promise<Share> {
  return inAccess(tenant, (ctx) => JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM project_shares WHERE project='prj_a' AND subject_kind='member' AND subject_id='mem_kim'").toArray()[0]!.value) as Share)
}

describe("rescope rows follow live authority", () => {
  it("lists the guest owner and the current admission signer, nobody else, with the machine's fields", async () => {
    const { tenant } = await accessFixture()
    const { proposal } = await kimProposal(tenant)
    expect(await signers(tenant)).toEqual({ owner: [], admin: [], member: [], guest: ["owner_acceptance"], kim: ["admission"] })
    expect(await rescopeRows(tenant, "kim")).toEqual([{ kind: "rescope", workspace: { id: tenant, slug: "work", name: "Work" }, href: "/w/work/devices/dev_guest", action: "review", createdAt: null, expiresAt: proposal.expiresAt, rescope: { proposal: proposal.id, device: "dev_guest", deviceName: "dev_guest", owner: { kind: "member", member: "mem_guest", name: "guest" }, proposer: { member: "mem_admin", name: "admin" }, as: "admission" } }])
  })
  it("drops the admission signer's row when the managing share expires, and again when it is revoked", async () => {
    for (const change of ["expired", "revoked"] as const) {
      const { tenant } = await accessFixture()
      await kimProposal(tenant)
      const share = await kimShare(tenant)
      await inAccess(tenant, (ctx) => setProjectShare(ctx, change === "expired" ? { ...share, expiresAt: new Date(ctx.now() - 1000).toISOString() } : null, share))
      expect(await signers(tenant)).toEqual({ owner: [], admin: [], member: [], guest: ["owner_acceptance"], kim: [] })
    }
  })
  it.each([
    ["the owner's revision changed", "UPDATE members SET revision=revision+1 WHERE id='mem_guest'"],
    ["the machine's scope changed", "UPDATE devices SET scope=json_set(scope,'$.maxEnvironment','protected'),scope_rev=scope_rev+1 WHERE id='dev_guest'"],
    ["the machine was revoked", "UPDATE devices SET revoked_at=1 WHERE id='dev_guest'"],
  ])("drops every row when %s", async (_why, statement) => {
    const { tenant } = await accessFixture()
    await kimProposal(tenant)
    await inAccess(tenant, (ctx) => { ctx.sql.exec(statement) })
    expect(await signers(tenant)).toEqual({ owner: [], admin: [], member: [], guest: [], kim: [] })
  })
  it("the row, its count and its validator leave every Worker read as soon as the share expires", async () => {
    const { tenant } = await accessFixture()
    await kimProposal(tenant)
    const tag = crypto.randomUUID().replaceAll("-", "").slice(0, 10), now = Date.now()
    await env.DB.batch([
      env.DB.prepare("INSERT OR IGNORE INTO accounts(id,name,created_at) VALUES ('acc_kim','Kim',?)").bind(now),
      env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_at) VALUES (?,?,'Work','active',?)").bind(tenant, `w${tag}`, now),
      env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,'acc_kim',?,'member','member',?)").bind(`mem_${tag}`, tenant, now),
    ])
    const account = { account: "acc_kim", name: "Kim", session: "ses_kim", securityEpoch: 0, transition: null, restrictedUntil: null }
    const url = new URL("https://vault.test/api/needs-you"), rc: RequestContext = { request: new Request(url), env: { ...env }, ctx: createExecutionContext(), url, params: {} }
    const options = { sessionKind: "web" as const, stubFor: (id: string) => env.TENANT_VAULT.getByName(id) }
    const read = async () => {
      const { inbox, unreadable, gateRefusal } = await accountInbox(rc, account, options)
      expect([unreadable, gateRefusal]).toEqual([null, null])
      const one = await workspaceInbox(rc, { workspace: inbox.workspaces[0]!.workspace, membership: `mem_${tag}`, account }, options)
      return { inbox, one, etag: await inboxEtag(inbox) }
    }
    const before = await read()
    expect(before.inbox.items.map((i) => i.kind)).toEqual(["rescope"])
    expect(before.one.items).toEqual(before.inbox.items)
    expect(before.inbox).toMatchObject({ count: 1, complete: true })
    const share = await kimShare(tenant)
    await inAccess(tenant, (ctx) => setProjectShare(ctx, { ...share, expiresAt: new Date(ctx.now() - 1000).toISOString() }, share))
    const after = await read()
    // /api/needs-you, /api/w/:ws/inbox and the app's inbox field all carry these items.
    expect(after.inbox.items).toEqual([])
    expect(after.one.items).toEqual([])
    expect(after.inbox).toMatchObject({ count: 0, complete: true })
    expect(after.inbox.workspaces[0]).toMatchObject({ state: "ok", count: 0 })
    expect(JSON.stringify(after)).not.toContain("dev_guest")
    expect(after.etag).not.toBe(before.etag)
  })
})
