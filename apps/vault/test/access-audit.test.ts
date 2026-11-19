import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { canonicalJson, type WorkspaceAuditPage } from "@mehen/protocol"
import { auditPrivateEvent, verifyAuditChain, type AuditRow } from "../src/vault/audit.ts"
import { credentialAudit } from "../src/vault/areas/items-workspace.ts"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, editAccessFixture, finishAccessSideEffectChecks, inAccess, workspaceInvoke } from "./access-test-support.ts"
import { credentialsFixture, devicePrincipal, seedCredential } from "./credentials-test-support.ts"

async function read(tenant: string, role = "member", query: Record<string, unknown> = {}): Promise<WorkspaceAuditPage> {
  const result = await workspaceInvoke(tenant, "tenant.audit", query, accountAuth(role))
  expect(result.ok).toBe(true)
  if (!result.ok) throw new Error(JSON.stringify(result))
  return result.value as WorkspaceAuditPage
}
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

async function fixture() {
  const f = await accessFixture()
  await inAccess(f.tenant, ctx => {
    editAccessFixture(ctx, state => { for (const c of state.credentials) c.slug = c.id.replace("itm_", "key-") })
    const append = (action: string, target: string | null, actor = "member:mem_owner", detail = {}) => ctx.audit({ actor, action, target, detail })
    append("own.action", null, "member:mem_member")
    append("own.machine", null, "device:dev_member")
    append("own.guest", null, "member:mem_guest")
    append("guest.machine", null, "device:dev_guest")
    append("project.edit", "prj_a")
    append("project.hidden", "prj_b")
    append("workspace.credential", "key-workspace", "member:mem_owner", { item: "itm_workspace" })
    append("team.own", "tm_engineering")
    append("team.foreign", "tm_service")
    append("workspace.other", ctx.tenant)
    for (const owner of ["member", "guest", "owner"]) auditPrivateEvent(ctx, { action: "relay.allow", at: ctx.now(), actor: { kind: "device", device: `dev_${owner}`, owner: { kind: "member", member: `mem_${owner}` } }, session: null, item: `itm_${owner}`, slug: `key-${owner}`, outcome: "allowed", run: null }, `mem_${owner}`)
  })
  return f
}

describe("tenant.audit workspace visibility", () => {
  it.each(["owner", "admin"])("%s reads every unchanged row and the complete verified chain", async role => {
    const { tenant } = await fixture(), result = await read(tenant, role)
    const original = await inAccess(tenant, ctx => ctx.sql.exec<AuditRow>("SELECT * FROM audit ORDER BY seq DESC").toArray())
    expect(result.events).toEqual(original)
    expect(result.filtered).toBe(false)
    expect(result.verified).toBe(true)
    expect(result.head).toEqual({ seq: original[0]!.seq, hash: original[0]!.hash })
    expect(verifyAuditChain([...result.events].reverse())).toEqual({ ok: true })
    expect(result.events.filter(row => row.action === "relay.allow").every(row => !row.detail.includes("host"))).toBe(true)
  })

  it("members see own actors, edited projects, usable workspace credentials, own teams and only own private events", async () => {
    const { tenant } = await fixture(), before = await accessSnapshot(tenant), result = await read(tenant)
    expect(result.events.map(row => row.action)).toEqual(["relay.allow", "team.own", "workspace.credential", "project.edit", "own.machine", "own.action"])
    expect(result.events.find(row => row.action === "relay.allow")?.detail).toContain('"member":"mem_member"')
    expect(result.filtered).toBe(true)
    expect(result.head).toBeNull()
    for (const row of result.events) expect(verifyAuditChain([row], row.prev)).toEqual({ ok: true })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("guests see only their own human and machine actors, never another person's rows", async () => {
    const { tenant } = await fixture(), result = await read(tenant, "guest")
    expect(result.events.map(row => row.actor)).toEqual(["device:dev_guest", "device:dev_guest", "member:mem_guest"])
    expect(result.filtered).toBe(true)
    expect(result.head).toBeNull()
    expect(JSON.stringify(result.events)).not.toContain("mem_owner")
    expect(JSON.stringify(result.events)).not.toContain("key-member")
  })

  it("removes project/team visibility when current shares and membership end", async () => {
    const { tenant } = await fixture()
    await inAccess(tenant, ctx => { ctx.sql.exec("DELETE FROM project_shares WHERE subject_id IN ('mem_member','tm_engineering')"); ctx.sql.exec("DELETE FROM team_members WHERE member='mem_member'") })
    const result = await read(tenant)
    expect(result.events.map(row => row.action)).toEqual(["relay.allow", "workspace.credential", "own.machine", "own.action"])
  })

  it("does not treat a use-only or expired project share as edit authority", async () => {
    const { tenant } = await fixture()
    await inAccess(tenant, ctx => {
      for (const row of ctx.sql.exec<{ id: string; value: string }>("SELECT id,value FROM project_shares WHERE subject_id='mem_member'").toArray()) {
        const share = JSON.parse(row.value)
        ctx.sql.exec("UPDATE project_shares SET value=? WHERE id=?", canonicalJson({ ...share, expiresAt: new Date(ctx.now() - 1).toISOString() }), row.id)
      }
    })
    expect((await read(tenant)).events.some(row => row.action === "project.edit")).toBe(false)
  })

  it("paginates after visibility filtering with original hashes and uniform absent/hidden item results", async () => {
    const { tenant } = await fixture(), all = await read(tenant), paged: AuditRow[] = []
    let cursor: string | null = null
    do { const page = await read(tenant, "member", { limit: 2, ...(cursor ? { cursor } : {}) }); paged.push(...page.events); cursor = page.next } while (cursor)
    expect(paged).toEqual(all.events)
    expect(await read(tenant, "member", { item: "key-owner" })).toEqual(await read(tenant, "member", { item: "absent-key" }))
    expect((await read(tenant, "member", { item: "key-member" })).events).toHaveLength(1)
    const before = await accessSnapshot(tenant)
    for (const query of [{ cursor: "bad" }, { cursor: "1", before: 1 }, { limit: 201 }, { limit: 0 }]) expect(await workspaceInvoke(tenant, "tenant.audit", query)).toMatchObject({ ok: false, error: { status: 400 } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })

  it("reports full-chain corruption even when the damaged row is hidden from the reader", async () => {
    const { tenant } = await fixture()
    await inAccess(tenant, ctx => ctx.sql.exec("UPDATE audit SET detail=? WHERE action='project.hidden'", '{"tampered":true}'))
    expect((await read(tenant)).verified).toBe(false)
  })

  it("uses immutable private ownership after admin purge and demotion, and fails closed without the index", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const item = await seedCredential(ctx, "purged-private", { kind: "member", member: "mem_member" })
      ctx.storage.transactionSync(() => { ctx.sql.exec("DELETE FROM items WHERE id=?", item.id); credentialAudit(ctx, { ...accountAuth("admin"), kind: "member", memberId: "mem_admin" }, item, "item.delete", "allowed") })
      ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_admin'")
      auditPrivateEvent(ctx, { action: "missing-index", at: ctx.now(), actor: { kind: "member", member: "mem_member" }, session: null, item: item.id, slug: item.slug, outcome: "allowed", run: null }, "mem_member")
      ctx.sql.exec("DELETE FROM audit_private_owners WHERE seq=(SELECT MAX(seq) FROM audit)")
    })
    expect((await read(f.tenant)).events.some(row => row.action === "item.delete")).toBe(true)
    expect((await read(f.tenant, "admin")).events.some(row => row.action === "item.delete")).toBe(false)
    expect((await read(f.tenant)).events.some(row => row.action === "missing-index")).toBe(false)
    expect((await read(f.tenant, "owner")).events.some(row => row.action === "missing-index")).toBe(true)
  })
})

it("private owner reads own minimal events through tenant.audit (ACCESS turn 2)", async () => {
  const f = await credentialsFixture()
  let expected!: AuditRow
  await inAccess(f.tenant, async ctx => {
    const item = await seedCredential(ctx, "private-golden", { kind: "member", member: "mem_member" })
    credentialAudit(ctx, devicePrincipal(), item, "relay.refuse", "refused:forbidden", {
      host: "private.example", path: "/hidden", fields: ["key"], body: "secret"
    }, "run_golden")
    expected = ctx.sql.exec<AuditRow>("SELECT * FROM audit WHERE action='relay.refuse' ORDER BY seq DESC LIMIT 1").toArray()[0]!
    expect(expected.detail).toBe(canonicalJson({
      action: "relay.refuse", at: expected.at,
      actor: { kind: "device", device: "dev_member", owner: { kind: "member", member: "mem_member" } },
      session: null, item: item.id, slug: "private-golden",
      outcome: "refused:forbidden", run: "run_golden"
    }))
  })
  const result = await workspaceInvoke(f.tenant, "tenant.audit", { item: "private-golden", limit: 200 }, accountAuth("member"))
  expect(result.ok).toBe(true)
  if (!result.ok) throw new Error("Expected the authorised audit view")
  const page = result.value as { events: AuditRow[] }
  expect(page.events.find(row => row.seq === expected.seq)).toEqual(expected)
})
