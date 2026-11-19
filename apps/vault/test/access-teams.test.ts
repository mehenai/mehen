import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { beginAccessSideEffectChecks, finishAccessSideEffectChecks, accessFixture, accessSnapshot, accountAuth, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { accessState } from "../src/vault/areas/workspace-runtime.ts"

beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

describe("access teams", () => {
  it("refuses non-admin mutations, guest membership and maintainer payloads atomically", async () => {
    const { tenant } = await accessFixture()
    const input = { team: "tm_engineering", member: "mem_kim", change: "add" } as const
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "access.team.members", input, accountAuth("member", { type: "team.members", ...input }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await workspaceInvoke(tenant, "access.team.members", { ...input, member: "mem_guest" }, accountAuth("owner", { type: "team.members", ...input, member: "mem_guest" }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await workspaceInvoke(tenant, "access.team.members", { ...input, role: "maintainer" }, accountAuth("owner", { type: "team.members", ...input }))).toEqual({ ok: false, error: { status: 400, vaultError: { error: "bad_request", message: "Invalid workspace request." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("has only ordinary team members and refuses deleting an active service's team", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, () => registerFixtureLifecycleHooks())
    const input = { team: "tm_engineering", member: "mem_kim", change: "add" } as const
    expect(await workspaceInvoke(tenant, "access.team.members", input, accountAuth("admin", { type: "team.members", ...input }))).toMatchObject({ ok: true, value: { members: expect.arrayContaining([{ member: "mem_kim", name: "Kim", role: "member" }]) } })
    const before = await accessSnapshot(tenant)
    const deletion = { team: "tm_service", change: "delete", name: null, slug: null } as const
    expect(await workspaceInvoke(tenant, "access.team.update", deletion, accountAuth("owner", { type: "team.update", ...deletion }))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "Revoke its machines first." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    await inAccess(tenant, (ctx) => expect(accessState(ctx).teams.find((t) => t.id === "tm_service")?.members).toEqual([]))
  })
  it("refuses duplicate ids and create/rename slug collisions as uniform conflicts", async () => {
    const { tenant } = await accessFixture()
    const before = await accessSnapshot(tenant)
    for (const input of [
      { team: "tm_engineering", change: "create", name: "Duplicate", slug: "unused-slug" },
      { team: "tm_duplicate", change: "create", name: "Duplicate", slug: "tm-engineering" },
      { team: "tm_engineering", change: "rename", name: "Duplicate", slug: "tm-service" },
    ] as const) {
      expect(await workspaceInvoke(tenant, "access.team.update", input, accountAuth("owner", { type: "team.update", ...input }))).toEqual({ ok: false, error: { status: 409, vaultError: { error: "conflict", message: "name not available" } } })
      expect(await accessSnapshot(tenant)).toBe(before)
    }
    expect(await workspaceInvoke(tenant, "access.team.update", { team: "invalid", change: "create", name: "Bad id", slug: "bad-id" }, accountAuth("owner"))).toEqual({ ok: false, error: { status: 400, vaultError: { error: "bad_request", message: "Invalid workspace request." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
  })
  it("creates, renames and deletes teams with their memberships and shares atomically", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, () => registerFixtureLifecycleHooks())
    const create = { team: "tm_new", change: "create", name: "New", slug: "new-team" } as const
    const rename = { ...create, change: "rename", name: "Renamed", slug: "renamed-team" } as const
    const before = await accessSnapshot(tenant)
    for (const input of [create, rename]) expect(await workspaceInvoke(tenant, "access.team.update", input, accountAuth("member", { type: "team.update", ...input }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "access.team.update", create, accountAuth("owner", { type: "team.update", ...create }))).toMatchObject({ ok: true, value: { name: "New", slug: "new-team" } })
    expect(await workspaceInvoke(tenant, "access.team.update", rename, accountAuth("owner", { type: "team.update", ...rename }))).toMatchObject({ ok: true, value: { name: "Renamed", slug: "renamed-team" } })
    await inAccess(tenant, (ctx) => {
      ctx.sql.exec("INSERT INTO team_members(team,member) VALUES ('tm_new','mem_member')")
      ctx.sql.exec("INSERT INTO project_shares VALUES ('shr_new','prj_a','team','tm_new',?)", JSON.stringify({ id: "shr_new", project: "prj_a", subject: { kind: "team", team: "tm_new" }, level: "use", protected: false, expiresAt: null }))
    })
    const deletion = { team: "tm_new", change: "delete", name: null, slug: null } as const
    expect(await workspaceInvoke(tenant, "access.team.update", deletion, accountAuth("owner", { type: "team.update", ...deletion }))).toEqual({ ok: true, value: {} })
    await inAccess(tenant, (ctx) => {
      expect(ctx.sql.exec("SELECT * FROM teams WHERE id='tm_new'").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM team_members WHERE team='tm_new'").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM project_shares WHERE subject_id='tm_new'").toArray()).toEqual([])
    })
  })

})
