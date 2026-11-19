import { describe, expect, it } from "vitest"
import { canonicalJson, type ProjectBinding } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { projectAccessState, projectWorkspaceOps } from "../src/vault/areas/projects-workspace.ts"
import { registerAccessStateProvider } from "../src/vault/areas/workspace-runtime.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { WORKSPACE_FULL_SCOPE } from "./workspace-fixtures.ts"
import { inAccess, projectDeviceInvocation, projectFixture } from "./projects-workspace-fixture.ts"
import { fixtureSql } from "./fixture-sql.ts"

const REMOTE_A = "github.com/acme/app"
const REMOTE_B = "github.com/acme/billing"
const MISS = { error: "not_found", message: "No such object." }

async function find(ctx: VaultContext, device: string, remote: string): Promise<unknown> {
  return projectWorkspaceOps["projects.find"]!.handler(ctx, { kind: "device", deviceId: device }, { remote }, await projectDeviceInvocation(ctx, device))
}
async function miss(ctx: VaultContext, device: string, remote: string): Promise<{ status: number; body: unknown }> {
  try {
    await find(ctx, device, remote)
  } catch (error) {
    if (error instanceof VaultError) return { status: error.status, body: error.toJSON() }
    throw error
  }
  throw new Error("found")
}
function bindRemotes(ctx: VaultContext): void {
  ctx.sql.exec("INSERT INTO remotes(remote,project) VALUES(?,'prj_a'),(?,'prj_b')", REMOTE_A, REMOTE_B)
  ctx.sql.exec("INSERT INTO vars(project,env,name,plain,updated_by,updated_at) VALUES('prj_a','dev','LOG_LEVEL','debug','member:mem_owner',?)", ctx.now())
}

describe("projects.find: the project bound to a checkout's remote, for a machine", () => {
  it("answers a machine that may use the project with its environments and variable names, never a value or an item", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      bindRemotes(ctx)
      const found = (await find(ctx, "dev_member", "git@github.com:Acme/App.git")) as ProjectBinding
      expect(found).toEqual({
        id: "prj_a",
        slug: "project-a",
        defaultEnv: "dev",
        environments: [
          { name: "dev", protected: false, variables: ["LOG_LEVEL", "TOKEN"] },
          { name: "prod", protected: true, variables: ["TOKEN"] },
          { name: "staging", protected: true, variables: [] },
        ],
      })
      expect(JSON.stringify(found)).not.toContain("debug")
      expect(JSON.stringify(found)).not.toContain("key-")
    })
  })

  it("answers a machine scoped to another project, a guest's machine without a share and an unknown remote with one miss", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      bindRemotes(ctx)
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_admin'", canonicalJson({ ...WORKSPACE_FULL_SCOPE, projects: ["prj_b"] }))
      expect(await find(ctx, "dev_admin", REMOTE_B)).toMatchObject({ id: "prj_b" })
      expect(await find(ctx, "dev_guest", REMOTE_A)).toMatchObject({ id: "prj_a" })
      const misses = [await miss(ctx, "dev_admin", REMOTE_A), await miss(ctx, "dev_guest", REMOTE_B), await miss(ctx, "dev_member", "github.com/acme/absent"), await miss(ctx, "dev_member", "/not/a/remote")]
      expect(misses).toEqual(Array(4).fill({ status: 404, body: MISS }))
    })
  })

  it("builds the workspace's access state for an unknown remote as for one bound to a project out of reach, so the time taken tells them apart no more than the answer", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      bindRemotes(ctx)
      let builds = 0
      registerAccessStateProvider("projects", (ctx, credentials) => { builds += 1; return { projects: projectAccessState(ctx, credentials) } })
      try {
        const counted = async (remote: string) => { builds = 0; expect(await miss(ctx, "dev_guest", remote)).toEqual({ status: 404, body: MISS }); return builds }
        const unknown = await counted("github.com/acme/absent"), unparsed = await counted("/not/a/remote"), outOfReach = await counted(REMOTE_B)
        expect(outOfReach).toBeGreaterThan(0)
        expect([unknown, unparsed]).toEqual([outOfReach, outOfReach])
      } finally {
        registerAccessStateProvider("projects", (ctx, credentials) => ({ projects: projectAccessState(ctx, credentials) }))
      }
    })
  })

  it("answers a machine whose owner is inactive with owner_inactive for a bound remote and an unbound one alike", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      bindRemotes(ctx)
      fixtureSql(ctx).exec("UPDATE members SET status='suspended' WHERE id='mem_member'")
      const answers = [await miss(ctx, "dev_member", REMOTE_A), await miss(ctx, "dev_member", REMOTE_B), await miss(ctx, "dev_member", "github.com/acme/absent")]
      expect(answers.map((a) => (a.body as { error: string }).error)).toEqual(["owner_inactive", "owner_inactive", "owner_inactive"])
      expect(new Set(answers.map((a) => JSON.stringify(a))).size).toBe(1)
    })
  })

  it("answers a machine in another workspace with the same miss", async () => {
    const work = await projectFixture()
    const other = await projectFixture()
    await inAccess(work.tenant, (ctx) => bindRemotes(ctx))
    await inAccess(other.tenant, async (ctx) => {
      expect(await miss(ctx, "dev_owner", REMOTE_A)).toEqual({ status: 404, body: MISS })
    })
  })
})
