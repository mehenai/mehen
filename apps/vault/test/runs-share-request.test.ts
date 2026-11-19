// A member's machine refused a run with project_unshared: the
// project's managers get a project_share_requested notice, once a UTC day
// per project and member however often the machine retries, and the
// refusal's next.url is the project's page, with no query mehen would
// refuse; the notice opens its Shared with form with the member chosen.
// The notice resolves, leaving Needs you, once the project is shared.
import { describe, expect, it } from "vitest"
import { VaultError } from "../src/http.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { drainOutbox, noticeScan } from "../src/vault/areas/workspace-runtime.ts"
import { accessMember } from "./workspace-fixtures.ts"
import { noticeRows } from "../src/ui/pages/needs-you.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { projectDeviceInvocation, projectFixture, projectState, inAccess } from "./projects-workspace-fixture.ts"

const UNSHARED = { project: "prj_b", env: "dev", envSource: "flag", remote: null, worktree: "/fixture", head: null, vars: [], command: "test", argv: ["test"] }
const DAY = 86_400_000

async function refused(ctx: VaultContext, input: unknown = UNSHARED, device = "dev_kim"): Promise<VaultError> {
  try {
    await workspaceRunOps["runs.create"]!.handler(ctx, { kind: "device", deviceId: device }, input, await projectDeviceInvocation(ctx, device))
  } catch (error) {
    if (error instanceof VaultError) return error
    throw error
  }
  throw new Error("Expected the run to be refused")
}
function shareNotices(ctx: VaultContext) {
  return ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox WHERE payload LIKE '%project_share_requested%' ORDER BY account,created_at").toArray().map((r) => ({ account: r.account, payload: JSON.parse(r.payload) as Record<string, unknown> }))
}

describe("runs.create refused project_unshared", () => {
  it("tells the project's managers once a UTC day, links the refusal to the project's page and the notice to the share form with the member chosen", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const error = await refused(ctx)
      expect(error.code).toBe("project_unshared")
      expect(error.message).toBe("This project has not been shared with the owner.")
      expect(error.extra.next).toEqual({ say: "Ask an owner or project manager to share this project with Kim.", url: `${ctx.env.VAULT_ORIGIN}/w/work/projects/prj_b` })
      // Owner and admin manage prj_b by role; Kim, who asked, cannot share it.
      const first = shareNotices(ctx)
      expect(first.map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
      expect(first[0]!.payload).toMatchObject({ kind: "project_share_requested", project: { id: "prj_b", slug: "project-b" }, member: { member: "mem_kim", name: "Kim" }, device: "dev_kim" })
      // A retry the same day is refused the same way and raises nothing new.
      expect((await refused(ctx)).extra).toEqual(error.extra)
      expect(shareNotices(ctx)).toEqual(first)
      // The notice opens the form with Kim chosen, and Needs you gives it a Share action.
      const shown = drainOutbox(ctx, 100).events.filter((e) => e.payload.kind === "project_share_requested")
      const form = `${ctx.env.VAULT_ORIGIN}/w/work/projects/prj_b?share=mem_kim`
      expect(shown.map((e) => e.url)).toEqual([form, form])
      const row = noticeRows(shown.slice(0, 1), ctx.env.VAULT_ORIGIN, false).toString()
      expect(row).toContain(`could not start a run in project-b: the project is not shared with Kim`)
      expect(row).toContain(`<a class="btn primary sm" href="/w/work/projects/prj_b?share=mem_kim" data-action="share-request">Share</a>`)
      // Shared with Kim, the request resolves: it leaves Needs you and pending.
      expect(noticeScan(ctx, accessMember(projectState(ctx), "owner"), null).notices.map((n) => n.payload.kind)).toContain("project_share_requested")
      const share = { id: "shr_kim_b", project: "prj_b", subject: { kind: "member", member: "mem_kim" }, level: "use", protected: false, expiresAt: null }
      ctx.sql.exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", share.id, share.project, "member", "mem_kim", JSON.stringify(share))
      expect(noticeScan(ctx, accessMember(projectState(ctx), "owner"), null).notices.map((n) => n.payload.kind)).not.toContain("project_share_requested")
      ctx.sql.exec("DELETE FROM project_shares WHERE id=?", share.id)
      // The next UTC day raises one more.
      const now = ctx.now
      ctx.now = () => now() + DAY
      try {
        await refused(ctx)
        expect(shareNotices(ctx).length).toBe(4)
      } finally {
        ctx.now = now
      }
    })
  })

  it("tells a member who manages the project by a share, not only owners and admins, and not a member who only uses it", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const share = (id: string, member: string, level: "manage" | "use") => ctx.sql.exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", id, "prj_b", "member", member, JSON.stringify({ id, project: "prj_b", subject: { kind: "member", member }, level, protected: false, expiresAt: null }))
      share("shr_member_b", "mem_member", "manage")
      share("shr_guest_b", "mem_guest", "use")
      expect((await refused(ctx)).code).toBe("project_unshared")
      expect(shareNotices(ctx).map((n) => n.account)).toEqual(["acc_admin", "acc_member", "acc_owner"])
    })
  })

  it("tells only those who may share with a guest when the refused machine is a guest's: not a member who manages the project", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      ctx.sql.exec("INSERT INTO project_shares VALUES (?,?,?,?,?)", "shr_member_b", "prj_b", "member", "mem_member", JSON.stringify({ id: "shr_member_b", project: "prj_b", subject: { kind: "member", member: "mem_member" }, level: "manage", protected: false, expiresAt: null }))
      const error = await refused(ctx, UNSHARED, "dev_guest")
      expect(error.code).toBe("project_unshared")
      expect(error.extra.next?.url).toBe(`${ctx.env.VAULT_ORIGIN}/w/work/projects/prj_b`)
      expect(shareNotices(ctx).map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
      expect(shareNotices(ctx)[0]!.payload).toMatchObject({ member: { member: "mem_guest" } })
    })
  })

  it("leaves a team machine's refusal as it was: no notice, and no link to the project", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const error = await refused(ctx, UNSHARED, "dev_service")
      expect(error.code).toBe("project_unshared")
      expect(error.extra.next?.url).toBeUndefined()
      expect(shareNotices(ctx)).toEqual([])
    })
  })

  it("leaves other refusals as they were", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const error = await refused(ctx, { ...UNSHARED, project: "prj_missing" })
      expect(error.code).not.toBe("project_unshared")
      expect(shareNotices(ctx)).toEqual([])
    })
  })
})
