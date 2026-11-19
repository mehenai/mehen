// The approval dial (areas/approval-dial-workspace.ts): how often Mehen
// asks in a workspace. Let it work lets a held request through as posture
// trust would, still uses an approval a person already gave, and refuses,
// never asks, where a new ask would be opened; Ask on writes (and no
// setting) is the relay as it was. Asking less needs the passkey over both
// levels, asking more does not, only owners and admins change it, and each
// change is audited with its before and after. The route, through
// worker.fetch, is in workspace-settings.test.ts.
import { afterEach, describe, expect, it, vi } from "vitest"
import type { WorkspaceSettingsView, WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { settingsArea } from "../src/vault/areas/settings-workspace.ts"
import { setSetting, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import { credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { DELETE_COMMENT, OPEN_ISSUE, UNREVIEWED, relayAs, seedGithub, setPosture } from "./postures-test-support.ts"
import { signMandate, terms } from "./mandates-test-support.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import type { ApprovalSubject } from "@mehen/protocol/api"
import { auditLine } from "../src/ui/wording.ts"
import { createProof, type ApprovalBundleCreated, type WorkspaceRunCreated } from "@mehen/protocol"
import { authoriseWorkspaceRelay, workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { registerCredentialProvider, registerCredentialServices } from "../src/vault/areas/items-workspace.ts"
import type { WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { deviceInvocation, devicePrincipal } from "./credentials-test-support.ts"
import { PROJECT_RUN_INPUT, projectFixture } from "./projects-workspace-fixture.ts"
import { runAsk } from "./approvals-batch-support.ts"

afterEach(() => { vi.restoreAllMocks() })

const ops = settingsArea.workspaceOps!
const audits = (ctx: VaultContext, action: string) => ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action=?", action).toArray().map((row) => ({ ...row, detail: JSON.parse(row.detail) as Record<string, unknown> }))
const asks = (ctx: VaultContext) => ctx.sql.exec("SELECT id FROM approvals").toArray().length
const withEnv = (ctx: VaultContext, env: Partial<VaultContext["env"]>): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, ...env } })
const read = (ctx: VaultContext, role: string) => ops["access.settings"]!.handler(ctx, memberPrincipal(ctx, role), {}, memberInvocation(ctx, role)) as WorkspaceSettingsView
async function change(ctx: VaultContext, role: string, before: string, after: string, signed?: WorkspaceStepUpAction): Promise<unknown> {
  return await ops["access.approvals"]!.handler(ctx, memberPrincipal(ctx, role), { before, after }, memberInvocation(ctx, role, signed))
}
async function refusal(run: () => Promise<unknown> | unknown): Promise<VaultError> {
  try { await run() } catch (error) { if (error instanceof VaultError) return error; throw error }
  throw new Error("Expected a refusal")
}
const LIKE_TRUST = "This request would need a person's approval, and this workspace is set to Let it work, so the vault refuses it instead of asking."
const at = (ctx: VaultContext, ms: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
// Every trace a new ask leaves: its row, its audit row, the bytes a rule
// could be made from, and the posture nudge's count.
const askTraces = (ctx: VaultContext) => ({
  approvals: ctx.sql.exec("SELECT id,status,policy_status,superseded_by FROM approvals ORDER BY created_at,id").toArray(),
  requested: ctx.sql.exec("SELECT seq FROM audit WHERE action='approval.request'").toArray().length,
  anchors: ctx.sql.exec("SELECT source FROM policy_rule_anchors").toArray().length,
  counts: ctx.sql.exec("SELECT item_id,asked FROM posture_ask_counts").toArray(),
})
// An approval of this held request, decided by the owner as the page does.
async function approve(ctx: VaultContext, id: string): Promise<void> {
  const row = workspaceApproval(ctx, id)!
  const subject = JSON.parse(row.subject) as ApprovalSubject
  await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "owner"), { id, decision: "approve" }, memberInvocation(ctx, "owner", { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }))
}
async function heldApproval(ctx: VaultContext, request: Record<string, unknown>, device = "dev_owner"): Promise<string> {
  const { error } = await relayAs(ctx, device, request)
  expect(error?.code).toBe("approval_required")
  return error!.extra.approval as string
}
const NEVER = "Let it work never covers protected environments, browser fill or pushes into other services, and refuses machines its trust does not reach, such as team machines and guests'."

describe("Let it work in the relay", () => {
  it("lets a held write on a template credential through as trust would, with no ask, and records the use", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      const before = asks(ctx)
      setSetting(ctx, "approval_dial", "work")
      for (const request of [OPEN_ISSUE, UNREVIEWED]) {
        const relayed = await relayAs(ctx, "dev_owner", request)
        expect(relayed.error).toBeNull()
        expect(relayed.material).not.toHaveProperty("postures")
        expect(relayed.material).not.toHaveProperty("mandate")
      }
      expect(asks(ctx)).toBe(before)
      expect(audits(ctx, "approvals.use").map((row) => row.detail)).toEqual([
        { entry: "github.issue-create", method: "POST", host: "api.github.com", item: expect.any(String), outcome: "work", run: null },
        { entry: "unreviewed", method: "POST", host: "api.github.com", item: expect.any(String), outcome: "work", run: null },
      ])
      expect(JSON.stringify(audits(ctx, "approvals.use"))).not.toContain("/repos/")
    })
  })

  it("refuses a floor route with forbidden and the floor's reason, never approval_required, and opens no ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      const { error } = await relayAs(ctx, "dev_owner", DELETE_COMMENT)
      expect(error?.code).toBe("forbidden")
      expect(error?.message).toBe(`${LIKE_TRUST} This request deletes or removes something, so it asks every time. ${NEVER}`)
      expect(error?.extra).toEqual({ dialRefused: "rule.destructive", next: { url: "https://vault.test/w/work/items/github-work", say: "Nothing is waiting on a person. To have a person decide requests like this one, an owner or admin sets the workspace back to Ask on writes in Settings." } })
      expect(asks(ctx)).toBe(0)
      expect(audits(ctx, "approvals.refuse").map((row) => row.detail)).toEqual([{ reason: "rule.destructive", method: "DELETE", host: "api.github.com", item: expect.any(String), outcome: "refused:forbidden", run: null }])
      expect(audits(ctx, "approvals.use")).toEqual([])
    })
  })

  it("still refuses a request outside the binding as binding_refused", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      const { error } = await relayAs(ctx, "dev_owner", { ...OPEN_ISSUE, url: "https://api.example.com/repos/acme/app/issues" })
      expect(error?.code).toBe("binding_refused")
      expect(audits(ctx, "approvals.use")).toEqual([])
    })
  })

  // Only where a new ask would be opened does Let it work refuse: an
  // approval a person gave before the dial moved is still spent, once.
  it("uses an approval granted before the dial moved to Let it work, once, then refuses", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const asked = await relayAs(ctx, "dev_owner", DELETE_COMMENT)
      expect(asked.error?.code).toBe("approval_required")
      const approval = asked.error?.extra.approval as string
      await approve(ctx, approval)
      setSetting(ctx, "approval_dial", "work")
      const before = asks(ctx)
      const used = await relayAs(ctx, "dev_owner", { ...DELETE_COMMENT, approval })
      expect(used.error).toBeNull()
      expect(audits(ctx, "approvals.use")).toEqual([])
      const again = await relayAs(ctx, "dev_owner", { ...DELETE_COMMENT, approval })
      expect(again.error?.code).toBe("forbidden")
      expect(again.error?.extra.dialRefused).toBe("rule.destructive")
      expect(asks(ctx)).toBe(before)
    })
  })

  it("reaches only machines whose owner manages the credential's home, and refuses the rest instead of asking", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-work", { kind: "project", project: "prj_a" })
      setSetting(ctx, "approval_dial", "work")
      for (const device of ["dev_owner", "dev_admin", "dev_kim"]) expect((await relayAs(ctx, device, OPEN_ISSUE)).error, device).toBeNull()
      for (const device of ["dev_member", "dev_service", "dev_guest"]) {
        const { error } = await relayAs(ctx, device, OPEN_ISSUE)
        expect(error?.code, device).toBe("forbidden")
        expect(error?.extra.dialRefused, device).toBe("machine")
      }
      expect(asks(ctx)).toBe(0)
    })
  })

  it("refuses what a credential no catalogue covers would ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      ctx.sql.exec("UPDATE items SET binding=? WHERE slug='github-work'", JSON.stringify({ hosts: ["api.example.com"] }))
      setSetting(ctx, "approval_dial", "work")
      const { error } = await relayAs(ctx, "dev_owner", { ...OPEN_ISSUE, url: "https://api.example.com/v1/things" })
      expect(error?.code).toBe("forbidden")
      expect(error?.extra.dialRefused).toBe("unreviewed")
    })
  })

  // Order: rules, grants, postures, the dial, then the machine's mandate,
  // then the refusal. What the dial covers is never a mandate use; what only
  // a mandate covers still goes through on it.
  it("is asked after a credential's posture and before the machine's mandate", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      setSetting(ctx, "approval_dial", "work")
      const covered = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(covered.error).toBeNull()
      expect(covered.material).not.toHaveProperty("mandate")
      const deleted = await relayAs(ctx, "dev_owner", DELETE_COMMENT)
      expect(deleted.error).toBeNull()
      expect(deleted.material).toMatchObject({ mandate: mandate.id })
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).material).toMatchObject({ postures: ["routine"] })
      expect(audits(ctx, "approvals.use")).toHaveLength(1)
    })
  })

  it("refuses with conflict when the dial moved between the hook and the last check", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      const real = ctx.storage.transactionSync.bind(ctx.storage)
      let moved = false
      vi.spyOn(ctx.storage, "transactionSync").mockImplementation(((fn: () => unknown) => {
        if (!moved) { moved = true; setSetting(ctx, "approval_dial", "writes") }
        return real(fn)
      }) as typeof ctx.storage.transactionSync)
      const { error } = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(error?.code).toBe("conflict")
      expect(audits(ctx, "approvals.use")).toEqual([])
    })
  })

  it("leaves a managed workspace asking its platform, whatever is stored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner", createdAt: ctx.now() })
      const { error } = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(error?.code).toBe("approval_required")
      expect(error?.message).toBe("This request needs approval.")
      expect(audits(ctx, "approvals.use")).toEqual([])
      expect(read(ctx, "owner")).not.toHaveProperty("approvals")
      expect((await refusal(() => change(ctx, "owner", "work", "writes"))).message).toBe("The platform decides what is asked in this workspace.")
    })
  })
})

describe("Ask on writes in the relay", () => {
  it("asks for a held write as before, unset or at writes", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const unset = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      setSetting(ctx, "approval_dial", "writes")
      const writes = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      for (const { error } of [unset, writes]) {
        expect(error?.code).toBe("approval_required")
        expect(error?.message).toBe("This request needs a human's approval.")
      }
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error?.code).toBe("approval_required")
      expect(audits(ctx, "approvals.refuse")).toEqual([])
    })
  })

  // A level stored before there were two, or one this build cannot read,
  // is Ask on writes.
  it("reads a stored level it does not know as Ask on writes", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "every")
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect(read(ctx, "owner").approvals).toEqual({ level: "writes", askLess: true, askMore: false })
    })
  })

  it("reads Let it work as Ask on writes with APPROVAL_DIAL off here", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      const off = withEnv(ctx, { APPROVAL_DIAL: "tn_elsewhere0001" })
      expect((await relayAs(off, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect((await relayAs(off, "dev_owner", DELETE_COMMENT)).error?.code).toBe("approval_required")
    })
  })
})

describe("changing the dial", () => {
  const LESS = { type: "workspace.approvals", before: "writes", after: "work" } as const

  it("asks less only with a passkey over exactly both levels, and audits before and after", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const unsigned = await refusal(() => change(ctx, "owner", "writes", "work"))
      expect([unsigned.code, unsigned.message]).toEqual(["forbidden", "This needs a passkey confirmation of the exact action."])
      for (const other of [{ type: "workspace.unfreeze" }, { type: "item.posture", item: "itm_x", digest: "d", level: "trust" }] as WorkspaceStepUpAction[])
        expect((await refusal(() => change(ctx, "owner", "writes", "work", other))).code, JSON.stringify(other)).toBe("forbidden")
      expect(read(ctx, "owner").approvals).toEqual({ level: "writes", askLess: true, askMore: false })
      expect((await refusal(() => change(ctx, "owner", "writes", "every", LESS))).code).toBe("bad_request")
      expect(await change(ctx, "owner", "writes", "work", LESS)).toEqual({ level: "work" })
      expect(read(ctx, "owner").approvals).toEqual({ level: "work", askLess: false, askMore: true })
      expect(audits(ctx, "workspace.approvals")).toEqual([{ actor: "member:mem_owner", target: ctx.tenant, detail: { before: "writes", after: "work" } }])
    })
  })

  it("asks more with no passkey, and audits it too", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      setSetting(ctx, "approval_dial", "work")
      expect(await change(ctx, "admin", "work", "writes")).toEqual({ level: "writes" })
      expect(read(ctx, "admin").approvals).toEqual({ level: "writes", askLess: true, askMore: false })
      expect(audits(ctx, "workspace.approvals")).toEqual([{ actor: "member:mem_admin", target: ctx.tenant, detail: { before: "work", after: "writes" } }])
    })
  })

  it("is for owners and admins: a member or a guest is refused either way, and reads the level with no rights", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      setSetting(ctx, "approval_dial", "work")
      for (const role of ["member", "guest", "kim"]) {
        expect((await refusal(() => change(ctx, role, "work", "writes"))).code, role).toBe("forbidden")
        expect((await refusal(() => change(ctx, role, "work", "writes", { ...LESS, before: "writes", after: "work" }))).code, role).toBe("forbidden")
        expect(read(ctx, role).approvals, role).toEqual({ level: "work", askLess: false, askMore: false })
      }
      expect(audits(ctx, "workspace.approvals")).toEqual([])
    })
  })

  it("refuses a change from a level the page no longer shows", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const stale = await refusal(() => change(ctx, "owner", "work", "writes"))
      expect([stale.code, stale.message]).toEqual(["conflict", "How often this workspace asks changed; review and try again."])
      setSetting(ctx, "approval_dial", "work")
      expect((await refusal(() => change(ctx, "owner", "writes", "work", LESS))).code).toBe("conflict")
      expect(audits(ctx, "workspace.approvals")).toEqual([])
    })
  })

  it("only asks more while frozen or cooling off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      setSetting(ctx, "frozen", true)
      expect((await refusal(() => change(ctx, "owner", "writes", "work", LESS))).code).toBe("frozen")
      expect(read(ctx, "owner").approvals).toEqual({ level: "writes", askLess: false, askMore: false })
      setSetting(ctx, "approval_dial", "work")
      expect(read(ctx, "owner").approvals).toEqual({ level: "work", askLess: false, askMore: true })
      expect(await change(ctx, "owner", "work", "writes")).toEqual({ level: "writes" })
      setSetting(ctx, "frozen", false)
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + 86_400_000, notice: "ntc_owner" })
      expect((await refusal(() => change(ctx, "owner", "writes", "work", LESS))).code).toBe("forbidden")
      expect(read(ctx, "owner").approvals).toEqual({ level: "writes", askLess: false, askMore: false })
      setSetting(ctx, "approval_dial", "work")
      expect(await change(ctx, "owner", "work", "writes")).toEqual({ level: "writes" })
    })
  })

  it("cannot be changed with APPROVAL_DIAL off, which the read leaves out", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const off = withEnv(ctx, { APPROVAL_DIAL: "off" })
      const refused = await refusal(() => change(off, "owner", "writes", "work", LESS))
      expect([refused.code, refused.message]).toEqual(["forbidden", "How often this workspace asks cannot be changed here yet."])
      expect((await refusal(() => change(off, "owner", "work", "writes"))).code).toBe("forbidden")
      expect(read(off, "owner")).toEqual({ frozen: false, rights: { rename: true, freeze: true, unfreeze: true } })
      expect(audits(ctx, "workspace.approvals")).toEqual([])
    })
  })
})

describe("the dial in Activity", () => {
  const said = (action: string, actor: string, target: string, detail: Record<string, unknown>) => {
    const line = auditLine({ actor, action, target, detail: JSON.stringify(detail) }, { self: "mem_owner", devices: new Map([["dev_owner", "Laptop"]]) })
    return line.actor + line.pieces.map((p) => p.text).join("")
  }
  it("says each change with its before and after, and each use and refusal without a path", () => {
    expect(said("workspace.approvals", "member:mem_owner", "tn_x", { before: "writes", after: "work" })).toBe("You changed how often Mehen asks here from Ask on writes to Let it work")
    expect(said("approvals.use", "device:dev_owner", "github-work", { method: "POST", host: "api.github.com", outcome: "work" })).toBe("An agent on Laptop used github-work without asking, as Let it work lets a trusted machine: POST api.github.com")
    expect(said("approvals.refuse", "device:dev_owner", "github-work", { method: "DELETE", host: "api.github.com", outcome: "refused:forbidden" })).toBe("An agent on Laptop tried to use github-work for DELETE api.github.com. Refused: it would need a person, and Let it work refuses instead of asking.")
  })
})

// The paths around the relay's ask at Let it work: a real protected
// environment, a placeholder-only workload's run, a bundle, and the asks
// that are not the relay's (a protected run, fill and a push, whose own
// tests are in browser-fill.test.ts and push-workspace.test.ts).
describe("Let it work on the other paths", () => {
  it("refuses an item-mode use in a real protected environment, asking no one", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialProvider()
      ctx.sql.exec("UPDATE items SET policy=?", JSON.stringify({ default: "allow", rules: [] }))
      ctx.sql.exec("UPDATE vars SET item='key-workspace' WHERE env='prod'")
      for (const project of ["prj_a", "prj_b"]) ctx.sql.exec("INSERT OR IGNORE INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES(?,'prod','TOKEN','key-workspace','key','member:mem_owner',?)", project, ctx.now())
      const request = { item: "key-workspace", method: "GET", url: "https://api.example.com/test", headers: [], context: { project: "prj_a", environment: "prod" } }
      const relay = async () => { try { await authoriseWorkspaceRelay(ctx, devicePrincipal(), request, await deviceInvocation(ctx)); return null } catch (error) { if (error instanceof VaultError) return error; throw error } }
      expect((await relay())?.code).toBe("approval_required")
      const before = askTraces(ctx)
      setSetting(ctx, "approval_dial", "work")
      const refused = await relay()
      expect(refused?.code).toBe("forbidden")
      expect(refused?.message).toBe(`${LIKE_TRUST} This credential is used in a protected environment, which always needs a person. ${NEVER}`)
      expect(refused?.extra.dialRefused).toBe("protected")
      expect(askTraces(ctx)).toEqual(before)
    })
  })

  it("still asks a person to start a protected run", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      setSetting(ctx, "approval_dial", "work")
      const row = await runAsk(ctx)
      expect(row.status).toBe("pending")
    })
  })

  it("lets a placeholder-only workload's run through as trust would, and refuses its floor route", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      ctx.sql.exec("UPDATE items SET binding=? WHERE slug='key-workspace'", JSON.stringify({ hosts: ["api.github.com"] }))
      const now = ctx.now()
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES ('wkl_build','dev_owner','build','{}','thumb-build',?,?,?,?)", JSON.stringify({ modes: ["placeholder"] }), now, now + 3_600_000, now + 3_600_000)
      const principal = { kind: "device" as const, deviceId: "dev_owner", workload: "wkl_build" }
      const invocation = async (url: string): Promise<WorkspaceInvocationContext> => {
        const proof = await createProof({ deviceId: "dev_owner", workloadId: "wkl_build", sign: async () => new Uint8Array(64) }, { method: "POST", url }, { tenant: ctx.tenant })
        return { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url, bodyHash: "" } }
      }
      const run = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, await invocation("https://vault.test/v1/runs")) as WorkspaceRunCreated
      const placeholder = run.vars.find((v) => v.delivery === "placeholder")!.value
      const viaRun = (request: { method: string; url: string; headers: [string, string][]; body?: string }) => ({ run: run.run, ...request, headers: [...request.headers, ["Authorization", `Bearer ${placeholder}`]] })
      const relay = async (request: Record<string, unknown>) => { try { await authoriseWorkspaceRelay(ctx, principal, request, await invocation("https://vault.test/v1/relay")); return null } catch (error) { if (error instanceof VaultError) return error; throw error } }
      expect((await relay(viaRun(OPEN_ISSUE)))?.code).toBe("approval_required")
      const before = asks(ctx)
      setSetting(ctx, "approval_dial", "work")
      expect(await relay(viaRun(OPEN_ISSUE))).toBeNull()
      expect(audits(ctx, "approvals.use").map((row) => row.detail)).toEqual([{ entry: "github.issue-create", method: "POST", host: "api.github.com", by: { workload: { id: "wkl_build", label: "build" } }, item: expect.any(String), outcome: "work", run: run.run }])
      const refused = await relay(viaRun(DELETE_COMMENT))
      expect(refused?.code).toBe("forbidden")
      expect(refused?.extra.dialRefused).toBe("rule.destructive")
      expect(asks(ctx)).toBe(before)
    })
  })

  it("reports a bundle's routine write allowed and its floor route refused with the reason, asking nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "approval_dial", "work")
      const answer = await workspaceRelayOps["approvals.bundle"]!.handler(ctx, devicePrincipal("dev_owner"), { requests: [{ item: "github-work", ...OPEN_ISSUE }, { item: "github-work", ...DELETE_COMMENT }] }, await deviceInvocation(ctx, "dev_owner")) as ApprovalBundleCreated
      expect(answer.results).toEqual([
        { index: 0, outcome: "allowed" },
        { index: 1, outcome: "refused", error: { error: "forbidden", message: `${LIKE_TRUST} This request deletes or removes something, so it asks every time. ${NEVER}`, next: expect.objectContaining({ url: "https://vault.test/w/work/items/github-work" }), dialRefused: "rule.destructive" } },
      ])
      expect(asks(ctx)).toBe(0)
      expect(audits(ctx, "approvals.use")).toEqual([])
    })
  })
})

// noAsk in prepareApprovedUse: a grant that matches is spent, found by its
// binding when no id is sent; one that changed, expired or was revoked is
// refused, and no refusal leaves an ask, its audit row, a rule anchor or a
// posture ask count behind.
describe("an approval a person already gave, at Let it work", () => {
  it("is found by the request itself when it names no approval id", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await approve(ctx, await heldApproval(ctx, DELETE_COMMENT))
      setSetting(ctx, "approval_dial", "work")
      const before = askTraces(ctx)
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error).toBeNull()
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error?.extra.dialRefused).toBe("rule.destructive")
      expect(askTraces(ctx).approvals).toHaveLength(before.approvals.length)
    })
  })

  for (const [why, spoil] of [
    ["changed", (ctx: VaultContext) => { ctx.sql.exec("UPDATE items SET config_rev=config_rev+1 WHERE slug='github-work'"); return ctx }],
    ["expired", (ctx: VaultContext) => at(ctx, ctx.now() + 11 * 60_000)],
    ["revoked", (ctx: VaultContext) => { ctx.sql.exec("UPDATE protected_use_grants SET revoked_at=?", ctx.now()); return ctx }],
  ] as const) {
    it(`refuses one whose grant ${why}, and creates no ask`, async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (raw) => {
        const ctx = withEnv(raw, { POLICY_RULES: "on" })
        await seedGithub(ctx)
        const approval = await heldApproval(ctx, DELETE_COMMENT)
        await approve(ctx, approval)
        setSetting(ctx, "approval_dial", "work")
        const before = askTraces(ctx)
        const later = spoil(ctx)
        for (const request of [{ ...DELETE_COMMENT, approval }, DELETE_COMMENT]) {
          const { error } = await relayAs(later, "dev_owner", request)
          expect(error?.code, why).toBe("forbidden")
          expect(error?.extra.dialRefused, why).toBe("rule.destructive")
        }
        expect(askTraces(ctx)).toEqual(before)
      })
    })
  }

  it("leaves the earlier pending ask a request replaces unchanged", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const earlier = await heldApproval(ctx, DELETE_COMMENT)
      setSetting(ctx, "approval_dial", "work")
      const before = askTraces(ctx)
      const { error } = await relayAs(ctx, "dev_owner", { ...DELETE_COMMENT, replaces: earlier })
      expect(error?.extra.dialRefused).toBe("rule.destructive")
      expect(askTraces(ctx)).toEqual(before)
      expect(workspaceApproval(ctx, earlier)).toMatchObject({ status: "pending", policy_status: null, superseded_by: null })
    })
  })

  it("writes no ask, audit row, rule anchor or posture count where the relay would have asked", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (raw) => {
      const ctx = withEnv(raw, { POLICY_RULES: "on" })
      await seedGithub(ctx)
      await seedGithub(ctx, "github-team", { kind: "project", project: "prj_a" })
      setSetting(ctx, "approval_dial", "writes")
      await heldApproval(ctx, UNREVIEWED, "dev_member")
      const asked = askTraces(ctx)
      expect([asked.requested, asked.anchors, asked.counts.length]).toEqual([1, 1, 1])
      setSetting(ctx, "approval_dial", "work")
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error?.code).toBe("forbidden")
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE, "github-team")).error?.extra.dialRefused).toBe("machine")
      expect(askTraces(ctx)).toEqual(asked)
    })
  })
})

describe("Let it work with postures switched off", () => {
  it("still lets through what trust would and refuses the rest, and can still be changed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (raw) => {
      const ctx = withEnv(raw, { POLICY_POSTURES: "off" })
      await seedGithub(ctx)
      expect(await change(ctx, "owner", "writes", "work", { type: "workspace.approvals", before: "writes", after: "work" })).toEqual({ level: "work" })
      const allowed = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(allowed.error).toBeNull()
      expect(allowed.material).not.toHaveProperty("postures")
      expect(audits(ctx, "approvals.use")).toHaveLength(1)
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error?.extra.dialRefused).toBe("rule.destructive")
      expect(audits(ctx, "posture.use")).toEqual([])
    })
  })
})
