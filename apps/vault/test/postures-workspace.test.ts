// How careful a credential is (areas/postures-workspace.ts): setting a
// posture through the action a passkey signs, what a person's and a
// machine's description show, the nudge's counts and quiet, and the
// storage migration. The relay's use is in relay-approval-hook.test.ts.
import { describe, expect, it } from "vitest"
import type { WorkspaceItemDescription, WorkspaceStepUpAction } from "@mehen/protocol"
import { itemPostureDigest } from "@mehen/protocol/policy-rules"
import type { VaultContext } from "../src/vault/core.ts"
import { itemsArea, ITEM_POSTURES_MIGRATION } from "../src/vault/areas/items.ts"
import { checkedCredential, prepareCredential, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { workspacePostureOps } from "../src/vault/areas/postures-workspace.ts"
import { workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { setSetting, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
import { OPEN_ISSUE, UNREVIEWED, postureAction, postureRow, relayAs, seedGithub, setPosture } from "./postures-test-support.ts"
import { decideBatch } from "./approvals-batch-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

const DAY = 86_400_000
const at = (ctx: VaultContext, ms: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
const audits = (ctx: VaultContext, action: string) => ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action=?", action).toArray().map((row) => ({ ...row, detail: JSON.parse(row.detail) as Record<string, unknown> }))
const describeAs = (ctx: VaultContext, role: string, slug = "github-work") => workspaceItemOps["items.describe"].handler(ctx, memberPrincipal(ctx, role), { slug }, memberInvocation(ctx, role)) as WorkspaceItemDescription
async function refusal(run: () => Promise<unknown> | unknown): Promise<{ code: string; message: string }> {
  try { await run() } catch (error) { return { code: (error as { code: string }).code, message: (error as Error).message } }
  throw new Error("Expected a refusal")
}

describe("setting how careful a credential is", () => {
  it("rebuilds the signed action from the item, the posture, its catalogue and the revision shown, and keeps config_rev", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      const before = checkedCredential(ctx, "github-work")!
      const action = await postureAction(ctx, "owner", "github-work", { level: "routine", machines: ["dev_admin", "dev_member"] }, 0)
      expect(action).toEqual({ type: "item.posture", item: item.id, level: "routine", digest: await itemPostureDigest({ item: item.id, level: "routine", machines: ["dev_admin", "dev_member"], catalogue: "github", catalogueVersion: 1, before: 0 }) })
      const shown = await setPosture(ctx, "owner", "github-work", { level: "routine", machines: ["dev_admin", "dev_member"] })
      expect(shown).toEqual({ level: "routine", machines: [{ id: "dev_admin", name: expect.any(String) }, { id: "dev_member", name: expect.any(String) }], catalogue: { template: "github", version: 1, current: 1 }, setBy: "owner", setAt: expect.any(String), rev: 1, eligible: expect.any(Array) })
      expect(postureRow(ctx)).toEqual({ level: "routine", machines: '["dev_admin","dev_member"]', catalogue: "github", catalogue_version: 1, rev: 1, set_by: "member:mem_owner" })
      const after = checkedCredential(ctx, "github-work")!
      expect([after.configRev, after.version, after.policy]).toEqual([before.configRev, before.version, before.policy])
      expect(audits(ctx, "posture.set").map((row) => row.detail)).toEqual([{ before: "ask", after: "routine", machines: 2, item: item.id, outcome: "routine", run: null }])
    })
  })

  it("refuses machines out of order or twice, a stale revision, and a signature over another posture", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      expect((await refusal(() => postureAction(ctx, "owner", "github-work", { level: "routine", machines: ["dev_member", "dev_admin"] }, 0))).code).toBe("bad_request")
      expect((await refusal(() => postureAction(ctx, "owner", "github-work", { level: "routine", machines: ["dev_admin", "dev_admin"] }, 0))).code).toBe("bad_request")
      expect((await refusal(() => postureAction(ctx, "owner", "github-work", { level: "routine", machines: ["dev_gone"] }, 0))).code).toBe("bad_request")
      const stale = await postureAction(ctx, "owner", "github-work", { level: "trust", machines: null }, 0)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      expect(await refusal(() => postureAction(ctx, "owner", "github-work", { level: "trust", machines: null }, 0))).toEqual({ code: "conflict", message: "How careful this credential is changed; review and try again." })
      expect((await refusal(() => workspacePostureOps["items.posture"].handler(ctx, memberPrincipal(ctx, "owner"), { slug: "github-work", posture: { level: "trust", machines: null }, rev: 0 }, memberInvocation(ctx, "owner", stale)))).code).toBe("conflict")
      const routine = await postureAction(ctx, "owner", "github-work", { level: "routine", machines: ["dev_admin"] }, 1)
      expect((await refusal(() => workspacePostureOps["items.posture"].handler(ctx, memberPrincipal(ctx, "owner"), { slug: "github-work", posture: { level: "trust", machines: null }, rev: 1 }, memberInvocation(ctx, "owner", routine)))).code).toBe("conflict")
      expect((await refusal(() => workspacePostureOps["items.posture"].handler(ctx, memberPrincipal(ctx, "owner"), { slug: "github-work", posture: { level: "trust", machines: null }, rev: 1 }, memberInvocation(ctx, "owner")))).code).toBe("forbidden")
      expect(postureRow(ctx)).toMatchObject({ level: "routine", rev: 1 })
    })
  })

  it("offers only ask on a credential no catalogue covers", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "tasks-key")
      expect(await refusal(() => postureAction(ctx, "owner", "tasks-key", { level: "routine", machines: null }, 0))).toEqual({ code: "bad_request", message: "Nobody has reviewed this service's routes, so this credential can only ask for every change." })
      expect(await setPosture(ctx, "owner", "tasks-key", { level: "ask", machines: null })).toMatchObject({ level: "ask", catalogue: null, rev: 1 })
    })
  })

  it("is for someone who may change the credential: its home's managers, or a private credential's owner alone", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      for (const role of ["member", "guest"]) expect((await refusal(() => postureAction(ctx, role, "github-work", { level: "routine", machines: null }, 0))).code).toMatch(/forbidden|not_found/)
      expect(describeAs(ctx, "member")).not.toHaveProperty("posture")
      expect(describeAs(ctx, "admin").posture).toMatchObject({ level: "ask", rev: 0 })
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      expect(await setPosture(ctx, "member", "github-mine", { level: "trust", machines: null })).toMatchObject({ level: "trust" })
      expect((await refusal(() => postureAction(ctx, "owner", "github-mine", { level: "ask", machines: null }, 1))).code).toMatch(/forbidden|not_found/)
    })
  })

  it("tells someone who may see the credential but not set it nothing of its posture's revision", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      expect(describeAs(ctx, "member")).toMatchObject({ slug: "github-work" })
      const stale = await refusal(() => postureAction(ctx, "member", "github-work", { level: "trust", machines: null }, 0))
      const current = await refusal(() => postureAction(ctx, "member", "github-work", { level: "trust", machines: null }, 1))
      expect(stale.code).toBe("forbidden")
      expect(stale).toEqual(current)
      expect(await refusal(() => postureAction(ctx, "member", "github-work", { level: "trust", machines: ["dev_gone"] }, 1))).toEqual(current)
      expect(await refusal(() => postureAction(ctx, "owner", "github-work", { level: "trust", machines: null }, 0))).toEqual({ code: "conflict", message: "How careful this credential is changed; review and try again." })
    })
  })

  it("refuses someone whose rights went between the action and the apply as forbidden, even when the catalogue changed too", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const action = await postureAction(ctx, "admin", "github-work", { level: "routine", machines: null }, 0)
      // The admin is demoted and the hosts change after the action is checked and before it is applied.
      const storage = Object.assign(Object.create(ctx.storage) as DurableObjectStorage, { transactionSync: <T>(fn: () => T): T => {
        fixtureSql(ctx).exec("UPDATE members SET role='member' WHERE id='mem_admin'")
        ctx.sql.exec("UPDATE items SET binding=? WHERE slug='github-work'", JSON.stringify({ hosts: ["api.example.com"] }))
        return ctx.storage.transactionSync(fn)
      } })
      const racing = Object.assign(Object.create(ctx) as VaultContext, { storage })
      expect((await refusal(() => workspacePostureOps["items.posture"].handler(racing, memberPrincipal(ctx, "admin"), { slug: "github-work", posture: { level: "routine", machines: null }, rev: 0 }, memberInvocation(ctx, "admin", action)))).code).toBe("forbidden")
      expect(postureRow(ctx)).toBeNull()
    })
  })

  it("refuses a guest routine or trust on their own credential before any passkey, and lets them keep ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-guest", { kind: "member", member: "mem_guest" })
      const refused = { code: "forbidden", message: "Guests cannot let agents carry on without asking." }
      for (const level of ["routine", "trust"] as const) {
        expect(await refusal(() => postureAction(ctx, "guest", "github-guest", { level, machines: null }, 0))).toEqual(refused)
        expect(await refusal(() => workspacePostureOps["items.posture"].handler(ctx, memberPrincipal(ctx, "guest"), { slug: "github-guest", posture: { level, machines: null }, rev: 0 }, memberInvocation(ctx, "guest")))).toEqual(refused)
      }
      expect(postureRow(ctx, "github-guest")).toBeNull()
      expect(audits(ctx, "posture.set")).toEqual([])
      expect(await setPosture(ctx, "guest", "github-guest", { level: "ask", machines: null })).toMatchObject({ level: "ask", rev: 1 })
    })
  })

  it("refuses to widen in a frozen workspace and while cooling off, and lets either go back to ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      setSetting(ctx, "frozen", true)
      expect((await refusal(() => postureAction(ctx, "owner", "github-work", { level: "trust", machines: null }, 1))).code).toBe("frozen")
      setSetting(ctx, "frozen", false)
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      expect((await refusal(() => postureAction(ctx, "owner", "github-work", { level: "trust", machines: null }, 1))).code).toBe("forbidden")
      expect(await setPosture(ctx, "owner", "github-work", { level: "ask", machines: null }, 1)).toMatchObject({ level: "ask", catalogue: { template: "github", version: 1 }, rev: 2 })
      expect(postureRow(ctx)).toMatchObject({ level: "ask", machines: null, catalogue: null, catalogue_version: null, rev: 2 })
    })
  })

  it("cannot be set with POLICY_POSTURES off here, and is not shown", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, POLICY_POSTURES: "off" } })
      expect((await refusal(() => postureAction(off, "owner", "github-work", { level: "routine", machines: null }, 0))).code).toBe("forbidden")
      expect(describeAs(off, "owner")).not.toHaveProperty("posture")
    })
  })
})

describe("a managed workspace", () => {
  it("cannot set a posture, and a posture set before it was managed goes back to ask at the next read", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "trust", machines: null })
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await refusal(() => postureAction(ctx, "owner", "github-work", { level: "ask", machines: null }, 1))).toEqual({ code: "forbidden", message: "The platform decides how careful each credential is." })
      expect(describeAs(ctx, "owner")).not.toHaveProperty("posture")
      expect(postureRow(ctx)).toMatchObject({ level: "ask", machines: null, catalogue: null, rev: 2, set_by: "system" })
      expect(audits(ctx, "posture.reset")).toEqual([{ actor: "system", target: "github-work", detail: { reason: "managed", before: "trust", item: item.id, platform: "plt_x" } }])
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
    })
  })

  it("records the reset of a private credential as the vault's act, never its owner's, with only the reason", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      await setPosture(ctx, "member", "github-mine", { level: "trust", machines: null })
      expect(audits(ctx, "posture.set").map((row) => row.detail)).toEqual([{ action: "posture.set", at: expect.any(Number), actor: { kind: "member", member: "mem_member" }, session: expect.any(String), item: item.id, slug: "github-mine", outcome: "trust", run: null }])
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(describeAs(ctx, "member", "github-mine")).not.toHaveProperty("posture")
      expect(postureRow(ctx, "github-mine")).toMatchObject({ level: "ask", set_by: "system" })
      expect(audits(ctx, "posture.reset")).toEqual([{ actor: "system", target: "github-mine", detail: { item: item.id, outcome: "managed", platform: "plt_x" } }])
    })
  })
})

describe("a posture through rotation and restore", () => {
  // The posture is about routes, not the value: it stays, and each use reads
  // the value's prefix again, so a live key put back is still never covered.
  it("stays through both, and never covers a live key a restore put back", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const input = { ...credentialInput("github-work"), binding: { hosts: ["api.github.com"] }, policy: { default: "approve" as const, rules: [] }, secretFields: { key: "sk_live_never-returned" } }
      const prepared = await prepareCredential(ctx, input, null)
      ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE)).error?.code).toBe("approval_required")
      const rotated = await prepareCredential(ctx, { ...input, secretFields: { key: "plain-never-returned" } }, checkedCredential(ctx, "github-work")!)
      ctx.storage.transactionSync(() => storeCredential(ctx, rotated, memberPrincipal(ctx), "item.rotate"))
      expect(postureRow(ctx)).toMatchObject({ level: "routine", rev: 1 })
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE)).error).toBeNull()
      const terms = { version: checkedCredential(ctx, "github-work")!.version, previous: 1 }
      const action = await workspaceItemOps["items.action"].handler(ctx, memberPrincipal(ctx), { slug: "github-work", action: "restore", ...terms }, memberInvocation(ctx)) as WorkspaceStepUpAction
      await workspaceItemOps["items.restore"].handler(ctx, memberPrincipal(ctx), { slug: "github-work", ...terms }, memberInvocation(ctx, "owner", action))
      expect(postureRow(ctx)).toMatchObject({ level: "routine", rev: 1 })
      expect((await relayAs(ctx, "dev_member", { ...OPEN_ISSUE, body: Buffer.from(JSON.stringify({ title: "After the restore" })).toString("base64url") })).error?.code).toBe("approval_required")
      expect(audits(ctx, "posture.use")).toHaveLength(1)
    })
  })
})

describe("the machines a person's page may tick", () => {
  const eligible = (ctx: VaultContext, role: string, slug = "github-work") => [...(describeAs(ctx, role, slug).posture?.eligible ?? [])].sort((a, b) => a.device.localeCompare(b.device))

  it("lists each machine at the levels that would cover it now: never a guest's, a team's at routine only, trust only for a manager of the home", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      expect(eligible(ctx, "owner")).toEqual([
        { device: "dev_admin", name: "dev_admin", levels: ["routine", "trust"] },
        { device: "dev_kim", name: "dev_kim", levels: ["routine"] },
        { device: "dev_member", name: "dev_member", levels: ["routine"] },
        { device: "dev_owner", name: "dev_owner", levels: ["routine", "trust"] },
        { device: "dev_service", name: "dev_service", levels: ["routine"] },
      ])
    })
  })

  it("leaves out a machine the person may not read", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      expect(eligible(ctx, "member", "github-mine")).toEqual([{ device: "dev_member", name: "dev_member", levels: ["routine", "trust"] }])
    })
  })
})

describe("what a machine learns of a posture", () => {
  it("the level, whether it lets this key through, and the catalogue; never which machines", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: ["dev_admin"] })
      const read = async (device: string) => workspaceItemOps["items.describe"].handler(ctx, devicePrincipal(device), { slug: "github-work" }, await deviceInvocation(ctx, device)) as { posture?: unknown }
      expect((await read("dev_admin")).posture).toEqual({ level: "routine", coversThisKey: true, catalogue: { template: "github", version: 1 } })
      const other = await read("dev_member")
      expect(other.posture).toEqual({ level: "routine", coversThisKey: false, catalogue: { template: "github", version: 1 } })
      expect(JSON.stringify(other)).not.toContain("dev_admin")
    })
  })
})

describe("the nudge toward a posture", () => {
  const nudges = (ctx: VaultContext, role = "owner") => workspacePostureOps["items.nudges"].handler(ctx, memberPrincipal(ctx, role), {}, memberInvocation(ctx, role)) as { nudges: { slug: string; asked: number; routine: number }[] }
  const counts = (ctx: VaultContext) => ctx.sql.exec<{ asked: number; routine: number; denied: number }>("SELECT asked,routine,denied FROM posture_ask_counts").toArray()
  // n held requests, each a new ask (a resend would find the one it opened).
  let sent = 0
  async function asks(ctx: VaultContext, n: number, request: Record<string, unknown> = OPEN_ISSUE, slug = "github-work", device = "dev_member") {
    for (let i = 0; i < n; i++) expect((await relayAs(ctx, device, { ...request, body: Buffer.from(JSON.stringify(request === UNREVIEWED ? { name: `label-${sent++}` } : { title: `Issue ${sent++}` })).toString("base64url") }, slug)).error?.code).toBe("approval_required")
  }

  it("counts each new ask once, and the routine ones, without a value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await asks(ctx, 2)
      expect((await relayAs(ctx, "dev_member", { ...OPEN_ISSUE, body: Buffer.from(JSON.stringify({ title: `Issue ${sent - 1}` })).toString("base64url") })).error?.code).toBe("approval_required")
      await asks(ctx, 1, UNREVIEWED)
      expect(counts(ctx)).toEqual([{ asked: 3, routine: 2, denied: 0 }])
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM posture_ask_counts").toArray())).not.toContain("Issue")
    })
  })

  it("names a credential asked ten times in seven days, five of them routine and none denied, to who may set it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await asks(ctx, 9)
      expect(nudges(ctx).nudges).toEqual([])
      await asks(ctx, 1)
      expect(nudges(ctx).nudges).toEqual([{ slug: "github-work", asked: 10, routine: 10 }])
      expect(nudges(ctx, "member").nudges).toEqual([])
      expect(nudges(at(ctx, ctx.now() + 7 * DAY)).nudges).toEqual([])
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      expect(nudges(ctx).nudges).toEqual([])
    })
  })

  it("never nudges a guest toward a level they cannot set, and nudges a member on their own credential", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-guest", { kind: "member", member: "mem_guest" })
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id IN ('dev_guest','dev_member')")
      await asks(ctx, 10, OPEN_ISSUE, "github-guest", "dev_guest")
      await asks(ctx, 10, OPEN_ISSUE, "github-mine", "dev_member")
      expect(nudges(ctx, "guest").nudges).toEqual([])
      expect(nudges(ctx, "member").nudges).toEqual([{ slug: "github-mine", asked: 10, routine: 10 }])
    })
  })

  it("is silenced by one deny, and by too few routine asks", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await asks(ctx, 6, UNREVIEWED)
      await asks(ctx, 4)
      expect(nudges(ctx).nudges).toEqual([])
      await asks(ctx, 1)
      expect(nudges(ctx).nudges).toEqual([{ slug: "github-work", asked: 11, routine: 5 }])
      const pending = ctx.sql.exec<{ id: string; digest: string }>("SELECT id,digest FROM approvals WHERE status='pending' LIMIT 1").toArray()[0]!
      const action: WorkspaceStepUpAction = { type: "approval.decide", approval: pending.id, digest: pending.digest, decision: "deny", constraints: { uses: 1, ttlSeconds: 600 } }
      await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "owner"), { id: pending.id, decision: "deny" }, memberInvocation(ctx, "owner", action))
      expect(counts(ctx)).toEqual([{ asked: 11, routine: 5, denied: 1 }])
      expect(nudges(ctx).nudges).toEqual([])
    })
  })

  it("counts asks denied together through decide_many as it counts single denies, and still never nudges a guest", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-batch", { kind: "member", member: "mem_member" })
      await seedGithub(ctx, "github-single", { kind: "member", member: "mem_member" })
      await seedGithub(ctx, "github-guest", { kind: "member", member: "mem_guest" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id IN ('dev_guest','dev_member')")
      for (const slug of ["github-batch", "github-single"]) await asks(ctx, 10, OPEN_ISSUE, slug, "dev_member")
      await asks(ctx, 10, OPEN_ISSUE, "github-guest", "dev_guest")
      const slugs = (role: string) => nudges(ctx, role).nudges.map((n) => n.slug).sort()
      expect(slugs("member")).toEqual(["github-batch", "github-single"])
      expect(slugs("guest")).toEqual([])
      const pending = (slug: string) => ctx.sql.exec<{ id: string; digest: string }>("SELECT id,digest FROM approvals WHERE item=? AND status='pending'", slug).toArray()
      for (const { id, digest } of pending("github-single")) {
        const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest, decision: "deny", constraints: { uses: 1, ttlSeconds: 600 } }
        await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "member"), { id, decision: "deny" }, memberInvocation(ctx, "member", action))
      }
      expect(decideBatch(ctx, "member", pending("github-batch").map(({ id }) => ({ id, decision: "deny" as const })))).toMatchObject({ approved: 0, denied: 10, skipped: 0 })
      const counted = (slug: string) => ctx.sql.exec<{ asked: number; routine: number; denied: number }>("SELECT c.asked,c.routine,c.denied FROM posture_ask_counts c JOIN items i ON i.id=c.item_id WHERE i.slug=?", slug).toArray()
      expect(counted("github-batch")).toEqual([{ asked: 10, routine: 10, denied: 10 }])
      expect(counted("github-batch")).toEqual(counted("github-single"))
      expect(slugs("member")).toEqual([])
      expect(slugs("guest")).toEqual([])
    })
  })

  it("stays away from a person for seven days after Not now", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await asks(ctx, 10)
      workspacePostureOps["items.nudge_quiet"].handler(ctx, memberPrincipal(ctx, "owner"), { slug: "github-work" }, memberInvocation(ctx, "owner"))
      expect(nudges(ctx).nudges).toEqual([])
      expect(nudges(ctx, "admin").nudges).toHaveLength(1)
      expect(audits(ctx, "posture.nudge_quiet")).toHaveLength(1)
      expect(nudges(at(ctx, ctx.now() + 7 * DAY - 60_000)).nudges).toEqual([])
    })
  })

  it("prunes counts older than eight days and quiet that has ended", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      const today = Math.floor(ctx.now() / DAY)
      ctx.sql.exec("INSERT INTO posture_ask_counts(item_id,day,asked,routine) VALUES (?,?,1,1),(?,?,1,1)", item.id, today - 9, item.id, today - 8)
      ctx.sql.exec("INSERT INTO posture_nudge_quiet(member,item_id,until) VALUES ('mem_owner',?,?)", item.id, ctx.now() - 1)
      await asks(ctx, 1)
      expect(ctx.sql.exec("SELECT day FROM posture_ask_counts ORDER BY day").toArray()).toEqual([{ day: today - 8 }, { day: today }])
      expect(ctx.sql.exec("SELECT * FROM posture_nudge_quiet").toArray()).toEqual([])
    })
  })
})

describe("the posture tables", () => {
  it("keep the text of their migration as production runs it", async () => {
    const sha256 = async (text: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("")
    expect(await sha256(ITEM_POSTURES_MIGRATION)).toBe("2a14f942c9ce08e8a05e265ab20a660de2f4242a8d74e6ab0508b4dde05299fd")
  })

  it("are one migration appended last to the items area, which a workspace on the previous schema applies keeping its rows", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      expect(itemsArea.migrations.at(-1)).toBe(ITEM_POSTURES_MIGRATION)
      const item = await seedGithub(ctx)
      for (const table of ["posture_nudge_quiet", "posture_ask_counts", "item_postures"]) ctx.sql.exec(`DROP TABLE ${table}`)
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area='items'", itemsArea.migrations.length - 1)
      applyMigrations(ctx.sql, ctx.storage, [itemsArea])
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='items'").toArray()[0]!.applied).toBe(itemsArea.migrations.length)
      expect(checkedCredential(ctx, "github-work")?.id).toBe(item.id)
      expect(describeAs(ctx, "owner").posture).toMatchObject({ level: "ask", rev: 0 })
      expect(await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })).toMatchObject({ level: "routine", rev: 1 })
    })
  })
})
