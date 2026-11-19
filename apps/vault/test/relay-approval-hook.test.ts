import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { afterEach,describe,expect,it,vi } from "vitest"
import { VaultError } from "../src/http.ts"
import { authoriseWorkspaceRelay, workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import { items } from "../src/vault/areas/items.ts"
import type { ApprovalBundleCreated } from "@mehen/protocol/api"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, seedCredential } from "./credentials-test-support.ts"
import * as approvalModule from "../src/vault/areas/approvals.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { projects } from "../src/vault/areas/projects.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { freshTenant } from "./helpers.ts"
import { SYSTEM, policyFixture, policyItem } from "./policy-fixtures.ts"
import { PROJECT_RUN_INPUT, projectFixture } from "./projects-workspace-fixture.ts"
import { registerCredentialServices } from "../src/vault/areas/items-workspace.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { MANDATE_HEADER, POSTURE_HEADER, type WorkspaceRunCreated } from "@mehen/protocol"
import { signMandate, terms } from "./mandates-test-support.ts"
import { auditLine } from "../src/ui/wording.ts"
import { DELETE_COMMENT, OPEN_ISSUE, UNREVIEWED, relayAs, seedGithub, setPosture } from "./postures-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

afterEach(() => { setRelayServices({}); setUpstreamFetch(null); vi.restoreAllMocks() })
it("the shared relay engine cannot mint legacy approval grants without workspace authority",async () => {
  expect(approvalModule).not.toHaveProperty("approvals")
  setRelayServices({})
  await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()),async instance => {
    const ctx = instance.context,device = await policyFixture(ctx)
    const before = [ctx.sql.exec("SELECT * FROM approvals").toArray(),ctx.sql.exec("SELECT * FROM grants").toArray()]
    const open = vi.spyOn(ctx,"openField")
    await expect(authoriseRelay(ctx,device,{ item: "custom-key",method: "GET",url: "https://api.example.com/api/projects/12345/tasks",headers: [] })).rejects.toMatchObject({ code: "internal",message: "The workspace approval handler is unavailable." })
    expect([ctx.sql.exec("SELECT * FROM approvals").toArray(),ctx.sql.exec("SELECT * FROM grants").toArray()]).toEqual(before)
    expect(open).not.toHaveBeenCalled()
  })
})

// Plan mode (a bundle): the engine stops after the approval loop, so no
// secret is opened, nothing is checked for sending, consumed or recorded.
it("plan mode never opens a secret, asserts a send or consumes, for a held request or an allowed one", async () => {
  setRelayServices({})
  await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => {
    const ctx = instance.context, device = await policyFixture(ctx)
    await items.putItem(ctx, policyItem({ slug: "open-key", policy: { default: "allow", rules: [] } }), SYSTEM)
    const open = vi.spyOn(ctx, "openField")
    const hooks = { visible: (slug: string) => items.getItem(ctx, slug)!, reauth: () => { throw new Error("reauth") }, prepare: () => undefined, approve: vi.fn(() => true), secrets: vi.fn(), assertCurrent: vi.fn(), consume: vi.fn(), plan: true }
    const held = await authoriseRelay(ctx, device, { item: "custom-key", method: "POST", url: "https://api.example.com/api/projects/1", headers: [["Content-Type", "application/json"]], body: Buffer.from("{}").toString("base64url") }, hooks)
    expect(hooks.approve).toHaveBeenCalledTimes(1)
    const allowed = await authoriseRelay(ctx, device, { item: "open-key", method: "GET", url: "https://api.example.com/api/projects/1", headers: [] }, hooks)
    expect(hooks.approve).toHaveBeenCalledTimes(1)
    for (const material of [held, allowed]) {
      expect(material).toMatchObject({ headers: [], scrub: [] })
      expect(JSON.stringify(material)).not.toContain("policy-test-secret")
    }
    expect(hooks.secrets).not.toHaveBeenCalled()
    expect(hooks.assertCurrent).not.toHaveBeenCalled()
    expect(hooks.consume).not.toHaveBeenCalled()
    expect(open).not.toHaveBeenCalled()
    expect(ctx.sql.exec("SELECT * FROM audit WHERE action='relay.allow'").toArray()).toEqual([])
  })
})

// A bundle runs each request through the workspace relay in plan mode.
describe("a bundle's requests", () => {
  const SENTINEL = "test-secret-never-returned"
  const body = (text: string) => Buffer.from(text).toString("base64url")
  const bundle = async (ctx: import("../src/vault/core.ts").VaultContext, input: unknown) => await workspaceRelayOps["approvals.bundle"]!.handler(ctx, devicePrincipal(), input, await deviceInvocation(ctx)) as ApprovalBundleCreated

  it("asks for a held one, reports an allowed and a refused one, and never opens, sends, consumes or records a use", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "hook-key")
      await seedCredential(ctx, "open-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='hook-key'", JSON.stringify({ default: "approve", rules: [] }))
      const open = vi.spyOn(ctx, "openField"), send = vi.spyOn(globalThis, "fetch")
      const answer = await bundle(ctx, { reason: "Set up the databases", requests: [
        { item: "hook-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [["Content-Type", "application/json"]], body: body('{"name":"one"}') },
        { item: "open-key", method: "GET", url: "https://api.example.com/v1/databases", headers: [] },
        { item: "open-key", method: "GET", url: "https://elsewhere.example.org/v1", headers: [] },
      ] })
      expect(answer.bundle).toMatch(/^bnd_/)
      expect(answer.url).toBe(`${ctx.env.VAULT_ORIGIN}/w/work/g/${answer.bundle}`)
      expect(answer.results).toEqual([
        { index: 0, outcome: "ask", approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String), mandateCover: { classes: ["change"], state: "none", mandate: null, url: null } },
        { index: 1, outcome: "allowed" },
        { index: 2, outcome: "refused", error: expect.objectContaining({ error: expect.any(String), message: expect.any(String) }) },
      ])
      expect(JSON.stringify(answer)).not.toContain(SENTINEL)
      expect(open).not.toHaveBeenCalled()
      expect(send).not.toHaveBeenCalled()
      const asked = answer.results[0]!.approval!
      expect(ctx.sql.exec("SELECT bundle,status,policy_status FROM approvals").toArray()).toEqual([{ bundle: answer.bundle, status: "pending", policy_status: null }])
      expect(ctx.sql.exec("SELECT id FROM approvals WHERE id=?", asked).toArray()).toHaveLength(1)
      expect(ctx.sql.exec("SELECT id,device,workload,reason FROM approval_bundles").toArray()).toEqual([{ id: answer.bundle, device: "dev_member", workload: null, reason: "Set up the databases" }])
      expect(ctx.sql.exec("SELECT slug FROM items WHERE last_used_at IS NOT NULL").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action IN ('relay.allow','grant.use')").toArray()).toEqual([])
      const audit = ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action='approval.bundle'").toArray()
      expect(audit.map((row) => ({ ...row, detail: JSON.parse(row.detail) as unknown }))).toEqual([{ actor: "device:dev_member", target: answer.bundle, detail: { requests: 3, asked: 1, allowed: 1, refused: 1 } }])
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM audit").toArray())).not.toContain(SENTINEL)
    })
  })

  it("never supersedes, and takes an identical open ask into the bundle rather than asking twice", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "hook-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='hook-key'", JSON.stringify({ default: "approve", rules: [] }))
      const request = { item: "hook-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: body('{"name":"one"}') }
      let earlier = ""
      try { await authoriseWorkspaceRelay(ctx, devicePrincipal(), request, await deviceInvocation(ctx)) } catch (error) { if (!(error instanceof VaultError) || error.code !== "approval_required") throw error; earlier = error.extra.approval as string }
      const answer = await bundle(ctx, { requests: [request, { ...request, body: body('{"name":"two"}'), replaces: earlier }, request] })
      expect(answer.results.map((r) => [r.outcome, r.approval])).toEqual([["ask", earlier], ["ask", expect.not.stringMatching(earlier)], ["ask", earlier]])
      expect(ctx.sql.exec("SELECT bundle,policy_status,superseded_by FROM approvals ORDER BY created_at,id").toArray()).toEqual([{ bundle: answer.bundle, policy_status: null, superseded_by: null }, { bundle: answer.bundle, policy_status: null, superseded_by: null }])
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='approval.supersede'").toArray()).toEqual([])
    })
  })

  it("makes one ask for a run request whose two placeholders are both held, as a relay does, and reports it", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      await seedCredential(ctx, "second-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='second-key'", JSON.stringify({ default: "approve", rules: [] }))
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','dev','OTHER','second-key','key','member:mem_owner',?)", ctx.now())
      const principal = devicePrincipal("dev_owner"), invocation = await deviceInvocation(ctx, "dev_owner")
      const run = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev", vars: ["TOKEN", "OTHER"] }, invocation) as WorkspaceRunCreated
      const placeholders = run.vars.flatMap((v) => v.delivery === "placeholder" ? [v.value] : [])
      expect(placeholders).toHaveLength(2)
      const request = { run: run.run, method: "POST", url: "https://api.example.com/tasks", headers: [["Authorization", `Bearer ${placeholders[0]}`], ["Authorization", `Bearer ${placeholders[1]}`]], body: body('{"title":"one"}') }
      const answer = await workspaceRelayOps["approvals.bundle"]!.handler(ctx, principal, { requests: [request] }, invocation) as ApprovalBundleCreated
      const asked = ctx.sql.exec<{ id: string; binding_code: string }>("SELECT id,binding_code FROM approvals WHERE bundle=?", answer.bundle).toArray()
      expect(asked).toHaveLength(1)
      expect(answer.results).toEqual([{ index: 0, outcome: "ask", approval: asked[0]!.id, bindingCode: asked[0]!.binding_code }])
      expect(ctx.sql.exec("SELECT * FROM audit WHERE action='approval.request'").toArray()).toHaveLength(1)
      const audit = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='approval.bundle'").toArray()
      expect(audit.map((row) => JSON.parse(row.detail) as unknown)).toEqual([{ requests: 1, asked: 1, allowed: 0, refused: 0 }])
    })
  })

  // The agent did try each credential, and a tripwire is a security signal,
  // so a bundle keeps the rows the relay writes as well as its own.
  it("keeps the deny, refuse and tripwire rows of refused requests and the approval.request row of a new ask", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      await seedCredential(ctx, "deny-key")
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='deny-key'", JSON.stringify({ default: "deny", rules: [] }))
      const principal = devicePrincipal("dev_owner"), invocation = await deviceInvocation(ctx, "dev_owner")
      const run = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
      const placeholder = run.vars.flatMap((v) => v.delivery === "placeholder" ? [v.value] : [])[0]!
      const answer = await workspaceRelayOps["approvals.bundle"]!.handler(ctx, principal, { requests: [
        { item: "key-workspace", method: "POST", url: "https://api.example.com/tasks", headers: [], body: body('{"title":"one"}') },
        { item: "deny-key", method: "GET", url: "https://api.example.com/tasks", headers: [] },
        { item: "key-workspace", method: "GET", url: "https://elsewhere.example.org/tasks", headers: [] },
        { run: run.run, method: "GET", url: "https://api.example.com/tasks", headers: [["X-Other", placeholder]] },
      ] }, invocation) as ApprovalBundleCreated
      expect(answer.results.map((r) => [r.outcome, r.error?.error])).toEqual([["ask", undefined], ["refused", "policy_denied"], ["refused", "binding_refused"], ["refused", "surface_refused"]])
      const rows = ctx.sql.exec<{ action: string; target: string }>("SELECT action,target FROM audit WHERE action LIKE 'relay.%' OR action LIKE 'approval.%' ORDER BY action").toArray()
      expect(rows).toEqual([
        { action: "approval.bundle", target: answer.bundle },
        { action: "approval.request", target: answer.results[0]!.approval },
        { action: "relay.deny", target: "deny-key" },
        { action: "relay.refuse", target: "key-workspace" },
        { action: "relay.tripwire", target: "key-workspace" },
      ])
    })
  })

  // A member-private credential's rows go to its owner's private audit, so
  // the workspace's bundle row never counts a request on one.
  describe("on a member-private credential", () => {
    const ask = (item: string, name: string) => ({ item, method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: body(`{"name":"${name}"}`) })
    const privateHeld = async (ctx: import("../src/vault/core.ts").VaultContext) => {
      await seedCredential(ctx, "hook-key")
      await seedCredential(ctx, "own-key", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug IN ('hook-key','own-key')", JSON.stringify({ default: "approve", rules: [] }))
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
    }
    const bundleRows = (ctx: import("../src/vault/core.ts").VaultContext) => ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='approval.bundle'").toArray().map((row) => JSON.parse(row.detail) as unknown)
    const privateAsks = (ctx: import("../src/vault/core.ts").VaultContext) => ctx.sql.exec("SELECT a.seq FROM audit a JOIN audit_private_owners p ON p.seq=a.seq WHERE a.action='approval.request' AND p.member='mem_member'").toArray()

    it("counts only the requests on credentials the workspace audit shows", async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        await privateHeld(ctx)
        const answer = await bundle(ctx, { requests: [ask("hook-key", "one"), ask("own-key", "two"), ask("own-key", "three")] })
        expect(answer.results.map((r) => r.outcome)).toEqual(["ask", "ask", "ask"])
        expect(privateAsks(ctx)).toHaveLength(2)
        expect(bundleRows(ctx)).toEqual([{ requests: 1, asked: 1, allowed: 0, refused: 0 }])
      })
    })

    it("writes no workspace bundle row when every request is on one", async () => {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        await privateHeld(ctx)
        const answer = await bundle(ctx, { requests: [ask("own-key", "one"), ask("own-key", "two")] })
        expect(answer.results.map((r) => r.outcome)).toEqual(["ask", "ask"])
        expect(privateAsks(ctx)).toHaveLength(2)
        expect(bundleRows(ctx)).toEqual([])
      })
    })
  })
})

// What a held relay request records for batch approvals, worked out in the
// workspace's approve hook while the bytes are in hand.
describe("a held relay request's floor and shape", () => {
  const relay = async (ctx: import("../src/vault/core.ts").VaultContext, input: { method: string; url: string; body?: string; replaces?: string }): Promise<string> => {
    try {
      await authoriseWorkspaceRelay(ctx, devicePrincipal(), { item: "hook-key", headers: [], ...input }, await deviceInvocation(ctx))
    } catch (error) {
      if (error instanceof VaultError && error.code === "approval_required") return error.extra.approval as string
      throw error
    }
    throw new Error("Expected approval_required")
  }
  const stored = (ctx: import("../src/vault/core.ts").VaultContext, id: string) => ctx.sql.exec<{ floor: string; shape: string }>("SELECT floor,shape FROM approvals WHERE id=?", id).toArray()[0]!
  const held = async (ctx: import("../src/vault/core.ts").VaultContext) => {
    await seedCredential(ctx, "hook-key")
    ctx.sql.exec("UPDATE items SET policy=? WHERE slug='hook-key'", JSON.stringify({ default: "approve", rules: [] }))
  }
  const body = (text: string) => Buffer.from(text).toString("base64url")

  it("stores the floor for a send, a delete and a generic word, and none for a plain read", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const floor = async (input: { method: string; url: string }) => JSON.parse(stored(ctx, await relay(ctx, input)).floor) as string[]
      expect(await floor({ method: "GET", url: "https://api.example.com/v1/messages/send" })).toEqual(["send"])
      expect(await floor({ method: "DELETE", url: "https://api.example.com/v1/gateways/7" })).toEqual(["destructive"])
      expect(await floor({ method: "GET", url: "https://api.example.com/v1/roles" })).toEqual(["opaque"])
      expect(await floor({ method: "GET", url: "https://api.example.com/v1/gateways" })).toEqual([])
    })
  })

  it("gives one shape to requests that differ only in body or query, and another to another path or method", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const shape = async (input: { method: string; url: string; body?: string }) => stored(ctx, await relay(ctx, input)).shape
      const first = await shape({ method: "POST", url: "https://api.example.com/v1/databases", body: body('{"name":"one"}') })
      expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect(await shape({ method: "POST", url: "https://api.example.com/v1/databases", body: body('{"name":"two"}') })).toBe(first)
      expect(await shape({ method: "POST", url: "https://api.example.com/v1/databases?region=eu" })).toBe(first)
      expect(await shape({ method: "POST", url: "https://api.example.com/v1/tables" })).not.toBe(first)
      expect(await shape({ method: "PUT", url: "https://api.example.com/v1/databases" })).not.toBe(first)
    })
  })

  it("lets a re-sent request replace its earlier ask, and refuses replaces while batches are off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await held(ctx)
      const first = await relay(ctx, { method: "POST", url: "https://api.example.com/v1/databases", body: body('{"name":"one"}') })
      const second = await relay(ctx, { method: "POST", url: "https://api.example.com/v1/databases", body: body('{"name":"two"}'), replaces: first })
      expect(ctx.sql.exec("SELECT policy_status,superseded_by FROM approvals WHERE id=?", first).toArray()).toEqual([{ policy_status: "superseded", superseded_by: second }])
      const off = Object.assign(Object.create(ctx) as import("../src/vault/core.ts").VaultContext, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
      await expect(relay(off, { method: "POST", url: "https://api.example.com/v1/databases", body: body('{"name":"three"}'), replaces: second })).rejects.toMatchObject({ code: "forbidden", message: "Replacing an ask is not available yet." })
      expect(ctx.sql.exec("SELECT policy_status FROM approvals WHERE id=?", second).toArray()).toEqual([{ policy_status: null }])
    })
  })
})

// How careful a credential is (areas/postures-workspace.ts), asked in the
// approve hook after the standing rules, only for a request the policy holds.
describe("a posture in the approve hook", () => {
  const audits = (ctx: import("../src/vault/core.ts").VaultContext, action: string) => ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action=?", action).toArray().map((row) => ({ ...row, detail: JSON.parse(row.detail) as Record<string, unknown> }))

  // A project's credential, so a team's machine (dev_service, through a
  // share on prj_a) and a guest's (dev_guest) reach it too.
  const PROJECT = { kind: "project", project: "prj_a" } as const
  it("routine lets a routine write through for a member's and a team's machine, never a guest's, and says so in the header", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-work", PROJECT)
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE)).error?.code).toBe("approval_required")
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      const member = await relayAs(ctx, "dev_member", OPEN_ISSUE)
      expect(member.error).toBeNull()
      expect(member.material).toMatchObject({ postures: ["routine"] })
      expect((await relayAs(ctx, "dev_service", OPEN_ISSUE)).error).toBeNull()
      expect((await relayAs(ctx, "dev_guest", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect((await relayAs(ctx, "dev_member", UNREVIEWED)).error?.code).toBe("approval_required")
      const used = audits(ctx, "posture.use")
      expect(used.map((row) => row.detail)).toEqual([
        { entry: "github.issue-create", method: "POST", host: "api.github.com", level: "routine", item: expect.any(String), outcome: "routine", run: null },
        { entry: "github.issue-create", method: "POST", host: "api.github.com", level: "routine", item: expect.any(String), outcome: "routine", run: null },
      ])
      expect(JSON.stringify(used)).not.toContain("/repos/")
      setUpstreamFetch(async () => new Response("ok"))
      const response = await forwardRelay(member.material!, Buffer.from(OPEN_ISSUE.body, "base64url"))
      expect(response.headers.get(POSTURE_HEADER)).toBe("routine")
      expect(response.headers.has(MANDATE_HEADER)).toBe(false)
    })
  })

  // A mandate (areas/mandates-workspace.ts) is asked after the posture.
  it("names the mandate that let a request through in Mehen-Mandate", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      const relayed = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(relayed.error).toBeNull()
      setUpstreamFetch(async () => new Response("ok"))
      const response = await forwardRelay(relayed.material!, Buffer.from(OPEN_ISSUE.body, "base64url"))
      expect(response.headers.get(MANDATE_HEADER)).toBe(mandate.id)
      expect(response.headers.has(POSTURE_HEADER)).toBe(false)
    })
  })

  it("trust reaches only machines whose owner manages the credential, and a route nobody reviewed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-work", PROJECT)
      await setPosture(ctx, "owner", "github-work", { level: "trust", machines: null })
      expect((await relayAs(ctx, "dev_admin", UNREVIEWED)).error).toBeNull()
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error).toBeNull()
      expect((await relayAs(ctx, "dev_kim", OPEN_ISSUE)).error).toBeNull()
      for (const device of ["dev_member", "dev_service", "dev_guest"]) expect((await relayAs(ctx, device, OPEN_ISSUE)).error?.code).toBe("approval_required")
    })
  })

  it("trust on a private credential reaches its owner's machine, and the use is told only to its owner", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      await setPosture(ctx, "member", "github-mine", { level: "trust", machines: null })
      expect((await relayAs(ctx, "dev_member", UNREVIEWED, "github-mine")).error).toBeNull()
      const [used] = audits(ctx, "posture.use")
      expect(used?.detail).toMatchObject({ action: "posture.use", slug: "github-mine", outcome: "trust" })
      expect(JSON.stringify(used)).not.toContain("api.github.com")
      expect(ctx.sql.exec("SELECT a.seq FROM audit a JOIN audit_private_owners p ON p.seq=a.seq WHERE a.action='posture.use' AND p.member='mem_member'").toArray()).toHaveLength(1)
    })
  })

  // Design 2.5: a shared credential's use names the method and host, as the
  // relay's own rows do; a private credential's names neither; no row a path.
  it("records the method and host of a shared credential's use and neither for a private one, never a path or query", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      await setPosture(ctx, "member", "github-mine", { level: "routine", machines: null })
      for (const slug of ["github-work", "github-mine"]) expect((await relayAs(ctx, "dev_member", OPEN_ISSUE, slug)).error).toBeNull()
      const stored = ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action='posture.use' ORDER BY seq").toArray()
      const said = stored.map((row) => { const slug = (JSON.parse(row.detail) as { slug?: string }).slug ?? row.target; const line = auditLine({ actor: row.actor, action: "posture.use", target: slug, detail: row.detail }, { self: "mem_member", devices: new Map([["dev_member", "Laptop"]]) }); return line.actor + line.pieces.map((p) => p.text).join("") })
      expect(said).toEqual(["An agent on Laptop used github-work without asking, as routine building: POST api.github.com", "An agent on Laptop used github-mine without asking, as routine building"])
      expect(JSON.parse(stored[1]!.detail)).not.toHaveProperty("method")
      expect(stored[1]!.detail).not.toContain("api.github.com")
      for (const row of stored) expect(row.detail).not.toMatch(/\/repos\/|\?/)
    })
  })

  it("never reaches a guest's machine, even with trust set on the guest's own credential before they were made a guest", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      await setPosture(ctx, "member", "github-mine", { level: "trust", machines: null })
      fixtureSql(ctx).exec("UPDATE members SET role='guest' WHERE id='mem_member'")
      for (const request of [OPEN_ISSUE, UNREVIEWED]) expect((await relayAs(ctx, "dev_member", request, "github-mine")).error?.code).toBe("approval_required")
      expect(audits(ctx, "posture.use")).toEqual([])
    })
  })

  it("never lets the floor through, at any level", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "trust", machines: null })
      expect((await relayAs(ctx, "dev_owner", DELETE_COMMENT)).error?.code).toBe("approval_required")
      expect((await relayAs(ctx, "dev_owner", { ...OPEN_ISSUE, url: `${OPEN_ISSUE.url}?_method=DELETE` })).material).toBeNull()
      expect(audits(ctx, "posture.use")).toEqual([])
    })
  })

  it("is narrowed by its machines", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-work", PROJECT)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: ["dev_service"] })
      expect((await relayAs(ctx, "dev_service", OPEN_ISSUE)).error).toBeNull()
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE)).error?.code).toBe("approval_required")
    })
  })

  it("refuses with conflict when the posture changed between the hook and the last check", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      const real = ctx.storage.transactionSync.bind(ctx.storage)
      let changed = false
      vi.spyOn(ctx.storage, "transactionSync").mockImplementation(((fn: () => unknown) => {
        if (!changed) { changed = true; ctx.sql.exec("UPDATE item_postures SET rev=rev+1") }
        return real(fn)
      }) as typeof ctx.storage.transactionSync)
      const { error } = await relayAs(ctx, "dev_member", OPEN_ISSUE)
      expect(error?.code).toBe("conflict")
      expect(audits(ctx, "posture.use")).toEqual([])
    })
  })

  it("never covers a protected credential's request, or one its policy allows outright", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "trust", machines: null })
      const guarded = vi.spyOn(projects, "isProtectedItem").mockReturnValue(true)
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      guarded.mockRestore()
      ctx.sql.exec("UPDATE items SET policy=? WHERE slug='github-work'", JSON.stringify({ default: "allow", rules: [] }))
      const allowed = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(allowed.error).toBeNull()
      expect(allowed.material).not.toHaveProperty("postures")
      expect(audits(ctx, "posture.use")).toEqual([])
    })
  })

  // A lease hands the value over, outside the relay and its hook, so a
  // credential its policy holds is never leased, whatever its posture.
  it("never turns a held credential into a lease", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      ctx.sql.exec("UPDATE items SET binding=?,ceiling='lease' WHERE slug='key-workspace'", JSON.stringify({ hosts: ["api.github.com"] }))
      await setPosture(ctx, "owner", "key-workspace", { level: "trust", machines: null })
      const principal = devicePrincipal("dev_owner"), invocation = await deviceInvocation(ctx, "dev_owner")
      const run = await workspaceRunOps["runs.create"]!.handler(ctx, principal, { ...PROJECT_RUN_INPUT, env: "dev" }, invocation) as WorkspaceRunCreated
      expect(run.vars.map((v) => v.delivery)).toEqual(["placeholder"])
      expect(audits(ctx, "posture.use")).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM posture_ask_counts").toArray()).toEqual([])
    })
  })

  it("lets nothing through with POLICY_POSTURES off here", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      const off = Object.assign(Object.create(ctx) as import("../src/vault/core.ts").VaultContext, { env: { ...ctx.env, POLICY_POSTURES: "tn_elsewhere0001" } })
      expect((await relayAs(off, "dev_member", OPEN_ISSUE)).error?.code).toBe("approval_required")
    })
  })
})
