import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { createProof, jwkThumbprint, webCryptoSigner, type WorkspaceRunCreated, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { InvocationResult, VaultContext } from "../src/vault/core.ts"
import { registerOverrideResolutionHook } from "../src/vault/areas/runs-workspace.ts"
import { items } from "../src/vault/areas/items.ts"
import { beforeOffboarding, isolateAccessLifecycleForTests, registerAccessChangeHook, registerExposureProvider, registerOffboardingHook, runOffboardingHooks } from "../src/vault/areas/workspace-runtime.ts"
import { resolveOverride } from "../src/vault/areas/overrides-workspace.ts"
import { registerCredentialServices } from "../src/vault/areas/items-workspace.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { projectFixture, inAccess } from "./projects-workspace-fixture.ts"
import { accountAuth, accessSnapshot, workspaceInvoke } from "./access-test-support.ts"
import { seedCredential } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

let network: ReturnType<typeof vi.spyOn<typeof globalThis, "fetch">>
beforeEach(() => { network = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("Unexpected upstream send in overrides test") }) })
afterEach(() => { expect(network).not.toHaveBeenCalled(); network.mockRestore() })

const base = { project: "prj_a", environment: "dev", variable: "TOKEN" }
const runInput = { project: "prj_a", env: "dev", envSource: "flag", remote: null, worktree: "/fixture", head: null, vars: ["TOKEN"], command: "test", argv: ["test"] }
function value<T>(result: InvocationResult): T { if (!result.ok) throw new Error(JSON.stringify(result.error)); expect(result.ok).toBe(true); return result.value as T }
function wire(result: InvocationResult) { return result.ok ? result : { ok: false, error: result.error.vaultError } }
async function fixture() {
  const f = await projectFixture()
  const privateItem = await inAccess(f.tenant, async ctx => { registerCredentialServices(); return seedCredential(ctx, "member-private", { kind: "member", member: "mem_member" }) })
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE devices SET jwk=?,thumbprint=? WHERE id IN('dev_member','dev_owner','dev_service','dev_guest')", JSON.stringify(jwk), "fixture"))
  await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'"))
  const thumbprint = await jwkThumbprint(jwk)
  await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE devices SET thumbprint=? WHERE id IN('dev_member','dev_owner','dev_service','dev_guest')", thumbprint))
  async function device(op: string, input: unknown, id = "dev_member") {
    const url = "https://vault.test/v1/runs", body = JSON.stringify(input)
    const proof = await createProof(webCryptoSigner(id, keys.privateKey), { method: "POST", url, body }, { tenant: f.tenant })
    const { sha256B64 } = await import("@mehen/protocol")
    return workspaceInvoke(f.tenant, op, input, { kind: "device", proof, method: "POST", url, bodyHash: await sha256B64(body) })
  }
  async function set(source: { kind: "plain"; value: string } | { kind: "item"; item: string; field: string } | null, role = "member", extra: Partial<typeof base> = {}) {
    const input = { ...base, ...extra, source }
    const action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "overrides.action", input, accountAuth(role)))
    return workspaceInvoke(f.tenant, "overrides.set", input, accountAuth(role, action))
  }
  return { ...f, privateItem, device, set }
}
async function rows(ctx: VaultContext, table: string) { return ctx.sql.exec(`SELECT * FROM ${table}`).toArray() }

describe("personal overrides through TenantVault.invoke", () => {
  it("sets and clears only the calling person's own sources with exact signed actions", async () => {
    const f = await fixture(), source = { kind: "item" as const, item: f.privateItem.slug, field: "key" }
    expect(value(await f.set(source))).toMatchObject({ overrides: [{ environment: "dev", variable: "TOKEN", source }] })
    expect(value(await workspaceInvoke(f.tenant, "overrides.list", { project: "prj_a" }, accountAuth("owner")))).toEqual({ overrides: [] })
    expect(value(await workspaceInvoke(f.tenant, "overrides.list", { project: "prj_a" }, accountAuth("guest")))).toEqual({ overrides: [] })
    const foreignSelector = { ...base, member: "mem_member", source: null }
    expect(wire(await workspaceInvoke(f.tenant, "overrides.set", foreignSelector, accountAuth("owner")))).toMatchObject({ ok: false, error: { error: "bad_request" } })
    expect(value(await f.set(null))).toEqual({ overrides: [] })
    expect(value(await f.set({ kind: "plain", value: "https://local.example" }))).toMatchObject({ overrides: [{ source: { kind: "plain", value: "https://local.example" } }] })
  })

  it("registered resolution substitutes only for the owner, not other members or team machines", async () => {
    const f = await fixture()
    value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
    const own = value<WorkspaceRunCreated>(await f.device("runs.create", runInput))
    expect(own.overrides).toEqual(["TOKEN"])
    expect(own.vars).toEqual([expect.objectContaining({ name: "TOKEN", delivery: "placeholder", item: "member-private" })])
    for (const id of ["dev_owner", "dev_service"]) {
      const other = value<WorkspaceRunCreated>(await f.device("runs.create", runInput, id))
      expect(other.overrides).toEqual([])
      expect(JSON.stringify(other)).not.toContain("member-private")
      expect(other.vars[0]).toMatchObject({ item: "key-workspace" })
    }
    await inAccess(f.tenant, ctx => {
      const audit = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='run.create' AND target=?", own.run).toArray()[0]!
      expect(JSON.parse(audit.detail)).toMatchObject({ overrides: ["TOKEN"] })
      expect(audit.detail).not.toContain("member-private")
    })
  })

  it("unticked private resolution refuses the entire run without a shared fallback or secret open", async () => {
    const f = await fixture()
    value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
    await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('false')) WHERE id='dev_member'"))
    await inAccess(f.tenant, async ctx => {
      const open = vi.spyOn(ctx, "openField")
      expect(wire(await f.device("runs.create", runInput))).toEqual({ ok: false, error: { error: "not_found", message: "No such object.", next: { say: "Use a machine allowed to reach your private credentials, or clear your override." } } })
      expect(await rows(ctx, "runs")).toEqual([])
      expect(open).not.toHaveBeenCalled(); open.mockRestore()
    })
  })

  it("missing resolution registration fails closed through real dispatch", async () => {
    const f = await fixture()
    value(await f.set({ kind: "plain", value: "personal" }))
    registerOverrideResolutionHook(null)
    try {
      expect(wire(await f.device("runs.create", runInput))).toEqual({ ok: false, error: { error: "internal", message: "Workspace override resolution is not registered." } })
      await inAccess(f.tenant, async ctx => expect(await rows(ctx, "runs")).toEqual([]))
    } finally { registerOverrideResolutionHook(resolveOverride) }
  })

  it("guests may set their own unprotected plain override", async () => {
    const f = await fixture()
    value(await f.set({ kind: "plain", value: "guest-choice" }, "guest"))
    const run = value<WorkspaceRunCreated>(await f.device("runs.create", runInput, "dev_guest"))
    expect(run.overrides).toEqual(["TOKEN"])
    expect(run.vars).toEqual([{ name: "TOKEN", delivery: "plain", value: "guest-choice" }])
  })

  for (const refusal of ["protected", "unknown-project", "unknown-variable", "foreign-private", "shared-credential", "unknown-credential", "unknown-field", "no-use", "secret-plain", "wrong-proof", "no-proof", "source-changed"] as const) it(`refuses ${refusal} without a mutation or secret open`, async () => {
    const f = await fixture()
    const foreign = await inAccess(f.tenant, ctx => seedCredential(ctx, "foreign-private", { kind: "member", member: "mem_owner" }))
    let input: { project: string; environment: string; variable: string; source: { kind: "plain"; value: string } | { kind: "item"; item: string; field: string } } = { ...base, source: { kind: "plain", value: "safe" } }
    if (refusal === "protected") input.environment = "prod"
    if (refusal === "unknown-project") input.project = "prj_absent"
    if (refusal === "unknown-variable") input.variable = "ABSENT"
    if (["foreign-private", "shared-credential", "unknown-credential", "unknown-field"].includes(refusal)) input.source = { kind: "item", item: refusal === "foreign-private" ? foreign.slug : refusal === "shared-credential" ? "key-workspace" : refusal === "unknown-credential" ? "absent-key" : f.privateItem.slug, field: refusal === "unknown-field" ? "absent" : "key" }
    if (refusal === "secret-plain") input.source = { kind: "plain", value: "-----BEGIN PRIVATE KEY-----" }
    if (refusal === "no-use") await inAccess(f.tenant, ctx => fixtureSql(ctx).exec("DELETE FROM project_shares WHERE subject_id IN('mem_member','tm_engineering')"))
    const action = { type: "override.set", ...input } as const
    const proof = refusal === "no-proof" ? undefined : refusal === "wrong-proof" ? { type: "workspace.unfreeze" as const } : refusal === "source-changed" ? { ...action, source: { kind: "plain" as const, value: "other" } } : action
    const before = await accessSnapshot(f.tenant)
    await inAccess(f.tenant, async ctx => {
      const open = vi.spyOn(ctx, "openField")
      expect(wire(await workspaceInvoke(f.tenant, "overrides.set", input, accountAuth("member", proof)))).toMatchObject({ ok: false, error: { error: refusal === "protected" || ["wrong-proof", "no-proof", "source-changed"].includes(refusal) ? "forbidden" : refusal === "secret-plain" ? "bad_request" : "not_found" } })
      expect(open).not.toHaveBeenCalled(); open.mockRestore()
    })
    expect(await accessSnapshot(f.tenant)).toBe(before)
    if (refusal === "foreign-private") expect(await workspaceInvoke(f.tenant, "overrides.set", input, accountAuth("member", action))).toEqual(await workspaceInvoke(f.tenant, "overrides.set", { ...input, source: { kind: "item", item: "absent-key", field: "key" } }, accountAuth("member", action)))
  })

  it("machines and system callers cannot set, clear or list personal overrides", async () => {
    const f = await fixture()
    value(await f.set({ kind: "plain", value: "personal" }))
    for (const op of ["overrides.set", "overrides.action", "overrides.list"]) {
      const input = op === "overrides.list" ? { project: "prj_a" } : { ...base, source: null }
      for (const device of ["dev_member", "dev_service"]) expect(wire(await f.device(op, input, device))).toMatchObject({ ok: false, error: { error: "forbidden" } })
      expect(wire(await workspaceInvoke(f.tenant, op, input, { kind: "system", reason: "test" }))).toMatchObject({ ok: false, error: { error: "forbidden" } })
    }
  })

  it("audit failure rolls an override mutation back and no source bytes enter audit", async () => {
    const f = await fixture(), input = { ...base, source: { kind: "plain" as const, value: "private-host.example" } }
    const before = await accessSnapshot(f.tenant)
    await inAccess(f.tenant, async ctx => {
      const audit = vi.spyOn(ctx, "audit").mockImplementation(() => { throw new Error("audit failed") })
      expect(await workspaceInvoke(f.tenant, "overrides.set", input, accountAuth("member", { type: "override.set", ...input }))).toMatchObject({ ok: false })
      audit.mockRestore()
    })
    expect(await accessSnapshot(f.tenant)).toBe(before)
    value(await f.set(input.source))
    await inAccess(f.tenant, ctx => {
      const audit = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='override.set'").toArray()[0]!
      expect(JSON.parse(audit.detail)).toEqual({ environment: "dev", variable: "TOKEN", by: { account: "acc_member", session: "ses_member" } })
    })
  })
})

for (const change of ["delete", "rehome", "remove", "leave", "suspend", "project-delete"] as const) it(`clears overrides on ${change} through the real dispatcher, atomically with its audit`, async () => {
  const f = await fixture()
  value(await f.set(change === "remove" || change === "leave" ? { kind: "plain", value: "own-value" } : { kind: "item", item: f.privateItem.slug, field: "key" }))
  let op: string, input: Record<string, unknown>, action: WorkspaceStepUpAction
  if (change === "delete") { op = "items.delete"; input = { slug: f.privateItem.slug }; action = { type: "item.delete", item: f.privateItem.id } }
  else if (change === "rehome") {
    op = "items.rehome"; input = { slug: f.privateItem.slug, home: { kind: "project", project: "prj_a" } }
    action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "items.action", { slug: f.privateItem.slug, action: "rehome", home: input.home }, accountAuth("member")))
  } else if (change === "project-delete") { op = "projects.delete"; input = { project: "prj_a" }; action = { type: "project.delete", project: "prj_a" }; await inAccess(f.tenant, ctx => fixtureSql(ctx).exec("UPDATE items SET home_kind='workspace',home_id=NULL WHERE home_kind='project'")) }
  else { op = `access.members.${change}`; input = { member: "mem_member" }; action = { type: change === "remove" ? "member.remove" : change === "leave" ? "member.leave" : "member.suspend", member: "mem_member" } }
  const auth = accountAuth(change === "delete" || change === "rehome" || change === "leave" ? "member" : "owner", action)
  const before = await accessSnapshot(f.tenant)
  await inAccess(f.tenant, async ctx => {
    const original = ctx.audit.bind(ctx)
    const audit = vi.spyOn(ctx, "audit").mockImplementation(event => { if (event.action !== "project.references.remove") throw new Error("final audit failed"); original(event) })
    expect(await workspaceInvoke(f.tenant, op, input, auth)).toMatchObject({ ok: false })
    audit.mockRestore()
  })
  expect(await accessSnapshot(f.tenant)).toBe(before)
  value(await workspaceInvoke(f.tenant, op, input, auth))
  await inAccess(f.tenant, async ctx => expect(await rows(ctx, "overrides")).toEqual([]))
})

it("FK cascades clear overrides when a declared variable or environment is physically deleted", async () => {
  for (const table of ["vars", "environments"]) {
    const f = await fixture()
    value(await f.set({ kind: "plain", value: "own" }))
    await inAccess(f.tenant, async ctx => {
      ctx.sql.exec(`DELETE FROM ${table} WHERE project='prj_a' AND ${table === "vars" ? "env" : "name"}='dev'`)
      expect(await rows(ctx, "overrides")).toEqual([])
    })
  }
})

it("a shared-source unset preserves the owner's override and is missing for another member", async () => {
  const f = await fixture()
  value(await f.set({ kind: "plain", value: "own-value" }))
  const input = { project: "prj_a", env: "dev", name: "TOKEN", before: { kind: "item", item: "key-workspace", field: "key" } }
  const action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "projects.action", { change: "variable", input }, accountAuth("owner")))
  value(await workspaceInvoke(f.tenant, "projects.setVar", input, accountAuth("owner", action)))
  const own = value<WorkspaceRunCreated>(await f.device("runs.create", runInput))
  expect(own.overrides).toEqual(["TOKEN"])
  expect(own.vars).toEqual([{ name: "TOKEN", delivery: "plain", value: "own-value" }])
  const other = value<WorkspaceRunCreated>(await f.device("runs.create", runInput, "dev_owner"))
  expect(other.overrides).toEqual([])
  expect(other.vars).toEqual([expect.objectContaining({ name: "TOKEN", delivery: "missing" })])
})

it("protecting an environment atomically clears every override and later loosening revives nothing", async () => {
  const f = await fixture()
  const variable = { project: "prj_a", env: "staging", name: "TOKEN", before: null, plain: "shared" }
  // The fixture's staging is protected; set it unprotected first, through the real operation.
  const environment = { project: "prj_a", env: "staging", before: { protected: true, fences: [], fourEyes: false }, protected: false, fences: [], fourEyes: false }
  let action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "projects.action", { change: "environment", input: environment }, accountAuth("owner")))
  value(await workspaceInvoke(f.tenant, "projects.setEnvironment", environment, accountAuth("owner", action)))
  action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "projects.action", { change: "variable", input: variable }, accountAuth("owner")))
  value(await workspaceInvoke(f.tenant, "projects.setVar", variable, accountAuth("owner", action)))
  value(await f.set({ kind: "plain", value: "private-choice" }, "member", { environment: "staging" }))
  value(await f.set({ kind: "plain", value: "owner-choice" }, "owner", { environment: "staging" }))
  value(await f.set({ kind: "plain", value: "dev-choice" }))
  const protect = { ...environment, before: { ...environment.before, protected: false }, protected: true }
  action = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "projects.action", { change: "environment", input: protect }, accountAuth("owner")))
  const beforeProtection = await accessSnapshot(f.tenant)
  await inAccess(f.tenant, async ctx => {
    const original = ctx.audit.bind(ctx)
    const audit = vi.spyOn(ctx, "audit").mockImplementation(event => { if (event.action === "project.environment.update") throw new Error("protection audit failed"); original(event) })
    try { expect(wire(await workspaceInvoke(f.tenant, "projects.setEnvironment", protect, accountAuth("owner", action)))).toMatchObject({ ok: false, error: { error: "internal" } }) } finally { audit.mockRestore() }
  })
  expect(await accessSnapshot(f.tenant)).toBe(beforeProtection)
  value(await workspaceInvoke(f.tenant, "projects.setEnvironment", protect, accountAuth("owner", action)))
  await inAccess(f.tenant, ctx => {
    expect(ctx.sql.exec("SELECT * FROM overrides WHERE env='staging'").toArray()).toEqual([])
    expect(ctx.sql.exec("SELECT * FROM overrides WHERE env='dev'").toArray()).toHaveLength(1)
  })
  const ask = await f.device("runs.create", { ...runInput, env: "staging" })
  expect(wire(ask)).toMatchObject({ ok: false, error: { error: "approval_required" } })
  if (ask.ok) throw new Error("Expected approval")
  const approval = ask.error.vaultError.approval!
  const [row] = await inAccess(f.tenant, ctx => ctx.sql.exec<{ digest: string; presentation: string }>("SELECT digest,presentation FROM approvals WHERE id=?", approval).toArray())
  expect(row).toBeDefined()
  expect(row!.presentation).not.toContain("private-choice")
  value(await workspaceInvoke(f.tenant, "approvals.decide", { id: approval, decision: "approve" }, accountAuth("member", { type: "approval.decide", approval, digest: row!.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 3600 } })))
  const run = value<WorkspaceRunCreated>(await f.device("runs.create", { ...runInput, env: "staging", approval }))
  expect(run.overrides).toEqual([])
  expect(run.vars).toEqual([{ name: "TOKEN", delivery: "plain", value: "shared" }])
  const loosenAction = value<WorkspaceStepUpAction>(await workspaceInvoke(f.tenant, "projects.action", { change: "environment", input: environment }, accountAuth("owner")))
  value(await workspaceInvoke(f.tenant, "projects.setEnvironment", environment, accountAuth("owner", loosenAction)))
  const loosenedRun = value<WorkspaceRunCreated>(await f.device("runs.create", { ...runInput, env: "staging" }))
  expect(loosenedRun.overrides).toEqual([])
  expect(loosenedRun.vars).toEqual([{ name: "TOKEN", delivery: "plain", value: "shared" }])
  await inAccess(f.tenant, ctx => expect(ctx.sql.exec("SELECT * FROM overrides WHERE env='staging'").toArray()).toEqual([]))
})

it("private override leases resolve their field and cannot lease the displaced shared source", async () => {
  const f = await fixture()
  value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  await inAccess(f.tenant, ctx => fixtureSql(ctx).exec("UPDATE items SET injection=NULL WHERE id=?", f.privateItem.id))
  const run = value<WorkspaceRunCreated>(await f.device("runs.create", runInput))
  expect(run.vars).toEqual([{ name: "TOKEN", delivery: "lease", value: "test-secret-never-returned", item: f.privateItem.slug }])
  expect(value(await f.device("runs.lease", { run: run.run, item: f.privateItem.slug, field: "key" }))).toMatchObject({ value: "test-secret-never-returned" })
  await inAccess(f.tenant, async ctx => {
    const open = vi.spyOn(ctx, "openField")
    expect(wire(await f.device("runs.lease", { run: run.run, item: "key-workspace", field: "key" }))).toEqual({ ok: false, error: { error: "not_found", message: "No such credential in this run." } })
    expect(open).not.toHaveBeenCalled(); open.mockRestore()
    expect(ctx.sql.exec<{ member: string; item: string }>("SELECT member,item FROM exposures WHERE source='leased'").toArray()).toEqual([{ member: "mem_member", item: f.privateItem.id }])
  })
})

for (const path of ["runs.create", "runs.lease"] as const) it(`${path} rechecks the override source after secret opening`, async () => {
  const f = await fixture()
  value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  await inAccess(f.tenant, ctx => fixtureSql(ctx).exec("UPDATE items SET injection=NULL WHERE id=?", f.privateItem.id))
  const run = path === "runs.lease" ? value<WorkspaceRunCreated>(await f.device("runs.create", runInput)) : null
  await inAccess(f.tenant, async ctx => {
    const beforeExposures = ctx.sql.exec("SELECT * FROM exposures").toArray()
    const original = ctx.openField.bind(ctx)
    const open = vi.spyOn(ctx, "openField").mockImplementationOnce(async (...args) => { value(await f.set({ kind: "plain", value: "new-source" })); return original(...args) })
    expect(wire(await f.device(path, run ? { run: run.run, item: f.privateItem.slug, field: "key" } : runInput))).toEqual({ ok: false, error: { error: "conflict", message: "Run sources changed; start a new run." } })
    open.mockRestore()
    expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toHaveLength(run ? 1 : 0)
    expect(ctx.sql.exec("SELECT * FROM exposures").toArray()).toEqual(beforeExposures)
  })
})

it("a private override cannot bypass the machine's project scope", async () => {
  const f = await fixture()
  value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  await inAccess(f.tenant, async ctx => {
    ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.projects',json('[\"prj_b\"]')) WHERE id='dev_member'")
    const open = vi.spyOn(ctx, "openField")
    expect(wire(await f.device("runs.create", runInput))).toMatchObject({ ok: false, error: { error: "not_found" } })
    expect(open).not.toHaveBeenCalled(); open.mockRestore()
    expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
  })
})

it("machine metadata exposes only its own unprotected sources, never plain values", async () => {
  const f = await fixture()
  value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  expect(value(await f.device("overrides.machine", { project: "prj_a" }))).toEqual({ overrides: [{ environment: "dev", variable: "TOKEN", source: { kind: "item", item: "member-private", field: "key" } }] })
  for (const device of ["dev_owner", "dev_service"]) expect(value(await f.device("overrides.machine", { project: "prj_a" }, device))).toEqual({ overrides: [] })
  await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('false')) WHERE id='dev_member'"))
  expect(value(await f.device("overrides.machine", { project: "prj_a" }))).toEqual({ overrides: [] })
  value(await f.set({ kind: "plain", value: "private-host.example" }))
  expect(value(await f.device("overrides.machine", { project: "prj_a" }))).toEqual({ overrides: [{ environment: "dev", variable: "TOKEN", source: { kind: "plain" } }] })
  await inAccess(f.tenant, ctx => ctx.sql.exec("UPDATE environments SET protected=1 WHERE project='prj_a' AND name='dev'"))
  expect(value(await f.device("overrides.machine", { project: "prj_a" }))).toEqual({ overrides: [] })
  const hidden = await f.device("overrides.machine", { project: "prj_b" }, "dev_guest")
  const absent = await f.device("overrides.machine", { project: "prj_absent" }, "dev_guest")
  expect(wire(hidden)).toEqual({ ok: false, error: { error: "not_found", message: "No such object." } })
  expect(wire(hidden)).toEqual(wire(absent))
})

for (const source of ["private", "workspace"] as const) it(`runs.create refuses a ${source} lease whose credential rotated after opening`, async () => {
  const f = await fixture()
  if (source === "private") value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  await inAccess(f.tenant, async ctx => {
    const slug = source === "private" ? f.privateItem.slug : "key-workspace"
    fixtureSql(ctx).exec("UPDATE items SET injection=NULL,ceiling='lease' WHERE slug=?", slug)
    const before = items.getItem(ctx, slug)!
    const beforeExposures = ctx.sql.exec("SELECT * FROM exposures").toArray()
    const original = ctx.openField.bind(ctx)
    const open = vi.spyOn(ctx, "openField").mockImplementationOnce(async (...args) => {
      const plaintext = await original(...args)
      await items.replaceSecrets(ctx, slug, { key: "rotated-value-not-a-live-secret" }, { kind: "system", reason: "test rotation" })
      return plaintext
    })
    try {
      expect(wire(await f.device("runs.create", runInput))).toEqual({ ok: false, error: { error: "conflict", message: "The credential changed." } })
      expect(open).toHaveBeenCalledTimes(1)
    } finally { open.mockRestore() }
    expect(items.getItem(ctx, slug)).toMatchObject({ id: before.id, version: before.version + 1, configRev: before.configRev })
    expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
    expect(ctx.sql.exec("SELECT * FROM exposures").toArray()).toEqual(beforeExposures)
    expect(ctx.sql.exec("SELECT * FROM exposures WHERE source='leased' AND version=?", before.version).toArray()).toEqual([])
    expect(await items.openSecrets(ctx, items.getItem(ctx, slug)!)).toEqual({ key: "rotated-value-not-a-live-secret" })
  })
})

it("missing override lifecycle hooks fail member remove, leave and suspend closed", async () => {
  for (const change of ["remove", "leave", "suspend"] as const) {
    const f = await fixture()
    value(await f.set({ kind: "plain", value: "own-value" }))
    const snapshot = await inAccess(f.tenant, ctx => beforeOffboarding(ctx, "mem_member"))
    const before = await accessSnapshot(f.tenant)
    const restore = isolateAccessLifecycleForTests()
    try {
      for (const name of ["credentials", "projects", "consent"]) registerOffboardingHook(name, () => undefined)
      for (const name of ["projects", "consent"]) registerAccessChangeHook(name, () => undefined)
      registerExposureProvider(() => [])
      await inAccess(f.tenant, ctx => {
        expect(() => beforeOffboarding(ctx, "mem_member")).toThrow("Workspace lifecycle services are not registered.")
        expect(() => ctx.storage.transactionSync(() => runOffboardingHooks(ctx, snapshot))).toThrow("Workspace lifecycle services are not registered.")
      })
      const action: WorkspaceStepUpAction = { type: change === "remove" ? "member.remove" : change === "leave" ? "member.leave" : "member.suspend", member: "mem_member" }
      expect(wire(await workspaceInvoke(f.tenant, `access.members.${change}`, { member: "mem_member" }, accountAuth(change === "leave" ? "member" : "owner", action)))).toEqual({ ok: false, error: { error: "internal", message: "Workspace lifecycle services are not registered." } })
      expect(await accessSnapshot(f.tenant)).toBe(before)
    } finally { restore() }
  }
})

it("a stale override pointing at a credential that is no longer the member's own refuses the whole run", async () => {
  const f = await fixture()
  value(await f.set({ kind: "item", item: f.privateItem.slug, field: "key" }))
  await inAccess(f.tenant, async ctx => {
    fixtureSql(ctx).exec("UPDATE items SET home_id='mem_kim' WHERE id=?", f.privateItem.id)
    const open = vi.spyOn(ctx, "openField")
    try {
      expect(wire(await f.device("runs.create", runInput))).toEqual({ ok: false, error: { error: "not_found", message: "No such object." } })
      expect(open).not.toHaveBeenCalled()
    } finally { open.mockRestore() }
    expect(ctx.sql.exec("SELECT * FROM runs").toArray()).toEqual([])
  })
})

it("an override needs a declared variable row in the exact environment, even if another environment declares it", async () => {
  const f = await fixture()
  await inAccess(f.tenant, ctx => {
    expect(ctx.sql.exec("SELECT * FROM vars WHERE project='prj_a' AND env='prod' AND name='TOKEN'").toArray()).toHaveLength(1)
    ctx.sql.exec("DELETE FROM vars WHERE project='prj_a' AND env='dev' AND name='TOKEN'")
  })
  const before = await accessSnapshot(f.tenant)
  const input = { ...base, source: { kind: "plain" as const, value: "own-value" } }
  expect(wire(await workspaceInvoke(f.tenant, "overrides.action", input, accountAuth("member")))).toEqual({ ok: false, error: { error: "not_found", message: "No such object." } })
  expect(await accessSnapshot(f.tenant)).toBe(before)
})
