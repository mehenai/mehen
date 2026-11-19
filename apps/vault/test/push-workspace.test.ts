// Pushes in the workspace's object: the per-item allowance (ruling U1), the
// ask (push.prepare and push.ask, design 3.1), and the decide, execute,
// record and sweep that follow (design 3.2 and 3.3).
import { describe, expect, it } from "vitest"
import { getTemplate, type ApprovalBatchResult, type ApprovalGroupView, type ApprovalSubject, type CredentialHome, type ItemKind, type PushDestination, type PushPreview, type WorkspaceStepUpAction } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { itemsArea, stepUpDigest } from "../src/vault/areas/items.ts"
import { prepareCredential, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { beforeOffboarding, setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { workspaceApproval, workspaceApprovalOps, workspaceApprovalStatus } from "../src/vault/areas/approvals-workspace.ts"
import { pushesArea, sweepPushes, workspacePushOps, type PushHandOut, type PushPrepared } from "../src/vault/areas/pushes.ts"
import { workspaceApprovalBatchOps } from "../src/vault/areas/approvals-batch-workspace.ts"
import { workspacePendingOps, type WorkspaceInboxAnswer } from "../src/vault/areas/pending-workspace.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { editAccessFixture } from "./access-test-support.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

export const switchedPush = (ctx: VaultContext, value: string): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, PUSH: value } })

async function refusal(run: () => Promise<unknown>): Promise<{ code: string; message: string; extra: Record<string, unknown> }> {
  try {
    await run()
  } catch (error) {
    if (error instanceof VaultError) return { code: error.code, message: error.message, extra: error.extra }
    throw error
  }
  throw new Error("Expected a refusal")
}

async function seedKind(ctx: VaultContext, slug: string, kind: ItemKind, secretFields: Record<string, string>, publicFields: Record<string, string> = {}): Promise<void> {
  const prepared = await prepareCredential(ctx, { ...credentialInput(slug), kind, ceiling: "relay", injection: null, secretFields, publicFields }, null)
  ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}

// items.update with a passkey over the change, as the credential page signs it.
export async function updateItem(ctx: VaultContext, slug: string, change: Record<string, unknown>, role = "owner") {
  const item = ctx.sql.exec<{ id: string; version: number; config_rev: number }>("SELECT id,version,config_rev FROM items WHERE slug=?", slug).toArray()[0]!
  const action: WorkspaceStepUpAction = { type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: item.version, configRevision: item.config_rev }) }
  return workspaceItemOps["items.update"]!.handler(ctx, memberPrincipal(ctx, role), { slug, change }, memberInvocation(ctx, role, action))
}

const pushableOf = (ctx: VaultContext, slug: string) => ctx.sql.exec<{ pushable: number; config_rev: number }>("SELECT pushable,config_rev FROM items WHERE slug=?", slug).toArray()[0]!

describe("the allowance to put a credential into other services' secret stores", () => {
  it("is off until a person turns it on under item.update, which bumps the configuration revision, and the person's view shows it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "openai-prod")
      const describe = (p = memberPrincipal(ctx), invocation = memberInvocation(ctx)) => workspaceItemOps["items.describe"]!.handler(ctx, p, { slug: "openai-prod" }, invocation) as { pushable?: boolean }
      expect(pushableOf(ctx, "openai-prod")).toEqual({ pushable: 0, config_rev: item.configRev })
      expect(describe().pushable).toBe(false)
      await updateItem(ctx, "openai-prod", { pushable: true })
      expect(pushableOf(ctx, "openai-prod")).toEqual({ pushable: 1, config_rev: item.configRev + 1 })
      expect(describe().pushable).toBe(true)
      // A machine's description never says.
      expect("pushable" in describe(devicePrincipal(), await deviceInvocation(ctx))).toBe(false)
      // Another change leaves it as it is; turning it off takes it away.
      await updateItem(ctx, "openai-prod", { description: "Production key" })
      expect(pushableOf(ctx, "openai-prod").pushable).toBe(1)
      await updateItem(ctx, "openai-prod", { pushable: false })
      expect(pushableOf(ctx, "openai-prod").pushable).toBe(0)
    })
  })

  it("is covered by the item.update digest: a passkey over the change without it does not turn it on", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "openai-prod")
      const signedWithout: WorkspaceStepUpAction = { type: "item.update", item: item.id, digest: await stepUpDigest({ change: { description: "x" }, version: item.version, configRevision: item.configRev }) }
      const sent = { slug: "openai-prod", change: { description: "x", pushable: true } }
      expect(await refusal(() => workspaceItemOps["items.update"]!.handler(ctx, memberPrincipal(ctx), sent, memberInvocation(ctx, "owner", signedWithout)))).toMatchObject({ code: "conflict" })
      expect(pushableOf(ctx, "openai-prod").pushable).toBe(0)
      const planned = await workspaceItemOps["items.action"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", action: "update", change: { description: "x", pushable: true } }, memberInvocation(ctx))
      expect(planned).toEqual({ type: "item.update", item: item.id, digest: await stepUpDigest({ change: { description: "x", pushable: true }, version: item.version, configRevision: item.configRev }) })
      expect(planned).not.toEqual({ ...signedWithout })
    })
  })

  it("is offered only for kinds that could ever be leased, never an OAuth client or connection", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedKind(ctx, "header-map", "custom-headers", { headers: "{\"x-key\":\"value-not-real\"}" })
      await seedKind(ctx, "an-oauth-client", "oauth-client", { client_secret: "client-secret-not-real" }, { client_id: "a-client" })
      for (const slug of ["header-map", "an-oauth-client"]) {
        expect(await refusal(() => updateItem(ctx, slug, { pushable: true }))).toMatchObject({ code: "mode_refused", message: expect.stringContaining("may not be put into other services' secret stores") })
        expect(pushableOf(ctx, slug).pushable).toBe(0)
        // Off is always allowed.
        await updateItem(ctx, slug, { pushable: false })
      }
    })
  })

  it("cannot be turned on while pushing is off, or in a managed workspace", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai-prod")
      expect(await refusal(() => updateItem(switchedPush(ctx, "off"), "openai-prod", { pushable: true }))).toMatchObject({ code: "forbidden", message: "Pushing is not available yet." })
      expect(await refusal(() => updateItem(switchedPush(ctx, "tn_elsewhere0001"), "openai-prod", { pushable: true }))).toMatchObject({ code: "forbidden", message: "Pushing is not available yet." })
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await refusal(() => updateItem(ctx, "openai-prod", { pushable: true }))).toMatchObject({ code: "forbidden", message: "Pushing is not available in a managed workspace." })
      expect(pushableOf(ctx, "openai-prod").pushable).toBe(0)
    })
  })

  it("adds its column in a migration that a workspace on the previous items schema applies, keeping every row", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedCredential(ctx, "openai-prod")
      const index = itemsArea.migrations.findIndex((migration) => migration.includes("ADD COLUMN pushable"))
      expect(index).toBe(itemsArea.migrations.length - 2)
      // The posture tables come after it.
      for (const table of ["posture_nudge_quiet", "posture_ask_counts", "item_postures"]) withTrustedSchema(ctx, () => ctx.sql.exec(`DROP TABLE ${table}`))
      withTrustedSchema(ctx, () => ctx.sql.exec("ALTER TABLE items DROP COLUMN pushable"))
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area='items'", index)
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [itemsArea]))
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='items'").toArray()[0]!.applied).toBe(itemsArea.migrations.length)
      expect(ctx.sql.exec("SELECT id,slug,pushable FROM items").toArray()).toEqual([{ id: item.id, slug: "openai-prod", pushable: 0 }])
    })
  })
})

// A GitHub token this machine may use at relay, carrying the push.
export async function seedGitHubVia(ctx: VaultContext, slug = "gh-token", home: CredentialHome = { kind: "workspace" }, role = "owner"): Promise<void> {
  const prepared = await prepareCredential(ctx, { ...credentialInput(slug, home), provider: "github-pat", account: "acme-bot", ceiling: "placeholder", binding: { hosts: ["api.github.com"] }, policy: getTemplate("github-pat")!.policy, secretFields: { key: "ghp_test-via-never-returned" } }, null)
  ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx, role), "item.create"))
}

export const pushRequest = (to: Partial<Extract<PushDestination, { provider: "github" }>> = {}) => ({ item: "openai-prod", to: { provider: "github" as const, owner: "acme", repo: "api", store: "actions" as const, environment: null, name: "OPENAI_API_KEY", ...to } })

// push.prepare then push.ask, as POST /v1/push runs them; the approval id
// when a human must decide.
export async function askPush(ctx: VaultContext, request: Record<string, unknown> = pushRequest(), preview: PushPreview | null = null): Promise<{ approval: string; extra: Record<string, unknown> } | { done: unknown }> {
  const prepared = await workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), request, await deviceInvocation(ctx)) as PushPrepared
  try {
    return { done: await workspacePushOps["push.ask"]!.handler(ctx, { kind: "system" }, { ticket: prepared.ticket, preview }, systemInvocation(ctx)) }
  } catch (error) {
    if (error instanceof VaultError && error.code === "approval_required") return { approval: error.extra.approval as string, extra: error.extra }
    throw error
  }
}

export const systemInvocation = (ctx: VaultContext) => ({ auth: { kind: "system" as const, reason: "push" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } })

export async function pushReady(ctx: VaultContext): Promise<void> {
  await seedCredential(ctx, "openai-prod")
  await updateItem(ctx, "openai-prod", { pushable: true })
  await seedGitHubVia(ctx)
}

describe("asking for a push", () => {
  // The approval dial's Let it work (areas/approval-dial-workspace.ts)
  // covers only the relay: a push is still asked of a person.
  it("is still asked of a person when the workspace is set to Let it work", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      setSetting(ctx, "approval_dial", "work")
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      expect(workspaceApproval(ctx, asked.approval)).toMatchObject({ status: "pending" })
    })
  })

  it("hands the Worker the via's headers and only the preview reads its policy allows, never the value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const prepared = await workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), pushRequest(), await deviceInvocation(ctx)) as PushPrepared
      expect(prepared.via.headers).toEqual([["authorization", "Bearer ghp_test-via-never-returned"]])
      expect(prepared.allowed.map((c) => `${c.method} ${c.url}`)).toEqual(["GET https://api.github.com/repos/acme/api", "GET https://api.github.com/repos/acme/api/actions/secrets/OPENAI_API_KEY"])
      expect(JSON.stringify(prepared)).not.toContain("test-secret-never-returned")
    })
  })

  it("files a one-use approval naming where, what and with what, warning that it cannot be taken back", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const asked = await askPush(ctx, { ...pushRequest(), reason: "deploys need it" })
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      const row = workspaceApproval(ctx, asked.approval)!
      expect(JSON.parse(row.subject)).toMatchObject({ item: "openai-prod", method: "PUSH", url: "mehen-push:github:acme/api/OPENAI_API_KEY", constraints: { uses: 1, ttlSeconds: 600 } })
      const presentation = JSON.parse(row.presentation)
      expect(presentation.title).toBe("Put openai-prod into GitHub acme/api, Actions secret OPENAI_API_KEY, using gh-token")
      expect(presentation.details).toContainEqual({ label: "Using", value: "gh-token (as acme-bot)" })
      expect(presentation.details).toContainEqual({ label: "The agent says", value: "deploys need it" })
      expect(presentation.warnings).toEqual(["Mehen cannot take this back. Removing it later is done in GitHub.", "This workspace has never pushed to acme."])
      expect(presentation.push).toMatchObject({ destination: "github:acme/api/OPENAI_API_KEY", field: "key", via: "gh-token", newDestination: true })
      expect(asked.extra.next).toMatchObject({ url: `https://vault.test/w/work/a/${asked.approval}` })
      // The same ask again finds the same approval.
      const again = await askPush(ctx, { ...pushRequest(), reason: "deploys need it" })
      expect(again).toMatchObject({ approval: asked.approval })
    })
  })

  it("refuses when the credential is not allowed, the switch is off, there is no via, or two could carry it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai-prod")
      await seedGitHubVia(ctx)
      const prepare = (c: VaultContext = ctx, request: Record<string, unknown> = pushRequest()) => refusal(async () => workspacePushOps["push.prepare"]!.handler(c, devicePrincipal(), request, await deviceInvocation(ctx)))
      expect(await prepare()).toMatchObject({ code: "mode_refused", message: "openai-prod may not be put into other services' secret stores. Allow it on its page." })
      await updateItem(ctx, "openai-prod", { pushable: true })
      expect(await prepare(switchedPush(ctx, "off"))).toMatchObject({ code: "forbidden", message: "Pushing is not available yet." })
      expect(await prepare(ctx, { ...pushRequest(), with: "openai-prod" })).toMatchObject({ code: "bad_request", message: "openai-prod cannot carry a push to GitHub: it is not a GitHub credential." })
      expect(await prepare(ctx, { ...pushRequest(), to: { provider: "fly", app: "api", name: "KEY" } })).toMatchObject({ code: "bad_request", message: "Pushing to Fly is not available yet." })
      await seedGitHubVia(ctx, "gh-other")
      expect(await prepare()).toMatchObject({ code: "ambiguous", extra: { choices: [{ slug: "gh-other", account: "acme-bot" }, { slug: "gh-token", account: "acme-bot" }] } })
      fixtureSql(ctx).exec("DELETE FROM items WHERE provider='github-pat'")
      expect(await prepare()).toMatchObject({ code: "not_found", message: "This machine may use no GitHub credential to push with." })
    })
  })

  it("refuses a frozen or managed workspace, a via whose policy denies the write or whose binding misses it, and an oversized value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const prepare = () => refusal(async () => workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), pushRequest(), await deviceInvocation(ctx)))
      fixtureSql(ctx).exec("UPDATE items SET policy=? WHERE slug='gh-token'", JSON.stringify({ default: "allow", rules: [{ action: "deny", methods: ["PUT"], paths: ["/repos/*/*/actions/secrets/*"], note: "writing secrets" }] }))
      expect(await prepare()).toMatchObject({ code: "policy_denied", message: '"gh-token" may not be used for PUT /repos/acme/api/actions/secrets/OPENAI_API_KEY (writing secrets).' })
      fixtureSql(ctx).exec("UPDATE items SET policy=?,binding=? WHERE slug='gh-token'", JSON.stringify({ default: "allow", rules: [] }), JSON.stringify({ hosts: ["api.github.com"], paths: ["/user"] }))
      expect(await prepare()).toMatchObject({ code: "binding_refused" })
      fixtureSql(ctx).exec("UPDATE items SET binding=? WHERE slug='gh-token'", JSON.stringify({ hosts: ["api.github.com"] }))
      ctx.sql.exec("UPDATE item_secrets SET length=? WHERE item=(SELECT id FROM items WHERE slug='openai-prod')", 65 * 1024)
      expect(await prepare()).toMatchObject({ code: "too_large" })
      ctx.sql.exec("UPDATE item_secrets SET length=? WHERE item=(SELECT id FROM items WHERE slug='openai-prod')", 32)
      const ticket = (await workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), pushRequest(), await deviceInvocation(ctx)) as PushPrepared).ticket
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await prepare()).toMatchObject({ code: "forbidden", message: "Pushing is not available in a managed workspace." })
      // Nor is a push filed there, so the platform never decides one.
      expect(await refusal(async () => workspacePushOps["push.ask"]!.handler(ctx, { kind: "system" }, { ticket, preview: null }, systemInvocation(ctx)))).toMatchObject({ code: "forbidden", message: "Pushing is not available in a managed workspace." })
      expect(ctx.sql.exec("SELECT id FROM approvals").toArray()).toEqual([])
      setSetting(ctx, "frozen", true)
      expect(await prepare()).toMatchObject({ code: "frozen" })
    })
  })

  it("is carried by the via chosen when it was prepared, and refused once that via is gone", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const prepare = async () => (await workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), pushRequest(), await deviceInvocation(ctx)) as PushPrepared).ticket
      const ask = (ticket: string) => workspacePushOps["push.ask"]!.handler(ctx, { kind: "system" }, { ticket, preview: null }, systemInvocation(ctx))
      // Another via appearing after the preview does not change which carries it.
      const first = await prepare()
      await seedGitHubVia(ctx, "gh-other")
      const asked = await refusal(async () => ask(first))
      expect(asked).toMatchObject({ code: "approval_required" })
      expect(JSON.parse(workspaceApproval(ctx, asked.extra.approval as string)!.presentation).push).toMatchObject({ via: "gh-token" })
      // The previewed via gone, with one other left: refused, never carried by the other.
      fixtureSql(ctx).exec("DELETE FROM items WHERE slug='gh-other'")
      const second = await prepare()
      fixtureSql(ctx).exec("DELETE FROM items WHERE slug='gh-token'")
      await seedGitHubVia(ctx, "gh-other")
      expect(await refusal(async () => ask(second))).toMatchObject({ code: "not_found", message: 'No credential called "gh-token".' })
    })
  })

  it("is refused when the via was deleted and another credential took its name before the ask, with nothing filed or queued", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const prepared = await workspacePushOps["push.prepare"]!.handler(ctx, devicePrincipal(), pushRequest(), await deviceInvocation(ctx)) as PushPrepared
      const before = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='gh-token'").toArray()[0]!.id
      fixtureSql(ctx).exec("DELETE FROM items WHERE slug='gh-token'")
      await seedGitHubVia(ctx)
      expect(ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='gh-token'").toArray()[0]!.id).not.toBe(before)
      expect(await refusal(async () => workspacePushOps["push.ask"]!.handler(ctx, { kind: "system" }, { ticket: prepared.ticket, preview: null }, systemInvocation(ctx)))).toMatchObject({ code: "not_found", message: 'No credential called "gh-token".' })
      expect(ctx.sql.exec("SELECT id FROM approvals").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT id FROM pushes").toArray()).toEqual([])
    })
  })

  it("is stale once the credential or the via changes before anyone decides", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      const status = () => workspaceApprovalStatus(ctx, workspaceApproval(ctx, asked.approval)!)
      expect(status()).toBe("pending")
      fixtureSql(ctx).exec("UPDATE items SET version=version+1 WHERE slug='gh-token'")
      expect(status()).toBe("stale")
    })
  })
})

export async function approvePush(ctx: VaultContext, id: string, role = "member"): Promise<void> {
  const row = workspaceApproval(ctx, id)!
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }
  await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, role), { id, decision: "approve" }, memberInvocation(ctx, role, action))
}

const pushOf = (ctx: VaultContext, approval: string) => ctx.sql.exec<{ id: string; state: string; outcome: string | null }>("SELECT id,state,outcome FROM pushes WHERE approval=?", approval).toArray()[0]

describe("an approved push", () => {
  it("spends its one use at once, is queued, and offers no rule and no remember", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      const view = await workspaceApprovalOps["approvals.view"]!.handler(ctx, memberPrincipal(ctx, "member"), { id: asked.approval }, memberInvocation(ctx, "member")) as { approval: { ruleOffer?: unknown; push?: { state: string } } }
      expect(view.approval.ruleOffer).toBeUndefined()
      expect(view.approval.push?.state).toBe("pending")
      const row = workspaceApproval(ctx, asked.approval)!
      const remember: WorkspaceStepUpAction = { type: "approval.decide", approval: asked.approval, digest: row.digest, decision: "approve", constraints: { uses: 5, ttlSeconds: 600 } }
      expect(await refusal(async () => workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "member"), { id: asked.approval, decision: "approve", constraints: { uses: 5, ttlSeconds: 600 } }, memberInvocation(ctx, "member", remember)))).toMatchObject({ code: "bad_request", message: "A push is approved once, as asked, and never remembered." })
      await approvePush(ctx, asked.approval)
      expect(ctx.sql.exec<{ uses_left: number }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", asked.approval).toArray()[0]!.uses_left).toBe(0)
      expect(pushOf(ctx, asked.approval)?.state).toBe("queued")
      const status = await workspaceApprovalOps["approvals.status"]!.handler(ctx, devicePrincipal(), { id: asked.approval }, await deviceInvocation(ctx)) as { push?: unknown }
      expect(status.push).toMatchObject({ destination: "github:acme/api/OPENAI_API_KEY", field: "key", state: "queued" })
    })
  })

  it("hands its value to the Worker once, records what the provider said, and marks the value exposed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      await approvePush(ctx, asked.approval)
      const execute = () => workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as Promise<PushHandOut>
      const handOut = await execute()
      if (!handOut.sent) throw new Error(handOut.reason)
      expect(handOut.value).toEqual({ label: "openai-prod", value: "test-secret-never-returned" })
      expect(handOut.via.headers).toEqual([["authorization", "Bearer ghp_test-via-never-returned"]])
      expect(pushOf(ctx, asked.approval)?.state).toBe("sending")
      expect(await refusal(execute)).toMatchObject({ code: "conflict" })
      await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "created", providerStatus: 201 }, systemInvocation(ctx))
      expect(pushOf(ctx, asked.approval)).toMatchObject({ state: "done", outcome: "created" })
      const audit = ctx.sql.exec<{ action: string; detail: string }>("SELECT action,detail FROM audit WHERE action LIKE 'push.%'").toArray()
      expect(audit.map((a) => a.action)).toEqual(["push.done"])
      expect(audit[0]!.detail).not.toContain("test-secret-never-returned")
      expect(ctx.sql.exec("SELECT 1 FROM exposures WHERE source='pushed'").toArray()).toHaveLength(1)
      // Removing the machine's owner asks for the pushed value to be rotated.
      expect(beforeOffboarding(ctx, "mem_member").exposures).toContainEqual(expect.objectContaining({ source: "pushed", device: "dev_member", event: `push:${handOut.push}` }))
      // The same ask within ten minutes answers with what was done.
      expect(await askPush(ctx)).toMatchObject({ done: { push: handOut.push, item: "openai-prod", destination: "github:acme/api/OPENAI_API_KEY", via: "gh-token", outcome: "created" } })
    })
  })

  it("is not sent once its credential changed after the decision, nor after two minutes, and a send unrecorded for five minutes is unknown", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const first = await askPush(ctx)
      if (!("approval" in first)) throw new Error("Expected approval_required")
      await approvePush(ctx, first.approval)
      fixtureSql(ctx).exec("UPDATE items SET version=version+1 WHERE slug='openai-prod'")
      const refused = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: first.approval }, systemInvocation(ctx)) as PushHandOut
      expect(refused).toMatchObject({ sent: false, reason: "The credential or the one carrying it changed before Mehen sent it; nothing was sent." })
      expect(pushOf(ctx, first.approval)?.state).toBe("not_sent")

      const second = await askPush(ctx, pushRequest({ name: "SECOND" }))
      const third = await askPush(ctx, pushRequest({ name: "THIRD" }))
      if (!("approval" in second) || !("approval" in third)) throw new Error("Expected approval_required")
      await approvePush(ctx, second.approval)
      await approvePush(ctx, third.approval)
      const sending = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: third.approval }, systemInvocation(ctx)) as PushHandOut
      expect(sending.sent).toBe(true)
      const later = Object.assign(Object.create(ctx) as VaultContext, { now: () => ctx.now() + 300_000 })
      sweepPushes(later)
      expect(pushOf(ctx, second.approval)?.state).toBe("not_sent")
      expect(pushOf(ctx, third.approval)?.state).toBe("unknown")
      expect(ctx.sql.exec<{ action: string }>("SELECT action FROM audit WHERE action LIKE 'push.%' ORDER BY rowid").toArray().map((a) => a.action)).toEqual(["push.not_sent", "push.not_sent", "push.unknown"])
    })
  })
})

// Review together: a push is decided on its own page, where it is sent.
describe("a push ask in a review group", () => {
  const group = (ctx: VaultContext, role: string, id: string) => workspaceApprovalBatchOps["approvals.group"]!.handler(ctx, memberPrincipal(ctx, role), { id }, memberInvocation(ctx, role)) as ApprovalGroupView
  const decideMany = (ctx: VaultContext, role: string, entries: { id: string; decision: "approve" | "deny" }[]) => {
    const action = workspaceApprovalBatchOps["approvals.action_many"]!.handler(ctx, memberPrincipal(ctx, role), { entries }, memberInvocation(ctx, role)) as WorkspaceStepUpAction
    return workspaceApprovalBatchOps["approvals.decide_many"]!.handler(ctx, memberPrincipal(ctx, role), { entries }, memberInvocation(ctx, role, action)) as ApprovalBatchResult
  }

  it("is listed own-page for its push, refused in a batch whether approved or denied, and still queued and sent once when approved on its page", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      const row = workspaceApproval(ctx, asked.approval)!
      expect(row.review_group).toMatch(/^grp_/)
      expect(group(ctx, "member", row.review_group!).rows).toEqual([expect.objectContaining({ view: "detail", batch: "own-page", ownPage: "push" })])
      for (const decision of ["approve", "deny"] as const) expect(decideMany(ctx, "member", [{ id: asked.approval, decision }]).results).toEqual([{ approval: asked.approval, outcome: "own_page", message: "Decide this one on its own page." }])
      expect(workspaceApproval(ctx, asked.approval)!.status).toBe("pending")
      expect(ctx.sql.exec("SELECT id FROM pushes").toArray()).toEqual([])
      await approvePush(ctx, asked.approval)
      expect(ctx.sql.exec("SELECT state FROM pushes WHERE approval=?", asked.approval).toArray()).toEqual([{ state: "queued" }])
      const execute = () => workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as Promise<PushHandOut>
      expect(await execute()).toMatchObject({ sent: true })
      expect(await refusal(execute)).toMatchObject({ code: "conflict" })
      expect(ctx.sql.exec("SELECT state FROM pushes WHERE approval=?", asked.approval).toArray()).toEqual([{ state: "sending" }])
    })
  })

  it("is counted in the inbox's group row as decided on its own page, from the push itself, not its warning", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await pushReady(ctx)
      const first = await askPush(ctx, pushRequest({ name: "FIRST" })), second = await askPush(ctx, pushRequest({ name: "SECOND" }))
      if (!("approval" in first) || !("approval" in second)) throw new Error("Expected approval_required")
      ctx.sql.exec("UPDATE approvals SET presentation=json_remove(presentation,'$.warnings')")
      const inbox = workspacePendingOps["pending.inbox"]!.handler(ctx, memberPrincipal(ctx, "member"), { enrolments: [] }, memberInvocation(ctx, "member")) as WorkspaceInboxAnswer
      expect(inbox.items.flatMap((item) => item.kind === "group" ? [item.group] : [])).toEqual([expect.objectContaining({ count: 2, ownPage: 2, floor: 0 })])
    })
  })

  it("is an own-page stop row to a person who may deny it but not see what carries it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai-prod")
      await updateItem(ctx, "openai-prod", { pushable: true })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      await seedGitHubVia(ctx, "member-github", { kind: "member", member: "mem_member" }, "member")
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      const row = workspaceApproval(ctx, asked.approval)!
      expect(group(ctx, "owner", row.review_group!).rows).toEqual([{ view: "stop", stop: expect.objectContaining({ id: asked.approval }), batch: "own-page" }])
      expect(decideMany(ctx, "owner", [{ id: asked.approval, decision: "deny" }]).results).toEqual([{ approval: asked.approval, outcome: "own_page", message: "Decide this one on its own page." }])
      expect(workspaceApproval(ctx, asked.approval)!.status).toBe("pending")
    })
  })
})

// A done push of openai-prod to GitHub acme/api, asked by the machine and
// recorded as the Worker would, then a rotation to a new version.
async function pushedThenRotated(ctx: VaultContext): Promise<string> {
  await pushReady(ctx)
  const asked = await askPush(ctx)
  if (!("approval" in asked)) throw new Error("Expected approval_required")
  await approvePush(ctx, asked.approval)
  const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as PushHandOut
  await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "created", providerStatus: 201 }, systemInvocation(ctx))
  fixtureSql(ctx).exec("UPDATE items SET version=version+1 WHERE slug='openai-prod'")
  return handOut.push
}

describe("a person pushing a rotated value to where it went before", () => {
  it("signs item.push over the records' places and the current versions, and queues one push each, by the person", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const record = await pushedThenRotated(ctx)
      const described = workspaceItemOps["items.describe"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod" }, memberInvocation(ctx)) as { pushes: { push: string; current: boolean }[] }
      expect(described.pushes).toEqual([expect.objectContaining({ push: record, current: false })])
      const item = ctx.sql.exec<{ id: string; version: number }>("SELECT id,version FROM items WHERE slug='openai-prod'").toArray()[0]!
      const via = ctx.sql.exec<{ id: string; version: number }>("SELECT id,version FROM items WHERE slug='gh-token'").toArray()[0]!
      const action = workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx))
      expect(action).toEqual({ type: "item.push", item: item.id, field: "key", version: item.version, pushes: [{ destination: "github:acme/api/OPENAI_API_KEY", via: via.id, viaVersion: via.version }] })
      const queued = await workspacePushOps["push.again"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx, "owner", action as WorkspaceStepUpAction)) as { pushes: string[] }
      expect(ctx.sql.exec("SELECT item_version,member,device,approval,state FROM pushes WHERE id=?", queued.pushes[0]!).toArray()).toEqual([{ item_version: item.version, member: "mem_owner", device: null, approval: null, state: "queued" }])
      const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { push: queued.pushes[0]! }, systemInvocation(ctx)) as PushHandOut
      expect(handOut.sent).toBe(true)
    })
  })

  it("is refused without a passkey over the same action, for a credential or a via four eyes guard, and without the allowance", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const record = await pushedThenRotated(ctx)
      const again = (action?: WorkspaceStepUpAction) => refusal(async () => workspacePushOps["push.again"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx, "owner", action)))
      expect(await again()).toMatchObject({ code: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      const action = workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx)) as Extract<WorkspaceStepUpAction, { type: "item.push" }>
      expect(await again({ ...action, version: action.version - 1 })).toMatchObject({ code: "forbidden" })
      await updateItem(ctx, "openai-prod", { pushable: false })
      expect(await again(action)).toMatchObject({ code: "mode_refused" })
      await updateItem(ctx, "openai-prod", { pushable: true })
      const idOf = (slug: string) => ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug=?", slug).toArray()[0]!.id
      const item = idOf("openai-prod"), via = idOf("gh-token")
      const plan = () => workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx)) as WorkspaceStepUpAction
      const prod = (edit: (references: { variable: string; field: string; item: string; home: { kind: "workspace" }; revision: number }[]) => void) => editAccessFixture(ctx, (state) => { edit(state.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "prod")!.references as never) })
      // The via, then the credential, referenced from prj_a's protected, four-eyes environment.
      const signed = plan()
      prod((references) => references.push({ variable: "GITHUB", field: "key", item: via, home: { kind: "workspace" }, revision: 1 }))
      expect(await refusal(async () => plan())).toMatchObject({ code: "forbidden", message: "Push this from a machine's ask, so a second person decides." })
      expect(await again(signed)).toMatchObject({ code: "forbidden", message: "Push this from a machine's ask, so a second person decides." })
      prod((references) => references.splice(references.findIndex((r) => r.item === via), 1))
      prod((references) => references.push({ variable: "OPENAI", field: "key", item, home: { kind: "workspace" }, revision: 1 }))
      expect(await refusal(async () => plan())).toMatchObject({ code: "forbidden", message: "Push this from a machine's ask, so a second person decides." })
      expect(await again(signed)).toMatchObject({ code: "forbidden", message: "Push this from a machine's ask, so a second person decides." })
      prod((references) => references.splice(references.findIndex((r) => r.item === item), 1))
      // Queued before the via was put under four eyes: not sent.
      const queued = await workspacePushOps["push.again"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", records: [record] }, memberInvocation(ctx, "owner", plan())) as { pushes: string[] }
      prod((references) => references.push({ variable: "GITHUB", field: "key", item: via, home: { kind: "workspace" }, revision: 1 }))
      expect(await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { push: queued.pushes[0]! }, systemInvocation(ctx))).toMatchObject({ sent: false, reason: "Push this from a machine's ask, so a second person decides." })
    })
  })
})

// A done push of prj_a's openai-prod, then a rotation to a new version.
async function pushedProjectCredential(ctx: VaultContext): Promise<PushHandOut> {
  await seedCredential(ctx, "openai-prod", { kind: "project", project: "prj_a" })
  await updateItem(ctx, "openai-prod", { pushable: true })
  await seedGitHubVia(ctx)
  const asked = await askPush(ctx)
  if (!("approval" in asked)) throw new Error("Expected approval_required")
  await approvePush(ctx, asked.approval)
  const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as PushHandOut
  await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "created", providerStatus: 201 }, systemInvocation(ctx))
  fixtureSql(ctx).exec("UPDATE items SET version=version+1 WHERE slug='openai-prod'")
  return handOut
}

describe("who may push a credential again", () => {
  it("is an admin or a manager of a shared credential's project, and a member who only edits it gets the answer any change they may not manage gets", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const handOut = await pushedProjectCredential(ctx)
      const again = async (role: string) => {
        const action = workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx, role), { slug: "openai-prod", records: [handOut.push] }, memberInvocation(ctx, role)) as WorkspaceStepUpAction
        return workspacePushOps["push.again"]!.handler(ctx, memberPrincipal(ctx, role), { slug: "openai-prod", records: [handOut.push] }, memberInvocation(ctx, role, action)) as { pushes: string[] }
      }
      const update = await refusal(() => updateItem(ctx, "openai-prod", { description: "x" }, "member"))
      expect(update).toMatchObject({ code: "forbidden", message: "You are not allowed to do that." })
      const refused = await refusal(() => again("member"))
      expect({ code: refused.code, message: refused.message }).toEqual({ code: update.code, message: update.message })
      expect(ctx.sql.exec("SELECT id FROM pushes WHERE member IS NOT NULL").toArray()).toEqual([])
      const queued = (await again("kim")).pushes
      expect(queued).toHaveLength(1)
      // Checked again when it is sent: a manager who now only edits sends nothing.
      fixtureSql(ctx).exec("UPDATE project_shares SET value=json_set(value,'$.level','edit') WHERE id='shr_kim'")
      expect(await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { push: queued[0]! }, systemInvocation(ctx))).toMatchObject({ sent: false, reason: "You may no longer push this credential; nothing was sent." })
    })
  })

  it("is checked before the page plans the passkey: a member who only edits it gets that same answer, never one about the push", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const handOut = await pushedProjectCredential(ctx)
      const update = await refusal(() => updateItem(ctx, "openai-prod", { description: "x" }, "member"))
      const plan = async () => {
        const refused = await refusal(async () => workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx, "member"), { slug: "openai-prod", records: [handOut.push] }, memberInvocation(ctx, "member")))
        return { code: refused.code, message: refused.message }
      }
      expect(await plan()).toEqual({ code: update.code, message: update.message })
      // Not the allowance's refusal, which a manager would get.
      await updateItem(ctx, "openai-prod", { pushable: false })
      expect(await plan()).toEqual({ code: update.code, message: update.message })
    })
  })
})

describe("the pushes a credential lists", () => {
  it("name the credential that carried each only to a viewer who may see it, and never who pushed to a machine", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const SENTINEL = "members-private-github-sentinel"
      await seedCredential(ctx, "openai-prod")
      await updateItem(ctx, "openai-prod", { pushable: true })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      await seedGitHubVia(ctx, SENTINEL, { kind: "member", member: "mem_member" }, "member")
      const asked = await askPush(ctx)
      if (!("approval" in asked)) throw new Error("Expected approval_required")
      await approvePush(ctx, asked.approval)
      const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as PushHandOut
      await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "created", providerStatus: 201 }, systemInvocation(ctx))
      const byPerson = (role: string) => (workspaceItemOps["items.describe"]!.handler(ctx, memberPrincipal(ctx, role), { slug: "openai-prod" }, memberInvocation(ctx, role)) as { pushes: Record<string, unknown>[] }).pushes
      const byMachine = async (device: string) => (workspaceItemOps["items.describe"]!.handler(ctx, devicePrincipal(device), { slug: "openai-prod" }, await deviceInvocation(ctx, device)) as { pushes: Record<string, unknown>[] }).pushes
      expect(byPerson("member")).toEqual([expect.objectContaining({ via: SENTINEL, by: expect.any(String) })])
      const owner = byPerson("owner")
      expect(owner).toEqual([expect.objectContaining({ push: handOut.push, via: null })])
      expect(JSON.stringify(owner)).not.toContain(SENTINEL)
      const own = await byMachine("dev_member")
      expect(own).toEqual([expect.objectContaining({ via: SENTINEL })])
      expect(own[0]).not.toHaveProperty("by")
      const other = await byMachine("dev_owner")
      expect(other).toEqual([expect.objectContaining({ push: handOut.push, via: null })])
      expect(other[0]).not.toHaveProperty("by")
      expect(JSON.stringify(other)).not.toContain(SENTINEL)
      // The workspace's audit row for a shared credential names no private via.
      const audit = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='push.done'").toArray()
      expect(audit).toHaveLength(1)
      expect(audit[0]!.detail).not.toContain(SENTINEL)
    })
  })

  it("never name who pushed to a guest, a person or a machine", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const MEMBER = "member-name-sentinel", MACHINE = "machine-name-sentinel"
      await seedCredential(ctx, "openai-prod", { kind: "project", project: "prj_a" })
      await updateItem(ctx, "openai-prod", { pushable: true })
      await seedGitHubVia(ctx)
      const pushedByMachine = async (name: string) => {
        const asked = await askPush(ctx, pushRequest({ name }))
        if (!("approval" in asked)) throw new Error("Expected approval_required")
        await approvePush(ctx, asked.approval)
        const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { approval: asked.approval }, systemInvocation(ctx)) as PushHandOut
        await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "created", providerStatus: 201 }, systemInvocation(ctx))
        return handOut.push
      }
      const first = await pushedByMachine("FIRST")
      await pushedByMachine("SECOND")
      // Kim, a manager of prj_a, pushes the first place again.
      const action = workspacePushOps["push.action"]!.handler(ctx, memberPrincipal(ctx, "kim"), { slug: "openai-prod", records: [first] }, memberInvocation(ctx, "kim")) as WorkspaceStepUpAction
      const queued = await workspacePushOps["push.again"]!.handler(ctx, memberPrincipal(ctx, "kim"), { slug: "openai-prod", records: [first] }, memberInvocation(ctx, "kim", action)) as { pushes: string[] }
      const handOut = await workspacePushOps["push.execute"]!.handler(ctx, { kind: "system" }, { push: queued.pushes[0]! }, systemInvocation(ctx)) as PushHandOut
      await workspacePushOps["push.record"]!.handler(ctx, { kind: "system" }, { push: handOut.push, state: "done", outcome: "replaced", providerStatus: 204 }, systemInvocation(ctx))
      fixtureSql(ctx).exec("UPDATE members SET name=? WHERE id='mem_kim'", MEMBER)
      ctx.sql.exec("UPDATE approvals SET device_name=?", MACHINE)
      const byPerson = (role: string) => (workspaceItemOps["items.describe"]!.handler(ctx, memberPrincipal(ctx, role), { slug: "openai-prod" }, memberInvocation(ctx, role)) as { pushes: Record<string, unknown>[] }).pushes
      expect(byPerson("owner").map((p) => p.by).sort()).toEqual([MACHINE, MEMBER])
      const guest = byPerson("guest")
      expect(guest).toHaveLength(2)
      for (const p of guest) expect(p).not.toHaveProperty("by")
      expect(JSON.stringify(workspaceItemOps["items.describe"]!.handler(ctx, memberPrincipal(ctx, "guest"), { slug: "openai-prod" }, memberInvocation(ctx, "guest")))).not.toMatch(new RegExp(`${MEMBER}|${MACHINE}`))
    })
  })
})

describe("the pushes area", () => {
  it("creates its tables, a ticket keeping the via it was prepared with, in a migration a workspace without pushes applies", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP TABLE pushes"))
      withTrustedSchema(ctx, () => ctx.sql.exec("DROP TABLE push_tickets"))
      ctx.sql.exec("DELETE FROM _migrations WHERE area='pushes'")
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [pushesArea]))
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='pushes'").toArray()[0]!.applied).toBe(1)
      expect(ctx.sql.exec("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='pushes' AND sql IS NOT NULL ORDER BY name").toArray()).toEqual([{ name: "pushes_item" }, { name: "pushes_owner" }])
      expect(withTrustedSchema(ctx, () => ctx.sql.exec<{ name: string; type: string; notnull: number; pk: number }>("PRAGMA table_info(push_tickets)")).toArray().map(({ name, type, notnull, pk }) => ({ name, type, notnull, pk }))).toEqual([
        { name: "id", type: "TEXT", notnull: 0, pk: 1 },
        { name: "device", type: "TEXT", notnull: 1, pk: 0 },
        { name: "workload", type: "TEXT", notnull: 0, pk: 0 },
        { name: "request", type: "TEXT", notnull: 1, pk: 0 },
        { name: "via", type: "TEXT", notnull: 1, pk: 0 },
        { name: "workspace", type: "TEXT", notnull: 1, pk: 0 },
        { name: "expires_at", type: "INTEGER", notnull: 1, pk: 0 },
      ])
    })
  })
})
