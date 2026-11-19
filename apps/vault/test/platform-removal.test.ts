// Removing a platform with real managed workspaces: the cron deletes every
// subject and purges each one without waiting for the audit retention,
// then frees the slug (sweeps.ts with areas/managed.ts), so the slug can be
// registered again, as the operator console's Remove says. The changes are
// planned by operator-plan.ts, the planner the console and the operator
// script both run.

import { webCryptoPlatformSigner } from "@mehen/protocol"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import type { Env } from "../src/env.ts"
import { type PlatformChange, type PlatformPlan, newPlanIds, planPlatformChange, platformRowBySlug } from "../src/platform/operator-plan.ts"
import { maintainPlatforms } from "../src/platform/sweeps.ts"
import { purgeSubjectWorkspace } from "../src/platform/workspace-calls.ts"
import type { InvocationResult } from "../src/vault/core.ts"
import { signed } from "./managed-support.ts"
import { newPlatformKey, platformFetch, registerPlatform } from "./platform-fixtures.ts"

const ACTOR = "operator:test"

async function applyChange(world: Env, change: PlatformChange, now: number, ids = newPlanIds()): Promise<PlatformPlan> {
  const row = await world.DB.prepare(platformRowBySlug(change.slug)).first<Parameters<typeof planPlatformChange>[1] & object>()
  const planned = await planPlatformChange(change, row, async <T>(sql: string) => (await world.DB.prepare(sql).all<T>()).results, now, ids)
  if (typeof planned === "string") throw new Error(planned)
  await world.DB.batch(planned.statements.map((statement) => world.DB.prepare(statement)))
  return planned
}

async function makeSubjects(world: Env, platform: Awaited<ReturnType<typeof registerPlatform>>, subjects: string[]): Promise<void> {
  for (const subject of subjects) expect((await platformFetch(world, platform, { method: "PUT", path: `/v1/platform/subjects/${subject}`, body: {} })).status).toBe(201)
}

async function subjectStatuses(world: Env, platform: string): Promise<{ status: string; subject: string | null }[]> {
  return (await world.DB.prepare("SELECT status,subject FROM managed_workspaces WHERE platform=? ORDER BY tenant").bind(platform).all<{ status: string; subject: string | null }>()).results
}

describe("removing a platform", () => {
  it("purges its live and already deleted subjects in two cron runs, frees its slug, and the slug registers again", async () => {
    const world = env as Env
    const platform = await registerPlatform(world)
    await makeSubjects(world, platform, ["removal-live-0001", "removal-gone-0001"])
    // One subject the platform deleted itself, its audit kept for 30 days.
    expect((await platformFetch(world, platform, { method: "DELETE", path: "/v1/platform/subjects/removal-gone-0001", body: {} })).status).toBe(200)
    const now = Date.now()
    await applyChange(world, { command: "remove", slug: platform.slug, reason: "Set up again", actor: ACTOR }, now)

    await maintainPlatforms(world, now + 1)
    await maintainPlatforms(world, now + 2)

    expect(await subjectStatuses(world, platform.id)).toEqual([{ status: "purged", subject: null }, { status: "purged", subject: null }])
    const row = await world.DB.prepare("SELECT slug,removed_slug,status FROM platforms WHERE id=?").bind(platform.id).first<{ slug: string; removed_slug: string | null; status: string }>()
    expect(row).toMatchObject({ removed_slug: platform.slug, status: "retired", slug: expect.stringMatching(/^removed-/) })
    // The record of the removal is kept: its events and each subject's
    // final audit head.
    const actions = (await world.DB.prepare("SELECT action FROM platform_events WHERE platform=? AND action!='platform.activity' ORDER BY at,rowid").bind(platform.id).all<{ action: string }>()).results.map((e) => e.action)
    expect(actions).toEqual(["operator.remove", "platform.retired", "platform.removed"])
    const heads = await world.DB.prepare("SELECT final_audit_head FROM managed_workspaces WHERE platform=?").bind(platform.id).all<{ final_audit_head: string | null }>()
    expect(heads.results.every((h) => typeof h.final_audit_head === "string" && h.final_audit_head.length > 0)).toBe(true)

    const { jwk } = await newPlatformKey()
    const again = await applyChange(world, { command: "register", slug: platform.slug, name: "Again", key: jwk, limits: null, actor: ACTOR }, Date.now())
    expect(again.done).toContain(`Registered ${platform.slug}.`)
  })

  // What a platform that is set up again meets (build-on-mehen.md, Retiring
  // and removing): its old devices are refused, and every user starts anew.
  it("refuses an old device unauthenticated once its workspace is purged, and the platform registered again makes the same subject a new workspace", async () => {
    const world = env as Env
    const platform = await registerPlatform(world)
    await makeSubjects(world, platform, ["removal-again-0001"])
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const exported = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey
    const made = await platformFetch(world, platform, { method: "POST", path: "/v1/platform/subjects/removal-again-0001/devices", body: { name: "agent", jwk: { kty: "EC", crv: "P-256", x: exported.x, y: exported.y }, modes: ["relay"] } })
    expect(made.status).toBe(201)
    const old = (await made.json()) as { device: string; tenant: string }
    expect((await signed(old.tenant, { device: old.device, keys }, "/v1/items")).status).toBe(200)

    const now = Date.now()
    await applyChange(world, { command: "remove", slug: platform.slug, reason: "Set up again", actor: ACTOR }, now)
    await maintainPlatforms(world, now + 1)
    await maintainPlatforms(world, now + 2)
    const refused = await signed(old.tenant, { device: old.device, keys }, "/v1/items")
    expect({ status: refused.status, error: ((await refused.json()) as { error: string }).error }).toEqual({ status: 401, error: "unauthenticated" })

    const key = await newPlatformKey()
    const ids = newPlanIds()
    await applyChange(world, { command: "register", slug: platform.slug, name: "Again", key: key.jwk, limits: null, actor: ACTOR }, Date.now(), ids)
    const again = { id: ids.platform, slug: platform.slug, key: ids.key, signer: webCryptoPlatformSigner(ids.platform, ids.key, key.privateKey) }
    expect((await platformFetch(world, again, { method: "GET", path: "/v1/platform" })).status).toBe(200)
    const ensured = await platformFetch(world, again, { method: "PUT", path: "/v1/platform/subjects/removal-again-0001", body: {} })
    expect(ensured.status).toBe(201)
    const fresh = await world.DB.prepare("SELECT tenant FROM managed_workspaces WHERE platform=? AND subject=?").bind(ids.platform, "removal-again-0001").first<{ tenant: string }>()
    expect(fresh?.tenant).toMatch(/^tn_/)
    expect(fresh?.tenant).not.toBe(old.tenant)
  })

  it("never purges a live platform's deleted subject before its date, even when told to purge early", async () => {
    const world = env as Env
    const platform = await registerPlatform(world)
    await makeSubjects(world, platform, ["removal-kept-0001"])
    expect((await platformFetch(world, platform, { method: "DELETE", path: "/v1/platform/subjects/removal-kept-0001", body: {} })).status).toBe(200)
    const tenant = (await world.DB.prepare("SELECT tenant FROM managed_workspaces WHERE platform=?").bind(platform.id).first<{ tenant: string }>())?.tenant ?? ""
    // The directory's own early purge, for a platform that is not being
    // removed: the object refuses it.
    await expect(purgeSubjectWorkspace(world, tenant, true)).rejects.toMatchObject({ code: "conflict", message: "This subject's audit is kept until its purge date." })
    // Even with the directory's purge date brought forward, as for a
    // removal, the object keeps its own.
    await world.DB.prepare("UPDATE managed_workspaces SET purge_after=? WHERE tenant=?").bind(Date.now(), tenant).run()
    await maintainPlatforms(world, Date.now() + 1)
    expect(await subjectStatuses(world, platform.id)).toEqual([{ status: "deleted", subject: "removal-kept-0001" }])
  })

  it("lets no platform ask for the purge, early or not", async () => {
    const world = env as Env
    const platform = await registerPlatform(world)
    await makeSubjects(world, platform, ["removal-self-0001"])
    const tenant = (await world.DB.prepare("SELECT tenant FROM managed_workspaces WHERE platform=?").bind(platform.id).first<{ tenant: string }>())?.tenant ?? ""
    const auth = { kind: "platform", platform: platform.id, key: platform.key, subject: "removal-self-0001", jti: `jti_${crypto.randomUUID()}`, iat: Math.floor(Date.now() / 1000) } as const
    const result = (await world.TENANT_VAULT.getByName(tenant).invoke({ op: "platform.subjects.purge", input: { params: {}, query: null, body: { early: true } }, auth })) as InvocationResult
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.error.vaultError.error).toBe("forbidden")
    // Route 7's body takes no member at all.
    const removed = await platformFetch(world, platform, { method: "DELETE", path: "/v1/platform/subjects/removal-self-0001", body: { early: true } })
    expect(removed.status).toBe(400)
    expect(await subjectStatuses(world, platform.id)).toEqual([{ status: "active", subject: "removal-self-0001" }])
  })
})
