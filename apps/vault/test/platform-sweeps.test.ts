// The cron's platform work (src/platform/sweeps.ts), registered in the
// directory's maintenance.

import { runInDurableObject } from "cloudflare:test"
import { describe, expect, it, vi } from "vitest"
import { PLATFORM_DELETE_BATCH } from "@mehen/protocol"
import { maintainWorkspaceDirectory } from "../src/directory/workspace-maintenance.ts"
import type { PlatformVault } from "../src/platform/platform-vault.ts"
import { PLATFORM_CREATING_GRACE_MS, activityEventId, maintainPlatforms, sweepDeletingSubjects } from "../src/platform/sweeps.ts"
import { DEFAULT_WORKSPACE_ANSWER, PURGE_AFTER, addSubject, platformEnv, platformFetch, registerPlatform } from "./platform-fixtures.ts"

async function statuses(env: import("../src/env.ts").Env, platform: string): Promise<Record<string, string>> {
  const rows = await env.DB.prepare("SELECT tenant,status FROM managed_workspaces WHERE platform=?").bind(platform).all<{ tenant: string; status: string }>()
  return Object.fromEntries(rows.results.map((r) => [r.tenant, r.status]))
}

describe("platform sweeps", () => {
  it("delete subjects marked deleting, by route 31, 50 a run, through the workspace with system auth", async () => {
    const { env, calls } = await platformEnv()
    const platform = await registerPlatform(env)
    for (let i = 0; i < PLATFORM_DELETE_BATCH + 2; i++) await addSubject(env, platform.id, `subject-${String(i).padStart(4, "0")}`, "active", { createdAt: 1000 + i })
    expect((await platformFetch(env, platform, { method: "DELETE", path: "/v1/platform/subjects", body: { confirm: platform.slug } })).status).toBe(200)
    const now = Date.now()
    await sweepDeletingSubjects(env, now)
    expect(calls).toHaveLength(PLATFORM_DELETE_BATCH)
    expect(calls.every((c) => c.op === "platform.subjects.remove" && c.auth.kind === "system")).toBe(true)
    const after = Object.values(await statuses(env, platform.id))
    expect(after.filter((s) => s === "deleted")).toHaveLength(PLATFORM_DELETE_BATCH)
    expect(after.filter((s) => s === "deleting")).toHaveLength(2)
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM managed_workspaces WHERE status='deleted' AND deleted_at=? AND purge_after=?").bind(now, PURGE_AFTER).first()).toEqual({ n: PLATFORM_DELETE_BATCH })
    await sweepDeletingSubjects(env, now)
    expect(Object.values(await statuses(env, platform.id)).every((s) => s === "deleted")).toBe(true)
  })

  it("take the subjects tried least recently first, so a full batch that keeps failing never blocks the rest", async () => {
    const failing = new Set<string>()
    const { env, calls } = await platformEnv((call) => (call.op === "platform.subjects.remove" && failing.has(call.tenant) ? { ok: false, error: { vaultError: { error: "internal", message: "Something went wrong inside the vault." }, status: 500 } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    for (let i = 0; i < PLATFORM_DELETE_BATCH; i++) failing.add(await addSubject(env, platform.id, `subject-bad${String(i).padStart(3, "0")}`, "deleting", { createdAt: 1000 + i }))
    const later = [await addSubject(env, platform.id, "subject-good1", "deleting", { createdAt: 5000 }), await addSubject(env, platform.id, "subject-good2", "deleting", { createdAt: 5001 })]
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    const now = Date.now()
    await sweepDeletingSubjects(env, now)
    expect(new Set(calls.map((c) => c.tenant))).toEqual(failing)
    calls.length = 0
    await sweepDeletingSubjects(env, now + 1)
    expect(calls).toHaveLength(PLATFORM_DELETE_BATCH)
    expect(calls.map((c) => c.tenant)).toEqual(expect.arrayContaining(later))
    errors.mockRestore()
    const after = await statuses(env, platform.id)
    expect(later.map((tenant) => after[tenant])).toEqual(["deleted", "deleted"])
    expect([...failing].every((tenant) => after[tenant] === "deleting")).toBe(true)
  })

  it("remove a creation interrupted past its grace, keep a recent one, and leave a failed deletion for the next run", async () => {
    let failing = true
    const { env } = await platformEnv((call) => (call.op === "platform.subjects.remove" && failing ? { ok: false, error: { vaultError: { error: "internal", message: "Something went wrong inside the vault." }, status: 500 } } : DEFAULT_WORKSPACE_ANSWER(call)))
    const platform = await registerPlatform(env)
    const now = Date.now()
    const stale = await addSubject(env, platform.id, "subject-stale", "creating", { createdAt: now - PLATFORM_CREATING_GRACE_MS - 1 })
    const recent = await addSubject(env, platform.id, "subject-recent", "creating", { createdAt: now })
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined)
    await maintainPlatforms(env, now)
    expect(await statuses(env, platform.id)).toEqual({ [stale]: "deleting", [recent]: "creating" })
    expect(errors).toHaveBeenCalledWith(JSON.stringify({ at: "platform.sweep.delete", target: stale }))
    errors.mockRestore()
    failing = false
    await maintainPlatforms(env, now)
    expect(await statuses(env, platform.id)).toEqual({ [stale]: "deleted", [recent]: "creating" })
  })

  it("purge a deleted subject past its date: the audit head kept, the subject's name gone, its hash kept", async () => {
    const { env, calls } = await platformEnv()
    const platform = await registerPlatform(env)
    const due = await addSubject(env, platform.id, "subject-due1", "deleted", { purgeAfter: Date.now() - 1 })
    const later = await addSubject(env, platform.id, "subject-later", "deleted", { purgeAfter: Date.now() + 86_400_000 })
    await maintainPlatforms(env, Date.now())
    expect(calls.map((c) => [c.tenant, c.op, c.auth.kind])).toEqual([[due, "platform.subjects.purge", "system"]])
    expect(await env.DB.prepare("SELECT subject,subject_hash,status,final_audit_head FROM managed_workspaces WHERE tenant=?").bind(due).first()).toEqual({ subject: null, subject_hash: "hash-subject-due1", status: "purged", final_audit_head: `head-${due}` })
    expect(await env.DB.prepare("SELECT status FROM managed_workspaces WHERE tenant=?").bind(later).first()).toEqual({ status: "deleted" })
  })

  it("retire a platform past its date: every subject deleted, then its object erased, its keys revoked and it marked retired", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env, { status: "retiring", retireAfter: Date.now() + 86_400_000 })
    await addSubject(env, platform.id, "subject-aaaa")
    await addSubject(env, platform.id, "subject-bbbb", "creating")
    expect((await platformFetch(env, platform, { method: "GET", path: "/v1/platform" })).status).toBe(200)
    const now = Date.now()
    await maintainPlatforms(env, now)
    expect(Object.values(await statuses(env, platform.id)).sort()).toEqual(["active", "creating"])
    await env.DB.prepare("UPDATE platforms SET retire_after=? WHERE id=?").bind(now - 1, platform.id).run()
    await maintainPlatforms(env, now)
    // The first run marks every subject deleting, and deletes them; the platform waits for the next.
    expect(Object.values(await statuses(env, platform.id))).toEqual(["deleted", "deleted"])
    expect(await env.DB.prepare("SELECT status FROM platforms WHERE id=?").bind(platform.id).first()).toEqual({ status: "retiring" })
    await maintainPlatforms(env, now)
    expect(await env.DB.prepare("SELECT status,retire_after,status_by FROM platforms WHERE id=?").bind(platform.id).first()).toEqual({ status: "retired", retire_after: null, status_by: "system" })
    expect(await env.DB.prepare("SELECT revoked_at,revoked_by FROM platform_keys WHERE platform=?").bind(platform.id).first()).toEqual({ revoked_at: now, revoked_by: "system" })
    expect(await env.DB.prepare("SELECT action FROM platform_events WHERE platform=? AND action='platform.retired'").bind(platform.id).first()).toEqual({ action: "platform.retired" })
    const tables = await runInDurableObject(env.PLATFORM_VAULT.getByName(platform.id), (_: PlatformVault, state) => state.storage.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%'").toArray())
    expect(tables).toEqual([])
  })

  it("copy each platform's last day of activity to one row in D1, and run from the directory's maintenance", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    await platformFetch(env, platform, { method: "GET", path: "/v1/platform" })
    await platformFetch(env, platform, { method: "GET", path: "/v1/platform/subjects/subject-none" })
    await maintainWorkspaceDirectory(env)
    await maintainWorkspaceDirectory(env)
    const rows = await env.DB.prepare("SELECT id,action,detail FROM platform_events WHERE platform=? AND action='platform.activity'").bind(platform.id).all<{ id: string; action: string; detail: string }>()
    expect(rows.results).toHaveLength(1)
    expect(rows.results[0]?.id).toBe(activityEventId(platform.id))
    expect(JSON.parse(rows.results[0]?.detail ?? "{}")).toEqual({ "platform.view": { ok: 1 }, "subjects.get": { not_found: 1 } })
  })
})
