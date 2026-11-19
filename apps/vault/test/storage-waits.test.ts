// The long polls (storage-waits.ts): an approval, intake or adoption wait
// re-checks when its object's storage is written, and otherwise at most
// every LONG_POLL_RECHECK_MS until its deadline. Counted by the statements
// each check runs on its row, never timed.
import { describe, expect, it, vi } from "vitest"
import type { VaultContext } from "../src/vault/core.ts"
import { invocationContext } from "../src/vault/tenant-vault.ts"
import { LONG_POLL_MIN_GAP_MS, LONG_POLL_RECHECK_MS, storageWaiterCount } from "../src/vault/storage-waits.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { createWorkspaceIntake, workspaceIntakeOps } from "../src/vault/areas/intake-workspace.ts"
import { workspaceAdoptionOps } from "../src/vault/areas/adoptions.ts"
import { callProject, projectDeviceInvocation, projectFixture, projectState } from "./projects-workspace-fixture.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess } from "./credentials-test-support.ts"

const APPROVAL_READ = "SELECT * FROM approvals WHERE id=? AND ask IS NOT NULL"
const ACCESS_STATE_READ = "SELECT id,owner_kind,owner_id,scope,revoked_at FROM devices WHERE owner_kind IS NOT NULL"
const REQUEST_READ = "SELECT * FROM workspace_credential_requests WHERE id=?"
const BATCH_READ = "SELECT * FROM adoption_batches WHERE id=?"
const WAIT_MS = 300
const MOST_CHECKS = Math.ceil(WAIT_MS / LONG_POLL_RECHECK_MS) + 1

function reads(ctx: VaultContext, query: string): { count: () => number; restore: () => void } {
  const exec = vi.spyOn(ctx.sql, "exec")
  return { count: () => exec.mock.calls.filter((call) => call[0] === query).length, restore: () => exec.mockRestore() }
}
// Lets every queued microtask and the task after them run.
const settle = () => new Promise((resolve) => setTimeout(resolve, 0))
// Lets a woken wait's minimum gap pass, well inside LONG_POLL_RECHECK_MS.
const afterGap = () => new Promise((resolve) => setTimeout(resolve, LONG_POLL_MIN_GAP_MS + 50))
// Long enough that a wait woken at the start is still waiting after afterGap.
const GAP_WAIT_MS = 1_000

// Three approval waits from one machine, each its own call, on one pending approval.
async function threeApprovalWaits(ctx: VaultContext) {
  const SUBJECT = { item: "key-project", method: "POST", url: "https://api.example.com/write", contentType: "application/json", contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf("{}"), constraints: { uses: 1, ttlSeconds: 600 } }
  const presentation = { title: "Write a record", details: [{ label: "Action", value: "Write" }], body: "{}", headers: [] as [string, string][] }
  const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
  const principal = { kind: "device" as const, deviceId: "dev_kim" }
  const asked = prepareApprovedUse(ctx, state, { principal, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation, batch: { floor: [], shape: "shape-write", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, SUBJECT, null, ctx.now())
  const row = workspaceApproval(ctx, asked.approvalId)!
  const invocation = await projectDeviceInvocation(ctx)
  const settled: boolean[] = [false, false, false]
  const waits = settled.map((_, n) => Promise.resolve(workspaceApprovalOps["approvals.status"]!.handler(invocationContext(ctx), principal, { id: row.id, wait: true }, invocation)).finally(() => { settled[n] = true }))
  // Observed now, so a refusal before the test awaits it is not unhandled.
  const outcomes = Promise.allSettled(waits)
  const decide = () => callProject(invocationContext(ctx), projectState(ctx), "owner", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: SUBJECT.constraints })
  return { row, settled, outcomes, decide }
}

describe("long polls wake on a write to their object", () => {
  it("an approval wait returns approved once another call decides it, after one more check", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const SUBJECT = { item: "key-project", method: "POST", url: "https://api.example.com/write", contentType: "application/json", contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf("{}"), constraints: { uses: 1, ttlSeconds: 600 } }
      const presentation = { title: "Write a record", details: [{ label: "Action", value: "Write" }], body: "{}", headers: [] as [string, string][] }
      const state = projectState(ctx), item = state.credentials.find((c) => c.home.kind === "project")!
      const principal = { kind: "device" as const, deviceId: "dev_kim" }
      const asked = prepareApprovedUse(ctx, state, { principal, workspace: { id: ctx.tenant, name: "Work", slug: "work" }, presentation, batch: { floor: [], shape: "shape-write", replaces: null } }, { ...item, slug: "key-project", version: 1 }, { project: "prj_a", env: "prod" }, SUBJECT, null, ctx.now())
      const row = workspaceApproval(ctx, asked.approvalId)!
      const approvalReads = reads(ctx, APPROVAL_READ)
      try {
        let settled = false
        const pending = Promise.resolve(workspaceApprovalOps["approvals.status"]!.handler(invocationContext(ctx), principal, { id: row.id, wait: true }, await projectDeviceInvocation(ctx))).finally(() => { settled = true })
        await settle()
        expect(settled).toBe(false)
        expect(approvalReads.count()).toBe(1)
        const before = approvalReads.count()
        callProject(invocationContext(ctx), projectState(ctx), "owner", "approvals.decide", { id: row.id, decision: "approve" }, { type: "approval.decide", approval: row.id, digest: row.digest, decision: "approve", constraints: SUBJECT.constraints })
        const deciding = approvalReads.count() - before
        // Without the wake it would sleep until its LONG_POLL_RECHECK_MS re-check.
        await afterGap()
        expect(settled).toBe(true)
        await expect(pending).resolves.toMatchObject({ approval: row.id, status: "approved" })
        expect(approvalReads.count() - deciding).toBe(2)
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        approvalReads.restore()
      }
    })
  })

  it("three approval waits woken by one unrelated nonce write rebuild the access state once between them, and all return approved once it is decided", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const builds = reads(ctx, ACCESS_STATE_READ)
      try {
        const { row, settled, outcomes, decide } = await threeApprovalWaits(ctx)
        await settle()
        expect(settled).toEqual([false, false, false])
        expect(storageWaiterCount(ctx.storage)).toBe(3)
        const before = builds.count()
        ctx.sql.exec("INSERT INTO device_nonces (device, jti, expires_at) VALUES (?, ?, ?)", "dev_kim", "jti_unrelated", ctx.now() + 60_000)
        await afterGap()
        expect(settled).toEqual([false, false, false])
        expect(storageWaiterCount(ctx.storage)).toBe(3)
        expect(builds.count() - before).toBe(1)
        decide()
        await afterGap()
        expect(settled).toEqual([true, true, true])
        expect((await outcomes).map((o) => o.status === "fulfilled" ? o.value : o.reason)).toEqual([0, 1, 2].map(() => expect.objectContaining({ approval: row.id, status: "approved" })))
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        builds.restore()
      }
    })
  })

  it("a machine revoked while three of its approval waits are open is refused by every one of them", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const builds = reads(ctx, ACCESS_STATE_READ)
      try {
        const { settled, outcomes } = await threeApprovalWaits(ctx)
        await settle()
        expect(settled).toEqual([false, false, false])
        const before = builds.count()
        ctx.sql.exec("UPDATE devices SET revoked_at=? WHERE id='dev_kim'", ctx.now())
        await afterGap()
        expect(settled).toEqual([true, true, true])
        expect(builds.count() - before).toBe(1)
        // The evaluator's refusal for a machine that is no longer active (access.ts reach).
        expect((await outcomes).map((o) => o.status === "rejected" ? o.reason : o.value)).toEqual([0, 1, 2].map(() => expect.objectContaining({ code: "owner_inactive", status: 403 })))
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        builds.restore()
      }
    })
  })

  it(`an intake wait with no writes checks at most ${MOST_CHECKS} times and leaves nothing waiting`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const p = devicePrincipal(), i = await deviceInvocation(ctx)
      const { intake } = createWorkspaceIntake(ctx, p, { provider: "openai", kind: "api-key", slug: "quiet-intake", home: "project", project: "prj_a", reason: "test" }, i)
      const requestReads = reads(ctx, REQUEST_READ)
      try {
        await expect(workspaceIntakeOps["intake.status"].handler(ctx, p, { intake, waitMs: WAIT_MS }, i)).resolves.toMatchObject({ intake, status: "open" })
        expect(requestReads.count()).toBeLessThanOrEqual(MOST_CHECKS)
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        requestReads.restore()
      }
    })
  })

  it("an unrelated write wakes an intake wait, which checks again and keeps waiting", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const p = devicePrincipal(), i = await deviceInvocation(ctx)
      const { intake } = createWorkspaceIntake(ctx, p, { provider: "openai", kind: "api-key", slug: "woken-intake", home: "project", project: "prj_a", reason: "test" }, i)
      const requestReads = reads(ctx, REQUEST_READ)
      try {
        let settled = false
        const pending = workspaceIntakeOps["intake.status"].handler(ctx, p, { intake, waitMs: GAP_WAIT_MS }, i).finally(() => { settled = true })
        expect(requestReads.count()).toBe(1)
        expect(storageWaiterCount(ctx.storage)).toBe(1)
        ctx.storage.transactionSync(() => ctx.sql.exec("UPDATE members SET name='Kim A' WHERE id='mem_kim'"))
        await settle()
        expect(requestReads.count()).toBe(1)
        await afterGap()
        expect(requestReads.count()).toBe(2)
        expect(settled).toBe(false)
        expect(storageWaiterCount(ctx.storage)).toBe(1)
        await expect(pending).resolves.toMatchObject({ intake, status: "open" })
        expect(requestReads.count()).toBeLessThanOrEqual(MOST_CHECKS + 1)
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        requestReads.restore()
      }
    })
  })

  it("twenty quick writes wake an intake wait at most once before the minimum gap has passed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const p = devicePrincipal(), i = await deviceInvocation(ctx)
      const { intake } = createWorkspaceIntake(ctx, p, { provider: "openai", kind: "api-key", slug: "busy-intake", home: "project", project: "prj_a", reason: "test" }, i)
      const requestReads = reads(ctx, REQUEST_READ)
      try {
        const started = Date.now()
        const pending = workspaceIntakeOps["intake.status"].handler(ctx, p, { intake, waitMs: GAP_WAIT_MS }, i)
        for (let write = 0; write < 20; write++) {
          ctx.sql.exec("UPDATE members SET name=? WHERE id='mem_kim'", `Kim ${write}`)
          await settle()
        }
        // The first check and at most one wake per minimum gap that has
        // really passed: a slow runner may spend more than one gap on the
        // writes, and each gap it spends allows one more check.
        const gaps = Math.floor((Date.now() - started) / LONG_POLL_MIN_GAP_MS)
        expect(requestReads.count()).toBeLessThanOrEqual(2 + gaps)
        await expect(pending).resolves.toMatchObject({ intake, status: "open" })
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        requestReads.restore()
      }
    })
  })

  it(`an adoption wait with no writes checks at most ${MOST_CHECKS} times and leaves nothing waiting`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const p = devicePrincipal("dev_owner"), i = await deviceInvocation(ctx, "dev_owner")
      const { adoption } = await workspaceAdoptionOps["adoption.create"].handler(ctx, p, { machine: "office", expectedItems: 2 }, i) as { adoption: string }
      const batchReads = reads(ctx, BATCH_READ)
      try {
        await expect(workspaceAdoptionOps["adoption.status"].handler(ctx, p, { adoption, waitMs: WAIT_MS }, i)).resolves.toMatchObject({ adoption, status: "open" })
        expect(batchReads.count()).toBeLessThanOrEqual(MOST_CHECKS)
        expect(storageWaiterCount(ctx.storage)).toBe(0)
      } finally {
        batchReads.restore()
      }
    })
  })
})
