import { describe, expect, it, vi } from "vitest"
import { NOTICE_MAX_ATTEMPTS, deliverNoticeOutbox, queueNotice, registerNoticeDelivery } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, inAccess } from "./access-test-support.ts"

async function queue(tenant: string) { await inAccess(tenant, (ctx) => queueNotice(ctx, { kind: "machine_added", workspace: { id: tenant, slug: "work", name: "Work" }, device: "dev_member", name: "Laptop", owner: { kind: "member", member: "mem_member", name: "Sam" }, place: "Amsterdam", at: new Date().toISOString() })) }
async function rows(tenant: string) { return inAccess(tenant, (ctx) => ctx.sql.exec<{ id: string; acknowledged_at: number | null; attempts: number; next_retry_at: number }>("SELECT id,acknowledged_at,attempts,next_retry_at FROM notice_outbox ORDER BY id").toArray()) }
describe("workspace durable notice outbox", () => {
  it("retains and reschedules what no delivery acknowledges", async () => {
    const { tenant } = await accessFixture()
    await queue(tenant)
    await inAccess(tenant, async (ctx) => {
      const restore = registerNoticeDelivery(async () => [])
      try { await deliverNoticeOutbox(ctx) } finally { restore() }
    })
    expect((await rows(tenant)).every((row) => row.acknowledged_at === null && row.attempts === 1 && row.next_retry_at > Date.now())).toBe(true)
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec("SELECT * FROM schedule WHERE area='access' AND key='notice-outbox'").toArray()).toHaveLength(1))
  })
  it("acks exactly the durable subset and retries the rest", async () => {
    const { tenant } = await accessFixture()
    await queue(tenant)
    await inAccess(tenant, async (ctx) => {
      const restore = registerNoticeDelivery(async (_env, events) => [events[0]!.id, "not-submitted"])
      try { await deliverNoticeOutbox(ctx) } finally { restore() }
    })
    const saved = await rows(tenant)
    expect(saved.filter((row) => row.acknowledged_at !== null)).toHaveLength(1)
    expect(saved.filter((row) => row.acknowledged_at === null)).toHaveLength(1)
  })
  it("survives delivery failure and deduplicates the retry at the destination", async () => {
    const { tenant } = await accessFixture()
    await queue(tenant)
    const delivered = new Set<string>()
    await inAccess(tenant, async (ctx) => {
      let restore = registerNoticeDelivery(async (_env, events) => { for (const event of events) delivered.add(event.id); throw new Error("lost acknowledgement") })
      try { await deliverNoticeOutbox(ctx) } finally { restore() }
      expect(delivered.size).toBe(2)
      ctx.sql.exec("UPDATE notice_outbox SET next_retry_at=0")
      restore = registerNoticeDelivery(async (_env, events) => { for (const event of events) delivered.add(event.id); return events.map((event) => event.id) })
      try { await deliverNoticeOutbox(ctx) } finally { restore() }
      expect(delivered.size).toBe(2)
      expect(ctx.sql.exec("SELECT * FROM schedule WHERE area='access' AND key='notice-outbox'").toArray()).toEqual([])
    })
    expect((await rows(tenant)).every((row) => row.acknowledged_at !== null)).toBe(true)
  })
  it("stops retrying a notice after its last attempt, saying so once without the account", async () => {
    const { tenant } = await accessFixture()
    await queue(tenant)
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined)
    try {
      await inAccess(tenant, async (ctx) => {
        const [last, other] = ctx.sql.exec<{ id: string; account: string }>("SELECT id,account FROM notice_outbox ORDER BY id").toArray()
        ctx.sql.exec("UPDATE notice_outbox SET attempts=?,next_retry_at=0 WHERE id=?", NOTICE_MAX_ATTEMPTS - 1, last!.id)
        ctx.sql.exec("UPDATE notice_outbox SET next_retry_at=? WHERE id=?", ctx.now() + 60_000, other!.id)
        const restore = registerNoticeDelivery(async () => { throw new Error("unavailable") })
        try { await deliverNoticeOutbox(ctx) } finally { restore() }
        expect(ctx.sql.exec("SELECT attempts,acknowledged_at IS NOT NULL AS stopped FROM notice_outbox WHERE id=?", last!.id).toArray()).toEqual([{ attempts: NOTICE_MAX_ATTEMPTS, stopped: 1 }])
        expect(warn.mock.calls).toEqual([[JSON.stringify({ at: "workspace.notice.given_up", notice: last!.id, attempts: NOTICE_MAX_ATTEMPTS })]])
        expect(JSON.stringify(warn.mock.calls)).not.toContain(last!.account)
        // The other notice is still pending, so the outbox stays scheduled.
        expect(ctx.sql.exec("SELECT * FROM schedule WHERE area='access' AND key='notice-outbox'").toArray()).toHaveLength(1)
        ctx.sql.exec("UPDATE notice_outbox SET next_retry_at=0")
        await deliverNoticeOutbox(ctx)
        expect(ctx.sql.exec("SELECT attempts FROM notice_outbox WHERE id=?", last!.id).toArray()).toEqual([{ attempts: NOTICE_MAX_ATTEMPTS }])
        expect(warn).toHaveBeenCalledTimes(1)
      })
    } finally { warn.mockRestore() }
  })
  it("prunes only acknowledgements older than thirty days, never pending notices", async () => {
    const { tenant } = await accessFixture()
    await queue(tenant)
    await inAccess(tenant, async (ctx) => {
      const saved = ctx.sql.exec<{ id: string }>("SELECT id FROM notice_outbox ORDER BY id").toArray()
      ctx.sql.exec("UPDATE notice_outbox SET created_at=?,next_retry_at=?", ctx.now() - 60 * 86_400_000, ctx.now() + 60_000)
      ctx.sql.exec("UPDATE notice_outbox SET acknowledged_at=? WHERE id=?", ctx.now() - 31 * 86_400_000, saved[0]!.id)
      await deliverNoticeOutbox(ctx)
      expect(ctx.sql.exec<{ id: string }>("SELECT id FROM notice_outbox").toArray()).toEqual([{ id: saved[1]!.id }])
      expect(ctx.sql.exec<{ acknowledged_at: number | null }>("SELECT acknowledged_at FROM notice_outbox").toArray()[0]?.acknowledged_at).toBeNull()
    })
  })

})
