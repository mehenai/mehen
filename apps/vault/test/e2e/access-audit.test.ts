import { expect, it } from "vitest"
import { WorkspaceAuditPageSchema, type WorkspaceAuditPage } from "@mehen/protocol"
import { verifyAuditChain } from "../../src/vault/audit.ts"
import { body, workJourney } from "./workspace-journey.ts"

it("audit: real Worker filters guest and member history, preserves private bytes and verifies the complete chain", async () => {
  const f = await workJourney()
  const guest = await f.guest(f.alex, f.work, f.project.id, "Guest")
  const own = await f.credential(guest, f.work, "guest-private", { kind: "member", member: guest.member! })
  await f.credential(f.alex, f.work, "owner-private", { kind: "member", member: await f.member(f.alex, f.work) })
  await f.credential(f.alex, f.work, "workspace-key", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work)
  const read = async (person = guest, query = ""): Promise<WorkspaceAuditPage> => WorkspaceAuditPageSchema.parse(await body(await f.request(`/api/w/northwind/audit${query}`, person)))
  const guestPage = await read()
  expect(guestPage.filtered).toBe(true)
  expect(guestPage.events.length).toBeGreaterThan(0)
  expect(guestPage.events.every(row => row.actor === `member:${guest.member}`)).toBe(true)
  expect(JSON.stringify(guestPage.events)).not.toContain("owner-private")
  const privatePage = await read(guest, "?item=guest-private")
  expect(privatePage.events.some(row => row.target === own.id)).toBe(true)
  const original = await f.sql(f.work, "SELECT seq,at,actor,action,target,detail,prev,hash FROM audit WHERE target=? ORDER BY seq DESC", own.id)
  expect(privatePage.events).toEqual(original)
  for (const event of privatePage.events) {
    expect(verifyAuditChain([event], event.prev)).toEqual({ ok: true })
    expect(event.detail).not.toContain("hosts")
  }
  expect(await read(guest, "?item=owner-private")).toEqual(await read(guest, "?item=absent-private"))
  const ownerPage = await read(f.alex)
  expect(ownerPage.verified).toBe(true)
  expect(ownerPage.filtered).toBe(false)
  expect(verifyAuditChain([...ownerPage.events].reverse())).toEqual({ ok: true })
  const first = await read(f.alex, "?limit=2")
  expect(first.events).toHaveLength(2)
  expect(first.next).toBe(String(first.events[1]!.seq))
  const second = await read(f.alex, `?cursor=${first.next}&limit=2`)
  expect(second.events.every(row => row.seq < first.events[1]!.seq)).toBe(true)
  const before = await f.snapshot(f.work)
  expect((await f.deviceCall(machine, "/api/w/northwind/audit")).status).toBe(401)
  expect(await f.snapshot(f.work)).toEqual(before)
  // Real role mutation gives the same person current member edit reach. It
  // never grants another person's private history.
  await body(await f.memberChange(f.alex, f.work, guest.member!, "role", "member"))
  const memberPage = await read()
  expect(memberPage.events.some(row => row.action === "project.create")).toBe(true)
  expect(memberPage.events.some(row => row.target === "workspace-key")).toBe(true)
  expect(JSON.stringify(memberPage.events)).not.toContain("owner-private")
})
