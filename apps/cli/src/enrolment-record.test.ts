// The enrolment record: a validated reader that never prunes
// by expiry, the legacy mapping, the compare-and-mutate step every
// write after an await goes through, and the ledger never
// reading or writing it.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, symlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { askUrl, enrolAsk } from "./ask.ts"
import { ensureConfigDir } from "./config.ts"
import { type EnrolmentRecord, mutateAttempt, readEnrolmentRecord, recordFromLegacyEntry, writeEnrolmentRecord } from "./enrolment-record.ts"
import { pendingSlotPath } from "./home.ts"
import { addLedgerEntry, readLedger, readLegacyEnrolments, removeLedgerEntry } from "./ledger.ts"
import { tempDir } from "./testing/run-mehen.ts"

const ORIGIN = "https://app.mehen.dev"
const JWK = { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }
const PAST = new Date(Date.now() - 3_600_000).toISOString()

let dir: { path: string; remove(): Promise<void> }

beforeEach(async () => {
  dir = await tempDir()
})
afterEach(() => dir.remove())

function record(patch: Partial<EnrolmentRecord> = {}): EnrolmentRecord {
  return { v: 1, state: "pending", id: "enr_f1xtR3cP4y5KIRtrusg", code: "ABCD2345", url: `${ORIGIN}/w/example/e/ABCD2345`, origin: ORIGIN, intent: { workspace: "example", team: null }, name: "sam-mac-mini", backend: "software", jwk: JWK, session: null, startedAt: "2026-10-28T12:00:00.000Z", expiresAt: PAST, hardExpiresAt: null, renewals: 0, legacy: true, claimed: false, ...patch }
}

const enrolScope = { vaultUrl: ORIGIN, workspace: null, device: null }

describe("the reader", () => {
  test("round-trips a record, keeps an expired one, and refuses a tampered link, a link file, a loose file and a bad shape", async () => {
    await writeEnrolmentRecord(dir.path, record())
    expect(await readEnrolmentRecord(dir.path)).toEqual({ record: record() })
    const path = join(dir.path, "enrolment.json")
    for (const url of ["https://evil.example/w/example/e/ABCD2345", `${ORIGIN}/w/other/e/ABCD2345`, `${ORIGIN}/w/example/e/WRONGCODE1`]) {
      writeFileSync(path, JSON.stringify(record({ url })), { mode: 0o600 })
      expect(await readEnrolmentRecord(dir.path)).toMatchObject({ refused: expect.stringContaining("not a valid enrolment record") })
    }
    writeFileSync(path, JSON.stringify({ ...record(), jwk: { ...JWK, d: "secret" } }), { mode: 0o600 })
    expect(await readEnrolmentRecord(dir.path)).toMatchObject({ refused: expect.any(String) })
    writeFileSync(path, JSON.stringify(record()), { mode: 0o600 })
    chmodSync(path, 0o644)
    expect(await readEnrolmentRecord(dir.path)).toMatchObject({ refused: expect.stringContaining("readable or writable by other users") })
    const other = await tempDir()
    try {
      await writeEnrolmentRecord(other.path, record())
      const linked = join(dir.path, "linked")
      await ensureConfigDir(linked)
      symlinkSync(join(other.path, "enrolment.json"), join(linked, "enrolment.json"))
      expect(await readEnrolmentRecord(linked)).toMatchObject({ refused: expect.stringContaining("symbolic link") })
    } finally {
      await other.remove()
    }
    await expect(writeEnrolmentRecord(dir.path, record({ url: "https://evil.example/e/ABCD2345" }))).rejects.toThrow()
  })

  test("keeps a requested scope, reads a record without one as asking for none, and refuses one the protocol does not accept", async () => {
    const scope = { tags: ["agents"], modes: ["relay" as const], privateCredentials: false as const, workloads: "required" as const }
    await writeEnrolmentRecord(dir.path, record({ scope }))
    expect(await readEnrolmentRecord(dir.path)).toEqual({ record: record({ scope }) })
    await writeEnrolmentRecord(dir.path, record())
    const read = await readEnrolmentRecord(dir.path)
    expect(read && "record" in read ? Object.keys(read.record) : []).not.toContain("scope")
    const path = join(dir.path, "enrolment.json")
    for (const bad of [{ modes: ["reveal"] }, { privateCredentials: true }, { tags: [] }, { tags: ["agents"], extra: 1 }, null]) {
      writeFileSync(path, JSON.stringify({ ...record(), scope: bad }), { mode: 0o600 })
      expect(await readEnrolmentRecord(dir.path)).toMatchObject({ refused: expect.stringContaining("not a valid enrolment record") })
    }
  })

  test("the legacy mapping is field by field: never renewed, never claimed", () => {
    const url = askUrl(`${ORIGIN}/w/example/e/ABCD2345`, { vaultUrl: ORIGIN, workspaceSlug: "example" })!.url
    const ask = enrolAsk({ id: "enr_f1xtR3cP4y5KIRtrusg", url, name: "sam-mac-mini", backend: "software", fingerprint: "4SDW M2HG 3T0W 9MMW", expiresAt: PAST, requestedBy: { device: "sam-mac-mini", session: "pi-1" } })
    const mapped = recordFromLegacyEntry({ ask, createdAt: "2026-10-28T12:00:00.000Z", origin: ORIGIN, workspace: null, device: null, slug: null, command: null, enrol: { code: "ABCD2345", name: "sam-mac-mini", backend: "software", jwk: JWK, workspace: "example", team: null } })
    expect(mapped).toEqual(record({ session: "pi-1" }))
  })
})

// The record-to-ledger adapter is gone (the cutover commit): the ledger
// never presents, writes, removes or copies the record.
describe("the ledger and the record", () => {
  test("no ledger read under any scope sees the record, and a ledger write never touches enrolment.json or copies it into ledger.json", async () => {
    await writeEnrolmentRecord(dir.path, record({ hardExpiresAt: "2026-10-29T12:00:00.000Z", legacy: false, renewals: 2 }))
    const before = await readEnrolmentRecord(dir.path)
    for (const scope of [enrolScope, { ...enrolScope, workspaceSlug: "example" }, { vaultUrl: ORIGIN, workspace: "tn_x", device: "dev_x" }]) expect(await readLedger(dir.path, scope)).toEqual([])
    const later = new Date(Date.now() + 600_000).toISOString()
    const url = askUrl(record().url as string, { vaultUrl: ORIGIN, workspaceSlug: "example" })!.url
    const ask = enrolAsk({ id: record().id as string, url, name: "sam-mac-mini", backend: "software", fingerprint: "4SDW M2HG 3T0W 9MMW", expiresAt: later, requestedBy: { device: "sam-mac-mini", session: null } })
    await addLedgerEntry(dir.path, enrolScope, { ask, enrol: { code: "ABCD2345", name: "sam-mac-mini", backend: "software", jwk: JWK, workspace: "example", team: null } })
    expect(await readEnrolmentRecord(dir.path)).toEqual(before)
    expect((await readLegacyEnrolments(dir.path, ORIGIN)).map((e) => e.ask.id)).toEqual([record().id as string])
    await removeLedgerEntry(dir.path, enrolScope, record().id as string)
    expect(await readEnrolmentRecord(dir.path)).toEqual(before)
    expect(await readLedger(dir.path, enrolScope)).toEqual([])
  })
})

describe("mutateAttempt", () => {
  function slot(): string {
    return pendingSlotPath(dir.path, ORIGIN, "example")
  }

  test("applies a change, or a removal, only while the record is the attempt the caller holds", async () => {
    await ensureConfigDir(slot())
    await writeEnrolmentRecord(slot(), record())
    const held = { id: record().id as string, jwk: JWK }
    expect(await mutateAttempt(slot(), held, (r) => ({ ...r, renewals: r.renewals + 1 }))).toBe("applied")
    expect(await readEnrolmentRecord(slot())).toEqual({ record: record({ renewals: 1 }) })
    // A newer attempt (another id, or the same id with another key) is never touched.
    const newer = record({ id: "enr_newerAttempt00001", renewals: 7 })
    await writeEnrolmentRecord(slot(), newer)
    expect(await mutateAttempt(slot(), held, () => null)).toBe("superseded")
    expect(await mutateAttempt(slot(), { id: newer.id as string, jwk: { ...JWK, x: "z".repeat(43) } }, () => null)).toBe("superseded")
    expect(await readEnrolmentRecord(slot())).toEqual({ record: newer })
    // Removal, and then nothing left to change.
    expect(await mutateAttempt(slot(), { id: newer.id as string, jwk: JWK }, () => null)).toBe("applied")
    expect(await readEnrolmentRecord(slot())).toBeNull()
    expect(await mutateAttempt(slot(), held, (r) => r)).toBe("gone")
  })
})
