import { describe, expect, test } from "bun:test"
import { type Bytes, fromUtf8, randomBytes, utf8 } from "./bytes.ts"
import {
  type RecordAad,
  type RootKey,
  type SealedRecord,
  aadBytes,
  backupAad,
  deriveBackupKey,
  deriveTenantKek,
  importRootKey,
  openBackup,
  openRecord,
  rewrapRecord,
  sealBackup,
  sealRecord,
} from "./envelope.ts"

type RecordRef = Omit<RecordAad, "purpose">

const ROOT_RAW = randomBytes(32)
const REF: RecordRef = { tenant: "ten_alpha", type: "item", id: "itm_one" }
const SECRET = "sk-proj-the-real-secret-value"

async function rootKey(version = 1, raw: Bytes = ROOT_RAW): Promise<RootKey> {
  return importRootKey(raw, version)
}

async function kekFor(tenant: string, version = 1, raw: Bytes = ROOT_RAW): Promise<CryptoKey> {
  return deriveTenantKek(await rootKey(version, raw), tenant)
}

function flipBit(bytes: Bytes, index: number): Bytes {
  const copy = new Uint8Array(bytes)
  copy[index] = (copy[index] ?? 0) ^ 0x01
  return copy
}

async function sealed(ref: RecordRef = REF, text = SECRET): Promise<SealedRecord> {
  return sealRecord(await kekFor(ref.tenant), ref, utf8(text))
}

describe("aadBytes", () => {
  test("names tenant, type, id and purpose", () => {
    expect(fromUtf8(aadBytes({ ...REF, purpose: "dek" }))).toBe("mehen1|ten_alpha|item|itm_one|dek")
    expect(fromUtf8(aadBytes({ ...REF, purpose: "payload" }))).toBe("mehen1|ten_alpha|item|itm_one|payload")
  })

  test("refuses empty components and the separator", () => {
    expect(() => aadBytes({ ...REF, tenant: "", purpose: "dek" })).toThrow("invalid aad component")
    expect(() => aadBytes({ ...REF, type: "", purpose: "dek" })).toThrow("invalid aad component")
    expect(() => aadBytes({ ...REF, id: "", purpose: "dek" })).toThrow("invalid aad component")
    expect(() => aadBytes({ ...REF, id: "a|b", purpose: "dek" })).toThrow("invalid aad component")
    expect(() => aadBytes({ ...REF, tenant: "t|item", type: "x", purpose: "dek" })).toThrow("invalid aad component")
  })
})

describe("importRootKey", () => {
  test("requires exactly 32 bytes", async () => {
    await expect(importRootKey(randomBytes(31), 1)).rejects.toThrow("root key must be 32 bytes")
    await expect(importRootKey(randomBytes(33), 1)).rejects.toThrow("root key must be 32 bytes")
  })

  test("requires a positive integer version", async () => {
    await expect(importRootKey(ROOT_RAW, 0)).rejects.toThrow("positive integer")
    await expect(importRootKey(ROOT_RAW, -1)).rejects.toThrow("positive integer")
    await expect(importRootKey(ROOT_RAW, 1.5)).rejects.toThrow("positive integer")
    await expect(importRootKey(ROOT_RAW, Number.NaN)).rejects.toThrow("positive integer")
  })
})

describe("sealRecord and openRecord", () => {
  test("round trip returns the plaintext", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, utf8(SECRET))
    expect(fromUtf8(await openRecord(kek, REF, record))).toBe(SECRET)
  })

  test("round trip with an empty and a large payload", async () => {
    const kek = await kekFor(REF.tenant)
    const empty = await sealRecord(kek, REF, new Uint8Array())
    expect((await openRecord(kek, REF, empty)).length).toBe(0)
    const big = randomBytes(64 * 1024)
    expect(await openRecord(kek, REF, await sealRecord(kek, REF, big))).toEqual(big)
  })

  test("a fresh KEK derived from the same root and tenant opens the record", async () => {
    const record = await sealed()
    const again = await kekFor(REF.tenant)
    expect(fromUtf8(await openRecord(again, REF, record))).toBe(SECRET)
  })

  test("blobs have the version byte, a 12-byte IV and a tag, and differ per seal", async () => {
    const kek = await kekFor(REF.tenant)
    const a = await sealRecord(kek, REF, utf8(SECRET))
    const b = await sealRecord(kek, REF, utf8(SECRET))
    expect(a.ciphertext[0]).toBe(0x01)
    expect(a.wrappedDek[0]).toBe(0x01)
    expect(a.ciphertext.length).toBe(1 + 12 + utf8(SECRET).length + 16)
    expect(a.wrappedDek.length).toBe(1 + 12 + 32 + 16)
    expect(a.ciphertext).not.toEqual(b.ciphertext)
    expect(a.wrappedDek).not.toEqual(b.wrappedDek)
  })

  test("fails for another tenant, even with that tenant's own KEK", async () => {
    const record = await sealed()
    const other: RecordRef = { ...REF, tenant: "ten_beta" }
    await expect(openRecord(await kekFor(REF.tenant), other, record)).rejects.toThrow("failed authentication")
    await expect(openRecord(await kekFor("ten_beta"), other, record)).rejects.toThrow("failed authentication")
    await expect(openRecord(await kekFor("ten_beta"), REF, record)).rejects.toThrow("failed authentication")
  })

  test("fails for another record id", async () => {
    const record = await sealed()
    await expect(openRecord(await kekFor(REF.tenant), { ...REF, id: "itm_two" }, record)).rejects.toThrow(
      "failed authentication",
    )
  })

  test("fails for another record type", async () => {
    const record = await sealed()
    await expect(openRecord(await kekFor(REF.tenant), { ...REF, type: "integration" }, record)).rejects.toThrow(
      "failed authentication",
    )
  })

  test("fails when wrapped DEKs are swapped between records", async () => {
    const kek = await kekFor(REF.tenant)
    const refTwo: RecordRef = { ...REF, id: "itm_two" }
    const one = await sealRecord(kek, REF, utf8("first secret"))
    const two = await sealRecord(kek, refTwo, utf8("second secret"))
    await expect(openRecord(kek, REF, { wrappedDek: two.wrappedDek, ciphertext: one.ciphertext })).rejects.toThrow(
      "failed authentication",
    )
    await expect(openRecord(kek, refTwo, { wrappedDek: one.wrappedDek, ciphertext: two.ciphertext })).rejects.toThrow(
      "failed authentication",
    )
  })

  test("fails when payload ciphertexts are swapped between records", async () => {
    const kek = await kekFor(REF.tenant)
    const refTwo: RecordRef = { ...REF, id: "itm_two" }
    const one = await sealRecord(kek, REF, utf8("first secret"))
    const two = await sealRecord(kek, refTwo, utf8("second secret"))
    await expect(openRecord(kek, REF, { wrappedDek: one.wrappedDek, ciphertext: two.ciphertext })).rejects.toThrow(
      "failed authentication",
    )
  })

  test("fails when the payload and DEK blobs trade places", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, randomBytes(32))
    await expect(
      openRecord(kek, REF, { wrappedDek: record.ciphertext, ciphertext: record.wrappedDek }),
    ).rejects.toThrow("failed authentication")
  })

  test("fails under another root version of the same root bytes", async () => {
    const record = await sealed()
    await expect(openRecord(await kekFor(REF.tenant, 2), REF, record)).rejects.toThrow("failed authentication")
  })

  test("fails under other root bytes with the same version", async () => {
    const record = await sealed()
    await expect(openRecord(await kekFor(REF.tenant, 1, randomBytes(32)), REF, record)).rejects.toThrow(
      "failed authentication",
    )
  })

  test("a single bit flip anywhere in the payload ciphertext fails", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, utf8(SECRET))
    for (let i = 1; i < record.ciphertext.length; i++) {
      const tampered: SealedRecord = { ...record, ciphertext: flipBit(record.ciphertext, i) }
      await expect(openRecord(kek, REF, tampered)).rejects.toThrow("failed authentication")
    }
  })

  test("a single bit flip anywhere in the wrapped DEK fails", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, utf8(SECRET))
    for (let i = 1; i < record.wrappedDek.length; i++) {
      const tampered: SealedRecord = { ...record, wrappedDek: flipBit(record.wrappedDek, i) }
      await expect(openRecord(kek, REF, tampered)).rejects.toThrow("failed authentication")
    }
  })

  test("refuses an unknown version byte and truncated blobs", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, utf8(SECRET))
    const badVersion = new Uint8Array(record.ciphertext)
    badVersion[0] = 0x02
    await expect(openRecord(kek, REF, { ...record, ciphertext: badVersion })).rejects.toThrow("unrecognised ciphertext")
    await expect(openRecord(kek, REF, { ...record, wrappedDek: record.wrappedDek.slice(0, 28) })).rejects.toThrow(
      "unrecognised ciphertext",
    )
    await expect(openRecord(kek, REF, { ...record, ciphertext: new Uint8Array() })).rejects.toThrow(
      "unrecognised ciphertext",
    )
  })

  test("a truncated tag fails authentication", async () => {
    const kek = await kekFor(REF.tenant)
    const record = await sealRecord(kek, REF, utf8(SECRET))
    const short = record.ciphertext.slice(0, record.ciphertext.length - 1)
    await expect(openRecord(kek, REF, { ...record, ciphertext: short })).rejects.toThrow("failed authentication")
  })
})

describe("rewrapRecord", () => {
  test("keeps the payload decryptable under the new KEK only", async () => {
    const oldKek = await kekFor(REF.tenant, 1)
    const newKek = await kekFor(REF.tenant, 2, randomBytes(32))
    const record = await sealRecord(oldKek, REF, utf8(SECRET))
    const rewrapped = await rewrapRecord(oldKek, newKek, REF, record)
    expect(rewrapped.ciphertext).toEqual(record.ciphertext)
    expect(rewrapped.wrappedDek).not.toEqual(record.wrappedDek)
    expect(fromUtf8(await openRecord(newKek, REF, rewrapped))).toBe(SECRET)
    await expect(openRecord(oldKek, REF, rewrapped)).rejects.toThrow("failed authentication")
  })

  test("refuses to rewrap with the wrong old KEK or for another record", async () => {
    const oldKek = await kekFor(REF.tenant, 1)
    const newKek = await kekFor(REF.tenant, 2)
    const record = await sealRecord(oldKek, REF, utf8(SECRET))
    await expect(rewrapRecord(newKek, newKek, REF, record)).rejects.toThrow("failed authentication")
    await expect(rewrapRecord(oldKek, newKek, { ...REF, id: "itm_two" }, record)).rejects.toThrow(
      "failed authentication",
    )
  })

  test("a rewrapped DEK stays bound to its record", async () => {
    const oldKek = await kekFor(REF.tenant, 1)
    const newKek = await kekFor(REF.tenant, 2)
    const rewrapped = await rewrapRecord(oldKek, newKek, REF, await sealRecord(oldKek, REF, utf8(SECRET)))
    await expect(openRecord(newKek, { ...REF, id: "itm_two" }, rewrapped)).rejects.toThrow("failed authentication")
  })
})

describe("deriveBackupKey, sealBackup and openBackup", () => {
  const DUMP = utf8('{"format":"mehen-vault-dump/v1"}\n')
  const backupKey = async (tenant = REF.tenant, version = 1, raw: Bytes = ROOT_RAW) => deriveBackupKey(await rootKey(version, raw), tenant)

  test("round trip under the tenant, date and root version it names", async () => {
    const aad = backupAad(REF.tenant, "2026-11-01", 1)
    const blob = await sealBackup(await backupKey(), aad, DUMP)
    expect(blob[0]).toBe(0x01)
    expect(await openBackup(await backupKey(), backupAad(REF.tenant, "2026-11-01", 1), blob)).toEqual(DUMP)
  })

  test("fails for another tenant, another date or another root version in the aad", async () => {
    const blob = await sealBackup(await backupKey(), backupAad(REF.tenant, "2026-11-01", 1), DUMP)
    await expect(openBackup(await backupKey("ten_beta"), backupAad("ten_beta", "2026-11-01", 1), blob)).rejects.toThrow("failed authentication")
    await expect(openBackup(await backupKey(), backupAad("ten_beta", "2026-11-01", 1), blob)).rejects.toThrow("failed authentication")
    await expect(openBackup(await backupKey(), backupAad(REF.tenant, "2026-11-02", 1), blob)).rejects.toThrow("failed authentication")
    await expect(openBackup(await backupKey(), backupAad(REF.tenant, "2026-11-01", 2), blob)).rejects.toThrow("failed authentication")
  })

  test("fails under another root version or other root bytes", async () => {
    const aad = backupAad(REF.tenant, "2026-11-01", 1)
    const blob = await sealBackup(await backupKey(), aad, DUMP)
    await expect(openBackup(await backupKey(REF.tenant, 2), aad, blob)).rejects.toThrow("failed authentication")
    await expect(openBackup(await backupKey(REF.tenant, 1, randomBytes(32)), aad, blob)).rejects.toThrow("failed authentication")
  })

  test("is not the tenant KEK: neither opens the other's blobs", async () => {
    const aad = backupAad(REF.tenant, "2026-11-01", 1)
    const blob = await sealBackup(await backupKey(), aad, DUMP)
    await expect(openBackup(await kekFor(REF.tenant), aad, blob)).rejects.toThrow("failed authentication")
    const record = await sealed()
    await expect(openBackup(await backupKey(), aadBytes({ ...REF, purpose: "dek" }), record.wrappedDek)).rejects.toThrow("failed authentication")
  })

  test("backupAad refuses the separator, a malformed date and a bad version", () => {
    expect(fromUtf8(backupAad("tn_alpha", "2026-11-01", 3))).toBe("mehen-backup|tn_alpha|2026-11-01|3")
    for (const [tenant, date, version] of [["", "2026-11-01", 1], ["tn|x", "2026-11-01", 1], ["tn_alpha", "2026-11-1", 1], ["tn_alpha", "2026-11-01", 0], ["tn_alpha", "2026-11-01", 1.5]] as const) {
      expect(() => backupAad(tenant, date, version)).toThrow("invalid backup aad")
    }
  })
})
