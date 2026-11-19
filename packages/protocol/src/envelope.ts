// Envelope encryption: root key -> tenant key-encryption key -> one data
// key per record. WebCrypto only, so the same code runs in workerd, Bun and
// browsers.
//
//   ROOT (32 random bytes, a Worker secret, versioned)
//     HKDF-SHA256(salt "mehen/root/v<n>", info "mehen/tenant-kek/<tenant>")
//       -> tenant KEK, AES-256-GCM, never stored
//          wraps a random 256-bit DEK per record (AES-GCM, AAD bound)
//            DEK encrypts the record's secret payload (AES-GCM, AAD bound)
//
// Every blob is: 0x01 | 12-byte IV | ciphertext and 16-byte tag. The AAD
// names the tenant, record type, record id and purpose, so a ciphertext
// copied onto another record or tenant fails to decrypt instead of
// decrypting to the wrong secret.

import { type Bytes, concatBytes, randomBytes, utf8 } from "./bytes.ts"

const BLOB_VERSION = 0x01
const IV_LENGTH = 12

export type RootKey = { version: number; key: CryptoKey }

export type RecordAad = {
  tenant: string
  type: string
  id: string
  purpose: "dek" | "payload"
}

export function aadBytes(aad: RecordAad): Bytes {
  for (const part of [aad.tenant, aad.type, aad.id]) {
    if (part.length === 0 || part.includes("|")) throw new Error("invalid aad component")
  }
  return utf8(`mehen1|${aad.tenant}|${aad.type}|${aad.id}|${aad.purpose}`)
}

export async function importRootKey(raw: Bytes, version: number): Promise<RootKey> {
  if (raw.length !== 32) throw new Error("root key must be 32 bytes")
  if (!Number.isInteger(version) || version < 1) throw new Error("root key version must be a positive integer")
  const key = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"])
  return { version, key }
}

export async function deriveTenantKek(root: RootKey, tenant: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8(`mehen/root/v${root.version}`),
      info: utf8(`mehen/tenant-kek/${tenant}`),
    },
    root.key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

// The operator's backup of a workspace object (apps/vault, areas/vault-backup.ts):
// its own info under the same root, so a dump opens only with the root key
// version it names and only as its own tenant's, and is no record's key.
export async function deriveBackupKey(root: RootKey, tenant: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8(`mehen/root/v${root.version}`),
      info: utf8(`mehen/backup/v1/${tenant}`),
    },
    root.key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

export function backupAad(tenant: string, date: string, rootVersion: number): Bytes {
  if (tenant.length === 0 || tenant.includes("|") || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isInteger(rootVersion) || rootVersion < 1) throw new Error("invalid backup aad")
  return utf8(`mehen-backup|${tenant}|${date}|${rootVersion}`)
}

export function sealBackup(key: CryptoKey, aad: Bytes, plaintext: Bytes): Promise<Bytes> {
  return sealWith(key, plaintext, aad)
}

export function openBackup(key: CryptoKey, aad: Bytes, blob: Bytes): Promise<Bytes> {
  return openWith(key, blob, aad)
}

async function sealWith(key: CryptoKey, plaintext: Bytes, aad: Bytes): Promise<Bytes> {
  const iv = randomBytes(IV_LENGTH)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plaintext),
  )
  return concatBytes(Uint8Array.of(BLOB_VERSION), iv, ciphertext)
}

async function openWith(key: CryptoKey, blob: Bytes, aad: Bytes): Promise<Bytes> {
  if (blob.length < 1 + IV_LENGTH + 16 || blob[0] !== BLOB_VERSION) throw new Error("unrecognised ciphertext")
  const iv = blob.subarray(1, 1 + IV_LENGTH)
  const body = blob.subarray(1 + IV_LENGTH)
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, body))
  } catch {
    throw new Error("ciphertext failed authentication")
  }
}

export type SealedRecord = { wrappedDek: Bytes; ciphertext: Bytes }

// Encrypts a payload under a fresh DEK wrapped by the tenant KEK.
export async function sealRecord(
  kek: CryptoKey,
  ref: Omit<RecordAad, "purpose">,
  plaintext: Bytes,
): Promise<SealedRecord> {
  const dekRaw = randomBytes(32)
  try {
    const dek = await crypto.subtle.importKey("raw", dekRaw, "AES-GCM", false, ["encrypt"])
    const ciphertext = await sealWith(dek, plaintext, aadBytes({ ...ref, purpose: "payload" }))
    const wrappedDek = await sealWith(kek, dekRaw, aadBytes({ ...ref, purpose: "dek" }))
    return { wrappedDek, ciphertext }
  } finally {
    dekRaw.fill(0)
  }
}

export async function openRecord(
  kek: CryptoKey,
  ref: Omit<RecordAad, "purpose">,
  record: SealedRecord,
): Promise<Bytes> {
  const dekRaw = await openWith(kek, record.wrappedDek, aadBytes({ ...ref, purpose: "dek" }))
  try {
    const dek = await crypto.subtle.importKey("raw", dekRaw, "AES-GCM", false, ["decrypt"])
    return await openWith(dek, record.ciphertext, aadBytes({ ...ref, purpose: "payload" }))
  } finally {
    dekRaw.fill(0)
  }
}

// Re-wraps a record's DEK under a new KEK (root rotation) without touching
// the payload ciphertext.
export async function rewrapRecord(
  oldKek: CryptoKey,
  newKek: CryptoKey,
  ref: Omit<RecordAad, "purpose">,
  record: SealedRecord,
): Promise<SealedRecord> {
  const aad = aadBytes({ ...ref, purpose: "dek" })
  const dekRaw = await openWith(oldKek, record.wrappedDek, aad)
  try {
    return { wrappedDek: await sealWith(newKek, dekRaw, aad), ciphertext: record.ciphertext }
  } finally {
    dekRaw.fill(0)
  }
}
