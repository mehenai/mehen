// Root keys, per-tenant KEKs and the per-tenant fingerprint key inside the DO.

import { type RootKey, base64UrlDecode, deriveTenantKek, importRootKey, utf8 } from "@mehen/protocol"

export type RootKeyRing = { current: number; versions: Map<number, Promise<RootKey>> }

export function parseRootKeys(json: string): RootKeyRing {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error("ROOT_KEYS is not JSON")
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("ROOT_KEYS must be an object")
  const versions = new Map<number, Promise<RootKey>>()
  for (const [k, v] of Object.entries(parsed)) {
    const version = Number(k)
    if (!Number.isInteger(version) || version < 1 || typeof v !== "string") throw new Error("ROOT_KEYS entries are version: base64url")
    versions.set(version, importRootKey(base64UrlDecode(v), version))
  }
  if (versions.size === 0) throw new Error("ROOT_KEYS is empty")
  return { current: Math.max(...versions.keys()), versions }
}

// HMAC-SHA256 key for secret fingerprints, derived like the KEK (same salt)
// under its own info, so a fingerprint cannot be recomputed without the root.
export function deriveFingerprintKey(root: RootKey, tenant: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8(`mehen/root/v${root.version}`),
      info: utf8(`mehen/fingerprint/v1/${tenant}`),
    },
    root.key,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  )
}

export class TenantKeys {
  private readonly keks = new Map<number, Promise<CryptoKey>>()
  private readonly fingerprints = new Map<number, Promise<CryptoKey>>()

  constructor(
    private readonly ring: RootKeyRing,
    private readonly tenant: string,
  ) {}

  get current(): number {
    return this.ring.current
  }

  kek(version: number): Promise<CryptoKey> {
    let kek = this.keks.get(version)
    if (!kek) {
      const root = this.ring.versions.get(version)
      if (!root) return Promise.reject(new Error(`root key version ${version} is not configured`))
      kek = root.then((r) => deriveTenantKek(r, this.tenant))
      this.keks.set(version, kek)
    }
    return kek
  }

  // Under the root version a fingerprint was written with, which is stored
  // beside it, so a root rotation never silently changes what it means.
  fingerprintKey(version: number): Promise<CryptoKey> {
    let key = this.fingerprints.get(version)
    if (!key) {
      const root = this.ring.versions.get(version)
      if (!root) return Promise.reject(new Error(`root key version ${version} is not configured`))
      key = root.then((r) => deriveFingerprintKey(r, this.tenant))
      this.fingerprints.set(version, key)
    }
    return key
  }
}
