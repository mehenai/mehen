// The platform proof, checked in the Worker on every platform call with no
// cache: one header kind only, the key by its id with its platform, the
// signature over this exact request (and `sub` against the path), then the
// key's revocation and expiry, then the platform's status. The nonce is spent, and the platform's limits counted,
// by its PlatformVault (platform-vault.ts) before anything else runs.

import { PLATFORM_PROOF_HEADER, PROOF_HEADER, PROOF_MAX_SKEW_SECONDS, type PlatformProofClaims, importDeviceKey, parsePlatformProof, verifyPlatformProof } from "@mehen/protocol"
import { VaultError } from "../http.ts"
import { type PlatformRecord, effectivePlatformStatus, readPlatformKey } from "./registry.ts"

export type PlatformCaller = { platform: PlatformRecord; key: string; claims: PlatformProofClaims }

const EXPIRED_MESSAGE = `The Mehen-Platform-Proof is more than ${PROOF_MAX_SKEW_SECONDS} seconds old. Check the server's clock and retry.`

const PROOF_MESSAGES: Record<string, string> = {
  signature: "The Mehen-Platform-Proof signature does not verify with this platform key.",
  method: "The Mehen-Platform-Proof was signed for a different HTTP method than this request.",
  url: "The Mehen-Platform-Proof was signed for a different URL than this request.",
  body: "The Mehen-Platform-Proof was signed over a different body than this request sent.",
  expired: EXPIRED_MESSAGE,
  future: `The Mehen-Platform-Proof is dated more than ${PROOF_MAX_SKEW_SECONDS} seconds in the future. Check the server's clock and retry.`,
  subject: "The Mehen-Platform-Proof names a different subject than this request's path.",
}

export function platformExpiredRefusal(): VaultError {
  return new VaultError("proof_invalid", EXPIRED_MESSAGE)
}

export function platformReplayRefusal(): VaultError {
  return new VaultError("proof_invalid", "This Mehen-Platform-Proof has already been used. Sign every request afresh.")
}

export async function authenticatePlatform(request: Request, bodyHash: string, db: D1Database, now = Date.now()): Promise<PlatformCaller> {
  const token = request.headers.get(PLATFORM_PROOF_HEADER)
  if (request.headers.has(PROOF_HEADER)) throw new VaultError("bad_request", "Send either Mehen-Proof or Mehen-Platform-Proof, never both.")
  if (!token) throw new VaultError("unauthenticated", "Missing Mehen-Platform-Proof. Sign every platform call with the platform's key.")
  let parsed: ReturnType<typeof parsePlatformProof>
  try {
    parsed = parsePlatformProof(token)
  } catch {
    throw new VaultError("proof_invalid", "The Mehen-Platform-Proof header is malformed.")
  }
  const key = await readPlatformKey(db, parsed.kid)
  if (!key || key.platform.id !== parsed.claims.plt) throw new VaultError("unauthenticated", "This platform key is not known to the vault.")
  // The signature first, so nobody without the private key learns whether
  // the key is revoked or rotated out, or the platform's status.
  const check = await verifyPlatformProof(parsed, await importDeviceKey(key.jwk), { method: request.method, url: request.url, bodyHash, now })
  if (!check.ok) throw new VaultError("proof_invalid", PROOF_MESSAGES[check.reason] ?? "The Mehen-Platform-Proof does not verify.")
  if (key.revokedAt !== null) throw new VaultError("unauthenticated", "This platform key has been revoked.")
  if (key.expiresAt !== null && key.expiresAt <= now) throw new VaultError("unauthenticated", "This platform key was rotated out and has expired.")
  const status = effectivePlatformStatus(key.platform, now)
  if (status === "suspended" || status === "retired") throw new VaultError("platform_suspended", "This platform is suspended.")
  return { platform: key.platform, key: key.id, claims: check.claims }
}
