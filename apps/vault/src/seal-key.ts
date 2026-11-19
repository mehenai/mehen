// The vault's ECDH seal key. Browsers and the CLI encrypt secret fields to
// its public half before sending; only the tenant DO opens them.

import { jwkThumbprint } from "@mehen/protocol"
import type { Env } from "./env.ts"

type PrivateJwk = { kty: "EC"; crv: "P-256"; x: string; y: string; d: string }

let cached: { source: string; privateKey: Promise<CryptoKey>; publicJwk: Promise<{ jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }> } | null = null

function load(env: Env) {
  if (cached?.source === env.SEAL_PRIVATE_JWK) return cached
  const jwk = JSON.parse(env.SEAL_PRIVATE_JWK) as PrivateJwk
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d) throw new Error("SEAL_PRIVATE_JWK must be a P-256 private JWK")
  const pub = { kty: "EC" as const, crv: "P-256" as const, x: jwk.x, y: jwk.y }
  cached = {
    source: env.SEAL_PRIVATE_JWK,
    privateKey: crypto.subtle.importKey("jwk", { ...jwk, ext: false }, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]),
    publicJwk: jwkThumbprint(pub).then((t) => ({ jwk: pub, kid: t.slice(0, 16) })),
  }
  return cached
}

export function sealPrivateKey(env: Env): Promise<CryptoKey> {
  return load(env).privateKey
}

export function sealPublicJwk(env: Env) {
  return load(env).publicJwk
}
