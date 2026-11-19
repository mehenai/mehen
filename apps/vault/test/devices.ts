import type { DeviceScope } from "@mehen/protocol/api"

export const FULL_SCOPE: DeviceScope = {
  tags: [],
  projects: [],
  maxEnvironment: "unprotected",
  modes: ["relay", "sign", "mint", "placeholder", "lease"],
}

export async function newDeviceKey(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair
}

export async function publicJwk(keys: CryptoKeyPair): Promise<{ kty: "EC"; crv: "P-256"; x: string; y: string }> {
  const jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey
  return { kty: "EC", crv: "P-256", x: jwk.x ?? "", y: jwk.y ?? "" }
}
