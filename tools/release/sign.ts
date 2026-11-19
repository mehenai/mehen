// Signs a release manifest with a release key (keys.ts) through mehen-se,
// then verifies the signature against the compiled RELEASE_KEYS before
// anything is written, so a release that no client would accept is never
// assembled. release.ts calls it for every release that is not an
// explicitly unsigned trial build.
//
// Presence is enforced here. The key's sidecar must match its RELEASE_KEYS
// entry exactly, `presence` included. A key without presence signs with
// --no-interaction, so a blob that in fact needs Touch ID fails instead of
// waiting; a presence key signs interactively, in a desktop session.

import { type ReleaseKey, type ReleaseManifest, type ReleaseSignature, manifestSigningBytes, verifyManifestSignatures } from "../../packages/protocol/src/release-manifest.ts"

export class SigningError extends Error {}

// Signs the manifest's signing bytes; resolves with base64url r||s.
export type ManifestSigner = (data: Uint8Array) => Promise<string>

// The RELEASE_KEYS entry for a sidecar, which must agree with it on every
// field: a sidecar that says `none` for a key the binaries record as
// `required` (or the reverse), or a different public key, signs nothing.
export function trustedEntry(sidecar: ReleaseKey, trusted: readonly ReleaseKey[]): ReleaseKey {
  const entry = trusted.find((key) => key.id === sidecar.id)
  if (!entry) throw new SigningError(`${sidecar.id} is not in RELEASE_KEYS (packages/protocol/src/release-keys.ts), so no client would accept its signature.`)
  if (entry.jwk.x !== sidecar.jwk.x || entry.jwk.y !== sidecar.jwk.y) throw new SigningError(`The sidecar of ${sidecar.id} holds a different public key from its RELEASE_KEYS entry; refusing to sign.`)
  if (entry.presence !== sidecar.presence) throw new SigningError(`The sidecar of ${sidecar.id} says presence ${sidecar.presence} but RELEASE_KEYS says ${entry.presence}; refusing to sign.`)
  if (entry.alg !== sidecar.alg || entry.created !== sidecar.created) throw new SigningError(`The sidecar of ${sidecar.id} does not match its RELEASE_KEYS entry; refusing to sign.`)
  return entry
}

export function helperSigner(helper: string, key: { key: ReleaseKey; blob: string }): ManifestSigner {
  return async (data) => {
    const interactive = key.key.presence === "required"
    const proc = Bun.spawn([helper, "sign", "--key", key.blob, ...(interactive ? [] : ["--no-interaction"])], { stdin: new Uint8Array(data), stdout: "pipe", stderr: "pipe", timeout: interactive ? 180_000 : 30_000 })
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
    if (code !== 0) throw new SigningError(`mehen-se sign with ${key.key.id} failed: ${stderr.trim().split("\n")[0] || `exit ${code}`}`)
    return stdout.trim()
  }
}

export async function signManifest<M extends ReleaseManifest>(manifest: M, key: ReleaseKey, signer: ManifestSigner, trusted: readonly ReleaseKey[]): Promise<M & { signatures: ReleaseSignature[] }> {
  trustedEntry(key, trusted)
  const signature = await signer(manifestSigningBytes(manifest))
  const signed = { ...manifest, signatures: [{ keyId: key.id, alg: "ES256" as const, signature }] }
  const result = await verifyManifestSignatures(JSON.parse(JSON.stringify(signed)), trusted)
  if (!result.ok || result.keyId !== key.id) throw new SigningError(`The signature by ${key.id} does not verify against RELEASE_KEYS (${result.ok ? `verified as ${result.keyId}` : result.reason}); nothing was written.`)
  return signed
}
