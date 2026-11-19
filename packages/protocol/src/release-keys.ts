// The release keys Mehen trusts: the public halves of the Secure Enclave
// keys that sign release manifests (tools/release/keys.ts makes one and
// prints the literal for this list; add it here, in its own reviewed
// commit). Every `mehen` binary compiles this list in (apps/cli re-exports
// it as release-keys.ts) and installs, from the public download base, only
// a manifest one of these signed; the vault advertises a published release
// as recommended only when one of these signed it (apps/vault
// src/published-release.ts).
//
// rk-studio-2026-auto, the reference deployment's key, lives in the Secure
// Enclave of its release Mac and signs without Touch ID or a password
// (presence "none", the release owner's choice), so that Mac can release
// unattended: anything running as the release user on it, unlocked, can
// sign. A fork that publishes its own releases replaces it with its own key.
// An empty list fails closed: `mehen update` refuses
// ("no trusted release key is compiled into this build"),
// `tools/release/release.ts` refuses to sign and the vault advertises only
// its floor. Signing fixtures and the local pre-release run use
// MEHEN_RELEASE_KEYS through the permitted test paths
// (apps/cli/src/release-client.ts); trust-policy tests also exercise this
// list.

import type { ReleaseKey } from "./release-manifest.ts"

export const RELEASE_KEYS: readonly ReleaseKey[] = [
  {
    id: "rk-studio-2026-auto",
    alg: "ES256",
    jwk: { kty: "EC", crv: "P-256", x: "oAh4FhedQUyKlbxmNsVvhPy99A_kR2bF-XnqvjBkGDc", y: "3kM2MhoHQ_S4SHYLLfWBW19w6NssbL0BppYx8zIAACo" },
    presence: "none",
    created: "2026-10-29T11:36:12.503Z",
  },
]
