import { createHash } from "node:crypto"
import { gunzipSync } from "node:zlib"
import { type ReleaseKey, type ReleaseManifest, type SignedManifest, isReleaseKey, verifyManifestSignatures } from "@mehen/protocol/release-manifest"
import { CliError, usageError } from "./errors.ts"
import type { Env } from "./config.ts"
import { USER_AGENT } from "./http-client.ts"
import { RELEASE_KEYS } from "./release-keys.ts"
import { object } from "./setup/formats.ts"
import { BUILD_KIND, type BuildKind } from "./version.ts"

export type { ReleaseFile, ReleaseManifest, SignedManifest } from "@mehen/protocol/release-manifest"
export { compareVersions } from "@mehen/protocol/version"
export type ReleaseFetch = (url: string, init?: RequestInit) => Promise<Response>
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/
const HASH = /^[0-9a-f]{64}$/
const MAX_BINARY = 256 * 1024 * 1024
export const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex")
export function downloadBase(env: Env): string {
  const raw = (env.MEHEN_DL_BASE ?? "https://mehen.dev/dl").replace(/\/+$/, "")
  let url: URL
  try { url = new URL(raw) } catch { throw usageError("Invalid MEHEN_DL_BASE.") }
  if (url.username || url.password || url.search || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)))) throw usageError("MEHEN_DL_BASE must use https (or loopback http for tests), without credentials, query or fragment.")
  return raw
}
// The file names a manifest may list. An installed mehen refuses a manifest
// with any other name, so a release can add a binary only once the machines
// that update from it accept the name: the -musl builds are accepted here
// before any release lists them (docs/OPERATIONS.md, "The musl builds").
const RELEASE_FILE = /^mehen-(?:darwin-(?:arm64|x64)|linux-(?:arm64|x64)(?:-musl)?|se)$/

export function parseManifest(value: unknown): ReleaseManifest {
  if (!object(value) || typeof value.version !== "string" || !VERSION_PATTERN.test(value.version) || typeof value.commit !== "string" || typeof value.builtAt !== "string" || !Array.isArray(value.files)) throw new CliError("failed", "Invalid release manifest.")
  const names = new Set<string>()
  for (const file of value.files as unknown[]) {
    if (!object(file) || typeof file.name !== "string" || !RELEASE_FILE.test(file.name) || names.has(file.name) || typeof file.os !== "string" || typeof file.arch !== "string" || typeof file.url !== "string" || typeof file.sha256 !== "string" || !HASH.test(file.sha256) || typeof file.gzSha256 !== "string" || !HASH.test(file.gzSha256) || typeof file.size !== "number" || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > MAX_BINARY || typeof file.gzSize !== "number" || !Number.isSafeInteger(file.gzSize) || file.gzSize < 1 || file.gzSize > MAX_BINARY) throw new CliError("failed", "Invalid or duplicate release file.")
    names.add(file.name)
  }
  return value as ReleaseManifest
}

export async function releaseBytes(url: string, max: number, fetcher: ReleaseFetch = fetch): Promise<Uint8Array> {
  const response = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(30_000), headers: { "user-agent": USER_AGENT } })
  if (!response.ok || !response.body) throw new CliError("network", `Release download failed (HTTP ${response.status}).`)
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      size += part.value.length
      if (size > max) throw new CliError("failed", "Release download exceeded its declared size.")
      chunks.push(part.value)
    }
  } finally { await reader.cancel().catch(() => {}) }
  const bytes = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length }
  return bytes
}

// The keys a release manifest must be signed by. A release binary against
// the public download base trusts the compiled RELEASE_KEYS and nothing else;
// MEHEN_RELEASE_KEYS (a JSON array of ReleaseKey) replaces them only for a
// loopback http MEHEN_DL_BASE or a build that is not a release build, which
// is how tests and the local pre-release run name their test keys. An empty
// set fails closed: no release can be verified, so nothing is installed.
// `compiled` is always RELEASE_KEYS outside tests.
export function releaseTrust(env: Env, base: string, build: BuildKind = BUILD_KIND, compiled: readonly ReleaseKey[] = RELEASE_KEYS): readonly ReleaseKey[] {
  const override = env.MEHEN_RELEASE_KEYS
  const keys = override && (build !== "release" || loopbackHttp(base)) ? parseReleaseKeys(override) : compiled
  if (keys.length === 0) throw new CliError("failed", "No trusted release key is compiled into this build, so it cannot verify a release. Nothing was installed.")
  return keys
}

function loopbackHttp(base: string): boolean {
  const url = new URL(base)
  return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
}

function parseReleaseKeys(text: string): readonly ReleaseKey[] {
  let value: unknown
  try { value = JSON.parse(text) } catch { value = null }
  if (!Array.isArray(value) || value.length === 0 || !value.every(isReleaseKey)) throw usageError("MEHEN_RELEASE_KEYS must be a JSON array of one or more release keys ({ id, alg, jwk, presence, created }).")
  return value
}

const SIGNATURE_REFUSAL: Record<"unsigned" | "unknown_key" | "bad_signature" | "malformed", string> = {
  unsigned: "The release manifest is not signed, so it is not trusted. Nothing was installed.",
  unknown_key: "The release manifest is signed by a key this build does not trust. Nothing was installed.",
  bad_signature: "The release manifest's signature does not verify. Nothing was installed.",
  malformed: "The release manifest's signatures are malformed. Nothing was installed.",
}

// A manifest as the updater may act on it: well formed, and signed by one
// of `keys`.
export async function verifiedManifest(value: unknown, keys: readonly ReleaseKey[]): Promise<SignedManifest> {
  return (await verifiedRelease(value, keys)).manifest
}

// The same, with the id of the key whose signature actually verified: the
// provenance an installation records, never rediscovered by
// which trusted id a signature merely names.
export async function verifiedRelease(value: unknown, keys: readonly ReleaseKey[]): Promise<{ manifest: SignedManifest; keyId: string }> {
  parseManifest(value)
  const result = await verifyManifestSignatures(value, keys)
  if (!result.ok) throw new CliError("failed", SIGNATURE_REFUSAL[result.reason])
  return { manifest: result.manifest, keyId: result.keyId }
}

export async function latestRelease(base: string, keys: readonly ReleaseKey[], fetcher: ReleaseFetch = fetch): Promise<SignedManifest> {
  const bytes = await releaseBytes(`${base}/latest.json`, 1024 * 1024, fetcher)
  let value: unknown
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new CliError("failed", "Invalid release manifest JSON.") }
  return verifiedManifest(value, keys)
}
export async function verifiedBinary(base: string, manifest: ReleaseManifest, name: string, fetcher: ReleaseFetch = fetch): Promise<Uint8Array> {
  const file = manifest.files.find(f => f.name === name)
  if (!file) throw new CliError("not_available", `The release has no ${name}.`)
  // Construct from the chosen base rather than accepting a manifest-controlled
  // destination. This is also how the POSIX installer honours MEHEN_DL_BASE.
  const gz = await releaseBytes(`${base}/v${manifest.version}/${name}.gz`, file.gzSize, fetcher)
  if (gz.length !== file.gzSize || sha256(gz) !== file.gzSha256) throw new CliError("failed", "Compressed checksum or size mismatch. The installed binary was not changed.")
  let raw: Uint8Array
  try { raw = gunzipSync(gz, { maxOutputLength: file.size }) } catch { throw new CliError("failed", "Could not unpack release. The installed binary was not changed.") }
  if (raw.length !== file.size || sha256(raw) !== file.sha256) throw new CliError("failed", "Binary checksum or size mismatch. The installed binary was not changed.")
  return raw
}
