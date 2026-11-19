// The published CLI release, as the vault advertises it in Mehen-Cli
// (cli-version.ts): the version of https://mehen.dev/dl/latest.json, read
// through the RELEASES_WEB service binding to the mehen-web Worker (no
// public fetch, no release bucket), kept only when a key in RELEASE_KEYS,
// the list every `mehen` binary compiles in, signed it. Held in isolate
// memory: a /v1 request starts a read at most every five minutes with
// ctx.waitUntil, and no request ever waits for one. The last good read
// counts for an hour; before it, and after that hour, there is none. A
// read that fails logs its reason, never the body.

import { RELEASE_KEYS } from "@mehen/protocol/release-keys"
import { type ReleaseKey, verifyManifestSignatures } from "@mehen/protocol/release-manifest"
import type { Env } from "./env.ts"

export const PUBLISHED_RELEASE_URL = "https://mehen.dev/dl/latest.json"
export const PUBLISHED_RELEASE_REFRESH_MS = 5 * 60_000
export const PUBLISHED_RELEASE_KEPT_MS = 60 * 60_000
export const PUBLISHED_RELEASE_MAX_BYTES = 64 * 1024
export const PUBLISHED_RELEASE_TIMEOUT_MS = 5_000
// The strict x.y.z Mehen-Cli carries; a pre-release is never advertised.
const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/

type ReadFailureReason = "unreachable" | "timeout" | "status" | "too_large" | "not_json" | "version" | "unsigned" | "unknown_key" | "bad_signature" | "malformed"

class ReadFailure extends Error {
  constructor(readonly reason: ReadFailureReason) {
    super(reason)
  }
}

let published: { version: string; fetchedAt: number } | null = null
let lastReadAt: number | null = null
let reading = false

export function resetPublishedReleaseForTest(): void {
  published = null
  lastReadAt = null
  reading = false
}

// The verified version of the last good read, while it is under an hour old.
export function publishedCliVersion(now: number): string | null {
  return published !== null && now - published.fetchedAt < PUBLISHED_RELEASE_KEPT_MS ? published.version : null
}

// Starts a read when one is due (a binding, none in flight, none started in
// the last five minutes), for the caller to hand to ctx.waitUntil; null
// when none is. The promise never rejects. A good read replaces the last
// one whichever way it moved, so a paused release lowers the version.
// `keys` are the trusted release keys; tests pass keys of their own.
export function refreshPublishedRelease(env: Env, now: number, keys: readonly ReleaseKey[] = RELEASE_KEYS): Promise<void> | null {
  const web = env.RELEASES_WEB
  if (!web || reading || (lastReadAt !== null && now - lastReadAt < PUBLISHED_RELEASE_REFRESH_MS)) return null
  reading = true
  lastReadAt = now
  return readWithin(web, keys)
    .then(
      (version) => {
        published = { version, fetchedAt: now }
      },
      (error: unknown) => {
        console.error(JSON.stringify({ at: "published_release", reason: error instanceof ReadFailure ? error.reason : "unreachable" }))
      },
    )
    .finally(() => {
      reading = false
    })
}

async function readWithin(web: Fetcher, keys: readonly ReleaseKey[]): Promise<string> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort()
      reject(new ReadFailure("timeout"))
    }, PUBLISHED_RELEASE_TIMEOUT_MS)
  })
  try {
    return await Promise.race([readVerified(web, keys, controller.signal), timeout])
  } finally {
    clearTimeout(timer)
  }
}

async function readVerified(web: Fetcher, keys: readonly ReleaseKey[], signal: AbortSignal): Promise<string> {
  const response = await web.fetch(PUBLISHED_RELEASE_URL, { signal, headers: { accept: "application/json" } })
  if (response.status !== 200) {
    await response.body?.cancel()
    throw new ReadFailure("status")
  }
  let manifest: unknown
  try {
    manifest = JSON.parse(await boundedText(response))
  } catch (error) {
    throw error instanceof ReadFailure ? error : new ReadFailure("not_json")
  }
  const version = typeof manifest === "object" && manifest !== null ? (manifest as { version?: unknown }).version : undefined
  if (typeof version !== "string" || !VERSION.test(version)) throw new ReadFailure("version")
  const verified = await verifyManifestSignatures(manifest, keys)
  if (!verified.ok) throw new ReadFailure(verified.reason)
  return verified.manifest.version
}

async function boundedText(response: Response): Promise<string> {
  if (Number(response.headers.get("content-length")) > PUBLISHED_RELEASE_MAX_BYTES) {
    await response.body?.cancel()
    throw new ReadFailure("too_large")
  }
  const reader = response.body?.getReader()
  if (!reader) return ""
  const chunks: Uint8Array[] = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > PUBLISHED_RELEASE_MAX_BYTES) {
      await reader.cancel()
      throw new ReadFailure("too_large")
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)
}
