// A push into a GitHub repository's Actions, environment or Dependabot
// secrets (docs.github.com/en/rest/actions/secrets and
// /en/rest/dependabot/secrets, API version 2026-03-10). The value is sealed
// to the store's public key; if GitHub rotates that key between the read
// and the write (a 422, and a fresh read gives another key_id), the value
// is sealed again and the write retried once.

import type { PushPreview } from "@mehen/protocol"
import { type Answer, type GitHubDestination, type PreviewAllowed, type ProviderWords, type PushCall, type PushCalls, type PushValue, type PushVia, type PushWritten, answerError, booleanField, encodeSegment, field, ok, previewRead, readOk, pushFetch, scrubbedMessage, stringField } from "./common.ts"
import { sealForGitHub } from "./sealed-box.ts"
import { VaultError } from "../http.ts"

export const GITHUB_API = "https://api.github.com"
export const GITHUB_API_VERSION = "2026-03-10"
const GITHUB_HEADERS: [string, string][] = [["accept", "application/vnd.github+json"], ["x-github-api-version", GITHUB_API_VERSION]]

function repoUrl(d: GitHubDestination): string {
  return `${GITHUB_API}/repos/${encodeSegment(d.owner)}/${encodeSegment(d.repo)}`
}

function secretsUrl(d: GitHubDestination): string {
  if (d.store === "environment") return `${repoUrl(d)}/environments/${encodeSegment(d.environment ?? "")}/secrets`
  return `${repoUrl(d)}/${d.store === "dependabot" ? "dependabot" : "actions"}/secrets`
}

function words(d: GitHubDestination): ProviderWords {
  return { provider: "GitHub", place: `${d.owner}/${d.repo}`, store: d.store === "dependabot" ? "Dependabot secrets" : "secrets" }
}

export function githubCalls(d: GitHubDestination): PushCalls {
  const preview: PushCall[] = [{ method: "GET", url: repoUrl(d) }]
  if (d.store === "environment") preview.push({ method: "GET", url: `${repoUrl(d)}/environments/${encodeSegment(d.environment ?? "")}` })
  preview.push({ method: "GET", url: `${secretsUrl(d)}/${encodeSegment(d.name)}` })
  return { preview, write: [{ method: "GET", url: `${secretsUrl(d)}/public-key` }, { method: "PUT", url: `${secretsUrl(d)}/${encodeSegment(d.name)}` }] }
}

export async function githubPreview(d: GitHubDestination, via: PushVia, allowed: PreviewAllowed): Promise<Extract<PushPreview, { provider: "github" }>> {
  const preview: Extract<PushPreview, { provider: "github" }> = { provider: "github", owner: null, ownerType: null, private: null, fork: null, parent: null, exists: null, updatedAt: null }
  const [repoCall, ...rest] = githubCalls(d).preview
  const secretCall = rest.pop()!
  const say = words(d)
  if (allowed(repoCall!)) {
    const repo = await previewRead(repoCall!, via, say, GITHUB_HEADERS, true)
    if (readOk(repo)) {
      const owner = field(repo.body, "owner")
      preview.owner = stringField(owner, "login")
      preview.ownerType = stringField(owner, "type")
      preview.private = booleanField(repo.body, "private")
      preview.fork = booleanField(repo.body, "fork")
      preview.parent = preview.fork === true ? stringField(field(repo.body, "parent"), "full_name") : null
    }
  }
  for (const environmentCall of rest) if (allowed(environmentCall)) await previewRead(environmentCall, via, { ...say, place: `${say.place} environment ${d.environment}` }, GITHUB_HEADERS, true)
  if (allowed(secretCall)) {
    const secret = await previewRead(secretCall, via, say, GITHUB_HEADERS, false)
    if (secret?.status === 404) preview.exists = false
    else if (readOk(secret)) {
      preview.exists = true
      preview.updatedAt = stringField(secret.body, "updated_at")
    }
  }
  return preview
}

type PublicKey = { keyId: string; key: string }

async function publicKey(d: GitHubDestination, value: PushValue, via: PushVia): Promise<PublicKey> {
  const [keyCall] = githubCalls(d).write
  const answer = await pushFetch(keyCall!, via, words(d), GITHUB_HEADERS)
  if (!ok(answer)) throw answerError(answer, via, words(d), scrubbedMessage(stringField(answer.body, "message"), value, via))
  const keyId = stringField(answer.body, "key_id")
  const key = stringField(answer.body, "key")
  if (keyId === null || key === null) throw new VaultError("upstream_failed", "GitHub did not give a usable public key; nothing was written.", { retryAfter: 5 })
  return { keyId, key }
}

async function put(d: GitHubDestination, value: PushValue, via: PushVia, key: PublicKey): Promise<Answer> {
  const encrypted = sealForGitHub(value.value, key.key)
  if (encrypted === null) throw new VaultError("upstream_failed", "GitHub did not give a usable public key; nothing was written.", { retryAfter: 5 })
  const [, putCall] = githubCalls(d).write
  return pushFetch(putCall!, via, words(d), GITHUB_HEADERS, { encrypted_value: encrypted, key_id: key.keyId })
}

export async function githubWrite(d: GitHubDestination, value: PushValue, via: PushVia): Promise<PushWritten> {
  const first = await publicKey(d, value, via)
  let answer = await put(d, value, via, first)
  if (answer.status === 422) {
    const fresh = await publicKey(d, value, via)
    if (fresh.keyId !== first.keyId) answer = await put(d, value, via, fresh)
  }
  if (answer.status === 201) return { outcome: "created", providerStatus: 201 }
  if (answer.status === 204) return { outcome: "replaced", providerStatus: 204 }
  if (ok(answer)) return { outcome: "set", providerStatus: answer.status }
  throw answerError(answer, via, words(d), scrubbedMessage(stringField(answer.body, "message"), value, via))
}
