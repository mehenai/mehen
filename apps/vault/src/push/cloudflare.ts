// A push into a Cloudflare Worker's secrets (developers.cloudflare.com/api:
// "Account Details", GET /accounts/{account_id}; "List script secrets" and
// "Add script secret", GET and PUT
// /accounts/{account_id}/workers/scripts/{script_name}/secrets). Cloudflare
// deploys a new version of the Worker with the secret. Every answer is
// Cloudflare's envelope: `success`, `errors[]` and `result`.

import type { PushPreview } from "@mehen/protocol"
import { type CloudflareDestination, type PreviewAllowed, type ProviderWords, type PushCalls, type PushValue, type PushVia, type PushWritten, answerError, field, ok, previewRead, readOk, providerRefused, pushFetch, scrubbedMessage, stringField, encodeSegment, unreadableAnswer } from "./common.ts"

export const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"

function accountUrl(d: CloudflareDestination): string {
  return `${CLOUDFLARE_API}/accounts/${encodeSegment(d.account)}`
}

function secretsUrl(d: CloudflareDestination): string {
  return `${accountUrl(d)}/workers/scripts/${encodeSegment(d.script)}/secrets`
}

function words(d: CloudflareDestination): ProviderWords {
  return { provider: "Cloudflare", place: `Worker ${d.script}`, store: "secrets" }
}

export function cloudflareCalls(d: CloudflareDestination): PushCalls {
  return { preview: [{ method: "GET", url: accountUrl(d) }, { method: "GET", url: secretsUrl(d) }], write: [{ method: "PUT", url: secretsUrl(d) }] }
}

function cloudflareMessage(body: unknown): string | null {
  const errors = field(body, "errors")
  return Array.isArray(errors) ? stringField(errors[0], "message") : null
}

export async function cloudflarePreview(d: CloudflareDestination, via: PushVia, allowed: PreviewAllowed): Promise<Extract<PushPreview, { provider: "cloudflare" }>> {
  const preview: Extract<PushPreview, { provider: "cloudflare" }> = { provider: "cloudflare", accountName: null, exists: null, updatedAt: null }
  const [accountCall, secretsCall] = cloudflareCalls(d).preview
  // A token may write a Worker's secrets without reading its account: a
  // missing account read refuses nothing.
  if (allowed(accountCall!)) {
    const account = await previewRead(accountCall!, via, words(d), [], false)
    if (readOk(account)) preview.accountName = stringField(field(account.body, "result"), "name")
  }
  if (allowed(secretsCall!)) {
    const secrets = await previewRead(secretsCall!, via, words(d), [], true)
    const result = readOk(secrets) ? field(secrets.body, "result") : null
    if (Array.isArray(result)) preview.exists = result.some((secret) => stringField(secret, "name") === d.name)
  }
  return preview
}

export async function cloudflareWrite(d: CloudflareDestination, value: PushValue, via: PushVia): Promise<PushWritten> {
  const [writeCall] = cloudflareCalls(d).write
  const answer = await pushFetch(writeCall!, via, words(d), [], { name: d.name, text: value.value, type: "secret_text" })
  const message = scrubbedMessage(cloudflareMessage(answer.body), value, via)
  if (!ok(answer)) throw answerError(answer, via, words(d), message)
  if (typeof field(answer.body, "success") !== "boolean") throw unreadableAnswer(words(d), "secret")
  if (field(answer.body, "success") !== true) throw providerRefused(answer.status, `Cloudflare did not write ${d.name}${message === null ? "." : `: ${message}`}`)
  return { outcome: "set", providerStatus: answer.status }
}
