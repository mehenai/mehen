// A push into a Fly app's secrets (Fly Machines API, the OpenAPI document
// at docs.fly.io/api/machines/openapi.json: GET /v1/apps/{app_name}, GET
// /v1/apps/{app_name}/secrets and POST
// /v1/apps/{app_name}/secrets/{secret_name}). The secret is staged: running
// Machines see it after the next deploy. Fly's answers to a list or a write
// may carry secret values; only names, the organisation slug and `error`
// are read.

import type { PushPreview } from "@mehen/protocol"
import { type FlyDestination, type PreviewAllowed, type ProviderWords, type PushCalls, type PushValue, type PushVia, type PushWritten, answerError, encodeSegment, field, ok, previewRead, readOk, pushFetch, scrubbedMessage, stringField } from "./common.ts"

export const FLY_API = "https://api.machines.dev"

function appUrl(d: FlyDestination): string {
  return `${FLY_API}/v1/apps/${encodeSegment(d.app)}`
}

function words(d: FlyDestination): ProviderWords {
  return { provider: "Fly", place: `app ${d.app}`, store: "secrets" }
}

export function flyCalls(d: FlyDestination): PushCalls {
  return { preview: [{ method: "GET", url: appUrl(d) }, { method: "GET", url: `${appUrl(d)}/secrets` }], write: [{ method: "POST", url: `${appUrl(d)}/secrets/${encodeSegment(d.name)}` }] }
}

export async function flyPreview(d: FlyDestination, via: PushVia, allowed: PreviewAllowed): Promise<Extract<PushPreview, { provider: "fly" }>> {
  const preview: Extract<PushPreview, { provider: "fly" }> = { provider: "fly", organization: null, exists: null, updatedAt: null }
  const [appCall, secretsCall] = flyCalls(d).preview
  if (allowed(appCall!)) {
    const app = await previewRead(appCall!, via, words(d), [], true)
    if (readOk(app)) preview.organization = stringField(field(app.body, "organization"), "slug")
  }
  if (allowed(secretsCall!)) {
    const secrets = await previewRead(secretsCall!, via, words(d), [], true)
    const list = readOk(secrets) ? field(secrets.body, "secrets") : null
    if (Array.isArray(list)) preview.exists = list.some((secret) => stringField(secret, "name") === d.name)
  }
  return preview
}

export async function flyWrite(d: FlyDestination, value: PushValue, via: PushVia): Promise<PushWritten> {
  const [writeCall] = flyCalls(d).write
  const answer = await pushFetch(writeCall!, via, words(d), [], { value: value.value })
  if (!ok(answer)) throw answerError(answer, via, words(d), scrubbedMessage(stringField(answer.body, "error"), value, via))
  return { outcome: "set", providerStatus: answer.status }
}
