// @mehen/client/seal: sealing in a platform's web page. The person types a
// key into the platform's own form; the page seals each secret to the
// vault's seal key, from the intake the platform's server opened, and hands
// the server boxes it cannot open. A box opens only for that intake and that
// field, so a box the server keeps or replays is worthless.
//
// This entry imports nothing but the protocol's seal code (WebCrypto and
// base64url, no zod), so a page can load it without the rest of the client.

import { type SealedBox, importSealPublicKey, seal } from "@mehen/protocol/seal"

export type { SealedBox }

// The vault's public seal key, as an intake's answer carries it.
export type SealKey = { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }

const INTAKE_ID = /^int_[A-Za-z0-9_-]{1,60}$/
const FIELD_NAME = /^[a-z][a-z0-9_]{0,63}$/
const MAX_FIELDS = 16

// The context a field's box is sealed under, which the vault opens it with.
export function intakeSealContext(intake: string, field: string): string {
  if (!INTAKE_ID.test(intake)) throw new TypeError(`${JSON.stringify(intake)} is not an intake id (int_...).`)
  if (!FIELD_NAME.test(field)) throw new TypeError(`${JSON.stringify(field)} is not a field name.`)
  return `intake/${intake}/${field}`
}

// Seals each value to the vault for one intake: { field: box }, ready for
// the intake's submit. Only secret fields belong here; public fields go as
// they are.
export async function sealFields(sealKey: SealKey, intake: string, values: Record<string, string>): Promise<Record<string, SealedBox>> {
  const entries = Object.entries(values)
  if (entries.length < 1 || entries.length > MAX_FIELDS) throw new TypeError(`Seal between 1 and ${MAX_FIELDS} fields.`)
  const fields = entries.map(([field, value]) => {
    if (typeof value !== "string") throw new TypeError(`The value of ${field} is not text.`)
    return { field, value, context: intakeSealContext(intake, field) }
  })
  const key = await importSealPublicKey(sealKey.jwk)
  return Object.fromEntries(await Promise.all(fields.map(async ({ field, value, context }) => [field, await seal(key, value, context)] as const)))
}
