// Enrolment, on the mehen CLI's wire: POST /v1/enrol signed by the new key
// with ten "enrol" and dev "new" (the vault verifies it against the JWK in
// the body); the poll and the renewal signed by the same key with ten
// "enrol" and dev = the enrolment id. The person opens the link, types the
// fingerprint group the page hides, and accepts with their passkey.

import { z } from "zod"
import { type FingerprintGroupIndex, fingerprintGroupIndex } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, webCryptoSigner } from "@mehen/protocol/proof"
import { type EnrolOwnerIntentSchema, type EnrolRequestedScope, type WorkspaceEnrolStatus, WorkspaceEnrolStartSchema } from "@mehen/protocol/workspace"
import { MehenRefusal, MehenTransport } from "./errors.ts"
import { type KeyFingerprint, fingerprint } from "./keys.ts"
import { vaultOrigin } from "./origin.ts"
import { ENROLMENT_ID, EnrolRenewSchema, EnrolStatusSchema, linkedSchemas } from "./responses.ts"
import { type Credentials, type Transport, type TransportOptions, readAnswer, send, transportFor } from "./transport.ts"

const ENROL_TENANT = "enrol"
const NEW_DEVICE = "new"

export type EnrolmentKey = { privateKey: CryptoKey; jwk: DeviceJwk }

export type EnrolmentConnection = TransportOptions & {
  vaultUrl: string
  key: EnrolmentKey
  // Proof `sid`: an agent session label the vault records with the attempt.
  session?: string
}

export type EnrolOwnerIntent = z.infer<typeof EnrolOwnerIntentSchema>

export type StartEnrolmentInput = EnrolmentConnection & {
  workspace: string
  owner: EnrolOwnerIntent
  name: string
  host?: string
  // A connect code from the workspace's Connect an agent page.
  connect?: string
  // Asks for less than an enrolment gets by default; the person sees it.
  scope?: EnrolRequestedScope
}

export type EnrolmentStarted = {
  enrolment: string
  code: string
  // The link the person opens, on the vault's origin.
  url: string
  expiresAt: string
  // The lease's fixed end: renewal never moves it.
  hardExpiresAt: string
  fingerprint: KeyFingerprint
  // Which of the four groups the enrol page hides: the person types it.
  hiddenGroup: FingerprintGroupIndex
}

export type EnrolmentRenewal =
  | { kind: "renewed"; enrolment: string; expiresAt: string; hardExpiresAt: string }
  // Renewed less than a minute ago: keep waiting, renew after retryAfter s.
  | { kind: "later"; retryAfter: number }
  // The attempt has settled: the same answer a poll gives.
  | { kind: "settled"; status: WorkspaceEnrolStatus }

function connection(input: EnrolmentConnection, device: string): { transport: Transport; credentials: Credentials } {
  const transport = transportFor(vaultOrigin(input.vaultUrl), input)
  const credentials: Credentials = { tenant: ENROL_TENANT, signer: webCryptoSigner(device, input.key.privateKey), ...(input.session ? { session: input.session } : {}) }
  return { transport, credentials }
}

function enrolmentPath(enrolment: string, suffix = ""): string {
  if (!ENROLMENT_ID.test(enrolment)) throw new TypeError(`${JSON.stringify(enrolment)} is not an enrolment id (enr_...).`)
  return `/v1/enrol/${encodeURIComponent(enrolment)}${suffix}`
}

export async function startEnrolment(input: StartEnrolmentInput): Promise<EnrolmentStarted> {
  const body = WorkspaceEnrolStartSchema.safeParse({
    workspace: input.workspace,
    owner: input.owner,
    name: input.name,
    backend: "software",
    jwk: { kty: input.key.jwk.kty, crv: input.key.jwk.crv, x: input.key.jwk.x, y: input.key.jwk.y },
    ...(input.host !== undefined ? { host: input.host } : {}),
    ...(input.connect !== undefined ? { connect: input.connect } : {}),
    ...(input.scope !== undefined ? { scope: input.scope } : {}),
  })
  if (!body.success) throw new TypeError(`Invalid enrolment: ${body.error.issues[0]?.message ?? "rejected"}.`)
  const { transport, credentials } = connection(input, NEW_DEVICE)
  const sent = await send(transport, credentials, "POST", "/v1/enrol", JSON.stringify(body.data))
  const started = await readAnswer(transport, sent, linkedSchemas(transport.origin).EnrolStart)
  const own = await fingerprint(input.key.jwk)
  if (started.fingerprint.replaceAll(" ", "") !== own.fingerprint.replaceAll(" ", "")) {
    throw new MehenTransport("unexpected", "The vault's enrolment names a different key fingerprint from the key that signed it.")
  }
  const expected = `${transport.origin}/w/${body.data.workspace}/e/${started.code}`
  if (started.url !== expected) throw new MehenTransport("unexpected", "The vault's enrolment link is not the workspace's enrol page for its code.")
  return {
    enrolment: started.enrolment,
    code: started.code,
    url: started.url,
    expiresAt: started.expiresAt,
    hardExpiresAt: started.hardExpiresAt,
    fingerprint: own,
    hiddenGroup: await fingerprintGroupIndex(started.code),
  }
}

// One look at the attempt. Pending answers carry the lease's expiry; an
// active one carries the device id, the tenant and the accepted scope.
export async function enrolmentStatus(input: EnrolmentConnection & { enrolment: string }): Promise<WorkspaceEnrolStatus> {
  const path = enrolmentPath(input.enrolment)
  const { transport, credentials } = connection(input, input.enrolment)
  return readAnswer(transport, await send(transport, credentials, "GET", path, null), EnrolStatusSchema)
}

// A fresh lease on the same id, code and link, up to hardExpiresAt.
export async function renewEnrolment(input: EnrolmentConnection & { enrolment: string }): Promise<EnrolmentRenewal> {
  const path = enrolmentPath(input.enrolment, "/renew")
  const { transport, credentials } = connection(input, input.enrolment)
  let renewed: z.infer<typeof EnrolRenewSchema>
  try {
    renewed = await readAnswer(transport, await send(transport, credentials, "POST", path, null), EnrolRenewSchema)
  } catch (error) {
    if (!(error instanceof MehenRefusal) || error.code !== "conflict") throw error
    if (error.enrolment !== undefined) return { kind: "settled", status: error.enrolment }
    if (error.retryAfter !== undefined) return { kind: "later", retryAfter: error.retryAfter }
    throw error
  }
  if (renewed.enrolment !== input.enrolment) throw new MehenTransport("unexpected", `The vault's renewal names ${renewed.enrolment}, not ${input.enrolment}.`)
  return { kind: "renewed", ...renewed }
}
