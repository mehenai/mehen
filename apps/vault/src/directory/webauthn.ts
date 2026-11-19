// The passkey ceremonies, behind a seam so tests can stand in for real
// authenticators. The production implementation is @simplewebauthn/server.
// Passkeys are discoverable (resident), so sign-in needs no username, and
// user verification (Face ID, Touch ID, a PIN) is required: holding the
// device is not enough on its own.

import {
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"
import { VaultError } from "../http.ts"

export type PasskeyRecord = {
  credentialId: string
  publicKey: Uint8Array<ArrayBuffer>
  counter: number
  transports: string[]
}

// What the authenticator said about itself at registration. Null when it
// said nothing usable; `backedUp` is whether the passkey is synced.
export type RegisteredPasskey = PasskeyRecord & {
  aaguid: string | null
  deviceType: "singleDevice" | "multiDevice" | null
  backedUp: boolean | null
}

export type VerifiedAssertion = { counter: number; backedUp: boolean }

export type CeremonyExpectation = { challenge: string; origin: string; rpId: string }

export type PasskeyCeremonies = {
  // `exclude` lists the member's passkeys, so one authenticator cannot be
  // registered twice. `prefer` steers the browser's prompt towards this
  // device or a security key; sign-up leaves it out and allows either.
  registrationOptions(input: {
    rpId: string
    userId: Uint8Array<ArrayBuffer>
    name: string
    exclude?: { id: string; transports: string[] }[]
    prefer?: "localDevice" | "securityKey"
  }): Promise<PublicKeyCredentialCreationOptionsJSON>
  verifyRegistration(response: Record<string, unknown>, expected: CeremonyExpectation): Promise<RegisteredPasskey | null>
  // `challenge` is set for step-up, where it commits to the action; sign-in
  // gets a random one. `allow` lists the member's passkeys for step-up.
  authenticationOptions(input: {
    rpId: string
    challenge?: Uint8Array<ArrayBuffer>
    allow?: { id: string; transports: string[] }[]
  }): Promise<PublicKeyCredentialRequestOptionsJSON>
  // The authenticator's new signature counter and whether it says the
  // passkey is backed up (synced) now, or null when the assertion does not
  // verify.
  verifyAuthentication(response: Record<string, unknown>, expected: CeremonyExpectation, passkey: PasskeyRecord): Promise<VerifiedAssertion | null>
}

const RP_NAME = "Mehen"
const TIMEOUT_MS = 5 * 60_000

// The library validates the details; this only refuses bodies that are not
// shaped like a credential at all, before they reach it.
export function credentialId(response: unknown): string {
  if (typeof response !== "object" || response === null || Array.isArray(response)) fail()
  const r = response as Record<string, unknown>
  const inner = r.response
  const shaped =
    typeof r.id === "string" && r.id.length > 0 && r.id.length <= 1024 &&
    typeof r.rawId === "string" && r.type === "public-key" &&
    typeof inner === "object" && inner !== null && !Array.isArray(inner)
  if (!shaped) fail()
  return r.id as string
}

function fail(): never {
  throw new VaultError("bad_request", "That passkey response was not valid. Try again from the vault page.")
}

type Transport = NonNullable<RegistrationResponseJSON["response"]["transports"]>[number]

const AAGUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
// What an authenticator sends when it will not say what it is.
const NO_AAGUID = "00000000-0000-0000-0000-000000000000"

export const simpleWebAuthnCeremonies: PasskeyCeremonies = {
  async registrationOptions({ rpId, userId, name, exclude, prefer }) {
    return generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpId,
      userName: name,
      userDisplayName: name,
      userID: userId,
      timeout: TIMEOUT_MS,
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      ...(exclude ? { excludeCredentials: exclude } : {}),
      ...(prefer ? { preferredAuthenticatorType: prefer } : {}),
    })
  },

  async verifyRegistration(response, expected) {
    credentialId(response)
    try {
      const verification = await verifyRegistrationResponse({
        response: response as unknown as RegistrationResponseJSON,
        expectedChallenge: expected.challenge,
        expectedOrigin: expected.origin,
        expectedRPID: expected.rpId,
        requireUserVerification: true,
      })
      if (!verification.verified) return null
      const { credential, aaguid, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
      return {
        credentialId: credential.id,
        publicKey: new Uint8Array(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports ?? [],
        aaguid: AAGUID.test(aaguid) && aaguid !== NO_AAGUID ? aaguid : null,
        deviceType: credentialDeviceType === "singleDevice" || credentialDeviceType === "multiDevice" ? credentialDeviceType : null,
        backedUp: typeof credentialBackedUp === "boolean" ? credentialBackedUp : null,
      }
    } catch {
      return null
    }
  },

  async authenticationOptions({ rpId, challenge, allow }) {
    return generateAuthenticationOptions({
      rpID: rpId,
      userVerification: "required",
      timeout: TIMEOUT_MS,
      ...(challenge ? { challenge } : {}),
      ...(allow ? { allowCredentials: allow } : {}),
    })
  },

  async verifyAuthentication(response, expected, passkey) {
    credentialId(response)
    try {
      const verification = await verifyAuthenticationResponse({
        response: response as unknown as AuthenticationResponseJSON,
        expectedChallenge: expected.challenge,
        expectedOrigin: expected.origin,
        expectedRPID: expected.rpId,
        requireUserVerification: true,
        credential: {
          id: passkey.credentialId,
          publicKey: passkey.publicKey,
          counter: passkey.counter,
          transports: passkey.transports as Transport[],
        },
      })
      return verification.verified ? { counter: verification.authenticationInfo.newCounter, backedUp: verification.authenticationInfo.credentialBackedUp } : null
    } catch {
      return null
    }
  },
}

let ceremonies: PasskeyCeremonies = simpleWebAuthnCeremonies

export function passkeyCeremonies(): PasskeyCeremonies {
  return ceremonies
}

// Tests only: stand in for real authenticators. Returns the previous set.
export function setPasskeyCeremonies(next: PasskeyCeremonies): PasskeyCeremonies {
  const previous = ceremonies
  ceremonies = next
  return previous
}
