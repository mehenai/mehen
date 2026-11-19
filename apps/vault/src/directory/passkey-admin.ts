import { z } from "zod"
import type { RegisteredPasskey } from "./webauthn.ts"

export const PasskeyName = z.string().trim().min(1).max(64)
export const PasskeyKind = z.enum(["device", "security-key"])

export function authenticatorWords(transports: string[]): string {
  if (transports.includes("internal")) return "Built into a device"
  if (transports.includes("hybrid")) return "A phone, by QR code"
  if (transports.some((t) => t === "usb" || t === "nfc" || t === "ble")) return "A security key"
  return "A passkey"
}

// A reviewed handful of providers that name themselves by AAGUID, for the
// name a new passkey gets when the member gives none.
const KNOWN_AAGUIDS: Record<string, string> = {
  "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
  "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
  "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
  "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
  "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
  "531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
  "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5",
  "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5",
  "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 NFC",
  "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 NFC",
}

export function suggestedName(passkey: RegisteredPasskey): string {
  return (passkey.aaguid === null ? undefined : KNOWN_AAGUIDS[passkey.aaguid]) ?? authenticatorWords(passkey.transports)
}
