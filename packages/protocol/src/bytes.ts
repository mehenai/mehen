// Byte helpers shared by the Worker, the CLI and the browser. WebCrypto and
// the standard library only: every runtime we target has both.

export type Bytes = Uint8Array<ArrayBuffer>

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false })

export function utf8(text: string): Bytes {
  return new Uint8Array(encoder.encode(text))
}

export function fromUtf8(bytes: Bytes): string {
  return decoder.decode(bytes)
}

export function base64UrlEncode(bytes: Bytes | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ""
  for (let i = 0; i < view.length; i += 0x8000) {
    binary += String.fromCharCode(...view.subarray(i, i + 0x8000))
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")
}

const BASE64URL = /^[A-Za-z0-9_-]*$/

export function base64UrlDecode(text: string): Bytes {
  if (!BASE64URL.test(text) || text.length % 4 === 1) throw new Error("invalid base64url")
  const padded = text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4)
  const binary = atob(padded)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function concatBytes(...parts: Bytes[]): Bytes {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

// Prefixed random identifiers: dev_, itm_, int_ and so on. 16 random bytes
// is 128 bits, enough that ids double as unguessable lookup keys.
export function randomId(prefix: string, bytes = 16): string {
  return `${prefix}_${base64UrlEncode(randomBytes(bytes))}`
}

export async function sha256(data: Bytes | string): Promise<Bytes> {
  const bytes = typeof data === "string" ? utf8(data) : data
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))
}

export async function sha256B64(data: Bytes | string): Promise<string> {
  return base64UrlEncode(await sha256(data))
}

// Constant time for equal-length inputs; length is not secret here.
export function timingSafeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  return diff === 0
}

export function timingSafeEqualText(a: string, b: string): boolean {
  return timingSafeEqual(utf8(a), utf8(b))
}
