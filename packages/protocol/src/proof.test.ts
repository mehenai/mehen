import { describe, expect, test } from "bun:test"
import { type Bytes, base64UrlDecode, base64UrlEncode, fromUtf8, sha256B64, utf8 } from "./bytes.ts"
import {
  type DeviceJwk,
  type ProofCheck,
  PROOF_MAX_SKEW_SECONDS,
  PROOF_TYPE,
  bodyHash,
  createProof,
  importDeviceKey,
  isDeviceJwk,
  jwkThumbprint,
  normaliseUrl,
  parseProof,
  verifyProof,
  webCryptoSigner,
} from "./proof.ts"

type Device = { id: string; signer: ReturnType<typeof webCryptoSigner>; jwk: DeviceJwk; publicKey: CryptoKey }

const NOW = 1_800_000_000_000
const URL_A = "https://vault.example.com/v1/items/itm_one?expand=meta"
const BODY = '{"name":"stripe"}'

async function newDevice(id = "dev_laptop"): Promise<Device> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey)
  const jwk: DeviceJwk = { kty: "EC", crv: "P-256", x: String(exported.x), y: String(exported.y) }
  return { id, signer: webCryptoSigner(id, pair.privateKey), jwk, publicKey: await importDeviceKey(jwk) }
}

const device = await newDevice()

async function proofFor(
  overrides: { method?: string; url?: string; body?: string | null; now?: number } = {},
): Promise<string> {
  return createProof(
    device.signer,
    {
      method: overrides.method ?? "POST",
      url: overrides.url ?? URL_A,
      body: overrides.body === undefined ? BODY : overrides.body,
    },
    { tenant: "ten_alpha", now: overrides.now ?? NOW },
  )
}

async function check(
  token: string,
  received: { method?: string; url?: string; body?: string | null; now?: number } = {},
  publicKey: CryptoKey = device.publicKey,
): Promise<ProofCheck> {
  return verifyProof(parseProof(token), publicKey, {
    method: received.method ?? "POST",
    url: received.url ?? URL_A,
    bodyHash: await bodyHash(received.body === undefined ? BODY : received.body),
    now: received.now ?? NOW,
  })
}

// Signs an arbitrary header and payload with the test device, for tokens
// createProof would never produce.
async function signRaw(header: unknown, payload: unknown): Promise<string> {
  const input = `${base64UrlEncode(utf8(JSON.stringify(header)))}.${base64UrlEncode(utf8(JSON.stringify(payload)))}`
  return `${input}.${base64UrlEncode(await device.signer.sign(utf8(input)))}`
}

function decodeSegment(token: string, index: number): Record<string, unknown> {
  const segment = token.split(".")[index] ?? ""
  return JSON.parse(fromUtf8(base64UrlDecode(segment))) as Record<string, unknown>
}

async function validClaims(): Promise<Record<string, unknown>> {
  return decodeSegment(await proofFor(), 1)
}

const HEADER = { alg: "ES256", typ: PROOF_TYPE, kid: "dev_laptop" }

describe("createProof", () => {
  test("produces a compact JWS with the expected header and claims", async () => {
    const token = await createProof(
      device.signer,
      { method: "post", url: `${URL_A}#frag`, body: BODY },
      { tenant: "ten_alpha", session: "sess-1", grant: "gnt_1", now: NOW },
    )
    const parts = token.split(".")
    expect(parts.length).toBe(3)
    expect(decodeSegment(token, 0)).toEqual(HEADER)
    const claims = decodeSegment(token, 1)
    expect(claims.ten).toBe("ten_alpha")
    expect(claims.dev).toBe("dev_laptop")
    expect(claims.sid).toBe("sess-1")
    expect(claims.gnt).toBe("gnt_1")
    expect(claims.htm).toBe("POST")
    expect(claims.htu).toBe(URL_A)
    expect(claims.bh).toBe(await sha256B64(BODY))
    expect(claims.iat).toBe(NOW / 1000)
    expect(String(claims.jti)).toMatch(/^jti_[A-Za-z0-9_-]{16}$/)
    expect(base64UrlDecode(parts[2] ?? "").length).toBe(64)
  })

  test("omits sid and gnt when not given and uses a fresh jti each time", async () => {
    const a = decodeSegment(await proofFor(), 1)
    const b = decodeSegment(await proofFor(), 1)
    expect("sid" in a).toBe(false)
    expect("gnt" in a).toBe(false)
    expect(a.jti).not.toBe(b.jti)
  })

  test("refuses a signer that does not return a 64-byte r||s signature", async () => {
    const badSigner = { deviceId: "dev_laptop", sign: async (): Promise<Bytes> => new Uint8Array(70) }
    await expect(
      createProof(badSigner, { method: "GET", url: URL_A }, { tenant: "ten_alpha", now: NOW }),
    ).rejects.toThrow("64-byte")
  })
})

describe("bodyHash and normaliseUrl", () => {
  test("hashes no body as the empty string", async () => {
    const empty = await sha256B64("")
    expect(await bodyHash(null)).toBe(empty)
    expect(await bodyHash(undefined)).toBe(empty)
    expect(await bodyHash("")).toBe(empty)
    expect(await bodyHash(new Uint8Array())).toBe(empty)
  })

  test("hashes string and byte bodies identically", async () => {
    expect(await bodyHash(BODY)).toBe(await bodyHash(utf8(BODY)))
  })

  test("drops the fragment but keeps the query", () => {
    expect(normaliseUrl("https://h.example/a?b=1#c")).toBe("https://h.example/a?b=1")
    expect(normaliseUrl("https://h.example/a#")).toBe("https://h.example/a")
  })
})

describe("verifyProof", () => {
  test("a valid proof verifies and returns its claims", async () => {
    const result = await check(await proofFor())
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.claims.ten).toBe("ten_alpha")
      expect(result.claims.dev).toBe("dev_laptop")
    }
  })

  test("a proof with no body verifies against the empty body hash", async () => {
    const token = await proofFor({ method: "GET", body: null })
    expect(await check(token, { method: "GET", body: null })).toEqual({
      ok: true,
      claims: parseProof(token).claims,
    })
  })

  test("the method comparison is case insensitive on the received side", async () => {
    expect((await check(await proofFor(), { method: "post" })).ok).toBe(true)
  })

  test("the URL fragment is ignored on both sides", async () => {
    const token = await proofFor({ url: `${URL_A}#one` })
    expect((await check(token, { url: `${URL_A}#two` })).ok).toBe(true)
    expect((await check(token)).ok).toBe(true)
  })

  test("rejects another method", async () => {
    expect(await check(await proofFor(), { method: "PUT" })).toEqual({ ok: false, reason: "method" })
    expect(await check(await proofFor(), { method: "GET" })).toEqual({ ok: false, reason: "method" })
  })

  test("rejects another URL path, host, scheme or port", async () => {
    const token = await proofFor()
    for (const url of [
      "https://vault.example.com/v1/items/itm_two?expand=meta",
      "https://evil.example.com/v1/items/itm_one?expand=meta",
      "http://vault.example.com/v1/items/itm_one?expand=meta",
      "https://vault.example.com:8443/v1/items/itm_one?expand=meta",
    ]) {
      expect(await check(token, { url })).toEqual({ ok: false, reason: "url" })
    }
  })

  test("rejects a changed, added or removed query", async () => {
    const token = await proofFor()
    for (const url of [
      "https://vault.example.com/v1/items/itm_one?expand=all",
      "https://vault.example.com/v1/items/itm_one?expand=meta&x=1",
      "https://vault.example.com/v1/items/itm_one",
    ]) {
      expect(await check(token, { url })).toEqual({ ok: false, reason: "url" })
    }
  })

  test("rejects another body, including an empty one", async () => {
    const token = await proofFor()
    expect(await check(token, { body: '{"name":"stripf"}' })).toEqual({ ok: false, reason: "body" })
    expect(await check(token, { body: null })).toEqual({ ok: false, reason: "body" })
    expect(await check(token, { body: `${BODY} ` })).toEqual({ ok: false, reason: "body" })
  })

  test("accepts iat at the edge of the skew window both ways", async () => {
    const token = await proofFor()
    expect((await check(token, { now: NOW + PROOF_MAX_SKEW_SECONDS * 1000 })).ok).toBe(true)
    expect((await check(token, { now: NOW - PROOF_MAX_SKEW_SECONDS * 1000 })).ok).toBe(true)
  })

  test("rejects an iat too far in the past", async () => {
    const token = await proofFor()
    expect(await check(token, { now: NOW + (PROOF_MAX_SKEW_SECONDS + 1) * 1000 })).toEqual({
      ok: false,
      reason: "expired",
    })
  })

  test("rejects an iat too far in the future", async () => {
    const token = await proofFor()
    expect(await check(token, { now: NOW - (PROOF_MAX_SKEW_SECONDS + 1) * 1000 })).toEqual({
      ok: false,
      reason: "future",
    })
  })

  test("rejects a tampered signature", async () => {
    const token = await proofFor()
    const [h, p, s] = token.split(".") as [string, string, string]
    const sig = base64UrlDecode(s)
    for (const index of [0, 31, 32, 63]) {
      const flipped = new Uint8Array(sig)
      flipped[index] = (flipped[index] ?? 0) ^ 0x80
      expect(await check(`${h}.${p}.${base64UrlEncode(flipped)}`)).toEqual({ ok: false, reason: "signature" })
    }
  })

  test("rejects claims altered after signing", async () => {
    const token = await proofFor()
    const [h, , s] = token.split(".") as [string, string, string]
    const claims = await validClaims()
    const forged = base64UrlEncode(utf8(JSON.stringify({ ...claims, htu: "https://vault.example.com/v1/admin" })))
    expect(await check(`${h}.${forged}.${s}`, { url: "https://vault.example.com/v1/admin" })).toEqual({
      ok: false,
      reason: "signature",
    })
  })

  test("rejects a signature by another device key", async () => {
    const other = await newDevice()
    expect(await check(await proofFor(), {}, other.publicKey)).toEqual({ ok: false, reason: "signature" })
  })

  test("rejects a signature of the wrong length", async () => {
    const token = await proofFor()
    const [h, p] = token.split(".") as [string, string, string]
    expect(await check(`${h}.${p}.${base64UrlEncode(new Uint8Array(63))}`)).toEqual({ ok: false, reason: "signature" })
    expect(await check(`${h}.${p}.`)).toEqual({ ok: false, reason: "signature" })
  })
})

describe("parseProof", () => {
  test("parses a valid token", async () => {
    const parsed = parseProof(await proofFor())
    expect(parsed.claims.dev).toBe("dev_laptop")
    expect(parsed.signature.length).toBe(64)
  })

  test("rejects a kid that does not match the dev claim", async () => {
    const token = await signRaw({ ...HEADER, kid: "dev_other" }, await validClaims())
    expect(() => parseProof(token)).toThrow("proof key id does not match device")
    const missingKid = await signRaw({ alg: "ES256", typ: PROOF_TYPE }, await validClaims())
    expect(() => parseProof(missingKid)).toThrow("proof key id does not match device")
  })

  test("rejects other algorithms and types", async () => {
    const claims = await validClaims()
    for (const header of [
      { ...HEADER, alg: "none" },
      { ...HEADER, alg: "HS256" },
      { ...HEADER, alg: "es256" },
      { ...HEADER, typ: "JWT" },
      { kid: "dev_laptop" },
    ]) {
      expect(() => parseProof(`${base64UrlEncode(utf8(JSON.stringify(header)))}.${base64UrlEncode(utf8(JSON.stringify(claims)))}.`)).toThrow("unsupported proof type")
    }
  })

  test("rejects tokens with the wrong number of segments", async () => {
    const token = await proofFor()
    const [h, p, s] = token.split(".") as [string, string, string]
    expect(() => parseProof("")).toThrow("malformed proof")
    expect(() => parseProof(`${h}.${p}`)).toThrow("malformed proof")
    expect(() => parseProof(`${h}.${p}.${s}.${s}`)).toThrow("malformed proof")
  })

  test("rejects segments that are not base64url JSON objects", async () => {
    const token = await proofFor()
    const [h, p, s] = token.split(".") as [string, string, string]
    const enc = (text: string): string => base64UrlEncode(utf8(text))
    expect(() => parseProof(`${h}+.${p}.${s}`)).toThrow()
    expect(() => parseProof(`${h}.${p}.${s}=`)).toThrow()
    expect(() => parseProof(`${enc("not json")}.${p}.${s}`)).toThrow()
    expect(() => parseProof(`${enc("null")}.${p}.${s}`)).toThrow("malformed proof header")
    expect(() => parseProof(`${enc("42")}.${p}.${s}`)).toThrow("malformed proof header")
    expect(() => parseProof(`${h}.${enc("not json")}.${s}`)).toThrow()
    expect(() => parseProof(`${h}.${enc("null")}.${s}`)).toThrow("malformed proof claims")
    expect(() => parseProof(`${h}.${enc("[]")}.${s}`)).toThrow("malformed proof claims")
    expect(() => parseProof(`${base64UrlEncode(Uint8Array.of(0xff, 0xfe))}.${p}.${s}`)).toThrow()
  })

  test("rejects claims that are missing or malformed", async () => {
    const claims = await validClaims()
    const bad: Record<string, unknown>[] = [
      { ...claims, ten: undefined },
      { ...claims, ten: "" },
      { ...claims, ten: "ten alpha" },
      { ...claims, ten: "x".repeat(129) },
      { ...claims, dev: 7 },
      { ...claims, sid: "has space" },
      { ...claims, gnt: 1 },
      { ...claims, htm: "post" },
      { ...claims, htm: "GE" },
      { ...claims, htm: "DELETEXX" },
      { ...claims, htu: 1 },
      { ...claims, htu: `https://h.example/${"a".repeat(4096)}` },
      { ...claims, bh: "short" },
      { ...claims, bh: `${String(claims.bh)}A` },
      { ...claims, iat: "1800000000" },
      { ...claims, iat: 1800000000.5 },
      { ...claims, jti: "" },
      { ...claims, jti: "jti/../x" },
    ]
    for (const payload of bad) {
      const token = await signRaw(HEADER, payload)
      expect(() => parseProof(token)).toThrow("malformed proof claims")
    }
  })

  test("rejects oversized tokens before decoding", async () => {
    const token = await proofFor()
    expect(() => parseProof(`${token}${"A".repeat(8193 - token.length)}`)).toThrow("proof too large")
    expect(() => parseProof("A".repeat(100_000))).toThrow("proof too large")
  })
})

describe("device keys", () => {
  test("isDeviceJwk accepts a P-256 public JWK and nothing else", async () => {
    expect(isDeviceJwk(device.jwk)).toBe(true)
    expect(isDeviceJwk(null)).toBe(false)
    expect(isDeviceJwk("jwk")).toBe(false)
    expect(isDeviceJwk({ ...device.jwk, crv: "P-384" })).toBe(false)
    expect(isDeviceJwk({ ...device.jwk, kty: "RSA" })).toBe(false)
    expect(isDeviceJwk({ ...device.jwk, x: `${device.jwk.x}A` })).toBe(false)
    expect(isDeviceJwk({ ...device.jwk, y: "short" })).toBe(false)
    expect(isDeviceJwk({ kty: "EC", crv: "P-256", x: device.jwk.x })).toBe(false)
  })

  test("jwkThumbprint is the RFC 7638 hash of the canonical members", async () => {
    const canonical = JSON.stringify({ crv: "P-256", kty: "EC", x: device.jwk.x, y: device.jwk.y })
    expect(await jwkThumbprint(device.jwk)).toBe(await sha256B64(canonical))
    const other = await newDevice()
    expect(await jwkThumbprint(other.jwk)).not.toBe(await jwkThumbprint(device.jwk))
  })
})

describe("workload proofs", () => {
  test("a workload signs with its own key id and names its parent device", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const exported = await crypto.subtle.exportKey("jwk", pair.publicKey)
    const jwk: DeviceJwk = { kty: "EC", crv: "P-256", x: String(exported.x), y: String(exported.y) }
    const signer = webCryptoSigner("dev_host", pair.privateKey, "wl_task0001")
    const token = await createProof(signer, { method: "GET", url: URL_A }, { tenant: "ten_one", now: NOW })
    const parsed = parseProof(token)
    const header = JSON.parse(fromUtf8(base64UrlDecode(token.split(".")[0] ?? ""))) as Record<string, unknown>
    expect(header.kid).toBe("wl_task0001")
    expect(parsed.claims.dev).toBe("dev_host")
    expect(parsed.claims.wkl).toBe("wl_task0001")
    const check = await verifyProof(parsed, await importDeviceKey(jwk), { method: "GET", url: URL_A, bodyHash: await bodyHash(null), now: NOW })
    expect(check.ok).toBe(true)
  })

  test("a device proof carries no wkl claim", async () => {
    const parsed = parseProof(await proofFor())
    expect(parsed.claims.wkl).toBeUndefined()
  })

  test("refuses a proof whose key id is neither the workload nor, without one, the device", async () => {
    const token = await createProof(webCryptoSigner("dev_host", (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair).privateKey, "wl_task0001"), { method: "GET", url: URL_A }, { tenant: "ten_one", now: NOW })
    const [h, p, s] = token.split(".") as [string, string, string]
    const forged = base64UrlEncode(utf8(JSON.stringify({ alg: "ES256", typ: PROOF_TYPE, kid: "dev_host" })))
    expect(() => parseProof(`${forged}.${p}.${s}`)).toThrow("proof key id does not match device")
    expect(h).not.toBe(forged)
  })
})

// The device proof's bytes, frozen: the platform proof shares this module's
// helpers, and a device proof must not change by one byte.
test("a device proof's header, claims and signature segments are unchanged", async () => {
  const fixed = new Uint8Array(64).fill(7)
  const signer = { deviceId: "dev_laptop", workloadId: "wl_task00001", sign: async () => fixed }
  const token = await createProof(signer, { method: "post", url: `${URL_A}#frag`, body: BODY }, { tenant: "tn_abcdefgh12", session: "s1", grant: "gnt_1", now: NOW })
  const [h, p, s] = token.split(".") as [string, string, string]
  expect(fromUtf8(base64UrlDecode(h))).toBe('{"alg":"ES256","typ":"mehen-proof+jwt","kid":"wl_task00001"}')
  const claims = JSON.parse(fromUtf8(base64UrlDecode(p))) as Record<string, unknown>
  expect(Object.keys(claims)).toEqual(["ten", "dev", "wkl", "sid", "gnt", "htm", "htu", "bh", "iat", "jti"])
  expect(claims).toMatchObject({ ten: "tn_abcdefgh12", dev: "dev_laptop", wkl: "wl_task00001", sid: "s1", gnt: "gnt_1", htm: "POST", htu: URL_A, bh: await sha256B64(BODY), iat: NOW / 1000 })
  expect(claims.jti).toMatch(/^jti_[A-Za-z0-9_-]{16}$/)
  expect(s).toBe(base64UrlEncode(fixed))
  const short = { deviceId: "dev_laptop", sign: async () => new Uint8Array(63) }
  await expect(createProof(short, { method: "GET", url: URL_A }, { tenant: "tn_abcdefgh12" })).rejects.toThrow("device signer must return a 64-byte r||s signature")
})
