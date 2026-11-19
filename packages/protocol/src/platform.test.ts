import { describe, expect, test } from "bun:test"
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto"
import type { z } from "zod"
import { ERROR_CODES, EXIT, EXIT_FOR_ERROR, HTTP_STATUS_FOR_ERROR, type PolicyInput } from "./api.ts"
import { customItemPolicy, evaluatePolicy, parseDestination, type RuleAction } from "./binding.ts"
import { utf8 } from "./bytes.ts"
import {
  DEFAULT_PLATFORM_LIMITS,
  INITIAL_PLATFORM_DEFAULTS,
  PLATFORM_COMMON_REFUSALS,
  PLATFORM_DEVICE_MODES,
  PLATFORM_PROOF_HEADER,
  PLATFORM_PROOF_TYPE,
  PLATFORM_ROUTES,
  PLATFORM_STEP_UPS,
  type PlatformDefaults,
  PlatformDefaultsSchema,
  PlatformLimitsSchema,
  type PlatformPolicyRule,
  type PlatformRouteName,
  SealedBoxSchema,
  createPlatformProof,
  managedItemPolicy,
  parsePlatformProof,
  platformDeviceScope,
  platformMaySatisfy,
  platformPathSubject,
  platformRoute,
  platformSubjectHash,
  subjectMemberAccount,
  verifyPlatformProof,
  webCryptoPlatformSigner,
} from "./platform.ts"
import { PROOF_HEADER, PROOF_MAX_SKEW_SECONDS, bodyHash, createProof, importDeviceKey, parseProof, signCompactJws, webCryptoSigner } from "./proof.ts"
import { generateSealKeyPair, seal } from "./seal.ts"
import { OAUTH_PROVIDERS, TEMPLATES, connectionPolicy } from "./templates.ts"
import { WorkspaceDeviceScopeSchema, WorkspaceStepUpActionSchema } from "./workspace.ts"

// ---------------------------------------------------------------- fixtures

const NOW = 1_800_000_000_000
const SUBJECT = "globex_subject0001"
const DEVICES_URL = `https://vault.example.com/v1/platform/subjects/${SUBJECT}/devices`
const DEVICE_BODY = '{"name":"agent-1","modes":["relay"]}'

// Made once with node:crypto alone (generateKeyPairSync, sign with
// dsaEncoding "ieee-p1363"), never by this package.
const GOLDEN = {
  jwk: { kty: "EC", crv: "P-256", x: "4mCq7lVv1Mw5buWz0teQRcBwx20kZ8b3LzmJ8W2miCo", y: "g1Y3T2RJL6Kk57SvGp8OMxlOTJNBjXOv8Q56dh17Qpk" },
  token:
    "eyJhbGciOiJFUzI1NiIsInR5cCI6Im1laGVuLXBsYXRmb3JtK2p3dCIsImtpZCI6InBreV9nb2xkZW4wMDAxIn0" +
    ".eyJwbHQiOiJwbHRfZ29sZGVuMDAwMSIsInN1YiI6Imdsb2JleF9zdWJqZWN0MDAwMSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3ZhdWx0LmV4YW1wbGUuY29tL3YxL3BsYXRmb3JtL3N1YmplY3RzL2dsb2JleF9zdWJqZWN0MDAwMS9kZXZpY2VzIiwiYmgiOiJKdTh0RkRxSHJJT3czLXFWdUlDQ3pBTVBjYlY4WVloZkU3RHBLLU1Vcms4IiwiaWF0IjoxODAwMDAwMDAwLCJqdGkiOiJqdGlfZ29sZGVuMDAwMSJ9" +
    ".ap1dHyic1Cu3HGypYyGQINhQBz0l0Ov06BuzWuuZEumawvrtdCjyG0dGkpBi5i2srwU4-948s92jeDHHOQl3sw",
  header: '{"alg":"ES256","typ":"mehen-platform+jwt","kid":"pky_golden0001"}',
  claims: {
    plt: "plt_golden0001",
    sub: SUBJECT,
    htm: "POST",
    htu: DEVICES_URL,
    bh: "Ju8tFDqHrIOw3-qVuICCzAMPcbV8YYhfE7DpK-MUrk8",
    iat: 1_800_000_000,
    jti: "jti_golden0001",
  },
} as const

type Received = { method: string; url: string; body: string; now: number }

// A second implementation of the platform proof's verification, in
// node:crypto only: nothing from this package but the constants' values,
// written out again.
function nodeVerifyPlatformProof(token: string, jwk: { x: string; y: string }, received: Received): boolean {
  const [h, p, s] = token.split(".")
  if (h === undefined || p === undefined || s === undefined) return false
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as Record<string, unknown>
  const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>
  if (header.alg !== "ES256" || header.typ !== "mehen-platform+jwt" || typeof header.kid !== "string" || !header.kid.startsWith("pky_")) return false
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" })
  if (!nodeVerify("sha256", Buffer.from(`${h}.${p}`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"))) return false
  const url = new URL(received.url)
  url.hash = ""
  const match = /^\/v1\/platform\/subjects\/([^/]+)/.exec(url.pathname)
  const now = Math.floor(received.now / 1000)
  return (
    claims.htm === received.method.toUpperCase() &&
    claims.htu === url.toString() &&
    claims.bh === createHash("sha256").update(received.body).digest("base64url") &&
    typeof claims.iat === "number" && Math.abs(claims.iat - now) <= 60 &&
    (claims.sub ?? null) === (match?.[1] ?? null)
  )
}

async function newPlatformKey() {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey)
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: String(exported.x), y: String(exported.y) }
  return { pair, jwk, publicKey: await importDeviceKey(jwk), signer: webCryptoPlatformSigner("plt_globex0001", "pky_globex0001", pair.privateKey) }
}

const platform = await newPlatformKey()

async function received(url: string, body: string, overrides: Partial<Received> = {}) {
  const r = { method: "POST", url, body, now: NOW, ...overrides }
  return { method: r.method, url: r.url, bodyHash: await bodyHash(r.body), now: r.now }
}

function decodeSegment(token: string, index: number): string {
  return Buffer.from(token.split(".")[index] ?? "", "base64url").toString("utf8")
}

// ---------------------------------------------------------------- the proof

describe("the platform proof", () => {
  test("the golden proof verifies here and in node:crypto", async () => {
    const parsed = parsePlatformProof(GOLDEN.token)
    expect(parsed.kid).toBe("pky_golden0001")
    expect(parsed.claims).toEqual(GOLDEN.claims)
    expect(decodeSegment(GOLDEN.token, 0)).toBe(GOLDEN.header)
    const key = await importDeviceKey(GOLDEN.jwk)
    expect(await verifyPlatformProof(parsed, key, await received(DEVICES_URL, DEVICE_BODY))).toEqual({ ok: true, claims: GOLDEN.claims })
    expect(nodeVerifyPlatformProof(GOLDEN.token, GOLDEN.jwk, { method: "POST", url: DEVICES_URL, body: DEVICE_BODY, now: NOW })).toBe(true)
    expect(nodeVerifyPlatformProof(GOLDEN.token, GOLDEN.jwk, { method: "POST", url: DEVICES_URL, body: `${DEVICE_BODY} `, now: NOW })).toBe(false)
  })

  test("a proof made here verifies in node:crypto, with its header and claims in a fixed order", async () => {
    const token = await createPlatformProof(platform.signer, { method: "post", url: `${DEVICES_URL}#frag`, body: DEVICE_BODY }, { now: NOW })
    expect(decodeSegment(token, 0)).toBe('{"alg":"ES256","typ":"mehen-platform+jwt","kid":"pky_globex0001"}')
    const claims = JSON.parse(decodeSegment(token, 1)) as Record<string, unknown>
    expect(Object.keys(claims)).toEqual(["plt", "sub", "htm", "htu", "bh", "iat", "jti"])
    expect(claims).toMatchObject({ plt: "plt_globex0001", sub: SUBJECT, htm: "POST", htu: DEVICES_URL, iat: NOW / 1000 })
    expect(nodeVerifyPlatformProof(token, platform.jwk, { method: "POST", url: DEVICES_URL, body: DEVICE_BODY, now: NOW })).toBe(true)
    expect(await verifyPlatformProof(parsePlatformProof(token), platform.publicKey, await received(DEVICES_URL, DEVICE_BODY))).toMatchObject({ ok: true })
  })

  test("a route outside a subject carries no sub", async () => {
    const url = "https://vault.example.com/v1/platform/defaults"
    const token = await createPlatformProof(platform.signer, { method: "PUT", url, body: "{}" }, { now: NOW })
    expect(parsePlatformProof(token).claims.sub).toBeUndefined()
    expect(await verifyPlatformProof(parsePlatformProof(token), platform.publicKey, await received(url, "{}", { method: "PUT" }))).toMatchObject({ ok: true })
    expect(nodeVerifyPlatformProof(token, platform.jwk, { method: "PUT", url, body: "{}", now: NOW })).toBe(true)
  })

  test("verification refuses another key, method, URL, body and time", async () => {
    const token = await createPlatformProof(platform.signer, { method: "POST", url: DEVICES_URL, body: DEVICE_BODY }, { now: NOW })
    const parsed = parsePlatformProof(token)
    const other = await newPlatformKey()
    expect(await verifyPlatformProof(parsed, other.publicKey, await received(DEVICES_URL, DEVICE_BODY))).toEqual({ ok: false, reason: "signature" })
    expect(await verifyPlatformProof(parsed, platform.publicKey, await received(DEVICES_URL, DEVICE_BODY, { method: "PUT" }))).toEqual({ ok: false, reason: "method" })
    expect(await verifyPlatformProof(parsed, platform.publicKey, await received(`${DEVICES_URL}?x=1`, DEVICE_BODY))).toEqual({ ok: false, reason: "url" })
    expect(await verifyPlatformProof(parsed, platform.publicKey, await received(DEVICES_URL, "{}"))).toEqual({ ok: false, reason: "body" })
    const late = NOW + (PROOF_MAX_SKEW_SECONDS + 1) * 1000
    const early = NOW - (PROOF_MAX_SKEW_SECONDS + 1) * 1000
    expect(await verifyPlatformProof(parsed, platform.publicKey, await received(DEVICES_URL, DEVICE_BODY, { now: late }))).toEqual({ ok: false, reason: "expired" })
    expect(await verifyPlatformProof(parsed, platform.publicKey, await received(DEVICES_URL, DEVICE_BODY, { now: early }))).toEqual({ ok: false, reason: "future" })
  })

  test("sub is checked against the subject the path names", async () => {
    const otherSubject = "globex_subject0002"
    const otherUrl = DEVICES_URL.replace(SUBJECT, otherSubject)
    const sign = (claims: object) => signCompactJws({ alg: "ES256", typ: PLATFORM_PROOF_TYPE, kid: "pky_globex0001" }, claims, (data) => platform.signer.sign(data), "platform")
    const base = { plt: "plt_globex0001", htm: "POST", htu: otherUrl, bh: await bodyHash(DEVICE_BODY), iat: NOW / 1000, jti: "jti_one" }
    // A proof naming one subject over a URL that names another.
    const wrongSub = parsePlatformProof(await sign({ ...base, sub: SUBJECT }))
    expect(await verifyPlatformProof(wrongSub, platform.publicKey, await received(otherUrl, DEVICE_BODY))).toEqual({ ok: false, reason: "subject" })
    // No sub on a subject's route.
    const missing = parsePlatformProof(await sign(base))
    expect(await verifyPlatformProof(missing, platform.publicKey, await received(otherUrl, DEVICE_BODY))).toEqual({ ok: false, reason: "subject" })
    // A sub on a route that names no subject.
    const defaults = "https://vault.example.com/v1/platform/defaults"
    const stray = parsePlatformProof(await sign({ ...base, htu: defaults, sub: SUBJECT }))
    expect(await verifyPlatformProof(stray, platform.publicKey, await received(defaults, DEVICE_BODY))).toEqual({ ok: false, reason: "subject" })
    // The matching subject passes.
    const right = parsePlatformProof(await sign({ ...base, sub: otherSubject }))
    expect(await verifyPlatformProof(right, platform.publicKey, await received(otherUrl, DEVICE_BODY))).toMatchObject({ ok: true })
  })

  test("platformPathSubject reads only the segment after /v1/platform/subjects/", () => {
    expect(platformPathSubject(`/v1/platform/subjects/${SUBJECT}`)).toBe(SUBJECT)
    expect(platformPathSubject(`/v1/platform/subjects/${SUBJECT}/approvals/apr_1/decide`)).toBe(SUBJECT)
    expect(platformPathSubject("/v1/platform/subjects")).toBeNull()
    expect(platformPathSubject("/v1/platform/subjects/")).toBeNull()
    expect(platformPathSubject("/v1/platform")).toBeNull()
    expect(platformPathSubject(`/v1/items/${SUBJECT}`)).toBeNull()
    expect(platformPathSubject("/v1/platform/subjects/a%2Fb/devices")).toBe("a%2Fb")
  })

  test("parseProof refuses a platform proof, and parsePlatformProof a device proof", async () => {
    expect(() => parseProof(GOLDEN.token)).toThrow("unsupported proof type")
    const device = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair
    const deviceToken = await createProof(webCryptoSigner("dev_laptop", device.privateKey), { method: "POST", url: DEVICES_URL, body: DEVICE_BODY }, { tenant: "tn_abcdefgh12", now: NOW })
    expect(() => parsePlatformProof(deviceToken)).toThrow("unsupported proof type")
    expect(PLATFORM_PROOF_HEADER).not.toBe(PROOF_HEADER)
  })

  test("parsePlatformProof refuses a device-shaped key id or claims, extra members and a bad platform", async () => {
    const sign = (header: object, claims: object) => signCompactJws(header, claims, (data) => platform.signer.sign(data), "platform")
    const header = { alg: "ES256", typ: PLATFORM_PROOF_TYPE, kid: "pky_globex0001" }
    const claims = { plt: "plt_globex0001", htm: "GET", htu: "https://vault.example.com/v1/platform", bh: await bodyHash(""), iat: NOW / 1000, jti: "jti_one" }
    expect(parsePlatformProof(await sign(header, claims)).claims).toEqual(claims)
    await expect(sign({ ...header, kid: "dev_laptop" }, claims).then(parsePlatformProof)).rejects.toThrow("proof key id is not a platform key")
    await expect(sign({ ...header, alg: "ES384" }, claims).then(parsePlatformProof)).rejects.toThrow("unsupported proof type")
    await expect(sign({ ...header, jwk: platform.jwk }, claims).then(parsePlatformProof)).rejects.toThrow("malformed proof header")
    for (const bad of [{ ...claims, ten: "tn_abcdefgh12" }, { ...claims, dev: "dev_laptop" }, { ...claims, plt: "tn_abcdefgh12" }, { ...claims, sub: "short" }, { ...claims, htm: "get" }, { ...claims, iat: 1.5 }]) {
      await expect(sign(header, bad).then(parsePlatformProof)).rejects.toThrow("malformed proof claims")
    }
    expect(() => parsePlatformProof("a.b")).toThrow("malformed proof")
    expect(() => parsePlatformProof("x".repeat(9000))).toThrow("proof too large")
  })

  test("a signer must give a 64-byte signature", async () => {
    const short = { platformId: "plt_globex0001", keyId: "pky_globex0001", sign: async () => new Uint8Array(70) }
    await expect(createPlatformProof(short, { method: "GET", url: "https://vault.example.com/v1/platform" })).rejects.toThrow("platform signer must return a 64-byte r||s signature")
  })
})

// ---------------------------------------------------------------- ids

describe("ids", () => {
  test("the subject hash and the subject member's account are SHA-256 of platform, newline, subject", async () => {
    const hash = createHash("sha256").update(`plt_globex0001\n${SUBJECT}`).digest("base64url")
    expect(await platformSubjectHash("plt_globex0001", SUBJECT)).toBe(hash)
    expect(await subjectMemberAccount("plt_globex0001", SUBJECT)).toBe(`sbj_${hash.slice(0, 32)}`)
    expect(await subjectMemberAccount("plt_other001", SUBJECT)).not.toBe(await subjectMemberAccount("plt_globex0001", SUBJECT))
  })
})

// ---------------------------------------------------------------- the error tables

test("the error tables are complete, with both platform codes refused by rule", () => {
  expect(ERROR_CODES).toContain("platform_suspended")
  expect(ERROR_CODES).toContain("quota_exceeded")
  expect(Object.keys(HTTP_STATUS_FOR_ERROR).sort()).toEqual([...ERROR_CODES].sort())
  expect(Object.keys(EXIT_FOR_ERROR).sort()).toEqual([...ERROR_CODES].sort())
  for (const code of ["platform_suspended", "quota_exceeded"] as const) {
    expect(HTTP_STATUS_FOR_ERROR[code]).toBe(403)
    expect(EXIT_FOR_ERROR[code]).toBe(EXIT.refused)
  }
})

// ---------------------------------------------------------------- devices and step-ups

test("a platform device relays and serves placeholders only, through workloads", () => {
  expect([...PLATFORM_DEVICE_MODES]).toEqual(["relay", "placeholder"])
  const scope = platformDeviceScope(PLATFORM_DEVICE_MODES)
  expect(WorkspaceDeviceScopeSchema.parse(scope)).toEqual({ tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "placeholder"], privateCredentials: false, workloads: "required" })
})

test("a platform satisfies only its own step-ups, and item.update only for a project", () => {
  const parse = (action: unknown) => WorkspaceStepUpActionSchema.parse(action)
  expect(platformMaySatisfy(parse({ type: "item.update", item: "prj_abc", digest: "d" }))).toBe(true)
  expect(platformMaySatisfy(parse({ type: "item.update", item: "itm_abc", digest: "d" }))).toBe(false)
  expect(platformMaySatisfy(parse({ type: "item.delete", item: "itm_abc" }))).toBe(true)
  expect(platformMaySatisfy(parse({ type: "workspace.unfreeze" }))).toBe(true)
  for (const refused of [
    { type: "item.rehome", item: "itm_a", before: { kind: "workspace" }, after: { kind: "workspace" }, dependencyRevision: 1 },
    { type: "device.rescope", device: "dev_a", thumbprint: "t", before: platformDeviceScope(["relay"]), after: platformDeviceScope(["relay"]) },
    { type: "member.remove", member: "mem_a" },
    { type: "passkey.add" },
    { type: "policy.decide", proposal: "pol_a", digest: "d", decision: "deny", effectDigest: null },
    { type: "adoption.approve", adoption: "adp_a", digest: "d", repoints: 0 },
    { type: "item.restore", item: "itm_a", digest: "d" },
  ]) {
    expect(platformMaySatisfy(parse(refused))).toBe(false)
  }
  expect(PLATFORM_STEP_UPS).toHaveLength(10)
})

// ---------------------------------------------------------------- defaults and the managed item policy

const RANK: Record<RuleAction, number> = { allow: 0, approve: 1, deny: 2 }

// Concrete paths a pattern matches: every "**" and "*" filled in.
function samplePaths(pattern: string): string[] {
  const fill = (p: string, star: string) => p.replaceAll("**", "\u0000").replaceAll("*", star).replaceAll("\u0000", `${star}/${star}`)
  return [fill(pattern, "x"), fill(pattern, "abc123")].map((p) => (p.startsWith("/") ? p : `/${p}`))
}

function sampleHost(policyHosts: string[]): string {
  const host = policyHosts.find((h) => !h.includes("*")) ?? policyHosts[0] ?? "api.example.com"
  return host.replace(/^\*\./, "a.")
}

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
const BODIES = [null, utf8('{"query":"mutation { x }"}'), utf8('{"query":"query { x }"}')]

type Probe = { method: string; path: string; body: Uint8Array | null }

function probesFor(policy: PolicyInput, extra: PlatformPolicyRule[]): Probe[] {
  const paths = new Set<string>(["/", "/x", "/v1/x"])
  for (const rule of [...policy.rules, ...extra]) for (const p of rule.paths ?? []) for (const s of samplePaths(p)) paths.add(s)
  const probes: Probe[] = []
  for (const path of paths) for (const method of METHODS) for (const body of BODIES) probes.push({ method, path, body })
  return probes
}

// A deterministic generator, so a failure always replays.
function rng(seed: number) {
  let state = seed >>> 0
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0
    return state / 2 ** 32
  }
}

function platformRulesFor(policy: PolicyInput, seed: number): PlatformPolicyRule[] {
  const next = rng(seed)
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)] as T
  const patterns = [...new Set([...policy.rules.flatMap((r) => r.paths ?? []), "/**", "/x", "/v1/**"])]
  const rules: PlatformPolicyRule[] = []
  for (let i = 0; i < 6; i++) {
    const action = next() < 0.5 ? "approve" : "deny"
    rules.push({
      action,
      ...(next() < 0.6 ? { methods: [pick(METHODS)] } : {}),
      ...(next() < 0.8 ? { paths: [pick(patterns)] } : {}),
      ...(next() < 0.2 ? { body: "graphql-mutation" as const } : {}),
    })
  }
  return rules
}

function actionAt(policy: PolicyInput, host: string, probe: Probe): RuleAction {
  const parsed = parseDestination(probe.method, `https://${host}${probe.path}`)
  if (!parsed.ok) throw new Error(`bad probe ${probe.path}`)
  return evaluatePolicy(policy, parsed.destination, probe.body).action
}

describe("managedItemPolicy", () => {
  const catalogue: { id: string; policy: PolicyInput; hosts: string[] }[] = [
    ...Object.values(TEMPLATES).map((t) => ({ id: t.id, policy: t.policy, hosts: t.binding.hosts })),
    ...Object.values(OAUTH_PROVIDERS).map((p) => ({ id: p.id, policy: connectionPolicy(p), hosts: p.upstream.binding.hosts })),
  ]

  test("templates and providers share no id, so one record of rules can name both", () => {
    const templates = new Set(Object.keys(TEMPLATES))
    expect(Object.keys(OAUTH_PROVIDERS).filter((id) => templates.has(id))).toEqual([])
  })

  test("with no rules it is the catalogue's policy exactly", () => {
    for (const entry of catalogue) expect(managedItemPolicy(entry.id, INITIAL_PLATFORM_DEFAULTS)).toEqual(entry.policy)
  })

  test("never allows what the catalogue's policy holds or refuses, for every template and provider", () => {
    let probes = 0
    for (const [index, entry] of catalogue.entries()) {
      const host = sampleHost(entry.hosts)
      for (const seed of [1, 2, 3, 4, 5].map((n) => n * 7919 + index)) {
        const added = platformRulesFor(entry.policy, seed)
        // Rules for another id must change nothing here.
        const defaults: PlatformDefaults = PlatformDefaultsSchema.parse({ ...INITIAL_PLATFORM_DEFAULTS, rules: { [entry.id]: added, ...(entry.id === "openai" ? {} : { openai: [{ action: "deny" }] }) } })
        const managed = managedItemPolicy(entry.id, defaults)
        expect(managed.default).toBe(entry.policy.default)
        for (const probe of probesFor(entry.policy, added)) {
          const before = actionAt(entry.policy, host, probe)
          const after = actionAt(managed, host, probe)
          probes++
          if (RANK[after] < RANK[before]) throw new Error(`${entry.id}: ${probe.method} ${probe.path} was ${before}, became ${after}`)
        }
      }
    }
    expect(probes).toBeGreaterThan(10_000)
    // Exhaustive by design (every catalogue entry, five rule sets, every
    // probe): about 3 s locally and 7 s on a CI runner, past the 5 s default.
  }, 30_000)

  test("an allow rule that skipped the schema is dropped", () => {
    const smuggled = { ...INITIAL_PLATFORM_DEFAULTS, rules: { "github-oauth": [{ action: "allow", methods: ["POST", "PUT", "PATCH", "DELETE"] }] } } as unknown as PlatformDefaults
    expect(managedItemPolicy("github-oauth", smuggled)).toEqual(connectionPolicy(OAUTH_PROVIDERS["github-oauth"]!))
    const host = "api.github.com"
    expect(actionAt(managedItemPolicy("github-oauth", smuggled), host, { method: "POST", path: "/repos/a/b/issues", body: null })).toBe("approve")
  })

  test("a deny rule refuses, and an approve rule holds, what the catalogue allows", () => {
    const openai = TEMPLATES.openai!
    const host = sampleHost(openai.binding.hosts)
    const probe = { method: "GET", path: "/v1/models", body: null }
    expect(actionAt(openai.policy, host, probe)).toBe("allow")
    const deny = PlatformDefaultsSchema.parse({ ...INITIAL_PLATFORM_DEFAULTS, rules: { openai: [{ action: "deny", methods: ["GET"], paths: ["/v1/models"] }] } })
    const approve = PlatformDefaultsSchema.parse({ ...INITIAL_PLATFORM_DEFAULTS, rules: { openai: [{ action: "approve", methods: ["GET"] }] } })
    expect(actionAt(managedItemPolicy("openai", deny), host, probe)).toBe("deny")
    expect(actionAt(managedItemPolicy("openai", approve), host, probe)).toBe("approve")
  })

  test("a key with no template uses the custom policy with the platform's customReads", () => {
    expect(managedItemPolicy(null, INITIAL_PLATFORM_DEFAULTS)).toEqual(customItemPolicy(false))
    expect(managedItemPolicy(null, { ...INITIAL_PLATFORM_DEFAULTS, customReads: "allow" })).toEqual(customItemPolicy(true))
  })

  test("an item whose template left the catalogue holds everything", () => {
    expect(managedItemPolicy("retired-template", { ...INITIAL_PLATFORM_DEFAULTS, customReads: "allow" })).toEqual(customItemPolicy(false))
  })
})

describe("PlatformDefaults", () => {
  const good: PlatformDefaults = {
    templates: ["openai", "anthropic"],
    providers: ["google-gmail", "github-oauth"],
    scopes: { "google-gmail": ["gmail.readonly", "https://www.googleapis.com/auth/gmail.send"], "github-oauth": ["repo"] },
    tags: ["globex"],
    customReads: "approve",
    rules: { openai: [{ action: "deny", methods: ["DELETE"] }], "google-gmail": [{ action: "approve", methods: ["POST"], paths: ["/gmail/v1/users/*/drafts"] }] },
  }

  test("accepts narrowing defaults, and the initial ones", () => {
    expect(PlatformDefaultsSchema.parse(good)).toEqual(good)
    expect(PlatformDefaultsSchema.parse(INITIAL_PLATFORM_DEFAULTS)).toEqual(INITIAL_PLATFORM_DEFAULTS)
  })

  test("refuses an allow rule", () => {
    const result = PlatformDefaultsSchema.safeParse({ ...good, rules: { openai: [{ action: "allow", methods: ["POST"] }] } })
    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toBe("A platform rule may only hold (approve) or refuse (deny).")
  })

  test("refuses an id or scope the catalogue lacks, a bad tag and any extra member", () => {
    for (const bad of [
      { ...good, templates: ["no-such-template"] },
      { ...good, providers: ["openai"] },
      { ...good, scopes: { openai: ["x"] } },
      { ...good, scopes: { "google-gmail": ["drive"] } },
      { ...good, rules: { "no-such": [{ action: "deny" }] } },
      { ...good, tags: ["Globex"] },
      { ...good, tags: ["globex", "globex"] },
      { ...good, customReads: "yes" },
      { ...good, rules: { openai: [{ action: "deny", body: "graphql-query" }] } },
      { ...good, extra: true },
      { templates: good.templates },
    ]) {
      expect(PlatformDefaultsSchema.safeParse(bad).success).toBe(false)
    }
  })
})

test("the default limits are within their own schema, and a decision lasts 15 minutes at most", () => {
  expect(PlatformLimitsSchema.parse(DEFAULT_PLATFORM_LIMITS)).toEqual(DEFAULT_PLATFORM_LIMITS)
  expect(DEFAULT_PLATFORM_LIMITS).toMatchObject({ subjects: 1_000, devicesPerSubject: 16, itemsPerSubject: 100, projectsPerSubject: 16, openRequestsPerSubject: 10, callsPerMinute: 600, subjectWritesPerMinute: 60, decisionsPerMinute: 30, subjectDecisionsPerMinute: 10, decisionTtlSeconds: 900, auditRetentionDays: 30 })
  expect(PlatformLimitsSchema.safeParse({ ...DEFAULT_PLATFORM_LIMITS, decisionTtlSeconds: 901 }).success).toBe(false)
  expect(PlatformLimitsSchema.safeParse({ ...DEFAULT_PLATFORM_LIMITS, auditRetentionDays: 91 }).success).toBe(false)
  expect(PlatformLimitsSchema.safeParse({ ...DEFAULT_PLATFORM_LIMITS, other: 1 }).success).toBe(false)
})

// ---------------------------------------------------------------- the route table and every schema

const ISO = "2026-10-29T12:00:00.000Z"
const box = await (async () => seal((await generateSealKeyPair()).publicKey, "sk-secret", "intake/int_abc/key"))()
const item = { slug: "openai-key", kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: ["globex"], ceiling: "placeholder", hosts: ["api.openai.com"], status: "active", updatedAt: ISO, lastUsedAt: null }
const CALLBACK = "https://app.globex.ai/oauth/callback"
const customProvider = {
  name: "Yahoo Mail",
  authorizeUrl: "https://api.login.yahoo.com/oauth2/request_auth",
  tokenUrl: "https://api.login.yahoo.com/oauth2/get_token",
  scopes: ["mail-r"],
  pkce: "S256",
  clientAuth: "client_secret_basic",
  hosts: ["api.mail.yahoo.com"],
}
const subjectView = { subject: SUBJECT, status: "active", createdAt: ISO, counts: { devices: 1, items: 2, projects: 1 } }
const deviceView = { device: "dev_agent1", tenant: "tn_abcdefgh12", name: "agent 1", label: "agent:ag_1", scope: platformDeviceScope(["relay", "placeholder"]), createdAt: ISO, revoked: false }
const digest = "Ju8tFDqHrIOw3-qVuICCzAMPcbV8YYhfE7DpK-MUrk8"
const approvalView = {
  approval: "apr_abc", status: "pending", digest, device: "dev_agent1", workload: { id: "wl_grant0001", label: "grant:g1" }, item: "github",
  request: { method: "POST", url: "https://api.github.com/repos/a/b/issues", contentType: "application/json", contentEncoding: null, headersSha256: digest, bodySha256: digest },
  title: "Open an issue", warnings: [], constraints: { uses: 1, ttlSeconds: 900 }, expiresAt: ISO, decidedBy: null,
}
const projectView = { id: "prj_abc", slug: "computers", defaultEnv: "computers", environments: [{ name: "computers" }], vars: [{ name: "REGION", env: "computers", source: "plain", value: "eu-west-1" }, { name: "OPENAI_API_KEY", env: "computers", source: "item", item: "openai-key", field: "key" }] }

type Cases = { ok: unknown[]; bad: unknown[] }
type RouteCases = { query?: Cases; body?: Cases; answer: Cases }

const CASES: Record<PlatformRouteName, RouteCases> = {
  "platform.view": {
    answer: {
      ok: [{ platform: { id: "plt_globex0001", slug: "globex", name: "Globex", status: "active" }, limits: DEFAULT_PLATFORM_LIMITS, defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 1, usage: { subjects: 3 }, keys: [{ id: "pky_globex0001", createdAt: ISO, expiresAt: null, revoked: false }] }],
      bad: [{ platform: { id: "plt_globex0001", slug: "globex", name: "Globex", status: "paused" }, limits: DEFAULT_PLATFORM_LIMITS, defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 1, usage: { subjects: 3 }, keys: [] }],
    },
  },
  "subjects.list": {
    query: { ok: [{}, { cursor: "abc" }], bad: [{ cursor: "" }, { limit: 5 }] },
    answer: { ok: [{ subjects: [{ subject: SUBJECT, status: "active", createdAt: ISO }], next: null }, { subjects: [], next: "abc" }], bad: [{ subjects: [{ subject: "short", status: "active", createdAt: ISO }], next: null }, { subjects: [{ subject: SUBJECT, status: "purged", createdAt: ISO }], next: null }] },
  },
  "subjects.ensure": { body: { ok: [{}], bad: [{ subject: SUBJECT }, null] }, answer: { ok: [subjectView], bad: [{ ...subjectView, counts: { devices: -1, items: 0, projects: 0 } }] } },
  "subjects.get": { answer: { ok: [subjectView, { ...subjectView, status: "deleted" }], bad: [{ ...subjectView, createdAt: "yesterday" }] } },
  "subjects.remove": { body: { ok: [{}], bad: [{ now: true }] }, answer: { ok: [{ subject: SUBJECT, status: "deleted", purgeAfter: ISO }], bad: [{ subject: SUBJECT, status: "deleting", purgeAfter: ISO }] } },
  "devices.create": {
    body: {
      ok: [{ name: "agent 1", jwk: platform.jwk, modes: ["relay", "placeholder"], label: "agent:ag_1" }, { name: "agent 2", jwk: platform.jwk, modes: ["relay"] }],
      bad: [
        { name: "agent", jwk: platform.jwk, modes: ["lease"] },
        { name: "agent", jwk: platform.jwk, modes: ["reveal"] },
        { name: "agent", jwk: platform.jwk, modes: [] },
        { name: "agent", jwk: platform.jwk, modes: ["relay", "relay"] },
        { name: "agent", jwk: { ...platform.jwk, d: "private" }, modes: ["relay"] },
        { name: "", jwk: platform.jwk, modes: ["relay"] },
        { name: "agent", jwk: platform.jwk, modes: ["relay"], label: "two words" },
        { name: "agent", jwk: platform.jwk, modes: ["relay"], scope: { modes: ["lease"] } },
      ],
    },
    answer: { ok: [deviceView, { ...deviceView, label: null }], bad: [{ ...deviceView, tenant: "ten_x" }, { ...deviceView, scope: { ...deviceView.scope, modes: ["reveal"] } }] },
  },
  "devices.list": { answer: { ok: [{ devices: [{ ...deviceView, lastSeenAt: null, liveWorkloads: 2 }] }], bad: [{ devices: [deviceView] }] } },
  "devices.revoke": { answer: { ok: [{ ...deviceView, revoked: true }], bad: [{ ...deviceView, device: "wl_agent0001" }] } },
  "items.list": {
    query: { ok: [{}, { kind: "api-key", tag: "globex" }], bad: [{ kind: "spaceship" }, { tag: "Globex" }, { provider: "openai" }] },
    answer: { ok: [{ items: [item] }], bad: [{ items: [{ ...item, slug: undefined }] }, { items: [{ ...item, status: "lost" }] }] },
  },
  "items.remove": { answer: { ok: [{ slug: "openai-key", deleted: true, providerRevoked: false }], bad: [{ slug: "openai-key", deleted: false, providerRevoked: false }] } },
  "intakes.create": {
    body: {
      ok: [
        { slug: "openai-key", service: { template: "openai" }, tags: ["globex"], reason: "For your agent's model calls." },
        { slug: "acme-key", service: { host: "api.acme.example" } },
        { slug: "google-oauth-client", service: { template: "google-oauth-client" } },
        { slug: "yahoo-client", service: { customProvider } },
      ],
      bad: [
        { slug: "openai-key", service: { template: "no-such-template" } },
        { slug: "yahoo-client", service: { customProvider: { ...customProvider, tokenUrl: "https://10.0.0.1/token" } } },
        { slug: "yahoo-client", service: { customProvider, template: "google-oauth-client" } },
        { slug: "acme-key", service: { host: "API.acme.example" } },
        { slug: "acme-key", service: { host: "https://api.acme.example" } },
        { slug: "acme-key", service: { template: "openai", host: "api.openai.com" } },
        { slug: "Bad Slug", service: { template: "openai" } },
        { slug: "openai-key", service: { template: "openai" }, binding: { hosts: ["evil.example"] } },
        { slug: "openai-key", service: { template: "openai" }, tags: ["Globex"] },
      ],
    },
    answer: {
      ok: [{ intake: "int_abc", sealKey: { jwk: { kty: "EC", crv: "P-256", x: platform.jwk.x, y: platform.jwk.y }, kid: "seal1" }, fields: [{ name: "key", label: "Key", secret: true, required: true, multiline: false, hint: null }], binding: { hosts: ["api.openai.com"], known: true }, rotates: false, setup: null, expiresAt: ISO },
        { intake: "int_def", sealKey: { jwk: { kty: "EC", crv: "P-256", x: platform.jwk.x, y: platform.jwk.y }, kid: "seal1" }, fields: [{ name: "client_id", label: "Client ID", secret: false, required: true, multiline: false, hint: null }, { name: "client_secret", label: "Client secret", secret: true, required: true, multiline: false, hint: null }], binding: { hosts: ["oauth2.googleapis.com"], known: true }, rotates: false, setup: TEMPLATES["google-oauth-client"]!.clientSetup, expiresAt: ISO }],
      bad: [{ intake: "itm_abc", sealKey: { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, kid: "seal1" }, fields: [], binding: { hosts: [], known: false }, rotates: false, setup: null, expiresAt: ISO }, { intake: "int_abc", sealKey: { jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, kid: "seal1" }, fields: [], binding: { hosts: [], known: false }, rotates: false, expiresAt: ISO }],
    },
  },
  "intakes.submit": {
    body: {
      ok: [
        { sealed: { key: box } },
        { sealed: { key: box }, publicFields: { account: "me@example.com" } },
        { sealed: { key: box }, terms: { binding: { hosts: ["api.example.com"] }, injection: { in: "header", name: "X-Api-Key", format: "{key}" } } },
        { sealed: { key: box }, terms: { binding: { hosts: ["oauth2.example.com"], paths: ["/token"] }, injection: null } },
      ],
      bad: [
        { sealed: {} },
        { sealed: { key: "sk-plain" } },
        { sealed: { key: box }, slug: "elsewhere" },
        { sealed: { key: { ...box, v: 2 } } },
        { sealed: { Key: box } },
        { sealed: { key: box }, terms: { binding: { hosts: ["api.example.com"] } } },
        { sealed: { key: box }, terms: { binding: { hosts: [] }, injection: null } },
        { sealed: { key: box }, terms: { binding: { hosts: ["api.example.com"] }, injection: null, tags: [] } },
      ],
    },
    answer: { ok: [{ item }], bad: [{}] },
  },
  "intakes.cancel": { body: { ok: [{}], bad: [{ reason: "x" }] }, answer: { ok: [{}], bad: [null] } },
  "connects.start": {
    body: {
      ok: [
        { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK, scopes: ["gmail.readonly"], expect: "me@example.com", tags: ["globex"] },
        { provider: "google-gmail", client: "my-google-app", slug: "gmail", redirectUri: CALLBACK },
        { client: "yahoo-client", slug: "yahoo-mail", redirectUri: CALLBACK, scopes: ["mail-r"] },
      ],
      bad: [
        { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK, scopes: ["drive"] },
        { provider: "openai", slug: "openai", redirectUri: CALLBACK },
        { slug: "gmail", redirectUri: CALLBACK },
        { provider: "google-gmail", slug: "gmail" },
        { provider: "google-gmail", slug: "gmail", redirectUri: "http://app.globex.ai/oauth/callback" },
        { provider: "google-gmail", slug: "gmail", redirectUri: "https://localhost/oauth/callback" },
        { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK, scopes: [] },
        { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK, definition: customProvider },
      ],
    },
    answer: { ok: [{ connect: "con_abc", authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth?state=s", expiresAt: ISO }], bad: [{ connect: "con_abc", authorizeUrl: "http://accounts.google.com/", expiresAt: ISO }, { connect: "con_abc", url: "https://vault.example.com/c/con_abc", expiresAt: ISO }] },
  },
  "connects.finish": {
    body: { ok: [{ state: "s".repeat(32), code: "4/0Abc" }, { state: "s".repeat(32), error: "access_denied" }], bad: [{ state: "s".repeat(32), code: "c", error: "e" }, { state: "s".repeat(32) }, { state: "short", code: "c" }, { state: "s".repeat(32), code: "c", subject: SUBJECT }] },
    answer: { ok: [{ connect: "con_abc", status: "completed", item }, { connect: "con_abc", status: "failed", reason: "wider" }], bad: [{ connect: "con_abc", status: "failed", reason: "bored" }, { connect: "con_abc", status: "completed" }] },
  },
  "connects.get": { answer: { ok: [{ connect: "con_abc", status: "open", expiresAt: ISO }, { connect: "con_abc", status: "completed", item, account: "me@example.com", expiresAt: ISO }], bad: [{ connect: "con_abc", status: "done", expiresAt: ISO }] } },
  "connects.cancel": { body: { ok: [{}], bad: [{ force: true }] }, answer: { ok: [{}], bad: ["cancelled"] } },
  "approvals.list": { query: { ok: [{}, { status: "pending" }], bad: [{ status: "waiting" }] }, answer: { ok: [{ approvals: [approvalView] }], bad: [{ approvals: [{ ...approvalView, constraints: { uses: 0, ttlSeconds: 900 } }] }] } },
  "approvals.get": {
    answer: {
      ok: [approvalView, { ...approvalView, status: "approved", workload: null, decidedBy: { platform: "plt_globex0001", key: "pky_globex0001", ref: "card:123" } }],
      bad: [{ ...approvalView, decidedBy: { platform: "plt_globex0001", ref: null } }, { ...approvalView, approval: "itm_abc" }],
    },
  },
  "approvals.decide": {
    body: {
      ok: [{ decision: "approve", digest, ttlSeconds: 900, ref: "card:123" }, { decision: "deny", digest }],
      bad: [{ decision: "approve", digest, ttlSeconds: 901 }, { decision: "approve", digest, ttlSeconds: 59 }, { decision: "approve", digest, uses: 2 }, { decision: "approve", digest, ref: "two words" }, { decision: "approve", digest: "short" }, { decision: "maybe", digest }, { decision: "approve", digest, remember: { kind: "exact" } }],
    },
    answer: { ok: [{ ...approvalView, status: "approved" }], bad: [{ ...approvalView, status: "thinking" }] },
  },
  "projects.create": {
    body: {
      ok: [{ slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers" }],
      bad: [
        { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "prod" },
        { slug: "computers", environments: [{ name: "computers", protected: true }], defaultEnv: "computers" },
        { slug: "computers", environments: [{ name: "computers" }, { name: "computers" }], defaultEnv: "computers" },
        { slug: "computers", environments: [{ name: "computers" }], defaultEnv: "computers", remote: "github.com/a/b" },
        { slug: "computers", environments: [], defaultEnv: "computers" },
      ],
    },
    answer: { ok: [projectView], bad: [{ ...projectView, id: "proj_abc" }] },
  },
  "projects.get": { answer: { ok: [projectView], bad: [{ ...projectView, vars: [{ name: "1BAD", env: "computers", source: "plain" }] }] } },
  "projects.setVar": {
    body: {
      ok: [{ env: "computers", before: null, plain: "eu-west-1" }, { env: "computers", before: { plain: "eu-west-1" }, item: "openai-key", field: "key" }, { env: "computers", before: { item: "openai-key", field: null } }],
      bad: [{ env: "computers", before: null, plain: "a", item: "openai-key" }, { env: "computers", before: null, field: "key" }, { env: "computers", plain: "a" }, { env: "computers", before: { plain: "a", item: "b" }, plain: "c" }, { env: "Computers", before: null, plain: "a" }],
    },
    answer: { ok: [projectView], bad: [{ ...projectView, environments: [{ name: "Prod" }] }] },
  },
  "projects.remove": { body: { ok: [{}], bad: [{ cascade: true }] }, answer: { ok: [{ deleted: true }], bad: [{ deleted: false }] } },
  "audit.read": {
    query: { ok: [{}, { cursor: "5", limit: "50" }], bad: [{ cursor: "0" }, { limit: "500" }, { before: "5" }] },
    answer: { ok: [{ events: [{ seq: 1, at: NOW, actor: "platform:plt_globex0001", action: "workspace.create", target: null, detail: "{}", prev: "p", hash: "h" }], verified: true, next: null, filtered: false, head: { seq: 1, hash: "h" } }], bad: [{ events: [], verified: true, next: "0", filtered: false, head: null }] },
  },
  "workspace.freeze": { body: { ok: [{}], bad: [{ reason: "x" }] }, answer: { ok: [{ frozen: true }], bad: [{ frozen: false }] } },
  "workspace.unfreeze": { body: { ok: [{}], bad: [{ stepUp: {} }] }, answer: { ok: [{ frozen: false }], bad: [{ frozen: true }] } },
  "defaults.put": {
    body: { ok: [INITIAL_PLATFORM_DEFAULTS, { ...INITIAL_PLATFORM_DEFAULTS, providers: ["google-gmail"], tags: ["globex"] }], bad: [{ ...INITIAL_PLATFORM_DEFAULTS, rules: { openai: [{ action: "allow" }] } }, { ...INITIAL_PLATFORM_DEFAULTS, providers: ["nope"] }] },
    answer: { ok: [{ defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 2 }], bad: [{ defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 0 }] },
  },
  "subjects.removeAll": { body: { ok: [{ confirm: "globex" }], bad: [{ confirm: "Globex" }, {}, { confirm: "globex", subjects: [SUBJECT] }] }, answer: { ok: [{ deleting: 3 }], bad: [{ deleting: -1 }] } },
}

describe("PLATFORM_ROUTES", () => {
  // D0's numbers, kept stable; 2 and 3 (the platform's own OAuth clients)
  // are not built (D0 addendum on OAuth).
  test("D0's route numbers once each, without 2 and 3, unique names and unique method and path", () => {
    const numbers = Array.from({ length: 31 }, (_, i) => i + 1).filter((n) => n !== 2 && n !== 3)
    expect(PLATFORM_ROUTES.map((r): number => r.number).sort((a, b) => a - b)).toEqual(numbers)
    expect(new Set(PLATFORM_ROUTES.map((r) => r.name)).size).toBe(numbers.length)
    expect(new Set(PLATFORM_ROUTES.map((r) => `${r.method} ${r.path}`)).size).toBe(numbers.length)
    expect(PLATFORM_ROUTES.some((r) => r.path.includes("oauth-clients"))).toBe(false)
  })

  test("every route has prose: whole sentences with no dashes", () => {
    for (const route of PLATFORM_ROUTES) {
      expect(route.prose.length).toBeGreaterThan(20)
      expect(route.prose).toMatch(/^[A-Z].*\.$/)
      expect(route.prose).not.toMatch(/[\u2013\u2014]/)
    }
  })

  test("every path is under /v1/platform with a schema for each of its parameters, and a subject's routes name it", () => {
    for (const route of PLATFORM_ROUTES) {
      expect(route.path.startsWith("/v1/platform")).toBe(true)
      const params = [...route.path.matchAll(/:([a-z]+)/g)].map((m) => m[1])
      expect(Object.keys(route.params).sort()).toEqual(params.sort() as string[])
      expect(route.path.startsWith("/v1/platform/subjects/:subject")).toBe(params.includes("subject"))
      const sample = route.path.replace(":subject", SUBJECT)
      expect(platformPathSubject(sample)).toBe(params.includes("subject") ? SUBJECT : null)
    }
  })

  test("a GET has no body, and every refusal is an error code beyond the common ones", () => {
    for (const route of PLATFORM_ROUTES) {
      if (route.method === "GET") expect(route.body).toBeNull()
      for (const code of route.refusals) {
        expect(ERROR_CODES).toContain(code)
        expect(PLATFORM_COMMON_REFUSALS as readonly string[]).not.toContain(code)
      }
      expect(route.status.length).toBeGreaterThan(0)
    }
    expect(platformRoute("subjects.ensure").status).toEqual([200, 201])
    expect(platformRoute("projects.create").status).toEqual([200, 201])
    expect(platformRoute("approvals.decide").path).toBe("/v1/platform/subjects/:subject/approvals/:approval/decide")
  })

  test("route parameters accept the ids the vault mints and refuse others", () => {
    const params = (name: PlatformRouteName) => platformRoute(name).params as Record<string, z.ZodType<string>>
    expect(params("subjects.get").subject!.safeParse(SUBJECT).success).toBe(true)
    expect(params("subjects.get").subject!.safeParse("short").success).toBe(false)
    expect(params("subjects.get").subject!.safeParse("a/b/c/d/e/f").success).toBe(false)
    expect(params("devices.revoke").device!.safeParse("dev_agent1").success).toBe(true)
    expect(params("devices.revoke").device!.safeParse("wl_agent0001").success).toBe(false)
    expect(params("projects.setVar").name!.safeParse("OPENAI_API_KEY").success).toBe(true)
    expect(params("projects.setVar").name!.safeParse("1BAD").success).toBe(false)
    expect(params("approvals.decide").approval!.safeParse("apr_abc").success).toBe(true)
    expect(params("approvals.decide").approval!.safeParse("int_abc").success).toBe(false)
  })

  for (const route of PLATFORM_ROUTES) {
    test(`${route.number} ${route.name}: every schema's accept and refuse cases`, () => {
      const cases = CASES[route.name]
      const check = (schema: z.ZodType | null, given: Cases | undefined, part: string) => {
        if (schema === null) {
          expect(given, `${route.name} has no ${part}`).toBeUndefined()
          return
        }
        if (given === undefined) throw new Error(`${route.name}: no ${part} cases`)
        expect(given.ok.length).toBeGreaterThan(0)
        expect(given.bad.length).toBeGreaterThan(0)
        for (const value of given.ok) {
          const result = schema.safeParse(value)
          if (!result.success) throw new Error(`${route.name} ${part} refused ${JSON.stringify(value)}: ${result.error.message}`)
        }
        for (const value of given.bad) {
          if (schema.safeParse(value).success) throw new Error(`${route.name} ${part} accepted ${JSON.stringify(value)}`)
        }
      }
      check(route.query, cases.query, "query")
      check(route.body, cases.body, "body")
      check(route.answer, cases.answer, "answer")
    })
  }

  test("no answer's shape has a link: a url member is dropped or refused", () => {
    for (const route of PLATFORM_ROUTES) {
      for (const value of CASES[route.name].answer.ok) {
        if (typeof value !== "object" || value === null) continue
        const result = route.answer.safeParse({ ...value, url: "https://vault.example.com/i/int_abc" })
        if (result.success) expect((result.data as Record<string, unknown>).url).toBeUndefined()
      }
    }
  })
})

test("a real sealed box fits SealedBoxSchema", () => {
  expect(SealedBoxSchema.parse(box)).toEqual(box)
  expect(SealedBoxSchema.safeParse({ ...box, iv: "short" }).success).toBe(false)
})
