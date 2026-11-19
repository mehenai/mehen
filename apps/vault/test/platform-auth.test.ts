// The platform proof as the Worker checks it (src/platform/auth.ts), and
// its nonce as the PlatformVault spends it.

import { runInDurableObject } from "cloudflare:test"
import { afterEach, describe, expect, it, vi } from "vitest"
import { DEFAULT_PLATFORM_LIMITS, PROOF_HEADER, createProof, createPlatformProof, webCryptoSigner } from "@mehen/protocol"
import type { PlatformAdmission, PlatformVault } from "../src/platform/platform-vault.ts"
import { ORIGIN } from "./helpers.ts"
import { addPlatformKey, answerOf, fetchPlatformRequest, newPlatformKey, platformEnv, platformFetch, registerPlatform, signedRequest } from "./platform-fixtures.ts"

const VIEW = { method: "GET", path: "/v1/platform" }

afterEach(() => {
  vi.useRealTimers()
})

describe("the platform proof", () => {
  it("lets a signed call through and refuses one with no proof", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    expect((await platformFetch(env, platform, VIEW)).status).toBe(200)
    const missing = await answerOf(await platformFetch(env, platform, { ...VIEW, proof: null }))
    expect(missing).toEqual({ status: 401, body: { error: "unauthenticated", message: "Missing Mehen-Platform-Proof. Sign every platform call with the platform's key." } })
  })

  it("refuses a request carrying both proof headers, and each kind of proof in the other's place", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const both = await answerOf(await platformFetch(env, platform, { ...VIEW, headers: { [PROOF_HEADER]: "x.y.z" } }))
    expect(both).toEqual({ status: 400, body: { error: "bad_request", message: "Send either Mehen-Proof or Mehen-Platform-Proof, never both." } })
    // A device proof in the platform header does not parse as a platform proof.
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const deviceProof = await createProof(webCryptoSigner("dev_test", pair.privateKey), { method: "GET", url: `${ORIGIN}/v1/platform` }, { tenant: "tn_Alpha123456" })
    expect((await answerOf(await platformFetch(env, platform, { ...VIEW, proof: deviceProof }))).body).toEqual({ error: "proof_invalid", message: "The Mehen-Platform-Proof header is malformed." })
    // A platform proof in the device header is refused by the device route.
    const platformProof = await createPlatformProof(platform.signer, { method: "GET", url: `${ORIGIN}/v1/me` })
    const me = await answerOf(await fetchPlatformRequest(env, new Request(`${ORIGIN}/v1/me`, { headers: { [PROOF_HEADER]: platformProof } })))
    expect(me.body.error).toBe("proof_invalid")
  })

  it("refuses an unknown key, a key of another platform, a revoked key and a rotated-out key past its overlap, telling a key's state only to a proof its private key signed", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const other = await registerPlatform(env)
    const unknown = await answerOf(await platformFetch(env, platform, { ...VIEW, signer: { ...platform.signer, keyId: "pky_unknownkey" } }))
    expect(unknown).toEqual({ status: 401, body: { error: "unauthenticated", message: "This platform key is not known to the vault." } })
    // Another platform's key id, signing a proof that names this platform.
    const crossed = await answerOf(await platformFetch(env, platform, { ...VIEW, signer: { ...platform.signer, keyId: other.key } }))
    expect(crossed).toEqual(unknown)
    const revoked = await addPlatformKey(env, platform.id, { revokedAt: Date.now() - 1 })
    expect(await answerOf(await platformFetch(env, platform, { ...VIEW, signer: revoked.signer }))).toEqual({ status: 401, body: { error: "unauthenticated", message: "This platform key has been revoked." } })
    const rotatedOut = await addPlatformKey(env, platform.id, { expiresAt: Date.now() - 1 })
    expect(await answerOf(await platformFetch(env, platform, { ...VIEW, signer: rotatedOut.signer }))).toEqual({ status: 401, body: { error: "unauthenticated", message: "This platform key was rotated out and has expired." } })
    // Without the private key, a revoked or rotated-out key answers as any
    // key whose signature does not verify.
    for (const key of [revoked, rotatedOut]) {
      const forged = await answerOf(await platformFetch(env, platform, { ...VIEW, signer: { ...platform.signer, keyId: key.key } }))
      expect(forged).toEqual({ status: 401, body: { error: "proof_invalid", message: "The Mehen-Platform-Proof signature does not verify with this platform key." } })
    }
    const overlapping = await addPlatformKey(env, platform.id, { expiresAt: Date.now() + 3_600_000 })
    expect((await platformFetch(env, platform, { ...VIEW, signer: overlapping.signer })).status).toBe(200)
  })

  it("refuses a proof outside the 60-second skew, for another URL, method, body or subject", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const old = await answerOf(await platformFetch(env, platform, { ...VIEW, now: Date.now() - 61_000 }))
    expect(old.body).toEqual({ error: "proof_invalid", message: "The Mehen-Platform-Proof is more than 60 seconds old. Check the server's clock and retry." })
    // Well past the skew: on a loaded runner the vault's own clock reads
    // seconds later than the signer's, which brings a 61-second proof inside.
    const future = await answerOf(await platformFetch(env, platform, { ...VIEW, now: Date.now() + 120_000 }))
    expect(future.body.message).toBe("The Mehen-Platform-Proof is dated more than 60 seconds in the future. Check the server's clock and retry.")
    const proof = await createPlatformProof(platform.signer, { method: "GET", url: `${ORIGIN}/v1/platform/subjects` })
    expect((await answerOf(await platformFetch(env, platform, { ...VIEW, proof }))).body.message).toBe("The Mehen-Platform-Proof was signed for a different URL than this request.")
    const put = await createPlatformProof(platform.signer, { method: "PUT", url: `${ORIGIN}/v1/platform` })
    expect((await answerOf(await platformFetch(env, platform, { ...VIEW, proof: put }))).body.message).toBe("The Mehen-Platform-Proof was signed for a different HTTP method than this request.")
    const tampered = await answerOf(await platformFetch(env, platform, { method: "DELETE", path: "/v1/platform/subjects", body: { confirm: platform.slug }, sendBody: JSON.stringify({ confirm: "other-slug" }) }))
    expect(tampered.body.message).toBe("The Mehen-Platform-Proof was signed over a different body than this request sent.")
    // A proof whose claims name one subject, sent to another subject's path.
    const signedFor = await createPlatformProof(platform.signer, { method: "GET", url: `${ORIGIN}/v1/platform/subjects/subject-aaaa` })
    const elsewhere = await answerOf(await fetchPlatformRequest(env, new Request(`${ORIGIN}/v1/platform/subjects/subject-bbbb`, { headers: { "Mehen-Platform-Proof": signedFor } })))
    expect(elsewhere.body.error).toBe("proof_invalid")
  })

  it("spends each proof once, in the platform's own object, whichever Worker instance receives it", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const request = await signedRequest(platform, VIEW)
    const again = request.clone()
    expect((await fetchPlatformRequest({ ...env }, request)).status).toBe(200)
    // A second entry with its own copy of the bindings, as another isolate would have.
    const replay = await answerOf(await fetchPlatformRequest({ ...env }, again))
    expect(replay).toEqual({ status: 401, body: { error: "proof_invalid", message: "This Mehen-Platform-Proof has already been used. Sign every request afresh." } })
    const nonces = await runInDurableObject(env.PLATFORM_VAULT.getByName(platform.id), (_: PlatformVault, state) => state.storage.sql.exec<{ key: string }>("SELECT key FROM platform_nonces").toArray())
    expect(nonces).toEqual([{ key: platform.key }])
  })

  it("keeps a nonce for as long as any admission could accept its proof, whatever clock each admission was handed", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env)
    const vault = env.PLATFORM_VAULT.getByName(platform.id)
    const i = Math.floor(Date.now() / 1000)
    const freshUntil = (i + 61) * 1000
    vi.useFakeTimers({ toFake: ["Date"], now: i * 1000 + 500 })
    const admit = (jti: string, iat: number, now: number) => {
      const admission: PlatformAdmission = { key: platform.key, jti, iat, subjectHash: null, write: true, decision: false, limits: DEFAULT_PLATFORM_LIMITS }
      return runInDurableObject(vault, (instance: PlatformVault) => instance.admit(admission, now))
    }
    const replayed = { ok: false, error: { status: 401, vaultError: { error: "proof_invalid", message: "This Mehen-Platform-Proof has already been used. Sign every request afresh." } } }
    expect(await admit("jti-first", i, (i + 1) * 1000)).toEqual({ ok: true })
    expect(await admit("jti-first", i, (i + 1) * 1000)).toEqual(replayed)
    // A later call handed a clock at the first proof's freshness boundary,
    // then the first proof again handed a clock read before that boundary.
    expect(await admit("jti-later", i + 60, freshUntil)).toEqual({ ok: true })
    expect(await admit("jti-first", i, freshUntil - 1)).toEqual(replayed)
    // Handed a clock inside the window, with the object's own clock past it
    // by less than its 30-second grace, as after a slow body or a platform
    // clock running behind: admitted, and the first proof is still spent.
    vi.setSystemTime(freshUntil + 29_999)
    expect(await admit("jti-grace", i, freshUntil - 1)).toEqual({ ok: true })
    expect(await admit("jti-first", i, freshUntil - 1)).toEqual(replayed)
    // Past the grace by the object's own clock.
    vi.setSystemTime(freshUntil + 30_000)
    expect(await admit("jti-stale", i, freshUntil - 1)).toEqual({ ok: false, error: { status: 401, vaultError: { error: "proof_invalid", message: "The Mehen-Platform-Proof is more than 60 seconds old. Check the server's clock and retry." } } })
    const spentJtis = () => runInDurableObject(vault, (_: PlatformVault, state) => state.storage.sql.exec<{ jti: string }>("SELECT jti FROM platform_nonces ORDER BY jti").toArray())
    // A nonce stays until the object's clock is a minute past its proof's
    // window and grace, then goes.
    vi.setSystemTime(freshUntil + 89_999)
    const held = Math.floor(Date.now() / 1000)
    expect(await admit("jti-held", held, held * 1000)).toEqual({ ok: true })
    expect(await spentJtis()).toEqual([{ jti: "jti-first" }, { jti: "jti-grace" }, { jti: "jti-held" }, { jti: "jti-later" }])
    vi.setSystemTime(freshUntil + 90_000)
    const now = Math.floor(Date.now() / 1000)
    expect(await admit("jti-fresh", now, now * 1000)).toEqual({ ok: true })
    expect(await spentJtis()).toEqual([{ jti: "jti-fresh" }, { jti: "jti-held" }, { jti: "jti-later" }])
  })

  it("refuses a suspended or retired platform, and one whose retirement date has passed, after the signature", async () => {
    const { env } = await platformEnv()
    const suspended = await registerPlatform(env, { status: "suspended" })
    const retired = await registerPlatform(env, { status: "retired" })
    const pastRetirement = await registerPlatform(env, { status: "retiring", retireAfter: Date.now() - 1 })
    const retiring = await registerPlatform(env, { status: "retiring", retireAfter: Date.now() + 86_400_000 })
    for (const platform of [suspended, retired, pastRetirement]) {
      expect(await answerOf(await platformFetch(env, platform, VIEW))).toEqual({ status: 403, body: { error: "platform_suspended", message: "This platform is suspended." } })
    }
    expect((await platformFetch(env, retiring, VIEW)).status).toBe(200)
    // Someone without the key learns nothing of the platform's status.
    const { privateKey } = await newPlatformKey()
    const forged = { ...suspended.signer, sign: async (data: Uint8Array) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data)) }
    expect((await answerOf(await platformFetch(env, suspended, { ...VIEW, signer: forged }))).body.error).toBe("proof_invalid")
  })
})

describe("the platform invocation auth", () => {
  it("is one type, in core.ts, and the Worker's calls reach the workspace object with no cast", () => {
    const sources = import.meta.glob<string>("../src/**/*.ts", { query: "?raw", import: "default", eager: true })
    const defining = Object.entries(sources).filter(([, text]) => /export type PlatformInvocationAuth\b/.test(text)).map(([path]) => path)
    expect(defining).toEqual(["../src/vault/core.ts"])
    expect(sources["../src/platform/workspace-calls.ts"]).not.toContain("as unknown as")
  })
})
