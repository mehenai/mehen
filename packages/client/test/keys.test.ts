import { describe, expect, it } from "bun:test"
import { fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { createProof, importDeviceKey, jwkThumbprint, parseProof, verifyProof } from "@mehen/protocol/proof"
import { deviceSigner, exportPrivateKey, fingerprint, generateKey, importPrivateKey, workloadSigner } from "../src/index.ts"

describe("keys", () => {
  it("generates an extractable P-256 pair whose JWK is the public half", async () => {
    const key = await generateKey()
    expect(key.privateKey.extractable).toBe(true)
    expect(Object.keys(key.jwk).sort()).toEqual(["crv", "kty", "x", "y"])
    expect(key.jwk).toMatchObject({ kty: "EC", crv: "P-256" })
  })

  it("round-trips through PKCS #8, and a non-extractable import still signs proofs the JWK verifies", async () => {
    const key = await generateKey()
    const pkcs8 = await exportPrivateKey(key.privateKey)
    const extractable = await importPrivateKey(pkcs8, { extractable: true })
    expect(extractable.jwk).toEqual(key.jwk)
    expect(await exportPrivateKey(extractable.privateKey)).toEqual(pkcs8)
    const sealed = await importPrivateKey(pkcs8, { extractable: false })
    expect(sealed.jwk).toEqual(key.jwk)
    expect(sealed.privateKey.extractable).toBe(false)
    await expect(exportPrivateKey(sealed.privateKey)).rejects.toBeInstanceOf(TypeError)
    const url = "https://vault.example/v1/me"
    const proof = parseProof(await createProof(deviceSigner("dev_device0001", sealed.privateKey), { method: "GET", url }, { tenant: "tn_acme0000test" }))
    expect((await verifyProof(proof, await importDeviceKey(key.jwk), { method: "GET", url, bodyHash: proof.claims.bh })).ok).toBe(true)
  })

  it("gives the fingerprint the CLI prints: thumbprint, the four groups and the words", async () => {
    const { jwk } = await generateKey()
    const thumbprint = await jwkThumbprint(jwk)
    expect(await fingerprint(jwk)).toEqual({ thumbprint, fingerprint: fingerprintOf(thumbprint), groups: fingerprintGroups(fingerprintOf(thumbprint)), words: fingerprintWords(thumbprint) })
  })

  it("signs a workload's proofs with kid and wkl the workload and dev its device", async () => {
    const { privateKey } = await generateKey()
    const proof = parseProof(await createProof(workloadSigner("dev_device0001", "wl_workload0001", privateKey), { method: "GET", url: "https://vault.example/v1/me" }, { tenant: "tn_acme0000test" }))
    expect(proof.claims).toMatchObject({ dev: "dev_device0001", wkl: "wl_workload0001" })
    expect(() => workloadSigner("dev_device0001", "dev_device0001", privateKey)).toThrow(TypeError)
    expect(() => deviceSigner("wl_workload0001", privateKey)).toThrow(TypeError)
  })
})
