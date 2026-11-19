import { describe, expect, it } from "bun:test"
import { generateSealKeyPair, isSealedBox, openText } from "@mehen/protocol/seal"
import { type SealKey, intakeSealContext, sealFields } from "../src/seal.ts"

const INTAKE = "int_intake0001"

async function sealKeyPair(): Promise<{ sealKey: SealKey; privateKey: CryptoKey }> {
  const pair = await generateSealKeyPair()
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey
  return { sealKey: { jwk: { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) }, kid: "seal-2026" }, privateKey: pair.privateKey }
}

describe("sealFields", () => {
  it("seals each field under intake/<intake>/<field>, and a box opens for that field only", async () => {
    const { sealKey, privateKey } = await sealKeyPair()
    const boxes = await sealFields(sealKey, INTAKE, { client_secret: "not-a-real-secret", key: "sk-not-real" })
    expect(Object.keys(boxes).sort()).toEqual(["client_secret", "key"])
    expect(isSealedBox(boxes.client_secret)).toBe(true)
    expect(JSON.stringify(boxes)).not.toContain("not-a-real-secret")
    const secret = boxes.client_secret
    const key = boxes.key
    if (secret === undefined || key === undefined) throw new Error("missing box")
    expect(await openText(privateKey, secret, `intake/${INTAKE}/client_secret`)).toBe("not-a-real-secret")
    expect(await openText(privateKey, key, `intake/${INTAKE}/key`)).toBe("sk-not-real")
    await expect(openText(privateKey, secret, `intake/${INTAKE}/key`)).rejects.toThrow("sealed box failed authentication")
    await expect(openText(privateKey, secret, "intake/int_other0001/client_secret")).rejects.toThrow("sealed box failed authentication")
  })

  it("seals afresh each time", async () => {
    const { sealKey } = await sealKeyPair()
    const [a, b] = [await sealFields(sealKey, INTAKE, { key: "same" }), await sealFields(sealKey, INTAKE, { key: "same" })]
    expect(a.key?.ct).not.toBe(b.key?.ct)
    expect(a.key?.epk.x).not.toBe(b.key?.epk.x)
  })

  it("refuses an intake id, field names or a count the vault would refuse, and a seal key with no point", async () => {
    const { sealKey } = await sealKeyPair()
    await expect(sealFields(sealKey, "con_connect0001", { key: "v" })).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields(sealKey, INTAKE, { Key: "v" })).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields(sealKey, INTAKE, { "key/../other": "v" })).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields(sealKey, INTAKE, {})).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields(sealKey, INTAKE, Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`f${i}`, "v"])))).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields(sealKey, INTAKE, { key: 42 as unknown as string })).rejects.toBeInstanceOf(TypeError)
    await expect(sealFields({ ...sealKey, jwk: { ...sealKey.jwk, x: undefined as unknown as string } }, INTAKE, { key: "v" })).rejects.toBeInstanceOf(TypeError)
  })

  it("names the context the vault opens with", () => {
    expect(intakeSealContext(INTAKE, "client_secret")).toBe("intake/int_intake0001/client_secret")
    expect(() => intakeSealContext("int_", "key")).toThrow(TypeError)
  })
})
