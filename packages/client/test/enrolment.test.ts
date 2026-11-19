import { describe, expect, it } from "bun:test"
import { fingerprintGroupIndex, fingerprintOf } from "@mehen/protocol/fingerprint"
import { jwkThumbprint } from "@mehen/protocol/proof"
import { WorkspaceEnrolStartSchema } from "@mehen/protocol/workspace"
import { MehenRefusal, MehenTransport, enrolmentStatus, generateKey, renewEnrolment, startEnrolment } from "../src/index.ts"
import { DEVICE, FakeVault, ORIGIN, TENANT, json, refuse } from "./fake-vault.ts"
import { OWNER, SCOPE, WORKSPACE } from "./fixtures.ts"

const ENROLMENT = "enr_attempt0001"
const CODE = "K7Q2MX4D"

async function started(vault: FakeVault, overrides: Record<string, unknown> = {}) {
  vault.on("POST /v1/enrol", async (seen) => {
    const start = seen.json as { workspace: string; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string } }
    return json({ enrolment: ENROLMENT, code: CODE, url: `${ORIGIN}/w/${start.workspace}/e/${CODE}`, fingerprint: fingerprintOf(await jwkThumbprint(start.jwk)), expiresAt: "2026-10-29T10:15:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z", ...overrides }, 201)
  })
}

describe("startEnrolment", () => {
  it("signs POST /v1/enrol with the new key as ten enrol, dev new, and answers the link, code and fingerprint", async () => {
    const vault = new FakeVault()
    await started(vault)
    const key = await generateKey()
    const answer = await startEnrolment({ vaultUrl: ORIGIN, workspace: "acme", owner: { kind: "self" }, name: "globex-broker", host: "globex.example", scope: { tags: ["globex"], workloads: "required", privateCredentials: false }, key, session: "broker-1", fetch: vault.fetch })
    const seen = vault.last
    expect(seen.signedBy).toBe("enrolling")
    expect(seen.claims.ten).toBe("enrol")
    expect(seen.claims.dev).toBe("new")
    expect(seen.claims.sid).toBe("broker-1")
    expect(WorkspaceEnrolStartSchema.parse(seen.json)).toEqual({ workspace: "acme", owner: { kind: "self" }, name: "globex-broker", backend: "software", jwk: key.jwk, host: "globex.example", scope: { tags: ["globex"], workloads: "required", privateCredentials: false } })
    expect(seen.headers.get("content-type")).toBe("application/json")
    expect(answer.enrolment).toBe(ENROLMENT)
    expect(answer.code).toBe(CODE)
    expect(answer.url).toBe(`${ORIGIN}/w/acme/e/${CODE}`)
    expect(answer.fingerprint.fingerprint).toBe(fingerprintOf(await jwkThumbprint(key.jwk)))
    expect(answer.fingerprint.groups.join(" ")).toBe(answer.fingerprint.fingerprint)
    expect(answer.fingerprint.words).toHaveLength(4)
    expect(answer.hiddenGroup).toBe(await fingerprintGroupIndex(CODE))
  })

  it("refuses an answer whose link is off the vault's origin or not the enrol page, or that names another key", async () => {
    for (const overrides of [{ url: `https://evil.example/w/acme/e/${CODE}` }, { url: `${ORIGIN}/w/other/e/${CODE}` }, { url: `https://user@vault.example/w/acme/e/${CODE}` }, { fingerprint: "0000 0000 0000 0000" }]) {
      const vault = new FakeVault()
      await started(vault, overrides)
      const error = await startEnrolment({ vaultUrl: ORIGIN, workspace: "acme", owner: { kind: "self" }, name: "globex-broker", key: await generateKey(), fetch: vault.fetch }).catch((e: unknown) => e)
      expect(error).toBeInstanceOf(MehenTransport)
      expect((error as MehenTransport).reason).toBe("unexpected")
    }
  })

  it("refuses an invalid request before anything is sent", async () => {
    const vault = new FakeVault()
    await expect(startEnrolment({ vaultUrl: ORIGIN, workspace: "Not A Slug", owner: { kind: "self" }, name: "x", key: await generateKey(), fetch: vault.fetch })).rejects.toBeInstanceOf(TypeError)
    await expect(startEnrolment({ vaultUrl: "http://vault.example", workspace: "acme", owner: { kind: "self" }, name: "x", key: await generateKey(), fetch: vault.fetch })).rejects.toBeInstanceOf(TypeError)
    expect(vault.seen).toHaveLength(0)
  })
})

describe("enrolmentStatus", () => {
  it("polls signed by the same key as dev = the enrolment id, pending then active", async () => {
    const vault = new FakeVault()
    const key = await generateKey()
    vault.enrolments.set(ENROLMENT, key.jwk)
    vault.on(`GET /v1/enrol/${ENROLMENT}`, () => json({ status: "pending_owner_acceptance", expiresAt: "2026-10-29T10:15:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z" }))
    expect(await enrolmentStatus({ vaultUrl: ORIGIN, enrolment: ENROLMENT, key, fetch: vault.fetch })).toEqual({ status: "pending_owner_acceptance", expiresAt: "2026-10-29T10:15:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z" })
    expect(vault.last.claims).toMatchObject({ ten: "enrol", dev: ENROLMENT })
    expect(vault.last.body).toHaveLength(0)
    vault.on(`GET /v1/enrol/${ENROLMENT}`, () => json({ status: "active", tenant: TENANT, workspace: WORKSPACE, device: DEVICE, scope: SCOPE, owner: OWNER }))
    expect(await enrolmentStatus({ vaultUrl: ORIGIN, enrolment: ENROLMENT, key, fetch: vault.fetch })).toEqual({ status: "active", tenant: TENANT, workspace: WORKSPACE, device: DEVICE, scope: SCOPE, owner: OWNER })
  })

  it("is a transport failure when the active answer's workspace is not its tenant", async () => {
    const vault = new FakeVault()
    const key = await generateKey()
    vault.enrolments.set(ENROLMENT, key.jwk)
    vault.on(`GET /v1/enrol/${ENROLMENT}`, () => json({ status: "active", tenant: "tn_other0000000", workspace: WORKSPACE, device: DEVICE, scope: SCOPE, owner: OWNER }))
    await expect(enrolmentStatus({ vaultUrl: ORIGIN, enrolment: ENROLMENT, key, fetch: vault.fetch })).rejects.toBeInstanceOf(MehenTransport)
  })

  it("is refused when another key signs the poll", async () => {
    const vault = new FakeVault()
    vault.enrolments.set(ENROLMENT, (await generateKey()).jwk)
    vault.on(`GET /v1/enrol/${ENROLMENT}`, () => json({ status: "rejected" }))
    const error = await enrolmentStatus({ vaultUrl: ORIGIN, enrolment: ENROLMENT, key: await generateKey(), fetch: vault.fetch }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(MehenRefusal)
    expect((error as MehenRefusal).code).toBe("proof_invalid")
  })
})

describe("renewEnrolment", () => {
  async function renewing(handler: () => Response) {
    const vault = new FakeVault()
    const key = await generateKey()
    vault.enrolments.set(ENROLMENT, key.jwk)
    vault.on(`POST /v1/enrol/${ENROLMENT}/renew`, handler)
    return { vault, renew: () => renewEnrolment({ vaultUrl: ORIGIN, enrolment: ENROLMENT, key, fetch: vault.fetch }) }
  }

  it("renews in place with an empty body", async () => {
    const { vault, renew } = await renewing(() => json({ enrolment: ENROLMENT, expiresAt: "2026-10-29T10:30:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z" }))
    expect(await renew()).toEqual({ kind: "renewed", enrolment: ENROLMENT, expiresAt: "2026-10-29T10:30:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z" })
    expect(vault.last.body).toHaveLength(0)
    expect(vault.last.headers.has("content-type")).toBe(false)
  })

  it("reads a 409 with retryAfter as later and a 409 with the enrolment as settled", async () => {
    expect(await (await renewing(() => refuse("conflict", "This enrolment was renewed less than a minute ago; keep waiting.", { retryAfter: 42 }))).renew()).toEqual({ kind: "later", retryAfter: 42 })
    expect(await (await renewing(() => refuse("conflict", "This enrolment can no longer be renewed.", { enrolment: { status: "expired", reason: "hard_cap" } }))).renew()).toEqual({ kind: "settled", status: { status: "expired", reason: "hard_cap" } })
  })

  it("throws the refusal for a gone enrolment and a transport failure for a renewal of another id", async () => {
    const gone = await (await renewing(() => refuse("not_found", "No such enrolment."))).renew().catch((e: unknown) => e)
    expect(gone).toBeInstanceOf(MehenRefusal)
    expect((gone as MehenRefusal).code).toBe("not_found")
    const other = await (await renewing(() => json({ enrolment: "enr_someoneelse", expiresAt: "2026-10-29T10:30:00.000Z", hardExpiresAt: "2026-10-29T11:00:00.000Z" }))).renew().catch((e: unknown) => e)
    expect(other).toBeInstanceOf(MehenTransport)
  })
})
