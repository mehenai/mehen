import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { bodyHash, createProof, jwkThumbprint, webCryptoSigner } from "@mehen/protocol"
import { accessFixture, accessSnapshot, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
async function signerFor(tenant: string, device = "dev_member") {
  const key = await newDeviceKey()
  const jwk = await publicJwk(key)
  const thumbprint = await jwkThumbprint(jwk)
  await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); ctx.sql.exec("UPDATE devices SET jwk=?,thumbprint=? WHERE id=?", JSON.stringify(jwk), thumbprint, device) })
  return webCryptoSigner(device, key.privateKey)
}
async function deviceAuth(tenant: string, signer: Awaited<ReturnType<typeof signerFor>>, op: string, session?: string) {
  const url = `https://vault.test/v1/${op}`
  return { kind: "device" as const, proof: await createProof(signer, { method: "POST", url }, { tenant, ...(session ? { session } : {}) }), method: "POST", url, bodyHash: await bodyHash(null) }
}
describe("workspace machine key transfer", () => {
  it("refuses reassignment even for an owner, then revocation disables the actual old key", async () => {
    const { tenant } = await accessFixture()
    const signer = await signerFor(tenant)
    expect(await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, signer, "me"))).toMatchObject({ ok: true, value: { owner: { member: "mem_member" } } })
    const before = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.transfer", { device: "dev_member", owner: { kind: "member", member: "mem_kim" } }, accountAuth("owner"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    expect(await accessSnapshot(tenant)).toBe(before)
    expect(await workspaceInvoke(tenant, "devices.revoke", { device: "dev_member" }, accountAuth("owner", { type: "device.revoke", device: "dev_member" }))).toEqual({ ok: true, value: {} })
    expect(await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, signer, "me"))).toMatchObject({ ok: false, error: { status: 403, vaultError: { error: "device_revoked" } } })
    await inAccess(tenant, (ctx) => expect(ctx.sql.exec<{ owner_id: string }>("SELECT owner_id FROM devices WHERE id='dev_member'").toArray()[0]?.owner_id).toBe("mem_member"))
  })
  it("returns owner_inactive for status but lets a suspended owner's key revoke itself", async () => {
    const { tenant } = await accessFixture()
    const signer = await signerFor(tenant)
    expect(await workspaceInvoke(tenant, "access.members.suspend", { member: "mem_member" }, accountAuth("owner", { type: "member.suspend", member: "mem_member" }))).toMatchObject({ ok: true })
    expect(await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, signer, "me"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "owner_inactive", message: "You are not allowed to do that." } } })
    expect(await workspaceInvoke(tenant, "devices.revokeSelf", {}, await deviceAuth(tenant, signer, "devices/self/revoke"))).toEqual({ ok: true, value: {} })
  })
  it("refuses guest-machine freeze, while a team machine may freeze", async () => {
    const { tenant } = await accessFixture()
    const guest = await signerFor(tenant, "dev_guest")
    expect(await workspaceInvoke(tenant, "tenant.freeze", {}, await deviceAuth(tenant, guest, "freeze"))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } } })
    const team = await signerFor(tenant, "dev_service")
    expect(await workspaceInvoke(tenant, "tenant.freeze", {}, await deviceAuth(tenant, team, "freeze"))).toEqual({ ok: true, value: {} })
  })
  it("preserves the authenticated proof session in machine audit attribution", async () => {
    const { tenant } = await accessFixture()
    const signer = await signerFor(tenant)
    expect(await workspaceInvoke(tenant, "tenant.freeze", {}, await deviceAuth(tenant, signer, "freeze", "sid_recorded"))).toEqual({ ok: true, value: {} })
    await inAccess(tenant, (ctx) => {
      const detail = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='workspace.freeze'").toArray()[0]!.detail
      expect(JSON.parse(detail).by).toEqual({ owner: "member:mem_member", session: "sid_recorded" })
    })
  })

})

// G0 F-3: the CLI refuses a bare `mehen enrol`, so the device refusals name
// `mehen enrol --workspace <slug>`: the workspace's own slug where the vault
// records one, else the CLI's `<slug>` placeholder. Codes and statuses stay.
describe("device refusals name the enrol command the CLI accepts", () => {
  it("a revoked device and an unknown device are told mehen enrol --workspace with this workspace's slug", async () => {
    const { tenant } = await accessFixture()
    const signer = await signerFor(tenant)
    expect(await workspaceInvoke(tenant, "devices.revoke", { device: "dev_member" }, accountAuth("owner", { type: "device.revoke", device: "dev_member" }))).toEqual({ ok: true, value: {} })
    const revoked = await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, signer, "me"))
    expect(revoked).toMatchObject({ ok: false, error: { status: 403, vaultError: { error: "device_revoked", next: { command: "mehen enrol --workspace work", say: expect.stringContaining("`mehen enrol --workspace work`") } } } })
    const key = await newDeviceKey()
    const stranger = webCryptoSigner("dev_unknown", key.privateKey)
    const unknown = await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, stranger, "me"))
    expect(unknown).toMatchObject({ ok: false, error: { status: 401, vaultError: { error: "unauthenticated", next: { command: "mehen enrol --workspace work", say: expect.stringContaining("`mehen enrol --workspace work`") } } } })
  })

  it("a vault with no valid slug recorded names the <slug> placeholder, never a bare mehen enrol", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => { ctx.sql.exec("UPDATE tenant_state SET value=? WHERE key='workspace'", JSON.stringify({ id: tenant, slug: "Not A Slug", name: "Work" })) })
    const key = await newDeviceKey()
    const stranger = webCryptoSigner("dev_unknown", key.privateKey)
    const unknown = await workspaceInvoke(tenant, "devices.me", {}, await deviceAuth(tenant, stranger, "me"))
    expect(unknown).toMatchObject({ ok: false, error: { status: 401, vaultError: { error: "unauthenticated", next: { command: "mehen enrol --workspace <slug>" } } } })
  })
})
