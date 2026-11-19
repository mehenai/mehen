// GET /v1/me names the role of the device's owner, so `mehen adopt plan`
// knows whether this machine may store workspace credentials.
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { bodyHash, createProof, jwkThumbprint, webCryptoSigner } from "@mehen/protocol"
import { accessFixture, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess, registerFixtureLifecycleHooks, workspaceInvoke } from "./access-test-support.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)

async function me(tenant: string, device: string) {
  const key = await newDeviceKey()
  const jwk = await publicJwk(key)
  const thumbprint = await jwkThumbprint(jwk)
  await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); ctx.sql.exec("UPDATE devices SET jwk=?,thumbprint=? WHERE id=?", JSON.stringify(jwk), thumbprint, device) })
  const url = "https://vault.test/v1/me"
  const auth = { kind: "device" as const, proof: await createProof(webCryptoSigner(device, key.privateKey), { method: "POST", url }, { tenant }), method: "POST", url, bodyHash: await bodyHash(null) }
  return workspaceInvoke(tenant, "devices.me", {}, auth)
}

describe("devices.me", () => {
  it("names the owner's role in the workspace, guest for a guest's device, or team for a team's device", async () => {
    const { tenant } = await accessFixture()
    for (const [device, ownerRole] of [["dev_owner", "owner"], ["dev_admin", "admin"], ["dev_member", "member"], ["dev_guest", "guest"], ["dev_service", "team"]]) {
      expect(await me(tenant, device as string)).toMatchObject({ ok: true, value: { device, ownerRole } })
    }
  })
})
