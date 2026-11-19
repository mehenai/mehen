import { bodyHash,createProof,webCryptoSigner } from "@mehen/protocol"
import { expect,it } from "vitest"
import { env } from "cloudflare:workers"
import { ORIGIN } from "../helpers.ts"
import { workJourney } from "./workspace-journey.ts"

it("the workspace dispatcher refuses a proof claiming another workspace before nonce or audit writes",async () => {
  const f = await workJourney(),machine = await f.machine(f.alex,f.work)
  const proof = await createProof(webCryptoSigner(machine.device,machine.keys.privateKey),{ method: "GET",url: `${ORIGIN}/v1/me`,body: null },{ tenant: f.personal.id })
  const snapshot = async () => ({ nonces: await f.sql(f.work,"SELECT * FROM device_nonces ORDER BY device,jti"),audit: await f.sql(f.work,"SELECT * FROM audit ORDER BY seq") })
  const before = await snapshot()
  // HTTP routes by the unverified claim. Pin the defensive check at the DO seam.
  const result = await env.TENANT_VAULT.getByName(f.work.id).invoke({ op: "devices.me",input: {},auth: { kind: "device",proof,method: "GET",url: `${ORIGIN}/v1/me`,bodyHash: await bodyHash(null) } })
  expect(result).toEqual({ ok: false,error: { status: 401,vaultError: { error: "proof_invalid",message: "This Mehen-Proof was signed for a different vault." } } })
  expect(await snapshot()).toEqual(before)
})
