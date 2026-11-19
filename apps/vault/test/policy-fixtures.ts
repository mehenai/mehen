import { jwkThumbprint } from "@mehen/protocol"
import type { DevicePrincipal, VaultContext } from "../src/vault/core.ts"
import type { NewItem } from "../src/vault/services.ts"
import { devicePolicyState } from "../src/vault/areas/devices.ts"
import { items } from "../src/vault/areas/items.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import { testDevice } from "./helpers.ts"

export const SYSTEM = { kind: "system", reason: "policy-test" } as const
export const POLICY_DEVICE = "dev_policytest"
export function policyItem(overrides: Partial<NewItem> = {}): NewItem {
  return { slug: "custom-key", kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "placeholder", binding: { hosts: ["api.example.com"], paths: ["/api/**"] }, policy: { default: "approve", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" }, publicFields: {}, secretFields: { key: "policy-test-secret-0123456789" }, description: null, ...overrides }
}
export async function registerPolicyDevice(ctx: VaultContext, device: DevicePrincipal = testDevice({ device: POLICY_DEVICE })): Promise<DevicePrincipal> {
  if (devicePolicyState(ctx, device.device)) return device
  const jwk = await publicJwk(await newDeviceKey())
  const thumbprint = await jwkThumbprint(jwk)
  ctx.sql.exec("INSERT INTO devices(id,name,backend,host,jwk,thumbprint,scope,created_at,enrolment) VALUES (?,?,'software',NULL,?,?,?,?,?)",device.device,device.name,JSON.stringify(jwk),thumbprint,JSON.stringify(device.scope),ctx.now(),`enr_${device.device.slice(4)}`)
  return device
}
export async function policyFixture(ctx: VaultContext, overrides: Partial<NewItem> = {}, device: DevicePrincipal = testDevice({ device: POLICY_DEVICE, session: "supervisor" })): Promise<DevicePrincipal> {
  await registerPolicyDevice(ctx, device)
  await items.putItem(ctx, policyItem(overrides), SYSTEM)
  return device
}
