// The Worker's way into a tenant's Durable Object.

import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import type { Invocation, InvocationResult } from "./core.ts"
import { timed } from "../server-timing.ts"

export const TENANT_ID = /^tn_[A-Za-z0-9]{8,40}$/

export async function invokeVault(env: Env, tenant: string, invocation: Invocation): Promise<unknown> {
  if (!TENANT_ID.test(tenant)) throw new VaultError("unauthenticated", "Unknown vault.")
  const result = (await timed("workspace", () => env.TENANT_VAULT.getByName(tenant).invoke(invocation))) as InvocationResult
  if (result.ok) return result.value
  const { error, message, ...extra } = result.error.vaultError
  throw new VaultError(error, message, extra)
}
