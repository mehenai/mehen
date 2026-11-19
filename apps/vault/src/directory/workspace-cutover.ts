import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"

export const WORKSPACE_GENERATION = "workspaces-fresh-v1"
const CHECK_TTL_MS = 60_000
const checked = new WeakMap<Env["DB"], WeakMap<Env["TENANT_VAULT"], { at: number; until: number }>>()

// Cache only a verified schema and actual bound class, for at most a minute.
// Binding identity keeps a changed database or namespace from sharing a result.
export async function assertWorkspaceCutover(env: Env): Promise<void> {
  const now = Date.now(), cached = checked.get(env.DB)?.get(env.TENANT_VAULT)
  if (cached && now >= cached.at && now < cached.until) return
  checked.get(env.DB)?.delete(env.TENANT_VAULT)
  try {
    const marker = await env.DB.prepare(`SELECT generation, EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('members','tenants','invites','security_notices')) AS legacy FROM workspace_cutover WHERE id=1`).first<{ generation: string; legacy: number }>()
    if (marker?.generation !== WORKSPACE_GENERATION || marker.legacy || await env.TENANT_VAULT.getByName("workspace-cutover").cutoverGeneration() !== WORKSPACE_GENERATION) throw new Error("Incomplete workspace cutover")
    let namespaces = checked.get(env.DB)
    if (!namespaces) { namespaces = new WeakMap(); checked.set(env.DB, namespaces) }
    namespaces.set(env.TENANT_VAULT, { at: now, until: now + CHECK_TTL_MS })
  } catch {
    checked.get(env.DB)?.delete(env.TENANT_VAULT)
    throw new VaultError("upstream_failed", "Workspaces are unavailable until the fresh-start cutover completes.", { retryAfter: 60 })
  }
}
