// D1's device_cli_versions (migrations/0014) is the operator's fleet view
// (scripts/fleet-versions.ts), since D1 cannot read a workspace's object:
// a machine's row is written when its CLI version changes (devices.ts,
// authenticateDevice) and deleted when the machine is revoked. Best effort:
// a failed write is logged and never fails the call; the next change
// writes again.

import type { VaultContext } from "../core.ts"

function logFailure(at: string, error: unknown): void {
  console.error(JSON.stringify({ at, error: error instanceof Error ? error.name : "unknown" }))
}

export async function copyCliVersion(ctx: VaultContext, device: string, version: string, now: number): Promise<void> {
  try {
    await ctx.env.DB.prepare("INSERT INTO device_cli_versions(tenant,device,version,seen_at) VALUES (?,?,?,?) ON CONFLICT(tenant,device) DO UPDATE SET version=excluded.version,seen_at=excluded.seen_at")
      .bind(ctx.tenant, device, version, now)
      .run()
  } catch (error) {
    logFailure("device.cli_version.copy", error)
  }
}

// Revocations run inside synchronous transactions, so the delete is left
// to run after the call.
export function forgetCliVersions(ctx: VaultContext, devices: readonly string[]): void {
  if (devices.length === 0) return
  const forget = async () => {
    await ctx.env.DB.batch(devices.map((device) => ctx.env.DB.prepare("DELETE FROM device_cli_versions WHERE tenant=? AND device=?").bind(ctx.tenant, device)))
  }
  ctx.waitUntil(forget().catch((error: unknown) => logFailure("device.cli_version.forget", error)))
}
