// What must run before any write that can change who manages a credential's
// home (team membership, shares, a member's role or status, a credential
// made, deleted or moved, a project deleted): mandates lapse what expired
// shares took (settleShareExpiries) while access is still as it was. Its
// own module, with no imports but types, so any area may call it without
// an import cycle; tools/ci/management-guard.test.ts checks every such
// write calls it first.

import type { VaultContext } from "../core.ts"

type ManagementGuard = (ctx: VaultContext) => void
const managementGuards = new Map<string, ManagementGuard>()
export function registerManagementGuard(name: string, guard: ManagementGuard): void { managementGuards.set(name, guard) }
export function beforeManagementChange(ctx: VaultContext): void { for (const guard of managementGuards.values()) guard(ctx) }
// Test support only: clears the guards and hands back a restore.
export function isolateManagementGuardsForTests(): () => void {
  const saved = new Map(managementGuards)
  managementGuards.clear()
  return () => { managementGuards.clear(); for (const [name, guard] of saved) managementGuards.set(name, guard) }
}
