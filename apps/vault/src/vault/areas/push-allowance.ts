// Whether a credential may be put into other services' secret stores (ruling
// U1): a per-item allowance, off until a person turns it on with a passkey
// under item.update, and only where the kind could ever be leased. The push
// itself never lets the asking machine hold the value.

import { KINDS, modeAllowed, type ItemKind } from "@mehen/protocol"
import type { Env } from "../../env.ts"
import { VaultError } from "../../http.ts"
import { one, type VaultContext } from "../core.ts"
import { workspaceSwitchOn } from "../workspace-switch.ts"
import { managedSetting } from "./workspace-runtime.ts"

// Whether pushing is on for a workspace (its tn_ id), read as every
// per-workspace switch is.
export function pushesOn(env: Pick<Env, "PUSH">, workspace: string): boolean {
  return workspaceSwitchOn(env.PUSH, workspace)
}

export function pushesUnavailable(): VaultError {
  return new VaultError("forbidden", "Pushing is not available yet.")
}

export function pushesManaged(): VaultError {
  return new VaultError("forbidden", "Pushing is not available in a managed workspace.")
}

// Off, or a managed workspace: nothing about pushing is offered.
export function assertPushesHere(ctx: VaultContext): void {
  if (!pushesOn(ctx.env, ctx.tenant)) throw pushesUnavailable()
  if (managedSetting(ctx) !== null) throw pushesManaged()
}

// An OAuth client or connection is never pushed: the one is the vault's own
// way to sign in, the other refreshes itself and a copy elsewhere goes stale.
export function pushOffered(kind: ItemKind): boolean {
  return kind !== "oauth-connection" && kind !== "oauth-client" && modeAllowed(KINDS[kind].maxCeiling, "lease")
}

export function itemPushable(ctx: VaultContext, item: string): boolean {
  return one(ctx.sql.exec<{ pushable: number }>("SELECT pushable FROM items WHERE id=?", item))?.pushable === 1
}

// What turning the allowance on in an item.update must hold: pushing here,
// and a kind that may be pushed. Turning it off always may.
export function assertPushableChange(ctx: VaultContext, kind: ItemKind, pushable: boolean | undefined): void {
  if (pushable !== true) return
  assertPushesHere(ctx)
  if (!pushOffered(kind)) throw new VaultError("mode_refused", `A ${KINDS[kind].label} may not be put into other services' secret stores.`)
}
