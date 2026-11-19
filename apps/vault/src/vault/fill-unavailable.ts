// Fill, typing a credential into a web page, ships behind BROWSER_FILL.
// Where it is off, the vault refuses it wherever a person or an agent
// could set it: an item's ceiling, a machine's scope and a workload's
// modes. The modes an enrolment asks for are refused either way, since
// enrolment never grants fill.

import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { workspaceSwitchOn } from "./workspace-switch.ts"

export const FILL_NOT_AVAILABLE = "Typing into web pages is not available yet."

// Managed workspaces refuse fill until a platform's decision API has a fill shape.
export const FILL_MANAGED_REFUSAL = "A managed workspace's platform cannot decide fills yet, so typing into web pages is not available here."

// Whether fill is on for a workspace (its tn_ id), in POLICY_RULES's form.
export function browserFillOn(env: Pick<Env, "BROWSER_FILL">, workspace: string): boolean {
  return workspaceSwitchOn(env.BROWSER_FILL, workspace)
}

export function refuseFillUntilShipped(modes: readonly string[]): void {
  if (modes.includes("fill")) throw new VaultError("mode_refused", FILL_NOT_AVAILABLE)
}

export function refuseFillUnlessOn(ctx: { env: Pick<Env, "BROWSER_FILL">; tenant: string }, modes: readonly string[]): void {
  if (!browserFillOn(ctx.env, ctx.tenant)) refuseFillUntilShipped(modes)
}

// The pages a credential may be typed into (items.browser) change only
// where fill is on.
export function refuseBrowserChangeUnlessOn(ctx: { env: Pick<Env, "BROWSER_FILL">; tenant: string }, browser: unknown): void {
  if (browser !== undefined && !browserFillOn(ctx.env, ctx.tenant)) throw new VaultError("mode_refused", FILL_NOT_AVAILABLE)
}
