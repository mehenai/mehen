// Save with passkey on the How careful card (posture-card.ts), with no DOM
// so the tests drive this exact code. The page builds the posture from the
// choice (Custom is stored as ask, which names no machines), refuses to
// sign one that changes nothing, and signs one passkey over item.posture
// only once the vault's action carries the digest this page computed itself
// (itemPostureDigest) over the posture, the credential's current catalogue
// and the posture revision it showed; any other action sends nothing.

import type { Posture, PostureCatalogue, PostureLevel, WorkspaceStepUpAction } from "@mehen/protocol"
import { itemPostureDigest } from "@mehen/protocol/policy-rules"
import type { ShellState } from "./shell-logic.ts"
import { sameAction } from "./workspace-logic.ts"
import { type Passkey, browserPasskey, signed } from "./workspace-sign.ts"

export type PostureChoice = PostureLevel | "custom"

// The posture as the card showed it, from its data attributes: the
// credential's id and slug, the stored level, machines and revision, the
// credential's current catalogue (null with none) and whether the one the
// level was signed against has grown since.
export type PostureShown = { item: string; slug: string; rev: number; level: PostureLevel; machines: string[] | null; catalogue: PostureCatalogue | null; grown: boolean }

// The posture a choice stores: Custom and Ask are ask, with no machines;
// Routine and Trust reach every eligible machine, or only those ticked,
// sorted and each once. Null when only ticked machines are asked for and
// none is ticked.
export function chosenPosture(choice: PostureChoice, named: readonly string[] | null): Posture | null {
  if (choice === "ask" || choice === "custom") return { level: "ask", machines: null }
  if (named === null) return { level: choice, machines: null }
  const machines = [...new Set(named)].sort()
  return machines.length === 0 ? null : { level: choice, machines }
}

// Saving changes nothing when the level and machines are those stored, and
// the catalogue has not grown under a level that uses it.
export function postureUnchanged(shown: PostureShown, posture: Posture): boolean {
  if (posture.level !== shown.level) return false
  if (posture.level === "ask") return true
  return !shown.grown && JSON.stringify(posture.machines) === JSON.stringify(shown.machines)
}

// The item.posture action the vault should build for this posture.
export async function itemPostureAction(shown: PostureShown, posture: Posture): Promise<Extract<WorkspaceStepUpAction, { type: "item.posture" }>> {
  const digest = await itemPostureDigest({ ...posture, item: shown.item, catalogue: shown.catalogue?.template ?? null, catalogueVersion: shown.catalogue?.version ?? null, before: shown.rev })
  return { type: "item.posture", item: shown.item, digest, level: posture.level }
}

// A vault action other than the one expected is refused as changed since
// shown (signed), before any passkey.
export async function savePosture<T>(shell: ShellState, shown: PostureShown, posture: Posture, passkey: Passkey = browserPasskey): Promise<T> {
  const expected = await itemPostureAction(shown, posture)
  const path = `/items/${encodeURIComponent(shown.slug)}`
  const terms = { posture, rev: shown.rev }
  return signed<T>(shell, { prepare: { path: `${path}/action`, body: { action: "posture", ...terms } }, matches: (a) => sameAction(expected, a), mutation: { path: `${path}/posture`, body: terms } }, passkey)
}
