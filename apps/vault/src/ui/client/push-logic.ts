// The credential page's push changes, without the DOM: the item.update the
// allowance signs, and the check that the item.push the vault planned is
// the one the page showed: this credential at the version shown, the field,
// exactly the places ticked, and each carried by the credential its row
// named. The page shows those by slug, so it reads each as the viewer for
// the id and version the plan signs.

import type { WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { PUSH_AGAIN_CHOOSE_WORDS, PUSH_AGAIN_MAX, PUSH_AGAIN_TOO_MANY_WORDS } from "../push-wording.ts"
import { type Built, digestOf } from "./logic.ts"
import type { ShownItem } from "./workspace-logic.ts"

// The digest items.action rebuilds for an update: the change with the
// version and configuration revision the page showed.
export async function pushAllowanceAction(shown: Pick<ShownItem, "id" | "version" | "configRevision">, pushable: boolean): Promise<WorkspaceStepUpAction> {
  return { type: "item.update", item: shown.id, digest: await digestOf({ change: { pushable }, version: shown.version, configRevision: shown.configRevision }) }
}

// A ticked place as its row showed it: `via` is the slug of the credential
// that carried the push there, null when the viewer cannot see it.
export type ChosenPush = { record: string; destination: string; field: string; via: string | null }

// A carrying credential as the viewer's own read gives it, just before the
// plan is checked.
export type ViaRead = { id: string; version: number }

export function pushAgainChoice(chosen: readonly ChosenPush[]): Built<string[]> {
  if (chosen.length === 0) return { ok: false, problems: [PUSH_AGAIN_CHOOSE_WORDS] }
  if (chosen.length > PUSH_AGAIN_MAX) return { ok: false, problems: [PUSH_AGAIN_TOO_MANY_WORDS] }
  return { ok: true, value: chosen.map((c) => c.record) }
}

// The carrying credentials the ticked rows showed, each once, for the page
// to read as the viewer; null when a ticked row showed none.
export function pushAgainVias(chosen: readonly ChosenPush[]): string[] | null {
  if (chosen.some((c) => c.via === null)) return null
  return [...new Set(chosen.map((c) => c.via as string))]
}

// The vault's plan against the ticked rows, one entry for each by
// destination: this credential at the version shown, the field, and each
// entry carried by the credential its row showed, at the id and version the
// viewer's read of that slug gave.
export function pushAgainMatches(shown: Pick<ShownItem, "id" | "version">, chosen: readonly ChosenPush[], vias: ReadonlyMap<string, ViaRead>, received: unknown): boolean {
  if (typeof received !== "object" || received === null) return false
  const a = received as Record<string, unknown>
  if (Object.keys(a).sort().join() !== "field,item,pushes,type,version") return false
  if (a.type !== "item.push" || a.item !== shown.id || a.version !== shown.version) return false
  if (chosen.length === 0 || chosen.some((c) => c.field !== a.field)) return false
  const rows = new Map(chosen.map((c) => [c.destination, c]))
  const pushes = Array.isArray(a.pushes) ? (a.pushes as unknown[]) : []
  if (rows.size !== chosen.length || pushes.length !== chosen.length) return false
  const matched = new Set<string>()
  return pushes.every((p) => {
    if (typeof p !== "object" || p === null) return false
    const push = p as Record<string, unknown>
    if (Object.keys(push).sort().join() !== "destination,via,viaVersion" || typeof push.destination !== "string") return false
    const row = rows.get(push.destination)
    if (row === undefined || row.via === null || matched.has(row.destination)) return false
    matched.add(row.destination)
    const via = vias.get(row.via)
    return via !== undefined && push.via === via.id && push.viaVersion === via.version
  })
}
