// What changing a machine's scope or a project's repositories does, in
// words, before the passkey is asked for. Pure, so it is tested without a
// browser. A line widens when the machine or the repositories can reach
// more afterwards.

import type { DeviceScope } from "@mehen/protocol/api"
import { MODE_WORDS, joinWords } from "../wording.ts"
import { type ChangeLine, digestOf } from "./logic.ts"

function added<T>(before: readonly T[], after: readonly T[]): T[] {
  return after.filter((x) => !before.includes(x))
}

function listChange(before: string[], after: string[], everything: string, noun: (names: string[]) => string): ChangeLine[] {
  if (before.length === 0 && after.length === 0) return []
  if (before.length === 0) return [{ text: `Only ${noun(after)}, no longer ${everything}`, widens: false }]
  if (after.length === 0) return [{ text: `${everything.charAt(0).toUpperCase()}${everything.slice(1)}, not only ${noun(before)}`, widens: true }]
  const lines: ChangeLine[] = []
  const more = added(before, after)
  const fewer = added(after, before)
  if (more.length) lines.push({ text: `Also ${noun(more)}`, widens: true })
  if (fewer.length) lines.push({ text: `No longer ${noun(fewer)}`, widens: false })
  return lines
}

export function describeScopeChange(before: DeviceScope, after: DeviceScope, projectNames: ReadonlyMap<string, string>): ChangeLine[] {
  const name = (id: string) => projectNames.get(id) ?? id
  const lines = [
    ...listChange(before.tags, after.tags, "every credential", (tags) => `credentials tagged ${joinWords(tags, "or")}`),
    ...listChange(before.projects.map(name), after.projects.map(name), "every project", (projects) => joinWords(projects)),
  ]
  for (const mode of added(before.modes, after.modes)) {
    lines.push({ text: `May now use ${MODE_WORDS[mode].label.toLowerCase()}: ${MODE_WORDS[mode].words}`, widens: true })
  }
  for (const mode of added(after.modes, before.modes)) lines.push({ text: `May no longer use ${MODE_WORDS[mode].label.toLowerCase()}`, widens: false })
  if (before.maxEnvironment !== after.maxEnvironment) {
    lines.push(
      after.maxEnvironment === "protected"
        ? { text: "Protected environments too (prod); each use still needs your approval", widens: true }
        : { text: "Unprotected environments only; no more protected runs", widens: false },
    )
  }
  return lines
}

export type RemoteChange = { project: string; remote: string; bound: boolean }

// The digest the item.update step-up signs, as the vault computes it in
// remoteChangeDigest (vault/areas/projects.ts).
export function remoteChangeDigest(change: RemoteChange): Promise<string> {
  return digestOf({ change: change.bound ? "remote.bind" : "remote.unbind", project: change.project, remote: change.remote })
}
