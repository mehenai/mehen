// One spelling of a credential home as a form value, shared by the ask
// pages and their browser code: the radio's value names the home exactly,
// a private home with its member, so the browser signs the home the person
// picked from the list the vault permitted, never one rebuilt from words.

import type { CredentialHome } from "@mehen/protocol/workspace"

export function homeKey(home: CredentialHome): string {
  return home.kind === "project" ? `project:${home.project}` : home.kind === "member" ? `member:${home.member}` : "workspace"
}

// The permitted home a value names, or null when it names none of them.
export function homeOfKey(key: string, permitted: readonly CredentialHome[]): CredentialHome | null {
  return permitted.find((h) => homeKey(h) === key) ?? null
}
