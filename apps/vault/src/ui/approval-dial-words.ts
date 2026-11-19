// The approval dial's words, shared by the settings page and its browser
// side: each level's name and one line saying what it does, what Let it
// work never covers, and the line that says what a change signs. No
// imports beyond types, so the browser's bundle may carry it.
import type { ApprovalDial } from "@mehen/protocol/workspace"

export const APPROVAL_DIAL_TITLE = "How often Mehen asks"
export const APPROVAL_DIAL_LEAD = "For every agent in this workspace. Each credential's own How careful setting still applies, and neither level reaches past a credential's binding or the requests that always ask."
export const APPROVAL_DIAL_LABEL = "Agents in this workspace"
export const APPROVAL_DIAL_CHOICES: Readonly<Record<ApprovalDial, { name: string; words: string }>> = {
  writes: { name: "Ask on writes", words: "A person decides the requests a credential's rules hold, for most services its writes. The default." },
  work: { name: "Let it work", words: "What a trusted machine could send goes through without asking; anything that would still need a person is refused, not asked." },
}
// What Let it work does not cover, one line each, and the catalogue it reads.
export const APPROVAL_DIAL_WORK_LIMITS: readonly string[] = [
  "Protected environments still need a person.",
  "Browser fill still needs a person.",
  "Pushes into other services still need a person.",
  "Machines trust does not reach, such as team machines and guests', are refused, not asked.",
  "It follows Mehen's reviewed service templates as they are updated, without a new passkey.",
]
export const APPROVAL_DIAL_WORK_LIMITS_LABEL = "With Let it work"
export const APPROVAL_DIAL_SAVE = "Save"
export const APPROVAL_DIAL_SAVE_PASSKEY = "Save with passkey"
export const APPROVAL_DIAL_READ_ONLY = "Only an owner or admin can change it."
export const APPROVAL_DIAL_FROZEN = "While the workspace is frozen it can only be set to ask more often."

export function approvalDialSignsWords(before: ApprovalDial, after: ApprovalDial, less: boolean): string {
  const from = APPROVAL_DIAL_CHOICES[before].name, to = APPROVAL_DIAL_CHOICES[after].name
  return less ? `Your passkey signs this change: from ${from} to ${to}.` : `No passkey needed to ask more often: from ${from} to ${to}.`
}
