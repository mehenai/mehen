// The ask pages' browser decisions without a DOM: why an accepting action
// is off, and the exact actions a page may sign, each compared member for
// member with what the page showed. The handler tests and the
// Worker journeys use these same functions.

import { canonicalJson } from "@mehen/protocol/canonical-json"
import { type FingerprintWord, fingerprintGroups, fingerprintOf, fingerprintWords, normaliseFingerprintGroup } from "@mehen/protocol/fingerprint"
import type { ApiError } from "@mehen/protocol/api"
import type { CredentialHome, EnrolStartContext, WorkspaceDeviceScope, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { CHECKING_PAGE_WORDS, PAGE_MISMATCH_WORDS, TICK_CODE_WORDS } from "../wording.ts"

// Why the accepting action is off, said in the bar: the tick first, then
// the page's own check against the vault's record.
export function approvalCaption(digest: "checking" | "match" | "mismatch", ticked: boolean): string {
  if (digest === "mismatch") return PAGE_MISMATCH_WORDS
  if (!ticked) return TICK_CODE_WORDS
  return digest === "checking" ? CHECKING_PAGE_WORDS : ""
}

// The decide body a denial sends (PolicyDecideSchema: no effective change).
export const POLICY_DENY_BODY = { decision: "deny", effectiveChange: null } as const

// Every term of connect.start but the home, as the page read them
// (pages/workspace-asks.ts connectTerms).
export type ConnectTerms = { provider: string; slug: string; tags: string[]; expectedAccount: string | null; scopes: string[]; intent: "create" | "rotate"; target: string | null; targetRevision: number | null; client: string | null; clientRevision: number | null; dependencyRevision: number }

export const CONNECT_CLIENT_UNKNOWN: ApiError = { error: "conflict", message: "This page does not know which OAuth client the connection signs in through, so it will not ask for your passkey.", next: { say: "Nothing was signed. Reload the page; if this persists, add the client first." } }

// The one connect.start this page may sign: every term it showed, with the
// home the person chose; null when the page did not see a client.
export function connectStartExpected(connect: string, terms: ConnectTerms, home: CredentialHome): WorkspaceStepUpAction | null {
  if (terms.client === null || terms.clientRevision === null) return null
  return { type: "connect.start", connect, provider: terms.provider, slug: terms.slug, home, tags: terms.tags, expectedAccount: terms.expectedAccount, scopes: terms.scopes, intent: terms.intent, target: terms.target, targetRevision: terms.targetRevision, client: terms.client, clientRevision: terms.clientRevision, dependencyRevision: terms.dependencyRevision }
}

// What the enrolment page showed: the three visible groups, which one is
// hidden, the words; and, when it offers acceptance, every term of the
// enrol.accept it will sign but the thumbprint.
export type ShownFingerprint = { groups: string[]; hidden: number; words: FingerprintWord[] }
export type ShownAcceptance = { workspace: string; enrolment: string; account: string; member: string; scope: WorkspaceDeviceScope; start: EnrolStartContext }

const ACCEPT_KEYS = ["account", "enrolment", "member", "scope", "start", "thumbprint", "type", "workspace"]

// Why the planned acceptance is not the one this page showed, or null when
// it is: the action family and its exact members, every term but the
// thumbprint equal to the page's with the private-credentials choice
// applied, and the thumbprint's own fingerprint equal to the groups and
// words shown, its hidden group the one typed.
export function acceptanceMismatch(planned: unknown, shown: ShownAcceptance, fingerprint: ShownFingerprint, privateCredentials: boolean, typed: string): string | null {
  if (typeof planned !== "object" || planned === null) return "no action"
  const a = planned as Record<string, unknown>
  if (a.type !== "enrol.accept") return "another kind of action"
  if (JSON.stringify(Object.keys(a).sort()) !== JSON.stringify(ACCEPT_KEYS)) return "other members"
  const { thumbprint, type: _type, ...terms } = a
  if (canonicalJson(terms) !== canonicalJson({ ...shown, scope: { ...shown.scope, privateCredentials } })) return "other terms"
  if (typeof thumbprint !== "string") return "no key"
  let groups: string[]
  let words: FingerprintWord[]
  try {
    groups = [...fingerprintGroups(fingerprintOf(thumbprint))]
    words = fingerprintWords(thumbprint)
  } catch {
    return "a malformed key"
  }
  const visible = groups.filter((_, i) => i !== fingerprint.hidden)
  if (JSON.stringify(visible) !== JSON.stringify(fingerprint.groups)) return "another key"
  if (groups[fingerprint.hidden] !== normaliseFingerprintGroup(typed)) return "another key"
  if (canonicalJson(words) !== canonicalJson(fingerprint.words)) return "another key"
  return null
}
