// The warnings an ask page shows before a person decides: a
// page passes every string it renders, and gets back the warning for hidden
// text-direction or invisible characters and the one for control
// characters, each once, in that order. The rules are the cards' own
// (relay/spelling.ts textWarnings), so every ask page and the rescope card
// warn on exactly what the approval card warns on.
//
// Each ask page family names the strings it shows here, in one list per
// family, so a field added to a page is added to its warnings in the same
// place. A warned page leads with the warning card, and its declining
// action becomes the filled danger button while the accepting one goes
// quiet (decisionEmphasis); the accepting action stays behind its checks.

import type { PolicyAreaOffer, PolicyRuleOffer } from "@mehen/protocol/policy-mode"
import type { WorkspaceApprovalView, WorkspaceConnectView, WorkspaceEnrolView, WorkspaceIntakeView, WorkspacePolicyProposalView, WorkspaceRef } from "@mehen/protocol/workspace"
import { mapCardText } from "../relay/presentation.ts"
import { textWarnings } from "../relay/spelling.ts"
import type { ApprovalPresentation } from "../vault/services.ts"

export function askWarnings(texts: readonly string[]): string[] {
  return textWarnings(texts)
}

// The vault's own warnings first, then those the page finds, each once.
export function mergedWarnings(stored: readonly string[], texts: readonly string[]): string[] {
  return [...stored, ...askWarnings(texts).filter((w) => !stored.includes(w))]
}

export type ButtonTone = "primary" | "secondary" | "quiet" | "danger"

// The two actions' button classes. Unwarned: the accepting action is the
// primary and the declining one secondary. Warned: the declining action is
// filled danger, in the primary position, and the accepting one is quiet.
export function decisionEmphasis(warned: boolean): { decline: ButtonTone; accept: ButtonTone } {
  return warned ? { decline: "danger", accept: "quiet" } : { decline: "secondary", accept: "primary" }
}

function workspaceTexts(workspace: Pick<WorkspaceRef, "name" | "slug">): string[] {
  return [workspace.name, workspace.slug]
}

function ownerName(owner: { kind: string; name: string }): string {
  return owner.name
}

type ApprovalDetail = Extract<WorkspaceApprovalView, { view: "detail" }>["approval"]
type ApprovalStop = Exclude<WorkspaceApprovalView, { view: "detail" }>

// A rule offer's path choices and every string of its terms.
// A task grant offer: its terms' strings and every area the panel lists.
function areaOfferTexts(offer: PolicyAreaOffer | undefined): string[] {
  if (offer === undefined || offer.terms === null) return []
  const t = offer.terms
  return [...offer.areas.flatMap((a) => [a.id, a.name, a.words]), t.item, t.itemId, t.asker.device, t.asker.workload ?? "", t.host, t.catalogue, ...t.areas]
}

function ruleOfferTexts(offer: PolicyRuleOffer | undefined): string[] {
  if (offer === undefined || offer.terms === null) return []
  const t = offer.terms
  return [...offer.pathChoices, t.item, t.itemId, t.asker.device, t.asker.workload ?? "", t.method, t.host, t.path, t.anchorPath, ...t.queryNames, ...(t.graphql?.fields ?? []), ...(t.graphql?.nestedFields ?? [])]
}

// An approval: the workspace, the owner, the credential, who asked (the
// task included), the request line, the binding code, the deciders and the
// eligibility reason, every string of the stored card (title, details,
// body, warnings, headers and the email's recipients, headers, sections and
// attachments), a rule offer's path choices and terms, and a task grant
// offer's terms and areas.
export function approvalTexts(a: ApprovalDetail, run: { credentials: readonly { variable: string; slug: string | null }[] } | null = null): string[] {
  const texts = [
    ...workspaceTexts(a.workspace),
    ownerName(a.owner),
    a.item.slug,
    a.item.account ?? "",
    a.item.provider ?? "",
    a.requestedBy.deviceName,
    a.requestedBy.device,
    a.requestedBy.session ?? "",
    a.requestedBy.workload?.label ?? "",
    a.request.method,
    a.request.url,
    a.request.contentType ?? "",
    a.request.contentEncoding ?? "",
    a.bindingCode,
    ...(a.request.headers ?? []).flat(),
    ...a.eligibility.deciders,
    a.eligibility.reason ?? "",
    ...(a.decidedBy?.name !== undefined && a.decidedBy?.name !== null ? [a.decidedBy.name] : []),
    ...(run?.credentials ?? []).flatMap((c) => [c.variable, c.slug ?? ""]),
    ...ruleOfferTexts(a.rememberOptions?.rule),
    ...areaOfferTexts(a.rememberOptions?.area),
  ]
  const stored: ApprovalPresentation = { title: a.title, details: a.details, body: a.request.body, warnings: a.warnings, ...(a.email !== null ? { email: a.email } : {}) }
  mapCardText(stored, (text) => {
    texts.push(text)
    return text
  })
  return texts
}

// A stop view shows the workspace, the machine, its owner and the
// credential's name, and nothing else.
export function stopTexts(view: ApprovalStop | Extract<WorkspacePolicyProposalView, { view: "stop" }>): string[] {
  return [...workspaceTexts(view.workspace), view.machine.name, ownerName(view.machine.owner), view.item?.slug ?? ""]
}

// Every string inside a structured value (a destination, an injection).
export function stringsOf(value: unknown): string[] {
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.flatMap(stringsOf)
  if (typeof value === "object" && value !== null) return Object.entries(value).flatMap(([k, v]) => [k, ...stringsOf(v)])
  return []
}

function requesterTexts(by: WorkspaceIntakeView["requestedBy"] | WorkspaceConnectView["requestedBy"]): string[] {
  return "deviceName" in by ? [by.deviceName, by.device, by.session ?? ""] : []
}

// An intake: who asked and why, the name it will be saved as, the service,
// every destination and limit, the injection the agent proposed, the tags,
// and each field's label and hint.
export function intakeTexts(view: WorkspaceIntakeView): string[] {
  const binding = view.binding.value
  return [
    ...requesterTexts(view.requestedBy),
    view.reason,
    view.slug,
    view.kind,
    view.provider ?? "",
    view.providerName ?? "",
    ...stringsOf(binding),
    ...stringsOf(view.injection.value),
    ...view.tags,
    ...view.fields.flatMap((f) => [f.name, f.label, f.hint ?? ""]),
  ]
}

// A connect: who asked and why, the name it will be saved as, the account
// to expect, every scope, and the stored outcome's account and message.
export function connectTexts(view: WorkspaceConnectView): string[] {
  return [...requesterTexts(view.requestedBy), view.reason, view.slug, view.provider, view.providerName, view.expect ?? "", ...view.scopes, ...view.tags, ...(view.currentScopes ?? []), view.account ?? "", view.message ?? ""]
}

// An enrolment: the machine's name and host, where, when and by what it
// was asked, where the viewer is, the team or person it is for, who
// accepted it, who claimed it, and every scope entry.
export function enrolTexts(view: WorkspaceEnrolView): string[] {
  return [
    ...workspaceTexts(view.workspace),
    view.name,
    view.host ?? "",
    view.start.place ?? "",
    view.start.clientLabel,
    view.acceptorPlace ?? "",
    view.requestedOwner.kind === "team" ? view.requestedOwner.name : "",
    view.owner !== null ? ownerName(view.owner) : "",
    view.claimed?.name ?? "",
    ...view.scope.tags,
    ...view.scope.projects,
    ...view.fingerprint.words.map((w) => w.word),
  ]
}
