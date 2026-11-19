// The approval card's parts for a push (design push-providers 4): where the
// value goes with the facts the provider gave before anyone decided, which
// store and name, which value with its prefix and fingerprint, what carries
// it, who can read it there, any other detail the vault sent, the agent's
// reason as its own words, the exact request without the JSON it hashes,
// and how far the push got. The vault's
// warnings stay in the warning card the page puts first; nothing here
// repeats, hides or rewords them. pages/workspace-asks.ts renders these.

import type { ApprovalView } from "@mehen/protocol/api"
import { type PushApprovalView, type PushDestination, parsePushDestination } from "@mehen/protocol/push"
import { cardText, pill } from "./components.ts"
import { type Html, html } from "./html.ts"
import { PUSH_HASH_HEADING, PUSH_HASH_WORDS, pushExistsWords, pushOutcomeWords, pushReadersWords, pushStoreWords, pushWhereWords } from "./push-wording.ts"
import { RULE_REASON_WORDS, detailLabelWords } from "./wording.ts"

// The pushed field as `mehen show` describes it, read as the viewing person
// and only for the version the push names; null leaves the line out.
export type PushedValueFacts = { prefix: string | null; fingerprint: string }

// The push an approval asks for, when its subject is one and its
// destination reads; null for any other approval.
export function approvalPush(a: ApprovalView): { push: PushApprovalView; destination: PushDestination } | null {
  if (a.request.method !== "PUSH" || a.push === undefined) return null
  const destination = parsePushDestination(a.push.destination)
  return destination === null ? null : { push: a.push, destination }
}

function detailOf(a: ApprovalView, label: string): string | null {
  return a.details.find((d) => d.label === label)?.value ?? null
}

// The details the push card draws itself; any other the vault sends is
// shown after the summary as every approval shows its details.
const PUSH_CARD_DETAILS: ReadonlySet<string> = new Set(["Where", "Value", "Using", "The agent says"])

function otherDetails(a: ApprovalView): Html | string {
  const rows = a.details.filter((d) => !PUSH_CARD_DETAILS.has(d.label) && d.value !== a.title)
  if (rows.length === 0) return ""
  return html`<dl class="summary" data-region="push-details">${rows.map((d) => html`<dt>${cardText(detailLabelWords(d.label))}</dt><dd>${cardText(d.value)}</dd>`)}</dl>`
}

// New destination, Fork of and Public repository, each from a structured
// field the vault sent, never from a warning's words.
function wherePills(push: PushApprovalView): Html {
  const preview = push.preview?.provider === "github" ? push.preview : null
  return html`${push.newDestination ? html` ${pill("New destination", "danger", false)}` : ""}${preview?.fork === true ? html` <span class="pill danger">Fork of ${cardText(preview.parent ?? "another repository")}</span>` : ""}${preview?.private === false ? html` ${pill("Public repository", "warn", false)}` : ""}`
}

export function pushSummary(a: ApprovalView, push: PushApprovalView, d: PushDestination, value: PushedValueFacts | null): Html {
  const using = detailOf(a, "Using") ?? push.via
  return html`<dl class="summary" data-region="push-summary">
    <dt>Where</dt><dd data-region="push-where">${cardText(pushWhereWords(d, push.preview))}${wherePills(push)}</dd>
    <dt>Store</dt><dd>${cardText(pushStoreWords(d))}</dd>
    <dt>Name</dt><dd><code>${cardText(d.name)}</code><br><span class="small muted" data-region="push-exists">${cardText(pushExistsWords(push.preview))}</span></dd>
    <dt>Value</dt><dd><code>${cardText(a.item.slug)}</code>, field <code>${cardText(push.field)}</code>, version ${String(push.version)}${value !== null ? html`<br><span class="small muted" data-region="push-value-facts">${value.prefix !== null ? html`starts <code>${cardText(value.prefix)}</code>, ` : ""}fingerprint <code>${cardText(value.fingerprint)}</code></span>` : ""}</dd>
    <dt>Using</dt><dd>${cardText(using)}</dd>
    <dt>Who can read it there</dt><dd>${cardText(pushReadersWords(d))}</dd>
  </dl>${otherDetails(a)}`
}

// The agent's reason, quoted as its own words: the vault checks none of it.
export function pushReason(a: ApprovalView): Html | string {
  const reason = detailOf(a, "The agent says")
  if (reason === null) return ""
  return html`<div data-region="push-reason"><p class="eyebrow">The agent says</p><p class="small muted">${RULE_REASON_WORDS}</p><blockquote class="reason">${cardText(reason)}</blockquote></div>`
}

// How far the push got once it was approved; nothing while it waits.
export function pushOutcome(push: PushApprovalView, d: PushDestination): Html | string {
  const words = pushOutcomeWords(push, d.provider)
  if (words === null) return ""
  const tone = push.state === "done" ? "ok" : push.state === "queued" || push.state === "sending" ? "muted" : "danger"
  return html`<p class="strip" data-region="push-outcome" data-state="${push.state}">${pill(words, tone)}</p>`
}

// The exact request a push approval binds: PUSH, its canonical URL and the
// body's hash, with the fields the hash covers named from what this view
// already shows. The hashed JSON names the via's id, which this view may
// not show, so it is not printed.
export function pushRequestCard(a: ApprovalView, push: PushApprovalView): Html {
  return html`<section class="card" aria-label="The exact request" data-region="exact-request">
    <h2>The exact request</h2>
    <p class="request-line"><span class="method">${cardText(a.request.method)}</span> <code class="url">${cardText(a.request.url)}</code></p>
    <h3>${PUSH_HASH_HEADING}</h3>
    <p class="muted small">${PUSH_HASH_WORDS}</p>
    <dl class="kv small" data-region="push-hashed">
      <dt>Credential</dt><dd><code>${cardText(a.item.slug)}</code></dd>
      <dt>Field</dt><dd><code>${cardText(push.field)}</code></dd>
      <dt>Version</dt><dd>${String(push.version)}</dd>
      <dt>Destination</dt><dd><code>${cardText(push.destination)}</code></dd>
      <dt>Using</dt><dd><code>${cardText(push.via)}</code></dd>
    </dl>
    <dl class="kv small"><dt>Body SHA-256</dt><dd><code class="hash">${a.request.bodySha256}</code></dd></dl>
  </section>`
}
