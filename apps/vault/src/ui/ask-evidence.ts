// The evidence blocks every ask page shows a person before they decide:
// the warning card for text the vault could not show as it is, every header
// forwarded with a request, and an email's recipients, headers, sections
// and attachments. The workspace approval page (pages/workspace-asks.ts)
// renders them.
//
// The workspace ask pages also share the parts of one decision layout
// from here: the warning card that comes first on a warned
// page, the "Technical details" fold the digests go into, and the decision
// bar fixed to the foot of the page.

import type { ApprovalEmail } from "@mehen/protocol/api"
import { type ButtonTone, decisionEmphasis } from "./ask-safety.ts"
import { cardText, pill } from "./components.ts"
import { type Html, html } from "./html.ts"
import { icon } from "./icons.ts"
import { TECHNICAL_DETAILS_WORDS } from "./wording.ts"

// The first thing on a warned workspace ask page: an error notice (role
// alert) with every warning, before the decision card.
export function warningCard(warnings: readonly string[]): Html | string {
  if (warnings.length === 0) return ""
  return html`<div class="notice error ask-warnings" role="alert" data-region="warnings"><p class="notice-title">${icon("alert")}<span>Check this request yourself</span></p><ul>${warnings.map((w) => html`<li>${cardText(w)}</li>`)}</ul></div>`
}

// The digests a person need not read to decide, folded: "Technical
// details", each as a term and a value.
export function technicalFold(rows: readonly (readonly [string, Html | string])[], after: Html | string = ""): Html {
  return html`<details class="fold card technical" data-region="technical">
    <summary>${icon("chevronRight")}<span>${TECHNICAL_DETAILS_WORDS}</span></summary>
    <dl class="kv small" data-region="binding">${rows.map(([term, value]) => html`<dt>${term}</dt><dd>${value}</dd>`)}</dl>
    ${after}
  </details>`
}

// "Northwind (northwind) at app.mehen.dev": the workspace once, calm, at
// the head of a line of context.
export function askPlace(origin: string, workspace: { name: string; slug: string }): Html {
  let host = origin
  try {
    host = new URL(origin).host
  } catch {
    // An origin that is not a URL is shown as given.
  }
  return html`In <b>${cardText(workspace.name)}</b> (<code>${workspace.slug}</code>) at ${host}`
}

// One action in the decision bar. `form` ties the button to the decision
// card's form (id "decide"), so the bar outside the card still belongs to
// it; the page's script finds the button by its data-action.
export type BarAction = { action: string; label: Html | string; passkey?: boolean; disabled?: boolean; tone?: ButtonTone; attributes?: Html }

function barButton(action: BarAction, tone: ButtonTone, form: string | null): Html {
  return html`<button type="button"${form !== null ? html` form="${form}"` : ""} class="btn ${action.tone ?? tone}" data-action="${action.action}"${action.attributes ?? ""}${action.disabled === true ? html` disabled` : ""}>${action.passkey === true ? icon("passkey") : ""}<span>${action.label}</span></button>`
}

export type DecisionBarInput = {
  warned: boolean
  // The id of the decision card's form, or null on a page without one.
  form: string | null
  // The terms line, such as "Once, within 10 minutes" and its Change.
  terms?: Html | string
  // Why the accepting action is off, updated by the page's script.
  caption?: Html | string
  // Folded choices that open from the terms line (the approval's terms).
  fold?: Html | string
  decline: BarAction | null
  accept: BarAction | null
  // Further accepting actions, never emphasised: the approval page's
  // Approve and allow this from now on, and its task grant's Approve, and
  // let this agent carry on, beside Approve once.
  alsoAccept?: BarAction | readonly BarAction[] | null
}

// The fixed bar at the foot of an ask page: the declining action first in
// the document, the accepting one after it. Emphasis follows the warning
// (decisionEmphasis); CSS puts the emphasised action on the right, and
// lowest when the two stack.
export function decisionBar(input: DecisionBarInput): Html {
  const tones = decisionEmphasis(input.warned)
  return html`<div class="bar${input.warned ? " warned" : ""}" role="group" aria-label="Decide" data-region="bar">
    <div class="bar-inner">
      <p class="terms">${input.terms ?? ""}<span class="bar-caption" data-region="bar-caption" aria-live="polite">${input.caption ?? ""}</span></p>
      ${input.fold ?? ""}
      ${input.decline !== null ? barButton(input.decline, tones.decline, input.form) : ""}${(input.alsoAccept ? ([] as BarAction[]).concat(input.alsoAccept) : []).map((also) => barButton(also, input.warned ? "quiet" : "secondary", input.form))}
      ${input.accept !== null ? barButton(input.accept, tones.accept, input.form) : ""}
    </div>
  </div>`
}

export function warningsBlock(warnings: readonly string[]): Html | string {
  if (warnings.length === 0) return ""
  return html`<section class="card unreadable" role="alert">
    <p class="eyebrow">${icon("alert")}<span>Warning</span></p>
    <h2>Check this request yourself</h2>
    <ul>${warnings.map((w) => html`<li>${cardText(w)}</li>`)}</ul>
  </section>`
}

function formatSize(n: number): string {
  if (n < 1024) return `${n} bytes`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

// Every header forwarded from the agent, each name and value as text,
// spelled for reading (the list itself is as sent, and the boot carries
// it for the browser's recompute). The credential the vault adds is not
// among them; the digest binds the rest.
// The workspace page passes withDigest false and shows the digest in its
// technical fold instead.
export function headersBlock(headers: readonly [string, string][], headersSha256: string, withDigest = true): Html {
  return html`<section class="card request-headers">
    <h2>Headers sent with the request</h2>
    <p class="muted small">Every header the agent's request carries to the service, as sent. The credential the vault adds is not among them.</p>
    ${headers.length > 0
      ? html`<dl class="kv small">${headers.map(([name, value]) => html`<dt><code>${cardText(name)}</code></dt><dd>${value !== "" ? html`<code>${cardText(value)}</code>` : html`<span class="muted">empty</span>`}</dd>`)}</dl>`
      : html`<p class="lead">None.</p>`}
    ${withDigest ? html`<dl class="kv small"><dt>Headers SHA-256</dt><dd><code class="hash">${headersSha256}</code></dd></dl>` : ""}
  </section>`
}

export function emailBlocks(email: ApprovalEmail): Html {
  const external = email.recipients.filter((r) => r.external).length
  const count = email.recipients.length
  const outside = email.accountDomain === null ? "external" : html`outside ${cardText(email.accountDomain)}`
  return html`<section class="card recipients">
      <h2>Recipients</h2>
      <p class="count-line"><b class="count-big">${count}</b> <span class="muted">${count === 1 ? "recipient" : "recipients"} across To, Cc and Bcc${external > 0 ? "," : ""}</span>${external > 0 ? html` <span class="refused">${external} ${outside}</span>` : ""}</p>
      <p class="muted small">${email.accountDomain !== null ? html`External means not at <code>${cardText(email.accountDomain)}</code>, the account's own domain.` : "The account's own domain is not known, so every recipient counts as external."}</p>
      ${count > 0
        ? html`<ul class="recipients">${email.recipients.map((r) => html`<li><span class="hdr">${cardText(r.header)}</span><code>${cardText(r.address)}</code>${r.external ? pill("external", "danger", false) : ""}</li>`)}</ul>`
        : html`<p class="lead">Nobody: this message has no To, Cc or Bcc.</p>`}
    </section>
    <section class="card">
      <h2>Every header</h2>
      <dl class="kv">${email.headers.map((h) => html`<dt${h.highlight ? html` class="hl"` : ""}>${cardText(h.name)}</dt><dd${h.highlight ? html` class="hl"` : ""}>${cardText(h.value)}</dd>`)}</dl>
    </section>
    ${email.sections.map(
      (s) => html`<section class="card">
        <h2>${cardText(s.heading)}</h2>
        ${s.note !== null ? html`<p class="muted small">${cardText(s.note)}</p>` : ""}
        <pre class="request-body" tabindex="0">${cardText(s.text)}</pre>
      </section>`,
    )}
    ${email.attachments.length > 0
      ? html`<section class="card">
        <h2>Attachments</h2>
        ${email.attachments.map(
          (a) => html`<div class="attachment">
            <p><strong>${cardText(a.name)}</strong> <span class="muted">${cardText(a.type)}, ${formatSize(a.bytes)}</span></p>
            ${a.text !== null ? html`<pre class="request-body" tabindex="0">${cardText(a.text)}</pre>` : html`<dl class="kv small"><dt>SHA-256</dt><dd><code>${a.sha256 ?? ""}</code></dd></dl>`}
          </div>`,
        )}
      </section>`
      : ""}`
}
