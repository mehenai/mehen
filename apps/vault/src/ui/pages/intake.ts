// An agent asked for a credential. The page says who asked and why, where
// the secret will be allowed to go, who may use it, and takes the values.
// Every string an agent wrote or a human typed is spelled through cardText
// at the point it is rendered, so a hidden or control character shows as a
// marker instead of steering what the human reads.
// Inputs have no `name` and the form has no submit button, so nothing is
// ever posted natively: the browser code seals each secret before anything
// leaves. For a template that carries a `setup`, the page also walks
// through the provider's console, with the vault's redirect URI in a copy
// box where an OAuth client needs one.

import type { Injection, IntakeView } from "@mehen/protocol/api"
import { isLeaseOnly, leaseOnlyDelivery } from "@mehen/protocol/binding"
import { KINDS } from "@mehen/protocol/kinds"
import { type SetupStep, type Template, getTemplate } from "@mehen/protocol/templates"
import { type StepInput, cardText, copyBox, countdownTimer, destinationBlock, hostList, injectionWords, pill, plainText, requesterDetails, stateCard, steps, taskLine, whoMayUse } from "../components.ts"
import { type Html, html, safeHref } from "../html.ts"
import { icon, kindTile, serviceTile } from "../icons.ts"
import type { PageInput, Viewer } from "../layout.ts"
import { TAGS_ARE_ONE_LIMIT, askerAsks, askerName, bindingLimits, formatTime, isMemberAsk, patternWords, requestCommand, tagsChosenWords } from "../wording.ts"
import { intakeNeedsAcceptance, intakeSigninPages } from "../client/logic.ts"

// Intake links last 24 hours; the ring counts down from there.
const INTAKE_TOTAL_SECONDS = 24 * 3600

type Field = IntakeView["fields"][number]

function titleOf(view: IntakeView): string {
  return view.providerName ?? KINDS[view.kind]?.label ?? view.kind
}

function tileOf(view: IntakeView): Html {
  return view.provider !== null ? serviceTile({ provider: view.provider, slug: view.slug }, "xl") : kindTile(view.kind, undefined, "xl")
}

// The template behind a verified intake, when it carries a guided setup.
function setupOf(view: IntakeView): Template | null {
  if (!view.binding.verified || view.provider === null || view.rotates) return null
  const template = getTemplate(view.provider)
  return template?.setup ? template : null
}

function docsLinkText(url: string): string {
  try {
    const parsed = new URL(url)
    return `${parsed.host}${parsed.pathname === "/" ? "" : parsed.pathname}`
  } catch {
    return url
  }
}

function setupStep(step: SetupStep, template: Template, redirectUri: string | null, index: number): StepInput {
  const docs = step.docs && template.docsUrl !== null ? html` <a href="${safeHref(template.docsUrl)}" target="_blank" rel="noopener">${docsLinkText(template.docsUrl)} ${icon("external", "inline")}</a>` : ""
  const warn = step.warn !== undefined ? html`<div class="callout">${icon("alert")}<span>${step.warn}</span></div>` : ""
  const copy = step.redirectUri && redirectUri !== null ? copyBox(redirectUri) : ""
  return { title: step.title, body: html`${step.body}${docs}${copy}${warn}`, state: index === 0 ? "current" : "todo", field: step.field }
}

function setupCard(view: IntakeView, template: Template, origin: string): Html {
  const setup = template.setup
  if (!setup) return html``
  const redirectUri = setup.redirectUri !== undefined ? `${origin}${setup.redirectUri}` : null
  const name = view.providerName ?? template.displayName
  return html`<section class="card" aria-label="Setting up the ${name}" data-region="intake-setup">
    <h2>${setup.title}</h2>
    <p class="small muted">About five minutes. The steps tick as the fields below fill in; they are a guide, not a gate.</p>
    ${steps(setup.steps.map((step, i) => setupStep(step, template, redirectUri, i)))}
  </section>`
}

type FieldShape = { words: string; literals: string[] }

// The shape the template expects of a field's value, as its hint names it.
function fieldShape(field: Field, template: Template | null): FieldShape | null {
  const pattern = template?.fields[field.name]?.pattern
  return pattern !== undefined ? patternWords(pattern) : null
}

function literalWords(literals: readonly string[]): Html {
  return html`${literals.map((l, i) => html`${i > 0 ? " or " : ""}<code>${l}</code>`)}`
}

// Revealed by the page while the value lacks the expected shape: a nudge,
// never a gate, and it never repeats the value.
function shapeWarning(shape: FieldShape): Html {
  const miss = shape.words === "Starts" ? "start with" : "end in"
  return html`<span class="callout field-warn" data-region="field-warn" hidden role="status">${icon("alert")}<span>This does not ${miss} ${literalWords(shape.literals)}. Check you copied the right value, and all of it; you can still save it.</span></span>`
}

function fieldHint(field: Field, shape: FieldShape | null): Html {
  const words = shape !== null ? html`${shape.words} ${literalWords(shape.literals)}. ` : ""
  const promise = field.secret ? "Sealed in this browser before it is sent. Mehen has no page that shows the stored value again; the vault decrypts it only to use it, and a lease the workspace allows can pass it to a program." : ""
  const tone = field.secret ? pill("sealed", "accent", false) : ""
  if (words === "" && promise === "" && field.hint === null) return html``
  return html`<span class="hint">${tone}${words}${field.hint !== null ? html`${field.hint} ` : ""}${promise}</span>${shape !== null ? shapeWarning(shape) : ""}`
}

function fieldInput(field: Field, template: Template | null): Html {
  const shape = fieldShape(field, template)
  const expect = shape === null ? "" : html` data-expect-${shape.words === "Starts" ? "start" : "end"}="${shape.literals.join(" ")}"`
  const common = html`data-field="${field.name}"${expect} autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"${field.required ? html` required` : ""}`
  const control = field.multiline
    ? html`<textarea ${common} rows="5" class="${field.secret ? "secret" : "mono"}"></textarea>`
    : html`<input type="${field.secret ? "password" : "text"}" ${common} class="mono">`
  return html`<label class="field${field.secret ? " sealed" : ""}">
    <span class="label">${field.label}${field.required ? "" : html` <span class="muted">(optional)</span>`}</span>
    ${control}
    ${fieldHint(field, shape)}
  </label>`
}

function rotationDestination(view: IntakeView): Html {
  const limits = bindingLimits(view.binding.value)
  return html`<section class="card dest" aria-label="Where this secret may go">
    <p class="eyebrow">Keeps going only to</p>
    ${hostList(view.binding.value.hosts)}
    ${limits.length ? html`<ul class="limits">${limits.map((l) => html`<li>${cardText(l)}</li>`)}</ul>` : ""}
    <p class="dest-note">These are the credential's current destinations. Replacing the secret cannot change them; do that from <a href="/items/${encodeURIComponent(view.slug)}">the credential's own page</a>.</p>
  </section>`
}

// Shown only when the agent proposed it: how the relay will put the
// secret into each request.
function proposedInjectionBlock(injection: Injection): Html {
  return html`<section class="card dest unverified" aria-label="How this secret is sent" data-region="intake-injection">
    <p class="eyebrow">Proposed by the agent, not verified</p>
    <p class="dest-warning">The agent wants the vault to put this secret into each request like this. Check it is what the service expects.</p>
    <p>${injectionWords(injection)}</p>
  </section>`
}

// No template vouches for what agents may do with this credential, so every
// request waits for the human's approval unless they tick reads here.
function allowReadsTick(): Html {
  return html`<label class="tick"><input type="checkbox" data-input="allow-reads">
    <span>Let agents read with it without asking (GET, HEAD and OPTIONS requests). Everything else waits for your approval. You can change this later on the credential's page.</span></label>`
}

// "How may agents use it?" on a new password-login where typing into web
// pages is on (no Sign in for them yet). Type it into the sign-in page
// is signed as the fill ceiling; Not at all, as it starts, signs nothing new.
// The sign-in page line follows the address typed (client intakeSigninPages).
function fillChoice(view: IntakeView): Html {
  const pages = intakeSigninPages("", view.binding.value)
  return html`<fieldset class="field" data-region="fill-choice"><legend class="label">How may agents use it?</legend>
    <div><label class="tick"><input type="radio" name="fill-ceiling" data-input="fill-ceiling" value="fill"><span><strong>Type it into the sign-in page</strong> mehen types it in only after checking the page's address. A script on that page, including one the agent runs, can read it.</span></label>
    <label class="tick"><input type="radio" name="fill-ceiling" data-input="fill-ceiling" value="relay" checked><span><strong>Not at all</strong> Only you can use it.</span></label></div>
    <p class="hint" data-region="fill-signin-page"${pages.words === null ? html` hidden` : ""}>${pages.words ?? ""}</p>
    <p class="hint" data-region="fill-https-only" hidden>Only https sign-in pages can be filled.</p>
  </fieldset>`
}

// The asker chose these tags; they decide which machines may use the new
// credential, so the human sees them before signing over them.
function machinesBlock(view: IntakeView): Html {
  const unique = [...new Set(view.tags)]
  const chose = tagsChosenWords(view.requestedBy, "save", "request")
  return html`<section class="card" aria-label="Which machines may use it" data-region="intake-tags">
    <p class="eyebrow">Who may use it</p>
    ${unique.length
      ? html`<p class="lead">${whoMayUse(unique)}.</p>
          <p class="small muted" data-region="intake-tags-advice">${TAGS_ARE_ONE_LIMIT} ${chose}</p>`
      : html`<p class="lead">No tags: only machines allowed every credential can use it.</p>
          <p class="small muted" data-region="intake-tags-advice">${TAGS_ARE_ONE_LIMIT}</p>`}
  </section>`
}

// The way to ask again: ask the agent that asked (no app link: the page
// does not know which agent or app that is), and the mehen command as a copy
// box only when every part of it is plain text, so the box copies exactly
// what is read. The
// command carries no destination, so it is offered only where the template
// or the existing credential supplies one, and not for a client a connect
// was waiting on, which it would ask for alone. An ask a member made from
// Connect a service is started again from there.
function askAgain(view: IntakeView): { primary: Html | undefined; or: Html | undefined } {
  const by = view.requestedBy
  if (isMemberAsk(by)) {
    return { primary: html`<a class="btn primary" href="/connect">${icon("grid")}<span>Start again from Connect a service</span></a>`, or: undefined }
  }
  const primary = undefined
  const device = cardText(by.deviceName)
  const slug = cardText(view.slug)
  if (view.then !== undefined) return { primary, or: html`<p>Ask the agent on ${device} to start connecting the account again.</p>` }
  if (!view.rotates && !view.binding.verified && !isLeaseOnly(view.binding.value)) {
    return { primary, or: html`<p>Ask the agent on ${device} to request <code>${slug}</code> again; its proposed destination cannot be repeated from a command here.</p>` }
  }
  const parts = [view.kind, view.slug, view.provider ?? "", ...view.tags, view.reason]
  const or = parts.every(plainText)
    ? html`<p>Ask the agent on ${device} for a new link, or run this on the machine that asked:</p>${copyBox(requestCommand(view))}`
    : html`<p>Ask the agent on ${device} to request <code>${slug}</code> again. The reason it gave holds hidden or control characters, so no command is offered to copy.</p>`
  return { primary, or }
}

// What a closed link was for, above its state card.
function closedHead(view: IntakeView): Html {
  const slug = cardText(view.slug)
  return html`<section class="card intake-head" data-region="intake-head">
    <div class="item-head">
      ${tileOf(view)}
      <div class="item-head-text">
        <h1>${view.rotates ? slug : cardText(titleOf(view))}</h1>
        <p class="item-sub">${view.rotates ? html`A new secret for ${cardText(titleOf(view))}` : html`<code class="slug-inline">${slug}</code>`}</p>
      </div>
    </div>
  </section>`
}

function closedCard(view: IntakeView): Html {
  const asker = cardText(askerName(view.requestedBy))
  const slug = cardText(view.slug)
  switch (view.status) {
    case "completed":
      return stateCard({
        tone: "ok",
        icon: "check",
        level: 2,
        heading: "Already filled in",
        lead: view.rotates
          ? html`This request has been completed. The new secret for <code>${slug}</code> is stored.`
          : html`This request has been completed. <code>${slug}</code> is stored. ${whoMayUse(view.tags, " now")}.`,
        primary: html`<a class="btn secondary" href="/items/${encodeURIComponent(view.slug)}">Open the credential</a>`,
      })
    case "expired": {
      const { primary, or } = askAgain(view)
      return stateCard({
        tone: "expired",
        level: 2,
        icon: "clock",
        heading: html`This link ran out at ${formatTime(view.expiresAt)}`,
        lead: isMemberAsk(view.requestedBy)
          ? html`Nothing happened and nothing was stored. Start <code>${slug}</code> again when you are ready.`
          : html`Nothing happened and nothing was stored. ${asker} still needs <code>${slug}</code>; a new link takes a moment to ask for.`,
        primary,
        or,
      })
    }
    case "cancelled": {
      const { primary, or } = askAgain(view)
      if (view.superseded) {
        return stateCard({
          tone: "muted",
          icon: "refresh",
          level: 2,
          heading: "Replaced by a newer request",
          lead: html`${asker} asked again for <code>${slug}</code> with a newer link, so this one was closed. Nothing was stored here. Open the newer link from where it was posted, or from what needs you.`,
          primary: html`<a class="btn primary" href="/#needs-you">${icon("arrowRight")}<span>Open what needs you</span></a>`,
        })
      }
      return stateCard({
        tone: "muted",
        icon: "x",
        level: 2,
        heading: "This request was cancelled",
        lead: html`Nothing was stored. ${asker} may still need <code>${slug}</code>.`,
        primary,
        or,
      })
    }
    case "open":
      return html``
  }
}

function expiredCard(view: IntakeView): Html {
  const { primary, or } = askAgain(view)
  return html`<div data-region="intake-expired" hidden>${stateCard({
    tone: "expired",
    icon: "clock",
    level: 2,
    heading: html`This link ran out at ${formatTime(view.expiresAt)}`,
    lead: html`Nothing was stored. The form no longer saves; ${isMemberAsk(view.requestedBy) ? "start again from Connect a service" : "ask for a new link"}.`,
    primary,
    or,
  })}</div>`
}

function headCard(view: IntakeView, now: number): Html {
  const slug = cardText(view.slug)
  const who = view.rotates ? html`Keeps its destination and its machines.` : html`${whoMayUse(view.tags)}.`
  return html`<section class="card intake-head" data-region="intake-head">
    <div class="item-head">
      ${tileOf(view)}
      <div class="item-head-text">
        <p class="eyebrow">${cardText(askerAsks(view.requestedBy, view.rotates ? "replace the secret of" : "paste"))}</p>
        <h1>${view.rotates ? slug : cardText(titleOf(view))}</h1>
        ${taskLine(view.requestedBy)}
        <p class="item-sub">${view.then !== undefined ? html`<b>Step 1 of 2.</b> ` : ""}${view.rotates ? "" : html`Will be saved as <code class="slug-inline">${slug}</code>. `}${who} <span class="when">${countdownTimer(view.expiresAt, INTAKE_TOTAL_SECONDS, now)}, single use.</span></p>
      </div>
    </div>
    ${view.then !== undefined ? html`<div class="progress" aria-label="Step 1 of 2"><span class="current"></span><span></span></div><p class="small muted then-note">After saving, this page goes straight on to step 2: connecting the account.</p>` : ""}
    ${view.rotates ? html`<p class="rotation">This replaces the secret of the existing credential <code class="slug-inline">${slug}</code>. The vault stops using the old value as soon as you save. It still works at the service until you revoke it there.</p>` : ""}
    <details class="fold">
      <summary>${icon("chevronRight")}<span>${isMemberAsk(view.requestedBy) ? "Where this came from" : "Why it is asking"}</span></summary>
      <blockquote class="reason">${cardText(view.reason)}</blockquote>
      <dl class="kv small">
        ${requesterDetails(view.requestedBy)}
      </dl>
    </details>
  </section>`
}

function doneLead(view: IntakeView): Html {
  const slug = cardText(view.slug)
  if (view.then !== undefined) return html`The credential is stored as <code>${slug}</code>. Going on to step 2, connecting the account.`
  if (view.rotates) return html`The new secret for <code>${slug}</code> is stored, and the vault no longer uses the old value. It still works at the service until you revoke it there. You can close this page.`
  return html`The credential is stored as <code>${slug}</code>. ${whoMayUse(view.tags, " now")}, and only at the destination shown. You can close this page.`
}

function doneCard(view: IntakeView): Html {
  const then = view.then
  return html`<div data-region="intake-done" hidden>${stateCard({
    tone: "ok",
    icon: "check",
    level: 2,
    heading: "Saved",
    lead: doneLead(view),
    primary:
      then !== undefined
        ? html`<a class="btn primary" href="/c/${encodeURIComponent(then.connect)}">${icon("arrowRight")}<span>Continue to step 2</span></a>`
        : html`<a class="btn secondary" href="/items/${encodeURIComponent(view.slug)}">Open the credential</a>`,
  })}</div>`
}

// What turns the save button on, said under it.
function buttonHint(view: IntakeView, needsAcceptance: boolean): string {
  const required = view.fields.filter((f) => f.required).length
  const which = required === view.fields.length ? "" : "required "
  const fill = required === 0 ? null : `the ${which}${required > 1 ? "fields are" : "field is"} filled in`
  const conditions = [fill, needsAcceptance ? "the box is ticked" : null].filter((c): c is string => c !== null)
  return `${conditions.length > 0 ? `Turns on when ${conditions.join(" and ")}. ` : ""}Saving asks for your passkey.`
}

// `fill`: typing into web pages is on, so a new password-login offers the choice.
export function intakePage(viewer: Viewer, view: IntakeView, origin: string, now = Date.now(), fill = false): PageInput {
  if (view.status !== "open") {
    return {
      title: "Credential request",
      viewer,
      focus: true,
      boot: { page: "intake-closed", intake: view.intake },
      body: html`${closedHead(view)}${closedCard(view)}`,
    }
  }
  const verified = view.binding.verified
  // A rotation keeps the item's existing destination, which a human set
  // before, and a lease-only credential has none: nothing to accept.
  const needsAcceptance = intakeNeedsAcceptance({ verified, rotates: view.rotates, binding: view.binding.value })
  const template = setupOf(view)
  const hints = verified && view.provider !== null ? getTemplate(view.provider) : null
  const destination = view.rotates ? rotationDestination(view) : destinationBlock(view.binding.value, verified, view.providerName, leaseOnlyDelivery(view.kind, KINDS[view.kind].defaultCeiling))
  const injection = !view.rotates && !view.injection.verified && view.injection.value !== null ? proposedInjectionBlock(view.injection.value) : ""
  const offerFill = fill && view.kind === "password-login" && !view.rotates
  return {
    title: view.rotates ? `Replace ${view.slug}` : `Add ${view.slug}`,
    viewer,
    focus: true,
    wide: true,
    boot: {
      page: "intake",
      intake: view.intake,
      slug: view.slug,
      binding: view.binding.value,
      verified,
      rotates: view.rotates,
      tags: view.tags,
      customPolicy: view.customPolicy,
      ...(offerFill ? { fillChoice: true } : {}),
      fields: view.fields.map((f) => ({ name: f.name, label: f.label, secret: f.secret, required: f.required, multiline: f.multiline })),
      sealKey: view.sealKey,
      expiresAt: view.expiresAt,
      ...(view.then !== undefined ? { then: view.then.connect } : {}),
    },
    body: html`${headCard(view, now)}
      <div class="two-col" data-region="intake-columns">
        <div class="col-main">
          ${template !== null ? setupCard(view, template, origin) : ""}
          ${needsAcceptance ? html`${destination}${injection}` : ""}
          <section class="card" data-region="intake-form">
            <h2>${template?.kind === "oauth-client" ? "Paste the client" : "Fill it in"}</h2>
            <form class="stack" data-form="intake" autocomplete="off" novalidate>
              ${view.fields.map((f) => fieldInput(f, hints))}
              ${offerFill ? fillChoice(view) : ""}
              ${view.customPolicy ? allowReadsTick() : ""}
              ${!needsAcceptance
                ? ""
                : html`<label class="tick danger-tick"><input type="checkbox" data-input="accept-destination">
                    <span>I have read every host above and I accept that this secret may be sent ${view.binding.value.hosts.length === 1 ? "there" : "to all of them"}${view.injection.verified ? "" : ", in the way the agent proposed"}.</span></label>`}
              <button type="button" class="btn primary" data-action="submit-intake" disabled>${view.then !== undefined ? "Seal, save and go to step 2" : "Seal and save with passkey"}</button>
              <p class="hint">${buttonHint(view, needsAcceptance)}</p>
            </form>
          </section>
          ${doneCard(view)}
        </div>
        <div class="col-side">
          ${needsAcceptance ? "" : html`${destination}${injection}`}
          ${view.rotates ? "" : machinesBlock(view)}
        </div>
      </div>
      ${expiredCard(view)}`,
  }
}
