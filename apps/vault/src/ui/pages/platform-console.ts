// What the operator's pages (operator.ts) and a platform admin's pages
// (platform-admin.ts) share: a platform's status, its subjects counted by
// status, the last day's usage, its keys, its limits, its events, and the
// fields every form uses: a public key pasted or made in this browser
// (whose private half is shown once and never sent), the rotation overlap
// and the slug typed back. The data is the console routes' own answers
// (@mehen/protocol/platform-console). Nothing here reads inside a managed
// workspace: the pages have only the platform's row, keys and events.

import type { OperatorPlatformSummary, PlatformEventPage, PlatformEventView, PlatformKeyView, PlatformUsage, SubjectCountsByStatus } from "@mehen/protocol/platform-console"
import { PLATFORM_KEY_MAX_OVERLAP_HOURS } from "@mehen/protocol/platform-console"
import type { PlatformLimits, PlatformStatus } from "@mehen/protocol/platform"
import { PKCS8_IMPORT_LINE } from "../client/platform-key-logic.ts"
import { type PillTone, cardText, emptyState, kv, notice, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"

// ---------------------------------------------------------------- status

// The status facts both consoles have; the operator's answer adds who set
// the status, why, and who registered the platform.
export type ConsoleStatus = Pick<OperatorPlatformSummary, "id" | "slug" | "name" | "status" | "statusAt" | "retireAfter"> & Partial<Pick<OperatorPlatformSummary, "statusBy" | "statusReason" | "createdAt" | "createdBy">>

const STATUS_WORDS: Readonly<Record<PlatformStatus, string>> = { active: "Active", suspended: "Suspended", retiring: "Retiring", retired: "Retired" }
const STATUS_TONE: Readonly<Record<PlatformStatus, PillTone>> = { active: "ok", suspended: "danger", retiring: "warn", retired: "muted" }

export function platformStatusPill(status: PlatformStatus): Html {
  return pill(STATUS_WORDS[status], STATUS_TONE[status])
}

// The actor as the record names it: operator:<who>, admin:<account id>,
// platform:<key id> or system.
export function actorText(actor: string): Html {
  return html`<code>${cardText(actor)}</code>`
}

// "Suspended since <time> by operator:alex: abuse report.", then the
// retirement date when there is one.
export function statusLine(platform: ConsoleStatus): Html {
  const by = platform.statusBy !== undefined ? html` by ${actorText(platform.statusBy)}` : ""
  const reason = platform.statusReason !== undefined && platform.statusReason !== null ? html`: ${cardText(platform.statusReason)}` : ""
  const retire = platform.retireAfter !== null ? html`. Retires after ${timeTag(platform.retireAfter)}` : ""
  return html`${STATUS_WORDS[platform.status]} since ${timeTag(platform.statusAt)}${by}${reason}${retire}.`
}

export function platformFacts(platform: ConsoleStatus): Html {
  return kv([
    ["Slug", html`<code>${platform.slug}</code>`],
    ["Platform id", html`<code>${platform.id}</code>`],
    ["Status", html`${platformStatusPill(platform.status)} <span class="small">${statusLine(platform)}</span>`],
    ...(platform.createdAt !== undefined ? ([["Registered", html`${timeTag(platform.createdAt)}${platform.createdBy !== undefined ? html` by ${actorText(platform.createdBy)}` : ""}`]] as const) : []),
  ], "facts")
}

// ---------------------------------------------------------------- subjects and usage

const SUBJECT_STATUSES = ["creating", "active", "deleting", "deleted", "purged"] as const satisfies readonly (keyof SubjectCountsByStatus)[]
const SUBJECT_WORDS: Readonly<Record<keyof SubjectCountsByStatus, string>> = { creating: "being made", active: "active", deleting: "being deleted", deleted: "deleted, audit kept", purged: "purged" }

export function liveSubjects(counts: SubjectCountsByStatus): number {
  return counts.creating + counts.active
}

export function subjectStats(counts: SubjectCountsByStatus): Html {
  return html`<div class="stats" data-region="subject-counts">${SUBJECT_STATUSES.map((status) => html`<span class="stat${status === "deleting" && counts.deleting > 0 ? " danger" : ""}"><b>${counts[status]}</b><span>${SUBJECT_WORDS[status]}</span></span>`)}</div>`
}

export function usageBlock(usage: PlatformUsage): Html {
  if (usage === null) return html`<p class="small muted" data-region="usage-counts">No usage copied yet. The cron copies the last 24 hours every 15 minutes.</p>`
  const stat = (n: number, words: string, danger = false) => html`<span class="stat${danger && n > 0 ? " danger" : ""}"><b>${n}</b><span>${words}</span></span>`
  return html`<div class="stack" data-region="usage-counts"><div class="stats">
      ${stat(usage.devices, "devices made")}${stat(usage.itemsAdded, "items added")}${stat(usage.itemsDeleted, "items deleted")}${stat(usage.decisions, "decisions")}${stat(usage.refusals, "refusals", true)}
    </div><p class="small muted">The last 24 hours, as of ${timeTag(usage.asOf)}.</p></div>`
}

// ---------------------------------------------------------------- keys

export type KeyState = "live" | "ending" | "ended" | "revoked"

// `live` is the vault's own: neither revoked nor past its expiry. A live
// key with an expiry was rotated out and is inside its overlap.
export function keyState(key: PlatformKeyView): KeyState {
  if (key.revokedAt !== null) return "revoked"
  if (!key.live) return "ended"
  return key.expiresAt === null ? "live" : "ending"
}

function keyStateWords(key: PlatformKeyView): Html {
  switch (keyState(key)) {
    case "live":
      return pill("Live", "ok")
    case "ending":
      return html`${pill("Ending", "warn")} <span class="small muted">works until ${timeTag(key.expiresAt as string)}</span>`
    case "ended":
      return html`${pill("Ended", "muted")}${key.expiresAt !== null ? html` <span class="small muted">${timeTag(key.expiresAt)}</span>` : ""}`
    case "revoked":
      return html`${pill("Revoked", "muted")} <span class="small muted">${timeTag(key.revokedAt as string)}</span>`
  }
}

export function keyList(keys: readonly PlatformKeyView[]): Html {
  if (keys.length === 0) return emptyState("key", "No keys", "This platform has no key, so it cannot sign a call.")
  return html`<ul class="rows" data-region="keys">${keys.map((key) => html`<li class="row" data-key-row="${key.id}"><span class="row-main"><span class="row-title"><code>${key.id}</code> ${keyStateWords(key)}</span>
    <span class="row-sub">Added ${timeTag(key.createdAt)} by ${actorText(key.createdBy)}</span><span class="row-sub">Thumbprint <code class="key-thumbprint">${key.thumbprint}</code></span></span></li>`)}</ul>`
}

// Revoking a key: one of the live keys, picked, and the slug typed back.
// `keepLast` (an admin) offers only a key that leaves another live key with
// no expiry, as the vault requires: ending the platform's last key, now or
// once an overlap ends, is the operator's.
export function revokeKeyFold(slug: string, keys: readonly PlatformKeyView[], keepLast: boolean): Html {
  const live = keys.filter((k) => k.live)
  if (live.length === 0) return html``
  const offered = keepLast ? live.filter((k) => live.some((o) => o.id !== k.id && o.expiresAt === null)) : live
  if (offered.length === 0) return html`<p class="small muted" data-region="last-key">${live.length === 1 ? "Its one live key cannot" : "No key can"} be revoked here, as that would leave the platform with no key once its other keys end: add a new key first, or ask Mehen's operator.</p>`
  return html`<details class="fold" data-region="revoke-key"><summary>${icon("chevronRight")}<span>Revoke a key</span></summary>
    <form class="stack" data-form="revoke-key" novalidate>
      <p class="small">It ends at once: every call it signs is refused from now. ${keepLast ? "Only a key that leaves another with no end is listed. For a leak, add the platform's new key with 0 hours instead: that ends every other key at once." : "Use it for a leak, then add the platform's new key with 0 hours."}</p>
      <label class="field"><span class="label">Key</span><select data-input="key">${offered.map((k) => html`<option value="${k.id}">${k.id}${k.expiresAt !== null ? ", ending" : ""}</option>`)}</select></label>
      ${slugConfirm(slug)}
      <div class="actions"><button type="submit" class="btn danger">${icon("passkey")}<span>Revoke with passkey</span></button></div>
    </form></details>`
}

// ---------------------------------------------------------------- the form fields

// Pasted or made here. `form` names the radio group, so two forms on one
// page never share one. A made key's private half goes into `private-key`
// only in the browser, shown once; it is never a form field, so nothing
// submits it, and its region is marked translate="no", so a browser's page
// translation never sends it to a translation service.
export function keyFields(form: string, legend: string): Html {
  return html`<fieldset class="field key-source" data-region="key-source">
    <legend>${legend}</legend>
    <div class="check-list" role="radiogroup">
      <label><input type="radio" name="key-source-${form}" value="paste" data-input="key-source" checked><span>Paste the public key the platform sent</span></label>
      <label><input type="radio" name="key-source-${form}" value="make" data-input="key-source"><span>Make a key pair in this browser</span></label>
    </div>
    <div class="stack" data-region="key-paste">
      <label class="field"><span class="label">Public key, as a JWK</span><textarea data-input="public-jwk" rows="4" spellcheck="false" autocomplete="off" autocapitalize="off" placeholder='{"kty":"EC","crv":"P-256","x":"...","y":"..."}'></textarea><span class="hint">The platform makes its key on its own machine and sends only the public half. Only kty, crv, x and y are kept; a key with a private part is refused.</span></label>
    </div>
    <div class="stack" data-region="key-make" hidden>
      <p class="small muted">For a platform you run yourself. This browser makes the pair and sends only the public half to Mehen. You copy the private half once, into the platform server's secret store.</p>
      <div class="actions"><button type="button" class="btn secondary" data-action="make-key">${icon("key")}<span>Make a key pair</span></button></div>
      <div class="stack" data-region="key-made" translate="no" hidden>
        <div class="warning" role="alert"><b>Copy the private key now. It is shown once.</b> Mehen never receives it and cannot show it again; this page forgets it once the form is accepted, or when you switch to pasting, leave or make another. Whoever holds it can act as the platform. Never paste it into a chat or give it to an agent, and clear your clipboard once you have pasted it into the secret store.</div>
        <div class="field"><span class="label">Private key, PKCS8 in base64url</span><div class="copybox private-key"><code data-region="private-key"></code><button type="button" class="btn secondary sm" data-copy>${icon("copy")}<span>Copy</span></button></div>
          <span class="hint">The platform's server loads it with <code>${PKCS8_IMPORT_LINE}</code>.</span></div>
        <p class="small">Its public half's thumbprint: <code class="key-thumbprint" data-region="key-thumbprint"></code></p>
        <div class="check-list"><label><input type="checkbox" data-input="key-kept"><span>I have put the private key in the platform's secret store</span></label></div>
        <div class="actions"><button type="button" class="btn quiet sm" data-action="forget-key">Forget this key</button></div>
      </div>
    </div>
    <p class="inline-error" role="alert" data-region="key-problem" hidden></p>
  </fieldset>`
}

// The slug typed back, for every destructive change and every key added.
// `null` is a platform being registered, whose slug is the one typed above.
export function slugConfirm(slug: string | null): Html {
  const label = slug === null ? html`Type the slug again to confirm` : html`Type <code>${slug}</code> to confirm`
  return html`<label class="field"><span class="label">${label}</span><input type="text" class="mono" data-input="confirm" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="64" required></label>`
}

// What a key added in the console can do, said before the passkey is asked
// for: it is the platform, as the threat model says.
export function keyPowerLine(): Html {
  return html`<p class="small" data-region="key-power">Whoever holds this key's private half is the platform until the key is revoked: they can provision devices, use every credential by relay, decide held requests, and read item lists and audits in every one of the platform's users' workspaces.</p>`
}

export const OVERLAP_HOURS_DEFAULT = 24

export function overlapField(): Html {
  return html`<label class="field"><span class="label">Hours the other keys keep working</span><input type="text" inputmode="numeric" class="mono" data-input="overlap-hours" value="${OVERLAP_HOURS_DEFAULT}" maxlength="3" autocomplete="off"><span class="hint">0 to ${PLATFORM_KEY_MAX_OVERLAP_HOURS}. Every other live key ends then; deploy the new key inside it. 0 ends them at once, for a leak.</span></label>`
}

// The reason a change is recorded with.
export function reasonField(hint: string): Html {
  return html`<label class="field"><span class="label">Why</span><input type="text" data-input="reason" maxlength="200" required autocomplete="off"><span class="hint">${hint}</span></label>`
}

// ---------------------------------------------------------------- limits

// Each limit, in the words of the platform reference's limits section.
export const LIMIT_WORDS: Readonly<Record<keyof PlatformLimits, { label: string; hint: string }>> = {
  subjects: { label: "Subjects", hint: "Users at once, counting those still being deleted." },
  devicesPerSubject: { label: "Devices per subject", hint: "Live devices in one subject's workspace." },
  itemsPerSubject: { label: "Credentials per subject", hint: "Keys, OAuth apps and connections together." },
  projectsPerSubject: { label: "Projects per subject", hint: "Projects in one subject's workspace." },
  openRequestsPerSubject: { label: "Open requests per subject", hint: "Intakes and connects started and not finished." },
  callsPerMinute: { label: "Calls a minute", hint: "Across all of the platform's subjects." },
  subjectWritesPerMinute: { label: "Writes a minute per subject", hint: "Calls that change something, in one workspace." },
  decisionsPerMinute: { label: "Decisions a minute", hint: "Approvals and denials, across all subjects." },
  subjectDecisionsPerMinute: { label: "Decisions a minute per subject", hint: "Approvals and denials, in one workspace." },
  decisionTtlSeconds: { label: "Decision lifetime, seconds", hint: "The longest an approval the platform gives stays usable." },
  auditRetentionDays: { label: "Audit kept, days", hint: "How long a deleted subject's audit is kept. Secrets go at once." },
}

export const LIMIT_KEYS = Object.keys(LIMIT_WORDS) as (keyof PlatformLimits)[]

export function limitsList(limits: PlatformLimits): Html {
  return kv(LIMIT_KEYS.map((key) => [LIMIT_WORDS[key].label, html`<span class="mono">${limits[key].toLocaleString("en-GB")}</span>`] as const), "facts")
}

// ---------------------------------------------------------------- events

// The record's own action names, in words. Anything else is shown as its
// name, so a new kind of event is never hidden.
const EVENT_WORDS: Readonly<Record<string, string>> = {
  "operator.register": "Registered the platform",
  "operator.suspend": "Suspended it",
  "operator.resume": "Resumed it",
  "operator.rotate_key": "Added a key and set the others to end",
  "operator.revoke_key": "Revoked a key",
  "operator.limits": "Changed its limits",
  "operator.delete_subjects": "Marked every subject for deletion",
  "operator.retire": "Set it to retire",
  "operator.remove": "Started removing it",
  "operator.add_admin": "Added a platform admin",
  "operator.remove_admin": "Removed a platform admin",
  "admin.defaults": "Changed the defaults",
  "admin.rotate_key": "Added a key and set the others to end",
  "admin.revoke_key": "Revoked a key",
  "admin.delete_subject": "Deleted a subject",
  "defaults.put": "The platform changed its defaults",
  "subjects.remove_all": "The platform deleted every subject",
  "platform.retired": "Finished retiring",
  "platform.removed": "Finished removing it and freed its slug",
  "platform.activity": "Copied the last day's usage",
}

// The detail's own plain fields, as short facts: ids, counts and reasons,
// never a secret or a subject's name (the record holds neither).
export function detailFacts(detail: Readonly<Record<string, unknown>>): Html {
  const facts = Object.entries(detail).filter(([, value]) => typeof value === "string" || typeof value === "number" || typeof value === "boolean")
  if (facts.length === 0) return html``
  return html`<span class="row-sub event-facts">${facts.map(([key, value], i) => html`${i > 0 ? " · " : ""}${cardText(key)} <code>${cardText(String(value))}</code>`)}</span>`
}

function eventRow(event: PlatformEventView): Html {
  const words = Object.hasOwn(EVENT_WORDS, event.action) ? EVENT_WORDS[event.action] : undefined
  return html`<li class="row"><span class="row-main"><span class="row-title">${words ?? html`<code>${cardText(event.action)}</code>`}</span><span class="row-sub">${timeTag(event.at)} · ${actorText(event.actor)}</span>${detailFacts(event.detail)}</span></li>`
}

// `older` is the page's own address for the next page, or null at the end.
export function eventsCard(events: PlatformEventPage | null, older: string | null): Html {
  const body = events === null
    ? readFailed("Its events")
    : events.events.length === 0
      ? emptyState("list", "No events yet", "What the operator, its admins, the platform and the cron do to it is recorded here.")
      : html`<ul class="rows platform-events" data-region="events">${events.events.map(eventRow)}</ul>`
  return html`<section class="card" id="events" data-region="events-card"><h2>Events</h2>${body}${older !== null ? html`<p class="small"><a href="${older}">Older events</a></p>` : ""}</section>`
}

// ---------------------------------------------------------------- shared cards

export function readFailed(what: string): Html {
  return notice("warn", `${what} could not be read just now.`, "Reload the page to try again.")
}
