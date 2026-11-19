// Plain-language wording shared by the server pages and the browser code.
// No DOM and no Worker APIs, so both sides import it.

import type { BindingInput, PendingKind, PolicyInput, RequestedBy } from "@mehen/protocol/api"
import { ORIGIN_LIST_MAX } from "@mehen/protocol/fill"
import type { MandateClass, MandateSchedule, MandateState } from "@mehen/protocol/mandate-terms"
import { type Mode, MODES } from "@mehen/protocol/kinds"
import type { PolicyRuleRefusal } from "@mehen/protocol/policy-mode"
import { type PolicySummary, type PolicySummaryOptions, describeRuleMatchers, summarisePolicy } from "@mehen/protocol/policy-summary"
import { type PushProvider, parsePushDestination, pushDestinationWords } from "@mehen/protocol/push"
import type { ApprovalDial } from "@mehen/protocol/workspace"
import { APPROVAL_DIAL_CHOICES } from "./approval-dial-words.ts"

export const MODE_WORDS: Record<Mode, { label: string; words: string }> = {
  relay: { label: "Relay", words: "the vault makes the call; nothing leaves it" },
  sign: { label: "Sign", words: "the vault returns a signature, never the key" },
  mint: { label: "Mint", words: "the vault hands out a short-lived derived token" },
  placeholder: { label: "Placeholder", words: "programs get a stand-in that only works through the vault" },
  fill: { label: "Fill", words: "mehen types the value into a web page you allowed, after checking its address" },
  lease: { label: "Lease", words: "the real value goes into one program on the machine" },
  reveal: { label: "Reveal", words: "a person can see the value in the browser" },
}

// The credential page's In web pages card (pages/workspace-credentials.ts):
// adding a page of another service, a page fill could never use, and a page
// past the most one list keeps.
export const TYPE_INTO_WARNING = "This puts the credential into another service. Every time asks you first."
export const WEB_PAGE_HTTPS_ONLY = { signin: "Only https sign-in pages can be filled.", typeInto: "Only https pages can be typed into." } as const
export const WEB_PAGES_AT_MOST = `A credential can list at most ${ORIGIN_LIST_MAX} pages here.`

export function modesUpTo(ceiling: Mode): Mode[] {
  return MODES.slice(0, MODES.indexOf(ceiling) + 1)
}

// What happens to requests no rule matches, as the end of a sentence about
// them: "Requests no rule matches are allowed", "... will now be refused",
// "(before, they needed your approval)".
export const POLICY_WORDS: Record<PolicyInput["default"], { are: string; willBe: string; were: string }> = {
  allow: { are: "are allowed", willBe: "be allowed", were: "were allowed" },
  approve: { are: "need your approval", willBe: "need your approval", were: "needed your approval" },
  deny: { are: "are refused", willBe: "be refused", were: "were refused" },
}

// Least permissive first.
export const POLICY_ORDER: PolicyInput["default"][] = ["deny", "approve", "allow"]

export function joinWords(items: readonly string[], last = "and"): string {
  if (items.length <= 1) return items[0] ?? ""
  return `${items.slice(0, -1).join(", ")} ${last} ${items[items.length - 1]}`
}

function pathSegmentWords(segment: string): string {
  return segment === "**" ? "<anything>" : segment === "*" ? "<any>" : segment
}

// A binding's path glob as a person reads it: "/v1/**" is "anything under
// /v1/", "/repos/*/pulls" is "/repos/<any>/pulls", "/**" is "any path".
export function pathWords(pattern: string): string {
  const segments = pattern.split("/")
  if (segments.length > 1 && segments.at(-1) === "**") {
    const base = segments.slice(0, -1).map(pathSegmentWords).join("/")
    return base === "" ? "any path" : `anything under ${base}/`
  }
  return segments.map(pathSegmentWords).join("/")
}

// The parts of a binding beyond its hosts, spelled out. Absent means any,
// and so does a method of *.
export function bindingLimits(binding: BindingInput): string[] {
  const out: string[] = []
  if (binding.schemes?.length) out.push(`Only over ${joinWords(binding.schemes, "or")}`)
  if (binding.ports?.length) out.push(`Only on port ${joinWords(binding.ports.map(String), "or")}`)
  if (binding.paths?.length) out.push(`Only to ${joinWords(binding.paths.map(pathWords), "or")}`)
  if (binding.methods?.includes("*")) out.push("With any method")
  else if (binding.methods?.length) out.push(`Only with ${joinWords(binding.methods.map((m) => m.toUpperCase()), "or")} requests`)
  return out
}

export function describeRule(rule: PolicyInput["rules"][number]): string {
  const action = rule.action === "allow" ? "Allow" : rule.action === "approve" ? "Ask before" : "Refuse"
  const methods = rule.methods?.length ? joinWords(rule.methods.map((m) => m.toUpperCase()), "or") : "any"
  const paths = rule.paths?.length ? ` to ${joinWords(rule.paths, "or")}` : ""
  const body =
    rule.body === "graphql-mutation"
      ? " whose body is a GraphQL mutation or cannot be read as a query"
      : rule.body === "graphql-query"
        ? " whose body is a single read-only GraphQL query, with nothing in the URL's query string"
        : ""
  const note = rule.note ? ` (${rule.note})` : ""
  return `${action} ${methods} requests${paths}${body}${note}`
}

const SCOPE_WORDS: Record<string, string> = {
  openid: "Confirm who you are",
  email: "See your email address",
  profile: "See your name and profile picture",
  "userinfo.email": "See your email address",
  "userinfo.profile": "See your name and profile picture",
  "gmail.readonly": "Read your email",
  "gmail.modify": "Read, label, archive and draft email. Sending still needs your approval each time.",
  "gmail.compose": "Draft and send email",
  "gmail.send": "Send email as you",
  "gmail.labels": "Manage your email labels",
  "gmail.settings.basic": "Change your Gmail settings",
  "gmail.metadata": "See your email's headers and labels, not the messages",
  "gmail.insert": "Add messages to your mailbox",
  "calendar.readonly": "See your calendars",
  "calendar.events": "See and change events on your calendars",
  calendar: "See and change everything on your calendars",
  "calendar.events.readonly": "See events on your calendars",
  "calendar.freebusy": "See when you are free or busy",
  "drive.readonly": "See all your Google Drive files",
  "drive.file": "Only the Drive files this app creates or you open with it",
  drive: "See, change and delete all your Google Drive files",
  "drive.metadata.readonly": "See the names and details of your Drive files, not their contents",
  "drive.appdata": "Keep its own settings in your Drive",
  "contacts.readonly": "See your contacts",
  offline_access: "Keep access while you are away (a refresh token)",
  "User.Read": "Sign you in and read your profile",
  "Mail.Read": "Read your email",
  "Mail.ReadWrite": "Read, change and delete your email",
  "Mail.Send": "Send email as you",
  "Calendars.Read": "See your calendars",
  "Calendars.ReadWrite": "See and change your calendars",
  "Contacts.Read": "See your contacts",
  "Contacts.ReadWrite": "See and change your contacts",
  "Files.Read": "See your OneDrive files",
  "Files.ReadWrite": "See, change and delete your OneDrive files",
  "Tasks.ReadWrite": "See and change your tasks",
  repo: "Full control of your repositories, private ones included",
  "public_repo": "Change your public repositories",
  "read:user": "Read your profile",
  "user:email": "See your email addresses",
  "read:org": "See your organisations and teams",
  workflow: "Change GitHub Actions workflows",
  gist: "Create and change your gists",
  notifications: "See your notifications and mark them read",
  "read:project": "See your projects",
  project: "See and change your projects",
}

export function scopeWords(scope: string): string {
  const short = scope.replace(/^https:\/\/www\.googleapis\.com\/auth\//, "")
  return SCOPE_WORDS[short] ?? SCOPE_WORDS[scope] ?? scope
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

export function formatTime(value: string | number): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

// The project share form's end (client/workspace-logic.ts shareFormTerms):
// a UTC day, as formatTime shows every time, the share ending at 23:59 UTC.
export const SHARE_END_HINT = "The share ends at 23:59 UTC on this day, the time zone every time on this page is shown in. Empty means No end."
export const SHARE_NO_LONGER_ENDS_WORDS = "This share will no longer end."
export const SHARE_END_DATE_PROBLEM = "Choose the end as a date, or leave it empty for No end."
export const SHARE_END_PASSED_PROBLEM = "That end date has passed: choose today or a later day, or leave it empty for No end."
export const SHARE_END_TOO_LATE_PROBLEM = "A share must end within 365 days: choose an earlier day."

export function shareEndsLaterWords(expiresAt: string): string {
  return `This share will now end on ${formatTime(expiresAt)}.`
}

export function formatDuration(seconds: number): string {
  if (seconds < 3600) {
    const m = Math.max(1, Math.round(seconds / 60))
    return `${m} minute${m === 1 ? "" : "s"}`
  }
  if (seconds < 86_400) {
    const h = Math.round(seconds / 3600)
    return `${h} hour${h === 1 ? "" : "s"}`
  }
  const d = Math.round(seconds / 86_400)
  return `${d} day${d === 1 ? "" : "s"}`
}

export function expiresIn(iso: string, now = Date.now()): string {
  const ms = new Date(iso).getTime() - now
  if (Number.isNaN(ms)) return iso
  if (ms <= 0) return "expired"
  return `expires in ${formatDuration(ms / 1000)}`
}

export function formatUses(uses: number | null): string {
  if (uses === null) return "as many times as needed"
  return uses === 1 ? "once" : `${uses} times`
}

// An ask a member started from the vault's own pages, as opposed to one an
// agent on a machine made.
export function isMemberAsk(by: RequestedBy): by is { member: string; self: boolean } {
  return "member" in by
}

// Who asked, in words, from vault-known state only: the device name the
// owner approved at enrolment, or, for an ask a member made from the
// vault's pages, "You" when the vault says the reader is that member and
// "Another member" otherwise. The session label is the agent's own claim
// and never reaches this line; pages show it in the details, spelled.
export function askerName(by: RequestedBy): string {
  if (isMemberAsk(by)) return by.self ? "You" : "Another member"
  return `An agent on ${by.deviceName}`
}

// "An agent on Mac mini asks you to paste", "You asked to paste",
// "Another member asked you to paste".
export function askerAsks(by: RequestedBy, verb: string): string {
  if (!isMemberAsk(by)) return `${askerName(by)} asks you to ${verb}`
  return by.self ? `You asked to ${verb}` : `Another member asked you to ${verb}`
}

// Who gets to use what the ask stores: the agent that asked, or, for a
// member's ask, the agents on the machines its tags allow.
export function askerUsers(by: RequestedBy): string {
  return isMemberAsk(by) ? "Your agents" : askerName(by)
}

export const TAGS_ARE_ONE_LIMIT = "Tags are one limit on access. A machine must also reach it through the credential's home, its owner's current rights, its scope and the environment's protection; a matching tag alone grants nothing."

// Who chose an ask's tags, and what to do if they look wrong: not take the
// page's step ("save", "sign in"), and ask the agent again for a new
// "request" or "link", or start a member's ask again from Connect a service.
export function tagsChosenWords(by: RequestedBy, step: string, ask: string): string {
  if (isMemberAsk(by)) return `${askerName(by)} chose these tags. If they look wrong, do not ${step}; start again from Connect a service.`
  return `The agent chose these tags. If they look wrong, do not ${step}; ask for a new ${ask} instead.`
}

// A template field pattern as a hint a person can read: "^GOCSPX-" is
// "Starts GOCSPX-", "\.apps\.googleusercontent\.com$" is "Ends in.
// apps.googleusercontent.com". Anything more complex gets no hint.
export function patternWords(pattern: string): { words: string; literals: string[] } | null {
  const anchoredStart = /^\^(?:\(([^()]+)\))?([^()^$]*)$/.exec(pattern)
  const anchoredEnd = /^([^()^$]+)\$$/.exec(pattern)
  const literal = (text: string): string | null => {
    const plain = text.replace(/\\([.\-_/])/g, "$1")
    return /^[A-Za-z0-9._\-/]*$/.test(plain) ? plain : null
  }
  if (anchoredStart) {
    const alternatives = anchoredStart[1] !== undefined ? anchoredStart[1].split("|") : [anchoredStart[2] ?? ""]
    const tail = anchoredStart[1] !== undefined ? (anchoredStart[2] ?? "") : ""
    const literals = alternatives.map((a) => literal(a + tail))
    if (literals.some((l) => l === null || l === "")) return null
    return { words: "Starts", literals: literals as string[] }
  }
  if (anchoredEnd) {
    const end = literal(anchoredEnd[1] ?? "")
    if (end === null || end === "") return null
    return { words: "Ends in", literals: [end] }
  }
  return null
}

// Quotes one word for a POSIX shell, so a printed command runs as printed.
export function shellQuote(word: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`
}

// The mehen command that would ask for this credential again. The page only
// offers it when every part is plain text (see intake.ts), since a copy
// box must copy exactly what the human reads.
export function requestCommand(view: { kind: string; slug: string; provider: string | null; tags: readonly string[]; reason: string }): string {
  const words = ["mehen", "request", view.kind, "--name", shellQuote(view.slug)]
  if (view.provider !== null) words.push("--provider", shellQuote(view.provider))
  for (const tag of view.tags) words.push("--tag", shellQuote(tag))
  words.push("--reason", shellQuote(view.reason))
  return words.join(" ")
}

// ---------------------------------------------------------------- capability summaries

// Whether a policy's notes may be shown is decided in policy-trust.ts (it
// needs the templates, which the browser bundle should not carry); the
// words are made here from the policy and that decision alone.

type PolicyRule = PolicyInput["rules"][number]

// A rule in a few words for a one-line summary: "GET/HEAD anywhere",
// "POST on /v1/responses", "DELETE on 4 paths".
function shortMatchers(rule: PolicyRule): string {
  const paths = rule.paths ?? []
  if (paths.length <= 1) return describeRuleMatchers({ ...rule, body: undefined })
  const methods = rule.methods && rule.methods.length > 0 ? rule.methods.join("/") : "any method"
  return `${methods} on ${paths.length} paths`
}

// Up to `n` phrases; "and N more" when there are more.
function fewWords(phrases: readonly string[], n: number): string {
  if (phrases.length <= n) return joinWords(phrases)
  const kept = phrases.slice(0, n)
  const rest = phrases.length - n
  return `${kept.join(", ")} and ${rest} more`
}

// One line for a credential row: "reads and creates a draft on its own,
// sends email as you and the rest with your approval". Trusted notes read
// as the template wrote them; otherwise each rule is a few words about
// what it matches. "The rest" always lands where the default sends it, so
// the line never implies an allow the policy does not grant.
export function capabilityLine(policy: PolicyInput, notes: PolicySummaryOptions["notes"]): string {
  const summary: PolicySummary = notes === "trusted" ? summarisePolicy(policy, { notes: "trusted" }) : { allowed: [], approve: [], deny: [], rest: summarisePolicy(policy).rest }
  if (notes === "untrusted") {
    for (const rule of policy.rules) {
      const list = rule.action === "allow" ? summary.allowed : rule.action === "approve" ? summary.approve : summary.deny
      const phrase = shortMatchers(rule)
      if (!list.includes(phrase)) list.push(phrase)
    }
  }
  const withRest = (phrases: readonly string[], n: number, rest: boolean): string => (rest ? `${phrases.slice(0, n).join(", ")} and the rest` : fewWords(phrases, n))
  const own = summary.allowed.length > 0 ? `${withRest(summary.allowed, 2, summary.rest === "allowed")} on its own` : summary.rest === "allowed" ? "everything on its own" : null
  const ask = summary.approve.length > 0 ? `${withRest(summary.approve, 1, summary.rest === "approve")} with your approval` : summary.rest === "approve" ? (own !== null ? "the rest with your approval" : "every call with your approval") : null
  const refused = summary.rest === "deny" ? (own !== null || ask !== null ? "the rest refused" : "every call refused") : null
  return [own, ask, refused].filter((p): p is string => p !== null).join(", ")
}

// ---------------------------------------------------------------- relative times

const MINUTE = 60_000
const HOUR = 3_600_000
const DAY = 86_400_000
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

function dayStart(ms: number): number {
  return Math.floor(ms / DAY) * DAY
}

// "3 min ago", "2 hours ago", "yesterday", "4 days ago", "12 Oct"; null
// for a value that is not a time.
export function relativeAgo(value: string | number, now: number): string | null {
  const at = new Date(value).getTime()
  if (Number.isNaN(at)) return null
  const since = now - at
  if (since < MINUTE) return "just now"
  if (since < HOUR) return `${Math.round(since / MINUTE)} min ago`
  if (since < DAY) {
    const h = Math.round(since / HOUR)
    return `${h} hour${h === 1 ? "" : "s"} ago`
  }
  const days = Math.round((dayStart(now) - dayStart(at)) / DAY)
  if (days <= 1) return "yesterday"
  if (days < 14) return `${days} days ago`
  const d = new Date(at)
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

// The time column of an activity list: the clock time today, the weekday
// within the week, the date otherwise. UTC, like every time on the pages.
export function activityTime(value: string | number, now: number): string {
  const at = new Date(value).getTime()
  if (Number.isNaN(at)) return String(value)
  const d = new Date(at)
  const pad = (n: number) => String(n).padStart(2, "0")
  if (dayStart(at) === dayStart(now)) return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  if (dayStart(now) - dayStart(at) < 7 * DAY) return WEEKDAYS[d.getUTCDay()] as string
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
}

// Seven labels for a week of days ending today, oldest first.
export function weekLabels(days: readonly { day: string }[]): string[] {
  return days.map((d) => {
    const at = Date.parse(`${d.day}T00:00:00Z`)
    return Number.isNaN(at) ? d.day : (WEEKDAYS[new Date(at).getUTCDay()] as string)
  })
}

// ---------------------------------------------------------------- run approvals

// A run approval that is stale, or that changed while its page was built:
// its credentials (a configuration change included) or the access it would
// use are no longer what was requested. No source, value or revision is
// named.
export const CHANGED_SINCE_REQUESTED = "This request changed since it was asked for: a credential it uses, or the access it needs, is no longer what was requested. Nothing can be approved from this page; reload it, or ask the agent to run again for a fresh approval."

export const FOUR_EYES_EXPLAINED = "Four-eyes applies: the machine's owner cannot approve this. Someone else who manages every project whose four-eyes covers these credentials must."

// ---------------------------------------------------------------- enrolment

// The guest's way on once they have accepted: who can admit it, by role,
// never a directory of people.
export const GUEST_ADMISSION_WORDS = "Your machine waits for admission. Send this link to the person who invited you or to a manager of the shared project; they admit it, they never accept it for you."

// ---------------------------------------------------------------- account

// In place of the other sign-ins' End and Sign out everywhere, for a sign-in
// the vault would refuse them to (AccountSessionsRead.mayEndOtherSessions).
export const SESSIONS_RECOVERY_LIMIT_WORDS = "While a recovery is open, only a sign-in made with a passkey from before it can end other sign-ins."

// ---------------------------------------------------------------- ask pages

// The words the ask pages show for the technical ones (// glossary). The API keeps its own words (deny, digest, step-up); a page
// says these.
export const TECHNICAL_DETAILS_WORDS = "Technical details, for checking this page against the agent's record"
export const STOP_VIEW_WORDS = "You may stop this request. Your rights do not include its full details."
export const FOUR_EYES_TITLE = "Needs a second person"
export const SESSION_LABEL_WORDS = "a label the agent chose, not verified"
// A workload's label is the machine's words: it names the task, it proves nothing.
export const TASK_LABEL_WORDS = "as the machine named it"
export const PASSKEY_CONFIRMS_WORDS = "Your passkey confirms."

// A detail label the vault sends, in the page's words.
const DETAIL_LABEL_WORDS: Readonly<Record<string, string>> = { Placeholder: "Stand-in value", "Binding code": "Code" }

export function detailLabelWords(label: string): string {
  return DETAIL_LABEL_WORDS[label] ?? label
}

// What an approval will allow, as the bar's terms line says it: "Once,
// within 10 minutes".
export function allowWords(uses: number | null, ttlSeconds: number): string {
  const words = `${formatUses(uses)}, within ${formatDuration(ttlSeconds)}`
  return words.charAt(0).toUpperCase() + words.slice(1)
}

// The body the approval page shows is the vault's reading of it, not the
// bytes as sent: say so.
export const REQUEST_BODY_HEADING = "The request body, as the vault reads it"
export const REQUEST_BODY_NOTE = "Valid JSON is formatted and form fields decoded for reading; a body that is not UTF-8 text is shown only as its size and cannot be inspected here. The passkey signs the body as it was sent, by the SHA-256 below. Do not approve a request whose contents you cannot verify."

// What happens after each decision, under the decision card.
export const APPROVAL_NEXT_WORDS = "Approving sends the request now; the agent is told either way. Declining tells the agent no and keeps everything as it is."
export const RUN_NEXT_WORDS = "Approving lets this run start once, with these credentials; the agent is told either way. Declining tells the agent no and nothing runs."

// The bar's caption while the accepting action is off, in order.
export const TICK_CODE_WORDS = "Tick the code to continue."
export const CHECKING_PAGE_WORDS = "Checking this page against the vault's record."
export const PAGE_MISMATCH_WORDS = "This page does not match the vault's record, so it cannot be approved here. Decline it, or reload and check again."
export const TYPE_GROUP_WORDS = "This turns on once the typed group matches."
export const GROUP_MATCHES_WORDS = "The group matches. The vault checks it again before you sign."

// ---------------------------------------------------------------- standing rules on the approval page

// The accepting actions when the vault offers a standing rule
// (ApprovalView.rememberOptions.rule). coSign: the approver does not
// manage the credential's home, so a manager of it must co-sign.
export const APPROVE_ONCE_LABEL = "Approve once"
export const APPROVE_AND_ALLOW_LABEL = "Approve and allow this from now on"
export const APPROVE_AND_ASK_MANAGER_LABEL = "Approve once and ask a manager to allow it from now on"
export const RULE_COSIGN_WORDS = "A manager of this credential's home must co-sign before it takes effect."

// The panel that says what allowing it from now on means.
export const RULE_PANEL_TITLE = "From now on, without asking you"
export const RULE_PANEL_LABELS = { credential: "Credential", request: "Request", path: "Path", who: "Who", ttl: "How long", stillAsks: "Still asks", endsSooner: "Ends sooner", context: "Context" } as const
export const RULE_STILL_ASKS_WORDS = "Anything else on this credential, and any request that sends, pays, shares or deletes"
export const RULE_ENDS_SOONER_WORDS = "if access changes or this credential is edited"
export const RULE_ACTING_AS_WORDS = "acting as"
export const RULE_GRAPHQL_WORDS = { lead: "GraphQL mutation", tail: "only" } as const
export const RULE_QUERY_WORDS = "With the query parameters"
export const RULE_QUERY_VALUES_WORDS = "with any values"
export const RULE_PATH_EXACT_WORDS = "exactly this path"
export const RULE_PATH_PATTERN_WORDS = "any number or ID in place of *"
// A rule proposal's reason is the agent's own words: quoted, never checked.
export const RULE_REASON_LABEL = "Agent's reason"
export const RULE_REASON_WORDS = "Written by the agent. The vault does not check it."
export const RULE_MISMATCH_WORDS = "These terms do not match the vault's offer, so this page cannot allow them from now on. Approve once, or reload and check again."

// Who a rule is for: the key that asked, the machine's own or one task's.
export function ruleAskerWords(machine: string, task: string | null): string {
  return task === null ? `This machine, ${machine}` : `Only task ${task} on ${machine}`
}

// The project and environment the approval names, when it names them.
export function ruleContextWords(project: string | null, environment: string | null): string | null {
  const parts = [...(project !== null ? [`project ${project}`] : []), ...(environment !== null ? [`environment ${environment}`] : [])]
  if (parts.length === 0) return null
  const words = joinWords(parts)
  return words.charAt(0).toUpperCase() + words.slice(1)
}

// Why a request asks every time, one line for each refusal code
// (POLICY_RULE_REFUSALS).
export const RULE_REFUSAL_WORDS: Readonly<Record<PolicyRuleRefusal, string>> = {
  "rule.live-key": "This credential holds a live key, so it asks every time.",
  "rule.destination": "This request does not go to a standard HTTPS address, so it asks every time.",
  "rule.method": "Only GET, HEAD, POST, PUT and PATCH requests can be allowed from now on, so this one asks every time.",
  "rule.destructive": "This request deletes or removes something, so it asks every time.",
  "rule.deny": "This credential's rules refuse requests like this one, so it cannot be allowed from now on.",
  "rule.credential": "This request changes credentials or access, so it asks every time.",
  "rule.persistence": "This request sets up something that keeps running, so it asks every time.",
  "rule.sharing": "This request shares or publishes something, so it asks every time.",
  "rule.money": "This request pays or moves money, so it asks every time.",
  "rule.send": "This request sends mail or a message, so it asks every time.",
  "rule.opaque": "The vault cannot read what this request does, so it asks every time.",
  "rule.item-rule": "This credential's own rules ask for this request every time.",
  "rule.generic": "This request's path names something sensitive, so it asks every time.",
  "rule.body": "This request's body cannot be pinned down, so it asks every time.",
  "rule.graphql": "The vault cannot prove which GraphQL mutation this is, so it asks every time.",
  "rule.query": "This request's query string cannot be pinned down, so it asks every time.",
  "rule.binding": "This request reaches wider than the credential's binding lets a rule name, so it asks every time.",
  "rule.path": "No path for this request can become a rule, so it asks every time.",
  "rule.duration": "This request cannot be allowed for 1, 7 or 30 days, so it asks every time.",
  "rule.terms": "This request cannot become a rule, so it asks every time.",
}

// What happened, said in place of the decision once it is signed.
export function ruleAllowedWords(endsAt: number): string {
  return `Approved. Allowed from now on until ${formatTime(endsAt)}.`
}
export const RULE_COSIGN_ASKED_WORDS = "Approved once. Asked a manager of this credential's home to co-sign."
// Approved, and the vault named no rule and no co-sign: nothing is said
// to be allowed from now on.
export const RULE_NOT_NAMED_WORDS = "Approved once. The vault named no rule, so the next request like it may ask again."

// ---------------------------------------------------------------- task grants on the approval page

// Approve, and let the agent carry on with routine building in the areas
// ticked, for a short time and a number of requests (a task grant): the
// panel's words, the third button and what happened once it is signed.
export const AREA_PANEL_TITLE = "Carry on without asking you"
export const AREA_PANEL_LABELS = { credential: "Credential", who: "Who", context: "Context", areas: "Areas", ttl: "How long", uses: "Up to", stillAsks: "Still asks", endsSooner: "Ends sooner" } as const
export const AREA_STILL_ASKS_WORDS = "Deletes, secrets, sending, sharing, payments, and anything outside these areas"
export const AREA_ENDS_SOONER_WORDS = "once it has been used that many times, if access changes or this credential is edited, or when someone stops it"
// The requests a grant may allow, 50 offered first.
export const AREA_USES_CHOICES = [25, 50, 100, 200] as const
export function areaUsesWords(uses: number): string {
  return `${uses} request${uses === 1 ? "" : "s"}`
}
// The third button, naming the areas ticked and the duration chosen.
export function areaApproveLabel(areaNames: readonly string[], ttlSeconds: number): string {
  return `Approve, and let this agent carry on with ${joinWords(areaNames)} for ${formatDuration(ttlSeconds)}`
}
export const APPROVE_AND_ASK_MANAGER_AREA_LABEL = "Approve once and ask a manager to let it carry on"
export const AREA_COSIGN_WORDS = "A manager of this credential's home must co-sign before the agent may carry on."
export const AREA_MISMATCH_WORDS = "These terms do not match the vault's offer, so this page cannot let the agent carry on. Approve once, or reload and check again."
// Why a request cannot start a task grant: the vault's own sentences.
export { AREA_REFUSAL_WORDS } from "../vault/areas/policy-area-refusal-words.ts"
// Approved with a grant: the vault made it in the same transaction as the
// approval, so an approved answer means the grant the passkey signed.
export function areaAllowedWords(ttlSeconds: number, maxUses: number): string {
  return `Approved. The agent may carry on for ${formatDuration(ttlSeconds)}, up to ${areaUsesWords(maxUses)}. My rules shows the task grant and its uses.`
}
export const AREA_COSIGN_ASKED_WORDS = "Approved once. Asked a manager of this credential's home to let the agent carry on."
export const AREA_AREAS_PROBLEM = "Tick at least one of the areas the vault offers."
export const AREA_DURATION_PROBLEM = "Choose 15 minutes, 1 hour or 4 hours."
export const AREA_USES_PROBLEM = "Choose 25, 50, 100 or 200 requests."
export const AREA_TERMS_PROBLEM = "These terms cannot start a task grant."
export const AREA_OFFER_MISMATCH_MESSAGE = "The task grant shown does not match what the vault offers for this approval."
export const AREA_OFFER_MISMATCH_SAY = "Nothing was signed. Approve it once, or reload and check the task grant again."

// ---------------------------------------------------------------- the task grant proposal page

// A task grant waiting for a second person (/w/<slug>/p/<pol_id>): the
// areas, duration and uses as the first person signed them, read only, and
// Approve with passkey or Deny.
export const AREA_PROPOSAL_TITLE = "Let an agent carry on"
export const AREA_COSIGN_EYEBROW = "A task grant waiting for a second person"
export const AREA_PROPOSAL_SIGNED_WORDS = "The areas, how long and how many requests, as they were signed. Approving signs the same."
export const AREA_PROPOSAL_NEXT_WORDS = "Approving lets the agent carry on, or, when a manager of this credential's home must co-sign, waits for them; the agent is told either way. Denying tells the agent no and starts no task grant."
export const AREA_COSIGN_NEXT_WORDS = "Co-signing lets the agent carry on in these areas; the agent is told either way. Denying tells the agent no and starts no task grant."
export const AREA_PROPOSAL_MISMATCH_MESSAGE = "The task grant shown does not match what the vault holds for this proposal."
export const AREA_PROPOSAL_MISMATCH_SAY = "Nothing was signed. Deny it, or reload and check the task grant again."
export const AREA_PROPOSAL_SETTLED_WORDS: Readonly<Record<"approved" | "denied" | "expired" | "cancelled" | "stale", string>> = {
  approved: "It was approved.",
  denied: "It was denied, so no task grant was made and the agent was told no.",
  expired: "Nobody decided in time, so no task grant was made.",
  cancelled: "It was withdrawn, so no task grant was made.",
  stale: "The credential, or the first person's approval, changed since it was signed, so it no longer applies.",
}
export const AREA_PROPOSAL_COSIGN_WORDS = "Approved. A manager of this credential's home must co-sign before the agent may carry on."
export const AREA_PROPOSAL_DENIED_WORDS = "Denied. No task grant was made, and the agent has been told no."
// Approved: the grant the vault made, until its end and up to its uses.
export function areaProposalAllowedWords(endsAt: number, maxUses: number): string {
  return `Approved. The agent may carry on until ${formatTime(endsAt)}, up to ${areaUsesWords(maxUses)}.`
}
// The bar's one line: the areas on the host, for how long, up to how many.
export function areaTermsWords(areaNames: readonly string[], host: string, ttlSeconds: number, maxUses: number): string {
  return `${joinWords(areaNames)} on ${host}, for ${formatDuration(ttlSeconds)}, up to ${areaUsesWords(maxUses)}`
}

// ---------------------------------------------------------------- the rule proposal page

// A machine's proposal to allow a request from now on (/w/<slug>/p/<pol_id>),
// as Needs you names it too.
export const RULE_PROPOSAL_TITLE = "Allow from now on"
export const RULE_COSIGN_EYEBROW = "A rule waiting for a second person"
export const RULE_EXTEND_EYEBROW = "A rule to extend, waiting for a second person"
// The vault ends an extended rule no later than the duration from its
// co-sign, and sooner where an approval it rests on ends first, so the
// title names the duration, not an end.
export function ruleExtendTitle(rule: string, ttlSeconds: number): string {
  return `Extend ${rule} for up to ${formatDuration(ttlSeconds)}`
}
// The card's line is the proposal as it reached this person: the agent's
// own, or the terms a person approved or asked to extend.
export const RULE_AGENT_PROPOSED_LABEL = "The agent proposed:"
export const RULE_PROPOSED_LABEL = "Proposed:"
// The bar's line: the terms with the path and duration chosen, which the
// passkey signs.
export function ruleChosenTermsWords(terms: { method: string; host: string }, path: string, ttlSeconds: number): string {
  return `${terms.method} ${terms.host}${path}, ${formatDuration(ttlSeconds)}`
}
// A proposal lasts a day (policy-rules-workspace.ts PROPOSAL_TTL_MS).
export const RULE_PROPOSAL_TTL_SECONDS = 86_400
export function ruleApprovedByWords(name: string | null): string {
  return `Approved by ${name !== null ? `${name} as the machine's owner` : "the machine's owner"}; a manager of this credential's home must co-sign.`
}
// Why there is no Approve, in the vault's words for its refusals.
export const RULE_PROPOSAL_OWNER_ONLY_WORDS = "Only the machine's owner can allow this from now on."
export const RULE_PROPOSAL_OWN_APPROVAL_WORDS = "You approved this as the machine's owner; a second person must co-sign it."
export const RULE_PROPOSAL_SECOND_PERSON_WORDS = "Only a manager of this credential's home, other than the person who approved it, can co-sign it."
export const RULE_PROPOSAL_READ_ONLY_WORDS = "You can read this proposal. Your rights do not let you approve or deny it."
export const RULE_PROPOSAL_NEXT_WORDS = "Approving makes the rule, or, when a manager of this credential's home must co-sign, waits for them; the agent is told either way. Denying tells the agent no and makes no rule."
export const RULE_COSIGN_NEXT_WORDS = "Co-signing puts the rule in place; the agent is told either way. Denying tells the agent no and makes no rule."
export const RULE_PROPOSAL_PAGE_MISMATCH_WORDS = "This page does not match the vault's record, so it cannot be approved here. Deny it, or reload and check again."
export const RULE_PROPOSAL_MISMATCH_WORDS = "These terms do not match the vault's record of this proposal, so this page cannot approve them. Deny it, or reload and check again."
export const RULE_PROPOSAL_SETTLED_WORDS: Readonly<Record<"approved" | "denied" | "expired" | "cancelled" | "stale", string>> = {
  approved: "It was approved.",
  denied: "It was denied, so no rule was made and the agent was told no.",
  expired: "Nobody decided in time, so no rule was made. The agent can propose it again.",
  cancelled: "The agent withdrew it, so no rule was made.",
  stale: "The credential, or the machine owner's approval, changed since it was proposed, so it no longer applies. The agent can propose it again.",
}

// What deciding a rule proposal did, from the vault's answer.
export const RULE_PROPOSAL_COSIGN_WORDS = "Approved. A manager of this credential's home must co-sign before it takes effect."
export const RULE_PROPOSAL_DENIED_WORDS = "Denied. No rule was made, and the agent has been told no."
export function ruleProposalExtendedWords(rule: string, endsAt: number): string {
  return `Extended. ${rule} now ends ${formatTime(endsAt)}.`
}

// Refusals before the passkey, when the chosen terms are not ones the
// vault offered.
export const RULE_PATH_PROBLEM = "Choose one of the paths the vault offers."
export const RULE_DURATION_PROBLEM = "Choose 1, 7 or 30 days."
export const RULE_TERMS_PROBLEM = "These terms cannot become a rule."
export const RULE_PROPOSAL_DURATION_PROBLEM = "Choose 1, 7 or 30 days, no longer than proposed."
export const RULE_PROPOSAL_MISMATCH_MESSAGE = "The rule shown does not match what the vault holds for this proposal."
export const RULE_PROPOSAL_MISMATCH_SAY = "Nothing was signed. Deny it, or reload and check the rule again."
export const RULE_OFFER_MISMATCH_MESSAGE = "The rule shown does not match what the vault offers for this approval."
export const RULE_OFFER_MISMATCH_SAY = "Nothing was signed. Approve it once, or reload and check the rule again."

// ---------------------------------------------------------------- pending asks

export const PENDING_BUTTON: Record<PendingKind, string> = {
  policy: "Review",
  "policy-review": "Review",
  approval: "Decide",
  intake: "Open",
  connect: "Connect",
  reconnect: "Reconnect",
  review: "Review",
  adoption: "Review",
}

// An adoption ask's size: "1 credential", "212 credentials".
export function adoptionCount(items: number): string {
  return items === 1 ? "1 credential" : `${items} credentials`
}

// How long each kind of ask lives, for the ring's full circle.
export const PENDING_TOTAL_SECONDS: Record<PendingKind, number> = {
  policy: 3600,
  "policy-review": 0,
  approval: 3600,
  intake: 24 * 3600,
  connect: 15 * 60,
  reconnect: 0,
  review: 0,
  adoption: 24 * 3600,
}

// ---------------------------------------------------------------- audit sentences

export type AuditActorContext = {
  // The signed-in member's id, from the session, so "You" is only ever the
  // vault's own comparison and never anything an agent supplied.
  self: string | null
  // Device id to the name the owner approved at enrolment.
  devices: ReadonlyMap<string, string>
  // Member id to the name they chose, and project id to its slug, where
  // the page loaded them.
  members?: ReadonlyMap<string, string>
  projects?: ReadonlyMap<string, string>
}

// Who did it, in words. A device is named through askerName from the name
// the owner approved; a session label never reaches this line.
export function actorWords(actor: string, ctx: AuditActorContext): string {
  if (actor === "system") return "The vault"
  if (actor === "public") return "Someone not signed in"
  if (actor.startsWith("member:")) {
    const member = actor.slice("member:".length)
    if (member === ctx.self && ctx.self !== null) return "You"
    return ctx.members?.get(member) ?? "Another member"
  }
  if (actor.startsWith("device:")) {
    const device = actor.slice("device:".length)
    const name = ctx.devices.get(device)
    return name !== undefined ? askerName({ device, deviceName: name, session: null }) : "An agent on a machine the vault no longer lists"
  }
  if (actor.startsWith("enrolment:")) return "A machine enrolling"
  if (actor.startsWith("operator:")) return "The operator"
  return "Someone"
}

export type AuditPiece = { text: string; as?: "code" | "name" | "danger" | "ok" }
export type AuditLine = { actor: string; pieces: AuditPiece[]; link: { href: string; label: string } | null }

type AuditEventInput = { actor: string; action: string; target: string | null; detail: string }

function parseDetail(detail: string): Record<string, unknown> {
  try {
    const value = JSON.parse(detail) as unknown
    return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

// The workload a row names: `by.workload` on a row a workload's request
// wrote, `actor.workload` on a private row, `workload` on a workload's own.
function auditWorkload(detail: Record<string, unknown>): { id: string; label: string } | null {
  const by = detail.by, actor = detail.actor
  const candidates = [typeof by === "object" && by !== null ? (by as Record<string, unknown>).workload : undefined, typeof actor === "object" && actor !== null ? (actor as Record<string, unknown>).workload : undefined, detail.workload]
  for (const value of candidates) {
    if (typeof value !== "object" || value === null) continue
    const { id, label } = value as Record<string, unknown>
    if (typeof id === "string" && typeof label === "string") return { id, label }
  }
  return null
}

function str(detail: Record<string, unknown>, key: string): string | null {
  const value = detail[key]
  return typeof value === "string" && value !== "" ? value : null
}

function num(detail: Record<string, unknown>, key: string): number | null {
  const value = detail[key]
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

const code = (text: string): AuditPiece => ({ text, as: "code" })
const plain = (text: string): AuditPiece => ({ text })
const named = (text: string): AuditPiece => ({ text, as: "name" })

// A person an event is about, by the name the page read for their member
// id; never a name the event's own detail carries.
function memberPiece(member: string | null, ctx: AuditActorContext): AuditPiece {
  if (member !== null && member === ctx.self) return plain("you")
  const name = member !== null ? ctx.members?.get(member) : undefined
  return name !== undefined ? named(name) : plain("a member")
}

// A posture level as the audit tells it, or null for a row that names none.
function postureWords(level: string | null): string | null {
  return level === "routine" ? "let routine building through" : level === "trust" ? "trust the machines of those who manage it" : level === "ask" ? "ask for every change" : null
}
function itemPath(slug: string): string {
  return `/items/${encodeURIComponent(slug)}`
}

export const PUSH_PROVIDER_NAMES: Readonly<Record<PushProvider, string>> = { github: "GitHub", vercel: "Vercel", cloudflare: "Cloudflare", fly: "Fly" }

// push.done, push.failed, push.not_sent and push.unknown (areas/pushes.ts).
// A workspace row names the place, the version, the credential that carried
// it when it is not private, and the provider's status or the vault's reason
// it was not sent; a private credential's minimal row only its outcome. The
// credential is the row's target, never its detail's item id. A credential
// deleted before its push was settled leaves its id as the target, which
// reads as a deleted credential.
function pushAuditTarget(target: string | null): string | null {
  return target !== null && /^itm_/.test(target) ? null : target
}

function pushAuditPieces(action: string, target: string | null, d: Record<string, unknown>): AuditPiece[] {
  const slug = pushAuditTarget(target)
  const deleted = slug === null && target !== null
  const parsed = typeof d.destination === "string" ? parsePushDestination(d.destination) : null
  const provider = parsed !== null ? PUSH_PROVIDER_NAMES[parsed.provider] : null
  const version = num(d, "version")
  const via = str(d, "via")
  const what = [slug !== null ? code(slug) : plain(deleted ? "a deleted credential" : "a credential"), ...(version !== null ? [plain(` version ${version}`)] : [])]
  const where = [plain(" into "), ...(parsed !== null ? [code(pushDestinationWords(parsed))] : [plain("another service's secret store")]), ...(via !== null ? [plain(" with "), code(via)] : [])]
  const outcome = str(d, "outcome")
  switch (action) {
    case "push.done":
      return [plain(" put "), ...what, ...where, plain(outcome === "created" ? ", where it was new" : outcome === "replaced" ? ", replacing the value there" : "")]
    case "push.failed": {
      const status = num(d, "providerStatus")
      return [plain(" tried to put "), ...what, ...where, plain(". "), { text: "Refused", as: "danger" }, plain(`${provider !== null ? ` by ${provider}` : ""}${status !== null ? ` (${status})` : ""}`)]
    }
    case "push.not_sent":
      return [plain(" asked to put "), ...what, ...where, plain(". "), { text: "Not sent", as: "danger" }, plain(`: ${str(d, "reason") ?? "nothing was sent."}`)]
    default:
      return [plain(" put "), ...what, ...where, plain(`, but Mehen could not confirm it. Check ${provider ?? "the service"}.`)]
  }
}

// A fill refusal's reason, by the vault's error code; any other code is
// said as "Refused." alone, never spelled out.
const FILL_REFUSAL_WORDS: Readonly<Record<string, string>> = {
  origin_mismatch: "that page is not one it may be typed into",
  rate_limited: "too many in too short a time",
  totp_unreadable: "its one-time code secret cannot be read",
}

// The field a fill typed, in words: "the password", "the one-time code".
function fillFieldWords(field: string | null): string {
  if (field === null) return "a value"
  return field === "totp" || field === "code" ? "the one-time code" : `the ${field}`
}

// One audit row as a sentence: the actor, then pieces the page renders
// in order (each spelled), then a link where the event has a page. The
// raw action and detail stay beside it, folded, so nothing is lost.
export function auditLine(event: AuditEventInput, ctx: AuditActorContext): AuditLine {
  const actor = actorWords(event.actor, ctx)
  const d = parseDetail(event.detail)
  const target = event.target
  const method = str(d, "method")
  const host = str(d, "host")
  const item = str(d, "item") ?? target
  const call = method !== null && host !== null ? [code(method), plain(" "), code(host)] : host !== null ? [code(host)] : []
  const using = (slug: string | null): AuditPiece[] => (slug !== null ? [plain(" with "), code(slug)] : [])
  // A rule's extension, before its co-sign fixes the end: its duration, as
  // ruleExtendTitle names it.
  const extensionOf = (rule: string): AuditPiece[] => [plain("the extension of rule "), code(rule)]
  const upTo = (): AuditPiece[] => (num(d, "ttlSeconds") !== null ? [plain(` for up to ${formatDuration(num(d, "ttlSeconds") as number)}`)] : [])
  // A row a workload caused names its task after the sentence, in the machine's words.
  const task = auditWorkload(d)
  const taskPieces = task !== null ? [plain(". Task: "), code(task.label), plain(`, ${TASK_LABEL_WORDS}`)] : []
  const line = (pieces: AuditPiece[], link: AuditLine["link"] = null): AuditLine => ({ actor, pieces: [...pieces, ...taskPieces], link })
  // A workload's own rows name it in the sentence, and the machine it belongs to.
  const workload = (verb: string): AuditLine => {
    const device = str(d, "device")
    const machine = device !== null ? (ctx.devices.get(device) ?? null) : null
    return { actor, pieces: [plain(verb), ...(task !== null ? [code(task.label)] : [plain("a workload")]), ...(machine !== null ? [plain(" on "), named(machine)] : [])], link: { href: "/devices", label: "See machines" } }
  }
  switch (event.action) {
    case "workload.created":
      return workload(" created the workload ")
    case "workload.renewed":
      return workload(" renewed the workload ")
    case "workload.revoked":
      return workload(" revoked the workload ")
    case "workload.expired":
      return workload(" ended the expired workload ")
    case "workload.revoke_all": {
      // reason is absent on rows written before owner_inactive existed.
      const reason = str(d, "reason")
      const machine = target !== null ? ctx.devices.get(target) : undefined
      const why = reason === "owner_inactive" ? [plain(", because its owner lost access")] : reason === "device_revoked" ? [plain(", because the machine was revoked")] : []
      return { actor, pieces: [plain(" ended every workload of "), machine !== undefined ? named(machine) : plain(reason === "owner_inactive" ? "a machine" : "a revoked machine"), ...why], link: { href: "/devices", label: "See machines" } }
    }
    case "relay.allow":
      return line([plain(" called "), ...call, ...using(target)])
    case "relay.deny":
      return line([plain(" tried "), ...call, ...using(target), plain(". "), { text: "Refused", as: "danger" }, plain(" by its rules.")], target !== null ? { href: itemPath(target), label: "See the rules" } : null)
    case "relay.refuse": {
      const reason = str(d, "reason")
      const why = reason === "protected-item" ? " because the credential is only for protected runs" : reason !== null ? `: ${reason}` : ""
      return line([plain(" tried "), ...call, ...using(target), plain(". "), { text: "Refused", as: "danger" }, plain(why)])
    }
    case "relay.tripwire":
      return line([plain(" tripped a fence at "), ...(host !== null ? [code(host)] : [plain("a fenced host")]), ...using(target), plain(". "), { text: "Refused", as: "danger" }])
    case "relay.echo":
      return line([plain(" saw "), ...(host !== null ? [code(host)] : [plain("a service")]), plain(" echo the secret of "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(" back.")], target !== null ? { href: itemPath(target), label: "Review it" } : null)
    case "approval.request":
      return line([plain(" asked to use "), ...(item !== null ? [code(item)] : [plain("a credential")]), ...(method !== null ? [plain(" for a "), code(method), plain(" request")] : [])], target !== null ? { href: `/a/${encodeURIComponent(target)}`, label: "Open the request" } : null)
    case "approval.supersede": {
      const replacedBy = str(d, "replacedBy"), grant = str(d, "grant")
      // An ask a new task grant covers, closed so the agent sends it again.
      if (grant !== null) return line([plain(" closed an ask"), ...(item !== null ? [plain(" to use "), code(item)] : []), plain(" that task grant "), code(grant), plain(" now allows")])
      // The same on a member's private credential, whose minimal row names
      // the credential and says only that a grant closed it.
      if (str(d, "outcome") === "grant") {
        const slug = str(d, "slug")
        return line([plain(" closed an ask"), ...(slug !== null ? [plain(" to use "), code(slug)] : []), plain(" that a task grant now allows")])
      }
      return line([plain(" replaced an ask"), ...(item !== null ? [plain(" to use "), code(item)] : []), plain(" with a newer one to the same place")], replacedBy !== null ? { href: `/a/${encodeURIComponent(replacedBy)}`, label: "Open the newer request" } : null)
    }
    case "approval.bundle": {
      const requests = num(d, "requests"), asked = num(d, "asked")
      return line([plain(" asked for "), plain(requests === 1 ? "1 request" : requests !== null ? `${requests} requests` : "several requests"), plain(" at once"), ...(asked !== null ? [plain(`, ${asked} needing approval`)] : [])])
    }
    case "approval.approve": {
      const uses = num(d, "uses")
      return line([plain(" approved a request"), ...using(item), plain(uses === 1 ? ", once" : uses !== null ? `, ${uses} times` : "")])
    }
    case "approval.deny":
      return line([plain(" denied a request"), ...using(item)])
    case "approval.batch": {
      const counts = ([["approved", num(d, "approved")], ["denied", num(d, "denied")], ["left undecided", num(d, "skipped")]] as const).flatMap(([word, n]) => n ? [`${n} ${word}`] : [])
      return line([plain(` decided requests together${counts.length ? `: ${counts.join(", ")}` : ""}`)])
    }
    case "grant.use":
      return line([plain(" used an approval"), ...using(item)])
    case "grant.create":
      return line([plain(" saved permission "), ...(target !== null ? [code(target)] : [plain("to use an approval or remembered route")])])
    case "grant.invalidate":
      return line([plain(" ended saved permission "), ...(target !== null ? [code(target)] : [plain("to use an approval or remembered route")]), plain(" because access changed")])
    case "grant.revoke":
      return line([plain(" stopped saved permission "), ...(target !== null ? [code(target)] : [plain("to use an approval or remembered route")])])
    case "policy.expire":
      return line([plain(" ended window "), ...(target !== null ? [code(target)] : [plain("for wider access")]), plain(" because its time ran out")])
    case "policy.replace":
      return line([plain(" replaced window "), ...(target !== null ? [code(target)] : [plain("for wider access")]), plain(" with a newer window")])
    case "policy.stale":
      return line([plain(target?.startsWith("pol_") ? " closed proposal " : " ended window "), ...(target !== null ? [code(target)] : [plain("for wider access")]), plain(" because access changed")])
    case "policy.revoke":
      return line([plain(" stopped window "), ...(target !== null ? [code(target)] : [plain("for wider access")])])
    case "policy.cancel":
      return line([plain(" withdrew proposal "), ...(target !== null ? [code(target), plain(" for wider access")] : [plain("for wider access")])])
    case "policy.propose":
      return line([plain(" proposed wider access"), ...(target !== null ? [plain(" in "), code(target)] : []), ...(str(d, "item") !== null ? [plain(" for "), code(str(d, "item") as string)] : [])])
    case "policy.activate":
      return line([plain(" turned on window "), ...(target !== null ? [code(target), plain(" for wider access")] : [plain("for wider access")]), ...(str(d, "item") !== null ? [plain(" with "), code(str(d, "item") as string)] : [])])
    case "policy.approve":
    case "policy.deny":
      if (event.action === "policy.deny" && str(d, "extends") !== null) return line([plain(" denied "), ...extensionOf(str(d, "extends") as string), ...using(str(d, "item")), ...upTo()])
      // A manager declined to co-sign a task grant.
      if (event.action === "policy.deny" && str(d, "kind") === "area") return line([plain(" declined to let an agent carry on with routine work"), ...(call.length > 0 ? [plain(" on "), ...call] : []), ...using(str(d, "item"))])
      return line([plain(event.action === "policy.approve" ? " approved proposal " : " denied proposal "), ...(target !== null ? [code(target), plain(" for wider access")] : [plain("for wider access")])])
    // Standing rules (areas/policy-rules-workspace.ts): target is the rul_ id,
    // or the pol_ id for a proposal.
    // A task grant's rows carry kind "area": its host and areas, not a path.
    case "rule.create":
      if (str(d, "kind") === "area") return line([plain(" let an agent carry on with routine work on "), ...call, ...using(str(d, "item")), ...(target !== null ? [plain(" as task grant "), code(target)] : [])])
      return line([plain(" allowed "), ...call, ...(str(d, "path") !== null ? [plain(" "), code(str(d, "path") as string)] : []), ...using(str(d, "item")), plain(" from now on"), ...(target !== null ? [plain(" as rule "), code(target)] : [])])
    case "rule.use": {
      const uses = num(d, "uses"), grant = str(d, "kind") === "area"
      return line([plain(" used "), str(d, "item") !== null ? code(str(d, "item") as string) : plain("a credential"), plain(grant ? " under task grant " : " under rule "), ...(target !== null ? [code(target)] : [plain("a standing rule")]), plain(uses !== null ? `, use ${uses}` : "")])
    }
    case "rule.end": {
      const reason = str(d, "reason")
      const why = reason === "expired" ? " because its time ran out" : reason === "revoked" ? "" : reason === "credential-changed" ? " because the credential changed" : reason === "access-changed" ? " because access changed" : reason === "uses-spent" ? " because it was used as many times as it allows" : reason === "replaced" ? " because a newer one replaced it" : ""
      const what = str(d, "kind") === "area" ? "task grant " : "rule "
      return line([plain(reason === "revoked" ? ` stopped ${what}` : ` ended ${what}`), ...(target !== null ? [code(target)] : [plain("a standing rule")]), ...using(str(d, "item")), plain(why)])
    }
    case "rule.propose":
      if (str(d, "extends") !== null) return line([plain(" asked a second person to co-sign "), ...extensionOf(str(d, "extends") as string), ...using(str(d, "item")), ...upTo()], target !== null ? { href: `/p/${encodeURIComponent(target)}`, label: "Open the proposal" } : null)
      if (str(d, "kind") === "area") return line([plain(str(d, "stage") === "co-sign" ? " asked a second person to let an agent carry on with routine work on " : " proposed letting an agent carry on with routine work on "), ...call, ...using(str(d, "item"))], target !== null ? { href: `/p/${encodeURIComponent(target)}`, label: "Open the proposal" } : null)
      return line([plain(str(d, "stage") === "co-sign" ? " asked a second person to allow " : " proposed allowing "), ...call, ...(str(d, "path") !== null ? [plain(" "), code(str(d, "path") as string)] : []), ...using(str(d, "item")), plain(" from now on")], target !== null ? { href: `/p/${encodeURIComponent(target)}`, label: "Open the proposal" } : null)
    // A co-signed extension names the proposal it was co-signed through.
    case "rule.extend": {
      const rule = target !== null ? [code(target)] : [plain("a standing rule")]
      const ends = str(d, "endsAt")
      return line([...(str(d, "proposal") !== null ? [plain(" co-signed the extension of rule "), ...rule] : [plain(" extended rule "), ...rule]), ...using(str(d, "item")), ...(ends !== null ? [plain(` to ${formatTime(ends)}`)] : [])])
    }
    case "oauth.refresh":
      return line([plain(" refreshed the token of "), ...(target !== null ? [code(target)] : [plain("a connection")])])
    case "oauth.needs_reauth":
      return line([plain(" could not refresh the token of "), ...(target !== null ? [code(target)] : [plain("a connection")]), plain(": the provider stopped accepting it.")], target !== null ? { href: itemPath(target), label: "Reconnect" } : null)
    case "oauth.client_broken":
      return line([plain(" found the OAuth client "), ...(target !== null ? [code(target)] : []), plain(" refused by its provider")], target !== null ? { href: itemPath(target), label: "Review it" } : null)
    case "oauth.connect_create": {
      const connect = str(d, "connect")
      const reconnect = d.reconnect === true
      return line([plain(reconnect ? " asked to reconnect " : " asked to connect "), ...(target !== null ? [code(target)] : [plain("an account")]), ...(str(d, "provider") !== null ? [plain(" through "), code(str(d, "provider") as string)] : [])], connect !== null ? { href: `/c/${encodeURIComponent(connect)}`, label: "Open the request" } : null)
    }
    case "oauth.connect":
    case "oauth.reconnect":
      return line([plain(event.action === "oauth.reconnect" ? " reconnected " : " connected "), ...(target !== null ? [code(target)] : [plain("an account")]), ...(str(d, "provider") !== null ? [plain(" through "), code(str(d, "provider") as string)] : [])], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    case "oauth.connect_wider":
      return line([plain(" tried to connect "), ...(target !== null ? [code(target)] : [plain("an account")]), plain(". "), { text: "Refused", as: "danger" }, plain(": the provider granted more than was asked for, so nothing was saved")])
    case "oauth.scopes_unreadable":
      return line([plain(" could not read what "), ...(target !== null ? [code(target)] : [plain("a connection")]), plain(" was granted, so it uses none of it")], target !== null ? { href: itemPath(target), label: "Reconnect" } : null)
    case "oauth.connect_start":
      return line([plain(" started signing in for "), ...(target !== null ? [code(target)] : [plain("a connection")])])
    case "oauth.connect_mismatch":
      return line([plain(" signed in as the wrong account for "), ...(target !== null ? [code(target)] : [plain("a connection")]), plain(". Nothing was saved")])
    case "oauth.connect_late":
    case "oauth.connect_reuse":
      return line([plain(" used a connect link that had already closed for "), ...(target !== null ? [code(target)] : [plain("a connection")])])
    case "oauth.connect_supersede":
      return line([plain(" replaced an older connect link for "), ...(target !== null ? [code(target)] : [plain("a connection")])])
    case "oauth.connect_recover":
      return line([plain(" settled an interrupted connect for "), ...(target !== null ? [code(target)] : [plain("a connection")])])
    case "intake.create": {
      const intake = str(d, "intake")
      const rotation = d.rotation === true
      return line([plain(rotation ? " asked for a fresh secret for " : " asked for a credential, to be saved as "), ...(target !== null ? [code(target)] : [plain("a new name")])], intake !== null ? { href: `/i/${encodeURIComponent(intake)}`, label: "Open the request" } : null)
    }
    case "intake.complete":
      return line([plain(d.rotation === true ? " replaced the secret of " : " pasted the secret for "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "intake.complete_late":
    case "intake.reuse":
      return line([plain(" opened a request that had already closed for "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "intake.cancel":
      return line([plain(" cancelled the request for "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "intake.supersede":
      return line([plain(" replaced an older request for "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "intake.recover":
      return line([plain(" settled an interrupted request for "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "adoption.create":
      return line([plain(" started a batch of credentials to adopt")], target !== null ? { href: `/b/${encodeURIComponent(target)}`, label: "Open the batch" } : null)
    case "adoption.upload": {
      const accepted = num(d, "accepted") ?? 0
      return line([plain(` uploaded ${adoptionCount(accepted)} to adopt`)], target !== null ? { href: `/b/${encodeURIComponent(target)}`, label: "Open the batch" } : null)
    }
    case "adoption.approve":
      return line([plain(` approved a batch and stored ${adoptionCount(num(d, "created") ?? 0)}`)])
    case "adoption.refused":
      return line([plain(" tried to approve a batch, but some credentials could not be stored. Nothing was stored")])
    case "adoption.item":
      return line([plain(" adopted "), ...(target !== null ? [code(target)] : [plain("a credential")])], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    case "adoption.cancel":
      return line([plain(" cancelled a batch of credentials to adopt. Nothing in it was stored")])
    case "adoption.expire":
      return line([plain(" let a batch of credentials to adopt expire. Nothing in it was stored")])
    case "item.create":
      return line([plain(" stored "), ...(target !== null ? [code(target)] : [plain("a credential")])], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    case "item.replace":
      return line([plain(" stored a new version of "), ...(target !== null ? [code(target)] : [plain("a credential")])], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    case "item.update":
      return line([plain(" changed where or how "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(" is used")])
    case "item.rotate":
      return line([plain(" replaced the secret of "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "item.restore":
      return line([plain(" put back the previous secret of "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "item.delete":
      return line([plain(" deleted "), ...(target !== null ? [code(target)] : [plain("a credential")])])
    case "push.done":
    case "push.failed":
    case "push.not_sent":
    case "push.unknown": {
      const slug = pushAuditTarget(target)
      return line(pushAuditPieces(event.action, target, d), slug !== null ? { href: itemPath(slug), label: "Open the credential" } : null)
    }
    case "item.fill": {
      // A private credential's row carries `browser` and no page; the audit
      // page passes its own slug as the target.
      const browser = typeof d.browser === "object" && d.browser !== null ? (d.browser as Record<string, unknown>) : null
      const origin = browser !== null ? str(browser, "origin") : str(d, "origin")
      const field = browser !== null ? str(browser, "field") : str(d, "field")
      const page = browser !== null ? null : str(d, "page")
      const outcome = str(d, "outcome") ?? ""
      const refused = outcome.startsWith("refused:")
      const reason = refused ? FILL_REFUSAL_WORDS[outcome.slice("refused:".length)] : undefined
      const approval = browser !== null ? null : str(d, "approval")
      const into = origin !== null ? [plain(" into "), code(`${origin}${page ?? ""}`)] : []
      const pieces = [plain(`${refused ? " tried to type " : " typed "}${fillFieldWords(field)} of `), ...(target !== null ? [code(target)] : [plain("a credential")]), ...into, ...(refused ? [plain(". "), { text: "Refused", as: "danger" as const }, plain(reason !== undefined ? `: ${reason}.` : ".")] : [])]
      return line(pieces, browser !== null ? null : approval !== null ? { href: `/a/${encodeURIComponent(approval)}`, label: "Open the request" } : target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    }
    // How careful a credential is (areas/postures-workspace.ts). A private
    // credential's row keeps only its outcome, the level or the reason.
    case "posture.set": {
      const machines = num(d, "machines"), words = postureWords(str(d, "after") ?? str(d, "outcome"))
      return line([plain(" set how careful "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(` is${words !== null ? `: ${words}` : ""}${machines !== null ? `, on ${machines === 1 ? "1 machine" : `${machines} machines`}` : ""}`)], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    }
    case "posture.reset": {
      const reason = str(d, "reason") ?? str(d, "outcome")
      return line([plain(" put "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(` back to asking for every change${reason === "managed" ? ", as its platform decides" : reason === "rehome" ? ", as it moved to another home" : ""}`)])
    }
    case "posture.use": {
      const level = str(d, "level") ?? str(d, "outcome")
      return line([plain(" used "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(` without asking${level === "trust" ? ", on a trusted machine" : level === "routine" ? ", as routine building" : ""}`), ...(str(d, "method") !== null && str(d, "host") !== null ? [plain(": "), code(`${str(d, "method") as string} ${str(d, "host") as string}`)] : [])])
    }
    // The approval dial (areas/approval-dial-workspace.ts). A private
    // credential's use or refusal keeps only its outcome.
    case "workspace.approvals": {
      const name = (level: string | null) => (level !== null && Object.hasOwn(APPROVAL_DIAL_CHOICES, level) ? APPROVAL_DIAL_CHOICES[level as ApprovalDial].name : null)
      const before = name(str(d, "before")), after = name(str(d, "after"))
      return line([plain(" changed how often Mehen asks here"), ...(before !== null && after !== null ? [plain(" from "), named(before), plain(" to "), named(after)] : [])], { href: "/settings#approvals", label: "Open settings" })
    }
    case "approvals.use":
      return line([plain(" used "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(` without asking, as ${APPROVAL_DIAL_CHOICES.work.name} lets a trusted machine`), ...(method !== null && host !== null ? [plain(": "), code(`${method} ${host}`)] : [])])
    case "approvals.refuse":
      return line([plain(" tried to use "), ...(target !== null ? [code(target)] : [plain("a credential")]), ...(method !== null && host !== null ? [plain(" for "), code(`${method} ${host}`)] : []), plain(". "), { text: "Refused", as: "danger" as const }, plain(`: it would need a person, and ${APPROVAL_DIAL_CHOICES.work.name} refuses instead of asking.`)], target !== null ? { href: itemPath(target), label: "Open the credential" } : null)
    case "posture.nudge_quiet":
      return line([plain(" chose not to be reminded about "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(" for 7 days")])
    // What a machine may do without asking (areas/mandates-workspace.ts).
    // A mandate row names its machine; a use row names the credential.
    case "mandate.propose":
      return line([plain(" asked to carry on without asking")], target !== null ? { href: `/sign-mandate?proposal=${encodeURIComponent(target)}`, label: "Open the proposal" } : null)
    case "mandate.sign":
    case "mandate.pause":
    case "mandate.resume":
    case "mandate.stop":
    case "mandate.expire":
    case "mandate.trip": {
      const id = str(d, "device"), name = id !== null ? (ctx.devices.get(id) ?? null) : null
      const machine = name !== null ? [named(name)] : [plain("a machine")]
      const classes = Array.isArray(d.classes) ? d.classes.filter((c): c is string => typeof c === "string") : []
      const days = num(d, "ttlDays")
      const pieces = event.action === "mandate.sign" ? [plain(" let "), ...machine, plain(` ${classes.length > 0 ? mandateClassWords(classes) : "carry on"} without asking${days !== null ? ` for ${days === 1 ? "1 day" : `${days} days`}` : ""}`)]
        : event.action === "mandate.pause" ? [plain(" paused what "), ...machine, plain(" may do without asking")]
        : event.action === "mandate.resume" ? [plain(" let "), ...machine, plain(" carry on without asking again")]
        : event.action === "mandate.stop" ? [plain(" stopped what "), ...machine, plain(str(d, "reason") === "replaced" ? " may do without asking, signing new terms for it" : " may do without asking")]
        : event.action === "mandate.expire" ? [plain(" ended what "), ...machine, plain(" may do without asking, as its time ran out")]
        : [plain(" stopped letting "), ...machine, plain(" through without asking after too many requests in a minute")]
      return line(pieces, target !== null ? { href: `/mandates/${encodeURIComponent(target)}`, label: "Open the mandate" } : null)
    }
    case "mandate.use": {
      const classes = Array.isArray(d.classes) ? d.classes.filter((c): c is string => typeof c === "string") : []
      const method = str(d, "method"), host = str(d, "host")
      return line([plain(" used "), ...(target !== null ? [code(target)] : [plain("a credential")]), plain(` to ${classes.length > 0 ? mandateClassWords(classes) : "act"} without asking, on its mandate`), ...(method !== null && host !== null ? [plain(": "), code(`${method} ${host}`)] : [])])
    }
    case "device.enrol": {
      const name = str(d, "name") ?? (target !== null ? ctx.devices.get(target) : undefined) ?? null
      return line([plain(" enrolled "), ...(name !== null ? [named(name)] : [plain("a machine")])], { href: "/devices", label: "See machines" })
    }
    case "device.revoke": {
      const name = target !== null ? (ctx.devices.get(target) ?? null) : null
      return line([plain(" revoked "), ...(name !== null ? [named(name)] : [plain("a machine")])], { href: "/devices", label: "See machines" })
    }
    case "device.rescope": {
      const name = str(d, "name") ?? (target !== null ? (ctx.devices.get(target) ?? null) : null)
      return line([plain(" changed what "), ...(name !== null ? [named(name)] : [plain("a machine")]), plain(" may use")], { href: "/devices", label: "See machines" })
    }
    // A platform's managed workspace (areas/managed.ts).
    case "device.provision": {
      const name = str(d, "name") ?? (target !== null ? (ctx.devices.get(target) ?? null) : null)
      return line([plain(" added "), ...(name !== null ? [named(name)] : [plain("a machine")])], { href: "/devices", label: "See machines" })
    }
    case "workspace.delete":
      return line([plain(" deleted the workspace's machines, credentials and projects")])
    case "device.enrol_rejected":
      return line([plain(" rejected a machine enrolment")])
    case "device.rescope_proposed":
      return line([plain(" asked to change what a machine may use")])
    case "device.rescope_signed":
      return line([plain(" confirmed a proposed change to what a machine may use")])
    case "device.rescope_rejected":
      return line([plain(" rejected a proposed change to what a machine may use")])
    case "device.discard":
    case "device.sweep":
      return line([plain(" cleared an enrolment that was never approved")])
    case "run.create": {
      const command = str(d, "command")
      const envName = str(d, "env")
      const vars = d.vars
      const count = typeof vars === "object" && vars !== null ? Object.keys(vars as Record<string, unknown>).length : null
      const project = str(d, "project")
      const slug = project !== null ? (ctx.projects?.get(project) ?? null) : null
      return line(
        [
          plain(" ran "),
          ...(command !== null ? [code(command)] : [plain("a program")]),
          ...(envName !== null ? [plain(" in "), code(envName)] : []),
          ...(slug !== null ? [plain(envName !== null ? " of " : " in "), code(slug)] : []),
          plain(count === null ? "" : ` with ${count} variable${count === 1 ? "" : "s"}`),
        ],
        project !== null ? { href: `/projects/${encodeURIComponent(project)}`, label: "Open the project" } : null,
      )
    }
    case "run.lease":
      return line([plain(" received a real value for a run")])
    case "run.end":
      return line([plain(" finished a run")])
    case "project.share":
      return line([plain(" changed access to a project")])
    case "project.unshare":
      return line([plain(" removed a project share")])
    case "project.delete":
      return line([plain(" deleted a project")])
    case "project.create":
      return line([plain(" created the project "), ...(str(d, "slug") !== null ? [code(str(d, "slug") as string)] : [])], target !== null ? { href: `/projects/${encodeURIComponent(target)}`, label: "Open the project" } : null)
    case "project.var.set":
      return line([plain(" set "), ...(str(d, "name") !== null ? [code(str(d, "name") as string)] : [plain("a variable")]), ...(str(d, "env") !== null ? [plain(" in "), code(str(d, "env") as string)] : [])], target !== null ? { href: `/projects/${encodeURIComponent(target)}`, label: "Open the project" } : null)
    case "project.environment.update":
      return line([plain(" changed the protection or fences of "), ...(str(d, "env") !== null ? [code(str(d, "env") as string)] : [plain("an environment")])], target !== null ? { href: `/projects/${encodeURIComponent(target)}`, label: "Open the project" } : null)
    case "project.remote.bind":
    case "project.remote.unbind": {
      const remote = str(d, "remote")
      const bind = event.action === "project.remote.bind"
      const slug = target !== null ? (ctx.projects?.get(target) ?? null) : null
      return line(
        [plain(bind ? " bound " : " unbound "), ...(remote !== null ? [code(remote)] : [plain("a repository")]), plain(bind ? " to " : " from "), ...(slug !== null ? [code(slug)] : [plain("a project")])],
        target !== null ? { href: `/projects/${encodeURIComponent(target)}`, label: "Open the project" } : null,
      )
    }
    case "member.role":
      return line([plain(" updated a member's role")])
    case "member.promotion_cancelled":
      return line([plain(" cancelled a pending role promotion")])
    case "device.enrol_expired":
      return line([plain(" closed an expired machine enrolment")])
    case "member.join_aborted":
      return line([plain(" cancelled an incomplete invitation redemption")])
    case "member.invite":
      return line([plain(" invited someone to the workspace")])
    case "account.security.install":
      return line([plain(" updated account security")])
    case "account.security.restriction":
      return line([plain(" changed the account's temporary security limits")])
    case "account.session_revoke":
      return line([plain(" signed out a session")])
    case "name.miss_limit":
      return line([plain(" reached the hourly limit for unavailable names")])
    case "workspace.freeze":
      return line([plain(" froze the workspace. Every machine use is refused until an owner unfreezes it")])
    case "workspace.unfreeze":
      return line([plain(" unfroze the workspace")])
    case "workspace.create":
      return line([plain(" created the workspace")])
    case "workspace.update": {
      const name = str(d, "name")
      const slug = str(d, "slug")
      return line([plain(" renamed the workspace"), ...(name !== null ? [plain(" to "), named(name)] : []), ...(slug !== null ? [plain(name !== null ? ", short name " : " to the short name "), code(slug)] : [])])
    }
    case "workspace.identity_rule":
      return line([plain(" changed which roles must also verify a Google account here")])
    case "member.join":
      return line([plain(" joined the workspace")])
    case "member.leave":
      return line([plain(" left the workspace")])
    case "member.gate":
      return line([plain(d.admitted === true ? " passed the workspace's identity check" : " was held at the workspace's identity check")])
    case "member.confirm":
    case "member.suspend":
    case "member.reinstate":
    case "member.remove": {
      const verb = { "member.confirm": " confirmed ", "member.suspend": " suspended ", "member.reinstate": " reinstated ", "member.remove": " removed " }[event.action] as string
      const devices = num(d, "devices")
      const privateItems = num(d, "privateItems")
      const removed = event.action === "member.remove" && devices !== null && privateItems !== null ? [plain(`. ${devices} machine${devices === 1 ? "" : "s"} revoked, ${privateItems} private credential${privateItems === 1 ? "" : "s"} deleted`)] : []
      return line([plain(verb), memberPiece(target, ctx), ...removed])
    }
    case "member.invite_revoked":
      return line([plain(" revoked an invitation")])
    case "invite.emailed":
      return line([plain(" emailed an invitation's link to the invited address")])
    case "team.create":
      return line([plain(" created a team")])
    case "team.rename":
      return line([plain(" renamed a team")])
    case "team.delete":
      return line([plain(" deleted a team and its project shares")])
    case "team.member_add":
      return line([plain(" added "), memberPiece(str(d, "member"), ctx), plain(" to a team")])
    case "team.member_remove":
      return line([plain(" took "), memberPiece(str(d, "member"), ctx), plain(" out of a team")])
    case "tenant.freeze":
      return line([plain(" froze the vault. Every credential is refused until an owner unfreezes it")])
    case "tenant.unfreeze":
      return line([plain(" unfroze the vault")])
    case "system.restore": {
      const point = str(d, "target")
      const from = str(d, "source") === "dump" ? " restored the workspace from the backup of " : " restored the workspace to "
      return line([plain(point !== null ? from : " restored the workspace from a backup"), ...(point !== null ? [code(point)] : []), plain(". Everything after that point was undone")])
    }
    case "backup.recipient_add":
    case "backup.recipient_active":
    case "backup.recipient_remove": {
      const key = str(d, "fingerprint")
      const [before, after] = event.action === "backup.recipient_add" ? [" registered the backup key ", ". It can receive exports a day later"] : event.action === "backup.recipient_active" ? [" let the backup key ", " receive exports"] : [" removed the backup key ", null]
      return line([plain(before), ...(key !== null ? [code(key)] : [plain("a key")]), ...(after !== null ? [plain(after)] : [])], { href: "/settings", label: "Open settings" })
    }
    case "backup.export": {
      const key = str(d, "fingerprint")
      const items = num(d, "items") ?? 0
      return line([plain(` exported ${items === 1 ? "1 credential" : `${items} credentials`}, encrypted to the backup key `), ...(key !== null ? [code(key)] : [plain("a key")])], { href: "/settings", label: "Open settings" })
    }
    default:
      return line([plain(" recorded "), code(event.action), ...(target !== null ? [plain(" on "), code(target)] : [])])
  }
}

// Where to go after signing in: a path on this vault, never another site.
export function safeNext(raw: string | null | undefined): string {
  if (!raw || raw.length > 512) return "/"
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return "/"
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return "/"
  return raw
}

// ---------------------------------------------------------------- standing rules list

// The credential and machine pages' "Allowed without asking" card
// (policy-rules-list.ts), its Stop and Extend (client/pages/policy-rules.ts),
// and the compact line on those pages that counts the viewer's own rules.
export const RULES_CARD_TITLE = "Allowed without asking"
// The My rules page (/w/<slug>/rules, with POLICY_RULES on).
export const MY_RULES_TITLE = "My rules"
export const MY_RULES_LEAD = "Requests agents may make without asking anyone: on your own machines, and under rules you approved or co-signed. Stopping a rule needs no passkey; extending one does."
export const MY_RULES_EMPTY_TITLE = "No rules"
export const MY_RULES_EMPTY_WORDS = "Nothing is allowed without asking on your machines, or under a rule you approved or co-signed."
export const RULES_CARD_LEAD = "Requests an agent may make without asking anyone, until each rule ends. Stopping a rule needs no passkey; extending one does."
export const RULES_ENDED_HEADING = "Ended"
export const RULE_ACTIVE_WORDS = "Active"
export const RULE_ID_LABEL = "Rule"
// context: the approval panel's label, said with its ruleContextWords.
export const RULE_TERM_LABELS = { credential: "Credential", who: "Who", graphql: "GraphQL fields", context: RULE_PANEL_LABELS.context, approvedBy: "Approved by", used: "Used", ends: "Ends", ended: "Ended" } as const
export const RULE_OUTSIDE_PROJECT_WORDS = "outside any project"
export const RULE_APPROVER_HIDDEN_WORDS = "not shown"
export const RULE_COSIGNED_BY_WORDS = "co-signed by"
export const RULE_COSIGNER_HIDDEN_WORDS = "a manager"
export const RULE_STOPPED_ONLY_WORDS = "You may stop this rule, but not read what it allows."
export const RULE_STOP_LABEL = "Stop"
export const RULE_STOP_WORDS = "The agent then asks again for this request. Stopping only narrows, so it needs no passkey."
export const RULE_STOP_BUTTON = "Stop this rule"
export const RULE_STOPPING_WORDS = "Stopping..."
export const RULE_STOPPED_WORDS = "Stopped."
export const RULE_EXTEND_LABEL = "Extend"
export const RULE_EXTEND_FOR_LABEL = "Ends this long from now"
export const RULE_EXTEND_BUTTON = "Extend with passkey"
export const RULE_EXTEND_WAITING_WORDS = "Waiting for your passkey..."
export const RULE_EXTEND_CHOOSE_WORDS = "Choose how long it should last."
export const RULE_EXTEND_COSIGN_WORDS = "Extended once a manager of this credential's home co-signs."
export const RULE_COSIGN_LINK_WORDS = "Send a manager of this credential's home this link"
export const RULE_COSIGN_CODE_WORDS = "Binding code"

// PolicyAreaGrantView["endedReason"], a rule's and a task grant's, spelt
// here so this block needs no import.
type RuleEndedReason = "expired" | "revoked" | "access-changed" | "credential-changed" | "uses-spent" | "replaced" | null

export const RULE_TASK_WORDS = "task"

// A task grant's row on the same card and on My rules: the areas it
// covers, how many of its requests are used, Stop and, once it has ended,
// its receipt of what it did.
export function grantTitleWords(areaNames: readonly string[]): string {
  return `Task grant: ${areaNames.join(", ")}`
}
export function grantUsesWords(uses: number, maxUses: number): string {
  return `${uses} of ${maxUses} request${maxUses === 1 ? "" : "s"}`
}
export const GRANT_STOP_WORDS = "The agent then asks again in these areas. Stopping only narrows, so it needs no passkey."
export const GRANT_STOP_BUTTON = "Stop this task grant"
export const GRANT_RECEIPT_LABEL = "Receipt"
export const GRANT_RECEIPT_NONE_WORDS = "None"
export function grantReceiptLine(count: number, words: string): string {
  return `${count} × ${words}`
}

// The pill on an ended rule: "Stopped" when someone stopped it.
export function ruleEndedPill(reason: RuleEndedReason): string {
  return reason === "revoked" ? "Stopped" : "Ended"
}

export function ruleEndedWords(reason: RuleEndedReason): string {
  switch (reason) {
    case "expired": return "Its time ran out."
    case "revoked": return "Someone stopped it."
    case "access-changed": return "It ended because access changed."
    case "credential-changed": return "It ended because the credential was edited."
    case "uses-spent": return "It was used as many times as it allows."
    case "replaced": return "A newer task grant replaced it."
    default: return "It has ended."
  }
}

// The same, said to the viewer who just stopped it on this page.
export function ruleStoppedHereWords(reason: RuleEndedReason): string {
  return reason === "revoked" ? "It was stopped." : ruleEndedWords(reason)
}

// Stop's outcome on the row: the vault settles a rule before it revokes it,
// so a rule that had already ended comes back with why it ended instead.
export function ruleStopOutcomeWords(reason: RuleEndedReason): string {
  return reason === "revoked" ? RULE_STOPPED_WORDS : ruleEndedWords(reason)
}

// How often a rule was used, leading into the time of the last use when
// the vault gives one.
export function ruleUsesWords(uses: number, lastUsed: boolean): string {
  if (uses === 0) return "Not yet"
  const count = uses === 1 ? "Once" : `${uses} times`
  return lastUsed ? `${count}, last` : count
}

export function ruleExtendedWords(endsAt: string): string {
  return `Extended. It now ends ${formatTime(endsAt)}.`
}

// atLeast: the vault's list of ended rules was full, so more may be left out.
export function rulesEndedMoreWords(count: number, atLeast = false): string {
  return atLeast ? `At least ${count} older ended rules are not shown.` : count === 1 ? "1 older ended rule is not shown." : `${count} older ended rules are not shown.`
}

export function rulesAllowedWords(count: number): string {
  return count === 1 ? "1 request allowed without asking" : `${count} requests allowed without asking`
}

// ---------------------------------------------------------------- how careful a credential is

// The How careful card on a credential's page (posture-card.ts): Ask,
// Routine and Trust are the posture's levels; Custom stores Ask and points
// at the credential's own rules and its standing rules.
export const POSTURE_CARD_TITLE = "How careful"
export const POSTURE_CARD_LEAD = "What an agent may do with this credential without asking anyone first."
export const POSTURE_CHOICES = {
  ask: { name: "Ask for every change", words: "Every request this credential's rules hold waits for someone to approve it." },
  routine: { name: "Let routine building through", words: "Reads, and creating or changing things in the areas below. Deletes, secrets, sending and sharing still ask." },
  trust: { name: "Trust my own machines", words: "Everything except deletes and other destructive changes, secrets and access, sending and sharing, payments and anything that keeps running, on machines of people who manage this credential. Other machines still ask. Includes routes nobody has reviewed." },
  custom: { name: "Custom rules", words: "Asks, except where this credential's own rules or its standing rules let a request through." },
} as const
export const POSTURE_LEVELS_LABEL = "Choose how careful it is"
export const POSTURE_AREAS_LABEL = "Routine building covers"
export const POSTURE_MACHINES_LABEL = "On these machines"
export const POSTURE_EVERY_MACHINE_WORDS = "Every eligible machine"
export const POSTURE_NAMED_MACHINES_WORDS = "Only the machines ticked"
export const POSTURE_MACHINES_WORDS = "Routine reaches members' and teams' machines, never guests'. Trust reaches only machines of people who manage this credential."
export const POSTURE_NO_MACHINE_WORDS = "Tick at least one machine."
// A machine the posture names that this level would not cover now.
export const POSTURE_MACHINE_UNCOVERED_WORDS = "Not covered now."
export const POSTURE_SAVE_BUTTON = "Save with passkey"
export const POSTURE_NOTHING_TO_SAVE = "Nothing to save."
export const POSTURE_NO_CATALOGUE_WORDS = "Nobody has reviewed this service's routes, so this credential can only ask, or follow its own rules."
export const POSTURE_HELD_WORDS = "Your account is restricted after a recovery or a security change, so you may only set this credential to ask for every change."
export const POSTURE_GUEST_WORDS = "Guests cannot let agents carry on without asking, so you may only set this credential to ask for every change."
export const POSTURE_CUSTOM_RULES_LINK = "Allowed without asking"
export const POSTURE_CUSTOM_PROPOSE_WORDS = "An agent proposes a new rule with mehen policy propose, and you approve it with your passkey."
export const POSTURE_CUSTOM_NO_RULES_WORDS = "No standing rule lets anything through now."

// "Your standing rules are in Allowed without asking, below.", split round
// the link to the card.
export const POSTURE_CUSTOM_RULES_WORDS = { before: "Your standing rules are in ", after: ", below." } as const

// The catalogue the posture was signed against has grown since.
export function postureGrewWords(service: string): string {
  return `${service}'s reviewed list grew. Review and save to include the new routes.`
}

// Who set it last, and when (the time follows).
export function postureSetByWords(name: string): string {
  return `Set by ${name}`
}

// The credential's own rules in three lines, from summarisePolicy: what an
// agent may do on its own, what asks first, and what is refused; the
// policy's default joins the list it sends the rest to.
export function postureCustomLines(summary: PolicySummary): { own: string; asks: string; refused: string } {
  const line = (lead: string, phrases: readonly string[], rest: boolean): string => {
    const all = rest ? [...phrases, phrases.length > 0 ? "everything else" : "everything"] : [...phrases]
    return `${lead}: ${all.length > 0 ? joinWords(all) : "nothing"}.`
  }
  return {
    own: line("On its own", summary.allowed, summary.rest === "allowed"),
    asks: line("Asks first", summary.approve, summary.rest === "approve"),
    refused: line("Refused", summary.deny, summary.rest === "deny"),
  }
}

// ---------------------------------------------------------------- the home's nudge

// A credential that asked often this week with nothing denied, most of it
// routine building (items.nudges), on the home: one line each, a link to
// its How careful card and Not now, which quietens it for 7 days.
export const NUDGE_CARD_TITLE = "Asking often"
export const NUDGE_CHANGE_LINK = "Change how careful it is"
export const NUDGE_NOT_NOW_BUTTON = "Not now"
export const NUDGE_QUIETENING_WORDS = "Quietening..."

// After the credential's name: "asked 21 times this week, none denied; 15
// were routine building."
export function nudgeWords(asked: number, routine: number): string {
  return ` asked ${asked} times this week, none denied; ${routine} ${routine === 1 ? "was" : "were"} routine building.`
}

// ---------------------------------------------------------------- mandates

// A mandate's classes as a person says them, in the order the sign page
// shows them: "read, change and send".
const MANDATE_CLASS_ORDER = ["read", "change", "send", "delete"] as const
export function mandateClassWords(classes: readonly string[]): string {
  return joinWords(MANDATE_CLASS_ORDER.filter((c) => classes.includes(c)))
}
// The notices (mandate_signed, mandate_tripped, mandate_ending,
// mandate_lapsed), before the end date.
export function mandateSignedWords(signer: string, machine: string, classes: readonly string[]): string {
  return `${signer} let ${machine} ${mandateClassWords(classes)} without asking, until`
}
export function mandateEndingWords(machine: string): string {
  return `What ${machine} may do without asking ends unless you sign it again, on`
}
export function mandateLapsedNoticeWords(machine: string): string {
  return `The mandate you signed for ${machine} covers nothing now: something changed since you signed it, for example your role, an account recovery or what the machine may use. Resume it with your passkey to let it carry on. It ends`
}
export function mandateTrippedWords(machine: string): string {
  return `${machine} sent too many requests in a minute, so its mandate stopped letting anything through until its signer resumes it. It would have ended`
}

// The notice a run refused project_unshared raises for the project's managers.
export function shareRequestedWords(machine: string, member: string, project: string): string {
  return `${machine} could not start a run in ${project}: the project is not shared with ${member}`
}

// The mandate pages (pages/mandates.ts), the machine page's card and the
// home's strip. A class's plural, for caps and counts: "50 sends".
export const MANDATE_CLASS_PLURALS: Readonly<Record<MandateClass, string>> = { read: "reads", change: "changes", send: "sends", delete: "deletes" }
const countWords = (n: number, cls: MandateClass): string => `${n.toLocaleString("en-GB")} ${n === 1 ? cls : MANDATE_CLASS_PLURALS[cls]}`
export const MANDATE_CLASS_CHOICES: Readonly<Record<MandateClass, { name: string; words: string }>> = {
  read: { name: "Read", words: "Always included." },
  change: { name: "Change", words: "Create and update things." },
  send: { name: "Send", words: "Messages, email and anything else that reaches people." },
  delete: { name: "Delete", words: "Remove things." },
}
export const MANDATE_STATE_PILLS: Readonly<Record<MandateState, string>> = { active: "active", paused: "paused", tripped: "tripped", stopped: "stopped", expired: "expired" }
export const MANDATE_STATE_WORDS: Readonly<Record<MandateState, string>> = {
  active: "What it covers goes through without asking.",
  paused: "Paused: everything asks again until its signer resumes it.",
  tripped: "It sent too many requests in a minute, so it stopped letting anything through until its signer resumes it with their passkey.",
  stopped: "Stopped for good. Sign a new one to let this machine carry on again.",
  expired: "Its time ran out. Sign a new one to let this machine carry on again.",
}
export const MANDATE_REPLACED_WORDS = "A newer mandate for this machine replaced it."
// A live mandate whose signer no longer stands where they signed: it covers
// nothing until they resume it with their passkey.
export function mandateLapsedWords(signer: string, yours: boolean): string {
  return `This covers nothing until ${yours ? "you resume it with your passkey" : `${signer} resumes it with their passkey`}: something changed since ${yours ? "you" : "they"} signed it, for example ${yours ? "your" : "their"} role, a recovery of ${yours ? "your" : "their"} account, what the machine may use or the workspace's identity rule.`
}
export const MANDATE_CARD_TITLE = "Carry on without asking"
export const MANDATE_CARD_LEAD = "Let this machine send held requests without asking you, within daily caps, until a date you choose. You can pause or stop it at any time."
export const MANDATE_TRUST_BUTTON = "Trust this machine"
export const MANDATE_OPEN_LINK = "Open the mandate"
export const MANDATE_PAUSE_BUTTON = "Pause"
export const MANDATE_RESUME_BUTTON = "Resume"
export const MANDATE_RESUME_HINT = "It asks for your passkey when the vault needs one."
export const MANDATE_RESUME_NO_PASSKEY_WORDS = "No passkey needed."
export const MANDATE_RENEW_LINK = "Renew"
export const MANDATE_SIGN_AGAIN_LINK = "Sign again with these terms"
export const MANDATE_STOP_TITLE = "Stop this mandate"
export const MANDATE_STOP_WORDS = "Stopping ends it at once and for good: what it covered asks again. To let the machine carry on later, sign a new one."
export const MANDATE_STOP_BUTTON = "Stop for good"
export const MANDATE_WAITING_WORDS = "Waiting for the vault..."
export const MANDATE_LIST_TITLE = "Carrying on without asking"
export const MANDATE_LIST_LEAD = "Machines a person let send held requests without asking, within caps, until a date. Pause one from here or from its machine."
export const MANDATE_LIST_EMPTY = "No machine is carrying on without asking."
export const MANDATE_LIST_ENDED = "Ended"
export const MANDATE_PAUSE_ALL_BUTTON = "Pause all"
export function mandatePauseAllConfirmWords(n: number): string {
  return `Pause ${n === 1 ? "this machine's mandate" : `all ${n} machines' mandates`}? Everything ${n === 1 ? "it lets" : "they let"} through asks again until ${n === 1 ? "its signer resumes it" : "each signer resumes theirs"}.`
}
// After Pause all, before the list is shown again: how many it could not
// pause, each changed since the page was loaded or no longer the reader's
// to pause.
export function mandatePauseAllRefusedWords(refused: number, total: number): string {
  return `${refused} of ${total} could not be paused: ${refused === 1 ? "it" : "each"} changed since this page loaded, or is no longer yours to pause.`
}
export const MANDATE_PAUSE_ALL_RELOAD = "Show where each stands"
export function mandateSignSameWords(machine: string): string {
  return `Sign the same for ${machine}`
}
export const MANDATE_WAITING_TITLE = "Waiting for you"
export const MANDATE_WAITING_LEAD = "Machines asked to carry on without asking. Open one to review its terms, change any of them and sign."
export const MANDATE_WAITING_OPEN = "Review and sign"
export const MANDATE_RECEIPTS_TITLE = "Went through on trust"
export const MANDATE_RECEIPTS_EMPTY = "Nothing has gone through on trust yet."
export const MANDATE_RECEIPTS_LEAD = "Each request this mandate let through without asking, newest first. Kept for 30 days."
export const MANDATE_RECEIPTS_OLDER = "Older"
export const MANDATE_HIDDEN_CREDENTIAL = "a credential you cannot see"
export const MANDATE_UNREVIEWED_ENTRY = "on a service nobody has reviewed"
// items: "all" covers a credential only while its signer manages where it
// lives, so the words always say whose home.
export function mandateAllItemsWords(signer: string, yours: boolean): string {
  return `Every credential it can use whose home ${yours ? "you manage" : `${signer} manages`}, now and later`
}
export const MANDATE_ALL_CREDENTIALS = mandateAllItemsWords("", true)
export const MANDATE_ALL_LATER_WORDS = "That includes credentials it can use later, and covers each only while you manage where it lives."
export const MANDATE_CAPS_WORDS = "Caps count requests in a UTC day, not amounts or recipients. Once a class reaches its cap, those requests ask as they would without a mandate; the others carry on."
export const MANDATE_TERM_LABELS = { machine: "Machine", signer: "Signed by", state: "State", classes: "May", credentials: "With", schedule: "When", note: "For", signed: "Signed", ends: "Ends", ended: "Ended", today: "Today" } as const
export const MANDATE_ALWAYS_WORDS = "At any time"
// After the credentials it names that the reader may see, or alone.
export function mandateHiddenItemsWords(n: number, alone: boolean): string {
  const some = n === 1 ? (alone ? MANDATE_HIDDEN_CREDENTIAL : "1 credential you cannot see") : `${n} credentials you cannot see`
  return alone ? some : `and ${some}`
}
export function mandateTodayWords(used: number, cap: number, cls: MandateClass): string {
  return `${used.toLocaleString("en-GB")} of ${countWords(cap, cls)} today`
}
const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
// "on Monday and Friday from 09:00 to 18:00, Europe/London time"
export function mandateScheduleWords(schedule: MandateSchedule): string {
  return `${joinWords(schedule.windows.map((w) => `on ${joinWords(w.days.map((d) => DAY_NAMES[d] ?? ""))} from ${w.from} to ${w.to}`), "or")}, ${schedule.tz} time`
}
// The day a mandate ends, as a date: "6 Feb 2027" in the reader's time
// zone when the page knows it, else "6 Feb 2027 UTC".
export function mandateDayWords(value: string | number, timeZone?: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value)
  if (timeZone === undefined) return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} UTC`
  const part = (type: Intl.DateTimeFormatPartTypes) => Number(new Intl.DateTimeFormat("en-GB", { timeZone, day: "numeric", month: "numeric", year: "numeric" }).formatToParts(d).find((p) => p.type === type)?.value)
  return `${part("day")} ${MONTHS[part("month") - 1]} ${part("year")}`
}
// Within its last days (MANDATE_ENDING_NOTICE_MS), a live mandate says how
// many are left, counting a part day as one.
export function mandateEndsInWords(days: number): string {
  return days <= 1 ? "Ends within a day" : `Ends in ${days} days`
}
export function machinesNeedResumeWords(n: number): string {
  return `${n} ${n === 1 ? "machine needs" : "machines need"} you to resume ${n === 1 ? "its mandate" : "their mandates"}`
}
export function machinesCarryingOnWords(n: number): string {
  return `${n} ${n === 1 ? "machine is" : "machines are"} carrying on without asking`
}
// The ask page, for an ask a mandate could have let through.
export function mandateCoverWords(machine: string): string {
  return `Let ${machine} carry on with requests like this`
}
export const MANDATE_COVER_HELD_WORDS = { paused: "This machine's mandate is paused, so this asked.", tripped: "This machine's mandate tripped on too many requests, so this asked." } as const
// The ask page, for an ask a cap alone kept a mandate from letting through.
export function mandateCappedWords(cls: MandateClass, cap: number): string {
  return `This machine's mandate has used today's ${countWords(cap, cls)}.`
}

// The sign page.
export const MANDATE_SIGN_EYEBROW = "Carry on without asking"
export function mandateSignTitle(machine: string): string {
  return `Let ${machine} carry on without asking`
}
export const MANDATE_SIGN_LEAD = "Choose what it may do and for how long. Before your passkey, the page says in plain words what you are signing."
export const MANDATE_CLASSES_LABEL = "What it may do"
export const MANDATE_ITEMS_LABEL = "With which credentials"
export const MANDATE_LISTED_ITEMS = "Only the ones ticked"
export const MANDATE_NO_CANDIDATES = "This machine can use no credential whose home you manage yet. You may still choose every one it can use later."
export const MANDATE_CAPS_LABEL = "At most a day"
export function mandateCapHint(max: number): string {
  return `Up to ${max.toLocaleString("en-GB")}.`
}
export const MANDATE_TTL_LABEL = "How long"
export function mandateTtlWords(days: number): string {
  return days === 1 ? "1 day" : `${days} days`
}
export const MANDATE_SCHEDULE_TICK = "Only at certain times"
export const MANDATE_SCHEDULE_HINT = "Times are 24-hour, for example 09:00. A To earlier than From runs past midnight. Outside these times it asks."
export const MANDATE_SCHEDULE_LABELS = { tz: "Time zone", days: "Days", from: "From", to: "To" } as const
export const MANDATE_NOTE_LABEL = "What it is for"
export function mandateDefaultNote(machine: string): string {
  return `Routine work on ${machine}`
}
export const MANDATE_NOTE_HINT = "Up to 200 characters. Everyone who can see the machine sees it."
export const MANDATE_SUMMARY_TITLE = "What you are signing"
export const MANDATE_SIGN_BUTTON = "Sign with passkey"
export const MANDATE_SIGNING_WORDS = "Waiting for your passkey..."
export const MANDATE_REPLACES_WORDS = "Signing replaces what this machine may do without asking now."
export function mandateProposedWords(machine: string): string {
  return `${machine} asked for this. You may change any of it before you sign.`
}
export const MANDATE_PROPOSAL_CLOSED_WORDS = "This proposal was signed or has expired. You may still sign these terms as a new mandate."
// A proposal closed on upgrade: it named credentials by slug before the
// vault kept which credential each meant.
export function mandateProposalUnboundWords(slugs: readonly string[]): string {
  return `Mehen closed this proposal when it was updated: it was made before Mehen kept which credential each name meant${slugs.length ? ` (it named ${slugs.join(", ")})` : ""}, so it cannot be signed. The machine can propose again.`
}
// A mandate renewed or copied: its terms are shown, not filled in.
export const MANDATE_SOURCE_RENEW_WORDS = "You are signing again a mandate this machine had. The form starts on the narrowest terms; its old terms were:"
export function mandateSourceFromWords(machine: string): string {
  return `You are copying terms from ${machine}'s mandate. The form starts on the narrowest terms; those terms are:`
}
export const MANDATE_SOURCE_PROPOSAL_WORDS = "This proposal can no longer be signed as it stands. The form starts on the narrowest terms; it proposed:"
// The credentials a renewed, copied or closed source named that the form
// cannot offer now: the machine cannot reach them, or the reader does not
// manage where they live. formerNames: a proposal's names from before Mehen kept
// which credential each meant, never matched to today's credentials.
export function mandateSourceUnavailableWords(unavailable: number, formerNames: readonly string[]): string {
  if (formerNames.length > 0) return `It named ${joinWords(formerNames)} before Mehen kept which credential each name meant, so those are not matched to the credentials here now.`
  return unavailable === 1 ? "One credential it named cannot be included in this mandate now." : `${unavailable} credentials it named cannot be included in this mandate now.`
}
export const MANDATE_USE_SOURCE_BUTTON = "Use these terms"
export const MANDATE_PROPOSAL_SUPERSEDED_WORDS = "This proposal closed because a mandate was signed for this machine since. You may still sign these terms to replace it."
export function mandateNotOwnerWords(owner: string): string {
  return `Only ${owner} can let this machine carry on without asking.`
}
export const MANDATE_CANDIDATES_UNREAD_WORDS = "The credentials this machine can use could not be read just now. Reload the page to try again."
export const MANDATE_TEAM_MACHINE_WORDS = "A team's machine cannot carry on without asking yet: team machines get mandates signed by two people later. For routine work now, the machine can propose a task grant."
export const MANDATE_NOTHING_TICKED = "Tick at least one credential, or choose every credential it can use whose home you manage."
export const MANDATE_NO_NOTE = "Say what it is for."
export const MANDATE_BAD_SCHEDULE = "Choose at least one day, a From and a To that differ, and a time zone this browser knows."
export const MANDATE_BAD_CAPS = "Each cap is a whole number from 1 to its most."
export const MANDATE_REVIEWED_WORDS = "On services Mehen has reviewed, it still asks for anything that mints or reads keys, adds webhooks or forwarding, shares access, moves money or that Mehen cannot read, and always for protected credentials."
export const MANDATE_UNREVIEWED_WORDS = "On services nobody has reviewed, Mehen can only judge a request by its method, address and shape: it asks for what those name and lets the rest through."
export const MANDATE_PAUSE_ANYTIME_WORDS = "You can pause it from here or from the machine at any time."
// What a mandate's terms say, in the sign page's own words: the first sentence from the terms, then what it never covers.
// items: "all", or the slugs listed.
// timeZone: the reader's, when the page knows it.
export type MandateSummaryInput = { machine: string; classes: readonly MandateClass[]; caps: Readonly<Record<MandateClass, number>>; items: "all" | readonly string[]; endsAt: string | number; schedule: MandateSchedule | null; timeZone?: string }
const NAMED_ITEMS_MAX = 5
function summaryItemWords(items: "all" | readonly string[]): string {
  return items === "all" ? "every credential it can use whose home you manage, now and later"
    : items.length === 0 ? "no credential that can be included now"
    : items.length === 1 ? (items[0] ?? "")
    : items.length <= NAMED_ITEMS_MAX ? `${items.length} credentials, ${joinWords(items)}`
    : `${items.length} credentials`
}
export function mandateSummaryWords(input: MandateSummaryInput): string[] {
  const ticked = MANDATE_CLASS_ORDER.filter((c) => input.classes.includes(c))
  const items = summaryItemWords(input.items)
  const caps = joinWords(ticked.map((c) => countWords(input.caps[c], c)))
  const when = input.schedule !== null ? `, only ${mandateScheduleWords(input.schedule)}` : ""
  return [
    `${input.machine} may ${mandateClassWords(ticked)} with ${items}, without asking you, until ${mandateDayWords(input.endsAt, input.timeZone)}, at most ${caps} a day${when}.`,
    ...(input.items === "all" ? [MANDATE_ALL_LATER_WORDS] : []),
    MANDATE_REVIEWED_WORDS,
    MANDATE_UNREVIEWED_WORDS,
    MANDATE_PAUSE_ANYTIME_WORDS,
  ]
}
