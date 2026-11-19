// Renders every UI page through the real page shell with fixture data, as
// static HTML, then screenshots each one with headless Chrome at two phone
// widths, a tablet, the top bar and the rail, in light and dark, and checks
// every one for layout that spills, clips or scrolls sideways. A design
// tool for people and a check for CI: nothing here is imported by the
// Worker, and nothing it writes is served.
//
//   cd apps/vault && bun run build:ui
//   bun scripts/ui-gallery.ts <out-dir> [--no-shots | --measure-only] [--allow-layout] [--chrome <path>]
//
// The directory gets one <id>.html per state, the built assets (app.css,
// the fonts, the favicon) under assets/, png/<id>-<width>-<scheme>.png,
// layout.json with every layout finding, and index.html as a contact sheet.
// The run exits 1 when the layout check finds anything new against
// scripts/ui-layout-baseline.json, or a baseline entry that no longer
// occurs, unless --allow-layout is given. --measure-only loads and checks
// every state at every width and scheme without writing screenshots (what
// CI runs); --no-shots skips Chrome entirely. Without --chrome the script
// looks for Chrome or Chromium where macOS and Linux install it.
// Buttons are shown enabled: on the live pages the client bundle enables
// them once the page's own checks (digest, ticks) pass.

import { cp, mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import type { ConnectView, DeviceView, IntakeView, ItemDescription, ItemSummary, PendingAsk, Project } from "@mehen/protocol/api"
import { fingerprintGroups, fingerprintOf, fingerprintWords as wordsOf } from "@mehen/protocol/fingerprint"
import { OAUTH_PROVIDERS, TEMPLATES, connectionPolicy } from "@mehen/protocol/templates"
import {
  type ActivityDay,
  cardHead,
  cardText,
  chartLegend,
  copyBox,
  emptyState,
  fingerprintGlyphs,
  fingerprintWords,
  kv,
  notice as inlineNotice,
  pageHead,
  pill,
  responsiveTable,
  ring,
  row,
  sparklineWithCount,
  stateCard,
  steps,
  timeTag,
  timer,
  weekChart,
} from "../src/ui/components.ts"
import { type Html, escapeHtml, html } from "../src/ui/html.ts"
import { BRAND_SLUGS, ICON_NAMES, brandLogo, icon, iconTile, kindTile, machineDot, serviceTile, vaultMark } from "../src/ui/icons.ts"
import { NOT_FOUND_ERROR, type PageInput, SESSION_ENDED_HEADING, type Viewer, errorPageInput, renderDocument, sessionEndedError } from "../src/ui/layout.ts"
import { recoverPage, recoverPasskeyPage, signinPage } from "../src/ui/pages/account.ts"
import { workspaceApprovalPage } from "../src/ui/pages/workspace-asks.ts"
import { workspaceHomePage } from "../src/ui/pages/workspaces.ts"
import { type PaletteMatch, type PaletteTile, buildEntries, filterEntries, GROUP_WORDS, timeLeftWords, titlePieces } from "../src/ui/client/palette-logic.ts"
import { connectPage } from "../src/ui/pages/connect.ts"
import { intakePage } from "../src/ui/pages/intake.ts"
import { oidcGallery } from "../src/ui/oidc-gallery.ts"
import { shellGallery } from "../src/ui/shell-gallery.ts"
import { peopleGallery } from "../src/ui/people-gallery.ts"
import { accountGallery } from "../src/ui/account-gallery.ts"
import { workspaceProjectsGallery } from "../src/ui/workspace-projects-gallery.ts"
import { workspaceAsksGallery } from "../src/ui/workspace-asks-gallery.ts"
import { VIEWERS, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import { galleryEmailApproval } from "../src/ui/workspace-asks-gallery.ts"
import { settingsGallery } from "../src/ui/settings-gallery.ts"
import { consoleGallery } from "../src/ui/console-gallery.ts"
import { policyRulesGallery } from "../src/ui/policy-rules-gallery.ts"
import { postureGallery } from "../src/ui/posture-gallery.ts"
import { mandatesGallery } from "../src/ui/mandates-gallery.ts"
import { CHROME_CANDIDATES, type Cdp, findChrome, launchChrome } from "./chrome.ts"
import { type EvaluateReply, GALLERY_ENTRY_META, type LayoutBaselineEntry, type LayoutFinding, type LayoutIssue, type NavigateReply, acceptProbe, baselineKey, checkMeasured, checkNavigation, compareBaseline } from "./ui-layout-gate.ts"

// ---------------------------------------------------------------- fixtures

// Every relative time on the pages is measured from here, so the gallery
// renders the same whenever it is run.
const NOW = Date.parse("2026-10-24T18:30:00Z")

function at(minutesFromNow: number): string {
  return new Date(NOW + minutesFromNow * 60_000).toISOString()
}

const OWNER: Viewer = { name: "Alex", tenantName: "Alex's vault", role: "owner" }

const MAC_MINI = { device: "dev_7k2m9xq4rt8w", deviceName: "Mac mini", session: "native-app/2026-10-24T17:58" }
const LINUXBOX = { device: "dev_3n8pz5vb1hjc", deviceName: "the Linux box", session: null }

function templatePolicy(id: string): ItemDescription["policy"] {
  const template = TEMPLATES[id]
  if (template) return template.policy
  const provider = OAUTH_PROVIDERS[id]
  if (provider) return connectionPolicy(provider)
  throw new Error(`no template ${id}`)
}

const OPENAI: ItemSummary = {
  slug: "openai-personal",
  kind: "api-key",
  provider: "openai",
  account: null,
  accountVerified: false,
  tags: ["ai"],
  ceiling: "placeholder",
  hosts: ["api.openai.com"],
  status: "active",
  updatedAt: at(-3 * 24 * 60),
  lastUsedAt: at(-26 * 60),
  policy: templatePolicy("openai"),
}

const GMAIL: ItemSummary = {
  slug: "gmail-alex",
  kind: "oauth-connection",
  provider: "google-gmail",
  account: "alex@example.com",
  accountVerified: true,
  tags: ["google", "mail"],
  ceiling: "relay",
  hosts: ["gmail.googleapis.com"],
  status: "active",
  updatedAt: at(-60),
  lastUsedAt: at(-32),
  policy: templatePolicy("google-gmail"),
}

const GOOGLE_CLIENT: ItemSummary = {
  slug: "google-oauth-client",
  kind: "oauth-client",
  provider: "google-oauth-client",
  account: null,
  accountVerified: false,
  tags: ["google"],
  ceiling: "relay",
  hosts: ["oauth2.googleapis.com"],
  status: "active",
  updatedAt: at(-2 * 24 * 60),
  lastUsedAt: at(-60),
  policy: templatePolicy("google-oauth-client"),
}

// The GitHub template's policy with one allow rule a member added, so it
// no longer matches the template and is described from its matchers.
const GITHUB_POLICY: ItemDescription["policy"] = {
  default: "approve",
  rules: [
    { action: "allow", methods: ["GET", "HEAD"], note: "reads" },
    { action: "allow", methods: ["POST"], paths: ["/graphql"], body: "graphql-query", note: "read-only GraphQL queries" },
    { action: "allow", methods: ["POST"], paths: ["/repos/example/*/issues", "/repos/example/*/issues/*/comments"], note: "issues and comments on my own repositories" },
    { action: "deny", methods: ["POST", "PUT", "PATCH", "DELETE"], paths: ["/user/keys/**", "/repos/*/*/keys/**"], note: "SSH, signing and deploy keys" },
    { action: "deny", methods: ["POST", "PUT", "PATCH", "DELETE"], paths: ["/repos/*/*/hooks/**", "/orgs/*/hooks/**"], note: "webhooks" },
    { action: "deny", methods: ["POST", "PUT", "PATCH", "DELETE"], paths: ["/repos/*/*/collaborators/**", "/orgs/*/invitations/**"], note: "collaborators and invitations give someone else access" },
    { action: "approve", paths: ["/graphql"], body: "graphql-mutation", note: "GraphQL requests that are not plainly a query" },
  ],
}

const GITHUB: ItemSummary = {
  slug: "github-example",
  kind: "api-key",
  provider: "github-pat",
  account: "example",
  accountVerified: true,
  tags: ["code"],
  ceiling: "placeholder",
  hosts: ["api.github.com"],
  status: "active",
  review: { reason: "api.github.com echoed the token back in a response body", since: at(-2 * 24 * 60 + 15) },
  updatedAt: at(-9 * 24 * 60),
  lastUsedAt: at(-5),
  policy: GITHUB_POLICY,
}

const CALENDAR: ItemSummary = {
  slug: "calendar-alex",
  kind: "oauth-connection",
  provider: "google-calendar",
  account: "alex@example.com",
  accountVerified: true,
  tags: ["google"],
  ceiling: "relay",
  hosts: ["www.googleapis.com"],
  status: "needs_reauth",
  updatedAt: at(-6 * 60),
  lastUsedAt: at(-6 * 60),
  policy: templatePolicy("google-calendar"),
}

// No template: the agent proposed the host, and every call needs an approval.
const WEATHER: ItemSummary = {
  slug: "weather-api",
  kind: "api-key",
  provider: null,
  account: null,
  accountVerified: false,
  tags: ["home"],
  ceiling: "relay",
  hosts: ["api.weatherapi.com"],
  status: "active",
  updatedAt: at(-20),
  lastUsedAt: null,
  policy: { default: "approve", rules: [{ action: "allow", methods: ["GET"], paths: ["/v1/current.json", "/v1/forecast.json"], note: "read mail" }] },
}

const ITEMS: ItemSummary[] = [GMAIL, GITHUB, OPENAI, GOOGLE_CLIENT, CALENDAR, WEATHER]

// Fixture keys: a thumbprint stays here, the views carry what they may.
const ENROL_THUMBPRINT = "ZlSQ8zyOFnhkWls5Qf2JrXm9cTbA7hLp0eNvK1sYdGw"
const MAC_MINI_THUMBPRINT = "pR3vQ9xKz2mN7bT4wL8cF1hJ6dS0gY5aV2eU9iO3kXw"
const MACBOOK_THUMBPRINT = "H4k2Lm9Qp7Rt1Vx5Yz8Bc3Df6Gh0Jk2Mn4Pq7Sw9Tvw"

const DEVICES: DeviceView[] = [
  {
    device: MAC_MINI.device,
    name: "Mac mini",
    backend: "secure-enclave",
    host: "sam-mac-mini.home.lab",
    scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"] },
    createdAt: at(-12 * 24 * 60),
    lastSeenAt: at(-4),
    revoked: false,
    fingerprintWords: wordsOf(MAC_MINI_THUMBPRINT),
  },
  {
    device: LINUXBOX.device,
    name: "the Linux box",
    backend: "software",
    host: "linuxbox.home.lab",
    scope: { tags: ["code"], projects: ["prj_j4k9mw2x"], maxEnvironment: "unprotected", modes: ["relay", "placeholder"] },
    createdAt: at(-4 * 24 * 60),
    lastSeenAt: at(-26 * 60),
    revoked: false,
    fingerprintWords: wordsOf(ENROL_THUMBPRINT),
  },
  {
    device: "dev_q1w2e3r4t5y6",
    name: "MacBook (old)",
    backend: "software",
    host: "alexs-macbook.local",
    scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay"] },
    createdAt: at(-40 * 24 * 60),
    lastSeenAt: at(-20 * 24 * 60),
    revoked: true,
    revokedAt: at(-19 * 24 * 60),
    fingerprintWords: wordsOf(MACBOOK_THUMBPRINT),
  },
]

const PROJECTS: Project[] = [
  {
    id: "prj_j4k9mw2x",
    slug: "agent-runtime",
    remotes: ["github.com/example/agent-runtime"],
    defaultEnv: "dev",
    environments: [
      { name: "dev", protected: false, fences: [] },
      { name: "prod", protected: true, fences: ["db.example.com", "api.example.com"] },
    ],
    vars: [
      { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai-personal", field: "key", protectedBy: [{ project: "agent-runtime", env: "prod" }] },
      { name: "GITHUB_TOKEN", env: "dev", source: "item", item: "github-example", field: null },
      { name: "LOG_LEVEL", env: "dev", source: "plain", item: null, field: null },
      { name: "OPENAI_API_KEY", env: "prod", source: "item", item: "openai-personal", field: "key" },
      { name: "DATABASE_URL", env: "prod", source: "unset", item: null, field: null },
    ],
  },
  {
    id: "prj_8sd2hf7qlp",
    slug: "mehen",
    remotes: ["github.com/example/mehen"],
    defaultEnv: "dev",
    environments: [
      { name: "dev", protected: false, fences: [] },
      { name: "staging", protected: false, fences: [] },
      { name: "prod", protected: true, fences: [] },
    ],
    vars: [],
  },
]

const ENROL_HIDDEN = 2

const SEAL_KEY = { jwk: { kty: "EC" as const, crv: "P-256" as const, x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }, kid: "seal_2026_10" }

function intake(overrides: Partial<IntakeView> & Pick<IntakeView, "kind" | "slug" | "fields" | "binding">): IntakeView {
  return {
    intake: "int_9f2k7m3qwx",
    status: "open",
    provider: null,
    providerName: null,
    reason: "",
    requestedBy: MAC_MINI,
    rotates: false,
    injection: { value: null, verified: true },
    customPolicy: (overrides.provider ?? null) === null && overrides.rotates !== true,
    tags: [],
    sealKey: SEAL_KEY,
    expiresAt: at(27),
    ...overrides,
  }
}

const ORIGIN = "https://app.mehen.dev"

const INTAKE_GOOGLE_CLIENT = intake({
  kind: "oauth-client",
  slug: "google-oauth-client",
  provider: "google-oauth-client",
  providerName: "Google OAuth client",
  reason: "An OAuth client so the agent can connect Gmail as alex@example.com (\"gmail-alex\"): triage your inbox each morning, label what can wait, and draft replies for you to send.",
  fields: [
    { name: "client_id", label: "Client ID", secret: false, required: true, multiline: false, hint: null },
    { name: "client_secret", label: "Client secret", secret: true, required: true, multiline: false, hint: null },
  ],
  binding: { value: { hosts: ["oauth2.googleapis.com"], paths: ["/token", "/revoke"], methods: ["POST"] }, verified: true },
  tags: ["google"],
})

const INTAKE_GOOGLE_CLIENT_THEN: IntakeView = { ...INTAKE_GOOGLE_CLIENT, then: { connect: "con_4h8s2kd9pq", url: `${ORIGIN}/c/con_4h8s2kd9pq` } }

const INTAKE_OAUTH_CLIENT_PROPOSED = intake({
  kind: "oauth-client",
  slug: "fastmail-oauth-client",
  reason: "Fastmail has no template in the vault. This client lets me connect your Fastmail account through its OAuth endpoint.",
  fields: [
    { name: "client_id", label: "Client ID", secret: false, required: true, multiline: false, hint: null },
    { name: "client_secret", label: "Client secret", secret: true, required: true, multiline: false, hint: null },
  ],
  binding: { value: { hosts: ["api.fastmail.com"], paths: ["/oauth/token"], methods: ["POST"] }, verified: false },
  tags: ["mail"],
})

const INTAKE_OPENAI = intake({
  kind: "api-key",
  slug: "openai-personal",
  provider: "openai",
  providerName: "OpenAI API key",
  reason: "Summaries and embeddings for the brain. Reads and model calls go through without asking; deletes and admin calls do not.",
  fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }],
  binding: { value: { hosts: ["api.openai.com"] }, verified: true },
  tags: ["ai"],
})

const INTAKE_API_KEY_PROPOSED = intake({
  kind: "api-key",
  slug: "weather-api",
  reason: "Morning briefing: the forecast for Sheffield. WeatherAPI has no template, so I am proposing where the key may go and how it is sent.",
  fields: [{ name: "key", label: "Key", secret: true, required: true, multiline: false, hint: null }],
  binding: { value: { hosts: ["api.weatherapi.com"], paths: ["/v1/**"], methods: ["GET"] }, verified: false },
  injection: { value: { in: "query", name: "key", field: "key" }, verified: false },
  tags: ["home"],
})

const INTAKE_ROTATE = intake({
  kind: "api-key",
  slug: "github-example",
  provider: "github-pat",
  providerName: "GitHub personal access token",
  reason: "GitHub echoed the old token back on 22 Oct, so the vault flagged it. Please paste a fresh fine-grained token.",
  rotates: true,
  fields: [{ name: "key", label: "Token", secret: true, required: true, multiline: false, hint: null }],
  binding: { value: { hosts: ["api.github.com"] }, verified: true },
  tags: ["code"],
})

const INTAKE_SSH_KEY = intake({
  kind: "ssh-key",
  slug: "deploy-key",
  reason: "Deploys to the three web hosts sign in with this key.",
  fields: [
    { name: "private_key", label: "Private key", secret: true, required: true, multiline: true, hint: null },
    { name: "public_key", label: "Public key", secret: false, required: false, multiline: false, hint: null },
  ],
  binding: { value: { hosts: ["web-1.example.com", "web-2.example.com", "web-3.example.com"], ports: [22] }, verified: false },
  tags: ["deploy"],
})

const INTAKE_LONG_NAMES = intake({
  kind: "api-key",
  slug: "home-assistant-long-lived-access-token-kitchen-tablet",
  reason: "The kitchen tablet's dashboard reads sensor states.",
  fields: [{ name: "key", label: "Key", secret: true, required: true, multiline: false, hint: null }],
  binding: { value: { hosts: ["homeassistant-kitchen-tablet-dashboard.home.thejays.example"] }, verified: false },
  tags: ["home"],
})

function connect(overrides: Partial<ConnectView>): ConnectView {
  return {
    connect: "con_4h8s2kd9pq",
    status: "open",
    provider: "google-gmail",
    providerName: "Gmail",
    slug: "gmail-alex",
    scopes: ["https://www.googleapis.com/auth/gmail.modify", "openid", "email"],
    expect: "alex@example.com",
    reason: "Triage your inbox each morning, label what can wait, and draft replies for you to send.",
    requestedBy: MAC_MINI,
    reconnect: false,
    currentScopes: null,
    account: null,
    message: null,
    expiresAt: at(14),
    ...overrides,
  }
}

const GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
const GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"

// ---------------------------------------------------------------- foundation fixtures

// A week of calls per credential, for the strips and the chart. No read
// fills this yet; the live pages hide the strip when they have no data.
const WEEK_GMAIL: ActivityDay[] = [
  { allowed: 18, approved: 1, refused: 0 },
  { allowed: 26, approved: 0, refused: 0 },
  { allowed: 31, approved: 2, refused: 0 },
  { allowed: 12, approved: 0, refused: 0 },
  { allowed: 22, approved: 1, refused: 1 },
  { allowed: 9, approved: 0, refused: 0 },
  { allowed: 24, approved: 2, refused: 0 },
]
const WEEK_QUIET: ActivityDay[] = [
  { allowed: 2, approved: 0, refused: 0 },
  { allowed: 0, approved: 0, refused: 0 },
  { allowed: 3, approved: 0, refused: 1 },
  { allowed: 0, approved: 0, refused: 0 },
  { allowed: 0, approved: 0, refused: 0 },
  { allowed: 1, approved: 0, refused: 0 },
  { allowed: 0, approved: 0, refused: 0 },
]
const WEEK_LABELS = ["Sat", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri"]

const PENDING: PendingAsk[] = [
  {
    kind: "approval",
    id: "apr_6t3vb9nx2w",
    title: "Send an email to priya@acme.example",
    url: `${ORIGIN}/a/apr_6t3vb9nx2w`,
    expiresAt: at(9),
    requestedBy: MAC_MINI,
    item: "gmail-alex",
    bindingCode: "MK7RQ4",
  },
  {
    kind: "intake",
    id: "int_9f2k7m3qwx",
    title: "Paste the key for weather-api",
    url: `${ORIGIN}/i/int_9f2k7m3qwx`,
    expiresAt: at(27),
    requestedBy: MAC_MINI,
    item: "weather-api",
    kindRequested: "api-key",
    provider: null,
  },
  {
    kind: "connect",
    id: "con_4h8s2kd9pq",
    title: "Reconnect calendar-alex to Google Calendar as alex@example.com",
    url: `${ORIGIN}/c/con_4h8s2kd9pq`,
    expiresAt: at(12),
    requestedBy: LINUXBOX,
    item: "calendar-alex",
    provider: "google-calendar",
    account: "alex@example.com",
  },
  { kind: "review", id: "github-example", title: "Review github-example", url: `${ORIGIN}/items/github-example`, expiresAt: null, requestedBy: null, item: "github-example", reason: "api.github.com echoed the token back in a response body" },
]

// A hostile ask: the title carries a right-to-left override and the
// device name a zero-width space; both must show as markers.
const PENDING_HOSTILE: PendingAsk[] = [
  {
    kind: "approval",
    id: "apr_8w1xc5hn3v",
    title: "Send an email to \u202Emoc.rekcatta@yrrah\u202C",
    url: `${ORIGIN}/a/apr_8w1xc5hn3v`,
    expiresAt: at(4),
    requestedBy: { device: LINUXBOX.device, deviceName: "Sam\u200b on Mac mini", session: "Sam" },
    item: "gmail-alex",
    bindingCode: "RT6M2P",
  },
]

// ---------------------------------------------------------------- home fixtures (V-7's shapes)

const SELF = "mem_alex"

const INTAKE_MEMBER: IntakeView = { ...INTAKE_OPENAI, requestedBy: { member: SELF, self: true }, reason: "Started from Connect a service in the vault." }

// The palette as the client builds it, rendered here as static markup
// from the same entries and matches, so the gallery can show a query.
function paletteTile(tile: PaletteTile): Html {
  if (tile.kind === "brand") return html`<span class="tile">${brandLogo(tile.slug)}</span>`
  if (tile.kind === "icon") return iconTile(tile.name)
  return html`<span class="tile letter" aria-hidden="true"><span>${tile.letter}</span></span>`
}

function paletteTitle(match: PaletteMatch): Html {
  return html`<b>${titlePieces(match.entry.title, match.ranges).map((p) => (p.kind === "marker" ? html`<mark class="marker">${p.text}</mark>` : p.kind === "match" ? html`<mark>${p.text}</mark>` : p.text))}</b>`
}

function paletteStatic(query: string, pending: PendingAsk[], items: ItemSummary[] = ITEMS, devices: DeviceView[] = DEVICES): string {
  const entries = buildEntries({ pending, items, devices, projects: PROJECTS }, NOW)
  const matches = filterEntries(entries, query)
  let group: string | null = null
  const nodes: Html[] = []
  matches.forEach((match, i) => {
    if (match.entry.group !== group) {
      group = match.entry.group
      nodes.push(html`<div class="palette-group" role="presentation">${GROUP_WORDS[match.entry.group]}</div>`)
    }
    const left = timeLeftWords(match.entry, NOW)
    nodes.push(
      html`<a class="palette-item" href="${match.entry.href}" id="palette-item-${i}" role="option" aria-selected="${i === 0 ? "true" : "false"}" tabindex="-1">${paletteTile(match.entry.tile)}<span class="text">${paletteTitle(match)}<span>${left !== null ? `${left} \u00b7 ` : ""}${cardText(match.entry.sub)}</span></span>${match.entry.action !== null ? html`<span class="pill muted">${match.entry.action}</span>` : ""}</a>`,
    )
  })
  if (nodes.length === 0) nodes.push(html`<p class="palette-note">${query.trim() === "" ? "Nothing to show yet." : "Nothing matches."}</p>`)
  return html`${nodes}`.value
}

const FP_GROUPS = fingerprintGroups(fingerprintOf(ENROL_THUMBPRINT))
const FP_WORDS = wordsOf(ENROL_THUMBPRINT)
const FP_HIDDEN = ENROL_HIDDEN
const FP_TYPED = FP_GROUPS[FP_HIDDEN]
const FP_WRONG = `${FP_TYPED.slice(0, 3)}${FP_TYPED.endsWith("7") ? "9" : "7"}`

function componentCard(title: string, body: Html): Html {
  return html`<section class="card">${cardHead(title)}${body}</section>`
}

// The longest realistic values: every part below must
// wrap or ellipsise them at 360 px without leaving its card.
const LONG_WORKSPACE = "The Montgomery-Fitzwilliam household, office and consultancy vault"
const LONG_SLUG = "montgomery-fitzwilliam-office-and-consultancy-production-openai"
const LONG_EMAIL = `${"alexandra.montgomery-fitzwilliam.".repeat(6)}office@${"consultancy-".repeat(8)}example.com`
const LONG_HOST = `${"api-gateway-".repeat(9)}eu-west-1.internal.example.com`

function pagePartsCards(): Html {
  return html`${componentCard("Page head", pageHead({ tile: serviceTile({ provider: "openai", slug: LONG_SLUG }), eyebrow: "Credential", title: LONG_SLUG, lead: html`Belongs to ${LONG_WORKSPACE}. Used by <code>${LONG_HOST}</code>.`, actions: html`<a class="btn secondary sm" href="#">${icon("refresh")}<span>Replace the secret with passkey</span></a><a class="btn quiet sm" href="#">All of its history</a>` }))}
    <section class="card">${cardHead("Card head with actions", html`<div class="card-actions"><a class="btn secondary sm" href="#">Add a credential to this workspace</a><a class="more-link" href="#">See every credential ${icon("chevronRight")}</a></div>`)}
      <p>The title takes the line; the actions wrap under it when the card is narrow.</p>
      <div class="actions"><button type="button" class="btn primary">${icon("passkey")}<span>Accept this scope on my own machine with passkey</span></button><button type="button" class="btn secondary">${icon("passkey")}<span>Add a second passkey instead</span></button></div>
      <div class="actions"><button type="button" class="btn secondary">Revoke</button></div>
      <div class="actions"><button type="button" class="btn danger-quiet">${icon("passkey")}<span>A lone button keeps its own width on a wide card</span></button></div>
    </section>
    ${componentCard("Key-value list", kv([
      ["Workspace", html`${LONG_WORKSPACE} <code>${LONG_SLUG}</code>`],
      ["Email", LONG_EMAIL],
      ["Allowed to go only to", html`<code>${LONG_HOST}</code>`],
      ["Fingerprint", html`<code class="hash">${MAC_MINI_THUMBPRINT}${ENROL_THUMBPRINT}</code>`],
      ["Last used", timeTag(at(-26 * 60))],
    ]))}
    ${componentCard("Table that becomes a list", responsiveTable(["From", "Level", "Protected run", "Protected edit", "Until"], [
      [html`Team <b>Platform</b> <code>${LONG_SLUG}</code>`, "manage", "yes", "no", timeTag(at(7 * 24 * 60))],
      ["Workspace owner", "manage", "yes", "yes", "no end"],
    ]))}
    ${componentCard("A row with two pills", html`<ul class="rows">${row({ tile: serviceTile({ provider: "openai", slug: LONG_SLUG }), title: LONG_SLUG, sub: "OpenAI API key", side: html`${pill("Needs review", "warn")}${pill("Protected", "accent", false)}` })}</ul>`)}
    <div class="stack">
      ${inlineNotice("info", "Something the page wants you to know", html`It names <code>${LONG_HOST}</code> in full.`)}
      ${inlineNotice("warn", "Needs review since Wednesday", "The template behind it changed.", html`<a class="btn secondary sm" href="#">Review it</a>`)}
      ${inlineNotice("error", "The vault did not answer", "Nothing was changed; try again.")}
      ${inlineNotice("ok", "Saved", LONG_EMAIL)}
    </div>
    <section class="card"><h2>A form row</h2><div class="share-row"><label class="tick"><input type="checkbox"><span><code>platform</code></span></label><select aria-label="Level for platform"><option>use</option><option>manage (not for guests)</option></select><label class="tick"><input type="checkbox"><span>including protected environments</span></label></div>
      <label class="field invalid"><span class="label">Name</span><input type="text" value="${LONG_SLUG}"><span class="field-error" role="alert">Use lowercase letters, digits and dashes.</span></label>
      ${copyBox("tn_8kQw2Lm4Zp7Rt5Vx")}<p class="copybox-caption">The workspace's id; it does not change when the workspace is renamed.</p>
    </section>`
}

function componentsPage(): PageInput {
  const tones = ["ok", "warn", "danger", "accent", "muted"] as const
  const body = html`<header class="page-head"><h1>Components</h1><div class="stats"><span class="stat"><b>533</b> calls this week</span><span class="stat"><b>9</b> needed you</span><span class="stat danger"><b>3</b> refused</span></div></header>
    ${componentCard("Pills", html`<p class="stack" data-gallery="pills">${tones.map((t) => html`<span>${pill(`${t} with a dot`, t)} ${pill(`${t} fact`, t, false)}</span>`)}</p>`)}
    ${componentCard("Rings", html`<div class="stack"><p>${timer(1, "15 min left")} ${timer(0.6, "9 min left")} ${timer(0.2, "3 min left", undefined, "warn")} ${timer(0.05, "54 s left", undefined, "danger")} ${timer(0, "ran out", undefined, "danger")}</p><p>${ring(0.6, undefined, { expiresAt: at(9), totalSeconds: 900 }, "lg")} live, driven by the client from <code>data-expires</code></p></div>`)}
    ${componentCard("Strips and the week", html`<p>${sparklineWithCount(WEEK_GMAIL)} gmail-alex, ${sparklineWithCount(WEEK_QUIET)} a quiet one</p>${weekChart(WEEK_GMAIL, WEEK_LABELS)}${chartLegend()}`)}
    ${componentCard("Copy box", copyBox('mehen enrol --name "the Linux box"'))}
    ${componentCard("Card text with markers", html`<p>Generated by the vault: ${cardText("Pay \u202Efdp.exe\u202C now")}</p><p>Typed by someone else, left plain: ${cardText("Pay [RLO U+202E]fdp.exe now")}</p>`)}
    ${stateCard({ tone: "expired", icon: "clock", heading: html`This link ran out at <span class="ran-out">18:12</span>`, lead: html`Nothing happened. <b>the Linux box</b> is still waiting with the same key.`, primary: html`<a class="btn primary" href="#">${icon("arrowRight")}<span>Open the fresh link</span></a>`, secondary: html`<a class="btn secondary" href="#">${icon("sparkle")}<span>Ask the agent to try again</span></a>`, or: html`<p>Or, at the machine:</p>${copyBox('mehen enrol --name "the Linux box"')}` })}
    ${stateCard({ tone: "ok", icon: "check", heading: "You approved this at 18:31", lead: "The agent can send the email once, within the next 10 minutes." })}
    ${stateCard({ tone: "danger", icon: "x", heading: "The connection failed", lead: "Google did not complete the connection. Nothing was saved." })}
    ${stateCard({ tone: "muted", icon: "info", heading: "Already filled in", lead: "This request has been completed. The agent can use the credential now." })}
    ${componentCard("Empty state", emptyState("key", "No credentials yet", "An agent adds one when it needs one: it posts a link, you paste the secret, the vault seals it. You never type a secret into chat.", html`<a class="btn secondary sm" href="#">${icon("grid")}<span>Connect a service</span></a>`))}
    <section class="card fp">
      <p class="eyebrow">Does the terminal show this key?</p>
      ${fingerprintWords(FP_WORDS)}
      <p class="small muted">Hidden</p>${fingerprintGlyphs(FP_GROUPS, FP_HIDDEN)}
      <p class="small muted">Typed</p>${fingerprintGlyphs(FP_GROUPS, FP_HIDDEN, "typed", FP_TYPED)}
      <p class="small muted">Wrong</p>${fingerprintGlyphs(FP_GROUPS, FP_HIDDEN, "wrong", FP_WRONG)}
      <div class="fp-input"><label for="group">Type the third group</label><input id="group" type="text" placeholder="····" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="4"><span class="hint">${icon("info", "inline")} The page never contains it. No I, L, O or U.</span></div>
    </section>
    ${componentCard(
      "Steps",
      html`<div class="progress"><span class="done"></span><span class="current"></span><span></span></div>${steps([
        { title: "Open the credentials page", body: html`Pick or create a project. <a href="#">console.cloud.google.com ${icon("external", "inline")}</a>`, state: "done" },
        { title: "Set up the consent screen", body: html`<b>Internal</b> for a Workspace account, otherwise <b>External</b>.<div class="callout">${icon("alert")}<span>If it is External, <b>publish the app</b>, or Google signs you out every seven days.</span></div>`, state: "current" },
        { title: "Create a Web application client", body: html`Add this redirect URI exactly: ${copyBox("https://app.mehen.dev/oauth/callback")}`, state: "todo" },
      ])}`,
    )}
    ${componentCard("Buttons", html`<div class="stack"><p><button type="button" class="btn primary">${icon("passkey")}<span>Approve with passkey</span></button> <button type="button" class="btn secondary">Deny</button> <button type="button" class="btn danger-quiet">${icon("snowflake")}<span>Freeze</span></button> <button type="button" class="btn danger">Delete gmail-alex</button> <button type="button" class="btn quiet">Cancel</button></p><p><button type="button" class="btn primary sm">Decide</button> <button type="button" class="btn secondary sm">Open</button> <button type="button" class="btn primary" disabled data-keep-disabled>Disabled</button> <button type="button" class="btn primary busy">Busy</button></p><p><button type="button" class="button widen">Widen (compatibility)</button></p></div>`)}
    ${componentCard("Callouts and notices", html`<div class="stack"><div class="notice error"><p class="notice-title">Check this first</p><p>A problem the page found before anything left the browser.</p></div><div class="notice info"><p>Something the page wants you to know.</p></div><div class="notice warn"><p>Needs review since Wednesday.</p></div></div>`)}
    ${pagePartsCards()}`
  return { title: "Components", viewer: OWNER, boot: { page: "gallery" }, body, links: { credentials: true, catalogue: true, settings: true } }
}

function iconsPage(): PageInput {
  const body = html`<header class="page-head"><h1>Icons</h1></header>
    <section class="card">${cardHead("The mark")}<p class="stack"><span class="brand">${vaultMark()}<span class="brand-text"><span class="brand-name">Mehen</span><span class="brand-sub">Alex's vault</span></span></span></p></section>
    <section class="card">${cardHead("Interface")}<ul class="rows compact">${ICON_NAMES.map((n) => row({ tile: iconTile(n), title: n, sub: html`<code>icon("${n}")</code>` }))}</ul></section>
    <section class="card">${cardHead("Services")}<ul class="rows compact">${BRAND_SLUGS.map((s) => row({ tile: html`<span class="tile">${brandLogo(s)}</span>`, title: s, sub: html`<span class="tile sm">${brandLogo(s)}</span> <span class="tile lg">${brandLogo(s)}</span> <span class="tile xl">${brandLogo(s)}</span>` }))}
      ${row({ tile: serviceTile({ provider: "microsoft-graph", slug: "m365-alex" }), title: "Microsoft 365", sub: "No mark with a clear licence: a letter tile" })}</ul></section>
    <section class="card">${cardHead("Machines")}<ul class="rows compact">${[
      ["Mac mini", "secure-enclave"],
      ["the Linux box", "software"],
      ["MacBook", "software"],
      ["Cloudflare", "software"],
      ["iPhone", "software"],
      ["Watch", "software"],
      ["nova", "software"],
    ].map(([name, backend]) => row({ tile: kindTile("machine", backend, undefined, name), title: html`${machineDot(name as string)} ${name}`, sub: backend }))}</ul></section>`
  return { title: "Icons", viewer: OWNER, boot: { page: "gallery" }, body }
}

// ---------------------------------------------------------------- the gallery

type Entry = {
  id: string
  group: string
  title: string
  note: string
  page: PageInput
  // Regions hidden until the client bundle shows them, shown here instead.
  reveal?: string[]
  // Regions the client bundle hides once a page settles, hidden here instead.
  hide?: string[]
  // Folds (details with data-region) shown open.
  open?: string[]
  // The command palette shown open with this query typed (the client
  // normally fills the list; the gallery renders the same entries).
  palette?: string
  // Hostile strings for the palette instead of the usual fixtures.
  hostile?: boolean
  // The palette open before its lists have arrived.
  paletteLoading?: boolean
  // Text put into an empty `data-region` element the client would fill.
  fill?: Record<string, string>
  // Markup the client would build into an empty `data-region` element, such
  // as the list of recovery codes it makes from the one reply that has them.
  inject?: Record<string, string>
  // Markup swaps for what the client changes in place, such as a button's
  // busy label.
  swap?: [string | RegExp, string][]
  // The page notice the client shows, as it shows it.
  notice?: { tone: "warn" | "error" | "info"; title: string; lines: string[] }
  // A page of the pre-workspace vault that no route serves (legacyEntry).
  legacy?: boolean
}

// The pre-workspace vault's pages. They stay in the gallery
// and their code stays, because the workspace pages still reuse some of
// their renderers, but no route serves them as drawn here: the contact
// sheet and each page's title say "Legacy, not served" so nobody designs
// from them. They are to be deleted, consumer by consumer.
const LEGACY_NOTE = "Legacy, not served"
const LEGACY_GROUPS: ReadonlySet<string> = new Set(["Intake", "Connect"])
// Applied to this file's own entries only: a later gallery's group may
// share a legacy group's name and is live.
function legacyEntry(entry: Entry): Entry {
  return LEGACY_GROUPS.has(entry.group) ? { ...entry, legacy: true } : entry
}

function entries(): Entry[] {
  const vault: Entry[] = [
    { id: "shell-focus", group: "Foundation", title: "The focus shell", note: "An approval on the focus shell: the brand and one Home link, no rail, no tabs, two columns from 900 px.", page: { ...workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view: galleryEmailApproval(), project: null, items: [], now: NOW }), wide: true } },
    { id: "components", group: "Foundation", title: "Components", note: "Every shared component with fixture data: pills, rings, strips and the week chart, a copy box, markers, state cards, an empty state, the fingerprint, steps, buttons; then the page parts with the longest realistic values: a page head, a card head with actions, wrapping button rows, a key-value list, a table that becomes a list, a row with two pills, the four notices, a form row and a field error.", page: componentsPage() },
    { id: "icons", group: "Foundation", title: "Icons", note: "Every interface glyph labelled, every service logo on its tiles, the machine icons and hues.", page: iconsPage() },
    { id: "signin", group: "Account", title: "Sign in", note: "No session: the passkey prompt, what to do about a lost passkey, and the vault's address to check.", page: signinPage("/a/apr_6t3vb9nx2w", ORIGIN) },
    { id: "signin-failed", group: "Account", title: "Sign in, passkey cancelled", note: "The passkey prompt was cancelled or timed out: the notice the client shows.", page: signinPage("/a/apr_6t3vb9nx2w", ORIGIN), notice: { tone: "error", title: "The passkey check did not finish.", lines: ["It was cancelled or timed out. Nothing was changed; try again when you are ready."] } },
    { id: "recover", group: "Account", title: "Use a recovery code", note: "/recover: one field that never autocompletes or autocorrects, what a code does, and what happens for 24 hours.", page: recoverPage() },
    { id: "recover-typo", group: "Account", title: "Recovery code with a typo", note: "The check symbol failed: caught in the browser, so it uses no attempt.", page: recoverPage(), reveal: ["recover-error"], fill: { "recover-error": "That code has a typo. Check each group." } },
    { id: "recover-wrong", group: "Account", title: "Recovery code not valid", note: "A well-formed code the vault does not know, or one already used: one message for both.", page: recoverPage(), reveal: ["recover-error"], fill: { "recover-error": "That code is not valid or was already used. After 5 wrong codes this network waits an hour." } },
    { id: "recover-limited", group: "Account", title: "Recovery codes rate limited", note: "Five wrong codes from this network this hour: when to try again.", page: recoverPage(), reveal: ["recover-error"], fill: { "recover-error": "Too many tries from this network. Try again after 19:00 UTC." } },
    { id: "recover-passkey", group: "Account", title: "Set up a new passkey after a code", note: "/recover/passkey with a live recovery session: an optional name and the two buttons.", page: recoverPasskeyPage(true) },
    { id: "recover-passkey-busy", group: "Account", title: "Set up a new passkey, waiting", note: "The passkey prompt is open.", page: recoverPasskeyPage(true), swap: [[/(data-kind="device")><svg[\s\S]*?<\/svg><span>Create a passkey on this device<\/span>/, '$1 aria-busy="true" disabled>Creating the passkey...']] },
    { id: "recover-passkey-failed", group: "Account", title: "Set up a new passkey, cancelled", note: "The prompt was cancelled: the notice, and both buttons to try again.", page: recoverPasskeyPage(true), notice: { tone: "error", title: "The passkey check did not finish.", lines: ["It was cancelled or timed out. Nothing was changed; try again when you are ready."] } },
    { id: "recover-passkey-gone", group: "Account", title: "Recovery session gone", note: "The 15 minutes ran out, or the page was opened without a code: how to start again.", page: recoverPasskeyPage(false) },
    { id: "palette", group: "Palette", title: "Command palette", note: "⌘K over home with \"gm\" typed: the needs-you row that mentions gmail first with its time left, then the credentials, then the actions, matched characters marked.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "gm" },
    { id: "palette-empty-query", group: "Palette", title: "Command palette, nothing typed", note: "Everything, in group order: needs you, credentials, machines, projects, actions.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "" },
    { id: "palette-no-match", group: "Palette", title: "Command palette, nothing matches", note: "", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "zzzz" },
    { id: "palette-loading", group: "Palette", title: "Command palette, loading", note: "Opened before the lists have arrived.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "", paletteLoading: true },
    { id: "palette-hostile", group: "Palette", title: "Command palette, hidden characters", note: "A right-to-left override in an ask title and a zero-width space in a slug show as the same red marker the pages use, and the highlight for \"gm ail\" stops at the marker. An escape in an account is spelled as \\u001B in plain text, the server's rule.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "gm ail", hostile: true },
    { id: "palette-hostile-all", group: "Palette", title: "Command palette, hidden characters, nothing typed", note: "Every hostile entry: a machine whose name carries a right-to-left override shows the marker, and a slug someone typed as [RLO U+202E] stays plain text.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), palette: "", hostile: true },
    { id: "shortcuts", group: "Palette", title: "Keyboard shortcuts sheet", note: "The ? sheet over home: every key, and the rule that none of them decides.", page: workspaceHomePage(galleryShell(VIEWERS.owner)), reveal: ["shortcuts"] },

    { id: "intake-oauth-client-google", group: "Intake", title: "Intake: Google OAuth client", note: "Template-verified destination with the guided Google Cloud steps and the redirect URI in a copy box.", page: intakePage(OWNER, INTAKE_GOOGLE_CLIENT, ORIGIN, NOW) },
    { id: "intake-oauth-client-google-then", group: "Intake", title: "Intake: Google OAuth client, then connect", note: "The same intake chained to a connect: step 1 of 2, and the page goes on to the connect after saving.", page: intakePage(OWNER, INTAKE_GOOGLE_CLIENT_THEN, ORIGIN, NOW) },
    { id: "intake-oauth-client-proposed", group: "Intake", title: "Intake: OAuth client, proposed destination", note: "No template: the agent proposed the host, shown in red with a box to tick.", page: intakePage(OWNER, INTAKE_OAUTH_CLIENT_PROPOSED, ORIGIN, NOW) },
    { id: "intake-api-key-openai", group: "Intake", title: "Intake: OpenAI API key", note: "Template-verified destination, one secret field.", page: intakePage(OWNER, INTAKE_OPENAI, ORIGIN, NOW) },
    { id: "intake-api-key-proposed", group: "Intake", title: "Intake: API key, proposed destination and injection", note: "The agent proposed the host and that the key goes in a query parameter.", page: intakePage(OWNER, INTAKE_API_KEY_PROPOSED, ORIGIN, NOW) },
    { id: "intake-rotate", group: "Intake", title: "Intake: replace a secret", note: "Rotation keeps the item's destination; nothing new to accept.", page: intakePage(OWNER, INTAKE_ROTATE, ORIGIN, NOW) },
    { id: "intake-saved", group: "Intake", title: "Intake: saved", note: "After sealing and saving, as the page shows it.", page: intakePage(OWNER, INTAKE_OPENAI, ORIGIN, NOW), reveal: ["intake-done"] },
    { id: "intake-saved-then", group: "Intake", title: "Intake: saved, going on to step 2", note: "The moment before the page navigates to the connect.", page: intakePage(OWNER, INTAKE_GOOGLE_CLIENT_THEN, ORIGIN, NOW), reveal: ["intake-done"] },
    { id: "intake-ran-out", group: "Intake", title: "Intake: ran out while open", note: "The countdown reached zero on an open page: the client swaps in the expired card.", page: intakePage(OWNER, INTAKE_OPENAI, ORIGIN, NOW), reveal: ["intake-expired"] },
    { id: "intake-expired", group: "Intake", title: "Intake: expired", note: "Opened after the link ran out: when, that nothing happened, and how to ask again.", page: intakePage(OWNER, { ...INTAKE_GOOGLE_CLIENT, status: "expired", expiresAt: at(-18) }, ORIGIN, NOW) },
    { id: "intake-superseded", group: "Intake", title: "Intake: replaced by a newer request", note: "The agent asked again with a fresh link; this one was closed.", page: intakePage(OWNER, { ...INTAKE_GOOGLE_CLIENT, status: "cancelled", superseded: true }, ORIGIN, NOW) },
    { id: "intake-cancelled", group: "Intake", title: "Intake: cancelled", note: "", page: intakePage(OWNER, { ...INTAKE_OPENAI, status: "cancelled" }, ORIGIN, NOW) },
    { id: "intake-completed", group: "Intake", title: "Intake: already filled in", note: "", page: intakePage(OWNER, { ...INTAKE_OPENAI, status: "completed" }, ORIGIN, NOW) },
    { id: "intake-field-warn", group: "Intake", title: "Intake: a value without the expected start", note: "The key does not start sk-: a warning under the field that never blocks saving and never repeats the value.", page: intakePage(OWNER, INTAKE_OPENAI, ORIGIN, NOW), reveal: ["field-warn"] },
    { id: "intake-member", group: "Intake", title: "Intake: a member's own ask", note: "Started from Connect a service: You asked to paste; the member chose the tags.", page: intakePage(OWNER, INTAKE_MEMBER, ORIGIN, NOW) },
    { id: "intake-member-expired", group: "Intake", title: "Intake: a member's own ask, expired", note: "Started again from Connect a service, with no command.", page: intakePage(OWNER, { ...INTAKE_MEMBER, status: "expired", expiresAt: at(-18) }, ORIGIN, NOW) },
    { id: "intake-proposed-expired", group: "Intake", title: "Intake: proposed destination, expired", note: "No command to copy: mehen request cannot repeat the agent's proposed destination.", page: intakePage(OWNER, { ...INTAKE_API_KEY_PROPOSED, status: "expired", expiresAt: at(-18) }, ORIGIN, NOW) },
    { id: "intake-then-expired", group: "Intake", title: "Intake: chained client, expired", note: "Asks the agent to start connecting again, not for the client alone.", page: intakePage(OWNER, { ...INTAKE_GOOGLE_CLIENT_THEN, status: "expired", expiresAt: at(-18) }, ORIGIN, NOW) },
    { id: "intake-ssh-key", group: "Intake", title: "Intake: multi-line and optional fields", note: "An SSH key: the private key in a text area, the public key optional, several proposed hosts.", page: intakePage(OWNER, INTAKE_SSH_KEY, ORIGIN, NOW) },
    { id: "intake-long-names", group: "Intake", title: "Intake: a long name and a long host", note: "The head and the destination at 390 with a very long slug and host.", page: intakePage(OWNER, INTAKE_LONG_NAMES, ORIGIN, NOW) },

    { id: "connect-pending", group: "Connect", title: "Connect Gmail: pending", note: "Scopes in plain words, the expected account, the button to Google.", page: connectPage(OWNER, connect({}), NOW) },
    { id: "connect-awaiting", group: "Connect", title: "Connect Gmail: waiting on its client", note: "A chained connect whose Google client has not been pasted yet: step 1 first.", page: connectPage(OWNER, connect({ awaiting: { intake: "int_9f2k7m3qwx", url: `${ORIGIN}/i/int_9f2k7m3qwx`, status: "open" }, expiresAt: at(27) }), NOW) },
    { id: "connect-step-done", group: "Connect", title: "Connect Gmail: step 1 done", note: "Landed from the client intake: the green strip, then the account and the button.", page: connectPage(OWNER, connect({ awaiting: { intake: "int_9f2k7m3qwx", url: `${ORIGIN}/i/int_9f2k7m3qwx`, status: "completed" } }), NOW) },
    { id: "connect-reconnect", group: "Connect", title: "Reconnect Gmail: same scopes", note: "A reconnect from the catalogue: the title and button say Reconnect, the sentence says the token is replaced only after sign-in, the scopes are the connection's own.", page: connectPage(OWNER, connect({ reconnect: true, currentScopes: [GMAIL_READONLY], scopes: [GMAIL_READONLY], requestedBy: { member: SELF, self: true }, reason: "Started from Connect a service in the vault." }), NOW) },
    { id: "connect-reconnect-wider", group: "Connect", title: "Reconnect Gmail: wider than now", note: "An agent asked to reconnect with gmail.modify where the connection holds gmail.readonly: the wider scope is red with a pill and the page says not to sign in if unexpected.", page: connectPage(OWNER, connect({ reconnect: true, currentScopes: [GMAIL_READONLY], scopes: [GMAIL_MODIFY] }), NOW) },
    { id: "connect-completed", group: "Connect", title: "Connect Gmail: connected", note: "", page: connectPage(OWNER, connect({ status: "completed", account: "alex@example.com" }), NOW) },
    { id: "connect-mismatch", group: "Connect", title: "Connect Gmail: wrong account", note: "Signed in to Google as someone else; nothing saved.", page: connectPage(OWNER, connect({ status: "mismatch", account: "alex.rae@example.com" }), NOW) },
    { id: "connect-failed", group: "Connect", title: "Connect Gmail: failed", note: "The vault's own message, without its ask-the-agent ending, which the card says for the right asker.", page: connectPage(OWNER, connect({ status: "failed", message: "The sign-in was interrupted before the connection was stored. Ask the agent for a new link." }), NOW) },
    { id: "connect-failed-cancelled", group: "Connect", title: "Connect Gmail: its client request was cancelled", note: "A chained connect whose client intake was cancelled.", page: connectPage(OWNER, connect({ status: "failed", message: 'The request for the OAuth client "google-oauth-client" was cancelled, so this connection cannot be made. Ask the agent for a new link.', awaiting: { intake: "int_9f2k7m3qwx", url: `${ORIGIN}/i/int_9f2k7m3qwx`, status: "cancelled" } }), NOW) },
    { id: "connect-expired-client", group: "Connect", title: "Connect Gmail: the client was not added in time", note: "A chained connect whose client intake ran out.", page: connectPage(OWNER, connect({ status: "expired", expiresAt: at(-60), awaiting: { intake: "int_9f2k7m3qwx", url: `${ORIGIN}/i/int_9f2k7m3qwx`, status: "expired" } }), NOW) },
    { id: "connect-interrupted", group: "Connect", title: "Connect Gmail: back after an interrupted store", note: "The sign-in worked but storing failed: the page says so above the button.", page: connectPage(OWNER, connect({ message: "The sign-in was interrupted before the connection was stored. Start it again." }), NOW) },
    { id: "connect-no-expect", group: "Connect", title: "Connect Gmail: no account named", note: "The agent did not name the account.", page: connectPage(OWNER, connect({ expect: null }), NOW) },
    { id: "connect-ran-out", group: "Connect", title: "Connect Gmail: ran out while open", note: "The countdown reached zero on an open page.", page: connectPage(OWNER, connect({}), NOW), reveal: ["connect-expired"] },
    { id: "connect-expired", group: "Connect", title: "Connect Gmail: expired", note: "", page: connectPage(OWNER, connect({ status: "expired", expiresAt: at(-4) }), NOW) },


    {
      id: "error-not-found",
      group: "Errors",
      title: "Error: link not found",
      note: "An approval link that does not exist: the vault's own message (vault/areas/approvals.ts) and next step.",
      page: errorPageInput(OWNER, 404, { error: "not_found", message: "That approval link does not exist, or it belongs to another vault.", next: { say: "Ask the agent for a new link." } }),
    },
    { id: "error-unknown-route", group: "Errors", title: "Error: no page at this address", note: "A mistyped or stale address opened in a browser, signed in: the app shell around the not-found card.", page: errorPageInput(OWNER, 404, NOT_FOUND_ERROR) },
    { id: "error-read-failed", group: "Errors", title: "Error: the page's read failed", note: "The vault failed while reading the page's data: what happened, to reload, and the way home to the Freeze brake.", page: errorPageInput(OWNER, 500, { error: "internal", message: "Something went wrong inside the vault." }) },
    { id: "error-signed-out", group: "Errors", title: "Error: signed out", note: "The session ended while the page was open: the signed-out shell, one passkey button that returns to the page.", page: errorPageInput(null, 401, sessionEndedError("/a/apr_6t3vb9nx2w"), SESSION_ENDED_HEADING) },
  ]
  return [
    ...vault.map(legacyEntry),
    // The workspace shell, picker and Needs you pages (src/ui/shell-gallery.ts).
    ...shellGallery(),
    ...oidcGallery(),
    // The people, team and machine pages (src/ui/people-gallery.ts).
    ...peopleGallery(),
    // The account and account setup pages (src/ui/account-gallery.ts).
    ...accountGallery(),
    // Workspace projects, credentials and audit (src/ui/workspace-projects-gallery.ts).
    ...workspaceProjectsGallery(),
    // The workspace ask and enrolment pages (src/ui/workspace-asks-gallery.ts).
    ...workspaceAsksGallery(),
    // Standing rules on the credential and machine pages (src/ui/policy-rules-gallery.ts).
    ...policyRulesGallery(),
    // How careful a credential is, on its page (src/ui/posture-gallery.ts).
    ...postureGallery(),
    // What a machine may do without asking, its pages and its card (src/ui/mandates-gallery.ts).
    ...mandatesGallery(),
    // The workspace settings pages (src/ui/settings-gallery.ts).
    ...settingsGallery(),
    // The operator's and platform admins' consoles (src/ui/console-gallery.ts).
    ...consoleGallery(),
  ]
}

// ---------------------------------------------------------------- static html

function reveal(page: string, region: string): string {
  return page.replace(`data-region="${region}" hidden`, `data-region="${region}"`)
}

function staticHtml(entry: Entry): string {
  let page = renderDocument(entry.page).value
  // The layout gate checks each page it measures is this entry, not a
  // browser error page or another file.
  if (!page.includes("<head>\n")) throw new Error(`${entry.id}: no <head> to name the gallery entry in`)
  page = page.replace("<head>\n", `<head>\n<meta name="${GALLERY_ENTRY_META}" content="${escapeHtml(entry.id)}">\n`)
  // A legacy page says so in its tab, where whoever opens it sees it,
  // without changing the layout being measured.
  if (entry.legacy) page = page.replace("<title>", `<title>${LEGACY_NOTE}: `)
  page = page.replaceAll('href="/assets/', 'href="assets/').replace('src="/assets/theme.js"', 'src="assets/theme.js"')
  page = page.replace('<script type="module" src="/assets/app.js"></script>\n', "")
  // Every button shows enabled, except one marked data-keep-disabled
  // (the components page's Disabled sample), which this pattern skips.
  page = page.replace(/(<button\b[^>]*?) disabled>/g, "$1>")
  for (const region of entry.reveal ?? []) page = reveal(page, region)
  for (const region of entry.hide ?? []) page = page.replace(`data-region="${region}"`, `data-region="${region}" hidden`)
  for (const region of entry.open ?? []) page = page.replace(`data-region="${region}">`, `data-region="${region}" open>`)
  for (const [region, text] of Object.entries(entry.fill ?? {})) page = page.replace(`data-region="${region}"></`, `data-region="${region}">${escapeHtml(text)}</`)
  for (const [region, markup] of Object.entries(entry.inject ?? {})) page = page.replace(`data-region="${region}"></`, `data-region="${region}">${markup}</`)
  for (const [from, to] of entry.swap ?? []) {
    if (typeof from === "string" ? !page.includes(from) : !from.test(page)) throw new Error(`${entry.id}: nothing to swap for ${String(from)}`)
    page = page.replace(from, to)
  }
  if (entry.notice) {
    const { tone, title, lines } = entry.notice
    page = page.replace('<div id="notice" class="notice" role="alert" aria-live="assertive" hidden></div>', `<div id="notice" class="notice ${tone}" role="alert" aria-live="assertive"><p class="notice-title">${escapeHtml(title)}</p>${tone === "warn" ? `<ul>${lines.map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ul>` : lines.map((l) => `<p>${escapeHtml(l)}</p>`).join("")}</div>`)
  }
  if (entry.palette !== undefined) {
    page = reveal(page, "palette")
    page = page.replace('aria-expanded="false"', 'aria-expanded="true"').replace('placeholder="Search the vault"', `placeholder="Search the vault" value="${escapeHtml(entry.palette)}"`)
    const list = entry.paletteLoading
      ? '<p class="palette-note">Loading...</p>'
      : entry.hostile
      ? paletteStatic(entry.palette, PENDING_HOSTILE, [{ ...GMAIL, slug: "gm\u200bail-alex", account: "alex\u001b@example.com" }, { ...WEATHER, slug: "[RLO U+202E]typed" }], [{ ...(DEVICES[1] as DeviceView), name: "the \u202eLinuxbox" }])
      : paletteStatic(entry.palette, PENDING)
    page = page.replace('<div class="palette-list" id="palette-list" role="listbox" aria-label="Results"></div>', `<div class="palette-list" id="palette-list" role="listbox" aria-label="Results">${list}</div>`)
    page = page.replace("<body class=\"app\">", "<body class=\"app palette-open\">")
  }
  if (entry.reveal?.includes("terms-form")) page = page.replace('<body class="focus has-bar">', '<body class="focus has-bar terms-open">')
  // The client hides Approve when the recompute fails.
  if (entry.reveal?.includes("digest-mismatch")) page = page.replace('data-action="approve">', 'data-action="approve" hidden>')
  if (entry.hide?.includes("approval-open")) page = page.replace('<form class="bar"', '<form hidden class="bar"').replace('<body class="focus has-bar">', '<body class="focus">')
  // What the client bundle hides when it reveals these.
  if (entry.reveal?.includes("intake-done")) {
    for (const region of ["intake-form", "intake-setup", "intake-tags-advice"]) page = page.replace(`data-region="${region}">`, `data-region="${region}" hidden>`)
    page = page.replace('<span class="when">', '<span class="when" hidden>')
  }
  if (entry.reveal?.includes("intake-expired")) page = page.replace('<div class="two-col" data-region="intake-columns">', '<div class="two-col" data-region="intake-columns" hidden>')
  if (entry.reveal?.includes("field-warn")) page = page.replace('<input type="password" data-field="key" data-expect-start=', '<input type="password" value="not-a-key" data-field="key" data-expect-start=')
  if (entry.reveal?.includes("connect-expired")) {
    for (const region of ["connect-retry", "connect-awaiting", "connect-step-done", "connect-reconnect", "connect-account", "connect-scopes"]) page = page.replace(`data-region="${region}">`, `data-region="${region}" hidden>`)
  }
  return page
}

// ---------------------------------------------------------------- widths and schemes

// 360 is a small Android phone, 390 an iPhone, 768 a portrait tablet (still
// the tab bar), 1024 the top bar's width (900 to 1139 px), 1280 the rail.
const WIDTHS = [360, 390, 768, 1024, 1280] as const
const SCHEMES = ["light", "dark"] as const

type Shot = { id: string; width: (typeof WIDTHS)[number]; scheme: (typeof SCHEMES)[number] }

// The whole page, with the fixed bars hidden.
function shotName(shot: Shot): string {
  return `${shot.id}-${shot.width}-${shot.scheme}.png`
}

// The first screen, 900 px tall, with the fixed bars where a person sees them.
function screenName(shot: Shot): string {
  return `${shot.id}-${shot.width}-${shot.scheme}-screen.png`
}

// The layout check. It runs in each page once the page and its fonts have
// loaded, at every width and in both schemes, and fails the run on what a
// person would call broken at a glance:
//   page      the page scrolls sideways
//   viewport  an element passes the window's left or right edge
//   spill     an element sticks out of its card, notice, state card or the
//             switcher menu, on either side (2 px tolerance)
//   text      a box's own text runs past its edge
//   clipped   content cut off with no ellipsis: wider than a hidden
//             overflow, or past either side of the box that clips it
//             (moved left by a negative transform, say)
//   scrolls   a box scrolls sideways where nothing should
//   squeezed  text squeezed into a column a few letters wide
//   crushed   a row's right-hand column takes over half the row and leaves
//             its title under 40 %
// Only the outermost element of a spill is reported, so each finding names
// the element to fix. Code, tables, chips, the palette and the docs tables
// may scroll; icons and form fields may clip, and labels kept for screen
// readers (clipped to nothing) are not checked. Fixed elements (the tab bar,
// the decision bar) are not measured: whether they cover content is a
// question for an interaction check, not this one. The probe answers with
// the gallery entry the page names, which the gate checks (ui-layout-gate.ts).
const LAYOUT_CHECK = `(() => {
  const found = [];
  const selectorOf = (el) => {
    const cls = typeof el.className === "string" && el.className.trim() ? "." + el.className.trim().split(/\\s+/).join(".") : "";
    return el.tagName.toLowerCase() + cls;
  };
  const name = (el) => {
    const text = (el.textContent || "").replace(/\\s+/g, " ").trim().slice(0, 40);
    return selectorOf(el) + (text ? ' "' + text + '"' : "");
  };
  const add = (kind, px, el) => found.push({ kind, px: Math.round(px), selector: selectorOf(el), element: name(el) });
  const SCROLLERS = "pre, .chips, .table, .doc-table, .palette-list, .account-nav, .request-body";
  const CLIPPERS = SCROLLERS + ", .palette, svg, .tabs, input, select, textarea";
  const clipper = (el) => {
    for (let p = el.parentElement; p; p = p.parentElement) {
      const o = getComputedStyle(p).overflowX;
      if (o === "auto" || o === "scroll" || o === "hidden" || o === "clip") return p;
    }
    return null;
  };
  // Content past either side of the box that clips it. Past the right of
  // a scroller is reachable by scrolling (reported as scrolls); past its
  // left never is.
  const cutBy = (r, c) => {
    const cr = c.getBoundingClientRect();
    const left = cr.left + c.clientLeft;
    const right = left + c.clientWidth;
    const ox = getComputedStyle(c).overflowX;
    return Math.max(left - r.left, ox === "hidden" || ox === "clip" ? r.right - right : 0);
  };
  const vw = document.documentElement.clientWidth;
  // Labels kept for screen readers only: clipped to nothing on purpose.
  const unseen = [...document.body.querySelectorAll("*")].filter((el) => getComputedStyle(el).clipPath === "inset(50%)");
  const past = new Set();
  const out = new Set();
  const cut = new Set();
  const runs = [];
  for (const el of document.body.querySelectorAll("*")) {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || style.position === "fixed") continue;
    // A closed <details> keeps a layout box for its content in Chrome; it is not shown.
    if (el.closest("[hidden], dialog:not([open]), details:not([open]) > :not(summary), template, [data-region='palette-tiles']") || unseen.some((u) => u.contains(el))) continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const own = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent.trim()).join("");
    const size = parseFloat(style.fontSize);
    const line = parseFloat(style.lineHeight) || size * 1.4;
    if (own.length >= 6 && r.height > line * 4 && r.width < size * 3) add("squeezed", r.width, el);
    const clip = clipper(el);
    if (!clip && (r.right > vw + 1 || r.left < -1)) {
      past.add(el);
      if (!past.has(el.parentElement)) add("viewport", Math.max(r.right - vw, -r.left), el);
    }
    if (clip && !clip.matches(CLIPPERS) && getComputedStyle(clip).textOverflow !== "ellipsis") {
      const over = cutBy(r, clip);
      if (over > 2) {
        cut.add(el);
        if (!cut.has(el.parentElement)) add("clipped", over, el);
      }
    }
    const box = el.parentElement && el.parentElement.closest(".card, .notice, .state, .switcher-menu");
    if (box && (!clip || !box.contains(clip))) {
      const b = box.getBoundingClientRect();
      const over = Math.max(r.right - b.right, b.left - r.left);
      if (over > 2) {
        out.add(el);
        if (!out.has(el.parentElement)) add("spill", over, el);
      }
    }
    const ox = style.overflowX;
    const wider = el.scrollWidth - el.clientWidth;
    if ((ox === "hidden" || ox === "clip") && wider > 2 && style.textOverflow !== "ellipsis" && !el.matches(CLIPPERS)) add("clipped", wider, el);
    if ((ox === "auto" || ox === "scroll") && wider > 2 && !el.matches(SCROLLERS)) add("scrolls", wider, el);
    if (ox === "visible" && own.length > 0 && el.clientWidth > 0 && wider > 2) runs.push([el, wider]);
  }
  // A box whose text runs past it, unless an element inside it was already
  // found spilling: that element is the cause.
  for (const [el, wider] of runs) {
    if (out.has(el) || past.has(el) || [...out, ...past].some((o) => el.contains(o))) continue;
    add("text", wider, el);
  }
  for (const row of document.body.querySelectorAll(".row")) {
    const main = row.querySelector(":scope > .row-main");
    const side = row.querySelector(":scope > .row-side");
    if (!main || !side || row.closest("[hidden]")) continue;
    const w = row.getBoundingClientRect().width;
    const m = main.getBoundingClientRect().width;
    const s = side.getBoundingClientRect().width;
    if (w > 0 && m < w * 0.4 && s > w * 0.45) add("crushed", m, main);
  }
  const wide = document.documentElement.scrollWidth - vw;
  if (wide > 1) found.push({ kind: "page", px: wide, selector: "html", element: "html" });
  const meta = document.querySelector('meta[name="${GALLERY_ENTRY_META}"]');
  return { entry: meta ? meta.getAttribute("content") : null, issues: found };
})()`

// The non-regressing gate. scripts/ui-layout-baseline.json lists the
// findings left today, each with the lane that removes it (Lane in
// ui-layout-gate.ts). The run fails on a finding the baseline does not list, and on a baseline
// entry that no longer occurs: the lane that fixes a page deletes its
// entries in the same change. A finding matches an entry by page id,
// width, scheme, kind and selector; the px may change.
const BASELINE_PATH = path.resolve(import.meta.dirname, "ui-layout-baseline.json")

type ShotOptions = { capture: boolean }

// Runs as each document is created, before <html> exists.
const DARK_BEFORE_PAINT = `new MutationObserver((_, observer) => {
  if (!document.documentElement) return;
  document.documentElement.dataset.theme = "dark";
  observer.disconnect();
}).observe(document, { childList: true });`

// The probe's own check, run before the gallery: a page with one element
// spilling out of its card, one moved left out of a hidden-overflow box,
// one off the window's left edge, and beside them what must not be
// reported (a code block that scrolls, a line cut off with an ellipsis,
// hidden and screen-reader-only content, a fixed element, an element
// spilling inside a closed fold). The run stops unless the probe finds
// exactly the three, and then, with every fold open, the fold's too.
const CANARY_ID = "layout-probe-canary"
const CANARY_EXPECTED = ["clipped div.canary-left", "spill div.canary-spill", "viewport div.canary-off-left"]
const CANARY_FOLD_EXPECTED = [...CANARY_EXPECTED, "spill div.canary-fold"].sort()
const CANARY_HTML = `<!doctype html>
<html lang="en-GB">
<head>
<meta name="${GALLERY_ENTRY_META}" content="${CANARY_ID}">
<title>Layout probe canary</title>
</head>
<body>
<div class="card" style="width: 200px; padding: 10px; border: 1px solid">
  <div class="canary-spill" style="width: 260px">wider than its card</div>
  <div class="canary-wrapper" style="overflow: hidden"><div class="canary-left" style="transform: translateX(-80px)">moved left out of its box</div></div>
  <pre style="overflow-x: auto; white-space: pre">a code line much longer than the card it sits in, which may scroll</pre>
  <p class="canary-ellipsis" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis">a line cut off on purpose with an ellipsis at its end</p>
  <p class="canary-hidden" hidden style="width: 900px">hidden</p>
  <span style="position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap">a label kept for screen readers only</span>
</div>
<details class="card" style="width: 200px; padding: 10px; border: 1px solid"><summary>a closed fold</summary><div class="canary-fold" style="width: 260px">wider than its card, inside a closed fold</div></details>
<div class="canary-off-left" style="transform: translateX(-500px)">off the left edge of the window</div>
<div class="canary-fixed" style="position: fixed; left: -50px; bottom: 0">fixed</div>
</body>
</html>
`

// Loads one page and returns the probe's findings, or throws: a navigation
// Chrome reports as failed, a probe that threw or answered nothing, or a
// page that is not the entry asked for all stop the run.
async function measure(cdp: Cdp, sessionId: string, file: string, id: string, where: string): Promise<LayoutIssue[]> {
  const loaded = cdp.once("Page.loadEventFired", sessionId)
  const navigated = (await cdp.send("Page.navigate", { url: `file://${file}` }, sessionId)) as NavigateReply
  // A failed navigation never fires load: do not leave that waiting.
  if (navigated.errorText) loaded.catch(() => undefined)
  checkNavigation(where, navigated)
  await loaded
  const fonts = (await cdp.send("Runtime.evaluate", { expression: "document.fonts.ready.then(() => true)", awaitPromise: true }, sessionId)) as EvaluateReply
  if (fonts.exceptionDetails !== undefined) throw new Error(`layout: the fonts did not load on ${where}`)
  const reply = (await cdp.send("Runtime.evaluate", { expression: LAYOUT_CHECK, returnByValue: true }, sessionId)) as EvaluateReply
  return acceptProbe(where, id, reply)
}

// The second pass: every <details> on the page opened, so what sits in a
// closed fold (the danger zones, the forms under Manage, the switcher and
// the More sheet) is measured too. It answers how many it opened; a page
// with none is not measured twice.
const OPEN_FOLDS = `(() => {
  const closed = [...document.querySelectorAll("details:not([open])")];
  for (const d of closed) d.open = true;
  return closed.length;
})()`

// After the page was measured (and shot) as loaded: when it has a closed
// fold, measure it again with every fold open. Only what the first pass
// did not find is added, named in its element so the report says where
// to look.
async function measureFolds(cdp: Cdp, sessionId: string, id: string, where: string, shown: LayoutIssue[]): Promise<LayoutIssue[]> {
  const opened = (await cdp.send("Runtime.evaluate", { expression: OPEN_FOLDS, returnByValue: true }, sessionId)) as EvaluateReply
  if (opened.exceptionDetails !== undefined || typeof opened.result?.value !== "number") throw new Error(`layout: could not open the folds on ${where}`)
  if (opened.result.value === 0) return shown
  const reply = (await cdp.send("Runtime.evaluate", { expression: LAYOUT_CHECK, returnByValue: true }, sessionId)) as EvaluateReply
  const seen = new Set(shown.map((i) => `${i.kind} ${i.selector}`))
  const folded = acceptProbe(`${where}, every fold open`, id, reply).filter((i) => !seen.has(`${i.kind} ${i.selector}`))
  return [...shown, ...folded.map((i) => ({ ...i, element: `${i.element} (with every fold open)` }))]
}

// The decision bar and the tab bar are fixed to the window. The whole-page
// shot hides them (they would paint over the page's middle); a second shot
// of the first screen, at the same 900 px window, shows them where a person
// sees them. The window never changes size for a shot, so the pictures and
// the measured layout are the same layout.
const HIDE_FIXED_BARS = `(() => {
  const style = document.createElement("style");
  style.id = "gallery-capture";
  style.textContent = ".tabs, .bar { visibility: hidden !important; }";
  document.head.append(style);
})()`
const SHOW_FIXED_BARS = 'document.getElementById("gallery-capture")?.remove()'

async function screenshotAll(chromePath: string, out: string, ids: string[], options: ShotOptions): Promise<{ count: number; measured: number; findings: LayoutFinding[] }> {
  const { cdp, close } = await launchChrome(chromePath)
  const pngDir = path.join(out, "png")
  await mkdir(pngDir, { recursive: true })
  const findings: LayoutFinding[] = []
  let count = 0
  let measured = 0
  try {
    const { targetId } = (await cdp.send("Target.createTarget", { url: "about:blank" })) as { targetId: string }
    const { sessionId } = (await cdp.send("Target.attachToTarget", { targetId, flatten: true })) as { sessionId: string }
    await cdp.send("Page.enable", {}, sessionId)

    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 900, deviceScaleFactor: 1, mobile: true }, sessionId)
    const canaryFile = path.join(out, `${CANARY_ID}.html`)
    await writeFile(canaryFile, CANARY_HTML)
    const canaryShown = await measure(cdp, sessionId, canaryFile, CANARY_ID, "the probe canary")
    const canary = canaryShown.map((i) => `${i.kind} ${i.selector}`).sort()
    if (JSON.stringify(canary) !== JSON.stringify(CANARY_EXPECTED)) throw new Error(`layout: the probe found ${JSON.stringify(canary)} on its canary, not ${JSON.stringify(CANARY_EXPECTED)}`)
    const canaryFolds = (await measureFolds(cdp, sessionId, CANARY_ID, "the probe canary", canaryShown)).map((i) => `${i.kind} ${i.selector}`).sort()
    if (JSON.stringify(canaryFolds) !== JSON.stringify(CANARY_FOLD_EXPECTED)) throw new Error(`layout: with its folds open the probe found ${JSON.stringify(canaryFolds)} on its canary, not ${JSON.stringify(CANARY_FOLD_EXPECTED)}`)

    for (const width of WIDTHS) {
      const viewport = { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 }
      await cdp.send("Emulation.setDeviceMetricsOverride", viewport, sessionId)
      for (const scheme of SCHEMES) {
        // Reduced motion, so no shot catches a button mid-transition.
        await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }, { name: "prefers-reduced-motion", value: "reduce" }] }, sessionId)
        // Light is the default; dark is the appearance a member chooses, set
        // on <html> as the parser makes it, before the first paint, as
        // theme.js does: never after load, mid-transition.
        const dark = scheme === "dark" ? ((await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: DARK_BEFORE_PAINT }, sessionId)) as { identifier: string }) : null
        for (const id of ids) {
          const where = `${id} at ${width} px, ${scheme}`
          const shown = await measure(cdp, sessionId, path.join(out, `${id}.html`), id, where)
          measured++
          const shot = shotName({ id, width, scheme })
          if (!options.capture) {
            for (const issue of await measureFolds(cdp, sessionId, id, where, shown)) findings.push({ ...issue, id, width, scheme, shot })
            continue
          }
          const metrics = (await cdp.send("Page.getLayoutMetrics", {}, sessionId)) as { cssContentSize: { width: number; height: number } }
          const height = Math.max(900, Math.ceil(metrics.cssContentSize.height))
          await cdp.send("Runtime.evaluate", { expression: HIDE_FIXED_BARS }, sessionId)
          const page = (await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width, height, scale: 1 } }, sessionId)) as { data: string }
          await cdp.send("Runtime.evaluate", { expression: SHOW_FIXED_BARS }, sessionId)
          const screen = (await cdp.send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width, height: 900, scale: 1 } }, sessionId)) as { data: string }
          await writeFile(path.join(pngDir, shot), Buffer.from(page.data, "base64"))
          await writeFile(path.join(pngDir, screenName({ id, width, scheme })), Buffer.from(screen.data, "base64"))
          count += 2
          for (const issue of await measureFolds(cdp, sessionId, id, where, shown)) findings.push({ ...issue, id, width, scheme, shot })
        }
        if (dark) await cdp.send("Page.removeScriptToEvaluateOnNewDocument", { identifier: dark.identifier }, sessionId)
      }
    }
  } finally {
    await close()
    // Kept even when the run stops part way, for whoever reads the failure.
    await writeFile(path.join(out, "layout.json"), `${JSON.stringify(findings, null, 2)}\n`)
  }
  checkMeasured(measured, ids.length, WIDTHS.length, SCHEMES.length)
  return { count, measured, findings }
}

// Compares the findings with the baseline and prints what fails: findings
// the baseline does not list, and entries that no longer occur. Returns the
// number of failures.
function reportLayout(findings: readonly LayoutFinding[], baseline: readonly LayoutBaselineEntry[], out: string): number {
  const { fresh, gone } = compareBaseline(findings, baseline)
  const seen = new Set(findings.map(baselineKey))
  const kept = baseline.length - gone.length
  if (kept > 0) {
    console.log(`layout: ${kept} baseline findings still occur, left for their lanes:`)
    for (const lane of [...new Set(baseline.map((b) => b.lane))]) {
      const pages = [...new Set(baseline.filter((b) => b.lane === lane && seen.has(baselineKey(b))).map((b) => b.id))]
      if (pages.length > 0) console.log(`  ${lane}: ${pages.join(", ")}`)
    }
  }
  for (const b of gone) console.log(`layout: fixed, delete it from ${path.basename(BASELINE_PATH)}: ${baselineKey(b)} (lane ${b.lane})`)
  if (fresh.length > 0) console.log(`layout: ${fresh.length} findings not in the baseline:`)
  for (const f of fresh) console.log(`  ${f.id} at ${f.width} px, ${f.scheme}: ${f.kind} ${f.px} px, ${f.element}\n    ${path.join(out, "png", f.shot)}`)
  if (fresh.length === 0 && gone.length === 0) console.log("layout: nothing new spilling, clipped, squeezed or scrolling sideways")
  return fresh.length + gone.length
}

// ---------------------------------------------------------------- the contact sheet

// A group whose every entry is legacy carries the note under its heading;
// in a group that also holds live pages, each legacy entry carries it.
function contactSheet(all: Entry[], shots: boolean): string {
  const groups = [...new Set(all.map((e) => e.group))]
  const section = (group: string) => {
    const members = all.filter((e) => e.group === group)
    const legacyGroup = members.every((e) => e.legacy === true)
    return `<section${legacyGroup ? ' class="legacy"' : ""}>
  <h2 id="${escapeHtml(group.toLowerCase())}">${escapeHtml(group)}${legacyGroup ? ` <span class="legacy-tag">${LEGACY_NOTE}</span>` : ""}</h2>
  ${legacyGroup ? `<p class="legacy-note">${LEGACY_NOTE}: the vault before workspaces. No route serves these pages as drawn here; their renderers stay only while a workspace page still reuses them. Design from the workspace pages instead.</p>` : ""}
  ${members
    .map(
      (e) => `<article id="${escapeHtml(e.id)}">
    <h3>${escapeHtml(e.title)}${e.legacy && !legacyGroup ? ` <span class="legacy-tag">${LEGACY_NOTE}</span>` : ""} <a class="open" href="${escapeHtml(e.id)}.html">open</a></h3>
    ${e.note ? `<p>${escapeHtml(e.note)}</p>` : ""}
    ${
      shots
        ? `<div class="shots">${WIDTHS.flatMap((width) =>
            SCHEMES.map((scheme) => {
              const name = shotName({ id: e.id, width, scheme })
              return `<figure class="w${width}"><a href="png/${name}"><img src="png/${name}" alt="${escapeHtml(e.title)} at ${width} px, ${scheme}" loading="lazy"></a><figcaption>${width} px, ${scheme}: whole page, fixed bars hidden; <a href="png/${screenName({ id: e.id, width, scheme })}">first screen</a></figcaption></figure>`
            }),
          ).join("")}</div>`
        : ""
    }
  </article>`,
    )
    .join("\n")}
</section>`
  }
  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mehen UI gallery</title>
<style>
  body { margin: 0; padding: 24px; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; background: #202124; color: #e8eaed; }
  a { color: #8ab4f8; }
  h1 { font-size: 1.6rem; margin: 0 0 0.25rem; }
  h2 { font-size: 1.2rem; margin: 2.5rem 0 1rem; border-bottom: 1px solid #3c4043; padding-bottom: 0.25rem; }
  h3 { font-size: 1rem; margin: 1.5rem 0 0.25rem; }
  .open { font-weight: normal; font-size: 0.85rem; margin-left: 0.5rem; }
  .toc { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; margin: 0 0 1rem; padding: 0; list-style: none; }
  p { margin: 0 0 0.75rem; color: #bdc1c6; max-width: 70ch; }
  .shots { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-start; }
  figure { margin: 0; }
  figure img { display: block; border: 1px solid #3c4043; border-radius: 6px; max-height: 720px; object-fit: cover; object-position: top; }
  figure.w360 img { width: 222px; }
  figure.w390 img { width: 240px; }
  figure.w768 img { width: 340px; }
  figure.w1024 img { width: 450px; }
  figure.w1280 img { width: 560px; }
  figcaption { font-size: 0.8rem; color: #9aa0a6; margin-top: 4px; }
  .legacy-tag { font-size: 0.75rem; font-weight: 600; color: #202124; background: #fdd663; border-radius: 4px; padding: 1px 6px; vertical-align: middle; }
  .legacy-note { color: #fdd663; }
  section.legacy figure img { opacity: 0.55; }
  .toc .legacy a { color: #9aa0a6; text-decoration: line-through; }
</style>
</head>
<body>
<h1>Mehen UI gallery</h1>
<p>Every page state rendered through the real page shell with fixture data, at ${WIDTHS.join(", ")} px, light and dark. Buttons are shown enabled; on the live pages they enable once the page's checks pass. Each thumbnail is the whole page with the fixed tab and decision bars hidden, cropped to its top; open it for the whole page, or open "first screen" for the 900 px window as a person sees it, bars included.</p>
<p>Groups and pages marked <span class="legacy-tag">${LEGACY_NOTE}</span> are the vault before workspaces: kept for the code that still reuses them, never to design from.</p>
<ul class="toc">${groups.map((g) => `<li${all.filter((e) => e.group === g).every((e) => e.legacy === true) ? ' class="legacy"' : ""}><a href="#${escapeHtml(g.toLowerCase())}">${escapeHtml(g)}</a></li>`).join("")}</ul>
${groups.map(section).join("\n")}
</body>
</html>
`
}

// ---------------------------------------------------------------- main

async function main(argv: string[]): Promise<void> {
  const positional = argv.filter((a) => !a.startsWith("--"))
  const out = positional[0]
  if (!out) {
    console.error("usage: bun scripts/ui-gallery.ts <out-dir> [--no-shots | --measure-only] [--allow-layout] [--chrome <path>]")
    process.exit(2)
  }
  const shots = !argv.includes("--no-shots")
  const capture = !argv.includes("--measure-only")
  const chromeFlag = argv.indexOf("--chrome")
  const chromePath = (chromeFlag >= 0 ? argv[chromeFlag + 1] : findChrome()) ?? ""
  if (shots && chromePath === "") {
    console.error(`no Chrome or Chromium found (looked for ${CHROME_CANDIDATES.join(", ")}): pass --chrome <path>, or --no-shots`)
    process.exit(2)
  }

  const root = path.resolve(import.meta.dirname, "..")
  const css = path.join(root, "dist/assets/app.css")
  try {
    await readFile(css)
  } catch {
    console.error(`${css} is missing: run \`bun run build:ui\` in apps/vault first`)
    process.exit(1)
  }

  const all = entries()
  const ids = new Set<string>()
  for (const entry of all) {
    if (ids.has(entry.id)) throw new Error(`two gallery entries share the id ${entry.id}`)
    ids.add(entry.id)
  }
  const baseline = JSON.parse(await readFile(BASELINE_PATH, "utf8")) as LayoutBaselineEntry[]
  for (const b of baseline) if (!ids.has(b.id)) throw new Error(`${path.basename(BASELINE_PATH)} names ${b.id}, which is not a gallery entry`)

  const outDir = path.resolve(out)
  await mkdir(path.join(outDir, "assets"), { recursive: true })
  await cp(path.join(root, "dist/assets"), path.join(outDir, "assets"), { recursive: true })
  // The pages open from file://, so the stylesheet's absolute font URLs
  // become relative to it.
  await writeFile(path.join(outDir, "assets/app.css"), (await readFile(css, "utf8")).replaceAll("url(/assets/fonts/", "url(fonts/"))
  for (const entry of all) await writeFile(path.join(outDir, `${entry.id}.html`), staticHtml(entry))
  await writeFile(path.join(outDir, "index.html"), contactSheet(all, shots && capture))
  console.log(`${all.length} pages written to ${outDir}`)

  if (shots) {
    const { count, measured, findings } = await screenshotAll(chromePath, outDir, [...ids], { capture })
    console.log(`layout: measured ${measured} states (${ids.size} pages x ${WIDTHS.length} widths x ${SCHEMES.length} schemes), each as loaded and again with every fold open, after the probe passed its canary`)
    if (capture) console.log(`${count} screenshots written to ${path.join(outDir, "png")}`)
    const failing = reportLayout(findings, baseline, outDir)
    if (failing > 0 && !argv.includes("--allow-layout")) process.exit(1)
  }
}

await main(process.argv.slice(2))
