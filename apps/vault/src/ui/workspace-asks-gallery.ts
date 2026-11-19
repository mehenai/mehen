// The gallery entries for the workspace ask pages: an approval in each
// state a decider, the machine's owner and someone who may only stop it
// see, the intake and connect pages a credential is created through, and a
// new machine's enrolment page for acceptance and admission. The fixtures
// for people and projects are the people and projects galleries' own.
// Nothing here is imported by the Worker.

import type { WorkspaceAdoptionInventory, WorkspaceAdoptionItemView, WorkspaceAdoptionView } from "@mehen/protocol/adopt"
import type { PolicyRuleOffer, PolicyRuleTerms } from "@mehen/protocol/policy-mode"
import type { PolicyAreaGrantTerms, PolicyAreaOffer } from "@mehen/protocol/policy-mode"
import { policyCatalogueNamed } from "@mehen/protocol/policy-catalogue"
import type { PolicyAreaProposalViewProjection } from "@mehen/protocol/workspace"
import type { ApprovalGroupRow, ApprovalGroupView, PolicyRuleProposalViewProjection, WorkspaceApprovalView, WorkspaceConnectView, WorkspaceEnrolView, WorkspaceIntakeView } from "@mehen/protocol/workspace"
import type { PushApprovalState, PushOutcome } from "@mehen/protocol/push"
import { fingerprintWords } from "@mehen/protocol/fingerprint"
import { leaseOnlyBinding } from "@mehen/protocol/binding"
import { type FillFieldSpec, KINDS } from "@mehen/protocol"
import { ADOPTION_HOLDER_GONE } from "../adoption-words.ts"
import { FILL_GRANTS, fillCard } from "../vault/areas/browser-workspace.ts"
import type { ApprovalPresentation } from "../vault/services.ts"
import type { PeopleViewer } from "./client/people-logic.ts"
import { workspaceAdoptionPage } from "./pages/workspace-adopt.ts"
import { workspaceAdoptInventoryPage } from "./pages/workspace-adopt-inventory.ts"
import { workspaceApprovalPage, workspaceConnectPage, workspaceIntakePage, workspacePolicyPage, workspaceRuleProposalPage } from "./pages/workspace-asks.ts"
import { workspaceAreaProposalPage } from "./pages/workspace-asks.ts"
import { enrolmentPage } from "./pages/workspace-enrol.ts"
import { workspaceReviewPage } from "./pages/workspace-review.ts"
import { PEOPLE_PROJECTS, PEOPLE_WORKSPACE, THUMBPRINT, peopleShell } from "./people-gallery.ts"
import { GALLERY_ORIGIN, type ShellGalleryEntry } from "./shell-gallery.ts"
import { GALLERY_FIXTURES, GALLERY_ITEMS, GALLERY_WORKSPACE, VIEWERS, galleryProject, galleryShell } from "./workspace-projects-gallery.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const ISO = (offset: number) => new Date(NOW + offset).toISOString()
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()

const RUN_SUBJECT_URL = `${GALLERY_ORIGIN}/w/northwind/projects/prj_platform01`

export function galleryRunApproval(canApprove: boolean, deciders: string[]): WorkspaceApprovalView {
  return {
    view: "detail",
    binding: { snapshotDigest: "s9Lq2nR8vW3xY6zA1bC4dE7fG0hJ5kM2pQ8tU1wX4y0", presentationDigest: "p2Mw5rT8yB1eH4kN7qS0vX3zA6cF9iL2oR5uY8bD1g0" },
    approval: {
      approval: "apr_6t3vb9nx2w",
      status: "pending",
      decidedBy: null,
      bindingCode: "K7Q-2MX",
      item: { slug: "platform", account: null, provider: null },
      requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: "agent \"work\" session" },
      title: "Run platform in prod",
      details: [{ label: "Project", value: "platform" }, { label: "Environment", value: "prod" }, { label: "Variables", value: "OPENAI_API_KEY, GITHUB_TOKEN" }, { label: "Placeholder", value: "OPENAI_API_KEY" }],
      warnings: [],
      email: null,
      request: { method: "RUN", url: RUN_SUBJECT_URL, contentType: null, contentEncoding: null, headers: null, headersSha256: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", bodySha256: "b0dYsHa2Sha256OfTheRunInputxxxxxxxxxxxxxxx", body: "\"node\"\n\"deploy.js\"" },
      digest: "d1Gest0fSubjectAndBindingxxxxxxxxxxxxxxxxxx",
      constraints: { uses: 1, ttlSeconds: 3600 },
      expiresAt: ISO(45 * 60_000),
      workspace: GALLERY_WORKSPACE,
      owner: { kind: "member", member: "mem_alex0001", name: "Alex" },
      eligibility: { canApprove, canDeny: true, canReadAskDetail: true, deciders, reason: canApprove ? null : "Not an eligible approver" },
    },
  }
}

// The run approval after a reference change made it stale.
export function galleryStaleRunApproval(): WorkspaceApprovalView {
  const view = galleryRunApproval(true, ["Tom"])
  return view.view === "detail" ? { ...view, approval: { ...view.approval, status: "stale" } } : view
}

// A mail send through a member's Gmail: forwarded headers, an unreadable
// part the vault warns about, and the recipients laid out.
export function galleryEmailApproval(): WorkspaceApprovalView {
  const view = galleryRunApproval(true, ["Tom"])
  if (view.view !== "detail") return view
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: "apr_3mz8kq1vx5",
      title: "Send an email to priya@acme.example",
      item: { slug: "gmail-alex", account: "alex@northwind.example", provider: "google-gmail" },
      details: [],
      warnings: ["Part 2 of this message could not be read; check the raw body yourself."],
      email: { recipients: [{ header: "To", address: "priya@acme.example", external: true }], accountDomain: "northwind.example", headers: [{ name: "To", value: "priya@acme.example", highlight: true }, { name: "Subject", value: "Quarterly numbers", highlight: false }], sections: [{ heading: "Text", note: null, text: "Hi Priya, the numbers are attached." }], attachments: [] },
      request: { method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", contentType: "application/json", contentEncoding: null, headers: [["X-Goog-Request-Reason", "quarterly-report"]], headersSha256: "fwdHeadersDigestxxxxxxxxxxxxxxxxxxxxxxxxxxx", bodySha256: "bodyDigestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", body: "{\"raw\":\"...\"}" },
    },
  }
}

// The same mail send with text an agent could use to mislead: a
// right-to-left override and a zero-width space in the title, a header and
// the body, and a control character in the session label. The vault's
// card arrives already spelled; the page finds the rest itself.
export function galleryDeceptiveApproval(): WorkspaceApprovalView {
  const view = galleryEmailApproval()
  if (view.view !== "detail") return view
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: "apr_7rq2vx9kd3",
      title: "Send an email to priya@acme.example about invoice_\u202Efdp.exe",
      warnings: [],
      requestedBy: { ...view.approval.requestedBy, session: "agent\u0007work" },
      request: { ...view.approval.request, headers: [["X-Goog-Request-Reason", "quarterly\u200Breport"]], body: "{\"raw\":\"pay\u202Enow\"}" },
    },
  }
}

// A task's workload asked: the machine line stays, and a quieter line names
// the task in the machine's words.
export const GALLERY_TASK = { id: "wl_task8kq2mw4z", label: "globex:grant-7f3k" }
export function galleryWorkloadApproval(): WorkspaceApprovalView {
  const view = galleryEmailApproval()
  if (view.view !== "detail") return view
  return { ...view, approval: { ...view.approval, approval: "apr_6wk3mz8qv2", requestedBy: { ...view.approval.requestedBy, workload: GALLERY_TASK } } }
}

// Fill asks (POST /v1/fill), carrying the vault's own card (fillCard): a
// task typing a password into its sign-in page, and a key typed into
// another service's page, which is warned and asks every time.
function galleryFillApproval(id: string, slug: string, card: ApprovalPresentation, origin: string, constraints: { uses: number; ttlSeconds: number }): WorkspaceApprovalView {
  const view = galleryRunApproval(true, ["Tom"])
  if (view.view !== "detail") return view
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: id,
      title: card.title,
      item: { slug, account: null, provider: null },
      requestedBy: { ...view.approval.requestedBy, session: null, workload: GALLERY_TASK },
      details: card.details,
      warnings: card.warnings ?? [],
      request: { method: "FILL", url: `${origin}/`, contentType: null, contentEncoding: null, headers: null, headersSha256: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", bodySha256: "fillPurposeAndFieldsDigestxxxxxxxxxxxxxxxxx", body: null },
      constraints,
    },
  }
}
const fillField = (kind: "password-login" | "api-key", name: string) => KINDS[kind].fill.find((f) => f.name === name) as FillFieldSpec
export function galleryFillSignInApproval(): WorkspaceApprovalView {
  const card = fillCard({ slug: "github-alex", kind: "password-login", publicFields: { username: "alex@example.com" } }, fillField("password-login", "password"), "https://github.com", FILL_GRANTS.signIn)
  return galleryFillApproval("apr_f1llsgn1n0", "github-alex", card, "https://github.com", { ...FILL_GRANTS.signIn })
}
export function galleryFillTypeIntoApproval(): WorkspaceApprovalView {
  const card = fillCard({ slug: "cloudflare-api-token", kind: "api-key", publicFields: {} }, fillField("api-key", "key"), "https://dash.cloudflare.com", FILL_GRANTS.typeInto)
  return galleryFillApproval("apr_f1llty9e00", "cloudflare-api-token", card, "https://dash.cloudflare.com", { ...FILL_GRANTS.typeInto })
}

// A held GitHub comment the vault offers to allow from now on: the request's
// own path, or it with the issue number as *. termsDigest is the terms'
// policyRuleTermsDigest (workspace-asks-gallery.test.ts recomputes it).
export const GALLERY_RULE_TERMS: PolicyRuleTerms = { item: "github-alex", itemId: "itm_github01", asker: { device: "dev_macmini1", workload: null }, method: "POST", host: "api.github.com", path: "/repos/northwind/platform/issues/12/comments", anchorPath: "/repos/northwind/platform/issues/12/comments", queryNames: [], graphql: null, ttlSeconds: 604_800 }
export const GALLERY_RULE_OFFER: PolicyRuleOffer = { terms: GALLERY_RULE_TERMS, termsDigest: "AVPwGle_RY_YTEOzobptQQ5VOeRDgBXm22pjsH5tsqU", pathChoices: ["/repos/northwind/platform/issues/12/comments", "/repos/northwind/platform/issues/*/comments"], refused: null, coSign: false }

export function galleryRuleApproval(rule: PolicyRuleOffer = GALLERY_RULE_OFFER): WorkspaceApprovalView {
  const view = galleryRunApproval(true, [])
  if (view.view !== "detail") return view
  const url = "https://api.github.com/repos/northwind/platform/issues/12/comments"
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: "apr_5rl8mq2vx7",
      title: "POST api.github.com/repos/northwind/platform/issues/12/comments",
      item: { slug: "github-alex", account: "alex-northwind", provider: "github" },
      details: [{ label: "Credential", value: "github-alex (alex-northwind)" }, { label: "Request", value: "POST api.github.com/repos/northwind/platform/issues/12/comments" }],
      request: { method: "POST", url, contentType: "application/json", contentEncoding: null, headers: [], headersSha256: "T1PNoYwrqgwDVLtfmj7L5e0Sq02OEbqHPC8RFhICuUU", bodySha256: "bodyDigestOfTheCommentxxxxxxxxxxxxxxxxxxxx", body: "{\n  \"body\": \"Deployed to staging.\"\n}" },
      constraints: { uses: 1, ttlSeconds: 600 },
      rememberOptions: { route: null, rule },
    },
  }
}

// The same comment through Linear's GraphQL API, asked by a task on Kim's
// machine, whose credential's home Kim does not manage: approving asks a
// manager of it to co-sign the rule.
export const GALLERY_COSIGN_TERMS: PolicyRuleTerms = { item: "linear-work", itemId: "itm_linear01", asker: { device: "dev_kimlaptop1", workload: "wl_task8kq2mw4z" }, method: "POST", host: "api.linear.app", path: "/graphql", anchorPath: "/graphql", queryNames: [], graphql: { fields: ["commentCreate"], nestedFields: ["body", "comment", "id", "success"] }, ttlSeconds: 604_800 }
export const GALLERY_COSIGN_OFFER: PolicyRuleOffer = { terms: GALLERY_COSIGN_TERMS, termsDigest: "P0YvFG7v9RTt_mGRAtiHdjJWIWA2VKptVr4CgrOq0gY", pathChoices: ["/graphql"], refused: null, coSign: true }

export function galleryCosignApproval(): WorkspaceApprovalView {
  const view = galleryRuleApproval(GALLERY_COSIGN_OFFER)
  if (view.view !== "detail") return view
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: "apr_8cs2kq7mz4",
      title: "Comment on a Linear issue",
      item: { slug: "linear-work", account: "kim@northwind.example", provider: "linear" },
      requestedBy: { device: "dev_kimlaptop1", deviceName: "kim-laptop", session: null, workload: GALLERY_TASK },
      details: [{ label: "Credential", value: "linear-work (kim@northwind.example)" }, { label: "Request", value: "POST api.linear.app/graphql" }],
      request: { ...view.approval.request, url: "https://api.linear.app/graphql", body: "{\n  \"query\": \"mutation { commentCreate(input: $input) { success comment { id body } } }\"\n}" },
      owner: { kind: "member", member: "mem_kim00001", name: "Kim" },
    },
  }
}

// A mail send the vault will never allow from now on: one muted line why,
// and only Approve once.
export function galleryRefusedRuleApproval(): WorkspaceApprovalView {
  const view = galleryEmailApproval()
  if (view.view !== "detail") return view
  return { ...view, approval: { ...view.approval, approval: "apr_2rf9vq4mk8", warnings: [], rememberOptions: { route: null, rule: { terms: null, termsDigest: null, pathChoices: [], refused: "rule.send", coSign: false } } } }
}

// A held D1 database create on Cloudflare, which the vault offers to allow
// from now on and to start a task grant on: D1 databases ticked, 1 hour and
// 50 requests, with every other area of Cloudflare's reviewed list to tick.
// Each termsDigest is its terms' digest (workspace-asks-gallery.test.ts
// recomputes them).
const CF_D1_PATH = "/client/v4/accounts/0f3b8c1d2e4a5b6c7d8e9f0a1b2c3d4e/d1/database"
const CLOUDFLARE_AREAS = (policyCatalogueNamed("cloudflare-api-token")?.areas ?? []).map((a) => ({ id: a.id, name: a.name, words: a.words, requestArea: a.id === "d1" }))
export const GALLERY_AREA_TERMS: PolicyAreaGrantTerms = { kind: "area", item: "cloudflare-api-token-local-secrets-2", itemId: "itm_cloudflare1", asker: { device: "dev_macmini1", workload: null }, host: "api.cloudflare.com", catalogue: "cloudflare-api-token", catalogueVersion: 1, areas: ["d1"], ttlSeconds: 3600, maxUses: 50 }
export const GALLERY_AREA_OFFER: PolicyAreaOffer = { terms: GALLERY_AREA_TERMS, termsDigest: "oJVFYzXrQc027yH71Tf7mAFfN9W9XDiycEFInjcXwZ8", areas: CLOUDFLARE_AREAS, refused: null, coSign: false }
const GALLERY_D1_RULE_TERMS: PolicyRuleTerms = { item: "cloudflare-api-token-local-secrets-2", itemId: "itm_cloudflare1", asker: { device: "dev_macmini1", workload: null }, method: "POST", host: "api.cloudflare.com", path: CF_D1_PATH, anchorPath: CF_D1_PATH, queryNames: [], graphql: null, ttlSeconds: 604_800 }
export const GALLERY_D1_RULE_OFFER: PolicyRuleOffer = { terms: GALLERY_D1_RULE_TERMS, termsDigest: "H1IFcwSGQPAnn45WDINhMqthzNY-176uDytxQUgyM6o", pathChoices: [CF_D1_PATH], refused: null, coSign: false }

export function galleryAreaApproval(rule: PolicyRuleOffer = GALLERY_D1_RULE_OFFER, area: PolicyAreaOffer = GALLERY_AREA_OFFER): WorkspaceApprovalView {
  const view = galleryRuleApproval(rule)
  if (view.view !== "detail") return view
  const url = `https://api.cloudflare.com${CF_D1_PATH}`
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: "apr_7ta3kq9mw2",
      title: "Create a D1 database",
      item: { slug: "cloudflare-api-token-local-secrets-2", account: null, provider: "cloudflare" },
      details: [{ label: "Credential", value: "cloudflare-api-token-local-secrets-2" }, { label: "Request", value: `POST api.cloudflare.com${CF_D1_PATH}` }],
      request: { ...view.approval.request, url, body: "{\n  \"name\": \"local-secrets-staging\"\n}" },
      rememberOptions: { route: null, rule, area },
    },
  }
}

// The same create from Kim's machine, on a credential whose home Kim does
// not manage: both the rule and the task grant need a manager to co-sign.
export const GALLERY_AREA_COSIGN_OFFER: PolicyAreaOffer = { terms: { ...GALLERY_AREA_TERMS, asker: { device: "dev_kimlaptop1", workload: null } }, termsDigest: "2lcSjoEtEzGBbwhe_J-otO_ujY8JNvsSmfDXCq0hIL0", areas: CLOUDFLARE_AREAS, refused: null, coSign: true }
export const GALLERY_D1_RULE_COSIGN_OFFER: PolicyRuleOffer = { terms: { ...GALLERY_D1_RULE_TERMS, asker: { device: "dev_kimlaptop1", workload: null } }, termsDigest: "GIkwfTbwTuGs1srYk1sglq58j5a8uMGWyCsuVpkARa4", pathChoices: [CF_D1_PATH], refused: null, coSign: true }
export function galleryAreaCosignApproval(): WorkspaceApprovalView {
  const view = galleryAreaApproval(GALLERY_D1_RULE_COSIGN_OFFER, GALLERY_AREA_COSIGN_OFFER)
  if (view.view !== "detail") return view
  return { ...view, approval: { ...view.approval, approval: "apr_3cq8mz2kv6", requestedBy: { device: "dev_kimlaptop1", deviceName: "kim-laptop", session: null }, owner: { kind: "member", member: "mem_kim00001", name: "Kim" } } }
}

// The mail send again: neither a rule nor a task grant, each saying why.
export function galleryRefusedAreaApproval(): WorkspaceApprovalView {
  const view = galleryRefusedRuleApproval()
  if (view.view !== "detail") return view
  return { ...view, approval: { ...view.approval, approval: "apr_6nr4wq8kz3", rememberOptions: { route: null, rule: view.approval.rememberOptions!.rule!, area: { terms: null, termsDigest: null, areas: [], refused: "area.not-routine", coSign: false } } } }
}

// A task grant Kim signed from that approval, D1 databases and KV for 1
// hour and up to 50 requests, waiting for a manager of the credential's
// home to co-sign (/w/<slug>/p/<pol_id>). termsDigest and digest are the
// vault's (workspace-asks-gallery.test.ts recomputes them).
type AreaProposalDetail = PolicyAreaProposalViewProjection
const signedAreas = (ids: readonly string[]) => CLOUDFLARE_AREAS.filter((a) => ids.includes(a.id))
export const GALLERY_AREA_PROPOSAL: AreaProposalDetail = {
  view: "detail",
  proposal: {
    proposal: "pol_6ag3kq8mw2",
    item: "cloudflare-api-token-local-secrets-2",
    status: "pending",
    stage: "co-sign",
    bindingCode: "W8KD3P",
    summary: "Task grant on api.cloudflare.com: D1 databases, KV namespaces and values, from kim-laptop, outside any project, 1 hour, up to 50 requests",
    expiresAt: at(23 * 60),
    rule: null,
    kind: "area",
    extends: null,
    requestedBy: { member: "mem_kim00001", self: false },
    reason: null,
    terms: { ...GALLERY_AREA_TERMS, asker: { device: "dev_kimlaptop1", workload: null }, areas: ["d1", "kv"] },
    termsDigest: "N0xgvgVfDd644wxJ2615hsUta2sc6TjqEt1gZwNWdTg",
    areas: signedAreas(["d1", "kv"]),
    digest: "0iP7gye9vFlrigrsEN3pyCq3TeoG8N-t7m7Zb-RssAY",
    approvedBy: { name: "Kim" },
    canApprove: true,
    canDeny: true,
    workspace: GALLERY_WORKSPACE,
    owner: { kind: "member", member: "mem_kim00001", name: "Kim" },
    eligibility: { canApprove: true, canDeny: true, canReadAskDetail: true, deciders: [], reason: null },
  },
}
// Co-signed: the grant the vault made, until its end.
export const GALLERY_AREA_PROPOSAL_APPROVED: AreaProposalDetail = { view: "detail", proposal: { ...GALLERY_AREA_PROPOSAL.proposal, status: "approved", rule: { id: "rul_2ga8kq4mz7", endsAt: at(60) }, canApprove: false, canDeny: false } }

// A machine asks to put openai-prod into a GitHub repository (design
// push-providers 4). The vault always warns that a push cannot be taken
// back, so every push page is warned. The value's prefix and fingerprint
// are fixtures, as the page reads them for the version pushed.
export const GALLERY_PUSHED_VALUE = { prefix: "mehen_fixture_", fingerprint: "fixtureFp001" }
const PUSH_KNOWN = { owner: "northwind", repo: "platform", parent: null as string | null, fork: false, private: true, newDestination: false, exists: true as boolean | null }
type PushFixture = typeof PUSH_KNOWN & { id: string; reason?: string; status?: "pending" | "used"; state?: PushApprovalState; outcome?: PushOutcome; providerStatus?: number }

export function galleryPushApproval(f: PushFixture): WorkspaceApprovalView {
  const view = galleryRunApproval(true, [])
  if (view.view !== "detail") return view
  const destination = `github:${f.owner}/${f.repo}/OPENAI_API_KEY`
  const words = `GitHub ${f.owner}/${f.repo}, Actions secret OPENAI_API_KEY`
  const warnings = ["Mehen cannot take this back. Removing it later is done in GitHub."]
  if (f.newDestination) warnings.push(`This workspace has never pushed to ${f.owner}.`)
  if (f.fork) warnings.push(`Fork of ${f.parent ?? "another repository"}: its owner, not this workspace, controls it.`)
  return {
    ...view,
    approval: {
      ...view.approval,
      approval: f.id,
      status: f.status ?? "pending",
      decidedBy: f.status === "used" ? { name: "Alex", self: true } : null,
      title: `Put openai-prod into ${words}, using github-ci`,
      item: { slug: "openai-prod", account: null, provider: null },
      details: [{ label: "Where", value: words }, { label: "Value", value: "openai-prod, field key, version 3" }, { label: "Using", value: "github-ci (as northwind-bot)" }, ...(f.reason !== undefined ? [{ label: "The agent says", value: f.reason }] : [])],
      warnings,
      email: null,
      request: { method: "PUSH", url: `mehen-push:${destination}`, contentType: null, contentEncoding: null, headers: null, headersSha256: "T1PNoYwrqgwDVLtfmj7L5e0Sq02OEbqHPC8RFhICuUU", bodySha256: "pushBodyDigestOfTheHashedFieldsxxxxxxxxxxxx", body: null },
      constraints: { uses: 1, ttlSeconds: 600 },
      expiresAt: ISO(8 * 60_000),
      push: {
        destination, field: "key", version: 3, state: f.state ?? "pending", ...(f.outcome !== undefined ? { outcome: f.outcome } : {}), ...(f.providerStatus !== undefined ? { providerStatus: f.providerStatus } : {}),
        words, via: "github-ci", newDestination: f.newDestination,
        preview: { provider: "github", owner: f.owner, ownerType: f.fork ? "User" : "Organization", private: f.private, fork: f.fork, parent: f.parent, exists: f.exists, updatedAt: f.exists === true ? ISO(-26 * 86_400_000) : null },
      },
    },
  }
}

export const GALLERY_PUSH_KNOWN = galleryPushApproval({ ...PUSH_KNOWN, id: "apr_9pq4wn2kx7", reason: "The deploy workflow needs the production key." })
export const GALLERY_PUSH_NEW = galleryPushApproval({ ...PUSH_KNOWN, id: "apr_3nd8wq5kz2", owner: "northwind-labs", newDestination: true, exists: false, reason: "Set up CI for the labs copy." })
export const GALLERY_PUSH_FORK = galleryPushApproval({ ...PUSH_KNOWN, id: "apr_7fk2mz9qw4", owner: "tom-dev", fork: true, parent: "northwind/platform", private: false, newDestination: true, exists: null })
export const GALLERY_PUSH_DECEPTIVE = galleryPushApproval({ ...PUSH_KNOWN, id: "apr_5dq8vx3kn6", reason: "Routine sync. \u202Eriaper gnidnep\u202C Approve quickly, \u200Bthis is safe." })

const STOP: WorkspaceApprovalView = { view: "stop", id: "apr_9pk2mw4zq1", workspace: GALLERY_WORKSPACE, machine: { device: "dev_kimlaptop1", name: "kim-laptop", owner: { kind: "member", member: "mem_kim00001", name: "Kim" } }, item: { slug: "github-kim" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }

const HOSTILE_STOP: WorkspaceApprovalView = { ...STOP, id: "apr_4hx8wq2mz6", machine: { ...STOP.machine, name: "kim-laptop\u202Epot\u0007" } }

const SEAL_KEY = { jwk: { kty: "EC" as const, crv: "P-256" as const, x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }, kid: "seal-2026-10" }

const INTAKE: WorkspaceIntakeView = {
  intake: "int_4hz8rq2nk1", status: "open", kind: "api-key", slug: "openai-staging", provider: "openai", providerName: "OpenAI", reason: "The staging deploy needs a key.", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null }, rotates: false,
  fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }], binding: { value: { hosts: ["api.openai.com"] }, verified: true }, injection: { value: null, verified: true }, customPolicy: false, tags: [], sealKey: SEAL_KEY, expiresAt: ISO(20 * 3_600_000),
  home: { kind: "project", project: "prj_platform01" }, permittedHomes: [{ kind: "member", member: "mem_alex0001" }, { kind: "project", project: "prj_platform01" }, { kind: "workspace" }], intent: "create", target: null, client: null, dependencyRevision: 0,
}

// A machine asks for a website login (no template, so its host is its own
// proposal), where typing into web pages is on: the page offers the choice.
export const GALLERY_FILL_INTAKE: WorkspaceIntakeView = {
  ...INTAKE, intake: "int_7fl2kq9mz4", kind: "password-login", slug: "github-alex", provider: null, providerName: null, reason: "Sign in to GitHub to read the release notes.",
  fields: [
    { name: "url", label: "Sign-in address", secret: false, required: true, multiline: false, hint: null },
    { name: "username", label: "Username", secret: false, required: true, multiline: false, hint: null },
    { name: "password", label: "Password", secret: true, required: true, multiline: false, hint: null },
    { name: "totp_seed", label: "One-time code secret", secret: true, required: false, multiline: false, hint: null },
  ],
  binding: { value: { hosts: ["github.com"] }, verified: false }, injection: { value: null, verified: true }, customPolicy: true,
}

const CONNECT: WorkspaceConnectView = {
  connect: "con_8vw2kq5mz3", status: "open", provider: "google-gmail", providerName: "Gmail", slug: "gmail-alex", scopes: ["https://www.googleapis.com/auth/gmail.readonly"], tags: ["mail"], expect: "alex@northwind.example", reason: "Read the support inbox.", requestedBy: { member: "mem_alex0001", self: true }, reconnect: false, currentScopes: null, account: null, message: null, expiresAt: ISO(15 * 60_000),
  home: { kind: "member", member: "mem_alex0001" }, permittedHomes: [{ kind: "member", member: "mem_alex0001" }, { kind: "workspace" }], intent: "create", target: null, client: { item: "itm_gclient01", configRevision: 1 }, dependencyRevision: 0,
}

// An agent whose reason hides a direction override and whose machine name
// carries an invisible character.
const DECEPTIVE_INTAKE: WorkspaceIntakeView = { ...INTAKE, intake: "int_9vq3mz7kd2", reason: "The staging deploy needs a key. \u202Etrats ot yaw ruoy gniyap\u202C", requestedBy: { device: "dev_macmini1", deviceName: "mac\u200Boffice", session: null } }

// An account to expect that hides a zero-width space, so the name the
// person checks at the provider is not the one shown.
const DECEPTIVE_CONNECT: WorkspaceConnectView = { ...CONNECT, connect: "con_3kd9vx2mq7", expect: "alex@northwind\u200B.ai", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null } }

// Rule proposals (/w/<slug>/p/<pol_id>). termsDigest and digest are the
// vault's for what each shows (workspace-asks-gallery.test.ts recomputes
// them). A machine's own: the issue number as *, for 30 days, either of
// which its owner may narrow.
export const GALLERY_PROPOSED_TERMS: PolicyRuleTerms = { ...GALLERY_RULE_TERMS, path: "/repos/northwind/platform/issues/*/comments", ttlSeconds: 2_592_000 }
type RuleProposalDetail = Extract<PolicyRuleProposalViewProjection, { view: "detail" }>
export const GALLERY_RULE_PROPOSAL: RuleProposalDetail = {
  view: "detail",
  proposal: {
    proposal: "pol_7rk2mq9vx4",
    item: "github-alex",
    status: "pending",
    stage: "approve",
    bindingCode: "K7M2QX",
    summary: "POST api.github.com/repos/northwind/platform/issues/*/comments, from mac-mini, outside any project, 30 days",
    expiresAt: at(23 * 60),
    rule: null,
    kind: "rule",
    extends: null,
    requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null },
    reason: "Post the deploy status on each issue it closes",
    terms: GALLERY_PROPOSED_TERMS,
    termsDigest: "BEajoDA9bGWZw8EVt5Au3kkmkFFgXKvAdsBRv2yfTys",
    pathChoices: [GALLERY_RULE_TERMS.anchorPath, GALLERY_PROPOSED_TERMS.path],
    digest: "X0Zz4RoXjjKkKlwfYGRroM7zgAvvMGh3MrcFoI-5rcU",
    approvedBy: null,
    canApprove: true,
    canDeny: true,
    workspace: GALLERY_WORKSPACE,
    owner: { kind: "member", member: "mem_alex0001", name: "Alex" },
    eligibility: { canApprove: true, canDeny: true, canReadAskDetail: true, deciders: [], reason: null },
  },
}
export const GALLERY_RULE_ITEM = { provider: "github", account: "alex-northwind" }

// A task's proposal Kim approved as the machine's owner, waiting for a
// manager of the Linear credential's home to co-sign.
export const GALLERY_COSIGN_PROPOSAL: RuleProposalDetail = {
  view: "detail",
  proposal: {
    ...GALLERY_RULE_PROPOSAL.proposal,
    proposal: "pol_3cs8kq2mz6",
    item: "linear-work",
    stage: "co-sign",
    bindingCode: "R4WN8C",
    summary: "POST api.linear.app/graphql, commentCreate, from task globex:grant-7f3k on kim-laptop, outside any project, 7 days",
    requestedBy: { device: "dev_kimlaptop1", deviceName: "kim-laptop", session: null, workload: GALLERY_TASK },
    reason: "Comment on the issue when a task finishes",
    terms: GALLERY_COSIGN_TERMS,
    termsDigest: "P0YvFG7v9RTt_mGRAtiHdjJWIWA2VKptVr4CgrOq0gY",
    pathChoices: ["/graphql"],
    digest: "9tJbZfwIn-Y0Xr4am_D8o1JkU36fdce0xR6ke32eYzs",
    approvedBy: { name: "Kim" },
    owner: { kind: "member", member: "mem_kim00001", name: "Kim" },
  },
}

// Kim, who does not manage the GitHub credential's home, asked to extend
// its rule by 30 days: its path stays, and a manager must co-sign.
export const GALLERY_EXTEND_PROPOSAL: RuleProposalDetail = {
  view: "detail",
  proposal: {
    ...GALLERY_RULE_PROPOSAL.proposal,
    proposal: "pol_9ex4hq8mz2",
    stage: "co-sign",
    bindingCode: "T2HX7Q",
    summary: "POST api.github.com/repos/northwind/platform/issues/12/comments, from mac-mini, outside any project, 30 days",
    extends: "rul_4hq8mz2kx7",
    requestedBy: { member: "mem_kim00001", self: false },
    reason: null,
    terms: { ...GALLERY_RULE_TERMS, ttlSeconds: 2_592_000 },
    termsDigest: "sHAsIXrjddXi-qbgk-nvEfsGyTLL_9WVFDttjoUgF8U",
    pathChoices: [GALLERY_RULE_TERMS.path],
    digest: "MZE93wk4RW0F6HT43cpJoYiEd77Wy7erqe7PKLfJFik",
    approvedBy: { name: "Kim" },
  },
}

// Someone who may read the proposal and neither approve nor deny it.
export const GALLERY_READ_ONLY_PROPOSAL: RuleProposalDetail = { view: "detail", proposal: { ...GALLERY_RULE_PROPOSAL.proposal, canApprove: false, canDeny: false, eligibility: { canApprove: false, canDeny: false, canReadAskDetail: true, deciders: [], reason: null } } }

export const POLICY_STOP: Extract<PolicyRuleProposalViewProjection, { view: "stop" }> = { view: "stop", id: "pol_8kq2mw4zx1", workspace: GALLERY_WORKSPACE, machine: { device: "dev_kimlaptop1", name: "kim-laptop", owner: { kind: "member", member: "mem_kim00001", name: "Kim" } }, item: { slug: "github-kim" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }

// Tom, a member, accepting his own machine: the private tick starts on.
export const PEOPLE_ENROL: WorkspaceEnrolView = {
  workspace: PEOPLE_WORKSPACE,
  enrolment: "enr_new01",
  ref: "K7QX-29PD",
  code: "K7QX-29PD",
  name: "tom-laptop",
  host: "toms-mbp.local",
  backend: "secure-enclave",
  start: { at: at(-3), place: "Amsterdam, NL", clientLabel: "mehen 0.2.0 on macOS" },
  acceptorPlace: "Amsterdam, NL",
  requestedOwner: { kind: "self" },
  owner: null,
  scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials: true },
  digest: "dgst_enrol",
  fingerprint: { groups: ["7KQ2", "X9PD", "M4TR"], hidden: 2, check: "check_hash", words: fingerprintWords(THUMBPRINT) },
  state: "pending_owner_acceptance",
  actions: ["accept", "reject"],
  expiresAt: at(12),
  hardExpiresAt: at(23 * 60),
  lease: "live",
  claimed: null,
  reason: null,
  successor: null,
}

// The same machine as a guest's own: the private tick starts off.
export const GUEST_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL, scope: { ...PEOPLE_ENROL.scope, privateCredentials: false } }

// A machine that asked for less than usual: only relay and stand-in values,
// credentials tagged ci, none private, acting only through workloads.
export const SCOPED_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL, enrolment: "enr_scoped01", name: "globex-agent", scope: { tags: ["ci"], projects: [], maxEnvironment: "unprotected", modes: ["relay", "placeholder"], privateCredentials: false, workloads: "required" }, requested: { tags: ["ci"], modes: ["relay", "placeholder"], privateCredentials: false, workloads: "required" } }

// The same machine opened by its enrolment id: no clear code anywhere.
export const PEOPLE_ENROL_BY_ID: WorkspaceEnrolView = (() => {
  const { code: _code, ...rest } = PEOPLE_ENROL
  return { ...rest, ref: "enr_new01" }
})()

const HOSTILE_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL_BY_ID, enrolment: "enr_hostile01", ref: "enr_hostile01", name: "tom-laptop\u202Epot\u200B", host: "toms-mbp\u0007.local" }

// Past its hour, inside its day: an owner may still reject it.
const LAPSED_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL_BY_ID, expiresAt: at(-5), lease: "lapsed", actions: ["reject"] }

// Replaced by the same machine's newer attempt, which this viewer may open.
const SUPERSEDED_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL_BY_ID, enrolment: "enr_old01", ref: "enr_old01", state: "expired", actions: [], lease: "terminal", reason: "superseded", successor: { enrolment: "enr_new02", expiresAt: at(48) }, expiresAt: at(-70) }

// A team's machine never uses private credentials.
const TEAM_ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL, enrolment: "enr_team01", name: "team-bot", host: "ci-host", requestedOwner: { kind: "team", team: "tm_platform01", name: "Platform" }, scope: { ...PEOPLE_ENROL.scope, privateCredentials: false }, actions: ["admit", "reject"] }

function viewer(role: PeopleViewer["role"], member = "mem_alex01"): PeopleViewer {
  return { member, role, blocked: false }
}

// An adoption batch from two machines: an OpenAI key from a template, a
// custom destination, a stale source, two rows holding the same value, and
// a row whose proposed home this person cannot add to.
const ADOPT_HOMES: WorkspaceAdoptionItemView["homesAllowed"] = [{ kind: "workspace" }, { kind: "project", project: "prj_platform01" }, { kind: "member", member: "mem_alex0001" }]
const adoptRow = (ref: string, slug: string, extra: Partial<WorkspaceAdoptionItemView> = {}): WorkspaceAdoptionItemView => ({
  ref,
  slug,
  kind: "api-key",
  provider: "openai",
  providerName: "OpenAI API key",
  binding: { value: { hosts: ["api.openai.com"] }, verified: true },
  injection: { value: null, verified: true },
  home: { kind: "project", project: "prj_platform01" },
  homesAllowed: ADOPT_HOMES,
  tags: ["ai"],
  publicFields: {},
  secrets: [{ name: "key", length: 164, prefix: "sk-proj-", fingerprint: "AbC123xY", box: "b0xD1gestOfTheUploadedSealedBoxxxxxxxxxxxx" }],
  sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [] }],
  sameValueAs: [],
  repo: { remote: "github.com/northwind/platform", env: "dev" },
  problem: null,
  ...extra,
})
export const GALLERY_ADOPTION: WorkspaceAdoptionView = {
  adoption: "adp_7kq2mw4zx1",
  status: "open",
  expiresAt: ISO(20 * 3_600_000),
  requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: "agent \"adopt\" session" },
  machines: [{ device: "dev_macmini1", name: "mac-mini", items: 4 }, { device: "dev_laptop0001", name: "alex-laptop", items: 1 }],
  items: [
    adoptRow("a001", "openai-platform", { sameValueAs: ["a004"] }),
    adoptRow("a002", "weather-api", { provider: null, providerName: null, binding: { value: { hosts: ["api.weatherapi.com", "weather-proxy.example.net"] }, verified: false }, injection: { value: { in: "query", name: "key", field: "key" }, verified: false }, tags: [], secrets: [{ name: "key", length: 32, prefix: "", fingerprint: "Wq9Zt1Lm", box: "b0xD1gestOfTheWeatherBoxxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env", variable: "WEATHER_KEY", pointer: null, stale: [] }] }),
    adoptRow("a003", "openai-old", { sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env.backup", variable: "OPENAI_API_KEY", pointer: null, stale: ["commented out"] }] }),
    adoptRow("a004", "openai-scripts", { home: { kind: "member", member: "mem_alex0001" }, repo: null, sources: [{ machine: "alex-laptop", path: "/Users/alex/.config/scripts/settings.json", variable: null, pointer: "/openai/apiKey", stale: [] }] }),
    adoptRow("a005", "openai-website", { home: { kind: "project", project: "prj_website01" }, problem: "You cannot add credentials to this home; choose another.", repo: { remote: "github.com/northwind/website", env: null }, sources: [{ machine: "mac-mini", path: "/Users/alex/code/website/.dev.vars", variable: "OPENAI_API_KEY", pointer: null, stale: [] }] }),
  ],
}
const DECEPTIVE_ADOPTION: WorkspaceAdoptionView = { ...GALLERY_ADOPTION, adoption: "adp_4hx8wq2mz6", items: GALLERY_ADOPTION.items.map((i) => (i.ref === "a002" ? { ...i, binding: { value: { hosts: ["api.weatherapi.com\u200B.example.net"] }, verified: false } } : i)) }

// A secret only mehen run delivers: an agent asked for it with no host,
// and a machine adopting a .env found two with no template, a signing
// secret stored only until a human sets its ceiling to lease, and an SSH
// key stored only.
const LEASE_ONLY_INTAKE: WorkspaceIntakeView = { ...INTAKE, intake: "int_2kq8mw4zl5", kind: "generic", slug: "session-secret", provider: null, providerName: null, reason: "The app signs its sessions with it.", fields: [{ name: "value", label: "Value", secret: true, required: true, multiline: false, hint: null }], binding: { value: leaseOnlyBinding(), verified: false }, customPolicy: false }
const LEASE_ONLY_ADOPTION: WorkspaceAdoptionView = {
  ...GALLERY_ADOPTION,
  adoption: "adp_5lq2mw4zl9",
  machines: [{ device: "dev_macmini1", name: "mac-mini", items: 4 }],
  items: [
    adoptRow("a001", "jwt-secret", { kind: "generic", provider: null, providerName: null, binding: { value: leaseOnlyBinding(), verified: false }, tags: [], secrets: [{ name: "value", length: 64, prefix: "", fingerprint: "Jw7Tq2Lm", box: "b0xD1gestOfTheJwtBoxxxxxxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env", variable: "JWT_SECRET", pointer: null, stale: [] }] }),
    adoptRow("a002", "database-url", { kind: "database-url", provider: null, providerName: null, binding: { value: leaseOnlyBinding(), verified: false }, tags: [], secrets: [{ name: "url", length: 71, prefix: "", fingerprint: "Db4Rk9Pz", box: "b0xD1gestOfTheDatabaseBoxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env", variable: "DATABASE_URL", pointer: null, stale: [] }] }),
    adoptRow("a003", "webhook-signing", { kind: "hmac-key", provider: null, providerName: null, binding: { value: leaseOnlyBinding(), verified: false }, tags: [], secrets: [{ name: "key", length: 40, prefix: "", fingerprint: "Hm2Vx8Kq", box: "b0xD1gestOfTheSigningBoxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "mac-mini", path: "/Users/alex/code/platform/.env", variable: "WEBHOOK_SIGNING_SECRET", pointer: null, stale: [] }] }),
    adoptRow("a004", "deploy-ssh", { kind: "ssh-key", provider: null, providerName: null, binding: { value: leaseOnlyBinding(), verified: false }, tags: [], secrets: [{ name: "private_key", length: 411, prefix: "", fingerprint: "Ss5Nd3Yr", box: "b0xD1gestOfTheSshKeyBoxxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "mac-mini", path: "/Users/alex/.local-secrets/deploy_ed25519", variable: null, pointer: null, stale: [] }] }),
  ],
}

// A batch whose names the vault already holds: an OpenAI key the same as
// the stored one, an Anthropic key that differs from it and reaches two
// environments and two machines, a GitHub token staged in another batch
// still open, a Stripe key whose comparison was capped, a row whose holder
// has gone, and an ordinary row. The compare fingerprints are sentinels a
// page must never render: they are signing data only.
export const GALLERY_COMPARE_FINGERPRINTS = ["CmpSentinelOpenai01", "CmpSentinelAnthro02", "CmpSentinelGithub03"] as const
const storedHolder = (slug: string, version: number, extra: { rotatedAt?: string | null; lastUsedAt?: string | null; prefix?: string } = {}) => ({
  type: "stored" as const,
  id: `itm_${slug.replaceAll("-", "")}`,
  slug,
  kind: "api-key" as const,
  version,
  secrets: [{ name: "key", length: 164, prefix: extra.prefix ?? "sk-proj-" }],
  rotatedAt: extra.rotatedAt === undefined ? ISO(-40 * 86_400_000) : extra.rotatedAt,
  lastUsedAt: extra.lastUsedAt === undefined ? ISO(-2 * 3_600_000) : extra.lastUsedAt,
})
export const GALLERY_CONFLICT_ADOPTION: WorkspaceAdoptionView = {
  adoption: "adp_9cf3mw4zr2",
  status: "open",
  expiresAt: ISO(20 * 3_600_000),
  maxExpiresAt: ISO(6 * 86_400_000 + 20 * 3_600_000),
  requestedBy: { device: "dev_linuxbox00001", deviceName: "linuxbox", session: null },
  machines: [{ device: "dev_linuxbox00001", name: "linuxbox", items: 6 }],
  items: [
    adoptRow("c001", "openai-platform", {
      sources: [{ machine: "linuxbox", path: "/home/alex/code/platform/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [], mtime: ISO(-3 * 86_400_000) }],
      compare: { holder: storedHolder("openai-platform", 4), fields: [{ name: "key", result: "same", fingerprint: GALLERY_COMPARE_FINGERPRINTS[0] }], affected: { references: [{ project: "platform", env: "dev", variable: "OPENAI_API_KEY" }], machines: ["mac-mini"], leasingDevices: 1, connections: [] } },
    }),
    adoptRow("c002", "anthropic-platform", {
      provider: "anthropic",
      providerName: "Anthropic API key",
      binding: { value: { hosts: ["api.anthropic.com"] }, verified: true },
      secrets: [{ name: "key", length: 108, prefix: "sk-ant-", fingerprint: "Rw8Kd2Qp", box: "b0xD1gestOfTheAnthropicBoxxxxxxxxxxxxxxxx" }],
      sources: [{ machine: "linuxbox", path: "/home/alex/code/platform/.env", variable: "ANTHROPIC_API_KEY", pointer: null, stale: [], mtime: ISO(-86_400_000) }],
      compare: {
        holder: { ...storedHolder("anthropic-platform", 7, { prefix: "sk-ant-" }), secrets: [{ name: "key", length: 108, prefix: "sk-ant-" }] },
        fields: [{ name: "key", result: "differs", fingerprint: GALLERY_COMPARE_FINGERPRINTS[1] }],
        affected: { references: [{ project: "platform", env: "dev", variable: "ANTHROPIC_API_KEY" }, { project: "platform", env: "prod", variable: "ANTHROPIC_API_KEY" }], machines: ["hel1", "mac-mini"], leasingDevices: 2, connections: [] },
      },
    }),
    adoptRow("c003", "github-pat-gh", {
      provider: "github-pat",
      providerName: "GitHub personal access token",
      binding: { value: { hosts: ["api.github.com"] }, verified: true },
      repo: null,
      tags: [],
      secrets: [{ name: "key", length: 40, prefix: "gho_", fingerprint: "Gh5Tz1Vb", box: "b0xD1gestOfTheGithubBoxxxxxxxxxxxxxxxxxxx" }],
      sources: [{ machine: "linuxbox", path: "/home/alex/.config/gh/hosts.yml", variable: null, pointer: "/github.com/oauth_token", stale: [] }],
      compare: {
        holder: { type: "staged", id: "adp_7kq2mw4zx1/a009", slug: "github-pat-gh", kind: "api-key", version: null, secrets: [{ name: "key", length: 40, prefix: "gho_" }], sources: [{ machine: "mac-mini", path: "/Users/alex/.config/gh/hosts.yml", variable: null, pointer: "/github.com/oauth_token", stale: [], mtime: ISO(-5 * 86_400_000) }] },
        fields: [{ name: "key", result: "differs", fingerprint: GALLERY_COMPARE_FINGERPRINTS[2] }],
      },
    }),
    adoptRow("c004", "stripe-test", {
      provider: "stripe",
      providerName: "Stripe secret key",
      binding: { value: { hosts: ["api.stripe.com"] }, verified: true },
      repo: null,
      tags: [],
      secrets: [{ name: "key", length: 107, prefix: "sk_test_", fingerprint: "St3Wq7Nc", box: "b0xD1gestOfTheStripeBoxxxxxxxxxxxxxxxxxxx" }],
      sources: [{ machine: "linuxbox", path: "/home/alex/.config/stripe/config.toml", variable: null, pointer: "/test_mode_api_key", stale: [] }],
      compare: { holder: { ...storedHolder("stripe-test", 2, { prefix: "sk_test_", lastUsedAt: null }), secrets: [{ name: "key", length: 107, prefix: "sk_test_" }] }, fields: [{ name: "key", result: "unknown", fingerprint: null }], affected: { references: [], machines: [], leasingDevices: 0, connections: [] } },
    }),
    adoptRow("c005", "weather-api", { provider: null, providerName: null, binding: { value: { hosts: ["api.weatherapi.com"] }, verified: false }, injection: { value: { in: "query", name: "key", field: "key" }, verified: false }, tags: [], problem: ADOPTION_HOLDER_GONE, secrets: [{ name: "key", length: 32, prefix: "", fingerprint: "Wq9Zt1Lm", box: "b0xD1gestOfTheWeatherBoxxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "linuxbox", path: "/home/alex/code/platform/.env", variable: "WEATHER_KEY", pointer: null, stale: [] }], compare: null }),
    adoptRow("c006", "sentry-platform", { provider: "sentry", providerName: "Sentry auth token", binding: { value: { hosts: ["sentry.io"] }, verified: true }, tags: [], secrets: [{ name: "key", length: 71, prefix: "sntrys_", fingerprint: "Sn6Yr4Hd", box: "b0xD1gestOfTheSentryBoxxxxxxxxxxxxxxxxxxx" }], sources: [{ machine: "linuxbox", path: "/home/alex/code/platform/.env", variable: "SENTRY_AUTH_TOKEN", pointer: null, stale: [] }], compare: null }),
  ],
}

// Every name this person's adoptions touch: one held in the vault and
// waiting in the conflict batch above, one waiting in two batches, one only
// in a machine's plan, and one an approved batch kept the vault's value for.
const LINUXBOX_SOURCE = { machine: "linuxbox", path: "/home/alex/code/platform/.env", variable: "ANTHROPIC_API_KEY", pointer: null, stale: [] }
export const GALLERY_ADOPT_INVENTORY: WorkspaceAdoptionInventory = {
  rows: [
    {
      slug: "anthropic-platform",
      stored: { id: "itm_anthropicplatform", kind: "api-key", home: { kind: "project", project: "prj_platform01" }, version: 7 },
      entries: [
        { from: "staged", machine: "linuxbox", adoption: "adp_9cf3mw4zr2", ref: "c002", kind: "api-key", home: { kind: "project", project: "prj_platform01" }, sources: [LINUXBOX_SOURCE], compare: "differs" },
        { from: "approved", machine: "mac-mini", adoption: "adp_3hd8sk2pq7", ref: "a003", outcome: "created", sources: [{ ...LINUXBOX_SOURCE, machine: "mac-mini", path: "/Users/alex/code/platform/.env" }] },
        { from: "plan", machine: "linuxbox", ref: "c002", kind: "api-key", home: "project", project: "platform", include: true, exists: true, storeOnly: false, sources: [LINUXBOX_SOURCE], uses: [{ project: "platform", env: "dev", variable: "ANTHROPIC_API_KEY", field: "key" }] },
      ],
    },
    {
      slug: "github-pat-gh",
      stored: null,
      entries: [
        { from: "staged", machine: "mac-mini", adoption: "adp_7kq2mw4zx1", ref: "a009", kind: "api-key", home: { kind: "member", member: "mem_alex0001" }, sources: [{ machine: "mac-mini", path: "/Users/alex/.config/gh/hosts.yml", variable: null, pointer: "/github.com/oauth_token", stale: [] }], compare: null },
        { from: "staged", machine: "linuxbox", adoption: "adp_9cf3mw4zr2", ref: "c003", kind: "api-key", home: { kind: "member", member: "mem_alex0001" }, sources: [{ machine: "linuxbox", path: "/home/alex/.config/gh/hosts.yml", variable: null, pointer: "/github.com/oauth_token", stale: [] }], compare: "differs" },
      ],
    },
    {
      slug: "sentry-platform",
      stored: null,
      entries: [{ from: "plan", machine: "linuxbox", ref: "c006", kind: "api-key", home: "workspace", project: null, include: false, exists: false, storeOnly: true, sources: [{ ...LINUXBOX_SOURCE, variable: "SENTRY_AUTH_TOKEN" }], uses: [] }],
    },
    {
      slug: "stripe-test",
      stored: { id: "itm_stripetest", kind: "api-key", home: { kind: "workspace" }, version: 2 },
      entries: [{ from: "approved", machine: "mac-mini", adoption: "adp_3hd8sk2pq7", ref: "a004", outcome: "mapped", sources: [{ machine: "mac-mini", path: "/Users/alex/.config/stripe/config.toml", variable: null, pointer: "/test_mode_api_key", stale: [] }] }],
    },
  ],
  indexes: [{ device: "dev_linuxbox00001", machine: "linuxbox", indexedAt: ISO(-3_600_000), expiresAt: ISO(30 * 86_400_000 - 3_600_000) }],
}

// ---------------------------------------------------------------- Review together

// One machine's asks on one Cloudflare token, as approvals.group places
// them for an admin: two routine creates of the same shape (the older one
// says a newer one follows), a routine read, a delete to look at first, a
// protected credential's use, one carrying a warning, a run behind a stop
// view, one the viewer may only deny, a private stop row, and one settled.
const CF = "https://api.cloudflare.com/client/v4/accounts/abc"
function reviewRow(id: string, title: string, method: string, url: string, extra: Partial<Extract<ApprovalGroupRow, { view: "detail" }>> = {}, approval: Partial<ApprovalGroupDetail> = {}): ApprovalGroupRow {
  const base = galleryRunApproval(true, ["Tom"])
  if (base.view !== "detail") throw new Error("detail")
  const detail: ApprovalGroupDetail = {
    ...base.approval,
    approval: id,
    title,
    bindingCode: `${id.slice(4, 7).toUpperCase()}-${id.slice(7, 10).toUpperCase()}`,
    item: { slug: "cloudflare-api-token", account: null, provider: "cloudflare" },
    details: [{ label: "Account", value: "abc" }],
    request: { ...base.approval.request, method, url, contentType: method === "GET" || method === "DELETE" ? null : "application/json", body: method === "GET" || method === "DELETE" ? null : JSON.stringify({ name: title.toLowerCase().replaceAll(" ", "-") }) },
    constraints: { uses: 1, ttlSeconds: 600 },
    expiresAt: ISO(12 * 60_000),
    ...approval,
  }
  return { view: "detail", approval: detail, binding: base.binding ?? { snapshotDigest: "", presentationDigest: "" }, batch: "routine", ownPage: null, floor: [], createdAt: ISO(-20 * 60_000), replacedBy: null, protected: false, newerSameShape: null, ...extra }
}
type ApprovalGroupDetail = Extract<ApprovalGroupRow, { view: "detail" }>["approval"]
const REVIEW_STOP = (id: string, batch: "deny-only" | "own-page", status: "pending" | "approved" = "pending"): ApprovalGroupRow => ({ view: "stop", stop: { ...STOP, id, status } as Extract<ApprovalGroupRow, { view: "stop" }>["stop"], batch })
export const GALLERY_REVIEW_GROUP: ApprovalGroupView = {
  group: "grp_7kq2mw4zx1aaaaaaaaaaaa",
  kind: "machine",
  workspace: GALLERY_WORKSPACE,
  machine: { device: "dev_macmini1", name: "mac-mini", owner: { kind: "member", member: "mem_alex0001", name: "Alex" }, workload: null },
  item: { slug: "cloudflare-api-token" },
  reason: null,
  code: "K7QM3P",
  rows: [
    reviewRow("apr_d1old0001", "Create D1 database preview", "POST", `${CF}/d1/database`, { newerSameShape: "apr_d1new0002" }),
    reviewRow("apr_kvlist003", "List KV namespaces", "GET", `${CF}/storage/kv/namespaces`),
    reviewRow("apr_d1new0002", "Create D1 database preview-2", "POST", `${CF}/d1/database`),
    reviewRow("apr_dnsdel004", "Delete DNS record staging", "DELETE", "https://api.cloudflare.com/client/v4/zones/z1/dns_records/r9", { batch: "floor", floor: ["destructive"] }),
    reviewRow("apr_protkv005", "Write the production KV value", "PUT", `${CF}/storage/kv/namespaces/prod/values/flag`, { batch: "floor", protected: true }),
    reviewRow("apr_warned006", "Create worker route", "POST", "https://api.cloudflare.com/client/v4/zones/z1/workers/routes", { batch: "own-page", ownPage: "warning" }, { warnings: ["The request body names a host outside the credential's zone."] }),
    REVIEW_STOP("apr_runstop07", "own-page"),
    reviewRow("apr_denyonly8", "Purge the cache", "POST", "https://api.cloudflare.com/client/v4/zones/z1/purge_cache", { batch: "deny-only" }, { eligibility: { canApprove: false, canDeny: true, canReadAskDetail: true, deciders: ["Alex"], reason: "Not an eligible approver" } }),
    REVIEW_STOP("apr_privst009", "deny-only"),
    reviewRow("apr_settled10", "List Workers scripts", "GET", `${CF}/workers/scripts`, {}, { status: "approved", decidedBy: { name: "Tom", self: true } }),
  ],
}
// Every ask of the group decided in the last hour.
const REVIEW_SETTLED: ApprovalGroupView = { ...GALLERY_REVIEW_GROUP, rows: GALLERY_REVIEW_GROUP.rows.slice(0, 3).map((r) => (r.view === "detail" ? { ...r, approval: { ...r.approval, status: r.approval.approval === "apr_kvlist003" ? "denied" : "approved", decidedBy: { name: "Tom", self: true } }, newerSameShape: null } : r)) }
// An agent's bundle: its reason quoted, a task, and a floor ask.
const REVIEW_BUNDLE: ApprovalGroupView = {
  ...GALLERY_REVIEW_GROUP,
  group: "bnd_5lq2mw4zl9aaaaaaaaaaaa",
  kind: "bundle",
  item: null,
  reason: "Set up the staging D1 databases for the preview deploys",
  machine: { ...GALLERY_REVIEW_GROUP.machine, workload: GALLERY_TASK },
  rows: [GALLERY_REVIEW_GROUP.rows[1]!, GALLERY_REVIEW_GROUP.rows[2]!, GALLERY_REVIEW_GROUP.rows[3]!],
}
// A machine name hiding characters and a bundle reason with an override.
const REVIEW_HOSTILE: ApprovalGroupView = { ...REVIEW_BUNDLE, group: "bnd_4hx8wq2mz6aaaaaaaaaaaa", machine: { ...REVIEW_BUNDLE.machine, name: "mac-mini\u200B" }, reason: "Set up staging \u202Eexe.pots" }
// A bundle whose only deceptive text is a private stop row's credential name.
const REVIEW_HOSTILE_STOP: ApprovalGroupView = { ...REVIEW_BUNDLE, group: "bnd_6hs2wq8mz4aaaaaaaaaaaa", rows: [...REVIEW_BUNDLE.rows, { view: "stop", stop: { ...STOP, id: "apr_hidslug11", item: { slug: "github-kim\u202Etset" } } as Extract<ApprovalGroupRow, { view: "stop" }>["stop"], batch: "deny-only" }] }
// Only asks decided on their own page are waiting: no bar.
const REVIEW_OWN_PAGE_ONLY: ApprovalGroupView = { ...GALLERY_REVIEW_GROUP, rows: [GALLERY_REVIEW_GROUP.rows[5]!, GALLERY_REVIEW_GROUP.rows[6]!] }
// A group made before group codes: only the tick over the rows' own codes.
const REVIEW_SEPARATE_CODES: ApprovalGroupView = { ...GALLERY_REVIEW_GROUP, group: "grp_3sc8wq2mz5aaaaaaaaaaaa", code: null, rows: GALLERY_REVIEW_GROUP.rows.slice(0, 3) }
// Only asks the viewer may deny are waiting: Deny ticked, and no Approve.
const REVIEW_DENY_ONLY: ApprovalGroupView = { ...GALLERY_REVIEW_GROUP, rows: [GALLERY_REVIEW_GROUP.rows[7]!, GALLERY_REVIEW_GROUP.rows[8]!] }

// A single ask a newer one from the same machine replaced.
export function gallerySupersededApproval(): WorkspaceApprovalView {
  const view = galleryEmailApproval()
  return view.view === "detail" ? { ...view, approval: { ...view.approval, approval: "apr_3kq8vx2mz4", status: "superseded", replacedBy: "apr_9tq4mw2zx8" } } : view
}

export const WORKSPACE_ASK_PAGE_KINDS = ["ws-approval", "ws-review", "ws-intake", "ws-connect", "ws-policy", "ws-rule-proposal", "ws-area-proposal", "ws-adoption", "ws-adopt-inventory", "workspace-enrol", "enrol-closed"] as const

const GROUP = "Workspace projects and credentials"

export function workspaceAsksGallery(): ShellGalleryEntry[] {
  const owner = galleryShell(VIEWERS.owner)
  const ownerProject = galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)
  const workspaceItems = GALLERY_ITEMS.filter((i) => i.home.kind !== "member" || i.home.member === VIEWERS.owner.member)
  const machines = { viewer: viewer("owner"), projects: PEOPLE_PROJECTS, now: NOW }
  const tomMachines = { viewer: viewer("member", "mem_tom01"), projects: PEOPLE_PROJECTS, now: NOW }
  const guestEnrol: WorkspaceEnrolView = { ...GUEST_ENROL, state: "pending_admission", owner: { kind: "member", member: "mem_guest01", name: "Gina (contractor)" }, actions: [] }
  return [
    { id: "ws-approval-decider", group: GROUP, title: "Protected run approval, eligible decider", note: "The run's credentials with Belongs to, four-eyes explained, the binding the page recomputes, uses and time up to what was asked.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryRunApproval(true, ["Tom"]), project: ownerProject, items: workspaceItems, now: NOW }) },
    { id: "ws-approval-changed", group: GROUP, title: "Protected run approval that changed while the page was built", note: "The run's credential list is read from the project as it is now, so when the ask moved on the page says so and offers no decision.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryStaleRunApproval(), project: ownerProject, items: workspaceItems, changedSinceRequested: true }) },
    { id: "ws-approval-owner-four-eyes", group: GROUP, title: "Protected run approval, the machine's owner under four-eyes", note: "The owner reads it and may deny, but cannot approve.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryRunApproval(false, ["Tom"]), project: ownerProject, items: workspaceItems, now: NOW }) },
    { id: "ws-approval-request", group: GROUP, title: "Approval for an exact request, with headers and a warning", note: "Every forwarded header and its digest, content type, the vault's warning and the email laid out, as signed.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryEmailApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-mandate-capped", group: GROUP, title: "Approval a mandate's cap sent back", note: "The machine's mandate would have let this email through, but today's 50 sends are used: one line says so, and the ask is decided as any other.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryEmailApproval(), project: null, items: [], now: NOW, capped: { mandate: "mdt_tomlaptop0000000001", capped: [{ class: "send", cap: 50 }] } }) },
    { id: "ws-approval-mandate-cover", group: GROUP, title: "Approval a mandate could have let through", note: "The machine has no mandate: its owner is offered to let it carry on with requests like this, which opens the sign page on send.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryEmailApproval(), project: null, items: [], now: NOW, cover: { device: { id: "dev_tomlaptop01", name: "tom-laptop" }, classes: ["send"], state: "sign", mandate: null } }) },
    { id: "ws-approval-deceptive", group: GROUP, title: "Approval, deceptive characters", note: "Hidden direction and zero-width characters in the title, a header and the body, a control character in the session label: the warning card first, each marked where it sits, Decline filled and Approve quiet, still behind the code and the page check.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryDeceptiveApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-rule", group: GROUP, title: "Approval the vault offers to allow from now on", note: "Approve once beside Approve and allow this from now on; the panel names the credential, the request, the path to choose (the exact one first), the machine, 7 days by default, what still asks and what ends it sooner.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryRuleApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-rule-cosign", group: GROUP, title: "Allow from now on, a manager must co-sign", note: "A task on the machine asked through a GraphQL mutation; the owner does not manage the credential's home, so the second button asks a manager of it to allow it from now on.", page: workspaceApprovalPage(galleryShell(VIEWERS.manager), { viewer: VIEWERS.manager, view: galleryCosignApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-area", group: GROUP, title: "Approval the vault offers to let the agent carry on", note: "A D1 database create: Approve once, Approve and allow this from now on, and Approve, and let this agent carry on with D1 databases for 1 hour; the panel ticks D1 databases among Cloudflare's reviewed areas, each with its words, 1 hour and 50 requests chosen, and what still asks.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryAreaApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-area-cosign", group: GROUP, title: "Let the agent carry on, a manager must co-sign", note: "Kim does not manage the credential's home: the third button approves once and asks a manager to let it carry on, and the panel says a manager must co-sign.", page: workspaceApprovalPage(galleryShell(VIEWERS.manager), { viewer: VIEWERS.manager, view: galleryAreaCosignApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-area-refused", group: GROUP, title: "Approval that cannot start a task grant", note: "A mail send: one muted line says it cannot be allowed from now on, another that it is not routine building, and only Approve once is offered.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryRefusedAreaApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-rule-refused", group: GROUP, title: "Approval that asks every time", note: "A mail send cannot be allowed from now on: one muted line says why, and only Approve once is offered.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryRefusedRuleApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-fill-signin", group: GROUP, title: "Approval to type a password into its sign-in page", note: "A task asks to type the password into github.com: the page is the origin only, and the card says the same approval covers the one-time code, how many fields and for how long, and that the username needs none. No remember choice.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryFillSignInApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-fill-type-into", group: GROUP, title: "Approval to type a key into another service's page", note: "Typing a key into dash.cloudflare.com puts it into another service: the warning card first, Decline filled and Approve quiet, typed once, asked every time, with no remember choice.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryFillTypeIntoApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-approval-stop", group: GROUP, title: "Stop view", note: "An owner may stop a private ask: which machine, whose, the credential's name, Stop. Nothing about the request.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: STOP, project: null, items: [] }) },
    { id: "ws-approval-stop-hostile", group: GROUP, title: "Stop view, hostile machine name", note: "The machine's name marked where it hides characters; the one action, Stop, filled danger.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: HOSTILE_STOP, project: null, items: [] }) },
    { id: "ws-approval-superseded", group: GROUP, title: "Approval replaced by a newer ask", note: "The machine asked again to the same place: the page names the newer ask, linked, and offers no decision.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: gallerySupersededApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-review", group: GROUP, title: "Review together", note: "Ready rows ticked, the older of two same-shape creates unticked with its note; Look at these first unticked with the request open and its floor mark, the protected credential's use marked Protected; Decide on its own page with links and reasons; You can only deny these; one settled row greyed; the group code tick, the separate-codes tick beside it, Deny ticked and Approve with passkey.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: GALLERY_REVIEW_GROUP.group, view: GALLERY_REVIEW_GROUP, now: NOW }) },
    { id: "ws-review-separate-codes", group: GROUP, title: "Review together, a group with no group code", note: "A group made before group codes: only the tick over the rows' own codes.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_SEPARATE_CODES.group, view: REVIEW_SEPARATE_CODES, now: NOW }) },
    { id: "ws-review-bundle", group: GROUP, title: "Review together, an agent's bundle", note: "Requests to approve together, the agent's reason quoted as its own words and the task named as the machine named it.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_BUNDLE.group, view: REVIEW_BUNDLE, now: NOW }) },
    { id: "ws-review-hostile", group: GROUP, title: "Review together, deceptive machine name and reason", note: "The warning card first, the hidden characters marked where they sit, Deny ticked filled and Approve quiet.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_HOSTILE.group, view: REVIEW_HOSTILE, now: NOW }) },
    { id: "ws-review-hostile-stop", group: GROUP, title: "Review together, deceptive private credential name", note: "A stop row's credential name hides characters: the warning card first, as on the stop view, Deny ticked filled and Approve quiet.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_HOSTILE_STOP.group, view: REVIEW_HOSTILE_STOP, now: NOW }) },
    { id: "ws-review-held", group: GROUP, title: "Review together while the account cools off", note: "Approving is refused until it ends, said before anything is ticked; denying still works.", page: workspaceReviewPage({ ...galleryShell({ role: "admin", member: "mem_tom00001" }), accountHeld: true }, { viewer: { role: "admin", member: "mem_tom00001" }, group: GALLERY_REVIEW_GROUP.group, view: GALLERY_REVIEW_GROUP, now: NOW }) },
    { id: "ws-review-own-page", group: GROUP, title: "Review together, only asks for their own pages", note: "Nothing here can be decided together: each row links to its own page, and there is no bar.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_OWN_PAGE_ONLY.group, view: REVIEW_OWN_PAGE_ONLY, now: NOW }) },
    { id: "ws-review-deny-only", group: GROUP, title: "Review together, only asks you may deny", note: "Nothing here can be approved by this person: Deny ticked, and no Approve button.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_DENY_ONLY.group, view: REVIEW_DENY_ONLY, now: NOW }) },
    { id: "ws-review-settled", group: GROUP, title: "Review together, everything decided", note: "Nothing waiting here, how many were decided in the last hour, each greyed with its status.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: REVIEW_SETTLED.group, view: REVIEW_SETTLED, now: NOW }) },
    { id: "ws-review-empty", group: GROUP, title: "Review together, nothing to show", note: "A group with nothing this person may see reads as an empty one, with the way back to Needs you.", page: workspaceReviewPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, group: "grp_AAAAAAAAAAAAAAAAAAAAAA", view: null, now: NOW }) },
    { id: "ws-approval-push", group: GROUP, title: "Push into a known repository", note: "Put a credential into a GitHub Actions secret: where with its owner as GitHub said, the store, the name already there, the value's prefix and fingerprint, what carries it, who can read it there, and the agent's reason as its own words. The vault's warning that it cannot be taken back makes every push warned. Decline and Approve with passkey only: no uses, duration or from now on. The exact request shows PUSH, its URL, the body's hash and what the hash covers.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: GALLERY_PUSH_KNOWN, project: null, items: [], now: NOW, pushedValue: GALLERY_PUSHED_VALUE }) },
    { id: "ws-approval-push-new", group: GROUP, title: "Push to a new destination", note: "This workspace has neither bound the repository nor pushed to its owner: the New destination pill beside where, and the vault's warning first. The value's facts are left out when the page could not read them.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: GALLERY_PUSH_NEW, project: null, items: [], now: NOW }) },
    { id: "ws-approval-push-fork", group: GROUP, title: "Push into a public fork", note: "GitHub says the repository is a public fork owned by a user: New destination, Fork of and Public repository pills beside where; Mehen could not check whether the name exists.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: GALLERY_PUSH_FORK, project: null, items: [], now: NOW, pushedValue: GALLERY_PUSHED_VALUE }) },
    { id: "ws-approval-push-deceptive", group: GROUP, title: "Push with a deceptive reason", note: "The agent's reason hides a direction override and a zero-width space: the page's own warning joins the vault's, and the reason is marked where it hides them, under The agent says.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: GALLERY_PUSH_DECEPTIVE, project: null, items: [], now: NOW, pushedValue: GALLERY_PUSHED_VALUE }) },
    { id: "ws-approval-push-done", group: GROUP, title: "Push, done", note: "Approved and sent: the outcome as GitHub gave it, Put into GitHub: replaced.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryPushApproval({ ...PUSH_KNOWN, id: "apr_2dn6kq8vz3", status: "used", state: "done", outcome: "replaced" }), project: null, items: [], now: NOW, pushedValue: GALLERY_PUSHED_VALUE }) },
    { id: "ws-approval-push-refused", group: GROUP, title: "Push, refused by GitHub", note: "Approved, and GitHub refused the write: its status in the outcome line.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryPushApproval({ ...PUSH_KNOWN, id: "apr_6rf3wq9kd2", status: "used", state: "failed", providerStatus: 403 }), project: null, items: [], now: NOW }) },
    { id: "ws-approval-push-not-sent", group: GROUP, title: "Push, not sent", note: "Approved, and something changed before Mehen sent it: Not sent: nothing was sent.", page: workspaceApprovalPage(owner, { viewer: VIEWERS.owner, view: galleryPushApproval({ ...PUSH_KNOWN, id: "apr_4ns7mz2qx8", status: "used", state: "not_sent" }), project: null, items: [], now: NOW }) },
    { id: "ws-intake", group: GROUP, title: "Add a credential, choose where it belongs", note: "The agent proposed This project; the filler may choose another home they may create in.", page: workspaceIntakePage(owner, INTAKE, [ownerProject], NOW) },
    { id: "ws-approval-workload", group: GROUP, title: "Approval asked by a task's workload", note: "The machine line as ever, and under it, quieter, the task's label marked as the machine's words; Who asked lists the task too.", page: workspaceApprovalPage(galleryShell({ role: "admin", member: "mem_tom00001" }), { viewer: { role: "admin", member: "mem_tom00001" }, view: galleryWorkloadApproval(), project: null, items: [], now: NOW }) },
    { id: "ws-intake-fill", group: GROUP, title: "Add a website login where typing into web pages is on", note: "How may agents use it? Type it into the sign-in page, or Not at all (ticked). The sign-in page follows the address typed; one that is not https says only https pages can be filled.", page: workspaceIntakePage(owner, GALLERY_FILL_INTAKE, [ownerProject], NOW, true) },
    { id: "ws-intake-workload", group: GROUP, title: "Intake asked by a task's workload", note: "Task: its label, as the machine named it, under the ask.", page: workspaceIntakePage(owner, { ...INTAKE, intake: "int_6wk3mz8qv2", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null, workload: GALLERY_TASK } }, [ownerProject], NOW) },
    { id: "ws-connect-workload", group: GROUP, title: "Connect asked by a task's workload", note: "Task: its label, as the machine named it, under the ask.", page: workspaceConnectPage(owner, { ...CONNECT, connect: "con_6wk3mz8qv2", requestedBy: { device: "dev_macmini1", deviceName: "mac-mini", session: null, workload: GALLERY_TASK } }, [ownerProject], NOW) },
    { id: "ws-intake-deceptive", group: GROUP, title: "Intake, deceptive reason", note: "A reason with a direction override and a machine name with a zero-width space: the warning card first, Stop this request filled, Seal and save quiet.", page: workspaceIntakePage(owner, DECEPTIVE_INTAKE, [ownerProject], NOW) },
    { id: "ws-intake-held", group: GROUP, title: "Intake while the account cools off", note: "After a recovery or another security change: saving is refused until it ends, said before anything is filled in.", page: workspaceIntakePage({ ...owner, accountHeld: true }, INTAKE, [ownerProject], NOW) },
    { id: "ws-intake-lease-only", group: GROUP, title: "Add a credential with no host", note: "Asked for without a host or an injection: it reads No host, only delivered into a process with mehen run, with no destination to accept.", page: workspaceIntakePage(owner, LEASE_ONLY_INTAKE, [ownerProject], NOW) },
    { id: "ws-connect", group: GROUP, title: "Connect an account, choose where it belongs", note: "Starting the sign-in is signed with a passkey, home included.", page: workspaceConnectPage(owner, CONNECT, [ownerProject], NOW) },
    { id: "ws-connect-deceptive", group: GROUP, title: "Connect, deceptive account to expect", note: "The account to sign in as hides a zero-width space: the warning card first, Stop this request filled, Continue quiet.", page: workspaceConnectPage(owner, DECEPTIVE_CONNECT, [ownerProject], NOW) },
    { id: "ws-adoption", group: GROUP, title: "Adopt credentials a machine found", note: "Rows grouped by repository and folder; the custom destination, the stale source and the row whose home is refused start unticked; one passkey over the whole batch.", page: workspaceAdoptionPage(owner, GALLERY_ADOPTION, [ownerProject], NOW) },
    { id: "ws-adoption-deceptive", group: GROUP, title: "Adopt credentials, deceptive host", note: "A custom host hiding a zero-width space: the warning card first, Cancel batch filled, Approve quiet.", page: workspaceAdoptionPage(owner, DECEPTIVE_ADOPTION, [ownerProject], NOW) },
    { id: "ws-adoption-lease-only", group: GROUP, title: "Adopt .env secrets with no host", note: "A JWT secret and a database URL no template covers read No host, only delivered into a process with mehen run; a signing secret reads stored only until a human sets its ceiling to lease, and an SSH key stored only. Every row starts ticked, since there is no destination to check.", page: workspaceAdoptionPage(owner, LEASE_ONLY_ADOPTION, [ownerProject], NOW) },
    { id: "ws-adoption-approved", group: GROUP, title: "Adoption batch, approved", note: "Once approved, the page says the credentials are stored and the machine finishes with mehen adopt apply.", page: workspaceAdoptionPage(owner, { ...GALLERY_ADOPTION, status: "approved" }, [ownerProject], NOW) },
    { id: "ws-adoption-conflict", group: GROUP, title: "Adopt credentials that meet names in the vault", note: "Each row whose name is taken shows what holds it, the result per field in words and what else uses it; Keep the vault's value, Replace it with this value or Keep both, this one under another name, with the variables a kept copy may take over; a row whose holder is gone or hidden offers only Keep both; rows still to decide hold Approve back, and Keep open 3 more days, or what is left, until the longest the batch may stay open.", page: workspaceAdoptionPage(owner, GALLERY_CONFLICT_ADOPTION, [ownerProject], NOW) },
    { id: "ws-adopt-inventory", group: GROUP, title: "Adopted credentials", note: "Every name your machines' adoptions touch: what the vault holds under it, the batches waiting or done, each machine's plan, and when each plan was sent and is kept until.", page: workspaceAdoptInventoryPage(owner, GALLERY_ADOPT_INVENTORY, [ownerProject]) },
    { id: "ws-adopt-inventory-empty", group: GROUP, title: "Adopted credentials, none yet", note: "No machine has sent a plan or a batch: one line says how to start.", page: workspaceAdoptInventoryPage(owner, { rows: [], indexes: [] }, [ownerProject]) },
    { id: "ws-rule-proposal", group: GROUP, title: "Rule proposal from a machine", note: "The agent's reason quoted as its own words; the panel offers the exact path or the proposed * and 1, 7 or 30 days, starting at what was proposed; Approve behind the code and the page check, beside Deny.", page: workspaceRuleProposalPage(owner, GALLERY_RULE_PROPOSAL, GALLERY_RULE_ITEM, NOW) },
    { id: "ws-rule-proposal-cosign", group: GROUP, title: "Rule proposal waiting for a co-signer", note: "Kim approved it as the machine's owner; a manager of the credential's home co-signs, with no code to tick.", page: workspaceRuleProposalPage(galleryShell(VIEWERS.manager), GALLERY_COSIGN_PROPOSAL, { provider: "linear", account: "kim@northwind.example" }, NOW) },
    { id: "ws-rule-proposal-extend", group: GROUP, title: "Extending a rule, waiting for a co-signer", note: "Extend the rule for up to the new duration: only the rule's own path, and the new duration.", page: workspaceRuleProposalPage(owner, GALLERY_EXTEND_PROPOSAL, GALLERY_RULE_ITEM, NOW) },
    { id: "ws-rule-proposal-read-only", group: GROUP, title: "Rule proposal, read only", note: "Someone who may read it but neither approve nor deny: the terms as proposed, no choices and no bar.", page: workspaceRuleProposalPage(owner, GALLERY_READ_ONLY_PROPOSAL, GALLERY_RULE_ITEM, NOW) },
    { id: "ws-area-proposal-cosign", group: GROUP, title: "Task grant waiting for a co-signer", note: "Kim approved the request and signed a task grant; a manager of the credential's home reads the areas, how long and how many requests as signed, read only, and approves with a passkey or denies.", page: workspaceAreaProposalPage(galleryShell(VIEWERS.manager), GALLERY_AREA_PROPOSAL.proposal, { provider: "cloudflare", account: null }, NOW) },
    { id: "ws-area-proposal-approved", group: GROUP, title: "Task grant, co-signed", note: "Settled: the grant the vault made, until its end and up to its uses, and no bar.", page: workspaceAreaProposalPage(galleryShell(VIEWERS.manager), GALLERY_AREA_PROPOSAL_APPROVED.proposal, { provider: "cloudflare", account: null }, NOW) },
    { id: "ws-policy-stop", group: GROUP, title: "Policy proposal, stop view", note: "Someone who may only decline a private proposal: the machine, whose, the credential's name, Stop.", page: workspacePolicyPage(owner, POLICY_STOP) },
    { id: "enrol-accept", group: "Machines", title: "A machine to accept as your own", note: "Start time, place and client beside your place; the typed hidden group; the private tick on by default for a member's own machine; Accept as my own machine with its warning.", page: enrolmentPage(peopleShell("member", { member: "mem_tom01" }), PEOPLE_ENROL, tomMachines) },
    { id: "enrol-accept-guest", group: "Machines", title: "A guest's machine to accept as their own", note: "The private tick off by default for a guest's machine, with who turns it on later.", page: enrolmentPage(peopleShell("guest", { member: "mem_guest01" }), GUEST_ENROL, { viewer: viewer("guest", "mem_guest01"), projects: null, now: NOW }) },
    { id: "enrol-scoped", group: "Machines", title: "A machine that asked for less than usual", note: "What it asked for, in plain words, before what it may use; no private credentials tick, since it asked for none; acting only through short-lived workloads.", page: enrolmentPage(peopleShell("member", { member: "mem_tom01" }), SCOPED_ENROL, tomMachines) },
    { id: "enrol-by-id", group: "Machines", title: "Enrolment page by id", note: "Opened from Needs you by the enrolment's id: the same hidden group and check, and no clear code on the page.", page: enrolmentPage(peopleShell("member", { member: "mem_tom01" }), PEOPLE_ENROL_BY_ID, tomMachines) },
    { id: "enrol-hostile", group: "Machines", title: "Enrolment, hostile machine name", note: "A machine name with a direction override and a host with a control character: the warning card first, Reject filled, Accept quiet and still behind the typed group.", page: enrolmentPage(peopleShell("member", { member: "mem_tom01" }), HOSTILE_ENROL, tomMachines) },
    { id: "enrol-lapsed", group: "Machines", title: "Enrolment link lapsed", note: "Past its hour, inside its day: the three groups, how the agent brings the same link back, and Reject for an owner.", page: enrolmentPage(peopleShell("owner"), LAPSED_ENROL, machines) },
    { id: "enrol-superseded", group: "Machines", title: "Enrolment expired, newer link waiting", note: "The same machine asked again: the button to its newer link, which this viewer may open.", page: enrolmentPage(peopleShell("member", { member: "mem_tom01" }), SUPERSEDED_ENROL, tomMachines) },
    { id: "enrol-admit", group: "Machines", title: "A guest's machine to admit", note: "Admit Gina's machine, never accept it on her behalf.", page: enrolmentPage(peopleShell("owner"), { ...guestEnrol, actions: ["admit", "reject"] }, machines) },
    { id: "enrol-guest-waiting", group: "Machines", title: "A guest waiting for admission", note: "Who can admit it, by role, with the link to copy; no directory of people.", page: enrolmentPage(peopleShell("guest", { member: "mem_guest01" }), guestEnrol, { viewer: viewer("guest", "mem_guest01"), projects: null, now: NOW }) },
    { id: "enrol-team-admit", group: "Machines", title: "A team's machine to admit", note: "The whole-workspace credentials the team's projects let it use, named before the passkey.", page: enrolmentPage(peopleShell("owner"), TEAM_ENROL, { ...machines, delegation: ["openai-shared"] }) },
    { id: "enrol-team-unknown", group: "Machines", title: "A team's machine, reach unreadable", note: "When what the team's projects delegate cannot be read, there is no admission to sign.", page: enrolmentPage(peopleShell("owner"), TEAM_ENROL, { ...machines, delegation: null }) },
  ]
}
