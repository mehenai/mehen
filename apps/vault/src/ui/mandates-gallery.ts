// The mandate pages' gallery states (pages/mandates.ts): the list, one
// mandate in each state and as each reader sees it, a credential the
// reader cannot see, the sign page fresh, from a proposal, for every
// credential, renewing, closed by a later mandate and refused, and the machine page's card for its
// owner, waiting for its owner and for an admin. The home's strip is in shell-gallery.ts and the
// capped ask in workspace-asks-gallery.ts.

import { MANDATE_CAP_DEFAULTS, type MandateCandidates, type MandateOpenProposal, type MandateProposalView, type MandateReceiptsPage, type MandateView } from "@mehen/protocol/mandate-terms"
import { machinePage } from "./pages/machines.ts"
import { type MandateSignData, mandateSignDefaults, mandatePage, mandateSignPage, mandatesPage } from "./pages/mandates.ts"
import { PEOPLE_DEVICE, PEOPLE_PROJECTS, peopleShell } from "./people-gallery.ts"
import { GALLERY_NOW, type ShellGalleryEntry } from "./shell-gallery.ts"
import { VIEWERS, galleryShell } from "./workspace-projects-gallery.ts"
import type { Viewer } from "./workspace-rights.ts"

const GROUP = "Carry on without asking"
const MIN = 60_000
const DAY = 86_400_000
const iso = (offset: number) => new Date(GALLERY_NOW + offset).toISOString()

// Tom's laptop, which Tom signed for: he reads it as its signer, Alex (an
// owner) as someone who may pause and stop it, and the machine's page as
// either of them.
const TOM: Viewer = { role: "member", member: "mem_tom01" }
const ALEX: Viewer = VIEWERS.owner

export const GALLERY_MANDATE: MandateView = {
  id: "mdt_tomlaptop0000000001",
  device: { id: PEOPLE_DEVICE.device, name: PEOPLE_DEVICE.name },
  signer: { name: "Tom Barker", self: true },
  state: "active",
  rev: 2,
  signerCurrent: true,
  items: ["github-tom", "slack-platform"],
  hiddenItems: 0,
  classes: ["change", "read", "send"],
  caps: { read: 5000, change: 2000, send: 50, delete: 0 },
  today: { read: 412, change: 37, send: 12, delete: 0 },
  ttlDays: 30,
  schedule: { tz: "Europe/London", windows: [{ days: [1, 2, 3, 4, 5], from: "08:00", to: "19:00" }] },
  note: "Triage issues and post the daily build summary",
  createdAt: iso(-12 * DAY),
  expiresAt: iso(18 * DAY),
  endedReason: null,
}
const forAlex = (m: MandateView): MandateView => ({ ...m, signer: { name: m.signer.name, self: false } })

// Newest first: a GitHub comment, a Slack post, a request on a service
// nobody has reviewed, and one with a credential Alex may not see.
export const GALLERY_RECEIPTS: MandateReceiptsPage = {
  receipts: [
    { id: "mdu_0004", at: iso(-4 * MIN), classes: ["change"], method: "POST", credential: { slug: "github-tom", host: "api.github.com", entry: "github.issues.comment", run: "run_7Hq2Lm4Zp7Rt5Vx" } },
    { id: "mdu_0003", at: iso(-38 * MIN), classes: ["send"], method: "POST", credential: { slug: "slack-platform", host: "slack.com", entry: "slack.chat.post", run: null } },
    { id: "mdu_0002", at: iso(-95 * MIN), classes: ["read"], method: "GET", credential: { slug: "slack-platform", host: "status.internal.example", entry: "unreviewed", run: null } },
    { id: "mdu_0001", at: iso(-3 * 60 * MIN), classes: ["change"], method: "PATCH", credential: null },
  ],
  next: "1761500000000.mdu_0001",
}

// Tom's other machine, which he may sign the same terms for.
const TOM_DESK = { id: "dev_tomdesk00001", name: "tom-desk" }
const page = (viewer: Viewer, mandate: MandateView, receipts: MandateReceiptsPage | null = GALLERY_RECEIPTS) => mandatePage(galleryShell(viewer), { viewer, mandate, receipts, now: GALLERY_NOW, others: viewer.member === TOM.member ? [TOM_DESK] : [] })

const CANDIDATES: MandateCandidates = { items: [{ id: "itm_githubtom0000001", slug: "github-tom" }, { id: "itm_slackplat000001", slug: "slack-platform" }, { id: "itm_openaitom000001", slug: "openai-tom" }] }

const PROPOSAL: MandateProposalView = {
  id: "mdp_tomlaptop0000000001",
  device: { id: PEOPLE_DEVICE.device, name: PEOPLE_DEVICE.name },
  items: [CANDIDATES.items[0]!, CANDIDATES.items[1]!],
  hiddenItems: 0,
  classes: ["change", "read", "send"],
  caps: { ...MANDATE_CAP_DEFAULTS, delete: 0 },
  ttlDays: 30,
  schedule: GALLERY_MANDATE.schedule,
  note: GALLERY_MANDATE.note,
  reason: "I keep asking you to approve the same issue comments and the build summary post every morning.",
  state: "open",
  mandate: null,
  createdAt: iso(-20 * MIN),
  expiresAt: iso(7 * DAY - 20 * MIN),
}

// The proposal as a list shows it, waiting for its machine's owner.
const WAITING: MandateOpenProposal = { id: PROPOSAL.id, url: `https://vault.example/w/northwind/sign-mandate?proposal=${PROPOSAL.id}`, expiresAt: PROPOSAL.expiresAt, createdAt: PROPOSAL.createdAt, device: PROPOSAL.device, classes: PROPOSAL.classes, items: ["github-tom", "slack-platform"], hiddenItems: 0, reason: PROPOSAL.reason }

function sign(overrides: Partial<MandateSignData> = {}) {
  const viewer = overrides.viewer ?? TOM
  return mandateSignPage(peopleShell("member", { member: viewer.member }), { viewer, device: PEOPLE_DEVICE, candidates: CANDIDATES, start: mandateSignDefaults(PEOPLE_DEVICE.name), proposal: null, renews: null, replaces: null, now: GALLERY_NOW, ...overrides })
}

function machine(viewer: Viewer, mandate: MandateView | null, proposals: MandateOpenProposal[] = []) {
  const shell = viewer.member === TOM.member ? peopleShell("member", { member: TOM.member }) : peopleShell("owner")
  return machinePage(shell, PEOPLE_DEVICE, { viewer: { member: viewer.member, role: viewer.role, blocked: false }, projects: PEOPLE_PROJECTS, now: GALLERY_NOW, workloads: [], mandate, proposals })
}

export function mandatesGallery(): ShellGalleryEntry[] {
  const paused: MandateView = { ...GALLERY_MANDATE, state: "paused", rev: 3 }
  const tripped: MandateView = { ...GALLERY_MANDATE, state: "tripped", rev: 3 }
  const lapsed: MandateView = { ...GALLERY_MANDATE, signerCurrent: false }
  const ending: MandateView = { ...GALLERY_MANDATE, expiresAt: iso(2 * DAY - 3 * 60 * MIN), createdAt: iso(-28 * DAY) }
  const stopped: MandateView = { ...GALLERY_MANDATE, state: "stopped", rev: 4, endedReason: "stopped", today: { read: 0, change: 0, send: 0, delete: 0 } }
  const { signerCurrent: _current, ...ended } = GALLERY_MANDATE
  const expired: MandateView = { ...ended, state: "expired", endedReason: "expired", expiresAt: iso(-DAY), createdAt: iso(-31 * DAY), today: { read: 0, change: 0, send: 0, delete: 0 } }
  const hidden: MandateView = { ...forAlex(GALLERY_MANDATE), items: ["slack-platform"], hiddenItems: 1 }
  const unseen: MandateView = { ...forAlex(GALLERY_MANDATE), items: [], hiddenItems: 1 }
  const unseenReceipts: MandateReceiptsPage = { receipts: GALLERY_RECEIPTS.receipts.map((r) => ({ ...r, credential: null })), next: null }
  // Alex sees slack-platform only: the GitHub receipt is one he cannot see.
  const adminReceipts: MandateReceiptsPage = { ...GALLERY_RECEIPTS, receipts: GALLERY_RECEIPTS.receipts.map((r) => (r.credential?.slug === "slack-platform" ? r : { ...r, credential: null })) }
  const otherMachine: MandateView = { ...forAlex(GALLERY_MANDATE), id: "mdt_teambot0000000001", device: { id: "dev_teambot0001", name: "team-bot" }, signer: { name: "Alex Rae", self: false }, classes: ["change", "delete", "read", "send"], caps: { read: 5000, change: 2000, send: 50, delete: 20 }, items: "all" }
  return [
    { id: "ws-mandates-list", group: GROUP, title: "Carrying on without asking, the list", note: "The machines a person let carry on, with Pause all for the active ones the reader may pause: active, paused and tripped first, each with what it may do, who signed and until when; ended ones below.", page: mandatesPage(galleryShell(ALEX), { viewer: ALEX, mandates: [forAlex(GALLERY_MANDATE), { ...otherMachine, state: "tripped" }, { ...forAlex(paused), id: "mdt_kimdesk0000000001", device: { id: "dev_kimdesk01", name: "kim-desk" }, signer: { name: "Kim", self: false } }, forAlex(stopped), forAlex(expired)], proposals: [{ ...WAITING, id: "mdp_alexdesk000000001", device: { id: "dev_alexdesk01", name: "alex-desk" }, classes: ["read", "change"], reason: "Keep the release notes current while you are away." }], now: GALLERY_NOW }) },
    { id: "ws-mandates-empty", group: GROUP, title: "Carrying on without asking, none yet", note: "No machine carries on without asking: what a mandate is, in a line.", page: mandatesPage(galleryShell(ALEX), { viewer: ALEX, mandates: [], proposals: [], now: GALLERY_NOW }) },
    { id: "ws-mandate-active", group: GROUP, title: "A mandate, active, as its signer", note: "Its terms in plain words, today's counts against each cap, Pause, Sign the same for Tom's other machine, and Stop in a fold at the bottom; Went through on trust, newest first, one on a service nobody has reviewed and one with a credential nobody here may see, and Older.", page: page(TOM, GALLERY_MANDATE) },
    { id: "ws-mandate-active-admin", group: GROUP, title: "A mandate, active, as an owner who did not sign it", note: "Alex may pause or stop it but not resume or renew it; he sees one credential it names and is told of the other only that he cannot see it.", page: page(ALEX, hidden, adminReceipts) },
    { id: "ws-mandate-hidden", group: GROUP, title: "A mandate naming only a credential the reader cannot see", note: "Its one credential is a credential you cannot see, and so is every receipt: time, what it was and the method only.", page: page(ALEX, unseen, unseenReceipts) },
    { id: "ws-mandate-paused", group: GROUP, title: "A mandate, paused", note: "Everything asks again; its signer may Resume, and the vault decides whether that needs the passkey.", page: page(TOM, paused) },
    { id: "ws-mandate-tripped", group: GROUP, title: "A mandate, tripped", note: "Too many requests in a minute stopped it letting anything through; its signer resumes it with the passkey.", page: page(TOM, tripped) },
    { id: "ws-mandate-lapsed", group: GROUP, title: "A mandate whose signer no longer stands behind it", note: "Active, but it covers nothing: the page says so plainly and offers its signer Resume with the passkey.", page: page(TOM, lapsed) },
    { id: "ws-mandate-ending", group: GROUP, title: "A mandate in its last days", note: "Ends in 2 days, beside the state; its signer may Renew, which opens the sign page with these terms.", page: page(TOM, ending) },
    { id: "ws-mandate-stopped", group: GROUP, title: "A mandate, stopped", note: "Ended for good: its receipts are still here, and its signer may Sign again with these terms.", page: page(TOM, stopped) },
    { id: "ws-mandate-expired", group: GROUP, title: "A mandate that ran out yesterday", note: "Its time ran out; its signer may Sign again with these terms, however long ago it ended.", page: page(TOM, expired) },
    { id: "ws-mandate-sign", group: GROUP, title: "Letting a machine carry on, a fresh start", note: "The narrowest terms: read alone at a machine's proposal cap, the machine's credentials to tick (none yet), 30 days, no schedule and a note naming the machine; Sign with passkey waits for a credential.", page: sign() },
    { id: "ws-mandate-sign-none", group: GROUP, title: "Letting a machine carry on, no credential to tick", note: "The machine can use no credential whose home you manage yet: neither choice is ticked, and Sign with passkey waits until every credential is chosen.", page: sign({ candidates: { items: [] }, start: { ...mandateSignDefaults(PEOPLE_DEVICE.name), note: "Run the release checklist" } }) },
    { id: "ws-mandate-sign-proposal", group: GROUP, title: "Letting a machine carry on, as it proposed", note: "The machine's reason, its terms filled in to change as you like, and the summary of what you are signing: the sentence from the terms, what still asks on reviewed services, what nobody has reviewed means, and pausing.", page: sign({ proposal: PROPOSAL, start: { classes: PROPOSAL.classes, caps: PROPOSAL.caps, items: PROPOSAL.items === "all" ? "all" : PROPOSAL.items.map((i) => i.id), ttlDays: PROPOSAL.ttlDays, schedule: PROPOSAL.schedule, note: PROPOSAL.note } }) },
    { id: "ws-mandate-sign-superseded", group: GROUP, title: "A proposal a later mandate closed", note: "A mandate was signed for this machine since: the page says so and links to it; the form opens narrow, and its terms wait behind Use these terms.", page: sign({ proposal: { ...PROPOSAL, state: "expired", mandate: GALLERY_MANDATE.id }, start: { classes: PROPOSAL.classes, caps: PROPOSAL.caps, items: PROPOSAL.items === "all" ? "all" : PROPOSAL.items.map((i) => i.id), ttlDays: PROPOSAL.ttlDays, schedule: PROPOSAL.schedule, note: PROPOSAL.note } }) },
    { id: "ws-mandate-sign-all", group: GROUP, title: "Letting a machine carry on, every credential", note: "Every credential it can use whose home you manage, now and later, chosen: the summary says so, and that each counts only while you manage where it lives.", page: sign({ start: { ...mandateSignDefaults(PEOPLE_DEVICE.name), classes: ["change", "delete", "read", "send"], caps: { ...MANDATE_CAP_DEFAULTS }, items: "all", ttlDays: 90, note: "Run the release checklist" } }) },
    { id: "ws-mandate-sign-renew", group: GROUP, title: "Renewing a mandate", note: "The form opens on the narrowest terms; the old terms are shown in words with Use these terms, which fills them in, and a warning that signing replaces what the machine may do now.", page: sign({ renews: ending, replaces: ending, source: { kind: "renew", mandate: ending, start: { classes: ending.classes, caps: ending.caps, items: [CANDIDATES.items[0]!.id, CANDIDATES.items[1]!.id], ttlDays: ending.ttlDays, schedule: ending.schedule, note: ending.note } } }) },
    { id: "ws-mandate-sign-not-owner", group: GROUP, title: "Letting someone else's machine carry on", note: "Only its owner can, so the page says so and offers no form.", page: sign({ viewer: ALEX, candidates: null }) },
    { id: "machine-mandate-trust", group: GROUP, title: "Your machine, Carry on without asking", note: "No mandate yet: what one is, and Trust this machine, which opens the sign page.", page: machine(TOM, null) },
    { id: "machine-mandate-waiting", group: GROUP, title: "Your machine, waiting for you", note: "It proposed a mandate: Waiting for you, with what it asks for and its reason, linking to the sign page; Trust this machine below.", page: machine(TOM, null, [WAITING]) },
    { id: "machine-mandate-active", group: GROUP, title: "Your machine, carrying on without asking", note: "Its mandate's state, what it may do, who signed it, when it ends and today's counts, with Open the mandate, Pause and Stop.", page: machine(TOM, GALLERY_MANDATE) },
    { id: "machine-mandate-paused", group: GROUP, title: "Your machine, its mandate paused", note: "Resume on the card itself; the line under it says No passkey needed once the vault plans none for this press.", page: machine(TOM, paused) },
    { id: "machine-mandate-admin", group: GROUP, title: "Someone's machine, carrying on without asking, as an owner", note: "Alex may pause or stop Tom's machine's mandate; he is never offered to trust a machine that is not his.", page: machine(ALEX, forAlex(GALLERY_MANDATE)) },
  ]
}
