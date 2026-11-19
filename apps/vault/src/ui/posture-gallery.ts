// The How careful card's gallery states (posture-card.ts) on a Cloudflare
// API token's page: at ask, opening on Custom because a standing rule is
// live, letting routine building through on every eligible machine,
// trusting one named machine, a catalogue that grew since it was saved, a
// credential with no reviewed catalogue, a restricted account that may
// only ask, and a page that also draws In web pages above it.

import type { PostureEligibleMachine, WorkspaceItemPosture } from "@mehen/protocol"
import { getTemplate } from "@mehen/protocol/templates"
import type { WorkspaceItemSummary } from "@mehen/protocol/workspace"
import { type HumanItemDescription, workspaceCredentialPage } from "./pages/workspace-credentials.ts"
import { galleryRule } from "./policy-rules-gallery.ts"
import { GALLERY_NOW, type ShellGalleryEntry } from "./shell-gallery.ts"
import { GALLERY_ITEMS, VIEWERS, description, galleryShell } from "./workspace-projects-gallery.ts"
import type { Viewer } from "./workspace-rights.ts"

const GROUP = "How careful"
const at = (minutes: number) => new Date(GALLERY_NOW + minutes * 60_000).toISOString()

// The workspace's Cloudflare API token, with the template's hosts and
// policy, so its own rules read in the template's words.
const CLOUDFLARE_TEMPLATE = getTemplate("cloudflare-api-token")!
export const POSTURE_TOKEN: HumanItemDescription = {
  ...description({ ...(GALLERY_ITEMS[0] as WorkspaceItemSummary), slug: "cloudflare-prod", provider: "cloudflare-api-token", hosts: ["api.cloudflare.com"] }),
  policy: CLOUDFLARE_TEMPLATE.policy,
}
// An OpenAI key: no reviewed catalogue, so only Ask and Custom.
const OPENAI = description(GALLERY_ITEMS[0] as WorkspaceItemSummary)

// The machines the vault says this person may tick, each with the levels
// that would cover it now: Alex manages the token, Tom does not.
export const POSTURE_ELIGIBLE: PostureEligibleMachine[] = [{ device: "dev_alexmbp0001", name: "alex-mbp", levels: ["routine", "trust"] }, { device: "dev_tomlaptop01", name: "tom-laptop", levels: ["routine"] }]

// A posture as the person's description carries it: none ever set (rev 0)
// reads as ask with the credential's current catalogue.
const CATALOGUE = { template: "cloudflare-api-token", version: 1, current: 1 }
export const POSTURE_ASK: WorkspaceItemPosture = { level: "ask", machines: null, catalogue: CATALOGUE, setBy: null, setAt: null, rev: 0, eligible: POSTURE_ELIGIBLE }
const ROUTINE: WorkspaceItemPosture = { level: "routine", machines: null, catalogue: CATALOGUE, setBy: "Alex", setAt: at(-3 * 24 * 60), rev: 1, eligible: POSTURE_ELIGIBLE }
export const POSTURE_TRUST_NAMED: WorkspaceItemPosture = { level: "trust", machines: [{ id: "dev_alexmbp0001", name: "alex-mbp" }], catalogue: CATALOGUE, setBy: "Alex", setAt: at(-50), rev: 2, eligible: POSTURE_ELIGIBLE }
// Saved against an older reviewed list than the vault has now.
const GROWN: WorkspaceItemPosture = { ...ROUTINE, catalogue: { template: "cloudflare-api-token", version: 0, current: 1 } }

// A live standing rule on the token, from Alex's machine.
const RULE = galleryRule(GALLERY_NOW, { id: "rul_alexcfprod01", item: "cloudflare-prod", asker: { device: "dev_alexmbp0001", workload: null }, method: "PUT", host: "api.cloudflare.com", path: "/client/v4/accounts/0123456789abcdef0123456789abcdef/workers/scripts/site", approvedBy: "Alex", uses: 4, lastUsedAt: at(-30) })

// fill: typing into web pages is on, so the In web pages card shows too.
export function posturePage(item: HumanItemDescription, posture: WorkspaceItemPosture, viewer: Viewer = VIEWERS.owner, rules = false, fill = false) {
  return workspaceCredentialPage(galleryShell(viewer), {
    viewer, item: { ...item, posture }, projects: [], ...(fill ? { fill } : {}),
    ...(rules ? { rules: { rules: [RULE], machines: new Map([["dev_alexmbp0001", { name: "alex-mbp", owner: { kind: "member" as const, member: VIEWERS.owner.member, name: "Alex" } }]]), tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner" as const, held: false }, showCredential: false } } : {}),
  })
}

export function postureGallery(): ShellGalleryEntry[] {
  const held: Viewer = { ...VIEWERS.owner, held: true }
  return [
    { id: "ws-posture-ask", group: GROUP, title: "How careful, asking for every change", note: "Nobody has set it, so it asks: the four choices with their words, the areas routine building covers, and Save with passkey waiting until something changes.", page: posturePage(POSTURE_TOKEN, POSTURE_ASK) },
    { id: "ws-posture-custom", group: GROUP, title: "How careful, custom rules", note: "It asks, and a standing rule is live, so the card opens on Custom: the credential's own rules in three lines, a link to Allowed without asking below, and how an agent proposes a new rule. It stores Ask, so there is nothing to save.", page: posturePage(POSTURE_TOKEN, POSTURE_ASK, VIEWERS.owner, true) },
    { id: "ws-posture-routine", group: GROUP, title: "How careful, routine building on every machine", note: "Routine building is let through on every eligible machine; who set it and when.", page: posturePage(POSTURE_TOKEN, ROUTINE) },
    { id: "ws-posture-trust-named", group: GROUP, title: "How careful, trusting one machine", note: "Trust, only on the machine ticked.", page: posturePage(POSTURE_TOKEN, POSTURE_TRUST_NAMED) },
    { id: "ws-posture-grown", group: GROUP, title: "How careful, the reviewed list grew", note: "Cloudflare's reviewed list grew since routine was saved: saving again includes the new routes, so Save is ready.", page: posturePage(POSTURE_TOKEN, GROWN) },
    { id: "ws-posture-no-catalogue", group: GROUP, title: "How careful, no reviewed routes", note: "Nobody has reviewed this service's routes: only Ask and Custom.", page: posturePage(OPENAI, { ...POSTURE_ASK, catalogue: null }) },
    { id: "ws-posture-held", group: GROUP, title: "How careful, restricted account", note: "After a recovery the account may only set it to ask: Routine and Trust are there but cannot be chosen, and the card says why.", page: posturePage(POSTURE_TOKEN, ROUTINE, held) },
    { id: "ws-posture-with-web-pages", group: GROUP, title: "How careful, with In web pages above it", note: "Typing into web pages is on and a standing rule is live: In web pages, then How careful letting routine building through, then Allowed without asking, in the order the page draws them.", page: posturePage(POSTURE_TOKEN, ROUTINE, VIEWERS.owner, true, true) },
  ]
}
