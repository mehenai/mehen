// Standing rules for the gallery's credential, machine and My rules pages
// (people-gallery.ts, workspace-projects-gallery.ts): the "Allowed without
// asking" card with live rules, a stopped one, an extension waiting for a
// co-signer and the row someone who may stop but not read a rule sees, as
// the client draws the last two in place (client/pages/policy-rules.ts);
// and task grants, live and ended.

import { RULE_DEFAULT_DURATION, type PolicyAreaGrantView, type PolicyRuleStopped, type PolicyRuleView } from "@mehen/protocol/policy-mode"
import type { WorkspaceItemSummary } from "@mehen/protocol/workspace"
import { escapeHtml } from "./html.ts"
import type { PageInput } from "./layout.ts"
import { machinePage } from "./pages/machines.ts"
import { myRulesPage } from "./pages/my-rules.ts"
import { workspaceCredentialPage } from "./pages/workspace-credentials.ts"
import { GALLERY_WORKLOADS, PEOPLE_DEVICE, PEOPLE_PROJECTS, peopleShell } from "./people-gallery.ts"
import { stoppedOnlyRow } from "./policy-rules-row.ts"
import { GALLERY_NOW, GALLERY_ORIGIN, type ShellGalleryEntry } from "./shell-gallery.ts"
import { GALLERY_FIXTURES, GALLERY_ITEMS, VIEWERS, description, galleryProject, galleryShell } from "./workspace-projects-gallery.ts"
import { RULE_COSIGN_CODE_WORDS, RULE_COSIGN_LINK_WORDS, RULE_EXTEND_COSIGN_WORDS } from "./wording.ts"

type RuleFixture = Pick<PolicyRuleView, "id" | "item" | "asker" | "method" | "host" | "path"> & Partial<PolicyRuleView>

// A rule as GET /policy/rules lists it, drawn at `now`.
export function galleryRule(now: number, fixture: RuleFixture): PolicyRuleView {
  const at = (minutes: number) => new Date(now + minutes * 60_000).toISOString()
  return {
    itemId: `itm_${fixture.item.replaceAll("-", "")}`,
    anchorPath: fixture.path,
    queryNames: [],
    graphql: null,
    ttlSeconds: RULE_DEFAULT_DURATION,
    approvedBy: "Tom Barker",
    coSignedBy: null,
    context: null,
    createdAt: at(-2 * 24 * 60),
    endsAt: at(5 * 24 * 60),
    uses: 0,
    lastUsedAt: null,
    status: "active",
    endedReason: null,
    ...fixture,
  }
}

// A rule's row once an extension waits for a manager of the credential's
// home: Extend gone, and the outcome saying where to send the manager.
export function coSignOutcomeSwap(rule: string, url: string, code: string): [RegExp, string] {
  const at = new RegExp(`(data-rule="${rule}"[\\s\\S]*?)<details class="fold" data-region="rule-extend">[\\s\\S]*?</details>\\s*<div class="small" role="status" tabindex="-1" data-region="rule-outcome"></div>`)
  return [at, `$1<div class="small" role="status" tabindex="-1" data-region="rule-outcome"><p>${escapeHtml(RULE_EXTEND_COSIGN_WORDS)}</p><p>${escapeHtml(RULE_COSIGN_LINK_WORDS)}: <a href="${escapeHtml(url)}">${escapeHtml(url)}</a></p><p>${escapeHtml(RULE_COSIGN_CODE_WORDS)}: <code>${escapeHtml(code)}</code></p></div>`]
}

// The row once a viewer who may stop the rule but not read it stopped it.
export function stoppedOnlySwap(rule: PolicyRuleStopped): [RegExp, string] {
  return [new RegExp(`<li class="row" data-region="rule" data-rule="${rule.id}"[\\s\\S]*?</li>`), stoppedOnlyRow(rule).value]
}

// ---------------------------------------------------------------- the entries

const GROUP = "Allowed without asking"
const NOW = GALLERY_NOW
const at = (minutes: number) => new Date(NOW + minutes * 60_000).toISOString()
const TOM = { member: "mem_tom01" }

// Tom's laptop: a chat completion it may send, and a GraphQL mutation one
// of its tasks may send, each approved by Tom.
const CHAT = galleryRule(NOW, { id: "rul_tomchat0001", item: "openai-shared", asker: { device: PEOPLE_DEVICE.device, workload: null }, method: "POST", host: "api.openai.com", path: "/v1/chat/completions", context: { project: "prj_site01", environment: "dev" }, uses: 14, lastUsedAt: at(-12) })
const LINEAR = galleryRule(NOW, {
  id: "rul_tomlinear001", item: "linear-platform", asker: { device: PEOPLE_DEVICE.device, workload: GALLERY_WORKLOADS[0]!.workload }, method: "POST", host: "api.linear.app", path: "/graphql",
  graphql: { fields: ["issueCreate"], nestedFields: ["id", "identifier", "title"] }, coSignedBy: { name: "Alex Rae" }, uses: 3, lastUsedAt: at(-40), endsAt: at(22 * 60),
})
const STOPPED = { ...CHAT, status: "ended" as const, endedReason: "revoked" as const, endsAt: at(-3) }

// Tom's laptop as Tom sees it, or as an admin who is not its owner does.
function tomsMachine(rules: PolicyRuleView[], as: { member: string; role: "member" | "admin" } = { member: TOM.member, role: "member" }): PageInput {
  return machinePage(peopleShell(as.role, { member: as.member }), PEOPLE_DEVICE, {
    viewer: { member: as.member, role: as.role, blocked: false },
    projects: PEOPLE_PROJECTS,
    now: NOW,
    workloads: GALLERY_WORKLOADS,
    rules: { rules, machines: new Map([[PEOPLE_DEVICE.device, { name: PEOPLE_DEVICE.name, owner: PEOPLE_DEVICE.owner }]]), tasks: new Map(GALLERY_WORKLOADS.map((w) => [w.workload, w.label])), viewer: { member: as.member, role: as.role, held: false }, showCredential: true },
  })
}

// openai-prod, read by its workspace's owner: a rule for the owner's own
// machine, with Extend, and one for Tom's, with Stop only.
const ALEX_MACHINE = { device: "dev_alexmbp0001", name: "alex-mbp", owner: { kind: "member" as const, member: VIEWERS.owner.member, name: "Alex" } }
const TOM_MACHINE = { device: "dev_tomlaptop01", name: "tom-laptop", owner: { kind: "member" as const, member: "mem_tom00001", name: "Tom Barker" } }
const PROD_RULES = [
  galleryRule(NOW, { id: "rul_alexprod0001", item: "openai-prod", asker: { device: ALEX_MACHINE.device, workload: null }, method: "POST", host: "api.openai.com", path: "/v1/embeddings", approvedBy: "Alex", context: { project: "prj_platform01", environment: "prod" }, uses: 120, lastUsedAt: at(-1) }),
  galleryRule(NOW, { id: "rul_tomprod00001", item: "openai-prod", asker: { device: TOM_MACHINE.device, workload: "wl_tomtask0001" }, method: "GET", host: "api.openai.com", path: "/v1/models/*", anchorPath: "/v1/models/42", approvedBy: null, coSignedBy: { name: null } }),
]

// Task grants on the workspace's Cloudflare API token, cloudflare-prod
// (PolicyAreaGrantView): a live one on Alex's
// machine, D1 databases and DNS records, 14 of 50 requests used and 40
// minutes left; one that ran out of uses, with its receipt; and one a newer
// grant replaced.
type GrantFixture = Pick<PolicyAreaGrantView, "id" | "asker" | "areas"> & Partial<PolicyAreaGrantView>
export function galleryGrant(now: number, fixture: GrantFixture): PolicyAreaGrantView {
  const at = (minutes: number) => new Date(now + minutes * 60_000).toISOString()
  return {
    kind: "area", item: "cloudflare-prod", itemId: "itm_cloudflareprod", host: "api.cloudflare.com", catalogue: "cloudflare-api-token", catalogueVersion: 1, ttlSeconds: 3600, maxUses: 50,
    approvedBy: "Alex", coSignedBy: null, context: null, createdAt: at(-20), endsAt: at(40), uses: 0, lastUsedAt: null, status: "active", receipt: [], endedReason: null,
    ...fixture,
  }
}
const GRANT_LIVE = galleryGrant(NOW, { id: "rul_alexgrant001", asker: { device: ALEX_MACHINE.device, workload: null }, areas: ["d1", "dns"], uses: 14, lastUsedAt: at(-2), receipt: [{ entry: "cloudflare.d1-create", words: "Creates a D1 database", count: 6 }, { entry: "cloudflare.dns-record-create", words: "Adds a DNS record", count: 8 }] })
const GRANT_SPENT = galleryGrant(NOW, { id: "rul_alexgrant000", asker: { device: ALEX_MACHINE.device, workload: null }, areas: ["d1"], maxUses: 6, uses: 6, lastUsedAt: at(-90), createdAt: at(-120), endsAt: at(-90), status: "ended", endedReason: "uses-spent", receipt: [{ entry: "cloudflare.d1-create", words: "Creates a D1 database", count: 6 }] })
const GRANT_REPLACED = galleryGrant(NOW, { id: "rul_tomgrant0001", asker: { device: TOM_MACHINE.device, workload: null }, areas: ["kv"], approvedBy: "Tom Barker", uses: 0, createdAt: at(-30), endsAt: at(-25), status: "ended", endedReason: "replaced" })

export const RULES_COSIGN_URL = `${GALLERY_ORIGIN}/w/northwind/p/pol_extendchat01`
export const RULES_COSIGN_CODE = "7XK2M9QP"

export function policyRulesGallery(): ShellGalleryEntry[] {
  const owner = galleryShell(VIEWERS.owner)
  const prod = GALLERY_ITEMS[0] as WorkspaceItemSummary
  const machines = new Map([ALEX_MACHINE, TOM_MACHINE].map((m) => [m.device, { name: m.name, owner: m.owner }]))
  const withRules = { ...owner, pages: [...owner.pages, "rules" as const] }
  return [
    { id: "machine-rules", group: GROUP, title: "Your machine, with standing rules", note: "Each rule: who sends it, the request, GraphQL fields when there are any, its context (the project and environment it applies in, in the approval page's words), who approved it and who co-signed it, uses, when it ends, Stop and Extend. The line at the top counts them and links here.", page: tomsMachine([CHAT, LINEAR]) },
    { id: "machine-rule-stopped", group: GROUP, title: "Your machine, a rule stopped", note: "Stopped needs no passkey: the row says Stopped and why, with no Stop or Extend, and the line counts one. Once the page is read again the stopped rule is listed under Ended, the 5 most recent with a count of the rest.", page: tomsMachine([LINEAR, STOPPED]) },
    { id: "machine-rule-cosign", group: GROUP, title: "Your machine, an extension waiting for a co-signer", note: "The owner of the machine does not manage the credential: the rule keeps its end until a manager of the credential's home co-signs at the link, with the binding code.", page: tomsMachine([CHAT, LINEAR]), swap: [coSignOutcomeSwap(CHAT.id, RULES_COSIGN_URL, RULES_COSIGN_CODE)] },
    { id: "machine-rule-stopped-only", group: GROUP, title: "A rule you may stop but not read", note: "An admin stopped a rule they may not read: the row keeps only its id and that it ended, never what it allowed. Not their machine, so no line at the top and no Extend.", page: tomsMachine([CHAT, LINEAR], { member: "mem_alex01", role: "admin" }), swap: [stoppedOnlySwap({ id: CHAT.id, status: "ended", endedReason: "revoked" })] },
    { id: "ws-my-rules", group: GROUP, title: "My rules", note: "Every live rule on the viewer's own machines or that they approved or co-signed, each naming its credential, with the same Stop and Extend as the credential and machine cards. Linked from the navigation only while standing rules are on for the workspace.", page: myRulesPage(withRules, { rules: PROD_RULES, machines, tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: true }, [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)]) },
    { id: "ws-my-rules-empty", group: GROUP, title: "My rules, none", note: "No live rule touches the viewer: an empty state, and no Stop or Extend.", page: myRulesPage(withRules, { rules: [], machines: new Map(), tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: true }, null) },
    { id: "ws-my-rules-grant", group: GROUP, title: "My rules, with a task grant", note: "A live task grant beside the rules: the areas it covers, how many of its requests are used and when it ends, with Stop and no Extend.", page: myRulesPage(withRules, { rules: [GRANT_LIVE, ...PROD_RULES], machines, tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: true }, null) },
    { id: "ws-credential-grants", group: GROUP, title: "Credential, with task grants", note: "A live task grant, and under Ended one that was used as many times as it allows, with its receipt of what it did, and one a newer grant replaced.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description({ ...prod, slug: "cloudflare-prod", provider: "cloudflare-api-token", hosts: ["api.cloudflare.com"] }), projects: [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)], rules: { rules: [GRANT_LIVE, GRANT_SPENT, GRANT_REPLACED], machines, tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: false } }) },
    { id: "ws-credential-rules", group: GROUP, title: "Credential, with standing rules", note: "A rule for the viewer's own machine, with Extend, and one for a task on someone else's, with Stop only and its approver not shown. The line at the top links to the viewer's machine.", page: workspaceCredentialPage(owner, { viewer: VIEWERS.owner, item: description(prod), projects: [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, true)], rules: { rules: PROD_RULES, machines, tasks: new Map(), viewer: { member: VIEWERS.owner.member, role: "owner", held: false }, showCredential: false } }) },
  ]
}
