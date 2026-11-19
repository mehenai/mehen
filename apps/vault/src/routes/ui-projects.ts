// The workspace pages for projects, credentials, asks and the audit log,
// registered into the shell's WORKSPACE_PAGES. Each is served only while
// every read it lists is (routes/ui.ts), and reads its data through the
// same /api/w routes the browser calls, with the visitor's own cookie, so a
// page shows exactly what this account may see in this workspace.

import type { WorkspaceAdoptionInventory, WorkspaceAdoptionView } from "@mehen/protocol/adopt"
import type { ApiError } from "@mehen/protocol/api"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { TeamView, WorkspaceApprovalView, WorkspaceConnectView, WorkspaceDeviceView, WorkspaceIntakeView, WorkspaceItemSummary, WorkspaceMemberView, PolicyStandingProposalViewProjection, WorkspaceItemDescription, WorkspacePendingAsk, WorkspaceProject, WorkspaceSecurityNotice } from "@mehen/protocol/workspace"
import { type PageInput, errorPageInput, pageResponse, redirect } from "../ui/layout.ts"
import { type Loaded, loadPolicyRules, workspaceApiGet, workspaceReadServed } from "../ui/load.ts"
import { type ListedRules, type PolicyRulesCardData, hasActiveRule } from "../ui/policy-rules-list.ts"
import { myRulesPage } from "../ui/pages/my-rules.ts"
import { policyRulesOn } from "../vault/areas/policy-rules-workspace.ts"
import { browserFillOn } from "../vault/fill-unavailable.ts"
import type { PolicyRuleList } from "@mehen/protocol/policy-mode"
import { workspaceAdoptionPage } from "../ui/pages/workspace-adopt.ts"
import { workspaceAdoptInventoryPage } from "../ui/pages/workspace-adopt-inventory.ts"
import { workspaceApprovalPage, workspaceConnectPage, workspaceIntakePage, workspaceProposalPage } from "../ui/pages/workspace-asks.ts"
import { type WorkspaceAuditPage, workspaceAuditPage } from "../ui/pages/workspace-audit.ts"
import { type HumanItemDescription, workspaceCredentialPage, workspaceCredentialsPage } from "../ui/pages/workspace-credentials.ts"
import { type ProjectOverride, workspaceProjectPage, workspaceProjectsPage } from "../ui/pages/workspace-projects.ts"
import type { Viewer } from "../ui/workspace-rights.ts"
import { type PushedValueFacts, approvalPush } from "../ui/push-evidence.ts"
import { pushesOn } from "../vault/areas/push-allowance.ts"
import { mandatesOn } from "../vault/areas/mandates-workspace.ts"
import type { MandateCappedAsk, MandateCoverAsk } from "@mehen/protocol/mandate-terms"
import type { RequestContext } from "./context.ts"
import type { WorkspacePage, WorkspacePageContext } from "./ui.ts"

// The viewer's role in this workspace comes from the account read; without
// it the page offers the least, a guest's, and the vault decides anyway.
// A held account (restricted, or a security change still reaching its
// workspaces) is offered no changes; an account read that failed holds the
// shell too, but says nothing of a restriction, so it only falls to a guest.
export function viewerOf(page: WorkspacePageContext): Viewer {
  const membership = page.shell.memberships?.find((m) => m.workspace.id === page.shell.identity.workspace.id)
  return { role: membership?.role ?? "guest", member: membership?.member ?? page.workspace.membership, held: page.shell.accountHeld && page.shell.memberships !== null }
}

function failed(rc: RequestContext, page: WorkspacePageContext, status: number, error: ApiError): Response {
  if (error.error === "unauthenticated") return redirect(`/signin?next=${encodeURIComponent(rc.url.pathname + rc.url.search)}`)
  return pageResponse({ ...errorPageInput(null, status, error), workspace: page.shell }, status)
}

function param(rc: RequestContext, name: string): string {
  return encodeURIComponent(rc.params[name] ?? "")
}

async function read<T>(rc: RequestContext, page: WorkspacePageContext, path: string): Promise<Loaded<T>> {
  return workspaceApiGet<T>(rc, page.workspace, path)
}

// A read a page can do without; null when refused.
async function optional<T>(rc: RequestContext, page: WorkspacePageContext, path: string): Promise<T | null> {
  const loaded = await read<T>(rc, page, path)
  return loaded.ok ? loaded.value : null
}

function render<T>(rc: RequestContext, page: WorkspacePageContext, loaded: Loaded<T>, build: (value: T) => PageInput): Response {
  return loaded.ok ? pageResponse(build(loaded.value)) : failed(rc, page, loaded.status, loaded.error)
}

async function projectsOf(rc: RequestContext, page: WorkspacePageContext): Promise<WorkspaceProject[]> {
  return (await optional<{ projects: WorkspaceProject[] }>(rc, page, "/projects"))?.projects ?? []
}

// The credential's standing rules for its card, with POLICY_RULES on: one
// read, and the machines to name them by only when it listed a live one.
async function credentialRules(rc: RequestContext, page: WorkspacePageContext): Promise<PolicyRulesCardData | undefined> {
  const rules = await loadPolicyRules(rc, page.workspace, { item: rc.params.slug ?? "" })
  if (rules === null || !hasActiveRule(rules)) return undefined
  const devices = await optional<{ devices: WorkspaceDeviceView[] }>(rc, page, "/devices")
  const viewer = viewerOf(page)
  return {
    rules,
    machines: new Map((devices?.devices ?? []).map((d) => [d.device, { name: d.name, owner: d.owner }])),
    tasks: new Map(),
    viewer: { member: viewer.member, role: viewer.role, held: viewer.held === true },
    showCredential: false,
  }
}

// My rules: the person's own live rules and task grants (GET /policy/rules
// with include=grants, naming neither credential nor machine), and only
// when it listed a live one, the machines to name them by and the projects
// to name where each applies.
async function myRules(rc: RequestContext, page: WorkspacePageContext): Promise<Response> {
  const rules = await read<ListedRules>(rc, page, "/policy/rules?include=grants")
  const live = rules.ok && hasActiveRule(rules.value)
  const [devices, projects] = live ? await Promise.all([optional<{ devices: WorkspaceDeviceView[] }>(rc, page, "/devices"), projectsOf(rc, page)]) : [null, null]
  const viewer = viewerOf(page)
  return render(rc, page, rules, (list) => myRulesPage(page.shell, {
    rules: list,
    machines: new Map((devices?.devices ?? []).map((d) => [d.device, { name: d.name, owner: d.owner }])),
    tasks: new Map(),
    viewer: { member: viewer.member, role: viewer.role, held: viewer.held === true },
    showCredential: true,
  }, projects))
}

// A push card's prefix and fingerprint of the pushed field, as `mehen show`
// gives them: read as this person through their own items read, only for
// the pushed credential (never the one carrying it), and only when the
// version described is the one the push names. Any refusal or error leaves
// the line out, so the page never says whether the credential exists.
async function pushedValue(rc: RequestContext, page: WorkspacePageContext, view: WorkspaceApprovalView): Promise<PushedValueFacts | null> {
  if (view.view !== "detail") return null
  const push = approvalPush(view.approval)
  if (push === null) return null
  const item = await optional<WorkspaceItemDescription>(rc, page, `/items/${encodeURIComponent(view.approval.item.slug)}`).catch(() => null)
  if (item === null || item.version !== push.push.version) return null
  const field = item.secretFields.find((f) => f.name === push.push.field)
  return field !== undefined && field.set ? { prefix: field.prefix !== "" ? field.prefix : null, fingerprint: field.fingerprint } : null
}

// That a mandate could let asks like this through, for the person who may
// sign for the machine; null for anyone else or any other ask.
async function coverAsk(rc: RequestContext, page: WorkspacePageContext, view: WorkspaceApprovalView): Promise<MandateCoverAsk | null> {
  if (view.view !== "detail" || !mandatesOn(rc.env, page.workspace.workspace.id) || !workspaceReadServed("/mandate-covers/:approval")) return null
  // Only the machine's owner, never a guest, may sign for it: the vault is not asked for anyone else.
  const viewer = viewerOf(page), owner = view.approval.owner
  if (viewer.role === "guest" || owner.kind !== "member" || owner.member !== viewer.member) return null
  return optional<MandateCoverAsk>(rc, page, `/mandate-covers/${encodeURIComponent(view.approval.approval)}`)
}
// Which caps alone kept the machine's mandate from letting this ask
// through, with MANDATES on, for an ask this reader sees in full; null for
// any other ask, or one the vault does not keep caps for.
async function cappedAsk(rc: RequestContext, page: WorkspacePageContext, view: WorkspaceApprovalView): Promise<MandateCappedAsk | null> {
  if (view.view !== "detail" || !mandatesOn(rc.env, page.workspace.workspace.id) || !workspaceReadServed("/mandate-asks/:approval")) return null
  return optional<MandateCappedAsk>(rc, page, `/mandate-asks/${encodeURIComponent(view.approval.approval)}`)
}

export const WORKSPACE_PROJECT_PAGES: WorkspacePage[] = [
  { key: "rules", path: "/rules", reads: ["/policy/rules"], on: policyRulesOn, render: myRules },
  {
    key: "projects",
    path: "/projects",
    reads: ["/projects"],
    render: async (rc, page) => render(rc, page, await read<{ projects: WorkspaceProject[] }>(rc, page, "/projects"), (v) => workspaceProjectsPage(page.shell, { viewer: viewerOf(page), projects: v.projects })),
  },
  {
    key: "projects",
    path: "/projects/:id",
    reads: ["/projects/:id", "/items"],
    render: async (rc, page) => {
      const viewer = viewerOf(page)
      const id = param(rc, "id")
      // "Use my own" lights up once WS-OVERRIDES' read is registered.
      const overridesServed = workspaceReadServed("/projects/:id/overrides")
      // Teams, for share subjects and their names: never asked for on a
      // guest's behalf, and absent wherever the vault refuses the read.
      const teamsServed = viewer.role !== "guest" && workspaceReadServed("/teams")
      const [project, items, members, overrides, teams] = await Promise.all([
        read<WorkspaceProject>(rc, page, `/projects/${id}`),
        optional<{ items: WorkspaceItemSummary[] }>(rc, page, "/items"),
        viewer.role === "guest" ? Promise.resolve(null) : optional<WorkspaceMemberView[]>(rc, page, "/members"),
        overridesServed ? optional<{ overrides: ProjectOverride[] }>(rc, page, `/projects/${id}/overrides`) : Promise.resolve(null),
        teamsServed ? optional<{ teams: TeamView[] }>(rc, page, "/teams") : Promise.resolve(null),
      ])
      return render(rc, page, project, (p) => workspaceProjectPage(page.shell, { viewer, project: p, items: items?.items ?? null, members, overrides: overrides?.overrides ?? null, teams: teams?.teams ?? null }))
    },
  },
  {
    key: "credentials",
    path: "/credentials",
    reads: ["/items", "/projects"],
    render: async (rc, page) => {
      const [items, projects] = await Promise.all([read<{ items: WorkspaceItemSummary[] }>(rc, page, "/items"), projectsOf(rc, page)])
      return render(rc, page, items, (v) => workspaceCredentialsPage(page.shell, { viewer: viewerOf(page), items: v.items, projects }))
    },
  },
  {
    key: "credentials",
    path: "/items/:slug",
    reads: ["/items/:slug", "/projects"],
    render: async (rc, page) => {
      const [item, projects, rules] = await Promise.all([read<HumanItemDescription>(rc, page, `/items/${param(rc, "slug")}`), projectsOf(rc, page), credentialRules(rc, page)])
      return render(rc, page, item, (v) => workspaceCredentialPage(page.shell, { viewer: viewerOf(page), item: v, projects, ...(rules !== undefined ? { rules } : {}), pushes: pushesOn(rc.env, page.workspace.workspace.id), fill: browserFillOn(rc.env, page.workspace.workspace.id) }))
    },
  },
  {
    key: "asks",
    path: "/a/:id",
    reads: ["/approvals/:id"],
    render: async (rc, page) => {
      const view = await read<WorkspaceApprovalView>(rc, page, `/approvals/${param(rc, "id")}`)
      if (!view.ok) return failed(rc, page, view.status, view.error)
      // A run approval names its project by id at the end of its URL.
      const runProject = view.value.view === "detail" && view.value.approval.request.method === "RUN" ? (view.value.approval.request.url.split("/projects/")[1] ?? null) : null
      const [project, items] = await Promise.all([
        runProject !== null && /^prj_[A-Za-z0-9_-]+$/.test(runProject) ? optional<WorkspaceProject>(rc, page, `/projects/${runProject}`) : Promise.resolve(null),
        runProject !== null ? optional<{ items: WorkspaceItemSummary[] }>(rc, page, "/items") : Promise.resolve(null),
      ])
      if (runProject === null) {
        const [pushed, capped, cover] = await Promise.all([pushedValue(rc, page, view.value), cappedAsk(rc, page, view.value), coverAsk(rc, page, view.value)])
        return pageResponse(workspaceApprovalPage(page.shell, { viewer: viewerOf(page), view: view.value, project, items: items?.items ?? [], pushedValue: pushed, capped, cover }))
      }
      // The run's credential list comes from the project as it is now, not
      // from the approval's digest. Read the approval again after it: a
      // change in between (a reference write makes the ask stale) shows the
      // later state, says it changed, and offers no decision on this page.
      const again = await read<WorkspaceApprovalView>(rc, page, `/approvals/${param(rc, "id")}`)
      if (!again.ok) return failed(rc, page, again.status, again.error)
      const changed = canonicalJson(again.value) !== canonicalJson(view.value)
      return pageResponse(workspaceApprovalPage(page.shell, { viewer: viewerOf(page), view: again.value, project, items: items?.items ?? [], changedSinceRequested: changed }))
    },
  },
  {
    key: "asks",
    path: "/i/:id",
    reads: ["/intakes/:id"],
    render: async (rc, page) => {
      const [view, projects] = await Promise.all([read<WorkspaceIntakeView>(rc, page, `/intakes/${param(rc, "id")}`), projectsOf(rc, page)])
      return render(rc, page, view, (v) => workspaceIntakePage(page.shell, v, projects, Date.now(), browserFillOn(rc.env, page.workspace.workspace.id)))
    },
  },
  {
    // An adoption batch: every row the machine uploaded, to untick, rehome
    // and approve with one passkey.
    key: "asks",
    path: "/b/:id",
    reads: ["/adoptions/:id"],
    render: async (rc, page) => {
      const [view, projects] = await Promise.all([read<WorkspaceAdoptionView>(rc, page, `/adoptions/${param(rc, "id")}`), projectsOf(rc, page)])
      return render(rc, page, view, (v) => workspaceAdoptionPage(page.shell, v, projects))
    },
  },
  {
    // Every name this person's adoptions touch, each open batch linked.
    key: "credentials",
    path: "/adopt",
    reads: ["/adoptions"],
    render: async (rc, page) => {
      const [inventory, projects] = await Promise.all([read<WorkspaceAdoptionInventory>(rc, page, "/adoptions"), projectsOf(rc, page)])
      return render(rc, page, inventory, (v) => workspaceAdoptInventoryPage(page.shell, v, projects))
    },
  },
  {
    key: "asks",
    path: "/c/:id",
    reads: ["/connect/:id"],
    render: async (rc, page) => {
      const [view, projects] = await Promise.all([read<WorkspaceConnectView>(rc, page, `/connect/${param(rc, "id")}`), projectsOf(rc, page)])
      return render(rc, page, view, (v) => workspaceConnectPage(page.shell, v, projects))
    },
  },
  {
    // A policy proposal: the detail view for whoever may read it, the stop
    // view for whoever may only decline it, not found for anyone else. A
    // standing rule's terms name its credential, read for its account and
    // service where the person may read it.
    key: "asks",
    path: "/p/:id",
    reads: ["/policy/proposals/:id"],
    render: async (rc, page) => {
      const view = await read<PolicyStandingProposalViewProjection>(rc, page, `/policy/proposals/${param(rc, "id")}`)
      const rule = view.ok && view.value.view === "detail" && "kind" in view.value.proposal && view.value.proposal.kind === "rule" ? view.value.proposal.terms.item : null
      const item = rule !== null ? await optional<WorkspaceItemDescription>(rc, page, `/items/${encodeURIComponent(rule)}`) : null
      return render(rc, page, view, (v) => workspaceProposalPage(page.shell, v, item !== null ? { provider: item.provider, account: item.account } : null))
    },
  },
  {
    // ACCESS's filtered reader: which rows come back depends on the reader,
    // never their bytes.
    key: "audit",
    path: "/audit",
    reads: ["/audit"],
    render: async (rc, page) => {
      const viewer = viewerOf(page)
      const cursor = rc.url.searchParams.get("cursor")
      const item = rc.url.searchParams.get("item")
      const query = new URLSearchParams({ ...(cursor !== null && /^[1-9][0-9]{0,15}$/.test(cursor) ? { cursor } : {}), ...(item !== null && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(item) ? { item } : {}) }).toString()
      const [audit, members, devices] = await Promise.all([
        read<WorkspaceAuditPage>(rc, page, `/audit${query ? `?${query}` : ""}`),
        viewer.role === "guest" ? Promise.resolve(null) : optional<WorkspaceMemberView[]>(rc, page, "/members"),
        optional<{ devices: WorkspaceDeviceView[] }>(rc, page, "/devices"),
      ])
      const names = { members: new Map((members ?? []).map((m) => [m.member, m.name])), devices: new Map((devices?.devices ?? []).map((d) => [d.device, d.name])) }
      return render(rc, page, audit, (v) => workspaceAuditPage(page.shell, { viewer, page: v, names, item: query.includes("item=") ? item : null }))
    },
  },
]
