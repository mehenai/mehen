// The people, team, machine, enrolment and Connect an agent pages under
// /w/:ws, registered into WORKSPACE_PAGES. Each reads only through the
// workspace's own /api/w routes with the visitor's cookie, so it shows
// exactly what this account may see there, and each is served only while
// its reads are (routes/ui.ts pageServed).

import type { MandateList, WorkloadList, WorkloadView } from "@mehen/protocol"
import type { TeamView, WorkspaceDeviceView, WorkspaceEnrolView, WorkspaceMemberView, WorkspaceProject } from "@mehen/protocol/workspace"
import type { WorkspaceInviteView } from "../vault/areas/workspace-runtime.ts"
import { cliAdvice } from "../cli-version.ts"
import { emailInvitesCompletable } from "../directory/invite-email.ts"
import type { PeopleViewer } from "../ui/client/people-logic.ts"
import { type CredentialHomeOf, delegatedCredentials, elevated } from "../ui/client/people-logic.ts"
import { type PageInput, errorBody, pageResponse } from "../ui/layout.ts"
import { type Loaded, loadPolicyRules, workspaceApiGet, workspaceReadServed } from "../ui/load.ts"
import { type ListedRules, type PolicyRulesCardData, hasActiveRule } from "../ui/policy-rules-list.ts"
import { connectAgentPage } from "../ui/pages/connect-agent.ts"
import { machinePage, machinesPage } from "../ui/pages/machines.ts"
import { liveMandateOf } from "../ui/pages/mandates.ts"
import { mandatesOn } from "../vault/areas/mandates-workspace.ts"
import { peoplePage, teamsPage } from "../ui/pages/people.ts"
import { enrolmentPage } from "../ui/pages/workspace-enrol.ts"
import type { WorkspaceShell } from "../ui/shell.ts"
import { browserFillOn } from "../vault/fill-unavailable.ts"
import type { RequestContext } from "./context.ts"
import type { WorkspacePage, WorkspacePageContext } from "./ui.ts"

// This account's membership here, from the account read the shell already
// made; null when that read is not served, and then nothing is offered.
export function peopleViewer(shell: WorkspaceShell): PeopleViewer | null {
  const own = shell.memberships?.find((m) => m.workspace.id === shell.identity.workspace.id)
  return own === undefined || own.status !== "active" ? null : { member: own.member, role: own.role, blocked: shell.accountHeld }
}

export function refused(shell: WorkspaceShell, loaded: Extract<Loaded<unknown>, { ok: false }>): Response {
  const page: PageInput = { title: "Not available", viewer: null, workspace: shell, boot: { page: "error" }, body: errorBody(loaded.error, undefined, loaded.status) }
  return pageResponse(page, loaded.status)
}

async function optional<T>(rc: RequestContext, page: WorkspacePageContext, path: string): Promise<T | null> {
  const loaded = await workspaceApiGet<T>(rc, page.workspace, path)
  return loaded.ok ? loaded.value : null
}

// The machine's standing rules for its card, named from the reads the page
// already made: the machine itself and its workloads' labels.
function machineRules(device: WorkspaceDeviceView, rules: ListedRules | null, workloads: readonly WorkloadView[], viewer: PeopleViewer | null): PolicyRulesCardData | undefined {
  if (rules === null || !hasActiveRule(rules)) return undefined
  return {
    rules,
    machines: new Map([[device.device, { name: device.name, owner: device.owner }]]),
    tasks: new Map(workloads.map((w) => [w.workload, w.label])),
    viewer: viewer === null ? null : { member: viewer.member, role: viewer.role, held: viewer.blocked },
    showCredential: true,
  }
}

async function projects(rc: RequestContext, page: WorkspacePageContext): Promise<WorkspaceProject[] | null> {
  return (await optional<{ projects: WorkspaceProject[] }>(rc, page, "/projects"))?.projects ?? null
}

// Every credential this viewer can see, with its home, for the delegation
// a project grant carries; null when it cannot be read.
async function credentials(rc: RequestContext, page: WorkspacePageContext): Promise<CredentialHomeOf[] | null> {
  return (await optional<{ items: CredentialHomeOf[] }>(rc, page, "/items"))?.items ?? null
}

// The workspace credentials admitting a team's machine delegates: the
// team's shared projects within the machine's own project filter. Null
// when any part cannot be read.
async function teamDelegation(rc: RequestContext, page: WorkspacePageContext, view: WorkspaceEnrolView, list: WorkspaceProject[] | null): Promise<string[] | null> {
  if (view.requestedOwner.kind !== "team") return []
  const team = view.requestedOwner.team
  const [teams, items] = await Promise.all([optional<{ teams: TeamView[] }>(rc, page, "/teams"), credentials(rc, page)])
  const found = teams?.teams.find((t) => t.id === team)
  if (!found) return null
  const shared = found.shares.map((s) => s.project).filter((p) => view.scope.projects.length === 0 || view.scope.projects.includes(p))
  return delegatedCredentials(shared, list, items)
}

const param = (rc: RequestContext, name: string): string => encodeURIComponent(rc.params[name] ?? "")

export const PEOPLE_PAGES: WorkspacePage[] = [
  {
    key: "people",
    path: "/people",
    reads: ["/members"],
    render: async (rc, page) => {
      const viewer = peopleViewer(page.shell)
      // A guest may not list people: the page says so and asks nothing.
      if (viewer?.role === "guest") return pageResponse(peoplePage(page.shell, { viewer, members: [], invites: null, teams: null, projects: null, credentials: null }))
      const manager = viewer !== null && elevated(viewer.role)
      const [members, invites, teams, list, items] = await Promise.all([
        workspaceApiGet<WorkspaceMemberView[]>(rc, page.workspace, "/members"),
        manager ? optional<{ invites: WorkspaceInviteView[] }>(rc, page, "/invites") : Promise.resolve(null),
        optional<{ teams: TeamView[] }>(rc, page, "/teams"),
        projects(rc, page),
        manager ? credentials(rc, page) : Promise.resolve(null),
      ])
      if (!members.ok) return refused(page.shell, members)
      return pageResponse(peoplePage(page.shell, { viewer, members: members.value, invites: invites?.invites ?? null, teams: teams?.teams ?? null, projects: list, credentials: items, emailInvites: emailInvitesCompletable(rc.env) }))
    },
  },
  {
    key: "teams",
    path: "/teams",
    reads: ["/teams"],
    render: async (rc, page) => {
      const [teams, members, list] = await Promise.all([workspaceApiGet<{ teams: TeamView[] }>(rc, page.workspace, "/teams"), optional<WorkspaceMemberView[]>(rc, page, "/members"), projects(rc, page)])
      if (!teams.ok) return refused(page.shell, teams)
      return pageResponse(teamsPage(page.shell, { viewer: peopleViewer(page.shell), members: members ?? [], invites: null, teams: teams.value.teams, projects: list, credentials: null }))
    },
  },
  {
    key: "machines",
    path: "/devices",
    reads: ["/devices"],
    render: async (rc, page) => {
      const devices = await workspaceApiGet<{ devices: WorkspaceDeviceView[] }>(rc, page.workspace, "/devices")
      if (!devices.ok) return refused(page.shell, devices)
      return pageResponse(machinesPage(page.shell, devices.value.devices, { viewer: peopleViewer(page.shell), projects: null, now: Date.now(), cli: cliAdvice(rc.env) }))
    },
  },
  {
    key: "machines",
    path: "/devices/:id",
    reads: ["/devices/:id"],
    render: async (rc, page) => {
      const mandates = mandatesOn(rc.env, page.workspace.workspace.id) && workspaceReadServed("/mandates")
      const [device, list, workloads, rules, live] = await Promise.all([workspaceApiGet<WorkspaceDeviceView>(rc, page.workspace, `/devices/${param(rc, "id")}`), projects(rc, page), workspaceApiGet<WorkloadList>(rc, page.workspace, `/devices/${param(rc, "id")}/workloads`), loadPolicyRules(rc, page.workspace, { device: rc.params.id ?? "" }), mandates ? optional<MandateList>(rc, page, "/mandates") : Promise.resolve(null)])
      if (!device.ok) return refused(page.shell, device)
      const viewer = peopleViewer(page.shell)
      const card = machineRules(device.value, rules, workloads.ok ? workloads.value.workloads : [], viewer)
      // A list that could not be read draws no card rather than offering
      // to trust a machine that may already carry on without asking.
      const mandate = mandates && live !== null ? { mandate: liveMandateOf(live, device.value.device), proposals: live.proposals.filter((p) => p.device.id === device.value.device) } : {}
      return pageResponse(machinePage(page.shell, device.value, { viewer, projects: list, now: Date.now(), workloads: workloads.ok ? workloads.value.workloads : null, cli: cliAdvice(rc.env), fill: browserFillOn(rc.env, page.workspace.workspace.id), ...(card !== undefined ? { rules: card } : {}), ...mandate }))
    },
  },
  {
    key: "asks",
    // The code form or the id form (enr_...); the API decides which and who
    // may see it, and the page never carries the code on the id form.
    path: "/e/:ref",
    reads: ["/enrolments/:ref"],
    render: async (rc, page) => {
      const [view, list] = await Promise.all([workspaceApiGet<WorkspaceEnrolView>(rc, page.workspace, `/enrolments/${param(rc, "ref")}`), projects(rc, page)])
      if (!view.ok) return refused(page.shell, view)
      const delegation = view.value.actions.includes("admit") ? await teamDelegation(rc, page, view.value, list) : []
      return pageResponse(enrolmentPage(page.shell, view.value, { viewer: peopleViewer(page.shell), projects: list, now: Date.now(), delegation }))
    },
  },
  { key: "connect-agent", path: "/connect-agent", reads: [""], render: async (_rc, page) => pageResponse(connectAgentPage(page.shell)) },
]
