// The mandate pages under /w/:ws, registered into WORKSPACE_PAGES, served
// only with MANDATES on here: the list, the sign page and one mandate. Each
// reads through the workspace's own /api/w routes with the visitor's
// cookie, so it shows exactly the vault's projection for this reader.

import { type MandateCandidates, type MandateList, type MandateProposalView, type MandateReceiptsPage, type MandateView } from "@mehen/protocol/mandate-terms"
import type { WorkspaceDeviceView } from "@mehen/protocol/workspace"
import { pageResponse } from "../ui/layout.ts"
import { workspaceApiGet } from "../ui/load.ts"
import { type MandateSignStart, mandateSignDefaults, liveMandateOf, mandatePage, mandateSignPage, mandatesPage } from "../ui/pages/mandates.ts"
import { mandatesOn } from "../vault/areas/mandates-workspace.ts"
import { refused } from "./ui-people.ts"
import { viewerOf } from "./ui-projects.ts"
import type { RequestContext } from "./context.ts"
import type { WorkspacePage, WorkspacePageContext } from "./ui.ts"

const MANDATE_ID = /^mdt_[A-Za-z0-9_-]{1,60}$/
const PROPOSAL_ID = /^mdp_[A-Za-z0-9_-]{1,60}$/
const DEVICE_ID = /^dev_[A-Za-z0-9_-]{1,60}$/

// An address no mandate, proposal or machine could have, answered as the
// vault answers one it does not know.
const noSuch = (page: WorkspacePageContext, what: string): Response => refused(page.shell, { ok: false, status: 404, error: { error: "not_found", message: `No such ${what}.` } })

const read = <T,>(rc: RequestContext, page: WorkspacePageContext, path: string) => workspaceApiGet<T>(rc, page.workspace, path)

// A proposal's terms by credential id, as the vault named them for its
// machine's owner; a renewed mandate's by the slugs this person sees now,
// matched to the credentials they may name.
function proposalStart(p: MandateProposalView): MandateSignStart {
  return { classes: p.classes, caps: p.caps, items: p.items === "all" ? "all" : p.items.map((i) => i.id), ttlDays: p.ttlDays, schedule: p.schedule, note: p.note }
}
function renewStart(m: MandateView, candidates: MandateCandidates | null): MandateSignStart {
  const slugs = new Set(m.items === "all" ? [] : m.items)
  return { classes: m.classes, caps: m.caps, items: m.items === "all" ? "all" : (candidates?.items ?? []).filter((c) => slugs.has(c.slug)).map((c) => c.id), ttlDays: m.ttlDays, schedule: m.schedule, note: m.note }
}

// The reader's other machines, which they may sign the same terms for;
// none when the list cannot be read.
async function otherMachines(rc: RequestContext, page: WorkspacePageContext, member: string, except: string): Promise<{ id: string; name: string }[]> {
  const devices = await read<{ devices: WorkspaceDeviceView[] }>(rc, page, "/devices")
  if (!devices.ok) return []
  return devices.value.devices.filter((d) => d.device !== except && !d.revoked && d.owner.kind === "member" && d.owner.member === member).map((d) => ({ id: d.device, name: d.name }))
}

// /w/:ws/sign-mandate?device=, ?proposal= or ?renew=, and ?from= on another
// mandate's terms. The machine comes from the proposal or the mandate
// renewed when one is named. No address widens the terms: a proposal opens
// on its own, and a page without one on the narrowest, where choosing every
// credential or another kind is the person's own act.
async function signPage(rc: RequestContext, page: WorkspacePageContext): Promise<Response> {
  const q = rc.url.searchParams
  const proposalId = q.get("proposal"), renewId = q.get("renew"), fromId = q.get("from")
  let device = q.get("device")
  let proposal: MandateProposalView | null = null
  let renews: MandateView | null = null
  if (proposalId !== null) {
    if (!PROPOSAL_ID.test(proposalId)) return noSuch(page, "proposal")
    const loaded = await read<MandateProposalView>(rc, page, `/mandate-proposals/${encodeURIComponent(proposalId)}`)
    if (!loaded.ok) return refused(page.shell, loaded)
    proposal = loaded.value
    device = proposal.device.id
  } else if (renewId !== null) {
    if (!MANDATE_ID.test(renewId)) return noSuch(page, "mandate")
    const loaded = await read<MandateView>(rc, page, `/mandates/${encodeURIComponent(renewId)}`)
    if (!loaded.ok) return refused(page.shell, loaded)
    renews = loaded.value
    device = renews.device.id
  }
  if (device === null || !DEVICE_ID.test(device)) return noSuch(page, "machine")
  // ?from=: another machine's mandate, whose terms are offered as a source.
  let from: MandateView | null = null
  if (proposal === null && renews === null && fromId !== null) {
    if (!MANDATE_ID.test(fromId)) return noSuch(page, "mandate")
    const loaded = await read<MandateView>(rc, page, `/mandates/${encodeURIComponent(fromId)}`)
    if (!loaded.ok) return refused(page.shell, loaded)
    from = loaded.value
  }
  const [machine, candidates, list] = await Promise.all([
    read<WorkspaceDeviceView>(rc, page, `/devices/${encodeURIComponent(device)}`),
    read<MandateCandidates>(rc, page, `/mandate-candidates?device=${encodeURIComponent(device)}`),
    read<MandateList>(rc, page, "/mandates"),
  ])
  if (!machine.ok) return refused(page.shell, machine)
  if (!candidates.ok && candidates.error.error === "frozen") return refused(page.shell, candidates)
  const named = candidates.ok ? candidates.value : null
  // A mandate renewed or copied only names a source: its terms wait behind
  // Use these terms, and the form opens narrow. So does a proposal that is
  // not open and bound (mandateSignPage).
  const start = proposal !== null ? proposalStart(proposal) : mandateSignDefaults(machine.value.name)
  const sourced = renews ?? from
  const source = proposal === null && sourced !== null ? { kind: renews !== null ? "renew" as const : "from" as const, mandate: sourced, start: renewStart(sourced, named) } : null
  const replaces = liveMandateOf(list.ok ? list.value : null, device)
  return pageResponse(mandateSignPage(page.shell, {
    viewer: viewerOf(page), device: machine.value, candidates: named,
    start,
    proposal, renews, source, replaces, now: Date.now(),
  }))
}

export const MANDATE_PAGES: WorkspacePage[] = [
  {
    key: "machines",
    path: "/mandates",
    reads: ["/mandates"],
    on: mandatesOn,
    render: async (rc, page) => {
      const list = await read<MandateList>(rc, page, "/mandates")
      if (!list.ok) return refused(page.shell, list)
      return pageResponse(mandatesPage(page.shell, { viewer: viewerOf(page), mandates: list.value.mandates, proposals: list.value.proposals, now: Date.now() }))
    },
  },
  { key: "machines", path: "/sign-mandate", reads: ["/mandate-candidates", "/mandates/:id", "/mandate-proposals/:id"], on: mandatesOn, render: signPage },
  {
    key: "machines",
    path: "/mandates/:id",
    reads: ["/mandates/:id", "/mandates/:id/uses"],
    on: mandatesOn,
    render: async (rc, page) => {
      const id = rc.params.id ?? ""
      if (!MANDATE_ID.test(id)) return noSuch(page, "mandate")
      const before = rc.url.searchParams.get("before")
      const [mandate, receipts] = await Promise.all([
        read<MandateView>(rc, page, `/mandates/${encodeURIComponent(id)}`),
        read<MandateReceiptsPage>(rc, page, `/mandates/${encodeURIComponent(id)}/uses${before !== null ? `?before=${encodeURIComponent(before)}` : ""}`),
      ])
      if (!mandate.ok) return refused(page.shell, mandate)
      const viewer = viewerOf(page)
      const others = mandate.value.signer.self === true && viewer.role !== "guest" ? await otherMachines(rc, page, viewer.member, mandate.value.device.id) : []
      return pageResponse(mandatePage(page.shell, { viewer, mandate: mandate.value, receipts: receipts.ok ? receipts.value : null, now: Date.now(), others }))
    },
  },
]
