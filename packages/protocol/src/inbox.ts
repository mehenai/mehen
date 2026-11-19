// The Needs you inbox: every open ask, enrolment, member confirmation and
// scope proposal a signed-in account may act on, across its workspaces
// (GET /api/needs-you) or in one (GET /api/w/:ws/inbox). Responses only;
// the vault builds every `href` from kind and id on its own origin.

import type { FingerprintWord } from "./fingerprint.ts"
import type { EnrolStartContext, OwnerRef, WorkspaceNotice, WorkspacePendingAsk, WorkspaceRef, WorkspaceRole } from "./workspace.ts"

export type InboxAction = "decide" | "open" | "connect" | "review" | "reconnect" | "accept" | "admit" | "confirm" | "reject" | "stop"
export type InboxWorkspaceState = "ok" | "gated" | "inactive" | "unavailable"
// count is null unless state is "ok"; truncated when a cap cut this
// workspace's rows, so count is then a lower bound.
export type InboxWorkspace = { workspace: WorkspaceRef; role: WorkspaceRole | null; state: InboxWorkspaceState; reason: "limit" | "deadline" | "timeout" | "error" | null; count: number | null; truncated: boolean }
type InboxBase = { workspace: WorkspaceRef; href: string; action: InboxAction; createdAt: string | null; expiresAt: string | null }
export type InboxEnrolment = {
  enrolment: string
  name: string
  host: string | null
  backend: "software" | "secure-enclave"
  start: EnrolStartContext
  // The agent's label, unverified.
  session: string | null
  requestedOwner: { kind: "self" } | { kind: "team"; team: string; name: string }
  // Null until accepted: ownerless by design.
  owner: OwnerRef | null
  claimed: { account: string; name: string } | null
  state: "pending_owner_acceptance" | "pending_admission"
  // The hidden group is null.
  fingerprint: { groups: [string | null, string | null, string | null, string | null]; words: FingerprintWord[] }
  actions: ("accept" | "admit" | "reject")[]
  hardExpiresAt: string
}
export type InboxConfirmation = { member: string; name: string; role: WorkspaceRole; invite: string; termsDigest: string; boundEmail: string | null; joinedAt: string }
export type InboxRescope = { proposal: string; device: string; deviceName: string; owner: OwnerRef; proposer: { member: string; name: string }; as: "owner_acceptance" | "admission" }
// Two or more pending approvals of one review group (grp_) or bundle (bnd_),
// in one row whose href is the Review together page (/w/<slug>/g/<id>).
// floor and ownPage count the asks that need a closer look and those decided
// on their own page; reason is a bundle's, the agent's words, unverified.
// denyOnly counts those the viewer may only deny; absent reads as 0. Each
// ask counts in the one section Review together lists it under.
export type InboxGroup = { group: string; kind: "machine" | "bundle"; machine: { device: string; name: string; workload: { id: string; label: string } | null }; owner: OwnerRef; item: { slug: string } | null; count: number; floor: number; ownPage: number; denyOnly?: number; reason: string | null }
export type InboxItem = InboxBase & (
  | { kind: "ask"; ask: WorkspacePendingAsk }
  | { kind: "enrol"; enrol: InboxEnrolment }
  | { kind: "confirm"; confirm: InboxConfirmation }
  | { kind: "rescope"; rescope: InboxRescope }
  | { kind: "group"; group: InboxGroup })
// count counts items in "ok" workspaces; complete is true only when no
// workspace is gated, unavailable or truncated.
export type InboxResponse = { workspaces: InboxWorkspace[]; items: InboxItem[]; notices: WorkspaceNotice[]; count: number; complete: boolean }
export type WorkspaceInboxResponse = { workspace: InboxWorkspace; items: InboxItem[]; notices: WorkspaceNotice[] }
