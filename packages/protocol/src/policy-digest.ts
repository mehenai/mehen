import type { PolicyContext, PolicyProposalView } from "./policy-mode.ts"

export type PolicyProposalDigestSource = Pick<PolicyProposalView, "proposal" | "requestedBy" | "requested" | "reason" | "expiresAt"> & {
  context: Pick<PolicyContext, "snapshot" | "slotRevision" | "predecessor">
}

// Only immutable public proposal fields enter the passkey's digest. Member
// requesters have self:false for every viewer; ownership stays server-side.
export function policyProposalDigestInput(view: PolicyProposalDigestSource) {
  return {
    domain: "mehen-policy-proposal/v1",
    proposal: view.proposal,
    requester: view.requestedBy,
    requested: view.requested,
    reason: view.reason,
    snapshot: view.context.snapshot,
    slotRevision: view.context.slotRevision,
    predecessor: view.context.predecessor,
    expiresAt: view.expiresAt,
  }
}
