// Vault answers for mandates, as a machine's own routes give them: the
// device's view carries no signerCurrent, so a fake that adds one stands in
// for a vault that leaked it.

import type { MandateOpenProposal, MandateProposalCreated, MandateReceiptView, MandateView } from "@mehen/protocol/mandate-terms"

const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString()

export function mandateView(extra: Partial<MandateView> = {}): MandateView {
  return {
    id: "mdt_live",
    device: { id: "dev_test", name: "test-machine" },
    signer: { name: "Alex" },
    state: "active",
    rev: 2,
    items: ["github-work", "linear-work"],
    hiddenItems: 0,
    classes: ["change", "read", "send"],
    caps: { read: 5000, change: 2000, send: 50, delete: 0 },
    today: { read: 12, change: 4, send: 3, delete: 0 },
    ttlDays: 30,
    schedule: null,
    note: "Nightly triage of the support inbox",
    createdAt: new Date().toISOString(),
    expiresAt: inDays(30),
    endedReason: null,
    ...extra,
  }
}

export function mandateCreated(origin: string, slug = "mock-space"): MandateProposalCreated {
  return { id: "mdp_new", url: `${origin}/w/${slug}/sign-mandate?proposal=mdp_new`, expiresAt: inDays(7) }
}

// An open proposal as GET /v1/mandates lists it for the machine itself.
export function mandateOpenProposal(origin: string, slug = "mock-space", extra: Partial<MandateOpenProposal> = {}): MandateOpenProposal {
  const id = extra.id ?? "mdp_open"
  return { id, url: `${origin}/w/${slug}/sign-mandate?proposal=${id}`, expiresAt: "2030-01-09T09:00:00.000Z", createdAt: "2030-01-02T09:00:00.000Z", device: { id: "dev_test", name: "test-machine" }, classes: ["change", "read", "send"], items: "all", hiddenItems: 0, reason: "Tickets keep coming", ...extra }
}

export function mandateReceipt(extra: Partial<MandateReceiptView> = {}): MandateReceiptView {
  return { id: "mdu_1", at: new Date().toISOString(), classes: ["read", "send"], method: "POST", credential: { slug: "github-work", host: "api.github.com", entry: "/repos/acme/app/issues", run: null }, ...extra }
}

// With MANDATES off, every mandate route answers as an unknown one does.
export const MANDATES_OFF_BODY = { error: "not_found", message: "No such route." } as const
