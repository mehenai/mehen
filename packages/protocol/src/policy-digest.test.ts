import { expect, test } from "bun:test"
import { policyProposalDigestInput } from "./policy-digest.ts"
import type { PolicyProposalView } from "./policy-mode.ts"

const change: PolicyProposalView["requested"] = { kind: "mode", target: { kind: "item", item: "custom-key" }, selector: { device: "dev_test", session: "supervisor" }, policyMode: "relaxed", scope: { host: "api.example.com", methods: ["GET"], path: "/projects/**", anchorPath: "/projects/tasks", basis: "unreviewed" }, ttlSeconds: 3600, notAfter: null }
const view: PolicyProposalView = {
  proposal: "pol_test", item: "custom-key", status: "pending", bindingCode: "CODE", summary: "Access", expiresAt: "2026-10-26T12:00:00.000Z", outcome: null,
  requestedBy: { member: "mem_creator", self: false }, requestedByViewer: { member: "mem_creator", self: true }, requested: change, reason: "Work on this project.", baseDigest: "base", digest: "digest", diff: [], warnings: [],
  context: { item: "custom-key", selector: change.selector, baseMode: "standard", effectiveMode: "standard", basePolicy: { default: "approve", rules: [] }, floor: [], snapshot: { itemId: "itm_test", device: "dev_test", configRev: 1, scopeRev: 2, protectionRev: 3, safetyDigest: "safety", frozen: false }, baseDigest: "base", slotRevision: 4, predecessor: null, state: { widening: [], observedAt: "2026-10-26T11:00:00.000Z" } },
}
test("proposal digest input is precisely the immutable public wire fields", () => {
  expect(policyProposalDigestInput(view)).toEqual({ domain: "mehen-policy-proposal/v1", proposal: view.proposal, requester: { member: "mem_creator", self: false }, requested: change, reason: view.reason, snapshot: view.context.snapshot, slotRevision: 4, predecessor: null, expiresAt: view.expiresAt })
  expect(policyProposalDigestInput({ ...view, requestedBy: { device: "dev_test", deviceName: "Machine", session: "supervisor" } }).requester).toEqual({ device: "dev_test", deviceName: "Machine", session: "supervisor" })
})
test("view-only state, status, summary and existing digest do not enter the signed input", () => {
  const changed: PolicyProposalView = { ...view, requestedByViewer: { member: "mem_creator", self: false }, status: "approved", bindingCode: "OTHER", summary: "Different", digest: "different", context: { ...view.context, state: { widening: [], observedAt: "later" } } }
  expect(policyProposalDigestInput(changed)).toEqual(policyProposalDigestInput(view))
})
