import { createHash } from "node:crypto"
import { canonicalJson, type NextStep } from "@mehen/protocol/api"
import { hostMatches, restrictivePathMayMeet, type Destination } from "@mehen/protocol/binding"
import { type PolicyFloorView, type PolicySecuritySnapshot } from "@mehen/protocol/policy-mode"
import { POLICY_CATALOGUES } from "@mehen/protocol/policy-catalogue"
import { GENERIC_POLICY_FLOOR_WORDS, POLICY_FLOOR, POLICY_SAFETY_PROFILES, POLICY_SAFETY_VERSION, classifyPolicyRequest, resolvePolicyRequest } from "@mehen/protocol/policy-safety"
import { VaultError } from "../../http.ts"
import { type Area, type DevicePrincipal, type VaultContext, one } from "../core.ts"
import type { ItemRecord, PolicyPermit, PolicyService } from "../services.ts"
import { devicePolicyState } from "./devices.ts"
import { items } from "./items.ts"
import { projects } from "./projects.ts"

import { workspacePolicyOps, WORKSPACE_POLICY_MIGRATION } from "./policy-workspace.ts"
import { RULE_ANCHOR_SWEEP_KEY, WORKSPACE_POLICY_AREA_GRANTS_MIGRATION, WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION, WORKSPACE_POLICY_RULES_MIGRATION, sweepRuleAnchors } from "./policy-rules-workspace.ts"

export const policyHelpNext: NextStep = { command: "mehen policy propose --help", say: "Read the policy proposal options and try again." }
export const exactApprovalNext: NextStep = { say: "Send the exact relay request and ask for a fresh approval instead." }

export function policyDigest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("base64url")
}

// Synchronous metadata keeps the final authority transaction free of awaits.
// The same value as protocol's policySafetyDigest, catalogues included, so a
// catalogue change makes every permit in flight stale.
const SAFETY_DIGEST = policyDigest({ domain: POLICY_SAFETY_VERSION, profiles: POLICY_SAFETY_PROFILES, generic: GENERIC_POLICY_FLOOR_WORDS, catalogues: POLICY_CATALOGUES })
const FLOOR_VIEWS = POLICY_FLOOR.map((entry) => ({ ...entry, ruleDigest: policyDigest({ host: entry.host, action: entry.action, reason: entry.reason, rule: entry.rule }) }))
// The floors a request this item may make can meet: on one of its hosts and,
// when both name paths, on a path its binding admits, read as loosely as the
// relay reads it, so the view never hides a floor the relay applies. A view
// only; the relay applies POLICY_FLOOR itself.
export function itemPolicyFloor(item: ItemRecord): PolicyFloorView[] {
  const bound = item.binding.paths ?? []
  const reaches = (paths: string[] | undefined) => !paths?.length || !bound.length || paths.some((path) => bound.some((b) => restrictivePathMayMeet(path, b)))
  return FLOOR_VIEWS.filter((entry) => item.binding.hosts.some((host) => hostMatches(host, entry.host)) && reaches(entry.rule.paths))
}
export function guardDigest(snapshot: PolicySecuritySnapshot): string {
  return policyDigest({ domain: "mehen-policy-guard/v1", snapshot })
}
export function policyFrozen(ctx: VaultContext): boolean {
  return one(ctx.sql.exec<{ value: string }>("SELECT value FROM tenant_state WHERE key = 'frozen'"))?.value === "1"
}
export function snapshotCurrent(ctx: VaultContext, snapshot: PolicySecuritySnapshot, slug: string): boolean {
  const current = items.getItem(ctx, slug)
  if (!current || current.id !== snapshot.itemId) return false
  const device = devicePolicyState(ctx, snapshot.device)
  return !!device?.active && guardDigest(policy.snapshot(ctx, snapshot.device, current)) === guardDigest(snapshot)
}
// The item's own policy decides, in standard mode: nothing widens it here.
// A standing rule (policy-rules-workspace.ts) is looked up only after this
// holds a request for approval.
export function preparePolicy(ctx: VaultContext, device: DevicePrincipal, item: ItemRecord, destination: Destination, body: Uint8Array | null, contentType: string | null, contentEncoding: string | null): PolicyPermit {
  const snapshot = policy.snapshot(ctx, device.device, item)
  const input = { destination, body, contentType, contentEncoding, policy: item.policy, binding: item.binding }
  const result = resolvePolicyRequest({ ...input, policyMode: "standard", scope: null })
  const classification = classifyPolicyRequest(input)
  return { itemId: item.id, snapshot, guardDigest: guardDigest(snapshot), decision: result.action, reasons: result.reasons, request: { mode: "relay", run: null, item: item.slug, device: device.device, session: device.session, method: destination.method, host: destination.host, routeId: classification.routeId, policyMode: "standard" } }
}
export const policy: PolicyService = {
  snapshot(ctx, deviceId, item) {
    const device = devicePolicyState(ctx, deviceId)
    if (!device?.active) throw new VaultError("forbidden", "This device is not active.", { next: policyHelpNext })
    return { itemId: item.id, device: deviceId, configRev: item.configRev, scopeRev: device.scopeRev, protectionRev: projects.protectionRevision(ctx), safetyDigest: SAFETY_DIGEST, frozen: policyFrozen(ctx) }
  },
  prepare: preparePolicy,
  assertCurrent(ctx, permits) {
    for (const permit of permits) {
      if (permit.snapshot.frozen || !snapshotCurrent(ctx, permit.snapshot, permit.request.item)) throw new VaultError("conflict", "Access changed before authorisation. Ask for a fresh approval.", { next: exactApprovalNext })
    }
  },
  // The audit row keeps the fields it had while widening windows existed:
  // nothing widened this request.
  recordUse(ctx, permits, requestDigest) {
    for (const { request } of permits) ctx.audit({ actor: `device:${request.device}`, action: "relay.allow", target: request.item, detail: { ...request, requestDigest, source: null, parent: null, widened: false } })
  },
}
export const policyArea: Area = {
  name: "policy",
  workspaceOps: workspacePolicyOps,
  // Migrations only ever append: the legacy window tables (policy_window_slots,
  // policy_windows, policy_reviews) stay in the schema, read and written by
  // nothing. policy_proposals holds standing-rule proposals.
  migrations: [`CREATE TABLE policy_window_slots (item TEXT NOT NULL, device TEXT NOT NULL, revision INTEGER NOT NULL, active TEXT, PRIMARY KEY (item, device));
    CREATE TABLE policy_windows (id TEXT PRIMARY KEY, proposal TEXT NOT NULL, item TEXT NOT NULL, slug TEXT NOT NULL, device TEXT NOT NULL, session TEXT, mode TEXT NOT NULL, scope TEXT NOT NULL, snapshot TEXT NOT NULL, guard TEXT NOT NULL, activated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ended TEXT);
    CREATE TABLE policy_proposals (id TEXT PRIMARY KEY, requester TEXT NOT NULL, requested_by TEXT NOT NULL, device_name TEXT NOT NULL, item TEXT NOT NULL, slug TEXT NOT NULL, device TEXT NOT NULL, requested TEXT NOT NULL, reason TEXT NOT NULL, snapshot TEXT NOT NULL, guard TEXT NOT NULL, digest TEXT NOT NULL, code TEXT NOT NULL, slot_revision INTEGER NOT NULL, predecessor TEXT NOT NULL, preview TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_by TEXT, outcome TEXT);
    CREATE UNIQUE INDEX policy_pending_requester ON policy_proposals(requester, item, device) WHERE status = 'pending';
    CREATE TABLE policy_reviews (id TEXT PRIMARY KEY, source TEXT NOT NULL UNIQUE, acknowledged_at INTEGER, acknowledged_by TEXT);`, WORKSPACE_POLICY_MIGRATION, WORKSPACE_POLICY_RULES_MIGRATION, WORKSPACE_POLICY_RULE_ANCHORS_MIGRATION, WORKSPACE_POLICY_AREA_GRANTS_MIGRATION],
  async alarm(ctx, key) {
    if (key === RULE_ANCHOR_SWEEP_KEY) sweepRuleAnchors(ctx)
  },
}
