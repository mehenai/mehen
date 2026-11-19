import { describe, expect, it } from "vitest"
import type { EnvironmentState, InviteTerms, Share, WorkspaceRole, WorkspaceStepUpAction } from "@mehen/protocol"
import { backupScope, can, classify, effectiveAccess, eligibility, fourEyesProjects, environmentChangeIsLoosening, reach, stepUpSatisfies, type AccessAction, type AccessPrincipal, type AccessState, type AccessTarget } from "../src/vault/access.ts"
import { accessMember, workspaceAccessState, WORKSPACE_FULL_SCOPE } from "./workspace-fixtures.ts"
const NOW = 1_800_000_000_000
const roles: WorkspaceRole[] = ["owner", "admin", "member", "guest"]
const scope = { ...WORKSPACE_FULL_SCOPE, tags: ["work"], projects: ["prj_a"] }
const narrow = { ...scope, modes: ["relay"] as ["relay"] }
type MatrixCase = { action: AccessAction; roles: WorkspaceRole[]; stepUp: WorkspaceStepUpAction["type"] | null; machine?: boolean; target?: (role: WorkspaceRole) => AccessTarget }
const terms: InviteTerms = { role: "member", email: "member@example.com", teams: [], shares: [], expiresAt: "2027-12-01T00:00:00.000Z" }
const all = roles
const elevated: WorkspaceRole[] = ["owner", "admin"]
const ownTarget = (role: WorkspaceRole): AccessTarget => ({ member: `mem_${role}`, device: `dev_${role}`, project: "prj_a", environment: "dev", variable: "TOKEN", owningAccount: `acc_${role}`, acceptingAccount: `acc_${role}` })
const matrix: MatrixCase[] = [
 { action: { type: "passkey.add" }, roles: all, stepUp: "passkey.add" },
 { action: { type: "passkey.rename" }, roles: all, stepUp: null },
 { action: { type: "passkey.remove" }, roles: all, stepUp: "passkey.remove" },
 { action: { type: "session.end" }, roles: all, stepUp: null },
 { action: { type: "recovery.generate" }, roles: all, stepUp: "recovery.generate" },
 { action: { type: "identity.link" }, roles: all, stepUp: "identity.link" },
 { action: { type: "identity.unlink" }, roles: all, stepUp: "identity.unlink" },
 { action: { type: "workspace.create" }, roles: ["owner"], stepUp: "workspace.create" },
 { action: { type: "account.delete" }, roles: ["admin", "member", "guest"], stepUp: "account.delete" },
 ...(["workspace.update", "workspace.identity_rule", "workspace.delete", "workspace.delete_cancel", "workspace.unfreeze"] as const).map((type): MatrixCase => ({ action: { type }, roles: ["owner"], stepUp: type })),
 { action: { type: "workspace.freeze" }, roles: ["owner", "admin", "member"], stepUp: null, machine: true },
 { action: { type: "workspace.export" }, roles: elevated, stepUp: null },
 // The approval dial: asking less is signed, asking more is not; never a machine's.
 { action: { type: "workspace.approvals_less" }, roles: elevated, stepUp: "workspace.approvals" },
 { action: { type: "workspace.approvals_more" }, roles: elevated, stepUp: null },
 { action: { type: "member.invite" }, roles: elevated, stepUp: "member.invite", target: () => ({ role: "member" }) },
 { action: { type: "invite.revoke" }, roles: elevated, stepUp: null },
 { action: { type: "member.confirm" }, roles: elevated, stepUp: "member.confirm", target: () => ({ inviteTerms: terms }) },
 { action: { type: "member.role" }, roles: elevated, stepUp: "member.role", target: () => ({ member: "mem_guest", role: "member" }) },
 ...(["member.suspend", "member.reinstate", "member.remove"] as const).map((type): MatrixCase => ({ action: { type }, roles: elevated, stepUp: type, target: () => ({ member: "mem_guest" }) })),
 { action: { type: "member.leave" }, roles: ["admin", "member", "guest"], stepUp: "member.leave", target: ownTarget },
 { action: { type: "account.reset" }, roles: [], stepUp: null },
 { action: { type: "people.read" }, roles: ["owner", "admin", "member"], stepUp: null },
 { action: { type: "member.machines" }, roles: elevated, stepUp: null, target: () => ({ member: "mem_kim" }) },
 { action: { type: "team.update" }, roles: elevated, stepUp: "team.update" },
 { action: { type: "team.members" }, roles: elevated, stepUp: "team.members", target: () => ({ member: "mem_member", team: "tm_engineering" }) },
 { action: { type: "project.create" }, roles: ["owner", "admin", "member"], stepUp: "project.create" },
 { action: { type: "project.init" }, roles: [], stepUp: null, machine: true },
 { action: { type: "project.read" }, roles: all, stepUp: null, machine: true },
 { action: { type: "project.share" }, roles: elevated, stepUp: "project.share", target: () => ({ project: "prj_a", member: "mem_member" }) },
 { action: { type: "environment.update", before: { protected: false, fences: [], fourEyes: false }, after: { protected: true, fences: [], fourEyes: true } }, roles: elevated, stepUp: "item.update" },
 { action: { type: "environment.update", before: { protected: true, fences: [], fourEyes: true }, after: { protected: true, fences: [], fourEyes: false } }, roles: elevated, stepUp: "item.update" },
 { action: { type: "remote.update" }, roles: elevated, stepUp: "item.update" },
 { action: { type: "var.set", before: { kind: "item", item: "itm_workspace", field: "key" }, after: { kind: "plain", value: "ok" } }, roles: all, stepUp: "item.update", machine: true },
 { action: { type: "override.set" }, roles: all, stepUp: "override.set" },
 { action: { type: "run.unprotected" }, roles: [], stepUp: null, machine: true },
 { action: { type: "run.protected" }, roles: [], stepUp: null, machine: true, target: () => ({ project: "prj_a", environment: "prod", variable: "TOKEN" }) },
 { action: { type: "project.delete" }, roles: elevated, stepUp: "project.delete" },
 { action: { type: "credential.create" }, roles: elevated, stepUp: "intake.submit", target: () => ({ destinationHome: { kind: "workspace" } }) },
 { action: { type: "credential.adopt" }, roles: elevated, stepUp: "adoption.approve", target: () => ({ destinationHome: { kind: "workspace" } }) },
 { action: { type: "credential.adopt" }, roles: ["owner", "admin", "member"], stepUp: "adoption.approve", target: (role) => ({ destinationHome: { kind: "member", member: `mem_${role}` } }) },
 { action: { type: "item.read" }, roles: all, stepUp: null, machine: true, target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "item.use", context: { project: "prj_a", environment: "dev" } }, roles: [], stepUp: null, machine: true, target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.rotate" }, roles: elevated, stepUp: "intake.submit", machine: true, target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.restore" }, roles: elevated, stepUp: "item.restore", target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.update" }, roles: elevated, stepUp: "item.update", target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.push" }, roles: elevated, stepUp: "item.push", target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.rehome" }, roles: elevated, stepUp: "item.rehome", target: () => ({ credential: "itm_project", destinationHome: { kind: "workspace" } }) },
 { action: { type: "credential.delete" }, roles: elevated, stepUp: "item.delete", target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "credential.reveal" }, roles: [], stepUp: null },
 { action: { type: "intake.cancel" }, roles: all, stepUp: null, machine: true, target: (role) => ({ device: "dev_member", ask: { device: `dev_${role}`, credential: null, credentials: ["itm_workspace"], context: null } }) },
 { action: { type: "connect.cancel" }, roles: all, stepUp: null, machine: true, target: (role) => ({ device: "dev_member", ask: { device: `dev_${role}`, credential: null, credentials: ["itm_workspace"], context: null } }) },
 { action: { type: "credential.reconnect" }, roles: elevated, stepUp: "connect.start", target: () => ({ credential: "itm_workspace" }) },
 { action: { type: "enrol.accept" }, roles: all, stepUp: "enrol.accept", target: ownTarget },
 { action: { type: "enrol.approve" }, roles: elevated, stepUp: "enrol.approve", target: () => ({ member: "mem_guest", project: "prj_a" }) },
 { action: { type: "enrol.reject" }, roles: all, stepUp: null, target: ownTarget },
 { action: { type: "device.rescope", before: scope, after: narrow }, roles: all, stepUp: "device.rescope", target: ownTarget },
 { action: { type: "device.rescope_accept", before: scope, after: { ...scope, privateCredentials: true } }, roles: all, stepUp: "device.rescope_accept", target: ownTarget },
 { action: { type: "device.revoke" }, roles: all, stepUp: "device.revoke", target: ownTarget },
 { action: { type: "device.self_revoke" }, roles: [], stepUp: null, machine: true, target: () => ({ device: "dev_member" }) },
 { action: { type: "devices.read" }, roles: all, stepUp: null },
 { action: { type: "device.transfer" }, roles: [], stepUp: null },
 { action: { type: "approval.approve" }, roles: ["member"], stepUp: "approval.decide", target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "approval.deny" }, roles: ["owner", "admin", "member"], stepUp: "approval.decide", target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "policy.approve" }, roles: ["member"], stepUp: "policy.decide", target: () => ({ credential: "itm_member", ask: { device: "dev_member", credential: "itm_member", credentials: ["itm_member"], context: null } }) },
 { action: { type: "policy.rule.approve" }, roles: ["member"], stepUp: "policy.decide", target: () => ({ credential: "itm_member", ask: { device: "dev_member", credential: "itm_member", credentials: ["itm_member"], context: null } }) },
 { action: { type: "policy.cosign" }, roles: elevated, stepUp: "policy.decide", target: () => ({ credential: "itm_workspace", ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "policy.cosigner_revoke" }, roles: elevated, stepUp: null, target: () => ({ credential: "itm_workspace", ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "policy.deny" }, roles: ["owner", "admin", "member"], stepUp: "policy.decide", target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "policy.stop" }, roles: ["owner", "admin", "member"], stepUp: null, machine: true, target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "policy.acknowledge" }, roles: ["owner", "admin", "member"], stepUp: null, target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "audit.read" }, roles: all, stepUp: null },
 { action: { type: "asks.read" }, roles: all, stepUp: null },
 { action: { type: "approval.read" }, roles: ["owner", "admin", "member"], stepUp: null, target: () => ({ ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } } }) },
 { action: { type: "backup.recipient_add" }, roles: ["owner"], stepUp: "backup.recipient_add" },
 { action: { type: "backup.recipient_remove" }, roles: ["owner"], stepUp: "backup.recipient_remove", target: () => ({ member: "mem_owner" }) },
 { action: { type: "backup.export" }, roles: ["owner"], stepUp: null, target: () => ({ member: "mem_owner" }) },
 { action: { type: "backup.read" }, roles: ["owner", "admin", "member"], stepUp: null, machine: true },
]
function state(): AccessState {
 const s = workspaceAccessState(NOW)
 // Private policy tests require an explicitly accepted private tick.
 const d = s.devices.find((d) => d.id === "dev_member")
 if (d) d.scope.privateCredentials = true
 return s
}
describe("every 4.6 matrix row, required step-up kind and Machine column", () => {
 for (const [i, row] of matrix.entries()) it(`${i + 1}: ${row.action.type}`, () => {
  const s = state()
  if (row.action.type === "member.reinstate") s.members.find((m) => m.id === "mem_guest")!.status = "suspended"
  if (row.action.type === "environment.update") Object.assign(s.projects[0]!.environments[0]!, row.action.before)
  if (row.action.type === "device.rescope" || row.action.type === "device.rescope_accept") for (const d of s.devices) d.scope = structuredClone(row.action.before)
  for (const role of roles) {
   const target = row.target?.(role) ?? { project: "prj_a", environment: "dev", variable: "TOKEN" }
   const result = can(s, accessMember(s, role), row.action, target, NOW)
   expect(result.allowed, `${role}: ${JSON.stringify(result)}`).toBe(row.roles.includes(role))
   if (result.allowed) {
    expect(result.stepUp).toBe(row.stepUp)
    expect(stepUpSatisfies(result, null)).toBe(row.stepUp === null)
    expect(stepUpSatisfies(result, { type: "workspace.unfreeze" })).toBe(row.stepUp === null || row.stepUp === "workspace.unfreeze")
   } else expect(stepUpSatisfies(result, { type: "workspace.unfreeze" })).toBe(false)
  }
  const target = row.target?.("member") ?? { project: "prj_a", environment: "dev", variable: "TOKEN" }
  const machine = can(s, { kind: "device", deviceId: "dev_member" }, row.action, target, NOW)
  expect(machine.allowed, JSON.stringify(machine)).toBe(row.machine === true)
  if (machine.allowed) expect(machine.stepUp).toBeNull()
 })
})
it("restores a kept value only with the rotation right and the right to change every protected environment that uses it", () => {
 const s = state()
 expect(check(s, "kim", { type: "credential.restore" }, { credential: "itm_project" })).toEqual({ allowed: true, stepUp: "item.restore" })
 s.projects.find((p) => p.id === "prj_b")!.environments.find((e) => e.name === "prod")!.references.push({ variable: "TOKEN", field: "key", item: "itm_project", home: { kind: "project", project: "prj_a" }, revision: 1 })
 expect(check(s, "kim", { type: "credential.rotate" }, { credential: "itm_project" })).toEqual({ allowed: true, stepUp: "intake.submit" })
 expect(check(s, "kim", { type: "credential.restore" }, { credential: "itm_project" })).toMatchObject({ allowed: false, error: "forbidden", message: "A protected environment uses this credential, and you may not change it." })
 expect(check(s, "admin", { type: "credential.restore" }, { credential: "itm_project" })).toEqual({ allowed: true, stepUp: "item.restore" })
 expect(can(s, { kind: "device", deviceId: "dev_member" }, { type: "credential.restore" }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
})
it("classes asking more often as narrow and asking less as a widening", () => {
 expect(classify(state(), { type: "workspace.approvals_more" }, {})).toBe("narrow")
 expect(classify(state(), { type: "workspace.approvals_less" }, {})).toBe("widen")
})
it("classes a co-signer ending a rule as narrow", () => {
 expect(classify(state(), { type: "policy.cosigner_revoke" }, { credential: "itm_workspace" })).toBe("narrow")
})
function share(project: string, member: string, level: Share["level"], tick = false): Share { return { id: `${project}-${member}`, project, subject: { kind: "member", member }, level, protected: tick, expiresAt: null } }
function check(s: AccessState, who: string, action: AccessAction, target: AccessTarget) { return can(s, accessMember(s, who), action, target, NOW) }
describe("capability sets and owner ceilings", () => {
 it("unions capabilities, never max-level plus OR of ticks, in either order and with independent expiry", () => {
  const s = state()
  for (const reverse of [false, true]) {
   if (reverse) s.shares.reverse()
   expect(effectiveAccess(s, { kind: "member", id: "mem_member" }, "prj_a", NOW)).toMatchObject({ level: "edit", runProtected: true, editProtected: false })
   expect(check(s, "member", { type: "var.set", before: null, after: { kind: "plain", value: "x" } }, { project: "prj_a", environment: "prod", variable: "TOKEN" }).allowed).toBe(false)
  }
  const team = s.shares.find((s) => s.id === "shr_team")
  if (!team) throw new Error("fixture share missing")
  team.expiresAt = new Date(NOW).toISOString()
  expect(effectiveAccess(s, { kind: "member", id: "mem_member" }, "prj_a", NOW)).toMatchObject({ level: "edit", runProtected: false, editProtected: false })
  team.expiresAt = null
  const direct = s.shares.find((s) => s.id === "shr_direct")
  if (direct) direct.expiresAt = new Date(NOW - 1).toISOString()
  expect(effectiveAccess(s, { kind: "member", id: "mem_member" }, "prj_a", NOW)).toMatchObject({ level: "use", runProtected: true, editProtected: false })
 })
 it("team has no implicit workspace/private use; only the exact authorised context reference grants use", () => {
  const s = state()
  const device: AccessPrincipal = { kind: "device", deviceId: "dev_service" }
  const use: AccessAction = { type: "item.use", context: null }
  expect(can(s, device, use, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
  expect(can(s, device, { ...use, context: { project: "prj_a", environment: "dev" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
  expect(can(s, device, { ...use, context: { project: "prj_b", environment: "dev" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
  expect(can(s, device, use, { credential: "itm_member" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
  const p = s.projects.find((p) => p.id === "prj_a")
  if (p) p.environments[0]!.references = []
  expect(can(s, device, { ...use, context: { project: "prj_a", environment: "dev" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
 })
 it("unticked private metadata and use refuse identically to absent; a tick cannot reach another owner", () => {
  const s = state()
  const d = s.devices.find((d) => d.id === "dev_member")!
  d.scope.privateCredentials = false
  for (const type of ["item.read", "item.use"] as const) {
   expect(can(s, { kind: "device", deviceId: d.id }, type === "item.use" ? { type, context: null } : { type }, { credential: "itm_member" }, NOW)).toEqual(can(s, { kind: "device", deviceId: d.id }, type === "item.use" ? { type, context: null } : { type }, { credential: "absent" }, NOW))
  }
  d.scope.privateCredentials = true
  expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.use", context: null }, { credential: "itm_member" }, NOW).allowed).toBe(true)
  expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.read" }, { credential: "itm_guest" }, NOW).allowed).toBe(false)
 })
 it("machines are capped by their live owner's status, shares, tags, modes and project/environment ceiling", () => {
  const s = state()
  const d = s.devices.find((d) => d.id === "dev_member")!
  const p: AccessPrincipal = { kind: "device", deviceId: d.id }
  const target = { project: "prj_a", environment: "prod", variable: "TOKEN" }
  expect(can(s, p, { type: "run.protected" }, target, NOW).allowed).toBe(true)
  d.scope.maxEnvironment = "unprotected"
  expect(can(s, p, { type: "run.protected" }, target, NOW).allowed).toBe(false)
  d.scope.projects = ["prj_b"]
  expect(reach(s, d, NOW).projects.prj_a).toBeUndefined()
  d.scope.projects = []
  d.scope.tags = ["other"]
  expect(can(s, p, { type: "item.read" }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
  d.scope.tags = []
  d.scope.modes = ["relay"]
  expect(can(s, p, { type: "item.use", context: null }, { credential: "itm_workspace", mode: "lease" }, NOW).allowed).toBe(false)
  s.members.find((m) => m.id === "mem_member")!.status = "removed"
  expect(reach(s, d, NOW).ownerActive).toBe(false)
  expect(can(s, p, { type: "project.read" }, target, NOW)).toMatchObject({ allowed: false, error: "owner_inactive" })
 })
 it("release one does not continuously Google-gate machines, even when the owner's human session needs verification", () => {
  const s = state()
  const m = s.members.find((m) => m.id === "mem_member")!
  m.standing.identityGate = { covered: true, admitted: false, checkedAt: NOW - 86400000 }
  expect(check(s, "member", { type: "project.read" }, { project: "prj_a" })).toMatchObject({ allowed: false, error: "identity_required" })
  expect(can(s, { kind: "device", deviceId: "dev_member" }, { type: "item.use", context: null }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
 })
 it("pendingRole never grants authority; guests never get team sources or freeze/init", () => {
  const s = state()
  s.members.find((m) => m.id === "mem_guest")!.standing.pendingRole = "owner"
  s.teams[0]!.members.push("mem_guest")
  expect(check(s, "guest", { type: "workspace.update" }, {}).allowed).toBe(false)
  expect(effectiveAccess(s, { kind: "member", id: "mem_guest" }, "prj_b", NOW).level).toBeNull()
  for (const id of ["dev_guest", "dev_service"]) expect(can(s, { kind: "device", deviceId: id }, { type: "project.init" }, {}, NOW).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_guest" }, { type: "workspace.freeze" }, {}, NOW).allowed).toBe(false)
 })
})
describe("protected reference graph and four-eyes (RS2-01)", () => {
 function graph() {
  const s = state()
  for (const p of s.projects) {
   const prod = p.environments.find((e) => e.name === "prod")!
   prod.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 3 }]
   prod.fourEyes = true
  }
  return s
 }
 it("Kim's member-created project cannot point protected variables at workspace credentials", () => {
  const s = graph()
  const a: AccessAction = { type: "var.set", before: null, after: { kind: "item", item: "itm_workspace", field: "key" } }
  for (const role of ["kim", "member", "guest"]) expect(check(s, role, a, { project: "prj_a", environment: "prod", variable: "NEW_TOKEN" }).allowed).toBe(false)
  for (const role of elevated) expect(check(s, role, a, { project: "prj_a", environment: "prod", variable: "NEW_TOKEN" }).allowed).toBe(true)
  expect(check(s, "kim", { ...a, after: { kind: "item", item: "itm_project", field: "key" } }, { project: "prj_a", environment: "prod", variable: "NEW_TOKEN" }).allowed).toBe(true)
 })
 it("contextless, dev and non-referencing protected contexts refuse before capability use", () => {
  const s = graph()
  for (const context of [undefined, { project: "prj_a", environment: "dev", variable: "TOKEN" }, { project: "prj_a", environment: "staging", variable: "TOKEN" }]) expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "item.use", context: context ?? null }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "item.use", context: { project: "prj_a", environment: "prod" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
 })
 it("B-only manager refuses, manager of both succeeds, Kim never self-approves", () => {
  const s = graph()
  s.shares.push(share("prj_b", "mem_member", "manage"))
  const ask = { device: "dev_kim", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "prod" } }
  expect(eligibility(s, "mem_member", ask, NOW).canApprove).toBe(false)
  expect(eligibility(s, "mem_kim", ask, NOW).canApprove).toBe(false)
  s.shares.push(share("prj_a", "mem_member", "manage"))
  expect(eligibility(s, "mem_member", ask, NOW)).toMatchObject({ canApprove: true, canReadAskDetail: true })
  for (const role of elevated) expect(eligibility(s, `mem_${role}`, ask, NOW).canApprove).toBe(true)
 })
 it("guest/service-shared unprotected workspace delegation is owner/admin-only", () => {
  const s = state()
  const a: AccessAction = { type: "var.set", before: null, after: { kind: "item", item: "itm_workspace", field: "key" } }
  expect(check(s, "kim", a, { project: "prj_a", environment: "dev", variable: "NEW_TOKEN" }).allowed).toBe(false)
  for (const role of elevated) expect(check(s, role, a, { project: "prj_a", environment: "dev", variable: "NEW_TOKEN" }).allowed).toBe(true)
  s.shares = s.shares.filter((s) => s.id !== "shr_guest" && s.id !== "shr_service")
  expect(check(s, "kim", a, { project: "prj_a", environment: "dev", variable: "NEW_TOKEN" }).allowed).toBe(true)
 })
 it("a member manager cannot give a team with a machine a project that uses a workspace credential, but can take it away", () => {
  const s = state()
  s.shares = s.shares.filter((s) => s.id !== "shr_guest" && s.id !== "shr_service")
  const target = { project: "prj_a", team: "tm_service" }
  const terms = { level: "use" as const, protected: false, expiresAt: null }
  const giving: AccessAction = { type: "project.share", after: terms }
  expect(check(s, "kim", giving, target)).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can share project-a with a team that has a machine: it uses workspace credentials." } })
  expect(check(s, "kim", { type: "project.share" }, target).allowed).toBe(false)
  for (const role of elevated) expect(check(s, role, giving, target).allowed).toBe(true)
  s.shares.push({ id: "shr_service", project: "prj_a", subject: { kind: "team", team: "tm_service" }, level: "edit", protected: false, expiresAt: null })
  expect(check(s, "kim", { type: "project.share", after: { ...terms, level: "manage" } }, target).allowed).toBe(false)
  expect(check(s, "kim", { type: "project.share", after: null }, target).allowed).toBe(true)
  // A team with no machine, or a project with no workspace credential, is the manager's to share.
  expect(check(s, "kim", giving, { project: "prj_a", team: "tm_engineering" }).allowed).toBe(true)
  for (const e of s.projects[0]!.environments) e.references = e.references.filter((r) => r.home.kind !== "workspace")
  expect(check(s, "kim", giving, target).allowed).toBe(true)
 })
 it("a member manager may narrow a team with a machine's share where removing it is allowed, never widen it", () => {
  const s = state()
  s.shares = s.shares.filter((s) => s.id !== "shr_guest" && s.id !== "shr_service")
  const target = { project: "prj_a", team: "tm_service" }
  const hours = (n: number) => new Date(NOW + n * 3_600_000).toISOString()
  const current: Share = { id: "shr_service", project: "prj_a", subject: { kind: "team", team: "tm_service" }, level: "edit", protected: true, expiresAt: hours(2) }
  s.shares.push(current)
  const change = (terms: Partial<Share>) => check(s, "kim", { type: "project.share", after: { level: current.level, protected: current.protected, expiresAt: current.expiresAt, ...terms } }, target)
  const narrower: Partial<Share>[] = [{}, { level: "use" }, { protected: false }, { expiresAt: hours(1) }, { level: "use", protected: false, expiresAt: hours(1) }]
  for (const terms of narrower) expect(change(terms), JSON.stringify(terms)).toEqual({ allowed: true, stepUp: "project.share" })
  const wider: Partial<Share>[] = [{ level: "manage" }, { expiresAt: null }, { expiresAt: hours(3) }, { level: "use", expiresAt: null }, { expiresAt: "not a date" }]
  for (const terms of wider) expect(change(terms), JSON.stringify(terms)).toMatchObject({ allowed: false, error: "forbidden", next: { say: expect.stringContaining("Only an owner or admin") } })
  expect(check(s, "kim", { type: "project.share" }, target).allowed).toBe(false)
  current.protected = false
  expect(change({ protected: true }).allowed).toBe(false)
  expect(change({ level: "use" }).allowed).toBe(true)
  current.level = "manage"
  expect(change({ level: "edit", protected: true }).allowed).toBe(true)
  // An ended share has nothing left to narrow.
  current.expiresAt = hours(-1)
  expect(change({ level: "use" }).allowed).toBe(false)
  expect(check(s, "kim", { type: "project.share", after: null }, target).allowed).toBe(true)
 })
 it("a member manager may give a team with a machine a share that never reaches the protected environment where alone a workspace credential is used", () => {
  const s = state()
  s.shares = s.shares.filter((s) => s.id !== "shr_guest" && s.id !== "shr_service")
  const [dev, prod] = s.projects[0]!.environments
  dev!.references = []
  prod!.references = [{ variable: "OPENAI_KEY", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 1 }]
  const target = { project: "prj_a", team: "tm_service" }
  const unprotected = { level: "use" as const, protected: false, expiresAt: null }
  expect(check(s, "kim", { type: "project.share", after: unprotected }, target)).toEqual({ allowed: true, stepUp: "project.share" })
  expect(check(s, "kim", { type: "project.share", after: { ...unprotected, level: "edit" } }, target).allowed).toBe(true)
  expect(check(s, "kim", { type: "project.share", after: { ...unprotected, protected: true } }, target).allowed).toBe(false)
  expect(check(s, "kim", { type: "project.share", after: { ...unprotected, level: "manage" } }, target).allowed).toBe(false)
  expect(check(s, "kim", { type: "project.share" }, target).allowed).toBe(false)
  s.shares.push({ id: "shr_service", project: "prj_a", subject: { kind: "team", team: "tm_service" }, level: "manage", protected: true, expiresAt: null })
  expect(check(s, "kim", { type: "project.share", after: null }, target).allowed).toBe(true)
 })
 it("every approval result implies readable detail, while private denial never does", () => {
  const s = graph()
  for (const m of s.members) for (const d of s.devices) for (const c of s.credentials) {
   const e = eligibility(s, m.id, { device: d.id, credential: c.id, credentials: [c.id], context: { project: "prj_a", environment: "prod" } }, NOW)
   expect(!e.canApprove || e.canReadAskDetail).toBe(true)
  }
  expect(eligibility(s, "mem_admin", { device: "dev_member", credential: "itm_member", credentials: ["itm_member"], context: null }, NOW)).toMatchObject({ canApprove: false, canDeny: true, canReadAskDetail: false })
 })
})
describe("question 5 and final fence decision", () => {
 const before: EnvironmentState = { protected: true, fences: ["old.example.test"], fourEyes: true }
 const loosenings: EnvironmentState[] = [{ ...before, protected: false }, { ...before, fourEyes: false }, { ...before, fences: [] }, { ...before, fences: ["new.example.test"] }]
 it("any loosening wins over simultaneous tightening; restricted classification remains widening", () => {
  for (const after of loosenings) {
   expect(environmentChangeIsLoosening(before, after)).toBe(true)
   expect(classify(state(), { type: "environment.update", before, after }, {})).toBe("widen")
  }
  expect(environmentChangeIsLoosening({ protected: false, fourEyes: false, fences: [] }, before)).toBe(false)
 })
 it("a member manager cannot loosen workspace references; owner/admin can", () => {
  const s = state()
  const env = s.projects[0]!.environments.find((e) => e.name === "staging")!
  env.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 1 }]
  Object.assign(env, before)
  for (const after of loosenings) {
   const action: AccessAction = { type: "environment.update", before, after }
   expect(check(s, "kim", action, { project: "prj_a", environment: "staging", variable: "TOKEN" })).toMatchObject({ allowed: false, error: "forbidden", next: { say: "Only an owner or admin can loosen project-a/staging: it uses workspace credentials." } })
   for (const role of elevated) expect(check(s, role, action, { project: "prj_a", environment: "staging", variable: "TOKEN" }).allowed).toBe(true)
  }
 })
 it("only-project managers can loosen non-fence protection, but all fence additions/removals require owner/admin", () => {
  const s = state()
  const env = s.projects[0]!.environments.find((e) => e.name === "staging")!
  env.references = [{ variable: "TOKEN", field: "key", item: "itm_project", home: { kind: "project", project: "prj_a" }, revision: 1 }]
  Object.assign(env, before)
  for (const after of [{ ...before, protected: false }, { ...before, fourEyes: false }]) expect(check(s, "kim", { type: "environment.update", before, after }, { project: "prj_a", environment: "staging", variable: "TOKEN" }).allowed).toBe(true)
  for (const after of [{ ...before, fences: [] }, { ...before, fences: ["old.example.test", "added.example.test"] }]) {
   expect(check(s, "kim", { type: "environment.update", before, after }, { project: "prj_a", environment: "staging", variable: "TOKEN" }).allowed).toBe(false)
   for (const role of elevated) expect(check(s, role, { type: "environment.update", before, after }, { project: "prj_a", environment: "staging", variable: "TOKEN" }).allowed).toBe(true)
  }
 })
 it("nobody can unprotect prod/production, before role checks", () => {
  const s = state()
  s.projects[0]!.environments.push({ ...structuredClone(s.projects[0]!.environments[1]!), name: "production" })
  for (const role of roles) for (const environment of ["prod", "production"]) expect(check(s, role, { type: "environment.update", before, after: { ...before, protected: false } }, { project: "prj_a", environment })).toMatchObject({ allowed: false, error: "bad_request" })
 })
 it("removing/repointing protected workspace references and deleting their project need owner/admin", () => {
  const s = state()
  const env = s.projects[0]!.environments.find((e) => e.name === "prod")!
  env.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 2 }]
  const before = { kind: "item" as const, item: "itm_workspace", field: "key" }
  for (const action of [{ type: "var.set", before, after: null }, { type: "var.set", before, after: { kind: "item", item: "itm_project", field: "key" } }, { type: "project.delete" }] satisfies AccessAction[]) {
   expect(check(s, "kim", action, { project: "prj_a", environment: "prod", variable: "TOKEN" })).toMatchObject({ allowed: false, error: "forbidden" })
   for (const role of elevated) expect(check(s, role, action, { project: "prj_a", environment: "prod", variable: "TOKEN" }).allowed).toBe(true)
  }
 })
})
describe("account security safe list, gates, acceptance and lifecycle", () => {
 it("pending/restricted refuse widening/approval but preserve read/narrow/freeze/deny/revoke", () => {
  for (const pending of [true, false]) {
   const s = state()
   const member = s.members.find((m) => m.id === "mem_member")!
   s.devices.find((d) => d.id === "dev_member")!.scope = structuredClone(scope)
   member.standing.transitionPending = pending
   member.standing.restriction = pending ? null : { reason: "recovery", until: NOW + 1, notice: "n" }
   for (const action of [{ type: "project.create" }, { type: "approval.approve" }] satisfies AccessAction[]) expect(check(s, "member", action, { ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } }).allowed).toBe(false)
   for (const action of [{ type: "project.read" }, { type: "workspace.freeze" }, { type: "device.rescope", before: scope, after: narrow }, { type: "device.revoke" }, { type: "approval.deny" }] satisfies AccessAction[]) expect(check(s, "member", action, { project: "prj_a", device: "dev_member", ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } }).allowed).toBe(true)
   expect(classify(s, { type: "device.rescope", before: scope, after: { ...scope, tags: [] } }, { device: "dev_member" })).toBe("widen")
  }
 })
 it("covered human widening needs evidence under twelve hours; ordinary reads do not re-gate with age", () => {
  const s = state()
  const m = s.members.find((m) => m.id === "mem_member")!
  m.standing.identityGate = { covered: true, admitted: true, checkedAt: NOW - 43_200_000 }
  expect(check(s, "member", { type: "project.create" }, {})).toMatchObject({ allowed: false, error: "identity_required" })
  expect(check(s, "member", { type: "project.read" }, { project: "prj_a" }).allowed).toBe(true)
  m.standing.identityGate.checkedAt = NOW - 43_200_000 + 1
  expect(check(s, "member", { type: "project.create" }, {}).allowed).toBe(true)
 })
 it("no admin-sponsored identity, acceptance/admission substitution or transfer", () => {
  const s = state()
  expect(check(s, "admin", { type: "enrol.accept" }, { owningAccount: "acc_member", acceptingAccount: "acc_member" }).allowed).toBe(false)
  expect(check(s, "member", { type: "enrol.accept" }, { owningAccount: "acc_member", acceptingAccount: "acc_member" })).toMatchObject({ allowed: true, stepUp: "enrol.accept" })
  expect(stepUpSatisfies({ allowed: true, stepUp: "enrol.accept" }, { type: "enrol.approve", enrolment: "e", digest: "d", owner: { kind: "member", member: "mem_member", name: "M" }, admissionRole: "admin" })).toBe(false)
  expect(check(s, "owner", { type: "device.transfer" }, {}).allowed).toBe(false)
 })
 it("owner actions, last-owner guard and guest/team membership constraints hold", () => {
  const s = state()
  expect(check(s, "admin", { type: "member.invite" }, { role: "owner" }).allowed).toBe(false)
  expect(check(s, "admin", { type: "member.confirm" }, { inviteTerms: { ...terms, role: "owner" } }).allowed).toBe(false)
  expect(check(s, "owner", { type: "member.leave" }, { member: "mem_owner" }).allowed).toBe(false)
  expect(check(s, "owner", { type: "team.members" }, { member: "mem_guest" }).allowed).toBe(false)
  expect(check(s, "member", { type: "invite.revoke" }, { creator: "mem_member" }).allowed).toBe(true)
 })
 it("private credentials belong to their owner, even guests; purging is the only admin exception", () => {
  const s = state()
  for (const role of roles) {
   const target = { credential: `itm_${role}` }
   for (const type of ["item.read", "credential.rotate", "credential.update", "credential.delete"] as const) expect(check(s, role, { type }, target).allowed).toBe(true)
   expect(check(s, role, { type: "credential.create" }, { destinationHome: { kind: "member", member: `mem_${role}` } }).allowed).toBe(true)
  }
  expect(check(s, "admin", { type: "item.read" }, { credential: "itm_member" })).toMatchObject({ allowed: false, error: "not_found" })
  expect(check(s, "admin", { type: "credential.delete" }, { credential: "itm_member" }).allowed).toBe(true)
  expect(check(s, "guest", { type: "credential.rehome" }, { credential: "itm_guest", destinationHome: { kind: "project", project: "prj_a" } }).allowed).toBe(true)
 })
})

describe("live before is authority; action.before is only an expected-value check", () => {
 it("a forged project-source before never bypasses protected workspace-reference ownership", () => {
  const s = state()
  const env = s.projects[0]!.environments.find((e) => e.name === "prod")!
  env.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 7 }]
  const action: AccessAction = { type: "var.set", before: { kind: "item", item: "itm_project", field: "key" }, after: null }
  const target = { project: "prj_a", environment: "prod", variable: "TOKEN" }
  expect(check(s, "kim", action, target)).toMatchObject({ allowed: false, error: "forbidden" })
  const owner = check(s, "owner", action, target)
  expect(owner).toMatchObject({ allowed: false, error: "conflict", next: { say: "Reload this page and review the change again." } })
  expect(JSON.stringify(owner)).not.toContain("itm_workspace")
 })
 it("forged scope before cannot turn a live widening into narrowing", () => {
  const s = state()
  s.devices.find((d) => d.id === "dev_member")!.scope = structuredClone(scope)
  const action: AccessAction = { type: "device.rescope", before: { ...scope, tags: [] }, after: { ...scope, tags: ["work", "extra"] } }
  expect(classify(s, action, { device: "dev_member" })).toBe("widen")
  expect(check(s, "member", action, { device: "dev_member" }).allowed).toBe(false)
  const stale: AccessAction = { type: "device.rescope", before: { ...scope, tags: ["wrong"] }, after: narrow }
  const result = check(s, "owner", stale, { device: "dev_member" })
  expect(result).toMatchObject({ allowed: false, error: "conflict" })
  expect(JSON.stringify(result)).not.toContain("work")
  expect(check(s, "guest", stale, { device: "dev_member" })).toMatchObject({ allowed: false, error: "not_found" })
 })
 it("live protection, not forged environment before, controls loosening; hidden variables never return conflict", () => {
  const s = state()
  const env = s.projects[0]!.environments.find((e) => e.name === "staging")!
  env.references = [{ variable: "TOKEN", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 7 }]
  const action: AccessAction = { type: "environment.update", before: { protected: false, fences: [], fourEyes: false }, after: { protected: false, fences: [], fourEyes: false } }
  expect(check(s, "kim", action, { project: "prj_a", environment: "staging" })).toMatchObject({ allowed: false, error: "forbidden" })
  expect(check(s, "member", { type: "var.set", before: { kind: "item", item: "guess", field: "key" }, after: null }, { project: "prj_b", environment: "dev", variable: "TOKEN" })).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 })
 it("invalid expiry fails closed and visible deciders never become a guest people directory", () => {
  const s = state()
  for (const grant of s.shares) if (grant.subject.kind === "member" && grant.subject.member === "mem_member" || grant.subject.kind === "team" && grant.subject.team === "tm_engineering") grant.expiresAt = "not-a-date"
  expect(effectiveAccess(s, { kind: "member", id: "mem_member" }, "prj_a", NOW).level).toBeNull()
  const privateAsk = { device: "dev_member", credential: "itm_member", credentials: ["itm_member"], context: null }
  expect(eligibility(s, "mem_member", privateAsk, NOW).deciders).toEqual(["member"])
  expect(eligibility(s, "mem_admin", privateAsk, NOW).deciders).toEqual([])
  const guestAsk = { device: "dev_guest", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "dev" } }
  expect(eligibility(s, "mem_guest", guestAsk, NOW).deciders).toEqual([])
 })
 it("machine request admission is capped at the owner's current create right, and fill rechecks its own right", () => {
  const s = state()
  const device = (id: string): AccessPrincipal => ({ kind: "device", deviceId: id })
  expect(can(s, device("dev_service"), { type: "credential.create" }, { destinationHome: { kind: "workspace" } }, NOW).allowed).toBe(false)
  expect(can(s, device("dev_member"), { type: "credential.create" }, { destinationHome: { kind: "workspace" } }, NOW).allowed).toBe(false)
  expect(can(s, device("dev_owner"), { type: "credential.create" }, { destinationHome: { kind: "workspace" } }, NOW)).toEqual({ allowed: true, stepUp: null })
  s.shares.find((s) => s.id === "shr_guest")!.level = "use"
  expect(can(s, device("dev_guest"), { type: "credential.create" }, { destinationHome: { kind: "project", project: "prj_a" } }, NOW).allowed).toBe(false)
  expect(can(s, device("dev_member"), { type: "credential.create" }, { destinationHome: { kind: "project", project: "prj_a" } }, NOW).allowed).toBe(true)
  const guestHome = { destinationHome: { kind: "member" as const, member: "mem_guest" } }
  // Its own owner's home without the tick is refused forbidden, saying why;
  // another member's home stays absent, ticked or not.
  expect(can(s, device("dev_guest"), { type: "credential.create" }, guestHome, NOW)).toMatchObject({ allowed: false, error: "forbidden", message: expect.stringContaining("without private credentials"), next: { say: expect.stringContaining("under Machines") } })
  expect(can(s, device("dev_guest"), { type: "credential.create" }, { destinationHome: { kind: "member", member: "mem_member" } }, NOW)).toEqual({ allowed: false, error: "not_found", message: "No such object." })
  s.devices.find((d) => d.id === "dev_guest")!.scope.privateCredentials = true
  expect(can(s, device("dev_guest"), { type: "credential.create" }, guestHome, NOW).allowed).toBe(true)
  expect(can(s, device("dev_guest"), { type: "credential.create" }, { destinationHome: { kind: "member", member: "mem_member" } }, NOW)).toEqual({ allowed: false, error: "not_found", message: "No such object." })
  s.devices.find((d) => d.id === "dev_guest")!.scope.privateCredentials = false
  // An admitted request never lets a guest fill another person's home.
  expect(check(s, "guest", { type: "credential.create" }, { destinationHome: { kind: "member", member: "mem_member" } }).allowed).toBe(false)
 })
})

it("only supplied stable run ids get the project_unshared occupancy bit; guest next names nobody", () => {
 const s = state()
 const member: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
 expect(can(s, member, { type: "project.read" }, { project: "prj_b" }, NOW)).toEqual(can(s, member, { type: "project.read" }, { project: "prj_unknown" }, NOW))
 for (const action of [{ type: "run.unprotected" }, { type: "run.protected" }] satisfies AccessAction[]) {
  expect(can(s, member, action, { project: "prj_b", environment: "dev" }, NOW)).toMatchObject({ allowed: false, error: "project_unshared" })
  expect(can(s, member, action, { project: "hidden-slug", environment: "dev" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
  expect(can(s, member, action, { project: "prj_unknown", environment: "dev" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 }
 for (const m of s.members) m.name = `Person ${m.id}`
 const guest = can(s, { kind: "device", deviceId: "dev_guest" }, { type: "run.unprotected" }, { project: "prj_b", environment: "dev" }, NOW)
 expect(guest).toMatchObject({ allowed: false, error: "project_unshared", next: { say: "Ask the person who invited you to share this project" } })
 for (const m of s.members) expect(JSON.stringify(guest)).not.toContain(m.name)
})

it("run approval rechecks the requester's live share and both project/protected scope ceilings", () => {
 const s = state()
 const ask = { device: "dev_service", credential: null, credentials: ["itm_project"], context: { project: "prj_a", environment: "prod" } }
 s.shares.find((s) => s.id === "shr_service")!.protected = true
 expect(eligibility(s, "mem_admin", ask, NOW).canApprove).toBe(true)
 const d = s.devices.find((d) => d.id === "dev_service")!
 d.scope.projects = ["prj_b"]
 expect(eligibility(s, "mem_admin", ask, NOW).canApprove).toBe(false)
 d.scope.projects = []
 d.scope.maxEnvironment = "unprotected"
 expect(eligibility(s, "mem_admin", ask, NOW).canApprove).toBe(false)
 d.scope.maxEnvironment = "protected"
 s.shares.find((s) => s.id === "shr_service")!.protected = false
 expect(eligibility(s, "mem_admin", ask, NOW).canApprove).toBe(false)
 s.shares.find((s) => s.id === "shr_service")!.protected = true
 s.shares.find((s) => s.id === "shr_service")!.expiresAt = new Date(NOW).toISOString()
 expect(eligibility(s, "mem_admin", ask, NOW).canApprove).toBe(false)
})
it("protected metadata stays visible without runnable protected scope, while protected use refuses explicitly", () => {
 const s = state()
 const d = s.devices.find((d) => d.id === "dev_owner")!
 d.scope.maxEnvironment = "unprotected"
 expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.read" }, { credential: "itm_project" }, NOW).allowed).toBe(true)
 expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.use", context: null }, { credential: "itm_project" }, NOW)).toMatchObject({ allowed: false, error: "environment_refused", next: { command: "mehen run --env <environment> -- <command>" } })
 // A guest/service needs only use on the referencing project for metadata.
 s.shares.find((s) => s.id === "shr_guest")!.protected = false
 s.devices.find((d) => d.id === "dev_guest")!.scope.maxEnvironment = "unprotected"
 expect(can(s, { kind: "device", deviceId: "dev_guest" }, { type: "item.read" }, { credential: "itm_project" }, NOW).allowed).toBe(true)
})
it("legacy lease-only machines use in their own mode but cannot describe", () => {
 const s = state()
 const d = s.devices.find((d) => d.id === "dev_owner")!
 d.scope.modes = ["lease"]
 expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.read" }, { credential: "itm_workspace" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 expect(can(s, { kind: "device", deviceId: d.id }, { type: "item.use", context: null }, { credential: "itm_workspace", mode: "lease" }, NOW).allowed).toBe(true)
})

describe("live authority refusals", () => {
 it("principal standing never outranks live state", () => {
  for (const live of ["demoted", "pending", "restricted", "suspended", "removed"] as const) {
   const s = state()
   const m = s.members.find((m) => m.id === "mem_owner")!
   const principal = { ...accessMember(s, "owner"), standing: structuredClone(m.standing) }
   if (live === "demoted") m.standing.effectiveRole = "member"
   if (live === "pending") m.standing.transitionPending = true
   if (live === "restricted") m.standing.restriction = { reason: "recovery", until: NOW + 1, notice: "n" }
   if (live === "suspended" || live === "removed") m.status = live
   const before = { protected: false, fences: [], fourEyes: false }
   for (const [action, target] of [
    [{ type: "workspace.update" }, {}],
    [{ type: "member.invite" }, { role: "owner" }],
    [{ type: "environment.update", before, after: { ...before, fences: ["example.com"] } }, { project: "prj_a", environment: "dev" }],
    [{ type: "approval.approve" }, { ask: { device: "dev_member", credential: "itm_project", credentials: ["itm_project"], context: { project: "prj_a", environment: "prod" } } }],
   ] satisfies [AccessAction, AccessTarget][]) expect(can(s, principal, action, target, NOW).allowed, `${live}: ${action.type}`).toBe(false)
  }
  const s = state()
  const principal = accessMember(s, "member")
  s.members = s.members.filter((m) => m.id !== "mem_member")
  expect(can(s, principal, { type: "workspace.update" }, {}, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 })
 it("session checks bind live rule revision and generation and never replace live gate admission", () => {
  const s = state()
  const m = s.members.find((m) => m.id === "mem_member")!
  m.standing.identityGate = { covered: true, admitted: true, checkedAt: NOW }
  const principal = accessMember(s, "member")
  if (principal.kind !== "member" || !principal.sessionCheck) throw new Error("missing check")
  expect(can(s, principal, { type: "project.create" }, {}, NOW).allowed).toBe(true)
  for (const patch of [{ identityRuleRev: 2 }, { gateGeneration: 2 }, { identityRuleRev: undefined }, { gateGeneration: undefined }]) {
   const modified = { ...s, members: s.members.map((member) => member === m ? { ...m, standing: { ...m.standing, ...patch } } : member) } as AccessState
   expect(can(modified, principal, { type: "project.create" }, {}, NOW)).toMatchObject({ allowed: false, error: "identity_required" })
  }
  for (const check of [null, { ...principal.sessionCheck, expiresAt: new Date(NOW).toISOString() }]) expect(can(s, { ...principal, sessionCheck: check }, { type: "project.create" }, {}, NOW)).toMatchObject({ allowed: false, error: "identity_required" })
  m.standing.identityGate.admitted = false
  expect(can(s, principal, { type: "project.create" }, {}, NOW)).toMatchObject({ allowed: false, error: "identity_required" })
 })
 it("a protected run inherits four-eyes through its environment's references, including team runs", () => {
  const s = state()
  const a = s.projects[0]!.environments[1]!
  const b = s.projects[1]!.environments[1]!
  a.references = structuredClone(s.projects[0]!.environments[0]!.references)
  b.references = structuredClone(a.references)
  b.fourEyes = false
  s.shares.push(share("prj_b", "mem_member", "use", true), share("prj_b", "mem_kim", "manage"))
  s.shares = s.shares.filter((share) => share.id !== "shr_kim")
  s.shares.find((share) => share.id === "shr_service")!.protected = true
  for (const device of ["dev_member", "dev_service"]) {
   const ask = { device, credential: null, credentials: ["itm_workspace"], context: { project: device === "dev_member" ? "prj_b" : "prj_a", environment: "prod" } }
   expect(eligibility(s, "mem_member", ask, NOW).canApprove).toBe(false)
   expect(eligibility(s, "mem_kim", ask, NOW).canApprove).toBe(false)
   for (const role of elevated) expect(eligibility(s, `mem_${role}`, ask, NOW).canApprove).toBe(true)
  }
  // The inherited project is hidden, not merely visible without manage.
  expect(effectiveAccess(s, { kind: "member", id: "mem_kim" }, "prj_a", NOW).level).toBeNull()
  s.shares.push(share("prj_a", "mem_kim", "manage"))
  for (const device of ["dev_member", "dev_service"]) expect(eligibility(s, "mem_kim", { device, credential: null, credentials: ["itm_workspace"], context: { project: device === "dev_member" ? "prj_b" : "prj_a", environment: "prod" } }, NOW).canApprove).toBe(true)
 })
 it("member manager cannot share with a guest whatever the target says", () => {
  const s = state()
  for (const role of [undefined, "member", "guest"] as const) {
   const target = { project: "prj_a", member: "mem_guest", role }
   expect(check(s, "kim", { type: "project.share" }, target).allowed).toBe(false)
   for (const actor of elevated) expect(check(s, actor, { type: "project.share" }, target).allowed).toBe(true)
  }
  for (const subject of [{ member: "missing" }, { team: "missing" }, {}]) expect(check(s, "owner", { type: "project.share" }, { project: "prj_a", ...subject })).toMatchObject({ allowed: false, error: "not_found" })
 })
 it("member manager may remove a guest's share, though never give or keep one", () => {
  const s = state()
  const target = { project: "prj_a", member: "mem_guest" }
  expect(check(s, "kim", { type: "project.share", after: null }, target)).toEqual({ allowed: true, stepUp: "project.share" })
  expect(check(s, "kim", { type: "project.share", after: { level: "use", protected: false, expiresAt: null } }, target).allowed).toBe(false)
  expect(check(s, "member", { type: "project.share", after: null }, target).allowed).toBe(false)
  expect(check(s, "guest", { type: "project.share", after: null }, target).allowed).toBe(false)
 })
 it("manager admits only a guest shared on that project", () => {
  const s = state()
  s.shares.push(share("prj_b", "mem_member", "manage"))
  for (const type of ["enrol.approve", "enrol.reject"] as const) {
   expect(check(s, "kim", { type }, { member: "mem_guest", project: "prj_a", after: { ...WORKSPACE_FULL_SCOPE, projects: ["prj_a"] } }).allowed).toBe(true)
   expect(check(s, "member", { type }, { member: "mem_guest", project: "prj_b", role: "guest" }).allowed).toBe(false)
   s.shares.find((share) => share.id === "shr_guest")!.expiresAt = new Date(NOW).toISOString()
   expect(check(s, "kim", { type }, { member: "mem_guest", project: "prj_a" }).allowed).toBe(false)
   s.shares.find((share) => share.id === "shr_guest")!.expiresAt = null
  }
 })
 it("supplied context must exist and reference the credential", () => {
  const s = state()
  s.projects[0]!.environments.push({ ...structuredClone(s.projects[0]!.environments[0]!), name: "empty", references: [] })
  for (const context of [{ project: "prj_missing", environment: "x" }, { project: "prj_a", environment: "staging" }, { project: "prj_a", environment: "empty" }]) {
   for (const action of [{ type: "item.use", context }, { type: "item.use", context: null }] satisfies AccessAction[]) expect(can(s, { kind: "device", deviceId: "dev_owner" }, action, { credential: "itm_workspace", context }, NOW).allowed).toBe(false)
   expect(eligibility(s, "mem_owner", { device: "dev_owner", credential: "itm_workspace", credentials: ["itm_workspace"], context }, NOW)).toMatchObject({ canApprove: false, canReadAskDetail: false })
  }
  expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "item.use", context: null }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
  const device = s.devices.find((device) => device.id === "dev_member")!
  device.scope.projects = ["prj_b"]
  expect(can(s, { kind: "device", deviceId: device.id }, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
 })
 it("owner cooling-off/pending leaves machine use and runs alone but refuses machine widening", () => {
  for (const pending of [true, false]) {
   const s = state()
   const m = s.members.find((m) => m.id === "mem_member")!
   m.standing.transitionPending = pending
   m.standing.restriction = pending ? null : { reason: "recovery", until: NOW + 1, notice: "n" }
   const principal: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
   for (const [action, target] of [
    [{ type: "item.use", context: null }, { credential: "itm_workspace" }],
    [{ type: "run.unprotected" }, { project: "prj_a", environment: "dev" }],
    [{ type: "run.protected" }, { project: "prj_a", environment: "prod" }],
   ] satisfies [AccessAction, AccessTarget][]) expect(can(s, principal, action, target, NOW).allowed).toBe(true)
   for (const [action, target] of [
    [{ type: "credential.create" }, { destinationHome: { kind: "project", project: "prj_a" } }],
    [{ type: "credential.rotate" }, { credential: "itm_workspace" }],
    [{ type: "var.set", before: null, after: { kind: "plain", value: "x" } }, { project: "prj_a", environment: "dev", variable: "NEW" }],
    [{ type: "project.init" }, {}],
   ] satisfies [AccessAction, AccessTarget][]) expect(can(s, principal, action, target, NOW)).toMatchObject({ allowed: false, error: pending ? "account_pending" : "forbidden" })
   const human = check(s, "member", { type: "approval.approve" }, { ask: { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } })
   expect(human.allowed).toBe(false)
   if (!pending) expect(human).toMatchObject({ message: expect.stringContaining("Your sign-in was recovered. Until"), next: { url: "/account" } })
  }
 })
 it("a push is a reveal: a cooling-off or pending owner's machine relays the credential but may not push it", () => {
  for (const pending of [true, false]) {
   const s = state()
   const m = s.members.find((m) => m.id === "mem_member")!
   m.standing.transitionPending = pending
   m.standing.restriction = pending ? null : { reason: "recovery", until: NOW + 1, notice: "n" }
   const principal: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
   expect(can(s, principal, { type: "item.use", context: null }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
   expect(can(s, principal, { type: "item.use", context: null }, { credential: "itm_workspace", push: true }, NOW)).toMatchObject({ allowed: false, error: pending ? "account_pending" : "forbidden" })
  }
  expect(classify(state(), { type: "item.use", context: null }, { credential: "itm_workspace", push: true })).toBe("reveal")
  expect(classify(state(), { type: "credential.push" }, { credential: "itm_workspace" })).toBe("reveal")
 })
 it("a person pushes again only a credential they manage, a private one only its owner, never one under four eyes", () => {
  const s = state()
  // A shared credential: an admin or a manager of its project, as for a machine's push; never a member who only uses or edits it.
  const project = s.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "prod")!
  project.references = []
  expect(check(s, "kim", { type: "credential.push" }, { credential: "itm_project" })).toMatchObject({ allowed: true, stepUp: "item.push" })
  expect(check(s, "admin", { type: "credential.push" }, { credential: "itm_project" })).toMatchObject({ allowed: true, stepUp: "item.push" })
  expect(check(s, "member", { type: "credential.update" }, { credential: "itm_project" }).allowed).toBe(false)
  expect(check(s, "member", { type: "credential.push" }, { credential: "itm_project" })).toEqual(check(s, "member", { type: "credential.update" }, { credential: "itm_project" }))
  expect(check(s, "guest", { type: "credential.push" }, { credential: "itm_project" })).toEqual(check(s, "guest", { type: "credential.update" }, { credential: "itm_project" }))
  expect(check(s, "member", { type: "credential.push" }, { credential: "itm_member" })).toMatchObject({ allowed: true, stepUp: "item.push" })
  expect(check(s, "owner", { type: "credential.push" }, { credential: "itm_member" }).allowed).toBe(false)
  expect(check(s, "guest", { type: "credential.push" }, { credential: "itm_guest" })).toMatchObject({ allowed: true, stepUp: "item.push" })
  for (const env of s.projects[0]!.environments) env.fourEyes = env.protected = true
  expect(check(s, "owner", { type: "credential.push" }, { credential: "itm_workspace" })).toMatchObject({ allowed: false, error: "forbidden", message: "Push this from a machine's ask, so a second person decides." })
 })
 it("machine rotation requests are live-reach bounded and never guest-shared", () => {
  const s = state()
  for (const deviceId of ["dev_owner", "dev_member", "dev_service"]) {
   expect(can(s, { kind: "device", deviceId }, { type: "credential.rotate" }, { credential: "itm_workspace" }, NOW)).toEqual({ allowed: true, stepUp: null })
   s.devices.find((device) => device.id === deviceId)!.scope.tags = ["unreachable"]
   expect(can(s, { kind: "device", deviceId }, { type: "credential.rotate" }, { credential: "itm_workspace" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
  }
  expect(can(s, { kind: "device", deviceId: "dev_guest" }, { type: "credential.rotate" }, { credential: "itm_workspace" }, NOW).allowed).toBe(false)
 })
 it("editor create via connect signs connect.start, intake signs intake.submit, and cancellation uses fill rights", () => {
  const s = state()
  const target: AccessTarget = { destinationHome: { kind: "project", project: "prj_a" } }
  const intake = check(s, "member", { type: "credential.create" }, target)
  const connect = check(s, "member", { type: "credential.connect" }, target)
  expect(intake).toEqual({ allowed: true, stepUp: "intake.submit" })
  expect(connect).toEqual({ allowed: true, stepUp: "connect.start" })
  const connectProof = { type: "connect.start", connect: "c", provider: "p", slug: "s", home: target.destinationHome!, tags: [], expectedAccount: null, scopes: [], intent: "create", target: null, targetRevision: null, client: "c", clientRevision: 1, dependencyRevision: 1 } as const
  expect(stepUpSatisfies(intake, { ...connectProof, tags: [], scopes: [] })).toBe(false)
  expect(stepUpSatisfies(connect, { type: "intake.submit", intake: "i", digest: "d" })).toBe(false)
  for (const type of ["intake.cancel", "connect.cancel"] as const) expect(check(s, "member", { type }, target).allowed).toBe(true)
  expect(check(s, "member", { type: "credential.reconnect" }, { credential: "itm_project" }).allowed).toBe(false)
 })
 it("sole owner cannot leave, be demoted, suspended or removed, or delete their account, whatever the target says", () => {
  const s = state()
  const target = { member: "mem_owner", role: "member" as const, lastUsableOwner: false }
  for (const type of ["member.leave", "member.role", "member.suspend", "member.remove", "account.delete"] as const) expect(check(s, "owner", { type }, target).allowed).toBe(false)
  s.members.find((m) => m.id === "mem_admin")!.standing.effectiveRole = "owner"
  expect(check(s, "owner", { type: "member.leave" }, target).allowed).toBe(true)
  s.members.find((m) => m.id === "mem_admin")!.status = "suspended"
  expect(check(s, "owner", { type: "member.leave" }, target).allowed).toBe(false)
 })
 it("admin confirming owner terms or missing terms refuses, and admin cannot change, suspend or remove an owner", () => {
  const s = state()
  expect(check(s, "admin", { type: "member.confirm" }, {}).allowed).toBe(false)
  expect(check(s, "admin", { type: "member.confirm" }, { inviteTerms: { ...terms, role: "owner" } }).allowed).toBe(false)
  expect(check(s, "owner", { type: "member.confirm" }, { inviteTerms: { ...terms, role: "owner" } }).allowed).toBe(true)
  for (const type of ["member.role", "member.suspend", "member.remove"] as const) expect(check(s, "admin", { type }, { member: "mem_owner", role: "member" }).allowed).toBe(false)
  for (const type of ["member.role", "member.suspend", "member.remove", "team.members"] as const) expect(check(s, "admin", { type }, { member: "missing", role: "member" })).toMatchObject({ allowed: false, error: "not_found" })
 })
 it("prod and production visibility precedes their always-protected refusal", () => {
  const s = state()
  const before = { protected: true, fences: [], fourEyes: false }
  for (const name of ["prod", "production"]) for (const project of [undefined, "prj_b"]) expect(check(s, "guest", { type: "environment.update", before, after: { ...before, protected: false } }, { project, environment: name })).toMatchObject({ allowed: false, error: "not_found" })
 })
 it("stale plain before conflicts without echoing the value", () => {
  const s = state()
  s.projects[0]!.environments[0]!.plainVariables = { PLAIN: "live-private-value" }
  const target = { project: "prj_a", environment: "dev", variable: "PLAIN" }
  const action: AccessAction = { type: "var.set", before: { kind: "plain", value: "stale-private-value" }, after: null }
  const result = check(s, "member", action, target)
  expect(result).toMatchObject({ allowed: false, error: "conflict" })
  expect(JSON.stringify(result)).not.toContain("private-value")
  expect(check(s, "member", { ...action, before: { kind: "plain", value: "live-private-value" } }, target).allowed).toBe(true)
 })
 it("member machines requires ownership by the supplied team, not arbitrary team membership", () => {
  const s = state()
  expect(check(s, "member", { type: "member.machines" }, { member: "mem_kim", device: "dev_kim", team: "tm_engineering" }).allowed).toBe(false)
  expect(check(s, "member", { type: "member.machines" }, { member: "mem_member", device: "dev_kim", team: "tm_engineering" }).allowed).toBe(false)
  s.devices.push({ id: "dev_engineering", owner: { kind: "team", id: "tm_engineering" }, scope: structuredClone(WORKSPACE_FULL_SCOPE), status: "active" })
  expect(check(s, "member", { type: "member.machines" }, { device: "dev_engineering", team: "tm_engineering" }).allowed).toBe(true)
 })
 it("protected overrides, cross-project/private rehomes and team private scopes always refuse", () => {
  const s = state()
  expect(check(s, "owner", { type: "override.set" }, { project: "prj_a", environment: "prod" }).allowed).toBe(false)
  expect(check(s, "owner", { type: "credential.rehome" }, { credential: "itm_workspace", destinationHome: { kind: "project", project: "prj_a" } }).allowed).toBe(false)
  expect(check(s, "owner", { type: "credential.rehome" }, { credential: "itm_project", destinationHome: { kind: "member", member: "mem_owner" } }).allowed).toBe(false)
  for (const actor of elevated) {
   const before = structuredClone(WORKSPACE_FULL_SCOPE)
   expect(check(s, actor, { type: "device.rescope", before, after: { ...before, privateCredentials: true } }, { device: "dev_service" }).allowed).toBe(false)
   s.devices.find((d) => d.id === "dev_member")!.scope = { ...before, projects: ["prj_a"] }
   expect(check(s, actor, { type: "device.rescope", before: { ...before, projects: ["prj_a"] }, after: before }, { device: "dev_member" }).allowed).toBe(false)
  }
  expect(can(s, { kind: "device", deviceId: "dev_service" }, { type: "workspace.freeze" }, {}, NOW)).toEqual({ allowed: true, stepUp: null })
 })
})

it("run delivery unions X/Y four-eyes and forbids self-approval through a third project", () => {
 const s = state()
 s.credentials.push({ id: "itm_y", home: { kind: "workspace" }, tags: [] })
 s.projects[0]!.environments[1]!.references = [{ variable: "X", field: "key", item: "itm_workspace", home: { kind: "workspace" }, revision: 1 }]
 s.projects[1]!.environments[1]!.references = [{ variable: "Y", field: "key", item: "itm_y", home: { kind: "workspace" }, revision: 1 }]
 s.projects.push({ id: "prj_c", slug: "project-c", environments: [{ name: "prod", protected: true, fourEyes: false, fences: [], revision: 1, protectionRevision: 1, references: [...s.projects[0]!.environments[1]!.references, ...s.projects[1]!.environments[1]!.references] }] })
 s.shares.push(share("prj_c", "mem_member", "manage"), share("prj_c", "mem_kim", "manage"))
 const ask = { device: "dev_member", credential: null, credentials: ["itm_workspace", "itm_y"], context: { project: "prj_c", environment: "prod" } }
 expect(eligibility(s, "mem_kim", ask, NOW).canApprove).toBe(false)
 expect(check(s, "kim", { type: "approval.approve" }, { ask }).allowed).toBe(false)
 s.shares.push(share("prj_b", "mem_kim", "manage"))
 expect(eligibility(s, "mem_kim", ask, NOW)).toMatchObject({ canApprove: true, canReadAskDetail: true })
 expect(check(s, "kim", { type: "approval.approve" }, { ask })).toMatchObject({ allowed: true, stepUp: "approval.decide" })
 s.shares.push(share("prj_a", "mem_member", "manage"), share("prj_b", "mem_member", "manage"))
 expect(eligibility(s, "mem_member", ask, NOW).canApprove).toBe(false)
 expect(check(s, "member", { type: "approval.approve" }, { ask }).allowed).toBe(false)
 expect(eligibility(s, "mem_kim", { ...ask, credentials: [] }, NOW).canApprove).toBe(true)
 expect(eligibility(s, "mem_kim", { ...ask, credentials: ["missing"] }, NOW).canApprove).toBe(false)
})

import { WORKSPACE_WHILE_RESTRICTED, WorkspaceStepUpActionSchema } from "@mehen/protocol"
it("restricted protocol signatures and every corresponding evaluator classification cannot drift", () => {
 const s = state()
 const rescope: AccessAction = { type: "device.rescope", before: WORKSPACE_FULL_SCOPE, after: WORKSPACE_FULL_SCOPE }
 const mapping: Record<WorkspaceStepUpAction["type"], AccessAction[]> = {
  "workspace.create": [{ type: "workspace.create" }], "workspace.update": [{ type: "workspace.update" }], "workspace.identity_rule": [{ type: "workspace.identity_rule" }], "workspace.delete": [{ type: "workspace.delete" }], "workspace.delete_cancel": [{ type: "workspace.delete_cancel" }], "workspace.unfreeze": [{ type: "workspace.unfreeze" }],
  "member.invite": [{ type: "member.invite" }], "member.confirm": [{ type: "member.confirm" }], "member.role": [{ type: "member.role" }], "member.suspend": [{ type: "member.suspend" }], "member.reinstate": [{ type: "member.reinstate" }], "member.remove": [{ type: "member.remove" }], "member.leave": [{ type: "member.leave" }], "account.delete": [{ type: "account.delete" }],
  "identity.link": [{ type: "identity.link" }], "identity.unlink": [{ type: "identity.unlink" }], "team.update": [{ type: "team.update" }], "team.members": [{ type: "team.members" }], "project.create": [{ type: "project.create" }], "project.share": [{ type: "project.share" }], "project.configure": [{ type: "remote.update" }, { type: "environment.update", before: { protected: false, fourEyes: false, fences: [] }, after: { protected: true, fourEyes: true, fences: [] } }], "project.delete": [{ type: "project.delete" }], "override.set": [{ type: "override.set" }], "item.rehome": [{ type: "credential.rehome" }], "connect.start": [{ type: "credential.connect" }, { type: "credential.reconnect" }], "enrol.accept": [{ type: "enrol.accept" }], "enrol.approve": [{ type: "enrol.approve" }], "device.rescope": [rescope, { type: "device.rescope_propose" }, { type: "device.rescope_admit" }], "device.rescope_accept": [{ ...rescope, type: "device.rescope_accept" }], "device.revoke": [{ type: "device.revoke" }], "approval.decide": [{ type: "approval.approve" }, { type: "approval.deny" }], "approval.decide_many": [{ type: "approval.approve" }, { type: "approval.deny" }], "policy.decide": [{ type: "policy.approve" }, { type: "policy.rule.approve" }, { type: "policy.cosign" }, { type: "policy.deny" }], "item.update": [{ type: "credential.update" }, { type: "var.set", before: null, after: null }], "item.delete": [{ type: "credential.delete" }], "intake.submit": [{ type: "credential.create" }, { type: "credential.rotate" }], "passkey.add": [{ type: "passkey.add" }], "passkey.remove": [{ type: "passkey.remove" }], "recovery.generate": [{ type: "recovery.generate" }],
  // Account recovery resolution is directory-only, not a workspace DO action.
  "recovery.resolve": [],
  // The operator console and platform admins are directory-only too.
  "platform.operate": [],
  "platform.administer": [],
  "operator.propose": [],
  "operator.approve": [],
  "operator.accept": [],
  "operator.break_glass_link": [],
  "adoption.approve": [{ type: "credential.adopt" }],
  "item.restore": [{ type: "credential.restore" }],
  "item.posture": [{ type: "credential.posture", level: "ask" }, { type: "credential.posture", level: "routine" }, { type: "credential.posture", level: "trust" }],
  "item.push": [{ type: "credential.push" }],
  "device.rescope_reject": [{ type: "device.rescope_reject" }],
  "workload.revoke": [{ type: "workload.revoke" }],
  "backup.recipient_add": [{ type: "backup.recipient_add" }],
  "backup.recipient_remove": [{ type: "backup.recipient_remove" }],
  "mandate.sign": [{ type: "mandate.sign" }],
  "mandate.resume": [{ type: "mandate.resume" }],
  "workspace.approvals": [{ type: "workspace.approvals_less" }],
 }
 expect(Object.keys(mapping).sort()).toEqual(WorkspaceStepUpActionSchema.options.map((option) => option.shape.type.value).sort())
 for (const [type, actions] of Object.entries(mapping) as [WorkspaceStepUpAction["type"], AccessAction[]][]) {
  const rule = WORKSPACE_WHILE_RESTRICTED[type]
  for (const action of actions) {
   const classification = classify(s, action, { device: "dev_member" })
   const safe = classification === "read" || classification === "narrow"
   expect(safe, `${type}: ${action.type}`).toBe(rule === "allowed" || rule === "scope" && action.type === "device.rescope" || rule === "decide" && (action.type.endsWith(".deny") || action.type === "credential.posture" && action.level === "ask"))
  }
 }
})


it("device self metadata and revocation have distinct live-owner requirements", () => {
 const s = state()
 const principal: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
 expect(classify(s, { type: "device.read_self" }, {})).toBe("read")
 expect(classify(s, { type: "device.self_revoke" }, {})).toBe("narrow")
 expect(can(s, principal, { type: "device.read_self" }, { device: "dev_member" }, NOW)).toEqual({ allowed: true, stepUp: null })
 expect(can(s, principal, { type: "device.read_self" }, { device: "dev_kim" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 s.members.find((member) => member.id === "mem_member")!.status = "suspended"
 expect(can(s, principal, { type: "device.read_self" }, { device: "dev_member" }, NOW)).toMatchObject({ allowed: false, error: "owner_inactive" })
 expect(can(s, principal, { type: "device.self_revoke" }, { device: "dev_member" }, NOW)).toEqual({ allowed: true, stepUp: null })
 expect(can(s, principal, { type: "device.self_revoke" }, { device: "dev_kim" }, NOW).allowed).toBe(false)
 s.devices.find((device) => device.id === "dev_member")!.status = "revoked"
 expect(can(s, principal, { type: "device.self_revoke" }, { device: "dev_member" }, NOW).allowed).toBe(false)
})


it("ending a run remains a narrow escape hatch after owner suspension or share loss", () => {
 const s = state()
 const target = { device: "dev_member", run: "run_live" }
 expect(classify(s, { type: "run.end" }, target)).toBe("narrow")
 expect(check(s, "member", { type: "run.end" }, target)).toEqual({ allowed: true, stepUp: null })
 s.members.find((member) => member.id === "mem_member")!.standing.identityGate = { covered: true, admitted: false, checkedAt: null }
 expect(check(s, "member", { type: "run.end" }, target)).toEqual({ allowed: true, stepUp: null })
 s.members.find((member) => member.id === "mem_member")!.status = "suspended"
 s.shares = []
 expect(can(s, { kind: "device", deviceId: "dev_member" }, { type: "run.end" }, target, NOW)).toEqual({ allowed: true, stepUp: null })
 expect(can(s, { kind: "device", deviceId: "dev_kim" }, { type: "run.end" }, target, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 for (const role of elevated) expect(check(s, role, { type: "run.end" }, target)).toEqual({ allowed: true, stepUp: null })
 expect(check(s, "kim", { type: "run.end" }, target)).toMatchObject({ allowed: false, error: "not_found" })
 expect(check(s, "owner", { type: "run.end" }, { device: "dev_member" })).toMatchObject({ allowed: false, error: "not_found" })
 s.devices.find((device) => device.id === "dev_member")!.status = "revoked"
 expect(can(s, { kind: "device", deviceId: "dev_member" }, { type: "run.end" }, target, NOW)).toMatchObject({ allowed: false, error: "not_found" })
})


it("rescope proposals do not substitute admin admission for the owning account's acceptance", () => {
 const s = state()
 const before = structuredClone(WORKSPACE_FULL_SCOPE)
 const after = { ...before, privateCredentials: true }
 s.devices.find((device) => device.id === "dev_member")!.scope = structuredClone(before)
 const target = { device: "dev_member", before, after }
 expect(classify(s, { type: "device.rescope_propose" }, target)).toBe("widen")
 expect(check(s, "admin", { type: "device.rescope_propose" }, target)).toEqual({ allowed: true, stepUp: "device.rescope" })
 expect(check(s, "member", { type: "device.rescope_propose" }, target)).toEqual({ allowed: true, stepUp: "device.rescope" })
 expect(check(s, "admin", { type: "device.rescope_accept", before, after }, { device: "dev_member", owningAccount: "acc_member" }).allowed).toBe(false)
 expect(s.devices.find((device) => device.id === "dev_member")!.scope).toEqual(before)
 expect(check(s, "member", { type: "device.rescope_propose" }, { device: "dev_service", before, after: before }).allowed).toBe(false)
 expect(check(s, "admin", { type: "device.rescope_propose" }, { device: "dev_service", before, after: before })).toEqual({ allowed: true, stepUp: "device.rescope" })
})
it("guest rescope admission requires a current shared project and an insider other than the guest", () => {
 const s = state()
 const before = structuredClone(WORKSPACE_FULL_SCOPE)
 const after = { ...before, privateCredentials: true, projects: ["prj_a"] }
 const target = { device: "dev_guest", before, after, proposal: "rsp_guest", project: "prj_a" }
 expect(classify(s, { type: "device.rescope_admit" }, target)).toBe("widen")
 expect(check(s, "kim", { type: "device.rescope_admit" }, target)).toEqual({ allowed: true, stepUp: "device.rescope" })
 s.shares.push(share("prj_b", "mem_member", "manage"))
 expect(check(s, "member", { type: "device.rescope_admit" }, { ...target, project: "prj_b" }).allowed).toBe(false)
 expect(check(s, "guest", { type: "device.rescope_admit" }, target).allowed).toBe(false)
 s.shares.find((share) => share.id === "shr_guest")!.expiresAt = new Date(NOW).toISOString()
 expect(check(s, "kim", { type: "device.rescope_admit" }, target).allowed).toBe(false)
 expect(check(s, "admin", { type: "device.rescope_admit" }, target).allowed).toBe(false)
})

it.each(["clear", "restricted", "pending"] as const)("rescope reject narrows with the signer's own accept or admit authority (%s)", (standing) => {
 const s = state()
 const before = structuredClone(WORKSPACE_FULL_SCOPE)
 const memberAfter = { ...before, privateCredentials: true }
 const guestAfter = { ...before, privateCredentials: true, projects: ["prj_a"] }
 const own = { device: "dev_member", owningAccount: "acc_member", before, after: memberAfter, proposal: "rsp_member" }
 const guest = { device: "dev_guest", before, after: guestAfter, proposal: "rsp_guest", project: "prj_a" }
 for (const device of s.devices) device.scope = structuredClone(before)
 for (const who of ["mem_member", "mem_kim"]) {
  const m = s.members.find((member) => member.id === who)!
  if (standing === "pending") m.standing.transitionPending = true
  if (standing === "restricted") m.standing.restriction = { reason: "recovery", until: NOW + 1, notice: "n" }
 }
 expect(classify(s, { type: "device.rescope_reject" }, own)).toBe("narrow")
 expect(check(s, "member", { type: "device.rescope_reject" }, { ...own, rescopeAs: "owner_acceptance" })).toEqual({ allowed: true, stepUp: "device.rescope_reject" })
 expect(check(s, "kim", { type: "device.rescope_reject" }, { ...guest, rescopeAs: "admission" })).toEqual({ allowed: true, stepUp: "device.rescope_reject" })
 // Accept and admit stay widening and keep the cooling-off and pending refusals.
 expect(check(s, "member", { type: "device.rescope_accept", before, after: memberAfter }, own).allowed).toBe(standing === "clear")
 expect(check(s, "kim", { type: "device.rescope_admit" }, guest).allowed).toBe(standing === "clear")
 // No signer role, or the wrong one, is no authority; neither is another's machine.
 expect(check(s, "member", { type: "device.rescope_reject" }, own).allowed).toBe(false)
 expect(check(s, "member", { type: "device.rescope_reject" }, { ...own, rescopeAs: "admission" }).allowed).toBe(false)
 expect(check(s, "kim", { type: "device.rescope_reject" }, { ...guest, rescopeAs: "owner_acceptance" }).allowed).toBe(false)
 expect(check(s, "admin", { type: "device.rescope_reject" }, { ...own, rescopeAs: "owner_acceptance" }).allowed).toBe(false)
 s.shares.find((share) => share.id === "shr_guest")!.expiresAt = new Date(NOW).toISOString()
 expect(check(s, "kim", { type: "device.rescope_reject" }, { ...guest, rescopeAs: "admission" }).allowed).toBe(false)
})

it("owner-only reference refusals use the live project slug and never an absent environment", () => {
 const s = state()
 s.projects[0]!.slug = "real-project"
 const env = s.projects[0]!.environments[2]!
 env.references = structuredClone(s.projects[0]!.environments[0]!.references)
 const before = { protected: true, fourEyes: false, fences: [] }
 expect(check(s, "kim", { type: "environment.update", before, after: { ...before, protected: false } }, { project: "prj_a", environment: "staging" })).toMatchObject({ allowed: false, next: { say: "Only an owner or admin can loosen real-project/staging: it uses workspace credentials." } })
 const deletion = check(s, "kim", { type: "project.delete" }, { project: "prj_a" })
 expect(deletion).toMatchObject({ allowed: false, next: { say: "Only an owner or admin can delete real-project: a protected environment uses workspace credentials." } })
 expect(JSON.stringify(deletion)).not.toContain("undefined")
 const kim = s.members.find((member) => member.id === "mem_kim")!
 kim.standing.identityGate = { covered: true, admitted: false, checkedAt: NOW }
 expect(check(s, "kim", { type: "environment.update", before, after: { ...before, protected: false } }, { project: "prj_a", environment: "staging" })).toMatchObject({ allowed: false, error: "identity_required" })
 expect(check(s, "kim", { type: "project.delete" }, { project: "prj_a" })).toMatchObject({ allowed: false, error: "identity_required" })
 kim.standing.identityGate = { covered: false, admitted: true, checkedAt: null }
 const dev = s.projects[0]!.environments[0]!
 dev.references = []
 const fences = { protected: false, fourEyes: false, fences: [] }
 expect(check(s, "kim", { type: "environment.update", before: fences, after: { ...fences, fences: ["example.com"] } }, { project: "prj_a", environment: "dev" })).toMatchObject({ allowed: false, next: { say: "Only an owner or admin can change fences for real-project/dev." } })
})


it("devices read only their own pending asks without project shares, including cooling-off and pending", () => {
 const s = state()
 s.shares = []
 const principal: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
 const member = s.members.find((member) => member.id === "mem_member")!
 expect(classify(s, { type: "asks.read" }, {})).toBe("read")
 for (const pending of [false, true]) {
  member.standing.transitionPending = pending
  member.standing.restriction = { reason: "recovery", until: NOW + 1, notice: "n" }
  expect(can(s, principal, { type: "asks.read" }, { device: "dev_member" }, NOW)).toEqual({ allowed: true, stepUp: null })
  expect(can(s, principal, { type: "asks.read" }, { device: "dev_kim" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
 }
 member.status = "suspended"
 expect(can(s, principal, { type: "asks.read" }, { device: "dev_member" }, NOW)).toMatchObject({ allowed: false, error: "owner_inactive" })
})

it("run four-eyes uses live context references whatever the delivery list says", () => {
 const s = state()
 const a = s.projects[0]!.environments[1]!
 const b = s.projects[1]!.environments[1]!
 a.references = structuredClone(s.projects[0]!.environments[0]!.references)
 b.references = [...structuredClone(a.references), { variable: "PROJECT", field: "key", item: "itm_project", home: { kind: "project", project: "prj_a" }, revision: 1 }]
 b.fourEyes = false
 s.shares.push(share("prj_b", "mem_member", "use", true), share("prj_b", "mem_kim", "manage"))
 const ask = { device: "dev_member", credential: null, credentials: ["itm_workspace", "itm_project"], context: { project: "prj_b", environment: "prod" } }
 for (const credentials of [["itm_workspace", "itm_project"], ["itm_project"], [], ["itm_member"]]) {
  expect(eligibility(s, "mem_member", { ...ask, credentials }, NOW).canApprove).toBe(false)
  expect(check(s, "member", { type: "approval.approve" }, { ask: { ...ask, credentials } }).allowed).toBe(false)
 }
 for (const credentials of [["itm_workspace", "itm_project"], ["itm_project"], []]) {
  expect(eligibility(s, "mem_kim", { ...ask, credentials }, NOW)).toMatchObject({ canApprove: true, canReadAskDetail: true })
  expect(check(s, "kim", { type: "approval.approve" }, { ask: { ...ask, credentials } })).toMatchObject({ allowed: true, stepUp: "approval.decide" })
 }
 expect(eligibility(s, "mem_kim", { ...ask, credentials: ["itm_member"] }, NOW)).toMatchObject({ canApprove: false, canReadAskDetail: false })
 expect(check(s, "kim", { type: "approval.approve" }, { ask: { ...ask, credentials: ["itm_member"] } }).allowed).toBe(false)
})

it("a manager other than the machine owner can approve a four-eyes run without references", () => {
 const s = state()
 s.projects[0]!.environments[1]!.references = []
 const ask = { device: "dev_member", credential: null, credentials: [], context: { project: "prj_a", environment: "prod" } }
 expect(eligibility(s, "mem_kim", ask, NOW)).toMatchObject({ canApprove: true, canReadAskDetail: true })
 expect(check(s, "kim", { type: "approval.approve" }, { ask })).toMatchObject({ allowed: true, stepUp: "approval.decide" })
 expect(eligibility(s, "mem_member", ask, NOW).canApprove).toBe(false)
 expect(check(s, "member", { type: "approval.approve" }, { ask }).allowed).toBe(false)
 for (const role of elevated) expect(eligibility(s, `mem_${role}`, ask, NOW).canApprove).toBe(true)
})

it("a member manager admits guest scope only within projects they manage and the guest is shared on", () => {
 const s = state()
 const before = { ...structuredClone(WORKSPACE_FULL_SCOPE), projects: ["prj_a"] }
 s.devices.find((device) => device.id === "dev_guest")!.scope = structuredClone(before)
 const guestB = share("prj_b", "mem_guest", "use")
 s.shares.push(guestB)
 for (const type of ["device.rescope_admit", "enrol.approve"] as const) {
  for (const projects of [["prj_a"], ["prj_b"], [], ["prj_a", "prj_b"]]) {
   const target = { member: "mem_guest", device: "dev_guest", project: "prj_a", before, after: { ...before, projects }, proposal: "rsp_guest" }
   expect(check(s, "kim", { type }, target).allowed, `${type}: ${JSON.stringify(projects)}`).toBe(projects.length === 1 && projects[0] === "prj_a")
   expect(check(s, "admin", { type }, target)).toMatchObject({ allowed: true, stepUp: type === "enrol.approve" ? "enrol.approve" : "device.rescope" })
  }
  const target = { member: "mem_guest", device: "dev_guest", project: "prj_a", before, after: { ...before, projects: ["prj_a", "prj_b"] }, proposal: "rsp_guest" }
  expect(check(s, "kim", { type }, { ...target, after: undefined }).allowed).toBe(false)
  s.shares.push(share("prj_b", "mem_kim", "manage"))
  expect(check(s, "kim", { type }, target).allowed).toBe(true)
  guestB.expiresAt = new Date(NOW).toISOString()
  expect(check(s, "kim", { type }, target).allowed).toBe(false)
  guestB.expiresAt = null
  s.shares = s.shares.filter((entry) => entry.subject.kind !== "member" || entry.subject.member !== "mem_kim" || entry.project !== "prj_b")
 }
})

it("human creators and eligible fillers can cancel asks but unrelated members cannot", () => {
 const s = state()
 for (const type of ["intake.cancel", "connect.cancel"] as const) {
  expect(classify(s, { type }, {})).toBe("narrow")
  expect(check(s, "member", { type }, { creator: "mem_member" })).toEqual({ allowed: true, stepUp: null })
  expect(check(s, "member", { type }, { creator: "mem_member", destinationHome: { kind: "member", member: "mem_member" } })).toEqual({ allowed: true, stepUp: null })
  const project = { creator: "mem_kim", destinationHome: { kind: "project" as const, project: "prj_a" } }
  expect(check(s, "member", { type }, project)).toEqual({ allowed: true, stepUp: null })
  expect(check(s, "kim", { type }, { creator: "mem_member", destinationHome: { kind: "member", member: "mem_member" } })).toMatchObject({ allowed: false, error: "not_found" })
  expect(check(s, "member", { type }, { credential: "itm_project", ...project })).toMatchObject({ allowed: false, error: "not_found" })
  expect(check(s, "kim", { type }, { credential: "itm_project" })).toEqual({ allowed: true, stepUp: null })
  expect(check(s, "admin", { type }, { creator: "mem_member" })).toEqual({ allowed: true, stepUp: null })
 }
})


it("a guest sharing a project credential reads only their own ask detail", () => {
 const s = state()
 const ask = { device: "dev_kim", credential: "itm_project", credentials: ["itm_project"], context: { project: "prj_a", environment: "prod" } }
 expect(effectiveAccess(s, { kind: "member", id: "mem_guest" }, "prj_a", NOW).level).toBe("edit")
 expect(eligibility(s, "mem_guest", ask, NOW)).toMatchObject({ canReadAskDetail: false, canApprove: false, canDeny: false, deciders: [] })
 expect(check(s, "guest", { type: "approval.read" }, { ask })).toMatchObject({ allowed: false, error: "not_found" })
 for (const type of ["approval.approve", "approval.deny"] as const) expect(check(s, "guest", { type }, { ask }).allowed).toBe(false)
 const own = { ...ask, device: "dev_guest" }
 expect(eligibility(s, "mem_guest", own, NOW)).toMatchObject({ canReadAskDetail: true, deciders: [] })
 expect(check(s, "guest", { type: "approval.read" }, { ask: own })).toEqual({ allowed: true, stepUp: null })
})

describe("invisible ask mutation refusals", () => {
  it("Kim cannot distinguish another member's private ask through mutation rows", () => {
    const state = workspaceAccessState()
    const before = JSON.stringify(state)
    const target = { ask: { device: "dev_member", credential: "itm_member", credentials: ["itm_member"], context: null } }
    for (const type of ["approval.approve", "approval.deny", "policy.approve", "policy.deny", "policy.stop"] as const) expect(can(state, accessMember(state, "kim"), { type }, target, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
    expect(can(state, accessMember(state, "owner"), { type: "approval.deny" }, target, Date.now())).toEqual({ allowed: true, stepUp: "approval.decide" })
    expect(JSON.stringify(state)).toBe(before)
  })
})

it("guest machines may request rotation only of their own ticked private credentials", () => {
 const s = workspaceAccessState()
 const principal = { kind: "device", deviceId: "dev_guest" } as const
 expect(can(s, principal, { type: "credential.rotate" }, { credential: "itm_guest" }, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 s.devices.find((device) => device.id === "dev_guest")!.scope.privateCredentials = true
 const before = JSON.stringify(s)
 expect(can(s, principal, { type: "credential.rotate" }, { credential: "itm_guest" }, Date.now())).toEqual({ allowed: true, stepUp: null })
 expect(can(s, principal, { type: "credential.rotate" }, { credential: "itm_workspace", context: { project: "prj_a", environment: "dev" } }, Date.now())).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that." })
 expect(JSON.stringify(s)).toBe(before)
})

it("protected OAuth clients require owner/admin connect authority derived from live references", () => {
 const s = workspaceAccessState()
 const client = "itm_workspace"
 const create = { client, destinationHome: { kind: "project" as const, project: "prj_a" } }
 const reconnect = { client, credential: "itm_member" }
 expect(can(s, accessMember(s, "member"), { type: "credential.connect" }, create, Date.now())).toEqual({ allowed: true, stepUp: "connect.start" })
 expect(can(s, accessMember(s, "member"), { type: "credential.reconnect" }, reconnect, Date.now())).toEqual({ allowed: true, stepUp: "connect.start" })
 s.projects.find((project) => project.id === "prj_b")!.environments.find((env) => env.name === "prod")!.references.push({ item: client, home: { kind: "workspace" }, variable: "CLIENT", field: "secret", revision: 3 })
 const before = JSON.stringify(s)
 const refusal = { allowed: false, error: "environment_refused", message: "This OAuth client requires an owner or admin.", next: { say: "Ask an owner or admin to connect using this client." } }
 expect(can(s, accessMember(s, "member"), { type: "credential.connect" }, create, Date.now())).toEqual(refusal)
 expect(can(s, accessMember(s, "member"), { type: "credential.reconnect" }, reconnect, Date.now())).toEqual(refusal)
 expect(can(s, accessMember(s, "owner"), { type: "credential.connect" }, create, Date.now())).toEqual({ allowed: true, stepUp: "connect.start" })
 expect(can(s, accessMember(s, "admin"), { type: "credential.reconnect" }, { client, credential: "itm_workspace" }, Date.now())).toEqual({ allowed: true, stepUp: "connect.start" })
 expect(can(s, accessMember(s, "guest"), { type: "credential.connect" }, { client: "itm_owner", destinationHome: { kind: "member", member: "mem_guest" } }, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 expect(JSON.stringify(s)).toBe(before)
})

it("prospective-home metadata reads stay visible while restricted without granting create or use", () => {
 const s = workspaceAccessState()
 const member = s.members.find((m) => m.id === "mem_member")!
 member.standing.restriction = { reason: "recovery", until: Date.now() + 86_400_000, notice: "ntc_recovery" }
 expect(can(s, accessMember(s, "member"), { type: "item.read" }, { destinationHome: { kind: "member", member: "mem_member" } }, Date.now())).toEqual({ allowed: true, stepUp: null })
 member.standing.restriction = null
 for (const share of s.shares) if (share.project === "prj_a" && (share.subject.kind === "member" && share.subject.member === "mem_member" || share.subject.kind === "team" && share.subject.team === "tm_engineering")) share.level = "use"
 const target = { destinationHome: { kind: "project" as const, project: "prj_a" } }
 expect(can(s, accessMember(s, "member"), { type: "item.read" }, target, Date.now())).toEqual({ allowed: true, stepUp: null })
 expect(can(s, accessMember(s, "member"), { type: "credential.create" }, target, Date.now())).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that." })
 expect(can(s, accessMember(s, "guest"), { type: "item.read" }, { destinationHome: { kind: "project", project: "prj_b" } }, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 expect(can(s, { kind: "device", deviceId: "dev_member" }, { type: "item.use", context: null }, target, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 const device = s.devices.find((d) => d.id === "dev_member")!
 device.scope.tags = ["ai"]
 expect(can(s, { kind: "device", deviceId: device.id }, { type: "item.read" }, target, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
 expect(can(s, { kind: "device", deviceId: device.id }, { type: "item.read" }, { ...target, prospectiveTags: ["ai"] }, Date.now())).toEqual({ allowed: true, stepUp: null })
 device.scope.modes = ["lease"]
 expect(can(s, { kind: "device", deviceId: device.id }, { type: "item.read" }, { ...target, prospectiveTags: ["ai"] }, Date.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
})

it("suspend, reinstate and role changes cannot bypass confirmation", () => {
 const s = state()
 expect(check(s, "owner", { type: "member.reinstate" }, { member: "mem_member" }).allowed).toBe(false)
 const subject = s.members.find((m) => m.id === "mem_member")!
 subject.status = "unconfirmed"
 for (const type of ["member.suspend", "member.reinstate", "member.role"] as const) expect(check(s, "owner", { type }, { member: subject.id, role: "admin" })).toEqual({ allowed: false, error: "conflict", message: "This membership cannot be confirmed this way." })
})
it("protecting a live workspace reference requires an owner or admin, not merely its project manager", () => {
 const s = state()
 const target = { project: "prj_a", environment: "dev" }
 const action = { type: "environment.update", before: { protected: false, fences: [], fourEyes: false }, after: { protected: true, fences: [], fourEyes: false } } as const
 expect(check(s, "kim", { ...action, before: { ...action.before, fences: [] }, after: { ...action.after, fences: [] } }, target)).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can protect project-a/dev: it uses workspace credentials." } })
 expect(check(s, "owner", { ...action, before: { ...action.before, fences: [] }, after: { ...action.after, fences: [] } }, target)).toEqual({ allowed: true, stepUp: "item.update" })
 const env = s.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!
 env.references = [{ variable: "TOKEN", field: "key", item: "itm_project", home: { kind: "project", project: "prj_a" }, revision: 2 }]
 expect(check(s, "kim", { ...action, before: { ...action.before, fences: [] }, after: { ...action.after, fences: [] } }, target)).toEqual({ allowed: true, stepUp: "item.update" })
})

it("fence additions have precise wording and a guest cannot probe share subjects", () => {
 const s = state()
 const env = s.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!
 const action: AccessAction = { type: "environment.update", before: { protected: env.protected, fences: env.fences, fourEyes: env.fourEyes }, after: { protected: env.protected, fences: ["api.example.com"], fourEyes: env.fourEyes } }
 expect(check(s, "kim", action, { project: "prj_a", environment: "dev" })).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can change fences for project-a/dev." } })
 const refusal = { allowed: false, error: "forbidden", message: "You are not allowed to do that." }
 for (const member of ["mem_member", "mem_missing"]) expect(check(s, "guest", { type: "project.share" }, { project: "prj_a", member })).toEqual(refusal)
})

it("guest admission checks every project widened by a non-project scope change", () => {
 const s = state()
 s.shares.push(share("prj_b", "mem_guest", "use", true))
 const device = s.devices.find((d) => d.id === "dev_guest")!
 device.scope = { ...device.scope, projects: ["prj_a", "prj_b"], maxEnvironment: "unprotected" }
 const target = { device: device.id, project: "prj_a", proposal: "rsp_review", before: device.scope, after: { ...device.scope, maxEnvironment: "protected" as const } }
 expect(check(s, "kim", { type: "device.rescope_admit" }, target)).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that." })
 expect(check(s, "owner", { type: "device.rescope_admit" }, target)).toEqual({ allowed: true, stepUp: "device.rescope" })
 device.scope = { ...device.scope, projects: ["prj_b"] }
 expect(check(s, "kim", { type: "device.rescope_admit" }, { ...target, before: device.scope, after: { ...device.scope, projects: ["prj_b", "prj_a"] } })).toEqual({ allowed: true, stepUp: "device.rescope" })
})

it("fence removal wording distinguishes project-only and workspace references", () => {
 const s = state()
 const env = s.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!
 env.fences = ["api.example.com"]
 const action: AccessAction = { type: "environment.update", before: { protected: false, fences: env.fences, fourEyes: false }, after: { protected: false, fences: [], fourEyes: false } }
 const target = { project: "prj_a", environment: "dev" }
 expect(check(s, "kim", action, target)).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can loosen project-a/dev: it uses workspace credentials." } })
 env.references = [{ variable: "TOKEN", field: "key", item: "itm_project", home: { kind: "project", project: "prj_a" }, revision: 2 }]
 expect(check(s, "kim", action, target)).toEqual({ allowed: false, error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can change fences for project-a/dev." } })
})

it("exports the live four-eyes union used to authorise decisions", () => {
 const s = state()
 for (const project of s.projects) project.environments.find((env) => env.name === "prod")!.references.push({ variable: "SHARED", item: "itm_workspace", home: { kind: "workspace" }, field: "key", revision: 2 })
 const ask = { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: { project: "prj_a", environment: "prod" } }
 expect(fourEyesProjects(s, ask).sort()).toEqual(["prj_a", "prj_b"])
 expect(eligibility(s, "mem_kim", ask, NOW).canApprove).toBe(false)
 expect(eligibility(s, "mem_owner", ask, NOW).canApprove).toBe(true)
})

for (const type of ["intake.cancel", "connect.cancel"] as const) it(`guest ${type} is limited to owned machine and owned human asks`, () => {
  const state = workspaceAccessState(), p = accessMember(state,"guest")
  const home = {kind:"project",project:"prj_a"} as const
  expect(can(state,p,{type},{destinationHome:home,device:"dev_member"},NOW)).toEqual({allowed:false,error:"not_found",message:"No such object."})
  expect(can(state,p,{type},{destinationHome:home,creator:"mem_member"},NOW)).toEqual({allowed:false,error:"not_found",message:"No such object."})
  expect(can(state,p,{type},{destinationHome:home,device:"dev_guest",ask:{device:"dev_guest",credential:null,credentials:[],context:null}},NOW).allowed).toBe(true)
  expect(can(state,p,{type},{destinationHome:home,creator:"mem_guest"},NOW).allowed).toBe(true)
})


describe("private credentials in owner run contexts", () => {
  it.each(["own", "contextless", "foreign", "unticked", "protected", "scope", "unshared-project", "team", "absent-environment", "shared-unreferenced"] as const)("keeps the %s context boundary", kind => {
    const state = workspaceAccessState(NOW), device = state.devices.find(d => d.id === (kind === "team" ? "dev_service" : "dev_member"))!
    device.scope.privateCredentials = kind !== "unticked"
    device.scope.projects = kind === "scope" ? ["prj_b"] : kind === "unshared-project" ? [] : ["prj_a"]
    const credential = kind === "foreign" ? "itm_owner" : kind === "shared-unreferenced" ? "itm_project" : "itm_member"
    const context = kind === "contextless" ? null : { project: kind === "unshared-project" ? "prj_b" : "prj_a", environment: kind === "protected" ? "prod" : kind === "absent-environment" ? "missing" : "dev" }
    const before = structuredClone(state)
    expect(can(state, { kind: "device", deviceId: device.id }, { type: "item.use", context }, { credential }, NOW).allowed).toBe(kind === "own" || kind === "contextless")
    expect(state).toEqual(before)
  })
})

describe("backups: owners only, the registrant's own machines, and nothing while cooling off", () => {
 it("classifies export as a reveal, removal as narrowing and the read as a read; workspace.export is unchanged", () => {
  const s = state()
  expect(classify(s, { type: "backup.export" }, {})).toBe("reveal")
  expect(classify(s, { type: "backup.recipient_add" }, {})).toBe("widen")
  expect(classify(s, { type: "backup.recipient_remove" }, {})).toBe("narrow")
  expect(classify(s, { type: "backup.read" }, {})).toBe("read")
  expect(classify(s, { type: "workspace.export" }, {})).toBe("read")
  expect(check(s, "admin", { type: "workspace.export" }, {})).toEqual({ allowed: true, stepUp: null })
 })
 it("exports only to the caller's own recipient, from a person or their own machine's key", () => {
  const s = state()
  const target = { member: "mem_owner" }
  expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "backup.export" }, target, NOW)).toEqual({ allowed: true, stepUp: null })
  expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "backup.export" }, { member: "mem_admin" }, NOW).allowed).toBe(false)
  expect(check(s, "owner", { type: "backup.export" }, { member: "mem_kim" }).allowed).toBe(false)
  for (const id of ["dev_admin", "dev_member", "dev_service"]) expect(can(s, { kind: "device", deviceId: id }, { type: "backup.export" }, target, NOW).allowed, id).toBe(false)
  s.workloads = [{ id: "wkl_task", device: "dev_owner", scope: {}, expiresAt: NOW + 60_000, revokedAt: null }]
  expect(can(s, { kind: "device", deviceId: "dev_owner", workload: "wkl_task" }, { type: "backup.export" }, target, NOW).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_owner", workload: "wkl_task" }, { type: "backup.read" }, {}, NOW).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_service" }, { type: "backup.read" }, {}, NOW).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_guest" }, { type: "backup.read" }, {}, NOW).allowed).toBe(false)
 })
 it("a demoted registrant may still remove their own recipient, never export to it", () => {
  const s = state()
  const owner = s.members.find((m) => m.id === "mem_owner")!
  owner.standing.effectiveRole = "admin"
  expect(check(s, "owner", { type: "backup.recipient_remove" }, { member: "mem_owner" })).toEqual({ allowed: true, stepUp: "backup.recipient_remove" })
  expect(check(s, "owner", { type: "backup.export" }, { member: "mem_owner" }).allowed).toBe(false)
  expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "backup.export" }, { member: "mem_owner" }, NOW).allowed).toBe(false)
  owner.standing.effectiveRole = "owner"
  owner.status = "suspended"
  expect(check(s, "owner", { type: "backup.export" }, { member: "mem_owner" }).allowed).toBe(false)
 })
 it("a restricted or pending owner cannot add or export, from the browser or a machine, but can remove and read", () => {
  for (const pending of [false, true]) {
   const s = state()
   const owner = s.members.find((m) => m.id === "mem_owner")!
   if (pending) owner.standing.transitionPending = true
   else owner.standing.restriction = { reason: "recovery", until: NOW + 1, notice: "n" }
   expect(check(s, "owner", { type: "backup.recipient_add" }, {}).allowed).toBe(false)
   expect(check(s, "owner", { type: "backup.export" }, { member: "mem_owner" }).allowed).toBe(false)
   expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "backup.export" }, { member: "mem_owner" }, NOW).allowed).toBe(false)
   expect(check(s, "owner", { type: "backup.recipient_remove" }, { member: "mem_owner" }).allowed).toBe(true)
   expect(check(s, "owner", { type: "backup.read" }, {}).allowed).toBe(true)
   expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "backup.read" }, {}, NOW).allowed).toBe(true)
   // Nothing else a machine does moves: approving its own run is not a reveal.
   expect(can(s, { kind: "device", deviceId: "dev_owner" }, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential: "itm_workspace" }, NOW).allowed).toBe(true)
  }
 })
 it("the scope: workspace and managed-project credentials and one's own private ones, four-eyes ones listed apart, no one else's", () => {
  const s = state()
  const ids = (list: { id: string }[]) => list.map((c) => c.id).sort()
  const owner = backupScope(s, "mem_owner", NOW)
  expect(ids(owner.credentials)).toEqual(["itm_owner", "itm_workspace"])
  expect(ids(owner.fourEyes)).toEqual(["itm_project"])
  expect(ids(owner.projects)).toEqual(["prj_a", "prj_b"])
  const kim = backupScope(s, "mem_kim", NOW)
  expect(ids(kim.credentials)).toEqual(["itm_kim"])
  expect(ids(kim.fourEyes)).toEqual(["itm_project"])
  expect(ids(kim.projects)).toEqual(["prj_a"])
  for (const scope of [owner, kim]) for (const c of [...scope.credentials, ...scope.fourEyes]) expect(c.home.kind !== "member" || c.home.member === (scope === owner ? "mem_owner" : "mem_kim")).toBe(true)
  s.projects[0]!.environments[1]!.fourEyes = false
  expect(ids(backupScope(s, "mem_owner", NOW).credentials)).toEqual(["itm_owner", "itm_project", "itm_workspace"])
  s.members.find((m) => m.id === "mem_owner")!.status = "removed"
  expect(backupScope(s, "mem_owner", NOW)).toEqual({ credentials: [], fourEyes: [], projects: [] })
 })
})
