// The evaluator intersects a workload's scope with its device's in one
// place (principalDevice): items, tags, projects and modes, never a union.
import { expect, it } from "vitest"
import type { WorkloadScope } from "@mehen/protocol"
import { can, eligibility, principalDevice, type AccessPrincipal, type AccessState } from "../src/vault/access.ts"
import { workspaceAccessState } from "./workspace-fixtures.ts"

const NOW = Date.UTC(2026, 9, 29, 12)
function state(scope: WorkloadScope, device: Partial<AccessState["devices"][number]["scope"]> = {}): AccessState {
  const s = workspaceAccessState(NOW)
  s.credentials = s.credentials.map((c) => ({ ...c, slug: c.id.replace("itm_", "cred-"), tags: c.id === "itm_workspace" ? ["work", "ci"] : ["work"] }))
  const d = s.devices.find((d) => d.id === "dev_member")!
  d.scope = { ...d.scope, ...device }
  s.workloads = [{ id: "wl_task00001", device: "dev_member", scope, expiresAt: NOW + 60_000, revokedAt: null }]
  return s
}
const task: AccessPrincipal = { kind: "device", deviceId: "dev_member", workload: "wl_task00001" }
const device: AccessPrincipal = { kind: "device", deviceId: "dev_member" }
const read = (s: AccessState, p: AccessPrincipal, credential: string) => can(s, p, { type: "item.read" }, { credential }, NOW)
const use = (s: AccessState, p: AccessPrincipal, credential: string, mode: "relay" | "sign" | "lease" = "relay") => can(s, p, { type: "item.use", context: null }, { credential, mode }, NOW)

it("items narrow by slug, and tags must meet both the device's and the workload's", () => {
  const s = state({ items: ["cred-workspace"] })
  expect(read(s, device, "itm_project").allowed).toBe(true)
  expect(read(s, task, "itm_workspace").allowed).toBe(true)
  expect(read(s, task, "itm_project")).toMatchObject({ allowed: false, error: "not_found" })
  const tagged = state({ tags: ["ci"] }, { tags: ["work"] })
  expect(read(tagged, task, "itm_workspace").allowed).toBe(true)
  expect(read(tagged, task, "itm_project")).toMatchObject({ allowed: false, error: "not_found" })
  // A workload tag the device's tags exclude never widens the device.
  const outside = state({ tags: ["ci"] }, { tags: ["elsewhere"] })
  expect(read(outside, task, "itm_workspace")).toMatchObject({ allowed: false, error: "not_found" })
})

it("modes intersect, so a workload never uses a mode its device lacks or it was not given", () => {
  const s = state({ modes: ["sign"] }, { modes: ["relay", "sign"] })
  expect(use(s, device, "itm_workspace", "relay").allowed).toBe(true)
  expect(use(s, task, "itm_workspace", "relay").allowed).toBe(false)
  expect(use(s, task, "itm_workspace", "sign").allowed).toBe(true)
  expect(use(state({ modes: ["lease"] }, { modes: ["relay"] }), task, "itm_workspace", "lease").allowed).toBe(false)
  expect(principalDevice(state({ modes: ["lease"] }, { modes: ["relay"] }), task, NOW)?.scope.modes).toEqual([])
})

it("projects intersect, and an empty intersection reaches no project rather than every one", () => {
  expect(can(state({ projects: ["prj_b"] }), task, { type: "project.read" }, { project: "prj_a" }, NOW)).toMatchObject({ allowed: false, error: "not_found" })
  expect(can(state({ projects: ["prj_a"] }), task, { type: "project.read" }, { project: "prj_a" }, NOW).allowed).toBe(true)
  const disjoint = state({ projects: ["prj_b"] }, { projects: ["prj_a"] })
  expect(principalDevice(disjoint, task, NOW)?.scope.projects).not.toEqual([])
  for (const project of ["prj_a", "prj_b"]) expect(can(disjoint, task, { type: "project.read" }, { project }, NOW).allowed).toBe(false)
  expect(can(disjoint, task, { type: "run.unprotected" }, { project: "prj_a", environment: "dev" }, NOW).allowed).toBe(false)
})

it("an ended workload, or one naming another device, acts as no device", () => {
  const s = state({})
  s.workloads![0]!.revokedAt = NOW - 1
  expect(read(s, task, "itm_workspace")).toMatchObject({ allowed: false, error: "workload_ended" })
  const expired = state({})
  expired.workloads![0]!.expiresAt = NOW
  expect(read(expired, task, "itm_workspace")).toMatchObject({ allowed: false, error: "workload_ended" })
  expect(read(state({}), { kind: "device", deviceId: "dev_kim", workload: "wl_task00001" }, "itm_workspace")).toMatchObject({ allowed: false, error: "workload_ended" })
})

it("who may approve a workload's ask follows the workload's scope", () => {
  const s = state({ items: ["cred-project"] })
  const ask = { device: "dev_member", credential: "itm_workspace", credentials: ["itm_workspace"], context: null }
  expect(eligibility(s, "mem_member", ask, NOW).canApprove).toBe(true)
  expect(eligibility(s, "mem_member", { ...ask, workload: "wl_task00001" }, NOW).canApprove).toBe(false)
})

it("only the asking key stops a grant: a workload its own, never its device's own key nor another workload", () => {
  const s = state({})
  s.workloads!.push({ id: "wl_task00002", device: "dev_member", scope: {}, expiresAt: NOW + 60_000, revokedAt: null })
  const ask = { device: "dev_member", workload: "wl_task00001", credential: "itm_workspace", credentials: ["itm_workspace"], context: null }
  expect(can(s, task, { type: "policy.stop" }, { ask }, NOW).allowed).toBe(true)
  expect(can(s, device, { type: "policy.stop" }, { ask }, NOW).allowed).toBe(false)
  expect(can(s, device, { type: "policy.stop" }, { ask: { ...ask, workload: undefined } }, NOW).allowed).toBe(true)
  expect(can(s, { kind: "device", deviceId: "dev_member", workload: "wl_task00002" }, { type: "policy.stop" }, { ask }, NOW).allowed).toBe(false)
})

it("a workload keeps its device's environment ceiling: never a protected run its device may not start", () => {
  const unprotected = state({}, { maxEnvironment: "unprotected" })
  expect(can(unprotected, device, { type: "run.protected" }, { project: "prj_a", environment: "prod" }, NOW).allowed).toBe(false)
  expect(can(unprotected, task, { type: "run.protected" }, { project: "prj_a", environment: "prod" }, NOW).allowed).toBe(false)
  expect(principalDevice(unprotected, task, NOW)?.scope.maxEnvironment).toBe("unprotected")
  expect(can(unprotected, task, { type: "run.unprotected" }, { project: "prj_a", environment: "dev" }, NOW).allowed).toBe(true)
})
