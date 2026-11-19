import { describe, expect, it, vi } from "vitest"
import { canonicalJson } from "@mehen/protocol"
import { assertApprovedUse, approvedUseSnapshot } from "../src/vault/areas/projects-workspace.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { workspaceAccessState } from "./workspace-fixtures.ts"
const NOW = 1_800_000_000_000
const ITEM = { id: "itm_workspace", slug: "workspace-key", home: { kind: "workspace" as const }, version: 1 }
function fixture() {
  const state = workspaceAccessState(NOW)
  for (const p of state.projects) {
    const prod = p.environments.find((e) => e.name === "prod")!
    prod.references = [{ variable: "TOKEN", field: "key", item: ITEM.id, home: ITEM.home, revision: 1 }]
  }
  const open = vi.fn(), send = vi.fn(), write = vi.fn()
  // Initial refusals cannot enter a secret/storage/upstream service.
  const ctx = { openField: open, sql: { exec: write } } as unknown as VaultContext
  return { state, ctx, open, send, write }
}
describe("protected use interface", () => {
  for (const invalid of ["dev", "non-reference", "scope", "share"] as const) {
    it(`refuses ${invalid} before secret open, storage change or upstream send`, () => {
      const f = fixture()
      const context = { project: "prj_a", env: invalid === "dev" ? "dev" : "prod" }
      if (invalid === "non-reference") f.state.projects[0]!.environments.find((e) => e.name === "prod")!.references = []
      if (invalid === "scope") f.state.devices.find((d) => d.id === "dev_kim")!.scope.maxEnvironment = "unprotected"
      if (invalid === "share") f.state.shares = f.state.shares.filter((s) => s.id !== "shr_kim")
      const before = canonicalJson(f.state)
      expect(() => approvedUseSnapshot(f.ctx, f.state, { kind: "device", deviceId: "dev_kim" }, ITEM, context, NOW)).toThrow()
      expect(canonicalJson(f.state)).toBe(before)
      expect(f.open).not.toHaveBeenCalled(); expect(f.send).not.toHaveBeenCalled(); expect(f.write).not.toHaveBeenCalled()
    })
  }
  it("binds every applicable project and refuses a changed reference before consulting a grant", () => {
    const f = fixture()
    const { snapshot, ask } = approvedUseSnapshot(f.ctx, f.state, { kind: "device", deviceId: "dev_kim" }, ITEM, { project: "prj_a", env: "prod" }, NOW)
    expect(snapshot.fourEyes).toEqual(["prj_a", "prj_b"])
    expect(ask?.context).toEqual({ project: "prj_a", environment: "prod" })
    f.state.projects[1]!.environments.find((e) => e.name === "prod")!.protectionRevision++
    expect(() => assertApprovedUse(f.ctx, f.state, snapshot, "apr_test", NOW)).toThrow("Access changed")
    expect(f.open).not.toHaveBeenCalled(); expect(f.send).not.toHaveBeenCalled(); expect(f.write).not.toHaveBeenCalled()
  })
})

import { fourEyesProjects } from "../src/vault/access.ts"
it("snapshots use the evaluator's four-eyes set across fixture graph permutations", () => {
  for (let mask=0;mask<32;mask++) {
    const f = fixture()
    const a = f.state.projects.find((p) => p.id === "prj_a")!, b = f.state.projects.find((p) => p.id === "prj_b")!
    a.environments.find((e) => e.name === "prod")!.fourEyes = Boolean(mask & 1)
    const prod = b.environments.find((e) => e.name === "prod")!, staging = b.environments.find((e) => e.name === "staging")!
    prod.fourEyes = Boolean(mask & 2)
    staging.fourEyes = Boolean(mask & 4)
    staging.references = mask & 8 ? structuredClone(prod.references) : []
    if (mask & 16) f.state.projects.reverse()
    const before = structuredClone(f.state)
    const result = approvedUseSnapshot(f.ctx, f.state, { kind: "device", deviceId: "dev_kim" }, ITEM, { project: "prj_a", env: "prod" }, NOW)
    expect(result.ask).not.toBeNull()
    expect(result.snapshot.fourEyes).toEqual(fourEyesProjects(f.state, result.ask!).sort())
    expect(f.state).toEqual(before)
  }
})
