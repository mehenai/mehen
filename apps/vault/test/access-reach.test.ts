import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { can } from "../src/vault/access.ts"
import { toWireError } from "../src/http.ts"
import { accessState, authorise, setProjectShare } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accountAuth, beginAccessSideEffectChecks, editAccessFixture, finishAccessSideEffectChecks, inAccess } from "./access-test-support.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
describe("live machine reach", () => {
  it("gains exactly an explicit team reference and loses it when the reference or share is removed", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      editAccessFixture(ctx, (state) => {
        state.credentials.push({ id: "itm_unrelated", home: { kind: "workspace" }, tags: [] })
        state.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!.references = []
      })
      const check = (credential: string) => {
        const state = accessState(ctx)
        return serviceUse(state, credential, ctx.now())
      }
      expect(check("itm_workspace")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      editAccessFixture(ctx, (state) => { state.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!.references = [{ item: "itm_workspace", home: { kind: "workspace" }, variable: "TOKEN", field: "key", revision: 2 }] })
      expect(check("itm_workspace")).toEqual({ allowed: true, stepUp: null })
      expect(check("itm_unrelated")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      expect(check("itm_member")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      editAccessFixture(ctx, (state) => { state.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!.references = [] })
      expect(check("itm_workspace")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      editAccessFixture(ctx, (state) => { state.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!.references = [{ item: "itm_workspace", home: { kind: "workspace" }, variable: "TOKEN", field: "key", revision: 3 }] })
      const share = accessState(ctx).shares.find((s) => s.id === "shr_service")!
      ctx.storage.transactionSync(() => setProjectShare(ctx, null, share))
      expect(check("itm_workspace")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      ctx.storage.transactionSync(() => setProjectShare(ctx, { ...share, expiresAt: new Date(ctx.now() - 1).toISOString() }, null))
      expect(check("itm_workspace")).toEqual({ allowed: false, error: "not_found", message: "No such object." })
    })
  })
  it("requires the accepted private tick for metadata and use, even for the owner's own credential", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const state = accessState(ctx)
      const before = JSON.stringify(ctx.sql.exec("SELECT * FROM devices WHERE id='dev_member'").toArray())
      for (const action of [{ type: "item.read" as const }, { type: "item.use" as const, context: null }]) expect(can(state, { kind: "device", deviceId: "dev_member" }, action, { credential: "itm_member" }, ctx.now())).toEqual(can(state, { kind: "device", deviceId: "dev_member" }, action, { credential: "itm_absent" }, ctx.now()))
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM devices WHERE id='dev_member'").toArray())).toBe(before)
      const device = state.devices.find((d) => d.id === "dev_member")!
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", JSON.stringify({ ...device.scope, privateCredentials: true }))
      expect(can(accessState(ctx), { kind: "device", deviceId: "dev_member" }, { type: "item.use", context: null }, { credential: "itm_member" }, ctx.now())).toEqual({ allowed: true, stepUp: null })
      expect(can(accessState(ctx), { kind: "device", deviceId: "dev_member" }, { type: "item.read" }, { credential: "itm_kim" }, ctx.now())).toEqual({ allowed: false, error: "not_found", message: "No such object." })
      // Member managers cannot delegate workspace references into a service-shared project.
      let refusal: unknown
      try { authorise(ctx, { auth: accountAuth("kim"), workspace: { id: tenant, slug: "work", name: "Work" } }, { type: "var.set", before: null, after: { kind: "item", item: "itm_workspace", field: "key" } }, { project: "prj_a", environment: "dev", variable: "OTHER" }, ctx.now()) } catch (error) { refusal = toWireError(error) }
      expect(refusal).toEqual({ status: 403, vaultError: { error: "forbidden", message: "You are not allowed to do that." } })
    })
  })
})
function serviceUse(state: import("../src/vault/access.ts").AccessState, credential: string, now: number) { return can(state, { kind: "device", deviceId: "dev_service" }, { type: "item.use", context: { project: "prj_a", environment: "dev" } }, { credential }, now) }
