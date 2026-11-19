import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { toWireError } from "../src/http.ts"
import { authorise, installSecurity, observeCommittedEpoch, principalOf, requireStepUp, security, setSetting, updateRestriction } from "../src/vault/areas/workspace-runtime.ts"
import { accessFixture, accountAuth, beginAccessSideEffectChecks, finishAccessSideEffectChecks, inAccess } from "./access-test-support.ts"
beforeEach(beginAccessSideEffectChecks)
afterEach(finishAccessSideEffectChecks)
describe("DO account security epoch barrier", () => {
  it("allows only the surviving-session safe list while pending, then refuses all prior epochs once commit is observed", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      installSecurity(ctx, "acc_owner", 0, { transitionId: "ast_pending", reservedEpoch: 1, revokedSessionIds: ["ses_revoked"], removedFactorIds: ["pk_removed"], restriction: null })
      const auth = accountAuth("owner")
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      expect(authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now()).allowed).toBe(true)
      expect(authorise(ctx, invocation, { type: "workspace.freeze" }, {}, ctx.now()).allowed).toBe(true)
      expect(authorise(ctx, invocation, { type: "device.revoke" }, { device: "dev_member" }, ctx.now()).allowed).toBe(true)
      expect(authorise(ctx, invocation, { type: "approval.deny" }, { ask: { device: "dev_owner", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } }, ctx.now()).allowed).toBe(true)
      for (const type of ["workspace.unfreeze", "credential.reveal", "approval.approve"] as const) {
        let refusal: unknown
        try { authorise(ctx, invocation, { type }, { ask: { device: "dev_owner", credential: "itm_workspace", credentials: ["itm_workspace"], context: null } }, ctx.now()) } catch (error) { refusal = toWireError(error) }
        expect(refusal).toEqual({ status: 403, vaultError: { error: "account_pending", message: "You are not allowed to do that.", transition: { id: "ast_pending", reservedEpoch: 1, targets: 0, acknowledged: 0, state: "pending" }, next: { url: "https://vault.test/account", say: "Wait for this account security change to finish." } } })
      }
      expect(() => principalOf(ctx, { ...auth, session: "ses_revoked" })).toThrow("no longer authorised")
      expect(() => principalOf(ctx, { ...auth, stepUpFactor: "pk_removed" })).toThrow("no longer authorised")
      // A lost committed message leaves only the pending safe list, never widening.
      expect(security(ctx, "acc_owner")?.installedEpoch).toBe(0)
      observeCommittedEpoch(ctx, "acc_owner", 1)
      expect(() => principalOf(ctx, auth)).toThrow("no longer authorised")
      expect(principalOf(ctx, { ...auth, securityEpoch: 1 })).toMatchObject({ securityEpoch: 1 })
    })
  })
  it("merges revocations monotonically, ignores stale installs and preserves a newer pending guard across an older commit", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, (ctx) => {
      const first = { transitionId: "ast_first", reservedEpoch: 1, revokedSessionIds: ["ses_one"], removedFactorIds: ["pk_one"], restriction: { reason: "recovery" as const, until: ctx.now() + 86_400_000, notice: "ntc_recovery" } }
      installSecurity(ctx, "acc_owner", 0, first)
      installSecurity(ctx, "acc_owner", 0, { ...first, reservedEpoch: 2, revokedSessionIds: ["ses_two"], removedFactorIds: ["pk_two"], restriction: null })
      observeCommittedEpoch(ctx, "acc_owner", 1)
      const beforeStale = security(ctx, "acc_owner")
      expect(beforeStale).toMatchObject({ installedEpoch: 1, pending: { reservedEpoch: 2 }, revokedSessionIds: ["ses_one", "ses_two"], removedFactorIds: ["pk_one", "pk_two"], restriction: first.restriction })
      installSecurity(ctx, "acc_owner", 0, first)
      expect(security(ctx, "acc_owner")).toEqual(beforeStale)
      const auth = { ...accountAuth("owner"), securityEpoch: 1 }
      const invocation = { auth, workspace: { id: tenant, slug: "work", name: "Work" } }
      expect(authorise(ctx, invocation, { type: "people.read" }, {}, ctx.now()).allowed).toBe(true)
      expect(() => authorise(ctx, invocation, { type: "workspace.unfreeze" }, {}, ctx.now())).toThrow("not allowed")
      expect(() => updateRestriction(ctx, "acc_owner", 1, null)).toThrow("not committed")
      observeCommittedEpoch(ctx, "acc_owner", 2)
      const after = updateRestriction(ctx, "acc_owner", 2, null)
      expect(after).toMatchObject({ installedEpoch: 2, pending: null, restriction: null, revokedSessionIds: ["ses_one", "ses_two"], removedFactorIds: ["pk_one", "pk_two"] })
      const auditLength = ctx.sql.exec("SELECT seq FROM audit").toArray().length
      observeCommittedEpoch(ctx, "acc_owner", 2); installSecurity(ctx, "acc_owner", 2, null)
      expect(ctx.sql.exec("SELECT seq FROM audit").toArray()).toHaveLength(auditLength)
    })
  })
  it("rechecks a prepared step-up after the last await and cannot mutate from a revoked session", async () => {
    const { tenant } = await accessFixture()
    await inAccess(tenant, async (ctx) => {
      const action = { type: "workspace.unfreeze" } as const
      const invocation = { auth: accountAuth("owner", action), workspace: { id: tenant, slug: "work", name: "Work" } }
      const decision = authorise(ctx, invocation, { type: "workspace.unfreeze" }, {}, ctx.now())
      let resume: () => void = () => undefined
      const barrier = new Promise<void>((resolve) => { resume = resolve })
      const waiting = (async () => { await barrier; ctx.storage.transactionSync(() => { requireStepUp(ctx, decision, action, invocation); setSetting(ctx, "losing_mutation", true) }) })()
      installSecurity(ctx, "acc_owner", 0, { transitionId: "ast_cancel", reservedEpoch: 1, revokedSessionIds: ["ses_owner"], removedFactorIds: ["pk_recovered"], restriction: { reason: "recovery", until: ctx.now() + 86_400_000, notice: "ntc_cancel" } })
      resume()
      await expect(waiting).rejects.toThrow("no longer authorised")
      expect(ctx.sql.exec("SELECT * FROM tenant_state WHERE key='losing_mutation'").toArray()).toEqual([])
    })
  })
})
